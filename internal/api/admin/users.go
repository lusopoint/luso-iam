package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

type userDTO struct {
	ID            string  `json:"id"`
	Email         *string `json:"email,omitempty"`
	Username      *string `json:"username,omitempty"`
	DisplayName   *string `json:"display_name,omitempty"`
	Status        string  `json:"status"`
	IsAdmin       bool    `json:"is_admin"`
	EmailVerified bool    `json:"email_verified"`
	LastLoginAt   *string `json:"last_login_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

func toUserDTO(u *postgres.User) userDTO {
	d := userDTO{
		ID:            uuidString(u.ID),
		Email:         u.Email,
		Username:      u.Username,
		DisplayName:   u.DisplayName,
		Status:        u.Status,
		IsAdmin:       u.IsAdmin,
		EmailVerified: u.EmailVerifiedAt != nil,
		CreatedAt:     u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     u.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if u.LastLoginAt != nil {
		s := u.LastLoginAt.UTC().Format(time.RFC3339)
		d.LastLoginAt = &s
	}
	return d
}

// listUsersResponse is the paginated response envelope
type listUsersResponse struct {
	Users  []userDTO `json:"users"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
}

// GET /admin/v1/users?search=&status=&limit=&offset=
func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	res, err := h.store.ListUsers(r.Context(), postgres.ListUsersFilter{
		Search: q.Get("search"),
		Status: q.Get("status"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list users.")
		return
	}

	out := listUsersResponse{
		Users:  make([]userDTO, 0, len(res.Users)),
		Total:  res.Total,
		Limit:  limit,
		Offset: offset,
	}
	for i := range res.Users {
		out.Users = append(out.Users, toUserDTO(&res.Users[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// createUserRequest is the wire shape for POST /admin/v1/users
// EmailVerified defaults to true because admin-created accounts skip
// any verification flow (which doesn't exist yet anyway)
type createUserRequest struct {
	Email         string  `json:"email"`
	Username      *string `json:"username,omitempty"`
	DisplayName   *string `json:"display_name,omitempty"`
	Password      string  `json:"password,omitempty"`
	IsAdmin       bool    `json:"is_admin,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}

// createUserResponse carries the new user plus, if we generated one, the plaintext password
type createUserResponse struct {
	User              userDTO `json:"user"`
	GeneratedPassword string  `json:"generated_password,omitempty"`
}

// POST /admin/v1/users
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}

	// "contains @" check is enough, a typo would fail at first sign-in anyway
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		writeProblem(w, http.StatusBadRequest, "invalid_email",
			"A valid email address is required.")
		return
	}

	// conflict check
	if existing, err := h.store.GetUserByEmail(r.Context(), email); err == nil && existing != nil {
		writeProblem(w, http.StatusConflict, "email_taken",
			"A user with that email already exists.")
		return
	} else if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not check for existing user.")
		return
	}

	// password validate or generate
	password := req.Password
	generated := false
	if password == "" {
		p, err := crypto.RandomPassword(20)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"Could not generate password.")
			return
		}
		password = p
		generated = true
	} else if len(password) < 12 {
		writeProblem(w, http.StatusBadRequest, "weak_password",
			"Password must be at least 12 characters.")
		return
	}

	u, err := h.store.CreateUser(r.Context(), postgres.CreateUserParams{
		Email:       &email,
		Username:    req.Username,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not create user.")
		return
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		_ = h.store.SoftDeleteUser(r.Context(), u.ID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not hash password.")
		return
	}
	if err := h.store.UpsertCredential(r.Context(), u.ID, hash); err != nil {
		_ = h.store.SoftDeleteUser(r.Context(), u.ID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not store credential.")
		return
	}

	// follow up update for the optional admin flag + email verification
	verified := true
	if req.EmailVerified != nil {
		verified = *req.EmailVerified
	}
	if req.IsAdmin || verified {
		up := postgres.UpdateUserParams{ID: u.ID}
		if req.IsAdmin {
			t := true
			up.IsAdmin = &t
		}
		if verified {
			now := time.Now().UTC()
			up.EmailVerifiedAt = &now
		}
		if updated, uerr := h.store.UpdateUser(r.Context(), up); uerr == nil {
			u = updated
		}
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:   audit.EventUserCreated,
		Actor:  &actor.ID,
		Target: &u.ID,
		Metadata: map[string]any{
			"email":              email,
			"password_generated": generated,
			"is_admin":           req.IsAdmin,
			"email_verified":     verified,
		},
	}))

	resp := createUserResponse{User: toUserDTO(u)}
	if generated {
		resp.GeneratedPassword = password
	}
	writeJSON(w, http.StatusCreated, resp)
}

// GET /admin/v1/users/{id}
func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	u, err := h.store.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load user.")
		return
	}
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

// updateUserRequest mirrors UpdateUserParams but with JSON-friendly types
type updateUserRequest struct {
	Email       *string `json:"email,omitempty"`
	Username    *string `json:"username,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Status      *string `json:"status,omitempty"`
	IsAdmin     *bool   `json:"is_admin,omitempty"`
}

// PATCH /admin/v1/users/{id}
func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	if req.Status != nil {
		switch *req.Status {
		case "active", "disabled", "pending":
		default:
			writeProblem(w, http.StatusBadRequest, "invalid_status",
				"status must be active, disabled, or pending.")
			return
		}
	}

	actor := adminUserFromContext(r.Context())

	if actor != nil && actor.ID == id {
		if req.IsAdmin != nil && !*req.IsAdmin {
			writeProblem(w, http.StatusBadRequest, "self_demote",
				"You cannot remove your own admin privileges.")
			return
		}
		if req.Status != nil && *req.Status == "disabled" {
			writeProblem(w, http.StatusBadRequest, "self_disable",
				"You cannot disable your own account.")
			return
		}
	}

	u, err := h.store.UpdateUser(r.Context(), postgres.UpdateUserParams{
		ID:          id,
		Email:       req.Email,
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Status:      req.Status,
		IsAdmin:     req.IsAdmin,
	})
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not update user.")
		return
	}

	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:     audit.EventUserUpdated,
		Actor:    &actor.ID,
		Target:   &u.ID,
		Metadata: changedFields(req),
	}))
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

// DELETE /admin/v1/users/{id}
func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	actor := adminUserFromContext(r.Context())
	if actor != nil && actor.ID == id {
		writeProblem(w, http.StatusBadRequest, "self_delete",
			"You cannot delete your own account.")
		return
	}
	if err := h.store.SoftDeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not delete user.")
		return
	}
	// also revoke any active sessions so the deleted account can't continue browsing
	_, _ = h.store.RevokeAllSessionsForUser(r.Context(), id)

	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:   audit.EventUserDeleted,
		Actor:  &actor.ID,
		Target: &id,
	}))
	w.WriteHeader(http.StatusNoContent)
}

// POST /admin/v1/users/{id}/lock: sets users.status = 'disabled'
func (h *Handler) lockUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	actor := adminUserFromContext(r.Context())
	if actor != nil && actor.ID == id {
		writeProblem(w, http.StatusBadRequest, "self_lock",
			"You cannot lock your own account.")
		return
	}
	status := "disabled"
	u, err := h.store.UpdateUser(r.Context(), postgres.UpdateUserParams{
		ID: id, Status: &status,
	})
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not lock user.")
		return
	}
	_, _ = h.store.RevokeAllSessionsForUser(r.Context(), id)

	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventUserLocked, Actor: &actor.ID, Target: &u.ID,
	}))
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

// POST /admin/v1/users/{id}/unlock: re-enables a disabled account
func (h *Handler) unlockUser(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	status := "active"
	u, err := h.store.UpdateUser(r.Context(), postgres.UpdateUserParams{
		ID: id, Status: &status,
	})
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not unlock user.")
		return
	}
	// reset the auto-lockout counter so the user isn't immediately re-locked
	// by the password service on their next attempt
	_ = h.store.ResetFailedAttempts(r.Context(), u.ID)

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventUserUnlocked, Actor: &actor.ID, Target: &u.ID,
	}))
	writeJSON(w, http.StatusOK, toUserDTO(u))
}

// resetUserPasswordRequest carries the new plaintext password from the admin
type resetUserPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// POST /admin/v1/users/{id}/password: admin-initiated password reset
func (h *Handler) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	var req resetUserPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request.")
		return
	}
	if len(req.NewPassword) < 12 {
		writeProblem(w, http.StatusBadRequest, "weak_password",
			"Password must be at least 12 characters.")
		return
	}
	if _, err := h.store.GetUserByID(r.Context(), id); err != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "User not found.")
		return
	}
	hash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not hash password.")
		return
	}
	if err := h.store.UpsertCredential(r.Context(), id, hash); err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not store credential.")
		return
	}
	// reset lockout state and revoke active sessions: any session that
	// might have been opened with the old password is now stale
	_ = h.store.ResetFailedAttempts(r.Context(), id)
	_, _ = h.store.RevokeAllSessionsForUser(r.Context(), id)

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventPasswordChanged, Actor: &actor.ID, Target: &id,
		Metadata: map[string]any{"by": "admin"},
	}))
	w.WriteHeader(http.StatusNoContent)
}

type sessionDTO struct {
	ID         string   `json:"id"`
	UserID     string   `json:"user_id"`
	ACR        string   `json:"acr"`
	AMR        []string `json:"amr"`
	IPAddress  *string  `json:"ip_address,omitempty"`
	UserAgent  *string  `json:"user_agent,omitempty"`
	CreatedAt  string   `json:"created_at"`
	LastSeenAt string   `json:"last_seen_at"`
	ExpiresAt  string   `json:"expires_at"`
}

// GET /admin/v1/users/{id}/sessions
func (h *Handler) listUserSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	sessions, err := h.store.ListSessionsForUser(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list sessions.")
		return
	}
	out := make([]sessionDTO, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionDTO{
			ID:         uuidString(s.ID),
			UserID:     uuidString(s.UserID),
			ACR:        s.ACR,
			AMR:        s.AMR,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			CreatedAt:  s.CreatedAt.UTC().Format(time.RFC3339),
			LastSeenAt: s.LastSeenAt.UTC().Format(time.RFC3339),
			ExpiresAt:  s.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// POST /admin/v1/users/{id}/revoke-all: terminates every active session
func (h *Handler) revokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	n, err := h.store.RevokeAllSessionsForUser(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not revoke sessions.")
		return
	}
	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventSessionRevoked, Actor: &actor.ID, Target: &id,
		Metadata: map[string]any{"count": n, "by": "admin"},
	}))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

func changedFields(r updateUserRequest) map[string]any {
	m := map[string]any{}
	if r.Email != nil {
		m["email"] = true
	}
	if r.Username != nil {
		m["username"] = true
	}
	if r.DisplayName != nil {
		m["display_name"] = true
	}
	if r.Status != nil {
		m["status"] = *r.Status
	}
	if r.IsAdmin != nil {
		m["is_admin"] = *r.IsAdmin
	}
	return m
}

func parseUUID(s string) (pgtype.UUID, bool) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, false
	}
	return u, u.Valid
}

// uuidString renders a pgtype.UUID into canonical hex form
func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	const hx = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, b := range u.Bytes {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hx[b>>4]
		out[pos+1] = hx[b&0x0f]
		pos += 2
	}
	return string(out)
}
