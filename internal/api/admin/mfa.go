package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// mfa management for the admin portal, the endpoints here let an
// operator recover users who have lost their second factor
// flow is "user lost phone -> admin removes the TOTP method -> user signs
// in with a backup code -> re-enrolls"
// removing methods is the only destructive verb the admin needs
// the user themself enrolls and regenerates backup codes via /mfa/enroll
//
// why no "force re-enroll" flag: tracking that as durable state on the
// user row means adding a new column and threading enforcement into the login flow
// the simpler operational story, admin deletes the bad method, user authenticates
// by other means, user re-enrolls
// covers every real case (lost phone, switched devices, suspected compromise)
// without any new state.

// mfaMethodDTO is the read shape returned to the SPA
// critically, we NEVER include the TOTP secret or WebAuthn credential bytes
// those stay server-side. The admin only needs metadata to make decisions
type mfaMethodDTO struct {
	ID          string  `json:"id"`
	Method      string  `json:"method"` // "totp" | "webauthn"
	Name        *string `json:"name,omitempty"`
	ConfirmedAt *string `json:"confirmed_at,omitempty"`
	LastUsedAt  *string `json:"last_used_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

type listUserMFAResponse struct {
	Methods           []mfaMethodDTO `json:"methods"`
	BackupCodesUnused int            `json:"backup_codes_unused"`
}

// GET /admin/v1/users/{id}/mfa
func (h *Handler) listUserMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}

	methods, err := h.store.ListAllMFAMethods(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list MFA methods.")
		return
	}

	// backup-code count is a separate table, fetched in parallel to the
	// methods so the UI can render the full security picture in one card
	codes, err := h.store.ListUnusedBackupCodes(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not count backup codes.")
		return
	}

	out := listUserMFAResponse{
		Methods:           make([]mfaMethodDTO, 0, len(methods)),
		BackupCodesUnused: len(codes),
	}
	for _, m := range methods {
		out.Methods = append(out.Methods, toMFAMethodDTO(m))
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /admin/v1/users/{id}/mfa/{methodId}
// removes a single method
// the user can still sign in if they have other methods or backup codes
// if this was their only one, they revert to password only auth on next
// sign-in, which is what we want for recovery
func (h *Handler) deleteUserMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}
	methodID, ok := parseUUID(r.PathValue("methodId"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid method id.")
		return
	}

	method, err := h.store.GetMFAMethod(r.Context(), methodID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Method not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load method.")
		return
	}
	// ownership check, the two UUIDs must match, otherwise an attacker
	// could check other users method ids via this route
	if method.UserID.Bytes != userID.Bytes {
		writeProblem(w, http.StatusNotFound, "not_found", "Method not found.")
		return
	}

	if err := h.store.DeleteMFAMethod(r.Context(), methodID); err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not delete method.")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:   audit.EventMFADeleted,
		Actor:  &actor.ID,
		Target: &userID,
		Metadata: map[string]any{
			"method":      method.Method,
			"method_id":   uuidString(methodID),
			"method_name": derefString(method.Name),
			"deleted_by":  "admin",
		},
	}))

	w.WriteHeader(http.StatusNoContent)
}

// DELETE /admin/v1/users/{id}/mfa
//
// removes every mfa method and wipes backup codes
// use case: user returned from a long absence with no phone, no codes, no recovery path
//
// this is more destructive than the single-method delete, so we
// expect the SPA to gate it behind a typed confirmation modal
// the server doesn't enforce that, it does its job atomically
func (h *Handler) deleteAllUserMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid user id.")
		return
	}

	methods, err := h.store.ListAllMFAMethods(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list methods.")
		return
	}

	// best effort delete loop, if one delete fails partway through, the
	// audit log still captures what we did manage to remove
	removed := 0
	for _, m := range methods {
		if err := h.store.DeleteMFAMethod(r.Context(), m.ID); err == nil {
			removed++
		}
	}

	// ReplaceBackupCodes with an empty slice wipes the users codes
	// we don't bail on error here, the methods are already gone, and
	// stale backup codes alone are not a path to login
	_ = h.store.ReplaceBackupCodes(r.Context(), userID, nil)

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:   audit.EventMFADeleted,
		Actor:  &actor.ID,
		Target: &userID,
		Metadata: map[string]any{
			"deleted_by":      "admin",
			"methods_removed": removed,
			"scope":           "all",
		},
	}))

	w.WriteHeader(http.StatusNoContent)
}

func toMFAMethodDTO(m postgres.UserMFAMethod) mfaMethodDTO {
	out := mfaMethodDTO{
		ID:        uuidString(m.ID),
		Method:    m.Method,
		Name:      m.Name,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
	}
	if m.ConfirmedAt != nil {
		s := m.ConfirmedAt.UTC().Format(time.RFC3339)
		out.ConfirmedAt = &s
	}
	if m.LastUsedAt != nil {
		s := m.LastUsedAt.UTC().Format(time.RFC3339)
		out.LastUsedAt = &s
	}
	return out
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
