package admin

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// allowlistEntryDTO is one email on a services allowlist
type allowlistEntryDTO struct {
	Email     string `json:"email"`
	CreatedAt string `json:"created_at"`
}

// allowlistResponse is the list envelope
type allowlistResponse struct {
	ServiceType string              `json:"service_type"`
	ServiceID   string              `json:"service_id"`
	Entries     []allowlistEntryDTO `json:"entries"`
	Total       int                 `json:"total"`
}

// allowlistMutateRequest is the JSON body for add/delete
type allowlistMutateRequest struct {
	Emails []string `json:"emails"`
}

// allowlistMutateResponse reports the outcome of an add/delete/import
type allowlistMutateResponse struct {
	Added   int      `json:"added"`
	Deleted int      `json:"deleted"`
	Invalid []string `json:"invalid,omitempty"`
	Total   int      `json:"total"`
}

func (h *Handler) listClientAllowlist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.store.GetOIDCClientAny(r.Context(), id); err != nil {
		h.allowlistServiceLookupError(w, err, "Client")
		return
	}
	h.allowlistList(w, r, postgres.AllowlistServiceOIDC, id)
}

func (h *Handler) addClientAllowlist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.store.GetOIDCClientAny(r.Context(), id); err != nil {
		h.allowlistServiceLookupError(w, err, "Client")
		return
	}
	h.allowlistAddFromJSON(w, r, postgres.AllowlistServiceOIDC, id)
}

func (h *Handler) deleteClientAllowlist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := h.store.GetOIDCClientAny(r.Context(), id); err != nil {
		h.allowlistServiceLookupError(w, err, "Client")
		return
	}
	h.allowlistDeleteFromJSON(w, r, postgres.AllowlistServiceOIDC, id)
}

func (h *Handler) listCASServiceAllowlist(w http.ResponseWriter, r *http.Request) {
	sid, ok := h.casServiceID(w, r)
	if !ok {
		return
	}
	h.allowlistList(w, r, postgres.AllowlistServiceCAS, sid)
}

func (h *Handler) addCASServiceAllowlist(w http.ResponseWriter, r *http.Request) {
	sid, ok := h.casServiceID(w, r)
	if !ok {
		return
	}
	h.allowlistAddFromJSON(w, r, postgres.AllowlistServiceCAS, sid)
}

func (h *Handler) deleteCASServiceAllowlist(w http.ResponseWriter, r *http.Request) {
	sid, ok := h.casServiceID(w, r)
	if !ok {
		return
	}
	h.allowlistDeleteFromJSON(w, r, postgres.AllowlistServiceCAS, sid)
}

// casServiceID validates the {id} path param, confirms the service
// exists, and returns its canonical string id (matching what the enforcement path uses)
func (h *Handler) casServiceID(w http.ResponseWriter, r *http.Request) (string, bool) {
	uid, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid service id.")
		return "", false
	}
	if _, err := h.store.GetCASService(r.Context(), uid); err != nil {
		h.allowlistServiceLookupError(w, err, "CAS service")
		return "", false
	}
	// postgres.UUIDString is the exact representation stored/looked up by
	// the enforcement path, so use it (not the raw path string)
	return postgres.UUIDString(uid), true
}

func (h *Handler) allowlistServiceLookupError(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, postgres.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", what+" not found.")
		return
	}
	writeProblem(w, http.StatusInternalServerError, "internal_error",
		"Could not load "+strings.ToLower(what)+".")
}

func (h *Handler) allowlistList(w http.ResponseWriter, r *http.Request, serviceType, serviceID string) {
	entries, err := h.store.ListServiceAllowlist(r.Context(), serviceType, serviceID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load allowlist.")
		return
	}
	out := allowlistResponse{
		ServiceType: serviceType,
		ServiceID:   serviceID,
		Entries:     make([]allowlistEntryDTO, 0, len(entries)),
		Total:       len(entries),
	}
	for _, e := range entries {
		out.Entries = append(out.Entries, allowlistEntryDTO{
			Email:     e.Email,
			CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) allowlistAddFromJSON(w http.ResponseWriter, r *http.Request, serviceType, serviceID string) {
	var req allowlistMutateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	h.allowlistAdd(w, r, serviceType, serviceID, req.Emails)
}

func (h *Handler) allowlistDeleteFromJSON(w http.ResponseWriter, r *http.Request, serviceType, serviceID string) {
	var req allowlistMutateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	valid, _ := normaliseEmails(req.Emails)
	deleted, err := h.store.DeleteServiceAllowlistEmails(r.Context(), serviceType, serviceID, valid)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not update allowlist.")
		return
	}
	h.auditAllowlist(r, serviceType, serviceID, "delete", int(deleted))
	h.allowlistRespond(w, r, serviceType, serviceID, allowlistMutateResponse{Deleted: int(deleted)})
}

// allowlistAdd validates + normalises the emails, upserts the valid ones,
// and writes the mutate response (including any invalid entries)
func (h *Handler) allowlistAdd(w http.ResponseWriter, r *http.Request, serviceType, serviceID string, raw []string) {
	valid, invalid := normaliseEmails(raw)
	added, err := h.store.AddServiceAllowlistEmails(r.Context(), serviceType, serviceID, valid)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not update allowlist.")
		return
	}
	h.auditAllowlist(r, serviceType, serviceID, "add", int(added))
	h.allowlistRespond(w, r, serviceType, serviceID, allowlistMutateResponse{
		Added:   int(added),
		Invalid: invalid,
	})
}

// allowlistRespond re-reads the current total and writes the response
func (h *Handler) allowlistRespond(w http.ResponseWriter, r *http.Request, serviceType, serviceID string, resp allowlistMutateResponse) {
	if entries, err := h.store.ListServiceAllowlist(r.Context(), serviceType, serviceID); err == nil {
		resp.Total = len(entries)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) auditAllowlist(r *http.Request, serviceType, serviceID, action string, count int) {
	if h.audit == nil {
		return
	}
	actor := adminUserFromContext(r.Context())
	var actorID *pgtype.UUID
	if actor != nil {
		actorID = &actor.ID
	}
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type:  audit.EventAllowlistUpdated,
		Actor: actorID,
		Metadata: map[string]any{
			"service_type": serviceType,
			"service_id":   serviceID,
			"action":       action,
			"count":        count,
		},
	}))
}

// normaliseEmails lower-cases + trims each candidate, validates it as an
// address, de-duplicates, and splits into valid/invalid
func normaliseEmails(raw []string) (valid, invalid []string) {
	seen := make(map[string]bool, len(raw))
	for _, e := range raw {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		if _, err := mail.ParseAddress(e); err != nil {
			invalid = append(invalid, e)
			continue
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		valid = append(valid, e)
	}
	return valid, invalid
}
