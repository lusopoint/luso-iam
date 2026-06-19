package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

type casServiceDTO struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	ServiceURLPattern  string   `json:"service_url_pattern"`
	MatchPattern       string   `json:"match_pattern"`
	Description        *string  `json:"description,omitempty"`
	ReleasedAttributes []string `json:"released_attributes"`
	Enabled            bool     `json:"enabled"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

func toCASServiceDTO(s *postgres.CASService) casServiceDTO {
	d := casServiceDTO{
		ID:                 uuidString(s.ID),
		Name:               s.Name,
		ServiceURLPattern:  s.ServiceURLPattern,
		MatchPattern:       s.MatchPattern,
		Description:        s.Description,
		ReleasedAttributes: s.ReleasedAttributes,
		Enabled:            s.Enabled,
		CreatedAt:          s.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:          s.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if d.ReleasedAttributes == nil {
		d.ReleasedAttributes = []string{}
	}
	return d
}

// GET /admin/v1/cas-services
func (h *Handler) listCASServices(w http.ResponseWriter, r *http.Request) {
	services, err := h.store.ListCASServices(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list CAS services.")
		return
	}
	out := make([]casServiceDTO, 0, len(services))
	for i := range services {
		out = append(out, toCASServiceDTO(&services[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

// GET /admin/v1/cas-services/{id}
func (h *Handler) getCASService(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid service id.")
		return
	}
	svc, err := h.store.GetCASService(r.Context(), id)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Service not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not load service.")
		return
	}
	writeJSON(w, http.StatusOK, toCASServiceDTO(svc))
}

// createCASServiceRequest carries the new service's fields
// the admin supplies a URL pattern; we derive a SQL LIKE pattern from it
type createCASServiceRequest struct {
	Name               string   `json:"name"`
	ServiceURLPattern  string   `json:"service_url_pattern"`
	Description        string   `json:"description,omitempty"`
	ReleasedAttributes []string `json:"released_attributes,omitempty"`
}

// POST /admin/v1/cas-services
func (h *Handler) createCASService(w http.ResponseWriter, r *http.Request) {
	var req createCASServiceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_field", "name is required.")
		return
	}
	if strings.TrimSpace(req.ServiceURLPattern) == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_field",
			"service_url_pattern is required.")
		return
	}

	matchPattern := toLikePattern(req.ServiceURLPattern)

	var desc *string
	if d := strings.TrimSpace(req.Description); d != "" {
		desc = &d
	}
	attrs := req.ReleasedAttributes
	if attrs == nil {
		attrs = []string{}
	}

	svc, err := h.store.CreateCASService(r.Context(), postgres.CreateCASServiceParams{
		Name:               req.Name,
		ServiceURLPattern:  req.ServiceURLPattern,
		MatchPattern:       matchPattern,
		Description:        desc,
		ReleasedAttributes: attrs,
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not create service.")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventCASServiceCreated, Actor: &actor.ID,
		Metadata: map[string]any{
			"service_id":          uuidString(svc.ID),
			"service_url_pattern": svc.ServiceURLPattern,
		},
	}))
	writeJSON(w, http.StatusCreated, toCASServiceDTO(svc))
}

// updateCASServiceRequest mirrors the patchable fields
type updateCASServiceRequest struct {
	Name               *string   `json:"name,omitempty"`
	ServiceURLPattern  *string   `json:"service_url_pattern,omitempty"`
	Description        *string   `json:"description,omitempty"`
	ReleasedAttributes *[]string `json:"released_attributes,omitempty"`
	Enabled            *bool     `json:"enabled,omitempty"`
}

// PATCH /admin/v1/cas-services/{id}
func (h *Handler) updateCASService(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid service id.")
		return
	}
	var req updateCASServiceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_body",
			"Could not parse request: "+err.Error())
		return
	}

	params := postgres.UpdateCASServiceParams{
		ID:                 id,
		Name:               req.Name,
		ServiceURLPattern:  req.ServiceURLPattern,
		Description:        req.Description,
		ReleasedAttributes: req.ReleasedAttributes,
		Enabled:            req.Enabled,
	}
	// re-derive the match pattern if the URL pattern changed
	if req.ServiceURLPattern != nil {
		mp := toLikePattern(*req.ServiceURLPattern)
		params.MatchPattern = &mp
	}

	svc, err := h.store.UpdateCASService(r.Context(), params)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Service not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not update service.")
		return
	}

	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventCASServiceUpdated, Actor: &actor.ID,
		Metadata: map[string]any{"service_id": uuidString(svc.ID)},
	}))
	writeJSON(w, http.StatusOK, toCASServiceDTO(svc))
}

// DELETE /admin/v1/cas-services/{id}
func (h *Handler) deleteCASService(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r.PathValue("id"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_id", "Invalid service id.")
		return
	}
	if err := h.store.SoftDeleteCASService(r.Context(), id); err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not_found", "Service not found.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not delete service.")
		return
	}
	actor := adminUserFromContext(r.Context())
	h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
		Type: audit.EventCASServiceDeleted, Actor: &actor.ID,
		Metadata: map[string]any{"service_id": uuidString(id)},
	}))
	w.WriteHeader(http.StatusNoContent)
}

// toLikePattern converts an admin-supplied URL prefix into a SQL LIKE
// pattern by appending '%'. If the admin already included '%' or '_'
// metacharacters, we trust them and pass through unchanged
func toLikePattern(s string) string {
	if strings.ContainsAny(s, "%_") {
		return s
	}
	return s + "%"
}
