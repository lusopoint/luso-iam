package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// auditDTO is the wire shape of an audit_log row. Metadata is returned
// as a generic map so the SPA can render whatever keys each event type
// emitted without us hard-coding a schema per event.
type auditDTO struct {
	ID        string         `json:"id"`
	EventType string         `json:"event_type"`
	ActorID   *string        `json:"actor_id,omitempty"`
	TargetID  *string        `json:"target_id,omitempty"`
	Metadata  map[string]any `json:"metadata"`
	IPAddress *string        `json:"ip_address,omitempty"`
	UserAgent *string        `json:"user_agent,omitempty"`
	CreatedAt string         `json:"created_at"`
}

func toAuditDTO(e *postgres.AuditEvent) auditDTO {
	d := auditDTO{
		ID:        uuidString(e.ID),
		EventType: e.EventType,
		IPAddress: e.IPAddress,
		UserAgent: e.UserAgent,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339),
		Metadata:  map[string]any{}, // never null on the wire, easier for the UI
	}
	if e.ActorID != nil {
		s := uuidString(*e.ActorID)
		d.ActorID = &s
	}
	if e.TargetID != nil {
		s := uuidString(*e.TargetID)
		d.TargetID = &s
	}
	if len(e.Metadata) > 0 {
		// Best-effort decode, if the column got corrupted, surface raw text
		// so the admin can still investigate.
		var m map[string]any
		if err := json.Unmarshal(e.Metadata, &m); err == nil {
			d.Metadata = m
		} else {
			d.Metadata = map[string]any{"raw": string(e.Metadata)}
		}
	}
	return d
}

// listAuditResponse is the paginated envelope.
type listAuditResponse struct {
	Events []auditDTO `json:"events"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

// GET /admin/v1/audit
//
// Query params: event_type, actor_id, target_id, since (RFC3339),
// until (RFC3339), limit, offset.
func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := postgres.ListAuditEventsFilter{
		EventType: q.Get("event_type"),
	}
	if s := q.Get("actor_id"); s != "" {
		if u, ok := parseUUID(s); ok {
			filter.ActorID = &u
		}
	}
	if s := q.Get("target_id"); s != "" {
		if u, ok := parseUUID(s); ok {
			filter.TargetID = &u
		}
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Since = t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Until = t
		}
	}
	filter.Limit, _ = strconv.Atoi(q.Get("limit"))
	filter.Offset, _ = strconv.Atoi(q.Get("offset"))

	res, err := h.store.ListAuditEvents(r.Context(), filter)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"Could not list audit events.")
		return
	}
	out := listAuditResponse{
		Events: make([]auditDTO, 0, len(res.Events)),
		Total:  res.Total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}
	for i := range res.Events {
		out.Events = append(out.Events, toAuditDTO(&res.Events[i]))
	}
	writeJSON(w, http.StatusOK, out)
}
