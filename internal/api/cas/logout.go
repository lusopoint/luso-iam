package cas

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lusopoint/lusoiam/internal/audit"
	"net/http"
)

// logout handles GET /cas/logout
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var actor pgtype.UUID
	if sess, err := h.sessions.Get(r.Context(), r); err == nil {
		actor = sess.UserID
	}

	_ = h.sessions.Destroy(r.Context(), w, r)

	if h.audit != nil && actor.Valid {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:  audit.EventLogout,
			Actor: &actor,
		}))
	}
	destination := r.URL.Query().Get("service")
	if destination == "" {
		destination = r.URL.Query().Get("url")
	}
	if destination == "" {
		destination = "/cas/login"
	}

	http.Redirect(w, r, destination, http.StatusFound)
}
