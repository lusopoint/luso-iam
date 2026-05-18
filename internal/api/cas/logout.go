package cas

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
)

// logout handles GET /cas/logout.
//
// CAS spec behaviour:
//   - Destroys the server-side session (revokes the TGT).
//   - Clears the session cookie on the browser.
//   - If `service` (or deprecated `url`) query parameter is present,
//     redirects there after logout; otherwise redirects to /cas/login.
//
// Note: single-sign-out propagation (notifying downstream services that
// sessions have ended) is a CAS 3.0 feature deferred to a later phase.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// Capture the active session BEFORE destroying it so we can record
	// who logged out. Read-only; doesn't fail the logout if it errors.
	var actor pgtype.UUID
	if sess, err := h.sessions.Get(r.Context(), r); err == nil {
		actor = sess.UserID
	}

	// Destroy the session. Errors here are non-fatal from the browser's
	// perspective — the cookie will be cleared regardless.
	_ = h.sessions.Destroy(r.Context(), w, r)

	if h.audit != nil && actor.Valid {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:  audit.EventLogout,
			Actor: &actor,
		}))
	}

	// The CAS spec allows `service` or the legacy `url` parameter.
	destination := r.URL.Query().Get("service")
	if destination == "" {
		destination = r.URL.Query().Get("url")
	}
	if destination == "" {
		destination = "/cas/login"
	}

	http.Redirect(w, r, destination, http.StatusFound)
}
