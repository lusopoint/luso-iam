package admin

import (
	"net/http"
)

// /me

// meResponse is what the SPA reads on every page load to render the nav
// (admin name) and to decide whether to redirect to /cas/login.
type meResponse struct {
	User userDTO `json:"user"`
}

// GET /admin/v1/me
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	u := adminUserFromContext(r.Context())
	if u == nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "Not signed in.")
		return
	}
	writeJSON(w, http.StatusOK, meResponse{User: toUserDTO(u)})
}

// /keys

// keyDTO is the public-key envelope for the admin UI. We expose just
// enough to identify the active signing key — full JWKS is already
// available at /.well-known/jwks.json for clients.
type keyDTO struct {
	Kid       string `json:"kid"`
	Algorithm string `json:"alg"`
}

// GET /admin/v1/keys
func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	out := []keyDTO{{
		Kid:       h.keys.KeyID(),
		Algorithm: "RS256",
	}}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}
