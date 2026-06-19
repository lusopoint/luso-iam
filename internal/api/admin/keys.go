package admin

import (
	"net/http"
)

// meResponse is what the SPA reads on every page load to render the nav
// (admin name) and to decide whether to redirect to /cas/login
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
// key is the per-key shape returned by GET /admin/v1/keys
// we surface the kid and a primary flag so operators can confirm which key new
// id_tokens are being signed with vs which are kept around for backward
// verification during a rotation grace period
type keyDTO struct {
	Kid       string `json:"kid"`
	Algorithm string `json:"alg"`
	Primary   bool   `json:"primary"`
	Source    string `json:"source,omitempty"`
}

// GET /admin/v1/keys
func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	infos := h.keys.Keys()
	out := make([]keyDTO, 0, len(infos))
	for _, k := range infos {
		out = append(out, keyDTO{
			Kid:       k.Kid,
			Algorithm: "RS256",
			Primary:   k.Primary,
			Source:    k.Source,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}
