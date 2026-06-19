package oidc

import (
	"errors"
	"net/http"

	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
)

// userinfo handles GET and POST /oauth2/userinfo
func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" && r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			token = r.FormValue("access_token")
		}
	}
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required.")
		return
	}

	claims, err := h.svc.UserInfo(r.Context(), token)
	if err != nil {
		if errors.Is(err, oidcsvc.ErrInvalidToken) {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="userinfo", error="invalid_token"`)
			oauthError(w, http.StatusUnauthorized, "invalid_token", "Token is invalid or expired.")
			return
		}
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not retrieve user info.")
		return
	}

	writeJSON(w, http.StatusOK, claims)
}
