package oidc

import (
	"net/http"
)

// introspect handles POST /oauth2/introspect
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse body.")
		return
	}

	// authenticate the introspecting party, errors are mapped to 401
	clientID, clientSecret := clientCreds(r)
	if _, err := h.svc.IntrospectAuth(r.Context(), clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
		return
	}

	token := r.FormValue("token")
	hint := r.FormValue("token_type_hint")

	resp, err := h.svc.Introspect(r.Context(), token, hint)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Introspection failed.")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// revoke handles POST /oauth2/revoke
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse body.")
		return
	}

	clientID, clientSecret := clientCreds(r)
	if _, err := h.svc.IntrospectAuth(r.Context(), clientID, clientSecret); err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="revoke"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
		return
	}

	_ = h.svc.Revoke(r.Context(), r.FormValue("token"), r.FormValue("token_type_hint"))
	w.WriteHeader(http.StatusOK)
}
