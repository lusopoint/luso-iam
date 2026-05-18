package oidc

import (
	"encoding/json"
	"net/http"
)

// serveDiscovery handles GET /.well-known/openid-configuration.
// Response is immutable for the lifetime of the process; a real deployment
// adds cache headers and optionally a reverse-proxy cache.
func (h *Handler) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // discovery must be public
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.disco)
}

// serveJWKS handles GET /.well-known/jwks.json.
// Clients cache this to verify id_token signatures; we emit the public
// key of the active signing key. Key rotation is handled in P7.
func (h *Handler) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(h.keys.JWKS())
}
