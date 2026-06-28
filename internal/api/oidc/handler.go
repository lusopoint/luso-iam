package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/metrics"
	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
	pkgoidc "github.com/lusopoint/lusoiam/pkg/oidc"
)

type Handler struct {
	svc      *oidcsvc.Service
	keys     *crypto.KeyManager
	sessions *session.Service
	baseURL  string
	disco    pkgoidc.DiscoveryDocument // built once at startup
	metrics  *metrics.Metrics
}
type Config struct {
	Service  *oidcsvc.Service
	Keys     *crypto.KeyManager
	Sessions *session.Service
	BaseURL  string
	Metrics  *metrics.Metrics
}

func New(cfg Config) *Handler {
	h := &Handler{
		svc:      cfg.Service,
		keys:     cfg.Keys,
		sessions: cfg.Sessions,
		baseURL:  cfg.BaseURL,
		metrics:  cfg.Metrics,
	}
	h.disco = h.buildDiscovery()
	return h
}

// Register attaches all OIDC routes to mux
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.serveDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.serveJWKS)
	mux.HandleFunc("GET /oauth2/authorize", h.authorize)
	mux.HandleFunc("POST /oauth2/authorize", h.authorizeConsent)
	mux.HandleFunc("POST /oauth2/token", h.token)
	mux.HandleFunc("GET /oauth2/userinfo", h.userinfo)
	mux.HandleFunc("POST /oauth2/userinfo", h.userinfo)
	mux.HandleFunc("POST /oauth2/introspect", h.introspect)
	mux.HandleFunc("POST /oauth2/revoke", h.revoke)
}

// oauthError writes an JSON error response and redirects if a
// redirect_uri is available, or returns a JSON body for direct errors
func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// writeJSON writes a JSON response with Cache-Control: no-store
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// bearerToken extracts the Bearer token from the Authorization header
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

// clientCreds extracts client_id and client_secret from either HTTP Basic
// auth or the POST body (application/x-www-form-urlencoded)
func clientCreds(r *http.Request) (id, secret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// buildDiscovery constructs the discovery document from the handler config
func (h *Handler) buildDiscovery() pkgoidc.DiscoveryDocument {
	b := h.baseURL
	return pkgoidc.DiscoveryDocument{
		Issuer:                b,
		AuthorizationEndpoint: b + "/oauth2/authorize",
		TokenEndpoint:         b + "/oauth2/token",
		JWKSURI:               b + "/.well-known/jwks.json",
		UserinfoEndpoint:      b + "/oauth2/userinfo",
		IntrospectionEndpoint: b + "/oauth2/introspect",
		RevocationEndpoint:    b + "/oauth2/revoke",

		ResponseTypesSupported:        []string{"code"},
		SubjectTypesSupported:         []string{"public"},
		IDTokenSigningAlgValues:       []string{"RS256"},
		ScopesSupported:               []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported:               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash", "email", "email_verified", "name", "preferred_username", "updated_at"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token", "client_credentials"},
		TokenEndpointAuthMethods:      []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported: []string{"S256"},
		ACRValuesSupported:            []string{"0", "1"},
		AMRValuesSupported:            []string{"pwd", "mfa", "totp"},
		ClaimsParameterSupported:      false,
		RequestParameterSupported:     false,
		RequestURIParameterSupported:  false,
	}
}
