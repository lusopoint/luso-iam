package oidc

import (
	"errors"
	"net/http"

	"github.com/lusopoint/lusoiam/internal/metrics"
	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
)

// token handles POST /oauth2/token
// dispatches to the correct grant handler based on grant_type
func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse request body.")
		return
	}

	clientID, clientSecret := clientCreds(r)
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.tokenAuthCode(w, r, clientID, clientSecret)
	case "refresh_token":
		h.tokenRefresh(w, r, clientID, clientSecret)
	case "client_credentials":
		h.tokenClientCredentials(w, r, clientID, clientSecret)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"Supported grant types: authorization_code, refresh_token, client_credentials.")
	}
}

func (h *Handler) tokenAuthCode(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	resp, err := h.svc.ExchangeCode(r.Context(),
		clientID, clientSecret,
		r.FormValue("code"),
		r.FormValue("redirect_uri"),
		r.FormValue("code_verifier"),
	)
	if err != nil {
		tokenError(w, err)
		return
	}
	h.writeTokenResponse(w, resp)
}

func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	// parse scope, if omitted, original scopes are kept
	var scopes []string
	if s := r.FormValue("scope"); s != "" {
		scopes = splitScope(s)
	}

	resp, err := h.svc.RefreshTokens(r.Context(),
		clientID, clientSecret,
		r.FormValue("refresh_token"),
		scopes,
	)
	if err != nil {
		tokenError(w, err)
		return
	}
	h.writeTokenResponse(w, resp)
}

func (h *Handler) tokenClientCredentials(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	scopes := splitScope(r.FormValue("scope"))
	resp, err := h.svc.ClientCredentials(r.Context(), clientID, clientSecret, scopes)
	if err != nil {
		tokenError(w, err)
		return
	}
	h.writeTokenResponse(w, resp)
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, resp *oidcsvc.TokenResponse) {
	body := map[string]any{
		"access_token": resp.AccessToken,
		"token_type":   resp.TokenType,
		"expires_in":   resp.ExpiresIn,
		"scope":        resp.Scope,
	}
	if resp.IDToken != "" {
		body["id_token"] = resp.IDToken
	}
	if resp.RefreshToken != "" {
		body["refresh_token"] = resp.RefreshToken
	}
	// count issued tokens by type all types
	// (auth_code, refresh, client_credentials) pass through here
	// we count each token that's actually present in the response
	if h.metrics != nil {
		if resp.AccessToken != "" {
			h.metrics.RecordTokenIssued(metrics.TokenAccess)
		}
		if resp.IDToken != "" {
			h.metrics.RecordTokenIssued(metrics.TokenID)
		}
		if resp.RefreshToken != "" {
			h.metrics.RecordTokenIssued(metrics.TokenRefresh)
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// tokenError maps service errors to OAuth2 error codes
func tokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oidcsvc.ErrInvalidClient):
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
	case errors.Is(err, oidcsvc.ErrInvalidGrant):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "The authorization code is invalid or has expired.")
	case errors.Is(err, oidcsvc.ErrPKCEFailed):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed.")
	case errors.Is(err, oidcsvc.ErrPKCERequired):
		oauthError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required.")
	case errors.Is(err, oidcsvc.ErrInvalidScope):
		oauthError(w, http.StatusBadRequest, "invalid_scope", "Requested scope exceeds original grant.")
	case errors.Is(err, oidcsvc.ErrUnsupportedGrantType):
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", err.Error())
	case errors.Is(err, oidcsvc.ErrUnauthorizedClient):
		oauthError(w, http.StatusUnauthorized, "unauthorized_client", err.Error())
	default:
		oauthError(w, http.StatusInternalServerError, "server_error", "An internal error occurred.")
	}
}

func splitScope(s string) []string {
	var out []string
	for _, part := range splitFields(s) {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitFields(s string) []string {
	var fields []string
	start := -1
	for i, r := range s {
		if r == ' ' || r == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}
