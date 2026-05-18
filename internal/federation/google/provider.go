// Package google implements the federation.Provider interface for
// Google Sign-In (OpenID Connect on top of OAuth 2.0).
//
// Authorization: https://accounts.google.com/o/oauth2/v2/auth
// Token:         https://oauth2.googleapis.com/token
// JWKS:          https://www.googleapis.com/oauth2/v3/certs
// Issuer:        https://accounts.google.com
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
)

const (
	authEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint = "https://oauth2.googleapis.com/token"
	jwksURL       = "https://www.googleapis.com/oauth2/v3/certs"
	issuer        = "https://accounts.google.com"
)

// Provider is the Google OIDC implementation.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
	jwks         *crypto.JWKSCache
}

// Config is the constructor input.
type Config struct {
	ClientID     string
	ClientSecret string
	// RedirectURL must be registered in the Google Cloud Console.
	// Typically: <BASE_URL>/oauth/callback/google
	RedirectURL string
	HTTPClient  *http.Client // optional; defaults to a 15s-timeout client
}

// New returns a configured Google provider.
func New(cfg Config) *Provider {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Provider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURL:  cfg.RedirectURL,
		httpClient:   client,
		jwks:         crypto.NewJWKSCache(jwksURL, 15*time.Minute, client),
	}
}

// Name implements federation.Provider.
func (p *Provider) Name() string { return "google" }

// AuthURL builds the Google authorization URL with PKCE and the required
// scopes. The `access_type=offline` parameter is omitted — we only need
// the id_token; refresh tokens aren't stored in P2.
func (p *Provider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":             {p.clientID},
		"redirect_uri":          {p.redirectURL},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		// Prompt forces account selection — useful for users with
		// multiple Google accounts.
		"prompt": {"select_account"},
	}
	return authEndpoint + "?" + params.Encode()
}

// Exchange redeems the authorization code and returns a normalized Identity.
// It verifies the id_token signature against Google's JWKS.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (*federation.Identity, error) {
	// ── Token exchange ────────────────────────────────────────────────
	tokenResp, err := p.exchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("google: token exchange: %w", err)
	}

	// ── Verify id_token ───────────────────────────────────────────────
	claims, err := crypto.VerifyRS256(ctx, tokenResp.IDToken, p.clientID, issuer, p.jwks)
	if err != nil {
		return nil, fmt.Errorf("google: verify id_token: %w", err)
	}

	return &federation.Identity{
		Sub:       claims.Subject,
		Email:     strings.ToLower(claims.Email),
		Name:      claims.Name,
		Picture:   claims.Picture,
		RawClaims: claims.RawClaims,
	}, nil
}

// ─── internal helpers ─────────────────────────────────────────────────────

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (p *Provider) exchangeCode(ctx context.Context, code, codeVerifier string) (*tokenResponse, error) {
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("token endpoint returned %d: %v", resp.StatusCode, errBody)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}
	return &tr, nil
}
