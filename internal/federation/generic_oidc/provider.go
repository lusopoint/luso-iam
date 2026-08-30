package generic_oidc

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

// generic_oidc implements a config-driven OIDC provider that
// works with any OpenID Connect-compliant identity provider: Microsoft
// Entra, GitLab, Auth0, Okta, Keycloak, etc
//
// it fetches the provider's discovery document at startup to resolve
// the authorization, token, and JWKS endpoints, then behaves like the
// Google provider for the token exchange flow

// Provider is a fully configurable OIDC provider.
type Provider struct {
	name         string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string

	// Resolved from discovery document at construction.
	authEndpoint  string
	tokenEndpoint string
	issuer        string

	httpClient *http.Client
	jwks       *crypto.JWKSCache
}

// Config is the constructor input.
type Config struct {
	// Name is the provider slug used in URLs and the DB.
	// e.g. "microsoft", "gitlab", "mycompany"
	Name string

	ClientID     string
	ClientSecret string
	// IssuerURL is the OIDC Issuer the discovery document is fetched
	// from <IssuerURL>/.well-known/openid-configuration.
	IssuerURL string
	// RedirectURL: <BASE_URL>/oauth/callback/<Name>
	RedirectURL string
	// Scopes defaults to ["openid", "email", "profile"] if nil.
	Scopes     []string
	HTTPClient *http.Client
}

// discoveryDoc is the minimal subset of an OIDC discovery response we use.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// New fetches the OIDC discovery document and returns a configured
// provider. Returns an error if the discovery document is unreachable
// or malformed.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	disco, err := fetchDiscovery(ctx, cfg.IssuerURL, client)
	if err != nil {
		return nil, fmt.Errorf("generic_oidc %q: discovery: %w", cfg.Name, err)
	}

	return &Provider{
		name:          cfg.Name,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		redirectURL:   cfg.RedirectURL,
		scopes:        scopes,
		authEndpoint:  disco.AuthorizationEndpoint,
		tokenEndpoint: disco.TokenEndpoint,
		issuer:        disco.Issuer,
		httpClient:    client,
		jwks:          crypto.NewJWKSCache(disco.JWKSURI, 15*time.Minute, client),
	}, nil
}

// Name implements federation.Provider.
func (p *Provider) Name() string { return p.name }

// AuthURL implements federation.Provider.
func (p *Provider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":             {p.clientID},
		"redirect_uri":          {p.redirectURL},
		"response_type":         {"code"},
		"scope":                 {strings.Join(p.scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return p.authEndpoint + "?" + params.Encode()
}

// Exchange implements federation.Provider.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (*federation.Identity, error) {
	idToken, err := p.exchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("generic_oidc %q: token exchange: %w", p.name, err)
	}

	claims, err := crypto.VerifyRS256(ctx, idToken, p.clientID, p.issuer, p.jwks)
	if err != nil {
		return nil, fmt.Errorf("generic_oidc %q: verify id_token: %w", p.name, err)
	}

	return &federation.Identity{
		Sub:           claims.Subject,
		Email:         strings.ToLower(claims.Email),
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		RawClaims:     claims.RawClaims,
	}, nil
}

// internal helpers

func fetchDiscovery(ctx context.Context, issuerURL string, client *http.Client) (*discoveryDoc, error) {
	// Ensure no double slash before .well-known
	base := strings.TrimRight(issuerURL, "/")
	discURL := base + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", discURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode discovery doc: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("incomplete discovery document from %s", discURL)
	}
	return &doc, nil
}

func (p *Provider) exchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST token: %w", err)
	}
	defer resp.Body.Close()

	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("provider error: %s", tr.Error)
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("no id_token in response")
	}
	return tr.IDToken, nil
}
