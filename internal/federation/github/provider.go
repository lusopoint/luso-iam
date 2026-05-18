// Package github implements the federation.Provider interface for GitHub.
//
// GitHub uses OAuth 2.0 but not OIDC — there's no id_token. Instead we
// call the GitHub REST API to fetch the user object and email list.
//
// Authorization: https://github.com/login/oauth/authorize
// Token:         https://github.com/login/oauth/access_token
// User API:      https://api.github.com/user
// Emails API:    https://api.github.com/user/emails
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/federation"
)

const (
	authEndpoint  = "https://github.com/login/oauth/authorize"
	tokenEndpoint = "https://github.com/login/oauth/access_token"
	userEndpoint  = "https://api.github.com/user"
	emailEndpoint = "https://api.github.com/user/emails"
)

// Provider is the GitHub OAuth2 implementation.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
}

// Config is the constructor input.
type Config struct {
	ClientID     string
	ClientSecret string
	// RedirectURL must match the OAuth App's "Authorization callback URL"
	// in GitHub settings. Typically: <BASE_URL>/oauth/callback/github
	RedirectURL string
	HTTPClient  *http.Client
}

// New returns a configured GitHub provider.
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
	}
}

// Name implements federation.Provider.
func (p *Provider) Name() string { return "github" }

// AuthURL builds the GitHub authorization URL.
// Note: GitHub OAuth does not support PKCE — we still include PKCE in our
// state management for defence-in-depth on our side, but GitHub ignores
// code_challenge/code_challenge_method parameters.
func (p *Provider) AuthURL(state, _ string) string {
	params := url.Values{
		"client_id":    {p.clientID},
		"redirect_uri": {p.redirectURL},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}
	return authEndpoint + "?" + params.Encode()
}

// Exchange redeems the authorization code and returns a normalized Identity.
func (p *Provider) Exchange(ctx context.Context, code, _ string) (*federation.Identity, error) {
	accessToken, err := p.exchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github: token exchange: %w", err)
	}

	user, err := p.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("github: fetch user: %w", err)
	}

	// GitHub users can have a private primary email — fetch the email
	// list and take the verified primary if the profile email is empty.
	email := user.Email
	if email == "" {
		email, err = p.fetchPrimaryEmail(ctx, accessToken)
		if err != nil {
			// Non-fatal: some users have no verified email.
			email = ""
		}
	}

	rawClaims := map[string]any{
		"id":         user.ID,
		"login":      user.Login,
		"name":       user.Name,
		"email":      email,
		"avatar_url": user.AvatarURL,
		"html_url":   user.HTMLURL,
	}

	return &federation.Identity{
		// GitHub's integer user ID is the stable sub — logins can change.
		Sub:       strconv.FormatInt(user.ID, 10),
		Email:     strings.ToLower(email),
		Name:      coalesce(user.Name, user.Login),
		Picture:   user.AvatarURL,
		RawClaims: rawClaims,
	}, nil
}

// ─── internal helpers ─────────────────────────────────────────────────────

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *Provider) exchangeCode(ctx context.Context, code string) (string, error) {
	body := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// GitHub can return JSON when we ask for it.
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST token: %w", err)
	}
	defer resp.Body.Close()

	var tr struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("github error %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty access_token")
	}
	return tr.AccessToken, nil
}

func (p *Provider) fetchUser(ctx context.Context, token string) (*githubUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, userEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET /user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /user returned %d", resp.StatusCode)
	}
	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return &user, nil
}

func (p *Provider) fetchPrimaryEmail(ctx context.Context, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, emailEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /user/emails: %w", err)
	}
	defer resp.Body.Close()

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("decode emails: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified primary email")
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
