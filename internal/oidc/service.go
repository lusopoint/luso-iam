package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

var (
	ErrInvalidClient           = errors.New("oidc: invalid client")
	ErrUnauthorizedClient      = errors.New("oidc: client not authorized for this grant")
	ErrInvalidRedirectURI      = errors.New("oidc: redirect_uri not registered")
	ErrInvalidScope            = errors.New("oidc: requested scope not allowed")
	ErrInvalidGrant            = errors.New("oidc: invalid or expired grant")
	ErrPKCERequired            = errors.New("oidc: pkce is required for this client")
	ErrPKCEFailed              = errors.New("oidc: code_verifier does not match code_challenge")
	ErrUnsupportedGrantType    = errors.New("oidc: unsupported grant_type")
	ErrUnsupportedResponseType = errors.New("oidc: unsupported response_type")
	ErrInvalidToken            = errors.New("oidc: invalid token")
)

// AuthRequest carries the parsed, raw authorization request parameters
type AuthRequest struct {
	ClientID      string
	RedirectURI   string
	ResponseType  string
	Scopes        []string
	State         string
	Nonce         string
	PKCEChallenge string
	PKCEMethod    string
	Prompt        string // "none" | "login" | "consent" | ""
}

type AuthorizeParams struct {
	AuthRequest
	UserID    pgtype.UUID
	SessionID pgtype.UUID
	AuthTime  time.Time
	ACR       string
	AMR       []string
}

type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64 // seconds
	IDToken      string
	RefreshToken string
	Scope        string
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// OIDC protocol engine
type Service struct {
	store   *postgres.Store
	keys    *crypto.KeyManager
	baseURL string
}

func New(store *postgres.Store, keys *crypto.KeyManager, baseURL string) *Service {
	return &Service{store: store, keys: keys, baseURL: baseURL}
}

// ValidateAuthRequest validates the incoming authorization request and
// returns the matching client, call before showing the consent screen
func (s *Service) ValidateAuthRequest(ctx context.Context, req AuthRequest) (*postgres.OIDCClient, error) {
	if req.ResponseType != "code" {
		return nil, fmt.Errorf("%w: only response_type=code is supported", ErrUnsupportedResponseType)
	}

	client, err := s.store.GetOIDCClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}

	// redirect URI must be registered exactly
	if err := s.store.ValidateRedirectURI(ctx, req.ClientID, req.RedirectURI); err != nil {
		return nil, ErrInvalidRedirectURI
	}

	// authorization_code must be in allowed grant types
	if !contains(client.AllowedGrantTypes, "authorization_code") {
		return nil, ErrUnauthorizedClient
	}

	// PKCE is required for public clients and for clients with require_pkce
	if (client.IsPublic || client.RequirePKCE) && req.PKCEChallenge == "" {
		return nil, ErrPKCERequired
	}
	if req.PKCEChallenge != "" && req.PKCEMethod != "S256" {
		return nil, fmt.Errorf("%w: only S256 is supported", ErrPKCERequired)
	}

	// openid scope is required for OIDC, at minimum one scope must be allowed
	if !s.scopesAllowed(client, req.Scopes) {
		return nil, ErrInvalidScope
	}

	return client, nil
}

// Authorize short lived authorization code for a validated request
func (s *Service) Authorize(ctx context.Context, p AuthorizeParams) (string, error) {
	tok, err := crypto.RandomToken(32)
	if err != nil {
		return "", err
	}
	id := "code_" + tok

	var nonce *string
	if p.Nonce != "" {
		nonce = &p.Nonce
	}
	var challenge *string
	if p.PKCEChallenge != "" {
		challenge = &p.PKCEChallenge
	}

	acr := p.ACR
	if acr == "" {
		acr = "0"
	}
	amr := p.AMR
	if len(amr) == 0 {
		amr = []string{"pwd"}
	}

	if err := s.store.CreateOIDCAuthCode(ctx, postgres.CreateOIDCAuthCodeParams{
		ID:            id,
		ClientID:      p.ClientID,
		UserID:        p.UserID,
		SessionID:     p.SessionID,
		RedirectURI:   p.RedirectURI,
		Scopes:        p.Scopes,
		Nonce:         nonce,
		PKCEChallenge: challenge,
		ACR:           acr,
		AMR:           amr,
		AuthTime:      p.AuthTime,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}); err != nil {
		return "", fmt.Errorf("create auth code: %w", err)
	}
	return id, nil
}

// ExchangeCode redeems an authorization code for tokens
func (s *Service) ExchangeCode(
	ctx context.Context,
	clientID, clientSecret,
	code, redirectURI, codeVerifier string,
) (*TokenResponse, error) {

	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	authCode, err := s.store.ConsumeOIDCAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}

	if authCode.ClientID != clientID {
		return nil, ErrInvalidGrant
	}
	if authCode.RedirectURI != redirectURI {
		return nil, ErrInvalidGrant
	}

	// PKCE verification
	if authCode.PKCEChallenge != nil {
		if !crypto.VerifyPKCE(codeVerifier, *authCode.PKCEChallenge) {
			return nil, ErrPKCEFailed
		}
	} else if client.RequirePKCE || client.IsPublic {
		return nil, ErrPKCERequired
	}

	user, err := s.store.GetUserByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}

	return s.issueTokens(ctx, client, user, &authCode.SessionID, authCode)
}

// RefreshTokens issues a new token set from a valid refresh token
// the old refresh token is rotated (consumed), a new one is returned
func (s *Service) RefreshTokens(
	ctx context.Context,
	clientID, clientSecret, refreshTokenID string,
	scopes []string, // if nil, keep original scopes (can only narrow, never expand)
) (*TokenResponse, error) {

	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if !contains(client.AllowedGrantTypes, "refresh_token") {
		return nil, ErrUnsupportedGrantType
	}

	rt, err := s.store.GetOIDCRefreshToken(ctx, refreshTokenID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}
	if rt.ClientID != clientID {
		return nil, ErrInvalidGrant
	}

	// scope downgrade only, can't request scopes not in original grant
	grantedScopes := rt.Scopes
	if len(scopes) > 0 {
		for _, sc := range scopes {
			if !contains(grantedScopes, sc) {
				return nil, ErrInvalidScope
			}
		}
		grantedScopes = scopes
	}

	user, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}

	// rotate the refresh token
	if err := s.store.RotateOIDCRefreshToken(ctx, rt.ID); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	// build a minimal synthetic auth code so issueTokensWithRotation can
	// read scopes, AMR, ACR, and AuthTime, The SessionID field is not read
	// from this struct, the real session id is passed separately as rt.SessionID
	synth := &postgres.OIDCAuthCode{
		ClientID: clientID,
		UserID:   rt.UserID,
		// SessionID intentionally zero, unused
		// real value passed separately below
		Scopes:   grantedScopes,
		ACR:      "0",
		AMR:      []string{"pwd"},
		AuthTime: rt.CreatedAt,
	}

	resp, err := s.issueTokensWithRotation(ctx, client, user, rt.SessionID, synth, &rt.ID)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ClientCredentials issues an access token for M2M flows (no user, no id_token)
func (s *Service) ClientCredentials(
	ctx context.Context,
	clientID, clientSecret string,
	scopes []string,
) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if client.IsPublic {
		return nil, fmt.Errorf("%w: public clients may not use client_credentials", ErrUnauthorizedClient)
	}
	if !contains(client.AllowedGrantTypes, "client_credentials") {
		return nil, ErrUnsupportedGrantType
	}
	if !s.scopesAllowed(client, scopes) {
		return nil, ErrInvalidScope
	}

	atID := "at_" + mustRandom()
	expiresAt := time.Now().Add(client.AccessTokenTTL)

	if err := s.store.CreateOIDCAccessToken(ctx, postgres.CreateOIDCAccessTokenParams{
		ID:        atID,
		ClientID:  clientID,
		UserID:    nil,
		SessionID: nil,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: atID,
		TokenType:   "Bearer",
		ExpiresIn:   int64(client.AccessTokenTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// Introspect implements RFC 7662, returns an active=false response
// (not an error) for invalid or expired tokens
func (s *Service) Introspect(ctx context.Context, token, tokenTypeHint string) (*IntrospectResponse, error) {
	inactive := &IntrospectResponse{Active: false}

	// try access token first (or per hint)
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		at, err := s.store.GetOIDCAccessTokenAny(ctx, token)
		if err == nil {
			if at.RevokedAt != nil || at.ExpiresAt.Before(time.Now()) {
				return inactive, nil
			}
			resp := &IntrospectResponse{
				Active:    true,
				ClientID:  at.ClientID,
				Scope:     strings.Join(at.Scopes, " "),
				Exp:       at.ExpiresAt.Unix(),
				Iat:       at.CreatedAt.Unix(),
				TokenType: "Bearer",
			}
			if at.UserID != nil && at.UserID.Valid {
				if u, err := s.store.GetUserByID(ctx, *at.UserID); err == nil {
					resp.Sub = uuidString(u.ID)
					if u.Email != nil {
						resp.Username = *u.Email
					}
				}
			}
			return resp, nil
		}
	}

	// try refresh token
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		rt, err := s.store.GetOIDCRefreshToken(ctx, token)
		if err == nil {
			return &IntrospectResponse{
				Active:    true,
				ClientID:  rt.ClientID,
				Scope:     strings.Join(rt.Scopes, " "),
				Sub:       uuidString(rt.UserID),
				Exp:       rt.ExpiresAt.Unix(),
				Iat:       rt.CreatedAt.Unix(),
				TokenType: "refresh_token",
			}, nil
		}
	}

	return inactive, nil
}

// revoke implements, silently succeeds for unknown tokens
func (s *Service) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	// Try access token.
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		if err := s.store.RevokeOIDCAccessToken(ctx, token); err == nil {
			return nil
		}
	}
	// try refresh token
	if err := s.store.RevokeOIDCRefreshToken(ctx, token); err == nil {
		return nil
	}
	return nil
}

// UserInfo validates the Bearer token and returns the authorized claims
func (s *Service) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	at, err := s.store.GetOIDCAccessToken(ctx, accessToken)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if at.UserID == nil || !at.UserID.Valid {
		// client_credentials token, no user claims
		return nil, ErrInvalidToken
	}

	user, err := s.store.GetUserByID(ctx, *at.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}

	return s.buildUserClaims(user, at.Scopes), nil
}

// issueTokens is the canonical token-minting path for authorization_code
func (s *Service) issueTokens(
	ctx context.Context,
	client *postgres.OIDCClient,
	user *postgres.User,
	sessionID *pgtype.UUID,
	code *postgres.OIDCAuthCode,
) (*TokenResponse, error) {
	return s.issueTokensWithRotation(ctx, client, user, sessionID, code, nil)
}

func (s *Service) issueTokensWithRotation(
	ctx context.Context,
	client *postgres.OIDCClient,
	user *postgres.User,
	sessionID *pgtype.UUID,
	code *postgres.OIDCAuthCode,
	previousRTID *string, // non-nil when rotating
) (*TokenResponse, error) {

	now := time.Now()
	atExpiry := now.Add(client.AccessTokenTTL)

	// access token
	atID := "at_" + mustRandom()
	if err := s.store.CreateOIDCAccessToken(ctx, postgres.CreateOIDCAccessTokenParams{
		ID:        atID,
		ClientID:  client.ID,
		UserID:    &user.ID,
		SessionID: sessionID,
		Scopes:    code.Scopes,
		ExpiresAt: atExpiry,
	}); err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	// refresh token (if offline_access in scope)
	var rtID string
	if contains(code.Scopes, "offline_access") && contains(client.AllowedGrantTypes, "refresh_token") {
		rtID = "rt_" + mustRandom()
		if err := s.store.CreateOIDCRefreshToken(ctx, postgres.CreateOIDCRefreshTokenParams{
			ID:         rtID,
			ClientID:   client.ID,
			UserID:     user.ID,
			SessionID:  sessionID,
			Scopes:     code.Scopes,
			PreviousID: previousRTID,
			ExpiresAt:  now.Add(client.RefreshTokenTTL),
		}); err != nil {
			return nil, fmt.Errorf("create refresh token: %w", err)
		}
	}

	// id_token (only when openid scope present)
	var idToken string
	if contains(code.Scopes, "openid") {
		var err error
		idToken, err = s.mintIDToken(client, user, code, atID, now)
		if err != nil {
			return nil, fmt.Errorf("mint id_token: %w", err)
		}
	}

	return &TokenResponse{
		AccessToken:  atID,
		TokenType:    "Bearer",
		ExpiresIn:    int64(client.AccessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: rtID,
		Scope:        strings.Join(code.Scopes, " "),
	}, nil
}

// mintIDToken builds and signs the OIDC id_token JWT
func (s *Service) mintIDToken(
	client *postgres.OIDCClient,
	user *postgres.User,
	code *postgres.OIDCAuthCode,
	accessTokenID string,
	now time.Time,
) (string, error) {

	claims := jwt.MapClaims{
		// required OIDC Core claims
		"iss":       s.baseURL,
		"sub":       uuidString(user.ID),
		"aud":       client.ID,
		"exp":       now.Add(client.IDTokenTTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": code.AuthTime.Unix(),
		"acr":       code.ACR,
		"amr":       code.AMR,
		// at_hash, required when access token is issued with id_token
		"at_hash": crypto.ATHash(accessTokenID),
	}

	// nonce, must be echoed if provided in the original auth request
	if code.Nonce != nil && *code.Nonce != "" {
		claims["nonce"] = *code.Nonce
	}

	// Scope-gated claims
	if contains(code.Scopes, "email") && user.Email != nil {
		claims["email"] = *user.Email
		claims["email_verified"] = user.EmailVerifiedAt != nil
	}
	if contains(code.Scopes, "profile") {
		if user.DisplayName != nil {
			claims["name"] = *user.DisplayName
		}
		if user.Username != nil {
			claims["preferred_username"] = *user.Username
		} else if user.Email != nil {
			claims["preferred_username"] = *user.Email
		}
	}

	return s.keys.Sign(claims)
}

// buildUserClaims assembles the UserInfo response payload
func (s *Service) buildUserClaims(user *postgres.User, scopes []string) map[string]any {
	m := map[string]any{
		"sub": uuidString(user.ID),
	}
	if contains(scopes, "email") && user.Email != nil {
		m["email"] = *user.Email
		m["email_verified"] = user.EmailVerifiedAt != nil
	}
	if contains(scopes, "profile") {
		if user.DisplayName != nil {
			m["name"] = *user.DisplayName
		}
		if user.Username != nil {
			m["preferred_username"] = *user.Username
		} else if user.Email != nil {
			m["preferred_username"] = *user.Email
		}
		m["updated_at"] = user.UpdatedAt.Unix()
	}
	return m
}

// authenticateClient verifies client credentials, public clients are
// identified by client_id alone, confidential clients require the secret
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*postgres.OIDCClient, error) {
	client, err := s.store.GetOIDCClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}

	if !client.IsPublic {
		if client.SecretHash == nil {
			return nil, ErrInvalidClient
		}
		ok, err := crypto.VerifyPassword(clientSecret, *client.SecretHash)
		if err != nil || !ok {
			slog.Warn("oidc: invalid client secret", "client_id", clientID)
			return nil, ErrInvalidClient
		}
	}

	return client, nil
}

func (s *Service) scopesAllowed(client *postgres.OIDCClient, scopes []string) bool {
	for _, sc := range scopes {
		if !contains(client.AllowedScopes, sc) {
			return false
		}
	}
	return true
}

// IntrospectAuth authenticates the party calling the introspect or revoke endpoint
// any valid client may introspect, not just the token owner
func (s *Service) IntrospectAuth(ctx context.Context, clientID, clientSecret string) (*postgres.OIDCClient, error) {
	return s.authenticateClient(ctx, clientID, clientSecret)
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func mustRandom() string {
	t, err := crypto.RandomToken(32)
	if err != nil {
		panic(err)
	}
	return t
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	const hx = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, by := range b {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hx[by>>4]
		out[pos+1] = hx[by&0x0f]
		pos += 2
	}
	return string(out)
}
