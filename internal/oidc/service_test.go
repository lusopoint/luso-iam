package oidc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
	"github.com/lusopoint/lusoiam/internal/store/postgrestest"
)

// sharedStore is provisioned once in TestMain and reused by every test in
// this file spinning up a fresh Postgres container per test would make
// this suite unbearably slow. Every test must therefore use unique
// fixture values (see clientParams/newTestUser below); none of them may
// assume the database starts empty.
var sharedStore *postgres.Store

func TestMain(m *testing.M) {
	store, cleanup, err := postgrestest.Start(context.Background(), "iam_test_oidc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "oidc: skipping integration tests, could not reach postgres (try `make compose-dev-up`): %v\n", err)
		os.Exit(0)
	}
	sharedStore = store
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// seq guarantees unique fixture identifiers across tests, even ones that
// run in the same nanosecond.
var seq int64

func uniqueName(prefix string) string {
	n := atomic.AddInt64(&seq, 1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	km, err := crypto.LoadOrGenerate("")
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return New(sharedStore, km, "https://auth.test")
}

func newTestUser(t *testing.T) *postgres.User {
	t.Helper()
	email := uniqueName("user") + "@example.com"
	name := "Test User"
	u, err := sharedStore.CreateUser(context.Background(), postgres.CreateUserParams{
		Email:       &email,
		DisplayName: &name,
	})
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return u
}

func newTestSession(t *testing.T, userID pgtype.UUID) *postgres.Session {
	t.Helper()
	sess, err := sharedStore.CreateSession(context.Background(), postgres.CreateSessionParams{
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
		ACR:       "1",
		AMR:       []string{"pwd", "otp"},
	})
	if err != nil {
		t.Fatalf("create test session: %v", err)
	}
	return sess
}

// clientOpts configures newTestClient; zero value is a confidential,
// non-PKCE-required client allowing every grant type and the openid/
// profile/email/offline_access scopes the common case most tests want.
type clientOpts struct {
	public         bool
	requirePKCE    bool
	requireConsent bool
	scopes         []string
	grantTypes     []string
	redirectURIs   []string
	accessTokenTTL time.Duration
}

func newTestClient(t *testing.T, opts clientOpts) (*postgres.OIDCClient, string) {
	t.Helper()

	scopes := opts.scopes
	if scopes == nil {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	grants := opts.grantTypes
	if grants == nil {
		grants = []string{"authorization_code", "refresh_token", "client_credentials"}
	}
	redirects := opts.redirectURIs
	if redirects == nil {
		redirects = []string{"https://app.example.com/callback"}
	}
	atTTL := opts.accessTokenTTL
	if atTTL == 0 {
		atTTL = time.Hour
	}

	const plainSecret = "s3cret-test-value"
	var secretHash *string
	if !opts.public {
		h, err := crypto.HashPassword(plainSecret)
		if err != nil {
			t.Fatalf("hash client secret: %v", err)
		}
		secretHash = &h
	}

	client, err := sharedStore.CreateOIDCClient(context.Background(), postgres.CreateOIDCClientParams{
		ID:                uniqueName("client"),
		SecretHash:        secretHash,
		Name:              "Test Client",
		RedirectURIs:      redirects,
		AllowedScopes:     scopes,
		AllowedGrantTypes: grants,
		IsPublic:          opts.public,
		RequirePKCE:       opts.requirePKCE,
		RequireConsent:    opts.requireConsent,
		AccessTokenTTL:    atTTL,
		RefreshTokenTTL:   30 * 24 * time.Hour,
		IDTokenTTL:        time.Hour,
	})
	if err != nil {
		t.Fatalf("create test client: %v", err)
	}
	return client, plainSecret
}

// --- ValidateAuthRequest -----------------------------------------------

func TestValidateAuthRequest_UnknownClient(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     "does-not-exist",
		ResponseType: "code",
	})
	if !errors.Is(err, ErrInvalidClient) {
		t.Errorf("got %v, want ErrInvalidClient", err)
	}
}

func TestValidateAuthRequest_UnsupportedResponseType(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     client.ID,
		ResponseType: "token", // implicit flow, disabled per project policy
	})
	if !errors.Is(err, ErrUnsupportedResponseType) {
		t.Errorf("got %v, want ErrUnsupportedResponseType", err)
	}
}

func TestValidateAuthRequest_RedirectURINotRegistered(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     client.ID,
		ResponseType: "code",
		RedirectURI:  "https://evil.example.com/callback",
		Scopes:       []string{"openid"},
	})
	if !errors.Is(err, ErrInvalidRedirectURI) {
		t.Errorf("got %v, want ErrInvalidRedirectURI", err)
	}
}

func TestValidateAuthRequest_PublicClientRequiresPKCE(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{public: true})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     client.ID,
		ResponseType: "code",
		RedirectURI:  client.RedirectURIs[0],
		Scopes:       []string{"openid"},
		// no PKCEChallenge
	})
	if !errors.Is(err, ErrPKCERequired) {
		t.Errorf("got %v, want ErrPKCERequired", err)
	}
}

func TestValidateAuthRequest_RejectsPlainPKCEMethod(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{public: true})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:      client.ID,
		ResponseType:  "code",
		RedirectURI:   client.RedirectURIs[0],
		Scopes:        []string{"openid"},
		PKCEChallenge: "somechallenge",
		PKCEMethod:    "plain", // disabled per project security policy, S256 only
	})
	if err == nil || !errors.Is(err, ErrPKCERequired) {
		t.Errorf("got %v, want an ErrPKCERequired-wrapped rejection of plain method", err)
	}
}

func TestValidateAuthRequest_ScopeNotAllowed(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{scopes: []string{"openid"}})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     client.ID,
		ResponseType: "code",
		RedirectURI:  client.RedirectURIs[0],
		Scopes:       []string{"openid", "admin"}, // "admin" not granted to this client
	})
	if !errors.Is(err, ErrInvalidScope) {
		t.Errorf("got %v, want ErrInvalidScope", err)
	}
}

func TestValidateAuthRequest_GrantTypeNotAllowed(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{grantTypes: []string{"client_credentials"}})
	_, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:     client.ID,
		ResponseType: "code",
		RedirectURI:  client.RedirectURIs[0],
		Scopes:       []string{"openid"},
	})
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Errorf("got %v, want ErrUnauthorizedClient", err)
	}
}

func TestValidateAuthRequest_HappyPath(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{public: true})
	_, challenge, err := crypto.NewPKCE()
	if err != nil {
		t.Fatalf("generate pkce: %v", err)
	}
	got, err := svc.ValidateAuthRequest(context.Background(), AuthRequest{
		ClientID:      client.ID,
		ResponseType:  "code",
		RedirectURI:   client.RedirectURIs[0],
		Scopes:        []string{"openid", "profile"},
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != client.ID {
		t.Errorf("got client %q, want %q", got.ID, client.ID)
	}
}

// --- Authorize + ExchangeCode --------------------------------------------

// issueCode drives ValidateAuthRequest + Authorize the way the HTTP layer
// does, returning the resulting code alongside the request/PKCE verifier
// used, so callers can exercise ExchangeCode against it.
func issueCode(t *testing.T, svc *Service, client *postgres.OIDCClient, user *postgres.User, sess *postgres.Session, extra func(*AuthRequest)) (code, verifier string) {
	t.Helper()
	var challenge string
	var err error
	verifier, challenge, err = crypto.NewPKCE()
	if err != nil {
		t.Fatalf("generate pkce: %v", err)
	}
	req := AuthRequest{
		ClientID:      client.ID,
		ResponseType:  "code",
		RedirectURI:   client.RedirectURIs[0],
		Scopes:        client.AllowedScopes,
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
	}
	if extra != nil {
		extra(&req)
	}
	if _, err := svc.ValidateAuthRequest(context.Background(), req); err != nil {
		t.Fatalf("ValidateAuthRequest: %v", err)
	}
	code, err = svc.Authorize(context.Background(), AuthorizeParams{
		AuthRequest: req,
		UserID:      user.ID,
		SessionID:   sess.ID,
		AuthTime:    sess.CreatedAt,
		ACR:         sess.ACR,
		AMR:         sess.AMR,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return code, verifier
}

func TestExchangeCode_HappyPath_IssuesAccessRefreshAndIDToken(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, nil)

	resp, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected a non-empty access token")
	}
	if resp.IDToken == "" {
		t.Error("expected a non-empty id_token (openid scope was granted)")
	}
	if resp.RefreshToken == "" {
		t.Error("expected a non-empty refresh token (offline_access scope was granted)")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
}

func TestExchangeCode_CannotBeRedeemedTwice(t *testing.T) {
	// The single most important property of the authorization_code grant:
	// a code is one-time-use. Replaying it (e.g. an attacker who
	// intercepted it after legitimate use) must fail.
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, nil)

	if _, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier); err != nil {
		t.Fatalf("first exchange: unexpected error: %v", err)
	}
	if _, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("replayed exchange: got %v, want ErrInvalidGrant", err)
	}
}

func TestExchangeCode_WrongClientRejected(t *testing.T) {
	// A code minted for client A must not be redeemable by client B, even
	// with a correct client B secret and the same redirect_uri.
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{})
	other, otherSecret := newTestClient(t, clientOpts{redirectURIs: client.RedirectURIs})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, nil)

	_, err := svc.ExchangeCode(context.Background(), other.ID, otherSecret, code, client.RedirectURIs[0], verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("got %v, want ErrInvalidGrant", err)
	}
}

func TestExchangeCode_MismatchedRedirectURIRejected(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{
		redirectURIs: []string{"https://app.example.com/callback", "https://app.example.com/other"},
	})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	var challenge string
	verifier, challenge, err := crypto.NewPKCE()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	req := AuthRequest{
		ClientID:      client.ID,
		ResponseType:  "code",
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        client.AllowedScopes,
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
	}
	if _, err := svc.ValidateAuthRequest(context.Background(), req); err != nil {
		t.Fatalf("ValidateAuthRequest: %v", err)
	}
	code, err := svc.Authorize(context.Background(), AuthorizeParams{
		AuthRequest: req, UserID: user.ID, SessionID: sess.ID, AuthTime: sess.CreatedAt,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// exchange using the OTHER registered redirect_uri: must fail, the
	// code is bound to the exact redirect_uri used at the authorize step
	_, err = svc.ExchangeCode(context.Background(), client.ID, secret, code, "https://app.example.com/other", verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("got %v, want ErrInvalidGrant", err)
	}
}

func TestExchangeCode_WrongPKCEVerifierRejected(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, _ := issueCode(t, svc, client, user, sess, nil)

	_, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], "wrong-verifier")
	if !errors.Is(err, ErrPKCEFailed) {
		t.Errorf("got %v, want ErrPKCEFailed", err)
	}
}

func TestExchangeCode_WrongClientSecretRejected(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, nil)

	_, err := svc.ExchangeCode(context.Background(), client.ID, "totally-wrong-secret", code, client.RedirectURIs[0], verifier)
	if !errors.Is(err, ErrInvalidClient) {
		t.Errorf("got %v, want ErrInvalidClient", err)
	}
}

func TestExchangeCode_UnknownCodeRejected(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})

	_, err := svc.ExchangeCode(context.Background(), client.ID, secret, "code_does-not-exist", client.RedirectURIs[0], "verifier")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("got %v, want ErrInvalidGrant", err)
	}
}

func TestExchangeCode_NoIDTokenWithoutOpenIDScope(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{scopes: []string{"profile", "email"}})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, func(r *AuthRequest) {
		r.Scopes = []string{"profile"} // no "openid"
	})

	resp, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.IDToken != "" {
		t.Error("expected no id_token when openid scope was not granted")
	}
}

func TestExchangeCode_NoRefreshTokenWithoutOfflineAccessScope(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, func(r *AuthRequest) {
		r.Scopes = []string{"openid"} // no "offline_access"
	})

	resp, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.RefreshToken != "" {
		t.Error("expected no refresh token when offline_access scope was not granted")
	}
}

// --- RefreshTokens --------------------------------------------------------

func TestRefreshTokens_RotationInvalidatesOldToken(t *testing.T) {
	// Refresh token theft detection depends entirely on this: once a
	// refresh token has been used, it must never work again.
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, nil)
	first, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	second, err := svc.RefreshTokens(context.Background(), client.ID, secret, first.RefreshToken, nil)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("expected a new, different refresh token, got %q", second.RefreshToken)
	}

	// replay the original (now-rotated) refresh token
	if _, err := svc.RefreshTokens(context.Background(), client.ID, secret, first.RefreshToken, nil); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("reused refresh token: got %v, want ErrInvalidGrant", err)
	}

	// the newly issued one must still work
	if _, err := svc.RefreshTokens(context.Background(), client.ID, secret, second.RefreshToken, nil); err != nil {
		t.Errorf("second refresh token should still be valid: %v", err)
	}
}

func TestRefreshTokens_CannotExpandScope(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	code, verifier := issueCode(t, svc, client, user, sess, func(r *AuthRequest) {
		r.Scopes = []string{"openid", "offline_access"} // no "profile" granted
	})
	tok, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	_, err = svc.RefreshTokens(context.Background(), client.ID, secret, tok.RefreshToken, []string{"profile"})
	if !errors.Is(err, ErrInvalidScope) {
		t.Errorf("got %v, want ErrInvalidScope for a scope-expansion attempt", err)
	}
}

// --- ClientCredentials -----------------------------------------------------

func TestClientCredentials_PublicClientRejected(t *testing.T) {
	svc := newTestService(t)
	client, _ := newTestClient(t, clientOpts{public: true, grantTypes: []string{"client_credentials"}})

	_, err := svc.ClientCredentials(context.Background(), client.ID, "", client.AllowedScopes)
	if !errors.Is(err, ErrUnauthorizedClient) {
		t.Errorf("got %v, want ErrUnauthorizedClient", err)
	}
}

func TestClientCredentials_HappyPath(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{
		scopes:     []string{"api:read"},
		grantTypes: []string{"client_credentials"},
	})

	resp, err := svc.ClientCredentials(context.Background(), client.ID, secret, []string{"api:read"})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected a non-empty access token")
	}
	if resp.IDToken != "" {
		t.Error("client_credentials must never produce an id_token (no user)")
	}
}

// --- Introspect / Revoke / UserInfo ---------------------------------------

func TestIntrospect_UnknownTokenIsInactiveNotError(t *testing.T) {
	svc := newTestService(t)
	resp, err := svc.Introspect(context.Background(), "at_does-not-exist", "")
	if err != nil {
		t.Fatalf("Introspect must not error for unknown tokens (RFC 7662): %v", err)
	}
	if resp.Active {
		t.Error("expected Active=false for an unknown token")
	}
}

func TestIntrospect_ActiveAccessToken(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)
	code, verifier := issueCode(t, svc, client, user, sess, nil)
	tok, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tok.AccessToken, "access_token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected Active=true for a freshly issued token")
	}
	if resp.ClientID != client.ID {
		t.Errorf("client_id = %q, want %q", resp.ClientID, client.ID)
	}
}

func TestIntrospect_RevokedTokenIsInactive(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)
	code, verifier := issueCode(t, svc, client, user, sess, nil)
	tok, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	if err := svc.Revoke(context.Background(), tok.AccessToken, "access_token"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tok.AccessToken, "access_token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Active {
		t.Error("expected Active=false for a revoked token")
	}
}

func TestRevoke_UnknownTokenSilentlySucceeds(t *testing.T) {
	// RFC 7009: the authorization server responds with 200 even if the
	// token was already invalid, to avoid token-existence oracles.
	svc := newTestService(t)
	if err := svc.Revoke(context.Background(), "at_does-not-exist", ""); err != nil {
		t.Errorf("Revoke of an unknown token should not error, got %v", err)
	}
}

func TestUserInfo_ScopesGateClaims(t *testing.T) {
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{})
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)
	code, verifier := issueCode(t, svc, client, user, sess, func(r *AuthRequest) {
		r.Scopes = []string{"openid"} // no "email", no "profile"
	})
	tok, err := svc.ExchangeCode(context.Background(), client.ID, secret, code, client.RedirectURIs[0], verifier)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	claims, err := svc.UserInfo(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if claims["sub"] == "" || claims["sub"] == nil {
		t.Error("expected a non-empty sub claim")
	}
	if _, present := claims["email"]; present {
		t.Error("email claim must not be present without the email scope")
	}
	if _, present := claims["name"]; present {
		t.Error("name claim must not be present without the profile scope")
	}
}

func TestUserInfo_ClientCredentialsTokenRejected(t *testing.T) {
	// A machine-to-machine token has no associated user; UserInfo must
	// reject it rather than return empty/zero-value user claims.
	svc := newTestService(t)
	client, secret := newTestClient(t, clientOpts{
		scopes:     []string{"api:read"},
		grantTypes: []string{"client_credentials"},
	})
	tok, err := svc.ClientCredentials(context.Background(), client.ID, secret, []string{"api:read"})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}

	_, err = svc.UserInfo(context.Background(), tok.AccessToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("got %v, want ErrInvalidToken", err)
	}
}
