package mfa

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// Sentinel errors

var (
	// ErrInvalidCode is returned for any verification failure — TOTP,
	// backup code, or WebAuthn assertion. The caller must not leak which
	// one failed; users must not be able to distinguish enrolled methods.
	ErrInvalidCode = errors.New("mfa: invalid code")

	// ErrNoMethods means the user has no enrolled methods of the type
	// requested — e.g. trying to verify a TOTP for a webauthn-only user.
	ErrNoMethods = errors.New("mfa: user has no eligible methods")

	// ErrWebAuthnDisabled means the server didn't configure a WebAuthn
	// relying-party (typically because BASE_URL is unreachable).
	ErrWebAuthnDisabled = errors.New("mfa: webauthn is not configured")
)

// Service is the MFA orchestrator. It owns the store, signer (for
// challenge + WebAuthn-session cookies), the TOTP issuer string, and
// an optional WebAuthn relying-party instance.
type Service struct {
	store      *postgres.Store
	signer     *crypto.CookieSigner
	totpIssuer string
	webauthn   *wa.WebAuthn // nil when WebAuthn is disabled
}

// Config is the constructor input. WebAuthnRPID and WebAuthnRPOrigins
// are optional — if either is empty the WebAuthn ceremonies will return
// ErrWebAuthnDisabled.
type Config struct {
	Store      *postgres.Store
	Signer     *crypto.CookieSigner
	TOTPIssuer string

	// WebAuthn relying-party configuration. RPID is typically the
	// effective domain of BASE_URL (e.g. "auth.example.com" — no scheme,
	// no port). Origins is the list of allowed browser origins.
	WebAuthnRPID    string
	WebAuthnRPName  string
	WebAuthnOrigins []string
}

// New constructs a Service.
func New(c Config) (*Service, error) {
	if c.Store == nil || c.Signer == nil {
		return nil, errors.New("mfa: store and signer are required")
	}
	issuer := c.TOTPIssuer
	if issuer == "" {
		issuer = "IAM"
	}

	s := &Service{
		store:      c.Store,
		signer:     c.Signer,
		totpIssuer: issuer,
	}

	// WebAuthn is only enabled when both RPID and at least one origin
	// are set. RPID must be a registrable domain — we accept it as-is
	// and let the library reject invalid values.
	if c.WebAuthnRPID != "" && len(c.WebAuthnOrigins) > 0 {
		rpName := c.WebAuthnRPName
		if rpName == "" {
			rpName = issuer
		}
		web, err := wa.New(&wa.Config{
			RPID:          c.WebAuthnRPID,
			RPDisplayName: rpName,
			RPOrigins:     c.WebAuthnOrigins,
		})
		if err != nil {
			return nil, fmt.Errorf("init webauthn: %w", err)
		}
		s.webauthn = web
	}

	return s, nil
}

// WebAuthnEnabled reports whether the server can serve WebAuthn ceremonies.
// Used by templates and handlers to gate the relevant UI.
func (s *Service) WebAuthnEnabled() bool { return s.webauthn != nil }

// Status / enforcement

// UserMFAStatus is the rolled-up MFA picture for a user — drives the
// login redirect decision and the management UI.
type UserMFAStatus struct {
	// MethodTypes is the set of confirmed method types, ordered. Empty
	// → no MFA enrolled → password login is sufficient.
	MethodTypes []string

	// HasBackupCodes is true when the user has at least one unused code.
	HasBackupCodes bool

	// Required is true when MFA must be satisfied for this user. In P4
	// we mirror the simple "if enrolled, required" policy from the
	// project guidelines; per-client acr_values policy is a P8 item.
	Required bool
}

// StatusForUser builds a UserMFAStatus from the store.
func (s *Service) StatusForUser(ctx context.Context, userID pgtype.UUID) (*UserMFAStatus, error) {
	methods, err := s.store.ListConfirmedMFAMethods(ctx, userID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, 2)
	types := make([]string, 0, 2)
	for _, m := range methods {
		if !seen[m.Method] {
			seen[m.Method] = true
			types = append(types, m.Method)
		}
	}

	backups, err := s.store.CountUnusedBackupCodes(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserMFAStatus{
		MethodTypes:    types,
		HasBackupCodes: backups > 0,
		Required:       len(methods) > 0,
	}, nil
}

// URL derivation helpers

// DeriveWebAuthnConfig extracts the RPID and an origin list from a
// BASE_URL. Convenience for main.go so it doesn't reimplement the same
// URL parsing twice.
//
//	BASE_URL=https://auth.example.com:8080
//	→ RPID="auth.example.com", Origins=["https://auth.example.com:8080"]
//
// Returns empty strings if BASE_URL is unparseable, which disables
// WebAuthn cleanly.
func DeriveWebAuthnConfig(baseURL string) (rpID string, origins []string) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", nil
	}
	return u.Hostname(), []string{u.Scheme + "://" + u.Host}
}
