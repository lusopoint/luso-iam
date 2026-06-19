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

var (
	// ErrInvalidCode is returned for any verification failure:
	// - TOTP, backup code, or WebAuthn assertion
	// we should not leak which one failed users must not be able to see the diff between enrolled methods
	ErrInvalidCode = errors.New("mfa: invalid code")

	// ErrNoMethods means the user has no enrolled methods of the type
	// requested, ex. trying to verify a TOTP for a webauthn-only user
	ErrNoMethods = errors.New("mfa: user has no eligible methods")

	// ErrWebAuthnDisabled means the server did not configure a WebAuthn
	// relying-party (typically because BASE_URL is unreachable)
	ErrWebAuthnDisabled = errors.New("mfa: webauthn is not configured")
)

// Service is the MFA system, it owns the store, signer
// (for challenge + WebAuthn-session cookies), the TOTP issuer string, and
// an optional WebAuthn relying-party instance
type Service struct {
	store      *postgres.Store
	signer     *crypto.CookieSigner
	totpIssuer string
	forceMFA   bool         // inforce mfa
	webauthn   *wa.WebAuthn // nil when WebAuthn is disabled
}

// Config is the constructor input, WebAuthnRPID and WebAuthnRPOrigins are optional
// if either is empty the WebAuthn ceremonies will return ErrWebAuthnDisabled
type Config struct {
	Store      *postgres.Store
	Signer     *crypto.CookieSigner
	TOTPIssuer string

	// ForceMFA, when true, marks every login as MFA required regardless
	// of whether the user has enrolled methods, users with no methods
	// get redirected to /mfa/enroll on login and cannot complete the
	// session until they enroll at least one
	ForceMFA bool

	// WebAuthn relying-party configuration. RPID is typically the
	// effective domain of BASE_URL (e.g. "auth.example.com", no scheme, no port)
	// origins is the list of allowed browser origins
	WebAuthnRPID    string
	WebAuthnRPName  string
	WebAuthnOrigins []string
}

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
		forceMFA:   c.ForceMFA,
	}

	// WebAuthn is only enabled when both RPID and at least one origin are set
	// RPID must be a registrable domain we accept it as-is and let the library reject invalid values
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

// WebAuthnEnabled reports whether the server can serve WebAuthn ceremonies
// used by templates and handlers to gate the relevant UI
func (s *Service) WebAuthnEnabled() bool { return s.webauthn != nil }

// UserMFAStatus is the rolled up MFA picture for a user drives the
// login redirect decision and the management UI
type UserMFAStatus struct {
	// MethodTypes is the set of confirmed method types, ordered
	MethodTypes []string

	// HasBackupCodes is true when the user has at least one unused code
	HasBackupCodes bool

	// Required is true when MFA must be satisfied for this login, true in two cases:
	// - the user has enrolled at least one method
	// - ForceMFA is enabled at the server level
	Required bool

	// EnrollmentRequired is true when MFA is Required but the user has
	// no enrolled methods, Only possible under ForceMFA: the user must
	// be sent to /mfa/enroll before they can complete login
	EnrollmentRequired bool
}

// StatusForUser builds a UserMFAStatus from the store
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

	return computeStatus(types, backups > 0, s.forceMFA), nil
}

// computeStatus rolls up the raw inputs (enrolled method types, whether
// backup codes exist, server wide force flag) into the policy status
// pulled out as a pure function so the policy is testable without a db
func computeStatus(methodTypes []string, hasBackup, forceMFA bool) *UserMFAStatus {
	enrolled := len(methodTypes) > 0
	required := enrolled || forceMFA
	return &UserMFAStatus{
		MethodTypes:        methodTypes,
		HasBackupCodes:     hasBackup,
		Required:           required,
		EnrollmentRequired: required && !enrolled,
	}
}

// DeriveWebAuthnConfig extracts the RPID and an origin list from a BASE_URL
// convenience for main.go so it doesn't reimplement the same URL parsing twice
//
//	BASE_URL=https://auth.example.com:8080
//	→ RPID="auth.example.com", Origins=["https://auth.example.com:8080"]
//
// returns empty strings if BASE_URL is unparseable, which disables WebAuthn cleanly
func DeriveWebAuthnConfig(baseURL string) (rpID string, origins []string) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return "", nil
	}
	return u.Hostname(), []string{u.Scheme + "://" + u.Host}
}
