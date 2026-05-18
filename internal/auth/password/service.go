// Package password is the authentication service for username + password
// credentials. It coordinates the user store, the credential store, and
// the argon2id verifier.
package password

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// Sentinel errors. Higher layers should not leak the distinction
// between InvalidCredentials and UserDisabled to end users; both map
// to a generic "login failed" message on the login page.
var (
	ErrInvalidCredentials = errors.New("password: invalid credentials")
	ErrUserDisabled       = errors.New("password: user disabled")
	ErrAccountLocked      = errors.New("password: account temporarily locked")
)

// Tuning constants. Could become config later if needed.
const (
	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute
)

// Service authenticates email + password combinations.
type Service struct {
	store *postgres.Store
}

// New returns a password auth service.
func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

// Authenticate returns the user iff email + password match a valid
// credential. The exact error returned indicates the failure mode but
// callers should usually not show the distinction to end users.
//
// On success: failure counter is reset and last_login_at is touched.
// On failure: failure counter is incremented; account may be locked.
func (s *Service) Authenticate(ctx context.Context, email, password string) (*postgres.User, error) {
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			// Run a dummy hash check to keep timing roughly constant
			// against email enumeration.
			_, _ = crypto.VerifyPassword(password, dummyHash)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.Status != "active" {
		return nil, ErrUserDisabled
	}

	cred, err := s.store.GetCredential(ctx, user.ID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			// User exists but has no password credential — could be
			// federated-only. Same surface error.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if cred.LockedUntil != nil && cred.LockedUntil.After(time.Now()) {
		return nil, ErrAccountLocked
	}

	ok, err := crypto.VerifyPassword(password, cred.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.recordFailure(ctx, user.ID)
		return nil, ErrInvalidCredentials
	}

	// Successful login — best-effort housekeeping; failures here are
	// logged but don't fail the login.
	if err := s.store.ResetFailedAttempts(ctx, user.ID); err != nil {
		slog.Warn("password: reset failed_attempts", "err", err)
	}
	if err := s.store.TouchUserLastLogin(ctx, user.ID); err != nil {
		slog.Warn("password: touch last_login_at", "err", err)
	}
	return user, nil
}

// recordFailure bumps the failure counter and, on threshold, sets a
// lockout window. Errors are logged but not returned — failure to
// record should not affect the user-visible login outcome.
func (s *Service) recordFailure(ctx context.Context, userID pgtype.UUID) {
	n, err := s.store.IncrementFailedAttempts(ctx, userID)
	if err != nil {
		slog.Warn("password: increment failed_attempts", "err", err)
		return
	}
	if n >= maxFailedAttempts {
		until := time.Now().Add(lockoutDuration)
		if err := s.store.SetLockout(ctx, userID, until); err != nil {
			slog.Warn("password: set lockout", "err", err)
		}
	}
}

// dummyHash equalizes timing between the not-found and wrong-password
// paths so an attacker can't distinguish registered emails by request
// timing. Generated once at init().
var dummyHash string

func init() {
	h, err := crypto.HashPassword("\x00not-a-real-password\x00")
	if err != nil {
		panic(err)
	}
	dummyHash = h
}
