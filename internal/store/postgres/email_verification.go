package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// EmailVerificationToken is the row shape for the
// email_verification_tokens table. token_hash is the only key — we
// never store the plaintext.
//
// Email is snapshotted at issue time so that an email-change
// race can't accidentally verify the wrong address.
type EmailVerificationToken struct {
	TokenHash string      `db:"token_hash"`
	UserID    pgtype.UUID `db:"user_id"`
	Email     string      `db:"email"`
	ExpiresAt time.Time   `db:"expires_at"`
	UsedAt    *time.Time  `db:"used_at"`
	CreatedAt time.Time   `db:"created_at"`
	RequestIP *string     `db:"request_ip"`
	UserAgent *string     `db:"user_agent"`
}

// CreateEmailVerificationToken inserts a fresh token row. The hash
// MUST be already computed by the caller (we don't see the plaintext
// here). requestIP and userAgent are optional context for audit.
//
// email is captured at issue time. If a user later changes their
// email address, in-flight tokens for the old address are still
// valid (verifying the OLD address) — which is the correct semantics
// for an "is this mailbox under your control" check. The signup
// service shouldn't change the user's email_verified_at when an
// old-email token is presented; it should check that the token's
// email still matches the user's current email.
func (s *Store) CreateEmailVerificationToken(ctx context.Context, tokenHash string, userID pgtype.UUID, email string, expiresAt time.Time, requestIP, userAgent string) error {
	var ip, ua any
	if requestIP != "" {
		ip = requestIP
	}
	if userAgent != "" {
		ua = userAgent
	}
	q := `INSERT INTO email_verification_tokens
	          (token_hash, user_id, email, expires_at, request_ip, user_agent)
	      VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := s.pool.Exec(ctx, q, tokenHash, userID, email, expiresAt, ip, ua); err != nil {
		return fmt.Errorf("insert email_verification_token: %w", err)
	}
	return nil
}

// GetEmailVerificationToken returns the row matching tokenHash, or
// ErrNotFound. The caller is responsible for checking ExpiresAt and
// UsedAt — we don't filter here so the caller can emit precise audit
// reasons ("expired" vs "already used" vs "unknown").
func (s *Store) GetEmailVerificationToken(ctx context.Context, tokenHash string) (*EmailVerificationToken, error) {
	q := `SELECT token_hash, user_id, email, expires_at, used_at, created_at, request_ip, user_agent
	      FROM email_verification_tokens WHERE token_hash = $1`
	rows, err := s.pool.Query(ctx, q, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("query email_verification_token: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[EmailVerificationToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan email_verification_token: %w", err)
	}
	return &t, nil
}

// MarkEmailVerificationTokenUsed sets used_at = NOW() so this token
// can't be used again. Idempotent.
func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, tokenHash string) error {
	q := `UPDATE email_verification_tokens SET used_at = NOW() WHERE token_hash = $1`
	if _, err := s.pool.Exec(ctx, q, tokenHash); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	return nil
}

// MarkUserEmailVerified sets the user's email_verified_at to NOW().
// Idempotent — calling on an already-verified user is a no-op (the
// timestamp is overwritten, which is fine; we don't care about the
// "first verification" timestamp specifically).
//
// Lives next to the verification-token plumbing rather than in users.go
// because it's part of the verification flow's contract; a generic
// "update arbitrary user fields" method already exists in admin.go,
// but a dedicated single-purpose method here makes the call site at
// the signup service much clearer.
func (s *Store) MarkUserEmailVerified(ctx context.Context, userID pgtype.UUID) error {
	q := `UPDATE users SET email_verified_at = NOW(), updated_at = NOW() WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("mark user email verified: %w", err)
	}
	return nil
}

// DeleteEmailVerificationTokensForUser removes ALL outstanding
// verification tokens for a user. Called after a successful
// verification, and could also be called on email change in the future.
func (s *Store) DeleteEmailVerificationTokensForUser(ctx context.Context, userID pgtype.UUID) error {
	q := `DELETE FROM email_verification_tokens WHERE user_id = $1`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("delete user verification tokens: %w", err)
	}
	return nil
}
