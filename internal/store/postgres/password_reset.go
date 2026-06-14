package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// PasswordResetToken is the row shape for the password_reset_tokens table.
// token_hash is the only key — we never store the plaintext.
type PasswordResetToken struct {
	TokenHash string      `db:"token_hash"`
	UserID    pgtype.UUID `db:"user_id"`
	ExpiresAt time.Time   `db:"expires_at"`
	UsedAt    *time.Time  `db:"used_at"`
	CreatedAt time.Time   `db:"created_at"`
	RequestIP *string     `db:"request_ip"`
	UserAgent *string     `db:"user_agent"`
}

// CreatePasswordResetToken inserts a fresh token row. The hash MUST be
// already computed by the caller (we don't see the plaintext here).
// requestIP and userAgent are optional context for audit purposes.
func (s *Store) CreatePasswordResetToken(ctx context.Context, tokenHash string, userID pgtype.UUID, expiresAt time.Time, requestIP, userAgent string) error {
	var ip, ua any
	if requestIP != "" {
		ip = requestIP
	}
	if userAgent != "" {
		ua = userAgent
	}
	q := `INSERT INTO password_reset_tokens
	          (token_hash, user_id, expires_at, request_ip, user_agent)
	      VALUES ($1, $2, $3, $4, $5)`
	if _, err := s.pool.Exec(ctx, q, tokenHash, userID, expiresAt, ip, ua); err != nil {
		return fmt.Errorf("insert password_reset_token: %w", err)
	}
	return nil
}

// GetPasswordResetToken returns the row matching tokenHash, or
// ErrNotFound. The caller is responsible for checking ExpiresAt and
// UsedAt — we don't filter here, so the caller can emit precise
// audit reasons ("expired" vs "already used" vs "unknown").
func (s *Store) GetPasswordResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	q := `SELECT token_hash, user_id, expires_at, used_at, created_at, request_ip, user_agent
	      FROM password_reset_tokens WHERE token_hash = $1`
	rows, err := s.pool.Query(ctx, q, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("query password_reset_token: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[PasswordResetToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan password_reset_token: %w", err)
	}
	return &t, nil
}

// MarkPasswordResetTokenUsed sets used_at = NOW() so this token can't
// be used again. Idempotent — running it twice is safe; subsequent
// lookups still find the row, with used_at non-NULL.
func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, tokenHash string) error {
	q := `UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1`
	if _, err := s.pool.Exec(ctx, q, tokenHash); err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	return nil
}

// DeletePasswordResetTokensForUser removes ALL outstanding tokens for
// a user. Called when the user changes their password (any path —
// admin reset, self-reset, or future signup-confirm). Ensures a
// previously-emailed reset link can't be replayed after the user has
// already chosen a new password through a different mechanism.
func (s *Store) DeletePasswordResetTokensForUser(ctx context.Context, userID pgtype.UUID) error {
	q := `DELETE FROM password_reset_tokens WHERE user_id = $1`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("delete user password_reset_tokens: %w", err)
	}
	return nil
}
