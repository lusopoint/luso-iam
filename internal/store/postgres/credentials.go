package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const credentialColumns = `
	user_id, password_hash, password_changed_at, must_change,
	failed_attempts, locked_until, created_at, updated_at
`

// GetCredential returns the credential row for userID, or ErrNotFound
func (s *Store) GetCredential(ctx context.Context, userID pgtype.UUID) (*Credential, error) {
	q := `SELECT ` + credentialColumns + ` FROM user_credentials WHERE user_id = $1`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("query credential: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Credential])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan credential: %w", err)
	}
	return &c, nil
}

// UpsertCredential creates or replaces the password hash for the given user
// resets failed_attempts and locked_until
func (s *Store) UpsertCredential(ctx context.Context, userID pgtype.UUID, passwordHash string) error {
	q := `INSERT INTO user_credentials (user_id, password_hash)
	      VALUES ($1, $2)
	      ON CONFLICT (user_id) DO UPDATE SET
	          password_hash = EXCLUDED.password_hash,
	          password_changed_at = now(),
	          failed_attempts = 0,
	          locked_until = NULL`
	if _, err := s.pool.Exec(ctx, q, userID, passwordHash); err != nil {
		return fmt.Errorf("upsert credential: %w", err)
	}
	return nil
}

// IncrementFailedAttempts atomically bumps the failure counter
func (s *Store) IncrementFailedAttempts(ctx context.Context, userID pgtype.UUID) (int32, error) {
	var n int32
	q := `UPDATE user_credentials
	      SET failed_attempts = failed_attempts + 1
	      WHERE user_id = $1
	      RETURNING failed_attempts`
	err := s.pool.QueryRow(ctx, q, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("increment failed_attempts: %w", err)
	}
	return n, nil
}

// ResetFailedAttempts zeroes the failure counter, call on successful login
func (s *Store) ResetFailedAttempts(ctx context.Context, userID pgtype.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_credentials SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1`,
		userID)
	if err != nil {
		return fmt.Errorf("reset failed_attempts: %w", err)
	}
	return nil
}

// SetLockout marks the account as locked until the given time
func (s *Store) SetLockout(ctx context.Context, userID pgtype.UUID, until time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_credentials SET locked_until = $2 WHERE user_id = $1`,
		userID, until)
	if err != nil {
		return fmt.Errorf("set lockout: %w", err)
	}
	return nil
}
