package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const sessionColumns = `
	id, user_id, expires_at, last_seen_at,
	ip_address::text, user_agent, created_at, revoked_at,
	acr, amr
`

// CreateSessionParams is the input to CreateSession
type CreateSessionParams struct {
	UserID    pgtype.UUID
	ExpiresAt time.Time
	IPAddress *string
	UserAgent *string
	// ACR / AMR carry the authentication context ACR="0" by default
	// the MFA service sets "1" once a second factor
	// succeeds, AMR may be empty, defaults to {} in the schema
	ACR string
	AMR []string
}

// CreateSession inserts a fresh session row and returns it
func (s *Store) CreateSession(ctx context.Context, p CreateSessionParams) (*Session, error) {
	acr := p.ACR
	if acr == "" {
		acr = "0"
	}
	amr := p.AMR
	if amr == nil {
		amr = []string{}
	}
	q := `INSERT INTO sessions (user_id, expires_at, ip_address, user_agent, acr, amr)
	      VALUES ($1, $2, $3::inet, $4, $5, $6)
	      RETURNING ` + sessionColumns
	rows, err := s.pool.Query(ctx, q,
		p.UserID, p.ExpiresAt, p.IPAddress, p.UserAgent, acr, amr)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}
	sess, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Session])
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return &sess, nil
}

// GetActiveSession returns the session if it exists, is not revoked and has not expired
func (s *Store) GetActiveSession(ctx context.Context, id pgtype.UUID) (*Session, error) {
	q := `SELECT ` + sessionColumns + ` FROM sessions
	      WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	sess, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Session])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return &sess, nil
}

func (s *Store) TouchSession(ctx context.Context, id pgtype.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, id)
	return err
}

// RevokeSession marks a session as revoked
func (s *Store) RevokeSession(ctx context.Context, id pgtype.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
		id)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}
