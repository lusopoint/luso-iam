package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const casServiceColumns = `
	id, name, service_url_pattern, match_pattern, description,
	released_attributes, enabled,
	created_at, updated_at, deleted_at
`

// FindCASServiceForURL returns the enabled, non-deleted service whose
// match_pattern matches the given URL via SQL LIKE. Returns ErrNotFound
// if no service matches.
//
// We order by length of the pattern descending so the most specific
// registration wins when several patterns overlap.
func (s *Store) FindCASServiceForURL(ctx context.Context, serviceURL string) (*CASService, error) {
	q := `SELECT ` + casServiceColumns + ` FROM cas_services
	      WHERE deleted_at IS NULL
	        AND enabled
	        AND $1 LIKE match_pattern
	      ORDER BY length(match_pattern) DESC
	      LIMIT 1`
	rows, err := s.pool.Query(ctx, q, serviceURL)
	if err != nil {
		return nil, fmt.Errorf("query cas_services: %w", err)
	}
	svc, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[CASService])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan cas_service: %w", err)
	}
	return &svc, nil
}

// CreateCASServiceParams is the input to CreateCASService.
type CreateCASServiceParams struct {
	Name               string
	ServiceURLPattern  string
	MatchPattern       string // SQL LIKE pattern derived from ServiceURLPattern
	Description        *string
	ReleasedAttributes []string
}

// CreateCASService registers a new CAS service.
func (s *Store) CreateCASService(ctx context.Context, p CreateCASServiceParams) (*CASService, error) {
	q := `INSERT INTO cas_services
	          (name, service_url_pattern, match_pattern, description, released_attributes)
	      VALUES ($1, $2, $3, $4, $5)
	      RETURNING ` + casServiceColumns
	rows, err := s.pool.Query(ctx, q,
		p.Name, p.ServiceURLPattern, p.MatchPattern,
		p.Description, p.ReleasedAttributes)
	if err != nil {
		return nil, fmt.Errorf("insert cas_service: %w", err)
	}
	svc, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[CASService])
	if err != nil {
		return nil, fmt.Errorf("scan inserted cas_service: %w", err)
	}
	return &svc, nil
}

// Tickets
// CreateCASTicketParams is the input to CreateCASTicket.
type CreateCASTicketParams struct {
	ID         string // caller-provided ticket value, e.g. "ST-<hex>"
	SessionID  pgtype.UUID
	ServiceURL string
	ExpiresAt  time.Time
	Renew      bool
}

// CreateCASTicket inserts a service ticket.
func (s *Store) CreateCASTicket(ctx context.Context, p CreateCASTicketParams) error {
	q := `INSERT INTO cas_tickets (id, session_id, service_url, expires_at, renew)
	      VALUES ($1, $2, $3, $4, $5)`
	_, err := s.pool.Exec(ctx, q, p.ID, p.SessionID, p.ServiceURL, p.ExpiresAt, p.Renew)
	if err != nil {
		return fmt.Errorf("insert cas_ticket: %w", err)
	}
	return nil
}

// ConsumeCASTicket atomically marks the ticket as consumed and returns
// it. Returns ErrNotFound if the ticket doesn't exist, has already been
// consumed, or has expired.
//
// This is the only correct way to validate a service ticket — a
// SELECT-then-UPDATE would race under concurrent validation.
func (s *Store) ConsumeCASTicket(ctx context.Context, id string) (*CASTicket, error) {
	q := `UPDATE cas_tickets
	      SET consumed_at = now()
	      WHERE id = $1
	        AND consumed_at IS NULL
	        AND expires_at > now()
	      RETURNING id, session_id, service_url, expires_at, consumed_at, renew, created_at`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("consume cas_ticket: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[CASTicket])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan cas_ticket: %w", err)
	}
	return &t, nil
}

// DeleteExpiredCASTickets removes old ticket rows. Intended for a
// periodic cleanup goroutine; not invoked on the request hot path.
func (s *Store) DeleteExpiredCASTickets(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM cas_tickets WHERE expires_at < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
