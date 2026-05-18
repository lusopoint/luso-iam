package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// audit_log
const auditLogColumns = `
	id, event_type, actor_id, target_id,
	metadata, ip_address, user_agent, created_at
`

// InsertAuditEventParams describes one event. Metadata must be valid JSON
// (typically a single-line marshalled map) — passing nil stores '{}'.
type InsertAuditEventParams struct {
	EventType string
	ActorID   *pgtype.UUID
	TargetID  *pgtype.UUID
	Metadata  []byte // JSON-encoded; nil/empty → '{}'
	IPAddress *string
	UserAgent *string
}

// InsertAuditEvent appends one event. The id and timestamp are server-side.
// Audit writes are best-effort — callers should log on failure but never
// abort the parent operation just because audit logging failed.
func (s *Store) InsertAuditEvent(ctx context.Context, p InsertAuditEventParams) error {
	meta := p.Metadata
	if len(meta) == 0 {
		meta = []byte(`{}`)
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log
		     (event_type, actor_id, target_id, metadata, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		p.EventType, p.ActorID, p.TargetID, meta, p.IPAddress, p.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListAuditEventsFilter narrows ListAuditEvents.
type ListAuditEventsFilter struct {
	// EventType filters to exact match (e.g. "login_success").
	EventType string
	// ActorID filters to events caused by this user.
	ActorID *pgtype.UUID
	// TargetID filters to events about this user.
	TargetID *pgtype.UUID
	// Since / Until is the inclusive time window. Zero values mean unbounded.
	Since time.Time
	Until time.Time
	// Limit / Offset for pagination. Limit capped at 500.
	Limit  int
	Offset int
}

// ListAuditEventsResult bundles the page + total matching count.
type ListAuditEventsResult struct {
	Events []AuditEvent
	Total  int
}

// ListAuditEvents returns a reverse-chronological page of events.
func (s *Store) ListAuditEvents(ctx context.Context, f ListAuditEventsFilter) (*ListAuditEventsResult, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where := []string{"1=1"}
	args := []any{}

	if f.EventType != "" {
		args = append(args, f.EventType)
		where = append(where, fmt.Sprintf("event_type = $%d", len(args)))
	}
	if f.ActorID != nil && f.ActorID.Valid {
		args = append(args, *f.ActorID)
		where = append(where, fmt.Sprintf("actor_id = $%d", len(args)))
	}
	if f.TargetID != nil && f.TargetID.Valid {
		args = append(args, *f.TargetID)
		where = append(where, fmt.Sprintf("target_id = $%d", len(args)))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !f.Until.IsZero() {
		args = append(args, f.Until)
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	whereSQL := strings.Join(where, " AND ")

	q := `SELECT ` + auditLogColumns + `, count(*) OVER () AS total_count
	      FROM audit_log
	      WHERE ` + whereSQL + `
	      ORDER BY created_at DESC
	      LIMIT $` + fmt.Sprint(len(args)+1) + `
	      OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	out := &ListAuditEventsResult{Events: make([]AuditEvent, 0, limit)}
	for rows.Next() {
		var e AuditEvent
		var total int
		if err := rows.Scan(
			&e.ID, &e.EventType, &e.ActorID, &e.TargetID,
			&e.Metadata, &e.IPAddress, &e.UserAgent, &e.CreatedAt,
			&total,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		out.Events = append(out.Events, e)
		out.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return out, nil
}
