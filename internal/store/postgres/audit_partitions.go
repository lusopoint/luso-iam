package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EnsureAuditLogPartitions creates the monthly partitions of audit_log
// covering `from`'s month through the following `months`-1 months, if they don't already exist
// it is safe to call repeatedly (at server startup, and again on every cleanup sweep)
// so a missed run is just caught by the next one, keeping inserts ahead of the DEFAULT partition under normal operation
func (s *Store) EnsureAuditLogPartitions(ctx context.Context, from time.Time, months int) error {
	from = from.UTC()
	monthStart := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < months; i++ {
		start := monthStart.AddDate(0, i, 0)
		end := start.AddDate(0, 1, 0)
		name := fmt.Sprintf("audit_log_%04d_%02d", start.Year(), start.Month())

		q := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF audit_log FOR VALUES FROM ('%s') TO ('%s')`,
			pgx.Identifier{name}.Sanitize(),
			start.Format("2006-01-02"),
			end.Format("2006-01-02"),
		)
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("ensure audit_log partition %s: %w", name, err)
		}
	}
	return nil
}
