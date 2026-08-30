package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lusopoint/lusoiam/internal/config"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// command audit-prune drops audit_log partitions older than a given month
// this is the retention mechanism for audit_log, and it exists as a separate
// manually-run command deliberately: the running server
// process never gets a code path that can delete audit data itself
// (see internal/store/migrations/0007_admin_audit.up.sql) so that
// compromising the server can't also be used to erase its own audit trail
// dropping a partition removes an entire month's rows in milliseconds; there is no undo
//
// Usage:
//
//	DATABASE_URL=postgres://... /audit-prune -before 2025-01
//	DATABASE_URL=postgres://... /audit-prune -before 2025-01 -dry-run

// partitionName matches the audit_log_YYYY_MM naming EnsureAuditLogPartitions
// uses. Anything else under audit_log (chiefly audit_log_default) is left alone.
var partitionName = regexp.MustCompile(`^audit_log_(\d{4})_(\d{2})$`)

func main() {
	before := flag.String("before", "", "drop partitions strictly before this month, format YYYY-MM (required)")
	dryRun := flag.Bool("dry-run", false, "list what would be dropped without dropping anything")
	flag.Parse()

	if err := run(*before, *dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "audit-prune: %v\n", err)
		os.Exit(1)
	}
}

func run(before string, dryRun bool) error {
	if before == "" {
		return errors.New("-before is required, e.g. -before 2025-01")
	}
	cutoff, err := time.Parse("2006-01", before)
	if err != nil {
		return fmt.Errorf("-before must be YYYY-MM: %w", err)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.Connect(ctx, config.DBConfig{URL: dbURL, MaxConns: 2, MinConns: 1})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
		JOIN pg_class child  ON pg_inherits.inhrelid  = child.oid
		WHERE parent.relname = 'audit_log'
		ORDER BY child.relname`)
	if err != nil {
		return fmt.Errorf("list partitions: %w", err)
	}

	var toDrop []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan partition name: %w", err)
		}
		m := partitionName.FindStringSubmatch(name)
		if m == nil {
			// audit_log_default, or anything not matching our naming scheme, is never touched
			continue
		}
		year, _ := strconv.Atoi(m[1])
		month, _ := strconv.Atoi(m[2])
		partitionMonth := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
		if partitionMonth.Before(cutoff) {
			toDrop = append(toDrop, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate partitions: %w", err)
	}

	if len(toDrop) == 0 {
		fmt.Println("nothing to prune: no partitions strictly before", before)
		return nil
	}

	for _, name := range toDrop {
		if dryRun {
			fmt.Println("would drop:", name)
			continue
		}
		if _, err := pool.Exec(ctx, "DROP TABLE "+pgx.Identifier{name}.Sanitize()); err != nil {
			return fmt.Errorf("drop %s: %w", name, err)
		}
		fmt.Println("dropped:", name)
	}
	return nil
}
