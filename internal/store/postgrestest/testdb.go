// Package postgrestest connects integration tests to a real, migrated
// Postgres database rather than a mock.
//
// It does not manage its own Postgres process. It expects one to already
// be reachable locally that's `make compose-dev-up` (the same
// container used for `make dev-server`); in CI it's a service container
// (see .github/workflows/ga-test.yml). Each caller gets its own
// database, created on demand, on that shared server: this keeps
// packages whose tests run concurrently (`go test ./...` runs different
// packages' test binaries in parallel) from truncating each other's
// fixtures, and keeps tests from ever touching a developer's real "iam"
// dev data.
package postgrestest

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// defaultBase matches deployments/docker-compose.dev.yml exactly, so
// `make compose-dev-up` is all a developer needs before running these
// tests locally. Override the server/credentials with TEST_DATABASE_URL
// (any database name in it is ignored see dsnForDB).
const defaultBase = "postgres://iam:iam@localhost:5432?sslmode=disable"

func baseDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return defaultBase
}

// dsnForDB returns base with its database path replaced by dbName.
func dsnForDB(base, dbName string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", base, err)
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

// Start ensures database dbName exists on the configured Postgres server
// (creating it against the "postgres" maintenance database if needed),
// applies every migration, wipes any data left over from a previous test
// run, and returns a connected *postgres.Store plus a cleanup func that
// closes the pool.
//
// dbName should be specific to the calling package (e.g. "iam_test_oidc")
// so concurrently-running packages don't truncate each other's data.
//
// Requires a reachable Postgres server run `make compose-dev-up`
// locally; CI starts one as a service container.
func Start(ctx context.Context, dbName string) (*postgres.Store, func(), error) {
	base := baseDSN()

	if err := ensureDatabaseExists(ctx, base, dbName); err != nil {
		return nil, nil, err
	}

	target, err := dsnForDB(base, dbName)
	if err != nil {
		return nil, nil, err
	}
	if err := postgres.Migrate(target); err != nil {
		return nil, nil, fmt.Errorf("apply migrations to %q: %w", dbName, err)
	}

	pool, err := pgxpool.New(ctx, target)
	if err != nil {
		return nil, nil, fmt.Errorf("connect pool to %q: %w", dbName, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("ping %q: %w", dbName, err)
	}
	if err := truncateAll(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("reset %q: %w", dbName, err)
	}

	return postgres.NewStore(pool), pool.Close, nil
}

// New starts (or reuses) the integration test database dbName for a
// single test, closing its pool automatically via t.Cleanup. See Start
// for the dbName convention and the required environment.
//
// If no Postgres server is reachable, the test is skipped rather than
// failed running `go test ./...` on a machine without
// `make compose-dev-up` running still passes, minus these tests.
func New(t *testing.T, dbName string) *postgres.Store {
	t.Helper()

	store, cleanup, err := Start(context.Background(), dbName)
	if err != nil {
		t.Skipf("postgrestest: %v run `make compose-dev-up` first", err)
	}
	t.Cleanup(cleanup)
	return store
}

// ensureDatabaseExists connects to the "postgres" maintenance database on
// the same server as base and creates dbName if it doesn't already exist.
func ensureDatabaseExists(ctx context.Context, base, dbName string) error {
	adminDSN, err := dsnForDB(base, "postgres")
	if err != nil {
		return err
	}

	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("connect to admin database (is postgres running? try `make compose-dev-up`): %w", err)
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P04" { // duplicate_database
			return nil
		}
		return fmt.Errorf("create database %q: %w", dbName, err)
	}
	return nil
}

// truncateAll wipes every application table so each test run starts from
// a clean slate without needing a throwaway database per run.
// schema_migrations (golang-migrate's bookkeeping table) is left alone.
func truncateAll(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT tablename FROM pg_tables
		WHERE schemaname = 'public' AND tablename NOT IN ('schema_migrations')`)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, pgx.Identifier{name}.Sanitize())
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	_, err = pool.Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" CASCADE")
	return err
}
