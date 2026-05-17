package postgres

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // pg driver
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/lusopoint/lusoiam/internal/store/migrations"
)

// Migrate applies any pending migrations against the given Postgres URL.
// It is safe to call repeatedly: if the database is already at the latest
// version, it returns nil.
//
// Migration files are embedded by the internal/store/migrations package
// (go:embed forbids '..' in patterns, which is why the FS lives there
// rather than in this file).
func Migrate(databaseURL string) error {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("init migrate: %w", err)
	}
	defer func() {
		// Errors here are pool teardown noise; surface only at debug.
		if srcErr, dbErr := m.Close(); srcErr != nil || dbErr != nil {
			slog.Debug("migrate close", "src_err", srcErr, "db_err", dbErr)
		}
	}()

	before, _, _ := m.Version()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}

	after, dirty, _ := m.Version()
	if dirty {
		return fmt.Errorf("migration state is dirty at version %d — manual intervention required", after)
	}

	if before == after {
		slog.Info("migrations: no change", "version", after)
	} else {
		slog.Info("migrations: applied", "from", before, "to", after)
	}
	return nil
}
