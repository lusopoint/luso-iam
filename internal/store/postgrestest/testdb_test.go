package postgrestest

import (
	"context"
	"testing"
)

// TestNew_MigratesAndConnects is a smoke test for the helper itself: the
// database is created/reused, migrations apply cleanly, and the pool can
// query.
func TestNew_MigratesAndConnects(t *testing.T) {
	store := New(t, "iam_test_postgrestest_selftest")

	var one int
	if err := store.Pool().QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query after migrate: %v", err)
	}
	if one != 1 {
		t.Fatalf("got %d, want 1", one)
	}
}
