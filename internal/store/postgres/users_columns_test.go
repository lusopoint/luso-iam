package postgres

import (
	"strings"
	"testing"
)

// TestUserColumnsAs pins the contract of the alias prefixer. The query
// in GetUserByProviderSub depends on every column appearing both prefixed
// (so Postgres can disambiguate against user_identities) AND aliased
// back to its bare name (so pgx.RowToStructByNameLax can still match
// struct fields by snake_case).
//
// If anyone "simplifies" userColumnsAs by dropping the "AS name" half,
// federation logins start silently scanning zero-valued users — every
// time. The struct mapper sees no column named "id", "email", etc.,
// and Lax mode just skips them rather than erroring. This test catches
// that exact mistake.
func TestUserColumnsAs(t *testing.T) {
	t.Parallel()

	got := userColumnsAs("u")

	for _, col := range userColumnNames {
		prefixed := "u." + col
		aliased := "AS " + col

		if !strings.Contains(got, prefixed) {
			t.Errorf("userColumnsAs missing prefixed reference %q in output:\n%s", prefixed, got)
		}
		if !strings.Contains(got, aliased) {
			t.Errorf("userColumnsAs missing %q in output (column %q lost its result-set name):\n%s", aliased, col, got)
		}
	}

	// The output should be a valid comma-separated projection list:
	// no trailing comma, no double commas, one entry per column.
	parts := strings.Split(got, ", ")
	if len(parts) != len(userColumnNames) {
		t.Errorf("expected %d parts, got %d:\n%s", len(userColumnNames), len(parts), got)
	}
}

// TestUserColumnsSeparate sanity-checks that the bare userColumns is
// still usable for single-table queries (no alias prefix, no AS).
// This documents the choice to have two forms instead of one universal one.
func TestUserColumnsSeparate(t *testing.T) {
	t.Parallel()
	if strings.Contains(userColumns, " AS ") {
		t.Errorf("userColumns must NOT contain AS clauses (those are for the aliased form):\n%s", userColumns)
	}
	if strings.Contains(userColumns, "u.") {
		t.Errorf("userColumns must NOT contain table-alias prefixes:\n%s", userColumns)
	}
	// Every name from the source list must be present.
	for _, c := range userColumnNames {
		if !strings.Contains(userColumns, c) {
			t.Errorf("userColumns missing column %q:\n%s", c, userColumns)
		}
	}
}

