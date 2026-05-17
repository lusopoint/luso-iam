// Package migrations exposes the SQL migration files as an embed.FS so
// they can be applied programmatically at startup or by tests without
// shipping a separate directory alongside the binary.
package migrations

import "embed"

// FS contains every .sql migration in this directory. Files are named
// NNNN_description.up.sql / .down.sql per the project conventions.
//
//go:embed *.sql
var FS embed.FS
