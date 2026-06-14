package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// userColumnNames is the canonical column list for the users table
var userColumnNames = []string{
	"id", "email", "username", "display_name", "status", "is_admin",
	"email_verified_at", "last_login_at",
	"created_at", "updated_at", "deleted_at",
}

// userColumns is the bare comma-separated list(no ambiguity possible)
var userColumns = strings.Join(userColumnNames, ", ")

// userColumnsAs returns the column list with a table alias prepended
// JOIN fixes the issue with ambiguous
func userColumnsAs(alias string) string {
	parts := make([]string, len(userColumnNames))
	for i, c := range userColumnNames {
		parts[i] = alias + "." + c + " AS " + c
	}
	return strings.Join(parts, ", ")
}

// GetUserByEmail returns the active user with the given email
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	q := `SELECT ` + userColumns + ` FROM users
	      WHERE email = $1 AND deleted_at IS NULL`
	rows, err := s.pool.Query(ctx, q, email)
	if err != nil {
		return nil, fmt.Errorf("query user by email: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

// GetUserByID returns the active user with the given id
func (s *Store) GetUserByID(ctx context.Context, id pgtype.UUID) (*User, error) {
	q := `SELECT ` + userColumns + ` FROM users
	      WHERE id = $1 AND deleted_at IS NULL`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("query user by id: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

type CreateUserParams struct {
	Email       *string
	Username    *string
	DisplayName *string
}

// CreateUser inserts a new user and returns the created row
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (*User, error) {
	q := `INSERT INTO users (email, username, display_name)
	      VALUES ($1, $2, $3)
	      RETURNING ` + userColumns
	rows, err := s.pool.Query(ctx, q, p.Email, p.Username, p.DisplayName)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		return nil, fmt.Errorf("scan inserted user: %w", err)
	}
	return &u, nil
}

// TouchUserLastLogin updates last_login_at to now() for the given user
func (s *Store) TouchUserLastLogin(ctx context.Context, userID pgtype.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("touch last_login_at: %w", err)
	}
	return nil
}
