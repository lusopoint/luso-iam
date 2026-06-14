package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const userIdentityColumns = `
	id, user_id, provider, sub,
	email, display_name, picture_url,
	raw_claims, created_at, updated_at
`

// GetUserIdentity returns the identity row for the given (provider, sub),
// or ErrNotFound
func (s *Store) GetUserIdentity(ctx context.Context, provider, sub string) (*UserIdentity, error) {
	q := `SELECT ` + userIdentityColumns + ` FROM user_identities
	      WHERE provider = $1 AND sub = $2`
	rows, err := s.pool.Query(ctx, q, provider, sub)
	if err != nil {
		return nil, fmt.Errorf("query user_identity: %w", err)
	}
	id, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserIdentity])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user_identity: %w", err)
	}
	return &id, nil
}

// GetUserByProviderSub is a convenience join that returns the IAM User
// that owns the given (provider, sub) identity, or ErrNotFound
func (s *Store) GetUserByProviderSub(ctx context.Context, provider, sub string) (*User, error) {
	q := `SELECT ` + userColumnsAs("u") + ` FROM users u
	      JOIN user_identities ui ON ui.user_id = u.id
	      WHERE ui.provider = $1 AND ui.sub = $2
	        AND u.deleted_at IS NULL`
	rows, err := s.pool.Query(ctx, q, provider, sub)
	if err != nil {
		return nil, fmt.Errorf("query user by provider sub: %w", err)
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

// CreateUserIdentityParams is the input to CreateUserIdentity
type CreateUserIdentityParams struct {
	UserID      pgtype.UUID
	Provider    string
	Sub         string
	Email       *string
	DisplayName *string
	PictureURL  *string
	RawClaims   map[string]any
}

// CreateUserIdentity inserts a new identity row
func (s *Store) CreateUserIdentity(ctx context.Context, p CreateUserIdentityParams) (*UserIdentity, error) {
	raw, err := marshalClaims(p.RawClaims)
	if err != nil {
		return nil, err
	}
	q := `INSERT INTO user_identities
	          (user_id, provider, sub, email, display_name, picture_url, raw_claims)
	      VALUES ($1, $2, $3, $4, $5, $6, $7)
	      RETURNING ` + userIdentityColumns
	rows, err := s.pool.Query(ctx, q,
		p.UserID, p.Provider, p.Sub,
		p.Email, p.DisplayName, p.PictureURL, raw)
	if err != nil {
		return nil, fmt.Errorf("insert user_identity: %w", err)
	}
	id, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserIdentity])
	if err != nil {
		return nil, fmt.Errorf("scan user_identity: %w", err)
	}
	return &id, nil
}

// UpdateUserIdentityParams carries the mutable fields refreshed on each upstream login
type UpdateUserIdentityParams struct {
	Provider    string
	Sub         string
	Email       *string
	DisplayName *string
	PictureURL  *string
	RawClaims   map[string]any
}

// UpdateUserIdentity refreshes the cached profile fields
func (s *Store) UpdateUserIdentity(ctx context.Context, p UpdateUserIdentityParams) error {
	raw, err := marshalClaims(p.RawClaims)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE user_identities
		 SET email = $3, display_name = $4, picture_url = $5,
		     raw_claims = $6
		 WHERE provider = $1 AND sub = $2`,
		p.Provider, p.Sub,
		p.Email, p.DisplayName, p.PictureURL, raw)
	if err != nil {
		return fmt.Errorf("update user_identity: %w", err)
	}
	return nil
}

// ListUserIdentities returns all identity rows for a given user
func (s *Store) ListUserIdentities(ctx context.Context, userID pgtype.UUID) ([]UserIdentity, error) {
	q := `SELECT ` + userIdentityColumns + ` FROM user_identities
	      WHERE user_id = $1 ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list user_identities: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[UserIdentity])
	if err != nil {
		return nil, fmt.Errorf("scan user_identities: %w", err)
	}
	return ids, nil
}

// GetUserIdentityByID returns the user_identity row with the given id, or ErrNotFound
// Used by the admin unlink endpoint to verify
func (s *Store) GetUserIdentityByID(ctx context.Context, id pgtype.UUID) (*UserIdentity, error) {
	q := `SELECT ` + userIdentityColumns + ` FROM user_identities WHERE id = $1`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("query user_identity: %w", err)
	}
	ui, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserIdentity])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user_identity: %w", err)
	}
	return &ui, nil
}

// DeleteUserIdentity removes a single user_identity row,
// We use a hard delete (not a soft delete) because once unlinked, the (provider, sub)
// pair must be free to re link, either to the same user via /mfa/enroll
// type flow, or to a different user if the upstream account changes hands
// a soft delete would leave the unique constraint occupied
func (s *Store) DeleteUserIdentity(ctx context.Context, id pgtype.UUID) error {
	cmd, err := s.pool.Exec(ctx, `DELETE FROM user_identities WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user_identity: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func marshalClaims(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal raw_claims: %w", err)
	}
	return b, nil
}
