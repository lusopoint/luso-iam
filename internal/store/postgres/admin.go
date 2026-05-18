package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Users
// ListUsersFilter narrows ListUsers. All fields are optional.
type ListUsersFilter struct {
	// Search matches against email, username, and display_name (ILIKE).
	Search string
	// Status filters by users.status (e.g. "active", "disabled"). Empty = any.
	Status string
	// Limit / Offset for pagination. Limit is capped at 200.
	Limit  int
	Offset int
}

// ListUsersResult bundles the page and the total matching count, so the
// UI can render pagination without a second roundtrip.
type ListUsersResult struct {
	Users []User
	Total int
}

// ListUsers returns a paginated slice of non-deleted users matching filter.
func (s *Store) ListUsers(ctx context.Context, f ListUsersFilter) (*ListUsersResult, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	// Build the WHERE clause incrementally so we can pass typed args
	// (rather than string-concat user input).
	where := []string{"deleted_at IS NULL"}
	args := []any{}

	if f.Search != "" {
		args = append(args, "%"+f.Search+"%")
		i := len(args)
		where = append(where,
			fmt.Sprintf("(email ILIKE $%d OR username ILIKE $%d OR display_name ILIKE $%d)", i, i, i))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	whereSQL := strings.Join(where, " AND ")

	// One round-trip: page + total via window function.
	q := `SELECT ` + userColumns + `, count(*) OVER () AS total_count
	      FROM users
	      WHERE ` + whereSQL + `
	      ORDER BY created_at DESC
	      LIMIT $` + fmt.Sprint(len(args)+1) + `
	      OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	out := &ListUsersResult{Users: make([]User, 0, limit)}
	for rows.Next() {
		var u User
		var total int
		if err := rows.Scan(
			&u.ID, &u.Email, &u.Username, &u.DisplayName, &u.Status, &u.IsAdmin,
			&u.EmailVerifiedAt, &u.LastLoginAt,
			&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
			&total,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out.Users = append(out.Users, u)
		out.Total = total
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return out, nil
}

// UpdateUserParams carries the editable fields. Nil pointers mean "do not
// change". DisplayName uses a sentinel struct so callers can distinguish
// "leave alone" (nil) from "clear" (non-nil, value == "").
type UpdateUserParams struct {
	ID          pgtype.UUID
	Email       *string
	Username    *string
	DisplayName *string
	Status      *string
	IsAdmin     *bool
	// EmailVerifiedAt: pass &time.Time{} (zero value) to clear, or a real
	// timestamp to set. nil leaves the column untouched. Provided so the
	// admin create-user flow can mark verified at insert time without
	// adding the field to CreateUserParams (and growing the SQL).
	EmailVerifiedAt *time.Time
}

// UpdateUser modifies the given user. Only non-nil fields are touched.
// Returns the updated row.
func (s *Store) UpdateUser(ctx context.Context, p UpdateUserParams) (*User, error) {
	sets := []string{}
	args := []any{}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if p.Email != nil {
		add("email", *p.Email)
	}
	if p.Username != nil {
		add("username", *p.Username)
	}
	if p.DisplayName != nil {
		// Empty string → store NULL so the UI can clear the field.
		if *p.DisplayName == "" {
			add("display_name", nil)
		} else {
			add("display_name", *p.DisplayName)
		}
	}
	if p.Status != nil {
		add("status", *p.Status)
	}
	if p.IsAdmin != nil {
		add("is_admin", *p.IsAdmin)
	}
	if p.EmailVerifiedAt != nil {
		// Zero time clears the column; any real time stamps it.
		if p.EmailVerifiedAt.IsZero() {
			add("email_verified_at", nil)
		} else {
			add("email_verified_at", *p.EmailVerifiedAt)
		}
	}
	if len(sets) == 0 {
		// Nothing to do — return current row.
		return s.GetUserByID(ctx, p.ID)
	}
	args = append(args, p.ID)
	q := `UPDATE users SET ` + strings.Join(sets, ", ") +
		` WHERE id = $` + fmt.Sprint(len(args)) + ` AND deleted_at IS NULL
		  RETURNING ` + userColumns

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan updated user: %w", err)
	}
	return &u, nil
}

// SoftDeleteUser marks the user deleted_at and disables the account.
// We don't hard-delete — foreign keys cascade to credentials/sessions/etc.,
// but audit history must remain queryable.
func (s *Store) SoftDeleteUser(ctx context.Context, id pgtype.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET deleted_at = now(), status = 'disabled'
		 WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("soft delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSessionsForUser returns all non-revoked sessions for a user, newest
// first. Used by the admin UI to surface "where is this user logged in?".
func (s *Store) ListSessionsForUser(ctx context.Context, userID pgtype.UUID) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY last_seen_at DESC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	sessions, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[Session])
	if err != nil {
		return nil, fmt.Errorf("scan sessions: %w", err)
	}
	return sessions, nil
}

// RevokeAllSessionsForUser is the nuclear option after a credential
// compromise or admin-initiated logout. Marks every active session revoked.
func (s *Store) RevokeAllSessionsForUser(ctx context.Context, userID pgtype.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// OIDC clients (admin CRUD)
// ListOIDCClients returns all non-deleted clients, newest first.
// Admin endpoints don't filter by enabled — admins need to see disabled rows
// to re-enable them.
func (s *Store) ListOIDCClients(ctx context.Context) ([]OIDCClient, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+oidcClientColumns+` FROM oidc_clients
		 WHERE deleted_at IS NULL ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list oidc clients: %w", err)
	}
	clients, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[OIDCClient])
	if err != nil {
		return nil, fmt.Errorf("scan oidc clients: %w", err)
	}
	return clients, nil
}

// CreateOIDCClientParams holds everything an admin can set when registering.
type CreateOIDCClientParams struct {
	ID                string
	SecretHash        *string // nil for public clients
	Name              string
	RedirectURIs      []string
	AllowedScopes     []string
	AllowedGrantTypes []string
	IsPublic          bool
	RequirePKCE       bool
	RequireConsent    bool
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	IDTokenTTL        time.Duration
}

// CreateOIDCClient inserts a new client.
func (s *Store) CreateOIDCClient(ctx context.Context, p CreateOIDCClientParams) (*OIDCClient, error) {
	q := `INSERT INTO oidc_clients
	          (id, secret_hash, name, redirect_uris,
	           allowed_scopes, allowed_grant_types,
	           is_public, require_pkce, require_consent,
	           access_token_ttl, refresh_token_ttl, id_token_ttl)
	      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	      RETURNING ` + oidcClientColumns
	rows, err := s.pool.Query(ctx, q,
		p.ID, p.SecretHash, p.Name, p.RedirectURIs,
		p.AllowedScopes, p.AllowedGrantTypes,
		p.IsPublic, p.RequirePKCE, p.RequireConsent,
		p.AccessTokenTTL, p.RefreshTokenTTL, p.IDTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("insert oidc client: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCClient])
	if err != nil {
		return nil, fmt.Errorf("scan oidc client: %w", err)
	}
	return &c, nil
}

// UpdateOIDCClientParams holds editable fields. Nil = unchanged.
type UpdateOIDCClientParams struct {
	ID                string
	Name              *string
	RedirectURIs      *[]string
	AllowedScopes     *[]string
	AllowedGrantTypes *[]string
	RequirePKCE       *bool
	RequireConsent    *bool
	Enabled           *bool
}

// UpdateOIDCClient applies the patch and returns the updated row.
func (s *Store) UpdateOIDCClient(ctx context.Context, p UpdateOIDCClientParams) (*OIDCClient, error) {
	sets := []string{}
	args := []any{}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if p.Name != nil {
		add("name", *p.Name)
	}
	if p.RedirectURIs != nil {
		add("redirect_uris", *p.RedirectURIs)
	}
	if p.AllowedScopes != nil {
		add("allowed_scopes", *p.AllowedScopes)
	}
	if p.AllowedGrantTypes != nil {
		add("allowed_grant_types", *p.AllowedGrantTypes)
	}
	if p.RequirePKCE != nil {
		add("require_pkce", *p.RequirePKCE)
	}
	if p.RequireConsent != nil {
		add("require_consent", *p.RequireConsent)
	}
	if p.Enabled != nil {
		add("enabled", *p.Enabled)
	}
	if len(sets) == 0 {
		// No-op: return current.
		return s.GetOIDCClientAny(ctx, p.ID)
	}
	args = append(args, p.ID)
	q := `UPDATE oidc_clients SET ` + strings.Join(sets, ", ") +
		` WHERE id = $` + fmt.Sprint(len(args)) + ` AND deleted_at IS NULL
		  RETURNING ` + oidcClientColumns
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("update oidc client: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCClient])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan updated client: %w", err)
	}
	return &c, nil
}

// RotateOIDCClientSecret stores a new secret hash. Caller is responsible
// for showing the plaintext to the admin once — it's never recoverable.
func (s *Store) RotateOIDCClientSecret(ctx context.Context, id, newHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE oidc_clients SET secret_hash = $2
		 WHERE id = $1 AND deleted_at IS NULL AND is_public = false`, id, newHash)
	if err != nil {
		return fmt.Errorf("rotate client secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDeleteOIDCClient marks the client deleted. Existing tokens issued
// to this client remain in the DB but the client can no longer authenticate.
func (s *Store) SoftDeleteOIDCClient(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE oidc_clients SET deleted_at = now(), enabled = false
		 WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("soft delete oidc client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetOIDCClientAny is the admin-side getter — unlike GetOIDCClient it
// returns disabled clients too (they may need to be re-enabled).
func (s *Store) GetOIDCClientAny(ctx context.Context, id string) (*OIDCClient, error) {
	q := `SELECT ` + oidcClientColumns + ` FROM oidc_clients
	      WHERE id = $1 AND deleted_at IS NULL`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("query oidc client: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCClient])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc client: %w", err)
	}
	return &c, nil
}

// CAS services (admin CRUD)
// (casServiceColumns is defined in cas.go and reused here.)

// ListCASServices returns all non-deleted CAS services, newest first.
func (s *Store) ListCASServices(ctx context.Context) ([]CASService, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+casServiceColumns+` FROM cas_services
		 WHERE deleted_at IS NULL ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list cas services: %w", err)
	}
	services, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[CASService])
	if err != nil {
		return nil, fmt.Errorf("scan cas services: %w", err)
	}
	return services, nil
}

// GetCASService returns one CAS service by id, or ErrNotFound.
func (s *Store) GetCASService(ctx context.Context, id pgtype.UUID) (*CASService, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+casServiceColumns+` FROM cas_services
		 WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, fmt.Errorf("query cas service: %w", err)
	}
	svc, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[CASService])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan cas service: %w", err)
	}
	return &svc, nil
}

// UpdateCASServiceParams holds editable fields. Nil = unchanged.
type UpdateCASServiceParams struct {
	ID                 pgtype.UUID
	Name               *string
	ServiceURLPattern  *string
	MatchPattern       *string
	Description        *string
	ReleasedAttributes *[]string
	Enabled            *bool
}

// UpdateCASService applies the patch and returns the updated row.
func (s *Store) UpdateCASService(ctx context.Context, p UpdateCASServiceParams) (*CASService, error) {
	sets := []string{}
	args := []any{}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if p.Name != nil {
		add("name", *p.Name)
	}
	if p.ServiceURLPattern != nil {
		add("service_url_pattern", *p.ServiceURLPattern)
	}
	if p.MatchPattern != nil {
		add("match_pattern", *p.MatchPattern)
	}
	if p.Description != nil {
		if *p.Description == "" {
			add("description", nil)
		} else {
			add("description", *p.Description)
		}
	}
	if p.ReleasedAttributes != nil {
		add("released_attributes", *p.ReleasedAttributes)
	}
	if p.Enabled != nil {
		add("enabled", *p.Enabled)
	}
	if len(sets) == 0 {
		return s.GetCASService(ctx, p.ID)
	}
	args = append(args, p.ID)
	q := `UPDATE cas_services SET ` + strings.Join(sets, ", ") +
		` WHERE id = $` + fmt.Sprint(len(args)) + ` AND deleted_at IS NULL
		  RETURNING ` + casServiceColumns
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("update cas service: %w", err)
	}
	svc, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[CASService])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan updated cas service: %w", err)
	}
	return &svc, nil
}

// SoftDeleteCASService removes a CAS service from active use.
func (s *Store) SoftDeleteCASService(ctx context.Context, id pgtype.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE cas_services SET deleted_at = now(), enabled = false
		 WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("soft delete cas service: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
