package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ─── Client ───────────────────────────────────────────────────────────────

const oidcClientColumns = `
	id, secret_hash, name, redirect_uris,
	allowed_scopes, allowed_grant_types,
	is_public, require_pkce, require_consent,
	access_token_ttl, refresh_token_ttl, id_token_ttl,
	enabled, created_at, updated_at, deleted_at
`

// GetOIDCClient returns the active, enabled client with the given id.
func (s *Store) GetOIDCClient(ctx context.Context, id string) (*OIDCClient, error) {
	q := `SELECT ` + oidcClientColumns + ` FROM oidc_clients
	      WHERE id = $1 AND deleted_at IS NULL AND enabled`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("query oidc_client: %w", err)
	}
	c, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCClient])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc_client: %w", err)
	}
	return &c, nil
}

// ValidateRedirectURI returns nil iff redirectURI is in the client's
// registered redirect_uris list (exact match, per OIDC spec).
func (s *Store) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT $2 = ANY(redirect_uris)
		 FROM oidc_clients WHERE id = $1 AND deleted_at IS NULL`,
		clientID, redirectURI,
	).Scan(&ok)
	if err != nil {
		return fmt.Errorf("validate redirect_uri: %w", err)
	}
	if !ok {
		return ErrNotFound // caller converts to invalid_redirect_uri
	}
	return nil
}

// ─── Authorization codes ──────────────────────────────────────────────────

const oidcAuthCodeColumns = `
	id, client_id, user_id, session_id,
	redirect_uri, scopes, nonce, pkce_challenge,
	acr, amr, auth_time,
	expires_at, consumed_at, created_at
`

// CreateOIDCAuthCodeParams carries all fields for a new auth code.
type CreateOIDCAuthCodeParams struct {
	ID            string
	ClientID      string
	UserID        pgtype.UUID
	SessionID     pgtype.UUID
	RedirectURI   string
	Scopes        []string
	Nonce         *string
	PKCEChallenge *string
	ACR           string
	AMR           []string
	AuthTime      time.Time
	ExpiresAt     time.Time
}

// CreateOIDCAuthCode inserts a new authorization code.
func (s *Store) CreateOIDCAuthCode(ctx context.Context, p CreateOIDCAuthCodeParams) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_auth_codes
		     (id, client_id, user_id, session_id,
		      redirect_uri, scopes, nonce, pkce_challenge,
		      acr, amr, auth_time, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.ClientID, p.UserID, p.SessionID,
		p.RedirectURI, p.Scopes, p.Nonce, p.PKCEChallenge,
		p.ACR, p.AMR, p.AuthTime, p.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert oidc_auth_code: %w", err)
	}
	return nil
}

// ConsumeOIDCAuthCode atomically marks the code as consumed and returns it.
// Returns ErrNotFound if the code is missing, already consumed, or expired.
// Atomicity prevents replay — do not use a SELECT-then-UPDATE pattern.
func (s *Store) ConsumeOIDCAuthCode(ctx context.Context, id string) (*OIDCAuthCode, error) {
	rows, err := s.pool.Query(ctx,
		`UPDATE oidc_auth_codes SET consumed_at = now()
		 WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING `+oidcAuthCodeColumns,
		id)
	if err != nil {
		return nil, fmt.Errorf("consume oidc_auth_code: %w", err)
	}
	code, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCAuthCode])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc_auth_code: %w", err)
	}
	return &code, nil
}

// ─── Access tokens ────────────────────────────────────────────────────────

const oidcAccessTokenColumns = `
	id, client_id, user_id, session_id,
	scopes, expires_at, revoked_at, created_at
`

// CreateOIDCAccessTokenParams carries all fields for a new access token.
type CreateOIDCAccessTokenParams struct {
	ID        string
	ClientID  string
	UserID    *pgtype.UUID // nil for client_credentials
	SessionID *pgtype.UUID
	Scopes    []string
	ExpiresAt time.Time
}

// CreateOIDCAccessToken inserts a new opaque access token.
func (s *Store) CreateOIDCAccessToken(ctx context.Context, p CreateOIDCAccessTokenParams) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_access_tokens
		     (id, client_id, user_id, session_id, scopes, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		p.ID, p.ClientID, p.UserID, p.SessionID, p.Scopes, p.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert oidc_access_token: %w", err)
	}
	return nil
}

// GetOIDCAccessToken returns the active (not revoked, not expired) access
// token, or ErrNotFound.
func (s *Store) GetOIDCAccessToken(ctx context.Context, id string) (*OIDCAccessToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+oidcAccessTokenColumns+` FROM oidc_access_tokens
		 WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`,
		id)
	if err != nil {
		return nil, fmt.Errorf("query oidc_access_token: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCAccessToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc_access_token: %w", err)
	}
	return &t, nil
}

// GetOIDCAccessTokenAny returns the token regardless of expiry or revocation
// status — used by introspection to report inactive tokens accurately.
func (s *Store) GetOIDCAccessTokenAny(ctx context.Context, id string) (*OIDCAccessToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+oidcAccessTokenColumns+` FROM oidc_access_tokens WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("query oidc_access_token: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCAccessToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc_access_token: %w", err)
	}
	return &t, nil
}

// RevokeOIDCAccessToken marks the access token as revoked.
func (s *Store) RevokeOIDCAccessToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE oidc_access_tokens SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`,
		id)
	return err
}

// ─── Refresh tokens ───────────────────────────────────────────────────────

const oidcRefreshTokenColumns = `
	id, client_id, user_id, session_id,
	scopes, previous_id,
	expires_at, rotated_at, revoked_at, created_at
`

// CreateOIDCRefreshTokenParams carries all fields for a new refresh token.
type CreateOIDCRefreshTokenParams struct {
	ID         string
	ClientID   string
	UserID     pgtype.UUID
	SessionID  *pgtype.UUID
	Scopes     []string
	PreviousID *string // chain link for refresh token rotation
	ExpiresAt  time.Time
}

// CreateOIDCRefreshToken inserts a new refresh token.
func (s *Store) CreateOIDCRefreshToken(ctx context.Context, p CreateOIDCRefreshTokenParams) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_refresh_tokens
		     (id, client_id, user_id, session_id, scopes, previous_id, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		p.ID, p.ClientID, p.UserID, p.SessionID,
		p.Scopes, p.PreviousID, p.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert oidc_refresh_token: %w", err)
	}
	return nil
}

// GetOIDCRefreshToken returns an active (not rotated, not revoked, not
// expired) refresh token, or ErrNotFound.
func (s *Store) GetOIDCRefreshToken(ctx context.Context, id string) (*OIDCRefreshToken, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+oidcRefreshTokenColumns+` FROM oidc_refresh_tokens
		 WHERE id = $1
		   AND revoked_at IS NULL AND rotated_at IS NULL
		   AND expires_at > now()`,
		id)
	if err != nil {
		return nil, fmt.Errorf("query oidc_refresh_token: %w", err)
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[OIDCRefreshToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan oidc_refresh_token: %w", err)
	}
	return &t, nil
}

// RotateOIDCRefreshToken atomically marks the existing token as rotated.
// The caller should immediately issue a new token with PreviousID set.
// If a rotated token is presented again, it indicates theft — the caller
// should revoke the entire family.
func (s *Store) RotateOIDCRefreshToken(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE oidc_refresh_tokens SET rotated_at = now()
		 WHERE id = $1 AND rotated_at IS NULL AND revoked_at IS NULL`,
		id)
	if err != nil {
		return fmt.Errorf("rotate oidc_refresh_token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeOIDCRefreshToken marks the token (and its descendants via
// previous_id chain) as revoked — used for logout and theft detection.
func (s *Store) RevokeOIDCRefreshToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE oidc_refresh_tokens SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL`,
		id)
	return err
}

// RevokeAllRefreshTokensForSession revokes all non-expired refresh tokens
// tied to a session — called when the user explicitly logs out.
func (s *Store) RevokeAllRefreshTokensForSession(ctx context.Context, sessionID pgtype.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE oidc_refresh_tokens SET revoked_at = now()
		 WHERE session_id = $1 AND revoked_at IS NULL`,
		sessionID)
	return err
}

// DeleteExpiredOIDCTokens is a maintenance helper for a periodic job.
func (s *Store) DeleteExpiredOIDCTokens(ctx context.Context) error {
	cutoff := time.Now().Add(-time.Hour) // keep 1h post-expiry for audit
	for _, q := range []string{
		`DELETE FROM oidc_auth_codes WHERE expires_at < $1`,
		`DELETE FROM oidc_access_tokens WHERE expires_at < $1`,
		`DELETE FROM oidc_refresh_tokens WHERE expires_at < $1`,
	} {
		if _, err := s.pool.Exec(ctx, q, cutoff); err != nil {
			return err
		}
	}
	return nil
}
