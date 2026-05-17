package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const mfaMethodColumns = `
	id, user_id, method, name,
	secret, credential, counter,
	confirmed_at, last_used_at,
	created_at, updated_at
`

// ─── User-facing queries ──────────────────────────────────────────────────

// ListConfirmedMFAMethods returns all confirmed MFA methods for a user,
// ordered by creation. Used to decide whether MFA is required and to
// render the choose-a-method screen during login.
func (s *Store) ListConfirmedMFAMethods(ctx context.Context, userID pgtype.UUID) ([]UserMFAMethod, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+mfaMethodColumns+` FROM user_mfa_methods
		 WHERE user_id = $1 AND confirmed_at IS NOT NULL
		 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list mfa methods: %w", err)
	}
	methods, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[UserMFAMethod])
	if err != nil {
		return nil, fmt.Errorf("scan mfa methods: %w", err)
	}
	return methods, nil
}

// ListAllMFAMethods returns every MFA row for a user, including
// unconfirmed ones — used in the enrollment / management UI.
func (s *Store) ListAllMFAMethods(ctx context.Context, userID pgtype.UUID) ([]UserMFAMethod, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+mfaMethodColumns+` FROM user_mfa_methods
		 WHERE user_id = $1 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list mfa methods: %w", err)
	}
	methods, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[UserMFAMethod])
	if err != nil {
		return nil, fmt.Errorf("scan mfa methods: %w", err)
	}
	return methods, nil
}

// GetMFAMethod returns one method by id, or ErrNotFound.
func (s *Store) GetMFAMethod(ctx context.Context, id pgtype.UUID) (*UserMFAMethod, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+mfaMethodColumns+` FROM user_mfa_methods WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("query mfa method: %w", err)
	}
	m, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserMFAMethod])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan mfa method: %w", err)
	}
	return &m, nil
}

// ─── TOTP ─────────────────────────────────────────────────────────────────

// CreateTOTPMethodParams is the input for enrolling a TOTP method.
// The row is created in unconfirmed state — call ConfirmMFAMethod after
// the user verifies their first code.
type CreateTOTPMethodParams struct {
	UserID pgtype.UUID
	Name   *string
	Secret string // base32 shared secret
}

// CreateTOTPMethod inserts an unconfirmed TOTP method.
func (s *Store) CreateTOTPMethod(ctx context.Context, p CreateTOTPMethodParams) (*UserMFAMethod, error) {
	rows, err := s.pool.Query(ctx,
		`INSERT INTO user_mfa_methods (user_id, method, name, secret)
		 VALUES ($1, 'totp', $2, $3)
		 RETURNING `+mfaMethodColumns,
		p.UserID, p.Name, p.Secret)
	if err != nil {
		return nil, fmt.Errorf("insert totp method: %w", err)
	}
	m, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserMFAMethod])
	if err != nil {
		return nil, fmt.Errorf("scan inserted method: %w", err)
	}
	return &m, nil
}

// ─── WebAuthn ─────────────────────────────────────────────────────────────

// CreateWebAuthnMethodParams is the input for storing a WebAuthn credential.
// Unlike TOTP, WebAuthn methods are confirmed immediately on creation —
// the registration ceremony has already proven possession.
type CreateWebAuthnMethodParams struct {
	UserID     pgtype.UUID
	Name       *string
	Credential []byte // JSON-encoded webauthn.Credential
	Counter    int64
}

// CreateWebAuthnMethod inserts a WebAuthn credential as a confirmed method.
func (s *Store) CreateWebAuthnMethod(ctx context.Context, p CreateWebAuthnMethodParams) (*UserMFAMethod, error) {
	rows, err := s.pool.Query(ctx,
		`INSERT INTO user_mfa_methods
		     (user_id, method, name, credential, counter, confirmed_at)
		 VALUES ($1, 'webauthn', $2, $3, $4, now())
		 RETURNING `+mfaMethodColumns,
		p.UserID, p.Name, p.Credential, p.Counter)
	if err != nil {
		return nil, fmt.Errorf("insert webauthn method: %w", err)
	}
	m, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[UserMFAMethod])
	if err != nil {
		return nil, fmt.Errorf("scan inserted method: %w", err)
	}
	return &m, nil
}

// UpdateWebAuthnCounter bumps the signature counter for a credential.
// The webauthn library returns the new counter from each assertion;
// monotonic increase detects cloned authenticators.
func (s *Store) UpdateWebAuthnCounter(ctx context.Context, id pgtype.UUID, counter int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_mfa_methods SET counter = $2, last_used_at = now()
		 WHERE id = $1`, id, counter)
	if err != nil {
		return fmt.Errorf("update webauthn counter: %w", err)
	}
	return nil
}

// ─── Shared mutations ─────────────────────────────────────────────────────

// ConfirmMFAMethod marks an unconfirmed method as confirmed.
func (s *Store) ConfirmMFAMethod(ctx context.Context, id pgtype.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE user_mfa_methods SET confirmed_at = now()
		 WHERE id = $1 AND confirmed_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("confirm mfa method: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchMFAMethodUsage updates last_used_at — call after every successful
// challenge so admins can see stale credentials.
func (s *Store) TouchMFAMethodUsage(ctx context.Context, id pgtype.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE user_mfa_methods SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// DeleteMFAMethod removes a method by id.
func (s *Store) DeleteMFAMethod(ctx context.Context, id pgtype.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM user_mfa_methods WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete mfa method: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Backup codes ─────────────────────────────────────────────────────────

// ReplaceBackupCodes atomically replaces all backup codes for a user.
// Use case: when a user requests a new set, the old ones must be revoked
// in the same transaction to prevent a race where both sets are valid.
func (s *Store) ReplaceBackupCodes(ctx context.Context, userID pgtype.UUID, hashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // safe on commit

	if _, err := tx.Exec(ctx,
		`DELETE FROM user_backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete old codes: %w", err)
	}

	for _, h := range hashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_backup_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, h); err != nil {
			return fmt.Errorf("insert backup code: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListUnusedBackupCodes returns the hashes of all unused codes for a user.
// We have to load all of them because we can't query by hash — argon2id
// salts make each hash unique, so verification iterates.
func (s *Store) ListUnusedBackupCodes(ctx context.Context, userID pgtype.UUID) ([]UserBackupCode, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, code_hash, used_at, created_at
		 FROM user_backup_codes
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("list backup codes: %w", err)
	}
	codes, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[UserBackupCode])
	if err != nil {
		return nil, fmt.Errorf("scan backup codes: %w", err)
	}
	return codes, nil
}

// MarkBackupCodeUsed atomically marks a code as consumed. Returns ErrNotFound
// if the code was already used (or never existed).
func (s *Store) MarkBackupCodeUsed(ctx context.Context, id pgtype.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE user_backup_codes SET used_at = now()
		 WHERE id = $1 AND used_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("mark backup code used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUnusedBackupCodes returns how many codes a user has left — used in
// the management UI to warn when running low.
func (s *Store) CountUnusedBackupCodes(ctx context.Context, userID pgtype.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM user_backup_codes
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count backup codes: %w", err)
	}
	return n, nil
}
