package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// service-type discriminators for service_email_allowlist.service_type
const (
	AllowlistServiceOIDC = "oidc"
	AllowlistServiceCAS  = "cas"
)

// UUIDString renders a pgtype.UUID as its canonical lower-case hyphenated form
// CAS service ids are uuids but the allowlist stores service_id as
// text, so both the admin (write) and enforcement (read) paths must agree
// on exactly this representation
func UUIDString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	const hx = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, b := range u.Bytes {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hx[b>>4]
		out[pos+1] = hx[b&0x0f]
		pos += 2
	}
	return string(out)
}

// isEmailAllowed reports whether email appears on the given services allowlist
// email matches case-insensitively (the column is citext)
func (s *Store) isEmailAllowed(ctx context.Context, serviceType, serviceID, email string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
		    SELECT 1 FROM service_email_allowlist
		    WHERE service_type = $1 AND service_id = $2 AND email = $3
		 )`,
		serviceType, serviceID, email,
	).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check allowlist membership: %w", err)
	}
	return ok, nil
}

// IsOIDCClientEmailAllowed reports whether email is on clientIDs allowlist
func (s *Store) IsOIDCClientEmailAllowed(ctx context.Context, clientID, email string) (bool, error) {
	return s.isEmailAllowed(ctx, AllowlistServiceOIDC, clientID, email)
}

// IsCASServiceEmailAllowed reports whether email is on the CAS services allowlist
func (s *Store) IsCASServiceEmailAllowed(ctx context.Context, serviceID pgtype.UUID, email string) (bool, error) {
	return s.isEmailAllowed(ctx, AllowlistServiceCAS, UUIDString(serviceID), email)
}

// ListServiceAllowlist returns every allowlist entry for a service ordered by email
func (s *Store) ListServiceAllowlist(ctx context.Context, serviceType, serviceID string) ([]AllowlistEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, service_type, service_id, email, created_at
		   FROM service_email_allowlist
		  WHERE service_type = $1 AND service_id = $2
		  ORDER BY email`,
		serviceType, serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("list allowlist: %w", err)
	}
	entries, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[AllowlistEntry])
	if err != nil {
		return nil, fmt.Errorf("scan allowlist: %w", err)
	}
	return entries, nil
}

// AddServiceAllowlistEmails inserts the given emails, ignoring duplicates
// Returns the number of rows actually added (duplicates count as 0)
// the caller is responsible for having validated/normalised the emails
func (s *Store) AddServiceAllowlistEmails(ctx context.Context, serviceType, serviceID string, emails []string) (int64, error) {
	if len(emails) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO service_email_allowlist (service_type, service_id, email)
		 SELECT $1, $2, unnest($3::citext[])
		 ON CONFLICT (service_type, service_id, email) DO NOTHING`,
		serviceType, serviceID, emails,
	)
	if err != nil {
		return 0, fmt.Errorf("add allowlist emails: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteServiceAllowlistEmails removes the given emails from a services allowlist
func (s *Store) DeleteServiceAllowlistEmails(ctx context.Context, serviceType, serviceID string, emails []string) (int64, error) {
	if len(emails) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM service_email_allowlist
		  WHERE service_type = $1 AND service_id = $2 AND email = ANY($3::citext[])`,
		serviceType, serviceID, emails,
	)
	if err != nil {
		return 0, fmt.Errorf("delete allowlist emails: %w", err)
	}
	return tag.RowsAffected(), nil
}
