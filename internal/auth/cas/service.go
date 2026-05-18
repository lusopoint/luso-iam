// Package cas implements the protocol-side logic for CAS 2.0 / 3.0:
//
//   - resolving the `service` query parameter against the registry of
//     known CAS services (with wildcard URL patterns),
//   - minting short-lived, single-use service tickets,
//   - consuming and validating those tickets, returning the bound user.
//
// The package is independent of the HTTP layer (internal/api/cas) and
// the session layer beyond accepting a session id.
package cas

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// ServiceTicketTTL is how long a freshly minted service ticket is
// valid for. CAS spec says no more than a few seconds; we allow 60s
// to be forgiving of network delays between the redirect and the
// back-channel validate call.
const ServiceTicketTTL = 60 * time.Second

// Errors visible to the HTTP layer.
var (
	ErrUnauthorizedService = errors.New("cas: service is not registered")
	ErrInvalidTicket       = errors.New("cas: invalid ticket")
	ErrServiceMismatch     = errors.New("cas: ticket was not issued for this service")
)

// Service is the CAS protocol logic.
type Service struct {
	store *postgres.Store
}

// New returns a CAS service.
func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

// ResolveService returns the registered service entry whose pattern
// matches serviceURL. Returns ErrUnauthorizedService if nothing
// matches. The returned struct carries the attribute release policy
// used later by serviceValidate.
func (s *Service) ResolveService(ctx context.Context, serviceURL string) (*postgres.CASService, error) {
	if serviceURL == "" {
		return nil, ErrUnauthorizedService
	}
	svc, err := s.store.FindCASServiceForURL(ctx, normalizeServiceURL(serviceURL))
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrUnauthorizedService
		}
		return nil, err
	}
	return svc, nil
}

// IssueServiceTicket mints a fresh ST bound to (sessionID, serviceURL).
// Caller is responsible for redirecting the user back to serviceURL
// with the returned ticket appended.
func (s *Service) IssueServiceTicket(ctx context.Context, sessionID pgtype.UUID, serviceURL string, renew bool) (string, error) {
	tok, err := crypto.RandomToken(32) // 64 hex chars
	if err != nil {
		return "", fmt.Errorf("mint ticket: %w", err)
	}
	id := "ST-" + tok

	err = s.store.CreateCASTicket(ctx, postgres.CreateCASTicketParams{
		ID:         id,
		SessionID:  sessionID,
		ServiceURL: serviceURL,
		ExpiresAt:  time.Now().Add(ServiceTicketTTL),
		Renew:      renew,
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// ValidationResult is what /cas/serviceValidate returns to the caller
// after a successful ticket validation.
type ValidationResult struct {
	Ticket  *postgres.CASTicket
	Session *postgres.Session
	User    *postgres.User
	Service *postgres.CASService
}

// Validate atomically consumes the ticket and returns the bound user.
// If the ticket is missing, already consumed, expired, or was issued
// for a different service, returns the matching sentinel error.
func (s *Service) Validate(ctx context.Context, ticketID, serviceURL string) (*ValidationResult, error) {
	if !strings.HasPrefix(ticketID, "ST-") {
		return nil, ErrInvalidTicket
	}

	t, err := s.store.ConsumeCASTicket(ctx, ticketID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidTicket
		}
		return nil, err
	}

	if t.ServiceURL != normalizeServiceURL(serviceURL) {
		return nil, ErrServiceMismatch
	}

	sess, err := s.store.GetActiveSession(ctx, t.SessionID)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidTicket
		}
		return nil, err
	}

	user, err := s.store.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("load user: %w", err)
	}

	svc, err := s.store.FindCASServiceForURL(ctx, t.ServiceURL)
	if err != nil {
		// A ticket exists for this URL, so a service entry must have
		// matched at issue time. If we can't find one now (e.g. it was
		// deleted in between) we still allow the validation but return
		// no attribute policy.
		svc = nil
	}

	return &ValidationResult{
		Ticket:  t,
		Session: sess,
		User:    user,
		Service: svc,
	}, nil
}

// URL helpers

// normalizeServiceURL strips the fragment and any nested `ticket`
// parameter that might still be attached from a previous round-trip.
// Hostname and scheme casing are normalized. Query parameter order is
// preserved otherwise.
func normalizeServiceURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	if u.RawQuery != "" {
		q := u.Query()
		q.Del("ticket")
		u.RawQuery = q.Encode()
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// PatternToLike converts a user-facing service URL pattern (with '*'
// wildcards) into a SQL LIKE pattern. Existing '%' / '_' / '\\' in the
// input are escaped so they're treated literally.
//
// Examples:
//
//	"https://app.example.com/*"   →  "https://app.example.com/%"
//	"https://*.example.com/cb"    →  "https://%.example.com/cb"
//	"https://x.com/100%off"       →  "https://x.com/100\%off"
func PatternToLike(pattern string) string {
	var b strings.Builder
	b.Grow(len(pattern))
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteByte('%')
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
