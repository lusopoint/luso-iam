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

// ServiceTicketTTL is how long a freshly minted service ticket is valid for
// cas spec says no more than a few seconds, we allow 60s to be forgiving
// of network delays between the redirect and the back-channel validate call
const ServiceTicketTTL = 60 * time.Second

// Errors visible to the HTTP layer
var (
	ErrUnauthorizedService = errors.New("cas: service is not registered")
	ErrInvalidTicket       = errors.New("cas: invalid ticket")
	ErrServiceMismatch     = errors.New("cas: ticket was not issued for this service")
	// ErrAccessDenied: the service is registered but this user is not on
	// its email allowlist (require_allowlist=true and email absent)
	ErrAccessDenied = errors.New("cas: user not permitted for this service")
)

type Service struct {
	store *postgres.Store
}

func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

// ResolveService returns the registered service entry whose pattern matches serviceURL
// returns ErrUnauthorizedService if nothing matches
// the returned struct carries the attribute release policy used later by serviceValidate
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

// CheckServiceAccess enforces a CAS services email allowlist
// it is a no-op unless svc.RequireAllowlist is set, in which case the users
// email must appear on the services allowlist
// a user with no email can never satisfy an email allowlist, returns ErrAccessDenied when the user is not permitted
func (s *Service) CheckServiceAccess(ctx context.Context, svc *postgres.CASService, userID pgtype.UUID) error {
	if svc == nil || !svc.RequireAllowlist {
		return nil
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("allowlist: load user: %w", err)
	}
	if user.Email == nil {
		return ErrAccessDenied
	}
	allowed, err := s.store.IsCASServiceEmailAllowed(ctx, svc.ID, *user.Email)
	if err != nil {
		return fmt.Errorf("allowlist: check email: %w", err)
	}
	if !allowed {
		return ErrAccessDenied
	}
	return nil
}

// Caller is responsible for redirecting the user back to serviceURL with the returned ticket appended
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
// after a successful ticket validation
type ValidationResult struct {
	Ticket  *postgres.CASTicket
	Session *postgres.Session
	User    *postgres.User
	Service *postgres.CASService
}

// Validate atomically consumes the ticket and returns the bound user
// if the ticket is missing, already consumed, expired, or was issued
// for a different service, returns the matching sentinel error
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
		// a ticket exists for this URL, so a service entry must have matched at issue time
		// if we ca not find one now (ex it was deleted in between)
		// we still allow the validation but return no attribute policy
		svc = nil
	}

	return &ValidationResult{
		Ticket:  t,
		Session: sess,
		User:    user,
		Service: svc,
	}, nil
}

// normalizeServiceURL strips the fragment and any nested `ticket`
// parameter that might still be attached from a previous round-trip
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

// PatternToLike converts a user-facing service URL pattern (with '*' wildcards)
// into a SQL LIKE pattern, existing '%' / '_' / '\\' in the input are escaped so they're treated literally
//
// Examples:
//
//	"https://app.example.com/*"   ->  "https://app.example.com/%"
//	"https://*.example.com/cb"    ->  "https://%.example.com/cb"
//	"https://x.com/100%off"       ->  "https://x.com/100\%off"
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
