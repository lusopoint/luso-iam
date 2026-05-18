// Package audit provides a typed event logger that writes to the
// audit_log table. Every security-relevant action in the codebase
// passes through this package — callers should never write to the
// store's InsertAuditEvent directly.
//
// Audit writes are deliberately synchronous: events that we never
// observed are worse than slightly slower handlers. Failure modes
// (DB down, write timeout) are logged but do not abort the parent
// operation — the audit log is best-effort durability, not a barrier.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// Service is the audit-log writer.
type Service struct {
	store *postgres.Store
}

// New returns a Service that writes via store.
func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

// Event types
//
// The set of canonical event_type values. Keeping these as constants — not
// magic strings — keeps the dashboard filters consistent and makes a
// "find all logout sites" search trivial.

const (
	// Authentication
	EventLoginSuccess    = "login_success"
	EventLoginFailure    = "login_failure"
	EventLogout          = "logout"
	EventPasswordChanged = "password_changed"
	EventSessionRevoked  = "session_revoked"

	// MFA
	EventMFAEnrolled          = "mfa_enrolled"
	EventMFADeleted           = "mfa_deleted"
	EventMFAChallengeSuccess  = "mfa_challenge_success"
	EventMFAChallengeFailure  = "mfa_challenge_failure"
	EventBackupCodesGenerated = "backup_codes_generated"

	// OIDC tokens
	EventTokenIssued       = "token_issued"
	EventTokenRevoked      = "token_revoked"
	EventTokenIntrospected = "token_introspected"

	// Federation
	EventUpstreamLinked   = "upstream_linked"
	EventUpstreamUnlinked = "upstream_unlinked"

	// Admin actions
	EventUserCreated         = "user_created"
	EventUserUpdated         = "user_updated"
	EventUserDeleted         = "user_deleted"
	EventUserLocked          = "user_locked"
	EventUserUnlocked        = "user_unlocked"
	EventClientCreated       = "client_created"
	EventClientUpdated       = "client_updated"
	EventClientDeleted       = "client_deleted"
	EventClientSecretRotated = "client_secret_rotated"
	EventCASServiceCreated   = "cas_service_created"
	EventCASServiceUpdated   = "cas_service_updated"
	EventCASServiceDeleted   = "cas_service_deleted"
)

// Event struct

// Event is the input to Log. Fields are optional except EventType.
// Metadata accepts any map; it is marshalled to JSON before storage.
type Event struct {
	Type     string
	Actor    *pgtype.UUID
	Target   *pgtype.UUID
	Metadata map[string]any

	// IP and UserAgent are typically pulled from the request via FromRequest.
	IP        string
	UserAgent string
}

// Log writes one event. Errors are logged but never returned to the
// caller — audit logging must not break the calling operation.
func (s *Service) Log(ctx context.Context, e Event) {
	var meta []byte
	if len(e.Metadata) > 0 {
		b, err := json.Marshal(e.Metadata)
		if err != nil {
			slog.Warn("audit: marshal metadata failed",
				"event", e.Type, "err", err)
			b = []byte(`{}`)
		}
		meta = b
	}

	var ip *string
	if e.IP != "" {
		ip = &e.IP
	}
	var ua *string
	if e.UserAgent != "" {
		ua = &e.UserAgent
	}

	if err := s.store.InsertAuditEvent(ctx, postgres.InsertAuditEventParams{
		EventType: e.Type,
		ActorID:   e.Actor,
		TargetID:  e.Target,
		Metadata:  meta,
		IPAddress: ip,
		UserAgent: ua,
	}); err != nil {
		slog.Warn("audit: write failed", "event", e.Type, "err", err)
	}
}

// Convenience helpers

// FromRequest extracts the client IP and User-Agent from r and applies
// them to e. Returns the same event for fluent chaining.
//
//	svc.Log(ctx, audit.FromRequest(r, audit.Event{Type: ..., Target: ...}))
func FromRequest(r *http.Request, e Event) Event {
	e.IP = clientIP(r)
	e.UserAgent = r.UserAgent()
	return e
}

// clientIP returns the best guess at the originating IP. When the server
// runs behind Caddy or Traefik, X-Forwarded-For is the source of truth;
// otherwise RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF is "client, proxy1, proxy2" — first hop is the real client.
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	// RemoteAddr is "host:port"; strip the port.
	addr := r.RemoteAddr
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
