package audit

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
	"log/slog"
	"net/http"
	"strings"
)

type Service struct {
	store *postgres.Store
}

func New(store *postgres.Store) *Service {
	return &Service{store: store}
}

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
	EventEmailVerified       = "email_verified"
	EventClientCreated       = "client_created"
	EventClientUpdated       = "client_updated"
	EventClientDeleted       = "client_deleted"
	EventClientSecretRotated = "client_secret_rotated"
	EventCASServiceCreated   = "cas_service_created"
	EventCASServiceUpdated   = "cas_service_updated"
	EventCASServiceDeleted   = "cas_service_deleted"
)

// Event is the input to Log. Fields are optional except EventType
// Metadata accepts any map; it is marshalled to JSON before storage
type Event struct {
	Type     string
	Actor    *pgtype.UUID
	Target   *pgtype.UUID
	Metadata map[string]any

	// IP and UserAgent are typically pulled from the request via FromRequest
	IP        string
	UserAgent string
}

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

// svc.Log(ctx, audit.FromRequest(r, audit.Event{Type: ..., Target: ...}))
func FromRequest(r *http.Request, e Event) Event {
	e.IP = clientIP(r)
	e.UserAgent = r.UserAgent()
	return e
}

// clientIP returns the best guess at the originating IP. When the server runs behind Caddy or Traefik
// X-Forwarded-For is the source of truth;
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF is "client, proxy1, proxy2", first hop is the real client.
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	// RemoteAddr is "host:port"; strip the port
	addr := r.RemoteAddr
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
