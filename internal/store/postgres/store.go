package postgres

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is the canonical store error for missing rows
// higher layers translate this to HTTP 404 or domain-specific errors
var ErrNotFound = errors.New("store: not found")

// Store is the data-access layer, methods are grouped by entity into
// separate files (users.go, sessions.go, ...) but share the underlying pool exposed here
//
// all methods accept context.Context as the first argument and use it
// for the underlying query, callers are responsible for setting timeouts and cancellation
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool exposes the underlying pgxpool
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

type User struct {
	ID              pgtype.UUID
	Email           *string
	Username        *string
	DisplayName     *string `db:"display_name"`
	FirstName       *string `db:"first_name"`
	LastName        *string `db:"last_name"`
	Status          string
	IsAdmin         bool       `db:"is_admin"`
	EmailVerifiedAt *time.Time `db:"email_verified_at"`
	LastLoginAt     *time.Time `db:"last_login_at"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
	DeletedAt       *time.Time `db:"deleted_at"`
}
type Credential struct {
	UserID            pgtype.UUID `db:"user_id"`
	PasswordHash      string      `db:"password_hash"`
	PasswordChangedAt time.Time   `db:"password_changed_at"`
	MustChange        bool        `db:"must_change"`
	FailedAttempts    int32       `db:"failed_attempts"`
	LockedUntil       *time.Time  `db:"locked_until"`
	CreatedAt         time.Time   `db:"created_at"`
	UpdatedAt         time.Time   `db:"updated_at"`
}
type Session struct {
	ID         pgtype.UUID
	UserID     pgtype.UUID `db:"user_id"`
	ExpiresAt  time.Time   `db:"expires_at"`
	LastSeenAt time.Time   `db:"last_seen_at"`
	IPAddress  *string     `db:"ip_address"`
	UserAgent  *string     `db:"user_agent"`
	CreatedAt  time.Time   `db:"created_at"`
	RevokedAt  *time.Time  `db:"revoked_at"`
	ACR        string      `db:"acr"`
	// ["pwd"], ["pwd","otp"], ["fed"], ["hwk"]
	AMR []string `db:"amr"`
}

type UserMFAMethod struct {
	ID          pgtype.UUID
	UserID      pgtype.UUID `db:"user_id"`
	Method      string      // "totp" | "webauthn"
	Name        *string
	Secret      *string    // TOTP base32 secret
	Credential  []byte     `db:"credential"` // WebAuthn credential JSON
	Counter     int64      // WebAuthn signature counter
	ConfirmedAt *time.Time `db:"confirmed_at"`
	LastUsedAt  *time.Time `db:"last_used_at"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
}

// UserBackupCode is a row from user_backup_codes
type UserBackupCode struct {
	ID        pgtype.UUID
	UserID    pgtype.UUID `db:"user_id"`
	CodeHash  string      `db:"code_hash"`
	UsedAt    *time.Time  `db:"used_at"`
	CreatedAt time.Time   `db:"created_at"`
}

// CASService is a registered CAS service URL pattern
type CASService struct {
	ID                 pgtype.UUID
	Name               string
	ServiceURLPattern  string `db:"service_url_pattern"`
	MatchPattern       string `db:"match_pattern"`
	Description        *string
	ReleasedAttributes []string `db:"released_attributes"`
	RequireAllowlist   bool     `db:"require_allowlist"`
	Enabled            bool
	CreatedAt          time.Time  `db:"created_at"`
	UpdatedAt          time.Time  `db:"updated_at"`
	DeletedAt          *time.Time `db:"deleted_at"`
}

// AllowlistEntry is a row from service_email_allowlist
// a service (an OIDC client or a CAS service) with require_allowlist=true only admits
// users whose email appears here
type AllowlistEntry struct {
	ID          pgtype.UUID
	ServiceType string `db:"service_type"` // "oidc" | "cas"
	ServiceID   string `db:"service_id"`
	Email       string
	CreatedAt   time.Time `db:"created_at"`
}

type UserIdentity struct {
	ID          pgtype.UUID
	UserID      pgtype.UUID `db:"user_id"`
	Provider    string
	Sub         string
	Email       *string
	DisplayName *string   `db:"display_name"`
	PictureURL  *string   `db:"picture_url"`
	RawClaims   []byte    `db:"raw_claims"` // JSONB
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type CASTicket struct {
	ID         string
	SessionID  pgtype.UUID `db:"session_id"`
	ServiceURL string      `db:"service_url"`
	ExpiresAt  time.Time   `db:"expires_at"`
	ConsumedAt *time.Time  `db:"consumed_at"`
	Renew      bool
	CreatedAt  time.Time `db:"created_at"`
}

type OIDCClient struct {
	ID                string
	SecretHash        *string `db:"secret_hash"` // nil for public clients
	Name              string
	RedirectURIs      []string `db:"redirect_uris"`
	AllowedScopes     []string `db:"allowed_scopes"`
	AllowedGrantTypes []string `db:"allowed_grant_types"`
	IsPublic          bool     `db:"is_public"`
	RequirePKCE       bool     `db:"require_pkce"`
	RequireConsent    bool     `db:"require_consent"`
	RequireAllowlist  bool     `db:"require_allowlist"`
	AccessTokenTTL    Duration `db:"access_token_ttl"`
	RefreshTokenTTL   Duration `db:"refresh_token_ttl"`
	IDTokenTTL        Duration `db:"id_token_ttl"`
	Enabled           bool
	CreatedAt         time.Time  `db:"created_at"`
	UpdatedAt         time.Time  `db:"updated_at"`
	DeletedAt         *time.Time `db:"deleted_at"`
}

// Duration wraps time.Duration for pgx scanning of Postgres interval values
type Duration = time.Duration

// OIDCAuthCode is a row from oidc_auth_codes
type OIDCAuthCode struct {
	ID            string
	ClientID      string      `db:"client_id"`
	UserID        pgtype.UUID `db:"user_id"`
	SessionID     pgtype.UUID `db:"session_id"`
	RedirectURI   string      `db:"redirect_uri"`
	Scopes        []string
	Nonce         *string
	PKCEChallenge *string `db:"pkce_challenge"`
	ACR           string
	AMR           []string
	AuthTime      time.Time  `db:"auth_time"`
	ExpiresAt     time.Time  `db:"expires_at"`
	ConsumedAt    *time.Time `db:"consumed_at"`
	CreatedAt     time.Time  `db:"created_at"`
}

type OIDCAccessToken struct {
	ID        string
	ClientID  string       `db:"client_id"`
	UserID    *pgtype.UUID `db:"user_id"` // nil for client_credentials
	SessionID *pgtype.UUID `db:"session_id"`
	Scopes    []string
	ExpiresAt time.Time  `db:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at"`
	CreatedAt time.Time  `db:"created_at"`
}

type OIDCRefreshToken struct {
	ID         string
	ClientID   string       `db:"client_id"`
	UserID     pgtype.UUID  `db:"user_id"`
	SessionID  *pgtype.UUID `db:"session_id"`
	Scopes     []string
	PreviousID *string    `db:"previous_id"`
	ExpiresAt  time.Time  `db:"expires_at"`
	RotatedAt  *time.Time `db:"rotated_at"`
	RevokedAt  *time.Time `db:"revoked_at"`
	CreatedAt  time.Time  `db:"created_at"`
}

type AuditEvent struct {
	ID        pgtype.UUID
	EventType string       `db:"event_type"`
	ActorID   *pgtype.UUID `db:"actor_id"`
	TargetID  *pgtype.UUID `db:"target_id"`
	Metadata  []byte       // JSONB encoded; callers decode as needed
	IPAddress *string      `db:"ip_address"`
	UserAgent *string      `db:"user_agent"`
	CreatedAt time.Time    `db:"created_at"`
}
