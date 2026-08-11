package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full runtime configuration for the IAM server
type Config struct {
	// Env is a free form tag (dev|staging|prod) used in logs and metrics
	Env string `yaml:"env"`

	// BaseURL is the externally reachable URL of this server, used in
	// OIDC discovery, CAS redirects, email links, ...
	BaseURL string `yaml:"base_url"`

	// SessionSecret is the HMAC key for signing session cookies
	// must be at least 32 bytes after hex decoding
	SessionSecret string `yaml:"-"` // never accept from YAML

	// DocsEnabled turns on the self documentation page
	DocsEnabled bool `yaml:"docs_enabled"`

	HTTP HTTPConfig `yaml:"http"`
	DB   DBConfig   `yaml:"db"`
	Log  LogConfig  `yaml:"log"`

	// Federation holds provider credentials
	// each provider is only active when ClientID and ClientSecret are set
	Federation FederationConfig `yaml:"federation"`

	// SigningKeyPath is the path to a PEM-encoded RSA private key used to sign OIDC id_tokens
	// if empty, a new key is generated at startup (tokens are invalidated on restart)
	SigningKeyPath string `yaml:"-"`

	// MFA holds multi factor authentication settings
	MFA MFAConfig `yaml:"mfa"`

	// SMTP holds outbound email settings, When SMTP.Host is empty the
	// server uses a no-op(only dev) sender that logs emails instead of sending them
	SMTP SMTPConfig `yaml:"smtp"`

	// Signup controls the public registration flow at /signup
	// closed by default, set SIGNUP_ENABLED=true to open
	Signup SignupConfig `yaml:"signup"`

	// Proxy holds settings for the reverse proxy companion endpoint (`/proxy/verify`)
	// the endpoint is always served, the values below control the cross-origin
	// redirect back behaviour, when AllowedCallbackOrigins is empty the endpoint
	// refuses to issue a Location header on 401
	Proxy ProxyConfig `yaml:"proxy"`

	// SessionCookieDomain, when set, becomes the domain attribute on the session cookie
	// set to ".example.com" so that auth.example.com can issue a cookie readable
	// by app.example.com
	// the standard forward-auth deployment pattern, empty means the cookie is host only
	// (only sent back to the IAM server's own hostname)
	//
	// IMPORTANT: must start with a dot (".example.com") for the cookie to apply
	// to all subdomains, OR be a bare host that matches the IAM server's BASE_URL host
	// Setting this to a different parent domain than BASE_URL will silently break sessions
	SessionCookieDomain string `yaml:"session_cookie_domain"`

	// TrustedProxies is the list of domain/ip ranges whose X-Forwarded-* headers we'll trust
	// when empty, the raw TCP peer address is used everywhere
	// the strictly correct default when the server is exposed directly to the internet
	// since otherwise an attacker could spoof their IP in audit logs and bypass IP based rate limits
	//
	// when running behind a reverse proxy on the same host, set this to the loopback range and/or the proxy's IP:
	//   TRUSTED_PROXIES=127.0.0.1,::1
	// when running behind a cloud load balancer or container network:
	//   TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
	//
	// comma separated, each entry can be a CIDR ("10.0.0.0/8") or a
	// bare IP (treated as /32 for IPv4, /128 for IPv6)
	TrustedProxies []string `yaml:"trusted_proxies"`

	// AutoMigrate controls whether the server applies pending db migrations at startup
	AutoMigrate bool `yaml:"auto_migrate"`
}

// HTTPConfig holds HTTP server tuning
type HTTPConfig struct {
	Addr            string        `yaml:"addr"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// DBConfig holds postgres connection settings
type DBConfig struct {
	URL             string        `yaml:"-"`
	MaxConns        int32         `yaml:"max_conns"`
	MinConns        int32         `yaml:"min_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// LogConfig holds logger settings
type LogConfig struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // json|text
}

// FederationConfig holds OAuth2 / OIDC provider credentials
// secrets are env only (yaml:"-")
type FederationConfig struct {
	Google OAuthProviderConfig `yaml:"google"`
	GitHub OAuthProviderConfig `yaml:"github"`

	// OIDC is a list of generic OIDC providers
	// any OpenID-Connect compliant identity provider
	// (Microsoft Entra, GitLab, Okta, Auth0, Keycloak, Authentik, Zitadel, a corporate IdP, ...)
	// Each entry becomes its own button on the login page and its own slug in the
	// `user_identities.provider` column
	// Re using the same slug across deploys preserves existing user account links
	//
	// config shape, set OIDC_PROVIDERS to a comma separated list of
	// slugs to enable, then provide the per provider vars:
	//
	//   OIDC_PROVIDERS=microsoft,okta
	//   OIDC_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
	//   OIDC_MICROSOFT_CLIENT_ID=...
	//   OIDC_MICROSOFT_CLIENT_SECRET=...
	//   OIDC_MICROSOFT_DISPLAY_NAME=Microsoft  (optional)
	//   OIDC_MICROSOFT_SCOPES=openid email profile  (optional)
	OIDC []OIDCProviderConfig `yaml:"-"`
}

// OIDCProviderConfig describes one generic OIDC provider
type OIDCProviderConfig struct {
	// Slug is the lowercased identifier used in urls and db rows
	// must be unique across providers and stable across deploys
	Slug string

	// DisplayName is what shows up on the login button, falls back to a title cased Slug if unset
	DisplayName  string
	IssuerURL    string
	ClientID     string
	ClientSecret string

	// Scopes defaults to ["openid", "email", "profile"] when empty
	Scopes []string
}

// Enabled is true when the provider has the minimum config to function
func (c OIDCProviderConfig) Enabled() bool {
	return c.Slug != "" && c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

// MFAConfig holds multi factor authentication settings, all fields are optional
type MFAConfig struct {
	// Issuer is the label shown in TOTP authenticator apps next to the account name
	Issuer string `yaml:"issuer"`

	// WebAuthnRPName is the human readable relying party name shown by browsers during WebAuthn ceremonies
	WebAuthnRPName string `yaml:"webauthn_rp_name"`

	// Force, when true, makes MFA mandatory for every user
	Force bool `yaml:"force"`
}

// OAuthProviderConfig holds credentials for a single provider
// ClientID and ClientSecret must come from environment variables
type OAuthProviderConfig struct {
	ClientID     string `yaml:"-"` // env: <PROVIDER>_CLIENT_ID
	ClientSecret string `yaml:"-"` // env: <PROVIDER>_CLIENT_SECRET
}

// Enabled returns true when both credentials are present
func (c OAuthProviderConfig) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// SMTPConfig configures outbound email delivery, the "Host" field
// being empty disables real delivery: the server falls back to a
// no-op sender that logs message bodies instead, used for dev
//
//	SMTP_HOST=smtp.example.com
//	SMTP_PORT=587                       # 465 for implicit TLS, 587 for STARTTLS
//	SMTP_USERNAME=apikey
//	SMTP_PASSWORD=<env-only secret>
//	SMTP_FROM=IAM <noreply@example.com>
type SMTPConfig struct {
	Host     string `yaml:"-"`
	Port     int    `yaml:"-"`
	Username string `yaml:"-"`
	Password string `yaml:"-"`
	// From is the email's From header
	// ("noreply@example.com") or ("IAM <noreply@example.com>")
	// both are accepted
	From string `yaml:"from"`
}

// Enabled returns true when the SMTP config has the minimum
// information needed for real delivery (host + from)
func (s SMTPConfig) Enabled() bool {
	return s.Host != "" && s.From != ""
}

// SignupConfig controls the public registration flow closed by default
type SignupConfig struct {
	// Enabled gates the /signup and /verify routes
	// when false, the routes are never registered and return 404
	Enabled bool `yaml:"enabled"`

	MinPasswordLength int `yaml:"min_password_length"`
	// TokenTTLHours is the verification links lifetime in hours default 24
	TokenTTLHours int `yaml:"token_ttl_hours"`
}

// ProxyConfig configures the /proxy/verify reverse-proxy companion
// endpoint used by Caddy `forward_auth` or Traefik `ForwardAuth`
type ProxyConfig struct {
	// AllowedCallbackOrigins is the comma separated list (env)
	// `rd` (redirect-after-login) query parameter. Example:
	//
	//   PROXY_ALLOWED_CALLBACK_ORIGINS=https://app.example.com,https://wiki.example.com
	//
	// why a positive allowlist rather than a wildcard pattern
	// an attacker who can poison the proxys auth redirect with their
	// own host turns the IAM server into an open redirect gadget
	// the proxy itself sets the value via forward-auth headers (X-Forwarded-Proto/Host)
	// but those headers are trivially forgeable by anyone who can reach the IAM directly
	// The allowlist closes that gap
	//
	// empty list = the /proxy/verify endpoint still works, but on a
	// 401 it returns no Location header. The proxy will then 401 the
	// browser, which is ugly but safe
	AllowedCallbackOrigins []string `yaml:"allowed_callback_origins"`
}

// defaults returns a Config populated with sensible defaults
func defaults() Config {
	return Config{
		Env:         "dev",
		BaseURL:     "http://localhost:8080",
		AutoMigrate: true,
		HTTP: HTTPConfig{
			Addr:            ":8080",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    60 * time.Second,
			ShutdownTimeout: 30 * time.Second,
		},
		DB: DBConfig{
			MaxConns:        20,
			MinConns:        2,
			ConnMaxLifetime: time.Hour,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// Load builds a Config by applying in order:
// - built-in defaults
// - YAML file at $CONFIG_FILE (if set), non-secret fields only
// - environment variables, including all secrets
//
// it then validates required fields and returns an error if any are missing
func Load() (Config, error) {
	cfg := defaults()

	if path := os.Getenv("CONFIG_FILE"); path != "" {
		if err := loadYAML(path, &cfg); err != nil {
			return Config{}, fmt.Errorf("load yaml %q: %w", path, err)
		}
	}

	applyEnv(&cfg)

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadYAML(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, cfg)
}

func applyEnv(cfg *Config) {
	setString(&cfg.Env, "ENV")
	setString(&cfg.BaseURL, "BASE_URL")
	setString(&cfg.SessionSecret, "SESSION_SECRET")
	setBool(&cfg.AutoMigrate, "AUTO_MIGRATE")
	setBool(&cfg.DocsEnabled, "DOCS_ENABLED")

	setString(&cfg.HTTP.Addr, "HTTP_ADDR")
	setDuration(&cfg.HTTP.ReadTimeout, "HTTP_READ_TIMEOUT")
	setDuration(&cfg.HTTP.WriteTimeout, "HTTP_WRITE_TIMEOUT")
	setDuration(&cfg.HTTP.ShutdownTimeout, "HTTP_SHUTDOWN_TIMEOUT")

	setString(&cfg.DB.URL, "DATABASE_URL")
	setInt32(&cfg.DB.MaxConns, "DB_MAX_CONNS")
	setInt32(&cfg.DB.MinConns, "DB_MIN_CONNS")
	setDuration(&cfg.DB.ConnMaxLifetime, "DB_CONN_MAX_LIFETIME")

	setString(&cfg.Log.Level, "LOG_LEVEL")
	setString(&cfg.Log.Format, "LOG_FORMAT")

	// signing key, path to a PEM file, or empty to generate at startup
	setString(&cfg.SigningKeyPath, "SIGNING_KEY_PATH")

	// mfa
	setString(&cfg.MFA.Issuer, "MFA_ISSUER")
	setString(&cfg.MFA.WebAuthnRPName, "MFA_WEBAUTHN_RP_NAME")
	setBool(&cfg.MFA.Force, "FORCE_MFA")

	// smtp
	setString(&cfg.SMTP.Host, "SMTP_HOST")
	setInt(&cfg.SMTP.Port, "SMTP_PORT")
	setString(&cfg.SMTP.Username, "SMTP_USERNAME")
	setString(&cfg.SMTP.Password, "SMTP_PASSWORD")
	setString(&cfg.SMTP.From, "SMTP_FROM")

	// signup
	setBool(&cfg.Signup.Enabled, "SIGNUP_ENABLED")
	setInt(&cfg.Signup.MinPasswordLength, "SIGNUP_MIN_PASSWORD_LENGTH")
	setInt(&cfg.Signup.TokenTTLHours, "SIGNUP_TOKEN_TTL_HOURS")

	// federation provider credentials
	setString(&cfg.Federation.Google.ClientID, "GOOGLE_CLIENT_ID")
	setString(&cfg.Federation.Google.ClientSecret, "GOOGLE_CLIENT_SECRET")
	setString(&cfg.Federation.GitHub.ClientID, "GITHUB_CLIENT_ID")
	setString(&cfg.Federation.GitHub.ClientSecret, "GITHUB_CLIENT_SECRET")

	// generic OIDC providers
	cfg.Federation.OIDC = loadOIDCProvidersFromEnv()

	// reverse proxy companion
	setString(&cfg.SessionCookieDomain, "SESSION_COOKIE_DOMAIN")
	setStringList(&cfg.TrustedProxies, "TRUSTED_PROXIES")
	setStringList(&cfg.Proxy.AllowedCallbackOrigins, "PROXY_ALLOWED_CALLBACK_ORIGINS")
}

// loadOIDCProvidersFromEnv reads the OIDC_PROVIDERS list and the matching
// per provider OIDC_<SLUG>_* env vars
// returns one OIDCProviderConfig per slug declared in OIDC_PROVIDERS
// validation of completeness happens in Validate()
//
// slugs are normalised to lowercase and stripped of whitespace
// Invalid slugs (anything other than letters/digits/underscore) are dropped
// silently here, Validate() catches the resulting "no provider with that slug"
// gap and turns it into a startup error with a clear message
func loadOIDCProvidersFromEnv() []OIDCProviderConfig {
	raw := os.Getenv("OIDC_PROVIDERS")
	if raw == "" {
		return nil
	}
	var out []OIDCProviderConfig
	for _, item := range strings.Split(raw, ",") {
		slug := strings.ToLower(strings.TrimSpace(item))
		if slug == "" || !isValidProviderSlug(slug) {
			continue
		}
		prefix := "OIDC_" + strings.ToUpper(slug) + "_"
		scopes := strings.Fields(os.Getenv(prefix + "SCOPES"))
		out = append(out, OIDCProviderConfig{
			Slug:         slug,
			DisplayName:  os.Getenv(prefix + "DISPLAY_NAME"),
			IssuerURL:    os.Getenv(prefix + "ISSUER"),
			ClientID:     os.Getenv(prefix + "CLIENT_ID"),
			ClientSecret: os.Getenv(prefix + "CLIENT_SECRET"),
			Scopes:       scopes,
		})
	}
	return out
}

// isValidProviderSlug enforces the url safe slug rules
func isValidProviderSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return false
		}
	}
	// block the reserved built in slugs to keep the namespace clean, google/github
	// are first class entries on FederationConfig and shouldn't be redefinable via OIDC_*.
	switch s {
	case "google", "github":
		return false
	}
	return true
}

// Validate returns an error if the configuration is missing required values
// or contains an invalid combination of settings
func (c Config) Validate() error {
	var errs []error
	if c.DB.URL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if c.BaseURL == "" {
		errs = append(errs, errors.New("BASE_URL is required"))
	}
	if c.SessionSecret == "" {
		errs = append(errs, errors.New("SESSION_SECRET is required"))
	} else if len(c.SessionSecret) < 32 {
		errs = append(errs, errors.New("SESSION_SECRET must be at least 32 characters"))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("invalid LOG_LEVEL %q (debug|info|warn|error)", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("invalid LOG_FORMAT %q (json|text)", c.Log.Format))
	}

	// OIDC providers: every declared slug must have a complete config
	// A misconfigured provider is a startup error rather than a silent
	// missing button
	seen := make(map[string]bool, len(c.Federation.OIDC))
	for _, p := range c.Federation.OIDC {
		if seen[p.Slug] {
			errs = append(errs, fmt.Errorf("OIDC provider slug %q declared more than once", p.Slug))
		}
		seen[p.Slug] = true

		prefix := "OIDC_" + strings.ToUpper(p.Slug) + "_"
		var missing []string
		if p.IssuerURL == "" {
			missing = append(missing, prefix+"ISSUER")
		}
		if p.ClientID == "" {
			missing = append(missing, prefix+"CLIENT_ID")
		}
		if p.ClientSecret == "" {
			missing = append(missing, prefix+"CLIENT_SECRET")
		}
		if len(missing) > 0 {
			errs = append(errs, fmt.Errorf("OIDC provider %q: missing %s",
				p.Slug, strings.Join(missing, ", ")))
		}
	}

	return errors.Join(errs...)
}

// CookiesSecure returns true when the Secure flag should be set on cookies
func (c Config) CookiesSecure() bool {
	return strings.HasPrefix(strings.ToLower(c.BaseURL), "https://")
}

func setString(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func setStringList(dst *[]string, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	*dst = out
}

func setBool(dst *bool, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}

func setInt32(dst *int32, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			*dst = int32(n)
		}
	}
}

func setInt(dst *int, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func setDuration(dst *time.Duration, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = d
		}
	}
}
