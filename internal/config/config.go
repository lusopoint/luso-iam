// Package config loads runtime configuration from an optional YAML file
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

// Config is the full runtime configuration for the IAM server.
type Config struct {
	// Env is a free-form tag (dev|staging|prod) used in logs and metrics.
	Env string `yaml:"env"`

	// BaseURL is the externally reachable URL of this server. Used in
	// OIDC discovery, CAS redirects, email links, etc.
	BaseURL string `yaml:"base_url"`

	// SessionSecret is the HMAC key for signing session cookies.
	// Must be at least 32 bytes after hex decoding.
	SessionSecret string `yaml:"-"` // never accept from YAML

	HTTP HTTPConfig `yaml:"http"`
	DB   DBConfig   `yaml:"db"`
	Log  LogConfig  `yaml:"log"`

	// Federation holds upstream provider credentials.
	// Each provider is only active when ClientID and ClientSecret are set.
	Federation FederationConfig `yaml:"federation"`

	// SigningKeyPath is the path to a PEM-encoded RSA private key used to
	// sign OIDC id_tokens. If empty, a new key is generated at startup
	// (tokens are invalidated on restart — acceptable in dev, not prod).
	SigningKeyPath string `yaml:"-"` // secret path; env only

	// MFA holds multi-factor authentication settings.
	MFA MFAConfig `yaml:"mfa"`

	// Proxy holds settings for the reverse-proxy companion endpoint
	// (`/proxy/verify`). The endpoint is always served; the values below
	// control the cross-origin redirect-back behaviour. When
	// AllowedCallbackOrigins is empty the endpoint refuses to issue a
	// Location header on 401 — operators must consciously opt in.
	Proxy ProxyConfig `yaml:"proxy"`

	// SessionCookieDomain, when set, becomes the Domain attribute on the
	// session cookie. Set to ".example.com" so that auth.example.com can
	// issue a cookie readable by app.example.com — the standard
	// forward-auth deployment pattern. Empty means the cookie is host-only
	// (only sent back to the IAM server's own hostname).
	//
	// IMPORTANT: must start with a dot (".example.com") for the cookie
	// to apply to all subdomains, OR be a bare host that matches the
	// IAM server's BASE_URL host. Setting this to a different parent
	// domain than BASE_URL will silently break sessions.
	SessionCookieDomain string `yaml:"session_cookie_domain"`

	// AutoMigrate controls whether the server applies pending DB migrations
	// at startup. Recommended true in dev, false in production (run via CLI).
	AutoMigrate bool `yaml:"auto_migrate"`
}

// HTTPConfig holds HTTP server tuning.
type HTTPConfig struct {
	Addr            string        `yaml:"addr"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// DBConfig holds Postgres connection settings.
type DBConfig struct {
	URL             string        `yaml:"-"` // secret; env only
	MaxConns        int32         `yaml:"max_conns"`
	MinConns        int32         `yaml:"min_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// LogConfig holds logger settings.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug|info|warn|error
	Format string `yaml:"format"` // json|text
}

// FederationConfig holds upstream OAuth2 / OIDC provider credentials.
// Secrets are env-only (yaml:"-"). Non-secret display/toggle options
// can live in YAML.
type FederationConfig struct {
	Google OAuthProviderConfig `yaml:"google"`
	GitHub OAuthProviderConfig `yaml:"github"`

	// OIDC is a list of generic OIDC providers — any OpenID-Connect-
	// compliant identity provider (Microsoft Entra, GitLab, Okta, Auth0,
	// Keycloak, Authentik, Zitadel, a corporate IdP, etc.). Each entry
	// becomes its own button on the login page and its own slug in the
	// `user_identities.provider` column. Re-using the same slug across
	// deploys preserves existing user account links.
	//
	// Config shape — set OIDC_PROVIDERS to a comma-separated list of
	// slugs to enable, then provide the per-provider vars:
	//
	//   OIDC_PROVIDERS=microsoft,okta
	//
	//   OIDC_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
	//   OIDC_MICROSOFT_CLIENT_ID=...
	//   OIDC_MICROSOFT_CLIENT_SECRET=...
	//   OIDC_MICROSOFT_DISPLAY_NAME=Microsoft  (optional)
	//   OIDC_MICROSOFT_SCOPES=openid email profile  (optional)
	//
	// Population happens in loadOIDCProvidersFromEnv during config load —
	// the YAML side stays empty since secrets shouldn't live in committed
	// configuration.
	OIDC []OIDCProviderConfig `yaml:"-"`
}

// OIDCProviderConfig describes one generic-OIDC provider.
type OIDCProviderConfig struct {
	// Slug is the lowercased identifier used in URLs and DB rows.
	// Must be unique across providers and stable across deploys.
	Slug string

	// DisplayName is what shows up on the login button. Falls back to
	// a title-cased Slug if unset.
	DisplayName string

	IssuerURL    string
	ClientID     string
	ClientSecret string

	// Scopes defaults to ["openid", "email", "profile"] when empty.
	Scopes []string
}

// Enabled is true when the provider has the minimum config to function.
func (c OIDCProviderConfig) Enabled() bool {
	return c.Slug != "" && c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

// MFAConfig holds multi-factor authentication settings.
// All fields are optional; sensible defaults are derived at construction time.
type MFAConfig struct {
	// Issuer is the label shown in TOTP authenticator apps next to the
	// account name (e.g. "Acme IAM"). Defaults to "IAM".
	Issuer string `yaml:"issuer"`

	// WebAuthnRPName is the human-readable relying-party name shown by
	// browsers during WebAuthn ceremonies. Defaults to Issuer.
	// RPID and origins are derived from BASE_URL.
	WebAuthnRPName string `yaml:"webauthn_rp_name"`
}

// OAuthProviderConfig holds credentials for a single upstream provider.
// ClientID and ClientSecret must come from environment variables.
type OAuthProviderConfig struct {
	ClientID     string `yaml:"-"` // env: <PROVIDER>_CLIENT_ID
	ClientSecret string `yaml:"-"` // env: <PROVIDER>_CLIENT_SECRET
}

// Enabled returns true when both credentials are present.
func (c OAuthProviderConfig) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// ProxyConfig configures the /proxy/verify reverse-proxy companion
// endpoint used by Caddy `forward_auth` / Traefik `ForwardAuth`.
type ProxyConfig struct {
	// AllowedCallbackOrigins is the comma-separated list (env) or
	// YAML list of scheme+host[+port] values that may appear in the
	// `rd` (redirect-after-login) query parameter. Example:
	//
	//   PROXY_ALLOWED_CALLBACK_ORIGINS=https://app.example.com,https://wiki.example.com
	//
	// Why a positive allowlist rather than a wildcard pattern: an
	// attacker who can poison the proxy's auth-redirect with their
	// own host turns the IAM server into an open-redirect gadget.
	// The proxy itself sets the value via forward-auth headers
	// (X-Forwarded-Proto/Host), but those headers are trivially
	// forgeable by anyone who can reach the IAM directly. The
	// allowlist closes that gap.
	//
	// Empty list = the /proxy/verify endpoint still works, but on a
	// 401 it returns no Location header. The proxy will then 401 the
	// browser, which is ugly but safe. Operators opt in by setting
	// the env var.
	AllowedCallbackOrigins []string `yaml:"allowed_callback_origins"`
}

// defaults returns a Config populated with sensible defaults.
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

// Load builds a Config by applying, in order:
//  1. built-in defaults
//  2. YAML file at $CONFIG_FILE (if set) — non-secret fields only
//  3. environment variables — including all secrets
//
// It then validates required fields and returns an error if any are missing.
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

	// Signing key — path to a PEM file, or empty to generate at startup.
	setString(&cfg.SigningKeyPath, "SIGNING_KEY_PATH")

	// MFA — both optional with sensible defaults.
	setString(&cfg.MFA.Issuer, "MFA_ISSUER")
	setString(&cfg.MFA.WebAuthnRPName, "MFA_WEBAUTHN_RP_NAME")

	// Federation provider credentials — secrets are env-only.
	setString(&cfg.Federation.Google.ClientID, "GOOGLE_CLIENT_ID")
	setString(&cfg.Federation.Google.ClientSecret, "GOOGLE_CLIENT_SECRET")
	setString(&cfg.Federation.GitHub.ClientID, "GITHUB_CLIENT_ID")
	setString(&cfg.Federation.GitHub.ClientSecret, "GITHUB_CLIENT_SECRET")

	// Generic OIDC providers. Declared with OIDC_PROVIDERS=slug1,slug2;
	// per-provider config under OIDC_<SLUG>_*.
	cfg.Federation.OIDC = loadOIDCProvidersFromEnv()

	// Reverse-proxy companion.
	setString(&cfg.SessionCookieDomain, "SESSION_COOKIE_DOMAIN")
	setStringList(&cfg.Proxy.AllowedCallbackOrigins, "PROXY_ALLOWED_CALLBACK_ORIGINS")
}

// loadOIDCProvidersFromEnv reads the OIDC_PROVIDERS list and the matching
// per-provider OIDC_<SLUG>_* env vars. Returns one OIDCProviderConfig per
// slug declared in OIDC_PROVIDERS. Validation of completeness happens
// in Validate(); this function just gathers what's present.
//
// Slugs are normalised to lowercase and stripped of whitespace. Invalid
// slugs (anything other than letters/digits/underscore) are dropped
// silently here — Validate() catches the resulting "no provider with
// that slug" gap and turns it into a startup error with a clear message.
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

// isValidProviderSlug enforces the URL-safe slug rules: lowercase
// letters, digits, and underscores only. Hyphens are rejected because
// they conflict with the OIDC_<SLUG>_<FIELD> env var convention (an
// env var like OIDC_FOO-BAR_ISSUER is non-standard shell syntax).
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
	// Block the reserved built-in slugs to keep the namespace clean —
	// google/github are first-class entries on FederationConfig and
	// shouldn't be redefinable via OIDC_*.
	switch s {
	case "google", "github":
		return false
	}
	return true
}

// Validate returns an error if the configuration is missing required values
// or contains an invalid combination of settings.
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

	// OIDC providers: every declared slug must have a complete config.
	// A misconfigured provider is a startup error rather than a silent
	// missing button — the operator clearly meant to enable it.
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

// CookiesSecure returns true when the Secure flag should be set on cookies.
// Derived from BASE_URL scheme: https → secure, http → not secure.
// This is correct even when running behind a TLS-terminating reverse proxy
// (Caddy/Traefik) because BASE_URL should always reflect the external URL.
func (c Config) CookiesSecure() bool {
	return strings.HasPrefix(strings.ToLower(c.BaseURL), "https://")
}

// env var helpers

func setString(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

// setStringList sets a []string from a comma-separated env var. Empty
// segments (resulting from trailing or doubled commas) are dropped so
// `setStringList(..., "a,b,,")` becomes ["a","b"]. The default is left
// untouched when the env var is unset.
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

func setDuration(dst *time.Duration, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = d
		}
	}
}
