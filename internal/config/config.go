// Package config loads runtime configuration from an optional YAML file
// (defaults) and environment variables (overrides). Secrets are never read
// from YAML; they must come from env or mounted files.
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
	setString(&cfg.MFA.WebAuthnRPName, "WEBAUTHN_RP_NAME")

	// Federation provider credentials — secrets are env-only.
	setString(&cfg.Federation.Google.ClientID, "GOOGLE_CLIENT_ID")
	setString(&cfg.Federation.Google.ClientSecret, "GOOGLE_CLIENT_SECRET")
	setString(&cfg.Federation.GitHub.ClientID, "GITHUB_CLIENT_ID")
	setString(&cfg.Federation.GitHub.ClientSecret, "GITHUB_CLIENT_SECRET")
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
