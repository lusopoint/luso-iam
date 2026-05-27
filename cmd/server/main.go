package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apiadmin "github.com/lusopoint/lusoiam/internal/api/admin"
	apicas "github.com/lusopoint/lusoiam/internal/api/cas"
	apifed "github.com/lusopoint/lusoiam/internal/api/federation"
	apihealth "github.com/lusopoint/lusoiam/internal/api/health"
	apimfa "github.com/lusopoint/lusoiam/internal/api/mfa"
	apioidc "github.com/lusopoint/lusoiam/internal/api/oidc"
	apiproxy "github.com/lusopoint/lusoiam/internal/api/proxy"
	apispa "github.com/lusopoint/lusoiam/internal/api/spa"
	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authfed "github.com/lusopoint/lusoiam/internal/auth/federation"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/password"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/config"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
	genericoidc "github.com/lusopoint/lusoiam/internal/federation/generic_oidc"
	"github.com/lusopoint/lusoiam/internal/federation/github"
	"github.com/lusopoint/lusoiam/internal/federation/google"
	"github.com/lusopoint/lusoiam/internal/middleware"
	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// version is overwritten at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// configuration initialization
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// logger
	logger := newLogger(cfg.Log)
	slog.SetDefault(logger)
	logger.Info("starting iam-server",
		"version", version,
		"env", cfg.Env,
		"base_url", cfg.BaseURL,
		"addr", cfg.HTTP.Addr,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// database
	pool, err := postgres.Connect(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("connect db: %w", err)
	}
	defer pool.Close()

	// migrations
	if cfg.AutoMigrate {
		if err := postgres.Migrate(cfg.DB.URL); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	} else {
		logger.Info("auto-migrate disabled; assuming schema is up to date")
	}

	// Signing key
	// LoadOrGenerate: if SIGNING_KEY_PATH is set and the file exists, load
	// the persistent key; otherwise generate a fresh ephemeral key.
	// Ephemeral keys are fine in dev — tokens are invalidated on restart.
	// Production should always set SIGNING_KEY_PATH to a persistent PEM file.
	keys, err := crypto.LoadOrGenerate(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if cfg.SigningKeyPath == "" {
		logger.Warn("SIGNING_KEY_PATH not set — using ephemeral signing key; " +
			"all tokens will be invalidated on restart")
	} else {
		logger.Info("signing key loaded", "path", cfg.SigningKeyPath, "kid", keys.KeyID())
	}

	// core services
	store := postgres.NewStore(pool)
	signer := crypto.NewCookieSigner(cfg.SessionSecret)

	passwordSvc := password.New(store)

	sessionSvc := session.New(session.Config{
		Store:  store,
		Signer: signer,
		Cookie: session.CookieOptions{
			Path:       "/",
			Domain:     cfg.SessionCookieDomain,
			SecureOnly: cfg.CookiesSecure(),
			SameSite:   http.SameSiteLaxMode,
		},
		Lifetime: 24 * time.Hour,
	})

	casSvc := authcas.New(store)
	fedSvc := authfed.New(store)
	oidcSvc := oidcsvc.New(store, keys, cfg.BaseURL)

	// Audit logger — used by admin handlers (and by auth/MFA flows in
	// future phases as more events are wired in).
	auditSvc := audit.New(store)

	// MFA service — TOTP always on; WebAuthn enabled only when BASE_URL
	// is parseable into an RPID and origin (essentially always, in practice).
	rpID, origins := authmfa.DeriveWebAuthnConfig(cfg.BaseURL)
	mfaSvc, err := authmfa.New(authmfa.Config{
		Store:           store,
		Signer:          signer,
		TOTPIssuer:      cfg.MFA.Issuer,
		WebAuthnRPID:    rpID,
		WebAuthnRPName:  cfg.MFA.WebAuthnRPName,
		WebAuthnOrigins: origins,
	})
	if err != nil {
		return fmt.Errorf("init mfa: %w", err)
	}
	if mfaSvc.WebAuthnEnabled() {
		logger.Info("mfa: webauthn enabled", "rp_id", rpID)
	} else {
		logger.Info("mfa: webauthn disabled (could not derive RPID from BASE_URL)")
	}

	// federation providers
	registry := buildRegistry(ctx, cfg, logger)

	// routes
	mux := http.NewServeMux()

	// infrastructure
	apihealth.Register(mux, pool)

	// Build the per-slug display-name overrides for the login page
	// Only OIDC providers carry an operator-supplied display name, the
	// built-in google/github buttons keep their fixed labels
	providerLabels := map[string]string{}
	for _, p := range cfg.Federation.OIDC {
		if p.DisplayName != "" {
			providerLabels[p.Slug] = "Continue with " + p.DisplayName
		}
	}

	apicas.New(apicas.Config{
		Password:             passwordSvc,
		Sessions:             sessionSvc,
		CAS:                  casSvc,
		Registry:             registry,
		MFA:                  mfaSvc,
		Signer:               signer,
		CookieSecure:         cfg.CookiesSecure(),
		Audit:                auditSvc,
		ProxyCallbackOrigins: cfg.Proxy.AllowedCallbackOrigins,
	}).Register(mux)

	// Reverse-proxy companion: Caddy `forward_auth` / Traefik
	// `ForwardAuth`. Same allowlist as /cas/login's `rd=` parameter so
	// the two endpoints can't drift on what's a legitimate callback.
	apiproxy.New(apiproxy.Config{
		Sessions:               sessionSvc,
		Store:                  store,
		BaseURL:                cfg.BaseURL,
		AllowedCallbackOrigins: cfg.Proxy.AllowedCallbackOrigins,
	}).Register(mux)

	// upstream SSO OAuth2 / OIDC callbacks
	apifed.New(apifed.Config{
		Registry: registry,
		FedSvc:   fedSvc,
		Sessions: sessionSvc,
		CASSvc:   casSvc,
		MFA:      mfaSvc,
		Signer:   signer,
		Secure:   cfg.CookiesSecure(),
		Audit:    auditSvc,
	}).Register(mux)

	// OIDC Provider (authorization server)
	apioidc.New(apioidc.Config{
		Service:  oidcSvc,
		Keys:     keys,
		Sessions: sessionSvc,
		BaseURL:  cfg.BaseURL,
	}).Register(mux)

	// MFA challenge + enrollment UI
	apimfa.New(apimfa.Config{
		MFA:      mfaSvc,
		Sessions: sessionSvc,
		Store:    store,
		CAS:      casSvc,
		Signer:   signer,
		Secure:   cfg.CookiesSecure(),
		Audit:    auditSvc,
	}).Register(mux)

	// Admin REST API (consumed by the React SPA at /admin/*).
	apiadmin.New(apiadmin.Config{
		Store:      store,
		Sessions:   sessionSvc,
		Audit:      auditSvc,
		Keys:       keys,
		Federation: registry,
		BaseURL:    cfg.BaseURL,
	}).Register(mux)

	// Admin SPA — serves the React app from web/dist embedded at compile time.
	// Any /admin path that isn't an API route falls through here; the SPA
	// owns client-side routing for /admin/users, /admin/clients, etc.
	apispa.Register(mux)

	// Root: redirect to the admin SPA. The SPA's auth check will bounce
	// unauthenticated users to /cas/login. We deliberately do NOT serve a
	// portal landing page here — there's nothing meaningful to show that
	// isn't already in /admin (for admins) or /mfa/enroll (for everyone).
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	handler := middleware.Chain(mux,
		middleware.RequestID,
		middleware.Recovery(logger),
		middleware.AccessLog(logger),
	)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	// serve until signalled
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http listening", "addr", cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err, ok := <-errCh:
		if ok && err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	// graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown error", "err", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// buildRegistry constructs the federation provider registry from config.
// Providers are only registered when both credentials are set.
// Errors (e.g. discovery doc unreachable) are logged; the provider is skipped.
func buildRegistry(ctx context.Context, cfg config.Config, logger *slog.Logger) *federation.Registry {
	r := federation.NewRegistry()
	base := cfg.BaseURL

	if cfg.Federation.Google.Enabled() {
		r.Register(google.New(google.Config{
			ClientID:     cfg.Federation.Google.ClientID,
			ClientSecret: cfg.Federation.Google.ClientSecret,
			RedirectURL:  base + "/oauth/callback/google",
		}))
		logger.Info("federation: google enabled")
	}

	if cfg.Federation.GitHub.Enabled() {
		r.Register(github.New(github.Config{
			ClientID:     cfg.Federation.GitHub.ClientID,
			ClientSecret: cfg.Federation.GitHub.ClientSecret,
			RedirectURL:  base + "/oauth/callback/github",
		}))
		logger.Info("federation: github enabled")
	}

	// Generic OIDC providers (Microsoft Entra, GitLab, Okta, Auth0,
	// Keycloak, Authentik, Zitadel, custom IdPs: anything OIDC-compliant).
	// Each entry was already validated for completeness in config.Validate,
	// so missing fields here would be a programming error. We still log
	// and skip per-provider discovery failures rather than abort, so a
	// flaky upstream IdP can't take the whole server down at startup
	for _, p := range cfg.Federation.OIDC {
		// A context timeout covers the case where the issuer URL is
		// reachable but slow — without it a misconfigured corporate IdP
		// could stall startup for minutes.
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		prov, err := genericoidc.New(dctx, genericoidc.Config{
			Name:         p.Slug,
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			IssuerURL:    p.IssuerURL,
			RedirectURL:  base + "/oauth/callback/" + p.Slug,
			Scopes:       p.Scopes,
		})
		cancel()
		if err != nil {
			// Log loudly, but keep the server running. The login page
			// just won't show this provider's button until the IdP
			// becomes reachable and the server is restarted.
			logger.Error("federation: oidc provider failed",
				"slug", p.Slug, "issuer", p.IssuerURL, "err", err)
			continue
		}
		r.Register(prov)
		logger.Info("federation: oidc provider enabled",
			"slug", p.Slug, "issuer", p.IssuerURL)
	}

	return r
}

// newLogger builds a structured slog.Logger from LogConfig.
func newLogger(cfg config.LogConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
