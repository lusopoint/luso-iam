package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	apiadmin "github.com/lusopoint/lusoiam/internal/api/admin"
	apicas "github.com/lusopoint/lusoiam/internal/api/cas"
	apifed "github.com/lusopoint/lusoiam/internal/api/federation"
	apihealth "github.com/lusopoint/lusoiam/internal/api/health"
	apimfa "github.com/lusopoint/lusoiam/internal/api/mfa"
	apioidc "github.com/lusopoint/lusoiam/internal/api/oidc"
	apipwreset "github.com/lusopoint/lusoiam/internal/api/passwordreset"
	apiproxy "github.com/lusopoint/lusoiam/internal/api/proxy"
	apisignup "github.com/lusopoint/lusoiam/internal/api/signup"
	apispa "github.com/lusopoint/lusoiam/internal/api/spa"
	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authfed "github.com/lusopoint/lusoiam/internal/auth/federation"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/password"
	authpwreset "github.com/lusopoint/lusoiam/internal/auth/passwordreset"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	authsignup "github.com/lusopoint/lusoiam/internal/auth/signup"
	"github.com/lusopoint/lusoiam/internal/config"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/email"
	emailnoop "github.com/lusopoint/lusoiam/internal/email/noop"
	emailsmtp "github.com/lusopoint/lusoiam/internal/email/smtp"
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
	// only if the AUTO_MIGRATE is enabled
	if cfg.AutoMigrate {
		if err := postgres.Migrate(cfg.DB.URL); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	} else {
		logger.Info("auto-migrate disabled; assuming schema is up to date")
	}

	// signing key
	keys, err := crypto.LoadOrGenerate(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if cfg.SigningKeyPath == "" {
		logger.Warn("SIGNING_KEY_PATH not set: using ephemeral signing key; " +
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
	// audit logger, basically used by admin handlers
	auditSvc := audit.New(store)
	// MFA service — TOTP always on; WebAuthn enabled only when BASE_URL
	// is parseable into an RPID and origin (essentially always, in practice).
	rpID, origins := authmfa.DeriveWebAuthnConfig(cfg.BaseURL)
	mfaSvc, err := authmfa.New(authmfa.Config{
		Store:           store,
		Signer:          signer,
		TOTPIssuer:      cfg.MFA.Issuer,
		ForceMFA:        cfg.MFA.Force,
		WebAuthnRPID:    rpID,
		WebAuthnRPName:  cfg.MFA.WebAuthnRPName,
		WebAuthnOrigins: origins,
	})
	if err != nil {
		return fmt.Errorf("init mfa: %w", err)
	}
	if cfg.MFA.Force {
		logger.Info("mfa: enforcement is global (FORCE_MFA=true)")
	}
	if mfaSvc.WebAuthnEnabled() {
		logger.Info("mfa: webauthn enabled", "rp_id", rpID)
	} else {
		logger.Info("mfa: webauthn disabled (could not derive RPID from BASE_URL)")
	}

	// email sender
	// development mode it will be logged in the looger
	// production we need to set SMTP_HOST + SMTP_FROM
	var sender email.Sender
	if cfg.SMTP.Enabled() {
		s, err := emailsmtp.New(emailsmtp.Config{
			Host:     cfg.SMTP.Host,
			Port:     cfg.SMTP.Port,
			Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password,
			From:     cfg.SMTP.From,
		})
		if err != nil {
			return fmt.Errorf("init smtp: %w", err)
		}
		sender = s
		logger.Info("email: smtp configured",
			"host", cfg.SMTP.Host,
			"port", cfg.SMTP.Port,
			"from", cfg.SMTP.From,
		)
	} else {
		sender = emailnoop.New(logger)
		logger.Warn("email: SMTP_HOST not set; using no-op sender (emails will be LOGGED, not delivered)")
	}

	// password reset, same thing applies here
	pwResetSvc, err := authpwreset.New(authpwreset.Config{
		Store:   store,
		Sender:  sender,
		BaseURL: cfg.BaseURL,
		From:    fallback(cfg.SMTP.From, "IAM <noreply@lusupoint.com>"),
	})
	if err != nil {
		return fmt.Errorf("init passwordreset: %w", err)
	}

	// signup only enabled if SIGNUP_ENABLED is true
	var signupSvc *authsignup.Service
	if cfg.Signup.Enabled {
		if !cfg.SMTP.Enabled() {
			logger.Warn("signup: SIGNUP_ENABLED=true but SMTP is not configured; verification emails will only be logged, not delivered")
		}
		ttl := time.Duration(cfg.Signup.TokenTTLHours) * time.Hour
		signupSvc, err = authsignup.New(authsignup.Config{
			Store:             store,
			Sender:            sender,
			BaseURL:           cfg.BaseURL,
			From:              fallback(cfg.SMTP.From, "IAM <noreply@lusopoint.com>"),
			TokenTTL:          ttl,
			MinPasswordLength: cfg.Signup.MinPasswordLength,
		})
		if err != nil {
			return fmt.Errorf("init signup: %w", err)
		}
		logger.Info("signup: enabled", "min_password_length", signupSvc.MinPasswordLength(), "token_ttl", signupSvc.TokenTTL())
	}

	// federation providers
	registry := buildRegistry(ctx, cfg, logger)

	// routes
	mux := http.NewServeMux()
	apihealth.Register(mux, pool)

	// CAS 1.0 / 2.0 / 3.0
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
		ProviderLabels:       providerLabels,
		SignupEnabled:        cfg.Signup.Enabled,
	}).Register(mux)

	// reverse-proxy
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

	//password reset
	apipwreset.New(pwResetSvc).Register(mux)

	// signup + email verification
	if signupSvc != nil {
		apisignup.New(signupSvc, auditSvc).Register(mux)
	}

	// admin REST API
	apiadmin.New(apiadmin.Config{
		Store:      store,
		Sessions:   sessionSvc,
		Audit:      auditSvc,
		Keys:       keys,
		Federation: registry,
		BaseURL:    cfg.BaseURL,
	}).Register(mux)

	// Admin SPA, serves the react from web/dist embedded at compile time
	apispa.Register(mux)

	// redirect to /admin
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	// parse TRUSTED_PROXIES once and share across middlewares that
	// need to derive the real client IP from X-Forwarded-For
	trustedProxies := middleware.NewTrustedProxies(strings.Join(cfg.TrustedProxies, ","))

	// Rate limiters
	loginLimiter := middleware.NewLimiter(5, time.Minute)
	tokenLimiter := middleware.NewLimiter(20, time.Minute)
	defer loginLimiter.Close()
	defer tokenLimiter.Close()

	// perRouteLimit wraps the mux to apply per-route rate limits
	// we don't use the middleware based wrapper from the rate limit
	// package because Go stdlib mux doesn't support per-route
	perRouteLimit := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == "/cas/login":
				ip := trustedProxies.ClientIP(r)
				if ok, retry := loginLimiter.Allow("login:" + ip); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retry))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"type":"about:blank","title":"Too Many Requests","status":429,"detail":"login rate limit exceeded; wait and try again"}`))
					return
				}
			case r.Method == "POST" && r.URL.Path == "/password/forgot":
				ip := trustedProxies.ClientIP(r)
				if ok, retry := loginLimiter.Allow("forgot:" + ip); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retry))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"type":"about:blank","title":"Too Many Requests","status":429,"detail":"reset-request rate limit exceeded"}`))
					return
				}
			case r.Method == "POST" && r.URL.Path == "/password/reset":
				ip := trustedProxies.ClientIP(r)
				if ok, retry := loginLimiter.Allow("reset:" + ip); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retry))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"type":"about:blank","title":"Too Many Requests","status":429,"detail":"reset rate limit exceeded"}`))
					return
				}
			case r.Method == "POST" && r.URL.Path == "/signup":
				ip := trustedProxies.ClientIP(r)
				if ok, retry := loginLimiter.Allow("signup:" + ip); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retry))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"type":"about:blank","title":"Too Many Requests","status":429,"detail":"signup rate limit exceeded"}`))
					return
				}
			case r.Method == "POST" && r.URL.Path == "/oauth2/token":
				key := tokenLimitKey(r, trustedProxies)
				if ok, retry := tokenLimiter.Allow(key); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(retry))
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":"too_many_requests","error_description":"token endpoint rate limit exceeded"}`))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}

	// SecurityHeaders runs early so its response headers are present even on rate-limit 429s and recovery panics
	csrfMW := middleware.NewCSRF(middleware.CSRFConfig{
		Secure: cfg.CookiesSecure(),
		ExemptPaths: []string{
			"/oauth2/token",
			"/oauth2/introspect",
			"/oauth2/revoke",
			"/federation/", // covers /federation/<slug>/callback (provider redirects)
			"/proxy/verify",
			"/metrics",
			"/healthz",
			"/readyz",
		},
	})

	handler := middleware.Chain(mux,
		middleware.RequestID,
		middleware.Recovery(logger),
		middleware.AccessLog(logger, trustedProxies),
		middleware.SecurityHeaders(cfg.CookiesSecure()),
		perRouteLimit,
		csrfMW,
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

// buildRegistry constructs the federation provider registry from config
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

	// generic OIDC providers
	// each entry was already validated for completeness in config.Validate
	// so missing fields here would be a programming error, we still log
	// and skip per provider discovery failures rather than abort
	for _, p := range cfg.Federation.OIDC {
		// a context timeout covers the case where the issuer URL is reachable but slow
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

// newLogger builds a structured slog.Logger from LogConfig
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

// tokenLimitKey computes the rate-limit key for /oauth2/token requests
func tokenLimitKey(r *http.Request, tp *middleware.TrustedProxies) string {
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return "token:client:" + id
	}
	if id := r.URL.Query().Get("client_id"); id != "" {
		return "token:client:" + id
	}
	return "token:ip:" + tp.ClientIP(r)
}

// used to derive an email From header when SMTP is in noop mode
func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
