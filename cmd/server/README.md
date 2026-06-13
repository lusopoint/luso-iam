# `cmd/server` — Server Entry Point

This is the main IAM server. It does no business logic of its own, its job is to load configuration, construct every service in the right order, and finally run the http server.

---

## Responsibilities

1. Load configuration and build logger
2. Connect to postgres and if the AUTO_MIGRATE is enabled it applies the migrations
3. Load or generate the token signing key
4. Construct all core services (sessions, password auth, CAS, OIDC, MFA, federation, email, password reset, audit)
5. Register all http routes
6. We wrap the mux in the global middleware chain (logging, security headers, rate limits, CSRF)
7. Serve http and shut down gracefully on `SIGINT` / `SIGTERM`

A failure at any step before the server starts returns an error from `run()`, which `main()` prints to stderr and exits with code 1.

---

### Signing key behaviour

`crypto.LoadOrGenerate(cfg.SigningKeyPath)`:

- **Path set + file exists** -> the persistent PEM key is loaded, its key ID is logged.
- **Path empty** -> a fresh **ephemeral** key is generated and a warning is logged. All issued tokens become invalid on restart. Acceptable for development only: production must set `SIGNING_KEY_PATH`.

### Email

If `cfg.SMTP.Enabled()` (i.e. `SMTP_HOST` is set), the real SMTP sender is built. Otherwise it is written the full message body to the log instead of delivering it. Same for the password reset service.

### WebAuthn

The WebAuthn Relying Party ID and allowed origins are **derived from `BASE_URL`** via `authmfa.DeriveWebAuthnConfig`, there is no separate WebAuthn URL setting. If `BASE_URL` cannot be parsed into an RP ID, WebAuthn is disabled (logged at startup), TOTP is always available.

---

## Route registration

Each `internal/api/*` package exposes a `Register` and owns its own path prefix. `main.go` only decides **which** packages are mounted and with **which dependencies**:

| Package             | Mounted area                          | Notable wiring                                                                                                                |
| ------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `api/health`        | `/healthz`, `/readyz`, `/metrics`     | Gets the raw `pgxpool` for the readiness check                                                                                |
| `api/cas`           | `/cas/*` (login UI + protocol)        | Receives `ProviderLabels`, per-slug "Continue with ..." button text built from the OIDC federation config                     |
| `api/proxy`         | `/proxy/verify`                       | Shares `AllowedCallbackOrigins` with CAS so the forward-auth callback allowlist and the `rd=` allowlist can never drift apart |
| `api/federation`    | `/oauth/callback/*`                   | Upstream SSO callbacks; needs CAS + MFA services to resume the original flow after login                                      |
| `api/oidc`          | `/oauth2/*`, `/.well-known/*`         | The authorization server                                                                                                      |
| `api/mfa`           | `/mfa/*`                              | Challenge + enrollment UI                                                                                                     |
| `api/passwordreset` | `/password/forgot`, `/password/reset` | Forgot-password flow                                                                                                          |
| `api/admin`         | `/admin/v1/*`                         | Admin REST API                                                                                                                |
| `api/spa`           | `/admin/*` (fallthrough)              | Serves the embedded React app; the SPA owns client-side routing (maybe this would be changed to a docker service)             |

**Root path** (`GET /`) simply redirects to `/admin/`. There is intentionally no landing page, unauthenticated users get bounced to `/cas/login` by the SPA's own auth check.

---

## Middleware

```
RequestID -> Recovery -> AccessLog -> SecurityHeaders -> perRouteLimit -> CSRF -> mux
```

- **SecurityHeaders before rate limiting/CSRF**: so CSP & friends are present even on 429 responses and recovered panics.
- **CSRF after rate limiting**: a rejected CSRF check still passes through logging and still carries security headers.
- **CSRF before the mux**: every state mutating route is covered automatically, handlers don't opt in.

### CSRF

Defined in `main.go`:

| Exempt path                                             | Why                                                                                                      |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke` | Machine-to-machine, authenticated by client credentials, CSRF would break standard OIDC client libraries |
| `/federation/` (callbacks)                              | The OAuth `state` parameter already provides cross-origin protection                                     |
| `/proxy/verify`                                         | Read-only                                                                                                |
| `/metrics`, `/healthz`, `/readyz`                       | Read-only                                                                                                |

### Per-route rate limiting

| Route                   | Limit  | Key                                 | Notes                                                                                                                                                  |
| ----------------------- | ------ | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /cas/login`       | 5/min  | per IP                              | Brute-force protection                                                                                                                                 |
| `POST /password/forgot` | 5/min  | per IP                              | Prevents account enumeration & SMTP DoS, shares the login limiter but with a separate key prefix, so login and forgot don't consume each other's quota |
| `POST /password/reset`  | 5/min  | per IP                              | Defense in depth against token grinding                                                                                                                |
| `POST /oauth2/token`    | 20/min | per `client_id`, falling back to IP | See `tokenLimitKey`                                                                                                                                    |

Limiters are **in-memory**! a restart resets all buckets. Client IPs are resolved through `TrustedProxies` so `X-Forwarded-For` is only respected from configured proxy addresses.

Rate-limited responses return `429` with a `Retry-After`.

---

## Build-time version

```go
var version = "dev"
```

The release pipeline overwrites this via:

```bash
# TODO: on the Dockerfile we set 'dev' we would need to think about version releases
go build -ldflags "-X main.version=v1.2.3" ./cmd/server
```

---

## Adding a new API package

To mount a new handler group, follow the existing pattern:

1. Create `internal/api/<name>` with a `New(Config) *Handler` and `(*Handler).Register(mux *http.ServeMux)`.
2. Construct its dependencies in `run()` (services live in `internal/auth/*` or similar — never in `main.go`).
3. Call `.Register(mux)` **before** `apispa.Register(mux)` so the SPA fallthrough doesn't shadow your routes.
4. If the new routes are state-mutating browser endpoints, CSRF covers them automatically. If they are machine-to-machine, add them to the CSRF `ExemptPaths` with a comment explaining why.
5. If they need rate limiting, add a case to `perRouteLimit`.
