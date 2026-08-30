# `cmd/server` Server Entry Point

This is the main IAM server. It runs no business logic of its own. Its job is to load configuration, build every service in the right order, and run the HTTP server.

---

## Responsibilities

1. Load the configuration and build the logger.
2. Connect to Postgres. If `AUTO_MIGRATE` is enabled, apply the migrations. (For multi-instance deployments, set `AUTO_MIGRATE=false` and run `cmd/migrate` as a discrete one-shot step instead see `internal/store/README.md`.)
3. Load or generate the token signing key.
4. Build all core services (sessions, password auth, CAS, OIDC, MFA, federation, email, password reset, audit).
5. Register all HTTP routes.
6. Wrap the mux in the global middleware chain (logging, security headers, rate limits, CSRF).
7. Serve HTTP, then shut down gracefully on `SIGINT` or `SIGTERM`.

Any step before the server starts can fail. On failure, `run()` returns an error. `main()` prints the error to stderr and exits with code 1.

---

### Signing key behaviour

`crypto.LoadOrGenerate(cfg.SigningKeyPath)`:

- **Path set and file exists** -> the server loads the persistent PEM key and logs its key ID.
- **Path empty** -> the server generates a fresh **ephemeral** key and logs a warning. All issued tokens become invalid on restart. Use this in development only. Production must set `SIGNING_KEY_PATH`.

### Email

If `cfg.SMTP.Enabled()` returns true (that is, `SMTP_HOST` is set), the server builds the real SMTP sender. Otherwise, the server writes the full message body to the log instead of sending it. The password reset service works the same way.

### WebAuthn

`authmfa.DeriveWebAuthnConfig` derives the WebAuthn Relying Party ID and allowed origins from **`BASE_URL`**. There is no separate WebAuthn URL setting. If the server cannot parse `BASE_URL` into an RP ID, it disables WebAuthn and logs this at startup. TOTP is always available.

---

## Route registration

Each `internal/api/*` package exposes a `Register` method and owns its own path prefix. `main.go` decides only **which** packages to mount and with **which dependencies**:

| Package             | Mounted area                          | Notable wiring                                                                                                                |
| ------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `api/health`        | `/healthz`, `/readyz`, `/metrics`     | Gets the raw `pgxpool` for the readiness check                                                                                |
| `api/cas`           | `/cas/*` (login UI + protocol)        | Receives `ProviderLabels`, the per-slug "Continue with ..." button text built from the OIDC federation config                 |
| `api/proxy`         | `/proxy/verify`                       | Shares `AllowedCallbackOrigins` with CAS so the forward-auth callback allowlist and the `rd=` allowlist can never drift apart |
| `api/federation`    | `/oauth/callback/*`                   | Upstream SSO callbacks. Needs CAS and MFA services to resume the original flow after login                                    |
| `api/oidc`          | `/oauth2/*`, `/.well-known/*`         | The authorization server                                                                                                      |
| `api/mfa`           | `/mfa/*`                              | Challenge and enrolment UI                                                                                                    |
| `api/passwordreset` | `/password/forgot`, `/password/reset` | Forgot-password flow                                                                                                          |
| `api/admin`         | `/admin/v1/*`                         | Admin REST API                                                                                                                |
| `api/spa`           | `/admin/*` (fallthrough)              | Serves the embedded React app. The SPA owns client-side routing. (This may change to a Docker service later.)                 |

The **root path** (`GET /`) redirects to `/admin/`. There is no landing page by design. The SPA's own auth check sends unauthenticated users to `/cas/login`.

---

## Middleware

```
RequestID -> Recovery -> AccessLog -> SecurityHeaders -> perRouteLimit -> CSRF -> mux
```

- **SecurityHeaders runs before rate limiting and CSRF.** This way, CSP and related headers are present even on 429 responses and recovered panics.
- **CSRF runs after rate limiting.** A rejected CSRF check still passes through logging and still carries security headers.
- **CSRF runs before the mux.** It covers every state-mutating route automatically. Handlers do not opt in.

### CSRF

Defined in `main.go`:

| Exempt path                                             | Why                                                                                                              |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke` | Machine-to-machine. Client credentials authenticate the request. CSRF would break standard OIDC client libraries |
| `/federation/` (callbacks)                              | The OAuth `state` parameter already provides cross-origin protection                                             |
| `/proxy/verify`                                         | Read-only                                                                                                        |
| `/metrics`, `/healthz`, `/readyz`                       | Read-only                                                                                                        |

### Per-route rate limiting

| Route                   | Limit  | Key                                 | Notes                                                                                                                                                 |
| ----------------------- | ------ | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /cas/login`       | 5/min  | per IP                              | Brute-force protection                                                                                                                                |
| `POST /password/forgot` | 5/min  | per IP                              | Prevents account enumeration and SMTP DoS. Shares the login limiter with a separate key prefix, so login and forgot do not consume each other's quota |
| `POST /password/reset`  | 5/min  | per IP                              | Defence in depth against token grinding                                                                                                               |
| `POST /oauth2/token`    | 20/min | per `client_id`, falling back to IP | See `tokenLimitKey`                                                                                                                                   |

The limiters are **in-memory**. A restart resets all buckets. The server resolves client IPs through `TrustedProxies`. So it respects `X-Forwarded-For` only from configured proxy addresses.

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
2. Build its dependencies in `run()`. Services live in `internal/auth/*` or similar, never in `main.go`.
3. Call `.Register(mux)` **before** `apispa.Register(mux)`, so the SPA fallthrough does not shadow your routes.
4. If the new routes are state-mutating browser endpoints, CSRF covers them automatically. If they are machine-to-machine, add them to the CSRF `ExemptPaths` with a comment that explains why.
5. If they need rate limiting, add a case to `perRouteLimit`.
