# IAM Server Project Guidelines

> An open-source Identity & Access Management server and portal providing MFA, SSO, and OpenID Connect services, with CAS compatibility and reverse-proxy integration.

---

## 1. Project Vision & Goals

| Goal                               | Description                                                                                                                      |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **OpenID Certified OIDC Provider** | Full conformance with OpenID Connect Core 1.0, Discovery, PKCE, and related specs                                                |
| **CAS Gateway**                    | Accept CAS 2.0/3.0 authentication requests and fulfil them via the internal IdP or upstream SSO                                  |
| **Upstream SSO Federation**        | Connect to Google, GitHub, Microsoft, GitLab, Apple, and any OAuth 2 / OIDC provider                                             |
| **MFA**                            | TOTP (RFC 6238), WebAuthn/FIDO2, email/SMS OTP                                                                                   |
| **Reverse Proxy Companion**        | First-class support for Caddy (`forward_auth`) and Traefik (`ForwardAuth`); compatible with any proxy that supports forward-auth |
| **Self-hosted & Open-Source**      | AGPL-3.0 licensed; single-binary deploy; Docker/K8s native                                                                       |

---

## 2. Repository Layout

```
/
├── cmd/
│   └── server/               # Main entry point (main.go)
├── internal/
│   ├── api/                  # HTTP handlers (REST + well-known endpoints)
│   │   ├── cas/              # CAS 2.0 / 3.0 protocol handlers
│   │   ├── oidc/             # OpenID Connect / OAuth 2 handlers
│   │   ├── admin/            # Admin REST API
│   │   └── proxy/            # Forward-auth / auth_request handlers
│   ├── auth/                 # Core authentication logic
│   │   ├── mfa/              # TOTP, WebAuthn, OTP
│   │   ├── session/          # Session management
│   │   └── token/            # JWT / opaque token lifecycle
│   ├── federation/           # Upstream IdP connectors
│   │   ├── google/
│   │   ├── github/
│   │   ├── microsoft/
│   │   └── generic_oidc/     # Generic OIDC upstream
│   ├── store/                # Database layer
│   │   ├── postgres/         # PostgreSQL implementations
│   │   └── migrations/       # SQL migration files (golang-migrate)
│   ├── config/               # Config loading (env + YAML)
│   ├── crypto/               # Key management, JWKS, signing
│   └── middleware/           # Rate limiting, CORS, logging
├── pkg/                      # Exported, reusable packages (no internal deps)
│   ├── cas/                  # CAS protocol types & XML helpers
│   └── oidc/                 # OIDC types & discovery helpers
├── web/                      # React / TypeScript front end
│   ├── src/
│   │   ├── pages/            # Login, MFA, Consent, Error, Admin
│   │   ├── components/       # Shared UI components
│   │   ├── hooks/            # Auth state, API hooks
│   │   ├── store/            # Zustand global state
│   │   ├── api/              # Typed API client (openapi-fetch)
│   │   └── i18n/             # Translations (i18next)
│   ├── public/
│   └── vite.config.ts
├── deployments/
│   ├── docker/               # Dockerfiles
│   ├── k8s/                  # Helm chart
│   └── compose/              # docker-compose.yml for local dev
├── docs/
│   ├── architecture.md
│   ├── protocols/            # CAS, OIDC, proxy integration guides
│   └── api/                  # OpenAPI spec (openapi.yaml)
├── scripts/                  # Build, release, keygen helpers
├── Makefile
└── .golangci.yml
```

---

## 3. Technology Stack

### 3.1 Backend (Go)

| Concern          | Library / Tool                                                      | Rationale                                                                          |
| ---------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| HTTP router      | `net/http` stdlib                                                   | Go 1.22+ native method+path routing; zero dependencies                             |
| DB driver        | `pgx/v5` + `pgxpool`                                                | Postgres-native protocol; required for LISTEN/NOTIFY, arrays, COPY                 |
| Code gen         | `sqlc`                                                              | Dev-time only; generates type-safe query functions from raw SQL; zero runtime cost |
| DB migrations    | `golang-migrate`                                                    | CLI + embedded migrations; well-maintained; not worth reinventing                  |
| JWT              | `golang-jwt/jwt/v5`                                                 | Spec-compliant, audited; JWT has subtle attack surface (alg confusion) justified   |
| JWKS / crypto    | stdlib: `crypto/rsa`, `crypto/ecdsa`, `encoding/base64`, `math/big` | JWKS serialisation is ~100 lines; no external lib needed                           |
| Password hashing | `golang.org/x/crypto` (argon2, bcrypt)                              | Go-team maintained; treated as extended stdlib                                     |
| WebAuthn         | `go-webauthn/webauthn`                                              | 200-page spec with CBOR + attestation parsing; never implement manually            |
| TOTP             | `pquerna/otp`                                                       | Tiny, audited, RFC 6238 edge cases handled                                         |
| Config           | `gopkg.in/yaml.v3` + `os.Getenv`                                    | Simple env loader + one YAML lib; replaces viper and its 15+ transitive deps       |
| Logging          | `log/slog` stdlib                                                   | Go 1.21+; structured, fast, zero dependencies                                      |
| Metrics          | `prometheus/client_golang`                                          | No stdlib alternative for Prometheus exposition format                             |
| Tracing          | `go.opentelemetry.io/otel`                                          | Wire behind an interface; lazy-load; no-op in non-prod builds                      |
| Testing          | stdlib `testing` + `testify` + `testcontainers-go`                  | Real Postgres in CI; testify is tiny and justified                                 |

### 3.2 Frontend (React + TypeScript)

| Concern      | Library / Tool                          |
| ------------ | --------------------------------------- |
| Build        | Vite 5                                  |
| UI framework | React 18 + TypeScript strict mode       |
| Styling      | Tailwind CSS v4 + CSS custom properties |
| i18n         | `i18next` + `react-i18next`             |
| Testing      | Vitest + Testing Library                |

### 3.3 Infrastructure

| Component     | Choice                                       |
| ------------- | -------------------------------------------- |
| Database      | PostgreSQL 16+                               |
| Container     | Docker (multi-stage, distroless final image) |
| Orchestration | Helm chart for Kubernetes (future / P8)      |
| CI            | GitHub Actions                               |
| Release       | GoReleaser (binary + container)              |

---

## 4. Protocol Implementation

### 4.1 CAS (Starting Point)

CAS is the entry-point protocol. Implement in order:

1. **CAS 2.0**: `/cas/login`, `/cas/logout`, `/cas/serviceValidate`
2. **CAS 3.0**: `/cas/p3/serviceValidate` (adds attributes in XML response)
3. **Proxy tickets**: `/cas/proxyValidate`, `/cas/proxy`
4. **SAML 1.1 validation**: `/cas/samlValidate` (optional, widely needed)

**CAS -> SSO bridge:** When a CAS service ticket is requested and the user is not locally authenticated, the server initiates an upstream OIDC/OAuth flow (Google, GitHub, etc.) and maps the returned identity to an internal user record before issuing the CAS ticket.

```
Client App  --CAS login-->  IAM Server  --OIDC flow-->  Google / GitHub
                <-- ST --                  <-- id_token --
Client App  --validate ST--> IAM Server
                <-- user attrs --
```

### 4.2 OpenID Connect / OAuth 2

Implement in conformance order:

| Phase                       | Specs                                                    |
| --------------------------- | -------------------------------------------------------- |
| Core                        | OIDC Core 1.0, OAuth 2.0 RFC 6749                        |
| Discovery                   | OIDC Discovery 1.0 (`/.well-known/openid-configuration`) |
| PKCE                        | RFC 7636 (mandatory for public clients)                  |
| Token introspection         | RFC 7662                                                 |
| Token revocation            | RFC 7009                                                 |
| Dynamic client registration | OIDC DCR 1.0 (RFC 7591)                                  |
| JARM                        | JWT-secured authorization response                       |
| PAR                         | Pushed Authorization Requests RFC 9126                   |
| Device flow                 | RFC 8628                                                 |

**Flows to support**: Authorization Code + PKCE, Client Credentials, Refresh Token. Implicit and Password flows should be disabled by default.

### 4.3 Reverse Proxy Integration

| Proxy                 | Mechanism                | Endpoint            | Config directive                               |
| --------------------- | ------------------------ | ------------------- | ---------------------------------------------- |
| **Caddy** _(primary)_ | `forward_auth` module    | `GET /proxy/verify` | `forward_auth` block in `Caddyfile`            |
| Traefik               | `ForwardAuth` middleware | `GET /proxy/verify` | `middlewares.iam.forwardAuth` in labels / YAML |

> Caddy is the recommended and documented companion proxy. It handles automatic TLS, has a clean `forward_auth` primitive, and pairs naturally with the single-binary deployment model. Traefik remains supported for container/K8s environments.

The `/proxy/verify` endpoint:

- Returns `200` with `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups` headers on success
- Returns `401` with `Location` header pointing to login on failure
- Accepts session cookie **or** `Authorization: Bearer <token>`

---

## 5. Database Schema Conventions

- All tables use `UUID v7` primary keys (time-sortable, index-friendly)
- All timestamps are `TIMESTAMPTZ` stored in UTC
- Soft deletes via `deleted_at TIMESTAMPTZ NULL`
- Every migration has an `up` and `down` file
- Migration files are named `NNNN_description.up.sql` / `.down.sql`

**Core tables:**

```
users              canonical user record
user_credentials   passwords (argon2id hash), passkeys
user_mfa_methods   TOTP secrets, WebAuthn credentials
sessions           browser sessions (sliding expiry)
clients            OIDC/OAuth registered applications
authorization_codes
access_tokens
refresh_tokens
cas_services       registered CAS service URLs
upstream_providers federated IdP configs (Google, GitHub, …)
audit_log          immutable append-only event log
```

---

## 6. Go Backend Conventions

### Package structure rules

- `internal/` packages are not exported; `pkg/` packages may be imported by external projects

- Each `internal/api/*` package registers its routes onto a `*http.ServeMux` and mounts onto the root mux via a prefix

- No circular imports dependency flows: `api -> auth -> store`, never reverse

### Error handling

- Define sentinel errors in each package: `var ErrNotFound = errors.New("not found")`

- Wrap with context: `fmt.Errorf("getUser: %w", err)`

- HTTP handlers translate domain errors to RFC 7807 Problem JSON responses

```go
// Standard Problem JSON response
type Problem struct {
    Type   string `json:"type"`
    Title  string `json:"title"`
    Status int    `json:"status"`
    Detail string `json:"detail,omitempty"`
}
```

### Configuration

- All config via environment variables (12-factor) with an optional YAML overlay

- Secrets (DB password, signing keys) via env or mounted files, never in YAML committed to git

- Signing keys managed as JWKS; support key rotation without restart

### Security defaults

- Passwords hashed with **Argon2id** (time=3, memory=64MB, threads=4)
- Sessions use **HMAC-SHA256** signed cookies, `HttpOnly; Secure; SameSite=Lax`
- CSRF protection on all state-mutating endpoints (double-submit cookie pattern)
- Rate limiting: login endpoint (5 req/min per IP), token endpoint (20 req/min per client)
- Content-Security-Policy headers served by the portal

### Dependency philosophy

Before adding any dependency, answer these questions:

| Question                                                     | Answer -> Action                                      |
| ------------------------------------------------------------ | ----------------------------------------------------- |
| Is it a protocol/spec implementation? (WebAuthn, JWT, TOTP)  | Keep specs have sharp edges and subtle attack surface |
| Is it glue or boilerplate? (routing, config, logging)        | Replace with stdlib equivalent                        |
| Is it a dev-time code generator? (sqlc, migrate)             | Keep zero runtime cost, prevents bug classes          |
| Would implementing it take < 200 lines? (JWKS serialisation) | Implement in `internal/crypto`                        |
| Is it Go-team maintained? (`golang.org/x/*`)                 | Treat as extended stdlib                              |

The **`go.mod` runtime section should stay short.** If a PR adds a new `require` entry, the commit message must justify it against this rubric.

- Unit tests alongside source files (`foo_test.go`)

- Integration tests in `internal/*/testdata/` using `testcontainers-go` for real Postgres

- OIDC conformance: run against official [openid-client conformance suite](https://openid.net/certification/) in CI

---

## 7. Frontend Conventions

### Architecture

- **Pages** map 1:1 to routes: `/login`, `/mfa`, `/consent`, `/error`, `/admin/*`

- **Components** are pure, prop-driven; no direct API calls inside components

- **Hooks** own all API and state logic

- All API calls go through the generated typed client no ad-hoc `fetch()` calls

### Auth flow (browser)

1. User hits protected app -> redirected to `/login?next=...`
2. Login page posts credentials -> server sets session cookie
3. If MFA required -> redirect to `/mfa`
4. On success -> redirect to original destination or consent screen
5. Consent screen (OIDC) -> user grants scopes -> server issues code

### Styling rules

- Use Tailwind utility classes for layout/spacing; CSS variables for brand tokens

- Dark mode via `prefers-color-scheme` + manual toggle stored in `localStorage`

- All interactive elements must meet WCAG 2.1 AA contrast ratios

- No hardcoded pixel values use Tailwind spacing scale

### i18n

- Every user-visible string goes through `t('key')` no raw strings in JSX

- Default locale: `en`; translations in `src/i18n/locales/{locale}.json`

- Locale auto-detected from browser `Accept-Language`, overridable in profile

---

## 8. Federation / Upstream SSO

Each upstream provider is a struct implementing a `Provider` interface:

```go
type Provider interface {
    // Returns the OAuth2 config for this provider
    OAuthConfig() *oauth2.Config
    // Exchanges a code for a normalized Identity
    Exchange(ctx context.Context, code string) (*Identity, error)
    // Returns the provider's OIDC discovery URL (if applicable)
    Issuer() string
}

type Identity struct {
    Sub        string
    Email      string
    Name       string
    Picture    string
    RawClaims  map[string]any
}
```

**Link vs. create:** On upstream callback:

1. Look for an existing `users` record linked to `(provider, sub)`
2. If found -> log in
3. If email matches existing user -> prompt to link accounts
4. Otherwise -> create new user, link provider

**Built-in providers (implement in order):**

1. Google (OIDC)
2. GitHub (OAuth 2 with `/user` + `/user/emails` API)
3. Microsoft / Entra (OIDC)
4. GitLab (OIDC)
5. Apple (OIDC, Sign in with Apple specifics)
6. Generic OIDC (config-driven, covers any OIDC-compliant IdP)
7. Generic OAuth 2 (config-driven, for non-OIDC providers)

---

## 9. MFA Implementation

| Method             | Library                | Notes                                          |
| ------------------ | ---------------------- | ---------------------------------------------- |
| TOTP               | `pquerna/otp`          | RFC 6238; 6-digit, 30s; show QR + backup codes |
| WebAuthn / Passkey | `go-webauthn/webauthn` | Resident keys for passwordless                 |
| Email OTP          | internal               | 6-digit code, 10-min TTL, rate-limited         |
| SMS OTP            | pluggable adapter      | Twilio / AWS SNS adapters                      |
| Backup codes       | internal               | 10 × 8-char codes, bcrypt-stored, single-use   |

MFA enforcement policy is per-client (OIDC `acr_values`) and per-user.

---

## 10. Admin Portal

Expose a REST admin API (`/admin/v1/`) and a React-based admin UI:

| Resource           | Operations                                             |
| ------------------ | ------------------------------------------------------ |
| Users              | CRUD, force password reset, lock/unlock, view sessions |
| Clients            | Register, rotate secrets, manage redirect URIs, scopes |
| CAS Services       | Register service URLs, attribute release policy        |
| Upstream providers | Add/edit/delete federated IdPs                         |
| Audit log          | Search, filter, export                                 |
| Keys               | View active JWKS, trigger rotation                     |

Admin API requires a separate admin session or a machine-to-machine client with `admin` scope.

---

## 11. Audit Logging

Every security-relevant event is written to `audit_log` (append-only, no updates/deletes):

```
login_success, login_failure, logout,
mfa_enrolled, mfa_challenge_success, mfa_challenge_failure,
password_changed, password_reset,
token_issued, token_revoked, token_introspected,
client_created, client_updated, client_deleted,
user_created, user_updated, user_deleted,
upstream_linked, upstream_unlinked,
admin_action
```

Each event stores: `id, event_type, actor_id, target_id, ip_address, user_agent, metadata JSONB, created_at`.

---

## 12. Deployment & Operations

### Single binary

The Go binary embeds the compiled React assets (`go:embed web/dist`) so a single file is the entire server.

### Environment variables (minimum required)

```
DATABASE_URL         postgresql://user:pass@host:5432/dbname
BASE_URL             https://auth.example.com
SESSION_SECRET       <32-byte random hex>
SIGNING_KEY_PATH     /etc/iam/keys/signing.pem   # or managed via JWKS
```

### Health endpoints

- `GET /healthz` liveness (always 200 if process is up)
- `GET /readyz` readiness (200 only when DB is reachable)
- `GET /metrics` Prometheus metrics

### Key rotation

1. Generate new signing key, add to JWKS as second key
2. Deploy new tokens signed with new key, old tokens validated against both
3. After max token TTL passes, remove old key from JWKS

---

## 13. OpenID Certification Checklist

To pursue official OpenID Certification:

- [ ] `/.well-known/openid-configuration` returns fully-formed discovery document
- [ ] All required OIDC Core claims present in `id_token`
- [ ] `nonce` binding in ID token
- [ ] `at_hash` / `c_hash` present when required
- [ ] `request` and `request_uri` parameter support
- [ ] PKCE mandatory for public clients (S256 only)
- [ ] UserInfo endpoint protected and returning correct claims
- [ ] `acr` and `amr` claims populated
- [ ] Conformance test suite passes: Basic, Implicit, Hybrid, Config, Dynamic

---

## 14. Development Workflow

### Local setup

```bash
# Start dependencies
docker compose -f deployments/compose/docker-compose.yml up -d

# Run DB migrations
make migrate-up

# Start backend (hot reload)
make dev-server

# Start frontend (Vite HMR)
make dev-web
```

### Makefile targets

| Target                      | Action                              |
| --------------------------- | ----------------------------------- |
| `make build`                | Compile binary with embedded assets |
| `make test`                 | Run all unit + integration tests    |
| `make lint`                 | golangci-lint + eslint              |
| `make migrate-up`           | Apply pending migrations            |
| `make migrate-new name=foo` | Create new migration pair           |
| `make generate`             | sqlc + openapi-typescript codegen   |
| `make release`              | GoReleaser build                    |

### Git conventions

- Branch: `feat-`, `fix-`, `chore-`, `docs-`
- Commits: Conventional Commits (`feat: add WebAuthn enrollment`)
- PRs require: passing CI, one approval, no lint warnings
- Releases: semver tags (`v1.2.3`) trigger GoReleaser

---

## 15. Security Policies

- **Dependency scanning:** `govulncheck` + `npm audit` in CI; block on HIGH/CRITICAL
- **SAST:** `gosec` in CI
- **Secret scanning:** `gitleaks` pre-commit hook
- **No secrets in source:** All credentials via env / mounted secrets
- **Responsible disclosure:** `SECURITY.md` with private disclosure contact
- **Dependency updates:** Dependabot or Renovate, weekly PRs
