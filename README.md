# IAM Server, Setup & Operations Guide

A complete walkthrough: dev setup, prod deployment, federation (Google/GitHub/others/generic OIDC), MFA enrollment, CAS service registration, and OIDC client integration.

---

## Part 1, Environment configuration

Every knob is an environment variable. The server reads them at startup and validates before opening any sockets. Set them in a `.env` file (loaded by `docker compose`) or export them in your shell — the server itself doesn't read `.env` directly, so for bare-metal runs you need to source it yourself.

### Required for any deployment

```bash
# Postgres connection string. SSL recommended in prod.
DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable

# Public URL the server is reachable at. Used in OIDC discovery,
# email verification links, and CAS responses. MUST match what
# downstream clients see (no trailing slash).
#
# A note on what this controls beyond URLs:
#   - WebAuthn RPID is derived from the host part of BASE_URL.
#   - The Secure flag on cookies is set when BASE_URL starts with https://
#     (so production https → secure cookies; dev http → not).
BASE_URL=http://localhost:8080

# 32-byte hex secret for HMAC-signing session cookies. Generate once,
# never commit. `openssl rand -hex 32` produces the right shape.
SESSION_SECRET=<64 hex chars>

# RSA-2048 PEM private key for signing OIDC id_tokens. The keygen
# Makefile target creates one at ./signing.pem.
SIGNING_KEY_PATH=/etc/iam/keys/signing.pem
```

### Common optional settings

```bash
# Listen address. Defaults to :8080.
HTTP_ADDR=:8080

# Auto-run migrations at startup. Default true in dev, set false in
# prod if you'd rather run `make migrate-up` as a deploy step.
AUTO_MIGRATE=true

# Slog level: debug | info | warn | error. Default: info.
LOG_LEVEL=info

# Log format: text (default, dev-friendly) | json (production).
LOG_FORMAT=json

# Environment tag, mostly for log enrichment. Free-form string.
ENV=production

# Postgres connection pool sizing. Defaults are sensible for most loads.
DB_MAX_CONNS=20
DB_MIN_CONNS=2
```

### Reverse-proxy companion (forward_auth)

Only needed if you're using the `/proxy/verify` endpoint (see Part 8):

```bash
# Make the IAM session cookie readable across all subdomains under the
# parent. Without this, the cookie is scoped to the auth host only.
SESSION_COOKIE_DOMAIN=.example.com

# Comma-separated allowlist of origins that may receive a redirect
# after login. Open-redirect defense — any origin not here will see
# a bare 401 with no Location header.
PROXY_ALLOWED_CALLBACK_ORIGINS=https://app.example.com,https://wiki.example.com
```

### MFA

```bash
# Display name shown in TOTP authenticator apps,
# e.g. "IAM Server (alice@example.com)".
MFA_ISSUER=IAM Server

# Relying-party name shown in WebAuthn / passkey prompts.
MFA_WEBAUTHN_RP_NAME=IAM Server
```

WebAuthn's RPID (the registrable domain it binds credentials to) is **automatically derived** from `BASE_URL`'s host — there's no env var for it. `BASE_URL=https://auth.example.com` gives RPID `auth.example.com`. This is correct for almost every deployment; the rare cases where you'd want a different RPID (multi-subdomain setups with credentials shared across hosts) aren't supported today.

### Federation, only set what you enable

First-class providers (one button each, fixed labels):

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

Generic OIDC providers — any OpenID-Connect-compliant IdP (Microsoft Entra, GitLab, Okta, Auth0, Keycloak, Authentik, Zitadel, a corporate IdP, etc.). Declare which ones are enabled in `OIDC_PROVIDERS`, then provide each one's settings under `OIDC_<SLUG>_*`:

```bash
OIDC_PROVIDERS=microsoft,okta

OIDC_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
OIDC_MICROSOFT_CLIENT_ID=...
OIDC_MICROSOFT_CLIENT_SECRET=...

OIDC_OKTA_ISSUER=https://acme.okta.com
OIDC_OKTA_CLIENT_ID=...
OIDC_OKTA_CLIENT_SECRET=...
OIDC_OKTA_DISPLAY_NAME=Acme SSO   # optional
```

See [Part 4](#part-4-federation-setup) for the full provider walkthrough, including the slug rules and per-provider quirks. Sign in with Apple isn't OIDC-compatible (its "client secret" is a per-request signed JWT) and is **planned but not yet wired**.

---

## Part 2, Development setup

Tested path: macOS / Linux with Docker, Go 1.26+, Node 25.1+.

### One-time setup

```bash
# Start Postgres (compose file mounts a named volume; data survives restarts)
make compose-up

# Generate a signing key
make keygen
# -> creates ./signing.pem
# -> prints the SIGNING_KEY_PATH=... line to paste into .env

# Create .env in the project root
cat > .env <<EOF
DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable
BASE_URL=http://localhost:8080
SESSION_SECRET=$(openssl rand -hex 32)
SIGNING_KEY_PATH=$PWD/signing.pem
AUTO_MIGRATE=true
LOG_LEVEL=debug
MFA_ISSUER=IAM Server (dev)
EOF

# Run migrations explicitly the first time so you see what happened
set -a; source .env; set +a
make migrate-up

# Create the bootstrap admin user (one-time)
make seed-user email=l@mail.com password=password123 admin=1

# Build the admin SPA assets
make web-build
```

### Two-terminal dev loop

```bash
# Terminal A, Go server with stub SPA initially, rebuild when you touch backend
set -a; source .env; set +a
make dev-server
# Reachable at http://localhost:8080

# Terminal B, Vite HMR for SPA work
make web-dev
# Reachable at http://localhost:5173 with API calls proxied to :8080
```

**Important:** the Vite dev server runs at `:5173` and proxies API calls (`/admin/v1`, `/cas`, `/oauth2`, `/.well-known`, `/mfa`) to the Go server at `:8080`. Cookies are shared because both look like the same dev origin to the browser. Use `:5173` for SPA-focused work, HMR is instant. Use `:8080` to test the embedded production-style build.

### Verify it works

1. `curl http://localhost:8080/healthz` -> `ok`
2. `curl http://localhost:8080/.well-known/openid-configuration` -> the discovery document
3. Open `http://localhost:8080/` in a browser -> redirects to `/admin/` -> bounces to `/cas/login?next=/admin/`
4. Sign in with the seeded admin credentials
5. You should land on the admin dashboard

### Resetting the dev database

```bash
make compose-down
# remove volumes
make compose-clear
make compose-up
make migrate-up
make seed-user email=l@mail.com password=... admin=1
```

---

## Part 3, Production deployment

The server is a single Go binary with the SPA embedded. Two common shapes:

### Shape A, Single VM behind Caddy

```bash
# On your build machine
make build

# On the server (Ubuntu 24)
sudo useradd -r -s /bin/false iam
sudo mkdir -p /opt/iam /etc/iam/keys /var/lib/iam
sudo cp bin/iam-server /opt/iam/iam-server
sudo openssl genrsa -out /etc/iam/keys/signing.pem 2048
sudo chown -R iam:iam /opt/iam /etc/iam /var/lib/iam
sudo chmod 600 /etc/iam/keys/signing.pem
```

**`/etc/iam/iam.env`** (mode 0640, owner `iam`):

```bash
DATABASE_URL=postgres://iam:STRONG_PASSWORD@db.internal:5432/iam?sslmode=require
BASE_URL=https://auth.example.com
SESSION_SECRET=GENERATE_WITH_openssl_rand_-hex_32
SIGNING_KEY_PATH=/etc/iam/keys/signing.pem
LOG_LEVEL=info
LOG_FORMAT=json
ENV=production
AUTO_MIGRATE=false
MFA_ISSUER=Auth.example.com
MFA_WEBAUTHN_RP_NAME=Example
```

(`COOKIES_SECURE` and the WebAuthn RPID are derived from `BASE_URL` automatically — https → secure cookies, RPID = `auth.example.com`.)

**`/etc/systemd/system/iam-server.service`:**

```ini
[Unit]
Description=IAM Server
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=iam
Group=iam
EnvironmentFile=/etc/iam/iam.env
ExecStart=/opt/iam/iam-server
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/iam
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictNamespaces=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

**Migrations on deploy** (`AUTO_MIGRATE=false` in prod means you run them explicitly):

```bash
sudo -u iam DATABASE_URL=postgres://... \
  /opt/iam/iam-server migrate up
```

**Caddy** (`/etc/caddy/Caddyfile`):

```caddyfile
auth.example.com {
    reverse_proxy 127.0.0.1:8080
    encode zstd gzip
}
```

That's all the TLS, HSTS, and certificate management you need from the reverse proxy. Caddy gets a Let's Encrypt cert on first request and renews automatically.

### Shape B, Container

The repo ships a multi-stage Dockerfile and a production-ready compose
stack under `deployments/`. Two ways to use them:

**Compose stack** (recommended: handles Postgres, IAM, and Caddy/TLS):

```bash
cd deployments
cp .env.example .env  &&  $EDITOR .env   # set BASE_URL, secrets, etc.
mkdir -p signing && openssl genrsa -out signing/signing.pem 2048
sudo chown 65532:65532 signing/signing.pem && chmod 600 signing/signing.pem
docker compose up -d
```

**Image only** (build, push to a registry, deploy however you like):

```bash
make docker-build IMAGE_TAG=ghcr.io/you/iam-server:v1.0.0
docker push ghcr.io/you/iam-server:v1.0.0
```

Run with the env file you'd use bare-metal:

```bash
docker run -d --name iam \
  --restart unless-stopped \
  --env-file /etc/iam/iam.env \
  -v /etc/iam/keys/signing.pem:/etc/iam/keys/signing.pem:ro \
  -p 127.0.0.1:8080:8080 \
  iam-server:latest
```

### Production checklist

- [ ] `BASE_URL=https://...` (the https scheme is what turns on the Secure flag on cookies; over plain http, browsers will silently drop session cookies)
- [ ] `AUTO_MIGRATE=false` and migrations run as a deploy step
- [ ] `SIGNING_KEY_PATH` points at a real RSA-2048 key, mode 600, owner = service user
- [ ] `SESSION_SECRET` is 32+ bytes of entropy and unique per environment
- [ ] Postgres uses `sslmode=require` (or `verify-full` with a CA bundle)
- [ ] `BASE_URL` exactly matches what users type in the browser, trailing slashes, port numbers, protocol all matter for OIDC redirect validation
- [ ] Backups of the `iam` database scheduled
- [ ] Backup of `signing.pem` stored encrypted off-host, losing it invalidates every active id_token and forces re-issue
- [ ] First admin user seeded with `make seed-user … admin=1` (or promote a federated user with `make grant-admin email=…`)

---

## Part 4, Federation setup

Each upstream provider has its own console, redirect-URI rules, and quirks. The pattern is the same:

- register an OAuth client there, get a client ID + secret, paste into the IAM server's env, restart. The IAM server's callback URL is always:

```
{BASE_URL}/oauth/callback/{provider}
```

### Google

1. **Google Cloud Console** -> APIs & Services -> Credentials -> Create credentials -> **OAuth client ID**
2. Application type: **Web application**
3. Authorized redirect URI: `https://auth.example.com/oauth/callback/google`
4. Copy the **Client ID** and **Client secret**
5. Set in env:
   ```bash
   GOOGLE_CLIENT_ID=…apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=…
   ```
6. Restart. The "Sign in with Google" button appears on `/cas/login` automatically when both vars are set!

The Google provider uses OIDC discovery (`https://accounts.google.com/.well-known/openid-configuration`) so no other URLs need configuring.

### GitHub

1. **GitHub** -> Settings -> Developer settings -> OAuth Apps -> New OAuth App
2. Application name: whatever
3. Homepage URL: `https://auth.example.com`
4. Authorization callback URL: `https://auth.example.com/oauth/callback/github`
5. Generate a client secret
6. Set in env:
   ```bash
   GITHUB_CLIENT_ID=…
   GITHUB_CLIENT_SECRET=…
   ```

GitHub isn't OIDC, it's plain OAuth 2. The IAM server fetches `/user` and `/user/emails` against the GitHub API to build the `Identity`. If a GitHub user has set their email to private, the IAM server uses the primary email from `/user/emails` (requires the `user:email` scope, which we request).

### Generic OIDC

For any OIDC-compliant IdP: Microsoft Entra, GitLab, Okta, Auth0, Keycloak, Authentik, Zitadel, a corporate IdP, anything that publishes an OIDC discovery document.

The IAM server can host any number of generic-OIDC providers side-by-side. Each one becomes its own button on the login page and its own slug in the `user_identities.provider` column.

**Setup is two-step.** First, declare which providers are enabled by listing their slugs in `OIDC_PROVIDERS`. Then provide each provider's settings under `OIDC_<SLUG>_*`. Slugs are lowercase letters / digits / underscores; they appear in URLs (`/oauth/callback/<slug>`) and in the database, so pick something stable and re-use the same slug across deploys to keep user account links intact.

```bash
# Declare which providers to enable. Comma-separated. Order is
# preserved on the login page.
OIDC_PROVIDERS=microsoft,okta

OIDC_MICROSOFT_ISSUER=https://login.microsoftonline.com/common/v2.0
OIDC_MICROSOFT_CLIENT_ID=...
OIDC_MICROSOFT_CLIENT_SECRET=...
OIDC_MICROSOFT_DISPLAY_NAME=Microsoft       # optional; defaults to title-cased slug
OIDC_MICROSOFT_SCOPES=openid email profile  # optional; defaults to these three

OIDC_OKTA_ISSUER=https://acme.okta.com
OIDC_OKTA_CLIENT_ID=0oaXXXXXXXXXXXX
OIDC_OKTA_CLIENT_SECRET=...
OIDC_OKTA_DISPLAY_NAME=Acme SSO
```

The redirect URI to register in each provider's console follows the same pattern as the built-ins:

```
https://auth.example.com/oauth/callback/<slug>
```

So with the config above you'd register `https://auth.example.com/oauth/callback/microsoft` in the Azure portal and `https://auth.example.com/oauth/callback/okta` in the Okta admin console.

**Failure modes worth knowing about:**

| Mistake                                                                                      | What happens                                                                                                         |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Slug in `OIDC_PROVIDERS` but missing `OIDC_<SLUG>_ISSUER` (or `CLIENT_ID` / `CLIENT_SECRET`) | Startup error naming each missing var                                                                                |
| Same slug listed twice                                                                       | Startup error — would silently link two different upstream accounts into one row                                     |
| Slug contains hyphens, uppercase, or special chars                                           | Silently dropped from the list — Validate then reports "no provider with that slug" if you also set its credentials  |
| `OIDC_<SLUG>_ISSUER` is unreachable at startup (DNS, firewall, etc.)                         | Logged error, server keeps running, that provider just doesn't appear on the login page until you fix it and restart |
| Slug `google` or `github`                                                                    | Reserved for the first-class providers; rejected to avoid colliding with those env vars                              |

The discovery document is fetched once at startup with a 15-second timeout per provider, so a flaky upstream IdP can't stall the entire server boot.

#### Provider-specific notes

- **Microsoft / Entra ID**: the tenant goes in the issuer URL. `common` for any AAD or personal account, `organizations` for any AAD account, or a tenant UUID for a single tenant. Full issuer: `https://login.microsoftonline.com/<tenant>/v2.0`.
- **GitLab**: the issuer is the root URL of your GitLab instance. `https://gitlab.com` for SaaS, `https://gitlab.example.internal` for self-hosted.
- **Auth0**: the issuer is `https://<your-tenant>.<region>.auth0.com/` (with the trailing slash).
- **Okta**: the issuer is your Okta domain root, e.g. `https://acme.okta.com`. Some Okta orgs require `/oauth2/default` appended to use the default authorization server.

---

> **The following providers are planned but not yet wired into `cmd/server/main.go`** as first-class buttons. Most of them can be configured today as generic OIDC providers (above) — only Apple needs special handling because its "client secret" is a per-request signed JWT.
>
> Each provider's Go package is partially or fully implemented under `internal/federation/`; the gap is operator-facing config. Tracked as P8.

### Apple, Sign in with Apple (planned)

Apple doesn't fit the generic-OIDC mold. Their "client secret" is a per-request signed JWT built from a `.p8` private key, plus the team ID and key ID — there's no static secret to put in `OIDC_APPLE_CLIENT_SECRET`. Wiring this requires a few extra env vars and a special-case provider, deferred to P8.

When it lands, the setup will go roughly:

1. **Apple Developer** → Certificates, Identifiers & Profiles
2. Identifiers → register a **Services ID** (becomes `APPLE_CLIENT_ID`)
3. Configure the Services ID for "Sign in with Apple": primary App ID, Domains: `auth.example.com`, Return URLs: `https://auth.example.com/oauth/callback/apple`
4. **Keys** → register a new key with "Sign in with Apple" enabled. Download the `.p8` file (once), note the Key ID (`APPLE_KEY_ID`)
5. Find your Team ID in the developer portal (`APPLE_TEAM_ID`)

Two Apple quirks worth knowing in advance:

- Apple returns the user's name **only on the very first sign-in**. Subsequent sign-ins (or sign-ins after a user revokes consent) don't repeat it.
- Apple users can opt to share a random relay email; you store whatever they send.

### Account linking behaviour

When an upstream callback succeeds, the federation handler looks for a matching account in this order:

1. `(provider, sub)` pair already in `user_upstream_links` -> log that user in
2. `users.email` matches the email from the upstream -> link the new provider to that user, log them in
3. Otherwise -> create a new user, link the provider, log them in

The first time someone signs in via Google with `l@mail.com`, a user row is created. If that same person later signs in via GitHub with the same email, the GitHub identity is linked to the existing row, they're the same user. Email is the join key, which is why verified emails matter; the IAM server trusts the upstream's verification.

---

## Part 5, MFA enrollment & enforcement

### What's available

| Method                 | When to use             | Notes                                                                                       |
| ---------------------- | ----------------------- | ------------------------------------------------------------------------------------------- |
| **TOTP**               | Most users              | RFC 6238 6-digit / 30s. Works with Google Authenticator, 1Password, Authy, any RFC 6238 app |
| **WebAuthn / passkey** | Best UX where supported | Touch ID, Face ID, Windows Hello, YubiKey, etc. Modern browsers only                        |
| **Backup codes**       | Recovery, always        | 10 single-use 8-char codes, argon2id-hashed at rest                                         |
| Email OTP, SMS OTP     | TODO                    | Not implemented yet                                                                         |

### Enrolling MFA on your own account

1. Sign in at `/cas/login`
2. Open `/mfa/enroll`
3. **Add TOTP:**
   - Click "Add TOTP"
   - Scan the QR with your authenticator app
   - Enter the 6-digit code to confirm
4. **Add a passkey:**
   - Click "Add passkey"
   - Your browser/OS prompts you (Touch ID, Windows Hello, YubiKey)
   - Pick a name so you can identify it later
5. **Generate backup codes:**
   - Click "Generate backup codes"
   - Save the 10 codes somewhere offline (password manager, printed card)
   - Each code works exactly once

The next time you sign in, after entering your password you're redirected to `/mfa` for the challenge. You can choose any enrolled method.

### Forcing MFA for other users (per-user)

There's no global "force MFA" toggle yet, TODO. Today, the flow is:

- A user with **zero enrolled methods** completes login on password alone (no MFA step)
- A user with **at least one enrolled method** is required to complete MFA on every login

If you want to require MFA for an admin or specific user, the practical answer is to tell them to enroll on `/mfa/enroll`. After they do, MFA is enforced for them automatically.

### Forcing MFA per OIDC client

OIDC clients can request a specific assurance level via `acr_values` in the authorize request. The IAM server understands two values:

| `acr_values`                              | Means         | What's enforced                                                         |
| ----------------------------------------- | ------------- | ----------------------------------------------------------------------- |
| `urn:mace:incommon:iap:silver`            | Password only | Default, current session is fine if MFA wasn't already done             |
| `urn:mace:incommon:iap:bronze` (or `mfa`) | MFA required  | If the current session is password-only, redirects to `/mfa` to step up |

Configure on the client side:

```js
// Example: oauth4webapi or similar
const authzUrl = new URL("/oauth2/authorize", "https://auth.example.com");
authzUrl.searchParams.set("acr_values", "mfa");
// …
```

The resulting `id_token` carries `acr` and `amr` claims so the relying-party can verify what actually happened (`amr: ["pwd", "totp"]` for password + TOTP).

### Backup codes, what happens when (TODO)

- User loses their phone -> admin marks them as needing reset -> user types a backup code on `/mfa` -> success -> optional: they enroll a new TOTP and revoke the lost device
- User runs out of codes -> they can regenerate from `/mfa/enroll` (invalidates the old set)
- User can't find any codes either -> admin path: open the user in the SPA -> "Revoke sessions" -> tell them to recover the account via federation (if they have it) or do a password reset + ask them to re-enroll

---

## Part 6, CAS service registration

CAS clients need to be registered before `/cas/login` will issue tickets for them. This is the "Service not authorized" guard from earlier in the project.

### Registering a CAS application

In the SPA: **CAS services -> Register service**. Fields:

```
Name:                    Wiki
Description:             Corporate wiki
Service URL pattern:     https://wiki.example.com/*
Released attributes:     email, display_name
```

**About the URL pattern:**

- `https://wiki.example.com/*` matches any path under that host
- `https://wiki.example.com/login` matches only that exact URL
- The server normalises the query string off before matching
- Wildcards are converted to SQL `LIKE` patterns internally

**About released attributes:**

- Empty list -> only `<cas:user>` is returned (CAS 2.0 default)
- `["email", "display_name"]` -> those user fields are released in the `<cas:attributes>` block (CAS 3.0 / p3)
- Don't release anything the downstream application doesn't need

### Configuring the CAS client side

Different applications have different configuration formats. The information you'll need to give them:

| Setting                | Value                                             |
| ---------------------- | ------------------------------------------------- |
| CAS Server URL         | `https://auth.example.com/cas`                    |
| Login URL              | `https://auth.example.com/cas/login`              |
| Validate URL (CAS 2.0) | `https://auth.example.com/cas/serviceValidate`    |
| Validate URL (CAS 3.0) | `https://auth.example.com/cas/p3/serviceValidate` |
| Logout URL             | `https://auth.example.com/cas/logout`             |

### Example: testing CAS with curl

```bash
# 1. Open /cas/login?service=https://wiki.example.com/cas in a browser
# 2. Sign in
# 3. The browser redirects to https://wiki.example.com/cas?ticket=ST-...
# 4. Take that ticket and validate it:
curl "https://auth.example.com/cas/p3/serviceValidate?service=https://wiki.example.com/cas&ticket=ST-abc123..."
# Returns XML:
# <cas:serviceResponse xmlns:cas="...">
#   <cas:authenticationSuccess>
#     <cas:user>l@mail.com</cas:user>
#     <cas:attributes>
#       <cas:email>l@mail.com</cas:email>
#       <cas:display_name>Alice</cas:display_name>
#     </cas:attributes>
#   </cas:authenticationSuccess>
# </cas:serviceResponse>
```

Tickets are single-use (validating consumes them) and have a 60-second TTL by default.

---

## Part 7, OIDC client integration

For applications speaking OAuth 2 / OIDC instead of CAS.

### Registering an OIDC client

In the SPA: **OIDC clients -> Register client**. Fields:

```
Client ID:           my-app                  # human-meaningful slug
Name:                My App
Public client:       false                   # true for SPAs / mobile, false for backends
Require PKCE:        true                    # force PKCE, recommended
Require consent:     false                   # show consent screen on first auth
Redirect URIs:       https://app.example.com/callback
                     https://app.example.com/silent-renew      # one per line
Allowed grant types: authorization_code
                     refresh_token
Allowed scopes:      openid profile email
Access token TTL:    1h
Refresh token TTL:   720h                    # 30 days
ID token TTL:        1h
```

**Public vs confidential:**

- **Public** (SPAs, mobile apps) -> no client secret, PKCE **must** be enabled, the IAM server enforces it
- **Confidential** (server-side web apps, machine-to-machine) -> gets a one-time secret on creation; copy it immediately, only the argon2id hash is stored

**On submit:** for confidential clients the response includes the plaintext secret in a one-time banner. Copy it now, there's no "view secret" later, only "rotate to a new one".

### The handshake from the client's side

Most OIDC libraries handle this for you. The two endpoints you point them at:

```
Discovery: https://auth.example.com/.well-known/openid-configuration
JWKS:      https://auth.example.com/.well-known/jwks.json
```

A typical authorization code + PKCE flow (browser/SPA):

```
1. SPA generates code_verifier + code_challenge (S256)
2. SPA redirects user to:
   https://auth.example.com/oauth2/authorize?
     response_type=code&
     client_id=my-app&
     redirect_uri=https://app.example.com/callback&
     scope=openid%20profile%20email&
     state=RANDOM_STATE&
     code_challenge=...&
     code_challenge_method=S256

3. User authenticates (and MFA-challenges if needed), grants consent
4. IAM server redirects back to:
   https://app.example.com/callback?code=...&state=RANDOM_STATE

5. SPA POSTs to /oauth2/token:
   POST /oauth2/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&
   code=...&
   redirect_uri=https://app.example.com/callback&
   client_id=my-app&
   code_verifier=...

6. Response:
   {
     "access_token": "...",
     "refresh_token": "...",
     "id_token": "<JWT>",
     "token_type": "Bearer",
     "expires_in": 3600
   }

7. SPA validates id_token signature against /.well-known/jwks.json
```

For **confidential clients** add `client_secret=...` to the token request, no `client_verifier` needed (PKCE is optional for confidential clients but still recommended).

### Example: oidc-client-ts (browser SPA)

```typescript
import { UserManager } from "oidc-client-ts";

const um = new UserManager({
  authority: "https://auth.example.com",
  client_id: "my-app",
  redirect_uri: "https://app.example.com/callback",
  scope: "openid profile email",
  response_type: "code",
  // PKCE is on by default in oidc-client-ts; required by our public clients
});

await um.signinRedirect();
// …on the callback page:
const user = await um.signinRedirectCallback();
console.log(user.profile.email, user.id_token);
```

### Example: golang-jwt + golang.org/x/oauth2 (Go backend)

```go
import (
  "context"
  "encoding/json"
  "net/http"

  "golang.org/x/oauth2"
)

cfg := &oauth2.Config{
  ClientID:     "my-app",
  ClientSecret: "the-one-time-secret-you-saved",
  Endpoint: oauth2.Endpoint{
    AuthURL:  "https://auth.example.com/oauth2/authorize",
    TokenURL: "https://auth.example.com/oauth2/token",
  },
  RedirectURL: "https://app.example.com/callback",
  Scopes:      []string{"openid", "profile", "email"},
}

// On /callback:
tok, err := cfg.Exchange(ctx, code)
// tok.AccessToken, tok.RefreshToken
// tok.Extra("id_token") is the id_token JWT
```

### Example: introspection (resource server validating tokens)

```bash
curl -X POST https://auth.example.com/oauth2/introspect \
  -u my-app:secret \
  -d 'token=eyJhbGc…'
```

Response:

```json
{
  "active": true,
  "sub": "11111111-...",
  "client_id": "my-app",
  "scope": "openid profile email",
  "exp": 1716000000,
  "iat": 1715996400
}
```

### Example: token revocation

```bash
curl -X POST https://auth.example.com/oauth2/revoke \
  -u my-app:secret \
  -d 'token=eyJhbGc…&token_type_hint=access_token'
```

Returns `200 OK` on success (and also on "unknown token", RFC 7009).

---

## Part 8, Reverse-proxy companion (forward_auth)

If you have a Caddy or Traefik reverse proxy in front of other apps, the IAM server can act as their gatekeeper. The pattern is called **forward auth**: for every incoming request, the proxy makes a quick sub-request to the IAM server to ask "is this user authenticated?". On yes, the request goes through with identifying headers attached; on no, the user is bounced to the login page.

### The endpoint

```
GET /proxy/verify
```

What it accepts:

- **Session cookie** (the same one issued by `/cas/login`). For this to reach `/proxy/verify` when the user is on `app.example.com`, the cookie must have been issued with `Domain=.example.com` — see `SESSION_COOKIE_DOMAIN` below.
- **`Authorization: Bearer <oidc-access-token>`** for API/M2M clients. The token must be active (not revoked, not expired) and bound to a user (client_credentials tokens are rejected — this endpoint is per-user by design).

What it returns:

- **200** with these response headers:

  | Header            | Value                                                               |
  | ----------------- | ------------------------------------------------------------------- |
  | `X-Auth-Sub`      | User UUID. The stable identifier; prefer this in upstream apps      |
  | `X-Auth-User`     | Primary identifier: username if set, otherwise email, otherwise sub |
  | `X-Auth-Username` | Username (may be empty)                                             |
  | `X-Auth-Email`    | Primary email (may be empty)                                        |
  | `X-Auth-Name`     | Display name (may be empty)                                         |
  | `X-Auth-Groups`   | Comma-separated; currently `"admin"` for admins, empty otherwise    |

  All values are sanitized — CR, LF, NUL, and control bytes are stripped so a hostile display name can't smuggle additional headers into the upstream request.

- **401** with optional `Location` header. The Location is included only when the requested origin (reconstructed from `X-Forwarded-Proto` + `X-Forwarded-Host`) appears in `PROXY_ALLOWED_CALLBACK_ORIGINS`. Without that allowlist match, the user sees a bare 401 from the proxy — safe, just ugly. Operators opt in by listing every protected origin.

### Required env vars

```bash
# Make the IAM session cookie readable across all subdomains under the parent.
# Without this, the cookie is scoped to auth.example.com only and the
# forward_auth sub-request gets no cookie to validate.
SESSION_COOKIE_DOMAIN=.example.com

# Every protected origin that may be redirected back to after login.
# Comma-separated. Anything not in this list will see a bare 401 with no
# Location header (no infinite redirect loop, but the UX is ugly).
PROXY_ALLOWED_CALLBACK_ORIGINS=https://app.example.com,https://wiki.example.com
```

`BASE_URL` should be the externally visible https URL (e.g. `https://auth.example.com`) — that's what turns on the Secure flag on cookies. Behind a TLS-terminating proxy, set `BASE_URL` to the public URL, not the internal one.

### Caddy

The simpler of the two. The directive is `forward_auth` and lives in your site block:

```caddyfile
app.example.com {
    forward_auth iam:8080 {
        uri /proxy/verify
        copy_headers X-Auth-Sub X-Auth-User X-Auth-Username X-Auth-Email X-Auth-Name X-Auth-Groups
    }
    reverse_proxy backend:3000
}
```

`copy_headers` tells Caddy which of the `X-Auth-*` headers to propagate from the `/proxy/verify` response onto the request that goes to `backend:3000`. List every one your backend cares about.

### Traefik

Traefik calls it `ForwardAuth`. Configured via labels (or YAML; labels shown here because Compose is the common case):

```yaml
services:
  iam:
    labels:
      - "traefik.http.middlewares.iam-forwardauth.forwardauth.address=http://iam:8080/proxy/verify"
      - "traefik.http.middlewares.iam-forwardauth.forwardauth.authResponseHeaders=X-Auth-Sub,X-Auth-User,X-Auth-Username,X-Auth-Email,X-Auth-Name,X-Auth-Groups"
      - "traefik.http.middlewares.iam-forwardauth.forwardauth.trustForwardHeader=true"

  protected-app:
    labels:
      - "traefik.http.routers.app.middlewares=iam-forwardauth@docker"
```

`authResponseHeaders` is the Traefik equivalent of Caddy's `copy_headers`.

### How the flow actually works

```
Browser ──────────►  Caddy/Traefik (app.example.com)
                          │
                          │  (1) Original request
                          ▼
                     Sub-request to iam:8080/proxy/verify
                          │  with browser's cookies + X-Forwarded-*
                          │
              ┌───────────┴───────────┐
              │                       │
            200 + X-Auth-*          401 + Location:
              │                       │   https://auth.example.com/cas/login?rd=<original>
              ▼                       ▼
       Proxy → backend:3000     Browser → auth.example.com
       (X-Auth-* copied                       │
        onto request)                         ▼
                                       User signs in
                                              │
                                              ▼
                                       /cas/login validates rd=
                                       against PROXY_ALLOWED_CALLBACK_ORIGINS,
                                       then redirects browser to original URL
                                              │
                                              ▼
                                       Back at app.example.com with a valid
                                       session cookie → next /proxy/verify
                                       returns 200
```

The `rd=` parameter on `/cas/login` is a CAS-protocol-aware cross-origin redirect — separate from `next=` (which is path-only, for first-party redirects). Both go through the same `PROXY_ALLOWED_CALLBACK_ORIGINS` check.

### Common mistakes

| Symptom                                                    | Cause                                                                      | Fix                                                                                                                                  |
| ---------------------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Browser gets stuck in a redirect loop between app and auth | `SESSION_COOKIE_DOMAIN` not set — cookie isn't readable from app subdomain | Set it to the parent domain (`.example.com`)                                                                                         |
| Bare 401 with no redirect when accessing protected app     | Origin not in `PROXY_ALLOWED_CALLBACK_ORIGINS`                             | Add the protected origin to the comma-separated list                                                                                 |
| Backend sees no `X-Auth-*` headers despite 200 from verify | `copy_headers` / `authResponseHeaders` missing or incomplete               | List every header your backend reads                                                                                                 |
| WebAuthn enrollment / login fails with RP mismatch         | RPID (derived from `BASE_URL` host) doesn't match what the browser sees    | Make `BASE_URL`'s host the registrable domain users will actually visit (e.g. `https://auth.example.com`, not an IP or alt hostname) |
| API client gets 401 with valid bearer token                | Token is from `client_credentials` grant (no user attached)                | The endpoint is per-user; for M2M, validate via `/oauth2/introspect` instead                                                         |

---

## Part 9, Common operational tasks

### Rotate a leaked client secret

```
SPA -> OIDC clients -> click the client -> "Rotate secret" -> copy the new value, share with the app's owners
```

The old secret stops working immediately. Tokens already issued continue to validate until they expire (typically 1h).

### Promote an existing user to admin

If they signed up via federation and you want to give them admin:

```bash
make grant-admin email=l@mail.com
```

Or in the SPA: open the user -> toggle "is_admin".

### Revoke all sessions for a compromised account

```
SPA -> Users -> click the user -> "Revoke sessions"
```

Every browser, every device. They'll be signed out within a few seconds. Combine with "Reset password" if the credentials themselves are compromised.

### Audit a suspicious sign-in

```
SPA -> Audit log -> filter event_type = login_success -> search the timestamp ± a few minutes
```

Click any row to expand metadata: IP address, user-agent, provider (if federated), MFA method used (`amr`).

### Disable a user without deleting them

```
SPA -> Users -> click -> toggle status to "disabled"
```

Their active sessions are revoked, they can no longer sign in, but the row is preserved and admin promotion / federation links are intact.

### Add a new admin user from scratch

```
SPA -> Users -> "New user" -> enter email, tick "Grant admin privileges"
```

The dialog generates a strong password, shown once. Send it to the new admin out-of-band. They sign in, enroll MFA, change their password from the profile page.

### Investigate "user can't sign in"

Order of operations:

1. **Audit log** filtered by their user ID -> look for `login_failure` events. Metadata includes the reason (`wrong_password`, `account_locked`, `mfa_failed`, etc.)
2. If `account_locked` -> SPA -> user detail -> toggle status from `disabled` back to `active`. The auto-lockout (after several failed password attempts) doesn't time out, an admin needs to release it
3. If `mfa_failed` repeatedly -> ask if they've changed phones. They might need backup codes, or an admin can revoke their MFA methods (SPA -> user detail -> MFA section) so they can re-enroll on next login

---

## Part 10, Troubleshooting

| Symptom                                                                              | Most likely cause                                                                                                                  | Fix                                                                                         |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| "Service not authorized" on `/cas/login?service=...`                                 | Service URL isn't in `cas_services` table                                                                                          | Register it in the SPA, or use `next=` for first-party redirects                            |
| Browser drops session cookies (login appears to work, then immediately bounces back) | `BASE_URL` scheme doesn't match what the browser sees (https vs http) — the server sets the Secure cookie flag based on `BASE_URL` | Make `BASE_URL` exactly the public URL users visit, including scheme and port               |
| OIDC client gets "invalid_redirect_uri"                                              | The redirect_uri sent doesn't exactly match a registered URI (trailing slash, port number, scheme)                                 | Re-register with the exact URI the client uses                                              |
| OIDC clients can't verify id_token signatures after a deploy                         | `signing.pem` regenerated; old tokens invalid                                                                                      | Restore the original key from backup; never regenerate the key during routine deploys       |
| Federated login lands on `/cas/login?error=…`                                        | Provider redirect URI mismatch; check the provider's console matches `{BASE_URL}/oauth/callback/{provider}` exactly                | Update the provider; restart the IAM server isn't required                                  |
| WebAuthn enrollment fails with "RP ID mismatch"                                      | RPID (derived from `BASE_URL` host) doesn't match what the browser address bar shows                                               | Make `BASE_URL` the registrable domain the user actually visits (not an IP or alt hostname) |

### Logs

```bash
journalctl -u iam-server -f       # systemd
docker logs -f iam                # docker
```

The server emits structured JSON logs (slog). Key fields: `level`, `msg`, `event`, `user_id`, `client_id`, `request_id`, `error`. Grep liberally.

### Health endpoints

- `GET /healthz` -> 200 if the process is up
- `GET /readyz` -> 200 only if Postgres is reachable

Use `/readyz` for load balancer health checks; `/healthz` is for liveness probes that should restart the process on failure.

---

## Part 11, What's TODO

- **No email/SMS delivery**, password resets and email verification require an out-of-band channel today. SMTP is P8.
- **No global "force MFA" policy**, it's per-user (any enrolled method -> enforced) or per-client (`acr_values`). A blanket policy lever is P7.
- **No public signup**, users come from `make seed-user`, federation, or the admin SPA's "New user". A self-service signup page is P8.
- **No automatic key rotation**, `signing.pem` is treated as long-lived. The Keys page is view-only; rotation tooling lands in P7.
- **No SAML**, this is an OIDC + CAS server, not a SAML IdP. If you need SAML, run something else for that side.
