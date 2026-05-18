# IAM Server, Setup & Operations Guide

A complete walkthrough: dev setup, prod deployment, federation (Google/GitHub/others/generic OIDC), MFA enrollment, CAS service registration, and OIDC client integration.

---

## Part 1, Environment configuration

Every knob is an environment variable. The server reads them at startup and validates before opening any sockets. Set them in a `.env` file (loaded by `docker compose`) or export them in your shell, the server itself doesn't read `.env` directly, so for bare-metal runs you need to source it yourself.

### Required for any deployment

```bash
# Postgres connection string. SSL recommended in prod.
DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable

# Public URL the server is reachable at. Used in OIDC discovery,
# email verification links, and CAS responses. MUST match what
# downstream clients see (no trailing slash)
BASE_URL=http://localhost:8080

# 32-byte hex secret for HMAC-signing session cookies. Generate once,
# never commit! (actually never commit .env)
# `openssl rand -hex 32` produces the right shape
SESSION_SECRET=<64 hex chars>

# RSA-2048 PEM private key for signing OIDC id_tokens. The keygen
# Makefile target creates one at ./signing.pem.
SIGNING_KEY_PATH=/etc/iam/keys/signing.pem
```

### Common optional settings

```bash
# Listen address. Defaults to :8080
HTTP_ADDR=:8080

# Auto-run migrations at startup. Default true in dev, set false in
# prod if you'd rather run `make migrate-up` as a deploy step.
AUTO_MIGRATE=true

# Slog level: debug | info | warn | error
LOG_LEVEL=info

# When true, the Secure cookie flag is set on all cookies. Required
# for production; defaults off so localhost works without TLS
COOKIES_SECURE=false

# Trust X-Forwarded-* headers (only when behind a reverse proxy).
TRUSTED_PROXIES=127.0.0.1,::1
```

### MFA configuration

```bash
# Display name shown in TOTP authenticator apps: e.g. "IAM Server (l@mail.com)"
MFA_ISSUER=IAM Server

# Relying-party name shown in WebAuthn / passkey prompts
MFA_WEBAUTHN_RP_NAME=IAM Server

# Relying-party ID, must be the registrable domain (no scheme, no port)
# Defaults to the host of BASE_URL when unset
# MFA_WEBAUTHN_RP_ID=auth.example.com
```

### Federation, only set what you enable

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
# or your tenant UUID
MICROSOFT_TENANT=common

GITLAB_CLIENT_ID=...
GITLAB_CLIENT_SECRET=...
# override for self-hosted GitLab
GITLAB_ISSUER=https://gitlab.com

APPLE_CLIENT_ID=...
APPLE_TEAM_ID=...
APPLE_KEY_ID=...
APPLE_PRIVATE_KEY_PATH=/etc/iam/keys/apple.p8
```

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
COOKIES_SECURE=false
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
COOKIES_SECURE=true
TRUSTED_PROXIES=127.0.0.1,::1
LOG_LEVEL=info
AUTO_MIGRATE=false
MFA_ISSUER=Auth.example.com
MFA_WEBAUTHN_RP_NAME=Example
MFA_WEBAUTHN_RP_ID=auth.example.com
```

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

The repo ships a Dockerfile under `deployments/docker/`. Build:

```bash
docker build -f deployments/docker/Dockerfile -t iam-server:latest .
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

- [ ] `COOKIES_SECURE=true` (otherwise the browser drops session cookies over HTTPS, silent failure)
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

### Microsoft / Entra ID

1. **Azure Portal** -> Microsoft Entra ID -> App registrations -> New registration
2. Redirect URI (web): `https://auth.example.com/oauth/callback/microsoft`
3. Supported account types:
   - "My organization only" -> use your tenant UUID
   - "Any AAD directory" -> tenant = `organizations`
   - "AAD + personal accounts" -> tenant = `common`
4. Certificates & secrets -> New client secret -> copy
5. Set in env:
   ```bash
   MICROSOFT_CLIENT_ID=…
   MICROSOFT_CLIENT_SECRET=…
   MICROSOFT_TENANT=common
   ```

The tenant value goes into the discovery URL: `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`. Pick the tenant that matches who you want to let in.

### GitLab

1. **GitLab.com** (or your self-hosted instance) -> User Settings -> Applications
2. Redirect URI: `https://auth.example.com/oauth/callback/gitlab`
3. Scopes: `openid`, `profile`, `email`
4. Set in env:
   ```bash
   GITLAB_CLIENT_ID=…
   GITLAB_CLIENT_SECRET=…
   GITLAB_ISSUER=https://gitlab.com    # or https://gitlab.example.internal
   ```

For self-hosted GitLab, set `GITLAB_ISSUER` to your instance's root URL, the IAM server appends `/.well-known/openid-configuration` to discover the rest.

### Apple, Sign in with Apple

The most awkward setup of the bunch because Apple wants a signed JWT instead of a static secret, and the cert flow happens in their Developer portal.

1. **Apple Developer** -> Certificates, Identifiers & Profiles
2. Identifiers -> register a **Services ID** (this becomes `APPLE_CLIENT_ID`)
3. Configure the Services ID for "Sign in with Apple":
   - Primary App ID: pick one (create one first if needed)
   - Domains: `auth.example.com`
   - Return URLs: `https://auth.example.com/oauth/callback/apple`
4. **Keys** -> register a new key with "Sign in with Apple" enabled
   - Download the `.p8` file, you can only download it **once**
   - Note the Key ID (10 chars), this is `APPLE_KEY_ID`
5. Your Team ID is in the top right of the developer portal, this is `APPLE_TEAM_ID`
6. Set in env:
   ```bash
   # the Services ID identifier
   APPLE_CLIENT_ID=com.example.auth.signin
   APPLE_TEAM_ID=ABCDE12345
   APPLE_KEY_ID=ABCDE12345
   APPLE_PRIVATE_KEY_PATH=/etc/iam/keys/apple_AuthKey_ABCDE12345.p8
   ```

The IAM server signs a fresh ES256 JWT every time it talks to Apple's token endpoint, that's the "client secret" Apple wants. The `.p8` file must stay readable by the service user.

Two Apple quirks worth knowing:

- Apple returns the user's name **only on the very first sign-in**. The IAM server captures it then; if you lose that callback (or the user revokes consent and signs in again), the name field stays empty.
- Apple users can opt to share a random relay email. The IAM server stores whatever address Apple sends; the user can update it later from the profile page.

### Generic OIDC

For any OIDC-compliant IdP not listed above (Okta, Auth0, Keycloak, Authentik, Zitadel, etc.):

In the IAM admin UI: **Upstream providers -> Add -> "Generic OIDC"** (or equivalent admin API call, see roadmap note below). Required fields:

```
Name:                  "Acme Corp Okta"
Issuer:                https://acme.okta.com
Client ID:             0oaXXXXXXXXXXXX
Client secret:         ...
Scopes:                openid profile email
Redirect URI: (read-only)  https://auth.example.com/oauth/callback/{slug}
```

**Roadmap note:** providers are currently env-configured at startup. Per-provider DB rows + the "Upstream providers" admin page exist in the schema and store layer but aren't wired into the SPA yet. For now, generic OIDC providers go in via env too, see `internal/federation/registry.go` for the format expected.

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

## Part 8, Common operational tasks

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

## Part 9, Troubleshooting

| Symptom                                                                              | Most likely cause                                                                                                   | Fix                                                                                      |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| "Service not authorized" on `/cas/login?service=...`                                 | Service URL isn't in `cas_services` table                                                                           | Register it in the SPA, or use `next=` for first-party redirects                         |
| Browser drops session cookies (login appears to work, then immediately bounces back) | `COOKIES_SECURE=true` over plain HTTP, or `BASE_URL` doesn't match what the browser sees                            | Match `BASE_URL` exactly; set `COOKIES_SECURE=false` for HTTP testing                    |
| OIDC client gets "invalid_redirect_uri"                                              | The redirect_uri sent doesn't exactly match a registered URI (trailing slash, port number, scheme)                  | Re-register with the exact URI the client uses                                           |
| OIDC clients can't verify id_token signatures after a deploy                         | `signing.pem` regenerated; old tokens invalid                                                                       | Restore the original key from backup; never regenerate the key during routine deploys    |
| Federated login lands on `/cas/login?error=…`                                        | Provider redirect URI mismatch; check the provider's console matches `{BASE_URL}/oauth/callback/{provider}` exactly | Update the provider; restart the IAM server isn't required                               |
| WebAuthn enrollment fails with "RP ID mismatch"                                      | `MFA_WEBAUTHN_RP_ID` doesn't match the browser's host                                                               | Set RP ID to the registrable domain (no scheme, no port)                                 |
| Apple sign-in fails with "invalid_client"                                            | `.p8` file path wrong, or `APPLE_KEY_ID` / `APPLE_TEAM_ID` mismatch                                                 | Check the file is readable by the service user; verify IDs in the Apple Developer portal |

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

## Part 10, What's TODO

- **No email/SMS delivery**, password resets and email verification require an out-of-band channel today. SMTP is P8.
- **No global "force MFA" policy**, it's per-user (any enrolled method -> enforced) or per-client (`acr_values`). A blanket policy lever is P7.
- **No public signup**, users come from `make seed-user`, federation, or the admin SPA's "New user". A self-service signup page is P8.
- **No automatic key rotation**, `signing.pem` is treated as long-lived. The Keys page is view-only; rotation tooling lands in P7.
- **No SAML**, this is an OIDC + CAS server, not a SAML IdP. If you need SAML, run something else for that side.
