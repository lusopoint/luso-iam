<div align="center">

# LusoIAM

**One Go binary for single sign-on, multi-factor authentication, and OpenID Connect.**

Self-hosted · single binary · Docker-native · CAS + OIDC + reverse-proxy auth

[![CI](https://github.com/lusopoint/luso-iam/actions/workflows/ga-test.yml/badge.svg)](https://github.com/lusopoint/luso-iam/actions/workflows/ga-test.yml)
[![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Node 26](https://img.shields.io/badge/Node-26-5FA04E?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![PostgreSQL 18](https://img.shields.io/badge/PostgreSQL-18-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

[Requirements](#requirements) ·
[Quick start](#quick-start) ·
[Production](#run-it-in-production) ·
[Configuration](#configuration) ·
[Endpoints](#protocol-surface) ·
[Commands](#common-commands) ·
[Security](#security) ·
[License](#license)

</div>

---

LusoIAM is a self-hosted identity server. It gives your apps single sign-on (SSO), multi-factor authentication (MFA), and OpenID Connect. It also adds CAS support and protects other apps behind a reverse proxy.

LusoIAM ships as **one Go binary** with the admin UI built in. You need only the binary and a PostgreSQL database to run it.

```mermaid
flowchart LR
  B["Browser"]
  O["OIDC / OAuth 2.0 apps"]
  C["CAS 2.0 / 3.0 apps"]
  P["Apps behind Caddy or Traefik"]
  LusoIAM["LusoIAM — one Go binary"]
  DB[("PostgreSQL 18")]
  U["Google, GitHub, other OIDC IdPs"]

  B -->|"sign in, MFA"| LusoIAM
  O -->|"authorize, tokens"| LusoIAM
  C -->|"service tickets"| LusoIAM
  P -->|"forward-auth"| LusoIAM
  U -->|"upstream SSO"| LusoIAM
  LusoIAM -->|"users, clients, sessions, audit"| DB
  LusoIAM -->|"id_token, JWKS"| O
  LusoIAM -->|"identity headers"| P
```

### What it does

| Capability | Summary |
| --- | --- |
| 🔑 **OIDC / OAuth 2.0 provider** | Act as an authorization server for your apps: PKCE, discovery, JWKS, introspection, and revocation. |
| 🎫 **CAS 2.0 / 3.0 server** | Serve older apps that speak CAS. Bridge them to modern SSO. |
| 🔗 **Upstream SSO** | Let users sign in with Google, GitHub, or a generic OIDC provider such as Microsoft, Okta, GitLab, or Keycloak. |
| 🛡️ **MFA** | Enforce TOTP, WebAuthn/passkeys, and single-use backup codes. |
| 🚦 **Reverse-proxy auth** | Protect any app behind Caddy or Traefik with a forward-auth endpoint. |
| 🖥️ **Admin portal** | Manage users, clients, services, and providers from the built-in React UI at `/admin`. |

> [!TIP]
> The server keeps sessions, clients, audit events, and MFA state in PostgreSQL. The signing key stays on disk. Back up both.

---

## Requirements

| Tool | Version | Why |
| --- | --- | --- |
| **Go** | 1.27+ | Build and run the server. The module pins toolchain `go1.27.4`. |
| **Node** | 26+ | Build the web UI only. |
| **Docker** | Current | Run PostgreSQL for development, and the full stack in production. |
| **PostgreSQL** | 18+ | The Compose stack uses `postgres:18-alpine`. |

> [!IMPORTANT]
> PostgreSQL 18 cannot use a 16 data directory. If you upgrade an existing deployment, follow [Upgrade from PostgreSQL 16](#upgrade-from-postgresql-16). Do not point 18 at the old volume.

---

## Quick start

PostgreSQL runs in Docker. The server runs on your machine.

> [!NOTE]
> Prefer the full walkthrough? See [auth.lusopoint.com/docs](https://auth.lusopoint.com/docs#development).

```console
# 1. start postgres
make compose-dev-up

# 2. create a signing key (writes ./signing.pem)
make keygen

# 3. create a .env file in the project root
cat > .env <<ENV
DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable
BASE_URL=http://localhost:8080
SESSION_SECRET=$(openssl rand -hex 32)
SIGNING_KEY_PATH=$PWD/signing.pem
AUTO_MIGRATE=true
LOG_LEVEL=debug
DOCS_ENABLED=true
ENV

# 4. load the .env, then set up the database
set -a; source .env; set +a
make migrate-up

# 5. create your first admin user
make seed-user email=you@example.com password=devpass123 admin=1
```

Start it in two terminals:

```bash
make dev-server   # Terminal A: backend on http://localhost:8080
make web-dev      # Terminal B: web UI with hot reload on http://localhost:5173
```

Open **http://localhost:8080** and sign in.

> [!TIP]
> Use `:5173` when you work on the web UI. It reloads instantly and proxies API calls to `:8080`. Use `:8080` to test the real embedded build. Both share the sign-in session.

**Reset the database:** run `make compose-dev-clear` to delete all data, then repeat steps 1, 4, and 5.

---

## Run it in production

Everything runs in Docker on your server. Put the server behind TLS. Caddy is the documented companion; a tunnel such as Cloudflare also works.

```console
cd deployments

# 1. configure
cp .env.example .env
$EDITOR .env
#   Set BASE_URL (your real https URL, e.g. https://auth.example.com)
#   POSTGRES_PASSWORD  -> openssl rand -hex 24
#   SESSION_SECRET     -> openssl rand -hex 32
#   ADMIN_EMAIL / ADMIN_PASSWORD  (your first admin login)

# 2. create the signing key (BACK THIS UP)
mkdir -p signing
openssl genrsa -out signing/signing.pem 2048
sudo chown 65532:65532 signing/signing.pem
chmod 600 signing/signing.pem

# 3. start everything (Postgres + LusoIAM)
docker compose up -d --build
```

The server creates the first admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on the first run. Open your URL, sign in, then go to `/mfa/enroll` and add a second factor.

> [!NOTE]
> The Compose stack publishes host port **32773** (container port `8080`). Point your TLS proxy or tunnel at that port. `BASE_URL` must be the public HTTPS URL that users type.

**Update:** `docker compose up -d --build` · **Logs:** `docker compose logs -f iam`

### Upgrade from PostgreSQL 16

The image is now `postgres:18-alpine`. PostgreSQL 18 cannot use a 16 data directory. Dump the data, check the dump, remove the old volume, then restore. The sequence stops on the first error and keeps one dump for each Compose project, so a retry never dumps from the new database.

- **A step before 3 fails:** the PostgreSQL 16 volume is still in place. Fix the error and run again from step 2. It reuses a valid dump or replaces an incomplete `iam.dump.tmp`.
- **A step after 3 fails:** keep the dump. Fix the PostgreSQL 18 startup or the restore error, then run again from step 2. Step 2 reuses the dump and step 3 uses the saved volume name.

> [!WARNING]
> Back up two things: the **`pgdata`** volume (your whole database) and **`signing/signing.pem`** (it signs your tokens). If you lose the signing key, every issued token stops working.

<details>
<summary><strong>Show the upgrade commands</strong></summary>

```console
cd deployments
set -e

# 1. stop LusoIAM, keep PostgreSQL 16 running
docker compose stop iam

# 2. dump once into a private directory for this project, then check the backup
PROJECT=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(docker compose ps -aq postgres)" || true)
test -n "$PROJECT" || { echo "Compose project not found; run 'docker compose create postgres' and try again"; exit 1; }
BACKUP_DIR="$HOME/pg-upgrade-backup-$PROJECT"
DUMP="$BACKUP_DIR/iam.dump"
if [ ! -s "$DUMP" ]; then
  install -d -m 700 "$BACKUP_DIR"
  # only a PostgreSQL 16 server may write the backup
  docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "SHOW server_version_num"' | grep -q '^16'
  docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$DUMP.tmp"
  test -s "$DUMP.tmp"
  docker compose exec -T postgres pg_restore --list < "$DUMP.tmp" > /dev/null
  mv "$DUMP.tmp" "$DUMP"
fi

# 3. remove this project's database volume and start PostgreSQL 18
VOLUME_FILE="$BACKUP_DIR/volume"
if [ ! -s "$VOLUME_FILE" ]; then
  docker inspect --format '{{range .Mounts}}{{.Name}}{{end}}' "$(docker compose ps -aq postgres)" > "$VOLUME_FILE" || true
fi
VOLUME=$(cat "$VOLUME_FILE")
test -n "$VOLUME" || { echo "Database volume not found; run 'docker compose create postgres' and try again"; exit 1; }
docker compose down
# a retry can find the volume already removed
if ! docker volume rm "$VOLUME" 2>/dev/null; then
  if docker volume inspect "$VOLUME" > /dev/null 2>&1; then
    echo "cannot remove volume $VOLUME"; exit 1
  fi
fi
docker compose up -d --wait postgres

# 4. restore in one transaction; a failure rolls back and you can retry
docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --single-transaction' < "$DUMP"

# 5. start LusoIAM only after a successful restore
docker compose up -d --build
```

</details>

---

## Build and test

| Command | What it does |
| --- | --- |
| `make build` | Compile one binary with the web UI embedded → `./bin/iam-server`. |
| `make run` | Build the binary, then run it. |
| `make test` | Run all unit and integration tests. |
| `make smoke-test` | Quick black-box health check against a running server. |
| `make lint` | Run gofmt, `go vet`, and Biome, as CI does. |
| `make vuln` | Scan Go dependencies with `govulncheck`. |
| `make vuln-web` | Audit the SPA production dependencies with npm. |

`make build` also builds the web UI, so the binary is self-contained.

> [!TIP]
> Run `make help` for every target, including coverage, migrations, seeding, and image builds.

---

## Configuration

You configure the server with environment variables. You always need these four:

| Variable | What it is |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. |
| `BASE_URL` | The public URL of the server. No trailing slash. |
| `SESSION_SECRET` | 32-byte hex secret. Generate with `openssl rand -hex 32`. |
| `SIGNING_KEY_PATH` | Path to the RSA key that signs tokens. |

`BASE_URL` does more than build links. An `https://` value turns on secure cookies and sets the passkey domain. Set it to exactly what users type in the browser.

Common optional settings:

| Variable | Effect |
| --- | --- |
| `LOG_LEVEL`, `LOG_FORMAT` | Log verbosity (`debug`, `info`, `warn`, `error`) and format (`text` or `json`). |
| `AUTO_MIGRATE` | Apply pending migrations on start. Set `false` in `deployments/.env` when you run more than one replica, then run `/migrate` once as a deploy step. |
| `FORCE_MFA` | Require a second factor for every user. Set it in `deployments/.env`. |
| `SIGNUP_ENABLED` | Open public registration at `/signup`. |
| `SESSION_COOKIE_DOMAIN` | Share the session cookie across subdomains for forward-auth. |
| `PROXY_ALLOWED_CALLBACK_ORIGINS` | Allow redirect-back origins for `/proxy/verify`. |
| `TRUSTED_PROXIES` | Trust `X-Forwarded-For` from these CIDR ranges only. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` | Send verification and password-reset email. When `SMTP_HOST` is empty, the server logs email instead. |
| `GOOGLE_*`, `GITHUB_*`, `OIDC_*` | Upstream provider credentials. A provider is active only when its id and secret are set. For generic OIDC, set `OIDC_PROVIDERS` and the matching `OIDC_<SLUG>_ISSUER`, `OIDC_<SLUG>_CLIENT_ID`, and `OIDC_<SLUG>_CLIENT_SECRET` in `deployments/.env`. Compose passes them to the container. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`, `ADMIN_USERNAME` | Seed the first admin account. Read by the Docker entrypoint on the first run. |
| `DOCS_ENABLED` | Serve the reference page at `/docs`. |

The full list, with **when to set each one**, is on the in-app docs page and in [`deployments/.env.example`](deployments/.env.example).

> [!TIP]
> Set `DOCS_ENABLED=true` in development. Open **`/docs`** for the environment reference, protocol endpoints, and setup guides.

---

## Protocol surface

| Area | Paths |
| --- | --- |
| 🩺 Health and metrics | `/healthz`, `/readyz`, `/metrics` |
| 🔎 OIDC discovery | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |
| 🔑 OAuth 2.0 / OIDC | `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/introspect`, `/oauth2/revoke` |
| 🎫 CAS | `/cas/login`, `/cas/logout`, `/cas/validate`, `/cas/serviceValidate`, `/cas/p3/serviceValidate`, `/cas/proxyValidate`, `/cas/p3/proxyValidate` |
| 🔗 Upstream SSO | `/oauth/authorize/{provider}`, `/oauth/callback/{provider}` |
| 🚦 Reverse proxy | `/proxy/verify` (forward-auth) |
| 🖥️ Admin | `/admin` (React UI), `/admin/v1` (REST API) |
| 📚 Reference | `/docs` (when `DOCS_ENABLED=true`) |

Supported OIDC flows: Authorization Code with PKCE, Client Credentials, and Refresh Token. `/proxy/verify` returns `X-Auth-User`, `X-Auth-Email`, and `X-Auth-Groups` on success.

---

## Common commands

| Command | What it does |
| --- | --- |
| `make help` | List every target. |
| `make seed-user email=… password=… admin=1` | Create a user. |
| `make grant-admin email=…` | Make an existing user an admin. |
| `make seed-client` | Register a test OIDC client with PKCE. |
| `make migrate-up` | Apply database migrations. |
| `make migrate-container` | Run `go run ./cmd/migrate` on the host against `DATABASE_URL` (the local dev database by default). It needs Go and a reachable database. Use it when `AUTO_MIGRATE=false`. |
| `make migrate-new name=…` | Create a new migration pair. |
| `make rotate-key dir=/etc/iam/keys` | Generate a new signing key. |
| `make compose-dev-up` / `-down` / `-clear` | Manage the development PostgreSQL container. |

---

## Documentation

The server ships a full [reference page](https://auth.lusopoint.com/docs). Set `DOCS_ENABLED=true` and open **`/docs`**.

---

## Contributing

- Branch prefixes: `feat-`, `fix-`, `chore-`, `docs-`, `test-`, …
- Commits: [Conventional Commits](https://www.conventionalcommits.org/) (`feat: add WebAuthn enrollment`).
- A pull request needs passing CI, one approval, and no lint warnings.
- Keep the runtime section of `go.mod` short. Justify any new `require` entry.

Run `make test` and `make lint` before you open a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full local setup and PR checklist, or the `/docs` page under **Contribution**.

---

## Security

> [!CAUTION]
> Did you find a security vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for how to report it privately.

The server ships with safe defaults: Argon2id password hashing, HMAC-signed `HttpOnly` cookies, CSRF protection on browser flows, a strict Content-Security-Policy, and rate limits on the login and token endpoints.

---

## License

AGPL-3.0. See [LICENSE](LICENSE).
