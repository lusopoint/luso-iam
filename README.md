<div align="center">
# IAM Server

**One Go binary for single sign-on, multi-factor authentication, and OpenID Connect.**

Self-hosted - single binary - Docker-native - CAS + OIDC + reverse-proxy auth

[Quick start](#quick-start) ·
[Configuration](#configuration) ·
[Commands](#common-commands) ·
[Full docs](#documentation) ·
[Security](#security) ·
[License](#license)

</div>

---

IAM Server is a self-hosted identity server. It gives your apps single sign-on (SSO), multi-factor authentication (MFA), and OpenID Connect. It also adds CAS support and protects other apps behind a reverse proxy if needed.

IAM Server ships as **one Go binary** with the admin UI built in. You need only the binary and a PostgreSQL database to run it.

### What it does

| Capability                    | Summary                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| **OIDC / OAuth 2.0 provider** | Act as an authorization server for your apps (PKCE, discovery, JWKS, introspection, revocation). |
| **CAS 2.0 / 3.0 server**      | Serve older apps that speak CAS. Bridge them to modern SSO.                                      |
| **Upstream SSO**              | Let users sign in with Google, GitHub, or any OIDC provider (Microsoft, Okta, GitLab, Keycloak). |
| **MFA**                       | Enforce TOTP, WebAuthn/passkeys, and single-use backup codes.                                    |
| **Reverse-proxy auth**        | Protect any app behind Caddy or Traefik with a forward-auth endpoint.                            |
| **Admin portal**              | Manage users, clients, services, and providers from a built-in React UI.                         |

---

## Requirements

- **Go** 1.26+
- **Node** 22+ (only to build the web UI)
- **Docker** (for PostgreSQL, and for production deployment)
- **PostgreSQL** 16+ (Docker provides this)

---

## [Quick start](https://auth.lusopoint.com/docs#development)

Postgres runs in Docker. The server runs on your machine.

> [More information auth.lusopoint.com/docs]()

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

> Use `:5173` when you work on the web UI; it reloads instantly. Use `:8080` to test the real embedded build. Both share the sign-in session.

**Reset the database:** run `make compose-dev-clear` to delete all data, then repeat steps 1, 4, and 5.

---

## [Run it in production (Docker)](https://auth.lusopoint.com/docs#production)

Everything runs in Docker on your server. Put the server behind TLS (Caddy is the documented companion; a tunnel such as Cloudflare also works).

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

# 3. start everything (Postgres + IAM)
docker compose up -d --build
```

The server creates the first admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on the first run. Open your URL, sign in, then go to `/mfa/enroll` and add a second factor.

**Update:** `docker compose up -d --build` · **Logs:** `docker compose logs -f iam`

> **Back up two things:** the **`pgdata`** volume (your whole database) and **`signing/signing.pem`** (it signs your tokens, if you lose it, every issued token stops working).

---

## [Build and test](http://localhost:8080/docs#scripts)

```bash
make build        # compile one binary with the web UI embedded -> ./bin/iam-server
make run          # build, then run it
make test         # run all unit + integration tests
make smoke-test   # quick health check against a running server
```

`make build` also builds the web UI, so the binary is self-contained.

---

## [Configuration](https://auth.lusopoint.com/docs#environment)

You configure the server with environment variables. You always need these four:

> [More information auth.lusopoint.com/docs](https://auth.lusopoint.com/docs#environment)

| Variable           | What it is                                               |
| ------------------ | -------------------------------------------------------- |
| `DATABASE_URL`     | PostgreSQL connection string                             |
| `BASE_URL`         | The public URL of the server (no trailing slash)         |
| `SESSION_SECRET`   | 32-byte hex secret; generate with `openssl rand -hex 32` |
| `SIGNING_KEY_PATH` | Path to the RSA key that signs tokens                    |

`BASE_URL` does more than build links. A `https://` value turns on secure cookies and sets the passkey domain. Set it to exactly what users type in the browser.

Common optional settings: `LOG_LEVEL`, `LOG_FORMAT`, `AUTO_MIGRATE`, `FORCE_MFA`, `SIGNUP_ENABLED`, `SESSION_COOKIE_DOMAIN`, `PROXY_ALLOWED_CALLBACK_ORIGINS`, and the federation credentials. The full list with **when to set each one** is on the in-app docs page and in `deployments/.env.example`.

---

## Common commands

```console
make help                                         # list every target
make seed-user email=... password=... admin=1     # create a user
make grant-admin email=...                         # make an existing user an admin
make migrate-up                                    # apply database migrations
make migrate-container                             # same, via the /migrate binary the container image ships (AUTO_MIGRATE=false deploy step)
make rotate-key dir=/etc/iam/keys                  # generate a new signing key
make compose-dev-up / -down / -clear               # manage the dev Postgres container
```

---

## [Documentation](https://auth.lusopoint.com/docs)

The server ships a full [reference page](https://auth.lusopoint.com/docs). Set `DOCS_ENABLED=true` and open **`/docs`**.

---

## [Contributing](https://auth.lusopoint.com/docs#contribution)

- Branch prefixes: `feat-`, `fix-`, `chore-`, `docs-`, `test-`, ...
- Commits: [Conventional Commits](https://www.conventionalcommits.org/) (`feat: add WebAuthn enrollment`)
- A pull request needs passing CI, one approval, and no lint warnings
- Keep the runtime section of `go.mod` short; justify any new `require` entry

Run `make test` and `make lint` before you open a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full local setup + PR checklist, or the `/docs` page under **Contribution**.

---

## Security

Did you find a security vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for how to report it privately.

The server ships with safe defaults: Argon2id password hashing, HMAC-signed `HttpOnly` cookies, CSRF protection on browser flows, a strict Content-Security-Policy, and rate limits on the login and token endpoints.

---

## License

AGPL-3.0. See [LICENSE](LICENSE).
