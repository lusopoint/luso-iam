# IAM Server

IAM Server is a self-hosted identity server. It gives your apps single sign-on (SSO), multi-factor authentication (MFA), and OpenID Connect. It also adds CAS support and protects other apps behind a reverse proxy.

IAM Server ships as **one Go binary** with the admin UI built in. You need only the binary and a PostgreSQL database to run it.

It can:

- Act as an **OIDC / OAuth 2** provider for your apps.
- Act as a **CAS** server for older apps.
- Let users **sign in with Google, GitHub, or any OIDC provider** (Microsoft, Okta, GitLab, Keycloak).
- Enforce **MFA** (authenticator apps and passkeys).
- Protect other apps behind **Caddy or Traefik** with forward-auth.
- Give you a built-in **admin UI** to manage everything.

---

## Requirements

- **Go** 1.26+
- **Node** 20+ (needed only to build the web UI)
- **Docker** (for PostgreSQL and for production deployment)
- **PostgreSQL** 16+ (Docker provides this automatically)

---

## Run it locally (development)

Postgres runs in Docker. The server runs on your machine.

```bash
# 1. Start Postgres
make compose-dev-up

# 2. Create a signing key (writes ./signing.pem)
make keygen

# 3. Create a .env file in the project root
cat > .env <<ENV
DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable
BASE_URL=http://localhost:8080
SESSION_SECRET=$(openssl rand -hex 32)
SIGNING_KEY_PATH=$PWD/signing.pem
AUTO_MIGRATE=true
LOG_LEVEL=debug
ENV

# 4. Load the .env into your shell, then set up the database
set -a; source .env; set +a
make migrate-up

# 5. Create your first admin user
make seed-user email=you@example.com password=devpass123 admin=1
```

Start it in two terminals:

```bash
make dev-server   # Terminal A: backend on http://localhost:8080
make web-dev      # Terminal B: web UI with hot reload on http://localhost:5173
```

Open **http://localhost:8080** and sign in.

> Use `:5173` when you work on the web UI. It reloads instantly. Use `:8080` to test the real embedded build. Both share the login session.

**Reset the database.** Run `make compose-dev-clear` to delete all data. Then repeat steps 1, 4, and 5.

---

## Run it in production (Docker)

Everything runs in Docker on your server.

```bash
cd deployments

# 1. Configure
cp .env.example .env
$EDITOR .env
#   Set: BASE_URL (your real https URL, e.g. https://auth.example.com)
#        POSTGRES_PASSWORD   (openssl rand -hex 24)
#        SESSION_SECRET      (openssl rand -hex 32)
#        ADMIN_EMAIL / ADMIN_PASSWORD   (your first admin login)

# 2. Create the signing key (BACK THIS UP, see below)
mkdir -p signing
openssl genrsa -out signing/signing.pem 2048
sudo chown 65532:65532 signing/signing.pem
chmod 600 signing/signing.pem

# 3. Create a Cloudflare tunnel to http://localhost:32773

# 4. Start everything (Postgres + IAM)
docker compose up -d --build
```

The server creates the first admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

Open your URL and sign in. Then go to `/mfa/enroll` and add a second factor.

**Updates:** run `docker compose up -d --build`.
**Logs:** run `docker compose logs -f iam`.

### Two things you must back up

- The **`pgdata`** volume holds your whole database.
- The **`signing/signing.pem`** file signs your tokens. If you lose it, every issued token stops working.

---

## Build and test

```bash
make build        # compile one binary with the web UI embedded -> ./bin/iam-server
make run          # build, then run it
make test         # run all tests
make smoke-test   # quick health check against a running server
```

The `make build` target also builds the web UI. This makes the binary self-contained.

---

## Configuration

You configure the server with environment variables. You always need these four:

| Variable           | What it is                                               |
| ------------------ | -------------------------------------------------------- |
| `DATABASE_URL`     | PostgreSQL connection string                             |
| `BASE_URL`         | The public URL of the server (no trailing slash)         |
| `SESSION_SECRET`   | 32-byte hex secret, generate with `openssl rand -hex 32` |
| `SIGNING_KEY_PATH` | Path to the RSA key that signs tokens                    |

`BASE_URL` does more than build links. When `BASE_URL` starts with `https://`, the server turns on secure cookies. The server also derives the passkey domain from the host. So set `BASE_URL` to exactly what users type in the browser.

Common optional settings: `LOG_LEVEL` (`debug`/`info`/`warn`/`error`), `LOG_FORMAT` (`text`/`json`), `AUTO_MIGRATE` (`true`/`false`), and `FORCE_MFA` (`true` to require MFA for everyone). The full list with examples is in `deployments/.env.example`.

---

## Useful commands

```bash
make seed-user email=... password=... admin=1   # create a user
make grant-admin email=...                       # make an existing user an admin
make migrate-up                                  # apply database migrations
make rotate-key dir=/etc/iam/keys                # generate a new signing key
make compose-dev-up / -down / -clear             # manage the dev Postgres container
```

Run `make help` to see every target.

---

## Set up the rest

This README covers how to start the server. For the deeper setup, see the **Setup & Operations Guide**. It covers upstream login providers, CAS and OIDC app registration, MFA enrolment, and the reverse proxy.

---

## Security

Did you find a security vulnerability? Do not open a public issue. See [SECURITY.md](SECURITY.md) for how to report it privately through GitHub.

## License

AGPL-3.0 license. See [LICENSE](LICENSE).
