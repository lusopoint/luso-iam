package docs

type Access string

const (
	AccessPublic  Access = "Public"  // no authentication
	AccessSession Access = "Session" // a logged-in end-user session
	AccessAdmin   Access = "Admin"   // admin session
	AccessClient  Access = "Client"  // an OAuth2 client (secret or bearer token)
	AccessSpec    Access = "Spec"    // protocol-defined validation endpoint
)

type Endpoint struct {
	Method string
	Path   string
	Access Access
	Desc   string
}

type EndpointGroup struct {
	Title string
	Intro string
	Items []Endpoint
}

type EnvVar struct {
	Name     string
	Default  string
	Required bool
	Secret   bool
	Desc     string
}

type EnvGroup struct {
	Title string
	Vars  []EnvVar
}

type SetupStep struct {
	Title string
	Body  string
	Code  string
}

type Guide struct {
	Title   string
	Intro   string
	Prereqs []string
	Steps   []SetupStep
}

type System struct {
	Name     string
	Summary  string
	Features []string
}

type Content struct {
	Guides    []Guide
	APIGroups []EndpointGroup
	EnvGroups []EnvGroup
	Systems   []System
}

func Build() Content {
	return Content{
		Guides:    guides(),
		APIGroups: apiGroups(),
		EnvGroups: envGroups(),
		Systems:   systems(),
	}
}

func guides() []Guide {
	return []Guide{
		{
			Title: "Development",
			Intro: "Postgres runs in Docker; the server runs on your machine. The whole loop is driven by make targets.",
			Prereqs: []string{
				"Go 1.26+",
				"Node 22+ (only to build the web UI)",
				"Docker (provides PostgreSQL 16+)",
			},
			Steps: []SetupStep{
				{
					Title: "Start Postgres",
					Body:  "Brings up a local PostgreSQL in Docker.",
					Code:  "make compose-dev-up",
				},
				{
					Title: "Generate a signing key",
					Body:  "Writes an RSA key to ./signing.pem for signing id_tokens (dev use).",
					Code:  "make keygen",
				},
				{
					Title: "Create a .env in the project root",
					Body:  "The minimum needed to boot. SESSION_SECRET must be at least 32 bytes.",
					Code: "cat > .env <<ENV\n" +
						"DATABASE_URL=postgres://iam:iam@localhost:5432/iam?sslmode=disable\n" +
						"BASE_URL=http://localhost:8080\n" +
						"SESSION_SECRET=$(openssl rand -hex 32)\n" +
						"SIGNING_KEY_PATH=$PWD/signing.pem\n" +
						"AUTO_MIGRATE=true\n" +
						"LOG_LEVEL=debug\n" +
						"DOCS_ENABLED=true\n" +
						"ENV",
				},
				{
					Title: "Load the env and apply migrations",
					Body:  "Source the .env into your shell, then create the schema.",
					Code:  "set -a; source .env; set +a\nmake migrate-up",
				},
				{
					Title: "Create your first admin user",
					Body:  "Seeds a local account you can sign in with.",
					Code:  "make seed-user email=you@example.com password=devpass123 admin=1",
				},
				{
					Title: "Run the backend and the web UI",
					Body:  "Two terminals. :8080 serves the embedded build; :5173 is the Vite dev server with hot reload. Both share the login session, use :5173 while working on the UI, :8080 to test the real build. Reset all data any time with make compose-dev-clear\n\n But you can also just run the server and build the web",
					Code:  "make dev-server   # Terminal A -> http://localhost:8080\nmake web-dev      # Terminal B -> http://localhost:5173 \n\n OR \n\n make web-build\n\n make dev-server",
				},
			},
		},
		{
			Title: "Production (Docker Compose)",
			Intro: "Everything runs in Docker on your server: PostgreSQL plus the single IAM binary. Terminate TLS in front of it.",
			Prereqs: []string{
				"Docker on the host",
				"A domain and TLS in front (reverse proxy or tunnel)",
				"Two things you MUST back up: the pgdata volume and signing/signing.pem",
			},
			Steps: []SetupStep{
				{
					Title: "Configure",
					Body:  "Copy the compose env template and fill in real values: BASE_URL (your real https URL), POSTGRES_PASSWORD, SESSION_SECRET, and ADMIN_EMAIL / ADMIN_PASSWORD (your first admin login).",
					Code:  "cd deployments\ncp .env.example .env\n$EDITOR .env\n#   POSTGRES_PASSWORD: openssl rand -hex 24\n#   SESSION_SECRET:    openssl rand -hex 32",
				},
				{
					Title: "Create and secure the signing key",
					Body:  "This key signs every token. Own it by the container's non-root uid and lock down the mode. Back it up off-host: if you lose it, every issued token stops working.",
					Code:  "mkdir -p signing\nopenssl genrsa -out signing/signing.pem 2048\nsudo chown 65532:65532 signing/signing.pem\nchmod 600 signing/signing.pem",
				},
				{
					Title: "Put it behind TLS",
					Body:  "The server speaks HTTP; terminate HTTPS in front with a reverse proxy (Caddy is the documented companion; Traefik works too) or a tunnel (e.g. Cloudflare) pointing at the container's HTTP port. BASE_URL must be the public https URL, and it must match what the proxy serves.",
				},
				{
					Title: "Boot",
					Body:  "Starts Postgres and IAM. The server creates the first admin account from ADMIN_EMAIL / ADMIN_PASSWORD on first run.",
					Code:  "docker compose up -d --build",
				},
				{
					Title: "Harden",
					Body:  "Sign in, then enroll a second factor at /mfa/enroll. Consider SIGNUP_ENABLED=false so registration stays closed, and set SESSION_COOKIE_DOMAIN plus PROXY_ALLOWED_CALLBACK_ORIGINS if you use the reverse-proxy companion across subdomains.",
				},
				{
					Title: "Operate",
					Body:  "Update by rebuilding; follow logs with the compose logs command.",
					Code:  "docker compose up -d --build   # update\ndocker compose logs -f iam     # logs",
				},
			},
		},
	}
}

func apiGroups() []EndpointGroup {
	return []EndpointGroup{
		{
			Title: "Health & discovery",
			Intro: "Unauthenticated endpoints for OIDC metadata.",
			Items: []Endpoint{
				{"GET", "/healthz", AccessPublic, "Liveness. Returns 200 whenever the process is up."},
				{"GET", "/readyz", AccessPublic, "Readiness. Returns 200 only when the database is reachable."},
				{"GET", "/.well-known/openid-configuration", AccessPublic, "OIDC discovery document."},
				{"GET", "/.well-known/jwks.json", AccessPublic, "JSON Web Key Set: the public keys tokens are signed with."},
			},
		},
		{
			Title: "OAuth 2.0 / OpenID Connect provider",
			Intro: "The authorization-server surface. Supported flows: Authorization Code + PKCE, Client Credentials, Refresh Token.",
			Items: []Endpoint{
				{"GET", "/oauth2/authorize", AccessSession, "Authorization endpoint. Starts the code flow; requires a user session."},
				{"POST", "/oauth2/authorize", AccessSession, "Consent submission for the authorization endpoint."},
				{"POST", "/oauth2/token", AccessClient, "Token endpoint: code exchange, refresh, client credentials."},
				{"GET", "/oauth2/userinfo", AccessClient, "UserInfo endpoint (bearer token)."},
				{"POST", "/oauth2/userinfo", AccessClient, "UserInfo endpoint (bearer token)."},
				{"POST", "/oauth2/introspect", AccessClient, "RFC 7662 token introspection."},
				{"POST", "/oauth2/revoke", AccessClient, "RFC 7009 token revocation."},
			},
		},
		{
			Title: "CAS",
			Intro: "CAS 2.0 / 3.0 protocol endpoints. Validation responses are XML.",
			Items: []Endpoint{
				{"GET", "/cas/login", AccessPublic, "CAS login. Authenticates the user and issues a service ticket for the requested service."},
				{"POST", "/cas/login", AccessPublic, "Credential submission for CAS login."},
				{"GET", "/cas/logout", AccessSession, "Ends the session (single logout)."},
				{"GET", "/cas/validate", AccessSpec, "CAS 1.0 ticket validation (plain text)."},
				{"GET", "/cas/serviceValidate", AccessSpec, "CAS 2.0 ticket validation."},
				{"GET", "/cas/p3/serviceValidate", AccessSpec, "CAS 3.0 ticket validation (adds released attributes)."},
				{"GET", "/cas/proxyValidate", AccessSpec, "Proxy-ticket validation."},
				{"GET", "/cas/p3/proxyValidate", AccessSpec, "CAS 3.0 proxy-ticket validation."},
			},
		},
		{
			Title: "Reverse-proxy companion",
			Intro: "forward-auth endpoint for Caddy (primary) and Traefik.",
			Items: []Endpoint{
				{"GET", "/proxy/verify", AccessSession, "Returns 200 with X-Auth-User / X-Auth-Email / X-Auth-Groups on success; 401 with a Location header pointing to login on failure. Accepts a session cookie or a bearer token."},
			},
		},
		{
			Title: "Upstream SSO (federation)",
			Intro: "Login via an external identity provider (Google, GitHub, Microsoft, GitLab, generic OIDC/OAuth2).",
			Items: []Endpoint{
				{"GET", "/oauth/authorize/{provider}", AccessPublic, "Begin login with an upstream provider."},
				{"GET", "/oauth/callback/{provider}", AccessPublic, "Upstream callback. Links to or creates the local user."},
			},
		},
		{
			Title: "Self-service",
			Intro: "End user account flows. Registration is closed unless SIGNUP_ENABLED is set.",
			Items: []Endpoint{
				{"GET", "/signup", AccessPublic, "Registration form."},
				{"POST", "/signup", AccessPublic, "Create an account and send a verification email."},
				{"GET", "/verify", AccessPublic, "Email-verification link handler."},
				{"GET", "/password/forgot", AccessPublic, "Forgot-password form."},
				{"POST", "/password/forgot", AccessPublic, "Request a password-reset email."},
				{"GET", "/password/reset", AccessPublic, "Password-reset form (token in the query)."},
				{"POST", "/password/reset", AccessPublic, "Set a new password with a valid reset token."},
			},
		},
		{
			Title: "MFA (challenge & enrollment)",
			Intro: "Second factor challenge during login, and enrollment for the signed in user. Supports TOTP, WebAuthn/passkeys, and backup codes.",
			Items: []Endpoint{
				{"GET", "/mfa", AccessSession, "MFA challenge page (pending-MFA session)."},
				{"POST", "/mfa/totp", AccessSession, "Submit a TOTP code."},
				{"POST", "/mfa/webauthn/begin", AccessSession, "Begin a WebAuthn assertion."},
				{"POST", "/mfa/webauthn/finish", AccessSession, "Complete a WebAuthn assertion."},
				{"GET", "/mfa/backup", AccessSession, "Backup-code challenge page."},
				{"POST", "/mfa/backup", AccessSession, "Submit a backup code."},
				{"GET", "/mfa/enroll", AccessSession, "Enrollment landing page."},
				{"GET", "/mfa/enroll/totp", AccessSession, "Begin TOTP enrollment (QR + secret)."},
				{"POST", "/mfa/enroll/totp/confirm", AccessSession, "Confirm TOTP enrollment."},
				{"POST", "/mfa/enroll/webauthn/begin", AccessSession, "Begin WebAuthn enrollment."},
				{"POST", "/mfa/enroll/webauthn/finish", AccessSession, "Complete WebAuthn enrollment."},
				{"POST", "/mfa/enroll/backup", AccessSession, "Generate a fresh set of backup codes."},
				{"POST", "/mfa/methods/{id}/delete", AccessSession, "Remove an enrolled method."},
			},
		},
		{
			Title: "Admin API",
			Intro: "Management REST API under /admin/v1. Requires an admin session or a machine to machine client with the admin scope. The React admin UI is served at /admin.",
			Items: []Endpoint{
				{"GET", "/admin", AccessAdmin, "Admin single-page application."},
				{"GET", "/admin/v1/me", AccessAdmin, "The current admin identity."},
				{"GET", "/admin/v1/users", AccessAdmin, "List users."},
				{"POST", "/admin/v1/users", AccessAdmin, "Create a user."},
				{"GET", "/admin/v1/users/{id}", AccessAdmin, "Get a user."},
				{"PATCH", "/admin/v1/users/{id}", AccessAdmin, "Update a user."},
				{"DELETE", "/admin/v1/users/{id}", AccessAdmin, "Soft-delete a user."},
				{"POST", "/admin/v1/users/{id}/lock", AccessAdmin, "Lock a user."},
				{"POST", "/admin/v1/users/{id}/unlock", AccessAdmin, "Unlock a user."},
				{"POST", "/admin/v1/users/{id}/password", AccessAdmin, "Set / force-reset a user's password."},
				{"POST", "/admin/v1/users/{id}/revoke-all", AccessAdmin, "Revoke all of a user's sessions."},
				{"GET", "/admin/v1/users/{id}/sessions", AccessAdmin, "List a user's sessions."},
				{"GET", "/admin/v1/users/{id}/mfa", AccessAdmin, "List a user's MFA methods."},
				{"DELETE", "/admin/v1/users/{id}/mfa", AccessAdmin, "Remove all of a user's MFA methods."},
				{"DELETE", "/admin/v1/users/{id}/mfa/{methodId}", AccessAdmin, "Remove one MFA method."},
				{"GET", "/admin/v1/users/{id}/federation", AccessAdmin, "List a user's federated identities."},
				{"DELETE", "/admin/v1/users/{id}/federation/{linkId}", AccessAdmin, "Unlink a federated identity."},
				{"GET", "/admin/v1/clients", AccessAdmin, "List OIDC/OAuth2 clients."},
				{"POST", "/admin/v1/clients", AccessAdmin, "Register a client."},
				{"GET", "/admin/v1/clients/{id}", AccessAdmin, "Get a client."},
				{"PATCH", "/admin/v1/clients/{id}", AccessAdmin, "Update a client (incl. require_allowlist)."},
				{"DELETE", "/admin/v1/clients/{id}", AccessAdmin, "Delete a client."},
				{"POST", "/admin/v1/clients/{id}/rotate", AccessAdmin, "Rotate a client secret."},
				{"GET", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "List a client's email allow-list."},
				{"POST", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "Add emails to a client's allow-list."},
				{"DELETE", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "Remove emails from a client's allow-list."},
				{"GET", "/admin/v1/cas-services", AccessAdmin, "List CAS services."},
				{"POST", "/admin/v1/cas-services", AccessAdmin, "Register a CAS service."},
				{"GET", "/admin/v1/cas-services/{id}", AccessAdmin, "Get a CAS service."},
				{"PATCH", "/admin/v1/cas-services/{id}", AccessAdmin, "Update a CAS service (incl. require_allowlist)."},
				{"DELETE", "/admin/v1/cas-services/{id}", AccessAdmin, "Delete a CAS service."},
				{"GET", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "List a CAS service's email allow-list."},
				{"POST", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "Add emails to a CAS service's allow-list."},
				{"DELETE", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "Remove emails from a CAS service's allow-list."},
				{"GET", "/admin/v1/federation/providers", AccessAdmin, "List configured upstream providers."},
				{"GET", "/admin/v1/audit", AccessAdmin, "Search the audit log."},
				{"GET", "/admin/v1/keys", AccessAdmin, "View active signing keys (JWKS)."},
			},
		},
		{
			Title: "Documentation",
			Intro: "This page.",
			Items: []Endpoint{
				{"GET", "/docs", AccessPublic, "This reference. Served only when DOCS_ENABLED is set."},
			},
		},
	}
}

func envGroups() []EnvGroup {
	return []EnvGroup{
		{
			Title: "Core",
			Vars: []EnvVar{
				{Name: "BASE_URL", Default: "http://localhost:8080", Required: true, Desc: "Externally reachable URL of this server. Used in OIDC discovery, CAS redirects, and email links."},
				{Name: "SESSION_SECRET", Required: true, Secret: true, Desc: "HMAC key for signing session cookies. At least 32 bytes after hex decoding."},
				{Name: "ENV", Default: "dev", Desc: "Free-form environment tag (dev | staging | prod) surfaced in logs and metrics."},
				{Name: "AUTO_MIGRATE", Default: "true", Desc: "Apply any pending database migrations on boot."},
				{Name: "DOCS_ENABLED", Default: "false", Desc: "Serve this documentation page at /docs. Off by default."},
				{Name: "CONFIG_FILE", Desc: "Path to an optional YAML overlay applied before env vars. Non-secret fields only."},
			},
		},
		{
			Title: "HTTP server",
			Vars: []EnvVar{
				{Name: "HTTP_ADDR", Default: ":8080", Desc: "Listen address."},
				{Name: "HTTP_READ_TIMEOUT", Default: "30s", Desc: "Request read timeout."},
				{Name: "HTTP_WRITE_TIMEOUT", Default: "60s", Desc: "Response write timeout."},
				{Name: "HTTP_SHUTDOWN_TIMEOUT", Default: "30s", Desc: "Graceful-shutdown grace period."},
			},
		},
		{
			Title: "Database",
			Vars: []EnvVar{
				{Name: "DATABASE_URL", Required: true, Secret: true, Desc: "PostgreSQL connection string (postgres://user:pass@host:5432/db)."},
				{Name: "DB_MAX_CONNS", Default: "20", Desc: "Maximum pooled connections."},
				{Name: "DB_MIN_CONNS", Default: "2", Desc: "Minimum idle connections."},
				{Name: "DB_CONN_MAX_LIFETIME", Default: "1h", Desc: "Maximum lifetime of a pooled connection."},
			},
		},
		{
			Title: "Logging",
			Vars: []EnvVar{
				{Name: "LOG_LEVEL", Default: "info", Desc: "debug | info | warn | error."},
				{Name: "LOG_FORMAT", Default: "text", Desc: "json | text."},
			},
		},
		{
			Title: "Crypto & tokens",
			Vars: []EnvVar{
				{Name: "SIGNING_KEY_PATH", Desc: "Path to a PEM-encoded RSA private key used to sign id_tokens. If unset, an ephemeral key is generated at startup (tokens are invalidated on restart)."},
			},
		},
		{
			Title: "Sessions & proxy trust",
			Vars: []EnvVar{
				{Name: "SESSION_COOKIE_DOMAIN", Desc: "Override the session cookie's Domain attribute."},
				{Name: "TRUSTED_PROXIES", Desc: "CIDR allowlist of proxy IP ranges trusted for X-Forwarded-For."},
			},
		},
		{
			Title: "MFA",
			Vars: []EnvVar{
				{Name: "MFA_ISSUER", Desc: "TOTP issuer label shown in authenticator apps."},
				{Name: "MFA_WEBAUTHN_RP_NAME", Desc: "WebAuthn relying-party display name."},
				{Name: "FORCE_MFA", Default: "false", Desc: "Require MFA for all users."},
			},
		},
		{
			Title: "Outbound email (SMTP)",
			Vars: []EnvVar{
				{Name: "SMTP_HOST", Desc: "SMTP server host. When empty, emails are logged instead of sent (dev only)."},
				{Name: "SMTP_PORT", Desc: "SMTP server port (e.g. 587)."},
				{Name: "SMTP_USERNAME", Desc: "SMTP auth username."},
				{Name: "SMTP_PASSWORD", Secret: true, Desc: "SMTP auth password."},
				{Name: "SMTP_FROM", Desc: "From address for outbound mail."},
			},
		},
		{
			Title: "Self-service signup",
			Vars: []EnvVar{
				{Name: "SIGNUP_ENABLED", Default: "false", Desc: "Open public registration at /signup."},
				{Name: "SIGNUP_MIN_PASSWORD_LENGTH", Default: "12", Desc: "Minimum password length for self-signup."},
				{Name: "SIGNUP_TOKEN_TTL_HOURS", Default: "24", Desc: "Lifetime of email-verification links, in hours."},
			},
		},
		{
			Title: "Reverse proxy",
			Vars: []EnvVar{
				{Name: "PROXY_ALLOWED_CALLBACK_ORIGINS", Desc: "Allowlist of cross-origin post-login destinations honoured by /proxy/verify."},
			},
		},
		{
			Title: "Federation (upstream SSO)",
			Vars: []EnvVar{
				{Name: "GOOGLE_CLIENT_ID", Desc: "Google OAuth client id. The provider is active only when both id and secret are set."},
				{Name: "GOOGLE_CLIENT_SECRET", Secret: true, Desc: "Google OAuth client secret."},
				{Name: "GITHUB_CLIENT_ID", Desc: "GitHub OAuth client id."},
				{Name: "GITHUB_CLIENT_SECRET", Secret: true, Desc: "GitHub OAuth client secret."},
				{Name: "OIDC_PROVIDERS", Desc: "Comma-separated slugs enabling generic OIDC upstreams (e.g. okta,keycloak,auth0)."},
				{Name: "OIDC_<SLUG>_ISSUER", Desc: "Per-provider issuer URL. Repeat the block for each slug in OIDC_PROVIDERS."},
				{Name: "OIDC_<SLUG>_CLIENT_ID", Desc: "Per-provider client id."},
				{Name: "OIDC_<SLUG>_CLIENT_SECRET", Secret: true, Desc: "Per-provider client secret."},
				{Name: "OIDC_<SLUG>_DISPLAY_NAME", Desc: "Per-provider button label (optional)."},
				{Name: "OIDC_<SLUG>_SCOPES", Desc: "Per-provider space-separated scopes (optional)."},
			},
		},
	}
}

func systems() []System {
	return []System{
		{
			Name:    "CAS gateway",
			Summary: "Entry-point SSO protocol. Accepts CAS 2.0 / 3.0 authentication and fulfils it from the local IdP or an upstream provider.",
			Features: []string{
				"CAS 2.0 and 3.0 login, logout, and ticket validation",
				"CAS 3.0 attribute release, configured per service",
				"Proxy-ticket validation",
				"Bridges to an upstream OIDC/OAuth login when the user isn't authenticated locally",
			},
		},
		{
			Name:    "OpenID Connect / OAuth 2.0 provider",
			Summary: "A standards-conformant authorization server.",
			Features: []string{
				"Authorization Code + PKCE, Client Credentials, and Refresh Token flows",
				"Discovery document and JWKS endpoint",
				"Token introspection (RFC 7662) and revocation (RFC 7009)",
				"UserInfo endpoint; acr/amr carried from the authenticating session",
			},
		},
		{
			Name:    "Upstream SSO federation",
			Summary: "Delegates authentication to external identity providers and maps the result to a local user.",
			Features: []string{
				"Built-in Google and GitHub; config-driven generic OIDC and OAuth2",
				"Account linking: match by (provider, sub), then by email, else create",
				"Caches provider claims for later attribute release",
			},
		},
		{
			Name:    "Multi-factor authentication",
			Summary: "Second-factor challenge on login and self-service enrollment.",
			Features: []string{
				"TOTP (RFC 6238) with QR enrollment",
				"WebAuthn / FIDO2 passkeys",
				"Single-use backup codes",
				"Per-user and per-client (acr_values) enforcement; optional FORCE_MFA",
			},
		},
		{
			Name:    "Per-service email allow-list",
			Summary: "Restricts an individual OIDC client or CAS service to an explicit set of user emails.",
			Features: []string{
				"Opt-in per service via require_allowlist; default open",
				"OIDC enforced at the authorization-code chokepoint; CAS enforced at ticket issuance",
				"A per-service access gate, denial never locks the account",
				"Managed from the admin API and UI",
			},
		},
		{
			Name:    "Reverse-proxy companion",
			Summary: "A forward-auth endpoint that lets any compatible proxy delegate authentication to the IAM server.",
			Features: []string{
				"First-class Caddy (forward_auth) support; Traefik (ForwardAuth) supported",
				"Returns identity headers (X-Auth-User / -Email / -Groups) on success",
				"Accepts a session cookie or a bearer token",
			},
		},
		{
			Name:    "Admin portal",
			Summary: "A REST API and React UI for operating the server.",
			Features: []string{
				"Manage users, clients, CAS services, allow-lists, and upstream providers",
				"Rotate client secrets; view and trigger signing-key rotation",
				"Search and export the audit log",
			},
		},
		{
			Name:    "Sessions & key management",
			Summary: "Browser-session lifecycle and the JWKS that signs tokens.",
			Features: []string{
				"HMAC-signed session cookies with sliding expiry; the session doubles as the CAS ticket-granting ticket",
				"JWKS with zero-downtime key rotation (sign with the new key, validate against both, retire the old)",
			},
		},
		{
			Name:    "Audit logging",
			Summary: "An append-only record of every security-relevant event.",
			Features: []string{
				"Immutable log with actor, target, IP, user-agent, and JSON metadata",
				"Covers logins, MFA, token lifecycle, admin actions, allow-list changes, and access denials",
			},
		},
		{
			Name:    "Self-service flows",
			Summary: "End-user account management that works without an admin.",
			Features: []string{
				"Optional public signup with email verification",
				"Forgot / reset password via single-use, time-limited tokens",
			},
		},
	}
}
