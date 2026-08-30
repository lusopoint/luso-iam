package docs

type Access string

const (
	AccessPublic  Access = "Public"  // no authentication
	AccessSession Access = "Session" // a signed-in end-user session
	AccessAdmin   Access = "Admin"   // an admin session or the admin scope
	AccessClient  Access = "Client"  // an OAuth2 client (secret or bearer token)
	AccessSpec    Access = "Spec"    // a protocol-defined validation endpoint
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
	When     string
}

type EnvGroup struct {
	Title string
	Intro string
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
			Title: "Local development",
			Intro: "Postgres runs in Docker. The server runs on your machine. The make targets drive the whole loop.",
			Prereqs: []string{
				"Go 1.26 or later",
				"Node 22 or later (only to build the web UI)",
				"Docker (it provides PostgreSQL 16 or later)",
			},
			Steps: []SetupStep{
				{
					Title: "Start Postgres",
					Body:  "This command starts a local PostgreSQL in Docker.",
					Code:  "make compose-dev-up",
				},
				{
					Title: "Generate a signing key",
					Body:  "This command writes an RSA key to ./signing.pem. The server signs id_tokens with this key.",
					Code:  "make keygen",
				},
				{
					Title: "Create a .env file in the project root",
					Body:  "This is the minimum needed to start. SESSION_SECRET must be at least 32 bytes.",
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
					Title: "Load the .env and apply migrations",
					Body:  "Load the .env into your shell. Then create the database schema.",
					Code:  "set -a; source .env; set +a\nmake migrate-up",
				},
				{
					Title: "Create your first admin user",
					Body:  "This command seeds a local account. You sign in with this account.",
					Code:  "make seed-user email=you@example.com password=devpass123 admin=1",
				},
				{
					Title: "Run the backend and the web UI",
					Body:  "Use two terminals. Port 8080 serves the embedded build. Port 5173 is the Vite dev server with hot reload. Both share the sign-in session. Use 5173 while you work on the UI. Use 8080 to test the real build. To reset all data, run make compose-dev-clear.",
					Code:  "make dev-server   # Terminal A -> http://localhost:8080\nmake web-dev      # Terminal B -> http://localhost:5173\n\n# Or build the UI once, then run only the backend:\nmake web-build\nmake dev-server",
				},
			},
		},
		{
			Title: "Production (Docker Compose)",
			Intro: "Everything runs in Docker on your server: PostgreSQL and the single IAM binary. Terminate TLS in front of the server.",
			Prereqs: []string{
				"Docker on the host",
				"A domain and TLS in front (a reverse proxy or a tunnel)",
				"A backup plan for two things: the pgdata volume and signing/signing.pem",
			},
			Steps: []SetupStep{
				{
					Title: "Configure the environment",
					Body:  "Copy the compose env template. Fill in real values: BASE_URL (your real https URL), POSTGRES_PASSWORD, SESSION_SECRET, and ADMIN_EMAIL with ADMIN_PASSWORD (your first admin sign-in).",
					Code:  "cd deployments\ncp .env.example .env\n$EDITOR .env\n#   POSTGRES_PASSWORD: openssl rand -hex 24\n#   SESSION_SECRET:    openssl rand -hex 32",
				},
				{
					Title: "Create and protect the signing key",
					Body:  "This key signs every token. Set the owner to the container's non-root user. Restrict the file mode. Back up the key off-host. If you lose the key, every issued token stops working.",
					Code:  "mkdir -p signing\nopenssl genrsa -out signing/signing.pem 2048\nsudo chown 65532:65532 signing/signing.pem\nchmod 600 signing/signing.pem",
				},
				{
					Title: "Put the server behind TLS",
					Body:  "The server speaks HTTP. Terminate HTTPS in front. Use a reverse proxy (Caddy is the documented companion; Traefik also works) or a tunnel (for example, Cloudflare) that points at the container's HTTP port. Set BASE_URL to the public https URL. BASE_URL must match what the proxy serves.",
				},
				{
					Title: "Start the stack",
					Body:  "This command starts Postgres and IAM. The server creates the first admin account from ADMIN_EMAIL and ADMIN_PASSWORD on the first run.",
					Code:  "docker compose up -d --build",
				},
				{
					Title: "Harden the deployment",
					Body:  "Sign in. Then enroll a second factor at /mfa/enroll. Set SIGNUP_ENABLED=false to keep registration closed. Set SESSION_COOKIE_DOMAIN and PROXY_ALLOWED_CALLBACK_ORIGINS if you use the reverse-proxy companion across subdomains.",
				},
				{
					Title: "Operate the server",
					Body:  "Update the server by a rebuild. Follow the logs with the compose logs command.",
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
			Intro: "Unauthenticated endpoints for health checks and OIDC metadata.",
			Items: []Endpoint{
				{"GET", "/healthz", AccessPublic, "Liveness. Returns 200 whenever the process is up."},
				{"GET", "/readyz", AccessPublic, "Readiness. Returns 200 only when the database is reachable."},
				{"GET", "/metrics", AccessPublic, "Prometheus metrics."},
				{"GET", "/.well-known/openid-configuration", AccessPublic, "OIDC discovery document."},
				{"GET", "/.well-known/jwks.json", AccessPublic, "JSON Web Key Set: the public keys that verify tokens."},
			},
		},
		{
			Title: "OAuth 2.0 / OpenID Connect provider",
			Intro: "The authorization-server surface. Supported flows: Authorization Code with PKCE, Client Credentials, and Refresh Token.",
			Items: []Endpoint{
				{"GET", "/oauth2/authorize", AccessSession, "Authorization endpoint. Starts the code flow. Requires a user session."},
				{"POST", "/oauth2/authorize", AccessSession, "Consent submission for the authorization endpoint."},
				{"POST", "/oauth2/token", AccessClient, "Token endpoint: code exchange, refresh, and client credentials."},
				{"GET", "/oauth2/userinfo", AccessClient, "UserInfo endpoint (bearer token)."},
				{"POST", "/oauth2/userinfo", AccessClient, "UserInfo endpoint (bearer token)."},
				{"POST", "/oauth2/introspect", AccessClient, "Token introspection (RFC 7662)."},
				{"POST", "/oauth2/revoke", AccessClient, "Token revocation (RFC 7009)."},
			},
		},
		{
			Title: "CAS",
			Intro: "CAS 2.0 and 3.0 protocol endpoints. The validation responses are XML.",
			Items: []Endpoint{
				{"GET", "/cas/login", AccessPublic, "CAS login. Authenticates the user. Issues a service ticket for the requested service."},
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
			Intro: "The forward-auth endpoint for Caddy (primary) and Traefik.",
			Items: []Endpoint{
				{"GET", "/proxy/verify", AccessSession, "Returns 200 with X-Auth-User, X-Auth-Email, and X-Auth-Groups on success. Returns 401 with a Location header to login on failure. Accepts a session cookie or a bearer token."},
			},
		},
		{
			Title: "Upstream SSO (federation)",
			Intro: "Sign in through an external identity provider (Google, GitHub, Microsoft, GitLab, or generic OIDC/OAuth2).",
			Items: []Endpoint{
				{"GET", "/oauth/authorize/{provider}", AccessPublic, "Starts sign-in with an upstream provider."},
				{"GET", "/oauth/callback/{provider}", AccessPublic, "The upstream callback. Links to or creates the local user."},
			},
		},
		{
			Title: "Self-service",
			Intro: "End-user account flows. Registration stays closed unless you set SIGNUP_ENABLED.",
			Items: []Endpoint{
				{"GET", "/signup", AccessPublic, "Registration form."},
				{"POST", "/signup", AccessPublic, "Creates an account. Sends a verification email."},
				{"GET", "/verify", AccessPublic, "Email-verification link handler."},
				{"GET", "/password/forgot", AccessPublic, "Forgot-password form."},
				{"POST", "/password/forgot", AccessPublic, "Requests a password-reset email."},
				{"GET", "/password/reset", AccessPublic, "Password-reset form (the token is in the query)."},
				{"POST", "/password/reset", AccessPublic, "Sets a new password with a valid reset token."},
			},
		},
		{
			Title: "MFA (challenge & enrollment)",
			Intro: "The second-factor challenge during sign-in, and enrollment for the signed-in user. Supports TOTP, WebAuthn/passkeys, and backup codes.",
			Items: []Endpoint{
				{"GET", "/mfa", AccessSession, "MFA challenge page (a pending-MFA session)."},
				{"POST", "/mfa/totp", AccessSession, "Submits a TOTP code."},
				{"POST", "/mfa/webauthn/begin", AccessSession, "Starts a WebAuthn assertion."},
				{"POST", "/mfa/webauthn/finish", AccessSession, "Completes a WebAuthn assertion."},
				{"GET", "/mfa/backup", AccessSession, "Backup-code challenge page."},
				{"POST", "/mfa/backup", AccessSession, "Submits a backup code."},
				{"GET", "/mfa/enroll", AccessSession, "Enrollment landing page."},
				{"GET", "/mfa/enroll/totp", AccessSession, "Starts TOTP enrollment (a QR code and a secret)."},
				{"POST", "/mfa/enroll/totp/confirm", AccessSession, "Confirms TOTP enrollment."},
				{"POST", "/mfa/enroll/webauthn/begin", AccessSession, "Starts WebAuthn enrollment."},
				{"POST", "/mfa/enroll/webauthn/finish", AccessSession, "Completes WebAuthn enrollment."},
				{"POST", "/mfa/enroll/backup", AccessSession, "Generates a fresh set of backup codes."},
				{"POST", "/mfa/methods/{id}/delete", AccessSession, "Removes an enrolled method."},
			},
		},
		{
			Title: "Admin API",
			Intro: "The management REST API under /admin/v1. It requires an admin session or a machine-to-machine client with the admin scope. The React admin UI is served at /admin.",
			Items: []Endpoint{
				{"GET", "/admin", AccessAdmin, "Admin single-page application."},
				{"GET", "/admin/v1/me", AccessAdmin, "The current admin identity."},
				{"GET", "/admin/v1/users", AccessAdmin, "Lists users."},
				{"POST", "/admin/v1/users", AccessAdmin, "Creates a user."},
				{"GET", "/admin/v1/users/{id}", AccessAdmin, "Gets a user."},
				{"PATCH", "/admin/v1/users/{id}", AccessAdmin, "Updates a user."},
				{"DELETE", "/admin/v1/users/{id}", AccessAdmin, "Soft-deletes a user."},
				{"POST", "/admin/v1/users/{id}/lock", AccessAdmin, "Locks a user."},
				{"POST", "/admin/v1/users/{id}/unlock", AccessAdmin, "Unlocks a user."},
				{"POST", "/admin/v1/users/{id}/password", AccessAdmin, "Sets or force-resets a user's password."},
				{"POST", "/admin/v1/users/{id}/revoke-all", AccessAdmin, "Revokes all of a user's sessions."},
				{"GET", "/admin/v1/users/{id}/sessions", AccessAdmin, "Lists a user's sessions."},
				{"GET", "/admin/v1/users/{id}/mfa", AccessAdmin, "Lists a user's MFA methods."},
				{"DELETE", "/admin/v1/users/{id}/mfa", AccessAdmin, "Removes all of a user's MFA methods."},
				{"DELETE", "/admin/v1/users/{id}/mfa/{methodId}", AccessAdmin, "Removes one MFA method."},
				{"GET", "/admin/v1/users/{id}/federation", AccessAdmin, "Lists a user's federated identities."},
				{"DELETE", "/admin/v1/users/{id}/federation/{linkId}", AccessAdmin, "Unlinks a federated identity."},
				{"GET", "/admin/v1/clients", AccessAdmin, "Lists OIDC/OAuth2 clients."},
				{"POST", "/admin/v1/clients", AccessAdmin, "Registers a client."},
				{"GET", "/admin/v1/clients/{id}", AccessAdmin, "Gets a client."},
				{"PATCH", "/admin/v1/clients/{id}", AccessAdmin, "Updates a client (this includes require_allowlist)."},
				{"DELETE", "/admin/v1/clients/{id}", AccessAdmin, "Deletes a client."},
				{"POST", "/admin/v1/clients/{id}/rotate", AccessAdmin, "Rotates a client secret."},
				{"GET", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "Lists a client's email allow-list."},
				{"POST", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "Adds emails to a client's allow-list."},
				{"DELETE", "/admin/v1/clients/{id}/allowlist", AccessAdmin, "Removes emails from a client's allow-list."},
				{"GET", "/admin/v1/cas-services", AccessAdmin, "Lists CAS services."},
				{"POST", "/admin/v1/cas-services", AccessAdmin, "Registers a CAS service."},
				{"GET", "/admin/v1/cas-services/{id}", AccessAdmin, "Gets a CAS service."},
				{"PATCH", "/admin/v1/cas-services/{id}", AccessAdmin, "Updates a CAS service (this includes require_allowlist)."},
				{"DELETE", "/admin/v1/cas-services/{id}", AccessAdmin, "Deletes a CAS service."},
				{"GET", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "Lists a CAS service's email allow-list."},
				{"POST", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "Adds emails to a CAS service's allow-list."},
				{"DELETE", "/admin/v1/cas-services/{id}/allowlist", AccessAdmin, "Removes emails from a CAS service's allow-list."},
				{"GET", "/admin/v1/federation/providers", AccessAdmin, "Lists the configured upstream providers."},
				{"GET", "/admin/v1/audit", AccessAdmin, "Searches the audit log."},
				{"GET", "/admin/v1/keys", AccessAdmin, "Views the active signing keys (JWKS)."},
			},
		},
		{
			Title: "Documentation",
			Intro: "This page.",
			Items: []Endpoint{
				{"GET", "/docs", AccessPublic, "This reference. The server serves it only when DOCS_ENABLED is set."},
			},
		},
	}
}

func envGroups() []EnvGroup {
	return []EnvGroup{
		{
			Title: "Core",
			Intro: "The four variables every deployment needs, plus a few switches. Set BASE_URL and SESSION_SECRET in every environment.",
			Vars: []EnvVar{
				{Name: "BASE_URL", Default: "http://localhost:8080", Required: true, Desc: "The externally reachable URL of this server. It is used in OIDC discovery, CAS redirects, and email links.", When: "Always set it. In production, set it to the exact https URL that users type. A https value also turns on secure cookies and sets the passkey domain."},
				{Name: "SESSION_SECRET", Required: true, Secret: true, Desc: "The HMAC key that signs session cookies. Use at least 32 bytes after hex decoding.", When: "Always set it. Generate it once per environment with openssl rand -hex 32. Do not reuse it across environments. If you change it, every session ends."},
				{Name: "ENV", Default: "dev", Desc: "A free-form environment tag (dev, staging, or prod). It appears in logs and metrics.", When: "Set it in staging and production so logs are easy to tell apart. Leave it as dev on your machine."},
				{Name: "AUTO_MIGRATE", Default: "true", Desc: "Applies any pending database migrations on start.", When: "Keep it true for a single-instance deployment. Set it false when you run more than one instance: a bad migration would otherwise take down every replica at once, and concurrent replicas can race applying it. Instead run the /migrate binary shipped in the container image as a one-shot step (a Kubernetes Job, a deploy hook) before rolling out the new server version."},
				{Name: "DOCS_ENABLED", Default: "false", Desc: "Serves this documentation page at /docs.", When: "Turn it on in development. Leave it off on a public production server unless you want the reference public."},
				{Name: "CONFIG_FILE", Desc: "The path to an optional YAML overlay. The server applies it before the environment variables. It holds non-secret fields only.", When: "Set it only if you prefer a YAML file for non-secret config. Most deployments do not need it. Never put secrets in it."},
			},
		},
		{
			Title: "HTTP server",
			Intro: "The listen address and the timeouts. The defaults are safe for most deployments.",
			Vars: []EnvVar{
				{Name: "HTTP_ADDR", Default: ":8080", Desc: "The listen address.", When: "Change it only if port 8080 is taken, or you bind to one interface."},
				{Name: "HTTP_READ_TIMEOUT", Default: "30s", Desc: "The request read timeout.", When: "Leave it at the default unless a proxy needs a different value."},
				{Name: "HTTP_WRITE_TIMEOUT", Default: "60s", Desc: "The response write timeout.", When: "Leave it at the default unless a proxy needs a different value."},
				{Name: "HTTP_SHUTDOWN_TIMEOUT", Default: "30s", Desc: "The graceful-shutdown grace period.", When: "Leave it at the default in most cases."},
			},
		},
		{
			Title: "Database",
			Intro: "The Postgres connection and the pool sizing.",
			Vars: []EnvVar{
				{Name: "DATABASE_URL", Required: true, Secret: true, Desc: "The PostgreSQL connection string (postgres://user:pass@host:5432/db).", When: "Always set it. Use sslmode=require against a remote database. Use sslmode=disable only for local Docker."},
				{Name: "DB_MAX_CONNS", Default: "20", Desc: "The maximum number of pooled connections.", When: "Raise it under heavy load. Keep it below the Postgres max_connections limit."},
				{Name: "DB_MIN_CONNS", Default: "2", Desc: "The minimum number of idle connections.", When: "Leave it at the default in most cases."},
				{Name: "DB_CONN_MAX_LIFETIME", Default: "1h", Desc: "The maximum lifetime of a pooled connection.", When: "Lower it if a proxy or load balancer closes idle connections early."},
			},
		},
		{
			Title: "Logging",
			Intro: "The log level and the format.",
			Vars: []EnvVar{
				{Name: "LOG_LEVEL", Default: "info", Desc: "The log level (debug, info, warn, or error).", When: "Use debug in development. Use info or warn in production."},
				{Name: "LOG_FORMAT", Default: "text", Desc: "The log format (json or text).", When: "Use text for a readable terminal. Use json when a log collector parses the output."},
			},
		},
		{
			Title: "Crypto & tokens",
			Intro: "The key that signs OIDC id_tokens.",
			Vars: []EnvVar{
				{Name: "SIGNING_KEY_PATH", Desc: "The path to a PEM-encoded RSA private key. The server signs id_tokens with this key. If it is unset, the server generates a temporary key at start, and a restart invalidates all tokens.", When: "Set it in every environment where tokens must survive a restart. This means always, in practice. Leave it unset only for a throwaway test."},
			},
		},
		{
			Title: "Sessions & proxy trust",
			Intro: "The cookie scope, and which proxies the server trusts for the client IP.",
			Vars: []EnvVar{
				{Name: "SESSION_COOKIE_DOMAIN", Desc: "Overrides the Domain attribute of the session cookie. Start the value with a dot to cover all subdomains (for example, .example.com).", When: "Set it only for the reverse-proxy companion, so one cookie works across subdomains. Leave it unset for a single host. A wrong value silently breaks sessions."},
				{Name: "TRUSTED_PROXIES", Desc: "A CIDR allow-list of proxy IP ranges. The server trusts X-Forwarded-For from these ranges only.", When: "Set it when a proxy or load balancer sits in front. Leave it unset when the server faces the internet directly, so no client can spoof its IP."},
			},
		},
		{
			Title: "MFA",
			Intro: "The labels shown in authenticator apps, and the global MFA switch.",
			Vars: []EnvVar{
				{Name: "MFA_ISSUER", Desc: "The TOTP issuer label shown in authenticator apps.", When: "Set it to your product or company name so users recognize the entry."},
				{Name: "MFA_WEBAUTHN_RP_NAME", Desc: "The WebAuthn relying-party display name.", When: "Set it to your product or company name so the passkey prompt is clear."},
				{Name: "FORCE_MFA", Default: "false", Desc: "Requires MFA for all users.", When: "Turn it on when every user must use a second factor. Leave it off to allow per-user or per-client policy."},
			},
		},
		{
			Title: "Outbound email (SMTP)",
			Intro: "The mail server for verification and password-reset emails. When SMTP_HOST is empty, the server logs emails instead of sending them.",
			Vars: []EnvVar{
				{Name: "SMTP_HOST", Desc: "The SMTP server host. When it is empty, the server logs emails instead of sending them (development only).", When: "Set it in production, and whenever you test signup or password reset. Leave it empty in development to read the email in the logs."},
				{Name: "SMTP_PORT", Desc: "The SMTP server port (for example, 587).", When: "Set it with SMTP_HOST."},
				{Name: "SMTP_USERNAME", Desc: "The SMTP auth username.", When: "Set it when the mail server needs authentication."},
				{Name: "SMTP_PASSWORD", Secret: true, Desc: "The SMTP auth password.", When: "Set it when the mail server needs authentication."},
				{Name: "SMTP_FROM", Desc: "The From address for outbound mail.", When: "Set it with SMTP_HOST. Use an address your mail server is allowed to send from."},
			},
		},
		{
			Title: "Self-service signup",
			Intro: "The optional public registration flow at /signup.",
			Vars: []EnvVar{
				{Name: "SIGNUP_ENABLED", Default: "false", Desc: "Opens public registration at /signup.", When: "Turn it on for an open service. Leave it off for an internal server where an admin creates users."},
				{Name: "SIGNUP_MIN_PASSWORD_LENGTH", Default: "12", Desc: "The minimum password length for self-signup.", When: "Raise it for a stronger policy. Do not lower it below 12."},
				{Name: "SIGNUP_TOKEN_TTL_HOURS", Default: "24", Desc: "The lifetime of email-verification links, in hours.", When: "Lower it for a stricter window. Raise it if users report expired links."},
			},
		},
		{
			Title: "Reverse proxy",
			Intro: "Controls the redirect-back behaviour of the forward-auth endpoint.",
			Vars: []EnvVar{
				{Name: "PROXY_ALLOWED_CALLBACK_ORIGINS", Desc: "An allow-list of cross-origin destinations that /proxy/verify may redirect back to after sign-in.", When: "Set it when the reverse-proxy companion protects apps on other subdomains. Leave it unset if you do not use forward-auth. An unlisted origin gets a bare 401 with no Location header."},
			},
		},
		{
			Title: "Federation (upstream SSO)",
			Intro: "Credentials for upstream providers. A provider becomes active only when both its id and secret are set.",
			Vars: []EnvVar{
				{Name: "GOOGLE_CLIENT_ID", Desc: "The Google OAuth client id.", When: "Set both the id and the secret to add a Google sign-in button. Leave both unset to hide it."},
				{Name: "GOOGLE_CLIENT_SECRET", Secret: true, Desc: "The Google OAuth client secret.", When: "Set it with GOOGLE_CLIENT_ID."},
				{Name: "GITHUB_CLIENT_ID", Desc: "The GitHub OAuth client id.", When: "Set both the id and the secret to add a GitHub sign-in button. Leave both unset to hide it."},
				{Name: "GITHUB_CLIENT_SECRET", Secret: true, Desc: "The GitHub OAuth client secret.", When: "Set it with GITHUB_CLIENT_ID."},
				{Name: "OIDC_PROVIDERS", Desc: "A comma-separated list of slugs that enable generic OIDC upstreams (for example, okta,keycloak,auth0).", When: "Set it to add any OIDC provider that is not built in. For each slug, add the four OIDC_<SLUG>_* variables below."},
				{Name: "OIDC_<SLUG>_ISSUER", Desc: "The issuer URL for one provider. Repeat the block for each slug in OIDC_PROVIDERS.", When: "Set it for each slug you listed in OIDC_PROVIDERS."},
				{Name: "OIDC_<SLUG>_CLIENT_ID", Desc: "The client id for one provider.", When: "Set it for each slug you listed in OIDC_PROVIDERS."},
				{Name: "OIDC_<SLUG>_CLIENT_SECRET", Secret: true, Desc: "The client secret for one provider.", When: "Set it for each slug you listed in OIDC_PROVIDERS."},
				{Name: "OIDC_<SLUG>_DISPLAY_NAME", Desc: "The button label for one provider (optional).", When: "Set it to control the button text. Leave it unset to use the slug."},
				{Name: "OIDC_<SLUG>_SCOPES", Desc: "The space-separated scopes for one provider (optional).", When: "Set it to request more scopes. Leave it unset to use the default openid profile email."},
			},
		},
		{
			Title: "Docker bootstrap (entrypoint only)",
			Intro: "These variables are read by the Docker entrypoint, not by the server. They seed the first admin on the first run.",
			Vars: []EnvVar{
				{Name: "ADMIN_EMAIL", Desc: "The email of the first admin account. The entrypoint creates this account on the first start.", When: "Set it once for the first Docker run. It has no effect after the account exists."},
				{Name: "ADMIN_PASSWORD", Secret: true, Desc: "The password of the first admin account.", When: "Set it once for the first Docker run. Change the password after you sign in."},
				{Name: "ADMIN_NAME", Desc: "The display name of the first admin account.", When: "Set it once for the first Docker run (optional)."},
				{Name: "ADMIN_USERNAME", Desc: "The username of the first admin account.", When: "Set it once for the first Docker run (optional)."},
			},
		},
	}
}

func systems() []System {
	return []System{
		{
			Name:    "CAS gateway",
			Summary: "The entry-point SSO protocol. It accepts CAS 2.0 and 3.0 authentication. It fulfils the request from the local IdP or an upstream provider.",
			Features: []string{
				"CAS 2.0 and 3.0 login, logout, and ticket validation",
				"CAS 3.0 attribute release, configured per service",
				"Proxy-ticket validation",
				"A bridge to upstream OIDC/OAuth sign-in when the user is not authenticated locally",
			},
		},
		{
			Name:    "OpenID Connect / OAuth 2.0 provider",
			Summary: "A standards-conformant authorization server.",
			Features: []string{
				"Authorization Code with PKCE, Client Credentials, and Refresh Token flows",
				"A discovery document and a JWKS endpoint",
				"Token introspection (RFC 7662) and revocation (RFC 7009)",
				"A UserInfo endpoint; acr and amr are carried from the authenticating session",
			},
		},
		{
			Name:    "Upstream SSO federation",
			Summary: "It delegates authentication to external identity providers. It maps the result to a local user.",
			Features: []string{
				"Built-in Google and GitHub; config-driven generic OIDC and OAuth2",
				"Account linking: match by (provider, sub), then by email, or else create",
				"Caches provider claims for later attribute release",
			},
		},
		{
			Name:    "Multi-factor authentication",
			Summary: "A second-factor challenge on sign-in, and self-service enrollment.",
			Features: []string{
				"TOTP (RFC 6238) with QR-code enrollment",
				"WebAuthn / FIDO2 passkeys",
				"Single-use backup codes",
				"Per-user and per-client (acr_values) enforcement; optional FORCE_MFA",
			},
		},
		{
			Name:    "Per-service email allow-list",
			Summary: "It restricts one OIDC client or CAS service to an explicit set of user emails.",
			Features: []string{
				"Opt in per service with require_allowlist; open by default",
				"OIDC is enforced at the authorization-code step; CAS is enforced at ticket issuance",
				"A per-service access gate; a denial never locks the account",
				"Managed from the admin API and UI",
			},
		},
		{
			Name:    "Reverse-proxy companion",
			Summary: "A forward-auth endpoint. It lets any compatible proxy delegate authentication to the IAM server.",
			Features: []string{
				"First-class Caddy (forward_auth) support; Traefik (ForwardAuth) is supported",
				"Returns identity headers (X-Auth-User, X-Auth-Email, and X-Auth-Groups) on success",
				"Accepts a session cookie or a bearer token",
			},
		},
		{
			Name:    "Admin portal",
			Summary: "A REST API and a React UI to operate the server.",
			Features: []string{
				"Manage users, clients, CAS services, allow-lists, and upstream providers",
				"Rotate client secrets; view and trigger signing-key rotation",
				"Search and export the audit log",
			},
		},
		{
			Name:    "Sessions & key management",
			Summary: "The browser-session lifecycle, and the JWKS that signs tokens.",
			Features: []string{
				"HMAC-signed session cookies with sliding expiry; the session doubles as the CAS ticket-granting ticket",
				"JWKS with zero-downtime key rotation: sign with the new key, verify against both, then retire the old key",
			},
		},
		{
			Name:    "Audit logging",
			Summary: "An append-only record of every security-relevant event.",
			Features: []string{
				"An immutable log with actor, target, IP, user-agent, and JSON metadata",
				"Covers sign-in, MFA, the token lifecycle, admin actions, allow-list changes, and access denials",
			},
		},
		{
			Name:    "Self-service flows",
			Summary: "End-user account management that works without an admin.",
			Features: []string{
				"Optional public signup with email verification",
				"Forgot and reset password with single-use, time-limited tokens",
			},
		},
	}
}
