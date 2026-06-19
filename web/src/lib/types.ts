/*
 * Wire types for the /admin/v1/* API. These mirror the DTO structs in
 * the Go admin handler package (internal/api/admin/*.go). Any field
 * shape change there must be reflected here — there is no code-gen
 * yet (openapi-typescript is planned for a later phase).
 */

export interface AdminUser {
  id: string;
  email?: string;
  username?: string;
  display_name?: string;
  status: "active" | "disabled" | "pending";
  is_admin: boolean;
  email_verified: boolean;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

/**
 * One enrolled MFA method on a user account. We never receive the
 * TOTP secret or WebAuthn credential bytes — admin only sees metadata.
 */
export interface MFAMethod {
  id: string;
  method: "totp" | "webauthn" | string; // forward-compat with future types
  name?: string;
  confirmed_at?: string; // ISO; absent for abandoned enrollments
  last_used_at?: string;
  created_at: string;
}

export interface ListUserMFAResponse {
  methods: MFAMethod[];
  backup_codes_unused: number;
}

// ─── Federation ───────────────────────────────────────────────────────────

/** A configured upstream provider as surfaced by the admin status page. */
export interface FederationProvider {
  name: string;          // slug: "google", "github", ...
  display_name: string;  // "Google", "GitHub", ...
  redirect_uri: string;
}

export interface ListProvidersResponse {
  providers: FederationProvider[];
}

/** One link between a user and an upstream provider account. */
export interface UserFederationIdentity {
  id: string;
  provider: string;
  display_name: string;
  sub: string;
  email?: string;
  /** The user's name as known by the provider — distinct from their IAM display_name. */
  provider_name?: string;
  picture_url?: string;
  created_at: string;
  updated_at: string;
}

export interface ListUserFederationResponse {
  identities: UserFederationIdentity[];
}

export interface ListUsersResponse {
  users: AdminUser[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Request body for POST /admin/v1/users. Email is required; everything
 * else is optional. If password is omitted the server generates one and
 * returns it in `generated_password` (shown once, like a client secret).
 */
export interface CreateUserRequest {
  email: string;
  username?: string;
  display_name?: string;
  password?: string;
  is_admin?: boolean;
  email_verified?: boolean;
}

export interface CreateUserResponse {
  user: AdminUser;
  /** Plaintext password — present only when the server generated it. */
  generated_password?: string;
}

export interface OIDCClient {
  id: string;
  name: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  allowed_grant_types: string[];
  is_public: boolean;
  require_pkce: boolean;
  require_consent: boolean;
  access_token_ttl: string;
  refresh_token_ttl: string;
  id_token_ttl: string;
  enabled: boolean;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateClientRequest {
  id: string;
  name: string;
  redirect_uris: string[];
  allowed_scopes?: string[];
  allowed_grant_types?: string[];
  is_public: boolean;
  require_pkce?: boolean;
  require_consent: boolean;
  access_token_ttl?: string;
  refresh_token_ttl?: string;
  id_token_ttl?: string;
}

export interface CreateClientResponse {
  client: OIDCClient;
  /** Plaintext secret — shown once, on creation. Empty for public clients. */
  secret?: string;
}

export interface CASService {
  id: string;
  name: string;
  service_url_pattern: string;
  match_pattern: string;
  description?: string;
  released_attributes: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateCASServiceRequest {
  name: string;
  service_url_pattern: string;
  description?: string;
  released_attributes?: string[];
}

export interface AdminSession {
  id: string;
  user_id: string;
  acr: string;
  amr: string[];
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  actor_id?: string;
  target_id?: string;
  metadata: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface ListAuditResponse {
  events: AuditEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface SigningKey {
  kid: string;
  alg: string;
  // primary=true marks the key currently used for signing new tokens.
  // Other entries are "retiring" — kept in JWKS so already-issued
  // tokens still verify until they expire, then removed by operator
  // after the next rotation grace period.
  primary: boolean;
  // source is the filename the key was loaded from (multi-key directory
  // mode). Empty for single-file mode and ephemeral keys.
  source?: string;
}

/** RFC 7807 problem envelope returned by every admin API on error. */
export interface ApiProblem {
  type: string;
  title: string;
  status: number;
  code?: string;
  detail?: string;
  trace_id?: string;
}
