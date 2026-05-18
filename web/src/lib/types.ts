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
