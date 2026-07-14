import type { ApiProblem } from "./types";

const ADMIN_BASE = "/admin/v1";

// thrown for any non-2xx HTTP response. Carries the parsed Problem envelope
export class ApiError extends Error {
  status: number;
  code: string | undefined;
  problem: ApiProblem;

  constructor(problem: ApiProblem) {
    super(problem.detail || problem.title);
    this.status = problem.status;
    this.code = problem.code;
    this.problem = problem;
    this.name = "ApiError";
  }
}

interface RequestOpts {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  query?: Record<string, string | number | undefined>;
  body?: unknown;
  // AbortSignal for cancellation from React effect cleanup
  signal?: AbortSignal;
}

const request = async <T>(path: string, opts: RequestOpts = {}): Promise<T> => {
  const method = opts.method ?? "GET";
  const url = buildURL(path, opts.query);

  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;

  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }

  // CSRF: the server's middleware issues an `iam_csrf` cookie that the
  // SPA must echo as X-CSRF-Token on every state-mutating request. We
  // attach it on POST/PATCH/DELETE only; GET requests don't get checked
  // server-side so the header would be wasted bytes there.
  //
  // The cookie is intentionally NOT HttpOnly so document.cookie can read
  // it, this is the standard double-submit pattern. Same-origin XSS
  // could read it too, but same-origin XSS already has full session
  // access via the session cookie; CSRF protects against cross-origin
  // attacks, not on-page code execution.
  if (method !== "GET") {
    const token = readCSRFCookie();
    if (token) {
      headers["X-CSRF-Token"] = token;
    }
  }

  const res = await fetch(url, {
    method,
    headers,
    body,
    credentials: "include", // session cookie + same-origin CSRF check
    signal: opts.signal,
  });

  // 204 No Content common for DELETE / lock / unlock.
  if (res.status === 204) {
    return undefined as T;
  }

  // Both success and failure bodies are JSON. For non-OK responses, try
  // to surface the Problem envelope; fall back to a synthetic one if the
  // body wasn't valid JSON.
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = text.length > 0 ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }

  if (!res.ok) {
    const problem: ApiProblem = isProblem(parsed)
      ? parsed
      : { type: "about:blank", title: res.statusText || "Error", status: res.status };
    throw new ApiError(problem);
  }

  return parsed as T;
}

function buildURL(path: string, query?: RequestOpts["query"]): string {
  const full = path.startsWith("http") ? path : `${ADMIN_BASE}${path}`;
  if (!query) return full;
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    search.set(k, String(v));
  }
  const qs = search.toString();
  return qs ? `${full}?${qs}` : full;
}

function isProblem(v: unknown): v is ApiProblem {
  return typeof v === "object" && v !== null && "status" in v && "title" in v;
}

/**
 * Reads the iam_csrf cookie from document.cookie. Returns "" when the
 * cookie isn't set yet, typically only on the very first page load
 * before any GET has bounced through the CSRF middleware.
 *
 * Hand-parses document.cookie because the standard says cookie values
 * can contain "=" (base64url tokens may end with padding, though ours
 * don't) and the simple split-on-"=" approach is wrong in general.
 */
function readCSRFCookie(): string {
  const name = "iam_csrf=";
  const cookies = document.cookie.split(";");
  for (const c of cookies) {
    const trimmed = c.trimStart();
    if (trimmed.startsWith(name)) {
      return trimmed.slice(name.length);
    }
  }
  return "";
}

import type {
  AdminUser,
  ListUsersResponse,
  CreateUserRequest,
  CreateUserResponse,
  ListUserMFAResponse,
  ListProvidersResponse,
  ListUserFederationResponse,
  OIDCClient,
  CreateClientRequest,
  CreateClientResponse,
  CASService,
  CreateCASServiceRequest,
  AdminSession,
  ListAuditResponse,
  SigningKey,
} from "./types";

export const api = {
  me: (signal?: AbortSignal) => request<{ user: AdminUser }>("/me", { signal }),

  // Users
  listUsers: (params: { search?: string; status?: string; limit?: number; offset?: number }, signal?: AbortSignal) =>
    request<ListUsersResponse>("/users", { query: params, signal }),
  createUser: (body: CreateUserRequest) =>
    request<CreateUserResponse>("/users", { method: "POST", body }),
  getUser: (id: string, signal?: AbortSignal) =>
    request<AdminUser>(`/users/${id}`, { signal }),
  updateUser: (id: string, body: Partial<Pick<AdminUser, "email" | "username" | "display_name" | "status" | "is_admin">>) =>
    request<AdminUser>(`/users/${id}`, { method: "PATCH", body }),
  lockUser: (id: string) => request<AdminUser>(`/users/${id}/lock`, { method: "POST" }),
  unlockUser: (id: string) => request<AdminUser>(`/users/${id}/unlock`, { method: "POST" }),
  deleteUser: (id: string) => request<void>(`/users/${id}`, { method: "DELETE" }),
  resetUserPassword: (id: string, newPassword: string) =>
    request<void>(`/users/${id}/password`, { method: "POST", body: { new_password: newPassword } }),
  listUserSessions: (id: string, signal?: AbortSignal) =>
    request<{ sessions: AdminSession[] }>(`/users/${id}/sessions`, { signal }),
  revokeUserSessions: (id: string) =>
    request<{ revoked: number }>(`/users/${id}/revoke-all`, { method: "POST" }),

  // User MFA management
  listUserMFA: (id: string, signal?: AbortSignal) =>
    request<ListUserMFAResponse>(`/users/${id}/mfa`, { signal }),
  deleteUserMFAMethod: (userId: string, methodId: string) =>
    request<void>(`/users/${userId}/mfa/${methodId}`, { method: "DELETE" }),
  deleteAllUserMFA: (id: string) =>
    request<void>(`/users/${id}/mfa`, { method: "DELETE" }),

  // Federation
  listFederationProviders: (signal?: AbortSignal) =>
    request<ListProvidersResponse>("/federation/providers", { signal }),
  listUserFederation: (id: string, signal?: AbortSignal) =>
    request<ListUserFederationResponse>(`/users/${id}/federation`, { signal }),
  unlinkUserFederation: (userId: string, linkId: string) =>
    request<void>(`/users/${userId}/federation/${linkId}`, { method: "DELETE" }),

  // OIDC clients
  listClients: (signal?: AbortSignal) =>
    request<{ clients: OIDCClient[] }>("/clients", { signal }),
  getClient: (id: string, signal?: AbortSignal) =>
    request<OIDCClient>(`/clients/${id}`, { signal }),
  createClient: (body: CreateClientRequest) =>
    request<CreateClientResponse>("/clients", { method: "POST", body }),
  updateClient: (id: string, body: Partial<OIDCClient>) =>
    request<OIDCClient>(`/clients/${id}`, { method: "PATCH", body }),
  deleteClient: (id: string) => request<void>(`/clients/${id}`, { method: "DELETE" }),
  rotateClientSecret: (id: string) =>
    request<{ secret: string }>(`/clients/${id}/rotate`, { method: "POST" }),

  // CAS services
  listCASServices: (signal?: AbortSignal) =>
    request<{ services: CASService[] }>("/cas-services", { signal }),
  getCASService: (id: string, signal?: AbortSignal) =>
    request<CASService>(`/cas-services/${id}`, { signal }),
  createCASService: (body: CreateCASServiceRequest) =>
    request<CASService>("/cas-services", { method: "POST", body }),
  updateCASService: (id: string, body: Partial<CASService>) =>
    request<CASService>(`/cas-services/${id}`, { method: "PATCH", body }),
  deleteCASService: (id: string) =>
    request<void>(`/cas-services/${id}`, { method: "DELETE" }),

  // Audit log
  listAudit: (params: { event_type?: string; actor_id?: string; target_id?: string; since?: string; until?: string; limit?: number; offset?: number }, signal?: AbortSignal) =>
    request<ListAuditResponse>("/audit", { query: params, signal }),

  // Signing keys
  listKeys: (signal?: AbortSignal) =>
    request<{ keys: SigningKey[] }>("/keys", { signal }),
};
