// Package proxy implements the reverse-proxy companion endpoint
// Output headers on success:
//
//	X-Auth-Sub       — user UUID (the stable identifier; prefer this upstream)
//	X-Auth-User      — username if present, otherwise email
//	X-Auth-Username  — username (may be empty)
//	X-Auth-Email     — primary email (may be empty)
//	X-Auth-Name      — display name (may be empty)
//	X-Auth-Groups    — comma-separated. Currently just "admin" for admins,
//	                   empty otherwise. Future-proofs for group/role membership.
//
// All header values are sanitised to ASCII and have CR/LF stripped, so
// a hostile display_name can't smuggle additional headers into the
// upstream request.
package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// Handler owns the /proxy/verify endpoint.
type Handler struct {
	sessions *session.Service
	store    *postgres.Store

	// baseURL is the IAM server's external URL, used to build the
	// Location header on 401.
	baseURL string

	// allowedOrigins is a set of accepted callback origins. A 401
	// response only includes Location if the client-requested
	// callback origin is in this set. nil/empty disables cross-origin
	// redirects entirely (the endpoint still works, but on 401 the
	// browser sees the bare 401 from the proxy).
	allowedOrigins map[string]struct{}
}

// Config bundles handler dependencies. baseURL and allowedOrigins are
// the only proxy-specific fields; the rest are the standard service
// surface used elsewhere.
type Config struct {
	Sessions               *session.Service
	Store                  *postgres.Store
	BaseURL                string
	AllowedCallbackOrigins []string
}

// New constructs the handler with the given dependencies.
func New(c Config) *Handler {
	origins := make(map[string]struct{}, len(c.AllowedCallbackOrigins))
	for _, o := range c.AllowedCallbackOrigins {
		// Normalise: trim spaces, strip trailing slash. We compare
		// scheme://host[:port] exactly.
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			origins[strings.ToLower(o)] = struct{}{}
		}
	}
	return &Handler{
		sessions:       c.Sessions,
		store:          c.Store,
		baseURL:        strings.TrimRight(c.BaseURL, "/"),
		allowedOrigins: origins,
	}
}

// Register installs the route on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	// GET only — forward-auth subrequests are always GET regardless of
	// the original request's method. The proxy is asking "is this
	// user authenticated?", not replaying the request.
	mux.HandleFunc("GET /proxy/verify", h.verify)
}

// verify answers the forward-auth subrequest.
//
// Order of authentication attempts:
//  1. Authorization: Bearer <token> if present
//  2. Session cookie otherwise
//
// We try Bearer first because clients that explicitly pass one are
// expecting machine-to-machine semantics; falling back to a stale
// cookie when an invalid token was provided would be surprising.
func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	// Don't let intermediaries cache forward-auth responses — the
	// authentication state changes per request.
	w.Header().Set("Cache-Control", "no-store")

	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if user, ok := h.userFromBearer(r.Context(), token); ok {
			writeAuthHeaders(w, user)
			w.WriteHeader(http.StatusOK)
			return
		}
		// Bearer was supplied but didn't validate. Don't silently
		// fall through to session — an API client wouldn't expect that.
		h.write401(w, r)
		return
	}

	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil {
		h.write401(w, r)
		return
	}

	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		// Session points at a now-deleted user. Treat as unauthenticated.
		h.write401(w, r)
		return
	}

	writeAuthHeaders(w, user)
	w.WriteHeader(http.StatusOK)
}

// userFromBearer resolves the access token to a user, or returns ok=false.
// We use the storage layer directly rather than oidc.Service.UserInfo
// because we need the User struct, not just the claims map.
func (h *Handler) userFromBearer(ctx context.Context, token string) (*postgres.User, bool) {
	if token == "" {
		return nil, false
	}
	at, err := h.store.GetOIDCAccessToken(ctx, token)
	if err != nil {
		// Could be ErrNotFound or a DB error; either way the client
		// gets a 401. We don't distinguish — that would be a side
		// channel for token guessing.
		return nil, false
	}
	if at.UserID == nil || !at.UserID.Valid {
		// client_credentials grant — no user attached. The /proxy/verify
		// contract is per-user, so this counts as no auth.
		return nil, false
	}
	if at.RevokedAt != nil {
		return nil, false
	}
	if !at.ExpiresAt.IsZero() && at.ExpiresAt.Before(now()) {
		return nil, false
	}
	user, err := h.store.GetUserByID(ctx, *at.UserID)
	if err != nil {
		return nil, false
	}
	if user.DeletedAt != nil {
		return nil, false
	}
	return user, true
}

// write401 writes the unauthenticated response. When the requested
// callback origin is in the allowlist, we include a Location header so
// the proxy can bounce the browser to /cas/login with a parameter that
// brings them back after authentication.
func (h *Handler) write401(w http.ResponseWriter, r *http.Request) {
	if loc, ok := h.buildLoginRedirect(r); ok {
		w.Header().Set("Location", loc)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// buildLoginRedirect constructs the login URL the browser should follow.
// The original URL the user wanted is reconstructed from the proxy's
// X-Forwarded-* headers (the proxy is upstream; we trust it).
//
// Returns ok=false when no callback can be built or the origin isn't
// in the allowlist. In that case the caller writes a bare 401 — the
// proxy will surface that to the browser as 401 too, which is ugly
// but never a security hole.
func (h *Handler) buildLoginRedirect(r *http.Request) (string, bool) {
	// Reconstruct the original URL the user wanted. Different proxies
	// set different combinations of these; we accept the broadest set.
	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	// Path: Traefik sets X-Forwarded-Uri; Caddy sets X-Forwarded-Path
	// (or just preserves the path on the verify request — depending on
	// configuration). We accept both, falling back to "/" if neither.
	path := r.Header.Get("X-Forwarded-Uri")
	if path == "" {
		path = r.Header.Get("X-Forwarded-Path")
	}
	if path == "" {
		path = "/"
	}
	if scheme == "" || host == "" {
		return "", false
	}

	origin := strings.ToLower(scheme + "://" + host)
	if _, ok := h.allowedOrigins[origin]; !ok {
		// Important: do NOT echo the disallowed origin back. An attacker
		// might be probing to see which origins are accepted.
		return "", false
	}

	full := origin + path
	// /cas/login accepts a `rd` parameter for cross-origin redirects
	// (we add it next). This is separate from `next` which is
	// same-origin-only.
	loc := h.baseURL + "/cas/login?rd=" + url.QueryEscape(full)
	return loc, true
}

// writeAuthHeaders sets the X-Auth-* headers describing the
// authenticated user. Every value is sanitised to defend against
// header injection via a malicious display_name.
func writeAuthHeaders(w http.ResponseWriter, u *postgres.User) {
	w.Header().Set("X-Auth-Sub", uuidToString(u.ID))

	username := derefSafe(u.Username)
	email := derefSafe(u.Email)
	name := derefSafe(u.DisplayName)

	// X-Auth-User is the "primary identifier" — most upstream apps
	// want the human-readable login name. Prefer username, fall back
	// to email, then sub.
	primary := username
	if primary == "" {
		primary = email
	}
	if primary == "" {
		primary = uuidToString(u.ID)
	}
	w.Header().Set("X-Auth-User", primary)
	w.Header().Set("X-Auth-Username", username)
	w.Header().Set("X-Auth-Email", email)
	w.Header().Set("X-Auth-Name", name)

	// X-Auth-Groups: comma-separated. We only have is_admin today;
	// future schema additions (roles, groups) plug in here.
	groups := []string{}
	if u.IsAdmin {
		groups = append(groups, "admin")
	}
	w.Header().Set("X-Auth-Groups", strings.Join(groups, ","))
}

// derefSafe returns the dereferenced string with header-unsafe bytes
// stripped: CR, LF, and any control character below space. Without this
// a display_name of "Alice\r\nX-Admin: true" would let an attacker
// inject arbitrary response headers, which the proxy would then copy
// into the upstream request.
func derefSafe(s *string) string {
	if s == nil {
		return ""
	}
	v := *s
	// Reject anything outside printable ASCII + utf8 high bytes that
	// could be header-interpretable. We keep utf-8 multi-byte chars
	// (≥ 0x80) because they're not header-special, even though net/http
	// would still reject any CR/LF inside them — that defence stays in
	// the stdlib.
	b := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		// Strip CR/LF/NUL and other control chars (except tab which
		// is permissible in field values per RFC 7230).
		if c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t') {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

// uuidToString renders pgtype.UUID in canonical 8-4-4-4-12 form.
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, b := range u.Bytes {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hex[b>>4]
		out[pos+1] = hex[b&0x0f]
		pos += 2
	}
	return string(out)
}

// now is a test seam; the bearer-token expiry check uses it so tests
// can compare against a fixed time without monkey-patching.
var now = func() time.Time { return time.Now() }
