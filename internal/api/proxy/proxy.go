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

type Handler struct {
	sessions *session.Service
	store    *postgres.Store
	// baseURL is the IAM server's external URL, used to build the
	baseURL string
	// allowedOrigins is a set of accepted callback origins
	allowedOrigins map[string]struct{}
}

type Config struct {
	Sessions               *session.Service
	Store                  *postgres.Store
	BaseURL                string
	AllowedCallbackOrigins []string
}

func New(c Config) *Handler {
	origins := make(map[string]struct{}, len(c.AllowedCallbackOrigins))
	for _, o := range c.AllowedCallbackOrigins {
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

// register installs the route on mux
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /proxy/verify", h.verify)
}

// verify answers the forward-auth subrequest
//
// order of authentication attempts:
//  1. Authorization: Bearer <token> if present
//  2. Session cookie otherwise
//
// we try Bearer first because clients that explicitly pass one are
// expecting machine-to-machine semantics; falling back to a stale
// cookie when an invalid token was provided would be surprising
func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		if user, ok := h.userFromBearer(r.Context(), token); ok {
			writeAuthHeaders(w, user)
			w.WriteHeader(http.StatusOK)
			return
		}
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
		// session points at a now-deleted user. Treat as unauthenticated
		h.write401(w, r)
		return
	}

	writeAuthHeaders(w, user)
	w.WriteHeader(http.StatusOK)
}

// userFromBearer resolves the access token to a user, or returns ok=false
func (h *Handler) userFromBearer(ctx context.Context, token string) (*postgres.User, bool) {
	if token == "" {
		return nil, false
	}
	at, err := h.store.GetOIDCAccessToken(ctx, token)
	if err != nil {
		return nil, false
	}
	if at.UserID == nil || !at.UserID.Valid {
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

func (h *Handler) write401(w http.ResponseWriter, r *http.Request) {
	if loc, ok := h.buildLoginRedirect(r); ok {
		w.Header().Set("Location", loc)
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// buildLoginRedirect constructs the login URL the browser should follow
func (h *Handler) buildLoginRedirect(r *http.Request) (string, bool) {
	scheme := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
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
		return "", false
	}

	full := origin + path
	loc := h.baseURL + "/cas/login?rd=" + url.QueryEscape(full)
	return loc, true
}

// writeAuthHeaders sets the X-Auth-* headers describing the authenticated user
func writeAuthHeaders(w http.ResponseWriter, u *postgres.User) {
	w.Header().Set("X-Auth-Sub", uuidToString(u.ID))

	username := derefSafe(u.Username)
	email := derefSafe(u.Email)
	name := derefSafe(u.DisplayName)
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

	groups := []string{}
	if u.IsAdmin {
		groups = append(groups, "admin")
	}
	w.Header().Set("X-Auth-Groups", strings.Join(groups, ","))
}

// derefSafe returns the dereferenced string with header-unsafe bytes
func derefSafe(s *string) string {
	if s == nil {
		return ""
	}
	v := *s
	b := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\r' || c == '\n' || c == 0 || (c < 0x20 && c != '\t') {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

// uuidToString renders pgtype.UUID in canonical 8-4-4-4-12 form
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
// can compare against a fixed time without monkey-patching
var now = func() time.Time { return time.Now() }
