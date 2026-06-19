package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/lusopoint/lusoiam/internal/audit"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// Handler owns all /admin/v1/* endpoints
// TODO: think about how to manage other versions (v2...)
type Handler struct {
	store    *postgres.Store
	sessions *session.Service
	audit    *audit.Service
	keys     *crypto.KeyManager
	// federation is the read-only registry of configured upstream providers
	// nil is allowed, the federation admin endpoints just return an empty list
	// in that case, which is the same shape the SPA already handles for "no providers configured"
	federation *federation.Registry
	baseURL    string
	// baseOrigin is the parsed scheme+host of baseURL, used for same-origin
	// CSRF checks. Computed once at construction time
	baseOrigin string
}

type Config struct {
	Store      *postgres.Store
	Sessions   *session.Service
	Audit      *audit.Service
	Keys       *crypto.KeyManager
	Federation *federation.Registry
	BaseURL    string
}

func New(c Config) *Handler {
	origin := ""
	if u, err := url.Parse(c.BaseURL); err == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	return &Handler{
		store:      c.Store,
		sessions:   c.Sessions,
		audit:      c.Audit,
		keys:       c.Keys,
		federation: c.Federation,
		baseURL:    c.BaseURL,
		baseOrigin: origin,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/v1/me", h.protected(h.me))
	mux.HandleFunc("GET    /admin/v1/users", h.protected(h.listUsers))
	mux.HandleFunc("POST   /admin/v1/users", h.protected(h.createUser))
	mux.HandleFunc("GET    /admin/v1/users/{id}", h.protected(h.getUser))
	mux.HandleFunc("PATCH  /admin/v1/users/{id}", h.protected(h.updateUser))
	mux.HandleFunc("DELETE /admin/v1/users/{id}", h.protected(h.deleteUser))
	mux.HandleFunc("POST   /admin/v1/users/{id}/lock", h.protected(h.lockUser))
	mux.HandleFunc("POST   /admin/v1/users/{id}/unlock", h.protected(h.unlockUser))
	mux.HandleFunc("POST   /admin/v1/users/{id}/password", h.protected(h.resetUserPassword))
	mux.HandleFunc("GET    /admin/v1/users/{id}/sessions", h.protected(h.listUserSessions))
	mux.HandleFunc("POST   /admin/v1/users/{id}/revoke-all", h.protected(h.revokeUserSessions))
	mux.HandleFunc("GET    /admin/v1/users/{id}/mfa", h.protected(h.listUserMFA))
	mux.HandleFunc("DELETE /admin/v1/users/{id}/mfa", h.protected(h.deleteAllUserMFA))
	mux.HandleFunc("DELETE /admin/v1/users/{id}/mfa/{methodId}", h.protected(h.deleteUserMFA))
	mux.HandleFunc("GET    /admin/v1/users/{id}/federation", h.protected(h.listUserFederation))
	mux.HandleFunc("DELETE /admin/v1/users/{id}/federation/{linkId}", h.protected(h.unlinkUserFederation))
	mux.HandleFunc("GET    /admin/v1/clients", h.protected(h.listClients))
	mux.HandleFunc("POST   /admin/v1/clients", h.protected(h.createClient))
	mux.HandleFunc("GET    /admin/v1/clients/{id}", h.protected(h.getClient))
	mux.HandleFunc("PATCH  /admin/v1/clients/{id}", h.protected(h.updateClient))
	mux.HandleFunc("DELETE /admin/v1/clients/{id}", h.protected(h.deleteClient))
	mux.HandleFunc("POST   /admin/v1/clients/{id}/rotate", h.protected(h.rotateClientSecret))
	mux.HandleFunc("GET    /admin/v1/cas-services", h.protected(h.listCASServices))
	mux.HandleFunc("POST   /admin/v1/cas-services", h.protected(h.createCASService))
	mux.HandleFunc("GET    /admin/v1/cas-services/{id}", h.protected(h.getCASService))
	mux.HandleFunc("PATCH  /admin/v1/cas-services/{id}", h.protected(h.updateCASService))
	mux.HandleFunc("DELETE /admin/v1/cas-services/{id}", h.protected(h.deleteCASService))
	mux.HandleFunc("GET /admin/v1/audit", h.protected(h.listAudit))
	mux.HandleFunc("GET /admin/v1/federation/providers", h.protected(h.listFederationProviders))
	mux.HandleFunc("GET /admin/v1/keys", h.protected(h.listKeys))
}

// Auth + CSRF wrapping

// contextKey is private to this package so callers can't accidentally
// collide with our keys.
type contextKey int

const (
	ctxKeyUser contextKey = iota
)

// adminUserFromContext returns the admin User attached by `protected`
// Returns nil if the handler is reached without going through `protected` (a programmer error, see panic)
func adminUserFromContext(ctx context.Context) *postgres.User {
	u, _ := ctx.Value(ctxKeyUser).(*postgres.User)
	return u
}

// the authenticated User is attached to the request context for use by
// downstream handlers (typically as the audit Actor)
func (h *Handler) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// active session
		sess, err := h.sessions.Get(r.Context(), r)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized",
				"Admin session required.")
			return
		}

		// user must be active and admin
		user, err := h.store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			if errors.Is(err, postgres.ErrNotFound) {
				writeProblem(w, http.StatusUnauthorized, "unauthorized",
					"Account not found.")
				return
			}
			slog.Error("admin: load session user", "err", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"Could not verify session.")
			return
		}
		if user.Status != "active" {
			writeProblem(w, http.StatusForbidden, "forbidden",
				"Account is not active.")
			return
		}
		if !user.IsAdmin {
			writeProblem(w, http.StatusForbidden, "forbidden",
				"Admin privileges required.")
			return
		}

		// same-origin check for state-mutating methods
		switch r.Method {
		case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
			if !h.sameOrigin(r) {
				writeProblem(w, http.StatusForbidden, "forbidden",
					"Cross-origin request rejected.")
				return
			}
		}

		// attach the admin user to the context
		ctx := context.WithValue(r.Context(), ctxKeyUser, user)
		next(w, r.WithContext(ctx))
	}
}

// sameOrigin reports whether the requests Origin matches configured BASE_URL
func (h *Handler) sameOrigin(r *http.Request) bool {
	if h.baseOrigin == "" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == h.baseOrigin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return strings.HasPrefix(ref, h.baseOrigin+"/") || ref == h.baseOrigin
	}
	return false
}

// plain prose for humans, machine-readable `code` for the SPA
type Problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, Problem{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	})
}

// decodeJSON reads the request body into
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
