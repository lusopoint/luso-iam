package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// The threat we're defending against: an attacker tricks the user's
// browser into submitting a request to our origin while authenticated.
// Without protection, GET-implied state-mutation (rare for us) or POST
// from a malicious site can succeed because the browser attaches our
// session cookie automatically
//
// What we already had: a same-origin check on Origin/Referer headers
// in the admin handler. That works for modern browsers and is the
// normal/baseline, but two failure modes drive us to add an explicit token:
//
//   1. Subdomain takeover. If an attacker controls anything.example.com
//      and our session cookie's Domain is .example.com, the same-origin
//      check passes (Origin: anything.example.com matches our domain
//      eligibility) while the attacker controls the request payload
//
//   2. Browsers that strip Origin/Referer (rare but real, some
//      privacy extensions, some old proxies). Without those headers
//      the same-origin check has to fail closed, which it does, but
//      that breaks legitimate users behind such proxies.
//
// Double-submit cookie pattern: issue a random token in a cookie that
// is NOT HttpOnly (the SPA needs to read it to echo). On every
// state-mutating request the client must present that same token in
// either:
//
//     - X-CSRF-Token header  (preferred for SPA fetches)
//     - _csrf form field     (for server-rendered HTML forms)
//
// The server checks the presented token matches the cookie. Because
// only same-origin JavaScript can read the cookie (browser policy),
// and only same-origin form submissions can include a same-origin
// cookie that the attacker can't otherwise know, the token is
// effectively a per-session shared secret between server and browser
//
// Trade-off accepted: XSS on the same origin can read the cookie and
// forge any request. That's fine, same-origin XSS already has full
// run of the session via the session cookie. CSRF protects against
// cross-origin attacks, not same-origin code execution
//
// **not-protected paths** (passed to NewCSRF as exemptions):
//     (machine to machine, authenticated by client credentials, no browser involved)
//   - /oauth2/token
//   - /oauth2/introspect
//   - /oauth2/revoke
//     (read only or provides CSRF)
//   - /federation/*/callback OAuth state parameter provides CSRF
//   - /proxy/verify  read-only, no state change
//   - /metrics, /healthz, /readyz  read-only ops endpoints
//
// Routes that ARE protected (the form-based flows):
//   - /cas/login (POST)
//   - /password/forgot
//   - /password/reset (POST)
//   - /mfa/* (POST verify, enroll, ...)
//   - /admin/v1/* (POST/PATCH/DELETE)
//   - /federation/*/start (POST when SPA initiated)

// CSRFCookieName is the name of the issued CSRF cookie
const CSRFCookieName = "iam_csrf"

// CSRFHeaderName is the header SPAs use to echo the token
const CSRFHeaderName = "X-CSRF-Token"

// CSRFFormField is the form field server-rendered HTML uses to echo the token
const CSRFFormField = "_csrf"

// ctxCSRFToken keys the per-request CSRF token in context
// handlers rendering HTML forms pull this out and inject into templates
type ctxCSRFTokenKey struct{}

// CSRFTokenFromContext returns the CSRF token to embed in form templates
func CSRFTokenFromContext(ctx context.Context) string {
	if v := ctx.Value(ctxCSRFTokenKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CSRFConfig configures the middleware
type CSRFConfig struct {
	// Secure marks the cookie as Secure when true. Set to false in
	// local http-only dev so the cookie is actually accepted by the
	// browser. Tie to whether BASE_URL is https
	Secure bool

	// ExemptPaths bypasses CSRF validation entirely. Used for
	// machine-to-machine endpoints that authenticate by client
	// credentials and aren't reachable from a browser. Path-prefix
	// matched ("/oauth2/" exempts everything under it). Always
	// include exemptions in the *callers* understanding  adding
	// a route after this list without consciously revisiting it
	// silently weakens the protection
	ExemptPaths []string
}

// NewCSRF returns a middleware that:
//
//  1. On every request, ensures a CSRF token cookie exists. If none
//     is present, issues one and exposes it via context. If one is
//     present, parses and exposes it via context.
//  2. On every state-mutating request (POST/PUT/PATCH/DELETE) NOT in
//     the exempt list, validates the request presents a matching
//     token via header or form field. Mismatch-> 403.
//
// The token in context is what HTML templates render into hidden
// _csrf inputs. The SPA reads it from the cookie directly using
// document.cookie.
func NewCSRF(cfg CSRFConfig) Middleware {
	// Normalize exempts: keep them as a slice; small enough that a
	// linear scan per request is faster than building a tree.
	exempts := make([]string, 0, len(cfg.ExemptPaths))
	for _, p := range cfg.ExemptPaths {
		if p != "" {
			exempts = append(exempts, p)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Exempt paths skip CSRF entirely  no cookie issued, no
			// validation. The "no cookie" half matters because /healthz
			// and /metrics are hit by probes and load balancers that
			// shouldn't be polluted with state cookies, and downstream
			// caches can be tripped up by Set-Cookie headers.
			if isExempt(r.URL.Path, exempts) {
				next.ServeHTTP(w, r)
				return
			}

			// Step 1: ensure cookie exists; capture token for context.
			token, err := ensureCSRFCookie(w, r, cfg.Secure)
			if err != nil {
				// Failure to generate a token means crypto/rand broke,
				// which is catastrophic  fail closed. The user will see
				// a 500; the operator sees the log line via Recovery.
				http.Error(w, "csrf: token initialization failed", http.StatusInternalServerError)
				return
			}

			// Step 2: validate on state-mutating methods.
			if isStateMutating(r.Method) {
				if !validateCSRFToken(r, token) {
					// Use a plain response  JSON formatting depends on
					// the requesting client. The body is informational;
					// the 403 is the signal.
					http.Error(w, "csrf: token missing or invalid", http.StatusForbidden)
					return
				}
			}

			// Stash token in context for HTML templates.
			ctx := context.WithValue(r.Context(), ctxCSRFTokenKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isStateMutating reports which HTTP methods should be CSRF-checked.
// GET/HEAD/OPTIONS are safe by definition (idempotent + no side effects
// in well-formed APIs); checking them would just create a needless
// auth-flow rabbit hole on initial page loads where no cookie exists yet.
func isStateMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// isExempt scans the prefix list. Prefix matching, not exact: it's
// common to want all of /oauth2/* exempted by writing "/oauth2/".
func isExempt(path string, exempts []string) bool {
	for _, p := range exempts {
		if path == p || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ensureCSRFCookie reads the existing cookie if any, else generates a
// new token, sets the cookie, and returns the token. The cookie is
// NOT HttpOnly  the SPA reads document.cookie to echo into a header
// on fetch calls. The standard double-submit pattern accepts this
// trade-off; see the package comment.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	if c, err := r.Cookie(CSRFCookieName); err == nil && c.Value != "" {
		// Existing cookie  re-use the value. Tokens don't need to
		// rotate per-request; rotating only on session boundaries
		// is the simpler, equally-secure pattern.
		return c.Value, nil
	}

	// Generate a fresh 32-byte token. base64url-encoded to keep it
	// cookie-safe (no =, no /, no characters that need URL escaping
	// when round-tripped through a form field).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		Secure:   secure,
		HttpOnly: false, // intentionally readable by JS for SPA echo
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7, // 1 week  comfortably longer than a session
	})
	return token, nil
}

// validateCSRFToken checks that the request carries a CSRF token
// matching the cookie. Checks header first (SPA path), falls back to
// the form field (server-rendered HTML form). Constant-time compare
// prevents timing-based discovery of partial matches.
func validateCSRFToken(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}

	// Prefer the header. r.Header.Get is case-insensitive.
	if h := r.Header.Get(CSRFHeaderName); h != "" {
		return subtle.ConstantTimeCompare([]byte(h), []byte(expected)) == 1
	}

	// Form field fallback. r.FormValue triggers ParseForm which
	// will read the body once; subsequent r.Body reads will be
	// empty. That's acceptable for the form-post endpoints we're
	// protecting, because they ALL use FormValue downstream too.
	// JSON-bodied endpoints don't use this path  they use the SPA
	// (header) path.
	if got := r.FormValue(CSRFFormField); got != "" {
		return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
	}

	return false
}
