package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// SecurityHeaders adds defense in depth response headers to every response
// the values are tuned to be safe defaults for an IAM server
// nothing fancy
//
// why use this headers:
//
//   - Strict-Transport-Security pins HTTPS in the browser for 1 year
//     set only when secure=true (example: BASE_URL is https), so
//     local dev over http doesn't get poisoned by an HSTS cache that
//     forces the same browser to require https forever
//
//   - X-Content-Type-Options: nosniff disables MIME-type sniffing
//     we always set Content-Type explicitly; nosniff blocks browsers
//     from second guessing us and, for example, executing a .txt upload as
//     JS because it happens to look like one
//
//   - X-Frame-Options: DENY forbids embedding any IAM page in an iframe
//     this is anti-clickjacking, without it, an attacker
//     could load /cas/login in a transparent iframe over their own
//     UI and trick a user into clicking the "Sign in" button
//     SAMEORIGIN would also work but DENY is stricter and we don't embed our own pages
//
//   - Referrer-Policy: strict-origin-when-cross-origin prevents leaking full URLs
//     (with potentially sensitive query strings like CAS service tickets)
//     to third parties when a user navigates away from an IAM page
//     we allow sending the origin (no path) so analytics/logging on
//     downstream apps still get useful information
//
//   - Permissions-Policy disables browser APIs the IAM server has
//     no business using, geolocation/camera/microphone/USB would be
//     foothold for compromise if a XSS ever slipped through
//
//   - Content-Security-Policy is the big one, controls where the
//     browser will load resources from. Our policy:
//
//   - default-src 'self', by default, only same-origin assets
//
//   - script-src 'self' 'nonce-<per-request>', a fresh random nonce is
//     generated for every response (see newCSPNonce below) and handlers
//     rendering an inline <script> (the shared base layout's dark-mode
//     detector, the MFA pages, the docs page) inject it via
//     CSPNonceFromContext into a nonce="" attribute. The browser only
//     runs an inline script whose nonce matches the one in THIS
//     response's header, so a script an attacker manages to inject via
//     XSS has no way to know it and doesn't execute. This replaces a
//     prior 'unsafe-inline', which allowed any inline script through
//     indiscriminately, ours or an attacker's
//
//   - style-src 'self' 'nonce-<per-request>', same mechanism. The admin
//     SPA doesn't need it at all (no inline style={{}} usage, Tailwind
//     compiles to a static stylesheet loaded via <link>); only the docs
//     page's inline <style> block uses it
//
//   - img-src 'self' data, data covers the QR codes we generate for TOTP enrollment
//     (rendered as data: URIs)
//
//   - frame-ancestors 'none', same intent as X-Frame-Options:
//     DENY, modern equivalent. Kept alongside X-Frame-Options
//     for browser compatibility (older browsers ignore CSP's
//     frame-ancestors but honor X-Frame-Options)
//
//   - form-action 'self'..., POST endpoints only same-origin
//     the redirect_uri-bound flows (OIDC, CAS) are GETs to
//     third parties via Location header, not form submissions
//
//   - base-uri 'self', blocks <base> tag injection from
//     redirecting relative URLs to attacker-controlled hosts
//
// On performance: this middleware runs on every request and just
// writes ~6 header pairs plus one crypto/rand call, so not that costly
//
// On compatibility: a few of these (Permissions-Policy, CSP frame-ancestors)
// are ignored by very old browsers but degrade gracefully
// the older browsers fall back to X-Frame-Options. CSP nonces need
// CSP Level 2 (every browser in support today; IE11 does not, and
// falls back to having no script-src/style-src restriction at all
// same as if this middleware didn't exist, not worse)
func SecurityHeaders(secure bool) Middleware {
	// Permissions-Policy lists capabilities we explicitly disable
	// Empty () means "no origin is allowed", i.e. fully disabled
	permissions := strings.Join([]string{
		"geolocation=()",
		"camera=()",
		"microphone=()",
		"payment=()",
		"usb=()",
		// publickey-credentials-get is REQUIRED for WebAuthn / passkeys
		// to work. We allow it on the IAM origin only (it's already
		// scoped to the requesting origin by browser policy, so this
		// is a no-op safety belt, but explicit is better)
		"publickey-credentials-get=(self)",
		"publickey-credentials-create=(self)",
	}, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce, err := newCSPNonce()
			if err != nil {
				// crypto/rand failing is catastrophic (same treatment
				// NewCSRF gives a rand.Read failure) fail closed rather
				// than serve a page with no CSP or a predictable nonce
				http.Error(w, "security headers: nonce generation failed", http.StatusInternalServerError)
				return
			}

			h := w.Header()

			// HSTS only when we're actually serving over https. Setting
			// it over http would either be ignored (correct behaviour)
			// or, in some browsers' history, cached and applied to the
			// origin going forward, which would brick local dev
			if secure {
				// max-age=1 year, no preload (operator must opt into
				// browser preload lists explicitly; preload is a
				// commitment that's hard to undo)
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", permissions)
			h.Set("Content-Security-Policy", buildCSP(nonce))

			ctx := context.WithValue(r.Context(), ctxCSPNonceKey{}, nonce)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// buildCSP assembles the policy string for one request's nonce
func buildCSP(nonce string) string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'nonce-" + nonce + "'",
		"style-src 'self' 'nonce-" + nonce + "'",
		"img-src 'self' data:",
		"font-src 'self' data:",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'self'",
		"object-src 'none'",
	}, "; ")
}

// ctxCSPNonceKey keys the per-request CSP nonce in context. Handlers
// rendering an inline <script> or <style> pull this out via
// CSPNonceFromContext and inject it into the tag's nonce="" attribute.
type ctxCSPNonceKey struct{}

// CSPNonceFromContext returns the CSP nonce to embed in inline
// <script nonce="..."> / <style nonce="..."> tags for this request.
// Empty if SecurityHeaders isn't in the middleware chain (it always is
// in production; only relevant to tests that call a handler directly).
func CSPNonceFromContext(ctx context.Context) string {
	if v := ctx.Value(ctxCSPNonceKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// newCSPNonce generates a fresh random nonce. Unlike the CSRF token,
// this must never be reused across requests, its entire security
// property is that an attacker can't predict it, so it's generated
// fresh every time rather than cached in a cookie or anywhere else.
func newCSPNonce() (string, error) {
	raw := make([]byte, 16) // 128 bits, the widely-recommended minimum for CSP nonces
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
