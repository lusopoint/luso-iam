package middleware

import (
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
//   - script-src 'self' 'unsafe-inline', needed for the inline
//     <script> blocks in MFA enrollment pages. CSP nonces would
//     be the next iteration; deferred because every template
//     would need a nonce-aware change
//
//   - style-src 'self' 'unsafe-inline', needed for React's
//     style={{}} prop and inline <style> blocks in templates
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
// writes ~6 header pairs so not that costly
//
// On compatibility: a few of these (Permissions-Policy, CSP frame-ancestors)
// are ignored by very old browsers but degrade gracefully
// the older browsers fall back to X-Frame-Options
func SecurityHeaders(secure bool) Middleware {
	// build CSP once at construction; same for every response
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self' data:",
		"connect-src 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'self'",
		"object-src 'none'",
	}, "; ")

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
			h.Set("Content-Security-Policy", csp)

			next.ServeHTTP(w, r)
		})
	}
}
