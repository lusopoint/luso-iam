package cas

import (
	"net/url"
	"strings"
)

// safeRedirect validates a cross-origin redirect URL (the `rd` query
// parameter, set by the /proxy/verify endpoint) against the configured
// PROXY_ALLOWED_CALLBACK_ORIGINS allowlist.
//
// Why a separate parameter from `next`:
//   - `next` is path-only; it can never reach a different host. That
//     makes it safe to accept without a registry lookup.
//   - `rd` is intentionally cross-origin — the reverse-proxy companion
//     needs to send the user back to app.example.com after they've
//     authenticated at auth.example.com. An open accept would turn the
//     IAM server into an open-redirect gadget that phishing pages
//     could leverage.
//
// The validation rules, in order:
//
//  1. Empty string → empty string (no redirect, fall through to default).
//  2. Parse as a URL. Reject anything that doesn't parse.
//  3. Require scheme=http or https. Reject javascript:, data:, etc.
//  4. Require a non-empty host.
//  5. Strip the path/query/fragment and lowercase, leaving just
//     "scheme://host[:port]" — the comparison key.
//  6. Check membership in h.proxyOrigins. Match → return the original
//     URL unchanged so the user lands exactly where they came from.
//     Miss → return empty string.
//
// Note we return the original URL on match, not the normalised one.
// The path/query/fragment are part of the user's intended destination
// and need to be preserved. Only the origin portion is checked for
// allowlist membership.
func (h *Handler) safeRedirect(rd string) string {
	if rd == "" {
		return ""
	}
	u, err := url.Parse(rd)
	if err != nil {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	// Composition key: scheme://host[:port], lowercased. Matches the
	// normalisation done in apicas.New when building the allowlist.
	key := strings.ToLower(u.Scheme + "://" + u.Host)
	if _, ok := h.proxyOrigins[key]; !ok {
		return ""
	}
	return rd
}
