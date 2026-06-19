package cas

import (
	"net/url"
	"strings"
)

// safeRedirect validates a cross-origin redirect URL (the `rd` query
// parameter, set by the /proxy/verify endpoint) against the configured
// PROXY_ALLOWED_CALLBACK_ORIGINS allowlist
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
	// composition key: scheme://host[:port], lowercased
	// matches the normalisation done in apicas.New when building the allowlist
	key := strings.ToLower(u.Scheme + "://" + u.Host)
	if _, ok := h.proxyOrigins[key]; !ok {
		return ""
	}
	return rd
}
