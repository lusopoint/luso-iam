package cas

import "testing"

// TestSafeRedirect_AllowlistEnforcement: the contract is "only
// scheme://host pairs explicitly in proxyOrigins pass through; everything
// else returns empty". The full URL (including path/query) is preserved
// on a match — the user's intended destination shouldn't be truncated.
func TestSafeRedirect_AllowlistEnforcement(t *testing.T) {
	t.Parallel()

	h := &Handler{
		proxyOrigins: map[string]struct{}{
			"https://app.example.com":  {},
			"https://wiki.example.com": {},
		},
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		// ── Accepted ──────────────────────────────────────────────────
		{"exact_match", "https://app.example.com/", "https://app.example.com/"},
		{"with_path", "https://app.example.com/dashboard", "https://app.example.com/dashboard"},
		{"with_query", "https://app.example.com/x?a=1&b=2", "https://app.example.com/x?a=1&b=2"},
		{"with_fragment", "https://app.example.com/x#section", "https://app.example.com/x#section"},
		{"second_origin", "https://wiki.example.com/page", "https://wiki.example.com/page"},
		// Case insensitivity on origin component:
		{"uppercase_scheme", "HTTPS://app.example.com/", "HTTPS://app.example.com/"},
		{"uppercase_host", "https://APP.example.com/", "https://APP.example.com/"},

		// ── Rejected ──────────────────────────────────────────────────
		{"empty", "", ""},
		{"not_in_allowlist", "https://evil.example.org/path", ""},
		{"subdomain_not_in_list", "https://other.example.com/", ""},
		{"wrong_scheme_http", "http://app.example.com/", ""}, // we listed https, not http
		{"javascript_scheme", "javascript:alert(1)", ""},
		{"data_scheme", "data:text/html,abc", ""},
		{"file_scheme", "file:///etc/passwd", ""},
		{"missing_scheme", "//app.example.com/path", ""},
		{"unparseable", "ht!tp:!//bad", ""},
		{"empty_host", "https:///path", ""},

		// ── Subtle: the "match" is exact, not a prefix ────────────────
		// (We have https://app.example.com — host with a port is
		// different. The proxy companion has the same normalisation
		// rule, so the two endpoints can't disagree on what's allowed.)
		{"port_changes_origin", "https://app.example.com:8080/", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := h.safeRedirect(c.in)
			if got != c.want {
				t.Errorf("safeRedirect(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSafeRedirect_NoOrigins: empty handler allowlist rejects everything.
// This is the deployment-default state when PROXY_ALLOWED_CALLBACK_ORIGINS
// is unset — `rd=` is silently dropped, which is the safe default.
func TestSafeRedirect_NoOrigins(t *testing.T) {
	t.Parallel()
	h := &Handler{proxyOrigins: nil}
	if got := h.safeRedirect("https://app.example.com/"); got != "" {
		t.Errorf("safeRedirect should reject everything with nil origins, got %q", got)
	}
}
