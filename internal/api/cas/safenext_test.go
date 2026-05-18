package cas

import "testing"

// safeNext is the open-redirect guard for the post-login `next` query
// parameter. A regression here is a phishing vector, so we test it
// exhaustively. The rule is simple: same-origin paths only — must
// begin with exactly one "/", no scheme, no protocol-relative URLs,
// no CR/LF, no backslash.
func TestSafeNext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		// ── Accepted ──────────────────────────────────────────────────
		{"plain_root",         "/",                "/"},
		{"plain_path",         "/admin/users",     "/admin/users"},
		{"query_string",       "/admin?tab=audit", "/admin?tab=audit"},
		{"fragment",           "/admin#section",   "/admin#section"},
		{"dot_segments",       "/a/./b/../c",      "/a/./b/../c"}, // not our job to normalise; browser handles

		// ── Rejected: empty ───────────────────────────────────────────
		{"empty",              "",                 ""},

		// ── Rejected: missing leading slash ───────────────────────────
		{"relative",           "admin/users",      ""},
		{"bare_path",          "users",            ""},

		// ── Rejected: absolute URLs ───────────────────────────────────
		// These are the classic open-redirect payloads.
		{"http_scheme",        "http://evil.com",     ""},
		{"https_scheme",       "https://evil.com",    ""},
		{"javascript_scheme",  "javascript:alert(1)", ""},
		{"data_scheme",        "data:text/html,abc",  ""},

		// ── Rejected: protocol-relative ───────────────────────────────
		// "//evil.com/path" inherits the scheme from the current page.
		{"protocol_relative",  "//evil.com",       ""},
		{"protocol_relative_with_path", "//evil.com/admin", ""},

		// ── Rejected: header injection ────────────────────────────────
		// A reflected newline in a Location header can split the
		// response. We reject before it ever reaches the response.
		{"cr_in_path",         "/admin\rfoo",      ""},
		{"lf_in_path",         "/admin\nfoo",      ""},
		{"crlf_in_path",       "/admin\r\nfoo",    ""},

		// ── Rejected: backslash ───────────────────────────────────────
		// Some user-agents treat "\" as "/" — especially on Windows,
		// which can flip "/\evil.com" into "//evil.com" after browser
		// normalisation. Reject defensively.
		{"backslash_path",     "/\\evil.com",      ""},
		{"backslash_segment",  "/admin\\users",    ""},

		// ── Edge: just a slash ────────────────────────────────────────
		{"slash_then_question","/?next=foo",       "/?next=foo"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := safeNext(c.in)
			if got != c.want {
				t.Errorf("safeNext(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
