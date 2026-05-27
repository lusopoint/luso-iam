package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// ─── derefSafe — header injection defense ────────────────────────────────

// TestDerefSafe_StripsCRLF: the whole point of this helper is to keep a
// hostile display_name from smuggling new response headers. Anything
// that would terminate a header line gets removed.
func TestDerefSafe_StripsCRLF(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain_ascii", "Alice", "Alice"},
		{"strip_lf", "Alice\nX-Admin: true", "AliceX-Admin: true"},
		{"strip_cr", "Alice\rX-Admin: true", "AliceX-Admin: true"},
		{"strip_crlf", "Alice\r\nX-Admin: true", "AliceX-Admin: true"},
		{"strip_nul", "Alice\x00bob", "Alicebob"},
		{"strip_control_chars", "Alice\x01\x02bob", "Alicebob"},
		{"keep_tab", "Alice\tBob", "Alice\tBob"},
		{"keep_high_bytes_utf8", "Álice", "Álice"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := c.in
			got := derefSafe(&s)
			if got != c.want {
				t.Errorf("derefSafe(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestDerefSafe_NilSafe: passing nil must not panic. The User struct
// has optional pointer fields, and we hit the nil branch on any user
// who hasn't set display_name.
func TestDerefSafe_NilSafe(t *testing.T) {
	t.Parallel()
	got := derefSafe(nil)
	if got != "" {
		t.Errorf("derefSafe(nil) = %q, want empty", got)
	}
}

// ─── writeAuthHeaders — output contract ──────────────────────────────────

// userPtr builds a *string from a literal — terser than `s := "x"; &s` everywhere.
func userPtr(s string) *string { return &s }

// mkUUID returns a deterministic UUID for tests.
func mkUUID() pgtype.UUID {
	var u pgtype.UUID
	for i := range u.Bytes {
		u.Bytes[i] = byte(i)
	}
	u.Valid = true
	return u
}

// TestWriteAuthHeaders_FullUser: every header is set, in canonical form.
func TestWriteAuthHeaders_FullUser(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	u := &postgres.User{
		ID:          mkUUID(),
		Username:    userPtr("alice"),
		Email:       userPtr("alice@example.com"),
		DisplayName: userPtr("Alice Smith"),
		IsAdmin:     true,
	}
	writeAuthHeaders(w, u)

	want := map[string]string{
		"X-Auth-Sub":      "00010203-0405-0607-0809-0a0b0c0d0e0f",
		"X-Auth-User":     "alice",
		"X-Auth-Username": "alice",
		"X-Auth-Email":    "alice@example.com",
		"X-Auth-Name":     "Alice Smith",
		"X-Auth-Groups":   "admin",
	}
	for k, v := range want {
		got := w.Header().Get(k)
		if got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// TestWriteAuthHeaders_FallbackUser: X-Auth-User must fall back through
// username → email → sub. Apps that key off X-Auth-User shouldn't see
// an empty value just because the user signed up via federation
// without a username.
func TestWriteAuthHeaders_FallbackUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		username    *string
		email       *string
		wantPrimary string
	}{
		{"username_present", userPtr("alice"), userPtr("alice@x"), "alice"},
		{"no_username", nil, userPtr("alice@x"), "alice@x"},
		{"no_email_either", nil, nil, "00010203-0405-0607-0809-0a0b0c0d0e0f"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			writeAuthHeaders(w, &postgres.User{
				ID:       mkUUID(),
				Username: c.username,
				Email:    c.email,
			})
			if got := w.Header().Get("X-Auth-User"); got != c.wantPrimary {
				t.Errorf("X-Auth-User = %q, want %q", got, c.wantPrimary)
			}
		})
	}
}

// TestWriteAuthHeaders_GroupsForNonAdmin: a non-admin user produces an
// empty X-Auth-Groups. The header is still SET (with empty value) so
// upstream Caddy config that copies X-Auth-Groups doesn't see a missing
// header on some requests and a present one on others — that's the
// kind of inconsistency that bites people writing access rules.
func TestWriteAuthHeaders_GroupsForNonAdmin(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeAuthHeaders(w, &postgres.User{ID: mkUUID(), IsAdmin: false})

	got := w.Header().Get("X-Auth-Groups")
	if got != "" {
		t.Errorf("X-Auth-Groups for non-admin = %q, want empty", got)
	}
	// The header must still be present in the map, even with empty value.
	if _, ok := w.Header()["X-Auth-Groups"]; !ok {
		t.Error("X-Auth-Groups header must be set even when empty")
	}
}

// TestWriteAuthHeaders_HostileDisplayName: a name carrying CRLF must
// not produce an extra response header. This is the integration of the
// derefSafe defense with the actual writeAuthHeaders code path —
// regression guard if anyone ever bypasses derefSafe for "performance".
func TestWriteAuthHeaders_HostileDisplayName(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	writeAuthHeaders(w, &postgres.User{
		ID:          mkUUID(),
		DisplayName: userPtr("Alice\r\nX-Admin: true"),
	})
	if v, ok := w.Header()["X-Admin"]; ok {
		t.Errorf("injection succeeded — X-Admin header present: %v", v)
	}
	if got := w.Header().Get("X-Auth-Name"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("X-Auth-Name still contains CR/LF: %q", got)
	}
}

// ─── buildLoginRedirect — origin allowlist enforcement ───────────────────

func newHandlerWithOrigins(origins ...string) *Handler {
	return New(Config{
		BaseURL:                "https://auth.example.com",
		AllowedCallbackOrigins: origins,
	})
}

// TestBuildLoginRedirect_AllowedOrigin: when the proxy-forwarded origin
// is in the allowlist, we get a Location pointing at /cas/login?rd=<url>.
func TestBuildLoginRedirect_AllowedOrigin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins("https://app.example.com")

	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Uri", "/dashboard?tab=overview")

	loc, ok := h.buildLoginRedirect(r)
	if !ok {
		t.Fatal("buildLoginRedirect returned ok=false for allowed origin")
	}
	if !strings.HasPrefix(loc, "https://auth.example.com/cas/login?rd=") {
		t.Errorf("Location prefix wrong: %q", loc)
	}
	// The encoded rd must decode back to the original URL.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location not a valid URL: %v", err)
	}
	rd := u.Query().Get("rd")
	if rd != "https://app.example.com/dashboard?tab=overview" {
		t.Errorf("rd = %q, want https://app.example.com/dashboard?tab=overview", rd)
	}
}

// TestBuildLoginRedirect_DisallowedOrigin: an origin not in the
// allowlist results in ok=false. The disallowed value must NOT appear
// in the returned string — that'd let an attacker probe what's
// accepted by varying the forwarded headers.
func TestBuildLoginRedirect_DisallowedOrigin(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins("https://app.example.com")

	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "evil.example.org")
	r.Header.Set("X-Forwarded-Uri", "/")

	loc, ok := h.buildLoginRedirect(r)
	if ok {
		t.Fatalf("expected ok=false for evil.example.org, got loc=%q", loc)
	}
	if strings.Contains(loc, "evil.example.org") {
		t.Errorf("disallowed origin echoed back: %q", loc)
	}
}

// TestBuildLoginRedirect_MissingHeaders: if the proxy didn't set
// X-Forwarded-Proto/Host, we can't build a sensible redirect — return
// ok=false and let the caller send a bare 401.
func TestBuildLoginRedirect_MissingHeaders(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins("https://app.example.com")

	cases := []struct {
		name  string
		proto string
		host  string
	}{
		{"no_proto", "", "app.example.com"},
		{"no_host", "https", ""},
		{"neither", "", ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
			if c.proto != "" {
				r.Header.Set("X-Forwarded-Proto", c.proto)
			}
			if c.host != "" {
				r.Header.Set("X-Forwarded-Host", c.host)
			}
			if _, ok := h.buildLoginRedirect(r); ok {
				t.Error("expected ok=false when proto/host missing")
			}
		})
	}
}

// TestBuildLoginRedirect_OriginNormalization: the allowlist comparison
// is case-insensitive on scheme/host, since that's how URLs are
// canonically compared. "HTTPS://APP.example.com" must match
// "https://app.example.com" in the configured list.
func TestBuildLoginRedirect_OriginNormalization(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins("https://app.example.com") // canonical

	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	r.Header.Set("X-Forwarded-Host", "APP.example.com")
	r.Header.Set("X-Forwarded-Uri", "/")

	if _, ok := h.buildLoginRedirect(r); !ok {
		t.Error("buildLoginRedirect should canonicalise case before allowlist check")
	}
}

// TestBuildLoginRedirect_EmptyAllowlist: with no configured origins,
// every request returns ok=false. This is the "operator hasn't opted
// in to proxy redirects" path — endpoint still works, just no Location
// on 401s.
func TestBuildLoginRedirect_EmptyAllowlist(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins() // no origins

	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")

	if _, ok := h.buildLoginRedirect(r); ok {
		t.Error("expected ok=false with empty allowlist")
	}
}

// TestBuildLoginRedirect_PathFallback: when neither X-Forwarded-Uri
// nor X-Forwarded-Path is set, the reconstruction uses "/" — the
// user lands on the app's homepage after auth, which is the right
// default when the proxy didn't tell us where they actually were.
func TestBuildLoginRedirect_PathFallback(t *testing.T) {
	t.Parallel()
	h := newHandlerWithOrigins("https://app.example.com")

	r := httptest.NewRequest(http.MethodGet, "/proxy/verify", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	// no Uri / Path

	loc, ok := h.buildLoginRedirect(r)
	if !ok {
		t.Fatal("expected ok=true")
	}
	u, _ := url.Parse(loc)
	if rd := u.Query().Get("rd"); rd != "https://app.example.com/" {
		t.Errorf("rd = %q, want https://app.example.com/", rd)
	}
}
