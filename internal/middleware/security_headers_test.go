package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hello is a trivial handler used to anchor the middleware tests.
func hello(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("hello"))
}

// TestSecurityHeaders_HappyPath: in secure mode, every defense header
// is set. This is the "default for production" path.
func TestSecurityHeaders_HappyPath(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(true)
	srv := mw(http.HandlerFunc(hello))

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if rr.Code != 200 {
		t.Fatalf("unexpected status: %d", rr.Code)
	}

	// Each of these must be present with a non-empty value.
	required := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Content-Security-Policy",
	}
	for _, h := range required {
		if v := rr.Header().Get(h); v == "" {
			t.Errorf("missing header: %s", h)
		}
	}
}

// TestSecurityHeaders_HSTSOnlyWhenSecure: HSTS must NOT be set when
// secure=false (i.e., serving over http). The reason is real and bites
// people: some browsers cache HSTS regardless of scheme, so serving
// `Strict-Transport-Security` over plain http can lock the same browser
// out of localhost forever (or until manually cleared). This test pins
// the safe behaviour.
func TestSecurityHeaders_HSTSOnlyWhenSecure(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(false)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(hello)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if v := rr.Header().Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS should not be set over http; got %q", v)
	}

	// Other headers should still be set, they're safe in http mode.
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"} {
		if v := rr.Header().Get(h); v == "" {
			t.Errorf("expected %s to be set even over http", h)
		}
	}
}

// TestSecurityHeaders_AntiClickjacking: both X-Frame-Options and CSP
// frame-ancestors must say DENY/'none' respectively. Two headers
// because old browsers don't understand frame-ancestors, modern ones
// honor either, and we want clickjacking protection everywhere.
func TestSecurityHeaders_AntiClickjacking(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(true)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(hello)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %q", csp)
	}
}

// TestSecurityHeaders_CSPUsesNoncesNotUnsafeInline: this is a regression
// guard for the thing that makes the CSP worth having at all. Several
// server-rendered templates (the shared base layout's dark-mode
// detector, the MFA pages, the docs page) have inline <script>/<style>
// blocks that need to keep working, but 'unsafe-inline' would let ANY
// inline script run, including one an attacker injected via XSS the
// whole point of this policy is that only OUR inline content, carrying
// the exact nonce minted for that response, is allowed to run.
func TestSecurityHeaders_CSPUsesNoncesNotUnsafeInline(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(true)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(hello)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP still allows unsafe-inline, defeating the point of nonces: %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Errorf("CSP missing a nonce-based script-src\nfull CSP: %s", csp)
	}
	if !strings.Contains(csp, "style-src 'self' 'nonce-") {
		t.Errorf("CSP missing a nonce-based style-src\nfull CSP: %s", csp)
	}
	if !strings.Contains(csp, "img-src 'self' data:") { // TOTP QR codes are data: URIs
		t.Errorf("CSP missing img-src data: carve-out\nfull CSP: %s", csp)
	}
}

// TestSecurityHeaders_NonceIsFreshPerRequestAndMatchesHeader: the nonce
// exposed to handlers via CSPNonceFromContext must be exactly the one
// in that response's CSP header (otherwise the inline tag it's stamped
// onto would get blocked by the browser), and it must differ across
// requests a reused or predictable nonce is no better than
// 'unsafe-inline' for an attacker who can observe one response.
func TestSecurityHeaders_NonceIsFreshPerRequestAndMatchesHeader(t *testing.T) {
	t.Parallel()

	var seen []string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, CSPNonceFromContext(r.Context()))
	})
	mw := SecurityHeaders(true)
	srv := mw(inner)

	var nonces [2]string
	for i := range nonces {
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
		nonces[i] = rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(nonces[i], "'nonce-"+seen[i]+"'") {
			t.Errorf("request %d: context nonce %q not present in CSP header %q", i, seen[i], nonces[i])
		}
	}
	if seen[0] == "" || seen[1] == "" {
		t.Fatal("expected a non-empty nonce on every request")
	}
	if seen[0] == seen[1] {
		t.Error("nonce was reused across two separate requests; it must be fresh every time")
	}
}

// TestSecurityHeaders_PermissionsPolicyAllowsWebAuthn: WebAuthn
// requires publickey-credentials-* permissions. If we set
// Permissions-Policy too aggressively we'd disable our own MFA.
// Regression guard against future hardening tightening that breaks
// passkey enrollment.
func TestSecurityHeaders_PermissionsPolicyAllowsWebAuthn(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(true)
	rr := httptest.NewRecorder()
	mw(http.HandlerFunc(hello)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	pp := rr.Header().Get("Permissions-Policy")
	for _, want := range []string{
		"publickey-credentials-get=(self)",
		"publickey-credentials-create=(self)",
	} {
		if !strings.Contains(pp, want) {
			t.Errorf("Permissions-Policy missing %q\nfull: %s", want, pp)
		}
	}
}

// TestSecurityHeaders_PassesThroughResponse: the middleware must not
// interfere with the underlying handler's body or status. Easy to
// accidentally break by, e.g., calling WriteHeader before the inner
// handler does.
func TestSecurityHeaders_PassesThroughResponse(t *testing.T) {
	t.Parallel()

	mw := SecurityHeaders(true)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom-From-Inner", "yes")
		w.WriteHeader(201)
		_, _ = w.Write([]byte("created"))
	})

	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, httptest.NewRequest("POST", "/", nil))

	if rr.Code != 201 {
		t.Errorf("status = %d, want 201", rr.Code)
	}
	if rr.Body.String() != "created" {
		t.Errorf("body = %q, want 'created'", rr.Body.String())
	}
	if rr.Header().Get("X-Custom-From-Inner") != "yes" {
		t.Errorf("inner handler's header lost")
	}
	// And our headers still came through:
	if rr.Header().Get("X-Frame-Options") == "" {
		t.Errorf("security headers lost when inner handler writes")
	}
}
