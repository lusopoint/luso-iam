package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// noopHandler responds 200 OK and writes nothing else. Used by tests
// to confirm whether or not the middleware called through to it.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
})

// echoTokenHandler reads the token from context and writes it as body.
// Lets tests assert the context plumbing works.
var echoTokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(CSRFTokenFromContext(r.Context())))
})

// TestCSRF_IssuesCookieOnSafeRequest: every GET should leave the
// browser with a CSRF cookie. Without this, the very first state-
// mutating request would have no cookie to validate against.
func TestCSRF_IssuesCookieOnSafeRequest(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	rr := httptest.NewRecorder()
	mw(noopHandler).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	cookies := rr.Result().Cookies()
	var csrf *http.Cookie
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			csrf = c
			break
		}
	}
	if csrf == nil {
		t.Fatal("expected CSRF cookie to be set on GET")
	}
	if csrf.Value == "" {
		t.Error("CSRF cookie should have a non-empty token")
	}
	if csrf.HttpOnly {
		t.Error("CSRF cookie must NOT be HttpOnly — SPA needs to read it")
	}
	if csrf.SameSite != http.SameSiteLaxMode {
		t.Errorf("CSRF cookie SameSite = %v, want Lax", csrf.SameSite)
	}
}

// TestCSRF_ReusesCookieIfPresent: a request already carrying a cookie
// shouldn't get a new one issued. Token stability across requests is
// the whole point of the double-submit pattern.
func TestCSRF_ReusesCookieIfPresent(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "preset-value-xyz"})

	rr := httptest.NewRecorder()
	mw(echoTokenHandler).ServeHTTP(rr, r)

	// Body is the context token — must match what we sent in.
	if got := rr.Body.String(); got != "preset-value-xyz" {
		t.Errorf("context token = %q, want preset-value-xyz", got)
	}

	// And no new Set-Cookie for CSRF (we reused, didn't issue).
	for _, c := range rr.Result().Cookies() {
		if c.Name == CSRFCookieName {
			t.Errorf("middleware re-issued the cookie when one was present")
		}
	}
}

// TestCSRF_BlocksUnauthenticatedPost: POST with no token gets 403.
// The inner handler must not run.
func TestCSRF_BlocksUnauthenticatedPost(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
	})

	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, httptest.NewRequest("POST", "/cas/login", nil))

	if rr.Code != 403 {
		t.Errorf("expected 403 for POST with no token, got %d", rr.Code)
	}
	if called {
		t.Error("inner handler was called despite CSRF failure")
	}
}

// TestCSRF_AcceptsMatchingHeader: SPA flow — cookie + matching
// X-CSRF-Token header → request passes through.
func TestCSRF_AcceptsMatchingHeader(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	const tok = "this-is-the-token"
	r := httptest.NewRequest("POST", "/admin/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: tok})
	r.Header.Set(CSRFHeaderName, tok)

	rr := httptest.NewRecorder()
	mw(noopHandler).ServeHTTP(rr, r)

	if rr.Code != 200 {
		t.Errorf("expected 200 for matched token, got %d", rr.Code)
	}
}

// TestCSRF_AcceptsMatchingFormField: server-rendered form flow —
// cookie + matching _csrf form field → passes through.
func TestCSRF_AcceptsMatchingFormField(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	const tok = "matching-token-value"
	body := url.Values{CSRFFormField: {tok}, "other": {"data"}}.Encode()
	r := httptest.NewRequest("POST", "/cas/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: tok})

	rr := httptest.NewRecorder()
	mw(noopHandler).ServeHTTP(rr, r)

	if rr.Code != 200 {
		t.Errorf("expected 200 for form _csrf match, got %d", rr.Code)
	}
}

// TestCSRF_RejectsMismatchedToken: the attacker scenario. They might
// somehow set a known cookie value but they don't know the user's
// browser's cookie value. A mismatched token in header or body MUST
// fail — this is the entire point of the protection.
func TestCSRF_RejectsMismatchedToken(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	r := httptest.NewRequest("POST", "/admin/v1/users", nil)
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "the-real-token"})
	r.Header.Set(CSRFHeaderName, "attacker-guess")

	rr := httptest.NewRecorder()
	mw(noopHandler).ServeHTTP(rr, r)

	if rr.Code != 403 {
		t.Errorf("expected 403 for mismatched token, got %d", rr.Code)
	}
}

// TestCSRF_ExemptPathsBypass: machine-to-machine endpoints (OAuth
// token, introspect, revoke) don't have a browser to manage cookies.
// They authenticate by client credentials and don't need CSRF.
//
// Exempt paths must ALSO skip cookie issuance — load-balancer probes
// hitting /healthz shouldn't accumulate state cookies, and downstream
// caches can be tripped up by surprise Set-Cookie headers.
func TestCSRF_ExemptPathsBypass(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{
		Secure:      false,
		ExemptPaths: []string{"/oauth2/", "/healthz"},
	})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	// POST with no CSRF token, to /oauth2/token — should bypass.
	rr := httptest.NewRecorder()
	mw(inner).ServeHTTP(rr, httptest.NewRequest("POST", "/oauth2/token", nil))
	if !called {
		t.Error("inner handler not called; exempt path should bypass CSRF")
	}
	if rr.Code != 200 {
		t.Errorf("expected 200 for exempt path, got %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == CSRFCookieName {
			t.Errorf("exempt path /oauth2/token issued a CSRF cookie; should not")
		}
	}

	// GET /healthz must not issue a cookie either — probes shouldn't
	// be polluted with state.
	rr = httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})).ServeHTTP(rr, httptest.NewRequest("GET", "/healthz", nil))
	for _, c := range rr.Result().Cookies() {
		if c.Name == CSRFCookieName {
			t.Errorf("exempt GET /healthz issued a CSRF cookie; should not")
		}
	}
}

// TestCSRF_SafeMethodsBypass: GET/HEAD/OPTIONS must never be checked.
// Doing so would 403 every initial page load (when no cookie exists
// yet) and break the entire browsing flow.
func TestCSRF_SafeMethodsBypass(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		rr := httptest.NewRecorder()
		mw(noopHandler).ServeHTTP(rr, httptest.NewRequest(method, "/admin/v1/users", nil))
		if rr.Code != 200 {
			t.Errorf("%s without token: got %d, want 200", method, rr.Code)
		}
	}
}

// TestCSRF_HeaderTakesPriorityOverForm: if both are present, the
// header is the source of truth. (Practical reason: it would be very
// strange for both to be present and differ, but if so we prefer the
// header because it's harder for an attacker to inject than a form
// field carried over from a stale page.)
func TestCSRF_HeaderTakesPriorityOverForm(t *testing.T) {
	t.Parallel()
	mw := NewCSRF(CSRFConfig{Secure: false})

	const cookieTok = "actual-token"
	body := url.Values{CSRFFormField: {cookieTok}}.Encode() // form has correct value
	r := httptest.NewRequest("POST", "/cas/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookieTok})
	r.Header.Set(CSRFHeaderName, "different-from-cookie") // header has wrong value

	rr := httptest.NewRecorder()
	mw(noopHandler).ServeHTTP(rr, r)

	// Even though form matches, header is checked first and wrong.
	if rr.Code != 403 {
		t.Errorf("header should take priority and cause 403; got %d", rr.Code)
	}
}

// TestCSRFTokenFromContext_NilContext: don't panic on weird inputs.
func TestCSRFTokenFromContext_NilContext(t *testing.T) {
	t.Parallel()
	if got := CSRFTokenFromContext(context.Background()); got != "" {
		t.Errorf("empty context should give empty token, got %q", got)
	}
}
