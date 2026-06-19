package mfa

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
)

// testSigner returns a CookieSigner with a fixed test key. Determinism
// in tests is more valuable than entropy here the goal is to verify
// our cookie logic, not the underlying HMAC implementation.
func testSigner() *crypto.CookieSigner {
	return crypto.NewCookieSigner("test-key-test-key-test-key-test!")
}

// roundTrip helper: issue a challenge on a recorder, then read it back
// via a fresh request that carries the Set-Cookie value. Mirrors what
// the real handlers do across the password → MFA boundary.
func roundTrip(t *testing.T, c Challenge) *Challenge {
	t.Helper()
	signer := testSigner()

	w := httptest.NewRecorder()
	if err := IssueChallenge(w, signer, false, c); err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	res := w.Result()
	defer res.Body.Close()

	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no Set-Cookie header on response")
	}

	r := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	for _, ck := range cookies {
		r.AddCookie(ck)
	}
	got, err := ReadChallenge(r, signer)
	if err != nil {
		t.Fatalf("ReadChallenge: %v", err)
	}
	return got
}

// TestChallengeRoundTrip: every field round-trips. Catches any
// json-tag drift between Challenge fields and the on-the-wire shape.
func TestChallengeRoundTrip(t *testing.T) {
	t.Parallel()
	in := Challenge{
		UserID:    "11111111-2222-3333-4444-555555555555",
		Service:   "https://app.example.com/cas-callback",
		NextURL:   "/admin/users",
		Methods:   []string{"totp", "webauthn"},
		HasBackup: true,
		// Expires is set by IssueChallenge, leave zero
	}
	got := roundTrip(t, in)

	if got.UserID != in.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, in.UserID)
	}
	if got.Service != in.Service {
		t.Errorf("Service: got %q, want %q", got.Service, in.Service)
	}
	if got.NextURL != in.NextURL {
		t.Errorf("NextURL: got %q, want %q", got.NextURL, in.NextURL)
	}
	if got.HasBackup != in.HasBackup {
		t.Errorf("HasBackup: got %v, want %v", got.HasBackup, in.HasBackup)
	}
	if strings.Join(got.Methods, ",") != strings.Join(in.Methods, ",") {
		t.Errorf("Methods: got %v, want %v", got.Methods, in.Methods)
	}
	// Expires must have been set to ~now+5min by IssueChallenge.
	if got.Expires <= 0 {
		t.Errorf("Expires not populated: got %d", got.Expires)
	}
	delta := got.Expires - time.Now().Unix()
	if delta < 60 || delta > 5*60+10 {
		t.Errorf("Expires looks off: %ds from now (expected ~300s)", delta)
	}
}

// TestChallengeMissingCookie: no cookie → ErrNoChallenge, not a panic.
func TestChallengeMissingCookie(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	_, err := ReadChallenge(r, testSigner())
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expected ErrNoChallenge, got %v", err)
	}
}

// TestChallengeBadSignature: cookie present, but signed with a
// different key. The two-signer setup mirrors a real attack: someone
// who knows the cookie structure but not the secret.
func TestChallengeBadSignature(t *testing.T) {
	t.Parallel()
	good := testSigner()
	bad := crypto.NewCookieSigner("totally-different-key-aaaaaaaaaa")

	w := httptest.NewRecorder()
	_ = IssueChallenge(w, good, false, Challenge{UserID: "u"})

	r := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	for _, ck := range w.Result().Cookies() {
		r.AddCookie(ck)
	}
	_, err := ReadChallenge(r, bad)
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expected ErrNoChallenge for wrong-key verify, got %v", err)
	}
}

// TestChallengeTamperedCookie: flipping a byte breaks the signature.
// Distinct from BadSignature because here the signer is the right one
// - the attacker just modified the cookie value in transit.
func TestChallengeTamperedCookie(t *testing.T) {
	t.Parallel()
	signer := testSigner()
	w := httptest.NewRecorder()
	_ = IssueChallenge(w, signer, false, Challenge{UserID: "u"})

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want exactly one cookie, got %d", len(cookies))
	}
	// Flip first byte.
	b := []byte(cookies[0].Value)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	tampered := &http.Cookie{Name: cookies[0].Name, Value: string(b)}

	r := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	r.AddCookie(tampered)
	_, err := ReadChallenge(r, signer)
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expected ErrNoChallenge for tampered cookie, got %v", err)
	}
}

// TestChallengeExpired: a challenge whose Expires field is in the past
// must be rejected. We build the cookie manually here because
// IssueChallenge always uses now+TTL, going around it gives us the
// fine-grained timestamp control the test needs.
func TestChallengeExpired(t *testing.T) {
	t.Parallel()
	signer := testSigner()

	// Construct a Challenge marked as already expired, sign it with the
	// same signer the verifier uses.
	expired := Challenge{
		UserID:  "u",
		Expires: time.Now().Add(-time.Minute).Unix(),
	}
	payload := mustJSON(t, expired)
	cookie := &http.Cookie{Name: ChallengeCookieName, Value: signer.Sign(payload)}

	r := httptest.NewRequest(http.MethodGet, "/mfa", nil)
	r.AddCookie(cookie)
	_, err := ReadChallenge(r, signer)
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("expected ErrNoChallenge for expired cookie, got %v", err)
	}
}

// TestClearChallenge: ClearChallenge writes a deletion cookie. Browsers
// recognise MaxAge<0 / expires-in-past as a delete signal.
func TestClearChallenge(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	ClearChallenge(w, false)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want one Set-Cookie, got %d", len(cookies))
	}
	if cookies[0].Name != ChallengeCookieName {
		t.Errorf("cookie name: got %q, want %q", cookies[0].Name, ChallengeCookieName)
	}
	if cookies[0].MaxAge >= 0 {
		t.Errorf("expected MaxAge<0 (deletion), got %d", cookies[0].MaxAge)
	}
}

// TestChallengeSecureFlag: when secure=true, the Secure attribute is
// set; when false, it isn't. Matters for prod-vs-dev, sending a
// Secure cookie over plain HTTP would silently lose the session.
func TestChallengeSecureFlag(t *testing.T) {
	t.Parallel()
	for _, secure := range []bool{true, false} {
		secure := secure
		t.Run("", func(t *testing.T) {
			w := httptest.NewRecorder()
			_ = IssueChallenge(w, testSigner(), secure, Challenge{UserID: "u"})
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("want one cookie, got %d", len(cookies))
			}
			if cookies[0].Secure != secure {
				t.Errorf("Secure flag: got %v, want %v", cookies[0].Secure, secure)
			}
			// HttpOnly is always on, not a configuration knob.
			if !cookies[0].HttpOnly {
				t.Error("HttpOnly must always be true")
			}
		})
	}
}

// mustJSON serialises v with encoding/json. Helper used by
// TestChallengeExpired to construct a payload directly.
func mustJSON(t *testing.T, v Challenge) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
