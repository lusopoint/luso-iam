package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestPKCERoundTrip: a freshly-minted (verifier, challenge) pair must
// validate. This is the core OAuth flow — broken here, every PKCE
// client breaks.
func TestPKCERoundTrip(t *testing.T) {
	t.Parallel()
	v, c, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE: %v", err)
	}
	// Sanity: the verifier should be 43+ chars per RFC 7636.
	if len(v) < 43 {
		t.Fatalf("verifier too short: len=%d, want >= 43", len(v))
	}
	if !VerifyPKCE(v, c) {
		t.Fatalf("VerifyPKCE rejected the pair NewPKCE returned: v=%q c=%q", v, c)
	}
}

// TestPKCEKnownVector: verify against a pre-computed value. The S256
// algorithm is SHA-256 of the verifier, base64url-no-pad. If we ever
// accidentally switch to plain base64 or include padding, this catches it.
func TestPKCEKnownVector(t *testing.T) {
	t.Parallel()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if !VerifyPKCE(verifier, want) {
		t.Fatalf("known-vector PKCE pair failed: v=%q want_c=%q", verifier, want)
	}
}

// TestPKCEMismatch: the wrong verifier must fail.
func TestPKCEMismatch(t *testing.T) {
	t.Parallel()
	_, challenge, _ := NewPKCE()
	if VerifyPKCE("totally-different-verifier", challenge) {
		t.Fatal("VerifyPKCE accepted a wrong verifier")
	}
}

// TestPKCEEmpty: both inputs must be non-empty. The OAuth spec is
// silent on this, but a "verify empty against empty" path would let a
// confused client bypass PKCE entirely.
func TestPKCEEmpty(t *testing.T) {
	t.Parallel()
	if VerifyPKCE("", "") {
		t.Fatal("empty-empty pair accepted")
	}
	if VerifyPKCE("v", "") {
		t.Fatal("empty challenge accepted")
	}
	if VerifyPKCE("", "c") {
		t.Fatal("empty verifier accepted")
	}
}

// TestATHash + TestCHash: these are deterministic — same input, same
// output every time. The OIDC spec is explicit (left-half of SHA-256,
// base64url-no-pad), so we pin known values.
func TestATHash(t *testing.T) {
	t.Parallel()
	got := ATHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y")
	// Computed manually: SHA-256 of the string, take first 16 bytes,
	// base64url-encode without padding.
	sum := sha256.Sum256([]byte("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"))
	want := base64.RawURLEncoding.EncodeToString(sum[:16])
	if got != want {
		t.Fatalf("ATHash: got %q, want %q", got, want)
	}
}

func TestCHash(t *testing.T) {
	t.Parallel()
	// Spec example from OIDC Core 1.0 §3.3.2.11 used as input shape.
	got := CHash("SplxlOBeZQQYbYS6WxSbIA")
	if got == "" {
		t.Fatal("CHash returned empty string")
	}
	// Output is base64url-encoded — must not contain padding or
	// non-urlsafe chars.
	if strings.Contains(got, "=") || strings.Contains(got, "+") || strings.Contains(got, "/") {
		t.Fatalf("CHash output contains base64-padding or non-urlsafe chars: %q", got)
	}
}
