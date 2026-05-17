package crypto

import (
	"errors"
	"strings"
	"testing"
)

// TestCookieRoundTrip is the contract: Sign produces a value that
// Verify accepts and yields the original payload. Anything else means
// signatures are non-deterministic or the encoder is asymmetric.
func TestCookieRoundTrip(t *testing.T) {
	t.Parallel()
	s := NewCookieSigner("a-32-byte-secret-aaaaaaaaaaaaaa!")
	const payload = "user=alice;exp=1716000000"

	cookie := s.Sign(payload)
	got, err := s.Verify(cookie)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != payload {
		t.Fatalf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestCookieEmptyPayload: empty strings round-trip too. A real caller
// shouldn't sign empty data, but the API contract says nothing
// special-cases length.
func TestCookieEmptyPayload(t *testing.T) {
	t.Parallel()
	s := NewCookieSigner("secretsecretsecretsecretsecret!!")
	c := s.Sign("")
	got, err := s.Verify(c)
	if err != nil || got != "" {
		t.Fatalf("empty payload didn't round-trip: got=%q err=%v", got, err)
	}
}

// TestCookieTamperedPayload: flipping a byte of the encoded payload
// must invalidate the signature. The signer keeps the format intact, so
// Verify returns ErrSignature, not a decode error.
func TestCookieTamperedPayload(t *testing.T) {
	t.Parallel()
	s := NewCookieSigner("secretsecretsecretsecretsecret!!")
	cookie := s.Sign("hello")

	dot := strings.IndexByte(cookie, '.')
	if dot < 0 {
		t.Fatalf("cookie has no dot separator: %q", cookie)
	}
	// Flip a byte in the payload half.
	b := []byte(cookie)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}

	_, err := s.Verify(string(b))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

// TestCookieTamperedSignature: flipping the signature half also fails.
func TestCookieTamperedSignature(t *testing.T) {
	t.Parallel()
	s := NewCookieSigner("secretsecretsecretsecretsecret!!")
	cookie := s.Sign("hello")

	dot := strings.IndexByte(cookie, '.')
	if dot < 0 {
		t.Fatalf("cookie has no dot separator: %q", cookie)
	}
	b := []byte(cookie)
	last := len(b) - 1
	if b[last] == 'a' {
		b[last] = 'b'
	} else {
		b[last] = 'a'
	}

	_, err := s.Verify(string(b))
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

// TestCookieMalformed: missing-separator, missing-half, and totally
// bogus values all fail with ErrSignature — never panic, never accept.
func TestCookieMalformed(t *testing.T) {
	t.Parallel()
	s := NewCookieSigner("secretsecretsecretsecretsecret!!")
	cases := []string{
		"",
		"no-dot-at-all",
		".only-sig",
		"only-payload.",
		"invalid base64!.also-invalid!",
	}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			if _, err := s.Verify(c); !errors.Is(err, ErrSignature) {
				t.Fatalf("expected ErrSignature for %q, got %v", c, err)
			}
		})
	}
}

// TestCookieDifferentKeys: a cookie signed with key A must not validate
// under key B. This is the property that lets us rotate session keys
// safely — old cookies become invalid the moment the secret changes.
func TestCookieDifferentKeys(t *testing.T) {
	t.Parallel()
	a := NewCookieSigner("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	b := NewCookieSigner("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	cookie := a.Sign("payload")
	if _, err := b.Verify(cookie); !errors.Is(err, ErrSignature) {
		t.Fatalf("cookie signed under A validated under B: err=%v", err)
	}
}
