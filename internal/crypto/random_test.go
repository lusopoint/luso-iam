package crypto

import (
	"strings"
	"testing"
)

// TestRandomTokenLength: 2n hex chars from n bytes, that's the API
// contract. The other thing we want is uniqueness across calls.
func TestRandomTokenLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 8, 16, 32, 64} {
		tok, err := RandomToken(n)
		if err != nil {
			t.Fatalf("RandomToken(%d): %v", n, err)
		}
		if len(tok) != 2*n {
			t.Fatalf("RandomToken(%d) length = %d, want %d", n, len(tok), 2*n)
		}
		// Verify it's hex, only 0-9, a-f.
		for _, c := range tok {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Fatalf("non-hex character in token: %q (full token: %q)", c, tok)
			}
		}
	}
}

// TestRandomTokenUniqueness: 100 32-byte tokens should all differ.
// Birthday paradox math says collision in 256-bit space is so unlikely
// it's effectively zero, so a single collision means our RNG is broken.
func TestRandomTokenUniqueness(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		tok, err := RandomToken(32)
		if err != nil {
			t.Fatalf("RandomToken: %v", err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token at iter %d: %q", i, tok)
		}
		seen[tok] = true
	}
}

// TestRandomPasswordLength: the generated password is exactly n chars.
// Off-by-ones here would surface as users unable to log in (their
// stored hash doesn't match what they typed back).
func TestRandomPasswordLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 12, 20, 64} {
		p, err := RandomPassword(n)
		if err != nil {
			t.Fatalf("RandomPassword(%d): %v", n, err)
		}
		if len(p) != n {
			t.Fatalf("RandomPassword(%d) length = %d, want %d", n, len(p), n)
		}
	}
}

// TestRandomPasswordAlphabet: every character must come from the
// passwordAlphabet constant. We deliberately exclude visually
// ambiguous characters; a regression that re-adds "0" or "l" would
// cause real-world transcription errors.
func TestRandomPasswordAlphabet(t *testing.T) {
	t.Parallel()
	// 500 chars gives us a high probability of hitting every letter,
	// while staying fast.
	p, err := RandomPassword(500)
	if err != nil {
		t.Fatalf("RandomPassword: %v", err)
	}
	for i, c := range p {
		if !strings.ContainsRune(passwordAlphabet, c) {
			t.Fatalf("char %q at pos %d not in passwordAlphabet (%q)", c, i, passwordAlphabet)
		}
	}
	// Specifically: ambiguous characters must be absent.
	for _, banned := range "0OlI1" {
		if strings.ContainsRune(p, banned) {
			t.Fatalf("ambiguous character %q appeared in password: %s", banned, p)
		}
	}
}

// TestRandomPasswordZeroLength: n=0 is a programming error and must
// return an error rather than silently returning an empty string.
func TestRandomPasswordZeroLength(t *testing.T) {
	t.Parallel()
	if _, err := RandomPassword(0); err == nil {
		t.Fatal("RandomPassword(0) returned nil error; expected validation failure")
	}
	if _, err := RandomPassword(-5); err == nil {
		t.Fatal("RandomPassword(-5) returned nil error; expected validation failure")
	}
}

// TestRandomPasswordUniqueness: same uniqueness argument as tokens.
// Lower iteration count because each call does several rand reads.
func TestRandomPasswordUniqueness(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		p, err := RandomPassword(20)
		if err != nil {
			t.Fatalf("RandomPassword: %v", err)
		}
		if seen[p] {
			t.Fatalf("duplicate password at iter %d: %q", i, p)
		}
		seen[p] = true
	}
}
