package passwordreset

import (
	"strings"
	"testing"
	"time"
)

// TestHashToken_Stable: same token in → same hash out. Required for
// DB lookups (we store the hash and look up by hash).
func TestHashToken_Stable(t *testing.T) {
	t.Parallel()
	const tok = "abc123"
	if hashToken(tok) != hashToken(tok) {
		t.Error("hashToken should be deterministic")
	}
}

// TestHashToken_DifferentInputs: different tokens → different hashes.
// If two tokens collided, the second user's reset link would consume
// the first user's row.
func TestHashToken_DifferentInputs(t *testing.T) {
	t.Parallel()
	if hashToken("a") == hashToken("b") {
		t.Error("different tokens should hash differently")
	}
}

// TestHashToken_NotPlaintext: defence-in-depth. The hash must NOT
// equal the input a coding mistake that returned the input would
// store plaintext in the DB without anything else flagging it.
func TestHashToken_NotPlaintext(t *testing.T) {
	t.Parallel()
	tok := "some-token-value"
	if hashToken(tok) == tok {
		t.Error("hashToken returned input unchanged, would store plaintext in DB")
	}
}

// TestHashToken_HexEncoded: the stored hash must be hex (DB column
// is TEXT). 32 raw bytes → 64 hex chars.
func TestHashToken_HexEncoded(t *testing.T) {
	t.Parallel()
	h := hashToken("anything")
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(h))
	}
	for _, c := range h {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Errorf("hash contains non-hex char %q (full: %s)", c, h)
		}
	}
}

// TestEmailHash_CaseAndWhitespaceNormalised: log correlation needs
// case-insensitive comparison. Two requests with "Alice@x" and
// "alice@x " should hash identically.
func TestEmailHash_CaseAndWhitespaceNormalised(t *testing.T) {
	t.Parallel()
	if emailHash("Alice@Example.com") != emailHash("alice@example.com  ") {
		t.Error("emailHash must be case- and whitespace-insensitive")
	}
}

// TestEmailMessage_ContainsLink: the email body must contain the
// reset URL, without it the user has no way to act on the email.
// Pins both text and HTML parts.
func TestEmailMessage_ContainsLink(t *testing.T) {
	t.Parallel()
	url := "https://auth.example.com/password/reset?token=xyz"
	msg := email_message("IAM <noreply@example.com>", "user@example.com", url, 30*time.Minute)

	if msg.To != "user@example.com" {
		t.Errorf("To = %q, want user@example.com", msg.To)
	}
	if msg.Subject == "" {
		t.Error("Subject must not be empty")
	}
	if !strings.Contains(msg.Text, url) {
		t.Error("text body missing reset URL")
	}
	if !strings.Contains(msg.HTML, url) {
		t.Error("html body missing reset URL")
	}
	// TTL surfaced to the user so they know how urgent the click is.
	if !strings.Contains(msg.Text, "30") {
		t.Error("text body should mention TTL in minutes (got missing 30)")
	}
}

// TestEmailMessage_BothPartsPresent: must always be multipart-capable
// some accessibility clients only parse the text alternative.
func TestEmailMessage_BothPartsPresent(t *testing.T) {
	t.Parallel()
	msg := email_message("a@b", "c@d", "https://x/y", time.Minute)
	if msg.Text == "" {
		t.Error("text part empty, accessibility clients can't render")
	}
	if msg.HTML == "" {
		t.Error("html part empty, modern clients expect HTML")
	}
}

// TestNew_RequiredFields: missing dependencies must fail loudly at
// construction. If we let Sender or Store be nil, the first reset
// request would crash with a nil-deref.
func TestNew_RequiredFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"missing_store", Config{}},
		// The rest require an actual *postgres.Store to construct
		// without erroring on Store-nil-check, so we settle for the
		// store-nil case as the canonical sanity check. The other
		// required fields (Sender, BaseURL, From) are covered by
		// inspection, they all do an explicit if-nil/empty-return.
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(c.cfg); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}
