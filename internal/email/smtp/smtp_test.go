package smtp

import (
	"strings"
	"testing"

	"github.com/lusopoint/lusoiam/internal/email"
)

// TestBuildBody_Multipart: when both Text and HTML are present, the
// body must be a well-formed multipart/alternative  boundary header,
// each part separated by --boundary, trailing --boundary--.
//
// Pins the wire format so a future refactor doesn't accidentally
// produce something the receiving MTA can't parse.
func TestBuildBody_Multipart(t *testing.T) {
	t.Parallel()
	body := buildBody("IAM <noreply@example.com>", email.Message{
		To:      "user@example.com",
		Subject: "Test",
		Text:    "plain version",
		HTML:    "<p>html version</p>",
	})
	s := string(body)

	// Headers
	for _, want := range []string{
		"From: IAM <noreply@example.com>",
		"To: user@example.com",
		"Subject: Test",
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative",
		"boundary=",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, s)
		}
	}
	// Both parts must be present, each with its own Content-Type.
	if !strings.Contains(s, "Content-Type: text/plain") {
		t.Error("missing text part Content-Type")
	}
	if !strings.Contains(s, "Content-Type: text/html") {
		t.Error("missing html part Content-Type")
	}
	if !strings.Contains(s, "plain version") {
		t.Error("missing text body content")
	}
	if !strings.Contains(s, "html version") {
		t.Error("missing html body content")
	}
	// Trailing boundary
	if !strings.Contains(s, "--\r\n") {
		t.Error("missing trailing boundary marker")
	}
}

// TestBuildBody_TextOnly: single-part text/plain when only Text is
// set. Verifies we don't emit multipart wrapper when unnecessary.
func TestBuildBody_TextOnly(t *testing.T) {
	t.Parallel()
	body := string(buildBody("a@b", email.Message{
		To:      "x@y",
		Subject: "S",
		Text:    "hello",
	}))
	if strings.Contains(body, "multipart") {
		t.Error("text-only should NOT use multipart")
	}
	if !strings.Contains(body, "Content-Type: text/plain") {
		t.Error("missing text/plain Content-Type")
	}
	if !strings.Contains(body, "hello") {
		t.Error("missing body content")
	}
}

// TestSanitizeHeader_StripsInjection: header values can't contain
// CR or LF. Attackers who could control Subject or recipient would
// otherwise inject Bcc: or extra body content. Pin the defense.
func TestSanitizeHeader_StripsInjection(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"normal":             "normal",
		"line1\nline2":       "line1line2",
		"line1\r\nBcc: evil": "line1Bcc: evil",
		"  padded  ":         "padded",
		"":                   "",
	}
	for in, want := range cases {
		if got := sanitizeHeader(in); got != want {
			t.Errorf("sanitizeHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExtractAddress: MAIL FROM envelope address must be just the
// bare email  display-formatted "Name <user@host>" must yield
// "user@host". Bare addresses must pass through unchanged.
func TestExtractAddress(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"user@example.com":          "user@example.com",
		"IAM <noreply@example.com>": "noreply@example.com",
		"<bare@example.com>":        "bare@example.com",
		"  spaces@example.com  ":    "spaces@example.com",
	}
	for in, want := range cases {
		if got := extractAddress(in); got != want {
			t.Errorf("extractAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNew_RequiredFields: missing host or from must be a constructor
// error so the operator finds out at startup, not at first send.
func TestNew_RequiredFields(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Error("empty config should be rejected")
	}
	if _, err := New(Config{Host: "smtp.example.com"}); err == nil {
		t.Error("missing From should be rejected")
	}
	if _, err := New(Config{Host: "h", From: "f@g", Port: -1}); err == nil {
		t.Error("invalid port should be rejected")
	}
	s, err := New(Config{Host: "smtp.example.com", From: "a@b"})
	if err != nil {
		t.Fatalf("valid config failed: %v", err)
	}
	if s.port != 587 {
		t.Errorf("default port = %d, want 587", s.port)
	}
}

// TestNew_ImplicitTLSOn465: port 465 must set implicitTLS so the
// connection starts as TLS rather than waiting for STARTTLS. Most
// real failures here would be silent (try plain on a TLS-only port,
// connection hangs).
func TestNew_ImplicitTLSOn465(t *testing.T) {
	t.Parallel()
	s, err := New(Config{Host: "h", From: "f@g", Port: 465})
	if err != nil {
		t.Fatal(err)
	}
	if !s.implicitTLS {
		t.Error("port 465 should set implicitTLS=true")
	}
}
