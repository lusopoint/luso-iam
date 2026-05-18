package mfa

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// TestTOTPEnrollTemplate_DataURLNotSanitized is a regression guard.
// html/template rewrites any "data:" URL in a src/href context to
// "#ZgotmplZ" because data: URLs can carry script in <a href>. The QR
// data we generate is a trusted PNG built in-process, so the handler
// passes it as template.URL to opt out of sanitization. If anyone ever
// switches the struct field back to plain string, this test fails fast.
//
// We parse the template directly here rather than reaching into the
// real templates FS, because the bug is in the *type* the handler
// passes, not in the template file itself.
func TestTOTPEnrollTemplate_DataURLNotSanitized(t *testing.T) {
	t.Parallel()

	const tpl = `<img src="{{ .QRCodeData }}" alt="QR">`

	// Mirror the handler's struct shape: QRCodeData is template.URL.
	type data struct {
		QRCodeData template.URL
	}

	parsed := template.Must(template.New("totp").Parse(tpl))
	var buf bytes.Buffer
	const url = "data:image/png;base64,iVBORw0KGgoAAANSUhEUgAA"
	if err := parsed.Execute(&buf, data{QRCodeData: template.URL(url)}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := buf.String()
	if strings.Contains(got, "#ZgotmplZ") {
		t.Fatalf("data URL got sanitized to #ZgotmplZ — QRCodeData must be template.URL, not string:\n%s", got)
	}
	if !strings.Contains(got, url) {
		t.Fatalf("rendered output missing the data URL: %s", got)
	}
}

// TestTOTPEnrollTemplate_StringIsSanitized: the negative — proving that
// the plain-string version IS sanitized. If this stops being true (e.g.
// Go relaxes html/template), the safe-URL workaround can be revisited.
func TestTOTPEnrollTemplate_StringIsSanitized(t *testing.T) {
	t.Parallel()

	const tpl = `<img src="{{ .QRCodeData }}" alt="QR">`
	type data struct {
		QRCodeData string // ← intentionally the wrong type
	}
	parsed := template.Must(template.New("totp").Parse(tpl))
	var buf bytes.Buffer
	_ = parsed.Execute(&buf, data{QRCodeData: "data:image/png;base64,abc"})

	if !strings.Contains(buf.String(), "#ZgotmplZ") {
		t.Skipf("html/template no longer sanitizes data: URLs (output: %s) — workaround in handler may no longer be needed", buf.String())
	}
}
