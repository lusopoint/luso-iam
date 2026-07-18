package mfa

import "testing"

// guard against the bug that shipped
func TestRenderedTemplateNamesResolve(t *testing.T) {
	for _, name := range []string{"challenge.html", "backup.html", "backup_codes.html", "enroll.html", "totp_enroll.html"} {
		if _, ok := templates[name]; !ok {
			t.Errorf("handler renders %q but no such template was parsed", name)
		}
	}
}
