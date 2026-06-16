package email

import (
	"strings"
	"testing"
)

// TestMessageValidate_Required ensures the basic invariants hold:
// To, Subject, and at least one body part are required. Each missing
// field is a separate failure path; pin them all so a future caller
// can't accidentally skip Subject without finding out at runtime.
func TestMessageValidate_Required(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		msg     Message
		wantErr string
	}{
		{"missing_to", Message{Subject: "s", Text: "t"}, "To"},
		{"missing_subject", Message{To: "a@b", Text: "t"}, "Subject"},
		{"missing_body", Message{To: "a@b", Subject: "s"}, "Text"},
		{"text_only_ok", Message{To: "a@b", Subject: "s", Text: "t"}, ""},
		{"html_only_ok", Message{To: "a@b", Subject: "s", HTML: "<p>"}, ""},
		{"both_ok", Message{To: "a@b", Subject: "s", Text: "t", HTML: "<p>"}, ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := c.msg.Validate()
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case c.wantErr != "" && err == nil:
				t.Errorf("expected error mentioning %q, got nil", c.wantErr)
			case c.wantErr != "" && err != nil && !strings.Contains(err.Error(), c.wantErr):
				t.Errorf("error %q doesn't mention %q", err, c.wantErr)
			}
		})
	}
}
