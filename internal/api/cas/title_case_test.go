package cas

import "testing"

// TestTitleCaseSlug pins the fallback label rendering for generic OIDC
// providers that don't have an operator-supplied DISPLAY_NAME. The
// fallback path matters because raw slugs like "mycorp_okta" look bad
// on a login button.
func TestTitleCaseSlug(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"okta", "Okta"},
		{"microsoft", "Microsoft"},
		{"mycorp_okta", "Mycorp Okta"},
		{"corp_dev_okta", "Corp Dev Okta"},
		{"a", "A"},
		{"", ""},
		// We don't normalize beyond underscores; if someone slips through
		// with mixed case, leave it alone rather than guessing.
		{"alreadyTitled", "AlreadyTitled"},
		// Trailing or repeated underscores produce empty segments
		// we pass those through, which results in extra spaces. That's
		// acceptable because Validate() ensures slugs don't contain
		// these shapes in the first place.
		{"foo__bar", "Foo  Bar"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			got := titleCaseSlug(c.in)
			if got != c.want {
				t.Errorf("titleCaseSlug(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
