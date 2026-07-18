package passwordreset

import "testing"

// guard against the bug that shipped
func TestRenderedTemplateNamesResolve(t *testing.T) {
	for _, name := range []string{"forgot.html", "reset.html", "reset_invalid.html"} {
		if _, ok := templates[name]; !ok {
			t.Errorf("handler renders %q but no such template was parsed", name)
		}
	}
}
