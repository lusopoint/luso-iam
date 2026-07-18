package cas

import "testing"

func TestRenderedTemplateNamesResolve(t *testing.T) {
	for _, name := range []string{"login.html", "error.html"} {
		if _, ok := templates[name]; !ok {
			t.Errorf("handler renders %q but no such template was parsed", name)
		}
	}
}
