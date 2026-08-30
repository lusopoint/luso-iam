package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// A page as the real ones are written: it overrides the base layout's default
// "title" and "content" blocks and leaves "scripts" alone.
var fixture = fstest.MapFS{
	"templates/hello.html": &fstest.MapFile{Data: []byte(
		`{{define "title"}}Hello - IAM{{end}}
		 {{define "content"}}<main class="card"><h1>{{ .Greeting }}</h1></main>{{end}}`,
	)},
	"templates/other.html": &fstest.MapFile{Data: []byte(
		`{{define "content"}}<main class="card">other</main>{{end}}`,
	)},
}

func TestRenderWrapsPageInBaseLayout(t *testing.T) {
	pages := MustPages(fixture, "templates/*.html")

	rec := httptest.NewRecorder()
	// base.html's inline dark-mode script has a nonce="{{.CSPNonce}}"
	// attribute, so every page's data struct must carry that field -
	// same contract every real caller under internal/api/* follows.
	Render(rec, pages, "hello.html", http.StatusOK, struct {
		Greeting string
		CSPNonce string
	}{"Sign in", "test-nonce"})

	body := rec.Body.String()

	for _, want := range []string{
		"<!doctype html>",
		`href="/static/tokens.css"`,  // shared design tokens
		`href="/static/auth.css"`,    // shared stylesheet
		"<title>Hello - IAM</title>", // page overrode the default title
		"Sign in",                    // page content, with its data
		`nonce="test-nonce"`,         // base layout's inline script carries the caller's CSPNonce
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("auth pages must not be cached")
	}
}

// Each page gets its own template set. If they shared one, the "content" block
// of whichever page parsed last would win and every page would render the same
// body, a subtle and very confusing failure.
func TestPagesDoNotShareContentBlocks(t *testing.T) {
	pages := MustPages(fixture, "templates/*.html")

	rec := httptest.NewRecorder()
	Render(rec, pages, "other.html", http.StatusOK, nil)

	if body := rec.Body.String(); !strings.Contains(body, "other") {
		t.Errorf("other.html rendered the wrong content block:\n%s", body)
	}
}

// A page that doesn't override "title" falls back to the layout's default
// rather than failing to parse.
func TestDefaultTitle(t *testing.T) {
	pages := MustPages(fixture, "templates/*.html")

	rec := httptest.NewRecorder()
	Render(rec, pages, "other.html", http.StatusOK, nil)

	if !strings.Contains(rec.Body.String(), "<title>IAM</title>") {
		t.Error("expected the base layout's default title")
	}
}

// The old code did `_ = tmpl.ExecuteTemplate(w, name, data)`, so a name that
// didn't resolve produced a 200 with an empty body. Two real pages shipped that
// way. Now it is at least a loud 500.
func TestUnknownPageIsNotSilentlyBlank(t *testing.T) {
	pages := MustPages(fixture, "templates/*.html")

	rec := httptest.NewRecorder()
	Render(rec, pages, "does_not_exist.html", http.StatusOK, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("unknown template: got %d, want 500 (a blank 200 is the bug)", rec.Code)
	}
}
