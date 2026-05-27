package cas

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

// templates is the parsed template set. Parsed once at init() so we
// fail fast at startup if a template is malformed.
var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// loginPageData drives the login.html template.
type loginPageData struct {
	Email     string
	Service   string
	Next      string // post-login destination for first-party redirects (no CAS ticket)
	Redirect  string // post-login cross-origin destination (proxy companion); pre-validated against allowlist
	Renew     bool
	Gateway   bool
	Error     string
	Providers []providerInfo // enabled upstream SSO providers
}

// providerInfo is passed to the login template for each upstream provider.
type providerInfo struct {
	Slug  string // "google", "github"
	Label string // "Continue with Google"
	Icon  string // inline SVG path data
}

// errorPageData drives the error.html template.
type errorPageData struct {
	Title   string
	Message string
	Detail  string
}

func renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		// Headers are already sent; nothing useful to do with the error.
		// AccessLog middleware captures status.
		return
	}
}

func renderError(w http.ResponseWriter, status int, data errorPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = templates.ExecuteTemplate(w, "error.html", data)
}
