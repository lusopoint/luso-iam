package cas

import (
	"embed"
	"net/http"

	"github.com/lusopoint/lusoiam/internal/api/web"
)

//go:embed templates/*.html
var templatesFS embed.FS

// templates holds one parsed set per page, each combining the shared base
// layout (internal/api/web) with that page's content block. Parsed at init so a
// malformed template fails at startup rather than on a user's sign-in attempt
var templates = web.MustPages(templatesFS, "templates/*.html")

// loginPageData drives the login.html template
type loginPageData struct {
	CSRFToken     string // double-submit cookie value; rendered into a hidden field
	Email         string
	Service       string
	Next          string // post-login destination for first-party redirects (no CAS ticket)
	Redirect      string // post-login cross-origin destination (proxy companion); pre-validated against allowlist
	Renew         bool
	Gateway       bool
	Error         string
	Providers     []providerInfo // enabled upstream SSO providers
	SignupEnabled bool           // when true, render a "Create account" link
}

// providerInfo is passed to the login template for each upstream provider
type providerInfo struct {
	Slug  string // "google", "github"
	Label string // "Continue with Google"
	Icon  string // inline SVG path data
}

// errorPageData drives the error.html template
type errorPageData struct {
	Title   string
	Message string
	Detail  string
}

func renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	web.Render(w, templates, "login.html", status, data)
}

func renderError(w http.ResponseWriter, status int, data errorPageData) {
	web.Render(w, templates, "error.html", status, data)
}
