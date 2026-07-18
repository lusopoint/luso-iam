package oidc

import (
	"embed"
	"net/http"

	"github.com/lusopoint/lusoiam/internal/api/web"
)

//go:embed templates/consent.html
var oidcTemplatesFS embed.FS

// combined with the shared base layout from internal/api/web
var oidcTemplates = web.MustPages(oidcTemplatesFS, "templates/*.html")

// consentData is the template data for the consent screen
// all form values are round-tripped as hidden inputs so the POST handler
// has everything it needs without a server-side session lookup
type consentData struct {
	CSRFToken   string
	ClientName  string
	Scopes      []string
	ClientID    string
	RedirectURI string
	State       string
	Nonce       string
	Scope       string // space-joined scopes for the hidden input
	Challenge   string // PKCE code_challenge
	Method      string // PKCE code_challenge_method
}

func renderConsent(w http.ResponseWriter, status int, data consentData) {
	web.Render(w, oidcTemplates, "consent.html", status, data)
}
