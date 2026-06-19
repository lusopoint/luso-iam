package oidc

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/consent.html
var oidcTemplatesFS embed.FS
var oidcTemplates = template.Must(
	template.ParseFS(oidcTemplatesFS, "templates/consent.html"),
)

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = oidcTemplates.ExecuteTemplate(w, "consent.html", data)
}
