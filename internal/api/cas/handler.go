// Package cas implements the HTTP layer for CAS 2.0 and 3.0 endpoints.
package cas

import (
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/password"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
)

// Handler holds the dependencies for all CAS HTTP endpoints.
type Handler struct {
	password     *password.Service
	sessions     *session.Service
	cas          *authcas.Service
	registry     *federation.Registry // upstream SSO providers; may be empty
	mfa          *authmfa.Service     // nil disables the MFA gate
	signer       *crypto.CookieSigner // signs the pending-MFA cookie
	cookieSecure bool                 // mirrors session cookie Secure flag
	audit        *audit.Service       // optional — nil disables audit logging
}

// Config is the constructor argument bundle.
type Config struct {
	Password     *password.Service
	Sessions     *session.Service
	CAS          *authcas.Service
	Registry     *federation.Registry // pass an empty registry if no providers configured
	MFA          *authmfa.Service     // optional — if nil, MFA enforcement is skipped
	Signer       *crypto.CookieSigner // required when MFA is set
	CookieSecure bool
	Audit        *audit.Service // optional — events are silently dropped when nil
}

// New constructs a Handler.
func New(cfg Config) *Handler {
	return &Handler{
		password:     cfg.Password,
		sessions:     cfg.Sessions,
		cas:          cfg.CAS,
		registry:     cfg.Registry,
		mfa:          cfg.MFA,
		signer:       cfg.Signer,
		cookieSecure: cfg.CookieSecure,
		audit:        cfg.Audit,
	}
}

// Register attaches all CAS routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /cas/login", h.loginGET)
	mux.HandleFunc("POST /cas/login", h.loginPOST)
	mux.HandleFunc("GET /cas/logout", h.logout)

	// CAS 1.0 — plain text response
	mux.HandleFunc("GET /cas/validate", h.v1Validate)

	// CAS 2.0 — XML without attributes
	mux.HandleFunc("GET /cas/serviceValidate", h.serviceValidate(false))
	mux.HandleFunc("GET /cas/proxyValidate", h.serviceValidate(false))

	// CAS 3.0 — XML with attribute release
	mux.HandleFunc("GET /cas/p3/serviceValidate", h.serviceValidate(true))
	mux.HandleFunc("GET /cas/p3/proxyValidate", h.serviceValidate(true))
}

// provider list helper

// providerLabels maps provider slugs to their display labels.
var providerLabels = map[string]string{
	"google": "Continue with Google",
	"github": "Continue with GitHub",
}

// providers returns the providerInfo list for the login template,
// built from the federation registry.
func (h *Handler) providers() []providerInfo {
	if h.registry == nil || h.registry.Empty() {
		return nil
	}
	infos := make([]providerInfo, 0, len(h.registry.All()))
	for _, p := range h.registry.All() {
		label, ok := providerLabels[p.Name()]
		if !ok {
			label = "Continue with " + p.Name()
		}
		infos = append(infos, providerInfo{
			Slug:  p.Name(),
			Label: label,
		})
	}
	return infos
}

// URL helpers

func appendTicket(serviceURL, ticket string) string {
	u, err := url.Parse(serviceURL)
	if err != nil {
		sep := "?"
		if len(serviceURL) > 0 && serviceURL[len(serviceURL)-1] == '?' {
			sep = ""
		}
		return serviceURL + sep + "ticket=" + url.QueryEscape(ticket)
	}
	q := u.Query()
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()
	return u.String()
}

// uuidToString renders a pgtype.UUID in canonical 8-4-4-4-12 hex form.
// Local to this package because pulling pgtype's String() requires Valid
// to be true and we want a deterministic format for cookie payloads.
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	const hx = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, b := range u.Bytes {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hx[b>>4]
		out[pos+1] = hx[b&0x0f]
		pos += 2
	}
	return string(out)
}
