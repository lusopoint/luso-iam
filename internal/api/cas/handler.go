// Package cas implements the HTTP layer for CAS 2.0 and 3.0 endpoints.
package cas

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/password"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
)

type Handler struct {
	password *password.Service
	sessions *session.Service
	cas      *authcas.Service
	// upstream SSO providers; may be empty
	registry *federation.Registry

	// nil disables the MFA gate
	mfa *authmfa.Service

	// signs the pending-MFA cookie
	signer *crypto.CookieSigner

	// mirrors session cookie Secure flag
	cookieSecure bool

	// optional — nil disables audit logging
	audit *audit.Service

	// proxyOrigins is the set of accepted cross-origin redirect targets
	// for the `rd=` parameter (used by the reverse-proxy companion).
	// Map for O(1) lookup; keys are scheme://host[:port] lowercased.
	proxyOrigins map[string]struct{}

	// providerLabels overrides the default "Continue with <slug>" button
	// text for specific slugs. Populated from the OIDC providers' optional
	// DISPLAY_NAME env var; built-in providers (google, github) use the
	// fixed labels in defaultProviderLabels.
	providerLabels map[string]string
}

// Config is the constructor argument bundle.
type Config struct {
	Password *password.Service
	Sessions *session.Service
	CAS      *authcas.Service
	// pass an empty registry if no providers configured
	Registry *federation.Registry
	// optional — if nil, MFA enforcement is skipped
	MFA *authmfa.Service
	// required when MFA is set
	Signer       *crypto.CookieSigner
	CookieSecure bool
	// optional, events are silently dropped when nil
	Audit *audit.Service
	// ProxyCallbackOrigins enumerates the cross-origin URLs that may
	// appear in the `rd=` query parameter on /cas/login. The proxy
	// companion (/proxy/verify) uses the same allowlist; both lists
	// are sourced from cfg.Proxy.AllowedCallbackOrigins so they can't
	// drift. Empty list = `rd=` is silently ignored.
	ProxyCallbackOrigins []string
	// ProviderLabels overrides the default button text for specific
	// provider slugs. The map key is the slug ("google", "okta", etc.);
	// the value is the button label ("Continue with Google"). Slugs not
	// in this map fall through to a sensible auto-generated label.
	ProviderLabels map[string]string
}

func New(cfg Config) *Handler {
	origins := make(map[string]struct{}, len(cfg.ProxyCallbackOrigins))
	for _, o := range cfg.ProxyCallbackOrigins {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o != "" {
			origins[strings.ToLower(o)] = struct{}{}
		}
	}
	return &Handler{
		password:       cfg.Password,
		sessions:       cfg.Sessions,
		cas:            cfg.CAS,
		registry:       cfg.Registry,
		mfa:            cfg.MFA,
		signer:         cfg.Signer,
		cookieSecure:   cfg.CookieSecure,
		audit:          cfg.Audit,
		proxyOrigins:   origins,
		providerLabels: cfg.ProviderLabels,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /cas/login", h.loginGET)
	mux.HandleFunc("POST /cas/login", h.loginPOST)
	mux.HandleFunc("GET /cas/logout", h.logout)

	// CAS 1.0 plain text response
	mux.HandleFunc("GET /cas/validate", h.v1Validate)

	// CAS 2.0 XML without attributes
	mux.HandleFunc("GET /cas/serviceValidate", h.serviceValidate(false))
	mux.HandleFunc("GET /cas/proxyValidate", h.serviceValidate(false))

	// CAS 3.0 XML with attribute release and JSON
	mux.HandleFunc("GET /cas/p3/serviceValidate", h.serviceValidate(true))
	mux.HandleFunc("GET /cas/p3/proxyValidate", h.serviceValidate(true))
}

// providerLabels maps provider slugs to their display labels
var defaultProviderLabels = map[string]string{
	"google": "Continue with Google",
	"github": "Continue with GitHub",
}

// providers returns the providerInfo list for the login template
// built from the federation registry
func (h *Handler) providers() []providerInfo {
	if h.registry == nil || h.registry.Empty() {
		return nil
	}
	infos := make([]providerInfo, 0, len(h.registry.All()))
	for _, p := range h.registry.All() {
		slug := p.Name()
		label := h.providerLabels[slug]
		if label == "" {
			label = defaultProviderLabels[slug]
		}
		if label == "" {
			label = "Continue with " + titleCaseSlug(slug)
		}
		infos = append(infos, providerInfo{
			Slug:  slug,
			Label: label,
		})
	}
	return infos
}

// titleCaseSlug turns "mycorp_okta" into "Mycorp Okta". Reserved for
// the no-label-configured case; nothing fancy because the operator
// always has the DISPLAY_NAME escape hatch if this doesn't look right.
func titleCaseSlug(slug string) string {
	parts := strings.Split(slug, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

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
