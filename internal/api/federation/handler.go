package federation

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authfed "github.com/lusopoint/lusoiam/internal/auth/federation"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/federation"
)

const (
	stateCookieName = "iam_oauth_state"
	stateCookieTTL  = 10 * time.Minute
)

// OAuth2 / OIDC redirect flow
type Handler struct {
	registry *federation.Registry
	fedSvc   *authfed.Service
	sessions *session.Service
	casSvc   *authcas.Service
	mfa      *authmfa.Service // optional, if nil, MFA enforcement is skipped
	signer   *crypto.CookieSigner
	audit    *audit.Service // optional, nil disables audit logging
	secure   bool           // whether to set Secure flag on the state cookie
}

// config bundles the constructor dependencies
type Config struct {
	Registry *federation.Registry
	FedSvc   *authfed.Service
	Sessions *session.Service
	CASSvc   *authcas.Service
	MFA      *authmfa.Service // optional, if nil, MFA enforcement is skipped
	Signer   *crypto.CookieSigner
	Audit    *audit.Service
	Secure   bool
}

func New(cfg Config) *Handler {
	return &Handler{
		registry: cfg.Registry,
		fedSvc:   cfg.FedSvc,
		sessions: cfg.Sessions,
		casSvc:   cfg.CASSvc,
		mfa:      cfg.MFA,
		signer:   cfg.Signer,
		audit:    cfg.Audit,
		secure:   cfg.Secure,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /oauth/authorize/{provider}", h.authorize)
	mux.HandleFunc("GET /oauth/callback/{provider}", h.callback)
}

// oauthState is the data we round-trip through the state cookie
type oauthState struct {
	State    string `json:"s"`   // random nonce for CSRF protection
	Verifier string `json:"v"`   // PKCE code_verifier
	Service  string `json:"svc"` // original CAS service URL (may be empty)
	Provider string `json:"p"`   // provider slug (redundant safety check)
	Expires  int64  `json:"exp"` // unix timestamp
}

// authorize handles GET /oauth/authorize/{provider}
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider, ok := h.registry.Get(providerName)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	serviceURL := r.URL.Query().Get("service")

	// generate PKCE pair
	verifier, challenge, err := crypto.NewPKCE()
	if err != nil {
		slog.Error("federation: generate pkce", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// generate random state nonce
	stateNonce, err := crypto.RandomToken(16)
	if err != nil {
		slog.Error("federation: generate state", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// persist state in a short-lived signed cookie
	st := oauthState{
		State:    stateNonce,
		Verifier: verifier,
		Service:  serviceURL,
		Provider: providerName,
		Expires:  time.Now().Add(stateCookieTTL).Unix(),
	}
	if err := h.writeStateCookie(w, st); err != nil {
		slog.Error("federation: write state cookie", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, provider.AuthURL(stateNonce, challenge), http.StatusFound)
}

// callback handles GET /oauth/callback/{provider}
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	provider, ok := h.registry.Get(providerName)
	if !ok {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}

	// validate state
	st, err := h.readStateCookie(r)
	if err != nil || st.Provider != providerName {
		slog.Warn("federation: invalid state cookie",
			"provider", providerName, "err", err)
		h.callbackError(w, r, "Login session expired or invalid. Please try again.")
		return
	}
	h.clearStateCookie(w)

	if time.Now().Unix() > st.Expires {
		h.callbackError(w, r, "Authorization request expired. Please sign in again.")
		return
	}

	if r.URL.Query().Get("state") != st.State {
		slog.Warn("federation: state mismatch", "provider", providerName)
		h.callbackError(w, r, "Invalid state parameter. Please sign in again.")
		return
	}

	// check for provider error
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		slog.Info("federation: provider returned error",
			"provider", providerName, "error", errParam, "desc", desc)
		h.callbackError(w, r, "Sign-in was cancelled or denied by the provider.")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.callbackError(w, r, "No authorization code received from provider.")
		return
	}

	// exchange code for identity
	identity, err := provider.Exchange(r.Context(), code, st.Verifier)
	if err != nil {
		slog.Error("federation: exchange code", "provider", providerName, "err", err)
		h.callbackError(w, r, "Could not complete sign-in with provider. Please try again.")
		return
	}

	// link or create IAM user
	user, isNewLink, err := h.fedSvc.LinkOrCreate(r.Context(), providerName, identity)
	if err != nil {
		slog.Error("federation: link or create", "provider", providerName, "err", err)
		h.callbackError(w, r, "Could not resolve your account. Please contact support.")
		return
	}

	if user.Status != "active" {
		h.callbackError(w, r, "Your account has been disabled. Contact your administrator.")
		return
	}

	if h.audit != nil && isNewLink {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventUpstreamLinked,
			Actor:    &user.ID,
			Metadata: map[string]any{"provider": providerName, "sub": identity.Sub},
		}))
	}

	// MFA gate
	if h.mfa != nil {
		status, err := h.mfa.StatusForUser(r.Context(), user.ID)
		if err != nil {
			slog.Error("federation: load mfa status", "err", err)
			h.callbackError(w, r, "Could not verify your security settings. Please try again.")
			return
		}
		if status.Required {
			ch := authmfa.Challenge{
				UserID:    uuidToString(user.ID),
				Service:   st.Service,
				Methods:   status.MethodTypes,
				HasBackup: status.HasBackupCodes,
			}
			if err := authmfa.IssueChallenge(w, h.signer, h.secure, ch); err != nil {
				slog.Error("federation: issue mfa challenge", "err", err)
				h.callbackError(w, r, "Could not start two-factor verification.")
				return
			}
			http.Redirect(w, r, "/mfa", http.StatusFound)
			return
		}
	}

	// create session
	sess, err := h.sessions.Create(r.Context(), w, r, session.CreateParams{
		UserID: user.ID,
		ACR:    "0",
		AMR:    []string{"fed", providerName},
	})
	if err != nil {
		slog.Error("federation: create session", "err", err)
		h.callbackError(w, r, "Could not create a login session. Please try again.")
		return
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventLoginSuccess,
			Actor:    &user.ID,
			Metadata: map[string]any{"method": "federation", "provider": providerName, "mfa": false},
		}))
	}

	// issue CAS ticket if service was set
	destination := "/"
	if st.Service != "" {
		if _, regErr := h.casSvc.ResolveService(r.Context(), st.Service); regErr == nil {
			ticket, ticketErr := h.casSvc.IssueServiceTicket(
				r.Context(), sess.ID, st.Service, false)
			if ticketErr != nil {
				slog.Error("federation: issue service ticket", "err", ticketErr)
				h.callbackError(w, r, "Could not issue a service ticket. Please try again.")
				return
			}
			destination = appendTicket(st.Service, ticket)
		} else if !errors.Is(regErr, authcas.ErrUnauthorizedService) {
			slog.Error("federation: resolve service", "err", regErr)
		}
	}

	http.Redirect(w, r, destination, http.StatusFound)
}

func (h *Handler) writeStateCookie(w http.ResponseWriter, st oauthState) error {
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    h.signer.Sign(string(payload)),
		Path:     "/",
		MaxAge:   int(stateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode, // must be Lax so provider redirects send the cookie
	})
	return nil
}

func (h *Handler) readStateCookie(r *http.Request) (oauthState, error) {
	c, err := r.Cookie(stateCookieName)
	if err != nil {
		return oauthState{}, err
	}
	payload, err := h.signer.Verify(c.Value)
	if err != nil {
		return oauthState{}, err
	}
	var st oauthState
	if err := json.Unmarshal([]byte(payload), &st); err != nil {
		return oauthState{}, err
	}
	return st, nil
}

func (h *Handler) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) callbackError(w http.ResponseWriter, r *http.Request, msg string) {
	// best effort, don't expose internal details
	http.Redirect(w, r, "/cas/login?error="+encodeMsg(msg), http.StatusFound)
}

func encodeMsg(msg string) string {
	return (&url.URL{RawQuery: "e=" + msg}).Query().Get("e")
}

func appendTicket(serviceURL, ticket string) string {
	sep := "?"
	for _, ch := range serviceURL {
		if ch == '?' {
			sep = "&"
			break
		}
	}
	return serviceURL + sep + "ticket=" + ticket
}

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
