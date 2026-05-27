package cas

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/password"
	"github.com/lusopoint/lusoiam/internal/auth/session"
)

// GET /cas/login
// CAS spec behaviour:
//
//   - renew=true -> force fresh authentication even if a valid session exists
//   - gateway=true -> silently check session, redirect to service without
//     a ticket if unauthenticated (never show the login form)
//   - Unregistered service -> 403 error page (never issue a ticket)
//   - No service param and authenticated -> redirect to / (portal stub)
func (h *Handler) loginGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	serviceURL := q.Get("service")
	nextURL := safeNext(q.Get("next"))
	// rd is the cross-origin redirect used by the reverse-proxy
	// Unlike `next`, it can reference a different host
	// but only origins on the configured "allowlist" are accepted
	redirectURL := h.safeRedirect(q.Get("rd"))
	renew := q.Get("renew") == "true"
	gateway := q.Get("gateway") == "true"

	// Check for an existing session
	if !renew {
		sess, err := h.sessions.Get(r.Context(), r)
		if err == nil {
			// Already authenticated, cases in priority order:
			//   1. service=<URL>  -> CAS ticket flow (downstream app login)
			//   2. next=<path>    -> first-party redirect (admin UI, ...)
			//   3. rd=<URL>       -> cross-origin redirect (proxy companion)
			//   4. nothing        -> fall back to "/"
			if serviceURL != "" {
				if _, regErr := h.cas.ResolveService(r.Context(), serviceURL); regErr != nil {
					renderError(w, http.StatusForbidden, errorPageData{
						Title:   "Service not authorized",
						Message: "This application is not registered with the IAM server.",
						Detail:  serviceURL,
					})
					return
				}
				ticket, err := h.cas.IssueServiceTicket(r.Context(), sess.ID, serviceURL, false)
				if err != nil {
					renderError(w, http.StatusInternalServerError, errorPageData{
						Title:   "Login error",
						Message: "Could not create a service ticket. Please try again.",
					})
					return
				}
				http.Redirect(w, r, appendTicket(serviceURL, ticket), http.StatusFound)
				return
			}
			if nextURL != "" {
				http.Redirect(w, r, nextURL, http.StatusFound)
				return
			}
			if redirectURL != "" {
				http.Redirect(w, r, redirectURL, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// No valid session
	// Gateway mode, redirect to service without authenticating
	if gateway && serviceURL != "" {
		http.Redirect(w, r, serviceURL, http.StatusFound)
		return
	}

	// Show the login form
	renderLogin(w, http.StatusOK, loginPageData{
		Service:  serviceURL,
		Next:     nextURL,
		Redirect: redirectURL,
		Renew:    renew,
		Gateway:  gateway,
		// set by federation callback on failure
		Error:     r.URL.Query().Get("error"),
		Providers: h.providers(),
	})
}

// POST /cas/login (form submission)
// It authenticates the submitted credentials, creates a session, and
// either redirects to the service with a ticket or sends the user to "/"
func (h *Handler) loginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, errorPageData{
			Title:   "Bad request",
			Message: "Could not parse form data.",
		})
		return
	}

	email := r.FormValue("email")
	pwd := r.FormValue("password")
	serviceURL := r.FormValue("service")
	nextURL := safeNext(r.FormValue("next"))
	redirectURL := h.safeRedirect(r.FormValue("rd"))
	renew := r.FormValue("renew") == "true"

	// Authenticate
	user, err := h.password.Authenticate(r.Context(), email, pwd)
	if err != nil {
		msg := "Invalid email or password. Please try again."
		switch {
		case errors.Is(err, password.ErrUserDisabled):
			msg = "Your account has been disabled. Contact your administrator."
		case errors.Is(err, password.ErrAccountLocked):
			msg = "Account temporarily locked due to too many failed attempts. Try again later."
		}
		// Audit the failed attempt. Actor is unknown (we never confirmed
		// who the user was) so leave it nil; record the submitted email
		// in metadata for forensic review
		if h.audit != nil {
			reason := "invalid_credentials"
			switch {
			case errors.Is(err, password.ErrUserDisabled):
				reason = "user_disabled"
			case errors.Is(err, password.ErrAccountLocked):
				reason = "account_locked"
			}
			h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
				Type:     audit.EventLoginFailure,
				Metadata: map[string]any{"email": email, "reason": reason},
			}))
		}
		renderLogin(w, http.StatusUnauthorized, loginPageData{
			Email:    email,
			Service:  serviceURL,
			Next:     nextURL,
			Redirect: redirectURL,
			Renew:    renew,
			Error:    msg,
		})
		return
	}

	// Verify the service before creating a session
	// We check early so we don't create a session that leads nowhere
	if serviceURL != "" {
		if _, err := h.cas.ResolveService(r.Context(), serviceURL); err != nil {
			if errors.Is(err, authcas.ErrUnauthorizedService) {
				renderError(w, http.StatusForbidden, errorPageData{
					Title:   "Service not authorized",
					Message: "This application is not registered with the IAM server.",
					Detail:  serviceURL,
				})
				return
			}
			renderError(w, http.StatusInternalServerError, errorPageData{
				Title:   "Login error",
				Message: "Could not verify the requesting service.",
			})
			return
		}
	}

	// MFA gate
	// If the user has any confirmed second factors, we don't create a
	// session yet — we issue a pending-MFA cookie and redirect to /mfa
	// The MFA handler creates the real session once verification succeeds
	if h.mfa != nil {
		status, err := h.mfa.StatusForUser(r.Context(), user.ID)
		if err != nil {
			slog.Error("cas: load mfa status", "err", err)
			renderError(w, http.StatusInternalServerError, errorPageData{
				Title:   "Login error",
				Message: "Could not verify your security settings. Please try again.",
			})
			return
		}
		if status.Required {
			ch := authmfa.Challenge{
				UserID:  uuidToString(user.ID),
				Service: serviceURL,
				NextURL: nextURL,
				// redirectURL is the cross-origin destination from
				// /proxy/verify (Caddy/Traefik forward_auth flow)
				// Pre-validated by h.safeRedirect; carries through MFA so
				// the user lands on the protected app after challenge
				Redirect:  redirectURL,
				Methods:   status.MethodTypes,
				HasBackup: status.HasBackupCodes,
			}
			if err := authmfa.IssueChallenge(w, h.signer, h.cookieSecure, ch); err != nil {
				slog.Error("cas: issue mfa challenge", "err", err)
				renderError(w, http.StatusInternalServerError, errorPageData{
					Title:   "Login error",
					Message: "Could not start two-factor verification.",
				})
				return
			}
			http.Redirect(w, r, "/mfa", http.StatusFound)
			return
		}
	}

	// Create session (single-factor: password only)
	sess, err := h.sessions.Create(r.Context(), w, r, session.CreateParams{
		UserID: user.ID,
		ACR:    "0",
		AMR:    []string{"pwd"},
	})
	if err != nil {
		renderError(w, http.StatusInternalServerError, errorPageData{
			Title:   "Login error",
			Message: "Could not create a login session. Please try again.",
		})
		return
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventLoginSuccess,
			Actor:    &user.ID,
			Metadata: map[string]any{"method": "password", "mfa": false},
		}))
	}

	// Issue service ticket and redirect
	if serviceURL != "" {
		ticket, err := h.cas.IssueServiceTicket(r.Context(), sess.ID, serviceURL, renew)
		if err != nil {
			renderError(w, http.StatusInternalServerError, errorPageData{
				Title:   "Login error",
				Message: "Could not issue a service ticket. Please try again.",
			})
			return
		}
		http.Redirect(w, r, appendTicket(serviceURL, ticket), http.StatusFound)
		return
	}

	// First-party redirect (e.g. admin SPA). next has already been
	// validated by safeNext to be a same-origin path
	if nextURL != "" {
		http.Redirect(w, r, nextURL, http.StatusFound)
		return
	}

	// Neither service nor next — send to the portal root
	http.Redirect(w, r, "/", http.StatusFound)
}

// safeNext sanitises a post-login `next` query parameter
// We only allow same-origin relative paths starting with a single "/", never URLs
// with a scheme, never protocol-relative ("//evil.com"), never values
// containing a CR/LF (header injection). Anything that doesn't fit the
// pattern is silently dropped, the redirect falls back to "/"
//
// This is the standard open-redirect guard. It exists because `next` is
// reflected into a Location header after authentication, which is
// exactly the gadget phishing campaigns look for.
func safeNext(s string) string {
	if s == "" {
		return ""
	}
	// Must start with "/" but NOT "//" (which is protocol-relative)
	if len(s) < 1 || s[0] != '/' {
		return ""
	}
	if len(s) >= 2 && s[1] == '/' {
		return ""
	}
	// Reject \, which some user-agents treat as / on Windows paths
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\\' {
			return ""
		}
	}
	return s
}
