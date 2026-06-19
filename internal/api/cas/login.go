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
	"github.com/lusopoint/lusoiam/internal/middleware"
)

// loginGET handles GET /cas/login
func (h *Handler) loginGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	serviceURL := q.Get("service")
	nextURL := safeNext(q.Get("next"))
	redirectURL := h.safeRedirect(q.Get("rd"))
	renew := q.Get("renew") == "true"
	gateway := q.Get("gateway") == "true"

	// check for an existing session
	if !renew {
		sess, err := h.sessions.Get(r.Context(), r)
		if err == nil {
			// already authenticated, cases in priority order:
			//   1. service=<URL>  -> CAS ticket flow (downstream app login)
			//   2. next=<path>    -> first-party redirect (admin UI, ...)
			//   3. rd=<URL>       -> cross-origin redirect (proxy companion)
			//   4. nothing        -> fall back to /
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

	// gateway mode: redirect to service without authenticating
	if gateway && serviceURL != "" {
		http.Redirect(w, r, serviceURL, http.StatusFound)
		return
	}

	// show the login form
	renderLogin(w, http.StatusOK, loginPageData{
		CSRFToken:     middleware.CSRFTokenFromContext(r.Context()),
		Service:       serviceURL,
		Next:          nextURL,
		Redirect:      redirectURL,
		Renew:         renew,
		Gateway:       gateway,
		Error:         r.URL.Query().Get("error"), // set by federation callback on failure
		Providers:     h.providers(),
		SignupEnabled: h.signupEnabled,
	})
}

// loginPOST handles POST /cas/login (form submission)
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
		// audit the failed attempt. Actor is unknown (we never confirmed
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
			CSRFToken:     middleware.CSRFTokenFromContext(r.Context()),
			Email:         email,
			Service:       serviceURL,
			Next:          nextURL,
			Redirect:      redirectURL,
			Renew:         renew,
			Error:         msg,
			SignupEnabled: h.signupEnabled,
		})
		return
	}

	// verify the service before creating a session
	// we check early so we don't create a session that leads nowhere
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

	// mfa gate
	// if the user has any confirmed second factors, we don't create a
	// session yet, we issue a pending MFA cookie and redirect to /mfa
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
		if status.Required && !status.EnrollmentRequired {
			ch := authmfa.Challenge{
				UserID:    uuidToString(user.ID),
				Service:   serviceURL,
				NextURL:   nextURL,
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

	// create session (single-factor: password only)
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

	// force mfa, if the server requires MFA globally but this user
	// has no enrolled methods, send them to enrollment
	if h.mfa != nil {
		if status, err := h.mfa.StatusForUser(r.Context(), user.ID); err == nil && status.EnrollmentRequired {
			http.Redirect(w, r, "/mfa/enroll?required=1", http.StatusFound)
			return
		}
	}

	// issue service ticket and redirect
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

	// first-party redirect (example admin SPA)
	if nextURL != "" {
		http.Redirect(w, r, nextURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func safeNext(s string) string {
	if s == "" {
		return ""
	}
	// must start with "/" but NOT "//" (which is protocol-relative)
	if len(s) < 1 || s[0] != '/' {
		return ""
	}
	if len(s) >= 2 && s[1] == '/' {
		return ""
	}
	// reject \, which some user-agents treat as / on Windows paths
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\\' {
			return ""
		}
	}
	return s
}
