package oidc

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// authorize handles GET /oauth2/authorize.
//
// Flow:
//  1. Parse + validate the authorization request parameters.
//  2. Check for an existing IAM session.
//     - No session → redirect to login with ?next= pointing back here.
//     - prompt=none + no session → return login_required to client.
//  3. Session found + no consent required → issue code immediately.
//  4. Session found + consent required → show consent screen.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := oidcsvc.AuthRequest{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		ResponseType:  q.Get("response_type"),
		Scopes:        strings.Fields(q.Get("scope")),
		State:         q.Get("state"),
		Nonce:         q.Get("nonce"),
		PKCEChallenge: q.Get("code_challenge"),
		PKCEMethod:    q.Get("code_challenge_method"),
		Prompt:        q.Get("prompt"),
	}

	// Validate before touching the session — redirect_uri must be registered
	// before we can redirect errors there.
	client, err := h.svc.ValidateAuthRequest(r.Context(), req)
	if err != nil {
		h.authorizeError(w, r, req, err)
		return
	}

	// Check session.
	sess, sessErr := h.sessions.Get(r.Context(), r)

	if sessErr != nil {
		// No valid session.
		if req.Prompt == "none" {
			redirectError(w, r, req.RedirectURI, req.State,
				"login_required", "Authentication required.")
			return
		}
		loginURL := "/cas/login?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// prompt=login forces re-authentication even with a valid session.
	if req.Prompt == "login" {
		loginURL := "/cas/login?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Consent check.
	if client.RequireConsent {
		if req.Prompt == "none" {
			redirectError(w, r, req.RedirectURI, req.State,
				"consent_required", "User consent required.")
			return
		}
		renderConsent(w, http.StatusOK, consentData{
			ClientName:  client.Name,
			Scopes:      req.Scopes,
			ClientID:    req.ClientID,
			RedirectURI: req.RedirectURI,
			State:       req.State,
			Nonce:       req.Nonce,
			Challenge:   req.PKCEChallenge,
			Method:      req.PKCEMethod,
			Scope:       strings.Join(req.Scopes, " "),
		})
		return
	}

	// Auto-approve: issue code and redirect.
	h.issueCodeAndRedirect(w, r, req, sess)
}

// authorizeConsent handles POST /oauth2/authorize (consent form submission).
func (h *Handler) authorizeConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req := oidcsvc.AuthRequest{
		ClientID:      r.FormValue("client_id"),
		RedirectURI:   r.FormValue("redirect_uri"),
		ResponseType:  "code",
		Scopes:        strings.Fields(r.FormValue("scope")),
		State:         r.FormValue("state"),
		Nonce:         r.FormValue("nonce"),
		PKCEChallenge: r.FormValue("code_challenge"),
		PKCEMethod:    r.FormValue("code_challenge_method"),
	}

	if r.FormValue("decision") != "allow" {
		redirectError(w, r, req.RedirectURI, req.State,
			"access_denied", "User denied the request.")
		return
	}

	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil {
		redirectError(w, r, req.RedirectURI, req.State,
			"login_required", "Session expired.")
		return
	}

	h.issueCodeAndRedirect(w, r, req, sess)
}

// issueCodeAndRedirect mints an auth code and redirects to redirect_uri.
// The session's ACR and AMR are propagated into the auth code so the
// resulting id_token reflects the authentication context — without this,
// an MFA login would still mint id_tokens with acr=0/amr=[pwd].
func (h *Handler) issueCodeAndRedirect(
	w http.ResponseWriter,
	r *http.Request,
	req oidcsvc.AuthRequest,
	sess *postgres.Session,
) {
	// Default to single-factor if the session pre-dates the MFA migration
	// or was never populated (defensive — should not happen post-P4).
	acr := sess.ACR
	if acr == "" {
		acr = "0"
	}
	amr := sess.AMR
	if len(amr) == 0 {
		amr = []string{"pwd"}
	}

	code, err := h.svc.Authorize(r.Context(), oidcsvc.AuthorizeParams{
		AuthRequest: req,
		UserID:      sess.UserID,
		SessionID:   sess.ID,
		AuthTime:    sess.CreatedAt,
		ACR:         acr,
		AMR:         amr,
	})
	if err != nil {
		slog.Error("oidc: authorize", "err", err)
		redirectError(w, r, req.RedirectURI, req.State,
			"server_error", "Could not issue authorization code.")
		return
	}

	dest := req.RedirectURI + "?code=" + url.QueryEscape(code)
	if req.State != "" {
		dest += "&state=" + url.QueryEscape(req.State)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// authorizeError handles validation errors on the authorization request.
// If redirect_uri is valid, errors are forwarded there.
// If redirect_uri itself is invalid, we show an error page (can't redirect).
func (h *Handler) authorizeError(w http.ResponseWriter, r *http.Request, req oidcsvc.AuthRequest, err error) {
	code := "invalid_request"
	desc := err.Error()
	switch {
	case errors.Is(err, oidcsvc.ErrInvalidClient):
		code = "unauthorized_client"
		desc = "Unknown or disabled client."
	case errors.Is(err, oidcsvc.ErrInvalidRedirectURI):
		// Cannot redirect — show a page.
		http.Error(w, "Invalid redirect_uri: not registered for this client.", http.StatusBadRequest)
		return
	case errors.Is(err, oidcsvc.ErrPKCERequired):
		code = "invalid_request"
		desc = "PKCE (S256) is required for this client."
	case errors.Is(err, oidcsvc.ErrInvalidScope):
		code = "invalid_scope"
		desc = "One or more requested scopes are not allowed."
	}
	redirectError(w, r, req.RedirectURI, req.State, code, desc)
}

// redirectError sends the OAuth2 error to the client's redirect_uri.
// If redirect_uri is empty, falls back to a JSON error response.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	if redirectURI == "" {
		oauthError(w, http.StatusBadRequest, code, desc)
		return
	}
	dest := redirectURI + "?error=" + url.QueryEscape(code) +
		"&error_description=" + url.QueryEscape(desc)
	if state != "" {
		dest += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
