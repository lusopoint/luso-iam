package oidc

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lusopoint/lusoiam/internal/middleware"
	oidcsvc "github.com/lusopoint/lusoiam/internal/oidc"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// authorize handles GET /oauth2/authorize
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

	// validate before touching the session, redirect_uri must be registered
	// before we can redirect errors there
	client, err := h.svc.ValidateAuthRequest(r.Context(), req)
	if err != nil {
		h.authorizeError(w, r, req, err)
		return
	}
	sess, sessErr := h.sessions.Get(r.Context(), r)
	if sessErr != nil {
		// no valid session
		if req.Prompt == "none" {
			redirectError(w, r, req.RedirectURI, req.State,
				"login_required", "Authentication required.")
			return
		}
		loginURL := "/cas/login?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// prompt=login forces re-authentication even with a valid session
	// renew=true makes /cas/login skip its existing-session short-circuit
	// and require a fresh credential entry, creating a new session with a
	// later auth_time (per OIDC Core prompt=login semantics)
	if req.Prompt == "login" && !reauthSatisfied(r, sess) {
		returnTo := *r.URL
		rq := returnTo.Query()
		rq.Set("rauth", strconv.FormatInt(time.Now().Unix(), 10))
		returnTo.RawQuery = rq.Encode()
		loginURL := "/cas/login?renew=true&next=" + url.QueryEscape(returnTo.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// consent check
	if client.RequireConsent {
		if req.Prompt == "none" {
			redirectError(w, r, req.RedirectURI, req.State,
				"consent_required", "User consent required.")
			return
		}
		renderConsent(w, http.StatusOK, consentData{
			CSRFToken:   middleware.CSRFTokenFromContext(r.Context()),
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
	h.issueCodeAndRedirect(w, r, req, sess)
}

// reauthSatisfied reports whether the session was created by a
// re-authentication that this authorize request already demanded
func reauthSatisfied(r *http.Request, sess *postgres.Session) bool {
	raw := r.URL.Query().Get("rauth")
	if raw == "" {
		return false
	}
	demandedAt, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	return sess.CreatedAt.Unix() >= demandedAt
}

// authorizeConsent handles POST /oauth2/authorize (consent form submission)
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

// issueCodeAndRedirect auth code and redirects to redirect_uri
// the session's ACR and AMR are propagated into the auth code so the
// resulting id_token reflects the authentication context
func (h *Handler) issueCodeAndRedirect(
	w http.ResponseWriter,
	r *http.Request,
	req oidcsvc.AuthRequest,
	sess *postgres.Session,
) {
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
		if errors.Is(err, oidcsvc.ErrAccessDenied) {
			redirectError(w, r, req.RedirectURI, req.State,
				"access_denied", "You are not authorized to access this application.")
			return
		}
		slog.Error("oidc: authorize", "err", err)
		redirectError(w, r, req.RedirectURI, req.State,
			"server_error", "Could not issue authorization code.")
		return
	}
	params := map[string]string{"code": code}
	if req.State != "" {
		params["state"] = req.State
	}
	dest, err := appendQuery(req.RedirectURI, params)
	if err != nil {
		// redirect_uri was validated as registered upstream; a parse
		// failure here is unexpected. Fail closed rather than emit a
		// malformed redirect.
		redirectError(w, r, req.RedirectURI, req.State,
			"server_error", "Could not build redirect.")
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// authorizeError handles validation errors on the authorization request
// if redirect_uri is valid, errors are forwarded there
// if redirect_uri itself is invalid, we show an error page (can't redirect)
func (h *Handler) authorizeError(w http.ResponseWriter, r *http.Request, req oidcsvc.AuthRequest, err error) {
	code := "invalid_request"
	desc := err.Error()
	switch {
	case errors.Is(err, oidcsvc.ErrInvalidClient):
		code = "unauthorized_client"
		desc = "Unknown or disabled client."
	case errors.Is(err, oidcsvc.ErrUnsupportedResponseType):
		code = "unsupported_response_type"
		desc = "Only response_type=code is supported."
	case errors.Is(err, oidcsvc.ErrInvalidRedirectURI):
		// cannot redirect, show a page
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

// redirectError sends the OAuth2 error to the client's redirect_uri
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	if redirectURI == "" {
		oauthError(w, http.StatusBadRequest, code, desc)
		return
	}
	params := map[string]string{
		"error":             code,
		"error_description": desc,
	}
	if state != "" {
		params["state"] = state
	}
	dest, err := appendQuery(redirectURI, params)
	if err != nil {
		// redirectURI was validated as registered before we got here, so
		// this should not happen; fail closed with a plain error rather
		// than emitting a malformed redirect.
		oauthError(w, http.StatusBadRequest, "server_error", "Could not build redirect.")
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func appendQuery(raw string, params map[string]string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
