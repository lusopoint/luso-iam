package mfa

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/api/web"
	"github.com/lusopoint/lusoiam/internal/audit"
	authcas "github.com/lusopoint/lusoiam/internal/auth/cas"
	authmfa "github.com/lusopoint/lusoiam/internal/auth/mfa"
	"github.com/lusopoint/lusoiam/internal/auth/session"
	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/middleware"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

//go:embed templates/*.html
var templatesFS embed.FS

// one parsed set per page, each combining the shared base layout (internal/api/web)
var templates = web.MustPages(templatesFS, "templates/*.html")

// handler owns all /mfa/* endpoints
type Handler struct {
	mfa      *authmfa.Service
	sessions *session.Service
	store    *postgres.Store
	cas      *authcas.Service
	signer   *crypto.CookieSigner
	secure   bool
	audit    *audit.Service // optional, nil disables audit logging
}
type Config struct {
	MFA      *authmfa.Service
	Sessions *session.Service
	Store    *postgres.Store
	CAS      *authcas.Service
	Signer   *crypto.CookieSigner
	Secure   bool
	Audit    *audit.Service
}

func New(c Config) *Handler {
	return &Handler{
		mfa:      c.MFA,
		sessions: c.Sessions,
		store:    c.Store,
		cas:      c.CAS,
		signer:   c.Signer,
		secure:   c.Secure,
		audit:    c.Audit,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /mfa", h.challengeGET)
	mux.HandleFunc("POST /mfa/totp", h.challengeTOTP)
	mux.HandleFunc("GET /mfa/backup", h.backupGET)
	mux.HandleFunc("POST /mfa/backup", h.challengeBackup)
	mux.HandleFunc("POST /mfa/webauthn/begin", h.challengeWebAuthnBegin)
	mux.HandleFunc("POST /mfa/webauthn/finish", h.challengeWebAuthnFinish)
	mux.HandleFunc("GET /mfa/enroll", h.enrollGET)
	mux.HandleFunc("GET /mfa/enroll/totp", h.enrollTOTPGET)
	mux.HandleFunc("POST /mfa/enroll/totp/confirm", h.enrollTOTPConfirm)
	mux.HandleFunc("POST /mfa/enroll/backup", h.enrollBackup)
	mux.HandleFunc("POST /mfa/enroll/webauthn/begin", h.enrollWebAuthnBegin)
	mux.HandleFunc("POST /mfa/enroll/webauthn/finish", h.enrollWebAuthnFinish)
	mux.HandleFunc("POST /mfa/methods/{id}/delete", h.deleteMethod)
}

// challengeGET renders the method-picker / TOTP code entry page
func (h *Handler) challengeGET(w http.ResponseWriter, r *http.Request) {
	ch, err := authmfa.ReadChallenge(r, h.signer)
	if err != nil {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}

	data := challengeData{
		CSRFToken:   middleware.CSRFTokenFromContext(r.Context()),
		HasTOTP:     contains(ch.Methods, "totp"),
		HasWebAuthn: contains(ch.Methods, "webauthn") && h.mfa.WebAuthnEnabled(),
		HasBackup:   ch.HasBackup,
		Error:       r.URL.Query().Get("error"),
	}
	renderTemplate(w, "challenge.html", http.StatusOK, data)
}

// challengeTOTP handles POST /mfa/totp
func (h *Handler) challengeTOTP(w http.ResponseWriter, r *http.Request) {
	ch, err := authmfa.ReadChallenge(r, h.signer)
	if err != nil {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}
	userID, ok := parseUUID(ch.UserID)
	if !ok {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	if _, err := h.mfa.VerifyTOTP(r.Context(), userID, code); err != nil {
		if h.audit != nil {
			h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
				Type:     audit.EventMFAChallengeFailure,
				Actor:    &userID,
				Metadata: map[string]any{"method": "totp"},
			}))
		}
		h.redirectToChallenge(w, r, "Invalid code. Try again.")
		return
	}

	h.completeChallenge(w, r, ch, userID, []string{"pwd", "otp"})
}

// backupGET renders the backup-code entry form
func (h *Handler) backupGET(w http.ResponseWriter, r *http.Request) {
	if _, err := authmfa.ReadChallenge(r, h.signer); err != nil {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}
	renderTemplate(w, "backup.html", http.StatusOK, simpleData{
		CSRFToken: middleware.CSRFTokenFromContext(r.Context()),
		Error:     r.URL.Query().Get("error"),
	})
}

// challengeBackup handles POST /mfa/backup
func (h *Handler) challengeBackup(w http.ResponseWriter, r *http.Request) {
	ch, err := authmfa.ReadChallenge(r, h.signer)
	if err != nil {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}
	userID, ok := parseUUID(ch.UserID)
	if !ok {
		http.Redirect(w, r, "/cas/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")

	if err := h.mfa.VerifyBackupCode(r.Context(), userID, code); err != nil {
		if h.audit != nil {
			h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
				Type:     audit.EventMFAChallengeFailure,
				Actor:    &userID,
				Metadata: map[string]any{"method": "backup_code"},
			}))
		}
		http.Redirect(w, r, "/mfa/backup?error="+esc("Invalid code."), http.StatusFound)
		return
	}

	h.completeChallenge(w, r, ch, userID, []string{"pwd", "mfa"})
}

// challengeWebAuthnBegin returns the assertion options for navigator.credentials.get()
func (h *Handler) challengeWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	ch, err := authmfa.ReadChallenge(r, h.signer)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	userID, ok := parseUUID(ch.UserID)
	if !ok {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	opts, err := h.mfa.BeginWebAuthnLogin(r.Context(), w, user, h.secure)
	if err != nil {
		slog.Warn("mfa: webauthn begin", "err", err)
		http.Error(w, "could not begin webauthn", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// challengeWebAuthnFinish verifies the assertion and completes the challenge
func (h *Handler) challengeWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	ch, err := authmfa.ReadChallenge(r, h.signer)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	userID, ok := parseUUID(ch.UserID)
	if !ok {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if _, err := h.mfa.FinishWebAuthnLogin(r.Context(), r, w, user); err != nil {
		slog.Warn("mfa: webauthn finish", "err", err)
		if h.audit != nil {
			h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
				Type:     audit.EventMFAChallengeFailure,
				Actor:    &userID,
				Metadata: map[string]any{"method": "webauthn"},
			}))
		}
		http.Error(w, "verification failed", http.StatusUnauthorized)
		return
	}

	// we need to complete the challenge but return JSON (since the
	// browser called us via fetch). Mint the session + ticket here and
	// return the redirect URL
	dest, err := h.finishChallenge(w, r, ch, userID, []string{"pwd", "hwk"})
	if err != nil {
		http.Error(w, "could not complete sign-in", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": dest})
}

// enrollment flow (requires active session)
func (h *Handler) enrollGET(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}

	methods, err := h.store.ListAllMFAMethods(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	remaining, _ := h.store.CountUnusedBackupCodes(r.Context(), sess.UserID)

	data := enrollData{
		CSRFToken:            middleware.CSRFTokenFromContext(r.Context()),
		WebAuthnEnabled:      h.mfa.WebAuthnEnabled(),
		HasBackupCodes:       remaining > 0,
		BackupCodesRemaining: remaining,
	}
	for _, m := range methods {
		v := methodView{
			ID:      uuidToString(m.ID),
			Name:    derefString(m.Name),
			Created: m.CreatedAt.UTC().Format("Jan 2, 2006"),
		}
		if m.LastUsedAt != nil {
			v.LastUsed = m.LastUsedAt.UTC().Format("Jan 2, 2006")
		}
		// skip unconfirmed entries (e.g. abandoned TOTP enrollments)
		// they shouldn't show up in the management UI
		if m.ConfirmedAt == nil {
			continue
		}
		switch m.Method {
		case "totp":
			data.TOTPMethods = append(data.TOTPMethods, v)
		case "webauthn":
			data.WebAuthnMethods = append(data.WebAuthnMethods, v)
		}
	}
	renderTemplate(w, "enroll.html", http.StatusOK, data)
}

func (h *Handler) enrollTOTPGET(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}
	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	accountLabel := userLabel(user)
	secret, err := h.mfa.BeginTOTPEnrollment(r.Context(), user.ID, accountLabel, "")
	if err != nil {
		slog.Error("mfa: begin totp enrollment", "err", err)
		http.Error(w, "could not start enrollment", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "totp_enroll.html", http.StatusOK, totpEnrollData{
		CSRFToken:  middleware.CSRFTokenFromContext(r.Context()),
		MethodID:   uuidToString(secret.MethodID),
		Secret:     secret.Base32,
		QRCodeData: template.URL(secret.QRCodeData),
		Error:      errorMessage(r.URL.Query().Get("error")),
	})
}

func (h *Handler) enrollTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	methodID, ok := parseUUID(r.FormValue("method_id"))
	if !ok {
		http.Error(w, "invalid method id", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	// ownership check: only the method's user may confirm it
	method, err := h.store.GetMFAMethod(r.Context(), methodID)
	if err != nil || !bytesEq(method.UserID.Bytes[:], sess.UserID.Bytes[:]) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := h.mfa.ConfirmTOTPEnrollment(r.Context(), methodID, code); err != nil {
		// re-rendering the QR would require keeping the otpauth URL around,
		// which we don't, send the user back to the enrollment start
		http.Redirect(w, r, "/mfa/enroll/totp?error=invalid", http.StatusFound)
		return
	}
	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventMFAEnrolled,
			Actor:    &sess.UserID,
			Metadata: map[string]any{"method": "totp", "method_id": uuidToString(methodID)},
		}))
	}
	http.Redirect(w, r, "/mfa/enroll", http.StatusFound)
}

func (h *Handler) enrollBackup(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}
	codes, err := h.mfa.GenerateBackupCodes(r.Context(), sess.UserID)
	if err != nil {
		slog.Error("mfa: generate backup codes", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventBackupCodesGenerated,
			Actor:    &sess.UserID,
			Metadata: map[string]any{"count": len(codes)},
		}))
	}
	renderTemplate(w, "backup_codes.html", http.StatusOK, backupCodesData{Codes: codes})
}

func (h *Handler) enrollWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}
	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	opts, err := h.mfa.BeginWebAuthnRegistration(r.Context(), w, user, h.secure)
	if err != nil {
		slog.Warn("mfa: webauthn register begin", "err", err)
		http.Error(w, "could not begin registration", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (h *Handler) enrollWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}
	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	method, err := h.mfa.FinishWebAuthnRegistration(r.Context(), r, w, user, "")
	if err != nil {
		slog.Warn("mfa: webauthn register finish", "err", err)
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}
	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventMFAEnrolled,
			Actor:    &sess.UserID,
			Metadata: map[string]any{"method": "webauthn", "method_id": uuidToString(method.ID)},
		}))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deleteMethod(w http.ResponseWriter, r *http.Request) {
	sess, err := h.requireSession(w, r)
	if err != nil {
		return
	}
	methodID, ok := parseUUID(r.PathValue("id"))
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	method, err := h.store.GetMFAMethod(r.Context(), methodID)
	if err != nil || !bytesEq(method.UserID.Bytes[:], sess.UserID.Bytes[:]) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := h.store.DeleteMFAMethod(r.Context(), methodID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventMFADeleted,
			Actor:    &sess.UserID,
			Metadata: map[string]any{"method": method.Method, "method_id": uuidToString(methodID)},
		}))
	}
	http.Redirect(w, r, "/mfa/enroll", http.StatusFound)
}

// completeChallenge is invoked from the form-based challenge endpoints
// (TOTP, backup), creates the real session, clears the challenge cookie, and redirects to the destination
func (h *Handler) completeChallenge(
	w http.ResponseWriter, r *http.Request,
	ch *authmfa.Challenge, userID pgtype.UUID, amr []string,
) {
	dest, err := h.finishChallenge(w, r, ch, userID, amr)
	if err != nil {
		slog.Error("mfa: complete challenge", "err", err)
		http.Error(w, "could not complete sign-in", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// finishChallenge does the side-effect-y bits and returns the redirect URL
func (h *Handler) finishChallenge(
	w http.ResponseWriter, r *http.Request,
	ch *authmfa.Challenge, userID pgtype.UUID, amr []string,
) (string, error) {
	// clear the pending-MFA cookie first
	authmfa.ClearChallenge(w, h.secure)

	sess, err := h.sessions.Create(r.Context(), w, r, session.CreateParams{
		UserID: userID,
		ACR:    "1",
		AMR:    amr,
	})
	if err != nil {
		return "", err
	}

	// audit the successful second factor + the resulting authenticated sessions
	// 2 events because the operator may filter on either
	if h.audit != nil {
		method := "totp"
		if len(amr) > 1 {
			method = amr[len(amr)-1] // last entry is the factor used
		}
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventMFAChallengeSuccess,
			Actor:    &userID,
			Metadata: map[string]any{"method": method},
		}))
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventLoginSuccess,
			Actor:    &userID,
			Metadata: map[string]any{"method": "password+mfa", "mfa": true, "amr": amr},
		}))
	}

	// resolve the destination
	// 1. CAS service ticket (downstream app login completed via CAS)
	// 2. ch.NextURL, first-party in-server path (admin UI, ...)
	// 3. ch.Redirect, cross-origin URL for the reverse-proxy companion
	//    (Caddy/Traefik forward_auth flow), already validated against
	//    the configured PROXY_ALLOWED_CALLBACK_ORIGINS allowlist at the
	//    time the challenge was issued, so we trust it here
	// 4. root
	if ch.Service != "" {
		if _, err := h.cas.ResolveService(r.Context(), ch.Service); err == nil {
			ticket, err := h.cas.IssueServiceTicket(r.Context(), sess.ID, ch.Service, false)
			if err == nil {
				return appendTicket(ch.Service, ticket), nil
			}
		}
	}
	if ch.NextURL != "" {
		return ch.NextURL, nil
	}
	if ch.Redirect != "" {
		return ch.Redirect, nil
	}
	return "/", nil
}

func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) (*postgres.Session, error) {
	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/cas/login?next="+esc(r.URL.RequestURI()), http.StatusFound)
		return nil, err
	}
	return sess, nil
}

func (h *Handler) redirectToChallenge(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/mfa?error="+esc(msg), http.StatusFound)
}

type simpleData struct {
	CSRFToken string
	Error     string
}

type challengeData struct {
	CSRFToken   string
	HasTOTP     bool
	HasWebAuthn bool
	HasBackup   bool
	Error       string
}

type totpEnrollData struct {
	CSRFToken  string
	MethodID   string
	Secret     string
	QRCodeData template.URL
	Error      string
}

type backupCodesData struct {
	Codes []string
}

type methodView struct {
	ID       string
	Name     string
	Created  string
	LastUsed string
}

type enrollData struct {
	CSRFToken            string
	TOTPMethods          []methodView
	WebAuthnMethods      []methodView
	WebAuthnEnabled      bool
	HasBackupCodes       bool
	BackupCodesRemaining int
}

// render helpers
func renderTemplate(w http.ResponseWriter, name string, status int, data any) {
	web.Render(w, templates, name, status, data)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// esc percent-encodes a value for inclusion in a query string
func esc(s string) string {
	return url.QueryEscape(s)
}

// parseUUID accepts a canonical 8-4-4-4-12 UUID string
func parseUUID(s string) (pgtype.UUID, bool) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, false
	}
	return u, u.Valid
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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// userLabel picks the best human-readable account label for TOTP QR codes
func userLabel(u *postgres.User) string {
	if u.Email != nil {
		return *u.Email
	}
	if u.Username != nil {
		return *u.Username
	}
	return uuidToString(u.ID)
}

// appendTicket appends ?ticket=<t> to serviceURL (shared with api/cas)
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

func errorMessage(code string) string {
	switch code {
	case "":
		return ""
	case "invalid":
		return "That code didn't match. Try again — your authenticator may have moved to the next 30-second window."
	default:
		return ""
	}
}
