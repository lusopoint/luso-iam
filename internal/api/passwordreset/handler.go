package passwordreset

import (
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	authpr "github.com/lusopoint/lusoiam/internal/auth/passwordreset"
	"github.com/lusopoint/lusoiam/internal/middleware"
)

var templatesFS embed.FS
var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// forgotPageData drives forgot.html
type forgotPageData struct {
	CSRFToken string // double-submit value
	Submitted bool   // true after POST → swaps the form for the "check your inbox" copy
	Error     string // non-empty when client-side validation fails (rare; the form is one field)
}

// resetPageData drives reset.html
type resetPageData struct {
	CSRFToken         string
	Token             string // re-emit so the POST form preserves it
	MinPasswordLength int    // surfaced in the form's help text
	Error             string
}

type Handler struct {
	svc *authpr.Service
}

func New(svc *authpr.Service) *Handler {
	if svc == nil {
		// optional feature: when SMTP is not configured we skip wiring
		// this handler entirely, constructing with nil is a programmer error
		panic("passwordreset: nil service")
	}
	return &Handler{svc: svc}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /password/forgot", h.forgotGET)
	mux.HandleFunc("POST /password/forgot", h.forgotPOST)
	mux.HandleFunc("GET /password/reset", h.resetGET)
	mux.HandleFunc("POST /password/reset", h.resetPOST)
}

// GET /password/forgot render the email-entry form
func (h *Handler) forgotGET(w http.ResponseWriter, r *http.Request) {
	renderForgot(w, http.StatusOK, forgotPageData{CSRFToken: middleware.CSRFTokenFromContext(r.Context())})
}

// POST /password/forgot accept the email, fire the reset email
// (if user exists), respond with the "check your inbox" page. ALWAYS
// 200 regardless of whether the account was real; account-enumeration
// defence depends on this being indistinguishable from success
func (h *Handler) forgotPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderForgot(w, http.StatusBadRequest, forgotPageData{CSRFToken: middleware.CSRFTokenFromContext(r.Context()), Error: "Invalid form submission."})
		return
	}
	email := r.PostFormValue("email")
	// Service.Request handles the empty-email and unknown-email cases
	// as silent no-ops, we don't branch on the result for security
	if err := h.svc.Request(r.Context(), email, clientIP(r), r.Header.Get("User-Agent")); err != nil {
		// operator-side failure (DB down, SMTP down). Log loudly. We
		// still render the success page so the failure mode looks
		// identical to a normal request preserves the enumeration
		// defence even when things are broken on our end
		slog.ErrorContext(r.Context(), "password-reset: request failed",
			"err", err, "email_present", email != "")
	}
	renderForgot(w, http.StatusOK, forgotPageData{CSRFToken: middleware.CSRFTokenFromContext(r.Context()), Submitted: true})
}

// GET /password/reset?token=... validate token, render new-password form
func (h *Handler) resetGET(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if _, err := h.svc.Verify(r.Context(), token); err != nil {
		if errors.Is(err, authpr.ErrInvalidToken) {
			renderResetInvalid(w)
			return
		}
		slog.ErrorContext(r.Context(), "password-reset: verify failed", "err", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	renderReset(w, http.StatusOK, resetPageData{
		CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
		Token:             token,
		MinPasswordLength: h.svc.MinPasswordLength(),
	})
}

// POST /password/reset consume the token and update the password
func (h *Handler) resetPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderResetInvalid(w)
		return
	}
	token := r.PostFormValue("token")
	pwd := r.PostFormValue("password")
	confirm := r.PostFormValue("password_confirm")
	minLen := h.svc.MinPasswordLength()

	if pwd != confirm {
		renderReset(w, http.StatusBadRequest, resetPageData{
			CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
			Token:             token,
			MinPasswordLength: minLen,
			Error:             "Passwords don't match.",
		})
		return
	}
	if len(pwd) < minLen {
		renderReset(w, http.StatusBadRequest, resetPageData{
			CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
			Token:             token,
			MinPasswordLength: minLen,
			Error:             "Password must be at least " + itoa(minLen) + " characters.",
		})
		return
	}
	if err := h.svc.Reset(r.Context(), token, pwd); err != nil {
		switch {
		case errors.Is(err, authpr.ErrInvalidToken):
			renderResetInvalid(w)
		case errors.Is(err, authpr.ErrWeakPassword):
			// race against the length check above (different minLen
			// could be configured between requests). Fall through to a
			// generic error
			renderReset(w, http.StatusBadRequest, resetPageData{
				CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
				Token:             token,
				MinPasswordLength: minLen,
				Error:             "Password doesn't meet requirements.",
			})
		default:
			slog.ErrorContext(r.Context(), "password-reset: reset failed", "err", err)
			http.Error(w, "Internal error.", http.StatusInternalServerError)
		}
		return
	}

	// success bounce to login, including a query flag so we can show
	// a "your password was reset, please sign in" banner
	http.Redirect(w, r, "/cas/login?password_reset=1", http.StatusFound)
}

func renderForgot(w http.ResponseWriter, status int, data forgotPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = templates.ExecuteTemplate(w, "forgot.html", data)
}

func renderReset(w http.ResponseWriter, status int, data resetPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = templates.ExecuteTemplate(w, "reset.html", data)
}

func renderResetInvalid(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = templates.ExecuteTemplate(w, "reset_invalid.html", nil)
}

// clientIP pulls the client IP from the request
func clientIP(r *http.Request) string {
	return r.RemoteAddr
}

// itoa is a no-allocation int-to-string helper for short positive
// values (form error messages), avoids pulling fmt for one call
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
