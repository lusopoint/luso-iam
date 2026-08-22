package signup

import (
	"embed"
	"errors"
	"log/slog"
	"net/http"

	"github.com/lusopoint/lusoiam/internal/api/web"

	"github.com/lusopoint/lusoiam/internal/audit"
	authsignup "github.com/lusopoint/lusoiam/internal/auth/signup"
	"github.com/lusopoint/lusoiam/internal/middleware"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates = web.MustPages(templatesFS, "templates/*.html")

// signupPageData drives signup.html
type signupPageData struct {
	CSRFToken         string
	Email             string // re-emit on failure so the user doesn't have to retype
	FirstName         string // re-emit on failure
	LastName          string // re-emit on failure
	MinPasswordLength int
	Error             string
}

// signupDoneData drives signup_done.html (the "check your inbox" page)
type signupDoneData struct {
	Email       string
	ExpiryHours int
}

// Handler is the HTTP-level orchestrator, main.go constructs one only
// when SIGNUP_ENABLED is true; the routes are registered conditionally
type Handler struct {
	svc   *authsignup.Service
	audit *audit.Service
}

func New(svc *authsignup.Service, auditSvc *audit.Service) *Handler {
	if svc == nil {
		// programmer error wiring should skip construction entirely
		// when signup is disabled, not pass nil
		panic("signup: nil service")
	}
	return &Handler{svc: svc, audit: auditSvc}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /signup", h.signupGET)
	mux.HandleFunc("POST /signup", h.signupPOST)
	mux.HandleFunc("GET /verify", h.verifyGET)
}

// GET /signup render the registration form
func (h *Handler) signupGET(w http.ResponseWriter, r *http.Request) {
	renderSignup(w, http.StatusOK, signupPageData{
		CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
		MinPasswordLength: h.svc.MinPasswordLength(),
	})
}

// POST /signup accept email + password, create the user, fire the
// verification email, render "check your inbox"
func (h *Handler) signupPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderSignup(w, http.StatusBadRequest, signupPageData{
			CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
			MinPasswordLength: h.svc.MinPasswordLength(),
			Error:             "Invalid form submission.",
		})
		return
	}
	email := r.PostFormValue("email")
	password := r.PostFormValue("password")
	firstName := r.PostFormValue("first_name")
	lastName := r.PostFormValue("last_name")

	user, err := h.svc.Register(r.Context(), authsignup.RegisterParams{
		Email:     email,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
		RequestIP: clientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
	})
	if err != nil {
		// translate the sentinel errors to user-facing messages
		// Any other error is operator-side (DB or SMTP down) and shows a
		// generic 500 the user can retry, the operator sees the log
		var msg string
		switch {
		case errors.Is(err, authsignup.ErrEmailInUse):
			msg = "That email already has an account. Try signing in instead."
		case errors.Is(err, authsignup.ErrInvalidEmail):
			msg = "That doesn't look like a valid email address."
		case errors.Is(err, authsignup.ErrWeakPassword):
			msg = "Password must be at least " + itoa(h.svc.MinPasswordLength()) + " characters."
		case errors.Is(err, authsignup.ErrMissingName):
			msg = "Please enter both your first and last name."
		default:
			slog.ErrorContext(r.Context(), "signup: register failed", "err", err)
			http.Error(w, "Internal error. Please try again.", http.StatusInternalServerError)
			return
		}
		renderSignup(w, http.StatusBadRequest, signupPageData{
			CSRFToken:         middleware.CSRFTokenFromContext(r.Context()),
			Email:             email,
			FirstName:         firstName,
			LastName:          lastName,
			MinPasswordLength: h.svc.MinPasswordLength(),
			Error:             msg,
		})
		return
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventUserCreated,
			Actor:    &user.ID,
			Target:   &user.ID,
			Metadata: map[string]any{"source": "self_signup", "email_verified": false},
		}))
	}

	// render the "check your inbox" page, show the email so the user
	// knows where to look (and notices a typo immediately)
	hours := int(h.svc.TokenTTL().Hours())
	if hours < 1 {
		hours = 1
	}
	renderSignupDone(w, http.StatusOK, signupDoneData{
		Email:       email,
		ExpiryHours: hours,
	})
}

// GET /verify?token=... consume the token, mark the user verified,
// redirect to login with a banner-friendly flag
//
// on invalid/expired/used tokens, render verify_invalid.html
// we could distinguish the cases (expired vs already used)
// but the user experience is the same: "click 'Sign in', or sign up
// again" so a unified error page is friendlier
func (h *Handler) verifyGET(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	user, err := h.svc.Verify(r.Context(), token)
	if err != nil {
		if errors.Is(err, authsignup.ErrInvalidToken) {
			renderVerifyInvalid(w)
			return
		}
		slog.ErrorContext(r.Context(), "signup: verify failed", "err", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}

	if h.audit != nil {
		h.audit.Log(r.Context(), audit.FromRequest(r, audit.Event{
			Type:     audit.EventEmailVerified,
			Actor:    &user.ID,
			Target:   &user.ID,
			Metadata: map[string]any{},
		}))
	}

	// redirect to login
	// the ?verified=1 flag lets the login page
	// render a "your email is confirmed, please sign in" banner if
	// it wants to, does not change the auth flow itself
	http.Redirect(w, r, "/cas/login?verified=1", http.StatusFound)
}

func renderSignup(w http.ResponseWriter, status int, data signupPageData) {
	web.Render(w, templates, "signup.html", status, data)
}

func renderSignupDone(w http.ResponseWriter, status int, data signupDoneData) {
	web.Render(w, templates, "signup_done.html", status, data)
}

func renderVerifyInvalid(w http.ResponseWriter) {
	web.Render(w, templates, "verify_invalid.html", http.StatusBadRequest, nil)
}

// itoa avoids pulling in strconv for one trivial use!
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// clientIP returns the immediate peers address sans port, the CSRF
// and rate-limit middleware already handles trusted-proxy XFF parsing upstream
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
