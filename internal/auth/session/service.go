package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// CookieName is the cookie that carries the signed session id
// the same cookie acts as the CAS Ticket-Granting Cookie
const CookieName = "iam_session"

// ErrInvalidSession is returned when the cookie is missing, malformed,
// signature-invalid, or refers to a session that's been revoked or expired
var ErrInvalidSession = errors.New("session: invalid")

type Service struct {
	store    *postgres.Store
	signer   *crypto.CookieSigner
	cookie   CookieOptions
	lifetime time.Duration
}

// CookieOptions controls cookie flags
type CookieOptions struct {
	Domain     string
	Path       string
	SecureOnly bool // true in production
	SameSite   http.SameSite
}

type Config struct {
	Store    *postgres.Store
	Signer   *crypto.CookieSigner
	Cookie   CookieOptions
	Lifetime time.Duration
}

func New(c Config) *Service {
	if c.Cookie.Path == "" {
		c.Cookie.Path = "/"
	}
	if c.Cookie.SameSite == 0 {
		c.Cookie.SameSite = http.SameSiteLaxMode
	}
	if c.Lifetime == 0 {
		c.Lifetime = 24 * time.Hour
	}
	return &Service{
		store:    c.Store,
		signer:   c.Signer,
		cookie:   c.Cookie,
		lifetime: c.Lifetime,
	}
}

// CreateParams carries the authentication context for a new session
type CreateParams struct {
	UserID pgtype.UUID
	// ACR is the OIDC Authentication Context Class Reference
	// "0" = single factor, "1" = MFA satisfied. Defaults to "0"
	ACR string
	// AMR lists the authentication methods used to establish the session
	// example {"pwd"}, {"pwd","otp"}, {"fed"}
	AMR []string
}

// Create persists a new session for the given user and writes the signed cookie on response
func (s *Service) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, p CreateParams) (*postgres.Session, error) {
	ua, ip := r.UserAgent(), clientIP(r)
	expiresAt := time.Now().Add(s.lifetime)

	sess, err := s.store.CreateSession(ctx, postgres.CreateSessionParams{
		UserID:    p.UserID,
		ExpiresAt: expiresAt,
		IPAddress: ipPtr(ip),
		UserAgent: stringPtr(ua),
		ACR:       p.ACR,
		AMR:       p.AMR,
	})
	if err != nil {
		return nil, err
	}

	s.writeCookie(w, sess)
	return sess, nil
}

// Get validates the cookie on response and returns the associated session
// on success, last_seen_at is updated
func (s *Service) Get(ctx context.Context, r *http.Request) (*postgres.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, ErrInvalidSession
	}
	idStr, err := s.signer.Verify(c.Value)
	if err != nil {
		return nil, ErrInvalidSession
	}

	var id pgtype.UUID
	if err := id.Scan(idStr); err != nil {
		return nil, ErrInvalidSession
	}

	sess, err := s.store.GetActiveSession(ctx, id)
	if err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			return nil, ErrInvalidSession
		}
		return nil, err
	}

	// sliding expiry: bump last_seen_at
	_ = s.store.TouchSession(ctx, sess.ID)
	return sess, nil
}

// Destroy revokes the session referred to by the cookie and clears the cookie
func (s *Service) Destroy(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(CookieName)
	if err == nil {
		if idStr, vErr := s.signer.Verify(c.Value); vErr == nil {
			var id pgtype.UUID
			if id.Scan(idStr) == nil {
				_ = s.store.RevokeSession(ctx, id)
			}
		}
	}
	s.clearCookie(w)
	return nil
}

func (s *Service) writeCookie(w http.ResponseWriter, sess *postgres.Session) {
	idStr := uuidToString(sess.ID)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    s.signer.Sign(idStr),
		Path:     s.cookie.Path,
		Domain:   s.cookie.Domain,
		Expires:  sess.ExpiresAt,
		MaxAge:   int(time.Until(sess.ExpiresAt).Seconds()),
		HttpOnly: true,
		Secure:   s.cookie.SecureOnly,
		SameSite: s.cookie.SameSite,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     s.cookie.Path,
		Domain:   s.cookie.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookie.SecureOnly,
		SameSite: s.cookie.SameSite,
	})
}

// uuidToString renders pgtype.UUID in canonical 8-4-4-4-12 form
func uuidToString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	b := u.Bytes
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i, by := range b {
		switch i {
		case 4, 6, 8, 10:
			out[pos] = '-'
			pos++
		}
		out[pos] = hexDigits[by>>4]
		out[pos+1] = hexDigits[by&0x0F]
		pos += 2
	}
	return string(out)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	// r.RemoteAddr is host:port; strip port
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ipPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
