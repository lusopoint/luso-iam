// Package mfa implements multi-factor authentication: TOTP, WebAuthn,
// and backup codes. It exposes a Service that the CAS and OIDC login
// flows use to gate access on enrolled second factors.
package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
)

// ChallengeCookieName is the cookie carrying the signed pending-MFA state.
const ChallengeCookieName = "iam_mfa_challenge"

// challengeTTL is the maximum time a user has to complete MFA after
// password authentication. Short enough to limit attack windows; long
// enough for users to fetch a code from their phone.
const challengeTTL = 5 * time.Minute

// ErrNoChallenge means the cookie was missing, malformed, signature
// invalid, or expired. From the caller's perspective these are
// indistinguishable — the user must re-authenticate from scratch.
var ErrNoChallenge = errors.New("mfa: no pending challenge")

// Challenge is the state we round-trip between password authentication
// and MFA verification. Stored client-side in an HMAC-signed cookie so
// the server is stateless across the gap.
type Challenge struct {
	UserID string `json:"u"`

	// CAS service URL (may be empty)
	Service string `json:"svc"`

	// post-MFA redirect (used by /oauth2/authorize)
	NextURL string `json:"next"`

	// post-MFA cross-origin redirect (used by /proxy/verify); pre-validated by caller
	Redirect string `json:"rd"`

	// enrolled method types: "totp", "webauthn"
	Methods []string `json:"m"`

	// user has backup codes
	HasBackup bool `json:"bk"`

	// unix seconds
	Expires int64 `json:"exp"`
}

// IssueChallenge signs a Challenge into a cookie on w. Sets a 5-minute
// MaxAge with HttpOnly + SameSite=Lax. Secure controls the Secure flag.
func IssueChallenge(w http.ResponseWriter, signer *crypto.CookieSigner, secure bool, c Challenge) error {
	c.Expires = time.Now().Add(challengeTTL).Unix()
	payload, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode challenge: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    signer.Sign(string(payload)),
		Path:     "/",
		MaxAge:   int(challengeTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// ReadChallenge extracts the Challenge from r. Returns ErrNoChallenge
// for any failure — never leak which step failed.
func ReadChallenge(r *http.Request, signer *crypto.CookieSigner) (*Challenge, error) {
	cookie, err := r.Cookie(ChallengeCookieName)
	if err != nil {
		return nil, ErrNoChallenge
	}
	payload, err := signer.Verify(cookie.Value)
	if err != nil {
		return nil, ErrNoChallenge
	}
	var c Challenge
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		return nil, ErrNoChallenge
	}
	if time.Now().Unix() > c.Expires {
		return nil, ErrNoChallenge
	}
	return &c, nil
}

// ClearChallenge removes the cookie. Idempotent.
func ClearChallenge(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
