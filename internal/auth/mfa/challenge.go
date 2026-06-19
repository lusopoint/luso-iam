package mfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lusopoint/lusoiam/internal/crypto"
)

const ChallengeCookieName = "iam_mfa_challenge"

// challengeTTL is the maximum time a user has to complete mfa after password authentication
// short enough to limit attack windows, long enough for users to fetch a code from their phone
const challengeTTL = 5 * time.Minute

// ErrNoChallenge means the cookie was missing, malformed, signature invalid, or expired
var ErrNoChallenge = errors.New("mfa: no pending challenge")

// Challenge is the state layer between password authentication and MFA verification
type Challenge struct {
	UserID    string   `json:"u"`
	Service   string   `json:"svc"`  // CAS service URL (may be empty)
	NextURL   string   `json:"next"` // post-MFA same-origin redirect (used by /oauth2/authorize)
	Redirect  string   `json:"rd"`   // post-MFA cross-origin redirect (used by /proxy/verify), pre-validated by caller
	Methods   []string `json:"m"`    // enrolled method types: "totp", "webauthn"
	HasBackup bool     `json:"bk"`   // user has backup codes
	Expires   int64    `json:"exp"`
}

// IssueChallenge signs a Challenge into a cookie on request writer
// sets a 5 minute MaxAge with HttpOnly + SameSite=Lax, secure controls the Secure flag
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

// ReadChallenge extracts the Challenge from request
func ReadChallenge(r *http.Request, signer *crypto.CookieSigner) (*Challenge, error) {
	cookie, err := r.Cookie(ChallengeCookieName)
	if err != nil {
		// ErrNoChallenge for any failure, never leak which step failed
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

// ClearChallenge removes the cookie
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
