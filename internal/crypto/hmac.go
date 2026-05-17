package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrSignature is returned by VerifyCookie when the signature is invalid
// or the format is malformed.
var ErrSignature = errors.New("crypto: invalid cookie signature")

// CookieSigner produces and validates HMAC-SHA256 signed cookie values.
// The cookie format is two URL-safe base64 segments joined by a dot:
//
//	<base64(payload)>.<base64(hmac_sha256(payload))>
//
// This is intentionally tiny — not a JWT, not a JWE — because all we
// need is tamper detection on an otherwise opaque session token.
type CookieSigner struct {
	key []byte
}

// NewCookieSigner returns a signer keyed on secret. secret should be at
// least 32 bytes of entropy; config.Validate enforces this at startup.
func NewCookieSigner(secret string) *CookieSigner {
	return &CookieSigner{key: []byte(secret)}
}

// Sign returns the cookie value carrying payload.
func (s *CookieSigner) Sign(payload string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return p + "." + sig
}

// Verify extracts the payload from value, returning ErrSignature if the
// signature doesn't match or the format is wrong. Constant-time
// comparison is used for the signature check.
func (s *CookieSigner) Verify(value string) (string, error) {
	dot := strings.IndexByte(value, '.')
	if dot < 0 {
		return "", ErrSignature
	}
	p, sig := value[:dot], value[dot+1:]

	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(p))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", ErrSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", ErrSignature
	}
	return string(payload), nil
}
