package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// if signature is invalid or format is malformed we return this error
var ErrSignature = errors.New("crypto: invalid cookie signature")

// CookieSigner produces and validates HMAC-SHA256 signed cookie values
//
//	<base64(payload)>.<base64(hmac_sha256(payload))>
//
// this is intentionally tiny, not a JWT, not a JWE, because all we
// need is tamper detection on an otherwise opaque session token
type CookieSigner struct {
	key []byte
}

func NewCookieSigner(secret string) *CookieSigner {
	return &CookieSigner{key: []byte(secret)}
}

// cookie value payload
func (s *CookieSigner) Sign(payload string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return p + "." + sig
}

// Verify extracts the payload from value, returning ErrSignature if the
// signature doesn't match or the format is wrong
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
