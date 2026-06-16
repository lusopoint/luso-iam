package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// NewPKCE generates a fresh PKCE code_verifier and its S256 code_challenge
// the verifier is 32 bytes of random data (43 base64url chars, well within the 43-128 char spec range)
// S256 is the only method we support, plain is disabled per project security policy
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("pkce: read random: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// VerifyPKCE checks that SHA256(verifier) == challenge (constant-time).
func VerifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ATHash computes the at_hash claim for an OIDC id_token:
// take the SHA-256 hash of the ASCII representation of the access toke
func ATHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// CHash computes c_hash, same algorithm as ATHash but over the authorization code
// included in id_token when code is returned alongside (hybrid flow) or for verification
func CHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}
