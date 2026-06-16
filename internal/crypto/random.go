package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandomToken returns n bytes of cryptographically secure random data, hex-encoded
// the returned string is 2n characters long
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MustRandomToken panics on rand failure, suitable for startup time use
func MustRandomToken(n int) string {
	s, err := RandomToken(n)
	if err != nil {
		panic(err)
	}
	return s
}

// passwordAlphabet excludes visually ambiguous characters: 0/O, 1/l/I
// 56 chars x 16 positions = 93 bits of entropy, strong enough for the
// short window before the user is expected to change it
const passwordAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RandomPassword returns a cryptographically random password of n
// characters drawn from passwordAlphabet
// n=16 is the recommended minimum, the admin handler default is 20 for a comfortable margin
//
// we sample uniformly by reading nx8 random bytes and rejecting any
// byte >= floor(256/|A|) |A|
// with |A|=56 the rejection rate is < 13%
// so the loop terminates in expected <= 1.15 n iterations
func RandomPassword(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("password length must be > 0")
	}
	out := make([]byte, 0, n)
	alphaLen := byte(len(passwordAlphabet))
	// largest multiple of |A| <= 256
	cutoff := byte(256 - (256 % int(alphaLen)))
	buf := make([]byte, 8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random: %w", err)
		}
		for _, b := range buf {
			if b >= cutoff {
				// modulo bias avoided by rejection sampling
				continue
			}
			out = append(out, passwordAlphabet[b%alphaLen])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}
