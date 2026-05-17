// Package crypto holds the small, focused cryptographic primitives used
// throughout the server: argon2id password hashing, secure random
// generation, and HMAC-signed cookie values.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per project guidelines section 6.
// These are fixed at compile time; if we ever need to change them, existing
// hashes still validate because the parameters are encoded in the PHC string.
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB → 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen uint32 = 16
)

// ErrInvalidHash is returned when the stored hash isn't a recognisable
// argon2id PHC string.
var ErrInvalidHash = errors.New("crypto: invalid argon2id hash format")

// HashPassword returns the PHC-encoded argon2id hash of password.
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword constant-time compares password against the stored PHC
// hash. Returns (true, nil) on match, (false, nil) on mismatch, and a
// non-nil error only if the encoded hash is malformed.
func VerifyPassword(password, encoded string) (bool, error) {
	params, salt, hash, err := decodeArgon2id(encoded)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey(
		[]byte(password),
		salt,
		params.time, params.memory, params.threads,
		uint32(len(hash)),
	)
	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeArgon2id parses the PHC-format string back into its components.
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func decodeArgon2id(s string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	// Leading empty + algo + version + params + salt + hash = 6 parts.
	if len(parts) != 6 || parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	return p, salt, hash, nil
}
