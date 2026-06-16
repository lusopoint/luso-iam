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

// Argon2id parameters, for now we will make it fixed
const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024 // KiB -> 64 MiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen uint32 = 16
)

// if not a valid argon2id PHC string we return this error
var ErrInvalidHash = errors.New("crypto: invalid argon2id hash format")

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

// VerifyPassword constant time compares password against the stored PHC hash
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

// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func decodeArgon2id(s string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(s, "$")
	// leading empty + algo + version + params + salt + hash = 6 parts
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
