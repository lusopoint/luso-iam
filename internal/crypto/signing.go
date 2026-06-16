package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// KeyManager holds RSA signing keys for JWT issuance
// to support rotation, it can hold one *primary* key (used to sign new tokens)
// plus any number of *retiring* keys
// (still present in the JWKS so already-issued tokens continue to verify until they expire)
//
// rotation flow (multi-key mode):
//
//  1. Operator runs `make rotate-key` which writes a new file into
//     the directory with a current-timestamp name
//  2. Operator restarts the server
//  3. Server loads the directory: the newest file becomes primary,
//     the previous primary becomes retiring
//  4. New tokens are signed by the new key. Old tokens continue to
//     verify because both keys are in the JWKS
//  5. After max-token-TTL (e.g. 1 hour) passes, the operator removes
//     the old key file and restarts again to clear the JWKS
type KeyManager struct {
	primary  *keyEntry
	retiring []*keyEntry
}

type keyEntry struct {
	privateKey *rsa.PrivateKey
	keyID      string
	// source is the filename the key came from, for logging /
	// debugging. Empty when the key was generated in-memory
	source string
}

// LoadOrGenerate returns a KeyManager backed by the given path
//
//	path == ""              -> generate one ephemeral key
//	path is a regular file  -> load it as the only key (single-key mode)
//	path is a directory     -> load every *.pem in it (multi-key mode)
func LoadOrGenerate(path string) (*KeyManager, error) {
	if path == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
		return &KeyManager{
			primary: &keyEntry{privateKey: key, keyID: computeKID(key)},
		}, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat signing key path %q: %w", path, err)
	}

	if info.IsDir() {
		return loadFromDir(path)
	}
	// Single-file mode, backward-compatible with pre-rotation deployments
	key, err := loadPEM(path)
	if err != nil {
		return nil, fmt.Errorf("load signing key %q: %w", path, err)
	}
	return &KeyManager{
		primary: &keyEntry{privateKey: key, keyID: computeKID(key), source: filepath.Base(path)},
	}, nil
}

// loadFromDir scans a directory for *.pem files, parses each, and orders them:
// - lexicographically highest filename becomes primary
// - the rest are retiring
// files that fail to parse are reported but not fatal
func loadFromDir(dir string) (*KeyManager, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read signing key dir %q: %w", dir, err)
	}

	// collect candidate filenames, then sort, sorting on the FILENAME
	// (not on the key's kid) is the contract, operators choose the
	// rotation order by naming, which is predictable and inspectable
	// without parsing PEM blobs
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".pem") {
			continue
		}
		names = append(names, e.Name())
	}
	// ascending: newest (highest) goes last
	sort.Strings(names)

	var loaded []*keyEntry
	var errs []string
	for _, name := range names {
		full := filepath.Join(dir, name)
		key, err := loadPEM(full)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		loaded = append(loaded, &keyEntry{
			privateKey: key,
			keyID:      computeKID(key),
			source:     name,
		})
	}

	if len(loaded) == 0 {
		msg := "no usable PEM keys found"
		if len(errs) > 0 {
			msg += "; " + strings.Join(errs, "; ")
		}
		return nil, fmt.Errorf("load signing keys from %q: %s", dir, msg)
	}

	// last sorted = primary, everything else is retiring
	km := &KeyManager{primary: loaded[len(loaded)-1]}
	if len(loaded) > 1 {
		km.retiring = loaded[:len(loaded)-1]
	}
	return km, nil
}

// Sign creates a signed RS256 JWT using the primary key, the kid
// header is set so verifiers can pick the right public key out of the JWKS
func (km *KeyManager) Sign(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = km.primary.keyID
	s, err := t.SignedString(km.primary.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return s, nil
}

// KeyID returns the primary key's identifier (used in id_token headers)
func (km *KeyManager) KeyID() string { return km.primary.keyID }

// PublicKey returns the primary key's public part (for test verification)
func (km *KeyManager) PublicKey() *rsa.PublicKey { return &km.primary.privateKey.PublicKey }

// KeyInfo is the per-key metadata exposed by Keys()
type KeyInfo struct {
	Kid     string `json:"kid"`
	Primary bool   `json:"primary"`
	Source  string `json:"source,omitempty"`
}

// Keys lists metadata for every loaded Keys
// The first element is always the primary
// remaining elements are retiring keys still
// published in the JWKS, used by the admin keys endpoint
func (km *KeyManager) Keys() []KeyInfo {
	out := make([]KeyInfo, 0, 1+len(km.retiring))
	out = append(out, KeyInfo{Kid: km.primary.keyID, Primary: true, Source: km.primary.source})
	for _, e := range km.retiring {
		out = append(out, KeyInfo{Kid: e.keyID, Primary: false, Source: e.source})
	}
	return out
}

type JWKSDocument struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS serializes ALL loaded public keys into a JWKSDocument suitable for the JWKS endpoint
func (km *KeyManager) JWKS() JWKSDocument {
	keys := make([]JSONWebKey, 0, 1+len(km.retiring))
	keys = append(keys, jsonWebKey(km.primary))
	for _, e := range km.retiring {
		keys = append(keys, jsonWebKey(e))
	}
	return JWKSDocument{Keys: keys}
}

func jsonWebKey(e *keyEntry) JSONWebKey {
	pub := &e.privateKey.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return JSONWebKey{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: e.keyID,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// computeKID derives a stable key identifier from the first 8 bytes of
// the public modulus, base64url-encoded. Same key file-> same kid
func computeKID(key *rsa.PrivateKey) string {
	n := key.PublicKey.N.Bytes()
	if len(n) > 8 {
		n = n[:8]
	}
	return base64.RawURLEncoding.EncodeToString(n)
}

func loadPEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
