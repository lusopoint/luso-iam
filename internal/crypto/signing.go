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

	"github.com/golang-jwt/jwt/v5"
)

// KeyManager holds the active RSA signing key and produces JWKS documents
// and signed JWTs. In production, load from a persistent PEM file so
// existing tokens stay valid across restarts. In dev, a new key is
// generated at startup (tokens invalidate on restart).
type KeyManager struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

// LoadOrGenerate returns a KeyManager backed by the PEM file at path,
// or generates a fresh 2048-bit RSA key if path is empty.
func LoadOrGenerate(path string) (*KeyManager, error) {
	if path != "" {
		key, err := loadPEM(path)
		if err != nil {
			return nil, fmt.Errorf("load signing key %q: %w", path, err)
		}
		return &KeyManager{privateKey: key, keyID: computeKID(key)}, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &KeyManager{privateKey: key, keyID: computeKID(key)}, nil
}

// Sign creates a signed RS256 JWT. The kid header is set automatically.
func (km *KeyManager) Sign(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = km.keyID
	s, err := t.SignedString(km.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return s, nil
}

// KeyID returns the key identifier embedded in signed tokens.
func (km *KeyManager) KeyID() string { return km.keyID }

// PublicKey returns the RSA public key (for test verification).
func (km *KeyManager) PublicKey() *rsa.PublicKey { return &km.privateKey.PublicKey }

// JWKS

// JWKSDocument is the JSON response body for GET /.well-known/jwks.json.
type JWKSDocument struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey is one entry in the JWKS key set.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS serializes the public key into a JWKSDocument suitable for the
// JWKS endpoint. Clients cache this and use it to verify id_tokens.
func (km *KeyManager) JWKS() JWKSDocument {
	pub := &km.privateKey.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return JWKSDocument{
		Keys: []JSONWebKey{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: km.keyID,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}
}

// helpers

// computeKID derives a stable key identifier from the first 8 bytes of
// the public modulus, base64url-encoded. Same key file → same kid.
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
