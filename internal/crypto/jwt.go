package crypto

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWTClaims is the minimal set of claims we extract from an OIDC id_token
// Providers may include additional claims in RawClaims
type JWTClaims struct {
	Issuer        string         `json:"iss"`
	Subject       string         `json:"sub"`
	Audience      audience       `json:"aud"` // string or []string
	ExpiresAt     int64          `json:"exp"`
	IssuedAt      int64          `json:"iat"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Name          string         `json:"name"`
	Picture       string         `json:"picture"`
	RawClaims     map[string]any // populated separately from the full payload
}

// audience handles the CAS where aud is either a string or []string
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var multi []string
	if err := json.Unmarshal(b, &multi); err == nil {
		*a = multi
		return nil
	}
	// fall back to single string
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	*a = []string{single}
	return nil
}

// VerifyRS256 parses and verifies an RS256 JWT using keys from jwksURL
// it validates signature, expiry, issuer, and that clientID appears in aud
func VerifyRS256(ctx context.Context, tokenStr, clientID, expectedIssuer string, cache *JWKSCache) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: malformed token (expected 3 parts)")
	}

	// header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("jwt: parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("jwt: unsupported algorithm %q (only RS256 accepted)", header.Alg)
	}

	// signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode signature: %w", err)
	}
	message := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(message))

	key, err := cache.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("jwt: fetch key %q: %w", header.Kid, err)
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("jwt: invalid signature: %w", err)
	}

	// claims
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode payload: %w", err)
	}
	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: parse claims: %w", err)
	}
	// keep the raw map for callers that want extra claims
	var raw map[string]any
	_ = json.Unmarshal(payloadJSON, &raw)
	claims.RawClaims = raw

	now := time.Now().Unix()
	const skew = 5 * 60 // 5 minutes

	if claims.ExpiresAt < now-skew {
		return nil, errors.New("jwt: token has expired")
	}
	if claims.IssuedAt > now+skew {
		return nil, errors.New("jwt: token issued in the future")
	}
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("jwt: unexpected issuer %q", claims.Issuer)
	}
	found := false
	for _, a := range claims.Audience {
		if a == clientID {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("jwt: client_id %q not in aud", clientID)
	}

	return &claims, nil
}

// JWKSCache fetches and caches RSA public keys from a JWKS endpoint
// it is safe for concurrent use
// keys are refreshed when they expire or when an unknown kid is requested (one retry)
type JWKSCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

func NewJWKSCache(url string, ttl time.Duration, client *http.Client) *JWKSCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	return &JWKSCache{url: url, ttl: ttl, client: client}
}

// GetKey returns the RSA public key for kid, fetching JWKS if needed
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// fast path: read lock only
	c.mu.RLock()
	key, ok := c.keys[kid]
	fresh := time.Now().Before(c.expiresAt)
	c.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	// slow path: refresh the keyset
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS after refresh", kid)
	}
	return key, nil
}

// refresh fetches the JWKS endpoint and updates the key map
func (c *JWKSCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("jwks: build request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("jwks: decode response: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			// skip malformed keys, don't fail entirely
			continue
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.expiresAt = time.Now().Add(c.ttl)
	c.mu.Unlock()
	return nil
}

// parseRSAPublicKey reconstructs an *rsa.PublicKey from the base64url-encoded
// modulus (n) and exponent (e) found in a JWKS entry
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
