package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// writeKey creates a fresh RSA key and writes it as PKCS#8 PEM to path.
// Helper for the multi-key tests so each test starts from a clean dir.
func writeKey(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestLoadOrGenerate_EphemeralKey: the dev path. Empty path returns a
// freshly-generated, fully-functional KeyManager, no file I/O.
func TestLoadOrGenerate_EphemeralKey(t *testing.T) {
	t.Parallel()
	km, err := LoadOrGenerate("")
	if err != nil {
		t.Fatalf("LoadOrGenerate(\"\"): %v", err)
	}
	if km.KeyID() == "" {
		t.Error("ephemeral key should have a kid")
	}
	if len(km.Keys()) != 1 {
		t.Errorf("ephemeral mode should have 1 key, got %d", len(km.Keys()))
	}
	if !km.Keys()[0].Primary {
		t.Error("the sole key must be marked primary")
	}
}

// TestLoadOrGenerate_SingleFile: backward-compatible path. A single
// .pem file works exactly like before  one primary, no retiring.
func TestLoadOrGenerate_SingleFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	writeKey(t, path)

	km, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate(file): %v", err)
	}
	if len(km.Keys()) != 1 {
		t.Errorf("single-file mode → 1 key; got %d", len(km.Keys()))
	}
	if !km.Keys()[0].Primary {
		t.Error("only key must be primary")
	}
	if km.Keys()[0].Source != "signing.pem" {
		t.Errorf("source = %q, want signing.pem", km.Keys()[0].Source)
	}
}

// TestLoadOrGenerate_DirectoryModePrimaryByName: the central contract
// of rotation. When the path is a directory with multiple PEMs, the
// lexicographically highest filename becomes primary. This is how
// `rotate-key`'s timestamp-prefixed naming works  newer files sort
// later, automatically becoming primary.
func TestLoadOrGenerate_DirectoryModePrimaryByName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Write three keys in non-sorted order to make sure load order
	// is what we expect, not just "whatever ReadDir returned".
	writeKey(t, filepath.Join(dir, "20240101-old.pem"))
	writeKey(t, filepath.Join(dir, "20260101-new.pem")) // newest → primary
	writeKey(t, filepath.Join(dir, "20250101-mid.pem"))

	km, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerate(dir): %v", err)
	}

	keys := km.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	// Primary is keys[0] per the API contract.
	if !keys[0].Primary || keys[0].Source != "20260101-new.pem" {
		t.Errorf("primary should be 20260101-new.pem, got %+v", keys[0])
	}
	// Retiring keys: primary not set, in load order (which is sort order).
	for i, want := range []string{"20240101-old.pem", "20250101-mid.pem"} {
		got := keys[i+1]
		if got.Primary {
			t.Errorf("retiring key %s should not be primary", got.Source)
		}
		if got.Source != want {
			t.Errorf("retiring[%d] = %s, want %s", i, got.Source, want)
		}
	}
}

// TestJWKS_ContainsEveryKey: the JWKS endpoint must publish ALL loaded
// keys so clients can verify tokens signed by the previous primary
// during the rotation grace period. Missing the retiring key would
// instantly invalidate every not-yet-expired token.
func TestJWKS_ContainsEveryKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeKey(t, filepath.Join(dir, "001.pem"))
	writeKey(t, filepath.Join(dir, "002.pem"))
	writeKey(t, filepath.Join(dir, "003.pem"))

	km, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	jwks := km.JWKS()
	if len(jwks.Keys) != 3 {
		t.Errorf("JWKS should include all 3 keys, got %d", len(jwks.Keys))
	}

	// Each JWK should be well-formed (kid + n + e present).
	for i, k := range jwks.Keys {
		if k.Kid == "" {
			t.Errorf("JWKS[%d].Kid empty", i)
		}
		if k.N == "" || k.E == "" {
			t.Errorf("JWKS[%d] missing modulus or exponent", i)
		}
		if k.Alg != "RS256" {
			t.Errorf("JWKS[%d].Alg = %q, want RS256", i, k.Alg)
		}
	}

	// The primary's kid must be first in JWKS.Keys  some buggy clients
	// pick keys[0] instead of looking up by kid.
	if jwks.Keys[0].Kid != km.KeyID() {
		t.Errorf("JWKS[0].kid = %s, want primary %s", jwks.Keys[0].Kid, km.KeyID())
	}
}

// TestSign_UsesPrimaryKey: signed tokens carry the primary key's kid
// in the header, never a retiring key's. Verifies that rotating doesn't
// silently strand new tokens with the wrong kid.
func TestSign_UsesPrimaryKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeKey(t, filepath.Join(dir, "a-old.pem"))
	writeKey(t, filepath.Join(dir, "b-new.pem"))

	km, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	primaryKid := km.KeyID()

	signed, err := km.Sign(jwt.MapClaims{"sub": "test"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, _, err := new(jwt.Parser).ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotKid, _ := parsed.Header["kid"].(string)
	if gotKid != primaryKid {
		t.Errorf("token kid = %q, want primary %q", gotKid, primaryKid)
	}
}

// TestLoadOrGenerate_NonexistentPath: a clear error when the path
// doesn't exist. Caught operators wondering why their typo failed
// silently  the original loader gave a generic open-file error.
func TestLoadOrGenerate_NonexistentPath(t *testing.T) {
	t.Parallel()
	_, err := LoadOrGenerate("/nonexistent/definitely-not-here.pem")
	if err == nil {
		t.Fatal("expected an error for missing path")
	}
}

// TestLoadOrGenerate_EmptyDirectoryFails: a directory with no .pem
// files is an error, not a silent zero-key state. Without this guard
// the server would happily start and produce empty JWKS, returning
// "could not verify" on every token. Loud failure is better.
func TestLoadOrGenerate_EmptyDirectoryFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := LoadOrGenerate(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}

// TestLoadOrGenerate_BrokenKeyFileSkipped: a malformed .pem in the
// directory shouldn't take down the server  it gets skipped, and as
// long as at least one valid key remains, load succeeds. This matters
// during rotation: an operator might leave a corrupt experimental file
// behind, and we don't want that to brick startup.
func TestLoadOrGenerate_BrokenKeyFileSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeKey(t, filepath.Join(dir, "good.pem"))
	if err := os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("not a real PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	km, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("expected to load the good key despite broken sibling: %v", err)
	}
	if len(km.Keys()) != 1 {
		t.Errorf("expected 1 key loaded (the good one), got %d", len(km.Keys()))
	}
}

// TestLoadOrGenerate_AllBrokenFails: but if EVERY file is broken,
// there's nothing to sign with  that's a real failure, error out.
func TestLoadOrGenerate_AllBrokenFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, n := range []string{"a.pem", "b.pem"} {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("garbage"), 0600)
	}
	if _, err := LoadOrGenerate(dir); err == nil {
		t.Fatal("expected error when all PEMs are broken")
	}
}

// TestLoadOrGenerate_IgnoresNonPEMFiles: a directory might contain
// README.md or similar. Only *.pem (case-insensitive) is considered.
func TestLoadOrGenerate_IgnoresNonPEMFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeKey(t, filepath.Join(dir, "key.pem"))
	_ = os.WriteFile(filepath.Join(dir, "README.md"), []byte("notes"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "backup.tar"), []byte{0, 1, 2}, 0644)

	km, err := LoadOrGenerate(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(km.Keys()) != 1 {
		t.Errorf("non-PEM files should be ignored, got %d keys", len(km.Keys()))
	}
}

// TestComputeKID_Stable: a stable kid across loads is essential  clients
// cache keys by kid and would re-fetch JWKS on every token if the kid
// changed between restarts. Load the same file twice; the kid must match.
func TestComputeKID_Stable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	writeKey(t, path)

	first, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Errorf("kid changed between loads (%s → %s); breaks client caching",
			first.KeyID(), second.KeyID())
	}
}
