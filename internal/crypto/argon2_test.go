package crypto

import (
	"errors"
	"strings"
	"testing"
)

// TestArgon2RoundTrip is the happy path: hash a password, then verify it
// with VerifyPassword. The hash format must contain the parameter set
// inline so we can also check it's well-formed PHC.
func TestArgon2RoundTrip(t *testing.T) {
	t.Parallel()
	const pwd = "correct horse battery staple"
	hash, err := HashPassword(pwd)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// Sanity check the PHC shape. Six $-separated parts: leading empty,
	// algo, version, params, salt, hash. We don't pin exact values
	// (those are tied to argonTime/Memory/Threads constants), but we do
	// require the algorithm prefix.
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash lacks argon2id prefix: %q", hash)
	}
	if n := strings.Count(hash, "$"); n != 5 {
		t.Fatalf("hash has %d $ separators, want 5: %q", n, hash)
	}

	ok, err := VerifyPassword(pwd, hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword returned false for correct password")
	}
}

// TestArgon2WrongPassword: same hash, different password → no error,
// ok=false. Error is reserved for malformed hashes.
func TestArgon2WrongPassword(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword("hunter3", hash)
	if err != nil {
		t.Fatalf("VerifyPassword returned error for wrong-password case: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword accepted wrong password")
	}
}

// TestArgon2DifferentSaltsPerHash: hashing the same password twice must
// produce different outputs (the salt is random per call). Without
// this, two users with the same password would have identical PHC strings.
func TestArgon2DifferentSaltsPerHash(t *testing.T) {
	t.Parallel()
	const pwd = "same password"
	a, _ := HashPassword(pwd)
	b, _ := HashPassword(pwd)
	if a == b {
		t.Fatalf("two hashes of the same password are identical — salt isn't random?\n%q", a)
	}
}

// TestArgon2MalformedHash: VerifyPassword should return ErrInvalidHash
// (wrapped) for anything that isn't a recognisable PHC string. Catching
// these as errors rather than ok=false lets the caller distinguish
// "wrong password" from "database corruption".
func TestArgon2MalformedHash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"no_dollar", "argon2idsomething"},
		{"wrong_algo", "$bcrypt$v=19$m=65536,t=3,p=4$abc$def"},
		{"missing_parts", "$argon2id$v=19$abc$def"},
		{"bad_version_str", "$argon2id$vXX$m=65536,t=3,p=4$abc$def"},
		{"bad_params", "$argon2id$v=19$bogus$abc$def"},
		{"bad_base64_salt", "$argon2id$v=19$m=65536,t=3,p=4$!!!notb64!!!$def"},
		{"bad_base64_hash", "$argon2id$v=19$m=65536,t=3,p=4$YWJj$!!!notb64!!!"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := VerifyPassword("anything", c.hash)
			if err == nil {
				t.Fatalf("expected error for malformed hash, got nil")
			}
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("expected ErrInvalidHash, got: %v", err)
			}
		})
	}
}

// TestArgon2TamperedHash: flipping a single byte of the hash portion
// must cause verification to fail. The format is still well-formed PHC,
// so the failure shows up as ok=false (not as an error).
func TestArgon2TamperedHash(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("legit password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// Flip a character somewhere safely in the hash segment — the last
	// few characters of the PHC string. Walking back from end avoids
	// hitting padding or separator territory.
	idx := len(hash) - 4
	flipped := []byte(hash)
	if flipped[idx] == 'a' {
		flipped[idx] = 'b'
	} else {
		flipped[idx] = 'a'
	}
	ok, err := VerifyPassword("legit password", string(flipped))
	if err != nil {
		// Some flips may yield invalid base64 — that's fine for our
		// purpose; we just want to ensure ok != true.
		return
	}
	if ok {
		t.Fatal("tampered hash verified as ok=true")
	}
}
