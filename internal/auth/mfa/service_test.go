package mfa

import (
	"testing"

	"github.com/lusopoint/lusoiam/internal/crypto"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
)

// an IP address is not a valid WebAuthn RPID. The server must still start.
func TestNewDisablesWebAuthnOnInvalidRPID(t *testing.T) {
	s, err := New(Config{
		Store:           &postgres.Store{},
		Signer:          crypto.NewCookieSigner("test-secret"),
		WebAuthnRPID:    "192.168.1.10",
		WebAuthnOrigins: []string{"https://192.168.1.10"},
	})
	if err != nil {
		t.Fatalf("New() returned an error for an invalid RPID: %v", err)
	}
	if s.WebAuthnEnabled() {
		t.Fatal("WebAuthn is enabled for an invalid RPID")
	}
}
