package mfa

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

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

// ForceMFA off means no user can be in the enrollment-required state, so the
// check returns without a store query.
func TestEnrollmentRequiredForUserForceOff(t *testing.T) {
	s, err := New(Config{
		Store:  &postgres.Store{},
		Signer: crypto.NewCookieSigner("test-secret"),
	})
	if err != nil {
		t.Fatalf("New() returned an error: %v", err)
	}
	required, err := s.EnrollmentRequiredForUser(context.Background(), pgtype.UUID{})
	if err != nil {
		t.Fatalf("EnrollmentRequiredForUser() returned an error: %v", err)
	}
	if required {
		t.Fatal("enrollment is required with ForceMFA off")
	}
}
