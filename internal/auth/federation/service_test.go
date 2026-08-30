package federation

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lusopoint/lusoiam/internal/federation"
	"github.com/lusopoint/lusoiam/internal/store/postgres"
	"github.com/lusopoint/lusoiam/internal/store/postgrestest"
)

// sharedStore is provisioned once in TestMain and reused by every test in
// this file (see internal/oidc/service_test.go for the same pattern and
// rationale). Every test must use unique fixture values.
var sharedStore *postgres.Store

func TestMain(m *testing.M) {
	store, cleanup, err := postgrestest.Start(context.Background(), "iam_test_federation")
	if err != nil {
		fmt.Fprintf(os.Stderr, "federation: skipping integration tests, could not reach postgres (try `make compose-dev-up`): %v\n", err)
		os.Exit(0)
	}
	sharedStore = store
	code := m.Run()
	cleanup()
	os.Exit(code)
}

var seq int64

func uniqueName(prefix string) string {
	n := atomic.AddInt64(&seq, 1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func newLocalUser(t *testing.T, email string) *postgres.User {
	t.Helper()
	u, err := sharedStore.CreateUser(context.Background(), postgres.CreateUserParams{Email: &email})
	if err != nil {
		t.Fatalf("create local user: %v", err)
	}
	return u
}

// TestLinkOrCreate_VerifiedEmailAutoLinksToExistingAccount is the intended,
// safe use of auto-link: a provider that attests it verified the email
// should link into the matching local account.
func TestLinkOrCreate_VerifiedEmailAutoLinksToExistingAccount(t *testing.T) {
	svc := New(sharedStore)
	email := uniqueName("victim") + "@example.com"
	local := newLocalUser(t, email)

	identity := &federation.Identity{
		Sub:           uniqueName("sub"),
		Email:         email,
		EmailVerified: true,
		Name:          "Legit User",
	}

	got, isNew, err := svc.LinkOrCreate(context.Background(), "google", identity)
	if err != nil {
		t.Fatalf("LinkOrCreate: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false when linking to an existing account")
	}
	if got.ID != local.ID {
		t.Errorf("linked to user %v, want %v", got.ID, local.ID)
	}

	stored, err := sharedStore.GetUserByProviderSub(context.Background(), "google", identity.Sub)
	if err != nil {
		t.Fatalf("GetUserByProviderSub after link: %v", err)
	}
	if stored.ID != local.ID {
		t.Errorf("identity row points at %v, want %v", stored.ID, local.ID)
	}
}

// TestLinkOrCreate_UnverifiedEmailDoesNotAutoLink is the regression test for
// the account-takeover gap: a provider claiming an email it did not verify
// must never be merged into the account that owns that email otherwise
// anyone who can get a permissive/misconfigured provider to assert a
// victim's address takes over the victim's account.
func TestLinkOrCreate_UnverifiedEmailDoesNotAutoLink(t *testing.T) {
	svc := New(sharedStore)
	email := uniqueName("victim") + "@example.com"
	victim := newLocalUser(t, email)

	attacker := &federation.Identity{
		Sub:           uniqueName("attacker-sub"),
		Email:         email,
		EmailVerified: false,
		Name:          "Attacker",
	}

	got, isNew, err := svc.LinkOrCreate(context.Background(), "generic_oidc", attacker)
	if err != nil {
		t.Fatalf("LinkOrCreate: %v", err)
	}
	if !isNew {
		t.Fatal("expected a new, separate account to be created, not linked to the victim's")
	}
	if got.ID == victim.ID {
		t.Fatal("attacker's unverified-email identity was linked to the victim's account")
	}

	// The victim's own account must still have no identity linked to it.
	if _, err := sharedStore.GetUserByProviderSub(context.Background(), "generic_oidc", attacker.Sub); err != nil {
		t.Fatalf("attacker identity should still be linked to their own new account: %v", err)
	}
}

// TestLinkOrCreate_KnownIdentityLogsInRegardlessOfVerification covers the
// returning-user path: once an identity is already linked, subsequent
// logins go through GetUserByProviderSub and never re-run the email-match
// logic, so EmailVerified is irrelevant here.
func TestLinkOrCreate_KnownIdentityLogsInRegardlessOfVerification(t *testing.T) {
	svc := New(sharedStore)
	email := uniqueName("user") + "@example.com"

	identity := &federation.Identity{
		Sub:           uniqueName("sub"),
		Email:         email,
		EmailVerified: true,
		Name:          "First Login",
	}
	first, isNew, err := svc.LinkOrCreate(context.Background(), "google", identity)
	if err != nil {
		t.Fatalf("first LinkOrCreate: %v", err)
	}
	if !isNew {
		t.Fatal("expected isNew=true on first login")
	}

	identity.EmailVerified = false // provider stops asserting verification; should not matter now
	second, isNew, err := svc.LinkOrCreate(context.Background(), "google", identity)
	if err != nil {
		t.Fatalf("second LinkOrCreate: %v", err)
	}
	if isNew {
		t.Error("expected isNew=false on the second login for a known identity")
	}
	if second.ID != first.ID {
		t.Errorf("second login resolved to %v, want %v", second.ID, first.ID)
	}
}

// TestLinkOrCreate_NoEmailCreatesNewUser covers providers that return no
// email at all (e.g. a GitHub user with a fully private email) should
// behave like the unverified case: create a new user, no email-based
// linking attempted.
func TestLinkOrCreate_NoEmailCreatesNewUser(t *testing.T) {
	svc := New(sharedStore)
	identity := &federation.Identity{
		Sub:  uniqueName("sub"),
		Name: "No Email User",
	}

	got, isNew, err := svc.LinkOrCreate(context.Background(), "github", identity)
	if err != nil {
		t.Fatalf("LinkOrCreate: %v", err)
	}
	if !isNew {
		t.Error("expected isNew=true")
	}
	if got.Email != nil {
		t.Errorf("expected no email on the created user, got %v", *got.Email)
	}
}
