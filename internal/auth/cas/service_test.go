package cas

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/lusopoint/lusoiam/internal/store/postgres"
	"github.com/lusopoint/lusoiam/internal/store/postgrestest"
)

// sharedStore is provisioned once in TestMain and reused by every test in
// this file (see internal/oidc/service_test.go for the same pattern and
// rationale). Every test must use unique fixture values.
var sharedStore *postgres.Store

func TestMain(m *testing.M) {
	store, cleanup, err := postgrestest.Start(context.Background(), "iam_test_cas")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cas: skipping integration tests, could not reach postgres (try `make compose-dev-up`): %v\n", err)
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

func newTestUser(t *testing.T) *postgres.User {
	t.Helper()
	email := uniqueName("user") + "@example.com"
	u, err := sharedStore.CreateUser(context.Background(), postgres.CreateUserParams{Email: &email})
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return u
}

func newTestSession(t *testing.T, userID pgtype.UUID) *postgres.Session {
	t.Helper()
	sess, err := sharedStore.CreateSession(context.Background(), postgres.CreateSessionParams{
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create test session: %v", err)
	}
	return sess
}

// newTestCASService registers a CAS service for pattern (in the
// URL-pattern syntax with '*' wildcards, converted via the real
// PatternToLike helper so tests exercise the same conversion production
// code uses) and returns the registered service row.
func newTestCASService(t *testing.T, pattern string) *postgres.CASService {
	t.Helper()
	svc, err := sharedStore.CreateCASService(context.Background(), postgres.CreateCASServiceParams{
		Name:               uniqueName("service"),
		ServiceURLPattern:  pattern,
		MatchPattern:       PatternToLike(pattern),
		ReleasedAttributes: []string{},
	})
	if err != nil {
		t.Fatalf("create test cas service: %v", err)
	}
	return svc
}

// --- ResolveService ---------------------------------------------------

func TestResolveService_EmptyURL(t *testing.T) {
	svc := New(sharedStore)
	_, err := svc.ResolveService(context.Background(), "")
	if !errors.Is(err, ErrUnauthorizedService) {
		t.Errorf("got %v, want ErrUnauthorizedService", err)
	}
}

func TestResolveService_NotRegistered(t *testing.T) {
	svc := New(sharedStore)
	_, err := svc.ResolveService(context.Background(), "https://"+uniqueName("nowhere")+".example.com/")
	if !errors.Is(err, ErrUnauthorizedService) {
		t.Errorf("got %v, want ErrUnauthorizedService", err)
	}
}

func TestResolveService_ExactMatch(t *testing.T) {
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	registered := newTestCASService(t, "https://"+host+"/callback")

	got, err := svc.ResolveService(context.Background(), "https://"+host+"/callback")
	if err != nil {
		t.Fatalf("ResolveService: %v", err)
	}
	if got.ID != registered.ID {
		t.Errorf("resolved service %v, want %v", got.ID, registered.ID)
	}
}

func TestResolveService_WildcardMatch(t *testing.T) {
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")

	_, err := svc.ResolveService(context.Background(), "https://"+host+"/some/deep/path?x=1")
	if err != nil {
		t.Fatalf("ResolveService should match the wildcard pattern: %v", err)
	}
}

func TestResolveService_WildcardDoesNotMatchOtherHost(t *testing.T) {
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")

	_, err := svc.ResolveService(context.Background(), "https://evil-"+host+"/anything")
	if !errors.Is(err, ErrUnauthorizedService) {
		t.Errorf("got %v, want ErrUnauthorizedService for an unregistered host", err)
	}
}

// --- IssueServiceTicket + Validate --------------------------------------

func TestValidate_MalformedTicketRejectedWithoutTouchingStore(t *testing.T) {
	// Tickets not shaped "ST-..." are rejected before any store call, so
	// this is safe to run even against a service backed by a nil store.
	svc := New(nil)
	_, err := svc.Validate(context.Background(), "not-a-cas-ticket", "https://app.example.com/")
	if !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("got %v, want ErrInvalidTicket", err)
	}
}

func TestIssueAndValidate_HappyPath(t *testing.T) {
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	serviceURL := "https://" + host + "/callback"
	ticket, err := svc.IssueServiceTicket(context.Background(), sess.ID, serviceURL, false)
	if err != nil {
		t.Fatalf("IssueServiceTicket: %v", err)
	}
	if ticket == "" {
		t.Fatal("expected a non-empty ticket")
	}

	result, err := svc.Validate(context.Background(), ticket, serviceURL)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.User.ID != user.ID {
		t.Errorf("resolved user %v, want %v", result.User.ID, user.ID)
	}
	if result.Session.ID != sess.ID {
		t.Errorf("resolved session %v, want %v", result.Session.ID, sess.ID)
	}
}

func TestValidate_TicketIsSingleUse(t *testing.T) {
	// The core CAS security property: a service ticket presented to
	// serviceValidate a second time must be rejected otherwise a
	// ticket sniffed off the wire (it travels in a URL query param) is
	// replayable indefinitely.
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	serviceURL := "https://" + host + "/callback"
	ticket, err := svc.IssueServiceTicket(context.Background(), sess.ID, serviceURL, false)
	if err != nil {
		t.Fatalf("IssueServiceTicket: %v", err)
	}

	if _, err := svc.Validate(context.Background(), ticket, serviceURL); err != nil {
		t.Fatalf("first validate: unexpected error: %v", err)
	}
	if _, err := svc.Validate(context.Background(), ticket, serviceURL); !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("replayed ticket: got %v, want ErrInvalidTicket", err)
	}
}

func TestValidate_ServiceURLMismatchRejected(t *testing.T) {
	// A ticket minted for one service URL must not validate against a
	// different one, even under the same registered CAS service pattern.
	svc := New(sharedStore)
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	issuedFor := "https://" + host + "/callback-a"
	ticket, err := svc.IssueServiceTicket(context.Background(), sess.ID, issuedFor, false)
	if err != nil {
		t.Fatalf("IssueServiceTicket: %v", err)
	}

	_, err = svc.Validate(context.Background(), ticket, "https://"+host+"/callback-b")
	if !errors.Is(err, ErrServiceMismatch) {
		t.Errorf("got %v, want ErrServiceMismatch", err)
	}
}

func TestValidate_UnknownTicketRejected(t *testing.T) {
	svc := New(sharedStore)
	_, err := svc.Validate(context.Background(), "ST-"+uniqueName("nonexistent"), "https://app.example.com/")
	if !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("got %v, want ErrInvalidTicket", err)
	}
}

func TestValidate_ExpiredTicketRejected(t *testing.T) {
	// Bypass IssueServiceTicket's fixed 60s TTL by inserting the ticket
	// row directly, already expired, to test the expiry check without
	// sleeping in the test suite.
	host := uniqueName("app") + ".example.com"
	newTestCASService(t, "https://"+host+"/*")
	user := newTestUser(t)
	sess := newTestSession(t, user.ID)

	serviceURL := "https://" + host + "/callback"
	ticketID := "ST-" + uniqueName("expired")
	err := sharedStore.CreateCASTicket(context.Background(), postgres.CreateCASTicketParams{
		ID:         ticketID,
		SessionID:  sess.ID,
		ServiceURL: normalizeServiceURL(serviceURL),
		ExpiresAt:  time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("insert expired ticket: %v", err)
	}

	svc := New(sharedStore)
	_, err = svc.Validate(context.Background(), ticketID, serviceURL)
	if !errors.Is(err, ErrInvalidTicket) {
		t.Errorf("got %v, want ErrInvalidTicket for an expired ticket", err)
	}
}

// --- PatternToLike / normalizeServiceURL (pure, no DB) -------------------

func TestPatternToLike(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com/*": "https://app.example.com/%",
		"https://*.example.com/cb":  "https://%.example.com/cb",
		"https://x.com/100%off":     `https://x.com/100\%off`,
		"a_b":                       `a\_b`,
	}
	for in, want := range cases {
		if got := PatternToLike(in); got != want {
			t.Errorf("PatternToLike(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeServiceURL_StripsTicketParamAndFragment(t *testing.T) {
	in := "https://App.Example.com/cb?foo=bar&ticket=ST-old-123#frag"
	got := normalizeServiceURL(in)
	want := "https://app.example.com/cb?foo=bar"
	if got != want {
		t.Errorf("normalizeServiceURL(%q) = %q, want %q", in, got, want)
	}
}
