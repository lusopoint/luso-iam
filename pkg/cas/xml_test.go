package cas_test

import (
	"encoding/xml"
	"strings"
	"testing"

	cas "github.com/lusopoint/lusoiam/pkg/cas"
)

// TestSuccessNoAttributes is the CAS 2.0 shape — just <cas:user>.
// Any CAS-2.0 client validating a ticket expects exactly this envelope.
// We marshal, then walk the bytes to assert structural properties
// rather than pinning whitespace: encoding/xml's output is stable but
// not promise-compatible across Go versions.
func TestSuccessNoAttributes(t *testing.T) {
	t.Parallel()
	r := cas.NewSuccess("alice", nil)
	out, err := xml.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)

	if !strings.Contains(s, `<cas:serviceResponse xmlns:cas="`+cas.XMLNamespace+`">`) {
		t.Errorf("missing serviceResponse with cas namespace: %s", s)
	}
	if !strings.Contains(s, `<cas:authenticationSuccess>`) {
		t.Errorf("missing authenticationSuccess element: %s", s)
	}
	if !strings.Contains(s, `<cas:user>alice</cas:user>`) {
		t.Errorf("missing or wrong user element: %s", s)
	}
	// CAS 2.0: no <cas:attributes> block when attrs is nil.
	if strings.Contains(s, `<cas:attributes>`) {
		t.Errorf("unexpected attributes block for CAS 2.0 envelope: %s", s)
	}
}

// TestSuccessWithAttributes is the CAS 3.0 / p3 shape. The attribute
// element names must be prefixed "cas:" because CAS clients expect the
// release to live in the cas namespace.
func TestSuccessWithAttributes(t *testing.T) {
	t.Parallel()
	r := cas.NewSuccess("alice", map[string]string{
		"email":      "alice@example.com",
		"first_name": "Alice",
	})
	out, err := xml.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)

	if !strings.Contains(s, `<cas:attributes>`) {
		t.Errorf("expected attributes block, got: %s", s)
	}
	if !strings.Contains(s, `<cas:email>alice@example.com</cas:email>`) {
		t.Errorf("missing cas:email element: %s", s)
	}
	if !strings.Contains(s, `<cas:first_name>Alice</cas:first_name>`) {
		t.Errorf("missing cas:first_name element: %s", s)
	}
}

// TestSuccessEscapesUsername: XML-special characters in the username
// must be escaped. Failing to escape would let an attacker break out
// of the cas:user element and inject arbitrary XML — the CAS validator
// might honour an attacker-controlled attribute. encoding/xml does
// this for us, but we verify the property explicitly.
func TestSuccessEscapesUsername(t *testing.T) {
	t.Parallel()
	r := cas.NewSuccess(`<script>alert(1)</script>`, nil)
	out, err := xml.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "<script>") {
		t.Errorf("username not escaped — raw <script> present: %s", s)
	}
	if !strings.Contains(s, "&lt;script&gt;") {
		t.Errorf("expected escaped tag, got: %s", s)
	}
}

// TestFailureFormat: <cas:authenticationFailure code="X">message</cas:authenticationFailure>.
// Code goes on the attribute, message as element text.
func TestFailureFormat(t *testing.T) {
	t.Parallel()
	r := cas.NewFailure(cas.FailureInvalidTicket, "Ticket not recognised.")
	out, err := xml.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(out)

	if !strings.Contains(s, `code="INVALID_TICKET"`) {
		t.Errorf("missing or wrong failure code attribute: %s", s)
	}
	if !strings.Contains(s, `>Ticket not recognised.</cas:authenticationFailure>`) {
		t.Errorf("missing failure message: %s", s)
	}
	if !strings.Contains(s, `<cas:serviceResponse xmlns:cas="`+cas.XMLNamespace+`">`) {
		t.Errorf("missing serviceResponse with cas namespace: %s", s)
	}
}

// TestFailureCodes: all the named constants are valid CAS failure
// codes. This is more documentation-as-test than logic — if someone
// renames a constant we want CI to flag it.
func TestFailureCodes(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"FailureInvalidRequest":      "INVALID_REQUEST",
		"FailureInvalidTicketSpec":   "INVALID_TICKET_SPEC",
		"FailureUnauthorizedService": "UNAUTHORIZED_SERVICE",
		"FailureInvalidTicket":       "INVALID_TICKET",
		"FailureInvalidService":      "INVALID_SERVICE",
		"FailureInternalError":       "INTERNAL_ERROR",
	}
	got := map[string]string{
		"FailureInvalidRequest":      cas.FailureInvalidRequest,
		"FailureInvalidTicketSpec":   cas.FailureInvalidTicketSpec,
		"FailureUnauthorizedService": cas.FailureUnauthorizedService,
		"FailureInvalidTicket":       cas.FailureInvalidTicket,
		"FailureInvalidService":      cas.FailureInvalidService,
		"FailureInternalError":       cas.FailureInternalError,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
