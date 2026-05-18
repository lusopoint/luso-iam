package cas

import (
	"encoding/json"
	"testing"
)

// TestJSONSuccessShape pins the exact wire shape clients depend on.
//
// Notably:
//   - The top-level wrapper key is `serviceResponse` (camelCase).
//   - On success, exactly one sub-key: `authenticationSuccess`.
//   - `attributes` is a map[string][]string — every value MUST be an
//     array, even when there's only one entry, because real CAS clients
//     unconditionally index `[0]` into attribute values (LDAP attrs are
//     multi-valued, and Apereo preserves that shape).
//
// If this test starts failing because someone "simplified" attribute
// values to bare strings, that's a breaking change for every CAS
// client integration — back it out.
func TestJSONSuccessShape(t *testing.T) {
	t.Parallel()

	body, err := marshalJSONSuccess("alice", map[string]string{
		"email":       "alice@example.com",
		"displayName": "Alice Smith",
	})
	if err != nil {
		t.Fatalf("marshalJSONSuccess: %v", err)
	}

	// Decode into a permissive shape to inspect.
	var got struct {
		ServiceResponse struct {
			Success *struct {
				User       string              `json:"user"`
				Attributes map[string][]string `json:"attributes"`
			} `json:"authenticationSuccess"`
			Failure any `json:"authenticationFailure"`
		} `json:"serviceResponse"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}

	if got.ServiceResponse.Success == nil {
		t.Fatalf("authenticationSuccess missing: %s", body)
	}
	if got.ServiceResponse.Failure != nil {
		t.Fatalf("authenticationFailure must be absent on success: %s", body)
	}
	if got.ServiceResponse.Success.User != "alice" {
		t.Errorf("user: got %q, want alice", got.ServiceResponse.Success.User)
	}
	// The array-wrapping is the critical property.
	if email := got.ServiceResponse.Success.Attributes["email"]; len(email) != 1 || email[0] != "alice@example.com" {
		t.Errorf("email attribute: got %v, want [alice@example.com]", email)
	}
	if name := got.ServiceResponse.Success.Attributes["displayName"]; len(name) != 1 || name[0] != "Alice Smith" {
		t.Errorf("displayName attribute: got %v, want [Alice Smith]", name)
	}
}

// TestJSONSuccessNoAttributes: when attrs is nil we still emit a clean
// envelope. CAS 2.0 endpoints take this path — the user identifier is
// the only thing released.
func TestJSONSuccessNoAttributes(t *testing.T) {
	t.Parallel()
	body, err := marshalJSONSuccess("alice", nil)
	if err != nil {
		t.Fatalf("marshalJSONSuccess: %v", err)
	}
	var got struct {
		ServiceResponse struct {
			Success *struct {
				User       string              `json:"user"`
				Attributes map[string][]string `json:"attributes"`
			} `json:"authenticationSuccess"`
		} `json:"serviceResponse"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if got.ServiceResponse.Success.User != "alice" {
		t.Errorf("user: got %q, want alice", got.ServiceResponse.Success.User)
	}
	// Attributes block must be omitted (omitempty), not an empty object.
	// An empty object would still let clients index into it and pull
	// undefined, but the omitempty matches Apereo's behaviour exactly.
	if got.ServiceResponse.Success.Attributes != nil {
		t.Errorf("attributes should be omitted when nil, got %v", got.ServiceResponse.Success.Attributes)
	}
}

// TestJSONFailureShape: failure envelope, including the rename from the
// XML element character-data to the JSON `description` field.
func TestJSONFailureShape(t *testing.T) {
	t.Parallel()

	body, err := marshalJSONFailure("INVALID_TICKET", "Ticket not recognized.")
	if err != nil {
		t.Fatalf("marshalJSONFailure: %v", err)
	}
	var got struct {
		ServiceResponse struct {
			Success *any `json:"authenticationSuccess"`
			Failure *struct {
				Code        string `json:"code"`
				Description string `json:"description"`
			} `json:"authenticationFailure"`
		} `json:"serviceResponse"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}

	if got.ServiceResponse.Success != nil {
		t.Errorf("authenticationSuccess must be absent on failure: %s", body)
	}
	if got.ServiceResponse.Failure == nil {
		t.Fatalf("authenticationFailure missing: %s", body)
	}
	if got.ServiceResponse.Failure.Code != "INVALID_TICKET" {
		t.Errorf("code: got %q, want INVALID_TICKET", got.ServiceResponse.Failure.Code)
	}
	if got.ServiceResponse.Failure.Description != "Ticket not recognized." {
		t.Errorf("description: got %q", got.ServiceResponse.Failure.Description)
	}
}
