package cas

import "encoding/json"

// CAS validation responses in JSON form, matching the Apereo CAS
// `format=json` convention. The shape is:
//
//	{
//	  "serviceResponse": {
//	    "authenticationSuccess": { "user": "...", "attributes": { ... } }
//	  }
//	}
//
//	{
//	  "serviceResponse": {
//	    "authenticationFailure": { "code": "INVALID_TICKET", "description": "..." }
//	  }
//	}
//
// Two things worth flagging for anyone touching this:
//
//  1. **Attribute values are arrays of strings**, never bare strings. LDAP
//     attributes can be multi-valued (think `memberOf`), and Apereo's
//     format preserves that even when there's only one value. Real CAS
//     clients depend on this — they unconditionally `[0]` into the value
//     and would crash on a bare string. We always emit single-element
//     arrays because our user model is single-valued, but the wrapping
//     stays.
//
//  2. Field name `description` in the failure body is the JSON convention.
//     The XML form puts the same text as element character-data on
//     `<cas:authenticationFailure>` — Apereo's translator renames it on
//     the JSON side, and clients (including the one we're integrating
//     with today) read `authenticationFailure.description`.

type jsonResponse struct {
	ServiceResponse jsonServiceResponse `json:"serviceResponse"`
}

type jsonServiceResponse struct {
	// Exactly one of these is non-nil for any given response.
	AuthenticationSuccess *jsonAuthSuccess `json:"authenticationSuccess,omitempty"`
	AuthenticationFailure *jsonAuthFailure `json:"authenticationFailure,omitempty"`
}

type jsonAuthSuccess struct {
	User       string              `json:"user"`
	Attributes map[string][]string `json:"attributes,omitempty"`
}

type jsonAuthFailure struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

// marshalJSONSuccess builds the success envelope. attrs may be nil — in
// which case the response carries `"user"` and nothing else, mirroring
// the no-attribute-release case in the XML response.
func marshalJSONSuccess(user string, attrs map[string]string) ([]byte, error) {
	out := jsonResponse{
		ServiceResponse: jsonServiceResponse{
			AuthenticationSuccess: &jsonAuthSuccess{User: user},
		},
	}
	if len(attrs) > 0 {
		wrapped := make(map[string][]string, len(attrs))
		for k, v := range attrs {
			// Single-element array — see note (1) above.
			wrapped[k] = []string{v}
		}
		out.ServiceResponse.AuthenticationSuccess.Attributes = wrapped
	}
	return json.Marshal(out)
}

// marshalJSONFailure builds the failure envelope.
func marshalJSONFailure(code, description string) ([]byte, error) {
	return json.Marshal(jsonResponse{
		ServiceResponse: jsonServiceResponse{
			AuthenticationFailure: &jsonAuthFailure{
				Code:        code,
				Description: description,
			},
		},
	})
}
