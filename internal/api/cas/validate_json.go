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
//	{
//	  "serviceResponse": {
//	    "authenticationFailure": { "code": "INVALID_TICKET", "description": "..." }
//	  }
//	}
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

func marshalJSONSuccess(user string, attrs map[string]string) ([]byte, error) {
	out := jsonResponse{
		ServiceResponse: jsonServiceResponse{
			AuthenticationSuccess: &jsonAuthSuccess{User: user},
		},
	}
	if len(attrs) > 0 {
		wrapped := make(map[string][]string, len(attrs))
		for k, v := range attrs {
			// single-element array
			wrapped[k] = []string{v}
		}
		out.ServiceResponse.AuthenticationSuccess.Attributes = wrapped
	}
	return json.Marshal(out)
}

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
