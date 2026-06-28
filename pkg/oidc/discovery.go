// Package oidc provides exported types for the OIDC protocol layer.
// No internal dependencies — safe to import from any package.
package oidc

// DiscoveryDocument is the JSON body of
// GET /.well-known/openid-configuration (OIDC Discovery 1.0 §4).
// Only the fields required by the spec and used by common OIDC clients
// are included; unknown fields are silently ignored by well-behaved clients.
type DiscoveryDocument struct {
	// REQUIRED fields
	Issuer                  string   `json:"issuer"`
	AuthorizationEndpoint   string   `json:"authorization_endpoint"`
	TokenEndpoint           string   `json:"token_endpoint"`
	JWKSURI                 string   `json:"jwks_uri"`
	ResponseTypesSupported  []string `json:"response_types_supported"`
	SubjectTypesSupported   []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues []string `json:"id_token_signing_alg_values_supported"`

	// RECOMMENDED fields
	UserinfoEndpoint              string   `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	ClaimsSupported               []string `json:"claims_supported,omitempty"`
	GrantTypesSupported           []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpoint         string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint            string   `json:"revocation_endpoint,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	ACRValuesSupported            []string `json:"acr_values_supported,omitempty"`
	AMRValuesSupported            []string `json:"amr_values_supported,omitempty"`
	ClaimsParameterSupported      bool     `json:"claims_parameter_supported"`
	RequestParameterSupported     bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported  bool     `json:"request_uri_parameter_supported"`
}
