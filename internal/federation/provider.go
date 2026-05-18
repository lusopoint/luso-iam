// Package federation defines the Provider interface that every upstream
// identity provider must implement, and the Identity struct that carries
// a normalized user record across all providers.
//
// Each upstream provider (Google, GitHub, generic OIDC, …) lives in its
// own sub-package and implements this interface.
package federation

import "context"

// Identity is the normalized user record returned by any provider after a
// successful token exchange. Field availability varies by provider — for
// example, GitHub doesn't guarantee an email address is public.
//
// This struct maps directly to the fields we store in user_identities and
// the attributes we release via CAS 3.0 / OIDC.
type Identity struct {
	// Sub is the provider's stable, unique identifier for this user.
	// For OIDC providers it is the `sub` claim; for GitHub it is the
	// integer user ID rendered as a string.
	Sub string

	// Email is the user's primary email, lower-cased. May be empty for
	// GitHub users who have made their email private.
	Email string

	// Name is the user's display name (full name or username).
	Name string

	// Picture is a URL to the user's avatar. May be empty.
	Picture string

	// RawClaims contains the full token claims / API user object so we
	// can store it for audit and future attribute release.
	RawClaims map[string]any
}

// Provider is the contract every upstream IdP must satisfy.
type Provider interface {
	// Name returns the provider's slug ("google", "github", …).
	// Used in redirect URLs and as the provider column in user_identities.
	Name() string

	// AuthURL builds the authorization redirect URL. The caller supplies
	// a cryptographically random state for CSRF protection and the S256
	// code_challenge for PKCE.
	AuthURL(state, codeChallenge string) string

	// Exchange redeems an authorization code for an Identity.
	// The codeVerifier is the PKCE verifier matching the challenge sent
	// in the initial AuthURL call.
	Exchange(ctx context.Context, code, codeVerifier string) (*Identity, error)
}
