package config

import (
	"strings"
	"testing"
)

func TestIsValidProviderSlug(t *testing.T) {
	t.Parallel()
	cases := []struct {
		slug string
		want bool
	}{
		// accepted
		{"okta", true},
		{"microsoft", true},
		{"gitlab", true},
		{"mycorp_okta", true},
		{"auth0", true},
		{"a", true},
		{"keycloak_v2", true},

		// rejected: empty
		{"", false},

		// rejected: case / character class
		{"Okta", false},      // uppercase
		{"MICROSOFT", false}, // uppercase
		{"my-corp", false},   // hyphen
		{"my.corp", false},   // dot
		{"my corp", false},   // space
		{"my/corp", false},   // slash — would break URL routing
		{"my:corp", false},   // colon
		{"my\\corp", false},  // backslash
		{"foo!", false},
		{"foo+bar", false},
		{"foo@bar", false},

		// rejected: reserved built-ins
		{"google", false},
		{"github", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.slug, func(t *testing.T) {
			t.Parallel()
			got := isValidProviderSlug(c.slug)
			if got != c.want {
				t.Errorf("isValidProviderSlug(%q) = %v, want %v", c.slug, got, c.want)
			}
		})
	}
}

// TestLoadOIDCProvidersFromEnv exercises the env-loading path. We
// scope env mutations to each subtest using t.Setenv (which restores
// on teardown), so the tests don't interfere with each other.
func TestLoadOIDCProvidersFromEnv(t *testing.T) {
	t.Run("empty_returns_nil", func(t *testing.T) {
		t.Setenv("OIDC_PROVIDERS", "")
		got := loadOIDCProvidersFromEnv()
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("single_provider_full_config", func(t *testing.T) {
		t.Setenv("OIDC_PROVIDERS", "okta")
		t.Setenv("OIDC_OKTA_ISSUER", "https://acme.okta.com")
		t.Setenv("OIDC_OKTA_CLIENT_ID", "client-id-123")
		t.Setenv("OIDC_OKTA_CLIENT_SECRET", "shh")
		t.Setenv("OIDC_OKTA_DISPLAY_NAME", "Acme SSO")
		t.Setenv("OIDC_OKTA_SCOPES", "openid email profile groups")

		got := loadOIDCProvidersFromEnv()
		if len(got) != 1 {
			t.Fatalf("expected 1 provider, got %d", len(got))
		}
		p := got[0]
		if p.Slug != "okta" {
			t.Errorf("slug = %q", p.Slug)
		}
		if p.IssuerURL != "https://acme.okta.com" {
			t.Errorf("issuer = %q", p.IssuerURL)
		}
		if p.ClientID != "client-id-123" || p.ClientSecret != "shh" {
			t.Errorf("credentials lost in transit")
		}
		if p.DisplayName != "Acme SSO" {
			t.Errorf("display name = %q", p.DisplayName)
		}
		if len(p.Scopes) != 4 || p.Scopes[3] != "groups" {
			t.Errorf("scopes = %v", p.Scopes)
		}
	})

	t.Run("multiple_providers_order_preserved", func(t *testing.T) {
		t.Setenv("OIDC_PROVIDERS", "okta,auth0,keycloak")
		t.Setenv("OIDC_OKTA_ISSUER", "https://acme.okta.com")
		t.Setenv("OIDC_OKTA_CLIENT_ID", "o1")
		t.Setenv("OIDC_OKTA_CLIENT_SECRET", "o2")
		t.Setenv("OIDC_AUTH0_ISSUER", "https://acme.auth0.com")
		t.Setenv("OIDC_AUTH0_CLIENT_ID", "a1")
		t.Setenv("OIDC_AUTH0_CLIENT_SECRET", "a2")
		t.Setenv("OIDC_KEYCLOAK_ISSUER", "https://kc.internal/realms/acme")
		t.Setenv("OIDC_KEYCLOAK_CLIENT_ID", "k1")
		t.Setenv("OIDC_KEYCLOAK_CLIENT_SECRET", "k2")

		got := loadOIDCProvidersFromEnv()
		want := []string{"okta", "auth0", "keycloak"}
		if len(got) != len(want) {
			t.Fatalf("expected %d providers, got %d", len(want), len(got))
		}
		for i := range want {
			if got[i].Slug != want[i] {
				t.Errorf("position %d: slug = %q, want %q", i, got[i].Slug, want[i])
			}
		}
	})

	t.Run("invalid_slugs_dropped", func(t *testing.T) {
		// Hyphen, uppercase, and a reserved slug — all silently dropped
		// at the load step. Validate() will then catch operators who
		// supplied credentials for a slug that no longer appears.
		t.Setenv("OIDC_PROVIDERS", "okta,GitHub,my-corp,google,auth0")
		t.Setenv("OIDC_OKTA_ISSUER", "https://acme.okta.com")
		t.Setenv("OIDC_OKTA_CLIENT_ID", "o1")
		t.Setenv("OIDC_OKTA_CLIENT_SECRET", "o2")
		t.Setenv("OIDC_AUTH0_ISSUER", "https://acme.auth0.com")
		t.Setenv("OIDC_AUTH0_CLIENT_ID", "a1")
		t.Setenv("OIDC_AUTH0_CLIENT_SECRET", "a2")

		got := loadOIDCProvidersFromEnv()
		if len(got) != 2 {
			t.Fatalf("expected 2 surviving providers, got %d: %v", len(got), got)
		}
		if got[0].Slug != "okta" || got[1].Slug != "auth0" {
			t.Errorf("survivors out of order or wrong: %v", got)
		}
	})

	t.Run("whitespace_in_list_trimmed", func(t *testing.T) {
		// Operators tend to pad CSV with spaces — we shouldn't break.
		t.Setenv("OIDC_PROVIDERS", "  okta ,  auth0  ")
		t.Setenv("OIDC_OKTA_ISSUER", "https://x")
		t.Setenv("OIDC_OKTA_CLIENT_ID", "x")
		t.Setenv("OIDC_OKTA_CLIENT_SECRET", "x")
		t.Setenv("OIDC_AUTH0_ISSUER", "https://y")
		t.Setenv("OIDC_AUTH0_CLIENT_ID", "y")
		t.Setenv("OIDC_AUTH0_CLIENT_SECRET", "y")

		got := loadOIDCProvidersFromEnv()
		if len(got) != 2 {
			t.Fatalf("expected 2 providers, got %d", len(got))
		}
	})

	t.Run("scopes_default_left_empty_for_provider_to_apply", func(t *testing.T) {
		// We don't substitute defaults at the config layer — the
		// provider's New() does that. Empty here is the right shape.
		t.Setenv("OIDC_PROVIDERS", "okta")
		t.Setenv("OIDC_OKTA_ISSUER", "https://x")
		t.Setenv("OIDC_OKTA_CLIENT_ID", "x")
		t.Setenv("OIDC_OKTA_CLIENT_SECRET", "x")
		// no OIDC_OKTA_SCOPES

		got := loadOIDCProvidersFromEnv()
		if len(got[0].Scopes) != 0 {
			t.Errorf("expected empty scopes, got %v", got[0].Scopes)
		}
	})
}

// TestValidateOIDC_DuplicateSlug rejects two providers with the same
// slug. The deeper concern: identity rows in user_identities are keyed
// on (provider, sub), and a duplicate slug would silently link two
// different upstream accounts into a single identity row.
func TestValidateOIDC_DuplicateSlug(t *testing.T) {
	t.Parallel()
	c := Config{
		BaseURL:       "https://auth.example.com",
		SessionSecret: strings.Repeat("a", 32),
		DB:            DBConfig{URL: "postgres://x"},
		Log:           LogConfig{Level: "info", Format: "json"},
		Federation: FederationConfig{
			OIDC: []OIDCProviderConfig{
				{Slug: "okta", IssuerURL: "https://x", ClientID: "a", ClientSecret: "b"},
				{Slug: "okta", IssuerURL: "https://y", ClientID: "c", ClientSecret: "d"},
			},
		},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "declared more than once") {
		t.Fatalf("expected duplicate-slug error, got: %v", err)
	}
}

// TestValidateOIDC_IncompleteFails: each missing required field is
// named in the error message so the operator knows what to set.
func TestValidateOIDC_IncompleteFails(t *testing.T) {
	t.Parallel()
	c := Config{
		BaseURL:       "https://auth.example.com",
		SessionSecret: strings.Repeat("a", 32),
		DB:            DBConfig{URL: "postgres://x"},
		Log:           LogConfig{Level: "info", Format: "json"},
		Federation: FederationConfig{
			OIDC: []OIDCProviderConfig{
				{Slug: "okta"}, // everything else missing
			},
		},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, fragment := range []string{"OIDC_OKTA_ISSUER", "OIDC_OKTA_CLIENT_ID", "OIDC_OKTA_CLIENT_SECRET"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("error message missing %q:\n%v", fragment, err)
		}
	}
}

// TestValidateOIDC_HappyPath: a complete provider passes validation.
func TestValidateOIDC_HappyPath(t *testing.T) {
	t.Parallel()
	c := Config{
		BaseURL:       "https://auth.example.com",
		SessionSecret: strings.Repeat("a", 32),
		DB:            DBConfig{URL: "postgres://x"},
		Log:           LogConfig{Level: "info", Format: "json"},
		Federation: FederationConfig{
			OIDC: []OIDCProviderConfig{
				{
					Slug:         "okta",
					IssuerURL:    "https://acme.okta.com",
					ClientID:     "client",
					ClientSecret: "secret",
				},
			},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}
