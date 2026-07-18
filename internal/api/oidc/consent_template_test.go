package oidc

import "testing"

func TestConsentTemplateResolves(t *testing.T) {
	if _, ok := oidcTemplates["consent.html"]; !ok {
		t.Error("renderConsent renders consent.html but no such template was parsed")
	}
}
