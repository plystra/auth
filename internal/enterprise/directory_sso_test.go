package enterprise

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/db"
)

func TestDirectorySSOClaimConfigurationRejectsReassignableIdentifiersAndPaths(t *testing.T) {
	for _, claim := range []string{"email", "EMAIL", "preferred_username", "userName", "upn", "name", "displayName",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "", "profile.oid", "claims[oid]", "oid\n", strings.Repeat("x", 513)} {
		if validDirectoryIdentityClaim(claim) {
			t.Errorf("unsafe claim accepted: %q", claim)
		}
	}
	for _, claim := range []string{"sub", "NameID", "oid", "employee_id", "http://schemas.microsoft.com/identity/claims/objectidentifier"} {
		if !validDirectoryIdentityClaim(claim) {
			t.Errorf("stable claim rejected: %q", claim)
		}
	}
}

func TestDirectorySSOClaimRequiresOneExactVerifiedString(t *testing.T) {
	for _, provider := range []string{"oidc", "saml"} {
		t.Run(provider, func(t *testing.T) {
			connection := db.SsoConnection{Provider: provider}
			claims := idTokenClaims{Subject: "Exact-Subject", VerifiedClaims: map[string]json.RawMessage{"oid": json.RawMessage(`"Exact-Object"`)},
				SAMLAttributes: map[string][]string{"oid": {"Exact-Object"}}}
			subjectClaim := "sub"
			if provider == "saml" {
				subjectClaim = "NameID"
			}
			if value, err := directoryIdentityValue(connection, subjectClaim, claims); err != nil || value != "Exact-Subject" {
				t.Fatalf("stable subject = %q %v", value, err)
			}
			value, err := directoryIdentityValue(connection, "oid", claims)
			if err != nil || value != "Exact-Object" {
				t.Fatalf("stable value = %q %v", value, err)
			}
			for _, raw := range []string{`["Exact-Object"]`, "null", `{"value":"Exact-Object"}`, `""`, "42"} {
				claims.VerifiedClaims["oid"] = json.RawMessage(raw)
				claims.SAMLAttributes["oid"] = []string{"Exact-Object", "Other"}
				if _, err := directoryIdentityValue(connection, "oid", claims); err == nil {
					t.Fatalf("ambiguous or invalid stable value accepted for %s", provider)
				}
			}
		})
	}
}
