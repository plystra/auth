package enterprise

import (
	"strings"
	"testing"

	"github.com/plystra/auth/internal/secret"
)

func TestSSOConnectionSecretsUseAuthenticatedEncryption(t *testing.T) {
	svc := &Service{DataKey: secret.New(strings.Repeat("d", 32))}
	secretText := "oidc-client-secret"
	ciphertext, err := svc.seal([]byte(secretText), clientSecretAAD)
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == secretText || strings.Contains(string(ciphertext), secretText) {
		t.Fatal("client secret was stored as plaintext")
	}
	opened, err := svc.open(ciphertext, clientSecretAAD)
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != secretText {
		t.Fatalf("opened secret = %q, want original secret", opened)
	}
	if _, err := svc.open(ciphertext, pkceVerifierAAD); err == nil {
		t.Fatal("ciphertext opened with the wrong associated data")
	}
}

func TestOIDCConnectionValidationRejectsUnsafeEndpoints(t *testing.T) {
	if err := validateIssuer("http://idp.example.com"); err == nil {
		t.Fatal("non-local HTTP issuer was accepted")
	}
	if err := validateEndpoint("https://attacker.example/jwks", "https://idp.example.com"); err == nil {
		t.Fatal("cross-origin discovery endpoint was accepted")
	}
	if err := validateRedirectURI("https://app.example/callback/*"); err == nil {
		t.Fatal("wildcard redirect URI was accepted")
	}
	if err := validateRedirectURI("http://localhost:8080/callback"); err != nil {
		t.Fatalf("localhost development redirect URI rejected: %v", err)
	}
}

func TestOIDCStateDigestsDoNotStorePlaintext(t *testing.T) {
	value := "sso_state_example"
	hash := digest(value)
	if string(hash) == value || strings.Contains(string(hash), value) {
		t.Fatal("state digest contains the plaintext state")
	}
	if !equalDigest(hash, value) || equalDigest(hash, value+"-tampered") {
		t.Fatal("state digest comparison is not exact")
	}
}
