package enterprise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestOIDCDiscoveryRequiresBoundedUsableMetadata(t *testing.T) {
	for _, tc := range []struct {
		name    string
		algs    []string
		padding int
		suffix  string
		wantOK  bool
	}{
		{name: "default algorithm", wantOK: true},
		{name: "supported asymmetric algorithms", algs: []string{"ES256", "RS256", "HS256"}, wantOK: true},
		{name: "no supported algorithm", algs: []string{"none", "HS256"}},
		{name: "empty advertised algorithms", algs: []string{}},
		{name: "oversized document", padding: maxDiscoveryBytes},
		{name: "trailing document", suffix: "{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				issuer := "https://" + r.Host
				doc := map[string]any{
					"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
					"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
				}
				if tc.algs != nil {
					doc["id_token_signing_alg_values_supported"] = tc.algs
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(doc)
				_, _ = w.Write([]byte(strings.Repeat(" ", tc.padding) + tc.suffix))
			}))
			t.Cleanup(server.Close)
			svc := &Service{HTTPClient: server.Client()}
			provider, err := svc.discovery(t.Context(), server.URL)
			if (err == nil) != tc.wantOK {
				t.Fatalf("discovery error = %v, want success = %v", err, tc.wantOK)
			}
			if tc.wantOK && provider.Endpoint().TokenURL != server.URL+"/token" {
				t.Fatal("provider did not retain the verified token endpoint")
			}
		})
	}
}
