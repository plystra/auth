package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSignerDecryptsEncryptedPEMAndRejectsWrongKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey := []byte(strings.Repeat("k", 32))
	pemData, err := EncryptSigningKeyPEM(key, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(path, "https://auth.test", encryptionKey)
	if err != nil {
		t.Fatalf("NewSigner() = %v", err)
	}
	now := time.Now().UTC()
	token, err := signer.Sign(Claims{Issuer: signer.Issuer(), Subject: "usr_encrypted_key", Audience: "app_test", ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), JWTID: "jti_encrypted_key", SessionID: "ses_encrypted_key", Type: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(token, now, "app_test"); err != nil {
		t.Fatalf("encrypted signer token rejected: %v", err)
	}
	if _, err := NewSigner(path, "https://auth.test", []byte(strings.Repeat("x", 32))); err == nil {
		t.Fatal("signing key decrypted with the wrong encryption key")
	}
}

func TestNewSignerRejectsPlaintextPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plain-signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: plain}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(path, "https://auth.test", []byte(strings.Repeat("k", 32))); err == nil {
		t.Fatal("plaintext signing key was accepted")
	}
}

func TestJWTVerificationRejectsAlgorithmIssuerAudienceTypeAndExpiryMismatches(t *testing.T) {
	signer, err := GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := Claims{Issuer: signer.Issuer(), Subject: "usr_jwt_test", Audience: "app_test", ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Add(-time.Second).Unix(), JWTID: "jti_jwt_test", SessionID: "ses_jwt_test", Type: "user"}
	token, err := signer.Sign(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(token, now, "app_test"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	for name, claims := range map[string]Claims{
		"issuer":   func() Claims { c := valid; c.Issuer = "https://other.test"; return c }(),
		"audience": func() Claims { c := valid; c.Audience = "other-app"; return c }(),
		"expired":  func() Claims { c := valid; c.ExpiresAt = now.Add(-time.Second).Unix(); return c }(),
		"type":     func() Claims { c := valid; c.Type = "operator"; return c }(),
	} {
		candidate, err := signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.Verify(candidate, now, "app_test"); err == nil {
			t.Fatalf("%s mismatch was accepted", name)
		}
	}

	for name, header := range map[string]string{
		"algorithm":   `{"alg":"HS256","typ":"at+jwt"}`,
		"header type": `{"alg":"ES256","typ":"JWT"}`,
	} {
		parts := strings.Split(token, ".")
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(header))
		if _, err := signer.Verify(strings.Join(parts, "."), now, "app_test"); err == nil {
			t.Fatalf("invalid %s was accepted", name)
		}
	}
}

func TestJWTClaimsUseStableJSONNames(t *testing.T) {
	payload, err := json.Marshal(Claims{Issuer: "i", Subject: "s", MemberID: "m", SpaceID: "p", Audience: "a", ExpiresAt: 1, IssuedAt: 1, JWTID: "j", SessionID: "sid", Assurance: 1, AMR: []string{"pwd"}, Actor: &ActorClaim{Subject: "a", MemberID: "a", Type: "agent"}, Type: "agent", Scopes: []string{"read"}, AgentTokenEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"iss"`, `"sub"`, `"mid"`, `"spc"`, `"aud"`, `"exp"`, `"iat"`, `"jti"`, `"sid"`, `"aal"`, `"amr"`, `"act"`, `"typ"`, `"scp"`, `"aep"`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("claims JSON missing %s: %s", field, payload)
		}
	}
}

func TestSigningKeyRotationKeepsOldTokensVerifiableAndPublishesOverlap(t *testing.T) {
	signer, err := GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := Claims{Issuer: signer.Issuer(), Subject: "usr_rotation_test", Audience: "app_test", ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), JWTID: "jti_rotation_old", SessionID: "ses_rotation_old", Type: "user"}
	oldToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	oldKid := jwtHeaderKid(t, oldToken)

	nextKid, err := signer.StageNext()
	if err != nil {
		t.Fatal(err)
	}
	if nextKid == oldKid {
		t.Fatal("staged key reused the active key id")
	}
	if keys := jwksKeyIDs(t, signer); len(keys) != 1 || keys[0] != oldKid {
		t.Fatalf("JWKS before promotion = %v, want only active key %q", keys, oldKid)
	}
	if err := signer.PromoteNext(); err != nil {
		t.Fatal(err)
	}
	claims.JWTID = "jti_rotation_new"
	newToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if jwtHeaderKid(t, newToken) != nextKid {
		t.Fatalf("new token kid = %q, want %q", jwtHeaderKid(t, newToken), nextKid)
	}
	if _, err := signer.Verify(oldToken, now, "app_test"); err != nil {
		t.Fatalf("old token was rejected during overlap: %v", err)
	}
	if _, err := signer.Verify(newToken, now, "app_test"); err != nil {
		t.Fatalf("new token was rejected after promotion: %v", err)
	}
	keys := jwksKeyIDs(t, signer)
	if len(keys) != 2 || keys[0] != nextKid && keys[1] != nextKid || keys[0] != oldKid && keys[1] != oldKid {
		t.Fatalf("JWKS during overlap = %v, want active and retiring keys %q/%q", keys, nextKid, oldKid)
	}
	if err := signer.DropRetiring(oldKid); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(oldToken, now, "app_test"); err == nil {
		t.Fatal("old token remained valid after retiring key removal")
	}
}

func jwtHeaderKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid token parts: %q", token)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(data, &header) != nil {
		t.Fatalf("invalid JWT header: %q", parts[0])
	}
	return header.Kid
}

func jwksKeyIDs(t *testing.T, signer *Signer) []string {
	t.Helper()
	set, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys, ok := set["keys"].([]any)
	if !ok {
		t.Fatalf("JWKS keys = %#v", set["keys"])
	}
	ids := make([]string, 0, len(keys))
	for _, raw := range keys {
		key, ok := raw.(map[string]string)
		if !ok {
			t.Fatalf("JWKS key = %#v", raw)
		}
		ids = append(ids, key["kid"])
	}
	return ids
}
