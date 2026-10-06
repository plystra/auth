package security

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
	payload, err := json.Marshal(Claims{Issuer: "i", Subject: "s", MemberID: "m", SpaceID: "p", Audience: "a", ExpiresAt: 1, IssuedAt: 1, JWTID: "j", SessionID: "sid", Assurance: 1, AMR: []string{"pwd"}, Actor: "a", Type: "agent", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"iss"`, `"sub"`, `"mid"`, `"spc"`, `"aud"`, `"exp"`, `"iat"`, `"jti"`, `"sid"`, `"aal"`, `"amr"`, `"act"`, `"typ"`, `"scp"`} {
		if !strings.Contains(string(payload), field) {
			t.Fatalf("claims JSON missing %s: %s", field, payload)
		}
	}
}
