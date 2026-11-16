package invoicesaas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

const testIssuer = "https://auth.example.test"

func exampleSigner(t *testing.T) *security.Signer {
	t.Helper()
	signer, err := security.GenerateSigner(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func exampleClaims() security.Claims {
	return security.Claims{Issuer: testIssuer, Subject: "mem_agent", MemberID: "mem_agent", Type: "agent",
		Audience: "invoice-saas", IssuedAt: time.Now().Add(-time.Second).Unix(), ExpiresAt: time.Now().Add(time.Minute).Unix(), JWTID: "jwt_invoice"}
}

func signExample(t *testing.T, signer *security.Signer, claims security.Claims) string {
	t.Helper()
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func writeKeys(t *testing.T, w http.ResponseWriter, signer *security.Signer) {
	t.Helper()
	keys, err := signer.JWKS()
	if err != nil {
		t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(keys)
}

func exampleClient(t *testing.T, endpoint string) *AuthClient {
	t.Helper()
	client, err := NewAuthClient(AuthConfig{Issuer: testIssuer, ServerURL: endpoint, JWKSURL: endpoint + "/.well-known/jwks.json",
		ClientID: "invoice-saas", APIKey: secret.New("example-server-key")})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSaaSJWTRejectsInvalidIdentity(t *testing.T) {
	signer := exampleSigner(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("JWKS fetch sent a credential")
		}
		writeKeys(t, w, signer)
	}))
	t.Cleanup(server.Close)
	client := exampleClient(t, server.URL)
	for _, kind := range []string{"agent", "user"} {
		claims := exampleClaims()
		claims.Type = kind
		token := signExample(t, signer, claims)
		if _, member, err := client.authenticate(context.Background(), "Bearer "+token); err != nil || member.MemberID != claims.MemberID || (kind == "user" && member.UserID != claims.Subject) {
			t.Fatalf("valid %s token rejected: %v", kind, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("known signing key was not cached")
	}
	for _, item := range []struct {
		name string
		edit func(*security.Claims)
	}{
		{"WrongIssuer", func(c *security.Claims) { c.Issuer = "https://other.example.test" }},
		{"WrongAudience", func(c *security.Claims) { c.Audience = "another-app" }},
		{"Expired", func(c *security.Claims) { c.ExpiresAt = time.Now().Add(-time.Second).Unix() }},
		{"ExpiryBoundary", func(c *security.Claims) { c.ExpiresAt = time.Now().Unix() }},
		{"FutureIssuedAt", func(c *security.Claims) { c.IssuedAt = time.Now().Add(time.Hour).Unix() }},
		{"MissingSubject", func(c *security.Claims) { c.Subject = "" }},
		{"MissingMember", func(c *security.Claims) { c.MemberID = "" }},
		{"WrongKind", func(c *security.Claims) { c.Type = "application" }},
		{"MissingKind", func(c *security.Claims) { c.Type = "" }},
		{"EmptyJWTID", func(c *security.Claims) { c.JWTID = "" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			claims := exampleClaims()
			item.edit(&claims)
			_, _, err := client.authenticate(context.Background(), "Bearer "+signExample(t, signer, claims))
			assertExampleError(t, err, "INVALID_TOKEN")
		})
	}
	valid := signExample(t, signer, exampleClaims())
	parts := strings.Split(valid, ".")
	for name, bearer := range map[string]string{
		"MissingBearer": valid, "Empty": "Bearer ", "Oversized": "Bearer " + strings.Repeat("x", 16385),
		"BadSignature": "Bearer " + parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := client.authenticate(context.Background(), bearer)
			assertExampleError(t, err, "INVALID_TOKEN")
		})
	}
	for name, header := range map[string]string{
		"AlgorithmNone":   `{"alg":"none","kid":"key","typ":"at+jwt"}`,
		"AlgorithmHS256":  `{"alg":"HS256","kid":"key","typ":"at+jwt"}`,
		"WrongHeaderType": `{"alg":"ES256","kid":"key","typ":"JWT"}`,
		"MissingKeyID":    `{"alg":"ES256","typ":"at+jwt"}`,
		"CriticalHeader":  `{"alg":"ES256","kid":"key","typ":"at+jwt","crit":["custom"],"custom":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := client.authenticate(context.Background(), "Bearer "+base64.RawURLEncoding.EncodeToString([]byte(header))+"."+parts[1]+"."+parts[2])
			assertExampleError(t, err, "INVALID_TOKEN")
		})
	}
}

func TestSaaSJWKSRefreshesForRotationAndBoundsUnknownKeys(t *testing.T) {
	signer := exampleSigner(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writeKeys(t, w, signer)
	}))
	t.Cleanup(server.Close)
	client := exampleClient(t, server.URL)
	old := signExample(t, signer, exampleClaims())
	if _, _, err := client.authenticate(context.Background(), "Bearer "+old); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.StageNext(); err != nil {
		t.Fatal(err)
	}
	if err := signer.PromoteNext(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.authenticate(context.Background(), "Bearer "+signExample(t, signer, exampleClaims())); err != nil {
		t.Fatalf("new active key was not discovered: %v", err)
	}
	if _, _, err := client.authenticate(context.Background(), "Bearer "+old); err != nil {
		t.Fatalf("overlap key stopped verifying: %v", err)
	}
	before := requests.Load()
	for range 10 {
		if key, err := client.signingKey(context.Background(), "unknown"); err != nil || key != nil {
			t.Fatal("unknown key accepted")
		}
	}
	if requests.Load() > before+1 {
		t.Fatal("unknown key IDs caused unbounded refreshes")
	}
}

func TestSaaSJWTRequiresClaimsAndRejectsFutureNotBefore(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := jwk.Import(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]string{"kid": "claims-key", "alg": "ES256", "use": "sig"} {
		if err := public.Set(field, value); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{public}})
	}))
	t.Cleanup(server.Close)
	client := exampleClient(t, server.URL)
	headers := jws.NewHeaders()
	_ = headers.Set("typ", "at+jwt")
	_ = headers.Set("kid", "claims-key")
	for _, omitted := range []string{"exp", "iat", "sub", "jti", "nbf"} {
		t.Run(omitted, func(t *testing.T) {
			claims := map[string]any{"iss": testIssuer, "aud": "invoice-saas", "sub": "mem_agent", "mid": "mem_agent", "typ": "agent",
				"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Add(-time.Second).Unix(), "jti": "jwt_claims"}
			if omitted == "nbf" {
				claims["nbf"] = time.Now().Add(time.Hour).Unix()
			} else {
				delete(claims, omitted)
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			token, err := jws.Sign(payload, jws.WithKey(jwa.ES256(), private, jws.WithProtectedHeaders(headers)))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = client.authenticate(context.Background(), "Bearer "+string(token))
			assertExampleError(t, err, "INVALID_TOKEN")
		})
	}
}

func TestSaaSJWKSRejectsUnusableKeySets(t *testing.T) {
	signer := exampleSigner(t)
	set, err := signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct{ Keys []map[string]any }
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DuplicateID", "PrivateMaterial", "WrongAlgorithm", "WrongUse", "InvalidPoint", "TooManyKeys"} {
		t.Run(name, func(t *testing.T) {
			key := make(map[string]any)
			for field, value := range raw.Keys[0] {
				key[field] = value
			}
			keys := []map[string]any{key}
			switch name {
			case "DuplicateID":
				other := exampleSigner(t)
				otherSet, err := other.JWKS()
				if err != nil {
					t.Fatal(err)
				}
				otherJSON, _ := json.Marshal(otherSet)
				var otherRaw struct{ Keys []map[string]any }
				if err := json.Unmarshal(otherJSON, &otherRaw); err != nil {
					t.Fatal(err)
				}
				otherRaw.Keys[0]["kid"] = key["kid"]
				keys = append(keys, otherRaw.Keys[0])
			case "PrivateMaterial":
				key["d"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			case "WrongAlgorithm":
				key["alg"] = "ES384"
			case "WrongUse":
				key["use"] = "enc"
			case "InvalidPoint":
				key["x"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			case "TooManyKeys":
				for range 32 {
					keys = append(keys, key)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			}))
			t.Cleanup(server.Close)
			_, err := exampleClient(t, server.URL).signingKey(context.Background(), key["kid"].(string))
			assertExampleError(t, err, "UNAVAILABLE")
		})
	}
}

func TestSaaSAuthClientRejectsUnsafeEndpointsAndUnavailableJWKS(t *testing.T) {
	for _, endpoint := range []string{"", "http://auth.example.test", "http://localhost:8080", "https://user:password@auth.example.test", "https://auth.example.test?secret=value", "https://auth.example.test/#fragment"} {
		if _, err := NewAuthClient(AuthConfig{Issuer: endpoint, ServerURL: endpoint, ClientID: "app", APIKey: "secret"}); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	for _, body := range []string{`not JSON`, `{"keys":[]}`, strings.Repeat(" ", 1<<20+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		client := exampleClient(t, server.URL)
		_, err := client.signingKey(context.Background(), "key")
		server.Close()
		assertExampleError(t, err, "UNAVAILABLE")
	}
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	t.Cleanup(target.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client := exampleClient(t, server.URL)
	_, err := client.signingKey(context.Background(), "key")
	assertExampleError(t, err, "UNAVAILABLE")
	var output any
	err = client.post(context.Background(), "/server/v1/authz/check", map[string]string{"token": "a-secret-token"}, &output, "req_example")
	assertExampleError(t, err, "UNAVAILABLE")
	if redirected.Load() != 0 {
		t.Fatal("Auth request followed a redirect")
	}
}

func assertExampleError(t *testing.T, err error, code string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}
