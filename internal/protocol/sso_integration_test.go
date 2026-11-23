package protocol

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type oidcTestCode struct {
	nonce         string
	subject       string
	email         string
	emailVerified bool
	groups        []string
	extra         map[string]any
	challenge     string
	redirectURI   string
}

type oidcTestProvider struct {
	discoveryRequests atomic.Int32
	server            *httptest.Server
	issuer            string
	key               *rsa.PrivateKey
	mu                sync.Mutex
	codes             map[string]oidcTestCode
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &oidcTestProvider{key: key, codes: make(map[string]oidcTestCode)}
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			provider.discoveryRequests.Add(1)
			writeOIDCTestJSON(w, map[string]any{
				"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize",
				"token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/jwks",
			})
		case "/jwks":
			writeOIDCTestJSON(w, map[string]any{"keys": []any{rsaPublicJWK(&provider.key.PublicKey)}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			provider.mu.Lock()
			codeValue := r.Form.Get("code")
			code, ok := provider.codes[codeValue]
			if ok && code.challenge != "" {
				challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				ok = base64.RawURLEncoding.EncodeToString(challenge[:]) == code.challenge && r.Form.Get("redirect_uri") == code.redirectURI
				if ok {
					delete(provider.codes, codeValue)
				}
			}
			provider.mu.Unlock()
			if !ok || r.Form.Get("code_verifier") == "" {
				http.Error(w, "invalid code", http.StatusBadRequest)
				return
			}
			audience := r.Form.Get("client_id")
			if basicID, _, basicOK := r.BasicAuth(); basicOK {
				audience = basicID
			}
			idToken := signOIDCTestToken(t, provider.key, provider.issuer, audience, code)
			writeOIDCTestJSON(w, map[string]any{"access_token": "oidc-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
		default:
			http.NotFound(w, r)
		}
	}))
	server.Listener = listener
	server.Start()
	provider.server = server
	provider.issuer = "http://localhost:" + strings.TrimPrefix(server.URL, "http://127.0.0.1:")
	t.Cleanup(server.Close)
	return provider
}

func (p *oidcTestProvider) addCode(code string, value oidcTestCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = value
}

func writeOIDCTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func rsaPublicJWK(key *rsa.PublicKey) map[string]string {
	exponent := make([]byte, 4)
	exponent[0] = byte(key.E >> 24)
	exponent[1] = byte(key.E >> 16)
	exponent[2] = byte(key.E >> 8)
	exponent[3] = byte(key.E)
	for len(exponent) > 1 && exponent[0] == 0 {
		exponent = exponent[1:]
	}
	return map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "oidc-test-key",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func signOIDCTestToken(t *testing.T, key *rsa.PrivateKey, issuer, audience string, code oidcTestCode) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"oidc-test-key","typ":"JWT"}`))
	claims := map[string]any{
		"iss": issuer, "aud": audience, "sub": code.subject, "email": code.email,
		"email_verified": code.emailVerified, "nonce": code.nonce, "groups": code.groups,
		"iat": time.Now().UTC().Unix(), "exp": time.Now().UTC().Add(5 * time.Minute).Unix(),
	}
	for name, value := range code.extra {
		claims[name] = value
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	message := header + "." + encodedPayload
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func newSSOHTTPFixture(t *testing.T) (*store.Store, *authorization.Service, *enterprise.Service, authorization.Member, string, *oidcTestProvider) {
	t.Helper()
	ctx := context.Background()
	database, err := protocolDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status) VALUES ('usr_sso_http_owner', 'sso-http-owner@example.test', 'sso-http-owner@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	space, owner, err := authorizer.CreateSpace(ctx, "usr_sso_http_owner", "SSO HTTP Space", "sso-http-space")
	if err != nil {
		t.Fatal(err)
	}
	grantID := string(ids.New[ids.GrantID]("grt"))
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ($1, $2, '["auth.connections:manage"]'::jsonb, $3, 'space', $2, $3)
	`, grantID, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("sso-http-session-hmac-key-0000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	provider := newOIDCTestProvider(t)
	svc := &enterprise.Service{
		Store: st, Authorization: authorizer, Sessions: sessions, DataKey: secret.New(strings.Repeat("d", 32)),
		Passwords: security.DefaultPasswordHasher(), HTTPClient: provider.server.Client(),
	}
	return st, authorizer, svc, owner, space.ID, provider
}

func TestOIDCSSOHTTPEnforcesReplayCrossConnectionUnverifiedEmailAndDisable(t *testing.T) {
	ctx := context.Background()
	st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	connection, err := svc.CreateConnection(requestCtx, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Acme Workforce", Provider: "oidc", Issuer: provider.issuer, ClientID: "sso-http-client", ClientSecret: "client-secret",
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateConnection(requestCtx, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Acme Workforce Secondary", Provider: "oidc", Issuer: provider.issuer, ClientID: "sso-http-client-secondary", ClientSecret: "client-secret",
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	(HTTP{Enterprise: svc}).Register(&mux)
	start := func(connectionID string) enterprise.StartResult {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/v1/sso/"+connectionID+"/start", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("SSO start status = %d, body = %s", response.Code, response.Body.String())
		}
		var body struct {
			Data enterprise.StartResult `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Data
	}
	callback := func(connectionID string, input map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/sso/"+connectionID+"/callback", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}

	first := start(connection.ID)
	if got := provider.discoveryRequests.Load(); got != 1 {
		t.Fatalf("SSO start made %d discovery requests, want one", got)
	}
	firstURL, err := url.Parse(first.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	provider.addCode("sso-valid-code", oidcTestCode{nonce: firstURL.Query().Get("nonce"), subject: "idp-user-1", email: "sso-user@example.test", emailVerified: true, groups: []string{"engineering"}})
	valid := callback(connection.ID, map[string]string{"state": first.State, "code": "sso-valid-code", "redirect_uri": connection.RedirectURI})
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"email":"sso-user@example.test"`) || !strings.Contains(valid.Body.String(), `"access_token"`) {
		t.Fatalf("valid OIDC callback did not issue the expected session (HTTP %d)", valid.Code)
	}
	if got := provider.discoveryRequests.Load(); got != 2 {
		t.Fatalf("expected one discovery request for start and one for callback, got %d", got)
	}
	if replay := callback(connection.ID, map[string]string{"state": first.State, "code": "sso-valid-code", "redirect_uri": connection.RedirectURI}); replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "invalid_grant") {
		t.Fatalf("replayed OIDC state = %d %s", replay.Code, replay.Body.String())
	}

	cross := start(second.ID)
	crossURL, err := url.Parse(cross.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	provider.addCode("sso-cross-connection-code", oidcTestCode{nonce: crossURL.Query().Get("nonce"), subject: "idp-user-2", email: "cross@example.test", emailVerified: true})
	crossResponse := callback(second.ID, map[string]string{"state": cross.State, "code": "sso-valid-code", "redirect_uri": second.RedirectURI})
	if crossResponse.Code != http.StatusBadRequest || !strings.Contains(crossResponse.Body.String(), "invalid_grant") {
		t.Fatalf("cross-connection code = %d %s", crossResponse.Code, crossResponse.Body.String())
	}

	unverified := start(connection.ID)
	unverifiedURL, err := url.Parse(unverified.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	provider.addCode("sso-unverified-code", oidcTestCode{nonce: unverifiedURL.Query().Get("nonce"), subject: "idp-unverified", email: "unverified@example.test", emailVerified: false})
	unverifiedResponse := callback(connection.ID, map[string]string{"state": unverified.State, "code": "sso-unverified-code", "redirect_uri": connection.RedirectURI})
	if unverifiedResponse.Code != http.StatusBadRequest || !strings.Contains(unverifiedResponse.Body.String(), "invalid_grant") {
		t.Fatalf("unverified OIDC email = %d %s", unverifiedResponse.Code, unverifiedResponse.Body.String())
	}
	var created int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email_normalized = 'unverified@example.test'`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatal("unverified OIDC identity created a user")
	}

	revoked := start(connection.ID)
	revokedURL, err := url.Parse(revoked.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	provider.addCode("sso-disabled-code", oidcTestCode{nonce: revokedURL.Query().Get("nonce"), subject: "idp-disabled", email: "disabled@example.test", emailVerified: true})
	if err := svc.DisableConnection(requestCtx, owner.ID, spaceID, connection.ID); err != nil {
		t.Fatal(err)
	}
	disabledResponse := callback(connection.ID, map[string]string{"state": revoked.State, "code": "sso-disabled-code", "redirect_uri": connection.RedirectURI})
	if disabledResponse.Code != http.StatusForbidden || !strings.Contains(disabledResponse.Body.String(), "disabled") {
		t.Fatalf("disabled OIDC callback = %d %s", disabledResponse.Code, disabledResponse.Body.String())
	}
}

func TestOIDCConnectionRejectsRoleMappingOutsideSpace(t *testing.T) {
	ctx := context.Background()
	st, authorizer, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_sso_foreign', 'sso-foreign@example.test', 'sso-foreign@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	foreignSpace, _, err := authorizer.CreateSpace(ctx, "usr_sso_foreign", "Foreign SSO Space", "foreign-sso-space")
	if err != nil {
		t.Fatal(err)
	}
	_, err = authorizer.CreateRole(ctx, owner.ID, foreignSpace.ID, "Foreign role", "", []string{"self:read"})
	if err == nil {
		t.Fatal("foreign role creation unexpectedly succeeded with an actor from another Space")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO roles (id, space_id, name, managed) VALUES ('rol_sso_foreign', $1, 'Foreign role', false)`, foreignSpace.ID); err != nil {
		t.Fatal(err)
	}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	_, err = svc.CreateConnection(requestCtx, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Invalid mapping", Provider: "oidc", Issuer: provider.issuer, ClientID: "mapping-client", ClientSecret: "client-secret",
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback", RoleMappings: map[string]string{"engineering": "rol_sso_foreign"},
	})
	if err == nil || !strings.Contains(err.Error(), "outside this Space") {
		t.Fatalf("foreign role mapping error = %v", err)
	}
}
