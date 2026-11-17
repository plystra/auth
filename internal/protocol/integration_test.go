package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var protocolDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	protocolDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := protocolDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestOAuthRefreshGrantUsesAgentAccessTokenRenewal(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_oauth_refresh_protocol', 'oauth-refresh-protocol@example.test', 'oauth-refresh-protocol@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_oauth_refresh_protocol", "OAuth Refresh Space", "oauth-refresh-protocol")
	if err != nil {
		t.Fatal(err)
	}
	credentialKey := []byte("protocol-oauth-refresh-hmac-key-0001")
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{credentialKey}}
	clientID := "https://refresh.client/metadata.json"
	clientSecret := "oauth-refresh-client-secret"
	clientHMACKey := []byte("protocol-oauth-client-hmac-key-0002")
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, manifest_permissions, client_id, client_secret_hash)
		VALUES ('app_oauth_refresh_protocol', $1, 'OAuth Refresh Client', '[]'::jsonb, '["auth.authz:check"]'::jsonb, '["auth.authz:check"]'::jsonb, $2, $3)
	`, owner.SpaceID, clientID, hmacSHA256(clientHMACKey, clientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, type, binding_policy, status)
		VALUES ('mem_oauth_refresh_application', $1, 'OAuth Refresh Client', 'application', 'single', 'active')
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO roles (id, space_id, name, managed)
		VALUES ('rol_oauth_refresh_application', $1, 'application:ins_oauth_refresh_protocol', true)
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT 'rol_oauth_refresh_application', id FROM permissions WHERE key = 'auth.authz:check'
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, role_id, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_oauth_refresh_application', $1, 'rol_oauth_refresh_application', 'mem_oauth_refresh_application', 'space', $1, $2)
	`, owner.SpaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO application_installations (id, application_id, space_id, member_id, role_id, scope, approved_permissions, installed_by)
		VALUES ('ins_oauth_refresh_protocol', 'app_oauth_refresh_protocol', $1, 'mem_oauth_refresh_application', 'rol_oauth_refresh_application', 'space', '["auth.authz:check"]'::jsonb, $2)
	`, owner.SpaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	wrongClientID := "https://other-refresh.client/metadata.json"
	wrongClientSecret := "other-refresh-client-secret"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash)
		VALUES ('app_oauth_refresh_other', $1, 'Other Refresh Client', '[]'::jsonb, '[]'::jsonb, $2, $3)
	`, owner.SpaceID, wrongClientID, hmacSHA256(clientHMACKey, wrongClientSecret)); err != nil {
		t.Fatal(err)
	}
	ag, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "oauth-protocol-agent", Source: "oauth", OAuthClientID: clientID, ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := agents.CreateOAuthRefreshCredential(ctx, ag.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	apps := &application.Service{Store: st, HMACKeys: [][]byte{clientHMACKey}}
	var mux http.ServeMux
	(HTTP{Applications: apps, Agents: agents, Sessions: sessions}).Register(&mux)

	request := func(token, id, secret, resource string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {id}, "resource": {resource}}
		if secret != "" {
			form.Set("client_secret", secret)
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	missing := request(refresh, clientID, "", clientID)
	if missing.Code != http.StatusUnauthorized || missing.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing OAuth client authentication status=%d body=%s", missing.Code, missing.Body.String())
	}
	wrongSecret := request(refresh, clientID, "wrong-secret", clientID)
	if wrongSecret.Code != http.StatusUnauthorized {
		t.Fatalf("wrong OAuth client authentication status=%d body=%s", wrongSecret.Code, wrongSecret.Body.String())
	}
	wrongClient := request(refresh, wrongClientID, wrongClientSecret, wrongClientID)
	if wrongClient.Code != http.StatusUnauthorized {
		t.Fatalf("wrong OAuth client binding status=%d body=%s", wrongClient.Code, wrongClient.Body.String())
	}
	wrongResource := request(refresh, clientID, clientSecret, "https://other-resource.test")
	if wrongResource.Code != http.StatusBadRequest {
		t.Fatalf("wrong resource status=%d body=%s", wrongResource.Code, wrongResource.Body.String())
	}
	first := request(refresh, clientID, clientSecret, clientID)
	if first.Code != http.StatusOK {
		t.Fatalf("OAuth refresh status = %d, body = %s", first.Code, first.Body.String())
	}
	var firstBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	if firstBody.AccessToken == "" || firstBody.RefreshToken == "" || firstBody.RefreshToken == refresh {
		t.Fatalf("OAuth refresh response = %+v", firstBody)
	}
	claims, active, err := sessions.Introspect(ctx, firstBody.AccessToken, clientID)
	if err != nil || !active || claims.Type != "agent" || claims.Subject != ag.ID {
		t.Fatalf("renewed Agent access token claims=%+v active=%v err=%v", claims, active, err)
	}
	replay := request(refresh, clientID, clientSecret, clientID)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed OAuth refresh status = %d, want 400", replay.Code)
	}
	if next := request(firstBody.RefreshToken, clientID, clientSecret, clientID); next.Code != http.StatusBadRequest {
		t.Fatalf("family token after replay status = %d, want 400", next.Code)
	}
}

func TestOAuthUserinfoReturnsUserAndAgentSubjects(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at, display_name, avatar_url)
		VALUES ('usr_userinfo_protocol', 'userinfo@example.test', 'userinfo@example.test', 'test-password-hash', 'active', now(), 'Info User', 'https://cdn.test/avatar.png')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_userinfo_protocol", "Userinfo Space", "userinfo")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{[]byte("protocol-userinfo-hmac-key-0001")}}
	ag, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "userinfo-agent", Source: "oauth", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	accounts := &account.Service{Store: st}
	var mux http.ServeMux
	(HTTP{Agents: agents, Accounts: accounts, Sessions: sessions}).Register(&mux)
	userTokens, err := sessions.CreateForMember(ctx, "usr_userinfo_protocol", "", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, ag.ID, owner.SpaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	request := func(token string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		var body map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatalf("userinfo response is not JSON: %v", err)
		}
		return res.Code, body
	}
	if status, body := request(userTokens.AccessToken); status != http.StatusOK || body["sub"] != "usr_userinfo_protocol" || body["email"] != "userinfo@example.test" || body["email_verified"] != true || body["name"] != "Info User" || body["picture"] != "https://cdn.test/avatar.png" {
		t.Fatalf("user userinfo status=%d body=%v", status, body)
	}
	if status, body := request(agentTokens.AccessToken); status != http.StatusOK || body["sub"] != ag.ID || body["member_id"] != ag.ID || body["space_id"] != owner.SpaceID || body["principal_type"] != "agent" {
		t.Fatalf("agent userinfo status=%d body=%v", status, body)
	}
	if status, body := request("not-a-token"); status != http.StatusUnauthorized || body["error"].(map[string]any)["code"] != "invalid_token" {
		t.Fatalf("invalid userinfo status=%d body=%v", status, body)
	}
}

func TestOAuthAuthorizationCodeUsesPKCEAndCreatesBoundAgent(t *testing.T) {
	testOAuthAuthorizationCodeInstallation(t, "space")
}

func TestOAuthAuthorizationCodeWithGroupInstallations(t *testing.T) {
	for _, scope := range []string{"group", "group_tree"} {
		t.Run(scope, func(t *testing.T) { testOAuthAuthorizationCodeInstallation(t, scope) })
	}
}

func testOAuthAuthorizationCodeInstallation(t *testing.T, installationScope string) {
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
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_oauth_code_protocol', 'oauth-code@example.test', 'oauth-code@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_oauth_code_protocol", "OAuth Code Space", "oauth-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO permissions (id, key, description, principal_kinds, agent_approval, risk, status)
		VALUES ('prm_oauth_group_read', 'oauth.group:read', 'OAuth group-scoped read', '["human","agent","application"]'::jsonb, 'none', 'low', 'active')
		ON CONFLICT (key) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ('grp_oauth_scope', $1, 'OAuth Scope', 'standard', 'active')
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_oauth_owner_scope', $1, '["oauth.group:read"]'::jsonb, $2, 'group', 'grp_oauth_scope', $2)
	`, owner.SpaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	clientID := "https://client.test/metadata.json"
	clientSecret := "oauth-client-secret-for-test"
	clientHMACKey := []byte("protocol-oauth-client-hmac-key-0001")
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash)
		VALUES ('app_oauth_code_protocol', $1, 'OAuth Code Client', '["https://client.test/callback"]'::jsonb, '["oauth.group:read"]'::jsonb, $2, $3)
	`, owner.SpaceID, clientID, hmacSHA256(clientHMACKey, clientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, type, binding_policy, status)
		VALUES ('mem_oauth_code_application', $1, 'OAuth Code Client', 'application', 'single', 'active')
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, type, binding_policy, status)
		VALUES ('mem_oauth_code_unbound', $1, 'Unbound User', 'human', 'single', 'active')
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO roles (id, space_id, name, managed)
		VALUES ('rol_oauth_code_application', $1, 'application:ins_oauth_code_protocol', true)
	`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ('rol_oauth_code_application', 'prm_oauth_group_read')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, role_id, grantee_member_id, scope, anchor_space_id, anchor_group_id, granted_by)
		VALUES ('grt_oauth_code_application', $1, 'rol_oauth_code_application', 'mem_oauth_code_application', $3,
		        CASE WHEN $3::text = 'space' THEN $1::text END, CASE WHEN $3::text <> 'space' THEN 'grp_oauth_scope' END, $2)
	`, owner.SpaceID, owner.ID, installationScope); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO application_installations (id, application_id, space_id, member_id, role_id, scope, anchor_group_id, approved_permissions, installed_by)
		VALUES ('ins_oauth_code_protocol', 'app_oauth_code_protocol', $1, 'mem_oauth_code_application', 'rol_oauth_code_application', $3,
		        CASE WHEN $3::text <> 'space' THEN 'grp_oauth_scope' END, '["oauth.group:read"]'::jsonb, $2)
	`, owner.SpaceID, owner.ID, installationScope); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		DELETE FROM role_permissions rp
		USING permissions p, member_roles mr
		WHERE rp.permission_id = p.id AND rp.role_id = mr.role_id
		  AND mr.member_id = $1 AND p.key = 'auth.grants:assign'
	`, owner.ID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{[]byte("protocol-oauth-code-hmac-key-0001")}}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	accounts := &account.Service{Store: st}
	apps := &application.Service{Store: st, HMACKeys: [][]byte{clientHMACKey}}
	var mux http.ServeMux
	(HTTP{Issuer: "https://auth.test", Agents: agents, Accounts: accounts, Applications: apps, Sessions: sessions, Authorization: authorizer}).Register(&mux)
	userTokens, err := sessions.CreateForMember(ctx, "usr_oauth_code_protocol", owner.ID, nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	verifier := "oauth-code-verifier-for-pkce"
	digest := sha256.Sum256([]byte(verifier))
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"https://client.test/callback"},
		"scope":                 {"oauth.group:read"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-123"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	badRedirectQuery := cloneValues(authorizeQuery)
	badRedirectQuery.Set("redirect_uri", "https://client.test/other")
	badRedirectRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+badRedirectQuery.Encode(), nil)
	badRedirectRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	badRedirectResponse := httptest.NewRecorder()
	mux.ServeHTTP(badRedirectResponse, badRedirectRequest)
	if badRedirectResponse.Code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect status=%d body=%s", badRedirectResponse.Code, badRedirectResponse.Body.String())
	}
	badResourceQuery := cloneValues(authorizeQuery)
	badResourceQuery.Set("resource", "https://resource.test")
	badResourceRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+badResourceQuery.Encode(), nil)
	badResourceRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	badResourceResponse := httptest.NewRecorder()
	mux.ServeHTTP(badResourceResponse, badResourceRequest)
	if badResourceResponse.Code != http.StatusBadRequest {
		t.Fatalf("unregistered resource status=%d body=%s", badResourceResponse.Code, badResourceResponse.Body.String())
	}
	unboundMemberQuery := cloneValues(authorizeQuery)
	unboundMemberQuery.Set("member_id", "mem_oauth_code_unbound")
	unboundMemberRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+unboundMemberQuery.Encode(), nil)
	unboundMemberRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	unboundMemberResponse := httptest.NewRecorder()
	mux.ServeHTTP(unboundMemberResponse, unboundMemberRequest)
	if unboundMemberResponse.Code != http.StatusOK {
		t.Fatalf("pre-consent request status=%d body=%s", unboundMemberResponse.Code, unboundMemberResponse.Body.String())
	}
	var unboundBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(unboundMemberResponse.Body.Bytes(), &unboundBody); err != nil {
		t.Fatal(err)
	}
	unboundConsent := oauthConsentRequest(&mux, userTokens.AccessToken, unboundBody.RequestID, "approve", "mem_oauth_code_unbound", []string{"oauth.group:read"})
	if unboundConsent.Code != http.StatusBadRequest || !strings.Contains(unboundConsent.Body.String(), "not bound") {
		t.Fatalf("unbound member status=%d body=%s", unboundConsent.Code, unboundConsent.Body.String())
	}
	outOfManifestQuery := cloneValues(authorizeQuery)
	outOfManifestQuery.Set("scope", "auth.authz:check")
	outOfManifestRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+outOfManifestQuery.Encode(), nil)
	outOfManifestRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	outOfManifestResponse := httptest.NewRecorder()
	mux.ServeHTTP(outOfManifestResponse, outOfManifestRequest)
	if outOfManifestResponse.Code != http.StatusBadRequest || !strings.Contains(outOfManifestResponse.Body.String(), "not allowed") {
		t.Fatalf("out-of-manifest scope status=%d body=%s", outOfManifestResponse.Code, outOfManifestResponse.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO permissions (id, key, description, principal_kinds, agent_approval, risk, status)
		VALUES ('prm_oauth_unheld_read', 'oauth.unheld:read', 'OAuth unheld read', '["human","agent","application"]'::jsonb, 'none', 'low', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE applications SET allowed_scopes = '["oauth.group:read","oauth.unheld:read"]'::jsonb,
			manifest_permissions = '["oauth.group:read","oauth.unheld:read"]'::jsonb
		WHERE id = 'app_oauth_code_protocol'
		;
		UPDATE application_installations
		SET approved_permissions = '["oauth.group:read","oauth.unheld:read"]'::jsonb
		WHERE id = 'ins_oauth_code_protocol'
	`); err != nil {
		t.Fatal(err)
	}
	unheldScopeQuery := cloneValues(authorizeQuery)
	unheldScopeQuery.Set("scope", "oauth.unheld:read")
	unheldScopeRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+unheldScopeQuery.Encode(), nil)
	unheldScopeRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	unheldScopeResponse := httptest.NewRecorder()
	mux.ServeHTTP(unheldScopeResponse, unheldScopeRequest)
	if unheldScopeResponse.Code != http.StatusOK {
		t.Fatalf("unheld scope request status=%d body=%s", unheldScopeResponse.Code, unheldScopeResponse.Body.String())
	}
	var unheldBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(unheldScopeResponse.Body.Bytes(), &unheldBody); err != nil {
		t.Fatal(err)
	}
	unheldConsent := oauthConsentRequest(&mux, userTokens.AccessToken, unheldBody.RequestID, "approve", owner.ID, []string{"oauth.unheld:read"})
	if unheldConsent.Code != http.StatusBadRequest || !strings.Contains(unheldConsent.Body.String(), "cannot grant") {
		t.Fatalf("unheld scope status=%d body=%s", unheldConsent.Code, unheldConsent.Body.String())
	}
	authorizeRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery.Encode(), nil)
	authorizeRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	authorizeResponse := httptest.NewRecorder()
	mux.ServeHTTP(authorizeResponse, authorizeRequest)
	if authorizeResponse.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", authorizeResponse.Code, authorizeResponse.Body.String())
	}
	var authorizationBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(authorizeResponse.Body.Bytes(), &authorizationBody); err != nil {
		t.Fatal(err)
	}
	if authorizationBody.RequestID == "" {
		t.Fatal("authorization request handle is missing")
	}
	var prematureCodes int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes`).Scan(&prematureCodes); err != nil {
		t.Fatal(err)
	}
	if prematureCodes != 0 {
		t.Fatalf("GET /oauth/authorize issued %d codes before consent", prematureCodes)
	}
	var prematureAgents int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE source = 'oauth' AND oauth_client_id = $1`, clientID).Scan(&prematureAgents); err != nil {
		t.Fatal(err)
	}
	if prematureAgents != 0 {
		t.Fatalf("GET /oauth/authorize created %d Agents before consent", prematureAgents)
	}
	if unauthenticated := oauthConsentRequest(&mux, "", authorizationBody.RequestID, "approve", owner.ID, []string{"oauth.group:read"}); unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated consent status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}
	consentResponse := oauthConsentRequest(&mux, userTokens.AccessToken, authorizationBody.RequestID, "approve", owner.ID, []string{"oauth.group:read"})
	if consentResponse.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consentResponse.Code, consentResponse.Body.String())
	}
	var consentBody struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(consentResponse.Body.Bytes(), &consentBody); err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(consentBody.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if redirect.Query().Get("state") != "state-123" || redirect.Query().Get("code") == "" {
		t.Fatalf("authorize redirect=%s", redirect)
	}
	code := redirect.Query().Get("code")
	newTokenRequest := func(secret string) *http.Request {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {clientID},
			"redirect_uri":  {"https://client.test/callback"},
			"code":          {code},
			"code_verifier": {verifier},
		}
		if secret != "" {
			form.Set("client_secret", secret)
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	tokenResponse := httptest.NewRecorder()
	mux.ServeHTTP(tokenResponse, newTokenRequest(""))
	if tokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("missing client authentication status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	if tokenResponse.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing client authentication challenge")
	}
	tokenResponse = httptest.NewRecorder()
	mux.ServeHTTP(tokenResponse, newTokenRequest("wrong-client-secret"))
	if tokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong client authentication status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	tokenResponse = httptest.NewRecorder()
	mux.ServeHTTP(tokenResponse, newTokenRequest(clientSecret))
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokenBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	if tokenBody.AccessToken == "" || !strings.HasPrefix(tokenBody.RefreshToken, "ply_rt_") || tokenBody.Scope != "oauth.group:read" {
		t.Fatalf("token response=%+v", tokenBody)
	}
	claims, active, err := sessions.Introspect(ctx, tokenBody.AccessToken, clientID)
	if err != nil || !active || claims.Type != "agent" || claims.Subject == owner.ID {
		t.Fatalf("OAuth access claims=%+v active=%v err=%v", claims, active, err)
	}
	if _, active, err := sessions.Introspect(ctx, tokenBody.AccessToken, "https://other-client.test/metadata.json"); err != nil || active {
		t.Fatalf("OAuth token was accepted for another audience: active=%v err=%v", active, err)
	}
	agentMember, err := agents.OAuthAgent(ctx, owner.ID, clientID)
	if err != nil || agentMember.ID != claims.Subject {
		t.Fatalf("OAuth Agent=%+v err=%v claims=%+v", agentMember, err, claims)
	}
	var directKeyCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_credentials WHERE member_id = $1 AND kind = 'key'`, agentMember.ID).Scan(&directKeyCount); err != nil {
		t.Fatal(err)
	}
	if directKeyCount != 0 {
		t.Fatalf("OAuth Agent has %d hidden direct keys, want none", directKeyCount)
	}
	if _, err := agents.CreateOAuth(ctx, agent.CreateInput{
		OwnerMemberID: owner.ID, CreatedByUser: "usr_oauth_code_protocol", Name: "Duplicate OAuth Agent",
		Source: "oauth", OAuthClientID: clientID, ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}); err == nil {
		t.Fatal("database accepted a second live OAuth Agent for the same owner and client")
	}
	wrongVerifierQuery := cloneValues(authorizeQuery)
	wrongVerifierQuery.Set("state", "state-wrong-verifier")
	wrongAuthorizeRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+wrongVerifierQuery.Encode(), nil)
	wrongAuthorizeRequest.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	wrongAuthorizeResponse := httptest.NewRecorder()
	mux.ServeHTTP(wrongAuthorizeResponse, wrongAuthorizeRequest)
	if wrongAuthorizeResponse.Code != http.StatusOK {
		t.Fatalf("second authorize status=%d body=%s", wrongAuthorizeResponse.Code, wrongAuthorizeResponse.Body.String())
	}
	var wrongRequestBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(wrongAuthorizeResponse.Body.Bytes(), &wrongRequestBody); err != nil {
		t.Fatal(err)
	}
	wrongConsent := oauthConsentRequest(&mux, userTokens.AccessToken, wrongRequestBody.RequestID, "approve", owner.ID, []string{"oauth.group:read"})
	if wrongConsent.Code != http.StatusOK {
		t.Fatalf("second consent status=%d body=%s", wrongConsent.Code, wrongConsent.Body.String())
	}
	var wrongConsentBody struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(wrongConsent.Body.Bytes(), &wrongConsentBody); err != nil {
		t.Fatal(err)
	}
	wrongCode, err := url.Parse(wrongConsentBody.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	wrongTokenRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {"https://client.test/callback"},
		"code":          {wrongCode.Query().Get("code")},
		"code_verifier": {"wrong-verifier"},
		"client_secret": {clientSecret},
	}.Encode()))
	wrongTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongTokenResponse := httptest.NewRecorder()
	mux.ServeHTTP(wrongTokenResponse, wrongTokenRequest)
	if wrongTokenResponse.Code != http.StatusBadRequest {
		t.Fatalf("wrong PKCE verifier status=%d body=%s", wrongTokenResponse.Code, wrongTokenResponse.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {"https://client.test/callback"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_secret": {clientSecret},
	}.Encode()))
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayResponse := httptest.NewRecorder()
	mux.ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("authorization code replay status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}

	deniedID := oauthStartRequest(t, &mux, authorizeQuery)
	denied := oauthConsentRequest(&mux, userTokens.AccessToken, deniedID, "deny", "", nil)
	if denied.Code != http.StatusOK {
		t.Fatalf("denied consent status=%d body=%s", denied.Code, denied.Body.String())
	}
	var deniedBody struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(denied.Body.Bytes(), &deniedBody); err != nil {
		t.Fatal(err)
	}
	deniedRedirect, err := url.Parse(deniedBody.RedirectTo)
	if err != nil || deniedRedirect.Query().Get("error") != "access_denied" || deniedRedirect.Query().Get("code") != "" || deniedRedirect.Query().Get("state") != "state-123" {
		t.Fatalf("denied redirect=%q error=%v", deniedBody.RedirectTo, err)
	}
	if reused := oauthConsentRequest(&mux, userTokens.AccessToken, deniedID, "approve", owner.ID, []string{"oauth.group:read"}); reused.Code != http.StatusBadRequest {
		t.Fatalf("denied request was reused: %d %s", reused.Code, reused.Body.String())
	}

	retryID := oauthStartRequest(t, &mux, authorizeQuery)
	if invalid := oauthConsentRequest(&mux, userTokens.AccessToken, retryID, "approve", owner.ID, []string{"oauth.unheld:read"}); invalid.Code != http.StatusBadRequest {
		t.Fatalf("out-of-request scope was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	if corrected := oauthConsentRequest(&mux, userTokens.AccessToken, retryID, "approve", owner.ID, []string{"oauth.group:read"}); corrected.Code != http.StatusOK {
		t.Fatalf("corrected consent failed: %d %s", corrected.Code, corrected.Body.String())
	}

	concurrentID := oauthStartRequest(t, &mux, authorizeQuery)
	results := make(chan int, 2)
	for range 2 {
		go func() {
			results <- oauthConsentRequest(&mux, userTokens.AccessToken, concurrentID, "approve", owner.ID, []string{"oauth.group:read"}).Code
		}()
	}
	first, second := <-results, <-results
	statuses := []int{first, second}
	slices.Sort(statuses)
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusBadRequest {
		t.Fatalf("concurrent consent statuses = %d, %d", first, second)
	}

	rollbackID := oauthStartRequest(t, &mux, authorizeQuery)
	var codesBefore, grantsBefore int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes`).Scan(&codesBefore); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, agentMember.ID).Scan(&grantsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_oauth_consent_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'oauth.consent.approve' THEN RAISE EXCEPTION 'audit failed'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_oauth_consent_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_oauth_consent_audit()
	`); err != nil {
		t.Fatal(err)
	}
	failed := oauthConsentRequest(&mux, userTokens.AccessToken, rollbackID, "approve", owner.ID, []string{"oauth.group:read"})
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit failure consent status=%d body=%s", failed.Code, failed.Body.String())
	}
	var requestStatus string
	var codesAfter, grantsAfter int
	rollbackHash := sha256.Sum256([]byte(rollbackID))
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM oauth_authorization_requests WHERE request_hash = $1`, rollbackHash[:]).Scan(&requestStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes`).Scan(&codesAfter); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, agentMember.ID).Scan(&grantsAfter); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "pending" || codesAfter != codesBefore || grantsAfter != grantsBefore {
		t.Fatalf("audit failure committed partial consent: request=%s codes=%d/%d grants=%d/%d", requestStatus, codesAfter, codesBefore, grantsAfter, grantsBefore)
	}
}

func oauthStartRequest(t *testing.T, mux *http.ServeMux, query url.Values) string {
	t.Helper()
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("authorization request status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.RequestID == "" {
		t.Fatal("authorization request handle is missing")
	}
	return body.RequestID
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func oauthConsentRequest(mux *http.ServeMux, userToken, requestID, decision, memberID string, permissions []string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"request_id": requestID, "decision": decision, "member_id": memberID, "permissions": permissions,
	})
	request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+userToken)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func TestOAuthTokenExchangeRestrictsScopeToParentAndChildAuthority(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_token_exchange_protocol', 'token-exchange-protocol@example.test', 'token-exchange-protocol@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_token_exchange_protocol", "Token Exchange Space", "token-exchange-protocol")
	if err != nil {
		t.Fatal(err)
	}
	credentialKey := []byte("protocol-token-exchange-hmac-key-0001")
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{credentialKey}}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "exchange-parent", Source: "manual", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "exchange-child", Source: "delegation", ExpiresAt: time.Now().UTC().Add(90 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	_, siblingKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "exchange-sibling", Source: "manual", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_token_exchange_parent', $1, '["auth.members:read", "auth.members:manage"]'::jsonb, $2, 'space', $1, $3),
		       ('grt_token_exchange_child', $1, '["auth.members:read", "auth.members:manage"]'::jsonb, $4, 'space', $1, $3)
	`, owner.SpaceID, parent.ID, owner.ID, child.ID); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Hour, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
		},
	}
	h := HTTP{Issuer: "https://auth.test", Agents: agents, Sessions: sessions, Authorization: authorizer}
	var mux http.ServeMux
	h.Register(&mux)

	now := time.Now().UTC()
	parentToken, err := signer.Sign(security.Claims{
		Issuer: signer.Issuer(), Subject: parent.ID, MemberID: parent.ID, SpaceID: owner.SpaceID,
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(), JWTID: "jti_token_exchange_parent", Type: "agent",
		Scopes: []string{"auth.members:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(subjectToken, actorToken, scope string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token": {subjectToken},
			"actor_token":   {actorToken},
			"resource":      {security.DefaultApplicationAudience},
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	decode := func(res *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		var body struct {
			AccessToken string `json:"access_token"`
			Error       struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.AccessToken, body.Error.Code
	}

	firstResponse := request(parentToken, childKey, "auth.members:read")
	issued, code := decode(firstResponse)
	if code != "" || issued == "" {
		t.Fatalf("scoped token exchange status=%d code=%q token=%q body=%s", firstResponse.Code, code, issued, firstResponse.Body.String())
	}
	claims, active, err := sessions.Introspect(ctx, issued, security.DefaultApplicationAudience)
	if err != nil || !active {
		t.Fatalf("exchanged token active=%v err=%v", active, err)
	}
	if claims.Subject != child.ID || len(claims.Scopes) != 1 || claims.Scopes[0] != "auth.members:read" || claims.Actor == nil || claims.Actor.Subject != parent.ID {
		t.Fatalf("exchanged claims=%+v", claims)
	}
	parentClaims, _, err := sessions.Introspect(ctx, parentToken, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ExpiresAt > parentClaims.ExpiresAt {
		t.Fatalf("child expiry %d exceeds parent expiry %d", claims.ExpiresAt, parentClaims.ExpiresAt)
	}

	inherited, code := decode(request(parentToken, childKey, ""))
	if code != "" || inherited == "" {
		t.Fatalf("scope inheritance code=%q token=%q", code, inherited)
	}
	inheritedClaims, active, err := sessions.Introspect(ctx, inherited, security.DefaultApplicationAudience)
	if err != nil || !active || len(inheritedClaims.Scopes) != 1 || inheritedClaims.Scopes[0] != "auth.members:read" {
		t.Fatalf("inherited claims=%+v active=%v err=%v", inheritedClaims, active, err)
	}
	if _, code := decode(request(parentToken, childKey, "auth.members:manage")); code != "invalid_scope" {
		t.Fatalf("scope expansion error code=%q, want invalid_scope", code)
	}

	manageParent, err := signer.Sign(security.Claims{
		Issuer: signer.Issuer(), Subject: parent.ID, MemberID: parent.ID, SpaceID: owner.SpaceID,
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt: now.Unix(), JWTID: "jti_token_exchange_manage_parent", Type: "agent",
		Scopes: []string{"auth.groups:manage"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, code := decode(request(manageParent, childKey, "auth.groups:manage")); code != "invalid_scope" {
		t.Fatalf("child authority expansion error code=%q, want invalid_scope", code)
	}
	if _, code := decode(request(parentToken, siblingKey, "auth.members:read")); code != "invalid_grant" {
		t.Fatalf("unrelated Agent error code=%q, want invalid_grant", code)
	}

	expiredParent, err := signer.Sign(security.Claims{
		Issuer: signer.Issuer(), Subject: parent.ID, MemberID: parent.ID, SpaceID: owner.SpaceID,
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(-time.Minute).Unix(),
		IssuedAt: now.Add(-2 * time.Minute).Unix(), JWTID: "jti_token_exchange_expired_parent", Type: "agent",
		Scopes: []string{"auth.members:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, code := decode(request(expiredParent, childKey, "auth.members:read")); code != "invalid_grant" {
		t.Fatalf("expired parent error code=%q, want invalid_grant", code)
	}
	t.Run("GroupScopedAuthority", func(t *testing.T) {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
			VALUES ('grp_exchange_project', $1, 'Project', 'standard')`, owner.SpaceID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group', anchor_space_id = NULL, anchor_group_id = 'grp_exchange_project'
			WHERE id = 'grt_token_exchange_child'`); err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"group", "group_tree"} {
			if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = $1 WHERE id = 'grt_token_exchange_child'`, kind); err != nil {
				t.Fatal(err)
			}
			if token, code := decode(request(parentToken, childKey, "auth.members:read")); code != "" || token == "" {
				t.Fatalf("%s authority could not exchange a narrowed token: code=%s", kind, code)
			}
		}
		// A broad stored child grant can be narrowed by its owner's group
		// authority. The candidate resource must come from that owner boundary.
		if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'space', anchor_space_id = $1, anchor_group_id = NULL
			WHERE id = 'grt_token_exchange_child'`, owner.SpaceID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group', anchor_space_id = NULL, anchor_group_id = 'grp_exchange_project'
			WHERE id = 'grt_token_exchange_parent'`); err != nil {
			t.Fatal(err)
		}
		if token, code := decode(request(parentToken, childKey, "auth.members:read")); code != "" || token == "" {
			t.Fatalf("owner-narrowed authority could not exchange a token: code=%s", code)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_token_exchange_parent'`); err != nil {
			t.Fatal(err)
		}
		if _, code := decode(request(parentToken, childKey, "auth.members:read")); code != "invalid_scope" {
			t.Fatalf("revoked owner authority exchanged a token: code=%s", code)
		}
	})
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = (SELECT home_group_id FROM members WHERE id = $1)`, child.ID); err != nil {
		t.Fatal(err)
	}
	if _, code := decode(request(parentToken, childKey, "auth.members:read")); code != "invalid_grant" {
		t.Fatalf("inactive Agent group error code=%q, want invalid_grant", code)
	}
}

func TestOAuthRevokeDisablesAgentAuthorizationTree(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_oauth_revoke_protocol', 'oauth-revoke-protocol@example.test', 'oauth-revoke-protocol@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_oauth_revoke_protocol", "OAuth Revoke Space", "oauth-revoke-protocol")
	if err != nil {
		t.Fatal(err)
	}
	clientID := "https://revoke.client/metadata.json"
	clientSecret := "oauth-revoke-client-secret"
	clientHMACKey := []byte("protocol-oauth-revoke-client-hmac-0002")
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, redirect_uris, allowed_scopes, client_id, client_secret_hash)
		VALUES ('app_oauth_revoke_protocol', $1, 'OAuth Revoke Client', '[]'::jsonb, '[]'::jsonb, $2, $3)
	`, owner.SpaceID, clientID, hmacSHA256(clientHMACKey, clientSecret)); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{[]byte("protocol-oauth-revoke-hmac-key-0001")}}
	root, rootKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "oauth-root", Source: "oauth", OAuthClientID: clientID, ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: root.ID, Name: "oauth-child", Source: "delegation", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := agents.CreateOAuthRefreshCredential(ctx, root.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
		},
	}
	rootAccess, err := sessions.CreateAgentAccess(ctx, root.ID, owner.SpaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	childAccess, err := sessions.CreateAgentAccess(ctx, child.ID, owner.SpaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, HMACKeys: [][]byte{clientHMACKey}}
	var mux http.ServeMux
	(HTTP{Applications: apps, Agents: agents, Sessions: sessions, Authorization: authorizer}).Register(&mux)
	revoke := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	accessOnly, accessOnlyKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "oauth-access-only", Source: "oauth", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	accessOnlyToken, err := sessions.CreateAgentAccess(ctx, accessOnly.ID, owner.SpaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if res := revoke(accessOnlyToken.AccessToken); res.Code != http.StatusOK || res.Body.Len() != 0 {
		t.Fatalf("access-token revocation status=%d body=%q", res.Code, res.Body.String())
	}
	if _, active, err := sessions.Introspect(ctx, accessOnlyToken.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("access-only token after revoke active=%v err=%v", active, err)
	}
	if _, err := agents.AuthenticateKey(ctx, accessOnlyKey); err == nil {
		t.Fatal("access-token revocation left OAuth Agent key usable")
	}
	if _, active, err := sessions.Introspect(ctx, rootAccess.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
		t.Fatalf("root access before revoke active=%v err=%v", active, err)
	}
	if _, active, err := sessions.Introspect(ctx, childAccess.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
		t.Fatalf("child access before revoke active=%v err=%v", active, err)
	}
	res := revoke(refresh)
	if res.Code != http.StatusOK || res.Body.Len() != 0 {
		t.Fatalf("refresh revocation status=%d body=%q", res.Code, res.Body.String())
	}
	if _, active, err := sessions.Introspect(ctx, rootAccess.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("root access after revoke active=%v err=%v", active, err)
	}
	if _, active, err := sessions.Introspect(ctx, childAccess.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("child access after revoke active=%v err=%v", active, err)
	}
	if _, err := agents.AuthenticateKey(ctx, rootKey); err == nil {
		t.Fatal("revoked OAuth Agent key remained usable")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "client_secret": {clientSecret}}
	refreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRes := httptest.NewRecorder()
	mux.ServeHTTP(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusBadRequest {
		t.Fatalf("revoked refresh grant status=%d body=%s", refreshRes.Code, refreshRes.Body.String())
	}
	if res := revoke("not-a-known-token"); res.Code != http.StatusOK {
		t.Fatalf("unknown token revocation status=%d", res.Code)
	}
	missing := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(missing, req)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing token status=%d body=%s", missing.Code, missing.Body.String())
	}
}
