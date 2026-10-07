package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
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
	ag, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "oauth-protocol-agent", Source: "oauth", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
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
	var mux http.ServeMux
	(HTTP{Agents: agents, Sessions: sessions}).Register(&mux)

	request := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "resource": {security.DefaultApplicationAudience}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	first := request(refresh)
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
	claims, active, err := sessions.Introspect(ctx, firstBody.AccessToken, security.DefaultApplicationAudience)
	if err != nil || !active || claims.Type != "agent" || claims.Subject != ag.ID {
		t.Fatalf("renewed Agent access token claims=%+v active=%v err=%v", claims, active, err)
	}
	replay := request(refresh)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed OAuth refresh status = %d, want 400", replay.Code)
	}
	if next := request(firstBody.RefreshToken); next.Code != http.StatusBadRequest {
		t.Fatalf("family token after replay status = %d, want 400", next.Code)
	}
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
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = (SELECT home_group_id FROM members WHERE id = $1)`, child.ID); err != nil {
		t.Fatal(err)
	}
	if _, code := decode(request(parentToken, childKey, "auth.members:read")); code != "invalid_grant" {
		t.Fatalf("inactive Agent group error code=%q, want invalid_grant", code)
	}
}
