package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestServerKeyUsesCurrentInstallationMemberAuthority(t *testing.T) {
	ctx := context.Background()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("installed key test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	check := func(targetSpace, subjectID string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, subjectID, subjectID, targetSpace)
		req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if allowed := check(spaceID, member.ID); allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"decision":"allow"`) {
		t.Fatalf("installed key baseline = %d %s", allowed.Code, allowed.Body.String())
	}
	var installationMemberID string
	if err := st.Pool.QueryRow(ctx, `SELECT member_id FROM application_installations WHERE application_id = 'app_server_test' AND space_id = $1`, spaceID).Scan(&installationMemberID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, installationMemberID); err != nil {
		t.Fatal(err)
	}
	if denied := check(spaceID, member.ID); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"NO_MATCHING_PERMISSION"`) {
		t.Fatalf("revoked installation grant = %d %s", denied.Code, denied.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = NULL WHERE grantee_member_id = $1`, installationMemberID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE application_installations SET status = 'suspended' WHERE application_id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	if denied := check(spaceID, member.ID); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"APPLICATION_NOT_INSTALLED"`) {
		t.Fatalf("suspended installation = %d %s", denied.Code, denied.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE application_installations SET status = 'active' WHERE application_id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	otherSpace, otherMember, err := authz.CreateSpace(ctx, "usr_server_actor", "Other Server Space", "other-server-space")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE application_id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	if denied := check(otherSpace.ID, otherMember.ID); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"APPLICATION_NOT_INSTALLED"`) {
		t.Fatalf("uninstalled Space with unrestricted key = %d %s", denied.Code, denied.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET status = 'suspended' WHERE id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	if denied := check(spaceID, member.ID); denied.Code != http.StatusUnauthorized {
		t.Fatalf("suspended application key = %d %s", denied.Code, denied.Body.String())
	}
}

func TestServerKeyImmediatelyLosesRemovedManifestPermission(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, key, sessions := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	api := &API{Applications: apps, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("manifest key test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	check := func() *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, actor.ID, actor.ID, spaceID)
		request := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if baseline := check(); baseline.Code != http.StatusOK || !strings.Contains(baseline.Body.String(), `"decision":"allow"`) {
		t.Fatalf("manifest key baseline = %d %s", baseline.Code, baseline.Body.String())
	}
	manifest := []string{"auth.tokens:introspect"}
	if _, err := apps.UpdatePrivate(ctx, actor.ID, "app_server_test", application.UpdateInput{ManifestPermissions: &manifest}); err != nil {
		t.Fatal(err)
	}
	denied := check()
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), `"code":"PERMISSION_DENIED"`) {
		t.Fatalf("key retained removed manifest permission: %d %s", denied.Code, denied.Body.String())
	}
	var scopes []byte
	if err := st.Pool.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE application_id = 'app_server_test' AND name = 'server-test'`).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(scopes), "auth.authz:check") {
		t.Fatalf("key still stores removed manifest permission: %s", scopes)
	}
}

func TestServerKeyLosesAndRegainsSpaceAfterInstallationLifecycle(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, key, sessions := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	var installationID string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM application_installations WHERE application_id = 'app_server_test' AND space_id = $1`, spaceID).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: apps, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("lifecycle key test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	check := func() *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, actor.ID, actor.ID, spaceID)
		req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	assertCheck := func(want string) {
		t.Helper()
		result := check()
		if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), want) {
			t.Fatalf("authz.check after installation state change = %d %s, want %q", result.Code, result.Body.String(), want)
		}
	}
	assertCheck(`"decision":"allow"`)
	for _, step := range []struct {
		action string
		want   string
	}{
		{"suspend", `"deny_code":"APPLICATION_NOT_INSTALLED"`},
		{"resume", `"decision":"allow"`},
		{"uninstall", `"deny_code":"APPLICATION_NOT_INSTALLED"`},
	} {
		if _, err := apps.ChangeInstallationStatus(ctx, actor.ID, spaceID, installationID, step.action); err != nil {
			t.Fatalf("%s installation: %v", step.action, err)
		}
		assertCheck(step.want)
	}
}

func TestServerKeySourceIPAllowlistUsesDirectPeerNotForwardedHeaders(t *testing.T) {
	ctx := context.Background()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET allowed_ip_cidrs = '["192.0.2.0/24"]'::jsonb WHERE application_id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("IP restricted key test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	check := func(remoteAddr, forwardedFor string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
		req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
		req.RemoteAddr = remoteAddr
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-Forwarded-For", forwardedFor)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if allowed := check("192.0.2.17:1234", "198.51.100.8"); allowed.Code != http.StatusOK {
		t.Fatalf("allowed direct peer = %d %s", allowed.Code, allowed.Body.String())
	}
	for _, remote := range []string{"198.51.100.8:1234", ""} {
		denied := check(remote, "192.0.2.17")
		if denied.Code != http.StatusUnauthorized || !strings.Contains(denied.Body.String(), `"code":"unauthorized"`) {
			t.Fatalf("disallowed direct peer %q = %d %s", remote, denied.Code, denied.Body.String())
		}
	}
}

func TestIntrospectionStopsWhenInstallationLosesPermission(t *testing.T) {
	ctx := context.Background()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	issued, err := sessions.CreateForMember(ctx, "usr_server_actor", member.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := sessions.Signer.Sign(security.Claims{
		Issuer: sessions.Signer.Issuer(), Subject: "usr_server_actor", MemberID: member.ID,
		SpaceID: spaceID, Audience: "server-test-client", SessionID: issued.SessionID,
		ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), JWTID: "jti_installed_introspection", Type: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func() bool {
		t.Helper()
		out, err := api.introspect(ctx, &IntrospectInput{Authorization: "Bearer " + key, Body: struct {
			Token string `json:"token"`
		}{Token: token}})
		if err != nil {
			t.Fatal(err)
		}
		return out.Body.Data.Active
	}
	if !check() {
		t.Fatal("token was inactive while installation held introspection permission")
	}
	var memberID string
	if err := st.Pool.QueryRow(ctx, `SELECT member_id FROM application_installations WHERE application_id = 'app_server_test'`).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, memberID); err != nil {
		t.Fatal(err)
	}
	if check() {
		t.Fatal("token remained introspectable after installation member lost permission")
	}
}

func TestServerKeyRequiresInstallationAtAgentSubjectSpace(t *testing.T) {
	ctx := context.Background()
	st, authz, member, resourceSpace, key, sessions := newServerFixture(t)
	otherSpace, otherOwner, err := authz.CreateSpace(ctx, "usr_server_actor", "Agent Subject Space", "agent-subject-space")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	_, agentKey, err := agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: otherOwner.ID, Name: "foreign-agent", ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE application_id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions, Agents: agents}
	decision, err := api.check(ctx, &CheckInput{
		Authorization: "Bearer " + key,
		Body: CheckBody{
			Subject: CheckSubject{Token: agentKey}, Action: "self:read",
			Resource: CheckResource{Type: "member", ID: member.ID, SpaceID: resourceSpace},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Body.Data.DenyCode != "APPLICATION_NOT_INSTALLED" {
		t.Fatalf("Agent subject in uninstalled Space %s returned %+v", otherSpace.ID, decision.Body.Data)
	}
}
