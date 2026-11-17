package principal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var principalDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	principalDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := principalDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestIdentityEndpointsUseAuthorizationEngine(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{
		Accounts:      &account.Service{Store: st},
		Authorization: authz,
		Sessions:      sessions,
		Signer:        signer,
		Agents:        &agent.Service{Store: st},
	}
	header := "Bearer " + tokens.AccessToken
	if _, err := api.me(ctx, &BearerInput{Authorization: header}); err != nil {
		t.Fatalf("baseline /v1/me authorization = %v", err)
	}
	if _, err := api.listAgents(ctx, &agentsListInput{Authorization: header}); err != nil {
		t.Fatalf("baseline /v1/me/agents authorization = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'self:read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.me(ctx, &BearerInput{Authorization: header}); err == nil {
		t.Fatal("/v1/me bypassed the authorization engine")
	} else {
		assertPrincipalError(t, err, "PERMISSION_DISABLED")
	}
	if _, err := api.listAgents(ctx, &agentsListInput{Authorization: header}); err == nil {
		t.Fatal("/v1/me/agents bypassed the authorization engine")
	} else {
		assertPrincipalError(t, err, "PERMISSION_DISABLED")
	}
}

func TestMeAndSpaceMembersHTTPEndpointsReturnAuthorizedData(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	api := &API{
		Accounts:      &account.Service{Store: st},
		Authorization: authz,
		Sessions:      sessions,
		Signer:        signer,
		Agents:        &agent.Service{Store: st},
	}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	me := request("/v1/me")
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), `"email":"principal-actor@example.test"`) {
		t.Fatalf("GET /v1/me = %d %s, want authorized user data", me.Code, me.Body.String())
	}
	members := request("/v1/spaces/" + spaceID + "/members")
	if members.Code != http.StatusOK || !strings.Contains(members.Body.String(), `"id":"`+actor.ID+`"`) {
		t.Fatalf("GET /v1/spaces/{id}/members = %d %s, want authorized member data", members.Code, members.Body.String())
	}
}

func TestMeUpdateChangesPublicProfileButNeverPrivateMetadata(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET private_metadata = '{"internal":"secret"}'::jsonb WHERE id = 'usr_principal_actor'`); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	req := httptest.NewRequest(http.MethodPatch, "/v1/me", strings.NewReader(`{"name":"Carol","avatar_url":"https://cdn.example.test/avatar.png","public_metadata":{"team":"security"}}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"Carol"`) || !strings.Contains(w.Body.String(), `"team":"security"`) || strings.Contains(w.Body.String(), "internal") {
		t.Fatalf("PATCH /v1/me = %d %s, want public profile without private metadata", w.Code, w.Body.String())
	}
	var displayName, avatarURL string
	var publicMetadata, privateMetadata []byte
	if err := st.Pool.QueryRow(ctx, `SELECT display_name, avatar_url, public_metadata, private_metadata FROM users WHERE id = 'usr_principal_actor'`).Scan(&displayName, &avatarURL, &publicMetadata, &privateMetadata); err != nil {
		t.Fatal(err)
	}
	var publicValues map[string]string
	if err := json.Unmarshal(publicMetadata, &publicValues); err != nil {
		t.Fatal(err)
	}
	var privateValues map[string]string
	if err := json.Unmarshal(privateMetadata, &privateValues); err != nil {
		t.Fatal(err)
	}
	if displayName != "Carol" || avatarURL != "https://cdn.example.test/avatar.png" || publicValues["team"] != "security" || privateValues["internal"] != "secret" {
		t.Fatalf("stored profile = name %q avatar %q public %s private %s", displayName, avatarURL, publicMetadata, privateMetadata)
	}

	agentService := &agent.Service{Store: st}
	created, _, err := agentService.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "profile-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.updateMe(ctx, &MePatchInput{Authorization: "Bearer " + agentTokens.AccessToken}); err == nil {
		t.Fatal("Agent was allowed to update a user profile")
	} else {
		assertPrincipalError(t, err, "USER_ACCOUNT_REQUIRED")
	}
}

func TestGroupMembershipManagementEndpointUsesTargetGroupFacts(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Group endpoint target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	groupID := "grp_endpoint_membership"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ($1, $2, 'Endpoint group', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.groups:manage")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	req := httptest.NewRequest(http.MethodPut, "/v1/spaces/"+spaceID+"/groups/"+groupID+"/members/"+target.ID, nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()
	route.Middleware(route.Principal, mux).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT group membership = %d %s, want 200", w.Code, w.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1 AND member_id = $2`, groupID, target.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("endpoint membership rows = %d, want 1", count)
	}
}

func TestGroupCreationManagementEndpointCreatesStandardRoot(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/groups", strings.NewReader(`{"name":"Operations"}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	route.Middleware(route.Principal, mux).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST group creation = %d %s, want 200", w.Code, w.Body.String())
	}
	var kind, status string
	if err := st.Pool.QueryRow(ctx, `SELECT kind, status FROM groups WHERE space_id = $1 AND name = 'Operations'`, spaceID).Scan(&kind, &status); err != nil {
		t.Fatal(err)
	}
	if kind != "standard" || status != "active" {
		t.Fatalf("endpoint-created group = kind %q status %q, want standard active", kind, status)
	}
}

func TestInvitationCreationManagementEndpointStoresOnlyTokenHash(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}, Invitations: &invitation.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/invitations", strings.NewReader(`{"email":"Invitee@Example.Test"}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	route.Middleware(route.Principal, mux).ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"email_normalized":"invitee@example.test"`) || !strings.Contains(w.Body.String(), `"token":"iv_`) {
		t.Fatalf("POST invitation = %d %s, want one-time token response", w.Code, w.Body.String())
	}
	var tokenHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM invitation_tokens WHERE email_normalized = 'invitee@example.test'`).Scan(&tokenHash); err != nil {
		t.Fatal(err)
	}
	if len(tokenHash) != 32 || strings.Contains(w.Body.String(), string(tokenHash)) {
		t.Fatalf("invitation token storage or response is unsafe: hash length=%d response=%s", len(tokenHash), w.Body.String())
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'invitation.create' AND actor_id = $1`, owner.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("invitation audit rows = %d, want 1", audits)
	}
}

func TestGroupMoveManagementEndpointUsesTargetFacts(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	const sourceID = "grp_endpoint_move_source"
	const parentID = "grp_endpoint_move_parent"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ($1, $3, 'Endpoint move source', 'standard', 'active'), ($2, $3, 'Endpoint move parent', 'standard', 'active')
	`, sourceID, parentID, spaceID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.groups:manage")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/groups/"+sourceID+"/move", strings.NewReader(`{"parent_group_id":"`+parentID+`"}`))
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	route.Middleware(route.Principal, mux).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST group move = %d %s, want 200", w.Code, w.Body.String())
	}
	var parent string
	if err := st.Pool.QueryRow(ctx, `SELECT coalesce(parent_id, '') FROM groups WHERE id = $1`, sourceID).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != parentID {
		t.Fatalf("endpoint group parent = %q, want %q", parent, parentID)
	}
}

func TestSuspendedSpaceDeniesManagementLikeAuthorizationCheck(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	input := &membersListInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}
	if _, err := api.listMembers(ctx, input); err != nil {
		t.Fatalf("active Space management: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, spaceID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "SPACE_INACTIVE" {
		t.Fatalf("authz.check = %+v, want SPACE_INACTIVE", decision)
	}
	if _, err := api.listMembers(ctx, input); err == nil {
		t.Fatal("suspended Space allowed management endpoint")
	} else {
		assertPrincipalError(t, err, decision.Code)
	}
}

func TestMePermissionsEndpointUsesEffectiveEngineDecisionsForHumanAndAgent(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "permissions-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "self:read")
	humanTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	for name, token := range map[string]string{"human": humanTokens.AccessToken, "agent": agentTokens.AccessToken} {
		out, err := api.mePermissions(ctx, &BearerInput{Authorization: "Bearer " + token})
		if err != nil {
			t.Fatalf("%s permissions: %v", name, err)
		}
		found := false
		for _, permission := range out.Body.Data {
			if permission.Permission == "self:read" && permission.Scope == "space" && permission.Anchor == spaceID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s permissions = %+v, want effective self:read Space scope", name, out.Body.Data)
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'self:read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.mePermissions(ctx, &BearerInput{Authorization: "Bearer " + humanTokens.AccessToken}); err == nil {
		t.Fatal("disabled self:read was accepted by /v1/me/permissions")
	} else {
		assertPrincipalError(t, err, "PERMISSION_DISABLED")
	}
}

func TestUserSessionEndpointsListAndRevokeCurrentOrAllSessions(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	first, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "first", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "second", 1)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := api.listSessions(ctx, &BearerInput{Authorization: "Bearer " + first.AccessToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Body.Data) != 2 {
		t.Fatalf("listed sessions = %+v, want both active sessions", listed.Body.Data)
	}
	revoked, err := api.revokeSession(ctx, &SessionPathInput{Authorization: "Bearer " + first.AccessToken, ID: second.SessionID})
	if err != nil || !revoked.Body.Data.Revoked {
		t.Fatalf("revoke session = %+v, %v", revoked, err)
	}
	if _, active, err := sessions.Introspect(ctx, second.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("revoked session introspection = active=%v err=%v", active, err)
	}
	if _, err := api.logout(ctx, &LogoutInput{Authorization: "Bearer " + first.AccessToken}); err != nil {
		t.Fatal(err)
	}
	if _, active, err := sessions.Introspect(ctx, first.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("current logout introspection = active=%v err=%v", active, err)
	}
	third, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "third", 1)
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "fourth", 1)
	if err != nil {
		t.Fatal(err)
	}
	all := &struct {
		All bool `json:"all,omitempty"`
	}{All: true}
	if _, err := api.logout(ctx, &LogoutInput{Authorization: "Bearer " + third.AccessToken, Body: all}); err != nil {
		t.Fatal(err)
	}
	if _, active, err := sessions.Introspect(ctx, fourth.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("all-session logout introspection = active=%v err=%v", active, err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "session-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.listSessions(ctx, &BearerInput{Authorization: "Bearer " + agentTokens.AccessToken}); err == nil {
		t.Fatal("Agent accessed user device sessions")
	} else {
		assertPrincipalError(t, err, "USER_ACCOUNT_REQUIRED")
	}
}

func TestRemoveCurrentMemberRevokesOnlyCurrentHumanBinding(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	other, err := authz.CreateMember(ctx, owner.ID, "usr_principal_actor", spaceID, "second identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "self-remove", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	req := httptest.NewRequest(http.MethodDelete, "/v1/me/member", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"accepted":true`) {
		t.Fatalf("DELETE /v1/me/member = %d %s, want accepted", w.Code, w.Body.String())
	}
	var currentStatus, otherStatus string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM user_members WHERE user_id = $1 AND member_id = $2`, "usr_principal_actor", owner.ID).Scan(&currentStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM user_members WHERE user_id = $1 AND member_id = $2`, "usr_principal_actor", other.ID).Scan(&otherStatus); err != nil {
		t.Fatal(err)
	}
	if currentStatus != "revoked" || otherStatus != "active" {
		t.Fatalf("self removal statuses = current %q other %q, want revoked/active", currentStatus, otherStatus)
	}
	if _, active, err := sessions.Introspect(ctx, tokens.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("current member token after self removal = active %v err %v, want inactive", active, err)
	}
	otherTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", other.ID, nil, "remaining", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, active, err := sessions.Introspect(ctx, otherTokens.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
		t.Fatalf("remaining member token = active %v err %v, want active", active, err)
	}
}

func TestAgentCanRemoveItselfAndItsSubtreeThroughMemberEndpoint(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	root, rootKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "self-removing-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: root.ID, Name: "self-removing-child", ExpiresAt: time.Now().UTC().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, root.ID, "self:read")
	tokens, err := sessions.CreateAgentAccess(ctx, root.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	req := httptest.NewRequest(http.MethodDelete, "/v1/me/member", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"accepted":true`) {
		t.Fatalf("Agent DELETE /v1/me/member = %d %s, want accepted", w.Code, w.Body.String())
	}
	var rootStatus, childStatus, removedGroups int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE id = $1 AND status = 'removed'`, root.ID).Scan(&rootStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE id = $1 AND status = 'removed'`, child.ID).Scan(&childStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE owner_member_id = $1 AND status = 'removed'`, root.ID).Scan(&removedGroups); err != nil {
		t.Fatal(err)
	}
	if rootStatus != 1 || childStatus != 1 || removedGroups != 1 {
		t.Fatalf("agent self removal tombstones = root %d child %d groups %d, want 1/1/1", rootStatus, childStatus, removedGroups)
	}
	if _, err := agents.AuthenticateKey(ctx, rootKey); err == nil {
		t.Fatal("root Agent credential remained usable after self removal")
	}
	if _, err := agents.AuthenticateKey(ctx, childKey); err == nil {
		t.Fatal("child Agent credential remained usable after parent self removal")
	}
	if _, active, err := sessions.Introspect(ctx, tokens.AccessToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatalf("removed Agent token = active %v err %v, want inactive", active, err)
	}
}

func TestMeMembersHTTPEndpointReturnsOnlyActiveUserBindings(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	second, err := authz.CreateMember(ctx, actor.ID, "usr_principal_actor", spaceID, "second identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	api := &API{
		Accounts:      &account.Service{Store: st},
		Authorization: authz,
		Sessions:      sessions,
		Signer:        signer,
		Agents:        &agent.Service{Store: st},
	}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request("/v1/me/members")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+actor.ID+`"`) || !strings.Contains(w.Body.String(), `"id":"`+second.ID+`"`) {
		t.Fatalf("active member bindings = %d %s, want both members", w.Code, w.Body.String())
	}
	if w = request("/v1/me/members?type=human"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+second.ID+`"`) {
		t.Fatalf("human member filter = %d %s, want both human members", w.Code, w.Body.String())
	}
	if w = request("/v1/me/members?type=agent"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"data":[]`) {
		t.Fatalf("agent member filter = %d %s, want an empty result", w.Code, w.Body.String())
	}
	if w = request("/v1/me/members?type=unknown"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("invalid member filter = %d %s, want VALIDATION_FAILED", w.Code, w.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 minute' WHERE user_id = 'usr_principal_actor' AND member_id = $1`, second.ID); err != nil {
		t.Fatal(err)
	}
	w = request("/v1/me/members")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+actor.ID+`"`) || strings.Contains(w.Body.String(), `"id":"`+second.ID+`"`) {
		t.Fatalf("revoked member bindings = %d %s, want only the active member", w.Code, w.Body.String())
	}
}

func TestCurrentMemberUsesSelectedBindingWhenUserHasMultipleMembers(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	selected, err := authz.CreateMember(ctx, actor.ID, "usr_principal_actor", spaceID, "second identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, actor.ID, selected.ID, "self:read")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", selected.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: authz.Store}}
	memberID, userID, ctx, err := api.currentMember(ctx, "Bearer "+tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if memberID != selected.ID || userID != "usr_principal_actor" {
		t.Fatalf("current member = %q, user = %q; want selected member", memberID, userID)
	}
	if _, err := api.listAgents(ctx, &agentsListInput{Authorization: "Bearer " + tokens.AccessToken}); err != nil {
		t.Fatalf("selected member could not use a permitted endpoint: %v", err)
	}
}

func TestManagementAuthorizationUsesTargetGroupFactsAndMatchesCheck(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	member, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "group target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	outside, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "outside target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	groupID := "grp_scope_target"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Scoped operators', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO group_members (group_id, member_id) VALUES ($1, $2), ($1, $3)
	`, groupID, actor.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_scope_target', $1, '["auth.members:manage"]'::jsonb, $2, 'group_tree', $3, $2)
	`, spaceID, actor.ID, groupID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	spaceDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	createErr := error(nil)
	if _, createErr = api.createMember(ctx, &createMemberInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}); createErr == nil {
		t.Fatal("group-scoped manager was allowed to manage the whole Space")
	} else {
		assertPrincipalError(t, createErr, spaceDecision.Code)
	}
	outsideGroup, err := authz.ResourceGroupForMember(ctx, outside.ID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	targetDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID, ResourceGroup: outsideGroup})
	if err != nil {
		t.Fatal(err)
	}
	suspendErr := error(nil)
	if _, suspendErr = api.suspendMember(ctx, &memberPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: outside.ID}); suspendErr == nil {
		t.Fatal("group-scoped manager was allowed to manage a member outside the group")
	} else {
		assertPrincipalError(t, suspendErr, targetDecision.Code)
	}
	insideDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID, ResourceGroup: groupID})
	if err != nil {
		t.Fatal(err)
	}
	if insideDecision.Effect != engine.Allow {
		t.Fatalf("authz.check equivalent target decision = %+v, want allow", insideDecision)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_scope_assign_target', $1, '["auth.grants:assign"]'::jsonb, $2, 'group_tree', $3, $2)
	`, spaceID, actor.ID, groupID); err != nil {
		t.Fatal(err)
	}
	insideGrant := &createGrantInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}
	insideGrant.Body.Grantee.MemberID = member.ID
	insideGrant.Body.Permissions = []string{"auth.members:read"}
	if _, err := api.createGrant(ctx, insideGrant); err != nil {
		t.Fatalf("group-scoped grant manager could not make an empty-delta change in its group: %v", err)
	}
	outsideGrant := &createGrantInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}
	outsideGrant.Body.Grantee.MemberID = outside.ID
	outsideGrant.Body.Permissions = []string{"auth.members:read"}
	if _, err := api.createGrant(ctx, outsideGrant); err == nil {
		t.Fatal("group-scoped grant manager changed a member outside the group")
	} else {
		assertPrincipalError(t, err, "SCOPE_OUT_OF_BOUNDS")
	}
	if _, err := api.suspendMember(ctx, &memberPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: member.ID}); err != nil {
		t.Fatalf("management endpoint denied the same target authz.check allows: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.createMember(ctx, &createMemberInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}); err == nil {
		t.Fatal("management endpoint accepted a disabled permission")
	} else {
		assertPrincipalError(t, err, "PERMISSION_DISABLED")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'active', principal_kinds = '["agent"]'::jsonb WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.createMember(ctx, &createMemberInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}); err == nil {
		t.Fatal("management endpoint accepted a disallowed principal kind")
	} else {
		assertPrincipalError(t, err, "PRINCIPAL_KIND_NOT_ALLOWED")
	}
}

func TestGrantRevokeManagementUsesGrantTargetGroupFacts(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "group revoke target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	outside, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "space revoke target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	groupID := "grp_revoke_scope"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Grant revoke scope', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO group_members (group_id, member_id) VALUES ($1, $2), ($1, $3)
	`, groupID, actor.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	groupGrant, err := authz.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID)
	if err != nil {
		t.Fatalf("create group target grant: %v", err)
	}
	spaceGrant, err := authz.CreateInlineGrant(ctx, actor.ID, spaceID, outside.ID, []string{"auth.members:read"}, "space", spaceID)
	if err != nil {
		t.Fatalf("create Space target grant: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_revoke_scope_manager', $1, '["auth.grants:assign"]'::jsonb, $2, 'group_tree', $3, $2)
	`, spaceID, actor.ID, groupID); err != nil {
		t.Fatal(err)
	}
	groupDecision, _, err := authz.Check(ctx, authorization.CheckRequest{
		MemberID: actor.ID, Permission: "auth.grants:assign", ResourceSpace: spaceID, ResourceGroup: groupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if groupDecision.Effect != engine.Allow {
		t.Fatalf("group target authz.check = %+v, want allow", groupDecision)
	}
	spaceDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.grants:assign", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if spaceDecision.Effect != engine.Deny || spaceDecision.Code != "SCOPE_OUT_OF_BOUNDS" {
		t.Fatalf("Space target authz.check = %+v, want SCOPE_OUT_OF_BOUNDS", spaceDecision)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	if _, err := api.revokeGrant(ctx, &revokeGrantInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, GrantID: groupGrant.ID}); err != nil {
		t.Fatalf("group-scoped manager could not revoke a group target grant: %v", err)
	}
	var revoked bool
	if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM authorization_grants WHERE id = $1`, groupGrant.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("group target grant was not revoked")
	}
	if _, err := api.revokeGrant(ctx, &revokeGrantInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, GrantID: spaceGrant.ID}); err == nil {
		t.Fatal("group-scoped manager revoked a grant outside its target group")
	} else {
		assertPrincipalError(t, err, spaceDecision.Code)
	}
}

func TestMemberInMultipleGroupsRequiresSpaceWideManagement(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "multiple groups", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status) VALUES
		('grp_a_scope', $1, 'Scoped', 'standard', 'active'),
		('grp_z_other', $1, 'Other', 'standard', 'active')
	`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO group_members (group_id, member_id) VALUES
		('grp_a_scope', $1), ('grp_a_scope', $2), ('grp_z_other', $2)
	`, actor.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_scoped_multi', $1, '["auth.members:manage"]'::jsonb, $2, 'group_tree', 'grp_a_scope', $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	if _, err := api.suspendMember(ctx, &memberPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: target.ID}); err == nil {
		t.Fatal("group-scoped manager changed a member shared with another group")
	} else {
		assertPrincipalError(t, err, "SCOPE_OUT_OF_BOUNDS")
	}
	if err := authz.SetMemberStatus(ctx, actor.ID, spaceID, target.ID, "suspended"); err == nil {
		t.Fatal("transactional management changed a member shared with another group")
	} else {
		assertPrincipalError(t, err, "SCOPE_OUT_OF_BOUNDS")
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, target.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("target status = %q after denied management", status)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_space_multi', $1, '["auth.members:manage"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := api.suspendMember(ctx, &memberPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: target.ID}); err != nil {
		t.Fatalf("Space-wide manager was denied: %v", err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, target.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("target status = %q after Space-wide management", status)
	}
}

func TestNestedInactiveAgentOwnerReturnsOwnerInactiveAtManagementEndpoint(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "parent", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, memberID := range []string{parent.ID, child.ID} {
		if _, err := st.Pool.Exec(ctx, `
			INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["auth.members:manage"]'::jsonb, $3, 'space', $2, $4)
		`, "grt_owner_chain_"+memberID, spaceID, memberID, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := sessions.CreateAgentAccess(ctx, child.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: child.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Code != "OWNER_INACTIVE" {
		t.Fatalf("authz.check decision = %+v, want OWNER_INACTIVE", decision)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+tokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
		t.Fatal("child Agent with inactive ancestor used management endpoint")
	} else {
		assertPrincipalError(t, err, "OWNER_INACTIVE")
	}
}

func TestManagementEndpointRejectsPermissionExcludedBySpaceEnvelope(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+tokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
		t.Fatalf("baseline management permission = %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO space_envelope_entries (space_id, permission_id, mode)
		SELECT $1, id, 'delegate' FROM permissions WHERE key = 'auth.members:read'
	`, spaceID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "ENVELOPE_EXCLUDED" {
		t.Fatalf("authz.check decision = %+v, want ENVELOPE_EXCLUDED", decision)
	}
	if _, err := api.createMember(ctx, &createMemberInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}); err == nil {
		t.Fatal("management endpoint ignored the Space envelope")
	} else {
		assertPrincipalError(t, err, "ENVELOPE_EXCLUDED")
	}
}

func TestAgentManagementUsesOwnerEnvelopeAndSupportsHAEndpoints(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "management-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.members:manage")
	humanTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+humanTokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
		t.Fatalf("human management decision = %v", err)
	}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
		t.Fatalf("Agent H/A management endpoint was denied: %v", err)
	}
	for _, token := range []string{humanTokens.AccessToken, agentTokens.AccessToken} {
		input := &createMemberInput{Authorization: "Bearer " + token, ID: spaceID}
		input.Body.Name = "management endpoint member"
		input.Body.Kind = "human"
		input.Body.BindingPolicy = "single"
		if _, err := api.createMember(ctx, input); err != nil {
			t.Fatalf("H/A management handler denied an equivalent grant: %v", err)
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
		t.Fatal("Agent retained a permission after its owner's grant was revoked")
	} else {
		assertPrincipalError(t, err, "OWNER_ENVELOPE_EXCLUDED")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
		t.Fatal("Agent with inactive owner was allowed by a management endpoint")
	} else {
		assertPrincipalError(t, err, "OWNER_INACTIVE")
	}
}

func TestAssignmentRightManagementEndpointsUseAuthorizationEngineAndPreserveGrants(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "delegated member", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	authz.StepUp = sessions
	create := &createAssignmentRightInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}
	create.Body.HolderMemberID = target.ID
	create.Body.Permissions = []string{"auth.members:manage"}
	seedStepUpProof(t, st, tokens.SessionID, "assignment_rights.create", map[string]any{"space_id": spaceID, "holder_member_id": target.ID, "permissions": create.Body.Permissions, "anchor_space_id": "", "anchor_group_id": "", "covers_subtree": false, "can_redelegate": false, "expires_at": nil})
	rightOut, err := api.createAssignmentRight(ctx, create)
	if err != nil {
		t.Fatalf("assignment-right endpoint create = %v", err)
	}
	if rightOut.Body.Data.ID == "" || rightOut.Body.Data.ParentID == "" {
		t.Fatalf("created assignment right = %+v", rightOut.Body.Data)
	}
	seedStepUpProof(t, st, tokens.SessionID, "assignment_rights.list", map[string]any{"space_id": spaceID})
	listOut, err := api.listAssignmentRights(ctx, &assignmentRightsInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID})
	if err != nil {
		t.Fatalf("assignment-right endpoint list = %v", err)
	}
	if len(listOut.Body.Data) != 2 {
		t.Fatalf("assignment-right list = %d entries, want system and delegated rights", len(listOut.Body.Data))
	}
	if _, err := authz.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("create existing grant = %v", err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "assignment_rights.revoke", map[string]any{"space_id": spaceID, "assignment_right_id": rightOut.Body.Data.ID})
	if _, err := api.revokeAssignmentRight(ctx, &assignmentRightPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, RightID: rightOut.Body.Data.ID}); err != nil {
		t.Fatalf("assignment-right endpoint revoke = %v", err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "assignment_rights.list", map[string]any{"space_id": spaceID})
	listOut, err = api.listAssignmentRights(ctx, &assignmentRightsInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if len(listOut.Body.Data) != 1 || listOut.Body.Data[0].Source != "system" {
		t.Fatalf("active assignment-right list after revoke = %+v", listOut.Body.Data)
	}
	var grants int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, target.ID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Fatalf("revoking assignment right removed %d existing grants", grants)
	}
}

func TestAssignmentRightManagementEndpointRejectsAgentDeltaWithoutOwnerAssignmentCoverage(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "assignment-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.assign_rights:manage")
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "delegated member", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	create := &createAssignmentRightInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}
	create.Body.HolderMemberID = target.ID
	create.Body.Permissions = []string{"auth.members:manage"}
	if _, err := api.createAssignmentRight(ctx, create); err == nil {
		t.Fatal("Agent created an assignment right without owner assignment-right coverage")
	} else {
		assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
}

func TestAgentManagementRequiresVerifiedApprovalFact(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "approval-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.bindings:manage")
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.bindings:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("unapproved Agent decision = %+v, want APPROVAL_REQUIRED", decision)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	if _, _, err := api.actorForSpace(ctx, "Bearer "+tokens.AccessToken, spaceID, "auth.bindings:manage"); err == nil {
		t.Fatal("Agent governance operation ignored the missing approval")
	} else {
		assertPrincipalError(t, err, decision.Code)
	}
}

func TestAgentCanCreateSpaceOnBehalfOfOwnerUser(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "space-creator", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	if _, err := api.createSpace(ctx, &createSpaceInput{Authorization: "Bearer " + agentTokens.AccessToken}); err == nil {
		t.Fatal("Agent without self:read was allowed to create a Space")
	} else {
		assertPrincipalError(t, err, "NO_MATCHING_PERMISSION")
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "self:read")
	in := &createSpaceInput{Authorization: "Bearer " + agentTokens.AccessToken}
	in.Body.Name = "Agent Created Space"
	in.Body.Slug = "agent-created-space"
	out, err := api.createSpace(ctx, in)
	if err != nil {
		t.Fatalf("Agent Space creation failed: %v", err)
	}
	if out.Body.Data.Member.Kind != "human" {
		t.Fatalf("created administrator kind = %q, want human owner membership", out.Body.Data.Member.Kind)
	}
	bindings, err := authz.ListBindings(ctx, out.Body.Data.Member.ID, out.Body.Data.Space.ID, out.Body.Data.Member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].UserID != "usr_principal_actor" || bindings[0].Status != "active" {
		t.Fatalf("created administrator bindings = %+v, want active owner user binding", bindings)
	}
}

func TestHumanSpaceCreationUsesAuthorizationEngine(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	in := &createSpaceInput{Authorization: "Bearer " + tokens.AccessToken}
	in.Body.Name = "Denied Human Space"
	in.Body.Slug = "denied-human-space"
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := api.createSpace(ctx, in); err == nil {
		t.Fatal("human created a Space without self:read")
	} else {
		assertPrincipalError(t, err, "NO_MATCHING_PERMISSION")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM spaces WHERE slug = $1`, in.Body.Slug).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Space was created after the authorization engine denied its creator")
	}
}

func TestAgentCannotAssignNewSpaceToArbitrarySharedOwnerUser(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "shared-space-creator", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "self:read")
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_shared_owner', 'shared-owner@example.test', 'shared-owner@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO user_members (user_id, member_id, status)
		VALUES ('usr_shared_owner', $1, 'active')
	`, owner.ID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	in := &createSpaceInput{Authorization: "Bearer " + tokens.AccessToken}
	in.Body.Name = "Ambiguous Space"
	in.Body.Slug = "ambiguous-space"
	if _, err := api.createSpace(ctx, in); err == nil {
		t.Fatal("Agent assigned a new Space to an arbitrary shared owner user")
	} else {
		assertPrincipalError(t, err, "USER_ACCOUNT_REQUIRED")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM spaces WHERE slug = 'ambiguous-space'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("Space was created despite ambiguous owner account")
	}
}

func TestAgentCannotCreateChildWithoutAgentsPermission(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "limited-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	_, err = api.createAgent(ctx, &agentsInput{Authorization: "Bearer " + tokens.AccessToken})
	if err == nil {
		t.Fatal("Agent without auth.agents:create created a child Agent")
	}
	assertPrincipalError(t, err, "NO_MATCHING_PERMISSION")
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_agent_create_owner', $1, '["auth.agents:create"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.agents:create")
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	_, err = api.createAgent(ctx, &agentsInput{Authorization: "Bearer " + tokens.AccessToken})
	if err == nil {
		t.Fatal("Agent created a child after its owner lost auth.agents:create")
	}
	assertPrincipalError(t, err, "OWNER_ENVELOPE_EXCLUDED")
}

func TestAgentCreatesChildWithoutHumanStepUp(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.agents:create")
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "parent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, parent.ID, "auth.agents:create")
	tokens, err := sessions.CreateAgentAccess(ctx, parent.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	in := &agentsInput{Authorization: "Bearer " + tokens.AccessToken}
	in.Body.Name = "child"
	expires := parent.ExpiresAt.Add(-time.Minute)
	in.Body.ExpiresAt = &expires
	out, err := api.createAgent(ctx, in)
	if err != nil {
		t.Fatalf("Agent creation without human step-up = %v", err)
	}
	if out.Body.Data.Agent.CreatedByMember != parent.ID {
		t.Fatalf("created Agent parent = %q, want %q", out.Body.Data.Agent.CreatedByMember, parent.ID)
	}
}

func TestCreateAgentEndpointReturnsOneTimeAgentCredential(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_endpoint_agent_create', $1, '["auth.agents:create"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	agents.StepUp = sessions
	in := &agentsInput{Authorization: "Bearer " + tokens.AccessToken}
	in.Body.Name = "one-time-credential"
	seedStepUpProof(t, st, tokens.SessionID, "me.agents.create", map[string]any{"name": in.Body.Name, "expires_at": nil, "source": ""})
	out, err := api.createAgent(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.Body.Data.AgentKey, "ply_ag_") || out.Body.Data.Credential != "agent_key" {
		t.Fatalf("agent creation response = %+v, want one-time ply_ag_ credential", out.Body.Data)
	}
	credential, err := agents.AuthenticateKey(ctx, out.Body.Data.AgentKey)
	if err != nil {
		t.Fatalf("returned credential was not usable: %v", err)
	}
	if credential.MemberID != out.Body.Data.Agent.ID || credential.SpaceID != spaceID {
		t.Fatalf("credential = %+v, want created Agent %s in Space %s", credential, out.Body.Data.Agent.ID, spaceID)
	}
	var grants int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, out.Body.Data.Agent.ID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("new Agent has %d grants, want no initial grants", grants)
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE member_id = $1`, out.Body.Data.Agent.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), out.Body.Data.AgentKey) {
		t.Fatal("agent credential secret was stored in plaintext")
	}
}

func TestAgentGrantReplacementEndpointReplacesDirectGrants(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "grant-replacement-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.CreateAssignmentRight(ctx, owner.ID, spaceID, created.ID, []string{"auth.grants:assign", "auth.members:read", "auth.members:manage"}, spaceID, "", true, true, nil); err != nil {
		t.Fatalf("owner could not delegate Agent grant coverage: %v", err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.grants:assign")
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	in := &agentGrantInput{Authorization: "Bearer " + tokens.AccessToken, ID: created.ID}
	in.Body.Permissions = []string{"auth.grants:assign", "auth.members:read"}
	in.Body.Scope = "space"
	in.Body.AnchorSpaceID = spaceID
	if _, err := api.replaceAgentGrants(ctx, in); err != nil {
		t.Fatalf("first Agent grant replacement failed: %v", err)
	}
	in.Body.Permissions = []string{"auth.grants:assign", "auth.members:manage"}
	if _, err := api.replaceAgentGrants(ctx, in); err != nil {
		t.Fatalf("second Agent grant replacement failed: %v", err)
	}
	var active, revoked int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM authorization_grants WHERE grantee_member_id = $1 AND role_id IS NULL`, created.ID).Scan(&active, &revoked); err != nil {
		t.Fatal(err)
	}
	if active != 1 || revoked != 2 {
		t.Fatalf("Agent direct grants active=%d revoked=%d, want 1 active and 2 revoked", active, revoked)
	}
	readDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if readDecision.Effect != engine.Deny {
		t.Fatalf("replaced Agent grant still allowed members:read: %+v", readDecision)
	}
	manageDecision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if manageDecision.Effect != engine.Allow {
		t.Fatalf("replacement Agent grant was not effective: %+v", manageDecision)
	}
}

func TestOwnerDelegatesToAgentWithoutOrdinaryAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "system-right-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		DELETE FROM role_permissions rp USING permissions p, authorization_grants g
		WHERE rp.permission_id = p.id AND rp.role_id = g.role_id
		  AND g.grantee_member_id = $1 AND p.key = 'auth.grants:assign'
	`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: owner.ID, Permission: "auth.grants:assign", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Deny {
		t.Fatalf("ordinary grant permission = %+v err=%v, want deny", decision, err)
	}
	userTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	in := &agentGrantInput{Authorization: "Bearer " + userTokens.AccessToken, ID: created.ID}
	in.Body.Permissions = []string{"auth.members:read"}
	in.Body.Scope = "space"
	in.Body.AnchorSpaceID = spaceID
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal test", "1.0.0")))
	body, err := json.Marshal(in.Body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/me/agents/"+created.ID+"/grants", strings.NewReader(string(body)))
	req.Header.Set("Authorization", in.Authorization)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("owner system assignment right over HTTP = %d %s", res.Code, res.Body.String())
	}
	decision, _, err = authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("Agent delegated permission = %+v err=%v, want allow", decision, err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO permissions (id, key, description, principal_kinds, agent_approval, risk, status)
		VALUES ('prm_agent_human_only', 'agent.human:only', 'Human only', '["human"]'::jsonb, 'none', 'low', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "agent.human:only")
	in.Body.Permissions = []string{"agent.human:only"}
	_, err = api.replaceAgentGrants(ctx, in)
	assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	decision, _, err = authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("denied principal-kind replacement changed Agent authority: %+v err=%v", decision, err)
	}
	oauthAgent, err := agents.CreateOAuth(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "OAuth Agent", Source: "oauth", OAuthClientID: "https://client.example.test/metadata.json", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	in.ID = oauthAgent.ID
	in.Body.Permissions = []string{"auth.members:read"}
	_, err = api.replaceAgentGrants(ctx, in)
	assertPrincipalError(t, err, "VALIDATION_FAILED")
}

func TestAgentOwnerCannotDelegateApprovalRequiredPermission(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "delegating-parent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, CreatedByUser: "usr_principal_actor", Name: "delegating-child", ExpiresAt: parent.ExpiresAt.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, parent.ID, "auth.members:read")
	seedTestInlineGrant(t, st, spaceID, owner.ID, parent.ID, "auth.connections:manage")
	parentTokens, err := sessions.CreateAgentAccess(ctx, parent.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	in := &agentGrantInput{Authorization: "Bearer " + parentTokens.AccessToken, ID: child.ID}
	in.Body.Permissions = []string{"auth.members:read"}
	in.Body.Scope = "space"
	in.Body.AnchorSpaceID = spaceID
	if _, err := api.replaceAgentGrants(ctx, in); err != nil {
		t.Fatalf("parent Agent could not delegate usable permission: %v", err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: child.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("child delegated permission = %+v err=%v, want allow", decision, err)
	}
	in.Body.Permissions = []string{"auth.connections:manage"}
	_, err = api.replaceAgentGrants(ctx, in)
	assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	decision, _, err = authz.Check(ctx, authorization.CheckRequest{MemberID: child.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("denied replacement changed child authority: %+v err=%v", decision, err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.members:read'
	`, parent.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = authz.Check(ctx, authorization.CheckRequest{MemberID: child.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Deny || decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
		t.Fatalf("child authority after parent revocation = %+v err=%v, want owner-envelope deny", decision, err)
	}
}

func newPrincipalFixture(t *testing.T) (*store.Store, *authorization.Service, authorization.Member, string, *session.Service, *security.Signer) {
	t.Helper()
	ctx := context.Background()
	database, err := principalDB.Clone(ctx)
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
		VALUES ('usr_principal_actor', 'principal-actor@example.test', 'principal-actor@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, member, err := authz.CreateSpace(ctx, "usr_principal_actor", "Principal Test Space", "principal-test-space")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("h", 32))},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	return st, authz, member, space.ID, sessions, signer
}

func assertPrincipalError(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("error = %v, want API error %q", err, want)
	}
}

func seedTestInlineGrant(t *testing.T, st *store.Store, spaceID, actorID, memberID, permission string) {
	t.Helper()
	encoded, err := json.Marshal([]string{permission})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ($1, $2, $3::jsonb, $4, 'space', $2, $5)
	`, string(ids.New[ids.GrantID]("grt")), spaceID, string(encoded), memberID, actorID); err != nil {
		t.Fatal(err)
	}
}

func seedStepUpProof(t *testing.T, st *store.Store, sessionID, operation string, request any) {
	t.Helper()
	digest, err := stepup.DigestValue(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `
		UPDATE sessions
		SET step_up_operation = $2, step_up_digest = $3, step_up_method = 'totp',
		    step_up_expires_at = now() + interval '5 minutes'
		WHERE id = $1
	`, sessionID, operation, digest); err != nil {
		t.Fatal(err)
	}
}
