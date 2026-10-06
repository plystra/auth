package principal

import (
	"context"
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
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
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
	request := func() *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/me/members", nil)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+actor.ID+`"`) || !strings.Contains(w.Body.String(), `"id":"`+second.ID+`"`) {
		t.Fatalf("active member bindings = %d %s, want both members", w.Code, w.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 minute' WHERE user_id = 'usr_principal_actor' AND member_id = $1`, second.ID); err != nil {
		t.Fatal(err)
	}
	w = request()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"`+actor.ID+`"`) || strings.Contains(w.Body.String(), `"id":"`+second.ID+`"`) {
		t.Fatalf("revoked member bindings = %d %s, want only the active member", w.Code, w.Body.String())
	}
}

func TestCurrentMemberUsesSelectedBindingWhenUserHasMultipleMembers(t *testing.T) {
	ctx := context.Background()
	_, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	selected, err := authz.CreateMember(ctx, actor.ID, "usr_principal_actor", spaceID, "second identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.CreateInlineGrant(ctx, actor.ID, spaceID, selected.ID, []string{"self:read"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", selected.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: authz.Store}}
	memberID, userID, err := api.currentMember(ctx, "Bearer "+tokens.AccessToken)
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
	if _, err := api.actorForSpace(ctx, "Bearer "+tokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
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
	if _, err := api.actorForSpace(ctx, "Bearer "+tokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
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
	if _, err := authz.CreateInlineGrant(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	humanTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	if _, err := api.actorForSpace(ctx, "Bearer "+humanTokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
		t.Fatalf("human management decision = %v", err)
	}
	if _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err != nil {
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
	if _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
		t.Fatal("Agent retained a permission after its owner's grant was revoked")
	} else {
		assertPrincipalError(t, err, "OWNER_ENVELOPE_EXCLUDED")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := api.actorForSpace(ctx, "Bearer "+agentTokens.AccessToken, spaceID, "auth.members:manage"); err == nil {
		t.Fatal("Agent with inactive owner was allowed by a management endpoint")
	} else {
		assertPrincipalError(t, err, "OWNER_INACTIVE")
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
	if _, err := authz.CreateInlineGrant(ctx, owner.ID, spaceID, created.ID, []string{"self:read"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
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
	bindings, err := authz.ListBindings(ctx, out.Body.Data.Member.ID)
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
	if _, err := authz.CreateInlineGrant(ctx, owner.ID, spaceID, created.ID, []string{"self:read"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
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
	if _, err := authz.CreateInlineGrant(ctx, owner.ID, spaceID, created.ID, []string{"auth.agents:create"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	_, err = api.createAgent(ctx, &agentsInput{Authorization: "Bearer " + tokens.AccessToken})
	if err == nil {
		t.Fatal("Agent created a child after its owner lost auth.agents:create")
	}
	assertPrincipalError(t, err, "OWNER_ENVELOPE_EXCLUDED")
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
