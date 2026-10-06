package principal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
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
	if _, err := api.createMember(ctx, &createMemberInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID}); err == nil {
		t.Fatal("group-scoped manager was allowed to manage the whole Space")
	} else {
		assertPrincipalError(t, err, "SCOPE_OUT_OF_BOUNDS")
	}
	if _, err := api.suspendMember(ctx, &memberPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: outside.ID}); err == nil {
		t.Fatal("group-scoped manager was allowed to manage a member outside the group")
	} else {
		assertPrincipalError(t, err, "SCOPE_OUT_OF_BOUNDS")
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
