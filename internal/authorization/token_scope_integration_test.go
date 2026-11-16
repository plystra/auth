package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
)

func TestTokenScopeConstrainsCachedAndTransactionalAuthorization(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	request := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID}
	check := func(ctx context.Context, request CheckRequest, want string) {
		t.Helper()
		got, _, err := svc.Check(ctx, request)
		if err != nil || got.Code != want {
			t.Fatalf("scope decision = %+v, error = %v, want %s", got, err, want)
		}
	}
	check(ctx, request, "allowed")
	readOnly := WithTokenScopes(ctx, actor.ID, []string{"auth.members:read"})
	check(readOnly, request, "TOKEN_SCOPE_EXCLUDED")
	check(ctx, request, "allowed")
	request.TokenScopes = []string{"auth.members:manage"}
	check(readOnly, request, "TOKEN_SCOPE_EXCLUDED")
	check(ctx, request, "allowed")
	check(WithTokenScopes(ctx, actor.ID, []string{}), request, "TOKEN_SCOPE_EXCLUDED")
	check(WithTokenScopes(readOnly, actor.ID, []string{"auth.members:manage"}), request, "TOKEN_SCOPE_EXCLUDED")
	request.Permission = "auth.members:read"
	request.TokenScopes = nil
	check(readOnly, request, "allowed")
	if _, err := svc.CreateMember(readOnly, actor.ID, "", spaceID, "excluded-write", "human", "single"); err == nil {
		t.Fatal("transactional authorization restored scope-excluded authority")
	} else {
		assertAPIErrorCode(t, err, "TOKEN_SCOPE_EXCLUDED")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE name = 'excluded-write'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("scope-excluded transaction wrote %d members: %v", count, err)
	}
}

func TestTokenScopeDoesNotReplacePersistedOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "scope-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceAgentGrants(ctx, owner.ID, spaceID, parent.ID, []string{"auth.members:read", "auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "scope-child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceAgentGrants(ctx, parent.ID, spaceID, child.ID, []string{"auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	// Delta snapshots read other members' durable authority in the actor's
	// transaction; its credential restriction must not rewrite those facts.
	request := CheckRequest{MemberID: child.ID, Permission: "auth.members:manage", ResourceSpace: spaceID}
	bound := WithTokenScopes(ctx, parent.ID, []string{"auth.members:read"})
	decision, _, err := svc.Check(bound, request)
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("persisted owner authority = %+v, error = %v", decision, err)
	}
	request.TokenScopes = []string{"auth.members:manage"}
	decision, _, err = svc.Check(ctx, request)
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("child credential scope incorrectly constrained its owners: %+v, %v", decision, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, parent.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil || decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
		t.Fatalf("credential scope restored revoked owner authority: %+v, %v", decision, err)
	}
}
