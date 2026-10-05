package authorization

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func TestAuthorizationCheckRejectsGroupScopedManagementOutsideGroup(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	groupID := "grp_01h000000000000000000001"
	permissionKeys, _ := json.Marshal([]string{"auth.members:manage"})
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ($1, $2, 'Operators', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_01h000000000000000000001', $1, $2, $3, 'group_tree', $3, $4)
	`, spaceID, permissionKeys, groupID, actor.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "SCOPE_OUT_OF_BOUNDS" {
		t.Fatalf("group-scoped management grant = %+v, want SCOPE_OUT_OF_BOUNDS", decision)
	}
}

func TestAuthorizationCheckRejectsDisabledPermission(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "PERMISSION_DISABLED" {
		t.Fatalf("disabled permission decision = %+v", decision)
	}
}

func TestAuthorizationCheckRejectsPrincipalKind(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["agent"]'::jsonb WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "PRINCIPAL_KIND_NOT_ALLOWED" {
		t.Fatalf("principal kind decision = %+v", decision)
	}
}

func TestAgentAuthorizationUsesOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: actor.ID, Name: "owner-envelope-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, created.ID, []string{"auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	humanDecision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	agentDecision, _, err := svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if humanDecision.Effect != engine.Allow || agentDecision.Effect != engine.Allow {
		t.Fatalf("human and agent decisions differ: human=%+v agent=%+v", humanDecision, agentDecision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	agentDecision, _, err = svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if agentDecision.Code != "OWNER_ENVELOPE_EXCLUDED" {
		t.Fatalf("owner without permission decision = %+v", agentDecision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	agentDecision, _, err = svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if agentDecision.Code != "OWNER_INACTIVE" {
		t.Fatalf("inactive owner decision = %+v", agentDecision)
	}
}

func TestAuthorizationCheckAndTransactionalManagementUseSameDecision(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	outside, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	var inside engine.Decision
	if err := st.InTx(ctx, func(q *db.Queries) error {
		var err error
		inside, err = svc.CheckTx(ctx, q, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if outside.Effect != inside.Effect || outside.Code != inside.Code {
		t.Fatalf("outside=%+v inside=%+v", outside, inside)
	}
}
