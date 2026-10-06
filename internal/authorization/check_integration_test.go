package authorization

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
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

func TestAuditFailureRollsBackMemberStatus(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Audit rollback target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_test_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_audit_insert BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_test_audit_insert();
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetMemberStatus(ctx, actor.ID, spaceID, target.ID, "suspended"); err == nil {
		t.Fatal("member status changed despite audit failure")
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, target.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("member status = %q after audit failure, want active", status)
	}
}

func TestPrefixedIDConstraintRejectsWrongPrefix(t *testing.T) {
	ctx := context.Background()
	st, _, _, _ := newBindingFixture(t)
	_, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('mem_not_a_user', 'wrong-prefix@example.test', 'wrong-prefix@example.test', 'hash', 'active')
	`)
	if err == nil {
		t.Fatal("database accepted a user ID with the member prefix")
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	ctx := context.Background()
	database, err := integrationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	if err := store.Migrate(ctx, database.URL); err != nil {
		t.Fatalf("reapplying migrations: %v", err)
	}
	verificationStore, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer verificationStore.Close()
	if err := store.CheckMigrationVersion(ctx, verificationStore.Pool); err != nil {
		t.Fatalf("migration readiness check: %v", err)
	}
}

func TestPermissionDirectoryUsesStatusAndDisablesImmediately(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	var hasStatus, hasEnabled bool
	if err := st.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'permissions' AND column_name = 'status'),
		       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'permissions' AND column_name = 'enabled')
	`).Scan(&hasStatus, &hasEnabled); err != nil {
		t.Fatal(err)
	}
	if !hasStatus || hasEnabled {
		t.Fatalf("permission columns status=%v enabled=%v, want status only", hasStatus, hasEnabled)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Code != "PERMISSION_DISABLED" {
		t.Fatalf("disabled permission decision = %+v, want PERMISSION_DISABLED", decision)
	}
}
