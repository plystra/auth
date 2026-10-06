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

func TestSpaceSuspensionPropagatesThroughAuthorizationCheck(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, parentID := newBindingFixture(t)
	childID := "spc_suspension_child"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id) VALUES ($1, 'Child', 'suspension-child', $2)`, childID, parentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'space_tree' WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	request := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: childID}
	check := func(wantEffect engine.Effect, wantCode string) {
		t.Helper()
		decision, _, err := svc.Check(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Effect != wantEffect || decision.Code != wantCode {
			t.Fatalf("Check = %+v, want effect=%s code=%q", decision, wantEffect, wantCode)
		}
		var transactional engine.Decision
		if err := st.InTx(ctx, func(q *db.Queries) error {
			var err error
			transactional, err = svc.CheckTx(ctx, q, request)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if transactional.Effect != decision.Effect || transactional.Code != decision.Code {
			t.Fatalf("CheckTx = %+v, Check = %+v", transactional, decision)
		}
	}
	check(engine.Allow, "allowed")
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, parentID); err != nil {
		t.Fatal(err)
	}
	check(engine.Deny, "SPACE_INACTIVE")
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'active' WHERE id = $1`, parentID); err != nil {
		t.Fatal(err)
	}
	check(engine.Allow, "allowed")
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, childID); err != nil {
		t.Fatal(err)
	}
	check(engine.Deny, "SPACE_INACTIVE")
}

func TestSubjectHomeSpaceSuspensionDeniesOtherResource(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, parentID := newBindingFixture(t)
	childID := "spc_subject_suspended"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id) VALUES ($1, 'Member home', 'subject-suspended', $2)`, childID, parentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET space_id = $1 WHERE id = $2`, childID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_subject_child', $1, '["auth.members:manage"]'::jsonb, $2, 'space', $1, $2)
	`, childID, actor.ID); err != nil {
		t.Fatal(err)
	}
	request := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: parentID}
	decision, _, err := svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "SCOPE_OUT_OF_BOUNDS" {
		t.Fatalf("active subject home Space = %+v, want SCOPE_OUT_OF_BOUNDS", decision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, childID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "SPACE_INACTIVE" {
		t.Fatalf("suspended subject home Space = %+v, want SPACE_INACTIVE", decision)
	}
}

func TestParentGroupSuspensionDeniesChildGroupResource(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	parentID, childID := "grp_suspension_parent", "grp_suspension_child"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ($1, $3, 'Parent'), ($2, $3, 'Child')`, parentID, childID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET parent_id = $1 WHERE id = $2`, parentID, childID); err != nil {
		t.Fatal(err)
	}
	request := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID, ResourceGroup: childID}
	decision, _, err := svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("active group chain = %+v, want allow", decision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, parentID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "RESOURCE_GROUP_INACTIVE" {
		t.Fatalf("suspended ancestor group = %+v, want RESOURCE_GROUP_INACTIVE", decision)
	}
}

func TestSuspendedGrantGroupStopsContributingAuthority(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	groupID := "grp_suspended_grant"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ($1, $2, 'Grant source')`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_suspended_group', $1, '["auth.members:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, groupID, actor.ID); err != nil {
		t.Fatal(err)
	}
	request := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID}
	decision, _, err := svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("active grant group = %+v, want allow", decision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, groupID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny {
		t.Fatalf("suspended grant group = %+v, want deny", decision)
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

func TestAgentGroupGrantStillRequiresOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "group-grant-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	groupID := "grp_agent_grant"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Agent grant group', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_agent_group_grant', $1, '["auth.members:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, groupID, owner.ID); err != nil {
		t.Fatal(err)
	}
	check := func(wantEffect engine.Effect, wantCode string) {
		t.Helper()
		decision, _, err := svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Effect != wantEffect || decision.Code != wantCode {
			t.Fatalf("Agent group grant decision = %+v, want %s %s", decision, wantEffect, wantCode)
		}
	}
	check(engine.Allow, "allowed")
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	check(engine.Deny, "OWNER_ENVELOPE_EXCLUDED")
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
	for _, status := range []string{"active", "deprecated"} {
		if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.members:manage'`, status); err != nil {
			t.Fatal(err)
		}
		decision, _, err := svc.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Effect != engine.Allow {
			t.Fatalf("%s permission decision = %+v, want allow", status, decision)
		}
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

func TestBuiltinGovernancePermissionsMatchAuthorizationModel(t *testing.T) {
	ctx := context.Background()
	st, _, _, _ := newBindingFixture(t)
	type expectedPermission struct {
		kinds     []string
		risk      string
		approval  string
		delegable bool
	}
	want := map[string]expectedPermission{
		"auth.spaces:manage":        {[]string{"human", "agent"}, "critical", "none", true},
		"auth.members:read":         {[]string{"human", "agent", "application"}, "low", "none", true},
		"auth.members:manage":       {[]string{"human", "agent", "application"}, "high", "none", true},
		"auth.roles:manage":         {[]string{"human", "agent"}, "high", "none", true},
		"auth.grants:assign":        {[]string{"human", "agent", "application"}, "high", "none", true},
		"auth.assign_rights:manage": {[]string{"human", "agent"}, "critical", "none", true},
		"auth.envelopes:manage":     {[]string{"human", "agent"}, "critical", "none", true},
		"auth.audit:read":           {[]string{"human", "agent"}, "high", "none", true},
		"auth.authz:check":          {[]string{"application"}, "low", "none", true},
		"auth.tokens:introspect":    {[]string{"application"}, "high", "none", true},
		"auth.bindings:manage":      {[]string{"human", "agent"}, "critical", "required", true},
		"auth.agents:create":        {[]string{"human", "agent", "application"}, "high", "none", true},
		"auth.groups:manage":        {[]string{"human", "agent", "application"}, "high", "none", true},
		"auth.applications:manage":  {[]string{"human", "agent"}, "critical", "none", true},
		"auth.connections:manage":   {[]string{"human", "agent"}, "critical", "required", true},
		"auth.audit:write":          {[]string{"application"}, "low", "none", true},
		"auth.authz:explain":        {[]string{"application"}, "high", "none", true},
		"auth.users:manage":         {[]string{"application"}, "critical", "none", true},
		"auth.users:impersonate":    {[]string{"human"}, "critical", "none", false},
		"auth.envelopes:apply":      {[]string{"application"}, "critical", "none", false},
	}
	rows, err := st.Pool.Query(ctx, `
		SELECT key, principal_kinds, risk, agent_approval, delegable
		FROM permissions
		WHERE key LIKE 'auth.%'
		ORDER BY key
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(want))
	for rows.Next() {
		var key, risk, approval string
		var rawKinds []byte
		var delegable bool
		if err := rows.Scan(&key, &rawKinds, &risk, &approval, &delegable); err != nil {
			t.Fatal(err)
		}
		expected, ok := want[key]
		if !ok {
			t.Fatalf("unexpected built-in permission %q", key)
		}
		var kinds []string
		if err := json.Unmarshal(rawKinds, &kinds); err != nil {
			t.Fatal(err)
		}
		if len(kinds) != len(expected.kinds) {
			t.Fatalf("%s principal_kinds = %v, want %v", key, kinds, expected.kinds)
		}
		for i := range kinds {
			if kinds[i] != expected.kinds[i] {
				t.Fatalf("%s principal_kinds = %v, want %v", key, kinds, expected.kinds)
			}
		}
		if risk != expected.risk || approval != expected.approval || delegable != expected.delegable {
			t.Fatalf("%s metadata = risk:%s approval:%s delegable:%v, want risk:%s approval:%s delegable:%v", key, risk, approval, delegable, expected.risk, expected.approval, expected.delegable)
		}
		seen[key] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(want) {
		t.Fatalf("built-in permission count = %d, want %d", len(seen), len(want))
	}
}
