package authorization

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/db"
)

func TestTopLevelSpaceCreatorReceivesDefaultAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	rights, err := st.Queries().ListActiveAssignRightsForHolder(ctx, db.ListActiveAssignRightsForHolderParams{HolderMemberID: actor.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rights) != 1 {
		t.Fatalf("creator rights = %d, want one", len(rights))
	}
	right := rights[0]
	if right.Source != "system" || !right.AnchorSpaceID.Valid || right.AnchorSpaceID.String != spaceID || right.AnchorGroupID.Valid || !right.CoversSubtree || !right.CanRedelegate || right.ParentID.Valid || right.ExpiresAt.Valid {
		t.Fatalf("creator right has wrong scope or provenance: %+v", right)
	}
	var permissions []string
	if err := json.Unmarshal(right.PermissionKeys, &permissions); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(permissions, "auth.members:manage") || slices.Contains(permissions, "auth.users:impersonate") {
		t.Fatalf("default assignable permissions = %v", permissions)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'assign_right.system_create' AND resource_id = $1`, right.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("assignment right audit events = %d, want one", audits)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:manage'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET delegable = false WHERE key = 'auth.roles:manage'`); err != nil {
		t.Fatal(err)
	}
	_, nextCreator, err := svc.CreateSpace(ctx, "usr_binding_actor", "Second Space", "second-space")
	if err != nil {
		t.Fatal(err)
	}
	nextRights, err := st.Queries().ListActiveAssignRightsForHolder(ctx, db.ListActiveAssignRightsForHolderParams{HolderMemberID: nextCreator.ID})
	if err != nil || len(nextRights) != 1 {
		t.Fatalf("new creator rights = %v, %v", nextRights, err)
	}
	if err := json.Unmarshal(nextRights[0].PermissionKeys, &permissions); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(permissions, "auth.members:manage") || slices.Contains(permissions, "auth.roles:manage") {
		t.Fatalf("disabled or nondelegable permission entered the new right: %v", permissions)
	}
}

func TestTopLevelSpaceAndAssignmentRightRollbackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st, svc, _, _ := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_assignment_right_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'assign_right.system_create' THEN
				RAISE EXCEPTION 'injected assignment right audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_assignment_right_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_assignment_right_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateSpace(ctx, "usr_binding_actor", "Rolled Back Space", "rolled-back-space"); err == nil {
		t.Fatal("Space creation succeeded without assignment right audit")
	}
	var spaces, rights int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM spaces WHERE slug = 'rolled-back-space'`).Scan(&spaces); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM assign_rights ar JOIN spaces s ON s.id = ar.anchor_space_id WHERE s.slug = 'rolled-back-space'`).Scan(&rights); err != nil {
		t.Fatal(err)
	}
	if spaces != 0 || rights != 0 {
		t.Fatalf("failed audit left %d Spaces and %d assignment rights", spaces, rights)
	}
}

func TestAssignmentRightConstraintsAndActiveLookup(t *testing.T) {
	ctx := context.Background()
	st, _, actor, spaceID := newBindingFixture(t)
	groupID := "grp_assignment_right_anchor"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Right anchor', 'standard', 'active')`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		id          string
		permissions string
		groupID     any
		source      string
	}{
		{"wrong prefix", "wrong_right", `["self:read"]`, nil, "system"},
		{"empty permission set", "ar_empty_right", `[]`, nil, "system"},
		{"non-array permission set", "ar_nonarray_right", `{}`, nil, "system"},
		{"invalid source", "ar_invalid_source", `["self:read"]`, nil, "delegated"},
		{"two anchors", "ar_two_anchors", `["self:read"]`, groupID, "system"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := st.Pool.Exec(ctx, `
				INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, anchor_group_id,
				    covers_subtree, can_redelegate, source)
				VALUES ($1, $2, $3::jsonb, $4, $5, true, true, $6)
			`, test.id, actor.ID, test.permissions, spaceID, test.groupID, test.source); err == nil {
				t.Fatal("invalid assignment right was accepted")
			}
		})
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	rights, err := st.Queries().ListActiveAssignRightsForHolder(ctx, db.ListActiveAssignRightsForHolderParams{HolderMemberID: actor.ID})
	if err != nil || len(rights) != 0 {
		t.Fatalf("revoked assignment right remains active: %v, %v", rights, err)
	}
}
