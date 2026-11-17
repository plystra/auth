package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/engine"
)

func TestGroupMembershipPositiveDeltaRequiresAssignmentCoverageAndRollsBack(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Group member", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_group_delta", "group-delta@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_group_delta"); err != nil {
		t.Fatal(err)
	}
	groupID := "grp_group_delta"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ($1, $2, 'Delta group', 'standard', 'active')
	`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_group_delta_read', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, groupID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_group_delta_manage', $1, '["auth.groups:manage", "auth.grants:assign"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}

	err = svc.AddMemberToGroup(ctx, actor.ID, spaceID, groupID, target.ID)
	var apiErr *apierr.Error
	if !errors.As(err, &apiErr) || apiErr.Code != "AUTHORITY_DELTA_NOT_COVERED" {
		t.Fatalf("uncovered group membership error = %v, want AUTHORITY_DELTA_NOT_COVERED", err)
	}
	details, ok := apiErr.Details.(map[string]string)
	if !ok || !strings.Contains(details["uncovered"], "auth.members:read") {
		t.Fatalf("uncovered details = %v, want auth.members:read", apiErr.Details)
	}
	var memberships int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1 AND member_id = $2`, groupID, target.ID).Scan(&memberships); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 {
		t.Fatalf("rejected group membership persisted %d rows", memberships)
	}

	encoded, err := json.Marshal([]string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, can_redelegate, source)
		VALUES ('ar_group_delta_cover', $1, $2, $3, true, true, 'system')
	`, actor.ID, encoded, spaceID); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMemberToGroup(ctx, actor.ID, spaceID, groupID, target.ID); err != nil {
		t.Fatalf("covered group membership failed: %v", err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("group-derived permission decision = %+v, want allow", decision)
	}
}

func TestGroupMovePositiveDeltaRequiresAssignmentCoverageAndRollsBack(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	const sourceID = "grp_move_source_denied"
	const parentID = "grp_move_parent_denied"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, parent_id) VALUES
		('grp_move_root_denied', $3, 'Root', NULL),
		($1, $3, 'Move source', 'grp_move_root_denied'),
		($2, $3, 'Move parent', 'grp_move_root_denied')
	`, sourceID, parentID, spaceID); err != nil {
		t.Fatal(err)
	}
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Move target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_group_move_denied", "group-move-denied@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id, status) VALUES ('usr_group_move_denied', $1, 'active')`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id, source) VALUES ($1, $2, $3, 'manual')`, sourceID, target.ID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_move_read_denied', $1, '["auth.members:read"]'::jsonb, $2, 'group_tree', $2, $3)
	`, spaceID, parentID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_move_manage_denied', $1, '["auth.groups:manage"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.MoveGroup(ctx, actor.ID, spaceID, sourceID, parentID); err == nil {
		t.Fatal("group move transferred authority without assignment-right coverage")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "AUTHORITY_DELTA_NOT_COVERED" {
			t.Fatalf("uncovered group move error = %v, want AUTHORITY_DELTA_NOT_COVERED", err)
		}
		if details, ok := public.Details.(map[string]string); !ok || !strings.Contains(details["uncovered"], "auth.members:read") {
			t.Fatalf("uncovered group move details = %v, want auth.members:read", public.Details)
		}
	}
	var parent string
	if err := st.Pool.QueryRow(ctx, `SELECT coalesce(parent_id, '') FROM groups WHERE id = $1`, sourceID).Scan(&parent); err != nil {
		t.Fatal(err)
	}
	if parent != "grp_move_root_denied" {
		t.Fatalf("rejected group move persisted parent %q", parent)
	}
}

func TestGroupMoveUsesUnifiedDeltaCoverage(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	const sourceID = "grp_move_source_allowed"
	const parentID = "grp_move_parent_allowed"
	const childID = "grp_move_child_allowed"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, parent_id) VALUES
		('grp_move_root_allowed', $4, 'Root', NULL),
		($1, $4, 'Move source', 'grp_move_root_allowed'),
		($2, $4, 'Move parent', 'grp_move_root_allowed'),
		($3, $4, 'Move child', $1)
	`, sourceID, parentID, childID, spaceID); err != nil {
		t.Fatal(err)
	}
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Move target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	external, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "External grant target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_group_move_allowed", "group-move-allowed@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id, status) VALUES ('usr_group_move_allowed', $1, 'active')`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id, source) VALUES ($1, $2, $3, 'manual')`, sourceID, target.ID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_group_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_move_read_allowed', $1, '["auth.members:read"]'::jsonb, $2, 'group_tree', $2, $3)
	`, spaceID, parentID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_move_source_id_stable', $1, '["auth.members:read"]'::jsonb, $2, 'group_tree', $3, $4)
	`, spaceID, external.ID, sourceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_move_manage_allowed', $1, '["auth.groups:manage"]'::jsonb, $2, 'space', $1, $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.MoveGroup(ctx, actor.ID, spaceID, sourceID, parentID); err != nil {
		t.Fatalf("covered group move failed: %v", err)
	}
	var childParent string
	if err := st.Pool.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id = $1`, childID).Scan(&childParent); err != nil {
		t.Fatal(err)
	}
	if childParent != sourceID {
		t.Fatalf("moved subtree child parent = %q, want stable source ID %q", childParent, sourceID)
	}
	var anchorGroup string
	if err := st.Pool.QueryRow(ctx, `SELECT anchor_group_id FROM authorization_grants WHERE id = 'grt_move_source_id_stable'`).Scan(&anchorGroup); err != nil {
		t.Fatal(err)
	}
	if anchorGroup != sourceID {
		t.Fatalf("grant anchor after move = %q, want stable source ID %q", anchorGroup, sourceID)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.members:read", ResourceSpace: spaceID, ResourceGroup: sourceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("moved member decision = %+v, want allow", decision)
	}
}

func TestGroupMoveEnforcesSpaceCycleAndSubtreeDepthBoundaries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	create := func(space, name, parent string) Group {
		t.Helper()
		group, err := svc.CreateGroup(ctx, actor.ID, space, name, parent)
		if err != nil {
			t.Fatal(err)
		}
		return group
	}
	root := create(spaceID, "Root", "")
	moving := create(spaceID, "Moving", root.ID)
	leaf := create(spaceID, "Moving leaf", moving.ID)
	parents := []Group{root}
	for depth := 2; depth <= 15; depth++ {
		parents = append(parents, create(spaceID, "Level "+strconv.Itoa(depth), parents[len(parents)-1].ID))
	}
	other, otherActor, err := svc.CreateSpace(ctx, "usr_binding_actor", "Other tree", "other-move-tree")
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := svc.CreateGroup(ctx, otherActor.ID, other.ID, "Other root", "")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var out string
		if err := st.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
			'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
			'versions', (SELECT jsonb_agg(policy_version ORDER BY id) FROM spaces),
			'audits', (SELECT count(*) FROM audit_logs))::text`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, invalid := range []struct{ name, group, parent, code string }{
		{"cross_space", moving.ID, otherRoot.ID, "NOT_FOUND"},
		{"cycle", moving.ID, leaf.ID, "VALIDATION_FAILED"},
		{"subtree_exceeds_depth_16", moving.ID, parents[14].ID, "VALIDATION_FAILED"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			before := snapshot()
			assertAPIErrorCode(t, svc.MoveGroup(ctx, actor.ID, spaceID, invalid.group, invalid.parent), invalid.code)
			if snapshot() != before {
				t.Fatal("rejected move changed the tree, policy version, or audit")
			}
		})
	}
	if err := svc.MoveGroup(ctx, actor.ID, spaceID, moving.ID, parents[13].ID); err != nil {
		t.Fatalf("move placing subtree leaf at depth 16 failed: %v", err)
	}
	var depth int
	if err := st.Pool.QueryRow(ctx, `WITH RECURSIVE chain AS (
		SELECT id, parent_id, 1 AS depth FROM groups WHERE id = $1
		UNION ALL SELECT g.id, g.parent_id, c.depth + 1 FROM groups g JOIN chain c ON g.id = c.parent_id
	) SELECT max(depth) FROM chain`, leaf.ID).Scan(&depth); err != nil || depth != 16 {
		t.Fatalf("moved subtree leaf depth = %d, want 16: %v", depth, err)
	}
}
