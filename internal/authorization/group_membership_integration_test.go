package authorization

import (
	"context"
	"encoding/json"
	"errors"
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
