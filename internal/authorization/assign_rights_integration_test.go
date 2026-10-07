package authorization

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
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

func TestHumanCanDelegateCoveredAssignmentRightAndRevokeItWithoutRemovingGrants(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	right, err := svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	if err != nil {
		t.Fatalf("covered delegation failed: %v", err)
	}
	if right.Source != "delegated" || right.ParentID == "" || right.HolderMemberID != target.ID {
		t.Fatalf("delegated right = %+v", right)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatalf("grant before revocation: %v", err)
	}
	if err := svc.RevokeAssignmentRight(ctx, actor.ID, spaceID, right.ID); err != nil {
		t.Fatalf("revoke delegated right: %v", err)
	}
	var revoked bool
	if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM assign_rights WHERE id = $1`, right.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("delegated right was not revoked")
	}
	var grants int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, target.ID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Fatalf("revoking assignment right removed %d existing grants", grants)
	}
}

func TestHumanCanDelegateAssignmentRightAnchoredAtGroup(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Group administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	groupID := "grp_delegated_assignment"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Delegated group', 'standard', 'active')`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	right, err := svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, "", groupID, true, false, nil)
	if err != nil {
		t.Fatalf("group anchored delegation failed: %v", err)
	}
	if right.AnchorGroupID != groupID || right.AnchorSpaceID != "" || !right.CoversSubtree {
		t.Fatalf("group anchored right = %+v", right)
	}
}

func TestAssignmentRightDelegationRejectsUncoveredPermissionAndSubtreeExpansion(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*store.Store, string) error
		want   string
	}{
		{
			name: "permission outside parent set",
			mutate: func(st *store.Store, actorID string) error {
				_, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET permission_keys = '["auth.members:manage"]'::jsonb WHERE holder_member_id = $1`, actorID)
				return err
			},
			want: "AUTHORITY_DELTA_NOT_COVERED",
		},
		{
			name: "parent cannot cover subtree",
			mutate: func(st *store.Store, actorID string) error {
				_, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = false WHERE holder_member_id = $1`, actorID)
				return err
			},
			want: "AUTHORITY_DELTA_NOT_COVERED",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, svc, actor, spaceID := newBindingFixture(t)
			target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.mutate(st, actor.ID); err != nil {
				t.Fatal(err)
			}
			coversSubtree := tc.name == "parent cannot cover subtree"
			permissions := []string{"auth.members:manage"}
			if tc.name == "permission outside parent set" {
				permissions = []string{"auth.members:manage", "auth.roles:manage"}
			}
			_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, permissions, spaceID, "", coversSubtree, false, nil)
			assertAPIErrorCode(t, err, tc.want)
		})
	}
}

func TestAssignmentRightDelegationRequiresRedelegationAndDelegateEnvelope(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(*store.Store, string, string) error
	}{
		{
			name: "parent cannot redelegate",
			setup: func(st *store.Store, actorID, _ string) error {
				_, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET can_redelegate = false WHERE holder_member_id = $1`, actorID)
				return err
			},
		},
		{
			name: "envelope only assign",
			setup: func(st *store.Store, _, spaceID string) error {
				if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1) ON CONFLICT DO NOTHING`, spaceID); err != nil {
					return err
				}
				_, err := st.Pool.Exec(ctx, `
					INSERT INTO space_envelope_entries (space_id, permission_id, mode)
					SELECT $1, id, CASE key WHEN 'auth.members:manage' THEN 'assign' ELSE 'delegate' END
					FROM permissions WHERE key IN ('auth.members:manage', 'auth.assign_rights:manage')
					ON CONFLICT (space_id, permission_id) DO UPDATE SET mode = EXCLUDED.mode
				`, spaceID)
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, svc, actor, spaceID := newBindingFixture(t)
			target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.setup(st, actor.ID, spaceID); err != nil {
				t.Fatal(err)
			}
			_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
			assertAPIErrorCode(t, err, map[string]string{"parent cannot redelegate": "AUTHORITY_DELTA_NOT_COVERED", "envelope only assign": "PERMISSION_OUTSIDE_ENVELOPE"}[tc.name])
		})
	}
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1) ON CONFLICT DO NOTHING`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO space_envelope_entries (space_id, permission_id, mode)
		SELECT $1, id, 'delegate' FROM permissions WHERE key IN ('auth.members:manage', 'auth.assign_rights:manage')
		ON CONFLICT (space_id, permission_id) DO UPDATE SET mode = EXCLUDED.mode
	`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil); err != nil {
		t.Fatalf("delegate envelope should allow delegation: %v", err)
	}
}

func TestAssignmentRightDelegationRejectsOutOfSpaceHolderExpiredChildAndAgentActor(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	_, otherMember, err := svc.CreateSpace(ctx, "usr_binding_actor", "Other Space", "other-assignment-space")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, otherMember.SpaceID, "", false, false, nil)
	assertAPIErrorCode(t, err, "SCOPE_OUT_OF_BOUNDS")

	parentExpiry := time.Now().UTC().Add(time.Hour)
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET expires_at = $1 WHERE holder_member_id = $2`, parentExpiry, actor.ID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	assertAPIErrorCode(t, err, "VALIDATION_FAILED")
	childExpiry := parentExpiry.Add(-time.Minute)
	_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, &childExpiry)
	if err != nil {
		t.Fatalf("child expiry within parent should be accepted: %v", err)
	}

	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: actor.ID, CreatedByUser: "usr_binding_actor", Name: "delegating-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_agent_assign_rights_check', $1, '["auth.assign_rights:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, created.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateAssignmentRight(ctx, created.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
}

func TestAgentCanDelegateOwnerCoveredAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, owner.ID, "", spaceID, "Agent delegated administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_binding_actor", Name: "delegating-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_agent_assign_rights_allow', $1, '["auth.assign_rights:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, created.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAssignmentRight(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:manage", "auth.assign_rights:manage"}, spaceID, "", true, true, nil); err != nil {
		t.Fatalf("owner delegation to Agent failed: %v", err)
	}
	delegated, err := svc.CreateAssignmentRight(ctx, created.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	if err != nil {
		t.Fatalf("owner-covered Agent delegation failed: %v", err)
	}
	if delegated.HolderMemberID != target.ID || delegated.ParentID == "" {
		t.Fatalf("delegated Agent right = %+v", delegated)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1 AND source = 'system'`, owner.ID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateAssignmentRight(ctx, created.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
}

func TestAgentAssignmentDelegationHonorsPrincipalKindsAndApproval(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		permission string
		want       string
	}{
		{name: "principal kind", permission: "auth.users:impersonate", want: "PRINCIPAL_KIND_NOT_ALLOWED"},
		{name: "approval required", permission: "auth.bindings:manage", want: "AUTHORITY_DELTA_NOT_COVERED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, svc, owner, spaceID := newBindingFixture(t)
			agents := &agent.Service{Store: st}
			created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_binding_actor", Name: "delegating-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: created.ID, CreatedByUser: "usr_binding_actor", Name: "child-agent", ExpiresAt: time.Now().UTC().Add(30 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `
				INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
				VALUES ('grt_agent_assign_rights_policy', $1, '["auth.assign_rights:manage"]'::jsonb, $2, 'space', $1, $3)
			`, spaceID, created.ID, owner.ID); err != nil {
				t.Fatal(err)
			}
			if tc.permission == "auth.users:impersonate" {
				if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET delegable = true WHERE key = $1`, tc.permission); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET permission_keys = permission_keys || '"auth.users:impersonate"'::jsonb WHERE holder_member_id = $1 AND source = 'system'`, owner.ID); err != nil {
					t.Fatal(err)
				}
			}
			if tc.permission == "auth.users:impersonate" {
				if _, err := st.Pool.Exec(ctx, `
					INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, can_redelegate, source, parent_id)
					SELECT 'ar_agent_principal_policy', $1, '["auth.assign_rights:manage", "auth.users:impersonate"]'::jsonb, $2, true, true, 'delegated', id
					FROM assign_rights WHERE holder_member_id = $3 AND source = 'system' AND revoked_at IS NULL
				`, created.ID, spaceID, owner.ID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := svc.CreateAssignmentRight(ctx, owner.ID, spaceID, created.ID, []string{"auth.assign_rights:manage", tc.permission}, spaceID, "", true, true, nil); err != nil {
				t.Fatalf("owner delegation failed: %v", err)
			}
			_, err = svc.CreateAssignmentRight(ctx, created.ID, spaceID, child.ID, []string{tc.permission}, spaceID, "", false, false, nil)
			assertAPIErrorCode(t, err, tc.want)
		})
	}
}

func TestAssignmentRightAuditFailureRollsBackAndBumpsNoPolicyVersion(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Delegated administrator", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_assignment_right_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'assign_right.create' THEN
				RAISE EXCEPTION 'injected assignment right audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_assignment_right_create_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_assignment_right_create_audit();
	`); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil)
	if err == nil {
		t.Fatal("assignment right creation succeeded despite audit failure")
	}
	var rights, after int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM assign_rights WHERE holder_member_id = $1 AND source = 'delegated'`, target.ID).Scan(&rights); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if rights != 0 || int64(after) != before {
		t.Fatalf("audit failure left rights=%d policy_version=%d (before %d)", rights, after, before)
	}
}
