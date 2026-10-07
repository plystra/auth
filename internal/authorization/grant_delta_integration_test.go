package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func TestGrantCreationRejectsPositiveDeltaDespiteMatchingActorPermissionKey(t *testing.T) {
	for _, kind := range []string{"inline", "role"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			st, svc, actor, spaceID := newBindingFixture(t)
			target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Grant target", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if err := insertUser(ctx, st, "usr_grant_target", "grant-target@example.test"); err != nil {
				t.Fatal(err)
			}
			if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_grant_target"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
				t.Fatal(err)
			}
			var versionBefore int64
			if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
				t.Fatal(err)
			}
			var createErr error
			permissions := []string{"auth.members:read", "auth.roles:manage"}
			if kind == "inline" {
				_, createErr = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, permissions, "space", spaceID)
			} else {
				role, err := svc.CreateRole(ctx, actor.ID, spaceID, "reader", "", permissions)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
					t.Fatal(err)
				}
				_, createErr = svc.CreateGrant(ctx, actor.ID, spaceID, target.ID, role.ID, "space", spaceID)
			}
			assertAPIErrorCode(t, createErr, "AUTHORITY_DELTA_NOT_COVERED")
			var public *apierr.Error
			if !errors.As(createErr, &public) {
				t.Fatalf("error = %v, want uncovered delta details", createErr)
			}
			details, ok := public.Details.(map[string]string)
			if !ok || !strings.Contains(details["uncovered"], "auth.members:read@space:"+spaceID) || !strings.Contains(details["uncovered"], "auth.roles:manage@space:"+spaceID) {
				t.Fatalf("uncovered delta details = %v", public.Details)
			}
			var count int
			if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1`, target.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("denied grant persisted %d rows", count)
			}
			var versionAfter int64
			if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionAfter); err != nil {
				t.Fatal(err)
			}
			if versionAfter != versionBefore {
				t.Fatalf("denied grant changed policy version: %d to %d", versionBefore, versionAfter)
			}
		})
	}
}

func TestMemberAndGroupManagementCannotElevateAuthority(t *testing.T) {
	for _, managerPermission := range []string{"auth.members:manage", "auth.groups:manage"} {
		t.Run(managerPermission, func(t *testing.T) {
			ctx := context.Background()
			st, svc, actor, spaceID := newBindingFixture(t)
			target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Elevation target", "human", "single")
			if err != nil {
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
				VALUES ('grt_manager_only', $1, jsonb_build_array($2::text), $3, 'space', $1, $3)
			`, spaceID, managerPermission, actor.ID); err != nil {
				t.Fatal(err)
			}

			if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err == nil {
				t.Fatal("member/group manager created a grant without auth.grants:assign")
			} else {
				assertAPIErrorCode(t, err, "NO_MATCHING_PERMISSION")
			}
			if _, err := svc.CreateAssignmentRight(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:manage"}, spaceID, "", false, false, nil); err == nil {
				t.Fatal("member/group manager created an assignment right without auth.assign_rights:manage")
			} else {
				assertAPIErrorCode(t, err, "NO_MATCHING_PERMISSION")
			}
			var grants, rights int
			if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, target.ID).Scan(&grants); err != nil {
				t.Fatal(err)
			}
			if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM assign_rights WHERE holder_member_id = $1 AND revoked_at IS NULL`, target.ID).Scan(&rights); err != nil {
				t.Fatal(err)
			}
			if grants != 0 || rights != 0 {
				t.Fatalf("manager-only elevation persisted grants=%d rights=%d", grants, rights)
			}
		})
	}
}

func TestGrantCreationCoversPositiveDeltaWithAssignmentRight(t *testing.T) {
	for _, kind := range []string{"inline", "role"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			st, svc, actor, spaceID := newBindingFixture(t)
			target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Grant target", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if err := insertUser(ctx, st, "usr_covered_grant", "covered-grant@example.test"); err != nil {
				t.Fatal(err)
			}
			if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_covered_grant"); err != nil {
				t.Fatal(err)
			}
			if kind == "inline" {
				_, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID)
			} else {
				var role Role
				role, err = svc.CreateRole(ctx, actor.ID, spaceID, "Covered role", "", []string{"auth.members:read"})
				if err == nil {
					_, err = svc.CreateGrant(ctx, actor.ID, spaceID, target.ID, role.ID, "space", spaceID)
				}
			}
			if err != nil {
				t.Fatalf("covered positive grant failed: %v", err)
			}
			decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
			if err != nil || decision.Effect != "allow" {
				t.Fatalf("target decision = %+v, %v", decision, err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
				t.Fatal(err)
			}
			assertAPIErrorCode(t, func() error {
				_, grantErr := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.roles:manage"}, "space", spaceID)
				return grantErr
			}(), "AUTHORITY_DELTA_NOT_COVERED")
		})
	}
}

func TestGrantCreationRequiresAssignableEnvelopeMode(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Envelope target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_envelope_grant", "envelope-grant@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_envelope_grant"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO space_envelope_entries (space_id, permission_id, mode)
		SELECT $1, id, CASE WHEN key = 'auth.members:read' THEN 'use' ELSE 'delegate' END
		FROM permissions WHERE status = 'active' AND delegable = true
	`, spaceID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID)
	assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	if _, err := st.Pool.Exec(ctx, `
		UPDATE space_envelope_entries SET mode = 'assign'
		WHERE space_id = $1 AND permission_id = (SELECT id FROM permissions WHERE key = 'auth.members:read')
	`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("assign envelope should permit covered grant: %v", err)
	}
}

func TestGroupAssignmentRightCoversSelfGrantButNotSpaceGrant(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Group recipient", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_group_right", "group-right@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_group_right"); err != nil {
		t.Fatal(err)
	}
	groupID := "grp_group_right_scope"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Right scope', 'standard', 'active')`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_group_id, covers_subtree, can_redelegate, source)
		VALUES ('ar_group_right_scope', $1, '["auth.members:read"]'::jsonb, $2, false, false, 'system')
	`, actor.ID, groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "self", spaceID); err != nil {
		t.Fatalf("group right should cover recipient self grant: %v", err)
	}
	_, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID)
	assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
}

func TestMemberGrantRejectsScopeAnchorOutsideMemberSpaceTree(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Scope target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	otherSpaceID, _, err := svc.CreateSpace(ctx, "usr_binding_actor", "Other scope", "other-grant-scope")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", otherSpaceID.ID)
	assertAPIErrorCode(t, err, "SCOPE_OUT_OF_BOUNDS")
	var grants int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1`, target.ID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("invalid grant persisted %d rows", grants)
	}
}

func TestGrantToAgentUsesOwnerEnvelopeAndAssignmentCoverage(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	agents := &agent.Service{Store: st}
	target, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: actor.ID, CreatedByUser: "usr_binding_actor", Name: "Grant target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("owner-covered Agent grant failed: %v", err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("owner-covered Agent grant decision = %+v, want allow", decision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.roles:manage"}, "space", spaceID)
	assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
}

func TestAgentCanGrantWithOwnerCoveredAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	agents := &agent.Service{Store: st}
	actor, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_binding_actor", Name: "granting-agent"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := svc.CreateMember(ctx, owner.ID, "", spaceID, "Agent grant target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_agent_grants_assign', $1, '["auth.grants:assign"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, actor.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAssignmentRight(ctx, owner.ID, spaceID, actor.ID, []string{"auth.grants:assign", "auth.members:read"}, spaceID, "", true, true, nil); err != nil {
		t.Fatalf("owner could not delegate grant coverage to Agent: %v", err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("owner-covered Agent grant failed: %v", err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: target.ID, Permission: "auth.members:read", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("Agent-created grant decision = %+v, want allow", decision)
	}
}

func TestGrantCreationForUnboundHumanHasNoActingIdentityDelta(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Unbound identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("unbound human has no acting identity yet: %v", err)
	}
	if err := insertUser(ctx, st, "usr_unbound_grant", "unbound-grant@example.test"); err != nil {
		t.Fatal(err)
	}
	assertAPIErrorCode(t, svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_unbound_grant"), "AUTHORITY_DELTA_NOT_COVERED")
}

func TestGrantValidationLocksTargetMemberBeforeWrite(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Concurrent grant target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}

	locked := make(chan struct{})
	release := make(chan struct{})
	lockErr := make(chan error, 1)
	go func() {
		lockErr <- st.InTx(ctx, func(q *db.Queries) error {
			if _, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: target.ID, SpaceID: spaceID}); err != nil {
				return err
			}
			close(locked)
			<-release
			return nil
		})
	}()
	select {
	case err := <-lockErr:
		t.Fatalf("member lock transaction ended before the contender started: %v", err)
	case <-locked:
	}

	grantErr := make(chan error, 1)
	go func() {
		_, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID)
		grantErr <- err
	}()
	select {
	case err := <-grantErr:
		t.Fatalf("grant validation/write bypassed the target-member lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(release)
	if err := <-lockErr; err != nil {
		t.Fatal(err)
	}
	if err := <-grantErr; err != nil {
		t.Fatalf("grant failed after the lock was released: %v", err)
	}
}

func TestGrantCreationAllowsEmptyDelta(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Already granted", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_grant_existing", "grant-existing@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_grant_existing"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_existing_read', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, target.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("duplicate effective grant should have no positive delta: %v", err)
	}
}

func TestEmptyAuthorityDeltaNeedsOnlyGrantManagement(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Existing authority", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_empty_delta", "empty-delta@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_empty_delta"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_empty_delta_existing', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, target.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("empty authority delta should need only auth.grants:assign: %v", err)
	}
}

func TestGroupScopedGrantManagerCanMakeEmptyDeltaChangeWithinGroup(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Group target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_group_grant", "group-grant@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, target.ID, "usr_group_grant"); err != nil {
		t.Fatal(err)
	}
	groupID := "grp_01h00000000000000000000999"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, status) VALUES ($1, $2, 'Grant group', 'standard', 'active')`, groupID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ($1, $2)`, groupID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_group_target_read', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, target.ID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_group_assign_manager', $1, '["auth.grants:assign"]'::jsonb, $2, 'group', $3, $2)
	`, spaceID, actor.ID, groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, target.ID, []string{"auth.members:read"}, "space", spaceID); err != nil {
		t.Fatalf("group manager could not make empty-delta change in its group: %v", err)
	}
}
