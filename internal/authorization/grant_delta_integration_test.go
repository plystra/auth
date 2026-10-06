package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/apierr"
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
