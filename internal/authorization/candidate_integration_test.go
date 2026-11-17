package authorization

import (
	"context"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func TestDirectoryPrincipalKindsApplyBeforeMissingGrantsForEveryMemberType(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	human, err := svc.CreateMember(ctx, owner.ID, "", spaceID, "Unassigned human", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "Unassigned Agent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id, space_id, name, kind, type, binding_policy, status) VALUES ('mem_unassigned_app', $1, 'Unassigned application', 'service', 'application', 'single', 'active')`, spaceID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, member, allowed string }{
		{"human", human.ID, `["agent"]`},
		{"agent", created.ID, `["human"]`},
		{"application", "mem_unassigned_app", `["human"]`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = $1::jsonb WHERE key = 'auth.members:manage'`, tc.allowed); err != nil {
				t.Fatal(err)
			}
			in := CheckRequest{MemberID: tc.member, Permission: "auth.members:manage", ResourceSpace: spaceID}
			check, _, err := svc.Check(ctx, in)
			if err != nil || check.Code != "PRINCIPAL_KIND_NOT_ALLOWED" {
				t.Fatalf("unassigned %s = %+v, %v", tc.kind, check, err)
			}
			if err := st.InTx(ctx, func(q *db.Queries) error {
				transactional, err := svc.CheckTx(ctx, q, in)
				if err == nil && (transactional.Code != check.Code || !slices.Equal(transactional.Trace, check.Trace)) {
					t.Fatal("transactional decision differs from Check")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human", "agent", "application"]'::jsonb WHERE key = 'auth.members:manage'`); err != nil {
				t.Fatal(err)
			}
			check, _, err = svc.Check(ctx, in)
			if err != nil || check.Code != "NO_MATCHING_PERMISSION" {
				t.Fatalf("restoring kind created authority: %+v, %v", check, err)
			}
		})
	}
}

func TestManagementAndCheckChooseClosestGrantFailure(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES
		('grp_candidate_root', $1, 'Root', NULL),
		('grp_candidate_excluded', $1, 'Excluded', 'grp_candidate_root'),
		('grp_candidate_outside', $1, 'Outside', 'grp_candidate_root')`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_candidate_excluded')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by) VALUES
		('grt_candidate_excluded', $1, '["auth.members:manage"]'::jsonb, $2, 'group', 'grp_candidate_excluded', $2),
		('grt_candidate_outside', $1, '["auth.members:manage"]'::jsonb, $2, 'group', 'grp_candidate_outside', $2)
	`, spaceID, actor.ID); err != nil {
		t.Fatal(err)
	}
	in := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID}
	for _, want := range []string{"SCOPE_OUT_OF_BOUNDS", "ENVELOPE_EXCLUDED"} {
		check, _, err := svc.Check(ctx, in)
		if err != nil || check.Code != want || check.Effect != engine.Deny {
			t.Fatalf("closest candidate = %+v, %v; want %s", check, err, want)
		}
		if _, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Forbidden candidate write", "human", "single"); err == nil {
			t.Fatal("a failed candidate authorized a management write")
		} else {
			assertAPIErrorCode(t, err, want)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_candidate_outside'`); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE name = 'Forbidden candidate write'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied management operation changed state: count=%d error=%v", count, err)
	}
}
