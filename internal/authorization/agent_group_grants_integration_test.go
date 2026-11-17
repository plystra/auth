package authorization

import (
	"context"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
)

func TestAgentGroupGrantUsesActualDescendantSpaceAndItsEnvelope(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
		VALUES ('spc_group_anchor_child', 'Child', 'group-anchor-child', $1)`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
		VALUES ('grp_descendant_anchor', 'spc_group_anchor_child', 'Documents', 'standard')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'space_tree' WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "descendant-group"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "group_tree", "grp_descendant_anchor")
	if err != nil || grant.AnchorGroupID != "grp_descendant_anchor" || grant.AnchorSpaceID != "" {
		t.Fatalf("descendant group grant = %+v, %v", grant, err)
	}
	request := CheckRequest{MemberID: created.ID, Permission: "auth.members:read", ResourceSpace: "spc_group_anchor_child", ResourceGroup: "grp_descendant_anchor"}
	decision, _, err := svc.Check(ctx, request)
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("descendant group authorization = %+v, %v", decision, err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_descendant_anchor')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT 'grp_descendant_anchor', id, 'use' FROM permissions WHERE key = 'auth.members:read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "group_tree", "grp_descendant_anchor"); err != nil {
		t.Fatalf("owner system assignment must accept use-only group envelope: %v", err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("owner use-only group authorization = %+v, %v", decision, err)
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM group_envelope_entries WHERE group_id = 'grp_descendant_anchor'`); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, request)
	if err != nil || decision.Code != "ENVELOPE_EXCLUDED" {
		t.Fatalf("descendant envelope = %+v, %v", decision, err)
	}
}

func TestAgentGroupGrantValidatesEveryOwnerScopeAndDirectoryRule(t *testing.T) {
	for _, condition := range []string{"owner_group_only", "upstream_group_only", "disabled", "human_only", "approval_required", "token_scope", "inactive_owner", "inactive_group", "foreign_anchor"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			st, svc, owner, spaceID := newBindingFixture(t)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
				VALUES ('grp_owner_boundary', $1, 'Boundary', 'standard')`, spaceID); err != nil {
				t.Fatal(err)
			}
			agents := &agent.Service{Store: st}
			parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "parent"})
			if err != nil {
				t.Fatal(err)
			}
			child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: parent.ExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			permissions := []string{"auth.members:read"}
			original, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, parent.ID, permissions, "group_tree", "grp_owner_boundary")
			if err != nil {
				t.Fatal(err)
			}
			want := "AUTHORITY_DELTA_NOT_COVERED"
			switch condition {
			case "owner_group_only":
				_, err = st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group' WHERE id = $1`, original.ID)
			case "upstream_group_only":
				_, err = st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID)
				if err == nil {
					_, err = st.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
						VALUES ('grt_upstream_only', $1, '["auth.members:read"]'::jsonb, $2, 'group', 'grp_owner_boundary', $2)`, spaceID, owner.ID)
				}
			case "disabled":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:read'`)
			case "human_only":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human"]'::jsonb WHERE key = 'auth.members:read'`)
			case "approval_required":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET agent_approval = 'required' WHERE key = 'auth.members:read'`)
			case "token_scope":
				ctx = WithTokenScopes(ctx, parent.ID, []string{"self:read"})
			case "inactive_owner":
				_, err = st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID)
				want = "OWNER_INACTIVE"
			case "inactive_group":
				_, err = st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = 'grp_owner_boundary'`)
				want = "RESOURCE_GROUP_INACTIVE"
			case "foreign_anchor":
				_, err = st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_foreign_group', 'Foreign', 'foreign-group')`)
				if err == nil {
					_, err = st.Pool.Exec(ctx, `UPDATE groups SET space_id = 'spc_foreign_group' WHERE id = 'grp_owner_boundary'`)
				}
				want = "SCOPE_OUT_OF_BOUNDS"
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.ReplaceAgentGroupGrants(ctx, parent.ID, spaceID, child.ID, permissions, "group_tree", "grp_owner_boundary")
			if err == nil {
				t.Fatal("group delegation bypassed the owner's boundary")
			}
			assertAPIErrorCode(t, err, want)
			var count int
			if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1`, child.ID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("denied delegation persisted %d grants: %v", count, err)
			}
		})
	}
}

func TestAgentGroupGrantAuditFailureRestoresGrantAndPolicyVersions(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
		VALUES ('grp_rollback_boundary', $1, 'Rollback', 'standard')`, spaceID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "rollback"})
	if err != nil {
		t.Fatal(err)
	}
	original, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "group_tree", "grp_rollback_boundary")
	if err != nil {
		t.Fatal(err)
	}
	var memberVersion, spaceVersion int64
	if err := st.Pool.QueryRow(ctx, `SELECT m.version, s.policy_version FROM members m JOIN spaces s ON s.id = m.space_id WHERE m.id = $1`, created.ID).Scan(&memberVersion, &spaceVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_group_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'grant.replace' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_group_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_group_grant_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:manage"}, "group", "grp_rollback_boundary"); err == nil {
		t.Fatal("group grant committed without audit")
	}
	var currentMember, currentSpace int64
	var originalLive bool
	if err := st.Pool.QueryRow(ctx, `SELECT m.version, s.policy_version, g.revoked_at IS NULL FROM members m
		JOIN spaces s ON s.id = m.space_id JOIN authorization_grants g ON g.id = $2 WHERE m.id = $1`, created.ID, original.ID).Scan(&currentMember, &currentSpace, &originalLive); err != nil {
		t.Fatal(err)
	}
	if currentMember != memberVersion || currentSpace != spaceVersion || !originalLive {
		t.Fatalf("audit failure changed authority: member %d/%d Space %d/%d original=%t", currentMember, memberVersion, currentSpace, spaceVersion, originalLive)
	}
}

func TestAgentGroupGrantAdministratorRequiresCoveringRightsAndAnchorEnvelope(t *testing.T) {
	for _, condition := range []string{"covered", "missing_right", "anchor_use_only", "descendant_covered", "descendant_missing_right", "descendant_anchor_use_only", "narrowing_without_right"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			st, svc, administrator, spaceID := newBindingFixture(t)
			if err := insertUser(ctx, st, "usr_group_agent_owner", "group-agent-owner@example.test"); err != nil {
				t.Fatal(err)
			}
			owner, err := svc.CreateMember(ctx, administrator.ID, "usr_group_agent_owner", spaceID, "Agent owner", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.CreateInlineGrant(ctx, administrator.ID, spaceID, owner.ID, []string{"auth.members:read"}, "space_tree", spaceID); err != nil {
				t.Fatal(err)
			}
			anchorSpace := spaceID
			if strings.HasPrefix(condition, "descendant_") {
				anchorSpace = "spc_administrator_anchor"
				if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
					VALUES ($1, 'Anchor child', 'administrator-anchor', $2)`, anchorSpace, spaceID); err != nil {
					t.Fatal(err)
				}
			}
			for _, groupID := range []string{"grp_administrator_before", "grp_administrator_after"} {
				if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
					VALUES ($1, $2, $1, 'standard')`, groupID, anchorSpace); err != nil {
					t.Fatal(err)
				}
			}
			agents := &agent.Service{Store: st}
			created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "managed-group-agent"})
			if err != nil {
				t.Fatal(err)
			}
			original, err := svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "group_tree", "grp_administrator_before")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(condition, "missing_right") || condition == "narrowing_without_right" {
				if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, administrator.ID); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(condition, "use_only") {
				if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_administrator_after');
					INSERT INTO group_envelope_entries (group_id, permission_id, mode)
					SELECT 'grp_administrator_after', id, 'use' FROM permissions WHERE key = 'auth.members:read'`); err != nil {
					t.Fatal(err)
				}
			}
			var memberVersion, spaceVersion int64
			if err := st.Pool.QueryRow(ctx, `SELECT m.version, s.policy_version FROM members m
				JOIN spaces s ON s.id = m.space_id WHERE m.id = $1`, created.ID).Scan(&memberVersion, &spaceVersion); err != nil {
				t.Fatal(err)
			}
			anchor, scope := "grp_administrator_after", "group_tree"
			if condition == "narrowing_without_right" {
				anchor, scope = "grp_administrator_before", "group"
			}
			replacement, err := svc.ReplaceAgentGroupGrants(ctx, administrator.ID, spaceID, created.ID, []string{"auth.members:read"}, scope, anchor)
			if strings.Contains(condition, "missing_right") || strings.Contains(condition, "use_only") {
				assertAPIErrorCode(t, err, "AUTHORITY_DELTA_NOT_COVERED")
				var live bool
				var currentMember, currentSpace int64
				if err := st.Pool.QueryRow(ctx, `SELECT g.revoked_at IS NULL, m.version, s.policy_version
					FROM authorization_grants g JOIN members m ON m.id = g.grantee_member_id
					JOIN spaces s ON s.id = m.space_id WHERE g.id = $1`, original.ID).Scan(&live, &currentMember, &currentSpace); err != nil {
					t.Fatal(err)
				}
				if !live || currentMember != memberVersion || currentSpace != spaceVersion {
					t.Fatalf("denied replacement changed authority: live=%t member=%d/%d Space=%d/%d", live, currentMember, memberVersion, currentSpace, spaceVersion)
				}
				return
			}
			if err != nil || replacement.AnchorGroupID != anchor || replacement.Scope != scope {
				t.Fatalf("covered replacement = %+v, %v", replacement, err)
			}
			decision, _, err := svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:read", ResourceSpace: anchorSpace, ResourceGroup: anchor})
			if err != nil || decision.Effect != engine.Allow {
				t.Fatalf("covered group authorization = %+v, %v", decision, err)
			}
		})
	}
}

func TestSharedAgentGrantRevalidatesActingUserInsideTransaction(t *testing.T) {
	for _, scope := range []string{"space", "group_tree"} {
		for _, condition := range []string{"revoked_binding", "expired_binding", "inactive_user"} {
			t.Run(scope+"/"+condition, func(t *testing.T) {
				ctx := context.Background()
				st, svc, owner, spaceID := newBindingFixture(t)
				agents := &agent.Service{Store: st}
				created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_binding_actor", Name: "shared-transaction"})
				if err != nil {
					t.Fatal(err)
				}
				original, err := svc.ReplaceAgentGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "space", spaceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `UPDATE members SET binding_policy = 'shared' WHERE id = $1`, owner.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
					VALUES ('grp_shared_transaction', $1, 'Shared transaction', 'standard')`, spaceID); err != nil {
					t.Fatal(err)
				}
				switch condition {
				case "revoked_binding":
					_, err = st.Pool.Exec(ctx, `UPDATE user_members SET revoked_at = now() WHERE user_id = 'usr_binding_actor' AND member_id = $1`, owner.ID)
				case "expired_binding":
					_, err = st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 second' WHERE user_id = 'usr_binding_actor' AND member_id = $1`, owner.ID)
				case "inactive_user":
					_, err = st.Pool.Exec(ctx, `UPDATE users SET status = 'suspended' WHERE id = 'usr_binding_actor'`)
				}
				if err != nil {
					t.Fatal(err)
				}
				ctx = WithHumanActor(ctx, owner.ID, "usr_binding_actor")
				if scope == "space" {
					_, err = svc.ReplaceAgentGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, scope, spaceID)
				} else {
					_, err = svc.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, scope, "grp_shared_transaction")
				}
				assertAPIErrorCode(t, err, "UNAUTHENTICATED")
				var live bool
				if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, original.ID).Scan(&live); err != nil || !live {
					t.Fatalf("inactive user replaced authority: live=%t %v", live, err)
				}
			})
		}
	}
}
