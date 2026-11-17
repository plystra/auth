package authorization

import (
	"context"
	"testing"

	"github.com/plystra/auth/internal/agent"
)

func TestTokenScopeValidationUsesLiveResourceAuthority(t *testing.T) {
	for _, condition := range []string{
		"group", "owner_group", "upstream_group", "nested_group_intersection", "disjoint_groups",
		"descendant_space_group", "self", "owner_self", "global", "deprecated", "disabled",
		"human_only", "envelope_excluded", "group_inactive", "owner_inactive", "owner_revoked",
		"approval_required", "token_scope_excluded", "unknown_permission", "depth_exceeded",
	} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			st, svc, owner, spaceID := newBindingFixture(t)
			agents := &agent.Service{Store: st}
			parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "scope-parent"})
			if err != nil {
				t.Fatal(err)
			}
			child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "scope-child", ExpiresAt: parent.ExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := st.Pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO groups (id, space_id, name, parent_id) VALUES
				('grp_scope_common', $1, 'Common root', NULL),
				('grp_scope_root', $1, 'Scoped branch', 'grp_scope_common'),
				('grp_scope_other', $1, 'Other', 'grp_scope_common')`, spaceID)
			exec(`INSERT INTO groups (id, space_id, name, kind, parent_id)
				VALUES ('grp_scope_leaf', $1, 'Leaf', 'standard', 'grp_scope_root')`, spaceID)
			exec(`INSERT INTO authorization_grants
				(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by) VALUES
				('grt_scope_parent', $1, '["auth.members:read"]', $2, 'space', $1, $4),
				('grt_scope_child', $1, '["auth.members:read"]', $3, 'space', $1, $4)`, spaceID, parent.ID, child.ID, owner.ID)
			groupGrant := func(grantID, kind, anchor string) {
				t.Helper()
				exec(`UPDATE authorization_grants SET scope = $2, anchor_group_id = $3, anchor_space_id = NULL WHERE id = $1`, grantID, kind, anchor)
			}
			permissions := []string{"auth.members:read"}
			want := true
			switch condition {
			case "group":
				groupGrant("grt_scope_child", "group", "grp_scope_leaf")
			case "owner_group":
				groupGrant("grt_scope_parent", "group", "grp_scope_leaf")
			case "upstream_group":
				exec(`UPDATE authorization_grants SET scope = 'group', anchor_group_id = 'grp_scope_leaf', anchor_space_id = NULL WHERE grantee_member_id = $1`, owner.ID)
			case "nested_group_intersection":
				groupGrant("grt_scope_parent", "group_tree", "grp_scope_root")
				groupGrant("grt_scope_child", "group", "grp_scope_leaf")
			case "disjoint_groups":
				groupGrant("grt_scope_parent", "group_tree", "grp_scope_root")
				groupGrant("grt_scope_child", "group", "grp_scope_other")
				want = false
			case "descendant_space_group":
				exec(`INSERT INTO spaces (id, name, slug, parent_id) VALUES ('spc_scope_descendant', 'Descendant', 'scope-descendant', $1)`, spaceID)
				exec(`INSERT INTO groups (id, space_id, name, kind) VALUES ('grp_scope_descendant', 'spc_scope_descendant', 'Descendant', 'standard')`)
				exec(`UPDATE authorization_grants SET scope = 'space_tree' WHERE grantee_member_id IN ($1, $2)`, owner.ID, parent.ID)
				groupGrant("grt_scope_child", "group", "grp_scope_descendant")
			case "self":
				exec(`UPDATE authorization_grants SET scope = 'self', anchor_space_id = NULL WHERE id = 'grt_scope_child'`)
			case "owner_self":
				exec(`UPDATE authorization_grants SET scope = 'self', anchor_space_id = NULL WHERE grantee_member_id IN ($1, $2)`, owner.ID, parent.ID)
			case "global":
				exec(`UPDATE authorization_grants SET scope = 'global', anchor_space_id = NULL WHERE id IN ('grt_scope_parent', 'grt_scope_child')`)
			case "deprecated":
				exec(`UPDATE permissions SET status = 'deprecated' WHERE key = 'auth.members:read'`)
			case "disabled":
				exec(`UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:read'`)
				want = false
			case "human_only":
				exec(`UPDATE permissions SET principal_kinds = '["human"]' WHERE key = 'auth.members:read'`)
				want = false
			case "envelope_excluded":
				groupGrant("grt_scope_child", "group", "grp_scope_leaf")
				exec(`INSERT INTO group_envelopes (group_id) VALUES ('grp_scope_leaf')`)
				want = false
			case "group_inactive":
				groupGrant("grt_scope_child", "group", "grp_scope_leaf")
				exec(`UPDATE groups SET status = 'suspended' WHERE id = 'grp_scope_root'`)
				want = false
			case "owner_inactive":
				exec(`UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID)
				want = false
			case "owner_revoked":
				exec(`UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID)
				want = false
			case "approval_required":
				exec(`UPDATE permissions SET agent_approval = 'required' WHERE key = 'auth.members:read'`)
				want = false
			case "token_scope_excluded":
				ctx = WithTokenScopes(ctx, child.ID, []string{"self:read"})
				want = false
			case "unknown_permission":
				permissions = append(permissions, "invoice:missing")
				want = false
			case "depth_exceeded":
				svc.MaxDelegationDepth = 1
				want = false
			}
			allowed, err := svc.ValidateTokenScopes(ctx, child.ID, permissions)
			if err != nil || allowed != want {
				t.Fatalf("scope validation = %v, %v; want %v", allowed, err, want)
			}
		})
	}
}
