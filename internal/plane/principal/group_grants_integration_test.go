package principal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
)

func groupGrantHTTP(f groupRemovalFixture, token, groupID string, input authorization.GrantInput) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"grantee": map[string]string{"group_id": groupID}, "role_id": input.RoleID, "permissions": input.Permissions,
		"scope": input.Scope, "anchor_space_id": input.AnchorSpaceID, "anchor_group_id": input.AnchorGroupID,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+f.spaceID+"/grants", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func TestGroupGrantHTTPInheritsAcrossSubtreeAndHonorsResourceScopes(t *testing.T) {
	for _, source := range []string{"inline", "role"} {
		for _, scope := range []string{"self", "group", "group_tree", "space", "space_tree"} {
			t.Run(source+"/"+scope, func(t *testing.T) {
				ctx := context.Background()
				f := newGroupRemovalFixture(t)
				if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_grant_child', $1, 'Child', 'grp_remove_a');
					INSERT INTO members (id, space_id, name, type) VALUES ('mem_grant_descendant', $1, 'Descendant', 'human'), ('mem_grant_outsider', $1, 'Outsider', 'human');
					INSERT INTO user_members (user_id, member_id) VALUES ('usr_principal_actor', 'mem_grant_descendant'), ('usr_principal_actor', 'mem_grant_outsider');
					INSERT INTO group_members (group_id, member_id, space_id, source) VALUES ('grp_grant_child', 'mem_grant_descendant', $1, 'manual'), ('grp_remove_b', 'mem_grant_outsider', $1, 'manual')`, pgx.QueryExecModeSimpleProtocol, f.spaceID); err != nil {
					t.Fatal(err)
				}
				input := authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: scope}
				if source == "role" {
					role, err := f.authz.CreateRole(ctx, f.owner.ID, f.spaceID, "Project manager", "", input.Permissions)
					if err != nil {
						t.Fatal(err)
					}
					input.RoleID, input.Permissions = role.ID, nil
				}
				if scope == "group" || scope == "group_tree" {
					input.AnchorGroupID = "grp_remove_a"
				}
				out := groupGrantHTTP(f, f.token, "grp_remove_a", input)
				var result struct{ Data authorization.Grant }
				if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Data.GranteeGroupID != "grp_remove_a" || result.Data.ID == "" {
					t.Fatalf("group grant HTTP response: status=%d body=%s", out.Code, out.Body.String())
				}
				check := func(memberID, groupID string, allow bool) {
					t.Helper()
					decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: "auth.members:manage", ResourceSpace: f.spaceID, ResourceGroup: groupID, ResourceOwner: memberID})
					if err != nil || (decision.Effect == engine.Allow) != allow {
						t.Fatalf("group authority: member=%s group=%s effect=%s code=%s error=%v", memberID, groupID, decision.Effect, decision.Code, err)
					}
				}
				for _, memberID := range []string{f.target.ID, "mem_grant_descendant"} {
					check(memberID, "grp_remove_a", true)
					check(memberID, "grp_grant_child", scope != "group")
					check(memberID, "grp_remove_b", scope != "group" && scope != "group_tree")
				}
				check("mem_grant_outsider", "grp_remove_a", false)
				req := httptest.NewRequest(http.MethodDelete, "/v1/spaces/"+f.spaceID+"/grants/"+result.Data.ID, nil)
				req.Header.Set("Authorization", "Bearer "+f.token)
				revoked := httptest.NewRecorder()
				f.handler.ServeHTTP(revoked, req)
				if revoked.Code != http.StatusOK {
					t.Fatalf("group grant revocation: status=%d", revoked.Code)
				}
				check(f.target.ID, "grp_remove_a", false)
				check("mem_grant_descendant", "grp_remove_a", false)
			})
		}
	}
}

func TestGroupGrantHTTPUsesUnifiedActorAndOwnerAuthority(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, scenario := range []string{"allow", "outside_scope", "envelope", "disabled", "principal_kind", "missing_right", "uncovered_anchor", "use_only", "owner_excluded", "owner_inactive", "owner_right", "token_scope"} {
			if kind == "human" && (strings.HasPrefix(scenario, "owner_") || scenario == "token_scope") {
				continue
			}
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				ctx := context.Background()
				f := newGroupRemovalFixture(t)
				actorID, token := f.owner.ID, f.token
				if kind == "agent" {
					created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "group-grant-manager"})
					if err != nil {
						t.Fatal(err)
					}
					actorID = created.ID
					if scenario == "token_scope" {
						tokens, err := f.sessions.CreateAgentDelegatedAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience, f.owner.ID, []string{"self:read"}, 0)
						if err != nil {
							t.Fatal(err)
						}
						token = tokens.AccessToken
					} else {
						tokens, err := f.sessions.CreateAgentAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience)
						if err != nil {
							t.Fatal(err)
						}
						token = tokens.AccessToken
					}
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1;
					UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, pgx.QueryExecModeSimpleProtocol, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				actors := []string{f.owner.ID}
				if actorID != f.owner.ID {
					actors = append(actors, actorID)
				}
				for _, memberID := range actors {
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
						VALUES ('grt_group_manager_' || $1, $2, '["auth.grants:assign"]', $1, 'group_tree', 'grp_remove_a', $3);
						INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_group_id, covers_subtree, can_redelegate, source)
						VALUES ('ar_group_manager_' || $1, $1, '["auth.members:manage"]', 'grp_remove_a', true, false, 'system')`, pgx.QueryExecModeSimpleProtocol, memberID, f.spaceID, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				}
				groupID, anchor := "grp_remove_a", "grp_remove_a"
				var scopes []string
				wantCode := ""
				switch scenario {
				case "outside_scope":
					groupID, anchor = "grp_remove_b", "grp_remove_b"
				case "envelope":
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_remove_a')`); err != nil {
						t.Fatal(err)
					}
				case "disabled":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.grants:assign'`); err != nil {
						t.Fatal(err)
					}
				case "principal_kind":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["application"]' WHERE key = 'auth.grants:assign'`); err != nil {
						t.Fatal(err)
					}
				case "missing_right", "owner_right":
					target := actorID
					if scenario == "owner_right" {
						target = f.owner.ID
					}
					if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, target); err != nil {
						t.Fatal(err)
					}
					wantCode = "AUTHORITY_DELTA_NOT_COVERED"
				case "uncovered_anchor":
					anchor, wantCode = "grp_remove_b", "AUTHORITY_DELTA_NOT_COVERED"
				case "use_only":
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_remove_a');
						INSERT INTO group_envelope_entries (group_id, permission_id, mode)
						SELECT 'grp_remove_a', id, CASE WHEN key = 'auth.members:manage' THEN 'use' ELSE 'delegate' END
						FROM permissions WHERE key IN ('auth.grants:assign', 'auth.members:manage')`); err != nil {
						t.Fatal(err)
					}
					wantCode = "AUTHORITY_DELTA_NOT_COVERED"
				case "owner_excluded":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				case "owner_inactive":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				case "token_scope":
					scopes = []string{"self:read"}
				}
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: "auth.grants:assign", ResourceSpace: f.spaceID, ResourceGroup: groupID, TokenScopes: scopes})
				if err != nil {
					t.Fatal(err)
				}
				out := groupGrantHTTP(f, token, groupID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: anchor})
				if scenario == "allow" {
					if decision.Effect != engine.Allow || out.Code != http.StatusOK {
						t.Fatalf("group grant diverged: engine=%s status=%d body=%s", decision.Code, out.Code, out.Body.String())
					}
					return
				}
				if wantCode == "" {
					wantCode = decision.Code
					if decision.Effect != engine.Deny {
						t.Fatal("expected the unified engine to deny this management action")
					}
				}
				if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), wantCode) {
					t.Fatalf("group grant failure: want=%s status=%d body=%s", wantCode, out.Code, out.Body.String())
				}
				var count int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_group_id = $1 AND permission_keys ? 'auth.members:manage'`, groupID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("denied group grant persisted: count=%d error=%v", count, err)
				}
			})
		}
	}
}

func TestEmptyGroupGrantDoesNotBypassFutureJoinCoverage(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_grant_empty', $1, 'Empty', 'grp_remove_root');
		UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $2`, pgx.QueryExecModeSimpleProtocol, f.spaceID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	input := authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: "grp_grant_empty"}
	if out := groupGrantHTTP(f, f.token, "grp_grant_empty", input); out.Code != http.StatusOK {
		t.Fatalf("empty group has no effective positive delta: status=%d body=%s", out.Code, out.Body.String())
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/spaces/"+f.spaceID+"/groups/grp_grant_empty/members/"+f.target.ID, nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("join bypassed the current assignment rights: status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestGroupGrantDescendantSpaceAnchorsUseActualAncestryAndEnvelopes(t *testing.T) {
	for _, scope := range []string{"space", "space_tree", "group", "group_tree"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			f := newGroupRemovalFixture(t)
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
				VALUES ('spc_grant_child', 'Child', 'grant-child', $1), ('spc_grant_grandchild', 'Grandchild', 'grant-grandchild', 'spc_grant_child');
				INSERT INTO groups (id, space_id, name) VALUES ('grp_grant_downstream', 'spc_grant_child', 'Downstream')`, pgx.QueryExecModeSimpleProtocol, f.spaceID); err != nil {
				t.Fatal(err)
			}
			input := authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: scope}
			if scope == "space" || scope == "space_tree" {
				input.AnchorSpaceID = "spc_grant_child"
			} else {
				input.AnchorGroupID = "grp_grant_downstream"
			}
			if out := groupGrantHTTP(f, f.token, "grp_remove_a", input); out.Code != http.StatusOK {
				t.Fatalf("descendant grant: status=%d body=%s", out.Code, out.Body.String())
			}
			check := func(space, group string, allow bool) {
				t.Helper()
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "auth.members:manage", ResourceSpace: space, ResourceGroup: group})
				if err != nil || (decision.Effect == engine.Allow) != allow {
					t.Fatalf("descendant resource: space=%s group=%s code=%s error=%v", space, group, decision.Code, err)
				}
			}
			check("spc_grant_child", "grp_grant_downstream", true)
			check(f.spaceID, "grp_remove_a", false)
			check("spc_grant_grandchild", "", scope == "space_tree")
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ('spc_grant_child')`); err != nil {
				t.Fatal(err)
			}
			check("spc_grant_child", "grp_grant_downstream", false)
		})
	}
}

func TestGroupGrantRejectsInvalidCatalogAnchorsAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_grant_foreign', 'Foreign', 'grant-foreign');
		INSERT INTO groups (id, space_id, name) VALUES ('grp_grant_foreign', 'spc_grant_foreign', 'Foreign');
		INSERT INTO roles (id, space_id, name) VALUES ('rol_grant_foreign', 'spc_grant_foreign', 'Foreign')`); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, group, code string
		input             authorization.GrantInput
	}{
		{"foreign_grantee", "grp_grant_foreign", "NOT_FOUND", authorization.GrantInput{Permissions: []string{"auth.members:manage"}}},
		{"foreign_role", "grp_remove_a", "NOT_FOUND", authorization.GrantInput{RoleID: "rol_grant_foreign"}},
		{"foreign_anchor", "grp_remove_a", "SCOPE_OUT_OF_BOUNDS", authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group", AnchorGroupID: "grp_grant_foreign"}},
		{"missing_anchor", "grp_remove_a", "VALIDATION_FAILED", authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group"}},
		{"global", "grp_remove_a", "VALIDATION_FAILED", authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "global"}},
		{"unknown_permission", "grp_remove_a", "AUTHORITY_DELTA_NOT_COVERED", authorization.GrantInput{Permissions: []string{"unknown:action"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if out := groupGrantHTTP(f, f.token, test.group, test.input); out.Code < http.StatusBadRequest || !strings.Contains(out.Body.String(), test.code) {
				t.Fatalf("invalid group grant: status=%d body=%s", out.Code, out.Body.String())
			}
		})
	}
	for _, status := range []string{"deprecated", "disabled"} {
		if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.members:manage'`, status); err != nil {
			t.Fatal(err)
		}
		if out := groupGrantHTTP(f, f.token, "grp_remove_a", authorization.GrantInput{Permissions: []string{"auth.members:manage"}}); out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
			t.Fatalf("new %s permission granted: status=%d", status, out.Code)
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'active' WHERE key = 'auth.members:manage';
		CREATE FUNCTION reject_group_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'grant.inline.create' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_group_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_group_grant_audit()`); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if out := groupGrantHTTP(f, f.token, "grp_remove_a", authorization.GrantInput{Permissions: []string{"auth.members:manage"}}); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("unaudited grant succeeded: status=%d", out.Code)
	}
	var count int
	var unchanged bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM authorization_grants WHERE grantee_group_id = 'grp_remove_a' AND permission_keys ? 'auth.members:manage'),
		(SELECT policy_version = $2 FROM spaces WHERE id = $1)`, f.spaceID, version).Scan(&count, &unchanged); err != nil || count != 0 || !unchanged {
		t.Fatalf("failed audit did not roll back grant/version: count=%d unchanged=%v error=%v", count, unchanged, err)
	}
}

func TestGroupGrantConcurrentJoinCannotEscapeRecipientSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f := newGroupRemovalFixture(t)
	joining, err := f.authz.CreateMember(ctx, f.owner.ID, "", f.spaceID, "Concurrent joiner", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_principal_actor', $1)`, joining.ID); err != nil {
		t.Fatal(err)
	}
	locked, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- f.store.InTx(ctx, func(q *db.Queries) error {
			if _, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID}); err != nil {
				return err
			}
			close(locked)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
			return q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: "grp_remove_a", SpaceID: f.spaceID, MemberID: joining.ID, Source: "manual"})
		})
	}()
	select {
	case <-locked:
	case err := <-writer:
		t.Fatalf("could not establish the membership write barrier: %v", err)
	}
	granted := make(chan error, 1)
	go func() {
		_, err := f.authz.CreateGroupGrant(ctx, f.owner.ID, f.spaceID, "grp_remove_a", authorization.GrantInput{
			Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: "grp_remove_a",
		})
		granted <- err
	}()
	for {
		var waiting bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%-- name: LockSpaceForAuthorization%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-granted:
			t.Fatalf("grant bypassed the write barrier: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	var public *apierr.Error
	if err := <-granted; !errors.As(err, &public) || public.Code != "CONFLICT" {
		t.Fatalf("grant failed to detect its changed recipient set: %v", err)
	}
	decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: joining.ID, Permission: "auth.members:manage", ResourceSpace: f.spaceID, ResourceGroup: "grp_remove_a"})
	if err != nil || decision.Effect != engine.Deny {
		t.Fatalf("unvalidated grant reached a concurrent joiner: code=%s error=%v", decision.Code, err)
	}
}

func TestInstallationRoleCannotBeReusedForMemberOrGroupGrant(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id) VALUES ('app_role_reuse', $1, 'Installation role', 'role-reuse');
		INSERT INTO members (id, space_id, name, type) VALUES ('mem_role_reuse', $1, 'Installation', 'application');
		INSERT INTO roles (id, space_id, name, managed) VALUES ('rol_installation_only', $1, 'Installation manifest', true);
		INSERT INTO application_installations (id, application_id, space_id, member_id, role_id, scope, approved_permissions, installed_by)
		VALUES ('ins_role_reuse', 'app_role_reuse', $1, 'mem_role_reuse', 'rol_installation_only', 'space', '[]', $2)`, pgx.QueryExecModeSimpleProtocol, f.spaceID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	if out := groupGrantHTTP(f, f.token, "grp_remove_a", authorization.GrantInput{RoleID: "rol_installation_only"}); out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("group reused an installation's independently approved role: status=%d", out.Code)
	}
	_, err := f.authz.CreateGrant(ctx, f.owner.ID, f.spaceID, f.target.ID, "rol_installation_only", "space", f.spaceID)
	assertPrincipalError(t, err, "VALIDATION_FAILED")
}
