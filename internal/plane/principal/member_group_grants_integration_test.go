package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func memberGroupGrantHTTP(f groupRemovalFixture, token, memberID string, input authorization.GrantInput) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"grantee": map[string]string{"member_id": memberID}, "role_id": input.RoleID, "permissions": input.Permissions,
		"scope": input.Scope, "anchor_space_id": input.AnchorSpaceID, "anchor_group_id": input.AnchorGroupID,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+f.spaceID+"/grants", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func TestMemberGroupGrantHTTPScopesSourcesRecipientsAndIndependentRevocation(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, source := range []string{"inline", "role"} {
			for _, scope := range []string{"group", "group_tree"} {
				t.Run(kind+"/"+source+"/"+scope, func(t *testing.T) {
					ctx := context.Background()
					f := newGroupRemovalFixture(t)
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_member_anchor_child', $1, 'Child', 'grp_remove_a')`, f.spaceID); err != nil {
						t.Fatal(err)
					}
					memberID := f.target.ID
					if kind == "agent" {
						created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "scoped-recipient"})
						if err != nil {
							t.Fatal(err)
						}
						memberID = created.ID
					}
					input := authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: scope, AnchorGroupID: "grp_remove_a"}
					if source == "role" {
						role, err := f.authz.CreateRole(ctx, f.owner.ID, f.spaceID, "Scoped member manager", "", input.Permissions)
						if err != nil {
							t.Fatal(err)
						}
						input.RoleID, input.Permissions = role.ID, nil
					}
					out := memberGroupGrantHTTP(f, f.token, memberID, input)
					var response struct{ Data authorization.Grant }
					if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &response) != nil || response.Data.ID == "" || response.Data.GranteeMemberID != memberID || response.Data.AnchorGroupID != input.AnchorGroupID || response.Data.AnchorSpaceID != "" {
						t.Fatalf("member group grant: status=%d body=%s", out.Code, out.Body.String())
					}
					if independent := memberGroupGrantHTTP(f, f.token, memberID, authorization.GrantInput{Permissions: []string{"auth.roles:manage"}, Scope: "group", AnchorGroupID: "grp_remove_b"}); independent.Code != http.StatusOK {
						t.Fatalf("independent member grant: status=%d body=%s", independent.Code, independent.Body.String())
					}
					remote, err := store.Open(ctx, f.store.Pool.Config().ConnString())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(remote.Close)
					services := []*authorization.Service{f.authz, {Store: remote}}
					check := func(permission, group string, allow bool) {
						t.Helper()
						for _, svc := range services {
							decision, _, err := svc.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: permission, ResourceSpace: f.spaceID, ResourceGroup: group})
							if err != nil || (decision.Effect == engine.Allow) != allow {
								t.Fatalf("scoped member decision: group=%s code=%s error=%v", group, decision.Code, err)
							}
						}
					}
					check("auth.members:manage", "grp_remove_a", true)
					check("auth.members:manage", "grp_member_anchor_child", scope == "group_tree")
					check("auth.members:manage", "grp_remove_b", false)
					check("auth.members:manage", "", false)
					check("auth.roles:manage", "grp_remove_b", true)
					req := httptest.NewRequest(http.MethodDelete, "/v1/spaces/"+f.spaceID+"/grants/"+response.Data.ID, nil)
					req.Header.Set("Authorization", "Bearer "+f.token)
					revoked := httptest.NewRecorder()
					f.handler.ServeHTTP(revoked, req)
					if revoked.Code != http.StatusOK {
						t.Fatalf("scoped member revocation: status=%d", revoked.Code)
					}
					check("auth.members:manage", "grp_remove_a", false)
					check("auth.roles:manage", "grp_remove_b", true)
					req = httptest.NewRequest(http.MethodGet, "/v1/spaces/"+f.spaceID+"/audit-logs?member_id="+memberID+"&limit=100", nil)
					req.Header.Set("Authorization", "Bearer "+f.token)
					events := httptest.NewRecorder()
					f.handler.ServeHTTP(events, req)
					var logs struct{ Data []audit.Event }
					if events.Code != http.StatusOK || json.Unmarshal(events.Body.Bytes(), &logs) != nil {
						t.Fatal("could not query the member grant audit")
					}
					found := false
					for _, event := range logs.Data {
						if event.ResourceID == response.Data.ID && (event.Action == "grant.create" || event.Action == "grant.inline.create") {
							var metadata struct {
								AnchorGroupID string `json:"anchor_group_id"`
							}
							if err := json.Unmarshal(event.Metadata, &metadata); err != nil {
								t.Fatal(err)
							}
							found = event.ActorID == f.owner.ID && event.MemberID == memberID && event.UserID == "usr_principal_actor" && event.SpaceID == f.spaceID && metadata.AnchorGroupID == input.AnchorGroupID
							if kind == "agent" && (len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != f.owner.ID) {
								t.Fatal("member grant audit omitted the Agent owner")
							}
						}
					}
					if !found || strings.Contains(events.Body.String(), f.token) {
						t.Fatal("member grant audit omitted target/source facts or contained a credential")
					}
				})
			}
		}
	}
}

func TestMemberGroupGrantHTTPUsesRecipientPositionAndRecursiveActorAuthority(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, scenario := range []string{"allow", "outside_scope", "ambiguous_position", "position_right", "uncovered_anchor", "missing_right", "envelope", "disabled", "principal_kind", "owner_excluded", "owner_inactive", "owner_right", "token_scope"} {
			if kind == "human" && (strings.HasPrefix(scenario, "owner_") || scenario == "token_scope") {
				continue
			}
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				ctx := context.Background()
				f := newGroupRemovalFixture(t)
				actorID, token := f.owner.ID, f.token
				if kind == "agent" {
					created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "member-grant-manager"})
					if err != nil {
						t.Fatal(err)
					}
					actorID = created.ID
					var tokens session.Tokens
					if scenario == "token_scope" {
						tokens, err = f.sessions.CreateAgentDelegatedAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience, f.owner.ID, []string{"self:read"}, 0)
					} else {
						tokens, err = f.sessions.CreateAgentAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience)
					}
					if err != nil {
						t.Fatal(err)
					}
					token = tokens.AccessToken
				}
				targetGroup, anchor := "grp_remove_a", "grp_remove_a"
				if scenario != "ambiguous_position" && scenario != "position_right" {
					if _, err := f.store.Pool.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND member_id = $2`, "grp_remove_b", f.target.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					targetGroup = ""
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
					govScope := "group_tree"
					var govSpace, govGroup any = nil, "grp_remove_a"
					if scenario == "position_right" {
						govScope, govSpace, govGroup = "space", f.spaceID, nil
					}
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, anchor_group_id, granted_by)
						VALUES ('grt_member_manager_' || $1, $2, '["auth.grants:assign"]', $1, $3, $4, $5, $6);
						INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_group_id, covers_subtree, can_redelegate, source)
						VALUES ('ar_member_manager_' || $1, $1, '["auth.members:manage"]', 'grp_remove_a', true, false, 'system')`, pgx.QueryExecModeSimpleProtocol, memberID, f.spaceID, govScope, govSpace, govGroup, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				}
				wantCode := ""
				var scopes []string
				switch scenario {
				case "outside_scope":
					if _, err := f.store.Pool.Exec(ctx, `DELETE FROM group_members WHERE member_id = $1;
						INSERT INTO group_members (group_id, member_id, space_id, source) VALUES ('grp_remove_b', $1, $2, 'manual')`, pgx.QueryExecModeSimpleProtocol, f.target.ID, f.spaceID); err != nil {
						t.Fatal(err)
					}
					targetGroup = "grp_remove_b"
				case "position_right":
					wantCode = "AUTHORITY_DELTA_NOT_COVERED"
				case "uncovered_anchor":
					anchor, wantCode = "grp_remove_b", "AUTHORITY_DELTA_NOT_COVERED"
				case "missing_right", "owner_right":
					member := actorID
					if scenario == "owner_right" {
						member = f.owner.ID
					}
					if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, member); err != nil {
						t.Fatal(err)
					}
					wantCode = "AUTHORITY_DELTA_NOT_COVERED"
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
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: "auth.grants:assign", ResourceSpace: f.spaceID, ResourceGroup: targetGroup, TokenScopes: scopes})
				if err != nil {
					t.Fatal(err)
				}
				out := memberGroupGrantHTTP(f, token, f.target.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: anchor})
				if scenario == "allow" {
					if decision.Effect != engine.Allow || out.Code != http.StatusOK {
						t.Fatalf("member grant allow diverged: engine=%s status=%d body=%s", decision.Code, out.Code, out.Body.String())
					}
					return
				}
				if wantCode == "" {
					wantCode = decision.Code
					if decision.Effect != engine.Deny {
						t.Fatal("the management engine should deny this recipient position")
					}
				}
				if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), wantCode) {
					t.Fatalf("member grant denial: want=%s status=%d body=%s", wantCode, out.Code, out.Body.String())
				}
				var count int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND permission_keys ? 'auth.members:manage'`, f.target.ID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("denied member grant persisted: count=%d error=%v", count, err)
				}
			})
		}
	}
}

func TestMemberGroupGrantUsesDescendantAnchorSpaceAndItsEnvelope(t *testing.T) {
	for _, scope := range []string{"group", "group_tree"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			f := newGroupRemovalFixture(t)
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id) VALUES ('spc_member_anchor', 'Anchor', 'member-anchor', $1);
				INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_member_anchor', 'spc_member_anchor', 'Anchor', NULL), ('grp_member_anchor_child', 'spc_member_anchor', 'Child', 'grp_member_anchor')`, pgx.QueryExecModeSimpleProtocol, f.spaceID); err != nil {
				t.Fatal(err)
			}
			out := memberGroupGrantHTTP(f, f.token, f.target.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: scope, AnchorGroupID: "grp_member_anchor"})
			if out.Code != http.StatusOK {
				t.Fatalf("descendant anchor grant: status=%d body=%s", out.Code, out.Body.String())
			}
			for _, resource := range []struct {
				space, group string
				allow        bool
			}{{"spc_member_anchor", "grp_member_anchor", true}, {"spc_member_anchor", "grp_member_anchor_child", scope == "group_tree"}, {f.spaceID, "grp_remove_a", false}} {
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "auth.members:manage", ResourceSpace: resource.space, ResourceGroup: resource.group})
				if err != nil || (decision.Effect == engine.Allow) != resource.allow {
					t.Fatalf("descendant anchor resource: code=%s error=%v", decision.Code, err)
				}
			}
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_member_anchor')`); err != nil {
				t.Fatal(err)
			}
			decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "auth.members:manage", ResourceSpace: "spc_member_anchor", ResourceGroup: "grp_member_anchor"})
			if err != nil || decision.Code != "ENVELOPE_EXCLUDED" {
				t.Fatalf("descendant anchor envelope ignored: code=%s error=%v", decision.Code, err)
			}
		})
	}
}

func TestMemberGroupGrantRejectsInvalidFactsAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_member_foreign', 'Foreign', 'member-foreign');
		INSERT INTO groups (id, space_id, name) VALUES ('grp_member_foreign', 'spc_member_foreign', 'Foreign');
		INSERT INTO members (id, space_id, name, type) VALUES ('mem_member_foreign', 'spc_member_foreign', 'Foreign', 'human')`); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, member, scope, anchor, anchorSpace, code string
	}{
		{"foreign_member", "mem_member_foreign", "group", "grp_remove_a", "", "NOT_FOUND"},
		{"missing_member", "mem_member_missing", "group", "grp_remove_a", "", "NOT_FOUND"},
		{"foreign_anchor", f.target.ID, "group", "grp_member_foreign", "", "SCOPE_OUT_OF_BOUNDS"},
		{"missing_anchor", f.target.ID, "group", "grp_member_missing", "", "NOT_FOUND"},
		{"no_anchor", f.target.ID, "group", "", "", "VALIDATION_FAILED"},
		{"mixed_anchor", f.target.ID, "group", "grp_remove_a", f.spaceID, "VALIDATION_FAILED"},
		{"wrong_scope", f.target.ID, "space", "grp_remove_a", "", "VALIDATION_FAILED"},
	} {
		t.Run(item.name, func(t *testing.T) {
			out := memberGroupGrantHTTP(f, f.token, item.member, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: item.scope, AnchorGroupID: item.anchor, AnchorSpaceID: item.anchorSpace})
			if out.Code < http.StatusBadRequest || !strings.Contains(out.Body.String(), item.code) {
				t.Fatalf("invalid member grant: status=%d body=%s", out.Code, out.Body.String())
			}
		})
	}
	oauth, err := (&agent.Service{Store: f.store}).CreateOAuth(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, CreatedByUser: "usr_principal_actor", Name: "consent-agent", Source: "oauth", OAuthClientID: "https://client.example.test/metadata.json", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if out := memberGroupGrantHTTP(f, f.token, oauth.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group", AnchorGroupID: "grp_remove_a"}); out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("generic grant bypassed OAuth consent: status=%d", out.Code)
	}
	for _, status := range []string{"deprecated", "disabled"} {
		if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.members:manage'`, status); err != nil {
			t.Fatal(err)
		}
		if out := memberGroupGrantHTTP(f, f.token, f.target.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group", AnchorGroupID: "grp_remove_a"}); out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
			t.Fatalf("new %s permission was granted: status=%d", status, out.Code)
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'active' WHERE key = 'auth.members:manage';
		CREATE FUNCTION reject_member_group_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'grant.inline.create' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_member_group_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_member_group_grant_audit()`); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if out := memberGroupGrantHTTP(f, f.token, f.target.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group", AnchorGroupID: "grp_remove_a"}); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("unaudited member grant committed: status=%d", out.Code)
	}
	var count int
	var unchanged bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND permission_keys ? 'auth.members:manage'),
		(SELECT policy_version = $3 FROM spaces WHERE id = $2)`, f.target.ID, f.spaceID, version).Scan(&count, &unchanged); err != nil || count != 0 || !unchanged {
		t.Fatalf("audit failure did not roll back the member grant: count=%d unchanged=%v error=%v", count, unchanged, err)
	}
}

func TestMemberGroupGrantLocksRecipientAndAnchorBeforeWrite(t *testing.T) {
	for _, node := range []string{"member", "anchor"} {
		t.Run(node, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			f := newGroupRemovalFixture(t)
			locked, release := make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			go func() {
				writer <- f.store.InTx(ctx, func(q *db.Queries) error {
					var err error
					if node == "member" {
						_, err = q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: f.target.ID, SpaceID: f.spaceID})
					} else {
						_, err = q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: "grp_remove_a", SpaceID: f.spaceID})
					}
					if err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			select {
			case <-locked:
			case err := <-writer:
				t.Fatalf("could not establish grant barrier: %v", err)
			}
			granted := make(chan error, 1)
			go func() {
				_, err := f.authz.CreateMemberGroupGrant(ctx, f.owner.ID, f.spaceID, f.target.ID, authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: "grp_remove_a"})
				granted <- err
			}()
			for {
				var waiting bool
				if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
					AND wait_event_type = 'Lock' AND query LIKE '%FOR UPDATE%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-granted:
					t.Fatalf("grant bypassed the %s lock: %v", node, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			if err := <-granted; err != nil {
				t.Fatalf("member grant failed after releasing its %s lock: %v", node, err)
			}
		})
	}
}
