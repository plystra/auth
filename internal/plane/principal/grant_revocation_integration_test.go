package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func grantRevocationHTTP(ctx context.Context, f groupRemovalFixture, token, grantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/spaces/"+f.spaceID+"/grants/"+grantID, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func TestGrantRevocationRechecksRecipientPositionAfterConcurrentMembershipChange(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, change := range []string{"move_to_sibling", "add_second_group", "remove_only_group", "move_within_authority"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				f := newGroupRemovalFixture(t)
				if err := f.authz.RemoveMemberFromGroup(ctx, f.owner.ID, f.spaceID, "grp_remove_b", f.target.ID); err != nil {
					t.Fatal(err)
				}
				grant, err := f.authz.CreateMemberGroupGrant(ctx, f.owner.ID, f.spaceID, f.target.ID, authorization.GrantInput{
					Permissions: []string{"auth.roles:manage"}, Scope: "group_tree", AnchorGroupID: "grp_remove_a",
				})
				if err != nil {
					t.Fatal(err)
				}
				actorID, token := f.owner.ID, f.token
				if kind == "agent" {
					created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "grant-revoker"})
					if err != nil {
						t.Fatal(err)
					}
					actorID = created.ID
					tokens, err := f.sessions.CreateAgentAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience)
					if err != nil {
						t.Fatal(err)
					}
					token = tokens.AccessToken
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				actors := []string{f.owner.ID}
				if actorID != f.owner.ID {
					actors = append(actors, actorID)
				}
				for _, id := range actors {
					scope := "group_tree"
					var anchorSpace, anchorGroup any = nil, "grp_remove_a"
					if change == "move_within_authority" {
						scope, anchorSpace, anchorGroup = "space_tree", f.spaceID, nil
					}
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, anchor_group_id, granted_by)
						VALUES ('grt_revoke_manager_' || $1, $2, '["auth.grants:assign"]', $1, $3, $4, $5, $6)`, id, f.spaceID, scope, anchorSpace, anchorGroup, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				}
				locked, changePosition := make(chan struct{}), make(chan struct{})
				writer := make(chan error, 1)
				// The membership writer holds the recipient before changing its
				// position. Revocation must resolve the position after that lock.
				go func() {
					writer <- f.store.InTx(ctx, func(q *db.Queries) error {
						if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.target.ID}); err != nil {
							return err
						}
						close(locked)
						select {
						case <-changePosition:
						case <-ctx.Done():
							return ctx.Err()
						}
						if _, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID}); err != nil {
							return err
						}
						for _, id := range []string{"grp_remove_a", "grp_remove_b"} {
							if _, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: id, SpaceID: f.spaceID}); err != nil {
								return err
							}
						}
						if change != "add_second_group" {
							if err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: "grp_remove_a", MemberID: f.target.ID, SpaceID: f.spaceID}); err != nil {
								return err
							}
						}
						if change != "remove_only_group" {
							return q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: "grp_remove_b", MemberID: f.target.ID, SpaceID: f.spaceID, Source: "manual"})
						}
						return nil
					})
				}()
				select {
				case <-locked:
				case err := <-writer:
					t.Fatalf("could not establish membership barrier: %v", err)
				}
				revocation := make(chan *httptest.ResponseRecorder, 1)
				go func() { revocation <- grantRevocationHTTP(ctx, f, token, grant.ID) }()
				for {
					var waiting bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
						AND wait_event_type = 'Lock' AND query LIKE '%members%FOR UPDATE%')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case out := <-revocation:
						t.Fatalf("revocation bypassed the recipient lock: status=%d", out.Code)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				close(changePosition)
				if err := <-writer; err != nil {
					t.Fatal(err)
				}
				out := <-revocation
				groupID := ""
				if change == "move_to_sibling" || change == "move_within_authority" {
					groupID = "grp_remove_b"
				}
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{
					MemberID: actorID, Permission: "auth.grants:assign", ResourceSpace: f.spaceID, ResourceGroup: groupID,
				})
				allowed := change == "move_within_authority"
				if err != nil || (decision.Effect == engine.Allow) != allowed || allowed && out.Code != http.StatusOK || !allowed && (out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), decision.Code)) {
					t.Fatalf("revocation used an obsolete position: check=%s error=%v status=%d body=%s", decision.Code, err, out.Code, out.Body.String())
				}
				var revoked bool
				var auditCount int
				var auditGroup string
				if err := f.store.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL,
					(SELECT count(*) FROM audit_logs WHERE action = 'grant.revoke' AND resource_id = $1),
					COALESCE((SELECT resource_group_id FROM audit_logs WHERE action = 'grant.revoke' AND resource_id = $1), '')
					FROM authorization_grants WHERE id = $1`, grant.ID).Scan(&revoked, &auditCount, &auditGroup); err != nil || revoked != allowed || !allowed && auditCount != 0 || allowed && (auditCount != 1 || auditGroup != groupID) {
					t.Fatalf("concurrent revocation state or audit mismatch: revoked=%v audits=%d group=%s error=%v", revoked, auditCount, auditGroup, err)
				}
			})
		}
	}
}

func TestGrantRevocationHTTPIsAtomicConcurrentAndIdempotent(t *testing.T) {
	for _, recipient := range []string{"human", "agent", "group"} {
		for _, source := range []string{"inline", "role"} {
			t.Run(recipient+"/"+source, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				f := newGroupRemovalFixture(t)
				memberID, groupID := f.target.ID, ""
				if recipient == "agent" {
					created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "revocation-recipient"})
					if err != nil {
						t.Fatal(err)
					}
					memberID = created.ID
				}
				if recipient == "group" {
					groupID = "grp_remove_a"
				}
				create := func(input authorization.GrantInput) authorization.Grant {
					t.Helper()
					var out *httptest.ResponseRecorder
					if groupID != "" {
						out = groupGrantHTTP(f, f.token, groupID, input)
					} else {
						out = memberGroupGrantHTTP(f, f.token, memberID, input)
					}
					var response struct{ Data authorization.Grant }
					if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &response) != nil || response.Data.ID == "" {
						t.Fatalf("could not create revocation fixture: status=%d body=%s", out.Code, out.Body.String())
					}
					return response.Data
				}
				input := authorization.GrantInput{Permissions: []string{"auth.roles:manage"}, Scope: "group_tree", AnchorGroupID: "grp_remove_a"}
				if source == "role" {
					role, err := f.authz.CreateRole(ctx, f.owner.ID, f.spaceID, "Revocable role", "", input.Permissions)
					if err != nil {
						t.Fatal(err)
					}
					input.RoleID, input.Permissions = role.ID, nil
				}
				grant := create(input)
				create(authorization.GrantInput{Permissions: []string{"auth.members:manage"}, Scope: "group_tree", AnchorGroupID: "grp_remove_a"})
				remote, err := store.Open(ctx, f.store.Pool.Config().ConnString())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(remote.Close)
				services := []*authorization.Service{f.authz, {Store: remote}}
				check := func(permission string, allow bool) {
					t.Helper()
					for _, svc := range services {
						decision, _, err := svc.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: permission, ResourceSpace: f.spaceID, ResourceGroup: "grp_remove_a"})
						if err != nil || (decision.Effect == engine.Allow) != allow {
							t.Fatalf("grant revocation visibility: permission=%s code=%s error=%v", permission, decision.Code, err)
						}
					}
				}
				check("auth.roles:manage", true)
				check("auth.members:manage", true)
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_grant_revocation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.action = 'grant.revoke' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
					CREATE TRIGGER reject_grant_revocation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_grant_revocation_audit()`); err != nil {
					t.Fatal(err)
				}
				var spaceVersion, memberVersion int64
				readVersions := func() (int64, int64) {
					var space, member int64
					if err := f.store.Pool.QueryRow(ctx, `SELECT s.policy_version, m.version FROM spaces s, members m WHERE s.id = $1 AND m.id = $2`, f.spaceID, memberID).Scan(&space, &member); err != nil {
						t.Fatal(err)
					}
					return space, member
				}
				spaceVersion, memberVersion = readVersions()
				if out := grantRevocationHTTP(ctx, f, f.token, grant.ID); out.Code != http.StatusServiceUnavailable {
					t.Fatalf("unaudited revocation committed: status=%d body=%s", out.Code, out.Body.String())
				}
				if space, member := readVersions(); space != spaceVersion || member != memberVersion {
					t.Fatal("failed revocation changed a policy version")
				}
				check("auth.roles:manage", true)
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_grant_revocation_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				results := make(chan *httptest.ResponseRecorder, 2)
				for range 2 {
					go func() { results <- grantRevocationHTTP(ctx, f, f.token, grant.ID) }()
				}
				for range 2 {
					if out := <-results; out.Code != http.StatusOK {
						t.Fatalf("concurrent revocation failed: status=%d body=%s", out.Code, out.Body.String())
					}
				}
				spaceVersion, memberVersion = readVersions()
				if out := grantRevocationHTTP(ctx, f, f.token, grant.ID); out.Code != http.StatusOK {
					t.Fatalf("repeated revocation failed: status=%d", out.Code)
				}
				if space, member := readVersions(); space != spaceVersion || member != memberVersion {
					t.Fatal("repeated revocation changed a policy version")
				}
				check("auth.roles:manage", false)
				check("auth.members:manage", true)
				req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+f.spaceID+"/audit-logs?action=grant.revoke&limit=100", nil)
				req.Header.Set("Authorization", "Bearer "+f.token)
				out := httptest.NewRecorder()
				f.handler.ServeHTTP(out, req)
				var logs struct{ Data []audit.Event }
				if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &logs) != nil || len(logs.Data) != 1 {
					t.Fatalf("revocation audit was omitted or duplicated: status=%d body=%s", out.Code, out.Body.String())
				}
				event := logs.Data[0]
				subjectID, location := memberID, groupID
				if groupID == "" {
					location, err = f.authz.ResourceGroupForMember(ctx, memberID, f.spaceID)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					subjectID = f.owner.ID
				}
				if event.ResourceID != grant.ID || event.ResourceType != "grant" || event.ResourceGroupID != location || event.SpaceID != f.spaceID || event.ActorID != f.owner.ID || event.MemberID != subjectID || event.UserID != "usr_principal_actor" || event.Plane != "principal" || event.CredentialType == "" {
					t.Fatalf("revocation audit omitted its subject or location: %+v", event)
				}
				if recipient == "agent" && (len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != f.owner.ID) {
					t.Fatal("revocation audit omitted the affected Agent's owner")
				}
				if strings.Contains(out.Body.String(), f.token) {
					t.Fatal("revocation audit included a credential")
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				if denied := grantRevocationHTTP(ctx, f, f.token, grant.ID); denied.Code != http.StatusForbidden {
					t.Fatalf("repeated revocation bypassed current authorization: status=%d", denied.Code)
				}
			})
		}
	}
}
