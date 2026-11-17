package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/store"
)

var grantIdentityOperations = []string{
	"member_role", "member_inline", "member_group_role", "member_group_inline",
	"group_role", "group_inline", "member_revoke", "group_revoke", "list",
	"owner_agent_space", "owner_agent_group", "admin_agent_space", "admin_agent_group",
	"group_join", "group_leave",
}

func grantIdentityOperation(t *testing.T, f governanceAuditFixture, name string) governanceAuditOperation {
	t.Helper()
	ctx := context.Background()
	if f.parentID != "" {
		permissions := []string{"auth.groups:manage", "auth.grants:assign", "auth.members:read"}
		for _, pair := range [][2]string{{f.ownerID, f.parentID}, {f.parentID, f.actorID}} {
			if _, err := f.authz.ReplaceAgentGrants(ctx, pair[0], f.spaceID, pair[1], permissions, "space", f.spaceID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.authz.AddMemberToGroup(ctx, f.ownerID, f.spaceID, f.fromID, f.holderID); err != nil {
		t.Fatal(err)
	}
	base := "/v1/spaces/" + f.spaceID
	op := governanceAuditOperation{method: http.MethodPost, path: base + "/grants", groupID: f.fromID}
	body := map[string]any{"grantee": map[string]string{"member_id": f.holderID}, "scope": "space", "permissions": []string{"auth.members:read"}}
	op.body = body
	switch name {
	case "member_role", "member_inline", "member_group_role", "member_group_inline", "group_role", "group_inline":
		if strings.HasPrefix(name, "group_") {
			body["grantee"] = map[string]string{"group_id": f.fromID}
		}
		if strings.Contains(name, "group") {
			body["scope"], body["anchor_group_id"] = "group_tree", f.fromID
		}
		if strings.HasSuffix(name, "_role") {
			delete(body, "permissions")
			body["role_id"] = f.roleID
		}
	case "member_revoke":
		grant, err := f.authz.CreateInlineGrant(ctx, f.ownerID, f.spaceID, f.holderID, []string{"auth.members:read"}, "space", f.spaceID)
		if err != nil {
			t.Fatal(err)
		}
		op.method, op.path, op.body = http.MethodDelete, base+"/grants/"+grant.ID, nil
	case "group_revoke":
		grant, err := f.authz.CreateGroupGrant(ctx, f.ownerID, f.spaceID, f.fromID, authorization.GrantInput{Permissions: []string{"auth.members:read"}, Scope: "group_tree", AnchorGroupID: f.fromID})
		if err != nil {
			t.Fatal(err)
		}
		op.method, op.path, op.body = http.MethodDelete, base+"/grants/"+grant.ID, nil
	case "list":
		op.method, op.body = http.MethodGet, nil
	case "owner_agent_space", "owner_agent_group", "admin_agent_space", "admin_agent_group":
		ownerID := f.actorID
		if strings.HasPrefix(name, "admin_") {
			ownerID = f.holderID
		}
		agents := &agent.Service{Store: f.store}
		created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, CreatedByUser: "usr_principal_actor", Name: "Grant recipient", ExpiresAt: time.Now().Add(30 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		op.method, op.path = http.MethodPut, "/v1/me/agents/"+created.ID+"/grants"
		op.groupID = created.HomeGroupID
		op.body = map[string]any{"permissions": []string{"auth.members:read"}, "scope": "space"}
		if strings.HasSuffix(name, "_group") {
			op.body.(map[string]any)["scope"], op.body.(map[string]any)["anchor_group_id"] = "group_tree", f.fromID
			op.groupID = f.fromID
		}
	case "group_join", "group_leave":
		op.method, op.path, op.body = http.MethodPut, base+"/groups/"+f.toID+"/members/"+f.holderID, nil
		op.groupID = f.toID
		if name == "group_leave" {
			op.method, op.path = http.MethodDelete, base+"/groups/"+f.fromID+"/members/"+f.holderID
			op.groupID = f.fromID
		}
	default:
		t.Fatalf("unknown grant identity operation %q", name)
	}
	return op
}

func grantIdentityRequest(t *testing.T, ctx context.Context, f governanceAuditFixture, op governanceAuditOperation) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if op.body != nil {
		var err error
		body, err = json.Marshal(op.body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(op.method, op.path, strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "req_grant_identity")
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, request)
	return out
}

func waitForGrantIdentityLock(t *testing.T, ctx context.Context, st *store.Store, completed <-chan error) {
	t.Helper()
	for {
		var waiting bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-completed:
			t.Fatalf("operation did not wait for its identity or target lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestGrantManagementHTTPRechecksIdentityAfterWaitingForLocks(t *testing.T) {
	t.Parallel()
	for _, name := range grantIdentityOperations {
		for _, change := range []string{"binding", "expired_binding", "account", "owner", "expires_while_waiting", "expires_after_group_wait"} {
			if change == "expires_after_group_wait" && (name == "list" || name == "owner_agent_space") {
				continue
			}
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f := newGovernanceAuditFixture(t, kind, "group")
				op := grantIdentityOperation(t, f, name)
				expiresAt := time.Now().UTC().Add(3 * time.Second)
				waitingForExpiry := strings.HasPrefix(change, "expires_")
				if waitingForExpiry {
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}})
					}); err != nil {
						t.Fatal(err)
					}
				}
				state := func() string {
					t.Helper()
					var out string
					if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
						'grants', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM authorization_grants g),
						'memberships', (SELECT jsonb_agg(to_jsonb(g) ORDER BY group_id, member_id) FROM group_members g),
						'audits', (SELECT count(*) FROM audit_logs)
						)::text`).Scan(&out); err != nil {
						t.Fatal(err)
					}
					return out
				}
				before := state()
				barrier, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
				if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
					if change == "expires_after_group_wait" {
						_, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: op.groupID, SpaceID: f.spaceID})
						return err
					}
					if waitingForExpiry {
						_, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID})
						return err
					}
					if err := member.LockChainsTx(ctx, q, f.actorID); err != nil {
						return err
					}
					switch change {
					case "binding":
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.actorID})
					case "expired_binding":
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(-time.Second), Valid: true}})
					case "account":
						return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
					default:
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					}
				}); err != nil {
					t.Fatal(err)
				}
				completed := make(chan error, 1)
				var out *httptest.ResponseRecorder
				go func() {
					out = grantIdentityRequest(t, ctx, f, op)
					completed <- fmt.Errorf("HTTP status %d", out.Code)
				}()
				waitForGrantIdentityLock(t, ctx, f.store, completed)
				if waitingForExpiry {
					timer := time.NewTimer(time.Until(expiresAt.Add(25 * time.Millisecond)))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				if err := barrier.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case <-completed:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("grant management retained revoked %s identity: status=%d", change, out.Code)
				}
				if state() != before {
					t.Fatal("denied grant management changed grants, group memberships, or success audits")
				}
			})
		}
	}
}

func TestGrantManagementHTTPRetainsIdentityLocksUntilCommit(t *testing.T) {
	for _, name := range grantIdentityOperations {
		for _, change := range []string{"account", "binding", "owner"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f := newGovernanceAuditFixture(t, kind, "group")
				op := grantIdentityOperation(t, f, name)
				mutation, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
				out := grantIdentityRequest(t, mutation.Context(ctx), f, op)
				if out.Code != http.StatusOK {
					var response struct {
						Error struct{ Code string } `json:"error"`
					}
					if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					t.Fatalf("active grant manager denied: status=%d code=%s", out.Code, response.Error.Code)
				}
				writer := make(chan error, 1)
				go func() {
					if change == "binding" {
						writer <- f.authz.RevokeOwnBinding(ctx, f.userID, f.actorID)
						return
					}
					writer <- f.store.InTx(ctx, func(q *db.Queries) error {
						if change == "account" {
							return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
						}
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					})
				}()
				waitForGrantIdentityLock(t, ctx, f.store, writer)
				if err := mutation.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-writer:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				out = grantIdentityRequest(t, ctx, f, op)
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("next grant management request retained revoked %s identity: status=%d", change, out.Code)
				}
			})
		}
	}
}

func TestGrantManagementRoleLockOrderDoesNotDeadlockWithRoleUpdate(t *testing.T) {
	for _, name := range []string{"member_role", "member_group_role", "group_role"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f := newGovernanceAuditFixture(t, "human", "group")
			op := grantIdentityOperation(t, f, name)
			if _, err := f.authz.CreateGrant(ctx, f.ownerID, f.spaceID, f.holderID, f.roleID, "space_tree", f.spaceID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_role_editor', 'role-editor@example.test', 'role-editor@example.test', 'test-password-hash', 'active')`); err != nil {
				t.Fatal(err)
			}
			editor, err := f.authz.CreateMember(ctx, f.ownerID, "usr_role_editor", f.spaceID, "Role editor", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.authz.CreateInlineGrant(ctx, f.ownerID, f.spaceID, editor.ID, []string{"auth.roles:manage"}, "space", f.spaceID); err != nil {
				t.Fatal(err)
			}
			roleUpdate, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = roleUpdate.Rollback(context.Background()) })
			if err := f.store.InTx(roleUpdate.Context(ctx), func(q *db.Queries) error {
				if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: "usr_role_editor"}); err != nil {
					return err
				}
				_, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{ID: f.roleID, SpaceID: f.spaceID})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			completed := make(chan error, 1)
			var out *httptest.ResponseRecorder
			go func() {
				out = grantIdentityRequest(t, ctx, f, op)
				completed <- fmt.Errorf("HTTP status %d", out.Code)
			}()
			waitForGrantIdentityLock(t, ctx, f.store, completed)
			editorContext := authorization.WithHumanActor(roleUpdate.Context(ctx), editor.ID, "usr_role_editor")
			if _, err := f.authz.UpdateRole(editorContext, editor.ID, f.spaceID, f.roleID, "Edited concurrently", "", []string{"auth.members:read"}); err != nil {
				t.Fatal(err)
			}
			if err := roleUpdate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-completed:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if out.Code != http.StatusOK {
				t.Fatalf("role update and grant did not serialize successfully: status=%d", out.Code)
			}
		})
	}
}
