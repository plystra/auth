package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
)

func TestGovernanceManagementHTTPRechecksIdentityAfterWaitingForLocks(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"group_create", "group_move", "role_create", "role_update", "right_create", "right_revoke"} {
		for _, change := range []string{"binding", "expired_binding", "account", "owner", "expires_while_waiting"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f := newGovernanceAuditFixture(t, kind, "group")
				op := f.operation(t, name)
				expiresAt := time.Now().UTC().Add(3 * time.Second)
				if change == "expires_while_waiting" {
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}})
					}); err != nil {
						t.Fatal(err)
					}
				}
				state := func() string {
					t.Helper()
					var serialized string
					if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
						'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
						'roles', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM roles r),
						'permissions', (SELECT jsonb_agg(to_jsonb(p) ORDER BY role_id, permission_id) FROM role_permissions p),
						'rights', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM assign_rights r),
						'audits', (SELECT count(*) FROM audit_logs),
						'step_up', (SELECT jsonb_build_object('operation', step_up_operation, 'digest', encode(step_up_digest, 'hex'), 'expires_at', step_up_expires_at) FROM sessions WHERE id = $1)
						)::text`, f.sessionID).Scan(&serialized); err != nil {
						t.Fatal(err)
					}
					return serialized
				}
				before := state()
				barrier, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
				if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
					if change == "expires_while_waiting" {
						switch name {
						case "role_create":
							_, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID})
							return err
						case "role_update":
							_, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{ID: f.roleID, SpaceID: f.spaceID})
							return err
						case "right_revoke":
							_, err := q.LockAssignRight(ctx, db.LockAssignRightParams{ID: f.right.ID})
							return err
						default:
							groupID := f.fromID
							if name == "group_move" {
								groupID = f.movingID
							}
							_, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: groupID, SpaceID: f.spaceID})
							return err
						}
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
				encoded, err := json.Marshal(op.body)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(op.method, op.path, strings.NewReader(string(encoded))).WithContext(ctx)
				request.Header.Set("Authorization", "Bearer "+f.token)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Request-ID", "req_governance_identity_revoked")
				response := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					out := httptest.NewRecorder()
					f.handler.ServeHTTP(out, request)
					response <- out
				}()
				for {
					var waiting bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case out := <-response:
						t.Fatalf("governance request did not reach its mutation lock: status=%d", out.Code)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if change == "expires_while_waiting" {
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
				var out *httptest.ResponseRecorder
				select {
				case out = <-response:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("governance retained revoked %s authority: status=%d", change, out.Code)
				}
				if state() != before {
					t.Fatal("denied governance changed groups, roles, assignment rights, audits, or step-up")
				}
			})
		}
	}
}

func TestGovernanceManagementHTTPRetainsIdentityLocksUntilCommit(t *testing.T) {
	for _, name := range []string{"group_create", "group_move", "role_create", "role_update", "right_create", "right_revoke"} {
		for _, change := range []string{"account", "binding", "owner"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f := newGovernanceAuditFixture(t, kind, "group")
				op := f.operation(t, name)
				mutation, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
				body, err := json.Marshal(op.body)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(op.method, op.path, strings.NewReader(string(body))).WithContext(mutation.Context(ctx))
				request.Header.Set("Authorization", "Bearer "+f.token)
				request.Header.Set("Content-Type", "application/json")
				out := httptest.NewRecorder()
				f.handler.ServeHTTP(out, request)
				if out.Code != http.StatusOK {
					t.Fatalf("active governance caller denied: status=%d", out.Code)
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
				for {
					var waiting bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case err := <-writer:
						t.Fatalf("identity revocation bypassed governance locks: %v", err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if err := mutation.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-writer; err != nil {
					t.Fatal(err)
				}
				out = applicationAuditRequest(t, f.handler, op.method, op.path, f.token, "req_governance_after_revocation", op.body)
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("next governance request retained revoked %s identity: status=%d", change, out.Code)
				}
			})
		}
	}
}

func TestGovernanceGroupMoveRetainsDescendantLocksUntilCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newGovernanceAuditFixture(t, "human", "group")
	child, err := f.authz.CreateGroup(ctx, f.actorID, f.spaceID, "Moving descendant", f.movingID)
	if err != nil {
		t.Fatal(err)
	}
	op := f.operation(t, "group_move")
	mutation, err := f.store.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
	body, err := json.Marshal(op.body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(op.method, op.path, strings.NewReader(string(body))).WithContext(mutation.Context(ctx))
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, request)
	if out.Code != http.StatusOK {
		t.Fatalf("group move failed: status=%d", out.Code)
	}
	writer := make(chan error, 1)
	go func() {
		writer <- f.store.InTx(ctx, func(q *db.Queries) error {
			return q.UpdateGroupParent(ctx, db.UpdateGroupParentParams{GroupID: child.ID, SpaceID: f.spaceID, ParentID: pgtype.Text{String: f.fromID, Valid: true}})
		})
	}()
	for {
		var waiting bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-writer:
			t.Fatalf("descendant moved outside governance's subtree locks: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := mutation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	var parentID string
	if err := f.store.Pool.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id = $1`, child.ID).Scan(&parentID); err != nil {
		t.Fatal(err)
	}
	if parentID != f.fromID {
		t.Fatal("descendant move did not commit after the governing move")
	}
}
