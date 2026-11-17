package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
)

func assignmentListOperation(t *testing.T, f governanceAuditFixture) memberIdentityOperation {
	t.Helper()
	if f.userID != "" {
		seedStepUpProof(t, f.store, f.sessionID, "assignment_rights.list", map[string]any{"space_id": f.spaceID})
	}
	return memberIdentityOperation{governanceAuditOperation: governanceAuditOperation{
		method: http.MethodGet, path: "/v1/spaces/" + f.spaceID + "/assign-rights",
	}}
}

func TestAssignmentRightListHTTPUsesCurrentAuthority(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, change := range []string{"active", "deprecated", "group_scope", "disabled", "principal_kind", "envelope", "token_scope", "owner_permission", "owner_inactive"} {
			if kind == "human" && slices.Contains([]string{"token_scope", "owner_permission", "owner_inactive"}, change) {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newGovernanceAuditFixture(t, kind, "group")
				op := assignmentListOperation(t, f)
				var err error
				switch change {
				case "deprecated", "disabled":
					status := change
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.assign_rights:manage'`, status)
				case "principal_kind":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["application"]' WHERE key = 'auth.assign_rights:manage'`)
				case "envelope":
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
				case "group_scope", "owner_permission":
					id := f.actorID
					if change == "owner_permission" {
						id = f.ownerID
					}
					_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, id)
					if err == nil && change == "group_scope" {
						_, err = f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
							(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
							VALUES ('grt_right_list_group', $1, '["auth.assign_rights:manage"]', $2, 'group_tree', $3, $4)`, f.spaceID, id, f.fromID, f.ownerID)
					}
				case "owner_inactive":
					err = f.store.InTx(ctx, func(q *db.Queries) error {
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					})
				case "token_scope":
					issued, issueErr := f.sessions.CreateAgentDelegatedAccess(ctx, f.actorID, f.spaceID, security.DefaultApplicationAudience, f.parentID, []string{"auth.members:read"}, 0)
					err, f.token = issueErr, issued.AccessToken
				}
				if err != nil {
					t.Fatal(err)
				}
				request := authorization.CheckRequest{MemberID: f.actorID, Permission: "auth.assign_rights:manage", ResourceSpace: f.spaceID}
				if change == "token_scope" {
					request.TokenScopes = []string{"auth.members:read"}
				}
				decision, _, err := f.authz.Check(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				out := memberIdentityRequest(t, ctx, f, op)
				if change == "active" || change == "deprecated" {
					if decision.Effect != engine.Allow || out.Code != http.StatusOK {
						t.Fatalf("active list authority denied: check=%s HTTP=%d", decision.Code, out.Code)
					}
					var response struct {
						Data []authorization.AssignmentRight `json:"data"`
					}
					if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if !slices.ContainsFunc(response.Data, func(right authorization.AssignmentRight) bool {
						return right.ID == f.right.ID && right.AnchorGroupID == f.fromID
					}) {
						t.Fatal("authorized list omitted the group-anchored assignment right")
					}
				} else if decision.Effect != engine.Deny || out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), `"code":"`+decision.Code+`"`) || strings.Contains(out.Body.String(), f.right.ID) {
					t.Fatalf("list differs from unified check or disclosed a right: check=%s HTTP=%d", decision.Code, out.Code)
				}
			})
		}
	}
}

func TestAssignmentRightListHTTPRechecksAuthorityAfterWaiting(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, change := range []string{"grant", "disabled", "binding", "expired_binding", "account", "owner", "parent", "owner_grant", "expires_after_node_wait"} {
			if kind == "human" && slices.Contains([]string{"owner", "parent", "owner_grant"}, change) || kind == "agent" && slices.Contains([]string{"binding", "expired_binding", "account", "expires_after_node_wait"}, change) {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				f := newGovernanceAuditFixture(t, kind, "group")
				op := assignmentListOperation(t, f)
				expiresAt := time.Now().UTC().Add(3 * time.Second)
				if change == "expires_after_node_wait" {
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}})
					}); err != nil {
						t.Fatal(err)
					}
				}
				barrier, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
				if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
					if change == "expires_after_node_wait" {
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
					case "owner", "parent":
						id := f.ownerID
						if change == "parent" {
							id = f.parentID
						}
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: id, SpaceID: f.spaceID, Status: "suspended"})
					case "disabled":
						return nil
					default:
						id := f.actorID
						if change == "owner_grant" {
							id = f.ownerID
						}
						grants, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: id, Valid: true}})
						if err != nil {
							return err
						}
						for _, grant := range grants {
							if err := q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grant.GrantID}); err != nil {
								return err
							}
						}
						return nil
					}
				}); err != nil {
					t.Fatal(err)
				}
				completed := make(chan error, 1)
				var out *httptest.ResponseRecorder
				go func() {
					out = memberIdentityRequest(t, ctx, f, op)
					completed <- fmt.Errorf("HTTP status %d", out.Code)
				}()
				waitForGrantIdentityLock(t, ctx, f.store, completed)
				if change == "disabled" {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.assign_rights:manage'`); err != nil {
						t.Fatal(err)
					}
				}
				if change == "expires_after_node_wait" {
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
				status, code := http.StatusForbidden, "NO_MATCHING_PERMISSION"
				switch change {
				case "binding", "expired_binding", "account", "expires_after_node_wait":
					status, code = http.StatusUnauthorized, "UNAUTHENTICATED"
				case "owner", "parent":
					code = "OWNER_INACTIVE"
				case "owner_grant":
					code = "OWNER_ENVELOPE_EXCLUDED"
				case "disabled":
					code = "PERMISSION_DISABLED"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), `"code":"`+code+`"`) || strings.Contains(out.Body.String(), f.right.ID) {
					t.Fatalf("list retained revoked %s authority or disclosed a right: status=%d want=%s", change, out.Code, code)
				}
				if kind == "human" {
					var operation pgtype.Text
					if err := f.store.Pool.QueryRow(ctx, `SELECT step_up_operation FROM sessions WHERE id = $1`, f.sessionID).Scan(&operation); err != nil {
						t.Fatal(err)
					}
					if operation.String != "assignment_rights.list" {
						t.Fatal("denied read consumed the human step-up proof")
					}
				}
			})
		}
	}
}

func TestAssignmentRightListHTTPRetainsIdentityLocksUntilCommit(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"binding", "account", "owner", "parent"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			kind := "human"
			if change == "owner" || change == "parent" {
				kind = "agent"
			}
			f := newGovernanceAuditFixture(t, kind, "group")
			op := assignmentListOperation(t, f)
			read, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = read.Rollback(context.Background()) })
			if out := memberIdentityRequest(t, read.Context(ctx), f, op); out.Code != http.StatusOK {
				t.Fatalf("valid list was denied: status=%d", out.Code)
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
					id := f.ownerID
					if change == "parent" {
						id = f.parentID
					}
					return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: id, SpaceID: f.spaceID, Status: "suspended"})
				})
			}()
			waitForGrantIdentityLock(t, ctx, f.store, writer)
			if err := read.Commit(ctx); err != nil {
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
			if out := memberIdentityRequest(t, ctx, f, op); out.Code == http.StatusOK || strings.Contains(out.Body.String(), f.right.ID) {
				t.Fatalf("next list retained revoked identity: status=%d", out.Code)
			}
		})
	}
}

func TestAssignmentRightListHTTPStepUpIsRequestBoundSingleUseAndAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newGovernanceAuditFixture(t, "human", "group")
	op := memberIdentityOperation{governanceAuditOperation: governanceAuditOperation{method: http.MethodGet, path: "/v1/spaces/" + f.spaceID + "/assign-rights"}}
	for _, proof := range []string{"missing", "wrong_space", "valid"} {
		if proof != "missing" {
			spaceID := f.spaceID
			if proof == "wrong_space" {
				spaceID = "spc_other_list_target"
			}
			seedStepUpProof(t, f.store, f.sessionID, "assignment_rights.list", map[string]any{"space_id": spaceID})
		}
		out := memberIdentityRequest(t, ctx, f, op)
		if proof == "valid" {
			if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), f.right.ID) {
				t.Fatalf("valid list proof was denied: status=%d", out.Code)
			}
		} else if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "STEP_UP_REQUIRED") || strings.Contains(out.Body.String(), f.right.ID) {
			t.Fatalf("list accepted %s proof or disclosed a right: status=%d", proof, out.Code)
		}
	}
	if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("list reused consumed proof: status=%d", out.Code)
	}
	assignmentListOperation(t, f)
	// The database enforces a nonempty array; malformed persisted elements
	// must fail closed and roll back proof consumption during response decoding.
	if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET permission_keys = '[1]' WHERE id = $1`, f.right.ID); err != nil {
		t.Fatal(err)
	}
	out := memberIdentityRequest(t, ctx, f, op)
	if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "UNAVAILABLE") || strings.Contains(out.Body.String(), `"data"`) {
		t.Fatalf("malformed stored right returned partial data: status=%d", out.Code)
	}
	permissions, err := json.Marshal(f.right.Permissions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET permission_keys = $2::jsonb WHERE id = $1`, f.right.ID, permissions); err != nil {
		t.Fatal(err)
	}
	if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), f.right.ID) {
		t.Fatalf("read failure consumed proof or prevented recovery: status=%d", out.Code)
	}
}

func TestAssignmentRightListDomainUsesIdentityAndTokenScope(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		changes := []string{"token_scope", "binding", "wrong_user"}
		if kind == "agent" {
			changes = []string{"token_scope", "owner"}
		}
		for _, change := range changes {
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newGovernanceAuditFixture(t, kind, "group")
				if kind == "human" {
					ctx = authorization.WithHumanActor(ctx, f.actorID, f.userID)
				}
				code := "UNAUTHENTICATED"
				switch change {
				case "token_scope":
					ctx = authorization.WithTokenScopes(ctx, f.actorID, []string{"auth.members:read"})
					code = "TOKEN_SCOPE_EXCLUDED"
				case "wrong_user":
					ctx = authorization.WithHumanActor(ctx, f.holderID, f.userID)
				case "binding":
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.actorID})
					}); err != nil {
						t.Fatal(err)
					}
				case "owner":
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					}); err != nil {
						t.Fatal(err)
					}
					code = "OWNER_INACTIVE"
				}
				rows, err := f.authz.ListAssignmentRights(ctx, f.actorID, f.spaceID)
				assertPrincipalError(t, err, code)
				if rows != nil {
					t.Fatal("domain denial returned assignment-right data")
				}
			})
		}
	}
}
