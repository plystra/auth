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

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
)

var memberIdentityOperations = []string{
	"member_create", "member_create_bound", "member_policy", "member_suspend", "member_resume", "member_remove",
	"binding_create", "binding_revoke", "bindings_list", "members_list", "group_members_list", "roles_list",
}

type memberIdentityOperation struct {
	governanceAuditOperation
	approvalID string
}

func newMemberIdentityOperation(t *testing.T, kind, name string) (governanceAuditFixture, memberIdentityOperation) {
	t.Helper()
	ctx := context.Background()
	f := newGovernanceAuditFixture(t, kind, "group")
	if kind == "agent" {
		for _, id := range []string{f.parentID, f.actorID} {
			for _, permission := range []string{"auth.members:manage", "auth.bindings:manage", "auth.grants:assign", "auth.assign_rights:manage"} {
				seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, id, permission)
			}
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_member_recipient', 'member-recipient@example.test', 'member-recipient@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	if err := f.authz.AddMemberToGroup(ctx, f.ownerID, f.spaceID, f.fromID, f.holderID); err != nil {
		t.Fatal(err)
	}
	if name == "binding_revoke" || name == "bindings_list" {
		if err := f.authz.BindUser(ctx, f.ownerID, f.spaceID, f.holderID, "usr_member_recipient"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.sessions.CreateForMember(ctx, "usr_member_recipient", f.holderID, nil, "test", 1); err != nil {
			t.Fatal(err)
		}
	}
	if name == "member_resume" {
		if err := f.authz.SetMemberStatus(ctx, f.ownerID, f.spaceID, f.holderID, "suspended"); err != nil {
			t.Fatal(err)
		}
	}
	base := "/v1/spaces/" + f.spaceID
	target := base + "/members/" + f.holderID
	op := memberIdentityOperation{governanceAuditOperation: governanceAuditOperation{method: http.MethodGet, groupID: f.fromID}}
	switch name {
	case "member_create", "member_create_bound":
		op.method, op.path, op.groupID = http.MethodPost, base+"/members", ""
		op.body = map[string]any{"name": "New managed member", "type": "human", "binding_policy": "single"}
		if name == "member_create_bound" {
			op.body.(map[string]any)["user_id"] = "usr_member_recipient"
		}
	case "member_policy":
		op.method, op.path = http.MethodPatch, target
		op.body = map[string]any{"binding_policy": "shared"}
	case "member_suspend", "member_resume", "member_remove":
		op.method, op.path = http.MethodPost, target+"/"+strings.TrimPrefix(name, "member_")
	case "binding_create":
		op.method, op.path, op.action = http.MethodPost, target+"/users", "members.bindings.create"
		op.body = map[string]any{"user_id": "usr_member_recipient"}
	case "binding_revoke":
		op.method, op.path, op.action = http.MethodDelete, target+"/users/usr_member_recipient", "members.bindings.revoke"
	case "bindings_list":
		op.path = target + "/users"
	case "members_list":
		op.path, op.groupID = base+"/members", ""
	case "group_members_list":
		op.path = base + "/groups/" + f.fromID + "/members"
	case "roles_list":
		op.path, op.groupID = base+"/roles", ""
	default:
		t.Fatalf("unknown member identity operation %q", name)
	}
	approvals := &approval.Service{Store: f.store, Authorization: f.authz, StepUp: f.sessions}
	mux := http.NewServeMux()
	(&API{Authorization: f.authz, Sessions: f.sessions, Agents: &agent.Service{Store: f.store}, Approvals: approvals}).Register(humago.New(mux, route.HumaConfig("member identity test", "1.0.0")))
	f.handler = route.Middleware(route.Principal, mux)
	if kind == "human" && op.action != "" {
		seedStepUpProof(t, f.store, f.sessionID, op.action, map[string]any{"space_id": f.spaceID, "member_id": f.holderID, "user_id": "usr_member_recipient"})
	}
	if kind == "agent" && (name == "member_policy" || strings.HasPrefix(name, "binding_")) {
		initial := memberIdentityRequest(t, ctx, f, op)
		var denied struct {
			Error struct {
				Code    string
				Details struct {
					ApprovalID string `json:"approval_id"`
				}
			}
		}
		if err := json.Unmarshal(initial.Body.Bytes(), &denied); err != nil {
			t.Fatal(err)
		}
		if initial.Code != http.StatusForbidden || denied.Error.Code != "APPROVAL_REQUIRED" || denied.Error.Details.ApprovalID == "" {
			t.Fatalf("Agent management did not require approval: status=%d code=%s", initial.Code, denied.Error.Code)
		}
		op.approvalID = denied.Error.Details.ApprovalID
		seedStepUpProof(t, f.store, f.sessionID, "approvals.approve", map[string]any{"approval_id": op.approvalID})
		approved := applicationAuditRequest(t, f.handler, http.MethodPost, "/v1/approvals/"+op.approvalID+"/approve", f.ownerToken, "req_member_identity_approve", nil)
		if approved.Code != http.StatusOK {
			t.Fatalf("Agent management approval failed: status=%d", approved.Code)
		}
	}
	return f, op
}

func memberIdentityRequest(t *testing.T, ctx context.Context, f governanceAuditFixture, op memberIdentityOperation) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if op.body != nil {
		var err error
		encoded, err = json.Marshal(op.body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(op.method, op.path, strings.NewReader(string(encoded))).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "req_member_identity")
	if op.approvalID != "" {
		request.Header.Set("Approval-Id", op.approvalID)
	}
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, request)
	return out
}

func memberIdentityState(t *testing.T, ctx context.Context, f governanceAuditFixture) string {
	t.Helper()
	var serialized string
	if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
		'members', (SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM members m WHERE id <> ALL($1::text[])),
		'bindings', (SELECT jsonb_agg(to_jsonb(b) ORDER BY user_id, member_id) FROM user_members b WHERE member_id <> $2),
		'grants', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM authorization_grants g),
		'recipient_sessions', (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM sessions s WHERE user_id = 'usr_member_recipient'),
		'recipient_refreshes', (SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE s.user_id = 'usr_member_recipient'),
		'approvals', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM approval_requests a),
		'audits', (SELECT count(*) FROM audit_logs),
		'step_up', (SELECT jsonb_build_object('operation', step_up_operation, 'digest', encode(step_up_digest, 'hex'), 'expires_at', step_up_expires_at) FROM sessions WHERE id = $3)
		)::text`, []string{f.ownerID, f.actorID, f.parentID}, f.actorID, f.sessionID).Scan(&serialized); err != nil {
		t.Fatal(err)
	}
	return serialized
}

func TestMemberManagementHTTPRechecksIdentityAfterWaitingForLocks(t *testing.T) {
	t.Parallel()
	for _, name := range memberIdentityOperations {
		for _, change := range []string{"binding", "expired_binding", "account", "owner", "expires_while_waiting", "expires_after_group_wait"} {
			if change == "expires_after_group_wait" && (name == "member_create" || name == "member_create_bound" || name == "members_list" || name == "roles_list") {
				continue
			}
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f, op := newMemberIdentityOperation(t, kind, name)
				expiresAt := time.Now().UTC().Add(3 * time.Second)
				waitingForExpiry := strings.HasPrefix(change, "expires_")
				if waitingForExpiry {
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}})
					}); err != nil {
						t.Fatal(err)
					}
				}
				before := memberIdentityState(t, ctx, f)
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
					out = memberIdentityRequest(t, ctx, f, op)
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
					t.Fatalf("member management retained revoked %s identity: status=%d", change, out.Code)
				}
				if memberIdentityState(t, ctx, f) != before {
					t.Fatal("denied member management changed target members, bindings, grants, approvals, audits, or step-up")
				}
			})
		}
	}
}

func TestMemberManagementHTTPRetainsIdentityLocksUntilCommit(t *testing.T) {
	for _, name := range memberIdentityOperations {
		for _, change := range []string{"account", "binding", "owner"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" {
					kind = "agent"
				}
				f, op := newMemberIdentityOperation(t, kind, name)
				mutation, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
				out := memberIdentityRequest(t, mutation.Context(ctx), f, op)
				if out.Code != http.StatusOK {
					var response struct {
						Error struct{ Code string }
					}
					if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					t.Fatalf("active member manager denied: status=%d code=%s", out.Code, response.Error.Code)
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
				out = memberIdentityRequest(t, ctx, f, op)
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("next member management request retained revoked %s identity: status=%d", change, out.Code)
				}
			})
		}
	}
}

func TestMemberManagementHTTPAuditFailureRollsBackStateAndProof(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, name := range memberIdentityOperations {
			if strings.HasSuffix(name, "_list") {
				continue
			}
			t.Run(kind+"/"+name, func(t *testing.T) {
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, name)
				before := memberIdentityState(t, ctx, f)
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_member_identity_audit() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN RAISE EXCEPTION 'member audit unavailable'; END; $$;
					CREATE TRIGGER reject_member_identity_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_member_identity_audit()`); err != nil {
					t.Fatal(err)
				}
				out := memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "UNAVAILABLE") {
					t.Fatalf("member management ignored audit failure: status=%d", out.Code)
				}
				if memberIdentityState(t, ctx, f) != before {
					t.Fatal("audit failure changed member, binding, session, approval, audit, or step-up state")
				}
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_member_identity_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				out = memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusOK {
					t.Fatalf("member management could not retry after audit recovery: status=%d", out.Code)
				}
			})
		}
	}
}
