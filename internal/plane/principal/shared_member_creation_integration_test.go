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

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestSharedMemberCreationRequiresBindingManagementThroughHTTP(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			f, op := newMemberIdentityOperation(t, kind, "member_create_bound")
			for _, spec := range route.Specs() {
				if spec.Name == "members.create" && (spec.Permission != "auth.members:manage" || spec.ConditionalPermission != "auth.bindings:manage" || !spec.AuthoritativeCheck) {
					t.Fatal("member creation route does not declare its conditional binding authority")
				}
			}
			if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.actorID); err != nil {
				t.Fatal(err)
			}
			seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, f.actorID, "auth.members:manage")
			if out := memberIdentityRequest(t, ctx, f, op); out.Code != http.StatusOK {
				t.Fatalf("default personal member creation failed: status=%d", out.Code)
			}
			op.body.(map[string]any)["binding_policy"] = "shared"
			before := memberIdentityState(t, ctx, f)
			out := memberIdentityRequest(t, ctx, f, op)
			if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "NO_MATCHING_PERMISSION") {
				t.Fatalf("shared member creation bypassed binding authority: status=%d", out.Code)
			}
			if after := memberIdentityState(t, ctx, f); before != after {
				t.Fatal("denied shared member creation changed members, bindings, grants, audits, or proofs")
			}
			if _, err := f.authz.CreateMember(ctx, f.actorID, "", f.spaceID, "Direct shared creation", "human", "shared"); err == nil {
				t.Fatal("domain service bypassed shared member binding authority")
			} else {
				assertPrincipalError(t, err, "NO_MATCHING_PERMISSION")
			}
		})
	}
}

func TestSharedMemberCreationHTTPUsesSpaceAndCurrentBindingPolicy(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, change := range []string{"group_scope", "disabled", "principal_kind", "envelope", "members_permission", "token_scope", "owner_permission"} {
			if kind == "human" && (change == "token_scope" || change == "owner_permission") {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f, op := newMemberIdentityOperation(t, kind, "member_create_bound")
				op.body.(map[string]any)["binding_policy"] = "shared"
				var err error
				switch change {
				case "group_scope":
					_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.actorID)
					if err == nil {
						seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, f.actorID, "auth.members:manage")
						_, err = f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
							(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
							VALUES ('grt_shared_group', $1, '["auth.bindings:manage"]', $2, 'group', $3, $4)`, f.spaceID, f.actorID, f.fromID, f.ownerID)
					}
				case "disabled":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.bindings:manage'`)
				case "principal_kind":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["application"]' WHERE key = 'auth.bindings:manage'`)
				case "envelope":
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
					if err == nil {
						_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelope_entries (space_id, permission_id, mode)
							SELECT $1, id, 'delegate' FROM permissions WHERE key = 'auth.members:manage'`, f.spaceID)
					}
				case "members_permission", "owner_permission":
					target, permission := f.actorID, "auth.bindings:manage"
					if change == "owner_permission" {
						target, permission = f.ownerID, "auth.members:manage"
					}
					_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, target)
					if err == nil {
						seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, target, permission)
					}
				case "token_scope":
					issued, issueErr := f.sessions.CreateAgentDelegatedAccess(ctx, f.actorID, f.spaceID, security.DefaultApplicationAudience, f.parentID, []string{"auth.members:manage"}, 0)
					err, f.token = issueErr, issued.AccessToken
				}
				if err != nil {
					t.Fatal(err)
				}
				request := authorization.CheckRequest{MemberID: f.actorID, Permission: "auth.bindings:manage", ResourceSpace: f.spaceID}
				if change == "members_permission" {
					request.Permission = "auth.members:manage"
				}
				if change == "token_scope" {
					request.TokenScopes = []string{"auth.members:manage"}
				}
				decision, _, err := f.authz.Check(ctx, request)
				if err != nil || decision.Effect != engine.Deny || decision.Code == "APPROVAL_REQUIRED" {
					t.Fatalf("policy did not deny the expected authority: code=%s err=%v", decision.Code, err)
				}
				before := memberIdentityState(t, ctx, f)
				out := memberIdentityRequest(t, ctx, f, op)
				if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), `"code":"`+decision.Code+`"`) {
					t.Fatalf("shared creation differs from unified check: status=%d want=%s", out.Code, decision.Code)
				}
				if after := memberIdentityState(t, ctx, f); before != after {
					t.Fatal("denied shared creation changed state or created an approval")
				}
			})
		}
	}
}

func TestSharedMemberCreationHumanCanUseExistingActiveAndDeprecatedGrants(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"active", "deprecated"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			f, op := newMemberIdentityOperation(t, "human", "member_create_bound")
			op.body.(map[string]any)["binding_policy"] = "shared"
			if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.bindings:manage'`, status); err != nil {
				t.Fatal(err)
			}
			out := memberIdentityRequest(t, ctx, f, op)
			if out.Code != http.StatusOK {
				t.Fatalf("existing human binding authority denied: status=%d", out.Code)
			}
			assertSharedMemberCreated(t, f, out, true)
		})
	}
}

func approveSharedMemberCreation(t *testing.T, f governanceAuditFixture, op memberIdentityOperation) memberIdentityOperation {
	t.Helper()
	ctx := context.Background()
	out := memberIdentityRequest(t, ctx, f, op)
	var denied struct {
		Error struct {
			Code    string
			Details struct {
				ApprovalID string `json:"approval_id"`
			}
		}
	}
	if err := json.Unmarshal(out.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	if out.Code != http.StatusForbidden || denied.Error.Code != "APPROVAL_REQUIRED" || denied.Error.Details.ApprovalID == "" {
		t.Fatalf("shared creation did not require an automatic approval: status=%d code=%s", out.Code, denied.Error.Code)
	}
	op.approvalID = denied.Error.Details.ApprovalID
	var resource, operation, permission string
	if err := f.store.Pool.QueryRow(ctx, `SELECT resource_id, operation, permission_key FROM approval_requests WHERE id = $1`, op.approvalID).Scan(&resource, &operation, &permission); err != nil {
		t.Fatal(err)
	}
	if resource != f.spaceID || operation != "members.create" || permission != "auth.bindings:manage" {
		t.Fatal("shared creation approval did not bind the target Space and binding permission")
	}
	inbox := applicationAuditRequest(t, f.handler, http.MethodGet, "/v1/approvals", f.ownerToken, "req_shared_creation_inbox", nil)
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), op.approvalID) ||
		!strings.Contains(inbox.Body.String(), `"binding_policy":"shared"`) || !strings.Contains(inbox.Body.String(), f.actorID) ||
		!strings.Contains(inbox.Body.String(), f.parentID) {
		t.Fatalf("shared creation inbox omitted request or delegation details: status=%d", inbox.Code)
	}
	if pending := memberIdentityRequest(t, ctx, f, op); pending.Code != http.StatusForbidden || !strings.Contains(pending.Body.String(), "APPROVAL_PENDING") {
		t.Fatalf("pending shared creation approval accepted: status=%d", pending.Code)
	}
	seedStepUpProof(t, f.store, f.sessionID, "approvals.approve", map[string]any{"approval_id": op.approvalID})
	approved := applicationAuditRequest(t, f.handler, http.MethodPost, "/v1/approvals/"+op.approvalID+"/approve", f.ownerToken, "req_shared_creation_approve", nil)
	if approved.Code != http.StatusOK {
		t.Fatalf("shared creation approval failed: status=%d", approved.Code)
	}
	return op
}

func assertSharedMemberCreated(t *testing.T, f governanceAuditFixture, out *httptest.ResponseRecorder, bound bool) {
	t.Helper()
	var response struct {
		Data authorization.Member `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ID == "" || response.Data.BindingPolicy != "shared" || response.Data.Kind != "human" || response.Data.SpaceID != f.spaceID {
		t.Fatal("creation did not return the requested shared human member")
	}
	var members, bindings, audits int
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM members WHERE id = $1 AND binding_policy = 'shared'),
		(SELECT count(*) FROM user_members WHERE member_id = $1 AND user_id = 'usr_member_recipient'),
		(SELECT count(*) FROM audit_logs WHERE action = 'member.create' AND resource_id = $1)`, response.Data.ID).Scan(&members, &bindings, &audits); err != nil {
		t.Fatal(err)
	}
	wantBindings := 0
	if bound {
		wantBindings = 1
	}
	if members != 1 || bindings != wantBindings || audits != 1 {
		t.Fatalf("shared creation did not commit one member, expected binding and audit: members=%d bindings=%d audits=%d", members, bindings, audits)
	}
}

func TestSharedMemberCreationAgentApprovalIsRequestBoundAndAtomic(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"member_create", "member_create_bound"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f, op := newMemberIdentityOperation(t, "agent", name)
			op.body.(map[string]any)["binding_policy"] = "shared"
			op = approveSharedMemberCreation(t, f, op)
			before := memberIdentityState(t, ctx, f)
			originalName := op.body.(map[string]any)["name"]
			op.body.(map[string]any)["name"] = "Changed shared member"
			if changed := memberIdentityRequest(t, ctx, f, op); changed.Code != http.StatusForbidden || !strings.Contains(changed.Body.String(), "APPROVAL_REQUIRED") {
				t.Fatalf("approved creation accepted a different name: status=%d", changed.Code)
			}
			proofCtx := authorization.WithGovernanceApproval(ctx, op.approvalID, "members.create", f.spaceID, make([]byte, 32))
			if _, err := f.authz.CreateMember(proofCtx, f.actorID, "", f.spaceID, "Different domain request", "human", "shared"); err == nil {
				t.Fatal("domain creation trusted an approval digest supplied in context")
			} else {
				assertPrincipalError(t, err, "APPROVAL_REQUIRED")
			}
			op.body.(map[string]any)["name"] = originalName
			originalUserID, hadUserID := op.body.(map[string]any)["user_id"]
			op.body.(map[string]any)["user_id"] = "usr_principal_actor"
			if changed := memberIdentityRequest(t, ctx, f, op); changed.Code != http.StatusForbidden || !strings.Contains(changed.Body.String(), "APPROVAL_REQUIRED") {
				t.Fatalf("approved creation accepted a different initial binding: status=%d", changed.Code)
			}
			if hadUserID {
				op.body.(map[string]any)["user_id"] = originalUserID
			} else {
				delete(op.body.(map[string]any), "user_id")
			}
			if memberIdentityState(t, ctx, f) != before {
				t.Fatal("changed request consumed approval or changed state")
			}
			if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_shared_creation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.action = 'member.create' THEN RAISE EXCEPTION 'audit failed'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER reject_shared_creation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_shared_creation_audit()`); err != nil {
				t.Fatal(err)
			}
			if failed := memberIdentityRequest(t, ctx, f, op); failed.Code != http.StatusServiceUnavailable {
				t.Fatalf("audit failure did not abort shared creation: status=%d", failed.Code)
			}
			if memberIdentityState(t, ctx, f) != before {
				t.Fatal("audit failure retained a member, binding, success audit or approval consumption")
			}
			if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_shared_creation_audit ON audit_logs; DROP FUNCTION reject_shared_creation_audit()`); err != nil {
				t.Fatal(err)
			}
			results := make(chan *httptest.ResponseRecorder, 2)
			for range 2 {
				go func() { results <- memberIdentityRequest(t, ctx, f, op) }()
			}
			successes := 0
			for range 2 {
				out := <-results
				if out.Code == http.StatusOK {
					successes++
					assertSharedMemberCreated(t, f, out, name == "member_create_bound")
				} else if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "APPROVAL_REQUIRED") {
					t.Fatalf("unexpected concurrent shared creation result: status=%d", out.Code)
				}
			}
			if successes != 1 {
				t.Fatalf("one approval created %d members", successes)
			}
			if replay := memberIdentityRequest(t, ctx, f, op); replay.Code != http.StatusForbidden || !strings.Contains(replay.Body.String(), "APPROVAL_REQUIRED") {
				t.Fatalf("shared creation approval replay succeeded: status=%d", replay.Code)
			}
		})
	}
}

func TestSharedMemberCreationAgentApprovalCannotOverrideCurrentAuthority(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"owner_permission", "owner_inactive", "disabled", "approval_expired", "token_scope", "different_agent"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f, op := newMemberIdentityOperation(t, "agent", "member_create_bound")
			op.body.(map[string]any)["binding_policy"] = "shared"
			op = approveSharedMemberCreation(t, f, op)
			code := "APPROVAL_REQUIRED"
			var err error
			switch change {
			case "owner_permission":
				_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.ownerID)
				if err == nil {
					seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, f.ownerID, "auth.members:manage")
				}
				code = "OWNER_ENVELOPE_EXCLUDED"
			case "owner_inactive":
				_, err = f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.parentID)
				code = "OWNER_INACTIVE"
			case "disabled":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.bindings:manage'`)
				code = "PERMISSION_DISABLED"
			case "approval_expired":
				_, err = f.store.Pool.Exec(ctx, `UPDATE approval_requests SET approved_expires_at = now() - interval '1 second' WHERE id = $1`, op.approvalID)
			case "token_scope":
				issued, issueErr := f.sessions.CreateAgentDelegatedAccess(ctx, f.actorID, f.spaceID, security.DefaultApplicationAudience, f.parentID, []string{"auth.members:manage"}, 0)
				err, f.token = issueErr, issued.AccessToken
				code = "TOKEN_SCOPE_EXCLUDED"
			case "different_agent":
				issued, issueErr := f.sessions.CreateAgentAccess(ctx, f.parentID, f.spaceID, security.DefaultApplicationAudience)
				err, f.token = issueErr, issued.AccessToken
			}
			if err != nil {
				t.Fatal(err)
			}
			before := memberIdentityState(t, ctx, f)
			out := memberIdentityRequest(t, ctx, f, op)
			if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), `"code":"`+code+`"`) {
				t.Fatalf("approval bypassed %s: status=%d want=%s", change, out.Code, code)
			}
			if memberIdentityState(t, ctx, f) != before {
				t.Fatal("invalid approved request changed state or consumed approval")
			}
		})
	}
}

func TestSharedMemberCreationHTTPRechecksBindingAuthorityAfterWaiting(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f, op := newMemberIdentityOperation(t, kind, "member_create_bound")
			op.body.(map[string]any)["binding_policy"] = "shared"
			if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.actorID); err != nil {
				t.Fatal(err)
			}
			for _, permission := range []string{"auth.members:manage", "auth.bindings:manage"} {
				seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, f.actorID, permission)
			}
			if kind == "agent" {
				op = approveSharedMemberCreation(t, f, op)
			}
			var grantID string
			if err := f.store.Pool.QueryRow(ctx, `SELECT id FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL AND permission_keys ? 'auth.bindings:manage'`, f.actorID).Scan(&grantID); err != nil {
				t.Fatal(err)
			}
			before := memberIdentityState(t, ctx, f)
			barrier, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
			if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
				if err := member.LockChainsTx(ctx, q, f.actorID); err != nil {
					return err
				}
				return q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grantID})
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
			if err := barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case <-completed:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "NO_MATCHING_PERMISSION") {
				t.Fatalf("creation reused binding authority checked before its lock: status=%d", out.Code)
			}
			var status string
			if op.approvalID != "" {
				if err := f.store.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, op.approvalID).Scan(&status); err != nil || status != "approved" {
					t.Fatalf("revoked authority consumed approval: status=%s err=%v", status, err)
				}
			}
			if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = NULL WHERE id = $1`, grantID); err != nil {
				t.Fatal(err)
			}
			if memberIdentityState(t, ctx, f) != before {
				t.Fatal("denied request changed state or consumed an approval")
			}
		})
	}
}
