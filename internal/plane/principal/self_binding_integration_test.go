package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func newSelfBindingFixture(t *testing.T) groupRemovalFixture {
	t.Helper()
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `DELETE FROM group_members WHERE group_id = 'grp_remove_b' AND member_id = $1`, f.target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_self_unbind', $2, '["self:read"]', $1, 'group', 'grp_remove_a', $3)`,
		f.target.ID, f.spaceID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	tokens, err := f.sessions.CreateForMember(ctx, "usr_principal_actor", f.target.ID, nil, "self-unbind", 1)
	if err != nil {
		t.Fatal(err)
	}
	f.token = tokens.AccessToken
	return f
}

func TestHumanSelfUnbindingHTTPUsesActualGroupTarget(t *testing.T) {
	ctx := context.Background()
	f := newSelfBindingFixture(t)
	decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "self:read",
		ResourceSpace: f.spaceID, ResourceGroup: "grp_remove_a", ResourceOwner: f.target.ID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("expected current group authority: decision=%s error=%v", decision.Code, err)
	}
	response := removeOwnBinding(ctx, f)
	if response.Code != http.StatusOK {
		t.Fatalf("self-unbinding disagrees with the actual group decision: status=%d", response.Code)
	}
}

func removeOwnBinding(ctx context.Context, f groupRemovalFixture) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/me/member", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+f.token)
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, req)
	return response
}

func TestHumanSelfUnbindingHTTPMatchesCheckForTargetAndPolicy(t *testing.T) {
	for _, policy := range []string{"self", "outside_group", "multiple_groups", "disabled", "deprecated", "principal_kinds", "envelope"} {
		t.Run(policy, func(t *testing.T) {
			ctx := context.Background()
			f := newSelfBindingFixture(t)
			var err error
			groupID := "grp_remove_a"
			switch policy {
			case "self":
				_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'self', anchor_group_id = NULL, anchor_space_id = $1 WHERE id = 'grt_self_unbind'`, f.spaceID)
			case "outside_group":
				_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET anchor_group_id = 'grp_remove_b' WHERE id = 'grt_self_unbind'`)
			case "multiple_groups":
				groupID = ""
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id) VALUES ('grp_remove_b', $1)`, f.target.ID)
			case "disabled", "deprecated":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'self:read'`, policy)
			case "principal_kinds":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["agent"]' WHERE key = 'self:read'`)
			case "envelope":
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
			}
			if err != nil {
				t.Fatal(err)
			}
			decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "self:read", ResourceSpace: f.spaceID, ResourceGroup: groupID, ResourceOwner: f.target.ID})
			if err != nil {
				t.Fatal(err)
			}
			wantAllow := policy == "self" || policy == "deprecated"
			if (decision.Effect == engine.Allow) != wantAllow {
				t.Fatalf("unexpected policy decision: %s", decision.Code)
			}
			response := removeOwnBinding(ctx, f)
			if wantAllow {
				if response.Code != http.StatusOK {
					t.Fatalf("allowed unbinding failed: status=%d", response.Code)
				}
			} else {
				if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), decision.Code) {
					t.Fatalf("unbinding differs from check: check=%s status=%d", decision.Code, response.Code)
				}
				assertSelfBindingUnchanged(t, f, "active")
			}
		})
	}
}

func TestHumanSelfUnbindingHTTPRechecksAfterWaitingForLocks(t *testing.T) {
	for _, change := range []string{"permission", "position", "member", "binding", "expired_binding", "account"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f := newSelfBindingFixture(t)
			locked, release := make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			go func() {
				writer <- f.store.InTx(ctx, func(q *db.Queries) error {
					if change == "account" {
						if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: "usr_principal_actor"}); err != nil {
							return err
						}
					} else if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.target.ID}); err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					switch change {
					case "permission":
						return q.RevokeGrant(ctx, db.RevokeGrantParams{ID: "grt_self_unbind"})
					case "position":
						if err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: "grp_remove_a", MemberID: f.target.ID, SpaceID: f.spaceID}); err != nil {
							return err
						}
						return q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: "grp_remove_b", MemberID: f.target.ID, SpaceID: f.spaceID, Source: "manual"})
					case "member":
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.target.ID, SpaceID: f.spaceID, Status: "suspended"})
					case "binding":
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: "usr_principal_actor", MemberID: f.target.ID})
					case "expired_binding":
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: "usr_principal_actor", MemberID: f.target.ID, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}})
					default:
						return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: "usr_principal_actor", Status: "disabled"})
					}
				})
			}()
			select {
			case <-locked:
			case err := <-writer:
				t.Fatalf("could not establish revocation barrier: %v", err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- removeOwnBinding(ctx, f) }()
			for {
				var waiting bool
				if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case out := <-response:
					t.Fatalf("unbinding did not wait for current authority: status=%d", out.Code)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			out := <-response
			if change == "account" || change == "binding" || change == "expired_binding" {
				if out.Code != http.StatusUnauthorized || !strings.Contains(out.Body.String(), "UNAUTHENTICATED") {
					t.Fatalf("unbinding retained inactive account or binding: status=%d", out.Code)
				}
			} else {
				groupID := "grp_remove_a"
				if change == "position" {
					groupID = "grp_remove_b"
				}
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "self:read", ResourceSpace: f.spaceID, ResourceGroup: groupID, ResourceOwner: f.target.ID})
				if err != nil || decision.Effect != engine.Deny || out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), decision.Code) {
					t.Fatalf("unbinding used obsolete authority: check=%s error=%v status=%d", decision.Code, err, out.Code)
				}
			}
			wantBinding := "active"
			if change == "binding" {
				wantBinding = "revoked"
			}
			assertSelfBindingUnchanged(t, f, wantBinding)
		})
	}
}

func assertSelfBindingUnchanged(t *testing.T, f groupRemovalFixture, wantStatus string) {
	t.Helper()
	var status string
	var mutations int
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT status,
		(SELECT count(*) FROM audit_logs WHERE action IN ('member.binding.self_revoke', 'agent.binding.suspend'))
		FROM user_members WHERE user_id = 'usr_principal_actor' AND member_id = $1`, f.target.ID).Scan(&status, &mutations); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || mutations != 0 {
		t.Fatalf("denied unbinding changed state: binding=%s want=%s mutation_audits=%d", status, wantStatus, mutations)
	}
}
