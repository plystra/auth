package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
)

func TestStandardRootPromotionHTTPReturnsConflictWithoutChangingState(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			f := newGovernanceAuditFixture(t, kind, "group")
			before := standardTreeState(t, f)
			request := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+f.spaceID+"/groups/"+f.movingID+"/move", strings.NewReader(`{"parent_group_id":""}`))
			request.Header.Set("Authorization", "Bearer "+f.token)
			request.Header.Set("Content-Type", "application/json")
			out := httptest.NewRecorder()
			f.handler.ServeHTTP(out, request)
			if out.Code != http.StatusConflict || !strings.Contains(out.Body.String(), `"code":"CONFLICT"`) || strings.Contains(out.Body.String(), "groups_standard_root_unique") {
				t.Fatalf("conflicting root promotion returned the wrong public error: status=%d", out.Code)
			}
			if standardTreeState(t, f) != before {
				t.Fatal("conflicting root promotion changed the tree, policy version, or audit")
			}
		})
	}
}

func TestGroupMoveHTTPRequiresAuthorityAtBothPositions(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, allowedPosition := range []string{"source_only", "destination_only"} {
			t.Run(kind+"/"+allowedPosition, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newGovernanceAuditFixture(t, kind, "group")
				anchor := f.fromID
				if allowedPosition == "destination_only" {
					anchor = f.toID
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.actorID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
					(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
					VALUES ('grt_move_single_position', $1, '["auth.groups:manage"]', $2, 'group_tree', $3, $4)`, f.spaceID, f.actorID, anchor, f.ownerID); err != nil {
					t.Fatal(err)
				}
				for _, target := range []string{f.movingID, f.toID} {
					decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{
						MemberID: f.actorID, Permission: "auth.groups:manage", ResourceSpace: f.spaceID, ResourceGroup: target,
					})
					want := engine.Deny
					if target == f.movingID && allowedPosition == "source_only" || target == f.toID && allowedPosition == "destination_only" {
						want = engine.Allow
					}
					if err != nil || decision.Effect != want || want == engine.Deny && decision.Code != "SCOPE_OUT_OF_BOUNDS" {
						t.Fatalf("position decision = %+v, want %s: %v", decision, want, err)
					}
				}
				before := standardTreeState(t, f)
				out := applicationAuditRequest(t, f.handler, http.MethodPost,
					"/v1/spaces/"+f.spaceID+"/groups/"+f.movingID+"/move", f.token, "req_move_single_position",
					map[string]string{"parent_group_id": f.toID})
				if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), `"code":"SCOPE_OUT_OF_BOUNDS"`) {
					t.Fatalf("single-position move returned status %d, want SCOPE_OUT_OF_BOUNDS", out.Code)
				}
				if standardTreeState(t, f) != before {
					t.Fatal("single-position move changed the tree, policy version, or audit")
				}
			})
		}
	}
}

func standardTreeState(t *testing.T, f governanceAuditFixture) string {
	t.Helper()
	var out string
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT jsonb_build_object(
		'groups', (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
		'versions', (SELECT jsonb_agg(policy_version ORDER BY id) FROM spaces),
		'audits', (SELECT count(*) FROM audit_logs))::text`).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
