package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
)

func newSpaceCreationAuditFixture(t *testing.T, kind string) governanceAuditFixture {
	t.Helper()
	f := newGovernanceAuditFixture(t, kind, "space")
	if kind == "agent" {
		for _, id := range []string{f.parentID, f.actorID} {
			seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, id, "self:read")
		}
		issued, err := f.sessions.CreateAgentAccess(context.Background(), f.actorID, f.spaceID, security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		f.token = issued.AccessToken
		f.credentials = append(f.credentials, f.token)
	}
	return f
}

func TestSpaceCreationAuditHTTPPreservesNewSpaceAndActingChain(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newSpaceCreationAuditFixture(t, kind)
			out := applicationAuditRequest(t, f.handler, http.MethodPost, "/v1/spaces", f.token, "req_space_creation",
				map[string]string{"name": "ply_sk_private_space_label", "slug": "audit-created-space"})
			if out.Code != http.StatusOK {
				t.Fatalf("Space creation status=%d", out.Code)
			}
			var result struct{ Data createdSpaceData }
			if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil || result.Data.Space.ID == "" {
				t.Fatal("Space creation omitted its result")
			}
			created := result.Data
			tokens, err := f.sessions.CreateForMember(ctx, "usr_principal_actor", created.Member.ID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			path := "/v1/spaces/" + created.Space.ID + "/audit-logs?request_id=req_space_creation&member_id=" + f.ownerID
			page := decodeAuditPage(t, getAuditHTTP(f.handler, tokens.AccessToken, path))
			if len(page.Body.Data) != 2 {
				t.Fatalf("Space creation has %d queryable events, want 2", len(page.Body.Data))
			}
			var version int64
			if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, created.Space.ID).Scan(&version); err != nil || version != created.Space.PolicyVersion {
				t.Fatal("Space response does not contain its committed policy version")
			}
			for _, event := range page.Body.Data {
				if event.ActorType != "member" || event.ActorID != f.actorID || event.MemberID != f.actorID || event.MemberType != kind ||
					event.SpaceID != created.Space.ID || event.ResourceGroupID != "" || event.PermissionKey != "self:read" ||
					event.UserID != f.userID || event.CredentialType != f.credentialType || event.Plane != "principal" ||
					event.PolicyVersion != version || event.Outcome != "success" {
					t.Fatal("Space creation audit confuses actor and newly created resource")
				}
				var owners []string
				for _, owner := range event.OwnerChain {
					owners = append(owners, owner.MemberID)
					if owner.SpaceID != f.spaceID {
						t.Fatal("owner snapshot incorrectly uses the new Space")
					}
				}
				if !slices.Equal(owners, f.owners) {
					t.Fatal("Space audit lost the acting owner chain")
				}
				var metadata map[string]any
				if json.Unmarshal(event.Metadata, &metadata) != nil || metadata["owner_chain_complete"] != true {
					t.Fatal("invalid or incomplete audit provenance")
				}
				switch event.Action {
				case "space.create":
					if event.ResourceType != "space" || event.ResourceID != created.Space.ID || metadata["administrator_member_id"] != created.Member.ID || metadata["binding_user_id"] != "usr_principal_actor" || metadata["role_id"] == "" || metadata["grant_id"] == "" {
						t.Fatal("Space audit lost initial administrator provenance")
					}
				case "assign_right.system_create":
					if event.ResourceType != "assign_right" || metadata["holder_member_id"] != created.Member.ID || metadata["source"] != "system" {
						t.Fatal("initial assignment right has wrong provenance")
					}
					var matches bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM assign_rights WHERE id = $1 AND holder_member_id = $2 AND anchor_space_id = $3)`, event.ResourceID, created.Member.ID, created.Space.ID).Scan(&matches); err != nil || !matches {
						t.Fatal("assignment audit does not identify the committed right")
					}
				default:
					t.Fatal("unexpected Space creation event")
				}
			}
			encoded, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range append(slices.Clone(f.credentials), tokens.AccessToken, tokens.RefreshToken, "ply_sk_", "principal-actor@example.test", "test-password-hash") {
				if strings.Contains(string(encoded), private) {
					t.Fatal("Space audit exposed credentials or private labels")
				}
			}
			other := decodeAuditPage(t, getAuditHTTP(f.handler, f.ownerToken, "/v1/spaces/"+f.spaceID+"/audit-logs?request_id=req_space_creation"))
			if len(other.Body.Data) != 0 {
				t.Fatal("new Space events leaked into the actor's original Space")
			}
			if kind == "agent" {
				if err := (&agent.Service{Store: f.store}).Delete(ctx, f.ownerID, f.parentID); err != nil {
					t.Fatal(err)
				}
				if after := decodeAuditPage(t, getAuditHTTP(f.handler, tokens.AccessToken, path)); !cmp.Equal(page, after) {
					t.Fatal("Agent tombstones changed Space creation snapshots")
				}
			}
		})
	}
}

func TestSpaceCreationAuditHTTPFailureRollsBackWholeProvisioning(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, action := range []string{"assign_right.system_create", "space.create"} {
			t.Run(kind+"/"+action, func(t *testing.T) {
				t.Parallel()
				f := newSpaceCreationAuditFixture(t, kind)
				ctx := context.Background()
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_space_creation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.request_id = 'req_space_failure' AND NEW.action = '`+action+`' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$;
				CREATE TRIGGER reject_space_creation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_space_creation_audit()`); err != nil {
					t.Fatal(err)
				}
				state := func() string {
					t.Helper()
					var value string
					if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_array(
					(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM spaces s), (SELECT count(*) FROM members),
					(SELECT count(*) FROM user_members), (SELECT count(*) FROM roles), (SELECT count(*) FROM role_permissions),
					(SELECT count(*) FROM authorization_grants), (SELECT count(*) FROM assign_rights), (SELECT count(*) FROM audit_logs))::text`).Scan(&value); err != nil {
						t.Fatal(err)
					}
					return value
				}
				before := state()
				body := map[string]string{"name": "Atomic Space", "slug": "atomic-space"}
				out := applicationAuditRequest(t, f.handler, http.MethodPost, "/v1/spaces", f.token, "req_space_failure", body)
				if out.Code != http.StatusServiceUnavailable || state() != before {
					t.Fatalf("audit failure did not roll back provisioning: status=%d", out.Code)
				}
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_space_creation_audit ON audit_logs`); err != nil {
					t.Fatal(err)
				}
				if retry := applicationAuditRequest(t, f.handler, http.MethodPost, "/v1/spaces", f.token, "req_space_failure", body); retry.Code != http.StatusOK {
					t.Fatalf("retry failed: status=%d", retry.Code)
				}
				var count int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE request_id = 'req_space_failure'`).Scan(&count); err != nil || count != 2 {
					t.Fatal("retry did not commit exactly two creation events")
				}
			})
		}
	}
}

func TestSpaceCreationHTTPRechecksIdentityAndAuthorityAfterWaiting(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"binding", "account", "owner", "permission"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			kind := "human"
			if change == "owner" {
				kind = "agent"
			}
			f := newSpaceCreationAuditFixture(t, kind)
			var grantID string
			if change == "permission" {
				if err := f.store.Pool.QueryRow(ctx, `SELECT id FROM authorization_grants WHERE grantee_member_id = $1 AND role_id IS NOT NULL AND revoked_at IS NULL`, f.actorID).Scan(&grantID); err != nil {
					t.Fatal(err)
				}
			}
			barrier, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
			if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
				// Keep the change uncommitted through the HTTP preflight.
				if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: "usr_principal_actor"}); err != nil {
					return err
				}
				switch change {
				case "binding":
					return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.actorID})
				case "account":
					return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
				case "owner":
					return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
				default:
					return q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grantID})
				}
			}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/spaces", strings.NewReader(`{"name":"Denied Space","slug":"denied-space"}`)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Request-ID", "req_denied_space")
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				out := httptest.NewRecorder()
				f.handler.ServeHTTP(out, req)
				response <- out
			}()
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
					t.Fatalf("Space request did not wait for identity lock: status=%d", out.Code)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case out := <-response:
				status, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				switch change {
				case "owner":
					status, code = http.StatusForbidden, "OWNER_INACTIVE"
				case "permission":
					status, code = http.StatusForbidden, "NO_MATCHING_PERMISSION"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), code) {
					t.Fatalf("Space creation retained revoked authority: status=%d", out.Code)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var count int
			if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM spaces WHERE slug = 'denied-space') + (SELECT count(*) FROM audit_logs WHERE request_id = 'req_denied_space')`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied creation left state or success audit")
			}
		})
	}
}
