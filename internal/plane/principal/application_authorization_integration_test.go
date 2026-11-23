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
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
)

func TestApplicationManagementHTTPRechecksIdentityAfterWaitingForLocks(t *testing.T) {
	for _, operation := range []string{"register", "update", "oauth_secret_rotate", "key_list", "key_create", "key_grants", "key_rotate", "key_revoke", "install", "approve", "suspend", "resume", "uninstall"} {
		for _, change := range []string{"binding", "account", "owner"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				st, authz, apps, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
				if operation == "oauth_secret_rotate" {
					client, err := apps.Register(ctx, ownerID, application.RegisterInput{SpaceID: spaceID, Name: "Confidential",
						RedirectURIs: []string{"https://rp.example.test/login"}, ManifestPermissions: []string{"auth.authz:check", "auth.tokens:introspect"}, TokenEndpointAuthMethod: "client_secret_basic"})
					if err != nil {
						t.Fatal(err)
					}
					appID = client.ID
				}
				key, _, err := apps.CreateManagedKey(ctx, ownerID, appID, application.CreateManagedKeyInput{
					Name: "Original server", Grants: []string{"auth.authz:check", "auth.tokens:introspect"}, ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatal(err)
				}
				var installed application.Installation
				if operation == "approve" || operation == "suspend" || operation == "resume" || operation == "uninstall" {
					installed, err = apps.InstallSpace(ctx, ownerID, appID, spaceID)
					if err != nil {
						t.Fatal(err)
					}
					if operation == "resume" {
						if _, err := apps.ChangeInstallationStatus(ctx, ownerID, spaceID, installed.ID, "suspend"); err != nil {
							t.Fatal(err)
						}
					}
				}
				tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", ownerID, nil, "test", 1)
				if err != nil {
					t.Fatal(err)
				}
				actorID, token := ownerID, tokens.AccessToken
				if change == "owner" {
					agents := &agent.Service{Store: st}
					created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "Application manager", ExpiresAt: time.Now().Add(time.Hour)})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := authz.ReplaceAgentGrants(ctx, ownerID, spaceID, created.ID, []string{"auth.applications:manage"}, "space", spaceID); err != nil {
						t.Fatal(err)
					}
					issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
					if err != nil {
						t.Fatal(err)
					}
					actorID, token = created.ID, issued.AccessToken
				}
				method, path := http.MethodPost, "/v1/applications/"+appID
				var body any
				proof := func(operation string, request any) {
					t.Helper()
					if change != "owner" {
						seedStepUpProof(t, st, tokens.SessionID, operation, request)
					}
				}
				switch operation {
				case "register":
					path = "/v1/spaces/" + spaceID + "/applications"
					manifest := []string{"auth.authz:check"}
					body = map[string]any{"name": "Forbidden publisher", "manifest_permissions": manifest}
					proof("applications.register", map[string]any{"space_id": spaceID, "name": "Forbidden publisher", "manifest_permissions": manifest, "redirect_uris": []string(nil)})
				case "update":
					method, body = http.MethodPatch, map[string]any{"name": "Forbidden publisher"}
				case "oauth_secret_rotate":
					path, body = path+"/oauth-client-secret/rotate", map[string]any{"grace_period_seconds": 0}
					proof(application.RotateOAuthSecretOperation, map[string]any{"application_id": appID, "grace_period_seconds": 0})
				case "key_list":
					method, path = http.MethodGet, path+"/api-keys"
				case "key_create":
					path += "/api-keys"
					expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
					body = map[string]any{"name": "Forbidden server", "grants": []string{"auth.authz:check"}, "expires_at": expiresAt}
					proof("applications.keys.create", map[string]any{"application_id": appID, "name": "Forbidden server", "grants": []string{"auth.authz:check"}, "expires_at": expiresAt, "restrict_to": []application.KeyRestriction(nil), "allow_subject_assertion": false})
				case "key_grants":
					method, path, body = http.MethodPut, path+"/api-keys/"+key.ID+"/grants", map[string]any{"grants": []string{"auth.authz:check"}}
				case "key_rotate":
					path += "/api-keys/" + key.ID + "/rotate"
					proof("applications.keys.rotate", map[string]any{"application_id": appID, "key_id": key.ID})
				case "key_revoke":
					path += "/api-keys/" + key.ID + "/revoke"
				case "install":
					path, body = "/v1/spaces/"+spaceID+"/installations", map[string]any{"application_id": appID}
					proof("installations.create", map[string]any{"space_id": spaceID, "application_id": appID, "scope": "space"})
				case "approve":
					method, path, body = http.MethodPut, "/v1/spaces/"+spaceID+"/installations/"+installed.ID+"/approvals", map[string]any{}
				default:
					path = "/v1/spaces/" + spaceID + "/installations/" + installed.ID + "/" + operation
				}
				state := func() string {
					t.Helper()
					var out string
					if err := st.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
						'applications', (SELECT jsonb_agg(jsonb_build_object('id', id, 'name', name, 'manifest', manifest_permissions,
							'oauth_digest', oauth_client_secret_hash, 'previous_digest', oauth_previous_secret_hash, 'expires', oauth_previous_secret_expires_at) ORDER BY id) FROM applications),
						'keys', (SELECT jsonb_agg(jsonb_build_object('id', id, 'scopes', scopes, 'hash', encode(secret_hash, 'hex'), 'revoked_at', revoked_at) ORDER BY id) FROM api_keys),
						'grace', (SELECT jsonb_agg(to_jsonb(g) ORDER BY key_id, secret_hash) FROM api_key_grace_secrets g),
						'installations', (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM application_installations i),
						'audits', (SELECT count(*) FROM audit_logs),
						'step_up', (SELECT jsonb_build_object('operation', step_up_operation, 'digest', encode(step_up_digest, 'hex'), 'expires_at', step_up_expires_at) FROM sessions WHERE id = $1)
						)::text`, tokens.SessionID).Scan(&out); err != nil {
						t.Fatal(err)
					}
					return out
				}
				before := state()
				mutation, err := st.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
				if err := st.InTx(mutation.Context(ctx), func(q *db.Queries) error {
					if operation == "register" {
						if _, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: spaceID}); err != nil {
							return err
						}
					} else if _, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: appID}); err != nil {
						return err
					}
					if err := member.LockChainsTx(ctx, q, actorID); err != nil {
						return err
					}
					switch change {
					case "binding":
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: "usr_principal_actor", MemberID: ownerID})
					case "account":
						return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: "usr_principal_actor", Status: "disabled"})
					default:
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: ownerID, SpaceID: spaceID, Status: "suspended"})
					}
				}); err != nil {
					t.Fatal(err)
				}
				var encoded []byte
				if body != nil {
					encoded, err = json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
				}
				request := httptest.NewRequest(method, path, strings.NewReader(string(encoded))).WithContext(ctx)
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Request-ID", "req_application_revoked")
				response := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					out := httptest.NewRecorder()
					handler.ServeHTTP(out, request)
					response <- out
				}()
				for {
					var waiting bool
					if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case out := <-response:
						t.Fatalf("request did not reach a mutation barrier: status=%d", out.Code)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if err := mutation.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				var out *httptest.ResponseRecorder
				select {
				case out = <-response:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				want, code := http.StatusUnauthorized, "UNAUTHENTICATED"
				if change == "owner" {
					want, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != want || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), `"secret"`) {
					t.Fatalf("management retained revoked %s authority: status=%d", change, out.Code)
				}
				if state() != before {
					t.Fatal("denied application management changed state, credentials, audit, or step-up")
				}
			})
		}
	}
}
