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

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func applicationAuditRequest(t *testing.T, handler http.Handler, method, path, token, requestID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", requestID)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func TestApplicationCredentialAuditHTTPPreservesPublisherAndActorChains(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			st, authz, apps, ownerID, spaceID, sessions, _, _ := installationFixture(t, []string{"auth.authz:check"})
			agents := &agent.Service{Store: st, StepUp: sessions}
			mux := http.NewServeMux()
			(&API{Authorization: authz, Applications: apps, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("application audit test", "1.0.0")))
			handler := route.Middleware(route.Principal, mux)
			ownerToken, err := sessions.CreateForMember(ctx, "usr_principal_actor", ownerID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			actorID, token, userID, credentialType := ownerID, ownerToken.AccessToken, "usr_principal_actor", "user_access_token"
			var owners []string
			var parentID string
			credentials := []string{ownerToken.AccessToken, ownerToken.RefreshToken}
			if kind == "agent" {
				parent, parentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, CreatedByUser: "usr_principal_actor", Name: "Application audit parent", ExpiresAt: time.Now().Add(time.Hour)})
				if err != nil {
					t.Fatal(err)
				}
				parentID = parent.ID
				if _, err := authz.ReplaceAgentGrants(ctx, ownerID, spaceID, parent.ID, []string{"auth.applications:manage"}, "space", spaceID); err != nil {
					t.Fatal(err)
				}
				child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, CreatedByUser: "usr_principal_actor", Name: "Application audit child", ExpiresAt: parent.ExpiresAt.Add(-time.Minute)})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := authz.ReplaceAgentGrants(ctx, parent.ID, spaceID, child.ID, []string{"auth.applications:manage"}, "space", spaceID); err != nil {
					t.Fatal(err)
				}
				issued, err := sessions.CreateAgentAccess(ctx, child.ID, spaceID, security.DefaultApplicationAudience)
				if err != nil {
					t.Fatal(err)
				}
				actorID, token, userID, credentialType = child.ID, issued.AccessToken, "", "agent_access_token"
				owners = []string{parent.ID, ownerID}
				credentials = append(credentials, token, parentKey, childKey)
			}
			request := func(method, path, requestID string, body any) *httptest.ResponseRecorder {
				t.Helper()
				out := applicationAuditRequest(t, handler, method, path, token, requestID, body)
				if out.Code != http.StatusOK {
					t.Fatalf("application lifecycle request %s returned %d", requestID, out.Code)
				}
				return out
			}
			proof := func(operation string, value any) {
				t.Helper()
				if kind == "human" {
					seedStepUpProof(t, st, ownerToken.SessionID, operation, value)
				}
			}
			manifest := []string{"auth.authz:check", "auth.tokens:introspect"}
			proof("applications.register", map[string]any{"space_id": spaceID, "name": "Audited SaaS", "redirect_uris": []string(nil), "manifest_permissions": manifest})
			out := request(http.MethodPost, "/v1/spaces/"+spaceID+"/applications", "req_app_audit_register", map[string]any{"name": "Audited SaaS", "manifest_permissions": manifest})
			var registered struct {
				Data application.PublishedApplication `json:"data"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &registered); err != nil {
				t.Fatal(err)
			}
			appID := registered.Data.ID
			path := "/v1/applications/" + appID
			request(http.MethodPatch, path, "req_app_audit_update", map[string]any{"name": "Updated audited SaaS"})
			expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			proof("applications.keys.create", map[string]any{"application_id": appID, "name": "Audited server", "grants": manifest, "restrict_to": []application.KeyRestriction(nil), "expires_at": expiresAt, "allow_subject_assertion": false})
			out = request(http.MethodPost, path+"/api-keys", "req_app_audit_key_create", map[string]any{"name": "Audited server", "grants": manifest, "expires_at": expiresAt})
			var created struct {
				Data applicationKeyCreation `json:"data"`
			}
			if err := json.Unmarshal(out.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			keyID := created.Data.Key.ID
			credentials = append(credentials, created.Data.Secret.Value())
			keyPath := path + "/api-keys/" + keyID
			request(http.MethodPut, keyPath+"/grants", "req_app_audit_key_grants", map[string]any{"grants": []string{"auth.authz:check"}})
			proof("applications.keys.rotate", map[string]any{"application_id": appID, "key_id": keyID})
			out = request(http.MethodPost, keyPath+"/rotate", "req_app_audit_key_rotate", nil)
			if err := json.Unmarshal(out.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			credentials = append(credentials, created.Data.Secret.Value())
			request(http.MethodPost, keyPath+"/revoke", "req_app_audit_key_revoke", nil)
			auditPath := "/v1/spaces/" + spaceID + "/audit-logs"
			var snapshots []audit.Event
			for _, item := range []struct{ requestID, action, resourceType, resourceID string }{
				{"req_app_audit_register", "application.register", "application", appID},
				{"req_app_audit_update", "application.update", "application", appID},
				{"req_app_audit_key_create", "application.key.create", "api_key", keyID},
				{"req_app_audit_key_grants", "application.key.grants.replace", "api_key", keyID},
				{"req_app_audit_key_rotate", "application.key.rotate", "api_key", keyID},
				{"req_app_audit_key_revoke", "application.key.revoke", "api_key", keyID},
			} {
				response := getAuditHTTP(handler, ownerToken.AccessToken, auditPath+"?request_id="+item.requestID+"&member_id="+ownerID)
				page := decodeAuditPage(t, response)
				if len(page.Body.Data) != 1 {
					t.Fatalf("request %s has %d queryable audit records, want one", item.requestID, len(page.Body.Data))
				}
				event := page.Body.Data[0]
				if event.ActorType != "member" || event.ActorID != actorID || event.MemberID != actorID || event.MemberType != kind || event.UserID != userID || event.CredentialType != credentialType || event.Plane != "principal" || event.ApplicationID != appID || event.ResourceType != item.resourceType || event.ResourceID != item.resourceID || event.SpaceID != spaceID || event.ResourceGroupID != "" || event.Action != item.action || event.PermissionKey != "auth.applications:manage" || event.Outcome != "success" {
					t.Fatalf("request %s has an incorrect application audit snapshot", item.requestID)
				}
				var chain []string
				for _, owner := range event.OwnerChain {
					chain = append(chain, owner.MemberID)
				}
				if !slices.Equal(chain, owners) || !strings.Contains(string(event.Metadata), `"owner_chain_complete":true`) {
					t.Fatalf("request %s has an incomplete owner chain", item.requestID)
				}
				for _, credential := range credentials {
					if credential == "" || strings.Contains(response.Body.String(), credential) {
						t.Fatal("application audit exposed a credential or the test omitted a credential")
					}
				}
				snapshots = append(snapshots, event)
			}
			group, err := authz.CreateGroup(ctx, ownerID, spaceID, "Audit reader group", "")
			if err != nil {
				t.Fatal(err)
			}
			reader, err := authz.CreateMember(ctx, ownerID, "usr_principal_actor", spaceID, "Scoped audit reader", "human", "single")
			if err != nil {
				t.Fatal(err)
			}
			seedAuditGroupReader(t, st, spaceID, ownerID, reader.ID, group.ID)
			readerToken, err := sessions.CreateForMember(ctx, "usr_principal_actor", reader.ID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			page := decodeAuditPage(t, getAuditHTTP(handler, readerToken.AccessToken, auditPath+"?request_id=req_app_audit_key_revoke"))
			if len(page.Body.Data) != 0 {
				t.Fatal("group-only audit reader saw a publisher Space event")
			}
			otherSpace, otherOwner, err := authz.CreateSpace(ctx, "usr_principal_actor", "Other audit publisher", "other-audit-publisher")
			if err != nil {
				t.Fatal(err)
			}
			otherToken, err := sessions.CreateForMember(ctx, "usr_principal_actor", otherOwner.ID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			page = decodeAuditPage(t, getAuditHTTP(handler, otherToken.AccessToken, "/v1/spaces/"+otherSpace.ID+"/audit-logs?request_id=req_app_audit_key_revoke"))
			if len(page.Body.Data) != 0 {
				t.Fatal("another Space saw the publisher's credential audit")
			}
			if parentID != "" {
				if err := agents.Delete(ctx, ownerID, parentID); err != nil {
					t.Fatal(err)
				}
				for _, snapshot := range snapshots {
					page := decodeAuditPage(t, getAuditHTTP(handler, ownerToken.AccessToken, auditPath+"?request_id="+snapshot.RequestID))
					if len(page.Body.Data) != 1 || !cmp.Equal(snapshot, page.Body.Data[0]) {
						t.Fatal("Agent tombstones changed a historical application audit snapshot")
					}
				}
			}
		})
	}
}

func TestApplicationCredentialAuditHTTPFailureRollsBackStateAndStepUp(t *testing.T) {
	for _, operation := range []string{"register", "update", "key_create", "key_grants", "key_rotate", "key_revoke"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
			key, raw, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
				Name: "Original server", Grants: []string{"auth.authz:check", "auth.tokens:introspect"}, ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			method, path, action := http.MethodPost, "/v1/applications/"+appID, ""
			var body any
			switch operation {
			case "register":
				path, action = "/v1/spaces/"+spaceID+"/applications", "application.register"
				manifest := []string{"auth.authz:check"}
				body = map[string]any{"name": "Additional publisher", "manifest_permissions": manifest}
				seedStepUpProof(t, st, tokens.SessionID, "applications.register", map[string]any{
					"space_id": spaceID, "name": "Additional publisher", "redirect_uris": []string(nil), "manifest_permissions": manifest,
				})
			case "update":
				method, action, body = http.MethodPatch, "application.update", map[string]any{"name": "Changed publisher"}
			case "key_create":
				path, action = path+"/api-keys", "application.key.create"
				expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
				body = map[string]any{"name": "Additional server", "grants": []string{"auth.authz:check"}, "expires_at": expiresAt}
				seedStepUpProof(t, st, tokens.SessionID, "applications.keys.create", map[string]any{
					"application_id": appID, "name": "Additional server", "grants": []string{"auth.authz:check"},
					"restrict_to": []application.KeyRestriction(nil), "expires_at": expiresAt, "allow_subject_assertion": false,
				})
			case "key_grants":
				method, path, action = http.MethodPut, path+"/api-keys/"+key.ID+"/grants", "application.key.grants.replace"
				body = map[string]any{"grants": []string{"auth.authz:check"}}
			case "key_rotate":
				path, action = path+"/api-keys/"+key.ID+"/rotate", "application.key.rotate"
				seedStepUpProof(t, st, tokens.SessionID, "applications.keys.rotate", map[string]any{"application_id": appID, "key_id": key.ID})
			case "key_revoke":
				path, action = path+"/api-keys/"+key.ID+"/revoke", "application.key.revoke"
			}
			if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_application_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.request_id = 'req_app_audit_failure' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER reject_application_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_application_audit()`); err != nil {
				t.Fatal(err)
			}
			state := func() string {
				t.Helper()
				var serialized string
				if err := st.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
					'applications', (SELECT jsonb_agg(jsonb_build_object('id', id, 'name', name, 'manifest', manifest_permissions) ORDER BY id) FROM applications),
					'keys', (SELECT jsonb_agg(jsonb_build_object('id', id, 'scopes', scopes, 'hash', encode(secret_hash, 'hex'), 'revoked_at', revoked_at) ORDER BY id) FROM api_keys),
					'grace', (SELECT jsonb_agg(to_jsonb(g) ORDER BY key_id, secret_hash) FROM api_key_grace_secrets g),
					'audits', (SELECT count(*) FROM audit_logs),
					'step_up', (SELECT jsonb_build_object('operation', step_up_operation, 'digest', encode(step_up_digest, 'hex'), 'expires_at', step_up_expires_at) FROM sessions WHERE id = $1)
				)::text`, tokens.SessionID).Scan(&serialized); err != nil {
					t.Fatal(err)
				}
				return serialized
			}
			before := state()
			out := applicationAuditRequest(t, handler, method, path, tokens.AccessToken, "req_app_audit_failure", body)
			if out.Code != http.StatusServiceUnavailable || strings.Contains(out.Body.String(), `"secret"`) || strings.Contains(out.Body.String(), raw.Value()) {
				t.Fatalf("audit failure returned credentials or the wrong status: %d", out.Code)
			}
			if state() != before {
				t.Fatal("audit failure changed application, key, grace credentials, audit, or step-up state")
			}
			if _, err := apps.AuthenticateKey(ctx, raw.Value()); err != nil {
				t.Fatal("audit failure invalidated the original key")
			}
			if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_application_audit ON audit_logs`); err != nil {
				t.Fatal(err)
			}
			out = applicationAuditRequest(t, handler, method, path, tokens.AccessToken, "req_app_audit_failure", body)
			if out.Code != http.StatusOK {
				t.Fatalf("retry after audit recovery failed: status=%d", out.Code)
			}
			page := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, "/v1/spaces/"+spaceID+"/audit-logs?request_id=req_app_audit_failure"))
			if len(page.Body.Data) != 1 || page.Body.Data[0].Action != action || page.Body.Data[0].UserID != "usr_principal_actor" {
				t.Fatal("retry did not commit exactly one queryable application audit")
			}
		})
	}
}

func TestApplicationCredentialAuditHTTPUsesPublisherSpaceForAncestorAgent(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, ownerID, rootSpace, sessions, handler, _ := installationFixture(t, []string{"auth.authz:check"})
	publisher, publisherOwner, err := authz.CreateSpace(ctx, "usr_principal_actor", "Child publisher", "child-audit-publisher")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, rootSpace, publisher.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'space_tree'
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, ownerID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, publisher.ID, publisherOwner.ID, publisherOwner.ID, "auth.applications:manage")
	registered, err := apps.Register(ctx, publisherOwner.ID, application.RegisterInput{
		SpaceID: publisher.ID, Name: "Child SaaS", ManifestPermissions: []string{"auth.authz:check"},
	})
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "Ancestor manager", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, ownerID, rootSpace, parent.ID, []string{"auth.applications:manage"}, "space_tree", rootSpace); err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "Delegated ancestor manager", ExpiresAt: parent.ExpiresAt.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, parent.ID, rootSpace, child.ID, []string{"auth.applications:manage"}, "space_tree", rootSpace); err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateAgentAccess(ctx, child.ID, rootSpace, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	out := applicationAuditRequest(t, handler, http.MethodPost, "/v1/applications/"+registered.ID+"/api-keys", issued.AccessToken, "req_ancestor_app_audit", map[string]any{
		"name": "Child server", "grants": []string{"auth.authz:check"}, "expires_at": time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	})
	if out.Code != http.StatusOK {
		t.Fatalf("ancestor Agent key creation returned %d", out.Code)
	}
	publisherToken := manifestToken(t, sessions, publisherOwner.ID)
	page := decodeAuditPage(t, getAuditHTTP(handler, publisherToken, "/v1/spaces/"+publisher.ID+"/audit-logs?request_id=req_ancestor_app_audit"))
	if len(page.Body.Data) != 1 {
		t.Fatal("publisher cannot query its ancestor Agent's credential operation")
	}
	event := page.Body.Data[0]
	if event.SpaceID != publisher.ID || event.ResourceGroupID != "" || event.MemberID != child.ID || event.ApplicationID != registered.ID || event.MemberType != "agent" || event.CredentialType != "agent_access_token" || event.Action != "application.key.create" || len(event.OwnerChain) != 2 {
		t.Fatal("ancestor operation confused actor location with application location")
	}
	if event.OwnerChain[0].MemberID != parent.ID || event.OwnerChain[1].MemberID != ownerID || event.OwnerChain[0].SpaceID != rootSpace || event.OwnerChain[1].SpaceID != rootSpace {
		t.Fatal("publisher event lost the original ancestor owner locations")
	}
	rootToken := manifestToken(t, sessions, ownerID)
	rootPage := decodeAuditPage(t, getAuditHTTP(handler, rootToken, "/v1/spaces/"+rootSpace+"/audit-logs?request_id=req_ancestor_app_audit"))
	if len(rootPage.Body.Data) != 0 {
		t.Fatal("publisher event was attributed to the actor's Space")
	}
}
