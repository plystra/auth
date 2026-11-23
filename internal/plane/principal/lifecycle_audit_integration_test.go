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

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestAgentLifecycleAuditHTTPPreservesSubjectAndActorChains(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.agents:create")
	agents := &agent.Service{Store: st, StepUp: sessions}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("lifecycle audit test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := func(method, path, token, requestID, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", requestID)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s returned %d", method, path, response.Code)
		}
		return response
	}
	seedStepUpProof(t, st, tokens.SessionID, "me.agents.create", map[string]any{"name": "audit-parent", "expires_at": nil, "source": ""})
	response := request(http.MethodPost, "/v1/me/agents", tokens.AccessToken, "req_lifecycle_parent", `{"name":"audit-parent"}`)
	var parent, child agentCreatedOutput
	if err := json.Unmarshal(response.Body.Bytes(), &parent.Body); err != nil {
		t.Fatal(err)
	}
	parentID := parent.Body.Data.Agent.ID
	request(http.MethodPut, "/v1/me/agents/"+parentID+"/grants", tokens.AccessToken, "req_lifecycle_parent_grant",
		`{"permissions":["self:read","auth.agents:create","auth.members:read"]}`)
	parentToken, err := sessions.CreateAgentAccess(ctx, parentID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	childExpiry := parent.Body.Data.Agent.ExpiresAt.Add(-time.Minute).Format(time.RFC3339)
	response = request(http.MethodPost, "/v1/me/agents", parentToken.AccessToken, "req_lifecycle_child", fmt.Sprintf(`{"name":"audit-child","expires_at":%q}`, childExpiry))
	if err := json.Unmarshal(response.Body.Bytes(), &child.Body); err != nil {
		t.Fatal(err)
	}
	childID := child.Body.Data.Agent.ID
	request(http.MethodPut, "/v1/me/agents/"+childID+"/grants", parentToken.AccessToken, "req_lifecycle_child_grant", `{"permissions":["auth.members:read"]}`)
	request(http.MethodPost, "/v1/me/agents/"+childID+"/stop", parentToken.AccessToken, "req_lifecycle_child_stop", "")
	auditPath := "/v1/spaces/" + spaceID + "/audit-logs"
	var snapshots []audit.Event
	for _, tc := range []struct {
		requestID, action, subjectID, actorID, userID, credentialType string
		owners                                                        []string
	}{
		{"req_lifecycle_parent", "agent.create", parentID, owner.ID, "usr_principal_actor", "user_access_token", []string{owner.ID}},
		{"req_lifecycle_parent_grant", "grant.replace", parentID, owner.ID, "usr_principal_actor", "user_access_token", []string{owner.ID}},
		{"req_lifecycle_child", "agent.create", childID, parentID, "", "agent_access_token", []string{parentID, owner.ID}},
		{"req_lifecycle_child_grant", "grant.replace", childID, parentID, "", "agent_access_token", []string{parentID, owner.ID}},
		{"req_lifecycle_child_stop", "agent.stop", childID, parentID, "", "agent_access_token", []string{parentID, owner.ID}},
	} {
		page := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, auditPath+"?request_id="+tc.requestID))
		if len(page.Body.Data) != 1 {
			t.Fatalf("request %s has %d audit records, want 1", tc.requestID, len(page.Body.Data))
		}
		event := page.Body.Data[0]
		if event.Action != tc.action || event.MemberID != tc.subjectID || event.MemberType != "agent" || event.ActorID != tc.actorID || event.UserID != tc.userID || event.SpaceID != spaceID || event.Plane != "principal" || event.CredentialType != tc.credentialType {
			t.Fatalf("incorrect lifecycle identity snapshot: %+v", event)
		}
		var owners []string
		for _, snapshot := range event.OwnerChain {
			owners = append(owners, snapshot.MemberID)
		}
		if !slices.Equal(owners, tc.owners) || !strings.Contains(string(event.Metadata), `"owner_chain_complete":true`) {
			t.Fatalf("incorrect owner snapshot: %+v", event)
		}
		snapshots = append(snapshots, event)
	}
	request(http.MethodDelete, "/v1/me/agents/"+parentID, tokens.AccessToken, "req_lifecycle_delete", "")
	for _, snapshot := range snapshots {
		var owners []byte
		var memberID, userID, actorID string
		if err := st.Pool.QueryRow(ctx, `SELECT owner_chain, member_id, COALESCE(user_id, ''), actor_id FROM audit_logs WHERE id = $1`, snapshot.ID).Scan(&owners, &memberID, &userID, &actorID); err != nil {
			t.Fatal(err)
		}
		var chain []audit.MemberSnapshot
		if err := json.Unmarshal(owners, &chain); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(chain, snapshot.OwnerChain) || memberID != snapshot.MemberID || userID != snapshot.UserID || actorID != snapshot.ActorID {
			t.Fatal("Agent deletion rewrote a historical audit snapshot")
		}
	}
	response = getAuditHTTP(handler, tokens.AccessToken, auditPath+"?request_id=req_lifecycle_delete")
	deleted := decodeAuditPage(t, response)
	if len(deleted.Body.Data) != 1 || deleted.Body.Data[0].MemberID != parentID || deleted.Body.Data[0].UserID != "usr_principal_actor" {
		t.Fatal("Agent deletion event is not queryable with its verified caller")
	}
	for _, credential := range []string{parent.Body.Data.AgentKey, child.Body.Data.AgentKey, tokens.AccessToken, tokens.RefreshToken, parentToken.AccessToken} {
		var leaked bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_logs WHERE to_jsonb(audit_logs)::text LIKE '%' || $1 || '%')`, credential).Scan(&leaked); err != nil {
			t.Fatal(err)
		}
		if leaked || strings.Contains(response.Body.String(), credential) {
			t.Fatal("lifecycle audit leaked a credential")
		}
	}
}

func TestAgentLifecycleAuditHTTPFailureRollsBackStateAndAuthority(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.agents:create")
	agents := &agent.Service{Store: st}
	created, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "rollback-audit-agent"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authz.ReplaceAgentGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read"}, "space", spaceID)
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := st.Pool.QueryRow(ctx, `SELECT version FROM members WHERE id = $1`, created.ID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'audit rejected by test'; END; $$;
		CREATE TRIGGER test_reject_lifecycle_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("audit rollback test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	for _, tc := range []struct{ method, suffix, body string }{
		{http.MethodPut, "/grants", `{"permissions":["self:read"]}`},
		{http.MethodPost, "/stop", ""},
		{http.MethodDelete, "", ""},
	} {
		req := httptest.NewRequest(tc.method, "/v1/me/agents/"+created.ID+tc.suffix, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("audit failure status=%d for %s %s", response.Code, tc.method, tc.suffix)
		}
		var active bool
		if err := st.Pool.QueryRow(ctx, `SELECT m.status = 'active' AND m.version = $2 AND g.revoked_at IS NULL
			FROM members m JOIN authorization_grants g ON g.id = $3 WHERE m.id = $1`, created.ID, version, grant.ID).Scan(&active); err != nil {
			t.Fatal(err)
		}
		if !active {
			t.Fatal("audit failure changed Agent state, version, or grant")
		}
		if _, err := agents.AuthenticateKey(ctx, key); err != nil {
			t.Fatal("audit failure revoked the existing Agent credential")
		}
	}
}

func TestAgentCredentialHTTPAuditFailureRollsBackMutationAndStepUp(t *testing.T) {
	for _, operation := range []string{"create", "rotate"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			f := newGroupRemovalFixture(t)
			seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, f.owner.ID, "auth.agents:create")
			agents := &agent.Service{Store: f.store, StepUp: f.sessions}
			created, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "audit-credential-agent"})
			if err != nil {
				t.Fatal(err)
			}
			claims, err := f.sessions.VerifyAccess(t.Context(), f.token)
			if err != nil {
				t.Fatal(err)
			}
			path, body := "/v1/me/agents/"+created.ID+"/rotate", ""
			requestDigest := map[string]any{"agent_id": created.ID}
			if operation == "create" {
				path, body = "/v1/me/agents", `{"name":"audit-rollback-child"}`
				requestDigest = map[string]any{"name": "audit-rollback-child", "expires_at": nil, "source": ""}
			}
			seedStepUpProof(t, f.store, claims.SessionID, "me.agents."+operation, requestDigest)
			var membersBefore, credentialsBefore, groupsBefore int
			var versionBefore int64
			snapshot := `SELECT (SELECT count(*) FROM members), (SELECT count(*) FROM agent_credentials),
				(SELECT count(*) FROM groups), (SELECT policy_version FROM spaces WHERE id = $1)`
			if err := f.store.Pool.QueryRow(ctx, snapshot, f.spaceID).Scan(&membersBefore, &credentialsBefore, &groupsBefore, &versionBefore); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_credential_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'audit rejected by test'; END; $$;
				CREATE TRIGGER test_reject_credential_audit BEFORE INSERT ON audit_logs
				FOR EACH ROW EXECUTE FUNCTION reject_credential_audit()`); err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			(&API{Authorization: f.authz, Sessions: f.sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("Agent credential rollback", "1.0.0")))
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			route.Middleware(route.Principal, mux).ServeHTTP(response, req)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("credential mutation succeeded without audit: status=%d", response.Code)
			}
			var membersAfter, credentialsAfter, groupsAfter int
			var versionAfter int64
			if err := f.store.Pool.QueryRow(ctx, snapshot, f.spaceID).Scan(&membersAfter, &credentialsAfter, &groupsAfter, &versionAfter); err != nil {
				t.Fatal(err)
			}
			if membersAfter != membersBefore || credentialsAfter != credentialsBefore || groupsAfter != groupsBefore || versionAfter != versionBefore {
				t.Fatal("audit failure changed members, groups, credentials, or the policy version")
			}
			var proofIntact bool
			if err := f.store.Pool.QueryRow(ctx, `SELECT step_up_expires_at IS NOT NULL FROM sessions WHERE id = $1`, claims.SessionID).Scan(&proofIntact); err != nil || !proofIntact {
				t.Fatalf("audit failure consumed step-up: intact=%v error=%v", proofIntact, err)
			}
			if _, err := agents.AuthenticateKey(ctx, key); err != nil {
				t.Fatal("audit failure revoked the original Agent credential")
			}
		})
	}
}
