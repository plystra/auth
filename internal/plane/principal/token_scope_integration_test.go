package principal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestPrincipalManagementEnforcesNarrowedTokenScope(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.agents:create")
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.grants:assign")
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "scoped-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authz.ReplaceAgentGrants(ctx, owner.ID, spaceID, parent.ID, []string{"auth.members:read", "auth.members:manage", "auth.agents:create", "auth.grants:assign"}, "space", spaceID)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentDelegatedAccess(ctx, parent.ID, spaceID, security.DefaultApplicationAudience, owner.ID, []string{"auth.members:read"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal scope test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := request(http.MethodGet, "/v1/spaces/"+spaceID+"/members", ""); response.Code != http.StatusOK {
		t.Fatalf("included permission status = %d", response.Code)
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/spaces/" + spaceID + "/members", `{"name":"scope-must-deny","type":"human","binding_policy":"single"}`},
		{http.MethodPost, "/v1/me/agents", `{"name":"scope-must-deny"}`},
		{http.MethodPost, "/v1/me/agents/" + parent.ID + "/rotate", ""},
		{http.MethodPost, "/v1/me/agents/" + parent.ID + "/stop", ""},
		{http.MethodDelete, "/v1/me/agents/" + parent.ID, ""},
		{http.MethodDelete, "/v1/me/member", ""},
		{http.MethodDelete, "/v1/spaces/" + spaceID + "/grants/" + grant.ID, ""},
	} {
		response := request(tc.method, tc.path, tc.body)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"TOKEN_SCOPE_EXCLUDED"`) {
			t.Fatalf("excluded permission at %s: status=%d body=%s", tc.path, response.Code, response.Body.String())
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE name = 'scope-must-deny'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("excluded operations wrote %d members: %v", count, err)
	}
	if err := agents.ValidateActive(ctx, parent.ID); err != nil {
		t.Fatalf("excluded lifecycle operation changed the Agent: %v", err)
	}
	var revoked bool
	if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM authorization_grants WHERE id = $1`, grant.ID).Scan(&revoked); err != nil || revoked {
		t.Fatalf("excluded revocation changed the grant: revoked=%v, error=%v", revoked, err)
	}
}

func TestAgentOwnerSystemAssignmentCannotRestoreExcludedTokenScope(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "scoped-delegator", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "scoped-recipient", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, owner.ID, spaceID, parent.ID, []string{"auth.members:read", "auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentDelegatedAccess(ctx, parent.ID, spaceID, security.DefaultApplicationAudience, owner.ID, []string{"auth.members:read"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("owner scope test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	grant := func(permission string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/v1/me/agents/"+child.ID+"/grants", strings.NewReader(fmt.Sprintf(`{"permissions":[%q],"scope":"space","anchor_space_id":%q}`, permission, spaceID)))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := grant("auth.members:read"); response.Code != http.StatusOK {
		t.Fatalf("included owner delegation status = %d body=%s", response.Code, response.Body.String())
	}
	if response := grant("auth.members:manage"); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"AUTHORITY_DELTA_NOT_COVERED"`) {
		t.Fatalf("excluded owner delegation status = %d body=%s", response.Code, response.Body.String())
	}
	var permissions string
	if err := st.Pool.QueryRow(ctx, `SELECT permission_keys::text FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, child.ID).Scan(&permissions); err != nil || permissions != `["auth.members:read"]` {
		t.Fatalf("denied delegation replaced existing grant: %q, %v", permissions, err)
	}
}
