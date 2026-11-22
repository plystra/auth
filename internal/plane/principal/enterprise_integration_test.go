package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

type principalTXTResolver struct{ values []string }

func (r principalTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return r.values, nil
}

func TestSSOConnectionListUsesOneHumanAgentAuthorizationPath(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.connections:manage")
	enterpriseService := &enterprise.Service{Store: st, Authorization: authz, DataKey: secret.New(strings.Repeat("d", 32))}
	approvals := &approval.Service{Store: st, Authorization: authz}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Approvals: approvals, Enterprise: enterpriseService}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("SSO connection integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	humanTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	requestList := func(token, approvalID string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+spaceID+"/sso-connections", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if approvalID != "" {
			req.Header.Set("Approval-Id", approvalID)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	human := requestList(humanTokens.AccessToken, "")
	if human.Code != http.StatusOK || !strings.Contains(human.Body.String(), `"data":[]`) {
		t.Fatalf("human SSO connection list = %d %s", human.Code, human.Body.String())
	}

	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "sso-manager", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.connections:manage")
	agentTokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	pending := requestList(agentTokens.AccessToken, "")
	if pending.Code != http.StatusForbidden || !strings.Contains(pending.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("Agent SSO connection list without approval = %d %s", pending.Code, pending.Body.String())
	}
	var pendingBody struct {
		Error struct {
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(pending.Body.Bytes(), &pendingBody); err != nil {
		t.Fatal(err)
	}
	approvalID := pendingBody.Error.Details["approval_id"]
	if approvalID == "" {
		t.Fatalf("Agent approval response omitted approval_id: %s", pending.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE approval_requests
		SET status = 'approved', decided_by_user_id = 'usr_principal_actor', decided_at = now(), approved_expires_at = now() + interval '5 minutes'
		WHERE id = $1 AND status = 'pending'
	`, approvalID); err != nil {
		t.Fatal(err)
	}
	agentList := requestList(agentTokens.AccessToken, approvalID)
	if agentList.Code != http.StatusOK || !strings.Contains(agentList.Body.String(), `"data":[]`) {
		t.Fatalf("Agent SSO connection list after approval = %d %s", agentList.Code, agentList.Body.String())
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, approvalID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "consumed" {
		t.Fatalf("SSO list approval status = %q, want consumed", status)
	}
}

func TestForcedSSODomainRoutesSignInToConfiguredConnection(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, _, _ := newPrincipalFixture(t)
	service := &enterprise.Service{Store: st, Authorization: authz, DataKey: secret.New(strings.Repeat("d", 32))}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_principal_actor")
	connection, err := service.CreateConnection(requestCtx, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Routing OIDC", Provider: "oidc", Issuer: "https://idp.example.com/routing", ClientID: "client", ClientSecret: "secret",
		RedirectURI: "https://auth.example.com/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := service.CreateDomain(requestCtx, owner.ID, spaceID, enterprise.DomainInput{Domain: "acme.example", ConnectionID: connection.ID, ForceSSO: true})
	if err != nil {
		t.Fatal(err)
	}
	service.DNSResolver = principalTXTResolver{values: []string{domain.VerificationToken}}
	if err := service.VerifyDomain(requestCtx, owner.ID, spaceID, domain.ID); err != nil {
		t.Fatal(err)
	}
	api := &API{Enterprise: service}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("SSO routing integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/sign-in", strings.NewReader(`{"email":"user@acme.example"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_step":"sso"`) || !strings.Contains(response.Body.String(), connection.ID) {
		t.Fatalf("forced SSO sign-in routing = %d %s", response.Code, response.Body.String())
	}
}
