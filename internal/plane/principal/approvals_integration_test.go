package principal

import (
	"context"
	"crypto/sha256"
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
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/pquerna/otp/totp"
)

func TestApprovalPrincipalHTTPInboxStepUpAndUserOnlyDecision(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	createdAgent, _, err := agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor",
		Name: "approval-principal-agent", ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, createdAgent.ID, "auth.bindings:manage")
	approvals := &approval.Service{Store: st, Authorization: authz, StepUp: sessions}
	digest := sha256.Sum256([]byte("approval principal request"))
	first, err := approvals.CreateBusiness(ctx, "key_principal_approval", createdAgent.ID,
		"auth.bindings:manage", approval.Resource{Type: "invoice", ID: "inv_first", SpaceID: spaceID}, digest[:], "First request")
	if err != nil {
		t.Fatal(err)
	}
	second, err := approvals.CreateBusiness(ctx, "key_principal_approval", createdAgent.ID,
		"auth.bindings:manage", approval.Resource{Type: "invoice", ID: "inv_second", SpaceID: spaceID}, digest[:], "Second request")
	if err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions.Factors = factors
	enrollment, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test")
	if err != nil {
		t.Fatal(err)
	}
	userTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, createdAgent.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents, Approvals: approvals}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal approval test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	for _, path := range []string{"/v1/approvals", "/v1/approvals/" + first.ID + "/approve"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/approve") {
			method = http.MethodPost
		}
		denied := request(method, path, agentTokens.AccessToken, "")
		if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "USER_ACCOUNT_REQUIRED") {
			t.Fatalf("Agent %s = %d %s", path, denied.Code, denied.Body.String())
		}
	}
	inbox := request(http.MethodGet, "/v1/approvals", userTokens.AccessToken, "")
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), first.ID) || !strings.Contains(inbox.Body.String(), second.ID) {
		t.Fatalf("user inbox = %d %s", inbox.Code, inbox.Body.String())
	}
	var inboxBody struct {
		Data []struct {
			DelegationChain []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"delegation_chain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(inbox.Body.Bytes(), &inboxBody); err != nil {
		t.Fatal(err)
	}
	for _, item := range inboxBody.Data {
		if len(item.DelegationChain) != 2 || item.DelegationChain[0].ID != createdAgent.ID || item.DelegationChain[0].Name != createdAgent.Name || item.DelegationChain[0].Type != "agent" || item.DelegationChain[1].ID != owner.ID || item.DelegationChain[1].Type != "human" {
			t.Fatalf("approval inbox omitted the Agent identity or human owner: %+v", item.DelegationChain)
		}
	}
	withoutProof := request(http.MethodPost, "/v1/approvals/"+first.ID+"/approve", userTokens.AccessToken, "")
	if withoutProof.Code != http.StatusForbidden || !strings.Contains(withoutProof.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("approval without step-up = %d %s", withoutProof.Code, withoutProof.Body.String())
	}
	stepUp := func(approvalID, operation string) {
		t.Helper()
		code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{
			"mfa_code": code, "operation": operation, "request": map[string]any{"approval_id": approvalID},
		})
		if err != nil {
			t.Fatal(err)
		}
		response := request(http.MethodPost, "/v1/auth/step-up", userTokens.AccessToken, string(body))
		if response.Code != http.StatusOK {
			t.Fatalf("step-up for %s = %d %s", operation, response.Code, response.Body.String())
		}
	}
	stepUp(first.ID, "approvals.approve")
	wrongRequest := request(http.MethodPost, "/v1/approvals/"+second.ID+"/approve", userTokens.AccessToken, "")
	if wrongRequest.Code != http.StatusForbidden || !strings.Contains(wrongRequest.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("step-up accepted different approval = %d %s", wrongRequest.Code, wrongRequest.Body.String())
	}
	approved := request(http.MethodPost, "/v1/approvals/"+first.ID+"/approve", userTokens.AccessToken, "")
	if approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), `"status":"approved"`) {
		t.Fatalf("approval decision = %d %s", approved.Code, approved.Body.String())
	}
	if !principalStepUpOperation("approvals.reject") {
		t.Fatal("approval rejection is not accepted by the step-up endpoint")
	}
	seedStepUpProof(t, st, userTokens.SessionID, "approvals.reject", map[string]any{"approval_id": second.ID})
	rejected := request(http.MethodPost, "/v1/approvals/"+second.ID+"/reject", userTokens.AccessToken, "")
	if rejected.Code != http.StatusOK || !strings.Contains(rejected.Body.String(), `"status":"rejected"`) {
		t.Fatalf("rejection decision = %d %s", rejected.Code, rejected.Body.String())
	}
	after := request(http.MethodGet, "/v1/approvals", userTokens.AccessToken, "")
	if after.Code != http.StatusOK || strings.Contains(after.Body.String(), first.ID) || strings.Contains(after.Body.String(), second.ID) {
		t.Fatalf("decided requests remain in inbox = %d %s", after.Code, after.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE id IN ($1, $2) AND decided_by_user_id = $3`, first.ID, second.ID, "usr_principal_actor").Scan(&count); err != nil || count != 2 {
		t.Fatalf("approval decisions = %d, %v", count, err)
	}

	t.Run("a local account without enterprise admission cannot approve", func(t *testing.T) {
		const userID = "usr_principal_actor"
		pending, err := approvals.CreateBusiness(ctx, "key_principal_approval", createdAgent.ID,
			"auth.bindings:manage", approval.Resource{Type: "invoice", ID: "inv_managed", SpaceID: spaceID}, digest[:], "Managed request")
		if err != nil {
			t.Fatal(err)
		}
		unbound, err := sessions.CreateForMember(ctx, userID, "", nil, "", 1)
		if err != nil {
			t.Fatal(err)
		}
		admin := authorization.WithHumanActor(ctx, owner.ID, userID)
		enterpriseSvc := &enterprise.Service{Store: st, Authorization: authz, DataKey: factors.DataKey}
		connection, err := enterpriseSvc.CreateConnection(admin, owner.ID, spaceID, enterprise.ConnectionInput{
			Name: "Managed approval", Provider: "oidc", Issuer: "https://idp.example.test", ClientID: "approval-test",
			ClientSecret: "test-secret", RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
		})
		if err != nil {
			t.Fatal(err)
		}
		domain, err := enterpriseSvc.CreateDomain(admin, owner.ID, spaceID,
			enterprise.DomainInput{Domain: "example.test", ConnectionID: connection.ID, ForceSSO: true})
		if err != nil {
			t.Fatal(err)
		}
		enterpriseSvc.DNSResolver = principalTXTResolver{values: []string{domain.VerificationToken}}
		if err := enterpriseSvc.VerifyDomain(admin, owner.ID, spaceID, domain.ID); err != nil {
			t.Fatal(err)
		}
		sessions.SpaceSignInPolicy = enterpriseSvc
		inbox := request(http.MethodGet, "/v1/approvals", unbound.AccessToken, "")
		if inbox.Code != http.StatusOK || strings.Contains(inbox.Body.String(), pending.ID) {
			t.Fatalf("account-only session saw managed approval: HTTP %d", inbox.Code)
		}
		seedStepUpProof(t, st, unbound.SessionID, "approvals.approve", map[string]any{"approval_id": pending.ID})
		decision := request(http.MethodPost, "/v1/approvals/"+pending.ID+"/approve", unbound.AccessToken, "")
		if decision.Code != http.StatusUnauthorized || !strings.Contains(decision.Body.String(), "UNAUTHENTICATED") {
			t.Fatalf("account-only session reached managed approval decision: HTTP %d", decision.Code)
		}
	})
}
