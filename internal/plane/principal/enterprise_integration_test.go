package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func TestDirectoryManagementHTTPBindsVersionAndAcceptsBodylessDelete(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	service := &enterprise.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Enterprise: service}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("directory management", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.VerifyAccess(tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, version string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/v1/spaces/"+spaceID+"/directories"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("If-Match", version)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("%s directory endpoint = %d, want %d", method, res.Code, want)
		}
		return res
	}
	request("POST", "", `{"name":"Workforce"}`, "", 403)
	seedStepUpProof(t, st, claims.SessionID, "directories.create", map[string]any{"operation": "directories.create", "space_id": spaceID, "name": "Workforce",
		"sso_connection_id": nil, "sso_identity_claim": nil})
	created := request("POST", "", `{"name":"Workforce"}`, "", 200)
	var result struct {
		Data enterprise.Directory `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Data.Token.Value() == "" {
		t.Fatal("directory creation did not return its one-time credential")
	}
	directory := result.Data
	listed := request("GET", "", "", "", 200)
	if strings.Contains(listed.Body.String(), `"token"`) || strings.Contains(fmt.Sprintf("%+v", directory), directory.Token.Value()) {
		t.Fatal("directory credential leaked through listing or formatting")
	}
	seedStepUpProof(t, st, claims.SessionID, "directories.update", map[string]any{"operation": "directories.update", "space_id": spaceID,
		"directory_id": directory.ID, "name": "", "rotate_token": true, "version": int64(1), "sso_connection_id": nil, "sso_identity_claim": nil})
	request("PATCH", "/"+directory.ID, `{"rotate_token":true}`, `W/"2"`, 412)
	rotated := request("PATCH", "/"+directory.ID, `{"rotate_token":true}`, `W/"1"`, 200)
	if err := json.Unmarshal(rotated.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.Version != 2 || !result.Data.UpdatedAt.After(directory.UpdatedAt) || result.Data.Token.Value() == directory.Token.Value() {
		t.Fatal("rotation did not return the committed version, timestamp and new token")
	}
	seedStepUpProof(t, st, claims.SessionID, "directories.update", map[string]any{"operation": "directories.update", "space_id": spaceID, "directory_id": directory.ID, "name": "", "rotate_token": true, "version": int64(1),
		"sso_connection_id": nil, "sso_identity_claim": nil})
	request("PATCH", "/"+directory.ID, `{"rotate_token":true}`, `W/"2"`, 403)
	seedStepUpProof(t, st, claims.SessionID, "directories.delete", map[string]any{"operation": "directories.delete", "space_id": spaceID,
		"directory_id": directory.ID, "version": int64(2)})
	request("DELETE", "/"+directory.ID, "", `W/"2"`, 200)
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM directories WHERE id=$1`, directory.ID).Scan(&status); err != nil || status != "disabled" {
		t.Fatalf("directory delete status = %s, %v", status, err)
	}
}

func TestDirectorySSOConfigurationHTTPBindsClaimAndPresenceToStepUp(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	service := &enterprise.Service{Store: st, Authorization: authz, StepUp: sessions, DataKey: secret.New(strings.Repeat("d", 32))}
	actor := authorization.WithHumanActor(ctx, owner.ID, "usr_principal_actor")
	connection, err := service.CreateConnection(actor, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Directory OIDC", Provider: "oidc", Issuer: "https://idp.example.test", ClientID: "directory-client", ClientSecret: "test-secret",
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Enterprise: service}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("directory identity configuration", "1.0.0")))
	server := httptest.NewServer(route.Middleware(route.Principal, mux))
	t.Cleanup(server.Close)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.VerifyAccess(tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, suffix, body string, version int, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, server.URL+"/v1/spaces/"+spaceID+"/directories"+suffix, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("If-Match", fmt.Sprintf("W/\"%d\"", version))
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		data, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != want {
			t.Fatalf("directory configuration status=%d want=%d err=%v", res.StatusCode, want, err)
		}
		return data
	}
	seedStepUpProof(t, st, claims.SessionID, "directories.create", map[string]any{
		"operation": "directories.create", "space_id": spaceID, "name": "Workforce",
		"sso_connection_id": connection.ID, "sso_identity_claim": "oid",
	})
	request("POST", "", fmt.Sprintf(`{"name":"Workforce","sso_connection_id":%q,"sso_identity_claim":"sub"}`, connection.ID), 0, 403)
	data := request("POST", "", fmt.Sprintf(`{"name":"Workforce","sso_connection_id":%q,"sso_identity_claim":"oid"}`, connection.ID), 0, 200)
	var created struct{ Data enterprise.Directory }
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	directory := created.Data
	if directory.SSOConnectionID != connection.ID || directory.SSOIdentityClaim != "oid" {
		t.Fatal("directory SSO configuration was not returned")
	}
	seedStepUpProof(t, st, claims.SessionID, "directories.update", map[string]any{
		"operation": "directories.update", "space_id": spaceID, "directory_id": directory.ID, "version": int64(1), "name": "Renamed", "rotate_token": false,
		"sso_connection_id": nil, "sso_identity_claim": nil,
	})
	request("PATCH", "/"+directory.ID, `{"name":"Renamed","sso_connection_id":"","sso_identity_claim":""}`, 1, 403)
	data = request("PATCH", "/"+directory.ID, `{"name":"Renamed"}`, 1, 200)
	if err := json.Unmarshal(data, &created); err != nil || created.Data.SSOConnectionID != connection.ID || created.Data.Version != 2 {
		t.Fatal("omitting SSO fields changed the mapping")
	}
	request("PATCH", "/"+directory.ID, `{"rotate_token":true,"sso_connection_id":"","sso_identity_claim":""}`, 2, 400)
	seedStepUpProof(t, st, claims.SessionID, "directories.update", map[string]any{
		"operation": "directories.update", "space_id": spaceID, "directory_id": directory.ID, "version": int64(2), "name": "", "rotate_token": false,
		"sso_connection_id": "", "sso_identity_claim": "",
	})
	request("PATCH", "/"+directory.ID, `{"sso_connection_id":"","sso_identity_claim":""}`, 2, 200)
	var linked bool
	if err := st.Pool.QueryRow(ctx, "SELECT sso_connection_id IS NOT NULL OR sso_identity_claim IS NOT NULL FROM directories WHERE id=$1", directory.ID).Scan(&linked); err != nil || linked {
		t.Fatal("explicit clearing did not remove both mapping fields")
	}
}

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
		RedirectURI: "https://auth.example.com/v1/sso/{connection_id}/callback", CoversSubtree: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := service.CreateDomain(requestCtx, owner.ID, spaceID, enterprise.DomainInput{Domain: "acme.example", ConnectionID: connection.ID, ForceSSO: true, CoversSubtree: true})
	if err != nil {
		t.Fatal(err)
	}
	service.DNSResolver = principalTXTResolver{values: []string{domain.VerificationToken}}
	if err := service.VerifyDomain(requestCtx, owner.ID, spaceID, domain.ID); err != nil {
		t.Fatal(err)
	}
	childID := "spc_forced_sso_child"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id) VALUES ($1, 'Forced SSO Child', 'forced-sso-child', $2)`, childID, spaceID); err != nil {
		t.Fatal(err)
	}
	api := &API{Enterprise: service}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("SSO routing integration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/sign-in", strings.NewReader(`{"email":"user@acme.example","space_id":"`+childID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_step":"sso"`) || !strings.Contains(response.Body.String(), connection.ID) {
		t.Fatalf("forced SSO sign-in routing = %d %s", response.Code, response.Body.String())
	}
}
