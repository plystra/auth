package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestAgentBindingGovernanceApprovalIsRequestBoundAndSingleUse(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "governance target", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ('usr_governance_target', 'governance@example.test', 'governance@example.test', 'hash', 'active', now()),
		       ('usr_governance_other', 'other-governance@example.test', 'other-governance@example.test', 'hash', 'active', now())
	`); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	createdAgent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "governance-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, createdAgent.ID, "auth.bindings:manage")
	userTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentTokens, err := sessions.CreateAgentAccess(ctx, createdAgent.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	approvals := &approval.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents, Approvals: approvals}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("governance approval test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := func(method, path, token, approvalID, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if approvalID != "" {
			req.Header.Set("Approval-Id", approvalID)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	bindPath := fmt.Sprintf("/v1/spaces/%s/members/%s/users", spaceID, target.ID)
	bindBody := `{"user_id":"usr_governance_target"}`
	initial := request(http.MethodPost, bindPath, agentTokens.AccessToken, "", bindBody)
	if initial.Code != http.StatusForbidden {
		t.Fatalf("initial governance request = %d %s", initial.Code, initial.Body.String())
	}
	var denied struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				ApprovalID string `json:"approval_id"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(initial.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Error.Code != "APPROVAL_REQUIRED" || !strings.HasPrefix(denied.Error.Details.ApprovalID, "apr_") {
		t.Fatalf("automatic approval response = %s", initial.Body.String())
	}
	approvalID := denied.Error.Details.ApprovalID
	var bindings int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_governance_target' AND member_id = $1`, target.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("unapproved binding count = %d, %v", bindings, err)
	}
	inbox := request(http.MethodGet, "/v1/approvals", userTokens.AccessToken, "", "")
	if inbox.Code != http.StatusOK || !strings.Contains(inbox.Body.String(), approvalID) ||
		!strings.Contains(inbox.Body.String(), `"operation":"members.bindings.create"`) ||
		!strings.Contains(inbox.Body.String(), `"user_id":"usr_governance_target"`) {
		t.Fatalf("governance inbox = %d %s", inbox.Code, inbox.Body.String())
	}
	pending := request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, bindBody)
	if pending.Code != http.StatusForbidden || !strings.Contains(pending.Body.String(), "APPROVAL_PENDING") {
		t.Fatalf("pending governance retry = %d %s", pending.Code, pending.Body.String())
	}
	seedStepUpProof(t, st, userTokens.SessionID, "approvals.approve", map[string]any{"approval_id": approvalID})
	approved := request(http.MethodPost, "/v1/approvals/"+approvalID+"/approve", userTokens.AccessToken, "", "")
	if approved.Code != http.StatusOK {
		t.Fatalf("governance approval = %d %s", approved.Code, approved.Body.String())
	}
	businessDecision, _, err := authz.CheckBusiness(ctx, authorization.CheckRequest{
		MemberID: createdAgent.ID, Permission: "auth.bindings:manage", ResourceSpace: spaceID,
	}, "governance", target.ID)
	if err != nil || businessDecision.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("governance approval reached business check = %+v, %v", businessDecision, err)
	}
	changed := request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, `{"user_id":"usr_governance_other"}`)
	if changed.Code != http.StatusForbidden || !strings.Contains(changed.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("changed request retry = %d %s", changed.Code, changed.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_governance_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'member.binding.create' THEN RAISE EXCEPTION 'audit failed'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_governance_binding_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_governance_binding_audit()
	`); err != nil {
		t.Fatal(err)
	}
	failed := request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, bindBody)
	if failed.Code < 500 {
		t.Fatalf("audit failure did not abort binding = %d %s", failed.Code, failed.Body.String())
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, approvalID).Scan(&status); err != nil || status != "approved" {
		t.Fatalf("failed mutation left approval status = %s, %v", status, err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_governance_target' AND member_id = $1`, target.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("failed mutation left binding count = %d, %v", bindings, err)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_governance_binding_audit ON audit_logs; DROP FUNCTION reject_governance_binding_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	ownerExcluded := request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, bindBody)
	if ownerExcluded.Code != http.StatusForbidden || !strings.Contains(ownerExcluded.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("owner envelope retry = %d %s", ownerExcluded.Code, ownerExcluded.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = NULL WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	const attempts = 2
	results := make(chan *httptest.ResponseRecorder, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, bindBody)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result.Code == http.StatusOK {
			successes++
		} else if result.Code != http.StatusForbidden || !strings.Contains(result.Body.String(), "APPROVAL_REQUIRED") {
			t.Fatalf("concurrent governance retry = %d %s", result.Code, result.Body.String())
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent approval successes = %d", successes)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_governance_target' AND member_id = $1 AND status = 'active'`, target.ID).Scan(&bindings); err != nil || bindings != 1 {
		t.Fatalf("approved binding count = %d, %v", bindings, err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM approval_requests WHERE id = $1`, approvalID).Scan(&status); err != nil || status != "consumed" {
		t.Fatalf("approval status = %s, %v", status, err)
	}
	replayed := request(http.MethodPost, bindPath, agentTokens.AccessToken, approvalID, bindBody)
	if replayed.Code != http.StatusForbidden || !strings.Contains(replayed.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("replayed governance approval = %d %s", replayed.Code, replayed.Body.String())
	}
	revokePath := bindPath + "/usr_governance_target"
	initialRevoke := request(http.MethodDelete, revokePath, agentTokens.AccessToken, "", "")
	if initialRevoke.Code != http.StatusForbidden {
		t.Fatalf("initial governance revocation = %d %s", initialRevoke.Code, initialRevoke.Body.String())
	}
	if err := json.Unmarshal(initialRevoke.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Error.Code != "APPROVAL_REQUIRED" || denied.Error.Details.ApprovalID == approvalID {
		t.Fatalf("revocation approval response = %s", initialRevoke.Body.String())
	}
	revokeApprovalID := denied.Error.Details.ApprovalID
	seedStepUpProof(t, st, userTokens.SessionID, "approvals.approve", map[string]any{"approval_id": revokeApprovalID})
	approvedRevoke := request(http.MethodPost, "/v1/approvals/"+revokeApprovalID+"/approve", userTokens.AccessToken, "", "")
	if approvedRevoke.Code != http.StatusOK {
		t.Fatalf("revocation approval = %d %s", approvedRevoke.Code, approvedRevoke.Body.String())
	}
	revoked := request(http.MethodDelete, revokePath, agentTokens.AccessToken, revokeApprovalID, "")
	if revoked.Code != http.StatusOK {
		t.Fatalf("approved revocation = %d %s", revoked.Code, revoked.Body.String())
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_governance_target' AND member_id = $1 AND status = 'active'`, target.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("revoked binding count = %d, %v", bindings, err)
	}
	policyPath := fmt.Sprintf("/v1/spaces/%s/members/%s", spaceID, target.ID)
	policyBody := `{"binding_policy":"single"}`
	initialPolicy := request(http.MethodPatch, policyPath, agentTokens.AccessToken, "", policyBody)
	if initialPolicy.Code != http.StatusForbidden {
		t.Fatalf("initial policy change = %d %s", initialPolicy.Code, initialPolicy.Body.String())
	}
	if err := json.Unmarshal(initialPolicy.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	if denied.Error.Code != "APPROVAL_REQUIRED" || denied.Error.Details.ApprovalID == "" {
		t.Fatalf("policy approval response = %s", initialPolicy.Body.String())
	}
	policyApprovalID := denied.Error.Details.ApprovalID
	seedStepUpProof(t, st, userTokens.SessionID, "approvals.approve", map[string]any{"approval_id": policyApprovalID})
	approvedPolicy := request(http.MethodPost, "/v1/approvals/"+policyApprovalID+"/approve", userTokens.AccessToken, "", "")
	if approvedPolicy.Code != http.StatusOK {
		t.Fatalf("policy approval = %d %s", approvedPolicy.Code, approvedPolicy.Body.String())
	}
	updated := request(http.MethodPatch, policyPath, agentTokens.AccessToken, policyApprovalID, policyBody)
	if updated.Code != http.StatusOK {
		t.Fatalf("approved policy update = %d %s", updated.Code, updated.Body.String())
	}
	var bindingPolicy string
	if err := st.Pool.QueryRow(ctx, `SELECT binding_policy FROM members WHERE id = $1`, target.ID).Scan(&bindingPolicy); err != nil || bindingPolicy != "single" {
		t.Fatalf("binding policy = %q, %v", bindingPolicy, err)
	}
	rejectedBody := `{"binding_policy":"shared"}`
	initialRejected := request(http.MethodPatch, policyPath, agentTokens.AccessToken, "", rejectedBody)
	if initialRejected.Code != http.StatusForbidden {
		t.Fatalf("initial rejection case = %d %s", initialRejected.Code, initialRejected.Body.String())
	}
	if err := json.Unmarshal(initialRejected.Body.Bytes(), &denied); err != nil {
		t.Fatal(err)
	}
	rejectedID := denied.Error.Details.ApprovalID
	seedStepUpProof(t, st, userTokens.SessionID, "approvals.reject", map[string]any{"approval_id": rejectedID})
	rejected := request(http.MethodPost, "/v1/approvals/"+rejectedID+"/reject", userTokens.AccessToken, "", "")
	if rejected.Code != http.StatusOK {
		t.Fatalf("governance rejection = %d %s", rejected.Code, rejected.Body.String())
	}
	rejectedRetry := request(http.MethodPatch, policyPath, agentTokens.AccessToken, rejectedID, rejectedBody)
	if rejectedRetry.Code != http.StatusForbidden || !strings.Contains(rejectedRetry.Body.String(), "APPROVAL_REJECTED") {
		t.Fatalf("rejected governance retry = %d %s", rejectedRetry.Code, rejectedRetry.Body.String())
	}
	if err := st.Pool.QueryRow(ctx, `SELECT binding_policy FROM members WHERE id = $1`, target.ID).Scan(&bindingPolicy); err != nil || bindingPolicy != "single" {
		t.Fatalf("rejected policy change mutated member = %q, %v", bindingPolicy, err)
	}
}
