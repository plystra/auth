package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestAuthorizationDenyAuditCorrelatesDecisionAndSnapshotsOwnerChain(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "audit-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "audit-child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET scopes = '["auth.authz:check","auth.authz:explain"]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions, Agents: agents}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("authorization audit test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	body := fmt.Sprintf(`{"subject":{"token":%q},"action":"missing:read","resource":{"type":"invoice","id":"inv_audit","space_id":%q}}`, childKey, spaceID)
	var decisionIDs []string
	for _, endpoint := range []string{"check", "batch-check", "explain"} {
		t.Run(endpoint, func(t *testing.T) {
			payload := body
			if endpoint == "batch-check" {
				payload = `{"requests":[` + body + `]}`
			}
			req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/"+endpoint, strings.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("denied decision status = %d", response.Code)
			}
			var envelope struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			var decision CheckDecision
			if endpoint == "batch-check" {
				var decisions []CheckDecision
				if err := json.Unmarshal(envelope.Data, &decisions); err != nil || len(decisions) != 1 {
					t.Fatalf("batch decision decode: %v", err)
				}
				decision = decisions[0]
			} else if err := json.Unmarshal(envelope.Data, &decision); err != nil {
				t.Fatal(err)
			}
			if decision.Decision != "deny" || decision.DenyCode != "UNKNOWN_PERMISSION" || decision.DecisionID == "" {
				t.Fatalf("decision = %+v", decision)
			}
			var memberID, memberType, recordedSpace, applicationID, denyCode, permission, requestID, plane, credential string
			var chainJSON, recordJSON []byte
			if err := st.Pool.QueryRow(ctx, `
				SELECT member_id, member_type, space_id, application_id, deny_code, permission_key,
				       request_id, plane, credential_type, owner_chain, to_jsonb(audit_logs)
				FROM audit_logs WHERE decision_id = $1
			`, decision.DecisionID).Scan(&memberID, &memberType, &recordedSpace, &applicationID, &denyCode, &permission, &requestID, &plane, &credential, &chainJSON, &recordJSON); err != nil {
				t.Fatal(err)
			}
			if memberID != child.ID || memberType != "agent" || recordedSpace != spaceID || applicationID != "app_server_test" || denyCode != decision.DenyCode || permission != "missing:read" || requestID == "" || plane != "server" || credential != "application" {
				t.Fatalf("audit context = member %s/%s, Space %s, application %s, code %s, permission %s, request %s, plane %s, credential %s", memberID, memberType, recordedSpace, applicationID, denyCode, permission, requestID, plane, credential)
			}
			var chain []struct {
				ID   string `json:"member_id"`
				Type string `json:"member_type"`
			}
			if err := json.Unmarshal(chainJSON, &chain); err != nil {
				t.Fatal(err)
			}
			if len(chain) != 2 || chain[0].ID != parent.ID || chain[0].Type != "agent" || chain[1].ID != owner.ID || chain[1].Type != "human" {
				t.Fatalf("owner chain = %s", chainJSON)
			}
			for _, sensitive := range []string{key, childKey, "ply_sk_", "ply_ag_", "test-password-hash"} {
				if strings.Contains(string(recordJSON), sensitive) {
					t.Fatal("audit contains credential material")
				}
			}
			decisionIDs = append(decisionIDs, decision.DecisionID)
		})
	}
	if t.Failed() {
		return
	}
	if err := agents.Delete(ctx, owner.ID, parent.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range decisionIDs {
		var parentID string
		if err := st.Pool.QueryRow(ctx, `SELECT owner_chain->0->>'member_id' FROM audit_logs WHERE decision_id = $1`, id).Scan(&parentID); err != nil || parentID != parent.ID {
			t.Fatalf("historical owner snapshot after deletion: %q, %v", parentID, err)
		}
	}
}

func TestAuthorizationDenyAuditUsesVerifiedUserAndLeavesUnresolvedSubjectEmpty(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	issued, err := sessions.CreateForMember(ctx, "usr_server_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.Signer.Verify(issued.AccessToken, time.Now(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	claims.Audience = "server-test-client"
	token, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	input := &CheckInput{Authorization: "Bearer " + key, Body: CheckBody{
		Subject: CheckSubject{Token: token, UserID: "usr_untrusted"}, Action: "missing:read",
		Resource: CheckResource{Type: "invoice", ID: "inv_user_audit", SpaceID: spaceID},
	}}
	decision, err := api.check(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var userID, memberID, source string
	var chainLength int
	if err := st.Pool.QueryRow(ctx, `
		SELECT user_id, member_id, COALESCE(metadata->>'subject_source', ''), jsonb_array_length(owner_chain)
		FROM audit_logs WHERE decision_id = $1
	`, decision.Body.Data.DecisionID).Scan(&userID, &memberID, &source, &chainLength); err != nil {
		t.Fatal(err)
	}
	if userID != "usr_server_actor" || memberID != owner.ID || source != "" || chainLength != 0 {
		t.Fatalf("verified user audit: user=%q member=%q source=%q chain length=%d", userID, memberID, source, chainLength)
	}
	input.Body.Action = "self:read"
	input.Body.Resource.GroupID = "malformed-group"
	invalidGroup, err := api.check(ctx, input)
	if err != nil || invalidGroup.Body.Data.DenyCode != "RESOURCE_GROUP_NOT_FOUND" {
		t.Fatalf("invalid resource group did not retain its deny result: %v", err)
	}
	input.Body.Resource.GroupID = ""
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_audit_outside', 'Outside', 'audit-outside')`); err != nil {
		t.Fatal(err)
	}
	input.Body.Subject = CheckSubject{MemberID: owner.ID, UserID: "usr_untrusted"}
	input.Body.Resource.SpaceID = "spc_audit_outside"
	outside, err := api.check(ctx, input)
	if err != nil || outside.Body.Data.DenyCode != "KEY_SCOPE_EXCLUDED" {
		t.Fatalf("outside-scope decision: %v", err)
	}
	var emptyIdentity bool
	if err := st.Pool.QueryRow(ctx, `
		SELECT member_id IS NULL AND member_type IS NULL AND user_id IS NULL
		       AND owner_chain = '[]'::jsonb, metadata->>'subject_source'
		FROM audit_logs WHERE decision_id = $1
	`, outside.Body.Data.DecisionID).Scan(&emptyIdentity, &source); err != nil {
		t.Fatal(err)
	}
	if !emptyIdentity || source != "application_assertion" {
		t.Fatalf("unvalidated request identity became an audit fact: empty=%v source=%q", emptyIdentity, source)
	}
}

func TestAuthorizationDenyAuditFailureReturnsUnavailable(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION fail_decision_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.decision_id IS NOT NULL THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER fail_decision_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_decision_audit();
	`); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("unavailable audit test", "1.0.0")))
	body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"missing:read","resource":{"type":"invoice","id":"inv_audit_failure","space_id":%q}}`, owner.ID, spaceID)
	req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	route.Middleware(route.Server, mux).ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"UNAVAILABLE"`) {
		t.Fatalf("audit failure status = %d, want 503 UNAVAILABLE", response.Code)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'authz.check'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed audit left %d events: %v", count, err)
	}
}
