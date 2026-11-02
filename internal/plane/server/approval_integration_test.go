package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
)

func TestBusinessApprovalHTTPCreateAndCheckConsumption(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_server_actor", Name: "approval-server-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_server_approval', $1, '["auth.bindings:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, created.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	approvals := &approval.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions, Agents: agents, Approvals: approvals}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server approval test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	request := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	checkBody := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"auth.bindings:manage","resource":{"type":"invoice","id":"inv_http_1","space_id":%q}}`, created.ID, spaceID)
	before := request("/server/v1/authz/check", checkBody)
	if before.Code != http.StatusOK || !strings.Contains(before.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("unapproved HTTP check = %d %s", before.Code, before.Body.String())
	}
	digest := sha256.Sum256([]byte("invoice HTTP request"))
	createBody := strings.TrimSuffix(checkBody, "}") + fmt.Sprintf(`,"request_digest":%q,"reason":"Approve invoice"}`, hex.EncodeToString(digest[:]))
	createdResponse := request("/server/v1/approvals", createBody)
	if createdResponse.Code != http.StatusOK {
		t.Fatalf("approval create HTTP status = %d, body = %s", createdResponse.Code, createdResponse.Body.String())
	}
	var response struct {
		Data approval.Request `json:"data"`
	}
	if err := json.Unmarshal(createdResponse.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.Data.ID, "apr_") || response.Data.Status != "pending" {
		t.Fatalf("approval response = %+v", response.Data)
	}
	pending := request("/server/v1/authz/check", checkBody)
	if pending.Code != http.StatusOK || !strings.Contains(pending.Body.String(), "APPROVAL_PENDING") {
		t.Fatalf("pending HTTP check = %d %s", pending.Code, pending.Body.String())
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_server_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest, err := stepup.DigestValue(map[string]any{"approval_id": response.Data.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE sessions SET step_up_operation = 'approvals.approve', step_up_digest = $2,
		    step_up_method = 'totp', step_up_expires_at = now() + interval '5 minutes'
		WHERE id = $1
	`, tokens.SessionID, proofDigest); err != nil {
		t.Fatal(err)
	}
	proof := session.WithStepUpRequirement(ctx, session.StepUpRequirement{SessionID: tokens.SessionID, Operation: "approvals.approve", Digest: proofDigest})
	if _, err := approvals.Decide(proof, "usr_server_actor", response.Data.ID, true); err != nil {
		t.Fatal(err)
	}
	allowed := request("/server/v1/authz/check", checkBody)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"decision":"allow"`) {
		t.Fatalf("approved HTTP check = %d %s", allowed.Code, allowed.Body.String())
	}
	replayed := request("/server/v1/authz/check", checkBody)
	if replayed.Code != http.StatusOK || !strings.Contains(replayed.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("replayed HTTP check = %d %s", replayed.Code, replayed.Body.String())
	}
}
