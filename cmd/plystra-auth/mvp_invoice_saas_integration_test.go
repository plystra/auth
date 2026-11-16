package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plystra/auth/examples/invoice-saas"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/secret"
)

// The SaaS uses only public Auth HTTP endpoints and its own empty database.
// No Auth fixture SQL or domain service constructs its business authorization.
func runInvoiceSaaSScenario(t *testing.T, scenario mvpDelegationScenario, projectID, otherProjectID, parentID, parentKey, childToken string) func() {
	t.Helper()
	ctx := context.Background()
	binary := filepath.Join(t.TempDir(), "invoice-saas.exe")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./examples/invoice-saas/cmd/invoice-saas")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Invoice SaaS example: %v\n%s", err, output)
	}
	command := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "INVOICE_SAAS_DATABASE_URL="+scenario.BusinessDatabaseURL)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Invoice SaaS %s: %v\n%s", args[0], err, output)
		}
	}
	command("migrate")
	for _, invoice := range []struct{ id, group string }{
		{"inv_delegated", projectID}, {"inv_other", otherProjectID}, {"inv_approve", projectID}, {"inv_unavailable", projectID},
	} {
		command("seed", "--id", invoice.id, "--space-id", scenario.SpaceID, "--group-id", invoice.group, "--amount-cents", "12345", "--currency", "USD")
	}
	principal := httptest.NewServer(scenario.Principal)
	t.Cleanup(principal.Close)
	var authUnavailable atomic.Bool
	var auditUnavailable atomic.Bool
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authUnavailable.Load() || (r.URL.Path == "/server/v1/audit/events" && auditUnavailable.Load()) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		scenario.Server.ServeHTTP(w, r)
	}))
	t.Cleanup(auth.Close)
	client, err := invoicesaas.NewAuthClient(invoicesaas.AuthConfig{
		Issuer: scenario.Signer.Issuer(), ServerURL: auth.URL, JWKSURL: principal.URL + "/.well-known/jwks.json",
		ClientID: scenario.ClientID, APIKey: secret.New(scenario.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := invoicesaas.OpenStore(ctx, scenario.BusinessDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := store.StartAudit(ctx, client); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := store.StopAudit(stop); err != nil {
			t.Error(err)
		}
	})
	business := httptest.NewServer((&invoicesaas.API{Store: store, Auth: client}).Handler())
	t.Cleanup(business.Close)
	var parentToken struct {
		AccessToken string `json:"access_token"`
	}
	response := mvpToken(t, scenario.Principal, url.Values{"grant_type": {"agent_key"}, "agent_key": {parentKey}, "resource": {scenario.ClientID}})
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &parentToken) != nil || parentToken.AccessToken == "" {
		t.Fatal("native parent could not obtain the SaaS audience token")
	}
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, business.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "req_mvp_invoice")
		res, err := business.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		payload, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		out := httptest.NewRecorder()
		for key, values := range res.Header {
			out.Header()[key] = values
		}
		out.WriteHeader(res.StatusCode)
		_, _ = out.Write(payload)
		if res.StatusCode >= http.StatusBadRequest {
			t.Logf("Invoice SaaS %s %s status=%d", method, path, res.StatusCode)
		}
		for _, credential := range []string{token, parentKey, scenario.ServerKey} {
			if credential == "" || bytes.Contains(payload, []byte(credential)) {
				t.Error("business response leaked an Auth credential")
			}
		}
		return out
	}
	read := request(http.MethodGet, "/invoices/inv_delegated", childToken, "")
	invoice := mvpData[invoicesaas.Invoice](t, read)
	if invoice.AmountCents != 12345 || invoice.Status != "draft" || read.Header().Get("X-Auth-Decision-Id") == "" {
		t.Fatal("SaaS did not read the persisted resource under delegated authority")
	}
	outside := request(http.MethodGet, "/invoices/inv_other?group_id="+projectID, childToken, "")
	if outside.Code != http.StatusForbidden || !strings.Contains(outside.Body.String(), "SCOPE_OUT_OF_BOUNDS") {
		t.Fatal("SaaS accepted a client-supplied resource group outside delegated authority")
	}
	if denied := request(http.MethodPost, "/invoices/inv_approve/approve", childToken, `{"expected_version":1}`); denied.Code != http.StatusForbidden {
		t.Fatal("read-only child could approve an invoice")
	}
	first := request(http.MethodPost, "/invoices/inv_approve/approve", parentToken.AccessToken, `{"expected_version":1}`)
	var pending struct {
		Error struct {
			Code    string
			Details struct {
				ApprovalID    string `json:"approval_id"`
				RequestDigest string `json:"request_digest"`
			} `json:"details"`
		} `json:"error"`
	}
	if first.Code != http.StatusForbidden || json.Unmarshal(first.Body.Bytes(), &pending) != nil || pending.Error.Code != "APPROVAL_REQUIRED" || pending.Error.Details.ApprovalID == "" {
		t.Fatalf("SaaS high-risk action did not create an approval: status=%d", first.Code)
	}
	inbox := mvpData[[]approval.InboxRequest](t, mvpJSON(t, scenario.Principal, http.MethodGet, "/v1/approvals", scenario.UserToken, nil))
	var item approval.InboxRequest
	for _, entry := range inbox {
		if entry.ID == pending.Error.Details.ApprovalID {
			item = entry
		}
	}
	if item.ID == "" || item.RequestDigest != pending.Error.Details.RequestDigest || item.Resource.GroupID != projectID ||
		item.Resource.ID != "inv_approve" || !strings.Contains(item.Reason, "12345 minor units USD, version 1") ||
		len(item.DelegationChain) != 2 || item.DelegationChain[0].ID != parentID || item.DelegationChain[1].ID != scenario.UserMemberID {
		t.Fatal("human approval inbox lost the persisted invoice request or its owner chain")
	}
	mvpData[json.RawMessage](t, mvpJSON(t, scenario.Principal, http.MethodPost, "/v1/auth/step-up", scenario.UserToken, map[string]any{
		"mfa_code": scenario.MFACode(), "operation": "approvals.approve", "request": map[string]string{"approval_id": item.ID},
	}))
	mvpData[json.RawMessage](t, mvpJSON(t, scenario.Principal, http.MethodPost, "/v1/approvals/"+item.ID+"/approve", scenario.UserToken, nil))
	// A central audit outage must not lose a committed business event. The
	// SaaS keeps the event in its own transaction, then River resumes delivery.
	auditUnavailable.Store(true)
	results := make(chan *httptest.ResponseRecorder, 4)
	var concurrent sync.WaitGroup
	for range 4 {
		concurrent.Go(func() {
			results <- request(http.MethodPost, "/invoices/inv_approve/approve", parentToken.AccessToken, `{"expected_version":1}`)
		})
	}
	concurrent.Wait()
	close(results)
	allowed := 0
	for result := range results {
		if result.Code == http.StatusOK {
			allowed++
			approved := mvpData[invoicesaas.Invoice](t, result)
			if approved.Status != "approved" || approved.Version != 2 || approved.ApprovedBy != parentID {
				t.Fatal("approved invoice omitted the durable business change and authenticated actor")
			}
		} else if result.Code != http.StatusForbidden {
			t.Fatalf("concurrent SaaS approval status=%d", result.Code)
		}
	}
	if allowed != 1 {
		t.Fatalf("one human approval executed %d SaaS operations", allowed)
	}
	queued, err := store.AuditStatus(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	queuedSuccess := 0
	for _, event := range queued {
		if event.InvoiceID == "inv_approve" && event.Outcome == "success" {
			queuedSuccess++
			if event.State != "pending" || event.AuditID != "" {
				t.Fatal("unavailable central audit was treated as a confirmed delivery")
			}
		}
	}
	if queuedSuccess != 1 {
		t.Fatal("successful business commit did not durably enqueue exactly one audit")
	}
	auditUnavailable.Store(false)
	if replay := request(http.MethodPost, "/invoices/inv_approve/approve", parentToken.AccessToken, `{"expected_version":1}`); replay.Code != http.StatusForbidden {
		t.Fatal("SaaS replay reused a consumed approval")
	}
	authUnavailable.Store(true)
	if failed := request(http.MethodPost, "/invoices/inv_unavailable/approve", parentToken.AccessToken, `{"expected_version":1}`); failed.Code != http.StatusServiceUnavailable {
		t.Fatal("SaaS did not fail closed when Auth was unavailable")
	}
	authUnavailable.Store(false)
	unchanged := mvpData[invoicesaas.Invoice](t, request(http.MethodGet, "/invoices/inv_unavailable", childToken, ""))
	if unchanged.Status != "draft" || unchanged.Version != 1 {
		t.Fatal("Auth outage mutated the SaaS database")
	}
	for _, action := range []string{"approval.create", "approval.approved", "approval.consume"} {
		events := mvpData[[]audit.Event](t, mvpJSON(t, scenario.Principal, http.MethodGet,
			"/v1/spaces/"+scenario.SpaceID+"/audit-logs?"+url.Values{"member_id": {parentID}, "action": {action}}.Encode(), scenario.UserToken, nil))
		matched := 0
		for _, event := range events {
			if event.ResourceID == item.ID {
				matched++
				if event.ResourceGroupID != projectID || !strings.Contains(string(event.Metadata), item.RequestDigest) {
					t.Fatalf("SaaS %s audit lost its business resource or request digest", action)
				}
			}
		}
		if matched != 1 {
			t.Fatalf("SaaS %s audit matched its approved request %d times among %d records", action, matched, len(events))
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		events := mvpData[[]audit.Event](t, mvpJSON(t, scenario.Principal, http.MethodGet,
			"/v1/spaces/"+scenario.SpaceID+"/audit-logs?"+url.Values{"member_id": {parentID}, "action": {"invoice.approve"}}.Encode(), scenario.UserToken, nil))
		matched := 0
		for _, event := range events {
			if event.ResourceID == "inv_approve" && event.Outcome == "success" {
				matched++
				var metadata struct {
					SubjectSource string `json:"subject_source"`
				}
				if json.Unmarshal(event.Metadata, &metadata) != nil || event.MemberID != parentID || event.ResourceGroupID != projectID || event.RequestID != "req_mvp_invoice" ||
					len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != scenario.UserMemberID ||
					metadata.SubjectSource != "application_assertion" || event.DecisionID != "" {
					t.Fatal("reported SaaS success lost its resource, identity, owner chain or provenance")
				}
			}
		}
		if matched == 1 {
			break
		}
		if matched > 1 || time.Now().After(deadline) {
			t.Fatalf("SaaS audit delivery matched %d successful business events", matched)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return func() {
		t.Helper()
		denied := request(http.MethodGet, "/invoices/inv_delegated", childToken, "")
		var body struct {
			Error struct {
				Code    string
				Details struct {
					DecisionID string `json:"decision_id"`
				}
			}
		}
		if denied.Code != http.StatusForbidden || json.Unmarshal(denied.Body.Bytes(), &body) != nil ||
			body.Error.Code != "OWNER_ENVELOPE_EXCLUDED" || body.Error.Details.DecisionID == "" {
			t.Fatal("SaaS continued accepting its cached child JWT after upstream revocation")
		}
		events := mvpData[[]audit.Event](t, mvpJSON(t, scenario.Principal, http.MethodGet,
			"/v1/spaces/"+scenario.SpaceID+"/audit-logs?decision_id="+url.QueryEscape(body.Error.Details.DecisionID), scenario.UserToken, nil))
		if len(events) != 1 || events[0].RequestID != "req_mvp_invoice" || events[0].DenyCode != "OWNER_ENVELOPE_EXCLUDED" ||
			events[0].ResourceID != "inv_delegated" || events[0].ResourceGroupID != projectID || len(events[0].OwnerChain) != 2 {
			t.Fatal("SaaS denial could not be correlated with the public delegation audit")
		}
	}
}
