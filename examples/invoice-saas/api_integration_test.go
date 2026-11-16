package invoicesaas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/plystra/auth/examples/invoice-saas/internal/db"
	"github.com/plystra/auth/internal/testdb"
)

func TestInvoiceSaaSPostgresAndHTTP(t *testing.T) {
	ctx := context.Background()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.CloneEmpty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	for range 2 {
		if err := Migrate(ctx, database.URL); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStore(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var isolated bool
	if err := store.pool.QueryRow(ctx, `SELECT to_regclass('users') IS NULL AND to_regclass('invoices') IS NOT NULL`).Scan(&isolated); err != nil || !isolated {
		t.Fatal("SaaS migration did not produce an independent business database")
	}
	t.Run("SQLCQueriesPrepareAgainstBusinessDatabase", func(t *testing.T) {
		cmd := exec.CommandContext(ctx, "go", "tool", "sqlc", "vet", "-f", "sqlc.yaml")
		cmd.Env = append(os.Environ(), "INVOICE_SAAS_SQLC_DATABASE_URL="+database.URL)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("SaaS SQL preparation failed: %v\n%s", err, output)
		}
	})
	t.Run("SeedRejectsInvalidBusinessFacts", func(t *testing.T) {
		for _, item := range []struct {
			id, space, group, currency string
			amount                     int64
		}{
			{"wrong_prefix", "spc_customer", "grp_project", "USD", 100},
			{"inv_space", "grp_customer", "grp_project", "USD", 100},
			{"inv_group", "spc_customer", "spc_project", "USD", 100},
			{"inv_amount", "spc_customer", "grp_project", "USD", 0},
			{"inv_currency", "spc_customer", "grp_project", "usd", 100},
		} {
			if err := store.Seed(ctx, item.id, item.space, item.group, item.amount, item.currency); err == nil {
				t.Fatalf("invalid invoice accepted: %s", item.id)
			}
		}
	})
	if err := store.Seed(ctx, "inv_demo", "spc_customer", "grp_project", 12345, "USD"); err != nil {
		t.Fatal(err)
	}
	if err := store.Seed(ctx, "inv_demo", "spc_customer", "grp_project", 99999, "USD"); err == nil {
		t.Fatal("duplicate seed overwrote an existing business resource")
	}

	signer := exampleSigner(t)
	var reply atomic.Value
	reply.Store(`{"data":{"decision":"allow","decision_id":"dec_example"}}`)
	var checks, approvals atomic.Int64
	var observedMu sync.Mutex
	var observedCheck, observedApproval checkRequest
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			writeKeys(t, w, signer)
			return
		}
		if r.Header.Get("Authorization") != "Bearer example-server-key" || r.Header.Get("X-Request-Id") != "req_invoice_test" {
			t.Error("Auth request omitted the server credential or request correlation")
		}
		var input checkRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error("invalid Auth request body")
		}
		observedMu.Lock()
		defer observedMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/server/v1/authz/check":
			checks.Add(1)
			observedCheck = input
			body := reply.Load().(string)
			if body == "unavailable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				body = `{"error":{"code":"UNAVAILABLE","message":"example-server-key"}}`
			}
			_, _ = w.Write([]byte(body))
		case "/server/v1/approvals":
			approvals.Add(1)
			observedApproval = input
			_, _ = w.Write([]byte(`{"data":{"id":"apr_example"}}`))
		default:
			t.Error("unexpected Auth endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(auth.Close)
	api := (&API{Store: store, Auth: exampleClient(t, auth.URL)}).Handler()
	business := httptest.NewServer(api)
	t.Cleanup(business.Close)
	token := signExample(t, signer, exampleClaims())
	request := func(method, path, bearer, body string) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, business.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "req_invoice_test")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		response, err := business.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{token, "example-server-key"} {
			if bytes.Contains(payload, []byte(value)) {
				t.Error("SaaS response leaked an Auth credential")
			}
		}
		return response.StatusCode, response.Header, payload
	}
	assertDraft := func(t *testing.T) {
		t.Helper()
		row, err := store.queries.GetInvoice(ctx, db.GetInvoiceParams{ID: "inv_demo"})
		if err != nil || row.Status != "draft" || row.Version != 1 || row.ApprovedBy.Valid {
			t.Fatal("denied or unavailable authorization changed the invoice")
		}
	}
	t.Run("ReadUsesStoredResourceFacts", func(t *testing.T) {
		status, header, payload := request(http.MethodGet, "/invoices/inv_demo?group_id=grp_attacker", token, "")
		if status != http.StatusOK || header.Get("X-Auth-Decision-Id") != "dec_example" || !bytes.Contains(payload, []byte(`"amount_cents":12345`)) {
			t.Fatalf("invoice read status=%d", status)
		}
		observedMu.Lock()
		defer observedMu.Unlock()
		if observedCheck.Action != "invoice:read" || observedCheck.Subject.Token != token ||
			observedCheck.Resource != (resource{Type: "invoice", ID: "inv_demo", SpaceID: "spc_customer", GroupID: "grp_project"}) {
			t.Fatal("client-supplied target replaced authoritative business facts")
		}
	})
	t.Run("InvalidIdentityDoesNotCallAuthz", func(t *testing.T) {
		before := checks.Load()
		wrongAudience := exampleClaims()
		wrongAudience.Audience = "other-app"
		for _, bearer := range []string{"", "not-a-token", signExample(t, signer, wrongAudience)} {
			status, _, _ := request(http.MethodPost, "/invoices/inv_demo/approve", bearer, `{"expected_version":1}`)
			if status != http.StatusUnauthorized {
				t.Fatalf("invalid identity status=%d", status)
			}
		}
		if checks.Load() != before {
			t.Fatal("invalid identity reached Auth's judgment API")
		}
		assertDraft(t)
	})
	t.Run("RejectsClientResourceFacts", func(t *testing.T) {
		status, _, _ := request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1,"space_id":"spc_attacker"}`)
		if status < 400 || status >= 500 {
			t.Fatalf("unknown business field status=%d", status)
		}
		assertDraft(t)
	})
	t.Run("UnavailableOrMalformedAuthFailsClosed", func(t *testing.T) {
		for _, body := range []string{"unavailable", `not JSON`, `{}`, `{"data":{"decision":"allow"}}`,
			`{"data":{"decision":"allow","decision_id":"dec_bad","deny_code":"PERMISSION_DENIED"}}`,
			`{"data":{"decision":"deny","decision_id":"dec_bad"}}`, strings.Repeat(" ", 1<<20+1)} {
			reply.Store(body)
			status, _, _ := request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1}`)
			if status != http.StatusServiceUnavailable {
				t.Fatalf("invalid Auth response status=%d", status)
			}
			assertDraft(t)
		}
	})
	t.Run("DeniedPermissionPreservesDecisionAndInvoice", func(t *testing.T) {
		reply.Store(`{"data":{"decision":"deny","decision_id":"dec_denied","deny_code":"OWNER_ENVELOPE_EXCLUDED"}}`)
		status, header, payload := request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1}`)
		if status != http.StatusForbidden || header.Get("X-Request-Id") != "req_invoice_test" || !bytes.Contains(payload, []byte(`"decision_id":"dec_denied"`)) {
			t.Fatal("denied operation lost its correlation IDs")
		}
		assertDraft(t)
	})
	t.Run("ApprovalDigestUsesStoredInvoice", func(t *testing.T) {
		reply.Store(`{"data":{"decision":"deny","decision_id":"dec_approval","deny_code":"APPROVAL_REQUIRED"}}`)
		status, _, payload := request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1}`)
		if status != http.StatusForbidden || !bytes.Contains(payload, []byte(`"approval_id":"apr_example"`)) {
			t.Fatal("high-risk operation did not return the created approval")
		}
		sum := sha256.Sum256([]byte(`{"action":"invoice:approve","invoice_id":"inv_demo","version":1,"amount_cents":12345,"currency":"USD"}`))
		observedMu.Lock()
		input := observedApproval
		observedMu.Unlock()
		if input.RequestDigest != hex.EncodeToString(sum[:]) || input.Resource.GroupID != "grp_project" || input.Subject.Token != token ||
			!strings.Contains(input.Reason, "12345 minor units USD, version 1") {
			t.Fatal("approval did not describe the actual business request")
		}
		before := approvals.Load()
		reply.Store(`{"data":{"decision":"deny","decision_id":"dec_pending","deny_code":"APPROVAL_PENDING"}}`)
		status, _, _ = request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1}`)
		if status != http.StatusForbidden || approvals.Load() != before {
			t.Fatal("pending approval was duplicated or allowed")
		}
		assertDraft(t)
	})
	t.Run("ConcurrentApprovalUpdatesInvoiceOnce", func(t *testing.T) {
		reply.Store(`{"data":{"decision":"allow","decision_id":"dec_approved"}}`)
		results := make(chan int, 8)
		var requests sync.WaitGroup
		for range 8 {
			requests.Go(func() {
				status, _, _ := request(http.MethodPost, "/invoices/inv_demo/approve", token, `{"expected_version":1}`)
				results <- status
			})
		}
		requests.Wait()
		close(results)
		allowed := 0
		for status := range results {
			if status == http.StatusOK {
				allowed++
			} else if status != http.StatusConflict {
				t.Fatalf("unexpected concurrent mutation status=%d", status)
			}
		}
		row, err := store.queries.GetInvoice(ctx, db.GetInvoiceParams{ID: "inv_demo"})
		if err != nil || allowed != 1 || row.Version != 2 || row.Status != "approved" || row.ApprovedBy.String != "mem_agent" || !row.ApprovedAt.Valid {
			t.Fatal("invoice was not durably approved exactly once by the authenticated member")
		}
	})
	t.Run("CLIUsesIndependentDatabase", func(t *testing.T) {
		binary := filepath.Join(t.TempDir(), "invoice-saas.exe")
		build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/invoice-saas")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build SaaS CLI: %v\n%s", err, output)
		}
		for _, args := range [][]string{{"migrate"}, {"seed", "--id", "inv_cli", "--space-id", "spc_customer", "--group-id", "grp_project", "--amount-cents", "456", "--currency", "EUR"}} {
			command := exec.CommandContext(ctx, binary, args...)
			command.Env = append(os.Environ(), "INVOICE_SAAS_DATABASE_URL="+database.URL)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("SaaS CLI %s: %v\n%s", args[0], err, output)
			}
		}
		row, err := store.queries.GetInvoice(ctx, db.GetInvoiceParams{ID: "inv_cli"})
		if err != nil || row.AmountCents != 456 || row.Currency != "EUR" {
			t.Fatal("public CLI did not persist the seeded invoice")
		}
	})
}
