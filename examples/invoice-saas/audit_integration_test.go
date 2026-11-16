package invoicesaas

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

	"github.com/plystra/auth/examples/invoice-saas/internal/db"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/testdb"
	"github.com/riverqueue/river"
)

func TestInvoiceSaaSAuditOutbox(t *testing.T) {
	ctx := context.Background()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(ctx) })
	fixture := func(t *testing.T, report http.HandlerFunc) *auditFixture {
		t.Helper()
		database, err := harness.CloneEmpty(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close(ctx) })
		if err := Migrate(ctx, database.URL); err != nil {
			t.Fatal(err)
		}
		st, err := OpenStore(ctx, database.URL)
		if err != nil {
			t.Fatal(err)
		}
		f := &auditFixture{t: t, store: st, databaseURL: database.URL}
		t.Cleanup(func() { f.store.Close() })
		if err := st.Seed(ctx, "inv_audit", "spc_customer", "grp_project", 12345, "USD"); err != nil {
			t.Fatal(err)
		}
		signer := exampleSigner(t)
		f.signer = signer
		auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/jwks.json":
				writeKeys(t, w, signer)
			case "/server/v1/authz/check":
				_, _ = w.Write([]byte(`{"data":{"decision":"allow","decision_id":"dec_example"}}`))
			case "/server/v1/audit/events":
				if r.Header.Get("Authorization") != "Bearer example-server-key" || r.Header.Get("X-Request-Id") != "req_audit_test" {
					t.Error("audit report lost its credential or correlation")
				}
				report(w, r)
			default:
				t.Error("unexpected Auth request")
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(auth.Close)
		f.auth = exampleClient(t, auth.URL)
		f.token = signExample(t, signer, exampleClaims())
		f.handler = (&API{Store: st, Auth: f.auth}).Handler()
		return f
	}

	t.Run("BusinessMutationAndQueueRollbackTogether", func(t *testing.T) {
		f := fixture(t, func(http.ResponseWriter, *http.Request) { t.Error("unstarted worker sent a report") })
		if _, err := f.store.pool.Exec(ctx, `CREATE FUNCTION reject_audit_job() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'queue unavailable'; END $$;
			CREATE TRIGGER reject_audit_job BEFORE INSERT ON river_job FOR EACH ROW EXECUTE FUNCTION reject_audit_job()`); err != nil {
			t.Fatal(err)
		}
		if failed := f.approve(); failed.Code != http.StatusServiceUnavailable || strings.Contains(failed.Body.String(), "queue unavailable") {
			t.Fatalf("queue failure status=%d", failed.Code)
		}
		row, err := f.store.queries.GetInvoice(ctx, db.GetInvoiceParams{ID: "inv_audit"})
		statuses := f.statuses()
		if err != nil || row.Status != "draft" || row.Version != 1 || len(statuses) != 0 {
			t.Fatal("queue failure committed the business mutation or a partial delivery")
		}
		if _, err := f.store.pool.Exec(ctx, `DROP TRIGGER reject_audit_job ON river_job`); err != nil {
			t.Fatal(err)
		}
		if allowed := f.approve(); allowed.Code != http.StatusOK {
			t.Fatalf("recovery status=%d", allowed.Code)
		}
		if conflict := f.approve(); conflict.Code != http.StatusConflict {
			t.Fatalf("repeated approval status=%d", conflict.Code)
		}
		statuses = f.statuses()
		outcomes := make(map[string]int)
		for _, status := range statuses {
			outcomes[status.Outcome]++
		}
		var jobs int
		if err := f.store.pool.QueryRow(ctx, `SELECT count(*) FROM river_job`).Scan(&jobs); err != nil || len(statuses) != 2 || jobs != 2 ||
			outcomes["success"] != 1 || outcomes["failure"] != 1 {
			t.Fatal("business success or conflict lost its durable delivery job")
		}
		f.assertNoCredentials()
	})

	t.Run("HumanIdentityIsRetainedWithoutCredentials", func(t *testing.T) {
		f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			var input auditReport
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Subject.MemberID != "mem_human" || input.Subject.UserID != "usr_customer" {
				t.Error("human report lost its verified member or user identity")
			}
			writeAuditReceipt(w)
		})
		claims := exampleClaims()
		claims.Type, claims.Subject, claims.MemberID = "user", "usr_customer", "mem_human"
		f.token = signExample(t, f.signer, claims)
		f.requireQueued()
		if err := f.work(); err != nil || f.statuses()[0].State != "delivered" {
			t.Fatal("human business operation could not deliver its audit")
		}
		f.assertNoCredentials()
	})

	t.Run("RiverResumesCommittedEventsAfterRestart", func(t *testing.T) {
		var receivedMu sync.Mutex
		var received auditReport
		f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			var input auditReport
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			receivedMu.Lock()
			received = input
			receivedMu.Unlock()
			writeAuditReceipt(w)
		})
		if response := f.approve(); response.Code != http.StatusOK {
			t.Fatalf("approval status=%d", response.Code)
		}
		f.restart()
		if err := f.store.StartAudit(ctx, f.auth); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := f.store.StopAudit(stop); err != nil {
				t.Error(err)
			}
		})
		deadline := time.Now().Add(10 * time.Second)
		for f.statuses()[0].State != "delivered" && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		statuses := f.statuses()
		if statuses[0].State != "delivered" || statuses[0].AuditID != "aud_example" {
			t.Fatal("River did not resume the committed audit after a process restart")
		}
		receivedMu.Lock()
		defer receivedMu.Unlock()
		if received.Subject.MemberID != "mem_agent" || received.Subject.UserID != "" || received.Action != "invoice.approve" || received.Outcome != "success" ||
			received.Resource != (resource{Type: "invoice", ID: "inv_audit", SpaceID: "spc_customer", GroupID: "grp_project"}) || len(received.RequestDigest) != 64 {
			t.Fatal("delivery did not use verified identity and stored business facts")
		}
		f.assertNoCredentials()
	})

	t.Run("LostResponseKeepsIdempotencyKeyAcrossRestart", func(t *testing.T) {
		var mu sync.Mutex
		var keys []string
		f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if len(keys) == 1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
			w.Header().Set("Idempotency-Replayed", "true")
			writeAuditReceipt(w)
		})
		// Avoid net/http transparently retrying a replayable POST on the reused
		// authorization connection, so the durable worker sees the lost reply.
		f.auth.http.Transport = &http.Transport{DisableKeepAlives: true}
		f.requireQueued()
		if err := f.work(); err == nil || f.statuses()[0].State != "pending" {
			t.Fatal("a lost receipt was treated as a confirmed delivery")
		}
		f.restart()
		if err := f.work(); err != nil {
			t.Fatal(err)
		}
		if err := f.work(); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] || f.statuses()[0].AuditID != "aud_example" {
			t.Fatal("ambiguous retry changed its key or resent a confirmed delivery")
		}
	})

	t.Run("OnlyReplayedFailureAdvancesGeneration", func(t *testing.T) {
		var keys []string
		f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if len(keys) < 3 {
				if len(keys) == 2 {
					w.Header().Set("Idempotency-Replayed", "true")
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":{"code":"UNAVAILABLE","message":"example-server-key"}}`))
				return
			}
			writeAuditReceipt(w)
		})
		f.requireQueued()
		for range 2 {
			if err := f.work(); err == nil || strings.Contains(err.Error(), "example-server-key") {
				t.Fatal("failed response was accepted or exposed its content")
			}
		}
		if err := f.work(); err != nil {
			t.Fatal(err)
		}
		if len(keys) != 3 || keys[0] != keys[1] || keys[1] == keys[2] || f.statuses()[0].State != "delivered" {
			t.Fatal("cached failure recovery did not preserve safe retry generations")
		}
	})

	for _, reason := range []string{"IDEMPOTENCY_WINDOW_EXPIRED", "DESTINATION_CHANGED"} {
		t.Run(reason, func(t *testing.T) {
			calls := 0
			f := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusServiceUnavailable)
			})
			f.requireQueued()
			if err := f.work(); err == nil {
				t.Fatal("ambiguous failure was accepted")
			}
			if reason == "IDEMPOTENCY_WINDOW_EXPIRED" {
				if _, err := f.store.pool.Exec(ctx, `UPDATE invoice_audit_deliveries SET attempt_started_at = now() - interval '23 hours'`); err != nil {
					t.Fatal(err)
				}
			} else {
				config := f.auth.config
				config.APIKey = secret.New("rotated-server-key")
				var err error
				f.auth, err = NewAuthClient(config)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := f.work(); err == nil {
				t.Fatal("unsafe retry was accepted")
			}
			status := f.statuses()[0]
			if calls != 1 || status.State != "blocked" || status.LastError != reason || status.AuditID != "" {
				t.Fatal("unsafe retry was sent or not retained for reconciliation")
			}
		})
	}

	t.Run("ExhaustedJobsRemainVisible", func(t *testing.T) {
		f := fixture(t, func(http.ResponseWriter, *http.Request) { t.Error("failed job sent a report") })
		f.requireQueued()
		if _, err := f.store.pool.Exec(ctx, `UPDATE river_job SET state = 'discarded', finalized_at = now()`); err != nil {
			t.Fatal(err)
		}
		status := f.statuses()[0]
		if status.State != "failed" || status.AuditID != "" {
			t.Fatal("exhausted delivery disappeared or was reported as delivered")
		}
	})

	t.Run("MalformedReceiptNeverConfirmsOrChangesKey", func(t *testing.T) {
		var keys []string
		f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if len(keys) == 1 {
				_, _ = w.Write([]byte(`{"data":{"id":"aud_example"}}`))
				return
			}
			writeAuditReceipt(w)
		})
		f.requireQueued()
		if err := f.work(); err == nil || f.statuses()[0].LastError != "INVALID_RECEIPT" {
			t.Fatal("malformed receipt was accepted")
		}
		if err := f.work(); err != nil || keys[0] != keys[1] {
			t.Fatal("malformed receipt changed the retry scope")
		}
	})
}

type auditFixture struct {
	t           *testing.T
	store       *Store
	auth        *AuthClient
	databaseURL string
	token       string
	handler     http.Handler
	signer      *security.Signer
}

func (f *auditFixture) approve() *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/invoices/inv_audit/approve", strings.NewReader(`{"expected_version":1}`))
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req_audit_test")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, req)
	return response
}

func (f *auditFixture) statuses() []AuditDeliveryStatus {
	f.t.Helper()
	rows, err := f.store.AuditStatus(context.Background(), "", 100)
	if err != nil {
		f.t.Fatal(err)
	}
	return rows
}

func (f *auditFixture) requireQueued() {
	f.t.Helper()
	if response := f.approve(); response.Code != http.StatusOK || len(f.statuses()) != 1 {
		f.t.Fatalf("queue approval status=%d", response.Code)
	}
}

func (f *auditFixture) work() error {
	f.t.Helper()
	return (&auditWorker{store: f.store, auth: f.auth}).Work(context.Background(), &river.Job[auditDeliveryArgs]{Args: auditDeliveryArgs{DeliveryID: f.statuses()[0].ID}})
}

func (f *auditFixture) restart() {
	f.t.Helper()
	f.store.Close()
	var err error
	f.store, err = OpenStore(context.Background(), f.databaseURL)
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *auditFixture) assertNoCredentials() {
	f.t.Helper()
	for _, table := range []string{"invoice_audit_deliveries", "river_job"} {
		var serialized string
		if err := f.store.pool.QueryRow(context.Background(), fmt.Sprintf("SELECT coalesce(jsonb_agg(t)::text, '[]') FROM %s t", table)).Scan(&serialized); err != nil {
			f.t.Fatal(err)
		}
		for _, value := range []string{f.token, "example-server-key"} {
			if strings.Contains(serialized, value) {
				f.t.Fatal("durable audit delivery contains credential material")
			}
		}
	}
}

func writeAuditReceipt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":{"id":"aud_example","occurred_at":"2026-11-01T00:00:00Z"}}`))
}
