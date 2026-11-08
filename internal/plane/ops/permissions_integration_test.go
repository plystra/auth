package ops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

func TestOpsPermissionCatalogCreateListAndEnforceStepUp(t *testing.T) {
	ctx := context.Background()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	admin, err := pgx.Connect(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	key := []byte(strings.Repeat("k", 32))
	svc, err := operator.New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	createOpsTestUser(t, st, "usr_catalog_manager", `["ops:permissions:manage"]`)
	createOpsTestUser(t, st, "usr_catalog_other", `["ops:users:manage"]`)
	managerToken, managerSession := createOpsTestSession(t, st, key, "usr_catalog_manager", "m")
	otherToken, otherSession := createOpsTestSession(t, st, key, "usr_catalog_other", "o")
	mux := http.NewServeMux()
	(&API{Operators: svc}).Register(humago.New(mux, route.HumaConfig("ops catalog test", "1.0.0")))
	body := `{"key":"invoice:approve","description":"Approve an invoice","risk":"critical","principal_kinds":["human","agent"]}`
	request := operator.CreatePermissionInput{Key: "invoice:approve", Description: "Approve an invoice", Risk: "critical", PrincipalKinds: []string{"human", "agent"}}

	if response := opsPermissionRequest(t, mux, http.MethodPost, managerToken, body); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("creation without step-up = %d %s", response.Code, response.Body.String())
	}
	seedOpsPermissionStepUp(t, st, otherSession, request)
	if response := opsPermissionRequest(t, mux, http.MethodPost, otherToken, body); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "PERMISSION_DENIED") {
		t.Fatalf("creation without catalog capability = %d %s", response.Code, response.Body.String())
	}
	var versionBefore int64
	if err := st.Pool.QueryRow(ctx, `SELECT version FROM authorization_policy_state WHERE id = true`).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	seedOpsPermissionStepUp(t, st, managerSession, request)
	created := opsPermissionRequest(t, mux, http.MethodPost, managerToken, body)
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"agent_approval":"required"`) || !strings.Contains(created.Body.String(), `"status":"active"`) {
		t.Fatalf("critical business permission = %d %s", created.Code, created.Body.String())
	}
	var payload struct {
		Data operator.Permission `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(payload.Data.ID, "prm_") || payload.Data.Key != request.Key || payload.Data.Delegable != true || len(payload.Data.PrincipalKinds) != 2 {
		t.Fatalf("created permission metadata is incomplete: %+v", payload.Data)
	}
	var versionAfter int64
	if err := st.Pool.QueryRow(ctx, `SELECT version FROM authorization_policy_state WHERE id = true`).Scan(&versionAfter); err != nil || versionAfter <= versionBefore {
		t.Fatalf("catalog version = %d, before %d, error %v", versionAfter, versionBefore, err)
	}
	var auditCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'ops.permission.create' AND resource_id = $1 AND outcome = 'success'`, payload.Data.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("permission audit count = %d, error %v", auditCount, err)
	}
	if response := opsPermissionRequest(t, mux, http.MethodPost, managerToken, body); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("step-up proof reused = %d %s", response.Code, response.Body.String())
	}
	seedOpsPermissionStepUp(t, st, managerSession, request)
	if response := opsPermissionRequest(t, mux, http.MethodPost, managerToken, body); response.Code != http.StatusConflict {
		t.Fatalf("duplicate key = %d %s", response.Code, response.Body.String())
	}
	if response := opsPermissionRequest(t, mux, http.MethodPost, managerToken, `{"key":"auth.fake:manage"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("reserved permission prefix = %d %s", response.Code, response.Body.String())
	}
	listed := opsPermissionRequest(t, mux, http.MethodGet, managerToken, "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"key":"invoice:approve"`) {
		t.Fatalf("permission listing = %d %s", listed.Code, listed.Body.String())
	}

	if _, err := admin.Exec(ctx, `
		CREATE FUNCTION reject_catalog_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'catalog audit unavailable'; END;
		$$;
		CREATE TRIGGER reject_catalog_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_catalog_audit_insert();
	`); err != nil {
		t.Fatal(err)
	}
	rollbackRequest := operator.CreatePermissionInput{Key: "invoice:read"}
	seedOpsPermissionStepUp(t, st, managerSession, rollbackRequest)
	failed := opsPermissionRequest(t, mux, http.MethodPost, managerToken, `{"key":"invoice:read"}`)
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("permission creation with failed audit = %d %s", failed.Code, failed.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE key = 'invoice:read'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("permission survived audit rollback: count=%d error=%v", count, err)
	}
	if _, err := admin.Exec(ctx, `DROP TRIGGER reject_catalog_audit ON audit_logs; DROP FUNCTION reject_catalog_audit_insert()`); err != nil {
		t.Fatal(err)
	}
	if retried := opsPermissionRequest(t, mux, http.MethodPost, managerToken, `{"key":"invoice:read"}`); retried.Code != http.StatusOK {
		t.Fatalf("rolled-back step-up proof was consumed: %d %s", retried.Code, retried.Body.String())
	}
}

func createOpsTestUser(t *testing.T, st *store.Store, userID, capabilities string) {
	t.Helper()
	if _, err := st.Pool.Exec(context.Background(), `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, 'test-only-password-hash', 'active')
	`, userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `INSERT INTO operators (user_id, capabilities) VALUES ($1, $2::jsonb)`, userID, capabilities); err != nil {
		t.Fatal(err)
	}
}

func createOpsTestSession(t *testing.T, st *store.Store, key []byte, userID, marker string) (string, string) {
	t.Helper()
	raw := "ply_ops_" + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(marker, 32)))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("operator-session:" + raw))
	sessionID := string(ids.New[ids.OperatorSessionID]("ops"))
	if _, err := st.Pool.Exec(context.Background(), `
		INSERT INTO operator_sessions (id, user_id, token_hash, expires_at, idle_expires_at, access_expires_at, assurance_level)
		VALUES ($1, $2, $3, now() + interval '8 hours', now() + interval '30 minutes', now() + interval '10 minutes', 2)
	`, sessionID, userID, mac.Sum(nil)); err != nil {
		t.Fatal(err)
	}
	return raw, sessionID
}

func seedOpsPermissionStepUp(t *testing.T, st *store.Store, sessionID string, in operator.CreatePermissionInput) {
	t.Helper()
	digest, err := canonicalDigestValue(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `
		UPDATE operator_sessions SET step_up_operation = 'ops.permissions.create', step_up_digest = $1,
		step_up_expires_at = now() + interval '5 minutes' WHERE id = $2
	`, digest, sessionID); err != nil {
		t.Fatal(err)
	}
}

func opsPermissionRequest(t *testing.T, handler http.Handler, method, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "/ops/v1/permissions", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
