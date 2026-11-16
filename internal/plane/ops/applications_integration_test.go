package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp/totp"
)

func TestPublicApplicationReviewRequiresCapabilityAndRequestBoundStepUp(t *testing.T) {
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
	key := []byte(strings.Repeat("r", 32))
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	svc, err := operator.New(st, factors, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	createOpsTestUser(t, st, "usr_app_reviewer", `["ops:applications:manage","ops:session"]`)
	createOpsTestUser(t, st, "usr_app_unrelated", `["ops:users:manage"]`)
	reviewerToken, reviewerSession := createOpsTestSession(t, st, key, "usr_app_reviewer", "r")
	unrelatedToken, unrelatedSession := createOpsTestSession(t, st, key, "usr_app_unrelated", "u")
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_public_review', 'Publisher', 'public-review')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"app_public_review", "app_public_reject"} {
		if _, err := st.Pool.Exec(ctx, `
			INSERT INTO applications (id, space_id, name, client_id, visibility, review_status, pending_manifest_permissions)
			VALUES ($1, 'spc_public_review', 'Public App', $1, 'public', 'pending', '["auth.authz:check","auth.tokens:introspect"]'::jsonb)
		`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, client_id, visibility, review_status, pending_manifest_permissions)
		VALUES ('app_public_audit', 'spc_public_review', 'Audit Rollback', 'app_public_audit',
		        'public', 'pending', '["auth.authz:check"]'::jsonb)
	`); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Operators: svc}).Register(humago.New(mux, route.HumaConfig("public application review", "1.0.0")))
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, r)
		return out
	}
	stepUpReview := func(operation string, value any) {
		t.Helper()
		enrollment, err := factors.EnrollTOTPForUser(ctx, "usr_app_reviewer", "reviewer@example.test", operation)
		if err != nil {
			t.Fatal(err)
		}
		code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]any{"mfa_code": code, "operation": operation, "request": value})
		if err != nil {
			t.Fatal(err)
		}
		if got := request(http.MethodPost, "/ops/v1/auth/step-up", reviewerToken, string(body)); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"accepted":true`) {
			t.Fatalf("review step-up %s = %d %s", operation, got.Code, got.Body.String())
		}
	}
	path := "/ops/v1/applications/app_public_review/approve"
	body := `{"manifest_permissions":["auth.authz:check"]}`
	if got := request(http.MethodGet, "/ops/v1/applications", reviewerToken, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"review_status":"pending"`) {
		t.Fatalf("pending review listing = %d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, path, reviewerToken, body); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("approval without step-up = %d %s", got.Code, got.Body.String())
	}
	seedPublicReviewStepUp(t, st, unrelatedSession, "ops.applications.approve", map[string]any{"application_id": "app_public_review", "manifest_permissions": []string{"auth.authz:check"}})
	if got := request(http.MethodPost, path, unrelatedToken, body); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "PERMISSION_DENIED") {
		t.Fatalf("approval without capability = %d %s", got.Code, got.Body.String())
	}
	seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.approve", map[string]any{"application_id": "app_public_review", "manifest_permissions": []string{"auth.tokens:introspect"}})
	if got := request(http.MethodPost, path, reviewerToken, body); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("approval with wrong request digest = %d %s", got.Code, got.Body.String())
	}
	seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.approve", map[string]any{"application_id": "app_public_review", "manifest_permissions": []string{"auth.authz:check"}})
	if got := request(http.MethodPost, path, reviewerToken, `{"manifest_permissions":["auth.agents:create"]}`); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("different approved subset reused step-up = %d %s", got.Code, got.Body.String())
	}
	seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.approve", map[string]any{"application_id": "app_public_review", "manifest_permissions": []string{"auth.agents:create"}})
	if got := request(http.MethodPost, path, reviewerToken, `{"manifest_permissions":["auth.agents:create"]}`); got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("approval outside requested manifest = %d %s", got.Code, got.Body.String())
	}
	stepUpReview("ops.applications.approve", map[string]any{"application_id": "app_public_review", "manifest_permissions": []string{"auth.authz:check"}})
	if got := request(http.MethodPost, path, reviewerToken, body); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"review_status":"approved"`) {
		t.Fatalf("approved trimmed manifest = %d %s", got.Code, got.Body.String())
	}
	var approved, pending string
	if err := st.Pool.QueryRow(ctx, `SELECT manifest_permissions::text, COALESCE(pending_manifest_permissions::text, '') FROM applications WHERE id = 'app_public_review'`).Scan(&approved, &pending); err != nil || approved != `["auth.authz:check"]` || pending != "" {
		t.Fatalf("published manifest = %q pending = %q error = %v", approved, pending, err)
	}
	if got := request(http.MethodPost, path, reviewerToken, body); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("approval proof reused = %d %s", got.Code, got.Body.String())
	}
	rejectPath := "/ops/v1/applications/app_public_reject/reject"
	stepUpReview("ops.applications.reject", map[string]any{"application_id": "app_public_reject"})
	if got := request(http.MethodPost, rejectPath, reviewerToken, ""); got.Code != http.StatusOK {
		t.Fatalf("rejected application = %d %s", got.Code, got.Body.String())
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT review_status FROM applications WHERE id = 'app_public_reject'`).Scan(&status); err != nil || status != "rejected" {
		t.Fatalf("rejected review status = %q error = %v", status, err)
	}
	var auditCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('ops.application.approve', 'ops.application.reject') AND outcome = 'success'`).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("review audit count = %d error = %v", auditCount, err)
	}
	admin, err := pgx.Connect(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := admin.Exec(ctx, `
		CREATE FUNCTION reject_public_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'ops.application.approve' THEN RAISE EXCEPTION 'review audit unavailable'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_public_review_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_public_review_audit();
	`); err != nil {
		t.Fatal(err)
	}
	seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.approve", map[string]any{
		"application_id": "app_public_audit", "manifest_permissions": []string{"auth.authz:check"},
	})
	if got := request(http.MethodPost, "/ops/v1/applications/app_public_audit/approve", reviewerToken, body); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("approval without audit durability = %d %s", got.Code, got.Body.String())
	}
	var pendingStatus, effectiveManifest string
	if err := st.Pool.QueryRow(ctx, `SELECT review_status, manifest_permissions::text FROM applications WHERE id = 'app_public_audit'`).Scan(&pendingStatus, &effectiveManifest); err != nil || pendingStatus != "pending" || effectiveManifest != "[]" {
		t.Fatalf("failed review persisted status=%q manifest=%q error=%v", pendingStatus, effectiveManifest, err)
	}
	t.Run("GlobalSuspensionRequiresCapabilityAndRequestBoundMFA", func(t *testing.T) {
		path := "/ops/v1/applications/app_public_review/suspend"
		value := map[string]any{"application_id": "app_public_review"}
		for _, test := range []struct {
			token  string
			status int
		}{{reviewerToken, http.StatusForbidden}, {"ply_ag_wrong_plane", http.StatusUnauthorized}} {
			got := request(http.MethodPost, path, test.token, "")
			if got.Code != test.status {
				t.Fatalf("suspension without valid operations step-up status=%d", got.Code)
			}
		}
		seedPublicReviewStepUp(t, st, unrelatedSession, "ops.applications.suspend", value)
		if got := request(http.MethodPost, path, unrelatedToken, ""); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "PERMISSION_DENIED") {
			t.Fatalf("suspension without capability status=%d", got.Code)
		}
		seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.suspend", map[string]string{"application_id": "app_public_reject"})
		if got := request(http.MethodPost, path, reviewerToken, ""); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
			t.Fatalf("suspension reused a different target's MFA status=%d", got.Code)
		}
		seedPublicReviewStepUp(t, st, reviewerSession, "ops.applications.suspend", map[string]string{"application_id": "app_missing"})
		if got := request(http.MethodPost, "/ops/v1/applications/app_missing/suspend", reviewerToken, ""); got.Code != http.StatusNotFound {
			t.Fatalf("missing application suspension status=%d", got.Code)
		}
		stepUpReview("ops.applications.suspend", value)
		if got := request(http.MethodPost, path, reviewerToken, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"accepted":true`) {
			t.Fatalf("single operator suspension status=%d", got.Code)
		}
		if got := request(http.MethodPost, path, reviewerToken, ""); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
			t.Fatalf("suspension reused consumed MFA status=%d", got.Code)
		}
		var stopped, other string
		if err := st.Pool.QueryRow(ctx, `SELECT a.status, b.status FROM applications a CROSS JOIN applications b
			WHERE a.id = 'app_public_review' AND b.id = 'app_public_reject'`).Scan(&stopped, &other); err != nil || stopped != "suspended" || other != "active" {
			t.Fatalf("global suspension status=%s other=%s error=%v", stopped, other, err)
		}
	})
}

func seedPublicReviewStepUp(t *testing.T, st *store.Store, sessionID, operation string, value any) {
	t.Helper()
	digest, err := canonicalDigestValue(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(context.Background(), `
		UPDATE operator_sessions SET step_up_operation = $1, step_up_digest = $2,
		step_up_expires_at = now() + interval '5 minutes' WHERE id = $3
	`, operation, digest, sessionID); err != nil {
		t.Fatal(err)
	}
}
