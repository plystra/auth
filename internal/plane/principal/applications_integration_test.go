package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/pquerna/otp/totp"
)

func TestPrivateApplicationRegistrationAndListingRequireAuthorityAndStepUp(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, actor.ID, actor.ID, "auth.applications:manage")
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions.Factors = factors
	enrollment, err := factors.EnrollTOTPForUser(ctx, "usr_principal_actor", "actor@example.test", "application registration")
	if err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("application registration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/applications", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	const payload = `{"name":"Billing","manifest_permissions":["auth.authz:check"],"redirect_uris":["https://billing.example.test/callback"]}`
	withoutStepUp := post(payload)
	if withoutStepUp.Code != http.StatusForbidden || !strings.Contains(withoutStepUp.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("registration without step-up = %d %s", withoutStepUp.Code, withoutStepUp.Body.String())
	}
	stepUpRequest := map[string]any{
		"space_id": spaceID, "name": "Billing", "manifest_permissions": []string{"auth.authz:check"},
		"redirect_uris": []string{"https://billing.example.test/callback"},
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	stepBody, err := json.Marshal(map[string]any{"mfa_code": code, "operation": "applications.register", "request": stepUpRequest})
	if err != nil {
		t.Fatal(err)
	}
	stepRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/step-up", strings.NewReader(string(stepBody)))
	stepRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	stepRequest.Header.Set("Content-Type", "application/json")
	stepped := httptest.NewRecorder()
	handler.ServeHTTP(stepped, stepRequest)
	if stepped.Code != http.StatusOK || !strings.Contains(stepped.Body.String(), `"accepted":true`) {
		t.Fatalf("application registration step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	created := post(payload)
	if created.Code != http.StatusOK {
		t.Fatalf("registered application = %d %s", created.Code, created.Body.String())
	}
	var result struct {
		Data application.PublishedApplication `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Data.ID, "app_") || result.Data.ClientID != result.Data.ID || result.Data.Visibility != "private" || result.Data.Status != "active" ||
		len(result.Data.ManifestPermissions) != 1 || result.Data.ManifestPermissions[0] != "auth.authz:check" {
		t.Fatalf("registered application = %+v", result.Data)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+spaceID+"/applications", nil)
	list.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), result.Data.ID) {
		t.Fatalf("published applications = %d %s", listed.Code, listed.Body.String())
	}
	if duplicate := post(payload); duplicate.Code != http.StatusForbidden || !strings.Contains(duplicate.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("consumed step-up proof was reusable: %d %s", duplicate.Code, duplicate.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.applications:manage'`); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, list)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "PERMISSION_DISABLED") {
		t.Fatalf("disabled management permission still listed apps: %d %s", denied.Code, denied.Body.String())
	}
}

func TestPrivateApplicationRegistrationRejectsBadManifestAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, actor.ID, actor.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("application registration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/applications", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", map[string]any{
		"space_id": spaceID, "name": "Invalid", "manifest_permissions": []string{"unknown:read"},
		"redirect_uris": []string(nil),
	})
	invalid := post(`{"name":"Invalid","manifest_permissions":["unknown:read"]}`)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("unknown manifest permission = %d %s", invalid.Code, invalid.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_application_registration_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.register' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_application_registration_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_application_registration_audit();
	`); err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", map[string]any{
		"space_id": spaceID, "name": "Rollback", "manifest_permissions": []string{"auth.authz:check"},
		"redirect_uris": []string(nil),
	})
	failed := post(`{"name":"Rollback","manifest_permissions":["auth.authz:check"]}`)
	if failed.Code < 500 {
		t.Fatalf("audit failure unexpectedly registered application: %d %s", failed.Code, failed.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM applications WHERE name = 'Rollback' AND space_id = $1`, spaceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("application registration committed despite audit failure")
	}
}

func TestAgentCanRegisterPrivateApplicationOnlyWithinOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: owner.ID, Name: "publisher-agent", ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("application Agent test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	post := func(name string) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"name":"` + name + `","manifest_permissions":["auth.authz:check"]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/applications", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+access.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	withoutOwner := post("Denied")
	if withoutOwner.Code != http.StatusForbidden || !strings.Contains(withoutOwner.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent without owner permission = %d %s", withoutOwner.Code, withoutOwner.Body.String())
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.applications:manage")
	allowed := post("Allowed")
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"name":"Allowed"`) {
		t.Fatalf("Agent registration with owner permission = %d %s", allowed.Code, allowed.Body.String())
	}
}
