package principal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/application"
)

func TestHumanOIDCClientMetadataHonorsPublicReviewAndSuspension(t *testing.T) {
	ctx := t.Context()
	st, _, apps, owner, space, _, _, _ := installationFixture(t, []string{"auth.authz:check"})
	redirects := []string{"https://client.example.test/callback"}
	app, err := apps.Register(ctx, owner, application.RegisterInput{SpaceID: space, Name: "Staff", Visibility: "public",
		RedirectURIs: redirects, ManifestPermissions: []string{}, HumanOIDCEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.OAuthClient(ctx, app.ClientID); err == nil {
		t.Fatal("unreviewed public client was eligible")
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE applications SET review_status='approved', pending_manifest_permissions=NULL WHERE id=$1", app.ID); err != nil {
		t.Fatal(err)
	}
	business := []string{"auth.authz:check"}
	pending, err := apps.Update(ctx, owner, app.ID, application.UpdateInput{ManifestPermissions: &business})
	if err != nil || pending.ReviewStatus != "approved" || !slices.Equal(pending.PendingManifestPermissions, business) {
		t.Fatal("submitting a business manifest invalidated earlier sign-in approval", err)
	}
	client, err := apps.OAuthClient(ctx, app.ClientID)
	if err != nil || !client.HumanOIDCEnabled || len(client.AllowedScopes) != 0 || !slices.Equal(client.RedirectURIs, redirects) {
		t.Fatal("client metadata did not isolate human sign-in from business scopes", err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE applications SET status='suspended' WHERE id=$1", app.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.OAuthClient(ctx, app.ClientID); err == nil {
		t.Fatal("suspended public client was eligible")
	}
}

func TestHumanOIDCRegistrationAndSettingsRequireAuthorizedRequestBoundProof(t *testing.T) {
	ctx := t.Context()
	st, _, _, owner, space, sessions, handler, existing := installationFixture(t, []string{"auth.authz:check"})
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner, nil, "registration", 1)
	if err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err := st.Pool.QueryRow(ctx, "SELECT human_oidc_enabled FROM applications WHERE id=$1", existing).Scan(&enabled); err != nil || enabled {
		t.Fatal("application without explicit opt-in should have human OIDC disabled", err)
	}
	registerPath := "/v1/spaces/" + space + "/applications"
	redirects := []string{"https://client.example.test/callback"}
	register := map[string]any{"name": "Employee Login", "visibility": "public", "redirect_uris": redirects, "manifest_permissions": []string{}}
	post := func(body map[string]any) (int, application.PublishedApplication) {
		t.Helper()
		r := applicationAuditRequest(t, handler, http.MethodPost, registerPath, tokens.AccessToken, "register-login", body)
		var result struct {
			Data application.PublishedApplication
		}
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return r.Code, result.Data
	}
	if status, _ := post(register); status != http.StatusBadRequest {
		t.Fatalf("empty manifest without human sign-in = %d", status)
	}
	proof := map[string]any{"space_id": space, "name": "Employee Login", "visibility": "public", "redirect_uris": redirects, "manifest_permissions": []string{}}
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	register["human_oidc_enabled"] = true
	if status, _ := post(register); status != http.StatusForbidden {
		t.Fatalf("registration proof omitting sign-in opt-in = %d", status)
	}
	proof["human_oidc_enabled"] = true
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	status, app := post(register)
	if status != http.StatusOK || !app.HumanOIDCEnabled || app.ReviewStatus != "pending" ||
		app.ManifestPermissions == nil || app.PendingManifestPermissions == nil ||
		len(app.ManifestPermissions) != 0 || len(app.PendingManifestPermissions) != 0 {
		t.Fatalf("login-only public registration = %d, review=%s", status, app.ReviewStatus)
	}
	const disable = `{"human_oidc_enabled":false,"name":"Closed"}`
	request := map[string]any{"application_id": app.ID, "name": "Closed", "human_oidc_enabled": false}
	seedStepUpProof(t, st, tokens.SessionID, "applications.update", request)
	if got := patchApplication(t, handler, app.ID, tokens.AccessToken, `{"human_oidc_enabled":false,"name":"Changed"}`); got.Code != http.StatusForbidden {
		t.Fatalf("patch accepted fields outside proof: %d", got.Code)
	}
	if got := patchApplication(t, handler, existing, tokens.AccessToken, disable); got.Code != http.StatusForbidden {
		t.Fatalf("patch accepted proof for another application: %d", got.Code)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_login_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.update' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_login_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_login_audit()`); err != nil {
		t.Fatal(err)
	}
	if got := patchApplication(t, handler, app.ID, tokens.AccessToken, disable); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("update without audit = %d", got.Code)
	}
	if _, err := st.Pool.Exec(ctx, "DROP TRIGGER reject_login_audit ON audit_logs"); err != nil {
		t.Fatal(err)
	}
	if got := patchApplication(t, handler, app.ID, tokens.AccessToken, disable); got.Code != http.StatusOK {
		t.Fatalf("disable login-only application after rollback = %d", got.Code)
	}
	if got := patchApplication(t, handler, app.ID, tokens.AccessToken, disable); got.Code != http.StatusForbidden {
		t.Fatalf("reused patch proof = %d", got.Code)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	listRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+registerPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	listRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err := server.Client().Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var list struct {
		Data []application.PublishedApplication
	}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("listing publisher applications failed", response.StatusCode, err)
	}
	found := slices.ContainsFunc(list.Data, func(item application.PublishedApplication) bool {
		return item.ID == app.ID && !item.HumanOIDCEnabled && item.Name == "Closed" && item.ReviewStatus == "pending"
	})
	if !found {
		t.Fatal("publisher list did not reflect the committed setting")
	}
	var events int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE application_id=$1 AND
		((action='application.register' AND metadata->>'human_oidc_enabled'='true') OR
		 (action='application.update' AND metadata->>'human_oidc_enabled'='false'))`, app.ID).Scan(&events); err != nil || events != 2 {
		t.Fatal("expected an audit event for each successful setting change", err, events)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE permissions SET status='disabled' WHERE key='auth.applications:manage'"); err != nil {
		t.Fatal(err)
	}
	request["human_oidc_enabled"] = true
	seedStepUpProof(t, st, tokens.SessionID, "applications.update", request)
	if got := patchApplication(t, handler, app.ID, tokens.AccessToken, `{"human_oidc_enabled":true,"name":"Closed"}`); got.Code != http.StatusForbidden {
		t.Fatalf("configuration without publisher authority = %d", got.Code)
	}
}
