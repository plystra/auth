package principal

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/security"
)

func TestManagedAPIKeyCreateListRevokeThroughPrincipalHTTP(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	if _, err := apps.InstallPrivateSpace(ctx, actorID, appID, spaceID); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	restrictTo := []application.KeyRestriction{{SpaceID: spaceID}}
	request := map[string]any{
		"application_id": appID, "name": "billing-server", "grants": []string{"auth.authz:check"},
		"restrict_to": restrictTo, "expires_at": expiresAt, "allow_subject_assertion": true,
	}
	body, err := json.Marshal(map[string]any{
		"name": "billing-server", "grants": []string{"auth.authz:check"}, "restrict_to": restrictTo,
		"expires_at": expiresAt, "allow_subject_assertion": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/applications/" + appID + "/api-keys"
	post := func() *httptest.ResponseRecorder {
		return requestApplicationKey(t, handler, http.MethodPost, path, tokens.AccessToken, body)
	}
	if denied := post(); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("API key creation without step-up = %d %s", denied.Code, denied.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.create", request)
	created := post()
	if created.Code != http.StatusOK {
		t.Fatalf("API key creation = %d %s", created.Code, created.Body.String())
	}
	var creation struct {
		Data struct {
			Key    application.ManagedKey `json:"key"`
			Secret string                 `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	key := creation.Data.Key
	if !strings.HasPrefix(key.ID, "key_") || key.Prefix != "ply_sk_"+strings.TrimPrefix(key.ID, "key_") ||
		!strings.HasPrefix(creation.Data.Secret, key.Prefix+".") || !key.AllowSubjectAssertion {
		t.Fatalf("API key response has invalid public metadata: %+v", key)
	}
	if _, err := apps.AuthenticateKey(ctx, creation.Data.Secret); err != nil {
		t.Fatalf("created API key did not authenticate: %v", err)
	}
	if reused := post(); reused.Code != http.StatusForbidden || !strings.Contains(reused.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("reused step-up proof = %d %s", reused.Code, reused.Body.String())
	}
	request["name"] = "billing-secondary"
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.create", request)
	second := requestApplicationKey(t, handler, http.MethodPost, path, tokens.AccessToken,
		[]byte(strings.Replace(string(body), "billing-server", "billing-secondary", 1)))
	if second.Code != http.StatusOK {
		t.Fatalf("second API key creation = %d %s", second.Code, second.Body.String())
	}
	var secondCreation struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondCreation); err != nil {
		t.Fatal(err)
	}
	listed := requestApplicationKey(t, handler, http.MethodGet, path, tokens.AccessToken, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), key.ID) || strings.Contains(listed.Body.String(), creation.Data.Secret) || strings.Contains(listed.Body.String(), `"secret"`) {
		t.Fatalf("API key listing leaked secret or omitted key: %d %s", listed.Code, listed.Body.String())
	}
	var storedHash []byte
	var hashScheme string
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash, hash_scheme FROM api_keys WHERE id = $1`, key.ID).Scan(&storedHash, &hashScheme); err != nil {
		t.Fatal(err)
	}
	if hashScheme != "hmac_sha256" || len(storedHash) != 32 || strings.Contains(string(storedHash), creation.Data.Secret) {
		t.Fatal("database did not store a keyed digest")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id, manifest_permissions)
		VALUES ('app_key_isolation', $1, 'Other', 'other-key-app', '["auth.authz:check"]'::jsonb)`, spaceID); err != nil {
		t.Fatal(err)
	}
	wrongApp := requestApplicationKey(t, handler, http.MethodPost,
		"/v1/applications/app_key_isolation/api-keys/"+key.ID+"/revoke", tokens.AccessToken, nil)
	if wrongApp.Code != http.StatusNotFound {
		t.Fatalf("cross-application revocation = %d %s", wrongApp.Code, wrongApp.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_api_key_revoke_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.key.revoke' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_api_key_revoke_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_api_key_revoke_audit();
	`); err != nil {
		t.Fatal(err)
	}
	failedRevoke := requestApplicationKey(t, handler, http.MethodPost, path+"/"+key.ID+"/revoke", tokens.AccessToken, nil)
	if failedRevoke.Code < 500 {
		t.Fatalf("revoke survived audit failure = %d %s", failedRevoke.Code, failedRevoke.Body.String())
	}
	if _, err := apps.AuthenticateKey(ctx, creation.Data.Secret); err != nil {
		t.Fatalf("audit failure revoked API key: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_api_key_revoke_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	revoked := requestApplicationKey(t, handler, http.MethodPost, path+"/"+key.ID+"/revoke", tokens.AccessToken, nil)
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), `"revoked_at"`) || strings.Contains(revoked.Body.String(), creation.Data.Secret) {
		t.Fatalf("API key revocation = %d %s", revoked.Code, revoked.Body.String())
	}
	if _, err := apps.AuthenticateKey(ctx, creation.Data.Secret); err == nil {
		t.Fatal("revoked API key still authenticated")
	}
	if _, err := apps.AuthenticateKey(ctx, secondCreation.Data.Secret); err != nil {
		t.Fatalf("revoking one key affected another: %v", err)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id = $1 AND action IN ('application.key.create', 'application.key.revoke')`, key.ID).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("API key audits=%d error=%v", audits, err)
	}
}

func TestManagedAPIKeyRejectsOutOfManifestAndAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	expiresAt := time.Now().Add(time.Hour)
	if _, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "overreach", Grants: []string{"auth.tokens:introspect"}, ExpiresAt: expiresAt,
	}); err == nil {
		t.Fatal("API key grant outside the manifest was accepted")
	} else {
		assertPrincipalError(t, err, "GRANT_EXCEEDS_OWNER")
	}
	if _, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "uninstalled", Grants: []string{"auth.authz:check"}, ExpiresAt: expiresAt,
		RestrictTo: []application.KeyRestriction{{SpaceID: spaceID}},
	}); err == nil {
		t.Fatal("API key restriction to an uninstalled Space was accepted")
	} else {
		assertPrincipalError(t, err, "VALIDATION_FAILED")
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_api_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.key.create' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_api_key_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_api_key_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "rollback", Grants: []string{"auth.authz:check"}, ExpiresAt: expiresAt,
	}); err == nil {
		t.Fatal("API key creation committed despite audit failure")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE application_id = $1`, appID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed API key creation left %d keys: %v", count, err)
	}
}

func TestManagedAPIKeySourceIPRangesAreValidatedAndPersisted(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, _, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	input := application.CreateManagedKeyInput{
		Name: "source-restricted", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	for _, ranges := range [][]string{{"192.0.2.0"}, {"192.0.2.0/24", "192.0.2.7/24"}} {
		input.AllowedIPCIDRs = ranges
		if _, _, err := apps.CreateManagedKey(ctx, actorID, appID, input); err == nil {
			t.Fatalf("invalid or duplicate source IP ranges accepted: %v", ranges)
		}
	}
	input.AllowedIPCIDRs = []string{"192.0.2.7/24"}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.create", map[string]any{
		"application_id": appID, "name": input.Name, "grants": input.Grants,
		"restrict_to": []application.KeyRestriction(nil), "expires_at": input.ExpiresAt,
		"allow_subject_assertion": false, "allowed_ip_cidrs": input.AllowedIPCIDRs,
	})
	body, err := json.Marshal(map[string]any{
		"name": input.Name, "grants": input.Grants, "expires_at": input.ExpiresAt,
		"allowed_ip_cidrs": input.AllowedIPCIDRs,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := requestApplicationKey(t, handler, http.MethodPost, "/v1/applications/"+appID+"/api-keys", tokens.AccessToken, body)
	if response.Code != http.StatusOK {
		t.Fatalf("API key creation with source IP policy = %d %s", response.Code, response.Body.String())
	}
	var creation struct {
		Data struct {
			Key    application.ManagedKey `json:"key"`
			Secret string                 `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	created, raw := creation.Data.Key, creation.Data.Secret
	if len(created.AllowedIPCIDRs) != 1 || created.AllowedIPCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("source IP policy was not normalized: %+v", created.AllowedIPCIDRs)
	}
	listed, err := apps.ListManagedKeys(ctx, actorID, appID)
	if err != nil || len(listed) != 1 || len(listed[0].AllowedIPCIDRs) != 1 || listed[0].AllowedIPCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("source IP policy was not persisted: %+v, %v", listed, err)
	}
	allowed := requestinfo.With(ctx, requestinfo.Info{IP: net.ParseIP("192.0.2.8")})
	if _, err := apps.AuthenticateKey(allowed, raw); err != nil {
		t.Fatalf("allowed source IP was rejected: %v", err)
	}
	denied := requestinfo.With(ctx, requestinfo.Info{IP: net.ParseIP("198.51.100.8")})
	if _, err := apps.AuthenticateKey(denied, raw); err == nil {
		t.Fatal("outside source IP range authenticated")
	}
	rotated, next, err := apps.RotateManagedKey(ctx, actorID, appID, created.ID)
	if err != nil || len(rotated.AllowedIPCIDRs) != 1 || rotated.AllowedIPCIDRs[0] != "192.0.2.0/24" {
		t.Fatalf("rotation changed source IP policy: %+v, %v", rotated, err)
	}
	if _, err := apps.AuthenticateKey(allowed, next.Value()); err != nil {
		t.Fatalf("rotated key rejected an allowed source IP: %v", err)
	}
	if _, err := apps.AuthenticateKey(denied, next.Value()); err == nil {
		t.Fatal("rotated key bypassed source IP policy")
	}
}

func TestAgentCanManageAPIKeysOnlyWithinOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, _, _, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: ownerID, Name: "key-agent", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, ownerID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	body, err := json.Marshal(map[string]any{
		"name": "agent-key", "grants": []string{"auth.authz:check"}, "expires_at": expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/applications/" + appID + "/api-keys"
	allowed := requestApplicationKey(t, handler, http.MethodPost, path, access.AccessToken, body)
	if allowed.Code != http.StatusOK {
		t.Fatalf("Agent API key creation = %d %s", allowed.Code, allowed.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = $1 AND permission_keys @> '["auth.applications:manage"]'::jsonb`, ownerID); err != nil {
		t.Fatal(err)
	}
	denied := requestApplicationKey(t, handler, http.MethodPost, path, access.AccessToken, body)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent created API key after owner lost authority: %d %s", denied.Code, denied.Body.String())
	}
}

func TestManagedAPIKeyRotationKeepsIndependentGraceWindowsAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	if _, err := apps.InstallPrivateSpace(ctx, actorID, appID, spaceID); err != nil {
		t.Fatal(err)
	}
	created, original, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "rotating", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(72 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/applications/" + appID + "/api-keys/" + created.ID + "/rotate"
	rotate := func() *httptest.ResponseRecorder {
		t.Helper()
		return requestApplicationKey(t, handler, http.MethodPost, path, tokens.AccessToken, nil)
	}
	if missing := rotate(); missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("rotation without step-up = %d %s", missing.Code, missing.Body.String())
	}
	proof := map[string]any{"application_id": appID, "key_id": created.ID}
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.rotate", proof)
	first := rotate()
	if first.Code != http.StatusOK {
		t.Fatalf("first rotation = %d %s", first.Code, first.Body.String())
	}
	var firstResult struct {
		Data struct {
			Key    application.ManagedKey `json:"key"`
			Secret string                 `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.Data.Key.ID != created.ID || firstResult.Data.Secret == original.Value() ||
		!strings.HasPrefix(firstResult.Data.Secret, created.Prefix+".") ||
		strings.Contains(first.Body.String(), original.Value()) {
		t.Fatalf("rotation returned unsafe key metadata: %s", first.Body.String())
	}
	for _, raw := range []string{original.Value(), firstResult.Data.Secret} {
		if _, err := apps.AuthenticateKey(ctx, raw); err != nil {
			t.Fatalf("key rejected during grace: %v", err)
		}
	}
	var firstHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM api_keys WHERE id = $1`, created.ID).Scan(&firstHash); err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.rotate", proof)
	second := rotate()
	if second.Code != http.StatusOK {
		t.Fatalf("second rotation = %d %s", second.Code, second.Body.String())
	}
	var secondResult struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResult); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{original.Value(), firstResult.Data.Secret, secondResult.Data.Secret} {
		if _, err := apps.AuthenticateKey(ctx, raw); err != nil {
			t.Fatalf("sequential rotation invalidated a live secret: %v", err)
		}
	}
	var graceCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM api_key_grace_secrets WHERE key_id = $1 AND valid_until BETWEEN now() + interval '23 hours' AND now() + interval '25 hours'`, created.ID).Scan(&graceCount); err != nil || graceCount != 2 {
		t.Fatalf("grace windows=%d error=%v", graceCount, err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_key_grace_secrets SET valid_until = now() - interval '1 second' WHERE key_id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_key_grace_secrets SET valid_until = now() + interval '1 hour' WHERE key_id = $1 AND secret_hash = $2`, created.ID, firstHash); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.AuthenticateKey(ctx, original.Value()); err == nil {
		t.Fatal("expired grace secret authenticated")
	}
	if _, err := apps.AuthenticateKey(ctx, firstResult.Data.Secret); err != nil {
		t.Fatalf("independent grace secret was rejected: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_api_key_rotate_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.key.rotate' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_api_key_rotate_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_api_key_rotate_audit();
	`); err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.keys.rotate", proof)
	if failed := rotate(); failed.Code < 500 {
		t.Fatalf("rotation survived audit failure = %d %s", failed.Code, failed.Body.String())
	}
	if _, err := apps.AuthenticateKey(ctx, secondResult.Data.Secret); err != nil {
		t.Fatalf("failed rotation changed current secret: %v", err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM api_key_grace_secrets WHERE key_id = $1`, created.ID).Scan(&graceCount); err != nil || graceCount != 2 {
		t.Fatalf("failed rotation changed grace count=%d error=%v", graceCount, err)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_api_key_rotate_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.RevokeManagedKey(ctx, actorID, appID, created.ID); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{firstResult.Data.Secret, secondResult.Data.Secret} {
		if _, err := apps.AuthenticateKey(ctx, raw); err == nil {
			t.Fatal("revoked key or grace secret authenticated")
		}
	}
}

func requestApplicationKey(t *testing.T, handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
