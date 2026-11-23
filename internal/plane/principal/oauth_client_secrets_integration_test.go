package principal

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestPublisherOAuthSecretIssuanceAndReplicaRotation(t *testing.T) {
	ctx := t.Context()
	st, _, actor, space, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, space, actor.ID, actor.ID, "auth.applications:manage")
	replica, err := store.Open(ctx, st.Pool.Config().ConnConfig.ConnString())
	if err != nil {
		t.Fatal("could not open second replica")
	}
	t.Cleanup(replica.Close)
	hmacKey := bytes.Repeat([]byte("k"), 32)
	newReplica := func(database *store.Store) (http.Handler, *application.Service) {
		sessionReplica := *sessions
		sessionReplica.Store = database
		authz := &authorization.Service{Store: database, StepUp: &sessionReplica}
		apps := &application.Service{Store: database, Authorization: authz, StepUp: &sessionReplica, HMACKeys: [][]byte{hmacKey}}
		api := &API{Authorization: authz, Applications: apps, Sessions: &sessionReplica, Signer: signer}
		mux := http.NewServeMux()
		api.Register(humago.New(mux, route.HumaConfig("credential lifecycle", "1")))
		return route.MiddlewareWithIdempotency(route.Principal, mux, database, nil), apps
	}
	first, apps := newReplica(st)
	second, _ := newReplica(replica)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "publisher", 1)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h http.Handler, method, path string, body any, keys ...string) *httptest.ResponseRecorder {
		t.Helper()
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		for _, k := range keys {
			req.Header.Add("Idempotency-Key", k)
		}
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out
	}
	requireStatus := func(r *httptest.ResponseRecorder, status int) {
		t.Helper()
		if r.Code != status {
			t.Fatalf("HTTP status %d, want %d", r.Code, status)
		}
	}
	requirePrivate := func(r *httptest.ResponseRecorder) {
		t.Helper()
		requireStatus(r, 200)
		if r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Pragma") != "no-cache" {
			t.Fatal("response is cacheable")
		}
	}
	registerPath := "/v1/spaces/" + space + "/applications"
	redirects := []string{"https://rp.example.test/cb"}
	manifest := []string{"auth.authz:check"}
	payload := map[string]any{"name": "Publisher RP", "manifest_permissions": manifest, "redirect_uris": redirects, "token_endpoint_auth_method": "client_secret_basic"}
	proof := map[string]any{"space_id": space, "name": "Publisher RP", "manifest_permissions": manifest, "redirect_uris": redirects}
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	requireStatus(call(first, "POST", registerPath, payload), 403)
	proof["token_endpoint_auth_method"] = "client_secret_basic"
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	for _, key := range []string{"", "signup-replay"} {
		denied := call(first, "POST", registerPath, payload, key)
		requireStatus(denied, 400)
		if !strings.Contains(denied.Body.String(), "VALIDATION_FAILED") {
			t.Fatal("unexpected idempotency rejection")
		}
	}
	r := call(first, "POST", registerPath, payload)
	requirePrivate(r)
	var created struct {
		Data application.RegisteredApplication
	}
	if err := json.Unmarshal(r.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	app := created.Data
	entropy, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(app.ClientSecret.Value(), "ply_ocs_"))
	if app.TokenEndpointAuthMethod != "client_secret_basic" || !strings.HasPrefix(app.ClientSecret.Value(), "ply_ocs_") || err != nil || len(entropy) != 32 {
		t.Fatal("invalid issued credential")
	}
	if _, err := apps.AuthenticateKey(ctx, app.ClientSecret.Value()); err == nil {
		t.Fatal("OAuth client secret authenticated as an API key")
	}
	var stored []byte
	var generation int64
	if err := st.Pool.QueryRow(ctx, "SELECT oauth_client_secret_hash,human_oidc_generation FROM applications WHERE id=$1", app.ID).Scan(&stored, &generation); err != nil || !hmac.Equal(stored, application.HMACClientSecretHash(hmacKey, app.ClientSecret.Value())) {
		t.Fatal("stored digest does not match the issued credential")
	}
	list := call(second, "GET", registerPath, nil)
	requireStatus(list, 200)
	if strings.Contains(list.Body.String(), "client_secret") {
		t.Fatal("publisher list exposed credentials")
	}
	rotPath := "/v1/applications/" + app.ID + "/oauth-client-secret/rotate"
	rotate := func(grace int32, body map[string]any) application.OAuthSecretRotation {
		t.Helper()
		seedStepUpProof(t, st, tokens.SessionID, application.RotateOAuthSecretOperation, map[string]any{"application_id": app.ID, "grace_period_seconds": grace})
		response := call(second, "POST", rotPath, body)
		requirePrivate(response)
		var result struct {
			Data application.OAuthSecretRotation
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Data.ApplicationID != app.ID || result.Data.ClientID != app.ClientID || !strings.HasPrefix(result.Data.ClientSecret.Value(), "ply_ocs_") {
			t.Fatal("rotation returned incorrect client or credential")
		}
		return result.Data
	}
	valid := func(value secret.String, want bool) {
		t.Helper()
		err := st.InTx(ctx, func(q *db.Queries) error {
			_, err := apps.AuthenticateOAuthClientMethodTx(ctx, q, app.ClientID, value.Value(), "client_secret_basic")
			return err
		})
		if (err == nil) != want {
			t.Fatalf("unexpected client authentication outcome, want valid=%t", want)
		}
	}
	requireStatus(call(second, "POST", rotPath, map[string]any{}, "rotate-replay"), 400)
	firstRotation := rotate(86400, map[string]any{})
	if firstRotation.PreviousSecretExpiresAt == nil || time.Until(*firstRotation.PreviousSecretExpiresAt) < 23*time.Hour {
		t.Fatal("default grace period was not honored")
	}
	valid(app.ClientSecret, true)
	valid(firstRotation.ClientSecret, true)
	next := rotate(120, map[string]any{"grace_period_seconds": 120})
	valid(app.ClientSecret, false)
	valid(firstRotation.ClientSecret, true)
	valid(next.ClientSecret, true)
	if _, err := st.Pool.Exec(ctx, "UPDATE applications SET oauth_previous_secret_expires_at=clock_timestamp() WHERE id=$1", app.ID); err != nil {
		t.Fatal(err)
	}
	valid(firstRotation.ClientSecret, false)
	valid(next.ClientSecret, true)
	final := rotate(0, map[string]any{"grace_period_seconds": 0})
	if final.PreviousSecretExpiresAt != nil {
		t.Fatal("zero grace returned an expiry")
	}
	valid(next.ClientSecret, false)
	valid(final.ClientSecret, true)
	var after int64
	var receipts, leaked int
	if err := st.Pool.QueryRow(ctx, "SELECT human_oidc_generation FROM applications WHERE id=$1", app.ID).Scan(&after); err != nil || after != generation {
		t.Fatal("rotation invalidated login generation")
	}
	if err := st.Pool.QueryRow(ctx, "SELECT count(*) FROM idempotency_keys").Scan(&receipts); err != nil || receipts != 0 {
		t.Fatal("one-time operation entered replay storage")
	}
	if err := st.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE metadata::text LIKE '%ply_ocs_%' OR strpos(metadata::text,$1)>0", hex.EncodeToString(stored)).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("credential material entered audit")
	}
	var rotations, withExpiry int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE metadata ? 'previous_secret_expires_at')
		FROM audit_logs WHERE action='application.oauth_client_secret.rotate' AND actor_id=$1 AND space_id=$2
		AND application_id=$3 AND permission_key='auth.applications:manage' AND outcome='success'`, actor.ID, space, app.ID).Scan(&rotations, &withExpiry); err != nil || rotations != 3 || withExpiry != 2 {
		t.Fatal("rotation audit missing publisher, actor, application, permission or grace evidence", rotations, withExpiry, err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE applications SET status='suspended' WHERE id=$1", app.ID); err != nil {
		t.Fatal(err)
	}
	valid(final.ClientSecret, false)
	delete(payload, "redirect_uris")
	proof["redirect_uris"] = []string(nil)
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	requireStatus(call(first, "POST", registerPath, payload), 400)

	delete(payload, "token_endpoint_auth_method")
	delete(proof, "token_endpoint_auth_method")
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", proof)
	public := call(first, "POST", registerPath, payload, "public-registration")
	requireStatus(public, 200)
	replayed := call(second, "POST", registerPath, payload, "public-registration")
	requireStatus(replayed, 200)
	if replayed.Header().Get("Idempotency-Replayed") != "true" || strings.Contains(replayed.Body.String(), `"client_secret"`) {
		t.Fatal("public registration replay returned an unexpected result")
	}
	var publicClient struct {
		Data application.RegisteredApplication
	}
	if err := json.Unmarshal(public.Body.Bytes(), &publicClient); err != nil || publicClient.Data.TokenEndpointAuthMethod != "none" {
		t.Fatal("registration without a method did not create a public client")
	}
	seedStepUpProof(t, st, tokens.SessionID, application.RotateOAuthSecretOperation, map[string]any{"application_id": publicClient.Data.ID, "grace_period_seconds": 0})
	requireStatus(call(second, "POST", "/v1/applications/"+publicClient.Data.ID+"/oauth-client-secret/rotate", map[string]any{"grace_period_seconds": 0}), 409)
}

func TestPublisherOAuthSecretRollbackAndApproval(t *testing.T) {
	ctx := t.Context()
	st, authz, owner, space, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, space, owner.ID, owner.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions, HMACKeys: [][]byte{bytes.Repeat([]byte("h"), 32)}}
	agents := &agent.Service{Store: st}
	api := &API{Authorization: authz, Applications: apps, Agents: agents, Approvals: &approval.Service{Store: st, Authorization: authz, StepUp: sessions}, Sessions: sessions, Signer: signer}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("managed OAuth", "1")))
	handler := route.MiddlewareWithIdempotency(route.Principal, mux, st, nil)
	app, err := apps.Register(ctx, owner.ID, application.RegisterInput{SpaceID: space, Name: "Payroll RP", HumanOIDCEnabled: true, ManifestPermissions: []string{}, RedirectURIs: []string{"https://payroll.example.test/login"}, TokenEndpointAuthMethod: "client_secret_basic"})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "publisher", 1)
	if err != nil {
		t.Fatal(err)
	}
	agentMember, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "Release automation", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, space, owner.ID, agentMember.ID, "auth.applications:manage")
	agentToken, err := sessions.CreateAgentAccess(ctx, agentMember.ID, space, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/applications/" + app.ID + "/oauth-client-secret/rotate"
	post := func(token, proof, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if proof != "" {
			req.Header.Set("Approval-Id", proof)
		}
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		return result
	}
	request := map[string]any{"application_id": app.ID, "grace_period_seconds": 0}
	seedStepUpProof(t, st, tokens.SessionID, application.RotateOAuthSecretOperation, request)
	if r := post(tokens.AccessToken, "", `{"grace_period_seconds":9}`); r.Code != 403 {
		t.Fatal("rotation accepted mismatched proof", r.Code)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_oauth_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='application.oauth_client_secret.rotate' THEN RAISE EXCEPTION 'unavailable'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_oauth_rotation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_oauth_rotation_audit()`); err != nil {
		t.Fatal(err)
	}
	response := post(tokens.AccessToken, "", `{"grace_period_seconds":0}`)
	if response.Code != 503 || strings.Contains(response.Body.String(), "ply_ocs_") {
		t.Fatal("audit failure returned an invalid response", response.Code)
	}
	if err := st.InTx(ctx, func(q *db.Queries) error {
		_, err := apps.AuthenticateOAuthClientMethodTx(ctx, q, app.ClientID, app.ClientSecret.Value(), "client_secret_basic")
		return err
	}); err != nil {
		t.Fatal("audit failure changed credential")
	}
	if _, err := st.Pool.Exec(ctx, "DROP TRIGGER reject_oauth_rotation_audit ON audit_logs"); err != nil {
		t.Fatal(err)
	}
	if res := post(tokens.AccessToken, "", `{"grace_period_seconds":0}`); res.Code != 200 {
		t.Fatal("rolled-back proof could not retry", res.Code)
	}
	if res := post(tokens.AccessToken, "", `{"grace_period_seconds":0}`); res.Code != 403 {
		t.Fatal("proof was reusable", res.Code)
	}

	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET agent_approval='required' WHERE key='auth.applications:manage'`); err != nil {
		t.Fatal(err)
	}
	pending := post(agentToken.AccessToken, "", `{"grace_period_seconds":0}`)
	var denied struct {
		Error struct {
			Code    string
			Details struct {
				ApprovalID string `json:"approval_id"`
			}
		}
	}
	if err := json.Unmarshal(pending.Body.Bytes(), &denied); err != nil || pending.Code != 403 || denied.Error.Code != "APPROVAL_REQUIRED" || denied.Error.Details.ApprovalID == "" {
		t.Fatalf("agent approval request failed: %d %s", pending.Code, denied.Error.Code)
	}
	approvalID := denied.Error.Details.ApprovalID
	seedStepUpProof(t, st, tokens.SessionID, "approvals.approve", map[string]any{"approval_id": approvalID})
	approved := applicationAuditRequest(t, handler, "POST", "/v1/approvals/"+approvalID+"/approve", tokens.AccessToken, "req_approve_rotation", map[string]any{})
	if approved.Code != 200 {
		t.Fatal("owner could not approve OAuth rotation", approved.Code)
	}
	if res := post(agentToken.AccessToken, approvalID, `{"grace_period_seconds":3}`); res.Code != 403 {
		t.Fatal("agent approval accepted different grace", res.Code)
	}
	if res := post(agentToken.AccessToken, approvalID, `{"grace_period_seconds":0}`); res.Code != 200 {
		t.Fatal("approved agent rotation failed", res.Code)
	}
	if res := post(agentToken.AccessToken, approvalID, `{"grace_period_seconds":0}`); res.Code != 403 {
		t.Fatal("agent reused consumed approval", res.Code)
	}
}
