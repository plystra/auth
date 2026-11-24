package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
	"github.com/pquerna/otp/totp"
)

func TestOIDCClientSecretRotationPreservesLoginAndRejectsInFlightExchange(t *testing.T) {
	provider := newOIDCTestProvider(t)
	rp := newConfiguredHumanRP(t, false, provider)
	ctx := t.Context()
	const actorID = "usr_human_rp"
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, actorID, "OIDC secret rotation", "oidc-secret-rotation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_oidc_secret_manager',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	const oldSecret = "old fixture secret"
	const newSecret = " new fixture secret:+% "
	provider.useClientSecret(oldSecret)
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, actorID), owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce OIDC", Provider: "oidc", Issuer: provider.issuer, ClientID: "secret-rotation", ClientSecret: oldSecret,
		RedirectURI: rp.host.URL + "/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	adminPath := "/v1/spaces/" + space.ID + "/sso-connections/" + connection.ID
	loginPath := "/v1/sso/" + connection.ID
	client := employeeLifecycleClient{server: rp.host}
	const contentType = "application/json"
	proof := func(operation string, request map[string]string) {
		t.Helper()
		digest, err := stepup.DigestValue(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2, step_up_digest=$3,
			step_up_method='totp', step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, rp.session.SessionID, operation, digest); err != nil {
			t.Fatal(err)
		}
	}
	start := func(afterExchange func(context.Context)) map[string]string {
		t.Helper()
		started := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, loginPath+"/start", "", "", "", nil))
		authorizationURL, err := url.Parse(started.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		query := authorizationURL.Query()
		provider.addCode(started.State, oidcTestCode{nonce: query.Get("nonce"), subject: "rotation-employee",
			email: "rotation-employee@example.test", emailVerified: true, challenge: query.Get("code_challenge"),
			redirectURI: query.Get("redirect_uri"), afterExchange: afterExchange})
		return map[string]string{"state": started.State, "code": started.State, "redirect_uri": connection.RedirectURI}
	}
	login := func() account.AuthResult {
		t.Helper()
		out := employeeLifecycleData[account.AuthResult](t, client.send(t, http.MethodPost, loginPath+"/callback", "", contentType, "", start(nil)))
		if out.Tokens == nil {
			t.Fatal("enterprise login did not return a session")
		}
		return out
	}
	initial := login()
	proof("sso_connections.get", enterprise.ConnectionDetailRequest(space.ID, connection.ID))
	detail := client.send(t, http.MethodGet, adminPath, rp.session.AccessToken, "", "", nil)
	detail.requireStatus(t, http.StatusOK)
	oldTag := detail.etag
	if oldTag == "" || oldTag != connection.ETag() {
		t.Fatal("connection details did not provide the current version")
	}
	patch := func(tag string, body map[string]string) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPatch, adminPath, rp.session.AccessToken, contentType, tag, body)
	}
	payload := map[string]string{"client_secret": newSecret}
	patch("", payload).requireStatus(t, http.StatusPreconditionFailed)
	patch(oldTag, payload).requireStatus(t, http.StatusForbidden)
	patch(oldTag, map[string]string{"client_secret": newSecret, "saml_metadata": "fixture"}).requireStatus(t, http.StatusBadRequest)
	const operation = enterprise.SSOConnectionUpdateOperation
	proofRequest := enterprise.OIDCClientSecretUpdateRequest(space.ID, connection.ID, oldTag, secret.New(newSecret))
	proof(operation, proofRequest)
	patch(oldTag, map[string]string{"client_secret": oldSecret}).requireStatus(t, http.StatusForbidden)
	oversized := strings.Repeat("é", 2049)
	proof(operation, enterprise.OIDCClientSecretUpdateRequest(space.ID, connection.ID, oldTag, secret.New(oversized)))
	patch(oldTag, map[string]string{"client_secret": oversized}).requireStatus(t, http.StatusBadRequest)

	if _, err := rp.st.Pool.Exec(ctx, `CREATE FUNCTION reject_oidc_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='sso.connection.oidc_client_secret.update' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_oidc_rotation_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_oidc_rotation_audit()`); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: rp.st, DataKey: rp.workforce.DataKey}
	rp.workforce.Sessions.Factors = factors
	enrollment, err := factors.BeginTOTP(ctx, actorID, "rp@example.test")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rp.publisherPost(t, "/v1/auth/step-up", map[string]any{"operation": operation, "request": proofRequest, "mfa_code": code}, nil)
	patch(oldTag, payload).requireStatus(t, http.StatusServiceUnavailable)
	if _, err := rp.st.Pool.Exec(ctx, `DROP TRIGGER reject_oidc_rotation_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	login()

	entered, release := make(chan struct{}), make(chan struct{}, 1)
	defer func() { close(release) }()
	callback := start(func(ctx context.Context) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	body, err := json.Marshal(callback)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, rp.host.URL+loginPath+"/callback", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	type callbackResult struct {
		response *http.Response
		err      error
	}
	finished := make(chan callbackResult)
	go func() {
		res, err := rp.host.Client().Do(req)
		select {
		case finished <- callbackResult{res, err}:
		case <-requestCtx.Done():
			if res != nil {
				_ = res.Body.Close()
			}
		}
	}()
	select {
	case <-entered:
	case <-requestCtx.Done():
		t.Fatal("upstream did not accept the original client credentials")
	}
	updated := patch(oldTag, payload)
	current := employeeLifecycleData[enterprise.Connection](t, updated)
	if current.ID != connection.ID || current.Issuer != connection.Issuer || current.RedirectURI != connection.RedirectURI ||
		updated.etag == "" || updated.etag == oldTag || bytes.Contains(updated.body, []byte(newSecret)) ||
		bytes.Contains(updated.body, []byte(proofRequest["client_secret_digest"])) || bytes.Contains(updated.body, []byte(`"client_secret"`)) {
		t.Fatal("rotation altered connection identity, did not advance its version, or disclosed credential material")
	}
	release <- struct{}{}
	select {
	case result := <-finished:
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer func() { _ = result.response.Body.Close() }()
		if result.response.StatusCode != http.StatusConflict {
			t.Fatalf("login exchanged with the previous secret returned HTTP %d", result.response.StatusCode)
		}
	case <-requestCtx.Done():
		t.Fatal("in-flight login did not finish after rotation")
	}
	patch(oldTag, payload).requireStatus(t, http.StatusForbidden)
	proof(operation, proofRequest)
	patch(oldTag, payload).requireStatus(t, http.StatusPreconditionFailed)
	client.send(t, http.MethodPost, loginPath+"/callback", "", contentType, "", start(nil)).requireStatus(t, http.StatusBadRequest)
	provider.useClientSecret(newSecret)
	newLogin := login()
	if newLogin.User.ID != initial.User.ID || newLogin.Tokens.SessionID == initial.Tokens.SessionID {
		t.Fatal("a fresh login did not retain the original external identity")
	}
	if _, active, err := rp.workforce.Sessions.Introspect(ctx, initial.Tokens.AccessToken, security.DefaultApplicationAudience); !active || err != nil {
		t.Fatal("rotation interrupted an existing authenticated session")
	}
	var count int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='sso.connection.oidc_client_secret.update'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rotation generated %d audit records, want one: %v", count, err)
	}
	var metadata string
	if err := rp.st.Pool.QueryRow(ctx, `SELECT metadata::text FROM audit_logs WHERE action='sso.connection.oidc_client_secret.update'
		AND resource_id=$1 AND member_id=$2`, connection.ID, owner.ID).Scan(&metadata); err != nil ||
		strings.Contains(metadata, newSecret) || strings.Contains(metadata, proofRequest["client_secret_digest"]) {
		t.Fatal("rotation audit lacked attribution or recorded credential material")
	}
}
