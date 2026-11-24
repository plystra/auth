package protocol

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/stepup"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

func TestExistingAccountLinksEnterpriseOIDCAndSignsInToApplication(t *testing.T) {
	rp, browser, upstream, connection := workforceBrowser(t)
	ctx := t.Context()
	const userID = "usr_human_rp"
	const upstreamSubject = "stable-employee"
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE users SET email=$2,email_normalized=$2 WHERE id=$1`, userID, browserEmployee); err != nil {
		t.Fatal(err)
	}
	var memberID string
	if err := rp.st.Pool.QueryRow(ctx, `SELECT m.id FROM members m JOIN user_members u ON u.member_id=m.id WHERE m.space_id=$1 AND u.user_id=$2`, connection.SpaceID, userID).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New("fixture-identity-link-data-key32")}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(ctx, userID, browserEmployee)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rp.workforce.Sessions.Create(ctx, userID, nil, "other session", 1)
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	base := "/v1/me/sso-links/" + connection.ID
	post := func(path, bearer string, payload any) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPost, path, bearer, "application/json", "", payload)
	}
	codeFor := func(started enterprise.StartResult, email string) string {
		t.Helper()
		requestURL, err := url.Parse(started.AuthorizationURL)
		if err != nil || requestURL.Query().Get("state") != started.State || requestURL.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("OIDC start did not bind state and PKCE")
		}
		values := requestURL.Query()
		code := oauth2.GenerateVerifier()
		upstream.addCode(code, oidcTestCode{nonce: values.Get("nonce"), subject: upstreamSubject, email: email,
			emailVerified: true, challenge: values.Get("code_challenge"), redirectURI: values.Get("redirect_uri")})
		return code
	}
	seedProof := func(sessionID, state, code string) {
		t.Helper()
		proof, err := stepup.DigestValue(enterprise.IdentityLinkProofRequest(connection.ID, state, code))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2,step_up_digest=$3,step_up_method='totp',
			step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, sessionID, enterprise.CompleteIdentityLinkOperation, proof); err != nil {
			t.Fatal(err)
		}
	}
	plain := "/v1/sso/" + connection.ID
	plainStart := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, plain+"/start", "", "", "", nil))
	plainCode := codeFor(plainStart, browserEmployee)
	post(plain+"/callback", "", map[string]string{"state": plainStart.State, "code": plainCode}).requireError(t, http.StatusConflict, "conflict")
	start := func() enterprise.StartResult {
		t.Helper()
		return employeeLifecycleData[enterprise.StartResult](t, post(base+"/start", rp.session.AccessToken, nil))
	}
	bound := start()
	code := codeFor(bound, browserEmployee)
	payload := map[string]string{"state": bound.State, "code": code}
	post(base+"/complete", rp.session.AccessToken, payload).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	seedProof(other.SessionID, bound.State, code)
	post(base+"/complete", other.AccessToken, payload).requireError(t, http.StatusBadRequest, "invalid_grant")
	post(plain+"/callback", "", payload).requireError(t, http.StatusBadRequest, "invalid_grant")
	seedProof(rp.session.SessionID, plainStart.State, plainCode)
	post(base+"/complete", rp.session.AccessToken, map[string]string{"state": plainStart.State, "code": plainCode}).requireError(t, http.StatusBadRequest, "invalid_grant")
	mismatched := start()
	wrongCode := codeFor(mismatched, "different@example.test")
	seedProof(rp.session.SessionID, mismatched.State, wrongCode)
	post(base+"/complete", rp.session.AccessToken, map[string]string{"state": mismatched.State, "code": wrongCode}).requireError(t, http.StatusBadRequest, "invalid_grant")

	failed := start()
	failedCode := codeFor(failed, browserEmployee)
	seedProof(rp.session.SessionID, failed.State, failedCode)
	if _, err := rp.st.Pool.Exec(ctx, `CREATE FUNCTION reject_identity_link() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='auth.sso.identity.link' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_identity_link BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_identity_link()`); err != nil {
		t.Fatal(err)
	}
	post(base+"/complete", rp.session.AccessToken, map[string]string{"state": failed.State, "code": failedCode}).requireStatus(t, http.StatusServiceUnavailable)
	var rolledBack bool
	if err := rp.st.Pool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM external_identities WHERE issuer=$1)
		AND NOT EXISTS(SELECT 1 FROM sso_states WHERE state_hash=sha256(convert_to($2,'UTF8')) AND consumed_at IS NOT NULL)
		AND EXISTS(SELECT 1 FROM sessions WHERE id=$3 AND step_up_operation=$4)`, upstream.issuer, failed.State,
		rp.session.SessionID, enterprise.CompleteIdentityLinkOperation).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("audit failure did not roll back identity, state and MFA consumption")
	}
	if _, err := rp.st.Pool.Exec(ctx, `DROP TRIGGER reject_identity_link ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	proof := enterprise.IdentityLinkProofRequest(connection.ID, bound.State, code)
	mfa, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	post("/v1/auth/step-up", rp.session.AccessToken, map[string]any{
		"operation": enterprise.CompleteIdentityLinkOperation, "request": proof, "mfa_code": mfa,
	}).requireStatus(t, http.StatusOK)
	post(base+"/complete", rp.session.AccessToken, map[string]string{"state": bound.State, "code": code + "different"}).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	out := employeeLifecycleData[struct{ Linked bool }](t, post(base+"/complete", rp.session.AccessToken, payload))
	if !out.Linked {
		t.Fatal("the explicit link was not confirmed")
	}
	seedProof(rp.session.SessionID, bound.State, code)
	post(base+"/complete", rp.session.AccessToken, payload).requireError(t, http.StatusBadRequest, "invalid_grant")
	var unchanged bool
	if err := rp.st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM user_members b JOIN members m ON m.id=b.member_id WHERE b.user_id=$1 AND m.space_id=$2)=1
		AND NOT EXISTS(SELECT 1 FROM authorization_grants WHERE granted_by=$3)
		AND (SELECT count(*) FROM audit_logs WHERE action='auth.sso.identity.link' AND user_id=$1 AND member_id=$4 AND outcome='success')=1`,
		userID, connection.SpaceID, connection.ID, memberID).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("explicit linking changed membership or grants, or missed its audit")
	}

	relogin := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, plain+"/start", "", "", "", nil))
	signedIn := employeeLifecycleData[account.AuthResult](t, post(plain+"/callback", "", map[string]string{
		"state": relogin.State, "code": codeFor(relogin, browserEmployee),
	}))
	if signedIn.User.ID != userID || signedIn.Tokens == nil {
		t.Fatal("ordinary SSO did not return the original account")
	}
	verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	path := browser.beginFromAuthorization(t, verifier, state, nonce)
	upstreamCallback := startWorkforceBrowser(t, browser, upstream, connection, path, nil)
	view, _ := browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, rp.host.URL, "", http.StatusOK)
	if view.NextStep != "consent" {
		t.Fatal("the linked account did not reach application consent")
	}
	decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
	redirect, err := url.Parse(decision.RedirectTo)
	if err != nil || redirect.Query().Get("state") != state {
		t.Fatal("application redirect did not preserve state")
	}
	clientContext := oidc.ClientContext(ctx, rp.host.Client())
	tokens, err := rp.config.Exchange(clientContext, redirect.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("the relying party could not redeem the code")
	}
	raw, _ := tokens.Extra("id_token").(string)
	verified, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(clientContext, raw)
	if err != nil || verified.Subject != userID || verified.Nonce != nonce {
		t.Fatal("the relying party could not verify the original account's ID token")
	}
}
