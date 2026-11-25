package protocol

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/stepup"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

func TestExistingAccountLinksEnterpriseSAMLThroughRegisteredACS(t *testing.T) {
	ctx := t.Context()
	rp := newConfiguredHumanRP(t, false, newOIDCTestProvider(t))
	const userID, email, subject = "usr_human_rp", "rp@example.test", "stable-employee"
	postedForm := make(chan url.Values, 1)
	acs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
		if req.Method != http.MethodPost || req.URL.Path != "/acs" || req.ParseForm() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		postedForm <- req.PostForm
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(acs.Close)
	space, member, err := rp.workforce.Authorization.CreateSpace(ctx, userID, "SAML workforce", "saml-workforce")
	if err != nil {
		t.Fatal(err)
	}
	metadata, signing := newSAMLTestIssuer(t)
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, member.ID, userID), member.ID, space.ID, enterprise.ConnectionInput{
		Name: "SAML workforce", Provider: "saml", SAMLMetadata: strings.Replace(metadata, "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1), RedirectURI: acs.URL + "/acs",
	})
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	posted := func(path, token string, payload any) employeeLifecycleResponse {
		return client.send(t, http.MethodPost, path, token, "application/json", "", payload)
	}
	formFor := func(start enterprise.StartResult, responseEmail string) url.Values {
		t.Helper()
		wire, err := base64.StdEncoding.DecodeString(start.SAMLRequest)
		var request struct {
			ID  string `xml:"ID,attr"`
			ACS string `xml:"AssertionConsumerServiceURL,attr"`
		}
		if err != nil || xml.Unmarshal(wire, &request) != nil || request.ID == "" || request.ACS != connection.RedirectURI || start.AuthorizationMethod != http.MethodPost || start.RelayState != start.State {
			t.Fatal("SAML linking did not start a bound POST request to the registered ACS")
		}
		assertion := signedSAMLTestResponseForAudience(t, signing, connection.RedirectURI, rp.workforce.Issuer+"/saml/"+connection.ID, request.ID, subject, []samlTestAttribute{{name: "email", value: responseEmail}}, false)
		return url.Values{"RelayState": {start.RelayState}, "SAMLResponse": {assertion}}
	}
	plain := "/v1/sso/" + connection.ID
	ordinary := func() employeeLifecycleResponse {
		start := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, plain+"/start", "", "", "", nil))
		form := formFor(start, email)
		return client.send(t, http.MethodPost, plain+"/callback", "", "application/x-www-form-urlencoded", "", form)
	}
	ordinary().requireError(t, http.StatusConflict, "conflict")
	link := "/v1/me/sso-links/" + connection.ID
	start := employeeLifecycleData[enterprise.StartResult](t, posted(link+"/start", rp.session.AccessToken, nil))
	idpResponse := formFor(start, email)
	response, err := acs.Client().PostForm(connection.RedirectURI, idpResponse)
	if err != nil {
		t.Fatal("the signed IdP response could not reach the independent HTTPS ACS")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("the independent HTTPS ACS rejected the SAML form")
	}
	form := <-postedForm
	body := map[string]string{"state": form.Get("RelayState"), "saml_response": form.Get("SAMLResponse")}
	client.send(t, http.MethodPost, plain+"/callback", "", "application/x-www-form-urlencoded", "", form).requireError(t, http.StatusBadRequest, "invalid_grant")
	posted(link+"/complete", rp.session.AccessToken, body).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	posted(link+"/complete", rp.session.AccessToken, map[string]string{"state": start.State, "code": "wrong-protocol"}).requireError(t, http.StatusBadRequest, "invalid_request")
	seedProof := func(proof map[string]string) {
		t.Helper()
		digest, err := stepup.DigestValue(proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2, step_up_digest=$3, step_up_method='totp',
			step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, rp.session.SessionID, enterprise.CompleteIdentityLinkOperation, digest); err != nil {
			t.Fatal(err)
		}
	}
	wrongEmail := formFor(start, "wrong@example.test").Get("SAMLResponse")
	wrongBody := map[string]string{"state": start.State, "saml_response": wrongEmail}
	seedProof(enterprise.SAMLIdentityLinkProofRequest(connection.ID, start.State, wrongEmail))
	posted(link+"/complete", rp.session.AccessToken, wrongBody).requireError(t, http.StatusBadRequest, "invalid_grant")

	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(ctx, userID, email)
	if err != nil {
		t.Fatal(err)
	}
	mfa, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	proof := enterprise.SAMLIdentityLinkProofRequest(connection.ID, body["state"], body["saml_response"])
	posted("/v1/auth/step-up", rp.session.AccessToken, map[string]any{"operation": enterprise.CompleteIdentityLinkOperation, "request": proof, "mfa_code": mfa}).requireStatus(t, http.StatusOK)
	posted(link+"/complete", rp.session.AccessToken, wrongBody).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	if _, err := rp.st.Pool.Exec(ctx, `CREATE FUNCTION reject_saml_link_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='auth.sso.identity.link' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_saml_link_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_saml_link_audit()`); err != nil {
		t.Fatal(err)
	}
	posted(link+"/complete", rp.session.AccessToken, body).requireStatus(t, http.StatusServiceUnavailable)
	ordinary().requireError(t, http.StatusConflict, "conflict")
	if _, err := rp.st.Pool.Exec(ctx, `DROP TRIGGER reject_saml_link_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if !employeeLifecycleData[struct{ Linked bool }](t, posted(link+"/complete", rp.session.AccessToken, body)).Linked {
		t.Fatal("the signed SAML assertion did not link the account")
	}
	seedProof(proof)
	posted(link+"/complete", rp.session.AccessToken, body).requireError(t, http.StatusBadRequest, "invalid_grant")
	loggedIn := employeeLifecycleData[account.AuthResult](t, ordinary())
	if loggedIn.User.ID != userID || loggedIn.Tokens == nil {
		t.Fatal("ordinary SAML did not return the original account after linking")
	}
	rp.session = *loggedIn.Tokens
	code, verifier := rp.authorize(t, "openid")
	oidcCtx := oidc.ClientContext(ctx, rp.host.Client())
	tokens, err := rp.config.Exchange(oidcCtx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("the relying party could not redeem the authorization code")
	}
	raw, _ := tokens.Extra("id_token").(string)
	identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(oidcCtx, raw)
	if err != nil || identity.Subject != userID || identity.Nonce != "rp-test-nonce" {
		t.Fatal("the relying party received an unexpected identity after SAML sign-in")
	}
	var preserved bool
	if err := rp.st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.identity.link' AND user_id=$1 AND member_id=$2 AND resource_id=$3)=1
		AND (SELECT count(*) FROM user_members WHERE user_id=$1 AND member_id=$2)=1`, userID, member.ID, connection.ID).Scan(&preserved); err != nil || !preserved {
		t.Fatal("SAML linking did not preserve the original membership or its audit")
	}
}
