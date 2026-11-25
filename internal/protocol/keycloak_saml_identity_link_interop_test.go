//go:build interop

package protocol

import (
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
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/oauth2"
)

func TestKeycloakExistingAccountLinksSAMLAndSignsInToRelyingParty(t *testing.T) {
	ctx := t.Context()
	upstream := &http.Client{Timeout: 15 * time.Second}
	rp := newHumanRPWithWorkforce(t, false, upstream)
	adminPassword := oauth2.GenerateVerifier()
	issuer, transport := keycloakFixture(t, rp.host.URL+"/oidc/upstream", testcontainers.WithEnv(map[string]string{
		"KC_BOOTSTRAP_ADMIN_USERNAME": keycloakFixtureAdmin,
		"KC_BOOTSTRAP_ADMIN_PASSWORD": adminPassword,
	}))
	upstream.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
	const userID, username, email = "usr_human_rp", "original", "original@workforce.example.test"
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE users SET email=$2,email_normalized=$2 WHERE id=$1`, userID, email); err != nil {
		t.Fatal(err)
	}
	space, member, err := rp.workforce.Authorization.CreateSpace(ctx, userID, "SAML linking", "saml-linking")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_keycloak_saml_link',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan url.Values, 1)
	acs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
		if req.Method != http.MethodPost || req.URL.Path != "/acs" || req.ParseForm() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accepted <- req.PostForm
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(acs.Close)
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, member.ID, userID), member.ID, space.ID, enterprise.ConnectionInput{
		Name: "Keycloak SAML linking", Provider: "saml", SAMLMetadata: fetchKeycloakSAMLMetadata(t, upstream, issuer), RedirectURI: acs.URL + "/acs",
	})
	if err != nil {
		t.Fatal(err)
	}
	registerKeycloakSAMLConnection(t, rp, upstream, issuer, adminPassword, space.ID, connection)
	client := employeeLifecycleClient{server: rp.host}
	post := func(path, bearer string, body any) employeeLifecycleResponse {
		return client.send(t, http.MethodPost, path, bearer, "application/json", "", body)
	}
	loginForm := func(start enterprise.StartResult) url.Values {
		t.Helper()
		if start.AuthorizationMethod != http.MethodGet {
			t.Fatal("Keycloak fixture requires a Redirect request")
		}
		form := keycloakSAMLRedirectForm(t, transport, issuer, connection.RedirectURI, username, start.AuthorizationURL)
		if form.Get("RelayState") != start.State {
			t.Fatal("Keycloak did not preserve the issued state")
		}
		return form
	}
	sso := "/v1/sso/" + connection.ID
	login := func() employeeLifecycleResponse {
		t.Helper()
		start := keycloakInteropData[enterprise.StartResult](t, "SAML login start", client.send(t, http.MethodGet, sso+"/start", "", "", "", nil))
		return client.send(t, http.MethodPost, sso+"/callback", "", "application/x-www-form-urlencoded", "", loginForm(start))
	}
	login().requireError(t, http.StatusConflict, "conflict")
	link := "/v1/me/sso-links/" + connection.ID
	start := keycloakInteropData[enterprise.StartResult](t, "SAML link start", post(link+"/start", rp.session.AccessToken, nil))
	response, err := acs.Client().PostForm(connection.RedirectURI, loginForm(start))
	if err != nil {
		t.Fatal("Keycloak's form could not reach the independent HTTPS ACS")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("the registered ACS did not accept the Keycloak form")
	}
	form := <-accepted
	state, assertion := form.Get("RelayState"), form.Get("SAMLResponse")
	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(ctx, userID, email)
	if err != nil {
		t.Fatal(err)
	}
	mfa, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	post("/v1/auth/step-up", rp.session.AccessToken, map[string]any{
		"operation": enterprise.CompleteIdentityLinkOperation, "request": enterprise.SAMLIdentityLinkProofRequest(connection.ID, state, assertion), "mfa_code": mfa,
	}).requireStatus(t, http.StatusOK)
	linked := keycloakInteropData[struct{ Linked bool }](t, "SAML link completion", post(link+"/complete", rp.session.AccessToken, map[string]string{"state": state, "saml_response": assertion}))
	if !linked.Linked {
		t.Fatal("the original account did not link to Keycloak")
	}
	loggedIn := keycloakInteropData[account.AuthResult](t, "linked SAML login", login())
	if loggedIn.User.ID != userID || loggedIn.Tokens == nil {
		t.Fatal("Keycloak did not sign in to the original account")
	}
	rp.session = *loggedIn.Tokens
	code, verifier := rp.authorize(t, "openid")
	clientContext := oidc.ClientContext(ctx, rp.host.Client())
	tokens, err := rp.config.Exchange(clientContext, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("the relying party could not exchange the authorization code")
	}
	raw, _ := tokens.Extra("id_token").(string)
	identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(clientContext, raw)
	if err != nil || identity.Subject != userID || identity.Nonce != "rp-test-nonce" {
		t.Fatal("the relying party could not verify the original account")
	}
	var audited bool
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='auth.sso.identity.link')=1
		AND count(*) FILTER (WHERE action='auth.sso.login')=1 FROM audit_logs WHERE user_id=$1 AND member_id=$2 AND outcome='success'`, userID, member.ID).Scan(&audited); err != nil || !audited {
		t.Fatal("linking and sign-in were not audited for the original member")
	}
}
