package protocol

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/oauth2"
)

func samlWorkforceFixture(t *testing.T, method string, rollover bool) (*humanRP, oidcBrowser, enterprise.Connection, *dsig.SigningContext) {
	t.Helper()
	rp := newConfiguredHumanRP(t, false, newOIDCTestProvider(t))
	ctx := t.Context()
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, "usr_human_rp", "SAML Workforce", "saml-workforce")
	if err != nil {
		t.Fatal(err)
	}
	metadata, signer := newSAMLTestIssuer(t)
	if rollover {
		replacement, successor := newSAMLTestIssuer(t)
		metadata = appendSAMLTestKey(t, metadata, replacement, "signing")
		signer = successor
	}
	if method == http.MethodPost {
		metadata = strings.Replace(metadata, "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_rp_saml_workforce',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, "usr_human_rp"), owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce SAML", Provider: "saml", SAMLMetadata: metadata,
		RedirectURI: rp.host.URL + route.SAMLBrowserCallbackPrefix + "{connection_id}",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO sso_domains (id,space_id,domain,verification_token_hash,connection_id,force_sso,status,verified_at)
		VALUES ('dom_rp_saml_workforce',$1,'workforce.example.test',decode(repeat('00',32),'hex'),$2,true,'verified',clock_timestamp())`, space.ID, connection.ID); err != nil {
		t.Fatal(err)
	}
	return rp, newOIDCBrowser(t, rp), connection, signer
}

func startSAMLBrowser(t *testing.T, browser oidcBrowser, connection enterprise.Connection, path, method string) (requestID, relay string) {
	t.Helper()
	out, _ := browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": browserEmployee, "method": "password"}, browser.rp.host.URL, "", http.StatusOK)
	target, err := url.Parse(out.AuthorizationURL)
	if err != nil || target.Scheme != "https" || target.Host != "directory-idp.test" || target.Path != "/sso" ||
		out.NextStep != "sso" || out.SSOConnectionID != connection.ID || out.AuthorizationMethod != method {
		t.Fatal("the interaction did not start the configured SAML binding")
	}
	encoded, relay := out.SAMLRequest, out.RelayState
	if method == http.MethodGet {
		encoded, relay = target.Query().Get("SAMLRequest"), target.Query().Get("RelayState")
	}
	wire, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(wire) == 0 || relay == "" {
		t.Fatal("the SAML IdP did not receive a request and RelayState")
	}
	var body io.Reader = bytes.NewReader(wire)
	if method == http.MethodGet {
		inflated := flate.NewReader(body)
		defer func() { _ = inflated.Close() }()
		body = inflated
	}
	var request struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		ID      string   `xml:"ID,attr"`
		ACS     string   `xml:"AssertionConsumerServiceURL,attr"`
	}
	if err := xml.NewDecoder(body).Decode(&request); err != nil || request.ID == "" || request.ACS != connection.RedirectURI {
		t.Fatal("the authentication request was not bound to the registered ACS")
	}
	return request.ID, relay
}

func postSAMLBrowserForm(t *testing.T, rp *humanRP, target, body, contentType, key string, want int) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Origin", "https://directory-idp.test")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	client := &http.Client{Transport: rp.host.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != want || res.Header.Get("Access-Control-Allow-Origin") != "" || len(res.Cookies()) != 0 {
		t.Fatalf("SAML navigation status = %d, want %d, or unsafe response headers", res.StatusCode, want)
	}
	if want == http.StatusSeeOther && (len(data) != 0 || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer") {
		t.Fatal("the SAML redirect response is not private")
	}
	return res.Header.Get("Location")
}

func TestSAMLWorkforceBrowserReturnsToIndependentRelyingParty(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			rollover := method == http.MethodPost
			rp, browser, connection, signer := samlWorkforceFixture(t, method, rollover)
			callback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			t.Cleanup(callback.Close)
			rp.config.RedirectURL = callback.URL + "/callback"
			if _, err := rp.st.Pool.Exec(t.Context(), `UPDATE applications SET redirect_uris=jsonb_build_array($1::text) WHERE client_id=$2`, rp.config.RedirectURL, rp.config.ClientID); err != nil {
				t.Fatal(err)
			}
			verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
			path := browser.beginFromAuthorization(t, verifier, state, nonce)
			requestID, relay := startSAMLBrowser(t, browser, connection, path, method)
			payload := signedSAMLTestResponseForAudience(t, signer, connection.RedirectURI, rp.host.URL+"/saml/"+connection.ID, requestID, "saml-workforce", nil, false)
			if rollover {
				payload = samlTestWithoutKeyInfo(t, payload)
			}
			form := url.Values{"RelayState": {relay}, "SAMLResponse": {payload}}
			encoded := form.Encode()
			const contentType = "application/x-www-form-urlencoded"
			postSAMLBrowserForm(t, rp, connection.RedirectURI, encoded, contentType, "one-time", http.StatusBadRequest)
			postSAMLBrowserForm(t, rp, connection.RedirectURI, encoded+"&RelayState=extra", contentType, "", http.StatusBadRequest)
			postSAMLBrowserForm(t, rp, connection.RedirectURI, strings.Repeat("a", samlBrowserFormLimit+1), contentType, "", http.StatusRequestEntityTooLarge)
			mismatched := signedSAMLTestResponseForAudience(t, signer, connection.RedirectURI, rp.host.URL+"/saml/"+connection.ID, "_different_request", "saml-workforce", nil, false)
			postSAMLBrowserForm(t, rp, connection.RedirectURI, url.Values{"RelayState": {relay}, "SAMLResponse": {mismatched}}.Encode(), contentType, "", http.StatusBadRequest)
			location := postSAMLBrowserForm(t, rp, connection.RedirectURI, encoded, contentType, "", http.StatusSeeOther)
			id := strings.TrimPrefix(path, route.OIDCInteractionsPath+"/")
			if location != "/oidc/upstream#interaction="+id {
				t.Fatal("the SAML response did not return to the original interaction")
			}
			postSAMLBrowserForm(t, rp, connection.RedirectURI, encoded, contentType, "", http.StatusBadRequest)

			var ciphertext []byte
			var count int
			if err := rp.st.Pool.QueryRow(t.Context(), `SELECT ciphertext,
				(SELECT count(*) FROM sessions WHERE sso_connection_id=$1) FROM saml_browser_responses`, connection.ID).Scan(&ciphertext, &count); err != nil ||
				len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(payload)) || count != 0 {
				t.Fatal("the cross-site ACS did not isolate the staged response from login")
			}

			ordinary := "/v1/sso/" + connection.ID + "/callback"
			browser.request(t, http.MethodPost, ordinary, map[string]string{"state": relay, "code": payload}, "", "", http.StatusBadRequest)
			other := newOIDCBrowser(t, rp)
			other.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusBadRequest)
			browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, "https://other.example.test", "", http.StatusForbidden)
			view, _ := browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusOK)
			if view.NextStep != "consent" || view.Email != "different-saml-email@example.test" {
				t.Fatal("the original browser could not resume its consent")
			}
			browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusBadRequest)
			if err := rp.st.Pool.QueryRow(t.Context(), "SELECT count(*) FROM saml_browser_responses").Scan(&count); err != nil || count != 0 {
				t.Fatal("completion did not erase the staged response")
			}
			decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
			target, err := url.Parse(decision.RedirectTo)
			if err != nil || target.Scheme+"://"+target.Host+target.Path != rp.config.RedirectURL || target.Query().Get("state") != state {
				t.Fatal("the application did not receive its exact callback and state")
			}
			callbackResponse, err := callback.Client().Get(decision.RedirectTo)
			if err != nil {
				t.Fatal(err)
			}
			_ = callbackResponse.Body.Close()
			if callbackResponse.StatusCode != http.StatusNoContent {
				t.Fatal("the independent HTTPS callback did not receive the code")
			}
			ctx := oidc.ClientContext(t.Context(), rp.host.Client())
			token, err := rp.config.Exchange(ctx, target.Query().Get("code"), oauth2.VerifierOption(verifier))
			if err != nil {
				t.Fatal("the relying party could not redeem the SAML-backed authorization code")
			}
			raw, _ := token.Extra("id_token").(string)
			idToken, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(ctx, raw)
			if err != nil || idToken.Nonce != nonce {
				t.Fatal("the relying party could not verify the SAML-backed ID Token")
			}
			var signedClaims struct {
				AuthTime int64 `json:"auth_time"`
			}
			authenticatedAt, _ := time.Parse(time.RFC3339, samlTestAuthenticationTime)
			if err := idToken.Claims(&signedClaims); err != nil || signedClaims.AuthTime != authenticatedAt.Unix() {
				t.Fatal("the signed SAML authentication time was lost")
			}
			if err := rp.st.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_logs WHERE action='auth.sso.login'
				AND actor_id=$1 AND user_id=$2 AND outcome='success'`, connection.ID, idToken.Subject).Scan(&count); err != nil || count != 1 {
				t.Fatal("successful SAML sign-in was not audited once")
			}
		})
	}
}

func TestSAMLWorkforceBrowserPreservesStagedResponseOnRollbackAndExpiresIt(t *testing.T) {
	rp, browser, connection, signer := samlWorkforceFixture(t, http.MethodPost, false)
	path, _ := browser.begin(t, oauth2.GenerateVerifier(), "saml-state", "saml-nonce")
	requestID, relay := startSAMLBrowser(t, browser, connection, path, http.MethodPost)
	payload := signedSAMLTestResponseForAudience(t, signer, connection.RedirectURI, rp.host.URL+"/saml/"+connection.ID, requestID, "saml-workforce", nil, false)
	form := url.Values{"RelayState": {relay}, "SAMLResponse": {payload}}.Encode()
	postSAMLBrowserForm(t, rp, connection.RedirectURI, form, "application/x-www-form-urlencoded", "", http.StatusSeeOther)

	ctx := t.Context()
	if _, err := rp.st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_saml_browser_binding() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'test SAML interaction binding failure'; END;
		$$;
		CREATE TRIGGER reject_saml_browser_binding BEFORE UPDATE OF browser_session_id ON oidc_login_requests
		FOR EACH ROW WHEN (NEW.browser_session_id IS NOT NULL) EXECUTE FUNCTION reject_saml_browser_binding();
	`); err != nil {
		t.Fatal(err)
	}
	browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusServiceUnavailable)
	var consumed bool
	var sessions, identities, audited int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT s.consumed_at IS NOT NULL,
		(SELECT count(*) FROM sessions WHERE sso_connection_id=$1),
		(SELECT count(*) FROM external_identities WHERE subject='saml-workforce'),
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.login')
		FROM sso_states s JOIN saml_browser_responses p ON p.state_id=s.id`, connection.ID).Scan(&consumed, &sessions, &identities, &audited); err != nil ||
		consumed || sessions != 0 || identities != 0 || audited != 0 {
		t.Fatal("failed session binding changed the pending response or committed login")
	}
	if _, err := rp.st.Pool.Exec(ctx, `
		DROP TRIGGER reject_saml_browser_binding ON oidc_login_requests;
		UPDATE saml_browser_responses SET received_at=clock_timestamp()-interval '2 minutes',
			expires_at=clock_timestamp()-interval '1 minute';
	`); err != nil {
		t.Fatal(err)
	}
	browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusBadRequest)
	if err := rp.workforce.ExpireSAMLBrowserResponses(ctx); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := rp.st.Pool.QueryRow(ctx, "SELECT count(*) FROM saml_browser_responses").Scan(&pending); err != nil || pending != 0 {
		t.Fatal("expired encrypted responses were not removed")
	}
}
