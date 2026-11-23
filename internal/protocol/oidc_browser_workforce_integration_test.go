package protocol

import (
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
	"golang.org/x/oauth2"
)

const browserEmployee = "employee@workforce.example.test"

func workforceBrowser(t *testing.T) (*humanRP, oidcBrowser, *oidcTestProvider, enterprise.Connection) {
	t.Helper()
	upstream := newOIDCTestProvider(t)
	rp := newConfiguredHumanRP(t, false, upstream)
	authz := rp.workforce.Authorization
	ctx := t.Context()
	space, owner, err := authz.CreateSpace(ctx, "usr_human_rp", "Workforce", "workforce")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_rp_workforce',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, "usr_human_rp"), owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce OIDC", Provider: "oidc", Issuer: upstream.issuer, ClientID: "workforce-client",
		ClientSecret: "fixture-client-secret", RedirectURI: rp.host.URL + "/oidc/upstream",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO sso_domains (id,space_id,domain,verification_token_hash,connection_id,force_sso,status,verified_at)
		VALUES ('dom_rp_workforce',$1,'workforce.example.test',decode(repeat('00',32),'hex'),$2,true,'verified',clock_timestamp())`, space.ID, connection.ID); err != nil {
		t.Fatal(err)
	}
	return rp, newOIDCBrowser(t, rp), upstream, connection
}

func startWorkforceBrowser(t *testing.T, browser oidcBrowser, upstream *oidcTestProvider, connection enterprise.Connection, path string, extra map[string]any) map[string]string {
	t.Helper()
	identified, _ := browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": browserEmployee, "method": "password"}, browser.rp.host.URL, "", http.StatusOK)
	if identified.NextStep != "sso" || identified.SSOConnectionID != connection.ID {
		t.Fatal("the browser did not route the account to its required connection")
	}
	upstreamURL, err := url.Parse(identified.AuthorizationURL)
	if err != nil || upstreamURL.Scheme+"://"+upstreamURL.Host+upstreamURL.Path != upstream.issuer+"/authorize" {
		t.Fatal("the interaction did not provide a navigation to the configured IdP")
	}
	query := upstreamURL.Query()
	if query.Get("client_id") != "workforce-client" || query.Get("redirect_uri") != connection.RedirectURI ||
		query.Get("code_challenge_method") != "S256" || query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge") == "" {
		t.Fatal("the upstream request did not bind the callback, state, nonce and PKCE")
	}
	code := oauth2.GenerateVerifier()
	upstream.addCode(code, oidcTestCode{
		nonce: query.Get("nonce"), subject: "stable-employee", email: browserEmployee, emailVerified: true,
		challenge: query.Get("code_challenge"), redirectURI: query.Get("redirect_uri"), extra: extra,
	})
	return map[string]string{"state": query.Get("state"), "code": code}
}

func TestOIDCBrowserWorkforceContinuesAtIndependentRelyingParty(t *testing.T) {
	rp, browser, upstream, connection := workforceBrowser(t)
	origin := rp.host.URL
	callback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(callback.Close)
	rp.config.RedirectURL = callback.URL + "/callback"
	if _, err := rp.st.Pool.Exec(t.Context(), `UPDATE applications SET redirect_uris=jsonb_build_array($1::text) WHERE client_id=$2`, rp.config.RedirectURL, rp.config.ClientID); err != nil {
		t.Fatal(err)
	}
	verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	path, _ := browser.begin(t, verifier, state, nonce)
	authenticatedAt := time.Now().Add(-time.Hour).Unix()
	upstreamCallback := startWorkforceBrowser(t, browser, upstream, connection, path, map[string]any{"auth_time": authenticatedAt})
	read, _ := browser.request(t, http.MethodGet, path, nil, "", "", http.StatusOK)
	if read.NextStep != "sso" || read.SSOConnectionID != connection.ID || read.AuthorizationURL != "" {
		t.Fatal("the interaction did not retain the pending upstream step")
	}
	id := strings.TrimPrefix(path, route.OIDCInteractionsPath+"/")
	var capped bool
	if err := rp.st.Pool.QueryRow(t.Context(), `SELECT s.expires_at <= r.expires_at AND s.browser_bound FROM oidc_login_requests r
		JOIN sso_states s ON s.id=r.browser_sso_state_id WHERE r.id=$1`, id).Scan(&capped); err != nil || !capped {
		t.Fatal("the upstream state can outlive its bound interaction")
	}
	other := newOIDCBrowser(t, rp)
	otherPath, _ := other.begin(t, oauth2.GenerateVerifier(), "other-state", "other-nonce")
	_ = startWorkforceBrowser(t, other, upstream, connection, otherPath, nil)
	ordinary := "/v1/sso/" + connection.ID
	ordinaryState, _ := browser.request(t, http.MethodGet, ordinary+"/start", nil, "", "", http.StatusOK)
	ordinaryURL, err := url.Parse(ordinaryState.AuthorizationURL)
	if err != nil || ordinaryURL.Query().Get("state") == "" {
		t.Fatal("ordinary SSO did not start")
	}
	before := upstream.discoveryRequests.Load()
	browser.request(t, http.MethodPost, ordinary+"/callback", upstreamCallback, "", "", http.StatusBadRequest)
	other.request(t, http.MethodPost, otherPath+"/sso/complete", upstreamCallback, origin, "", http.StatusBadRequest)
	other.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, origin, "", http.StatusBadRequest)
	browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, "https://other.example.test", "", http.StatusForbidden)
	browser.request(t, http.MethodPost, path+"/sso/complete", map[string]string{"state": ordinaryURL.Query().Get("state"), "code": upstreamCallback["code"]}, origin, "", http.StatusBadRequest)
	if upstream.discoveryRequests.Load() != before {
		t.Fatal("a swapped state or browser reached the provider")
	}
	result, _ := browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, origin, "", http.StatusOK)
	if result.NextStep != "consent" || result.Email != browserEmployee {
		t.Fatal("enterprise authentication did not resume application consent")
	}
	browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, origin, "", http.StatusBadRequest)
	decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, origin, "", http.StatusOK)
	callbackURL, err := url.Parse(decision.RedirectTo)
	if err != nil || callbackURL.Scheme+"://"+callbackURL.Host+callbackURL.Path != rp.config.RedirectURL || callbackURL.Query().Get("state") != state {
		t.Fatal("consent changed the registered callback or application state")
	}
	res, err := callback.Client().Get(decision.RedirectTo)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatal("the registered relying-party callback failed")
	}
	_ = res.Body.Close()
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	tokens, err := rp.config.Exchange(ctx, callbackURL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("the relying party could not redeem the code")
	}
	raw, _ := tokens.Extra("id_token").(string)
	identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(ctx, raw)
	if err != nil || identity.Nonce != nonce {
		t.Fatal("the relying party could not verify the Auth ID Token")
	}
	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}
	if err := identity.Claims(&claims); err != nil || claims.AuthTime != authenticatedAt || claims.AuthTime >= identity.IssuedAt.Unix() {
		t.Fatal("the signed ID Token did not preserve the actual upstream authentication time")
	}
	info, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
	if err != nil || info.Subject != identity.Subject || info.Email != browserEmployee || !info.EmailVerified {
		t.Fatal("the relying party received the wrong workforce identity")
	}
	var audited int
	if err := rp.st.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_logs WHERE action='auth.sso.login'
		AND actor_id=$1 AND user_id=$2 AND outcome='success'`, connection.ID, identity.Subject).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("enterprise sign-in was not audited once for the signed-in identity")
	}
}

func TestOIDCBrowserWorkforceOmitsUnverifiedAuthenticationTime(t *testing.T) {
	rp, browser, upstream, connection := workforceBrowser(t)
	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{name: "absent"},
		{name: "malformed", extra: map[string]any{"auth_time": "untrusted"}},
		{name: "future", extra: map[string]any{"auth_time": time.Now().Add(time.Hour).Unix()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := oauth2.GenerateVerifier()
			path, _ := browser.begin(t, verifier, oauth2.GenerateVerifier(), oauth2.GenerateVerifier())
			callback := startWorkforceBrowser(t, browser, upstream, connection, path, tc.extra)
			browser.request(t, http.MethodPost, path+"/sso/complete", callback, rp.host.URL, "", http.StatusOK)
			decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
			redirect, err := url.Parse(decision.RedirectTo)
			if err != nil {
				t.Fatal(err)
			}
			ctx := oidc.ClientContext(t.Context(), rp.host.Client())
			tokens, err := rp.config.Exchange(ctx, redirect.Query().Get("code"), oauth2.VerifierOption(verifier))
			if err != nil {
				t.Fatal("the relying party could not redeem the code")
			}
			raw, _ := tokens.Extra("id_token").(string)
			identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(ctx, raw)
			if err != nil {
				t.Fatal("the relying party could not verify the Auth ID Token")
			}
			var claims map[string]any
			if err := identity.Claims(&claims); err != nil {
				t.Fatal(err)
			}
			if _, exists := claims["auth_time"]; exists {
				t.Fatal("the signed ID Token carried authentication time without valid upstream evidence")
			}
		})
	}
}

func TestOIDCBrowserWorkforceRollsBackWhenInteractionBindingFails(t *testing.T) {
	rp, browser, upstream, connection := workforceBrowser(t)
	path, _ := browser.begin(t, oauth2.GenerateVerifier(), "rollback-state", "rollback-nonce")
	upstreamCallback := startWorkforceBrowser(t, browser, upstream, connection, path, nil)
	ctx := t.Context()
	if _, err := rp.st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_workforce_browser_binding() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'test workforce interaction binding failure'; END;
		$$;
		CREATE TRIGGER reject_workforce_browser_binding BEFORE UPDATE OF browser_session_id ON oidc_login_requests
		FOR EACH ROW WHEN (NEW.browser_session_id IS NOT NULL) EXECUTE FUNCTION reject_workforce_browser_binding();
	`); err != nil {
		t.Fatal(err)
	}
	browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, rp.host.URL, "", http.StatusServiceUnavailable)
	var consumed bool
	var sessions, identities, credentials, audited int
	id := strings.TrimPrefix(path, route.OIDCInteractionsPath+"/")
	if err := rp.st.Pool.QueryRow(ctx, `SELECT s.consumed_at IS NOT NULL,
		(SELECT count(*) FROM sessions WHERE sso_connection_id=$2),
		(SELECT count(*) FROM external_identities WHERE subject='stable-employee'),
		(SELECT count(*) FROM refresh_tokens),
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.login')
		FROM oidc_login_requests r JOIN sso_states s ON s.id=r.browser_sso_state_id WHERE r.id=$1`, id, connection.ID).
		Scan(&consumed, &sessions, &identities, &credentials, &audited); err != nil || consumed || sessions != 0 || identities != 0 || credentials != 1 || audited != 0 {
		t.Fatal("failed binding committed workforce state, identity or credentials")
	}
	if _, err := rp.st.Pool.Exec(ctx, `DROP TRIGGER reject_workforce_browser_binding ON oidc_login_requests`); err != nil {
		t.Fatal(err)
	}
	browser.request(t, http.MethodPost, path+"/sso/complete", upstreamCallback, rp.host.URL, "", http.StatusBadRequest)
	newPath, _ := browser.begin(t, oauth2.GenerateVerifier(), "retry-state", "retry-nonce")
	fresh := startWorkforceBrowser(t, browser, upstream, connection, newPath, nil)
	result, _ := browser.request(t, http.MethodPost, newPath+"/sso/complete", fresh, rp.host.URL, "", http.StatusOK)
	if result.NextStep != "consent" || result.Email != browserEmployee {
		t.Fatal("a fresh upstream login could not resume consent after rollback")
	}
}
