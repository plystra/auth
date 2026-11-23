package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/db"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

func (rp *humanRP) publisherPost(t *testing.T, path string, body any, result any) {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.host.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal("could not create publisher request")
	}
	req.Header.Set("Authorization", "Bearer "+rp.session.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := rp.host.Client().Do(req)
	if err != nil {
		t.Fatal("publisher request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publisher %s returned HTTP %d", path, resp.StatusCode)
	}
	if result != nil && json.NewDecoder(resp.Body).Decode(result) != nil {
		t.Fatal("publisher response was invalid")
	}
}

func (rp *humanRP) provePublisherRequest(t *testing.T, operation string, body any, at time.Time) {
	t.Helper()
	code, err := totp.GenerateCode(rp.factorSecret.Value(), at)
	if err != nil {
		t.Fatal("could not generate a step-up code")
	}
	rp.publisherPost(t, "/v1/auth/step-up", map[string]any{"operation": operation, "request": body, "mfa_code": code}, nil)
}

func (rp *humanRP) registerClient(t *testing.T, space string) {
	t.Helper()
	body := map[string]any{"name": "Test RP", "manifest_permissions": []string{}, "redirect_uris": []string{rp.config.RedirectURL},
		"human_oidc_enabled": true, "token_endpoint_auth_method": "client_secret_basic"}
	proof := maps.Clone(body)
	proof["space_id"] = space
	rp.provePublisherRequest(t, "applications.register", proof, time.Now())
	var created struct {
		Data application.RegisteredApplication
	}
	rp.publisherPost(t, "/v1/spaces/"+space+"/applications", body, &created)
	if created.Data.ClientID == "" || created.Data.ClientSecret.Value() == "" {
		t.Fatal("registration did not return client credentials")
	}
	rp.applicationID, rp.config.ClientID, rp.config.ClientSecret = created.Data.ID, created.Data.ClientID, created.Data.ClientSecret.Value()
}

func clientForm(t *testing.T, endpoint string, form url.Values, method, clientID, password string) *http.Request {
	t.Helper()
	if method == "post" || method == "mixed" {
		form.Set("client_secret", password)
	}
	if method != "anonymous" && method != "malformed" {
		form.Set("client_id", clientID)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal("could not construct a protocol request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	switch method {
	case "basic", "mixed":
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(password))
	case "malformed":
		req.Header.Set("Authorization", "Basic !!!")
	}
	return req
}

func requireInvalidClient(t *testing.T, res *http.Response, realm string) {
	t.Helper()
	defer func() { _ = res.Body.Close() }()
	var problem struct {
		Error string `json:"error"`
	}
	if res.StatusCode != http.StatusUnauthorized || json.NewDecoder(res.Body).Decode(&problem) != nil || problem.Error != "invalid_client" ||
		res.Header.Get("WWW-Authenticate") != `Basic realm="`+realm+`"` || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("invalid client response for %s: HTTP %d", realm, res.StatusCode)
	}
}

func TestPublisherManagedBasicRelyingPartyLoginAndRevocation(t *testing.T) {
	rp := humanRPWithAuthMethod(t, true)
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	var metadata struct {
		Token      []string `json:"token_endpoint_auth_methods_supported"`
		Revocation []string `json:"revocation_endpoint_auth_methods_supported"`
		Revoke     string   `json:"revocation_endpoint"`
	}
	if err := rp.provider.Claims(&metadata); err != nil || !slices.Contains(metadata.Token, "client_secret_basic") ||
		!slices.Contains(metadata.Revocation, "client_secret_basic") || metadata.Revoke != rp.host.URL+"/oauth/revoke" {
		t.Fatal("relying party cannot discover confidential client authentication")
	}
	code, verifier := rp.authorize(t, "openid", "email")
	send := func(req *http.Request) *http.Response {
		t.Helper()
		res, err := rp.host.Client().Do(req)
		if err != nil {
			t.Fatal("relying party HTTP request failed")
		}
		return res
	}
	for _, method := range []string{"anonymous", "none", "basic", "post", "mixed", "malformed"} {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {rp.config.RedirectURL}}
		password := rp.config.ClientSecret
		if method == "basic" {
			password = "incorrect"
		}
		requireInvalidClient(t, send(clientForm(t, rp.config.Endpoint.TokenURL, form, method, rp.config.ClientID, password)), "oauth/token")
	}
	rp.provePublisherRequest(t, application.RotateOAuthSecretOperation, map[string]any{"application_id": rp.applicationID, "grace_period_seconds": 0}, time.Now().Add(30*time.Second))
	var rotated struct {
		Data application.OAuthSecretRotation
	}
	rp.publisherPost(t, "/v1/applications/"+rp.applicationID+"/oauth-client-secret/rotate", map[string]any{"grace_period_seconds": 0}, &rotated)
	expired := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {rp.config.RedirectURL}}
	requireInvalidClient(t, send(clientForm(t, rp.config.Endpoint.TokenURL, expired, "basic", rp.config.ClientID, rp.config.ClientSecret)), "oauth/token")
	rp.config.ClientSecret = rotated.Data.ClientSecret.Value()
	token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil || token == nil {
		t.Fatal("authenticated PKCE exchange failed after rejected credentials")
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		t.Fatal("missing ID token")
	}
	if _, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, rawID); err != nil {
		t.Fatal("relying party rejected the ID token")
	}
	access := oauth2.StaticTokenSource(token)
	revoke := func(clientID, password, method string) *http.Response {
		return send(clientForm(t, metadata.Revoke, url.Values{"token": {token.AccessToken}}, method, clientID, password))
	}
	for _, method := range []string{"anonymous", "none", "basic", "post", "mixed", "malformed"} {
		password := rp.config.ClientSecret
		if method == "basic" {
			password = "incorrect"
		}
		requireInvalidClient(t, revoke(rp.config.ClientID, password, method), "oauth/revoke")
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO applications(id,space_id,name,client_id) SELECT 'app_other_rp',space_id,'Other RP','other-rp' FROM applications WHERE id=$1`, rp.applicationID); err != nil {
		t.Fatal(err)
	}
	foreign := revoke("other-rp", "", "none")
	_ = foreign.Body.Close()
	if foreign.StatusCode != http.StatusOK {
		t.Fatalf("cross-client revocation revealed token ownership: HTTP %d", foreign.StatusCode)
	}
	if _, err := rp.provider.UserInfo(ctx, access); err != nil {
		t.Fatal("failed or foreign revocation consumed the access token")
	}
	for range 2 {
		res := revoke(rp.config.ClientID, rp.config.ClientSecret, "basic")
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("authenticated revocation failed: HTTP %d", res.StatusCode)
		}
	}
	if _, err := rp.provider.UserInfo(ctx, access); err == nil {
		t.Fatal("revoked UserInfo credential remained usable")
	}
}

func TestManagedAgentCodeAndRefreshRequireBasicBeforeConsumption(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		t.Run(grant, func(t *testing.T) {
			password := "ply_ocs_" + oauth2.GenerateVerifier()
			f := redemptionFixtureWithSecret(t, password)
			send := func(method, supplied string) *httptest.ResponseRecorder {
				form := f.form(grant)
				form.Del("client_id")
				out := httptest.NewRecorder()
				f.handler.ServeHTTP(out, clientForm(t, "/oauth/token", form, method, "app_redemption", supplied))
				return out
			}
			for _, method := range []string{"anonymous", "none", "post", "basic"} {
				supplied := password
				if method == "basic" {
					supplied = "incorrect"
				}
				requireInvalidClient(t, send(method, supplied).Result(), "oauth/token")
				f.assertUnchanged(t)
			}
			if out := send("basic", password); out.Code != http.StatusOK {
				t.Fatalf("valid Basic exchange returned HTTP %d", out.Code)
			}
		})
	}
}

func TestManagedAgentRevocationAuthenticatesTokenOwner(t *testing.T) {
	for _, kind := range []string{"refresh", "access", "governance"} {
		t.Run(kind, func(t *testing.T) {
			password := "ply_ocs_" + oauth2.GenerateVerifier()
			f := redemptionFixtureWithSecret(t, password)
			ctx := t.Context()
			raw, audience := f.refresh, "app_redemption"
			if kind == "governance" {
				audience = "default"
			}
			access, err := f.sessions.CreateAgentAccess(ctx, f.agent.ID, f.owner.SpaceID, audience)
			if err != nil {
				t.Fatal(err)
			}
			if kind != "refresh" {
				raw = access.AccessToken
			}
			send := func(method, id, supplied string) *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				f.handler.ServeHTTP(out, clientForm(t, "/oauth/revoke", url.Values{"token": {raw}}, method, id, supplied))
				return out
			}
			for _, method := range []string{"anonymous", "none", "post", "basic"} {
				supplied := password
				if method == "basic" {
					supplied = "incorrect"
				}
				requireInvalidClient(t, send(method, "app_redemption", supplied).Result(), "oauth/revoke")
			}
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO applications(id,space_id,name,client_id) VALUES('app_other_rp',$1,'Other RP','other-rp')`, f.owner.SpaceID); err != nil {
				t.Fatal(err)
			}
			if resp := send("none", "other-rp", ""); resp.Code != http.StatusOK || resp.Body.Len() != 0 {
				t.Fatal("cross-client revocation disclosed token ownership")
			}
			if _, active, err := f.sessions.Introspect(ctx, access.AccessToken, audience); err != nil || !active {
				t.Fatal("rejected revocation changed the OAuth identity")
			}
			if resp := send("basic", "app_redemption", password); resp.Code != http.StatusOK || resp.Body.Len() != 0 {
				t.Fatalf("client could not revoke its own token: HTTP %d", resp.Code)
			}
			if _, active, err := f.sessions.Introspect(ctx, access.AccessToken, audience); err != nil || active {
				t.Fatal("revoked OAuth identity is still active")
			}
		})
	}
}

func TestManagedRevocationRevalidatesSecretAfterConcurrentRotation(t *testing.T) {
	oldSecret, newSecret := "ply_ocs_"+oauth2.GenerateVerifier(), "ply_ocs_"+oauth2.GenerateVerifier()
	f := redemptionFixtureWithSecret(t, oldSecret)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	mutation, err := f.store.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
	if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error {
		tx, _ := q.Transaction()
		_, err := tx.Exec(ctx, `UPDATE applications SET oauth_client_secret_hash=$1 WHERE id='app_redemption'`,
			application.HMACClientSecretHash(f.applications.HMACKeys[0], newSecret))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	send := func(password string) *httptest.ResponseRecorder {
		req := clientForm(t, "/oauth/revoke", url.Values{"token": {f.refresh}}, "basic", "app_redemption", password)
		out := httptest.NewRecorder()
		f.handler.ServeHTTP(out, req.WithContext(ctx))
		return out
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- send(oldSecret) }()
	waitForRedemptionLock(t, ctx, f.store, result)
	if err := mutation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	requireInvalidClient(t, (<-result).Result(), "oauth/revoke")
	var revoked bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_credentials WHERE revoked_at IS NOT NULL)`).Scan(&revoked); err != nil || revoked {
		t.Fatal("an expired credential revoked the target")
	}
	if out := send(newSecret); out.Code != http.StatusOK {
		t.Fatalf("fresh credential could not revoke token: HTTP %d", out.Code)
	}
}
