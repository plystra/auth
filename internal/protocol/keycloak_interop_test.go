//go:build interop

package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/stepup"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

const (
	keycloakRealm        = "workforce-interop"
	keycloakClientID     = "workforce-rp"
	keycloakClientSecret = "fixture-workforce-client-secret"
	keycloakUserPassword = "fixture-workforce-user-password"
	keycloakEmployeeID   = "0ecc4840-867d-4867-8893-386e38e31839"
)

func TestKeycloakWorkforceOIDCUsesCurrentRoleMapping(t *testing.T) {
	ctx := t.Context()
	st, authz, svc, owner, spaceID, _ := newSSOHTTPFixture(t)
	svc.StepUp = svc.Sessions
	mux := http.NewServeMux()
	(&principal.API{Authorization: authz, Sessions: svc.Sessions, Enterprise: svc}).Register(
		humago.New(mux, route.HumaConfig("Workforce interop", "1")))
	(HTTP{Enterprise: svc}).Register(mux)
	host := httptest.NewTLSServer(route.Middleware(route.Principal, mux))
	t.Cleanup(host.Close)
	callback := host.URL + "/oidc/return"
	issuer, transport := keycloakFixture(t, callback)
	svc.HTTPClient = &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)

	const ownerUser = "usr_sso_http_owner"
	actor := authorization.WithHumanActor(ctx, owner.ID, ownerUser)
	role := func(name string) string {
		t.Helper()
		created, err := authz.CreateRole(actor, owner.ID, spaceID, name, "", []string{"auth.members:read"})
		if err != nil {
			t.Fatal(err)
		}
		return created.ID
	}
	oldRole, newRole := role("Original engineering"), role("Updated engineering")
	connection, err := svc.CreateConnection(actor, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Keycloak Workforce", Provider: "oidc", Issuer: issuer, ClientID: keycloakClientID,
		ClientSecret: keycloakClientSecret, RedirectURI: callback, RoleMappings: map[string]string{"engineering": oldRole},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: host}
	login := func(username string) account.AuthResult {
		t.Helper()
		path := "/v1/sso/" + connection.ID
		started := keycloakInteropData[enterprise.StartResult](t, "start", client.send(t, http.MethodGet, path+"/start", "", "", "", nil))
		returned := keycloakAuthorize(t, transport, started.AuthorizationURL, callback, username)
		if returned.Get("state") != started.State || returned.Get("code") == "" {
			t.Fatal("Keycloak return did not match the authorization request")
		}
		body := map[string]string{"state": returned.Get("state"), "code": returned.Get("code"), "redirect_uri": callback}
		result := keycloakInteropData[account.AuthResult](t, "callback", client.send(t, http.MethodPost, path+"/callback", "", "application/json", "", body))
		if result.Tokens == nil || !result.User.EmailVerified {
			t.Fatal("verified Keycloak login did not establish a session")
		}
		return result
	}
	assertRole := func(login account.AuthResult, present, absent string) {
		t.Helper()
		claims, err := svc.Sessions.VerifyAccess(ctx, login.Tokens.AccessToken)
		if err != nil || claims.MemberID == "" {
			t.Fatal("employee session did not bind a current member")
		}
		var count, unexpected int
		err = st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE role_id=$2), count(*) FILTER (WHERE role_id=$3)
			FROM authorization_grants WHERE grantee_member_id=$1 AND revoked_at IS NULL`, claims.MemberID, present, absent).Scan(&count, &unexpected)
		if err != nil || count != 1 || unexpected != 0 {
			t.Fatalf("unexpected role grants: expected=%d other=%d err=%v", count, unexpected, err)
		}
	}
	initial := login("original")
	assertRole(initial, oldRole, newRole)
	admin, err := svc.Sessions.CreateForMember(ctx, ownerUser, owner.ID, nil, "interop", 1)
	if err != nil {
		t.Fatal(err)
	}
	mappings := map[string]string{"engineering": newRole}
	digest, err := stepup.DigestValue(enterprise.SSORoleMappingUpdateRequest(spaceID, connection.ID, connection.ETag(), mappings))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2, step_up_digest=$3,
		step_up_method='totp', step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, admin.SessionID, enterprise.SSOConnectionUpdateOperation, digest); err != nil {
		t.Fatal(err)
	}
	updated := client.send(t, http.MethodPatch, "/v1/spaces/"+spaceID+"/sso-connections/"+connection.ID,
		admin.AccessToken, "application/json", connection.ETag(), map[string]any{"role_mappings": mappings})
	updated.requireStatus(t, http.StatusOK)
	assertRole(login("newcomer"), newRole, oldRole)
	again := login("original")
	if again.User.ID != initial.User.ID {
		t.Fatal("repeat Keycloak login did not reuse the original identity")
	}
	assertRole(again, oldRole, newRole)
}

func TestKeycloakExistingAccountLinksAndSignsInToRelyingParty(t *testing.T) {
	ctx := t.Context()
	upstream := &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	rp := newHumanRPWithWorkforce(t, false, upstream)
	callback := rp.host.URL + "/oidc/upstream"
	issuer, transport := keycloakFixture(t, callback)
	upstream.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)

	const userID, username, email = "usr_human_rp", "original", "original@workforce.example.test"
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE users SET email=$2,email_normalized=$2 WHERE id=$1`, userID, email); err != nil {
		t.Fatal(err)
	}
	authz := rp.workforce.Authorization
	space, owner, err := authz.CreateSpace(ctx, userID, "Workforce", "workforce")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_keycloak_link',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, userID), owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce Keycloak", Provider: "oidc", Issuer: issuer, ClientID: keycloakClientID,
		ClientSecret: keycloakClientSecret, RedirectURI: callback,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO sso_domains (id,space_id,domain,verification_token_hash,connection_id,force_sso,status,verified_at)
		VALUES ('dom_keycloak_link',$1,'workforce.example.test',decode(repeat('00',32),'hex'),$2,true,'verified',clock_timestamp())`, space.ID, connection.ID); err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	post := func(path, bearer string, payload any) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPost, path, bearer, "application/json", "", payload)
	}
	sso := "/v1/sso/" + connection.ID
	before := keycloakInteropData[enterprise.StartResult](t, "pre-link start", client.send(t, http.MethodGet, sso+"/start", "", "", "", nil))
	login := keycloakAuthorize(t, transport, before.AuthorizationURL, callback, username)
	post(sso+"/callback", "", map[string]string{"state": login.Get("state"), "code": login.Get("code")}).requireError(t, http.StatusConflict, "conflict")

	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(ctx, userID, email)
	if err != nil {
		t.Fatal(err)
	}
	link := "/v1/me/sso-links/" + connection.ID
	started := keycloakInteropData[enterprise.StartResult](t, "link start", post(link+"/start", rp.session.AccessToken, nil))
	returned := keycloakAuthorize(t, transport, started.AuthorizationURL, callback, username)
	state, code := returned.Get("state"), returned.Get("code")
	if state != started.State || code == "" {
		t.Fatal("Keycloak did not return the requested linking state")
	}
	mfa, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	post("/v1/auth/step-up", rp.session.AccessToken, map[string]any{"operation": enterprise.CompleteIdentityLinkOperation,
		"request": enterprise.IdentityLinkProofRequest(connection.ID, state, code), "mfa_code": mfa}).requireStatus(t, http.StatusOK)
	confirmed := keycloakInteropData[struct{ Linked bool }](t, "link completion", post(link+"/complete", rp.session.AccessToken,
		map[string]string{"state": state, "code": code}))
	if !confirmed.Linked {
		t.Fatal("binding was not confirmed")
	}

	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(app.Close)
	rp.config.RedirectURL = app.URL + "/callback"
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE applications SET redirect_uris=jsonb_build_array($1::text) WHERE client_id=$2`, rp.config.RedirectURL, rp.config.ClientID); err != nil {
		t.Fatal(err)
	}
	browser := newOIDCBrowser(t, rp)
	verifier, appState, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	path := browser.beginFromAuthorization(t, verifier, appState, nonce)
	identified, _ := browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": email, "method": "password"}, rp.host.URL, "", http.StatusOK)
	if identified.NextStep != "sso" || identified.SSOConnectionID != connection.ID {
		t.Fatal("application did not route to the required enterprise connection")
	}
	returned = keycloakAuthorize(t, transport, identified.AuthorizationURL, callback, username)
	view, _ := browser.request(t, http.MethodPost, path+"/sso/complete", map[string]string{"state": returned.Get("state"), "code": returned.Get("code")}, rp.host.URL, "", http.StatusOK)
	if view.NextStep != "consent" || view.Email != email {
		t.Fatal("enterprise login did not continue to application consent")
	}
	decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
	redirect, err := url.Parse(decision.RedirectTo)
	if err != nil || redirect.Query().Get("state") != appState || redirect.Scheme+"://"+redirect.Host+redirect.Path != rp.config.RedirectURL {
		t.Fatal("application redirect changed the registered callback or state")
	}
	response, err := app.Client().Get(decision.RedirectTo)
	if err != nil {
		t.Fatal("application callback was unavailable")
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("application callback failed")
	}
	oidcContext := oidc.ClientContext(ctx, rp.host.Client())
	tokens, err := rp.config.Exchange(oidcContext, redirect.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("relying party could not redeem the authorization code")
	}
	raw, _ := tokens.Extra("id_token").(string)
	verified, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(oidcContext, raw)
	if err != nil || verified.Subject != userID || verified.Nonce != nonce {
		t.Fatal("relying party could not verify the original local account and nonce")
	}
	var linked, signedIn int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='auth.sso.identity.link'),count(*) FILTER (WHERE action='auth.sso.login')
		FROM audit_logs WHERE user_id=$1 AND member_id=$2 AND outcome='success'`, userID, owner.ID).Scan(&linked, &signedIn); err != nil || linked != 1 || signedIn != 1 {
		t.Fatal("link and application login were not audited for the original member")
	}
}

func TestKeycloakDirectoryEmployeeLosesRelyingPartyAccessOnOffboarding(t *testing.T) {
	testKeycloakDirectoryEmployee(t, "oidc")
}

func TestKeycloakSAMLDirectoryEmployeeLosesRelyingPartyAccessOnOffboarding(t *testing.T) {
	testKeycloakDirectoryEmployee(t, "saml")
}

func testKeycloakDirectoryEmployee(t *testing.T, provider string) {
	t.Helper()
	upstream := &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	rp := newHumanRPWithWorkforce(t, false, upstream)
	callback := rp.host.URL + "/oidc/upstream"
	var options []testcontainers.ContainerCustomizer
	adminPassword := ""
	if provider == "saml" {
		adminPassword = oauth2.GenerateVerifier()
		options = append(options, testcontainers.WithEnv(map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": keycloakFixtureAdmin,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": adminPassword,
		}))
	}
	issuer, transport := keycloakFixture(t, callback, options...)
	upstream.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)

	ctx := t.Context()
	const adminID = "usr_human_rp"
	const employeeEmail = "original@workforce.example.test"
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, adminID, "Workforce", "workforce")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_keycloak_directory',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	admin := authorization.WithHumanActor(ctx, owner.ID, adminID)
	input := enterprise.ConnectionInput{
		Name: "Workforce Keycloak", Provider: "oidc", Issuer: issuer, ClientID: keycloakClientID,
		ClientSecret: keycloakClientSecret, RedirectURI: callback,
	}
	claim := "sub"
	if provider == "saml" {
		input = enterprise.ConnectionInput{
			Name: "Workforce Keycloak SAML", Provider: "saml",
			SAMLMetadata: fetchKeycloakSAMLMetadata(t, upstream, issuer),
			RedirectURI:  rp.host.URL + route.SAMLBrowserCallbackPrefix + "{connection_id}",
		}
		claim = keycloakSAMLDirectoryClaim
	}
	connection, err := rp.workforce.CreateConnection(admin, owner.ID, space.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if provider == "saml" {
		registerKeycloakSAMLClient(t, upstream, issuer, adminPassword, rp.host.URL+"/saml/"+connection.ID, connection.RedirectURI)
	}
	directory, err := rp.workforce.CreateDirectory(admin, owner.ID, space.ID, enterprise.DirectoryInput{
		Name: "Workforce directory", SSOConnectionID: connection.ID, SSOIdentityClaim: claim,
	})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := rp.workforce.CreateDomain(admin, owner.ID, space.ID,
		enterprise.DomainInput{Domain: "workforce.example.test", ConnectionID: connection.ID, ForceSSO: true})
	if err != nil {
		t.Fatal(err)
	}
	rp.workforce.DNSResolver = employeeDomainResolver{domain.VerificationToken}
	if err := rp.workforce.VerifyDomain(admin, owner.ID, space.ID, domain.ID); err != nil {
		t.Fatal(err)
	}
	app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(app.Close)
	rp.config.RedirectURL = app.URL + "/callback"
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE applications SET redirect_uris=jsonb_build_array($1::text) WHERE client_id=$2`, rp.config.RedirectURL, rp.config.ClientID); err != nil {
		t.Fatal(err)
	}

	client := employeeLifecycleClient{server: rp.host}
	const scim = "application/scim+json"
	users := "/scim/v2/" + directory.ID + "/Users"
	created := client.send(t, http.MethodPost, users, directory.Token.Value(), scim, "", map[string]any{
		"externalId": keycloakEmployeeID, "userName": employeeEmail, "displayName": "Workforce Employee", "active": true,
	})
	created.requireStatus(t, http.StatusCreated)
	var employee scimTestResource
	if err := json.Unmarshal(created.body, &employee); err != nil || employee.ID == "" || created.etag == "" {
		t.Fatal("SCIM did not provision the employee")
	}
	setActive := func(active bool, version string) string {
		t.Helper()
		result := client.send(t, http.MethodPatch, users+"/"+employee.ID, directory.Token.Value(), scim, version, map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
		})
		result.requireStatus(t, http.StatusOK)
		if result.etag == "" || result.etag == version {
			t.Fatal("SCIM did not advance the employee version")
		}
		return result.etag
	}

	browser := newOIDCBrowser(t, rp)
	consent := func(status int) (code, verifier, nonce string) {
		t.Helper()
		verifier, nonce, state := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		path := browser.beginFromAuthorization(t, verifier, state, nonce)
		identified, _ := browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": employeeEmail, "method": "password"}, rp.host.URL, "", http.StatusOK)
		if identified.NextStep != "sso" || identified.SSOConnectionID != connection.ID {
			t.Fatal("the employee was not routed to Keycloak")
		}
		var loggedIn interactionResponse
		if provider == "saml" {
			keycloakSAMLCallback(t, rp, transport, issuer, connection.RedirectURI, path, identified)
			loggedIn, _ = browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", status)
		} else {
			returned := keycloakAuthorize(t, transport, identified.AuthorizationURL, callback, "original")
			loggedIn, _ = browser.request(t, http.MethodPost, path+"/sso/complete", map[string]string{"state": returned.Get("state"), "code": returned.Get("code")}, rp.host.URL, "", status)
		}
		if status != http.StatusOK {
			return "", "", ""
		}
		if loggedIn.NextStep != "consent" || loggedIn.Email != employeeEmail {
			t.Fatal("the directory employee did not reach application consent")
		}
		decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
		redirect, err := url.Parse(decision.RedirectTo)
		if err != nil || redirect.Scheme+"://"+redirect.Host+redirect.Path != rp.config.RedirectURL || redirect.Query().Get("state") != state || redirect.Query().Get("code") == "" {
			t.Fatal("consent did not preserve the application's registered callback and state")
		}
		response, err := app.Client().Get(redirect.String())
		if err != nil {
			t.Fatal("the registered application callback was unavailable")
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("the registered application did not accept its callback")
		}
		return redirect.Query().Get("code"), verifier, nonce
	}

	oidcCtx := oidc.ClientContext(ctx, rp.host.Client())
	signIn := func() (string, *oauth2.Token) {
		t.Helper()
		code, verifier, nonce := consent(http.StatusOK)
		tokens, err := rp.config.Exchange(oidcCtx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatal("the relying party could not exchange the employee's authorization code")
		}
		raw, _ := tokens.Extra("id_token").(string)
		identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(oidcCtx, raw)
		if err != nil || identity.Nonce != nonce || identity.Subject == "" {
			t.Fatal("the relying party could not verify the employee identity")
		}
		info, err := rp.provider.UserInfo(oidcCtx, oauth2.StaticTokenSource(tokens))
		if err != nil || info.Subject != identity.Subject || info.Email != employeeEmail {
			t.Fatal("the relying party could not read the active employee identity")
		}
		return identity.Subject, tokens
	}
	subject, issued := signIn()
	pending, proof, _ := consent(http.StatusOK)
	suspended := setActive(false, created.etag)
	assertRevoked := func() {
		t.Helper()
		_, err := rp.config.Exchange(oidcCtx, pending, oauth2.VerifierOption(proof))
		var denied *oauth2.RetrieveError
		if !errors.As(err, &denied) || denied.ErrorCode != "invalid_grant" {
			t.Fatal("the relying party did not receive invalid_grant for the employee's old code")
		}
		client.send(t, http.MethodGet, "/oauth/userinfo", issued.AccessToken, "", "", nil).requireStatus(t, http.StatusUnauthorized)
	}
	assertRevoked()
	consent(http.StatusBadRequest)
	setActive(true, suspended)
	if restored, _ := signIn(); restored != subject {
		t.Fatal("rehire created a different relying-party subject")
	}
	assertRevoked()
	var loginCount, directoryUpdates int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='auth.sso.login' AND user_id=$1),
		count(*) FILTER (WHERE action='scim.user.update' AND actor_id=$2) FROM audit_logs WHERE outcome='success'`, subject, directory.ID).Scan(&loginCount, &directoryUpdates); err != nil || loginCount != 3 || directoryUpdates != 2 {
		t.Fatal("employee sign-ins and directory updates were not audited")
	}
}

func keycloakInteropData[T any](t *testing.T, phase string, response employeeLifecycleResponse) T {
	t.Helper()
	if response.status != http.StatusOK {
		var problem struct {
			Error struct{ Code, Message string }
		}
		_ = json.Unmarshal(response.body, &problem)
		t.Fatalf("Keycloak SSO %s returned HTTP %d: %s %s", phase, response.status, problem.Error.Code, problem.Error.Message)
	}
	return employeeLifecycleData[T](t, response)
}

func keycloakFixture(t *testing.T, callback string, options ...testcontainers.ContainerCustomizer) (string, *http.Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		Subject:  pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture TLS certificate could not be trusted")
	}
	tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	realm, err := json.Marshal(keycloakRealmConfiguration(callback))
	if err != nil {
		t.Fatal(err)
	}
	const port = "8443/tcp"
	customizers := []testcontainers.ContainerCustomizer{
		testcontainers.WithCmd("start-dev", "--http-enabled=false", "--hostname-strict=false", "--import-realm",
			"--https-certificate-file=/tmp/fixture-cert.pem", "--https-certificate-key-file=/tmp/fixture-key.pem"),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{Reader: bytes.NewReader(certPEM), ContainerFilePath: "/tmp/fixture-cert.pem", FileMode: 0444},
			testcontainers.ContainerFile{Reader: bytes.NewReader(privatePEM), ContainerFilePath: "/tmp/fixture-key.pem", FileMode: 0444},
			testcontainers.ContainerFile{Reader: bytes.NewReader(realm), ContainerFilePath: "/opt/keycloak/data/import/workforce.json", FileMode: 0444},
		),
		testcontainers.WithExposedPorts(port),
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.PortBindings = network.PortMap{network.MustParsePort(port): {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"}}}
		}),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/realms/"+keycloakRealm+"/.well-known/openid-configuration").
			WithPort(port).WithTLS(true, tlsConfig).WithStartupTimeout(100 * time.Second)),
	}
	container, err := testcontainers.Run(ctx, "quay.io/keycloak/keycloak:26.8.1", append(customizers, options...)...)
	if container != nil {
		t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	}
	if err != nil {
		t.Fatalf("start disposable Keycloak: %v", err)
	}
	endpoint, err := container.PortEndpoint(ctx, port, "https")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint + "/realms/" + keycloakRealm, &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
}

func keycloakRealmConfiguration(callback string) map[string]any {
	users := make([]map[string]any, 0, 2)
	for _, username := range []string{"original", "newcomer"} {
		user := map[string]any{
			"username": username, "enabled": true, "email": username + "@workforce.example.test", "emailVerified": true,
			"firstName": "Workforce", "lastName": "Employee", "groups": []string{"/engineering"},
			"credentials": []map[string]any{{"type": "password", "value": keycloakUserPassword, "temporary": false}},
		}
		if username == "original" {
			user["id"] = keycloakEmployeeID
			user["attributes"] = map[string][]string{keycloakSAMLDirectoryClaim: {keycloakEmployeeID}}
		}
		users = append(users, user)
	}
	return map[string]any{
		"realm": keycloakRealm, "enabled": true, "users": users,
		"groups": []map[string]string{{"name": "engineering"}},
		"clients": []map[string]any{{
			"clientId": keycloakClientID, "secret": keycloakClientSecret, "enabled": true, "protocol": "openid-connect",
			"clientAuthenticatorType": "client-secret", "standardFlowEnabled": true, "publicClient": false,
			"redirectUris": []string{callback}, "attributes": map[string]string{"pkce.code.challenge.method": "S256"},
			"protocolMappers": []map[string]any{{
				"name": "workforce-groups", "protocol": "openid-connect", "protocolMapper": "oidc-group-membership-mapper",
				"config": map[string]string{"id.token.claim": "true", "claim.name": "groups", "full.path": "false"},
			}},
		}},
	}
}

func keycloakAuthorize(t *testing.T, transport *http.Transport, authorizationURL, callback, username string) url.Values {
	t.Helper()
	result := submitKeycloakLogin(t, transport, authorizationURL, username)
	defer func() { _ = result.Body.Close() }()
	location, err := result.Location()
	if err != nil || result.StatusCode < 300 || result.StatusCode >= 400 || !strings.HasPrefix(location.String(), callback+"?") {
		t.Fatalf("Keycloak did not redirect to the registered callback: %d", result.StatusCode)
	}
	return location.Query()
}

func submitKeycloakLogin(t *testing.T, transport *http.Transport, authorizationURL, username string) *http.Response {
	t.Helper()
	start, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal("invalid upstream authorization URL")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if next.URL.Scheme != start.Scheme || next.URL.Host != start.Host || len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	response, err := browser.Get(authorizationURL)
	if err != nil {
		t.Fatal("fetch Keycloak login form failed")
	}
	node, parseErr := html.Parse(response.Body)
	_ = response.Body.Close()
	if parseErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak did not render the login form: %d", response.StatusCode)
	}
	form, err := response.Request.URL.Parse(keycloakLoginFormAction(node))
	if err != nil || form.Scheme != start.Scheme || form.Host != start.Host || !strings.HasPrefix(form.Path, "/realms/"+keycloakRealm+"/login-actions/") {
		t.Fatal("Keycloak login form used an unexpected destination")
	}
	result, err := browser.PostForm(form.String(), url.Values{"username": {username}, "password": {keycloakUserPassword}})
	if err != nil {
		t.Fatal("submit disposable Keycloak login failed")
	}
	return result
}

func keycloakLoginFormAction(node *html.Node) string {
	if node.Type == html.ElementNode && node.Data == "form" {
		var id, action string
		for _, attribute := range node.Attr {
			switch attribute.Key {
			case "id":
				id = attribute.Val
			case "action":
				action = attribute.Val
			}
		}
		if id == "kc-form-login" {
			return action
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if action := keycloakLoginFormAction(child); action != "" {
			return action
		}
	}
	return ""
}
