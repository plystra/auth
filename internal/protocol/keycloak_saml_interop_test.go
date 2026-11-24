//go:build interop

package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/stepup"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

const (
	keycloakFixtureAdmin       = "fixture-admin"
	keycloakSAMLDirectoryClaim = "employee_id"
	keycloakSAMLLaunchName     = "workforce-saml"
)

func TestKeycloakIdPInitiatedSAMLLoginAndDirectoryOffboarding(t *testing.T) {
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
	const adminID = "usr_human_rp"
	const employeeEmail = "original@workforce.example.test"
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, adminID, "Workforce SAML Launch", "workforce-saml-launch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_keycloak_saml_launch',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	admin := authorization.WithHumanActor(ctx, owner.ID, adminID)
	connection, err := rp.workforce.CreateConnection(admin, owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Keycloak IdP-initiated SAML", Provider: "saml", SAMLMetadata: fetchKeycloakSAMLMetadata(t, upstream, issuer),
		RedirectURI: rp.host.URL + "/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	registerKeycloakSAMLConnection(t, rp, upstream, issuer, adminPassword, space.ID, connection)
	directory, err := rp.workforce.CreateDirectory(admin, owner.ID, space.ID, enterprise.DirectoryInput{
		Name: "Workforce directory", SSOConnectionID: connection.ID, SSOIdentityClaim: keycloakSAMLDirectoryClaim,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	const scim = "application/scim+json"
	users := "/scim/v2/" + directory.ID + "/Users"
	created := client.send(t, http.MethodPost, users, directory.Token.Value(), scim, "", map[string]any{
		"externalId": keycloakEmployeeID, "userName": employeeEmail, "active": true,
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
	launch := func() url.Values {
		t.Helper()
		login := submitKeycloakLogin(t, transport, issuer+"/protocol/saml/clients/"+keycloakSAMLLaunchName, "original")
		defer func() { _ = login.Body.Close() }()
		page, err := html.Parse(io.LimitReader(login.Body, 128<<10))
		if err != nil || login.StatusCode != http.StatusOK {
			t.Fatalf("Keycloak did not produce a SAML launch form: HTTP %d", login.StatusCode)
		}
		form := keycloakSAMLForm(page, connection.RedirectURI)
		if len(form["SAMLResponse"]) != 1 || form.Get("SAMLResponse") == "" || form.Get("RelayState") != "" {
			t.Fatal("the IdP launch did not return a SAML response with no request state")
		}
		return form
	}
	callback := func(form url.Values) employeeLifecycleResponse {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, connection.RedirectURI, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal("could not construct the SAML launch callback")
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", strings.TrimSuffix(issuer, "/realms/"+keycloakRealm))
		res, err := rp.host.Client().Do(req)
		if err != nil {
			t.Fatal("could not submit the SAML launch form")
		}
		defer func() { _ = res.Body.Close() }()
		if res.Header.Get("Access-Control-Allow-Origin") != "" || res.Header.Get("Set-Cookie") != "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("a direct SAML launch response must be non-cacheable and carry no cross-origin or cookie authority")
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		if err != nil {
			t.Fatal("could not read the SAML launch response")
		}
		return employeeLifecycleResponse{status: res.StatusCode, body: body}
	}
	form := launch()
	first := keycloakInteropData[account.AuthResult](t, "IdP launch", callback(form))
	if first.Tokens == nil || first.User.Email != employeeEmail {
		t.Fatal("the IdP launch did not sign in the provisioned employee")
	}
	callback(form).requireError(t, http.StatusBadRequest, "invalid_grant")
	members := func(token string) employeeLifecycleResponse {
		return client.send(t, http.MethodGet, "/v1/me/members", token, "", "", nil)
	}
	active := employeeLifecycleData[[]authorization.Member](t, members(first.Tokens.AccessToken))
	if !slices.ContainsFunc(active, func(member authorization.Member) bool { return member.SpaceID == space.ID }) {
		t.Fatal("the employee session could not read its managed Space membership")
	}
	suspendedVersion := setActive(false, created.etag)
	members(first.Tokens.AccessToken).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
	client.send(t, http.MethodPost, "/v1/auth/refresh", "", "application/json", "",
		map[string]string{"refresh_token": first.Tokens.RefreshToken}).requireError(t, http.StatusBadRequest, "invalid_grant")
	callback(launch()).requireError(t, http.StatusBadRequest, "invalid_grant")
	setActive(true, suspendedVersion)
	restored := keycloakInteropData[account.AuthResult](t, "IdP launch after reprovisioning", callback(launch()))
	if restored.Tokens == nil || restored.User.ID != first.User.ID || restored.Tokens.SessionID == first.Tokens.SessionID {
		t.Fatal("reprovisioning did not preserve the employee identity and require a fresh session")
	}
	members(first.Tokens.AccessToken).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
	var logins, receipts int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.login' AND user_id=$1 AND outcome='success'),
		(SELECT count(*) FROM saml_assertion_uses WHERE connection_id=$2)`, first.User.ID, connection.ID).
		Scan(&logins, &receipts); err != nil || logins != 2 || receipts != 2 {
		t.Fatalf("expected two committed logins and assertion receipts, got %d/%d: %v", logins, receipts, err)
	}
}

func registerKeycloakSAMLConnection(t *testing.T, rp *humanRP, upstream *http.Client, issuer, password, spaceID string, connection enterprise.Connection) keycloakAdmin {
	t.Helper()
	ctx := t.Context()
	digest, err := stepup.DigestValue(enterprise.ConnectionDetailRequest(spaceID, connection.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation='sso_connections.get',
		step_up_digest=$2, step_up_method='totp', step_up_expires_at=clock_timestamp()+interval '5 minutes'
		WHERE id=$1`, rp.session.SessionID, digest); err != nil {
		t.Fatal(err)
	}
	management := employeeLifecycleClient{server: rp.host}
	path := "/v1/spaces/" + spaceID + "/sso-connections/" + connection.ID
	detail := keycloakInteropData[enterprise.ConnectionDetail](t, "SP metadata export",
		management.send(t, http.MethodGet, path, rp.session.AccessToken, "", "", nil))
	if detail.ID != connection.ID || detail.SAMLSPMetadata == "" {
		t.Fatal("Auth did not export metadata for the selected SAML connection")
	}
	return registerKeycloakSAMLClient(t, upstream, issuer, password, detail.SAMLSPMetadata,
		rp.workforce.Issuer+"/saml/"+connection.ID, connection.RedirectURI)
}

func fetchKeycloakSAMLMetadata(t *testing.T, client *http.Client, issuer string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer+"/protocol/saml/descriptor", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("fetch Keycloak SAML metadata failed")
	}
	defer func() { _ = res.Body.Close() }()
	const metadataLimit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(res.Body, metadataLimit+1))
	if err != nil || len(body) == 0 || len(body) > metadataLimit || res.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak SAML metadata is unavailable or invalid: %d", res.StatusCode)
	}
	return string(body)
}

type keycloakAdmin struct {
	client *http.Client
	realm  string
	token  string
}

func newKeycloakAdmin(t *testing.T, client *http.Client, issuer, password string) keycloakAdmin {
	t.Helper()
	origin := strings.TrimSuffix(issuer, "/realms/"+keycloakRealm)
	form := url.Values{
		"client_id": {"admin-cli"}, "grant_type": {"password"},
		"username": {keycloakFixtureAdmin}, "password": {password},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("authenticate to the disposable Keycloak administration endpoint failed")
	}
	var credential struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(&credential)
	_ = res.Body.Close()
	if err != nil || credential.AccessToken == "" || res.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak fixture administrator authentication failed: %d", res.StatusCode)
	}
	return keycloakAdmin{client: client, realm: origin + "/admin/realms/" + keycloakRealm, token: credential.AccessToken}
}

func registerKeycloakSAMLClient(t *testing.T, client *http.Client, issuer, password, metadata, entityID, callback string) keycloakAdmin {
	t.Helper()
	admin := newKeycloakAdmin(t, client, issuer, password)
	mapper := func(name, kind string) map[string]any {
		return map[string]any{
			"name": name, "protocol": "saml", "protocolMapper": kind,
			"config": map[string]string{"user.attribute": name, "attribute.name": name, "attribute.nameformat": "Basic"},
		}
	}
	var converted map[string]any
	admin.exchange(t, http.MethodPost, "/client-description-converter", "application/xml",
		strings.NewReader(metadata), &converted, http.StatusOK)
	attributes, ok := converted["attributes"].(map[string]any)
	redirects, _ := converted["redirectUris"].([]any)
	entityMatches := converted["clientId"] == entityID
	protocolMatches := converted["protocol"] == "saml"
	redirectMatches := slices.Contains(redirects, any(callback))
	postCallbackMatches := attributes["saml_assertion_consumer_url_post"] == callback
	assertionSigning := attributes["saml.assertion.signature"] == "true"
	// Keycloak leaves the client signature setting unset when the descriptor has no signing key.
	clientSignature := attributes["saml.client.signature"]
	unsignedRequests := clientSignature == nil || clientSignature == "false"
	if !ok || !entityMatches || !protocolMatches || !redirectMatches || !postCallbackMatches || !assertionSigning || !unsignedRequests {
		t.Fatalf("Keycloak import mismatch: attributes=%t entity=%t protocol=%t redirect=%t post_callback=%t signed_assertions=%t unsigned_requests=%t",
			ok, entityMatches, protocolMatches, redirectMatches, postCallbackMatches, assertionSigning, unsignedRequests)
	}
	// Client creation defaults an omitted signature setting to true. Set the SP's declared policy explicitly.
	attributes["saml.client.signature"] = "false"
	attributes["saml.force.post.binding"] = "true"
	attributes["saml.server.signature"] = "true"
	attributes["saml.signature.algorithm"] = "RSA_SHA256"
	attributes["saml.authnstatement"] = "true"
	attributes["saml_name_id_format"] = "persistent"
	attributes["saml_idp_initiated_sso_url_name"] = keycloakSAMLLaunchName
	converted["enabled"] = true
	converted["protocolMappers"] = []map[string]any{
		mapper("email", "saml-user-property-mapper"),
		mapper(keycloakSAMLDirectoryClaim, "saml-user-attribute-mapper"),
		{"name": "workforce-groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
			"config": map[string]string{"attribute.name": "groups", "attribute.nameformat": "Basic", "single": "true", "full.path": "false"}},
	}
	admin.call(t, http.MethodPost, "/clients", converted, nil, http.StatusCreated)
	return admin
}

func (a keycloakAdmin) call(t *testing.T, method, path string, input, output any, status int) string {
	t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	return a.exchange(t, method, path, "application/json", bytes.NewReader(body), output, status)
}

func (a keycloakAdmin) exchange(t *testing.T, method, path, contentType string, body io.Reader, output any, status int) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, a.realm+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+a.token)
	res, err := a.client.Do(req)
	if err != nil {
		t.Fatal("disposable Keycloak administration request failed")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != status {
		t.Fatalf("disposable Keycloak administration returned HTTP %d, want %d", res.StatusCode, status)
	}
	if output != nil && json.NewDecoder(io.LimitReader(res.Body, 256<<10)).Decode(output) != nil {
		t.Fatal("invalid Keycloak administration response")
	}
	return res.Header.Get("Location")
}

func keycloakSAMLCallback(t *testing.T, rp *humanRP, transport *http.Transport, issuer, callback, interaction, username string, identified interactionResponse) {
	t.Helper()
	target, err := url.Parse(identified.AuthorizationURL)
	if err != nil || identified.AuthorizationMethod != http.MethodGet ||
		target.Scheme+"://"+target.Host+target.EscapedPath() != issuer+"/protocol/saml" ||
		target.Query().Get("SAMLRequest") == "" || target.Query().Get("RelayState") == "" {
		t.Fatal("the interaction did not start the discovered Keycloak SAML endpoint")
	}
	login := submitKeycloakLogin(t, transport, target.String(), username)
	page, err := html.Parse(io.LimitReader(login.Body, 128<<10))
	_ = login.Body.Close()
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak did not return an HTML SAML callback: %d", login.StatusCode)
	}
	posted := keycloakSAMLForm(page, callback)
	if len(posted["SAMLResponse"]) != 1 || posted.Get("SAMLResponse") == "" ||
		len(posted["RelayState"]) != 1 || posted.Get("RelayState") != target.Query().Get("RelayState") {
		t.Fatal("Keycloak's POST was not bound to the exact ACS and original relay")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, callback, strings.NewReader(posted.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", target.Scheme+"://"+target.Host)
	acs := &http.Client{Transport: rp.host.Client().Transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := acs.Do(req)
	if err != nil {
		t.Fatal("POST the Keycloak form to the service provider failed")
	}
	defer func() { _ = res.Body.Close() }()
	redirect := "/oidc/upstream#interaction=" + strings.TrimPrefix(interaction, route.OIDCInteractionsPath+"/")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != redirect {
		t.Fatalf("the ACS did not resume its original interaction: %d", res.StatusCode)
	}
}

func keycloakSAMLForm(page *html.Node, callback string) url.Values {
	for form := range page.Descendants() {
		if form.Type != html.ElementNode || form.Data != "form" {
			continue
		}
		var action, method string
		for _, attr := range form.Attr {
			switch attr.Key {
			case "action":
				action = attr.Val
			case "method":
				method = attr.Val
			}
		}
		if action != callback || !strings.EqualFold(method, "POST") {
			continue
		}
		values := make(url.Values)
		for input := range form.Descendants() {
			if input.Type != html.ElementNode || input.Data != "input" {
				continue
			}
			var name, value string
			for _, attr := range input.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				}
			}
			if name == "SAMLResponse" || name == "RelayState" {
				values.Add(name, value)
			}
		}
		return values
	}
	return nil
}
