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

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/stepup"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/html"
)

const (
	keycloakRealm        = "workforce-interop"
	keycloakClientID     = "workforce-rp"
	keycloakClientSecret = "fixture-workforce-client-secret"
	keycloakUserPassword = "fixture-workforce-user-password"
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

func keycloakFixture(t *testing.T, callback string) (string, *http.Transport) {
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
	container, err := testcontainers.Run(ctx, "quay.io/keycloak/keycloak:26.8.1",
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
			WithPort(port).WithTLS(true, tlsConfig).WithStartupTimeout(100*time.Second)),
	)
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
		users = append(users, map[string]any{
			"username": username, "enabled": true, "email": username + "@workforce.example.test", "emailVerified": true,
			"firstName": "Workforce", "lastName": "Employee", "groups": []string{"/engineering"},
			"credentials": []map[string]any{{"type": "password", "value": keycloakUserPassword, "temporary": false}},
		})
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
	defer func() { _ = result.Body.Close() }()
	location, err := result.Location()
	if err != nil || result.StatusCode < 300 || result.StatusCode >= 400 || !strings.HasPrefix(location.String(), callback+"?") {
		t.Fatalf("Keycloak did not redirect to the registered callback: %d", result.StatusCode)
	}
	return location.Query()
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
