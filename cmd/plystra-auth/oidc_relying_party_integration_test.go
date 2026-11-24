package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/oauth2"
)

// httptest's TLS client routes this certificate-valid hostname to its listener.
const rpTestIssuer = "https://auth.example.com"

type oidcTestReplica struct {
	principal *httputil.ReverseProxy
	server    *httputil.ReverseProxy
}

// Run two independent serve processes behind a single HTTPS issuer. Switch
// between them at explicit points rather than depending on request scheduling.
func startOIDCTestIssuer(t *testing.T, database testdb.Database, dbAddress, hmacKey string, wrappingKey []byte) (*httptest.Server, *httptest.Server, func(), []string, func(*testing.T)) {
	t.Helper()
	ctx := t.Context()
	fixture := t.TempDir()
	binary := filepath.Join(fixture, "plystra-auth")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Auth server: %v\n%s", err, out)
	}
	dbURL := func(raw string) string {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal("invalid database fixture URL")
		}
		u.Host = dbAddress
		return u.String()
	}
	var dataKey [32]byte
	_, _ = rand.Read(dataKey[:])
	startProcess := func(name string) (*oidcTestReplica, string, testcontainers.Container) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("generate issuer fixture key", err)
		}
		pem, err := security.EncryptSigningKeyPEM(key, wrappingKey)
		if err != nil {
			t.Fatal("encrypt issuer fixture key", err)
		}
		keyFile := filepath.Join(fixture, name+"-issuer.pem")
		if err := os.WriteFile(keyFile, pem, 0600); err != nil {
			t.Fatal("write encrypted issuer fixture key", err)
		}
		const containerKeyFile = "/run/issuer.pem"
		process, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: "alpine:3.22", ImagePlatform: "linux/" + runtime.GOARCH, Cmd: []string{"/usr/local/bin/plystra-auth", "serve"},
				Files: []testcontainers.ContainerFile{
					{HostFilePath: binary, ContainerFilePath: "/usr/local/bin/plystra-auth", FileMode: 0555},
					{HostFilePath: keyFile, ContainerFilePath: containerKeyFile, FileMode: 0400},
				},
				Env: map[string]string{
					"PLYSTRA_AUTH_DATABASE_URL": dbURL(database.AppURL), "PLYSTRA_AUTH_MIGRATION_DATABASE_URL": dbURL(database.OwnerURL),
					"PLYSTRA_AUTH_ISSUER": rpTestIssuer, "PLYSTRA_AUTH_SESSION_HMAC_KEYS": hmacKey,
					"PLYSTRA_AUTH_DATA_KEY":                   base64.StdEncoding.EncodeToString(dataKey[:]),
					"PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString(wrappingKey),
					"PLYSTRA_AUTH_SIGNING_KEY_FILE":           containerKeyFile,
				},
				ExposedPorts: []string{"8080/tcp", "8081/tcp", "8090/tcp"},
				WaitingFor:   wait.ForHTTP("/.well-known/openid-configuration").WithPort("8080/tcp"),
			}, Started: true,
		})
		if process != nil {
			t.Cleanup(func() { _ = process.Terminate(context.Background()) })
		}
		if err != nil {
			t.Fatalf("start Auth process: %v", err)
		}
		proxy := func(port string) *httputil.ReverseProxy {
			t.Helper()
			backend, err := process.PortEndpoint(ctx, port, "http")
			if err != nil {
				t.Fatal(err)
			}
			target, err := url.Parse(backend)
			if err != nil {
				t.Fatal(err)
			}
			return httputil.NewSingleHostReverseProxy(target)
		}
		health, err := process.PortEndpoint(ctx, "8090/tcp", "http")
		if err != nil {
			t.Fatal(err)
		}
		return &oidcTestReplica{principal: proxy("8080/tcp"), server: proxy("8081/tcp")}, health + "/readyz", process
	}
	// Independently provisioned files may seed a pristine database. Once
	// initialized, both processes must use the same persisted issuer key.
	primary, primaryReady, primaryProcess := startProcess("primary")
	peer, peerReady, _ := startProcess("peer")
	var active atomic.Pointer[oidcTestReplica]
	active.Store(primary)
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Load().principal.ServeHTTP(w, r)
	}))
	t.Cleanup(issuer.Close)
	serverPlane := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Load().server.ServeHTTP(w, r)
	}))
	t.Cleanup(serverPlane.Close)
	switchBackend := func() {
		if active.Load() == primary {
			active.Store(peer)
		} else {
			active.Store(primary)
		}
	}
	losePrimary := func(t *testing.T) {
		t.Helper()
		if active.Load() != primary {
			t.Fatal("failover must begin on the primary")
		}
		stopTimeout := time.Duration(0)
		if err := primaryProcess.Stop(t.Context(), &stopTimeout); err != nil {
			t.Fatal("stop the primary issuer process", err)
		}
		state, err := primaryProcess.State(t.Context())
		if err != nil || state.Status != "exited" || state.Running {
			t.Fatal("the primary issuer process did not exit", err)
		}
		active.Store(peer)
	}
	return issuer, serverPlane, switchBackend, []string{primaryReady, peerReady}, losePrimary
}

func TestHumanOIDCIndependentRelyingPartyWithAuthProcess(t *testing.T) {
	ctx := t.Context()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal("open Auth fixture database")
	}
	t.Cleanup(st.Close)

	const subject, email, clientID = "usr_oidc_process", "relying-party@example.test", "app_oidc_process"
	password, clientSecret, hmacKey := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	passwordHash, err := security.DefaultPasswordHasher().Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,email_verified_at,status,display_name)
        VALUES ($1,$2,$2,$3,now(),'active','RP test account')`, subject, email, passwordHash); err != nil {
		t.Fatal(err)
	}
	var host string
	var port int
	if err := st.Pool.QueryRow(ctx, `SELECT host(inet_server_addr()), inet_server_port()`).Scan(&host, &port); err != nil {
		t.Fatal(err)
	}
	var wrappingKey [32]byte
	_, _ = rand.Read(wrappingKey[:])
	issuer, serverPlane, switchBackend, readyURLs, losePrimary := startOIDCTestIssuer(t, database, net.JoinHostPort(host, strconv.Itoa(port)), hmacKey, wrappingKey[:])
	client := issuer.Client()
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, rpTestIssuer)
	if err != nil {
		t.Fatal("independent RP could not discover issuer", err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	rp := httptest.NewUnstartedServer(nil)
	redirectURI := "https://" + rp.Listener.Addr().String() + "/callback"
	redirects, err := json.Marshal([]string{redirectURI})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id,space_id,name,client_id,redirect_uris,client_secret_hash,human_oidc_enabled)
       SELECT $1,id,'Relying party',$1,$2,$3,true FROM spaces WHERE slug='default'`, clientID, redirects, application.HMACClientSecretHash([]byte(hmacKey), clientSecret)); err != nil {
		t.Fatal(err)
	}
	state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	config := oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURI, Scopes: []string{oidc.ScopeOpenID, "email"}, Endpoint: endpoint}
	result := make(chan *oauth2.Token, 1)
	rp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/callback" || r.URL.Query().Get("state") != state || r.URL.Query().Get("code") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokens, err := config.Exchange(oidc.ClientContext(r.Context(), client), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		select {
		case result <- tokens:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusConflict)
		}
	})
	rp.StartTLS()
	t.Cleanup(rp.Close)

	request := func(t *testing.T, method, path, bearer string, input any, out any) int {
		t.Helper()
		var body io.Reader
		if input != nil {
			b, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, path, body)
		if err != nil {
			t.Fatal("could not construct RP request")
		}
		if input != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("RP request could not complete")
		}
		defer func() { _ = res.Body.Close() }()
		if out != nil {
			if res.StatusCode != http.StatusOK {
				t.Fatalf("%s %s returned %d", method, req.URL.Path, res.StatusCode)
			}
			if err := json.NewDecoder(res.Body).Decode(out); err != nil {
				t.Fatalf("invalid %s response", req.URL.Path)
			}
		}
		return res.StatusCode
	}
	startConsent := func(t *testing.T, config oauth2.Config, state, nonce, verifier string) string {
		t.Helper()
		var pending struct {
			Handle string   `json:"request_id"`
			Scopes []string `json:"scopes"`
		}
		authorize := config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
		request(t, http.MethodGet, authorize, "", nil, &pending)
		if pending.Handle == "" || !slices.Equal(pending.Scopes, config.Scopes) {
			t.Fatal("unexpected disclosure request")
		}
		return pending.Handle
	}
	handle := startConsent(t, config, state, nonce, verifier)
	type accountSignIn struct {
		Data struct {
			Tokens struct {
				Access  string `json:"access_token"`
				Refresh string `json:"refresh_token"`
			} `json:"tokens"`
		} `json:"data"`
	}
	passwordSignIn := func(t *testing.T) accountSignIn {
		t.Helper()
		var attempt struct {
			Data struct {
				ID   string `json:"attempt_id"`
				Next string `json:"next_step"`
			} `json:"data"`
		}
		request(t, http.MethodPost, rpTestIssuer+"/v1/auth/sign-in", "", map[string]string{"email": email}, &attempt)
		if attempt.Data.Next != "password" || attempt.Data.ID == "" {
			t.Fatal("issuer did not start password authentication")
		}
		var signedIn accountSignIn
		request(t, http.MethodPost, rpTestIssuer+"/v1/auth/sign-in/"+attempt.Data.ID, "", map[string]string{"password": password}, &signedIn)
		if signedIn.Data.Tokens.Access == "" || signedIn.Data.Tokens.Refresh == "" {
			t.Fatal("issuer did not return account session credentials")
		}
		return signedIn
	}
	signedIn := passwordSignIn(t)
	approve := func(t *testing.T, handle, state string) *url.URL {
		t.Helper()
		var consent struct {
			Redirect string `json:"redirect_to"`
		}
		request(t, http.MethodPost, endpoint.AuthURL, signedIn.Data.Tokens.Access, map[string]string{"request_id": handle, "decision": "approve"}, &consent)
		callback, err := url.Parse(consent.Redirect)
		if err != nil || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
			t.Fatal("consent did not return a code bound to the RP state")
		}
		target := *callback
		target.RawQuery = ""
		if target.String() != redirectURI {
			t.Fatal("unexpected consent callback")
		}
		return callback
	}
	t.Run("consent denial is final across issuer instances", func(t *testing.T) {
		deniedState := oauth2.GenerateVerifier()
		deniedHandle := startConsent(t, config, deniedState, oauth2.GenerateVerifier(), oauth2.GenerateVerifier())
		var decision struct {
			Redirect string `json:"redirect_to"`
		}
		switchBackend()
		request(t, http.MethodPost, endpoint.AuthURL, signedIn.Data.Tokens.Access, map[string]string{"request_id": deniedHandle, "decision": "deny"}, &decision)
		switchBackend()
		redirect, err := url.Parse(decision.Redirect)
		if err != nil {
			t.Fatal("issuer did not return a valid denial redirect")
		}
		query := redirect.Query()
		redirect.RawQuery = ""
		if redirect.String() != redirectURI || query.Get("state") != deniedState || query.Get("error") != "access_denied" || query.Has("code") {
			t.Fatal("denial was not bound to the original relying party and state")
		}
		status := request(t, http.MethodPost, endpoint.AuthURL, signedIn.Data.Tokens.Access, map[string]string{"request_id": deniedHandle, "decision": "approve"}, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("peer accepted approval after consent denial: status=%d", status)
		}
		var codes, denials int
		if err := st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_login_codes),
			(SELECT count(*) FROM audit_logs WHERE action='oidc.consent.deny' AND user_id=$1 AND application_id=$2)`, subject, clientID).Scan(&codes, &denials); err != nil || codes != 0 || denials != 1 {
			t.Fatal("denial must commit one audit event and no authorization code", err)
		}
	})
	callback := approve(t, handle, state)
	incorrect := *callback
	query := incorrect.Query()
	query.Set("state", oauth2.GenerateVerifier())
	incorrect.RawQuery = query.Encode()
	if status := request(t, http.MethodGet, incorrect.String(), "", nil, nil); status != http.StatusBadRequest {
		t.Fatal("RP accepted an uncorrelated callback")
	}
	// Redeem the primary's authorization code and obtain the JWKS from its peer.
	switchBackend()
	if status := request(t, http.MethodGet, rpTestIssuer+"/v1/me/sessions", signedIn.Data.Tokens.Access, nil, nil); status != http.StatusOK {
		t.Fatalf("peer rejected the primary's account access token with status %d", status)
	}
	t.Run("confidential client rejects missing and wrong secrets", func(t *testing.T) {
		missing := config
		missing.ClientSecret = ""
		missing.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		wrong := config
		wrong.ClientSecret = oauth2.GenerateVerifier()
		for _, tc := range []struct {
			name   string
			client oauth2.Config
		}{{"missing", missing}, {"wrong", wrong}} {
			t.Run(tc.name, func(t *testing.T) {
				code := callback.Query().Get("code")
				credentials, err := tc.client.Exchange(ctx, code, oauth2.VerifierOption(verifier))
				var response *oauth2.RetrieveError
				if credentials != nil || !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != http.StatusUnauthorized || response.ErrorCode != "invalid_client" {
					t.Fatal("confidential exchange must reject invalid client authentication without issuing credentials")
				}
				if response.Response.Header.Get("WWW-Authenticate") != `Basic realm="oauth/token"` {
					t.Fatal("confidential exchange did not return its client authentication challenge")
				}
				for _, value := range []string{code, verifier, clientSecret, wrong.ClientSecret} {
					if bytes.Contains(response.Body, []byte(value)) {
						t.Fatal("client authentication error disclosed a credential")
					}
				}
			})
		}
	})
	t.Run("code is bound to the original verifier and redirect URI", func(t *testing.T) {
		wrongRedirect := config
		wrongRedirect.RedirectURL += "/"
		for _, tc := range []struct {
			name     string
			client   oauth2.Config
			verifier string
		}{
			{"verifier", config, oauth2.GenerateVerifier()},
			{"redirect URI", wrongRedirect, verifier},
		} {
			t.Run(tc.name, func(t *testing.T) {
				credentials, err := tc.client.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(tc.verifier))
				var response *oauth2.RetrieveError
				if credentials != nil || !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != http.StatusBadRequest || response.ErrorCode != "invalid_grant" {
					t.Fatal("exchange must reject a mismatched authorization code binding without issuing credentials")
				}
			})
		}
	})
	// Failed exchanges must leave the original code redeemable by its legitimate client.
	if status := request(t, http.MethodGet, callback.String(), "", nil, nil); status != http.StatusNoContent {
		t.Fatalf("independent RP rejected callback with status %d", status)
	}
	var token *oauth2.Token
	select {
	case token = <-result:
	default:
		t.Fatal("RP callback did not complete the client_secret_basic and PKCE exchange")
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" || token.AccessToken == "" || token.RefreshToken != "" {
		t.Fatal("invalid login token response")
	}
	verification := oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{oidc.ES256}}
	idVerifier := provider.Verifier(&verification)
	claims, err := idVerifier.Verify(ctx, rawID)
	if err != nil || claims.Issuer != rpTestIssuer || !slices.Equal(claims.Audience, []string{clientID}) || claims.Nonce != nonce || claims.Subject != subject {
		t.Fatal("independent RP rejected signature, issuer, audience, subject, expiry or nonce")
	}
	t.Run("relying party verification policy", func(t *testing.T) {
		wrongAudience := verification
		wrongAudience.ClientID = "app_other_relying_party"
		if _, err := provider.Verifier(&wrongAudience).Verify(ctx, rawID); err == nil {
			t.Fatal("a different relying party accepted the ID Token")
		}
		wrongAlgorithm := verification
		wrongAlgorithm.SupportedSigningAlgs = []string{oidc.RS256}
		if _, err := provider.Verifier(&wrongAlgorithm).Verify(ctx, rawID); err == nil {
			t.Fatal("a relying party configured for RS256 accepted an ES256 ID Token")
		}
	})
	// Move back to the node that issued the code to check shared consumption.
	switchBackend()
	t.Run("authorization code redemption is one-time", func(t *testing.T) {
		_, err := config.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
		var response *oauth2.RetrieveError
		if !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != http.StatusBadRequest || response.ErrorCode != "invalid_grant" {
			t.Fatal("exchanging the redeemed authorization code did not return invalid_grant")
		}
	})
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != claims.Subject || info.Email != email || !info.EmailVerified {
		t.Fatal("independent RP did not receive the verified email for the ID Token subject")
	}
	var disclosed map[string]json.RawMessage
	if err := info.Claims(&disclosed); err != nil || len(disclosed) != 3 {
		t.Fatal("UserInfo returned fields outside openid and email")
	}
	for _, path := range []string{"/oauth/userinfo", "/v1/me"} {
		if status := request(t, http.MethodGet, rpTestIssuer+path, rawID, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("ID Token on %s returned %d", path, status)
		}
	}

	t.Run("verified account drives a live decision in the installed Space", func(t *testing.T) {
		authz := &authorization.Service{Store: st}
		space, member, err := authz.CreateSpace(ctx, claims.Subject, "Relying party workforce", "rp-workforce")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
			VALUES ('grt_rp_workforce_app_manage',$1,'["auth.applications:manage"]',$2,'space',$1,$2)`,
			space.ID, member.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE applications SET visibility='public', review_status='approved',
			manifest_permissions='["auth.authz:check"]' WHERE id=$1`, clientID); err != nil {
			t.Fatal(err)
		}
		apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(hmacKey)}}
		if _, err := apps.InstallSpace(ctx, member.ID, clientID, space.ID); err != nil {
			t.Fatal(err)
		}
		expires := time.Now().Add(time.Hour)
		apiKey, err := apps.CreateKey(ctx, clientID, "workforce-decision", []string{"auth.authz:check"}, &expires)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET allow_subject_assertion=true,
			restrict_to=jsonb_build_array(jsonb_build_object('space_id',$1::text,'include_descendants',false))
			WHERE application_id=$2 AND name='workforce-decision'`, space.ID, clientID); err != nil {
			t.Fatal(err)
		}
		target := serverPlane.URL + "/server/v1/authz/check"
		body := server.CheckBody{Subject: server.CheckSubject{UserID: claims.Subject}, Action: "self:read",
			Resource: server.CheckResource{Type: "member", ID: member.ID, SpaceID: space.ID}}
		var result struct {
			Data server.CheckDecision `json:"data"`
		}
		request(t, http.MethodPost, target, apiKey, body, &result)
		if result.Data.Decision != "allow" || result.Data.DecisionID == "" {
			t.Fatal("the installed application did not receive an allow decision for the signed account")
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET status='revoked',revoked_at=clock_timestamp()
			WHERE user_id=$1 AND member_id=$2`, claims.Subject, member.ID); err != nil {
			t.Fatal(err)
		}
		switchBackend()
		defer switchBackend()
		if status := request(t, http.MethodPost, target, apiKey, body, nil); status != http.StatusNotFound {
			t.Fatalf("peer did not reject a withdrawn binding: HTTP %d", status)
		}
	})

	t.Run("discovery advertises supported client authentication methods", func(t *testing.T) {
		type metadata struct {
			TokenEndpoint string   `json:"token_endpoint"`
			Methods       []string `json:"token_endpoint_auth_methods_supported"`
		}
		var oauthMetadata, oidcMetadata metadata
		request(t, http.MethodGet, rpTestIssuer+"/.well-known/oauth-authorization-server", "", nil, &oauthMetadata)
		if err := provider.Claims(&oidcMetadata); err != nil {
			t.Fatal("could not read the discovered OpenID provider metadata")
		}
		want := []string{"client_secret_basic", "client_secret_post", "none"}
		for _, doc := range []metadata{oauthMetadata, oidcMetadata} {
			slices.Sort(doc.Methods)
			if doc.TokenEndpoint != endpoint.TokenURL || !slices.Equal(doc.Methods, want) {
				t.Fatal("discovery did not advertise the token endpoint and its implemented client authentication methods")
			}
		}

		formClient := config
		formClient.Endpoint.TokenURL = oauthMetadata.TokenEndpoint
		formClient.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		handle := startConsent(t, formClient, state, nonce, verifier)
		code := approve(t, handle, state).Query().Get("code")
		credentials, err := formClient.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil || !credentials.Valid() {
			t.Fatal("confidential client could not redeem its code with client_secret_post")
		}
		rawID, _ := credentials.Extra("id_token").(string)
		verified, err := idVerifier.Verify(ctx, rawID)
		if err != nil || verified.Subject != subject || verified.Nonce != nonce {
			t.Fatal("confidential client could not verify the identity returned for client_secret_post")
		}
	})

	post := func(t *testing.T, path, bearer string, input, out any) {
		t.Helper()
		if status := request(t, http.MethodPost, rpTestIssuer+path, bearer, input, out); status != http.StatusOK {
			t.Fatalf("publisher POST %s returned %d", path, status)
		}
	}
	newPublisher := func(t *testing.T, slug string) (spaceID, memberID, bearer, factorSecret string) {
		t.Helper()
		// This isolated deployment admits new publishers. The end user's
		// unbound session stays separate from the publisher's Space and MFA.
		if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode='open', require_email_verification=false WHERE id`); err != nil {
			t.Fatal(err)
		}
		type tokens struct {
			Access  string `json:"access_token"`
			Refresh string `json:"refresh_token"`
		}
		var publisher struct{ Data struct{ Tokens tokens } }
		publisherPassword := oauth2.GenerateVerifier()
		post(t, "/v1/auth/sign-up", "", map[string]string{"email": slug + "@example.test", "password": publisherPassword}, &publisher)
		var space struct {
			Data struct{ Space, Member struct{ ID string } }
		}
		post(t, "/v1/spaces", publisher.Data.Tokens.Access, map[string]string{"name": "OIDC Publisher", "slug": slug}, &space)
		spaceID, memberID = space.Data.Space.ID, space.Data.Member.ID
		var selected struct{ Data tokens }
		post(t, "/v1/auth/refresh", "", map[string]string{"refresh_token": publisher.Data.Tokens.Refresh, "member_id": memberID}, &selected)
		bearer = selected.Data.Access
		post(t, "/v1/spaces/"+spaceID+"/grants", bearer, map[string]any{
			"grantee": map[string]string{"member_id": memberID}, "permissions": []string{"auth.applications:manage"},
			"scope": "space", "anchor_space_id": spaceID,
		}, nil)
		factor := map[string]string{"kind": "totp", "name": "Publisher"}
		post(t, "/v1/auth/step-up", bearer, map[string]any{"password": publisherPassword, "operation": "me.factors.create", "request": factor}, nil)
		var enrollment struct{ Data struct{ Secret string } }
		post(t, "/v1/me/factors", bearer, factor, &enrollment)
		return spaceID, memberID, bearer, enrollment.Data.Secret
	}
	stepUpPublisher := func(t *testing.T, bearer, factorSecret, operation string, proof any, at time.Time) {
		t.Helper()
		mfa, err := totp.GenerateCode(factorSecret, at)
		if err != nil {
			t.Fatal("could not generate the publisher's MFA proof")
		}
		post(t, "/v1/auth/step-up", bearer, map[string]any{"mfa_code": mfa, "operation": operation, "request": proof}, nil)
	}
	t.Run("public client uses PKCE and receives only the subject", func(t *testing.T) {
		spaceID, memberID, bearer, factorSecret := newPublisher(t, "oidc-publisher")
		registration := map[string]any{
			"name": "Public PKCE client", "visibility": "private", "redirect_uris": []string{redirectURI},
			"manifest_permissions": []string{}, "human_oidc_enabled": true,
		}
		path := "/v1/spaces/" + spaceID + "/applications"
		if status := request(t, http.MethodPost, rpTestIssuer+path, bearer, registration, nil); status != http.StatusForbidden {
			t.Fatalf("registration without a matching step-up returned %d, want 403", status)
		}
		proof := maps.Clone(registration)
		proof["space_id"] = spaceID
		stepUpPublisher(t, bearer, factorSecret, "applications.register", proof, time.Now())
		var registered struct {
			Data struct {
				ID, Visibility, Status string
				ClientID               string   `json:"client_id"`
				SpaceID                string   `json:"space_id"`
				HumanOIDCEnabled       bool     `json:"human_oidc_enabled"`
				ManifestPermissions    []string `json:"manifest_permissions"`
				RedirectURIs           []string `json:"redirect_uris"`
			}
		}
		post(t, path, bearer, registration, &registered)
		app := registered.Data
		if app.ClientID == "" || app.SpaceID != spaceID || !app.HumanOIDCEnabled || app.ManifestPermissions == nil || len(app.ManifestPermissions) != 0 ||
			app.Visibility != "private" || app.Status != "active" || !slices.Equal(app.RedirectURIs, []string{redirectURI}) {
			t.Fatal("publisher did not receive a login-only client registered to its Space and callback")
		}
		publicClientID := app.ClientID
		public := oauth2.Config{ClientID: publicClientID, RedirectURL: redirectURI, Scopes: []string{oidc.ScopeOpenID}, Endpoint: endpoint}
		public.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		callback := approve(t, startConsent(t, public, state, nonce, verifier), state)
		code := callback.Query().Get("code")

		switchBackend()
		defer switchBackend()
		credentials, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		var response *oauth2.RetrieveError
		if credentials != nil || !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != http.StatusBadRequest || response.ErrorCode != "invalid_grant" {
			t.Fatal("another client redeemed the public client's authorization code")
		}
		credentials, err = public.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil || credentials.AccessToken == "" || credentials.RefreshToken != "" {
			t.Fatal("public client did not redeem its code using PKCE")
		}
		rawID, _ := credentials.Extra("id_token").(string)
		verified, err := provider.Verifier(&oidc.Config{ClientID: publicClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, rawID)
		if err != nil || verified.Subject != subject || verified.Nonce != nonce || !slices.Equal(verified.Audience, []string{publicClientID}) {
			t.Fatal("public client could not verify the signed account identity")
		}
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(credentials))
		if err != nil || info.Subject != subject {
			t.Fatal("public client did not receive the subject in UserInfo")
		}
		var disclosed map[string]json.RawMessage
		if err := info.Claims(&disclosed); err != nil || len(disclosed) != 1 || disclosed["sub"] == nil {
			t.Fatal("public client received UserInfo fields outside openid")
		}
		var registrations, consents, exchanges int
		err = st.Pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE action='application.register' AND member_id=$2),
			count(*) FILTER (WHERE action='oidc.consent.approve' AND user_id=$3),
			count(*) FILTER (WHERE action='oidc.login.exchange' AND user_id=$3)
			FROM audit_logs WHERE application_id=$1 AND outcome='success'`,
			app.ID, memberID, subject).Scan(&registrations, &consents, &exchanges)
		if err != nil || registrations != 1 || consents != 1 || exchanges != 1 {
			t.Fatal("publisher registration and end-user consent and exchange must each have their own audit event", err)
		}

		t.Run("publisher disables login across issuer instances", func(t *testing.T) {
			waiting := startConsent(t, public, oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier())
			pendingState, pendingProof := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
			pending := startConsent(t, public, pendingState, oauth2.GenerateVerifier(), pendingProof)
			pendingCode := approve(t, pending, pendingState).Query().Get("code")

			// Disable on the peer, then retry against the instance that issued
			// the pending code and the UserInfo token.
			func() {
				switchBackend()
				defer switchBackend()
				update := rpTestIssuer + "/v1/applications/" + app.ID
				disable := map[string]bool{"human_oidc_enabled": false}
				if status := request(t, http.MethodPatch, update, bearer, disable, nil); status != http.StatusForbidden {
					t.Fatalf("disable without a matching step-up returned %d, want 403", status)
				}
				live, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(credentials))
				if err != nil || live.Subject != subject {
					t.Fatal("a rejected change interrupted the user's login")
				}
				// Registration consumed this factor's current TOTP time step.
				stepUpPublisher(t, bearer, factorSecret, "applications.update", map[string]any{"application_id": app.ID, "human_oidc_enabled": false}, time.Now().Add(30*time.Second))
				request(t, http.MethodPatch, update, bearer, disable, &registered)
				if registered.Data.ID != app.ID || registered.Data.HumanOIDCEnabled || registered.Data.Status != "active" {
					t.Fatal("publisher did not disable login on the registered application")
				}
			}()

			fresh := public.AuthCodeURL(oauth2.GenerateVerifier(), oidc.Nonce(oauth2.GenerateVerifier()), oauth2.S256ChallengeOption(oauth2.GenerateVerifier()))
			if status := request(t, http.MethodGet, fresh, "", nil, nil); status != http.StatusBadRequest {
				t.Fatalf("new authorization request for disabled login returned %d, want 400", status)
			}
			if status := request(t, http.MethodPost, endpoint.AuthURL, signedIn.Data.Tokens.Access, map[string]string{"request_id": waiting, "decision": "approve"}, nil); status != http.StatusBadRequest {
				t.Fatalf("consent to pending request after disabling login returned %d, want 400", status)
			}
			redeemed, err := public.Exchange(ctx, pendingCode, oauth2.VerifierOption(pendingProof))
			var rejected *oauth2.RetrieveError
			if redeemed != nil || !errors.As(err, &rejected) || rejected.Response == nil || rejected.Response.StatusCode != http.StatusBadRequest || rejected.ErrorCode != "invalid_grant" {
				t.Fatal("peer did not reject the outstanding code after disabling login")
			}
			if status := request(t, http.MethodGet, rpTestIssuer+"/oauth/userinfo", credentials.AccessToken, nil, nil); status != http.StatusUnauthorized {
				t.Fatalf("issued UserInfo token after disabling login returned %d, want 401", status)
			}
			if status := request(t, http.MethodGet, rpTestIssuer+"/v1/me/sessions", signedIn.Data.Tokens.Access, nil, nil); status != http.StatusOK {
				t.Fatalf("end user's own session returned %d, want 200", status)
			}
			unaffected, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
			if err != nil || unaffected.Subject != subject {
				t.Fatal("the other relying party lost access to its own UserInfo")
			}
			remaining, err := provider.Verifier(&oidc.Config{ClientID: publicClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, rawID)
			if err != nil || remaining.Subject != subject || remaining.Nonce != nonce || !remaining.Expiry.Equal(verified.Expiry) {
				t.Fatal("relying party could not verify the already issued ID Token")
			}
			var changes, minted int
			err = st.Pool.QueryRow(ctx, `SELECT
				count(*) FILTER (WHERE action='application.update' AND member_id=$2 AND metadata->>'human_oidc_enabled'='false'),
				count(*) FILTER (WHERE action='oidc.login.exchange')
				FROM audit_logs WHERE application_id=$1 AND outcome='success'`, app.ID, memberID).Scan(&changes, &minted)
			if err != nil || changes != 1 || minted != 1 {
				t.Fatal("expected one audited disable and only the original successful exchange", err)
			}
		})
	})

	newConfidentialClient := func(t *testing.T, spaceID, bearer, factorSecret, callback string) (string, oauth2.Config) {
		t.Helper()
		registration := map[string]any{"name": "Confidential RP", "human_oidc_enabled": true, "manifest_permissions": []string{},
			"redirect_uris": []string{callback}, "token_endpoint_auth_method": "client_secret_basic"}
		proof := maps.Clone(registration)
		proof["space_id"] = spaceID
		stepUpPublisher(t, bearer, factorSecret, "applications.register", proof, time.Now())
		var created struct {
			Data struct {
				ID           string
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
				Method       string `json:"token_endpoint_auth_method"`
			}
		}
		post(t, "/v1/spaces/"+spaceID+"/applications", bearer, registration, &created)
		app := created.Data
		if app.ID == "" || app.ClientID == "" || app.ClientSecret == "" || app.Method != "client_secret_basic" {
			t.Fatal("publisher did not receive a confidential login client")
		}
		return app.ID, oauth2.Config{ClientID: app.ClientID, ClientSecret: app.ClientSecret, Endpoint: endpoint, RedirectURL: callback, Scopes: []string{oidc.ScopeOpenID}}
	}
	rotateOnPeer := func(t *testing.T, appID, bearer, factorSecret string, grace int32) application.OAuthSecretRotation {
		t.Helper()
		switchBackend()
		defer switchBackend()
		stepUpPublisher(t, bearer, factorSecret, application.RotateOAuthSecretOperation, map[string]any{"application_id": appID, "grace_period_seconds": grace}, time.Now().Add(30*time.Second))
		var rotated struct {
			Data application.OAuthSecretRotation
		}
		post(t, "/v1/applications/"+appID+"/oauth-client-secret/rotate", bearer, map[string]int32{"grace_period_seconds": grace}, &rotated)
		return rotated.Data
	}
	invalidTokenClient := func(token *oauth2.Token, err error) bool {
		var invalid *oauth2.RetrieveError
		return token == nil && errors.As(err, &invalid) && invalid.ErrorCode == "invalid_client" && invalid.Response != nil &&
			invalid.Response.StatusCode == http.StatusUnauthorized && invalid.Response.Header.Get("WWW-Authenticate") == `Basic realm="oauth/token"`
	}

	t.Run("publisher secret rotation after code issuance across issuer instances", func(t *testing.T) {
		spaceID, memberID, bearer, factorSecret := newPublisher(t, "confidential-publisher")
		appID, relyingParty := newConfidentialClient(t, spaceID, bearer, factorSecret, redirectURI)
		oldSecret := relyingParty.ClientSecret
		state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		callback := approve(t, startConsent(t, relyingParty, state, nonce, verifier), state)
		code := callback.Query().Get("code")
		rotated := rotateOnPeer(t, appID, bearer, factorSecret, 0)
		if rotated.ApplicationID != appID || rotated.ClientID != relyingParty.ClientID || rotated.ClientSecret == "" ||
			rotated.ClientSecret.Value() == oldSecret || rotated.PreviousSecretExpiresAt != nil {
			t.Fatal("peer did not rotate the original client credential")
		}
		stale, err := relyingParty.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if !invalidTokenClient(stale, err) {
			t.Fatal("the issuing process did not reject the stale client secret")
		}
		relyingParty.ClientSecret = rotated.ClientSecret.Value()
		tokens, err := relyingParty.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil || !tokens.Valid() {
			t.Fatal("the current secret could not redeem the outstanding code")
		}
		id, _ := tokens.Extra("id_token").(string)
		verified, err := provider.Verifier(&oidc.Config{ClientID: relyingParty.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, id)
		if err != nil || verified.Subject != subject || verified.Nonce != nonce {
			t.Fatal("the relying party could not verify the original user's identity")
		}
		var discovery struct {
			Revoke string `json:"revocation_endpoint"`
		}
		if err := provider.Claims(&discovery); err != nil || discovery.Revoke != rpTestIssuer+"/oauth/revoke" {
			t.Fatal("missing issuer revocation endpoint")
		}
		revoke := func(password string, want int) {
			t.Helper()
			form := url.Values{"token": {tokens.AccessToken}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.Revoke, strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal("could not construct a revocation request")
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(url.QueryEscape(relyingParty.ClientID), url.QueryEscape(password))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("revocation request failed")
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != want {
				t.Fatalf("revocation returned HTTP %d, want %d", resp.StatusCode, want)
			}
			if want == http.StatusUnauthorized {
				var denied struct{ Error string }
				if json.NewDecoder(resp.Body).Decode(&denied) != nil || denied.Error != "invalid_client" || resp.Header.Get("WWW-Authenticate") != `Basic realm="oauth/revoke"` {
					t.Fatal("stale client did not receive an invalid_client challenge")
				}
			}
		}
		func() {
			switchBackend()
			defer switchBackend()
			revoke(oldSecret, http.StatusUnauthorized)
			userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
			if err != nil || userInfo.Subject != subject {
				t.Fatal("failed revocation consumed the relying party's credential")
			}
			revoke(relyingParty.ClientSecret, http.StatusOK)
		}()
		if status := request(t, http.MethodGet, rpTestIssuer+"/oauth/userinfo", tokens.AccessToken, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("issuing process returned HTTP %d for the revoked UserInfo token", status)
		}
		var registered, rotations, exchanges int
		err = st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='application.register' AND member_id=$2 AND space_id=$3),
			count(*) FILTER (WHERE action='application.oauth_client_secret.rotate' AND member_id=$2 AND space_id=$3),
			count(*) FILTER (WHERE action='oidc.login.exchange' AND user_id=$4)
			FROM audit_logs WHERE application_id=$1 AND outcome='success'`, appID, memberID, spaceID, subject).Scan(&registered, &rotations, &exchanges)
		if err != nil || registered != 1 || rotations != 1 || exchanges != 1 {
			t.Fatal("expected one publisher registration, one rotation and one successful login exchange")
		}
	})

	t.Run("publisher secret grace is bounded across issuer instances", func(t *testing.T) {
		spaceID, memberID, bearer, factorSecret := newPublisher(t, "confidential-grace-publisher")
		appID, previous := newConfidentialClient(t, spaceID, bearer, factorSecret, redirectURI)
		type login struct{ code, nonce, verifier string }
		newLogin := func() login {
			state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
			callback := approve(t, startConsent(t, previous, state, nonce, verifier), state)
			return login{code: callback.Query().Get("code"), nonce: nonce, verifier: verifier}
		}
		previousLogin, currentLogin, pending := newLogin(), newLogin(), newLogin()

		const grace int32 = 120
		databaseTime := func() time.Time {
			t.Helper()
			var now time.Time
			if err := st.Pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
				t.Fatal("could not read the issuer database clock", err)
			}
			return now
		}
		before := databaseTime()
		rotated := rotateOnPeer(t, appID, bearer, factorSecret, grace)
		after := databaseTime()
		window := time.Duration(grace) * time.Second
		if rotated.ApplicationID != appID || rotated.ClientID != previous.ClientID || rotated.ClientSecret == "" ||
			rotated.ClientSecret.Value() == previous.ClientSecret || rotated.PreviousSecretExpiresAt == nil ||
			rotated.PreviousSecretExpiresAt.Before(before.Add(window)) || rotated.PreviousSecretExpiresAt.After(after.Add(window)) {
			t.Fatal("rotation did not preserve the client binding and return a database-bounded grace deadline")
		}
		current := previous
		current.ClientSecret = rotated.ClientSecret.Value()
		idVerifier := provider.Verifier(&oidc.Config{ClientID: previous.ClientID, SupportedSigningAlgs: []string{oidc.ES256}})
		expectLogin := func(config oauth2.Config, attempt login) {
			t.Helper()
			tokens, err := config.Exchange(ctx, attempt.code, oauth2.VerifierOption(attempt.verifier))
			if err != nil || !tokens.Valid() || tokens.RefreshToken != "" {
				t.Fatal("valid confidential credentials could not redeem the login code")
			}
			rawID, _ := tokens.Extra("id_token").(string)
			identity, err := idVerifier.Verify(ctx, rawID)
			if err != nil || identity.Subject != subject || identity.Nonce != attempt.nonce {
				t.Fatal("relying party could not verify the signed account and nonce")
			}
		}
		expectLogin(previous, previousLogin)
		func() {
			switchBackend()
			defer switchBackend()
			expectLogin(current, currentLogin)
		}()

		lockCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		mutation, err := st.BeginIdempotency(lockCtx)
		if err != nil {
			t.Fatal("could not begin the fixture transaction", err)
		}
		defer func() { _ = mutation.Rollback(context.Background()) }()
		var blockerPID int32
		if err := st.InTx(mutation.Context(lockCtx), func(q *db.Queries) error {
			tx, _ := q.Transaction()
			return tx.QueryRow(lockCtx, "SELECT pg_backend_pid() FROM applications WHERE id=$1 FOR UPDATE", appID).Scan(&blockerPID)
		}); err != nil {
			t.Fatal("could not hold the application row lock", err)
		}
		rejected := make(chan bool, 1)
		go func() {
			tokens, err := previous.Exchange(lockCtx, pending.code, oauth2.VerifierOption(pending.verifier))
			rejected <- invalidTokenClient(tokens, err)
		}()
		for {
			var waiting bool
			if err := st.Pool.QueryRow(lockCtx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname=current_database() AND $1 = ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting); err != nil {
				t.Fatal("could not observe the issuing process waiting on the application row", err)
			}
			if waiting {
				break
			}
			select {
			case <-rejected:
				t.Fatal("the issuing process did not wait for the application row lock")
			case <-lockCtx.Done():
				t.Fatal(lockCtx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		// Move the fixture's cutoff to the current database clock while the exchange is
		// waiting. This exercises the expiry boundary without waiting the whole window.
		if err := st.InTx(mutation.Context(lockCtx), func(q *db.Queries) error {
			tx, _ := q.Transaction()
			changed, err := tx.Exec(lockCtx, `UPDATE applications SET oauth_previous_secret_expires_at=clock_timestamp()
				WHERE id=$1 AND oauth_previous_secret_expires_at>clock_timestamp()`, appID)
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return errors.New("previous secret is no longer inside its grace window")
			}
			return nil
		}); err != nil {
			t.Fatal("could not advance the previous secret to its expiry boundary", err)
		}
		if err := mutation.Commit(lockCtx); err != nil {
			t.Fatal("could not release the application row lock", err)
		}
		select {
		case invalid := <-rejected:
			if !invalid {
				t.Fatal("the issuing process accepted a previous secret past its deadline")
			}
		case <-lockCtx.Done():
			t.Fatal(lockCtx.Err())
		}
		// The rejected request must leave the same code and PKCE proof usable.
		func() {
			switchBackend()
			defer switchBackend()
			expectLogin(current, pending)
		}()
		var rotations, exchanges int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='application.oauth_client_secret.rotate'
				AND member_id=$2 AND space_id=$3 AND (metadata->>'previous_secret_expires_at')::timestamptz=$5),
			count(*) FILTER (WHERE action='oidc.login.exchange' AND user_id=$4)
			FROM audit_logs WHERE application_id=$1 AND outcome='success'`,
			appID, memberID, spaceID, subject, *rotated.PreviousSecretExpiresAt).Scan(&rotations, &exchanges); err != nil || rotations != 1 || exchanges != 3 {
			t.Fatal("expected the original grace deadline in one rotation audit and exactly three successful exchanges", err)
		}
	})

	t.Run("registered callback query survives consent across issuer instances", func(t *testing.T) {
		const registeredQuery = "team=North%20Wing&route=%2f&team=South+Wing"
		approveState, denyState := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/callback" || !strings.HasPrefix(r.URL.RawQuery, registeredQuery+"&") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			query := r.URL.Query()
			state := query.Get("state")
			approved := state == approveState && len(query["code"]) == 1 && query.Get("code") != "" && !query.Has("error")
			denied := state == denyState && len(query["error"]) == 1 && query.Get("error") == "access_denied" && !query.Has("code")
			if len(query["state"]) != 1 || (!approved && !denied) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(receiver.Close)
		registered := receiver.URL + "/callback?" + registeredQuery
		spaceID, _, bearer, factorSecret := newPublisher(t, "confidential-callback-publisher")
		_, relyingParty := newConfidentialClient(t, spaceID, bearer, factorSecret, registered)
		for _, scenario := range []struct{ decision, state string }{{"approve", approveState}, {"deny", denyState}} {
			nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
			handle := startConsent(t, relyingParty, scenario.state, nonce, verifier)
			var consent struct {
				Redirect string `json:"redirect_to"`
			}
			func() {
				switchBackend()
				defer switchBackend()
				request(t, http.MethodPost, endpoint.AuthURL, signedIn.Data.Tokens.Access,
					map[string]string{"request_id": handle, "decision": scenario.decision}, &consent)
			}()
			callback, err := url.Parse(consent.Redirect)
			if err != nil || !strings.HasPrefix(consent.Redirect, registered+"&") {
				t.Fatalf("%s did not retain the exact registered callback query", scenario.decision)
			}
			if status := request(t, http.MethodGet, callback.String(), "", nil, nil); status != http.StatusNoContent {
				t.Fatalf("RP rejected the %s callback with status %d", scenario.decision, status)
			}
			if scenario.decision == "deny" {
				continue
			}
			code := callback.Query().Get("code")
			tokens, err := relyingParty.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			if err != nil || !tokens.Valid() {
				t.Fatal("the original callback URI and PKCE proof could not redeem the code")
			}
			rawID, _ := tokens.Extra("id_token").(string)
			verified, err := provider.Verifier(&oidc.Config{ClientID: relyingParty.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, rawID)
			if err != nil || verified.Subject != subject || verified.Nonce != nonce {
				t.Fatal("the RP could not verify the signed account and nonce")
			}
		}
	})

	t.Run("live signer rotation and recovery across issuer instances", func(t *testing.T) {
		owner, err := store.Open(ctx, database.OwnerURL)
		if err != nil {
			t.Fatal("open deployment fixture for signing key transitions")
		}
		t.Cleanup(owner.Close)
		replacement, err := security.GenerateSigner(rpTestIssuer)
		if err != nil {
			t.Fatal(err)
		}
		next, err := replacement.SealActiveSigningKey(wrappingKey[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Pool.Exec(ctx, `INSERT INTO signing_keys (kid, issuer, private_key_ciphertext, status)
			VALUES ($1, $2, $3, 'next')`, next.KID, next.Issuer, next.Ciphertext); err != nil {
			t.Fatal("stage new issuer key", err)
		}
		both := func(check func()) {
			t.Helper()
			check()
			switchBackend()
			defer switchBackend()
			check()
		}
		kid := func(raw string) string {
			t.Helper()
			message, err := jws.ParseString(raw)
			if err != nil || len(message.Signatures()) != 1 {
				t.Fatal("missing token signature")
			}
			id, ok := message.Signatures()[0].ProtectedHeaders().KeyID()
			if !ok || id == "" {
				t.Fatal("missing signing key ID")
			}
			return id
		}
		published := func(want ...string) {
			t.Helper()
			var set struct{ Keys []struct{ KID string } }
			request(t, http.MethodGet, rpTestIssuer+"/.well-known/jwks.json", "", nil, &set)
			var got []string
			for _, key := range set.Keys {
				got = append(got, key.KID)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatal("issuer published the wrong signing key set")
			}
		}
		oldID := kid(rawID)
		both(func() { published(oldID) })
		// This transaction models the deployment's committed promotion. The
		// runtime application role only has read access to existing keys.
		if _, err := owner.Pool.Exec(ctx, `DO $$ BEGIN
			UPDATE signing_keys SET status='retiring' WHERE status='active';
			UPDATE signing_keys SET status='active' WHERE status='next';
		END $$`); err != nil {
			t.Fatal("promote staged issuer key", err)
		}
		pendingCode := func() (string, string, string) {
			t.Helper()
			state, nonce, proof := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
			handle := startConsent(t, config, state, nonce, proof)
			return approve(t, handle, state).Query().Get("code"), proof, nonce
		}
		exchange := func(code, proof, nonce string) {
			t.Helper()
			tokens, err := config.Exchange(ctx, code, oauth2.VerifierOption(proof))
			if err != nil {
				t.Fatal("RP could not exchange its code")
			}
			raw, _ := tokens.Extra("id_token").(string)
			identity, err := idVerifier.Verify(ctx, raw)
			if err != nil || identity.Subject != subject || identity.Nonce != nonce || kid(raw) != next.KID {
				t.Fatal("live issuer did not sign with the promoted key")
			}
		}
		both(func() {
			published(oldID, next.KID)
			exchange(pendingCode())
		})
		code, proof, loginNonce := pendingCode()
		refresh := map[string]string{"refresh_token": signedIn.Data.Tokens.Refresh}
		if _, err := owner.Pool.Exec(ctx, `UPDATE signing_keys SET private_key_ciphertext=set_byte(private_key_ciphertext, 0,
			(get_byte(private_key_ciphertext, 0)+1)%256) WHERE kid=$1`, next.KID); err != nil {
			t.Fatal("simulate key integrity failure", err)
		}
		both(func() {
			for _, endpoint := range []struct{ path, bearer string }{
				{"/.well-known/jwks.json", ""}, {"/v1/me/sessions", signedIn.Data.Tokens.Access},
			} {
				if status := request(t, http.MethodGet, rpTestIssuer+endpoint.path, endpoint.bearer, nil, nil); status != http.StatusServiceUnavailable {
					t.Fatalf("%s with unusable key ring returned %d, want 503", endpoint.path, status)
				}
			}
		})
		for _, endpoint := range readyURLs {
			if status := request(t, http.MethodGet, endpoint, "", nil, nil); status != http.StatusServiceUnavailable {
				t.Fatalf("readiness with unusable key ring returned %d, want 503", status)
			}
		}
		result, err := config.Exchange(ctx, code, oauth2.VerifierOption(proof))
		var rejected *oauth2.RetrieveError
		if result != nil || !errors.As(err, &rejected) || rejected.Response == nil ||
			rejected.Response.StatusCode != http.StatusServiceUnavailable || rejected.ErrorCode != "temporarily_unavailable" {
			t.Fatal("issuer did not report its unavailable signing service to the RP")
		}
		if status := request(t, http.MethodPost, rpTestIssuer+"/v1/auth/refresh", "", refresh, nil); status != http.StatusServiceUnavailable {
			t.Fatalf("session refresh with unusable key ring returned %d, want 503", status)
		}
		if _, err := owner.Pool.Exec(ctx, `UPDATE signing_keys SET private_key_ciphertext=$1 WHERE kid=$2`, next.Ciphertext, next.KID); err != nil {
			t.Fatal("restore the intact issuer key", err)
		}
		for _, endpoint := range readyURLs {
			if status := request(t, http.MethodGet, endpoint, "", nil, nil); status != http.StatusOK {
				t.Fatalf("readiness after restoring the key ring returned %d, want 200", status)
			}
		}
		exchange(code, proof, loginNonce)
		var renewed struct {
			Data struct {
				Access string `json:"access_token"`
			}
		}
		request(t, http.MethodPost, rpTestIssuer+"/v1/auth/refresh", "", refresh, &renewed)
		if kid(renewed.Data.Access) != next.KID {
			t.Fatal("session refresh used a superseded key")
		}
		both(func() {
			published(oldID, next.KID)
			for _, access := range []string{signedIn.Data.Tokens.Access, renewed.Data.Access} {
				if status := request(t, http.MethodGet, rpTestIssuer+"/v1/me/sessions", access, nil, nil); status != http.StatusOK {
					t.Fatalf("valid user token during signing key overlap returned %d, want 200", status)
				}
			}
		})
	})

	t.Run("original session sign-out", func(t *testing.T) {
		nextState, nextVerifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		nextHandle := startConsent(t, config, nextState, oauth2.GenerateVerifier(), nextVerifier)
		next := approve(t, nextHandle, nextState)
		nextCode := next.Query().Get("code")
		if nextCode == callback.Query().Get("code") {
			t.Fatal("second consent reused the already exchanged code")
		}
		// Sign out on the peer so the primary must observe the revocation.
		switchBackend()
		var signOut struct{ Data struct{ Revoked bool } }
		request(t, http.MethodPost, rpTestIssuer+"/v1/auth/sign-out", signedIn.Data.Tokens.Access, nil, &signOut)
		if !signOut.Data.Revoked {
			t.Fatal("auth did not revoke the originating user session")
		}
		switchBackend()
		if status := request(t, http.MethodGet, rpTestIssuer+"/oauth/userinfo", token.AccessToken, nil, nil); status != http.StatusUnauthorized {
			t.Fatalf("UserInfo after sign-out returned %d", status)
		}
		_, err := config.Exchange(ctx, nextCode, oauth2.VerifierOption(nextVerifier))
		var response *oauth2.RetrieveError
		if !errors.As(err, &response) || response.Response == nil || response.Response.StatusCode != http.StatusBadRequest || response.ErrorCode != "invalid_grant" {
			t.Fatal("pending authorization code did not return invalid_grant after sign-out")
		}
		remaining, err := idVerifier.Verify(ctx, rawID)
		if err != nil || remaining.Subject != claims.Subject || remaining.Nonce != nonce || !remaining.Expiry.Equal(claims.Expiry) {
			t.Fatal("RP could not verify the previously issued, unexpired ID Token after sign-out")
		}
		afterExpiry := verification
		afterExpiry.Now = func() time.Time { return claims.Expiry.Add(time.Second) }
		_, err = provider.Verifier(&afterExpiry).Verify(ctx, rawID)
		var expired *oidc.TokenExpiredError
		if !errors.As(err, &expired) || !expired.Expiry.Equal(claims.Expiry) {
			t.Fatal("RP did not reject the ID Token at the end of its validity period")
		}
	})

	t.Run("pending login survives primary process exit", func(t *testing.T) {
		signedIn = passwordSignIn(t)
		pendingState, pendingNonce, pendingVerifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		pending := startConsent(t, config, pendingState, pendingNonce, pendingVerifier)
		previousAccess, previousRefresh := signedIn.Data.Tokens.Access, signedIn.Data.Tokens.Refresh
		losePrimary(t)
		if status := request(t, http.MethodGet, rpTestIssuer+"/v1/me/sessions", previousAccess, nil, nil); status != http.StatusOK {
			t.Fatalf("the surviving issuer rejected the original session: status=%d", status)
		}
		var refreshed struct{ Data session.Tokens }
		request(t, http.MethodPost, rpTestIssuer+"/v1/auth/refresh", "", map[string]string{"refresh_token": previousRefresh}, &refreshed)
		if refreshed.Data.AccessToken == "" || refreshed.Data.RefreshToken == "" || refreshed.Data.RefreshToken == previousRefresh {
			t.Fatal("the surviving issuer did not rotate the original session refresh credential")
		}
		signedIn.Data.Tokens.Access = refreshed.Data.AccessToken
		callback := approve(t, pending, pendingState)
		credentials, err := config.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(pendingVerifier))
		if err != nil {
			t.Fatal("the relying party could not redeem the consent code after failover")
		}
		raw, _ := credentials.Extra("id_token").(string)
		identity, err := provider.Verifier(&verification).Verify(ctx, raw)
		if err != nil || identity.Subject != subject || identity.Nonce != pendingNonce {
			t.Fatal("the relying party could not verify the user identity after failover")
		}
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(credentials))
		if err != nil || info.Subject != subject || info.Email != email || !info.EmailVerified {
			t.Fatal("the relying party could not read current permitted user claims after failover")
		}
	})
}
