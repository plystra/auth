package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var enterpriseDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	enterpriseDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := enterpriseDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestOIDCConnectionConfigurationUsesAuthorizationAndEncryptedSecrets(t *testing.T) {
	ctx := context.Background()
	database, err := enterpriseDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status) VALUES ('usr_sso_owner', 'owner@example.test', 'owner@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	space, owner, err := authorizer.CreateSpace(ctx, "usr_sso_owner", "SSO Space", "sso-space")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, Authorization: authorizer, DataKey: secret.New(strings.Repeat("d", 32))}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_owner")
	connection, err := svc.CreateConnection(requestCtx, owner.ID, space.ID, ConnectionInput{
		Name: "Acme", Provider: "oidc", Issuer: "https://idp.example.com/tenant",
		ClientID: "client", ClientSecret: "super-secret", RedirectURI: "https://app.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(connection.RedirectURI, "{connection_id}") || !strings.Contains(connection.RedirectURI, connection.ID) {
		t.Fatalf("redirect URI was not bound to the connection: %q", connection.RedirectURI)
	}
	var ciphertext []byte
	if err := st.Pool.QueryRow(ctx, `SELECT client_secret_ciphertext FROM sso_connections WHERE id = $1`, connection.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "super-secret") {
		t.Fatal("OIDC client secret was stored in plaintext")
	}
	if err := svc.DisableConnection(requestCtx, owner.ID, space.ID, connection.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Start(ctx, connection.ID, ""); err == nil {
		t.Fatal("disabled OIDC connection was allowed to start")
	}
}

func TestOIDCStartStoresOneTimeStateAndBuildsPKCERequest(t *testing.T) {
	ctx := context.Background()
	database, err := enterpriseDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status) VALUES ('usr_sso_start', 'start@example.test', 'start@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	space, owner, err := authorizer.CreateSpace(ctx, "usr_sso_start", "Start Space", "sso-start")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		port := listener.Addr().(*net.TCPAddr).Port
		base := fmt.Sprintf("http://localhost:%d", port)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": base, "authorization_endpoint": base + "/authorize",
			"token_endpoint": base + "/token", "jwks_uri": base + "/jwks",
		})
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	issuer := "http://localhost:" + strings.TrimPrefix(server.URL, "http://127.0.0.1:")
	svc := &Service{Store: st, Authorization: authorizer, DataKey: secret.New(strings.Repeat("d", 32)), HTTPClient: server.Client()}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_start")
	connection, err := svc.CreateConnection(requestCtx, owner.ID, space.ID, ConnectionInput{
		Name: "Local OIDC", Provider: "oidc", Issuer: issuer,
		ClientID: "client", ClientSecret: "secret", RedirectURI: "http://localhost:8090/callback/{connection_id}",
	})
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.Start(ctx, connection.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	for _, key := range []string{"state", "nonce", "code_challenge", "code_challenge_method"} {
		if query.Get(key) == "" {
			t.Fatalf("authorization request omitted %s", key)
		}
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("state") != start.State {
		t.Fatalf("authorization request did not bind state and S256 PKCE: %v", query)
	}
	var stateCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM sso_states WHERE connection_id = $1 AND consumed_at IS NULL`, connection.ID).Scan(&stateCount); err != nil {
		t.Fatal(err)
	}
	if stateCount != 1 {
		t.Fatalf("pending SSO state count = %d, want 1", stateCount)
	}
	var stateHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT state_hash FROM sso_states WHERE connection_id = $1`, connection.ID).Scan(&stateHash); err != nil {
		t.Fatal(err)
	}
	if string(stateHash) == start.State {
		t.Fatal("plaintext state was stored")
	}
}
