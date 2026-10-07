package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var protocolDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	protocolDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := protocolDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestOAuthRefreshGrantUsesAgentAccessTokenRenewal(t *testing.T) {
	ctx := context.Background()
	database, err := protocolDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_oauth_refresh_protocol', 'oauth-refresh-protocol@example.test', 'oauth-refresh-protocol@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	_, owner, err := authorizer.CreateSpace(ctx, "usr_oauth_refresh_protocol", "OAuth Refresh Space", "oauth-refresh-protocol")
	if err != nil {
		t.Fatal(err)
	}
	credentialKey := []byte("protocol-oauth-refresh-hmac-key-0001")
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{credentialKey}}
	ag, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "oauth-protocol-agent", Source: "oauth", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := agents.CreateOAuthRefreshCredential(ctx, ag.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{
		Store: st, Signer: signer, HMACKeys: [][]byte{[]byte("session-hmac-key-0000000000000001")},
		Settings: func(context.Context) (session.Settings, error) {
			return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	var mux http.ServeMux
	(HTTP{Agents: agents, Sessions: sessions}).Register(&mux)

	request := func(token string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "resource": {security.DefaultApplicationAudience}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	first := request(refresh)
	if first.Code != http.StatusOK {
		t.Fatalf("OAuth refresh status = %d, body = %s", first.Code, first.Body.String())
	}
	var firstBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	if firstBody.AccessToken == "" || firstBody.RefreshToken == "" || firstBody.RefreshToken == refresh {
		t.Fatalf("OAuth refresh response = %+v", firstBody)
	}
	claims, active, err := sessions.Introspect(ctx, firstBody.AccessToken, security.DefaultApplicationAudience)
	if err != nil || !active || claims.Type != "agent" || claims.Subject != ag.ID {
		t.Fatalf("renewed Agent access token claims=%+v active=%v err=%v", claims, active, err)
	}
	replay := request(refresh)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed OAuth refresh status = %d, want 400", replay.Code)
	}
	if next := request(firstBody.RefreshToken); next.Code != http.StatusBadRequest {
		t.Fatalf("family token after replay status = %d, want 400", next.Code)
	}
}
