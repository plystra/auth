package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var serverDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	serverDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := serverDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestAuthzCheckSubjectAssertionAndKeyScope(t *testing.T) {
	ctx := context.Background()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st}, Authorization: authz, Sessions: sessions}
	if _, err := api.resolveSubject(ctx, application.Key{SpaceID: spaceID}, CheckSubject{MemberID: member.ID}, spaceID); err == nil {
		t.Fatal("member_id subject assertion succeeded without explicit API-key enablement")
	} else {
		assertServerError(t, err, "VALIDATION_FAILED")
	}
	out, err := api.check(ctx, &CheckInput{
		Authorization: "Bearer " + key,
		Body:          CheckBody{Subject: CheckSubject{MemberID: member.ID}, Action: "self:read", Resource: CheckResource{Type: "member", ID: member.ID, SpaceID: spaceID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Body.Data.Decision != "allow" || out.Body.Data.PolicyVersion == "" {
		t.Fatalf("subject assertion check = %+v, want allow with policy_version", out.Body.Data)
	}
	otherSpace := "spc_server_scope"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ($1, 'Other', 'server-scope-other')`, otherSpace); err != nil {
		t.Fatal(err)
	}
	out, err = api.check(ctx, &CheckInput{
		Authorization: "Bearer " + key,
		Body:          CheckBody{Subject: CheckSubject{MemberID: member.ID}, Action: "self:read", Resource: CheckResource{Type: "member", ID: member.ID, SpaceID: otherSpace}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Body.Data.DenyCode != "KEY_SCOPE_EXCLUDED" {
		t.Fatalf("out-of-scope authz.check = %+v, want KEY_SCOPE_EXCLUDED", out.Body.Data)
	}
}

func TestAuthzCheckTokenUsesSelectedMemberWhenUserHasMultipleMembers(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, key, sessions := newServerFixture(t)
	selected, err := authz.CreateMember(ctx, actor.ID, "usr_server_actor", spaceID, "second identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateForMember(ctx, "usr_server_actor", selected.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.Signer.Verify(issued.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	claims.Audience = "server-test-client"
	token, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st}, Authorization: authz, Sessions: sessions}
	resolved, err := api.resolveSubject(ctx, application.Key{SpaceID: spaceID, ClientID: "server-test-client"}, CheckSubject{Token: token}, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ID != selected.ID {
		t.Fatalf("authz.check token resolved %q, want selected member %q", resolved.ID, selected.ID)
	}
	out, err := api.check(ctx, &CheckInput{
		Authorization: "Bearer " + key,
		Body: CheckBody{Subject: CheckSubject{Token: token}, Action: "self:read", Resource: CheckResource{
			Type: "member", ID: selected.ID, SpaceID: spaceID, OwnerMemberID: selected.ID,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Body.Data.Decision != "deny" || out.Body.Data.DenyCode != "NO_MATCHING_PERMISSION" {
		t.Fatalf("authz.check evaluated %+v, want selected member without a grant", out.Body.Data)
	}
}

func TestTokenIntrospectionRequiresTheApplicationAudience(t *testing.T) {
	ctx := context.Background()
	st, _, _, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st}, Sessions: sessions}
	now := time.Now().UTC()
	foreign, err := sessions.Signer.Sign(security.Claims{
		Issuer: sessions.Signer.Issuer(), Subject: "usr_server_actor", Audience: "foreign-app",
		ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), JWTID: "jti_foreign", Type: "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := api.introspect(ctx, &IntrospectInput{Authorization: "Bearer " + key, Body: struct {
		Token string `json:"token"`
	}{Token: foreign}})
	if err != nil {
		t.Fatal(err)
	}
	if active.Body.Data.Active {
		t.Fatal("tokens.introspect accepted a token issued for a different audience")
	}
	if spaceID == "" {
		t.Fatal("fixture returned an empty Space ID")
	}
}

func TestTokenIntrospectionRejectsInvalidExpiredAndRevokedTokens(t *testing.T) {
	ctx := context.Background()
	st, _, _, _, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st}, Sessions: sessions}
	issued, err := sessions.Create(ctx, "usr_server_actor", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := security.Claims{
		Issuer: sessions.Signer.Issuer(), Subject: "usr_server_actor", Audience: "server-test-client",
		ExpiresAt: now.Add(time.Minute).Unix(), IssuedAt: now.Unix(), JWTID: "jti_introspection_test",
		SessionID: issued.SessionID, Type: "user",
	}
	valid, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	check := func(token string) bool {
		t.Helper()
		out, checkErr := api.introspect(ctx, &IntrospectInput{Authorization: "Bearer " + key, Body: struct {
			Token string `json:"token"`
		}{Token: token}})
		if checkErr != nil {
			t.Fatal(checkErr)
		}
		return out.Body.Data.Active
	}
	if !check(valid) {
		t.Fatal("live application-audience token was not active")
	}
	if check("not-a-token") {
		t.Fatal("invalid token was active")
	}
	claims.ExpiresAt = now.Add(-time.Second).Unix()
	expired, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	if check(expired) {
		t.Fatal("expired token was active")
	}
	if err := sessions.Revoke(ctx, issued.SessionID); err != nil {
		t.Fatal(err)
	}
	if check(valid) {
		t.Fatal("revoked token was active")
	}
}

func newServerFixture(t *testing.T) (*store.Store, *authorization.Service, authorization.Member, string, string, *session.Service) {
	t.Helper()
	ctx := context.Background()
	database, err := serverDB.Clone(ctx)
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
		VALUES ('usr_server_actor', 'server-actor@example.test', 'server-actor@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, member, err := authz.CreateSpace(ctx, "usr_server_actor", "Server Test Space", "server-test-space")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO applications (id, space_id, name, client_id)
		VALUES ('app_server_test', $1, 'Server Test Application', 'server-test-client')
	`, space.ID); err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st}
	key, err := apps.CreateKey(ctx, "app_server_test", "server-test", []string{"auth.authz:check", "auth.tokens:introspect"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET allow_subject_assertion = true WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}}
	return st, authz, member, space.ID, key, sessions
}

func assertServerError(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
