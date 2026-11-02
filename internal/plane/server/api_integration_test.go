package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
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
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
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
	var subjectSource string
	if err := st.Pool.QueryRow(ctx, `SELECT metadata->>'subject_source' FROM audit_logs WHERE action = 'authz.check' ORDER BY occurred_at DESC LIMIT 1`).Scan(&subjectSource); err != nil {
		t.Fatal(err)
	}
	if subjectSource != "application_assertion" {
		t.Fatalf("subject assertion audit marker = %q, want application_assertion", subjectSource)
	}
}

func TestAuthzCheckRejectsInlineFactsWithDocumentedError(t *testing.T) {
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)

	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	base := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	valid := request(base)
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"decision":"allow"`) {
		t.Fatalf("documented resource facts = %d %s, want allow", valid.Code, valid.Body.String())
	}
	for name, body := range map[string]string{
		"inline grants":     strings.TrimSuffix(base, "}") + `,"grants":[]}`,
		"inline roles":      strings.TrimSuffix(base, "}") + `,"roles":[]}`,
		"subject attribute": fmt.Sprintf(`{"subject":{"member_id":%q,"is_admin":true},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID),
		"agent_id alias":    fmt.Sprintf(`{"subject":{"agent_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID),
	} {
		t.Run(name, func(t *testing.T) {
			w := request(body)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"INLINE_GRANTS_NOT_ALLOWED"`) {
				t.Fatalf("inline facts = %d %s, want 400 INLINE_GRANTS_NOT_ALLOWED", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuthzBatchCheckEvaluatesItemsIndependently(t *testing.T) {
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	request := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/server/v1/authz/batch-check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	allowed := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	denied := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"missing:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	w := request(`{"requests":[` + allowed + `,` + denied + `]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("batch status = %d, body = %s", w.Code, w.Body.String())
	}
	var response struct {
		Data []CheckDecision `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data) != 2 || response.Data[0].Decision != "allow" || response.Data[1].Decision != "deny" || response.Data[1].DenyCode != "UNKNOWN_PERMISSION" {
		t.Fatalf("batch decisions = %+v, want allow then UNKNOWN_PERMISSION deny", response.Data)
	}
	items := make([]string, 101)
	for i := range items {
		items[i] = allowed
	}
	if w := request(`{"requests":[` + strings.Join(items, ",") + `]}`); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("oversized batch = %d %s, want 400 VALIDATION_FAILED", w.Code, w.Body.String())
	}
}

func TestAuthzExplainHTTPUsesGoldenTraceAndAuditsDenials(t *testing.T) {
	ctx := context.Background()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET scopes = '["auth.authz:check", "auth.authz:explain", "auth.tokens:introspect"]'::jsonb WHERE prefix = $1`, strings.SplitN(key, ".", 2)[0]); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	request := func(secret, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/server/v1/authz/explain", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	allow := request(key, body)
	if allow.Code != http.StatusOK {
		t.Fatalf("explain allow status = %d, body = %s", allow.Code, allow.Body.String())
	}
	var allowResponse struct {
		Data ExplainDecision `json:"data"`
	}
	if err := json.Unmarshal(allow.Body.Bytes(), &allowResponse); err != nil {
		t.Fatal(err)
	}
	if allowResponse.Data.Decision != string(engine.Allow) || allowResponse.Data.DecisionID == "" || len(allowResponse.Data.Trace) == 0 {
		t.Fatalf("explain allow response = %+v", allowResponse.Data)
	}
	assertExplainGolden(t, "explain_allow.golden", allowResponse.Data)

	deniedBody := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"missing:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	deny := request(key, deniedBody)
	if deny.Code != http.StatusOK {
		t.Fatalf("explain deny status = %d, body = %s", deny.Code, deny.Body.String())
	}
	var denyResponse struct {
		Data ExplainDecision `json:"data"`
	}
	if err := json.Unmarshal(deny.Body.Bytes(), &denyResponse); err != nil {
		t.Fatal(err)
	}
	if denyResponse.Data.Decision != string(engine.Deny) || denyResponse.Data.DenyCode != "UNKNOWN_PERMISSION" || len(denyResponse.Data.Trace) == 0 {
		t.Fatalf("explain deny response = %+v", denyResponse.Data)
	}
	assertExplainGolden(t, "explain_deny.golden", denyResponse.Data)
	var action, outcome, resourceID string
	if err := st.Pool.QueryRow(ctx, `SELECT action, outcome, resource_id FROM audit_logs WHERE action = 'authz.explain' ORDER BY occurred_at DESC LIMIT 1`).Scan(&action, &outcome, &resourceID); err != nil {
		t.Fatal(err)
	}
	if action != "authz.explain" || outcome != "deny" || resourceID != member.ID {
		t.Fatalf("explain deny audit = action=%q outcome=%q resource=%q", action, outcome, resourceID)
	}

	apps := &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	expiresAt := time.Now().Add(time.Hour)
	withoutExplain, err := apps.CreateKey(ctx, "app_server_test", "without-explain", []string{"auth.authz:check"}, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if denied := request(withoutExplain, body); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), `"code":"PERMISSION_DENIED"`) {
		t.Fatalf("missing explain scope = %d %s", denied.Code, denied.Body.String())
	}
}

func assertExplainGolden(t *testing.T, name string, decision ExplainDecision) {
	t.Helper()
	golden := struct {
		Decision string        `json:"decision"`
		DenyCode string        `json:"deny_code,omitempty"`
		Summary  string        `json:"summary"`
		Trace    []ExplainStep `json:"trace"`
	}{Decision: decision.Decision, DenyCode: decision.DenyCode, Summary: decision.Summary, Trace: decision.Trace}
	actual, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("testdata", name)
	want, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual)+"\n" != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("%s mismatch\nwant:\n%s\n got:\n%s", name, want, actual)
	}
}

func TestAuthzRoutesRejectUnknownFieldsAndUseDocumentedBodyLimits(t *testing.T) {
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	request := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	base := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, member.ID, spaceID)
	unknown := strings.TrimSuffix(base, "}") + `,"unexpected":true}`
	if w := request("/server/v1/authz/check", unknown); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("unknown authz.check field status = %d, body = %s, want 400 VALIDATION_FAILED", w.Code, w.Body.String())
	} else if strings.Contains(w.Body.String(), `"value"`) || strings.Contains(w.Body.String(), member.ID) {
		t.Fatalf("unknown authz.check field leaked request data: %s", w.Body.String())
	}
	largeAction := strings.Repeat("x", 70*1024)
	large := fmt.Sprintf(`{"subject":{"member_id":%q},"action":%q,"resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, largeAction, member.ID, spaceID)
	if w := request("/server/v1/authz/check", large); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("oversized authz.check status = %d, body = %s, want 400 VALIDATION_FAILED", w.Code, w.Body.String())
	}
	batchBody := `{"requests":[` + large + `]}`
	if w := request("/server/v1/authz/batch-check", batchBody); w.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("batch body under 256 KiB was rejected as oversized: %s", w.Body.String())
	}
	overBatch := `{"requests":[` + fmt.Sprintf(`{"subject":{"member_id":%q},"action":%q,"resource":{"type":"member","id":%q,"space_id":%q}}`, member.ID, strings.Repeat("y", 270*1024), member.ID, spaceID) + `]}`
	if w := request("/server/v1/authz/batch-check", overBatch); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("oversized batch status = %d, body = %s, want 400 VALIDATION_FAILED", w.Code, w.Body.String())
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
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
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
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Sessions: sessions}
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
	st, authz, _, _, key, sessions := newServerFixture(t)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
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
		INSERT INTO applications (id, space_id, name, client_id, manifest_permissions)
		VALUES ('app_server_test', $1, 'Server Test Application', 'server-test-client',
		        '["auth.authz:check", "auth.authz:explain", "auth.tokens:introspect"]'::jsonb)
	`, space.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_server_app_manage', $1, '["auth.applications:manage"]'::jsonb, $2, 'space', $1, $2)
	`, space.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	if _, err := apps.InstallPrivateSpace(ctx, member.ID, "app_server_test", space.ID); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour)
	key, err := apps.CreateKey(ctx, "app_server_test", "server-test", []string{"auth.authz:check", "auth.tokens:introspect"}, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE api_keys SET allow_subject_assertion = true,
		    restrict_to = jsonb_build_array(jsonb_build_object('space_id', $1::text, 'include_descendants', false))
		WHERE name = 'server-test'
	`, space.ID); err != nil {
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
