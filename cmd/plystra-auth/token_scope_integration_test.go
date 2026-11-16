package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

func TestNarrowedTokenScopeMatchesAcrossManagementCheckBatchAndExplain(t *testing.T) {
	ctx := context.Background()
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
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_scope_parity', 'scope@example.test', 'scope@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, owner, err := authz.CreateSpace(ctx, "usr_scope_parity", "Scope parity", "scope-parity")
	if err != nil {
		t.Fatal(err)
	}
	spaceID := space.ID
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id, manifest_permissions)
		VALUES ('app_scope_parity', $1, 'Scope checks', 'scope-parity-client', '["auth.authz:check", "auth.authz:explain"]'::jsonb)`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceInlineGrants(ctx, owner.ID, spaceID, owner.ID, []string{"auth.members:read", "auth.members:manage", "auth.applications:manage", "auth.authz:check", "auth.authz:explain"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "scope-parity", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.members:read", "auth.members:manage"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	if _, err := apps.InstallSpace(ctx, owner.ID, "app_scope_parity", spaceID); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	key, err := apps.CreateKey(ctx, "app_scope_parity", "scope-checks", []string{"auth.authz:check", "auth.authz:explain"}, &expires)
	if err != nil {
		t.Fatal(err)
	}
	serverMux := http.NewServeMux()
	(&server.API{Applications: apps, Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(serverMux, route.HumaConfig("server scope test", "1.0.0")))
	principalMux := http.NewServeMux()
	(&principal.API{Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(principalMux, route.HumaConfig("principal scope parity", "1.0.0")))
	serverHandler := route.Middleware(route.Server, serverMux)
	principalHandler := route.Middleware(route.Principal, principalMux)
	request := func(handler http.Handler, method, path, credential, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+credential)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	for _, tc := range []struct {
		name   string
		scopes []string
		allow  bool
	}{
		{"included", []string{"auth.members:read", "auth.members:manage"}, true},
		{"excluded", []string{"auth.members:read"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each surface requires its own audience. The same member, action,
			// target and credential restriction must yield the same decision.
			business, err := sessions.CreateAgentDelegatedAccess(ctx, created.ID, spaceID, "scope-parity-client", owner.ID, tc.scopes, 0)
			if err != nil {
				t.Fatal(err)
			}
			governance, err := sessions.CreateAgentDelegatedAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience, owner.ID, tc.scopes, 0)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(server.CheckBody{Subject: server.CheckSubject{Token: business.AccessToken}, Action: "auth.members:manage", Resource: server.CheckResource{Type: "space", ID: spaceID, SpaceID: spaceID}})
			if err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"check", "batch-check", "explain"} {
				payload := string(body)
				if endpoint == "batch-check" {
					payload = `{"requests":[` + payload + `]}`
				}
				response := request(serverHandler, http.MethodPost, "/server/v1/authz/"+endpoint, key, payload)
				want := `"decision":"allow"`
				if !tc.allow {
					want = `"deny_code":"TOKEN_SCOPE_EXCLUDED"`
				}
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
					t.Fatalf("%s status=%d body=%s", endpoint, response.Code, response.Body.String())
				}
			}
			response := request(principalHandler, http.MethodPost, "/v1/spaces/"+spaceID+"/members", governance.AccessToken, fmt.Sprintf(`{"name":%q,"type":"human","binding_policy":"single"}`, "scope-parity-"+tc.name))
			if tc.allow {
				if response.Code != http.StatusOK {
					t.Fatalf("included management status=%d body=%s", response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"TOKEN_SCOPE_EXCLUDED"`) {
				t.Fatalf("excluded management status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
