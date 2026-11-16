package server

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
	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestIntrospectionHTTPReturnsCurrentAgentAndHumanIdentity(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, agentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	for i, memberID := range []string{parent.ID, child.ID} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["self:read"]'::jsonb, $3, 'space', $2, $4)`, fmt.Sprintf("grt_introspection_%d", i), spaceID, memberID, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Agents: agents, Sessions: sessions}
	request := introspectionHTTP(t, api)
	wantChain := []agent.OwnerIdentity{
		{MemberID: parent.ID, MemberType: "agent", SpaceID: spaceID},
		{MemberID: owner.ID, MemberType: "human", SpaceID: spaceID},
	}
	issued, err := sessions.CreateAgentAccess(ctx, child.ID, spaceID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.Signer.Verify(issued.AccessToken, time.Now().UTC(), "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	// Even a signed act display claim is not the live ownership source.
	claims.Actor = &security.ActorClaim{Subject: "mem_stale_owner", MemberID: "mem_stale_owner", Type: "human"}
	jwt, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"native_key": agentKey, "access_token": jwt} {
		t.Run(name, func(t *testing.T) {
			identity := readIntrospection(t, request(key, token))
			if !identity.Active || identity.Subject != child.ID || identity.MemberID != child.ID || identity.MemberType != "agent" || identity.SpaceID != spaceID || identity.UserID != "" || identity.SessionID != "" || identity.ExpiresAt <= time.Now().Unix() {
				t.Fatalf("Agent identity = %+v", identity)
			}
			if diff := cmp.Diff(wantChain, identity.OwnerChain); diff != "" {
				t.Fatalf("owner chain (-want +got):\n%s", diff)
			}
		})
	}
	if got := readIntrospection(t, request(key, agentKey)).ExpiresAt; got != child.ExpiresAt.Unix() {
		t.Fatalf("native key expiry = %d, want %d", got, child.ExpiresAt.Unix())
	}
	claims.Audience = "foreign-app"
	foreign, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveIntrospection(t, request(key, foreign))
	claims.Audience, claims.ExpiresAt = "server-test-client", time.Now().Add(-time.Second).Unix()
	expired, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	assertInactiveIntrospection(t, request(key, expired))
	for _, selected := range []bool{false, true} {
		t.Run(fmt.Sprintf("human/selected=%t", selected), func(t *testing.T) {
			memberID := ""
			if selected {
				memberID = owner.ID
			}
			userSession, err := sessions.CreateForMember(ctx, "usr_server_actor", memberID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			userClaims, err := sessions.Signer.Verify(userSession.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
			if err != nil {
				t.Fatal(err)
			}
			userClaims.Audience = "server-test-client"
			userToken, err := sessions.Signer.Sign(userClaims)
			if err != nil {
				t.Fatal(err)
			}
			identity := readIntrospection(t, request(key, userToken))
			if !identity.Active || identity.Subject != "usr_server_actor" || identity.UserID != "usr_server_actor" || identity.SessionID != userSession.SessionID || identity.MemberID != memberID || len(identity.OwnerChain) != 0 {
				t.Fatalf("human identity = %+v", identity)
			}
			if selected && (identity.MemberType != "human" || identity.SpaceID != spaceID) || !selected && (identity.MemberType != "" || identity.SpaceID != "") {
				t.Fatalf("selected member facts = %+v", identity)
			}
		})
	}
	// Owner inactivity belongs to the shared authorization engine, not identity
	// introspection. The current relationship must still be reported accurately.
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	identity := readIntrospection(t, request(key, agentKey))
	if !identity.Active || cmp.Diff(wantChain, identity.OwnerChain) != "" {
		t.Fatalf("identity with inactive owner = %+v", identity)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: child.ID, Permission: "self:read", ResourceSpace: spaceID})
	if err != nil || decision.Code != "OWNER_INACTIVE" {
		t.Fatalf("authorization with inactive owner = %+v, %v", decision, err)
	}
}

func TestIntrospectionHTTPAgentLifecycleInvalidatesOnlyTargetSubtree(t *testing.T) {
	for _, operation := range []string{"stop", "delete", "expire"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			st, authz, owner, spaceID, key, sessions := newServerFixture(t)
			agents := &agent.Service{Store: st}
			var members []agent.Agent
			var credentials, tokens []string
			expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			for i, parent := range []int{-1, 0, -1} {
				ownerID := owner.ID
				if parent >= 0 {
					ownerID = members[parent].ID
				}
				created, credential, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: fmt.Sprintf("branch-%d", i), ExpiresAt: expiry})
				if err != nil {
					t.Fatal(err)
				}
				issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, "server-test-client")
				if err != nil {
					t.Fatal(err)
				}
				members, credentials, tokens = append(members, created), append(credentials, credential), append(tokens, issued.AccessToken)
			}
			api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Agents: agents, Sessions: sessions}
			request := introspectionHTTP(t, api)
			for _, token := range append(append([]string{}, credentials...), tokens...) {
				if !readIntrospection(t, request(key, token)).Active {
					t.Fatal("credential was inactive before lifecycle change")
				}
			}
			var err error
			switch operation {
			case "stop":
				err = agents.Stop(ctx, owner.ID, members[0].ID)
			case "delete":
				err = agents.Delete(ctx, owner.ID, members[0].ID)
			case "expire":
				_, err = st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, members[0].ID)
				if err == nil {
					_, err = agents.ExpireAgents(ctx)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for i := range members {
				for _, token := range []string{credentials[i], tokens[i]} {
					response := request(key, token)
					if i < 2 {
						assertInactiveIntrospection(t, response)
					} else if !readIntrospection(t, response).Active {
						t.Fatal("independent sibling lost its identity")
					}
				}
				_, err := sessions.CreateAgentAccess(ctx, members[i].ID, spaceID, "server-test-client")
				if i < 2 && err == nil || i == 2 && err != nil {
					t.Fatalf("exchange for branch %d after %s = %v", i, operation, err)
				}
			}
		})
	}
}

func TestIntrospectionHTTPIncludesApplicationOwnerIdentity(t *testing.T) {
	ctx := context.Background()
	st, authz, _, spaceID, key, sessions := newServerFixture(t)
	var ownerID string
	if err := st.Pool.QueryRow(ctx, `SELECT member_id FROM application_installations WHERE application_id = 'app_server_test'`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, credential, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "application-owned"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	request := introspectionHTTP(t, &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Agents: agents, Sessions: sessions})
	for _, token := range []string{credential, issued.AccessToken} {
		identity := readIntrospection(t, request(key, token))
		want := []agent.OwnerIdentity{{MemberID: ownerID, MemberType: "application", SpaceID: spaceID}}
		if !identity.Active || cmp.Diff(want, identity.OwnerChain) != "" {
			t.Fatalf("application owner identity = %+v", identity)
		}
	}
}

func TestIntrospectionHTTPEnforcesKeyScopeAndLiveInstallationForAllAgentCredentials(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	agents := &agent.Service{Store: st}
	created, agentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "installed-agent"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	request := introspectionHTTP(t, &API{Applications: apps, Authorization: authz, Agents: agents, Sessions: sessions})
	assertActive := func(want bool) {
		t.Helper()
		for _, token := range []string{agentKey, issued.AccessToken} {
			response := request(key, token)
			if !want {
				assertInactiveIntrospection(t, response)
			} else if !readIntrospection(t, response).Active {
				t.Fatal("installed and scoped Agent credential was inactive")
			}
		}
	}
	assertActive(true)
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id IN (SELECT member_id FROM application_installations WHERE application_id = 'app_server_test')`); err != nil {
		t.Fatal(err)
	}
	assertActive(false)
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = NULL
		WHERE grantee_member_id IN (SELECT member_id FROM application_installations WHERE application_id = 'app_server_test')`); err != nil {
		t.Fatal(err)
	}
	assertActive(true)
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.tokens:introspect'`); err != nil {
		t.Fatal(err)
	}
	assertActive(false)
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'active' WHERE key = 'auth.tokens:introspect'`); err != nil {
		t.Fatal(err)
	}
	assertActive(true)
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[{"space_id":"spc_other","include_descendants":false}]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	assertActive(false)
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	assertActive(true)
	other, otherOwner, err := authz.CreateSpace(ctx, "usr_server_actor", "uninstalled", "uninstalled")
	if err != nil {
		t.Fatal(err)
	}
	foreign, foreignKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: otherOwner.ID, Name: "foreign"})
	if err != nil {
		t.Fatal(err)
	}
	foreignJWT, err := sessions.CreateAgentAccess(ctx, foreign.ID, other.ID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{foreignKey, foreignJWT.AccessToken} {
		assertInactiveIntrospection(t, request(key, token))
	}
	var installationID string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM application_installations WHERE application_id = 'app_server_test' AND space_id = $1`, spaceID).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"suspend", "resume", "uninstall"} {
		if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, installationID, action); err != nil {
			t.Fatal(err)
		}
		assertActive(action == "resume")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET scopes = '["auth.authz:check"]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	response := request(key, agentKey)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"PERMISSION_DENIED"`) {
		t.Fatalf("caller scope = %d %s", response.Code, response.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at = now() WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	if response := request(key, agentKey); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked caller key status = %d", response.Code)
	}
}

func TestIntrospectionHTTPRejectsInvalidExpiredAndRevokedAgentKeys(t *testing.T) {
	for _, invalidation := range []string{"invalid_secret", "key_expired", "key_revoked", "agent_expired", "home_group_suspended"} {
		t.Run(invalidation, func(t *testing.T) {
			ctx := context.Background()
			st, authz, owner, _, key, sessions := newServerFixture(t)
			agents := &agent.Service{Store: st}
			created, credential, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "test-agent"})
			if err != nil {
				t.Fatal(err)
			}
			request := introspectionHTTP(t, &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Agents: agents, Sessions: sessions})
			if !readIntrospection(t, request(key, credential)).Active {
				t.Fatal("new credential was inactive")
			}
			switch invalidation {
			case "invalid_secret":
				credential = strings.SplitN(credential, ".", 2)[0] + ".invalid"
			case "key_expired":
				_, err = st.Pool.Exec(ctx, `UPDATE agent_credentials SET expires_at = now() - interval '1 second' WHERE member_id = $1`, created.ID)
			case "key_revoked":
				_, err = st.Pool.Exec(ctx, `UPDATE agent_credentials SET revoked_at = now() WHERE member_id = $1`, created.ID)
			case "agent_expired":
				_, err = st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, created.ID)
			case "home_group_suspended":
				_, err = st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, created.HomeGroupID)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertInactiveIntrospection(t, request(key, credential))
			for _, malformed := range []string{"ply_ag_unknown.invalid", "ply_ag_invalid", "ply_rt_unknown.invalid"} {
				assertInactiveIntrospection(t, request(key, malformed))
			}
		})
	}
}

func TestIntrospectionHTTPStorageFailureReturnsUnavailableWithoutIdentity(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	agents := &agent.Service{Store: st}
	created, credential, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "test-agent"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	closed, err := store.Open(ctx, st.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	request := introspectionHTTP(t, &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Agents: &agent.Service{Store: closed}, Sessions: sessions})
	for _, token := range []string{credential, issued.AccessToken} {
		response := request(key, token)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"UNAVAILABLE"`) || strings.Contains(response.Body.String(), created.ID) || strings.Contains(response.Body.String(), "closed pool") {
			t.Fatalf("storage failure = %d %s", response.Code, response.Body.String())
		}
	}
}

func introspectionHTTP(t *testing.T, api *API) func(string, string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("introspection test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	return func(key, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/server/v1/tokens/introspect", strings.NewReader(fmt.Sprintf(`{"token":%q}`, token)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), key) || strings.Contains(w.Body.String(), "secret_hash") {
			t.Fatal("introspection response leaked credential material")
		}
		return w
	}
}

func readIntrospection(t *testing.T, response *httptest.ResponseRecorder) IntrospectIdentity {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("introspection = %d %s", response.Code, response.Body.String())
	}
	var out IntrospectOutput
	if err := json.Unmarshal(response.Body.Bytes(), &out.Body); err != nil {
		t.Fatal(err)
	}
	return out.Body.Data
}

func assertInactiveIntrospection(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	identity := readIntrospection(t, response)
	if diff := cmp.Diff(IntrospectIdentity{}, identity); diff != "" {
		t.Fatalf("inactive identity (-want +got):\n%s", diff)
	}
	var out map[string]map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out["data"]) != 1 || string(out["data"]["active"]) != "false" {
		t.Fatalf("inactive response contains extra facts: %s", response.Body.String())
	}
}
