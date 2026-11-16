package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestAuthorizationHTTPDefaultsResourceToSubjectSpace(t *testing.T) {
	ctx := context.Background()
	st, authz, publisher, publisherSpace, key, sessions := newServerFixture(t)
	customerSpace, customer, err := authz.CreateSpace(ctx, "usr_server_actor", "Customer", "default-resource-customer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE applications SET visibility = 'public', review_status = 'approved' WHERE id = 'app_server_test';
		UPDATE api_keys SET scopes = '["auth.authz:check", "auth.authz:explain"]'::jsonb WHERE name = 'server-test'
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_default_customer_install', $1, '["auth.applications:manage"]'::jsonb, $2, 'space', $1, $2);
	`, customerSpace.ID, customer.ID); err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	installation, err := apps.InstallSpace(ctx, customer.ID, "app_server_test", customerSpace.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE api_keys SET restrict_to = jsonb_build_array(jsonb_build_object('space_id', $1::text)) WHERE name = 'server-test'
	`, customerSpace.ID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, agentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: customer.ID, Name: "customer-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, customer.ID, customerSpace.ID, created.ID, []string{"self:read"}, "space", customerSpace.ID); err != nil {
		t.Fatal(err)
	}
	agentToken, err := sessions.CreateAgentAccess(ctx, created.ID, customerSpace.ID, "server-test-client")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := authz.CreateMember(ctx, customer.ID, "usr_server_actor", customerSpace.ID, "Selected customer identity", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_default_selected', $1, '["self:read"]'::jsonb, $2, 'space', $1, $3)
	`, customerSpace.ID, selected.ID, customer.ID); err != nil {
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
	userToken, err := sessions.Signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Applications: apps, Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("subject Space test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	request := func(path string, value any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/server/v1/"+path, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	for _, tc := range []struct {
		name, memberID string
		subject        CheckSubject
	}{
		{"agent_key", created.ID, CheckSubject{Token: agentKey}},
		{"agent_token", created.ID, CheckSubject{Token: agentToken.AccessToken}},
		{"selected_user_token", selected.ID, CheckSubject{Token: userToken}},
		{"asserted_agent", created.ID, CheckSubject{MemberID: created.ID}},
		{"asserted_user_member", selected.ID, CheckSubject{MemberID: selected.ID, UserID: "usr_server_actor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := CheckBody{Subject: tc.subject, Action: "self:read", Resource: CheckResource{Type: "member", ID: tc.memberID, OwnerMemberID: tc.memberID}}
			for _, path := range []string{"authz/check", "authz/explain", "authz/batch-check"} {
				var input any = body
				if path == "authz/batch-check" {
					input = map[string]any{"requests": []CheckBody{body}}
				}
				response := request(path, input)
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"decision":"allow"`) {
					t.Fatalf("%s defaulted to publisher instead of subject Space: status=%d body=%s", path, response.Code, response.Body.String())
				}
				version, err := authz.PolicyVersion(ctx, customerSpace.ID)
				if err != nil || !strings.Contains(response.Body.String(), `"policy_version":"`+strconv.FormatInt(version, 10)+`"`) {
					t.Fatalf("%s did not return the subject Space policy version", path)
				}
			}
		})
	}
	t.Run("denial_audit_uses_subject_location", func(t *testing.T) {
		body := CheckBody{Subject: CheckSubject{Token: agentKey}, Action: "missing:read", Resource: CheckResource{Type: "invoice", ID: "inv_default_space"}}
		for _, path := range []string{"authz/check", "authz/explain", "authz/batch-check"} {
			var input any = body
			if path == "authz/batch-check" {
				input = map[string]any{"requests": []CheckBody{body}}
			}
			response := request(path, input)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deny_code":"UNKNOWN_PERMISSION"`) {
				t.Fatalf("%s returned an inconsistent default-Space denial", path)
			}
			var correct bool
			if err := st.Pool.QueryRow(ctx, `SELECT space_id = $1 AND member_id = $2 AND request_id = $3
				FROM audit_logs WHERE request_id = $3 AND permission_key = 'missing:read'`, customerSpace.ID, created.ID, response.Header().Get("X-Request-ID")).Scan(&correct); err != nil || !correct {
				t.Fatalf("%s lost the resolved subject, resource location, or request identity in its audit: %v", path, err)
			}
		}
	})
	t.Run("invalid_subject_is_not_a_default_space", func(t *testing.T) {
		accountSession, err := sessions.Create(ctx, "usr_server_actor", nil, "test", 1)
		if err != nil {
			t.Fatal(err)
		}
		accountClaims, err := sessions.Signer.Verify(accountSession.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		accountClaims.Audience = "server-test-client"
		accountToken, err := sessions.Signer.Sign(accountClaims)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			subject CheckSubject
			status  int
			code    string
		}{
			{CheckSubject{Token: "invalid-token"}, http.StatusUnauthorized, "UNAUTHENTICATED"},
			{CheckSubject{Token: issued.AccessToken}, http.StatusUnauthorized, "UNAUTHENTICATED"},
			{CheckSubject{Token: accountToken}, http.StatusBadRequest, "VALIDATION_FAILED"},
			{CheckSubject{MemberID: selected.ID, UserID: "usr_not_bound"}, http.StatusNotFound, "SUBJECT_NOT_FOUND"},
		} {
			response := request("authz/check", CheckBody{Subject: tc.subject, Action: "self:read", Resource: CheckResource{Type: "member", ID: selected.ID}})
			if response.Code != tc.status || !strings.Contains(response.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("invalid subject selected a default Space: status=%d body=%s", response.Code, response.Body.String())
			}
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET allow_subject_assertion = false WHERE name = 'server-test'`); err != nil {
			t.Fatal(err)
		}
		response := request("authz/check", CheckBody{Subject: CheckSubject{MemberID: created.ID}, Action: "self:read", Resource: CheckResource{Type: "member", ID: created.ID}})
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"VALIDATION_FAILED"`) {
			t.Fatal("default Space resolution bypassed subject assertion opt-in")
		}
		if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET allow_subject_assertion = true WHERE name = 'server-test'`); err != nil {
			t.Fatal(err)
		}
	})
	base := CheckBody{Subject: CheckSubject{Token: agentKey}, Action: "self:read", Resource: CheckResource{Type: "member", ID: created.ID, OwnerMemberID: created.ID}}
	for _, tc := range []struct {
		name, code string
		apply      func(*testing.T)
	}{
		{"key_excludes_subject", "KEY_SCOPE_EXCLUDED", func(t *testing.T) {
			if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = jsonb_build_array(jsonb_build_object('space_id', $1::text)) WHERE name = 'server-test'`, publisherSpace); err != nil {
				t.Fatal(err)
			}
		}},
		{"uninstalled_subject", "APPLICATION_NOT_INSTALLED", func(t *testing.T) {
			if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE name = 'server-test'`); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE application_installations SET status = 'suspended' WHERE id = $1`, installation.ID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.apply(t)
			for _, path := range []string{"authz/check", "authz/explain", "authz/batch-check"} {
				var input any = base
				if path == "authz/batch-check" {
					input = map[string]any{"requests": []CheckBody{base}}
				}
				response := request(path, input)
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deny_code":"`+tc.code+`"`) {
					t.Fatalf("%s default Space bypassed application authority: status=%d body=%s", path, response.Code, response.Body.String())
				}
				var location string
				var unresolved bool
				if err := st.Pool.QueryRow(ctx, `SELECT space_id, member_id IS NULL AND user_id IS NULL FROM audit_logs WHERE request_id = $1`, response.Header().Get("X-Request-ID")).Scan(&location, &unresolved); err != nil || location != customerSpace.ID || !unresolved {
					t.Fatal("application-scope denial audit promoted the subject or used the publisher Space")
				}
			}
		})
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE application_installations SET status = 'active' WHERE id = $1`, installation.ID); err != nil {
		t.Fatal(err)
	}
	base.Resource.SpaceID = publisherSpace
	base.Resource.ID, base.Resource.OwnerMemberID = publisher.ID, publisher.ID
	if response := request("authz/check", base); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deny_code":"SCOPE_OUT_OF_BOUNDS"`) {
		t.Fatalf("explicit resource Space was overwritten: status=%d body=%s", response.Code, response.Body.String())
	}
}
