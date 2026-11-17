package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type mvpDelegationScenario struct {
	Principal, Server, Observer                                         http.Handler
	Signer                                                              *security.Signer
	UserToken, UserMemberID, SpaceID, ClientID, ServerKey, ControlToken string
	MFACode                                                             func() string
	BusinessDatabaseURL                                                 string
}

func newMVPObserver(t *testing.T, databaseURL string, signer *security.Signer, hmacKey []byte, settings func(context.Context) (session.Settings, error)) http.Handler {
	t.Helper()
	st, err := store.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	authz := &authorization.Service{Store: st}
	mux := http.NewServeMux()
	(&server.API{
		Applications:  &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{hmacKey}},
		Authorization: authz, Sessions: &session.Service{Store: st, Signer: signer, Settings: settings, HMACKeys: [][]byte{hmacKey}},
		Agents: &agent.Service{Store: st, HMACKeys: [][]byte{hmacKey}},
	}).Register(humago.New(mux, route.HumaConfig("MVP independent observer", "1.0.0")))
	return route.Middleware(route.Server, mux)
}

func mvpJSON(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code >= http.StatusBadRequest {
		t.Logf("MVP %s %s returned status=%d", method, path, response.Code)
	}
	return response
}

func mvpData[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var result struct {
		Data  T                     `json:"data"`
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid MVP JSON response (status %d)", response.Code)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("MVP request failed: status=%d code=%s", response.Code, result.Error.Code)
	}
	return result.Data
}

func mvpToken(t *testing.T, handler http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func runNativeAgentDelegationScenario(t *testing.T, scenario mvpDelegationScenario) string {
	t.Helper()
	principal := func(method, path, token string, body any) *httptest.ResponseRecorder {
		return mvpJSON(t, scenario.Principal, method, path, token, body)
	}
	spacePath := "/v1/spaces/" + scenario.SpaceID
	mvpData[authorization.Grant](t, principal(http.MethodPost, spacePath+"/grants", scenario.UserToken, map[string]any{
		"grantee": map[string]string{"member_id": scenario.UserMemberID}, "permissions": []string{"auth.agents:create"},
		"scope": "space", "anchor_space_id": scenario.SpaceID,
	}))
	root := mvpData[authorization.Group](t, principal(http.MethodPost, spacePath+"/groups", scenario.UserToken, map[string]string{"name": "Projects"}))
	project := mvpData[authorization.Group](t, principal(http.MethodPost, spacePath+"/groups", scenario.UserToken, map[string]string{"name": "Invoice project", "parent_group_id": root.ID}))
	otherProject := mvpData[authorization.Group](t, principal(http.MethodPost, spacePath+"/groups", scenario.UserToken, map[string]string{"name": "Other project", "parent_group_id": root.ID}))
	parentExpiry := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	create := map[string]any{"name": "invoice-parent", "expires_at": parentExpiry, "source": "manual"}
	mvpData[json.RawMessage](t, principal(http.MethodPost, "/v1/auth/step-up", scenario.UserToken, map[string]any{
		"mfa_code": scenario.MFACode(), "operation": "me.agents.create", "request": create,
	}))
	type createdAgent struct {
		Agent agent.Agent `json:"agent"`
		Key   string      `json:"agent_key"`
	}
	parent := mvpData[createdAgent](t, principal(http.MethodPost, "/v1/me/agents", scenario.UserToken, create))
	role := mvpData[authorization.Role](t, principal(http.MethodPost, spacePath+"/roles", scenario.UserToken, map[string]any{
		"name": "Agent delegator", "permissions": []string{"auth.agents:create", "self:read"},
	}))
	mvpData[authorization.Grant](t, principal(http.MethodPost, spacePath+"/grants", scenario.UserToken, map[string]any{
		"grantee": map[string]string{"member_id": parent.Agent.ID}, "role_id": role.ID, "scope": "space", "anchor_space_id": scenario.SpaceID,
	}))
	replace := func(actor, target, scope string, permissions []string) authorization.Grant {
		t.Helper()
		return mvpData[authorization.Grant](t, principal(http.MethodPut, "/v1/me/agents/"+target+"/grants", actor, map[string]any{
			"permissions": permissions, "scope": scope, "anchor_group_id": project.ID,
		}))
	}
	mvpData[authorization.Grant](t, principal(http.MethodPost, spacePath+"/grants", scenario.UserToken, map[string]any{
		"grantee": map[string]string{"member_id": parent.Agent.ID}, "permissions": []string{"invoice:read", "invoice:approve"},
		"scope": "group_tree", "anchor_group_id": project.ID,
	}))
	var parentToken struct {
		AccessToken string `json:"access_token"`
	}
	response := mvpToken(t, scenario.Principal, url.Values{"grant_type": {"agent_key"}, "agent_key": {parent.Key}, "resource": {security.DefaultApplicationAudience}})
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &parentToken) != nil || parentToken.AccessToken == "" {
		t.Fatal("native parent credential could not obtain its Auth access token")
	}
	child := mvpData[createdAgent](t, principal(http.MethodPost, "/v1/me/agents", parentToken.AccessToken, map[string]any{
		"name": "invoice-reader", "source": "delegation", "expires_at": parentExpiry.Add(-time.Minute),
	}))
	replace(parentToken.AccessToken, child.Agent.ID, "group", []string{"invoice:read"})
	for _, permission := range []string{"invoice:approve", "auth.bindings:manage"} {
		denied := principal(http.MethodPut, "/v1/me/agents/"+child.Agent.ID+"/grants", parentToken.AccessToken, map[string]any{
			"permissions": []string{permission}, "scope": "group", "anchor_group_id": project.ID,
		})
		if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
			t.Fatalf("unsafe child delegation was not rejected: status=%d", denied.Code)
		}
	}
	exchange := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {parentToken.AccessToken},
		"actor_token": {child.Key}, "scope": {"invoice:read"}, "resource": {scenario.ClientID},
	}
	response = mvpToken(t, scenario.Principal, exchange)
	var childToken struct {
		AccessToken string `json:"access_token"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &childToken) != nil || childToken.AccessToken == "" {
		t.Fatalf("group-scoped native delegation could not exchange a child token: status=%d", response.Code)
	}
	claims, err := scenario.Signer.Verify(childToken.AccessToken, time.Now().UTC(), scenario.ClientID)
	if err != nil || claims.Subject != child.Agent.ID || !slices.Equal(claims.Scopes, []string{"invoice:read"}) ||
		claims.Actor == nil || claims.Actor.Subject != parent.Agent.ID || claims.Actor.Actor == nil || claims.Actor.Actor.Subject != scenario.UserMemberID {
		t.Fatal("child token did not preserve its identity, narrowed scope and full delegation chain")
	}
	if _, err := scenario.Signer.Verify(childToken.AccessToken, time.Unix(claims.ExpiresAt, 0), scenario.ClientID); err == nil {
		t.Fatal("offline verification accepted the delegated token at its expiry boundary")
	}
	check := func(handler http.Handler, path, token, group string) server.ExplainDecision {
		t.Helper()
		response := mvpJSON(t, handler, http.MethodPost, "/server/v1/authz/"+path, scenario.ServerKey, map[string]any{
			"subject": map[string]string{"token": token}, "action": "invoice:read",
			"resource": map[string]string{"type": "invoice", "id": "inv_delegated", "space_id": scenario.SpaceID, "group_id": group},
		})
		return mvpData[server.ExplainDecision](t, response)
	}
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		if result := check(handler, "check", childToken.AccessToken, project.ID); result.Decision != "allow" {
			t.Fatalf("delegated project operation was not allowed: %s", result.DenyCode)
		}
		if result := check(handler, "check", childToken.AccessToken, otherProject.ID); result.DenyCode != "SCOPE_OUT_OF_BOUNDS" {
			t.Fatalf("delegated operation escaped its resource group: %s", result.DenyCode)
		}
	}
	assertSaaSRevoked := runInvoiceSaaSScenario(t, scenario, project.ID, otherProject.ID, parent.Agent.ID, parent.Key, childToken.AccessToken)
	// Remove only the native parent's business grant; its named governance
	// role remains so it can still revoke the child through the normal API.
	replace(scenario.UserToken, parent.Agent.ID, "group_tree", []string{"invoice:approve"})
	assertSaaSRevoked()
	var deniedDecisions []string
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		for _, path := range []string{"check", "explain"} {
			result := check(handler, path, childToken.AccessToken, project.ID)
			if result.Decision != "deny" || result.DenyCode != "OWNER_ENVELOPE_EXCLUDED" || result.DecisionID == "" {
				t.Fatalf("parent narrowing did not invalidate child %s: %s", path, result.DenyCode)
			}
			deniedDecisions = append(deniedDecisions, result.DecisionID)
		}
	}
	if _, err := scenario.Signer.Verify(childToken.AccessToken, time.Now().UTC(), scenario.ClientID); err != nil {
		t.Fatal("online revocation should precede the existing JWT's offline expiry")
	}
	mvpData[authorization.Grant](t, principal(http.MethodPost, spacePath+"/grants", scenario.UserToken, map[string]any{
		"grantee": map[string]string{"group_id": project.ID}, "permissions": []string{"invoice:read"},
		"scope": "group_tree", "anchor_group_id": project.ID,
	}))
	membershipPath := spacePath + "/groups/" + project.ID + "/members/" + parent.Agent.ID
	mvpData[json.RawMessage](t, principal(http.MethodPut, membershipPath, scenario.UserToken, nil))
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		if result := check(handler, "check", childToken.AccessToken, project.ID); result.Decision != "allow" {
			t.Fatalf("group membership did not restore the parent's delegated authority: %s", result.DenyCode)
		}
	}
	mvpData[json.RawMessage](t, principal(http.MethodDelete, membershipPath, scenario.UserToken, nil))
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		result := check(handler, "explain", childToken.AccessToken, project.ID)
		if result.Decision != "deny" || result.DenyCode != "OWNER_ENVELOPE_EXCLUDED" || result.DecisionID == "" {
			t.Fatalf("group removal did not revoke the existing delegated token: %s", result.DenyCode)
		}
		deniedDecisions = append(deniedDecisions, result.DecisionID)
	}
	restoredGrant := mvpData[authorization.Grant](t, principal(http.MethodPost, spacePath+"/grants", scenario.UserToken, map[string]any{
		"grantee": map[string]string{"member_id": parent.Agent.ID}, "permissions": []string{"invoice:read"},
		"scope": "group_tree", "anchor_group_id": project.ID,
	}))
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		if result := check(handler, "check", childToken.AccessToken, project.ID); result.Decision != "allow" {
			t.Fatalf("new member grant did not restore delegated authority: %s", result.DenyCode)
		}
	}
	listGrants := func() []authorization.Grant {
		t.Helper()
		var result []authorization.Grant
		cursor := ""
		for range 100 {
			response := principal(http.MethodGet, spacePath+"/grants?limit=2&cursor="+url.QueryEscape(cursor), scenario.UserToken, nil)
			var page struct {
				Data       []authorization.Grant `json:"data"`
				NextCursor string                `json:"next_cursor"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Data == nil {
				t.Fatalf("public grant listing failed: status=%d body=%s", response.Code, response.Body.String())
			}
			result = append(result, page.Data...)
			if page.NextCursor == "" {
				return result
			}
			if page.NextCursor == cursor {
				t.Fatal("public grant cursor did not advance")
			}
			cursor = page.NextCursor
		}
		t.Fatal("public grant traversal did not terminate")
		return nil
	}
	configured := listGrants()
	grantPosition := slices.IndexFunc(configured, func(grant authorization.Grant) bool {
		return grant.ID == restoredGrant.ID && grant.GranteeMemberID == parent.Agent.ID && grant.AnchorGroupID == project.ID && slices.Equal(grant.Permissions, []string{"invoice:read"})
	})
	if grantPosition < 0 {
		t.Fatal("public grant listing could not discover the parent's revocable grant")
	}
	listedGrant := configured[grantPosition]
	for range 2 {
		mvpData[json.RawMessage](t, principal(http.MethodDelete, spacePath+"/grants/"+listedGrant.ID, scenario.UserToken, nil))
	}
	if slices.ContainsFunc(listGrants(), func(grant authorization.Grant) bool { return grant.ID == listedGrant.ID }) {
		t.Fatal("revoked grant remained in the public configuration list")
	}
	for _, handler := range []http.Handler{scenario.Server, scenario.Observer} {
		result := check(handler, "explain", childToken.AccessToken, project.ID)
		if result.Decision != "deny" || result.DenyCode != "OWNER_ENVELOPE_EXCLUDED" || result.DecisionID == "" {
			t.Fatalf("direct grant revocation did not invalidate the delegated token: %s", result.DenyCode)
		}
		deniedDecisions = append(deniedDecisions, result.DecisionID)
	}
	mvpData[json.RawMessage](t, principal(http.MethodPost, "/v1/me/agents/"+parent.Agent.ID+"/stop", scenario.UserToken, nil))
	for _, credential := range []string{parent.Key, child.Key, childToken.AccessToken} {
		identity := mvpData[server.IntrospectIdentity](t, mvpJSON(t, scenario.Observer, http.MethodPost, "/server/v1/tokens/introspect", scenario.ServerKey, map[string]string{"token": credential}))
		if identity.Active || identity.MemberID != "" || len(identity.OwnerChain) != 0 {
			t.Fatal("stopped delegation tree remained introspectable")
		}
	}
	for _, credential := range []string{parent.Key, child.Key} {
		if denied := mvpToken(t, scenario.Principal, url.Values{"grant_type": {"agent_key"}, "agent_key": {credential}}); denied.Code == http.StatusOK {
			t.Fatal("stopped delegation tree could still exchange an Agent key")
		}
	}
	if denied := mvpToken(t, scenario.Principal, exchange); denied.Code == http.StatusOK {
		t.Fatal("stopped delegation tree could still perform Token Exchange")
	}
	if result := check(scenario.Observer, "check", scenario.ControlToken, project.ID); result.Decision != "allow" {
		t.Fatal("native subtree revocation affected the independent OAuth Agent")
	}
	events := mvpData[[]audit.Event](t, principal(http.MethodGet, spacePath+"/audit-logs?member_id="+parent.Agent.ID+"&limit=100", scenario.UserToken, nil))
	seen := map[string]bool{}
	revocationEvents := 0
	for _, event := range events {
		seen[event.Action] = true
		seen[event.MemberID+":"+event.Action] = true
		if event.Action == "grant.revoke" && event.ResourceID == restoredGrant.ID {
			revocationEvents++
			if event.MemberID != parent.Agent.ID || event.ActorID != scenario.UserMemberID || event.SpaceID != scenario.SpaceID {
				t.Fatal("direct grant revocation audit omitted the affected parent or actor")
			}
		}
		if event.MemberID == child.Agent.ID && (len(event.OwnerChain) != 2 || event.OwnerChain[0].MemberID != parent.Agent.ID || event.OwnerChain[1].MemberID != scenario.UserMemberID) {
			t.Fatal("public child audit omitted its complete delegation chain")
		}
		if event.DecisionID != "" {
			deniedDecisions = slices.DeleteFunc(deniedDecisions, func(id string) bool { return id == event.DecisionID })
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		for _, credential := range []string{parent.Key, child.Key, parentToken.AccessToken, childToken.AccessToken, scenario.ServerKey, scenario.UserToken} {
			if credential == "" || bytes.Contains(encoded, []byte(credential)) {
				t.Fatal("public delegation audit contained a credential or fixture omitted one")
			}
		}
	}
	for _, action := range []string{"agent.create", "grant.replace", "grant.inline.create", "grant.revoke", "group.member.add", "group.member.remove", "agent.stop", "authz.check", "authz.explain"} {
		if !seen[action] {
			t.Fatalf("public delegation audit omitted %s", action)
		}
	}
	for _, memberID := range []string{parent.Agent.ID, child.Agent.ID} {
		for _, action := range []string{"agent.create", "grant.replace"} {
			if !seen[memberID+":"+action] {
				t.Fatalf("public delegation audit omitted %s for %s", action, memberID)
			}
		}
	}
	if len(deniedDecisions) != 0 {
		t.Fatal("public audit could not correlate every revoked check and explanation")
	}
	if revocationEvents != 1 {
		t.Fatalf("repeated direct revocation produced %d audit events, want one", revocationEvents)
	}
	return root.ID
}
