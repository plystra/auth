package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/security"
)

func runOAuthAgentDelegationScenario(t *testing.T, scenario mvpDelegationScenario, refresh string, parent agent.Agent, rootGroupID string) string {
	t.Helper()
	parentID := parent.ID
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {scenario.ClientID}, "refresh_token": {refresh},
		"resource": {security.DefaultApplicationAudience}, "scope": {"auth.agents:create invoice:read"}}
	response := mvpToken(t, scenario.Principal, refreshForm)
	var governance struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &governance) != nil ||
		governance.AccessToken == "" || governance.RefreshToken == "" || governance.RefreshToken == refresh ||
		governance.Scope != "auth.agents:create invoice:read" {
		t.Fatalf("OAuth parent could not obtain an explicit governance credential: status=%d", response.Code)
	}
	claims, err := scenario.Signer.Verify(governance.AccessToken, time.Now(), security.DefaultApplicationAudience)
	if err != nil || claims.Subject != parentID || !slices.Equal(claims.Scopes, []string{"auth.agents:create", "invoice:read"}) {
		t.Fatal("governance refresh changed the consenting OAuth identity or its scope")
	}
	if denied := mvpJSON(t, scenario.Principal, http.MethodPost, "/v1/me/agents", scenario.ControlToken,
		map[string]string{"name": "wrong audience", "source": "delegation"}); denied.Code != http.StatusUnauthorized {
		t.Fatal("SaaS parent JWT authenticated to the Auth management surface")
	}
	for _, surface := range []http.Handler{scenario.Server, scenario.Observer} {
		result := mvpData[struct{ Active bool }](t, mvpJSON(t, surface, http.MethodPost,
			"/server/v1/tokens/introspect", scenario.ServerKey, map[string]string{"token": governance.AccessToken}))
		if result.Active {
			t.Fatal("Auth governance token authenticated to the SaaS")
		}
	}
	spacePath := "/v1/spaces/" + scenario.SpaceID
	project := mvpData[authorization.Group](t, mvpJSON(t, scenario.Principal, http.MethodPost, spacePath+"/groups", scenario.UserToken,
		map[string]string{"name": "OAuth delegated invoices", "parent_group_id": rootGroupID}))
	type createdAgent struct {
		Agent agent.Agent `json:"agent"`
		Key   string      `json:"agent_key"`
	}
	child := mvpData[createdAgent](t, mvpJSON(t, scenario.Principal, http.MethodPost, "/v1/me/agents", governance.AccessToken,
		map[string]any{"name": "OAuth invoice reader", "source": "delegation", "expires_at": time.Now().UTC().Add(time.Hour)}))
	if child.Key == "" || child.Agent.OwnerMemberID != parentID || child.Agent.Source != "delegation" || child.Agent.ExpiresAt.After(parent.ExpiresAt) {
		t.Fatal("public child creation omitted its credential or persisted owner")
	}
	// The OAuth parent has no auth.grants:assign grant: this exercises the
	// documented direct-owner system assignment right through public HTTP.
	grant := mvpData[authorization.Grant](t, mvpJSON(t, scenario.Principal, http.MethodPut,
		"/v1/me/agents/"+child.Agent.ID+"/grants", governance.AccessToken,
		map[string]any{"permissions": []string{"invoice:read"}, "scope": "group_tree", "anchor_group_id": project.ID}))
	if grant.Scope != "group_tree" || grant.AnchorGroupID != project.ID || !slices.Equal(grant.Permissions, []string{"invoice:read"}) {
		t.Fatal("public OAuth delegation changed the selected resource boundary")
	}
	denied := mvpJSON(t, scenario.Principal, http.MethodPut, "/v1/me/agents/"+child.Agent.ID+"/grants", governance.AccessToken,
		map[string]any{"permissions": []string{"invoice:approve"}, "scope": "group_tree", "anchor_group_id": project.ID})
	if denied.Code != http.StatusForbidden {
		t.Fatal("OAuth parent delegated an approval-required permission to a child")
	}
	exchange := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {scenario.ControlToken}, "actor_token": {child.Key}, "resource": {scenario.ClientID}, "scope": {"invoice:read"}}
	response = mvpToken(t, scenario.Principal, exchange)
	var delegated struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &delegated) != nil || delegated.AccessToken == "" || delegated.Scope != "invoice:read" {
		t.Fatalf("SaaS parent could not exchange the delegated child identity: status=%d", response.Code)
	}
	childClaims, err := scenario.Signer.Verify(delegated.AccessToken, time.Now(), scenario.ClientID)
	if err != nil || childClaims.Subject != child.Agent.ID || !slices.Equal(childClaims.Scopes, []string{"invoice:read"}) ||
		childClaims.Actor == nil || childClaims.Actor.Subject != parentID || childClaims.Actor.Actor == nil ||
		childClaims.Actor.Actor.Subject != scenario.UserMemberID || childClaims.Actor.Actor.Actor != nil {
		t.Fatal("OAuth child token lost its narrowed scope or complete ownership chain")
	}
	check := func(surface http.Handler, path, group string) server.ExplainDecision {
		t.Helper()
		return mvpData[server.ExplainDecision](t, mvpJSON(t, surface, http.MethodPost, "/server/v1/authz/"+path, scenario.ServerKey,
			map[string]any{"subject": map[string]string{"token": delegated.AccessToken}, "action": "invoice:read",
				"resource": map[string]string{"type": "invoice", "id": "inv_oauth_child", "space_id": scenario.SpaceID, "group_id": group}}))
	}
	for _, surface := range []http.Handler{scenario.Server, scenario.Observer} {
		if result := check(surface, "check", project.ID); result.Decision != "allow" {
			t.Fatalf("OAuth child could not read its delegated project: %s", result.DenyCode)
		}
		if result := check(surface, "check", ""); result.Decision != "deny" || result.DenyCode != "SCOPE_OUT_OF_BOUNDS" {
			t.Fatal("group-scoped OAuth child could read the whole Space")
		}
		if result := check(surface, "explain", project.ID); result.Decision != "allow" || len(result.Trace) == 0 {
			t.Fatal("OAuth child explanation did not match the allowed decision")
		}
	}
	query := url.Values{"action": {"agent.token.exchange"}, "member_id": {parentID}}.Encode()
	events := mvpData[[]audit.Event](t, mvpJSON(t, scenario.Principal, http.MethodGet, spacePath+"/audit-logs?"+query, scenario.UserToken, nil))
	if len(events) != 1 || events[0].MemberID != child.Agent.ID || events[0].ActorID != parentID || events[0].ResourceGroupID != child.Agent.HomeGroupID ||
		len(events[0].OwnerChain) != 2 || events[0].OwnerChain[0].MemberID != parentID || events[0].OwnerChain[1].MemberID != scenario.UserMemberID {
		t.Fatal("public OAuth delegation audit lost its actor, child, location, or owner chain")
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{child.Key, delegated.AccessToken, governance.AccessToken, governance.RefreshToken, refresh, scenario.ControlToken} {
		if strings.Contains(string(encoded), credential) {
			t.Fatal("public OAuth delegation audit exposed a credential")
		}
	}
	mvpData[struct{ Accepted bool }](t, mvpJSON(t, scenario.Principal, http.MethodPost,
		"/v1/me/agents/"+child.Agent.ID+"/stop", governance.AccessToken, nil))
	for _, surface := range []http.Handler{scenario.Server, scenario.Observer} {
		identity := mvpData[struct{ Active bool }](t, mvpJSON(t, surface, http.MethodPost,
			"/server/v1/tokens/introspect", scenario.ServerKey, map[string]string{"token": delegated.AccessToken}))
		if identity.Active {
			t.Fatal("stopped OAuth descendant retained an active identity across instances")
		}
	}
	if response := mvpToken(t, scenario.Principal, exchange); response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_grant") {
		t.Fatal("stopped OAuth descendant exchanged another token")
	}
	return governance.RefreshToken
}
