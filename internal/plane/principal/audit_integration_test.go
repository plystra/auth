package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func TestSpaceAuditHTTPFiltersScopeBeforeCursorPagination(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	root, err := authz.CreateGroup(ctx, owner.ID, spaceID, "Audit root", "")
	if err != nil {
		t.Fatal(err)
	}
	team, err := authz.CreateGroup(ctx, owner.ID, spaceID, "Audit team", root.ID)
	if err != nil {
		t.Fatal(err)
	}
	child, err := authz.CreateGroup(ctx, owner.ID, spaceID, "Audit child", team.ID)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := authz.CreateGroup(ctx, owner.ID, spaceID, "Audit sibling", root.ID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := authz.CreateMember(ctx, owner.ID, "usr_principal_actor", spaceID, "Audit reader", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	grantID := seedAuditGroupReader(t, st, spaceID, owner.ID, reader.ID, team.ID)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", reader.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	all := writeAuditFixtureEvents(t, st, owner.ID, spaceID, "req_scope_audit", "", root.ID, team.ID, child.ID, sibling.ID, team.ID)
	expected := []string{all[2], all[3], all[5]}
	sort.Sort(sort.Reverse(sort.StringSlice(expected)))
	handler := auditHTTPHandler(authz, sessions)
	path := "/v1/spaces/" + spaceID + "/audit-logs"
	var seen []string
	cursor := ""
	for page := 0; page < 4; page++ {
		response := getAuditHTTP(handler, tokens.AccessToken, path+"?limit=1&cursor="+url.QueryEscape(cursor))
		result := decodeAuditPage(t, response)
		if len(result.Body.Data) != 1 {
			t.Fatalf("page %d contains %d entries, want one authorized entry", page, len(result.Body.Data))
		}
		seen = append(seen, result.Body.Data[0].ID)
		if result.Body.NextCursor == "" {
			break
		}
		if page == 0 {
			// A concurrent insertion before the cursor must not repeat or move
			// already traversed events, even when original timestamps tie.
			writeAuditFixtureEvents(t, st, owner.ID, spaceID, "req_new_audit", team.ID)
		}
		cursor = result.Body.NextCursor
	}
	if !slices.Equal(seen, expected) {
		t.Fatalf("visible pages = %v, want %v", seen, expected)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: reader.ID, Name: "Group audit agent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedAuditGroupReader(t, st, spaceID, owner.ID, created.ID, team.ID)
	agentToken, err := sessions.CreateAgentDelegatedAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience, reader.ID, []string{"auth.audit:read"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	humanPage := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, path))
	agentPage := decodeAuditPage(t, getAuditHTTP(handler, agentToken.AccessToken, path))
	if !slices.EqualFunc(humanPage.Body.Data, agentPage.Body.Data, func(a, b audit.Event) bool { return a.ID == b.ID }) {
		t.Fatal("human and Agent readers with equivalent group authority saw different events")
	}
	if response := getAuditHTTP(handler, agentToken.AccessToken, path+"?group_id="+sibling.ID); response.Code != http.StatusForbidden {
		t.Fatalf("Agent read audit records outside its owner's group: %d", response.Code)
	}
	filtered := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, path+"?group_id="+child.ID))
	if len(filtered.Body.Data) != 1 || filtered.Body.Data[0].ID != all[3] {
		t.Fatalf("group filter returned unrelated records: %+v", filtered.Body.Data)
	}
	for _, tc := range []struct {
		query string
		code  int
	}{
		{"?group_id=" + sibling.ID, http.StatusForbidden},
		{"?cursor=" + base64.RawURLEncoding.EncodeToString([]byte(all[4])), http.StatusBadRequest},
		{"?cursor=invalid!", http.StatusBadRequest},
		{"?limit=101", http.StatusBadRequest},
		{"?group_id=grp_missing", http.StatusNotFound},
	} {
		if response := getAuditHTTP(handler, tokens.AccessToken, path+tc.query); response.Code != tc.code {
			t.Fatalf("query %s status=%d body=%s", tc.query, response.Code, response.Body.String())
		}
	}
	otherSpace, otherOwner, err := authz.CreateSpace(ctx, "usr_principal_actor", "Other audit Space", "other-audit-space")
	if err != nil {
		t.Fatal(err)
	}
	otherEvents := writeAuditFixtureEvents(t, st, otherOwner.ID, otherSpace.ID, "req_other_audit", "")
	if response := getAuditHTTP(handler, tokens.AccessToken, path+"?cursor="+base64.RawURLEncoding.EncodeToString([]byte(otherEvents[0]))); response.Code != http.StatusBadRequest {
		t.Fatalf("cross-Space cursor status=%d", response.Code)
	}
	if response := getAuditHTTP(handler, tokens.AccessToken, "/v1/spaces/"+otherSpace.ID+"/audit-logs"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-Space audit status=%d", response.Code)
	}
	if err := authz.RevokeGrant(ctx, owner.ID, spaceID, grantID); err != nil {
		t.Fatal(err)
	}
	if response := getAuditHTTP(handler, tokens.AccessToken, path+"?cursor="+cursor); response.Code != http.StatusForbidden {
		t.Fatalf("revoked audit grant retained cursor access: %d", response.Code)
	}
	assertAuditHTTPDenied(t, getAuditHTTP(handler, agentToken.AccessToken, path+"?group_id="+team.ID), "OWNER_ENVELOPE_EXCLUDED")
}

func TestSpaceAuditHTTPFailsClosedWhenStorageIsUnavailable(t *testing.T) {
	ctx := context.Background()
	st, _, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	writeAuditFixtureEvents(t, st, owner.ID, spaceID, "req_unavailable_audit", "")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, st.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	handler := auditHTTPHandler(&authorization.Service{Store: &store.Store{Pool: pool}}, sessions)
	response := getAuditHTTP(handler, tokens.AccessToken, "/v1/spaces/"+spaceID+"/audit-logs")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"UNAVAILABLE"`) {
		t.Fatalf("storage failure status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"data"`) || strings.Contains(response.Body.String(), "req_unavailable_audit") {
		t.Fatal("failed query returned audit records")
	}
}

func TestSpaceAuditHTTPEnforcesAgentOwnerCatalogAndTokenScope(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	reader, err := authz.CreateMember(ctx, owner.ID, "usr_principal_actor", spaceID, "Agent audit owner", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, reader.ID, "auth.audit:read")
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: reader.ID, Name: "Audit agent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGrants(ctx, reader.ID, spaceID, created.ID, []string{"auth.audit:read"}, "space", spaceID); err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateAgentDelegatedAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience, reader.ID, []string{"auth.audit:read"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := sessions.CreateAgentDelegatedAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience, reader.ID, []string{"self:read"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeAuditFixtureEvents(t, st, created.ID, spaceID, "req_agent_audit", "")
	handler := auditHTTPHandler(authz, sessions)
	path := "/v1/spaces/" + spaceID + "/audit-logs"
	if page := decodeAuditPage(t, getAuditHTTP(handler, issued.AccessToken, path+"?action=authz.check")); len(page.Body.Data) != 1 {
		t.Fatalf("Agent audit entries = %d, want 1", len(page.Body.Data))
	}
	assertAuditHTTPDenied(t, getAuditHTTP(handler, restricted.AccessToken, path), "TOKEN_SCOPE_EXCLUDED")
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.audit:read'`); err != nil {
		t.Fatal(err)
	}
	assertAuditHTTPDenied(t, getAuditHTTP(handler, issued.AccessToken, path), "PERMISSION_DISABLED")
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'active', principal_kinds = '["human"]'::jsonb WHERE key = 'auth.audit:read'`); err != nil {
		t.Fatal(err)
	}
	assertAuditHTTPDenied(t, getAuditHTTP(handler, issued.AccessToken, path), "PRINCIPAL_KIND_NOT_ALLOWED")
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human","agent"]'::jsonb WHERE key = 'auth.audit:read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, reader.ID); err != nil {
		t.Fatal(err)
	}
	assertAuditHTTPDenied(t, getAuditHTTP(handler, issued.AccessToken, path), "OWNER_ENVELOPE_EXCLUDED")
}

func TestSpaceAuditHTTPQueriesPersistedDelegationSnapshots(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, _ := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	parent, parentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "audit-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "audit-child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	ids := writeAuditFixtureEvents(t, st, child.ID, spaceID, "req_chain_audit", "")
	writeAuditFixtureEvents(t, st, owner.ID, spaceID, "req_unrelated_audit", "")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := auditHTTPHandler(authz, sessions)
	path := "/v1/spaces/" + spaceID + "/audit-logs"
	first := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, path+"?member_id="+parent.ID+"&action=authz.check"))
	if len(first.Body.Data) != 1 || first.Body.Data[0].ID != ids[0] {
		t.Fatalf("owner-chain filter returned %d records", len(first.Body.Data))
	}
	event := first.Body.Data[0]
	if event.MemberID != child.ID || event.Plane != "server" || event.ApplicationID != "app_audit_fixture" || len(event.OwnerChain) != 2 || event.OwnerChain[0].MemberID != parent.ID || event.OwnerChain[1].MemberID != owner.ID {
		t.Fatalf("incomplete audit snapshot: %+v", event)
	}
	if err := agents.Delete(ctx, owner.ID, parent.ID); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"?decision_id=" + event.DecisionID,
		"?request_id=req_chain_audit",
		"?member_id=" + child.ID + "&action=authz.check",
		"?member_id=" + parent.ID + "&action=authz.check",
	} {
		response := getAuditHTTP(handler, tokens.AccessToken, path+query)
		page := decodeAuditPage(t, response)
		if len(page.Body.Data) != 1 || page.Body.Data[0].ID != event.ID || !slices.Equal(page.Body.Data[0].OwnerChain, event.OwnerChain) {
			t.Fatalf("snapshot query %s lost tombstoned delegation context", query)
		}
		for _, secret := range []string{parentKey, childKey, tokens.AccessToken, tokens.RefreshToken} {
			if secret != "" && strings.Contains(response.Body.String(), secret) {
				t.Fatal("audit response exposed a credential")
			}
		}
	}
	empty := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, path+"?action=missing.action"))
	if len(empty.Body.Data) != 0 || empty.Body.NextCursor != "" {
		t.Fatal("empty audit result must have an empty list and no cursor")
	}
}

func auditHTTPHandler(authz *authorization.Service, sessions *session.Service) http.Handler {
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions}).Register(humago.New(mux, route.HumaConfig("audit HTTP test", "1.0.0")))
	return route.Middleware(route.Principal, mux)
}

func getAuditHTTP(handler http.Handler, token, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func decodeAuditPage(t *testing.T, response *httptest.ResponseRecorder) auditLogsOutput {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("audit query status=%d body=%s", response.Code, response.Body.String())
	}
	var out auditLogsOutput
	if err := json.Unmarshal(response.Body.Bytes(), &out.Body); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertAuditHTTPDenied(t *testing.T, response *httptest.ResponseRecorder, code string) {
	t.Helper()
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("audit denial status=%d body=%s, want %s", response.Code, response.Body.String(), code)
	}
}

func seedAuditGroupReader(t *testing.T, st *store.Store, spaceID, actorID, memberID, groupID string) string {
	t.Helper()
	id := string(ids.New[ids.GrantID]("grt"))
	if _, err := st.Pool.Exec(context.Background(), `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ($1, $2, '["auth.audit:read"]'::jsonb, $3, 'group_tree', $4, $5)`, id, spaceID, memberID, groupID, actorID); err != nil {
		t.Fatal(err)
	}
	return id
}

func writeAuditFixtureEvents(t *testing.T, st *store.Store, memberID, spaceID, requestID string, groupIDs ...string) []string {
	t.Helper()
	ctx := requestinfo.With(context.Background(), requestinfo.Info{ID: requestID, Plane: "server"})
	decisions := make([]string, len(groupIDs))
	if err := st.InTx(ctx, func(q *db.Queries) error {
		for i, groupID := range groupIDs {
			decisions[i] = string(ids.New[ids.ID]("dec"))
			if err := audit.WriteAuthorizationDecision(ctx, q, audit.AuthorizationDecision{
				KeyID: "key_audit_fixture", ApplicationID: "app_audit_fixture", MemberID: memberID,
				SpaceID: spaceID, GroupID: groupID, ResourceType: "invoice", ResourceID: "inv_audit",
				Permission: "invoice:read", Action: "authz.check", DecisionID: decisions[i],
				DenyCode: "NO_MATCHING_PERMISSION", PolicyVersion: 1,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result := make([]string, len(decisions))
	for i, decision := range decisions {
		if err := st.Pool.QueryRow(ctx, `SELECT id FROM audit_logs WHERE decision_id = $1`, decision).Scan(&result[i]); err != nil {
			t.Fatal(err)
		}
	}
	return result
}
