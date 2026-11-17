package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
)

func groupInstallationHTTP(t *testing.T, handler http.Handler, key, method, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func TestServerGroupInstallationScopesAcrossInstances(t *testing.T) {
	for _, scope := range []string{"group", "group_tree"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			st, authz, owner, spaceID, key, sessions := newServerFixture(t)
			apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
			var previous string
			if err := st.Pool.QueryRow(ctx, `SELECT id FROM application_installations WHERE application_id = 'app_server_test'`).Scan(&previous); err != nil {
				t.Fatal(err)
			}
			if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, previous, "uninstall"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id)
				VALUES ('grp_server_root', $1, 'Root', NULL), ('grp_server_install', $1, 'Install', 'grp_server_root'),
				('grp_server_child', $1, 'Child', 'grp_server_install'), ('grp_server_outside', $1, 'Outside', 'grp_server_root')`, spaceID); err != nil {
				t.Fatal(err)
			}
			manifest := []string{"auth.audit:write", "auth.authz:check", "auth.authz:explain", "auth.tokens:introspect"}
			if _, err := apps.Update(ctx, owner.ID, "app_server_test", application.UpdateInput{ManifestPermissions: &manifest}); err != nil {
				t.Fatal(err)
			}
			installed, err := apps.Install(ctx, owner.ID, "app_server_test", spaceID, scope, "grp_server_install")
			if err != nil {
				t.Fatal(err)
			}
			var keyID string
			if err := st.Pool.QueryRow(ctx, `SELECT id FROM api_keys WHERE name = 'server-test'`).Scan(&keyID); err != nil {
				t.Fatal(err)
			}
			if _, err := apps.UpdateManagedKeyGrants(ctx, owner.ID, "app_server_test", keyID, manifest); err != nil {
				t.Fatal(err)
			}
			agents := &agent.Service{Store: st}
			created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "group-introspection"})
			if err != nil {
				t.Fatal(err)
			}
			issued, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, "server-test-client")
			if err != nil {
				t.Fatal(err)
			}
			var handlers []http.Handler
			for range 2 {
				mux := http.NewServeMux()
				(&API{Applications: apps, Authorization: &authorization.Service{Store: st}, Sessions: sessions, Agents: agents,
					Approvals: &approval.Service{Store: st, Authorization: authz}}).Register(humago.New(mux, route.HumaConfig("group installation", "1.0.0")))
				handlers = append(handlers, route.Middleware(route.Server, mux))
			}
			body := func(groupID string) CheckBody {
				return CheckBody{Subject: CheckSubject{MemberID: owner.ID}, Action: "self:read",
					Resource: CheckResource{Type: "invoice", ID: "inv_group", SpaceID: spaceID, GroupID: groupID}}
			}
			check := func(groupID, want string) {
				t.Helper()
				for _, handler := range handlers {
					for _, endpoint := range []string{"check", "explain", "batch-check"} {
						var input any = body(groupID)
						if endpoint == "batch-check" {
							input = map[string]any{"requests": []CheckBody{body(groupID)}}
						}
						out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/"+endpoint, input)
						if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), want) {
							t.Fatalf("%s/%s resource=%q: %d %s", scope, endpoint, groupID, out.Code, out.Body.String())
						}
						if want == "SCOPE_OUT_OF_BOUNDS" && endpoint == "explain" && !strings.Contains(out.Body.String(), `"step":"application.scope"`) {
							t.Fatal("explain did not attribute the boundary denial to the installation")
						}
					}
				}
			}
			check("grp_server_install", `"decision":"allow"`)
			childWant := "SCOPE_OUT_OF_BOUNDS"
			if scope == "group_tree" {
				childWant = `"decision":"allow"`
			}
			check("grp_server_child", childWant)
			check("grp_server_outside", "SCOPE_OUT_OF_BOUNDS")
			check("", "SCOPE_OUT_OF_BOUNDS")
			check("grp_missing_install", "RESOURCE_GROUP_NOT_FOUND")
			if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
				VALUES ('spc_group_install_child', 'Child Space', 'group-install-child', $1)`, spaceID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE id = $1`, keyID); err != nil {
				t.Fatal(err)
			}
			for _, handler := range handlers {
				input := body("")
				input.Resource.SpaceID = "spc_group_install_child"
				out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/check", input)
				if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "APPLICATION_NOT_INSTALLED") {
					t.Fatalf("group installation covered a descendant Space: %d %s", out.Code, out.Body.String())
				}
			}
			for _, handler := range handlers {
				discovery := groupInstallationHTTP(t, handler, key, http.MethodGet, "/server/v1/installations", nil)
				if discovery.Code != http.StatusOK || !strings.Contains(discovery.Body.String(), `"anchor_group_id":"grp_server_install"`) || !strings.Contains(discovery.Body.String(), installed.ID) {
					t.Fatalf("group discovery = %d %s", discovery.Code, discovery.Body.String())
				}
				introspection := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/tokens/introspect", map[string]any{"token": issued.AccessToken})
				if introspection.Code != http.StatusOK || !strings.Contains(introspection.Body.String(), `"active":false`) {
					t.Fatalf("group authority was widened for Space-level introspection: %d %s", introspection.Code, introspection.Body.String())
				}
				for _, groupID := range []string{"grp_server_install", "grp_server_outside"} {
					auditBody := map[string]any{"subject": CheckSubject{MemberID: owner.ID}, "action": "invoice.read", "resource": body(groupID).Resource, "outcome": "success"}
					out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/audit/events", auditBody)
					want := http.StatusOK
					if groupID == "grp_server_outside" {
						want = http.StatusForbidden
					}
					if out.Code != want {
						t.Fatalf("group audit resource=%q: %d %s", groupID, out.Code, out.Body.String())
					}
				}
			}
			if err := authz.MoveGroup(ctx, owner.ID, spaceID, "grp_server_child", "grp_server_outside"); err != nil {
				t.Fatal(err)
			}
			check("grp_server_child", "SCOPE_OUT_OF_BOUNDS")
			for _, step := range []struct{ action, want string }{{"suspend", "APPLICATION_NOT_INSTALLED"}, {"resume", `"decision":"allow"`}, {"uninstall", "APPLICATION_NOT_INSTALLED"}} {
				if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, installed.ID, step.action); err != nil {
					t.Fatal(err)
				}
				check("grp_server_install", step.want)
			}
		})
	}
}

func TestGroupInstallationBoundsBusinessApproval(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, key, sessions := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	var previous string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM application_installations WHERE application_id = 'app_server_test'`).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, previous, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_approval_root', $1, 'Approval root', NULL),
		('grp_approval_install', $1, 'Approval install', 'grp_approval_root'), ('grp_approval_outside', $1, 'Approval outside', 'grp_approval_root')`, spaceID); err != nil {
		t.Fatal(err)
	}
	installed, err := apps.Install(ctx, owner.ID, "app_server_test", spaceID, "group_tree", "grp_approval_install")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_server_actor", Name: "group-approval"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, created.ID, []string{"auth.bindings:manage"}, "group_tree", "grp_approval_install"); err != nil {
		t.Fatal(err)
	}
	approvals := &approval.Service{Store: st, Authorization: authz, StepUp: sessions}
	mux := http.NewServeMux()
	(&API{Applications: apps, Authorization: authz, Sessions: sessions, Agents: agents, Approvals: approvals}).Register(humago.New(mux, route.HumaConfig("group approval", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	body := CheckBody{Subject: CheckSubject{MemberID: created.ID}, Action: "auth.bindings:manage",
		Resource: CheckResource{Type: "invoice", ID: "inv_group_approval", SpaceID: spaceID, GroupID: "grp_approval_install"}}
	if out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/check", body); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("group approval baseline = %d %s", out.Code, out.Body.String())
	}
	request := map[string]any{"subject": body.Subject, "action": body.Action, "resource": body.Resource, "request_digest": strings.Repeat("ab", 32), "reason": "Approve group invoice"}
	out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/approvals", request)
	if out.Code != http.StatusOK {
		t.Fatalf("group approval creation = %d %s", out.Code, out.Body.String())
	}
	var response struct {
		Data approval.Request `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_server_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := stepup.DigestValue(map[string]any{"approval_id": response.Data.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation = 'approvals.approve', step_up_digest = $2,
		step_up_method = 'totp', step_up_expires_at = now() + interval '5 minutes' WHERE id = $1`, tokens.SessionID, digest); err != nil {
		t.Fatal(err)
	}
	proof := session.WithStepUpRequirement(ctx, session.StepUpRequirement{SessionID: tokens.SessionID, Operation: "approvals.approve", Digest: digest})
	if _, err := approvals.Decide(proof, "usr_server_actor", response.Data.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, installed.ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	if out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/check", body); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "APPLICATION_NOT_INSTALLED") {
		t.Fatalf("approved request bypassed suspended installation: %d %s", out.Code, out.Body.String())
	}
	var consumed bool
	if err := st.Pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approval_requests WHERE id = $1`, response.Data.ID).Scan(&consumed); err != nil || consumed {
		t.Fatalf("installation denial consumed an approval=%v error=%v", consumed, err)
	}
	if _, err := apps.ChangeInstallationStatus(ctx, owner.ID, spaceID, installed.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	if out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/check", body); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"decision":"allow"`) {
		t.Fatalf("group approved request = %d %s", out.Code, out.Body.String())
	}
	if out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/authz/check", body); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "APPROVAL_REQUIRED") {
		t.Fatalf("group approval replay = %d %s", out.Code, out.Body.String())
	}
	request["resource"] = CheckResource{Type: "invoice", ID: "inv_outside", SpaceID: spaceID, GroupID: "grp_approval_outside"}
	if out := groupInstallationHTTP(t, handler, key, http.MethodPost, "/server/v1/approvals", request); out.Code != http.StatusBadRequest {
		t.Fatalf("out-of-scope approval request = %d %s", out.Code, out.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE agent_member_id = $1`, created.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("out-of-scope approval persisted: count=%d error=%v", count, err)
	}
}
