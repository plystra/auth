package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
)

func TestExplainHTTPReportsEvaluatedStagesWithoutPrivateFacts(t *testing.T) {
	for _, scenario := range []struct{ name, code, fail string }{
		{"allow", "", ""},
		{"catalog_missing", "UNKNOWN_PERMISSION", "catalog"},
		{"catalog_disabled", "PERMISSION_DISABLED", "catalog"},
		{"principal_kind", "PRINCIPAL_KIND_NOT_ALLOWED", "principal_kind"},
		{"principal_without_grants", "PRINCIPAL_KIND_NOT_ALLOWED", "principal_kind"},
		{"envelope", "ENVELOPE_EXCLUDED", "envelope"},
		{"scope", "SCOPE_OUT_OF_BOUNDS", "scope"},
		{"closest_scope", "SCOPE_OUT_OF_BOUNDS", "scope"},
		{"resource_group", "RESOURCE_GROUP_NOT_FOUND", "application.resource_group"},
		{"key_scope", "KEY_SCOPE_EXCLUDED", "application"},
		{"installation", "APPLICATION_NOT_INSTALLED", "application"},
		{"owner_excluded", "OWNER_ENVELOPE_EXCLUDED", "owner_envelope"},
		{"owner_inactive", "OWNER_INACTIVE", "owner_envelope"},
		{"agent_allow", "", ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			st, authz, owner, spaceID, key, sessions := newServerFixture(t)
			if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET scopes = '["auth.authz:check", "auth.authz:explain"]'::jsonb`); err != nil {
				t.Fatal(err)
			}
			// Identifiable private policy data must never enter templates, including
			// a Space outside the application's installation and key scope.
			if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_private_explain', 'PRIVATE_SPACE_SENTINEL', 'private-explain')`); err != nil {
				t.Fatal(err)
			}
			agents := &agent.Service{Store: st}
			subject := CheckSubject{MemberID: owner.ID}
			body := CheckBody{Subject: subject, Action: "self:read", Resource: CheckResource{Type: "invoice", ID: "inv_explain", SpaceID: spaceID}}
			var agentID, credential string
			if strings.HasPrefix(scenario.name, "owner_") || scenario.name == "agent_allow" {
				created, raw, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "PRIVATE_AGENT_SENTINEL"})
				if err != nil {
					t.Fatal(err)
				}
				agentID, credential = created.ID, raw
				if _, err := authz.ReplaceAgentGrants(ctx, owner.ID, spaceID, created.ID, []string{"self:read"}, "space", spaceID); err != nil {
					t.Fatal(err)
				}
				body.Subject = CheckSubject{Token: raw}
			}
			var statement string
			switch scenario.name {
			case "catalog_missing":
				body.Action = "missing:read"
			case "catalog_disabled":
				statement = `UPDATE permissions SET status = 'disabled' WHERE key = 'self:read'`
			case "principal_kind", "principal_without_grants":
				statement = `UPDATE permissions SET principal_kinds = '["application"]'::jsonb WHERE key = 'self:read'`
				if scenario.name == "principal_without_grants" {
					if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
						t.Fatal(err)
					}
				}
			case "envelope":
				// A local envelope excluding only the business permission leaves
				// the installation's check/explain authority intact.
				if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, spaceID); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelope_entries (space_id, permission_id, mode) SELECT $1, id, 'delegate' FROM permissions WHERE key <> 'self:read'`, spaceID); err != nil {
					t.Fatal(err)
				}
			case "scope":
				statement = `UPDATE authorization_grants SET scope = 'self', anchor_space_id = NULL WHERE grantee_member_id = $1`
			case "closest_scope":
				if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ('grp_explain_excluded', $1, 'Excluded'), ('grp_explain_outside', $1, 'Outside')`, spaceID); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_explain_excluded')`); err != nil {
					t.Fatal(err)
				}
				if _, err := st.Pool.Exec(ctx, `
					INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by) VALUES
					('grt_explain_excluded', $1, '["self:read"]'::jsonb, $2, 'group', 'grp_explain_excluded', $2),
					('grt_explain_outside', $1, '["self:read"]'::jsonb, $2, 'group', 'grp_explain_outside', $2)
				`, spaceID, owner.ID); err != nil {
					t.Fatal(err)
				}
			case "resource_group":
				body.Resource.GroupID = "grp_private_missing"
			case "key_scope":
				body.Resource.SpaceID = "spc_private_explain"
			case "installation":
				statement = `UPDATE application_installations SET status = 'suspended'`
			case "owner_excluded":
				statement = `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`
			case "owner_inactive":
				statement = `UPDATE members SET status = 'suspended' WHERE id = $1`
			}
			if statement != "" {
				var args []any
				if strings.Contains(statement, "$1") {
					args = []any{owner.ID}
				}
				if _, err := st.Pool.Exec(ctx, statement, args...); err != nil {
					t.Fatal(err)
				}
			}
			mux := http.NewServeMux()
			(&API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions, Agents: agents}).Register(humago.New(mux, route.HumaConfig("explain test", "1.0.0")))
			handler := route.Middleware(route.Server, mux)
			request := func(path string) ExplainDecision {
				t.Helper()
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/"+path, strings.NewReader(string(encoded)))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+key)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != http.StatusOK {
					t.Fatalf("%s status = %d", path, response.Code)
				}
				for _, hidden := range []string{key, credential, owner.ID, agentID, spaceID, "spc_private_explain", "PRIVATE_SPACE_SENTINEL", "PRIVATE_AGENT_SENTINEL", "grp_private_missing", "ply_ag_", "ply_sk_"} {
					if hidden != "" && strings.Contains(response.Body.String(), hidden) {
						t.Fatalf("%s leaked a private identity or credential", path)
					}
				}
				var result struct {
					Data ExplainDecision `json:"data"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				return result.Data
			}
			check, explain := request("check"), request("explain")
			if check.Decision != explain.Decision || check.DenyCode != explain.DenyCode || explain.DenyCode != scenario.code {
				t.Fatalf("check/explain diverged: %s/%s vs %s/%s; want %s", check.Decision, check.DenyCode, explain.Decision, explain.DenyCode, scenario.code)
			}
			if scenario.fail != "" {
				last := explain.Trace[len(explain.Trace)-1]
				if last.Step != scenario.fail || last.Result != "fail" || !strings.Contains(explain.Summary, scenario.code) {
					t.Fatalf("failure/summary mismatch: %+v", explain)
				}
				if scenario.fail == "catalog" && len(explain.Trace) != 2 {
					t.Fatal("early catalog failure included unevaluated subject steps")
				}
				if scenario.code == "PRINCIPAL_KIND_NOT_ALLOWED" && slices.ContainsFunc(explain.Trace, func(step ExplainStep) bool { return step.Step == "permission" }) {
					t.Fatal("catalog principal-kind restriction was checked after grant matching")
				}
				if scenario.name == "resource_group" && slices.ContainsFunc(explain.Trace, func(step ExplainStep) bool { return !strings.HasPrefix(step.Step, "application.") }) {
					t.Fatal("missing resource group proceeded beyond installation authorization")
				}
			} else {
				for _, name := range []string{"application", "catalog", "subject", "subject_space", "resource_space", "permission", "principal_kind", "envelope", "scope"} {
					if !slices.ContainsFunc(explain.Trace, func(step ExplainStep) bool { return step.Step == name && step.Result == "pass" }) {
						t.Fatalf("allow trace omitted %s", name)
					}
				}
			}
			if scenario.name == "owner_excluded" && !slices.ContainsFunc(explain.Trace, func(step ExplainStep) bool { return step.Step == "owner.permission" && step.Result == "fail" }) {
				t.Fatal("explain discarded the owner's actual failing condition")
			}
			if scenario.name == "agent_allow" && !slices.ContainsFunc(explain.Trace, func(step ExplainStep) bool { return step.Step == "owner.scope" && step.Result == "pass" }) {
				t.Fatal("explain discarded the owner's authority trace")
			}
		})
	}
}
