package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type agentAdministrationFixture struct {
	store                            *store.Store
	authz                            *authorization.Service
	sessions                         *session.Service
	handler                          http.Handler
	actorID, ownerID, spaceID, token string
	target, child, outside           agent.Agent
	original                         authorization.Grant
}

func newAgentAdministrationFixture(t *testing.T, actorKind string) agentAdministrationFixture {
	t.Helper()
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	var targets []agent.Agent
	for _, suffix := range []string{"target", "outside"} {
		userID := "usr_admin_" + suffix
		if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
			VALUES ($1, $2, $2, 'test-password-hash', 'active')`, userID, suffix+"-admin@example.test"); err != nil {
			t.Fatal(err)
		}
		member, err := authz.CreateMember(ctx, owner.ID, userID, spaceID, suffix+" owner", "human", "single")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authz.CreateInlineGrant(ctx, owner.ID, spaceID, member.ID, []string{"auth.members:read", "auth.members:manage"}, "space", spaceID); err != nil {
			t.Fatal(err)
		}
		created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: member.ID, CreatedByUser: userID, Name: suffix, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, created)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, parent_id)
		VALUES ('grp_admin_documents', $1, 'Documents', 'standard', NULL),
		('grp_admin_nested_documents', $1, 'Nested', 'standard', 'grp_admin_documents')`, spaceID); err != nil {
		t.Fatal(err)
	}
	original, err := authz.ReplaceAgentGroupGrants(ctx, targets[0].OwnerMemberID, spaceID, targets[0].ID, []string{"auth.members:read", "auth.members:manage"}, "group_tree", "grp_admin_documents")
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: targets[0].ID, Name: "child", ExpiresAt: targets[0].ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.ReplaceAgentGroupGrants(ctx, targets[0].ID, spaceID, child.ID, []string{"auth.members:read"}, "group", "grp_admin_nested_documents"); err != nil {
		t.Fatal(err)
	}
	actorID := owner.ID
	permissions := []string{"auth.grants:assign", "auth.groups:manage"}
	if actorKind == "agent" {
		actor, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "administrator"})
		if err != nil {
			t.Fatal(err)
		}
		actorID = actor.ID
		if _, err := authz.ReplaceAgentGroupGrants(ctx, owner.ID, spaceID, actorID, permissions, "group_tree", targets[0].HomeGroupID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_scoped_agent_administrator', $1, '["auth.grants:assign","auth.groups:manage"]'::jsonb, $2, 'group_tree', $3, $2)`, spaceID, owner.ID, targets[0].HomeGroupID); err != nil {
		t.Fatal(err)
	}
	var issued session.Tokens
	if actorKind == "agent" {
		issued, err = sessions.CreateAgentAccess(ctx, actorID, spaceID, security.DefaultApplicationAudience)
	} else {
		issued, err = sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	}
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}).Register(humago.New(mux, route.HumaConfig("Agent administration test", "1.0.0")))
	return agentAdministrationFixture{store: st, authz: authz, sessions: sessions, handler: route.Middleware(route.Principal, mux), actorID: actorID, ownerID: owner.ID, spaceID: spaceID, token: issued.AccessToken, target: targets[0], child: child, outside: targets[1], original: original}
}

func (f agentAdministrationFixture) request(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, req)
	return response
}

func TestNonOwnerAdministratorHTTPViewsAndNarrowsAgentWithinTargetGroup(t *testing.T) {
	for _, actorKind := range []string{"human", "agent"} {
		t.Run(actorKind, func(t *testing.T) {
			ctx := context.Background()
			f := newAgentAdministrationFixture(t, actorKind)
			for _, target := range []agent.Agent{f.target, f.child} {
				response := f.request(t, http.MethodGet, "/v1/spaces/"+f.spaceID+"/groups/"+target.HomeGroupID+"/members", "")
				if response.Code != http.StatusOK {
					t.Fatalf("group member listing = %d %s", response.Code, response.Body.String())
				}
				var result struct{ Data []authorization.Member }
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Data) != 1 || result.Data[0].ID != target.ID || result.Data[0].Kind != "agent" || strings.Contains(response.Body.String(), f.outside.ID) {
					t.Fatalf("group listing escaped the requested group: %s", response.Body.String())
				}
			}
			remote, err := store.Open(ctx, f.store.Pool.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(remote.Close)
			remoteAuthz := &authorization.Service{Store: remote}
			request := authorization.CheckRequest{MemberID: f.child.ID, Permission: "auth.members:read", ResourceSpace: f.spaceID, ResourceGroup: "grp_admin_nested_documents"}
			decision, _, err := remoteAuthz.Check(ctx, request)
			if err != nil || decision.Effect != engine.Allow {
				t.Fatalf("initial child authority = %+v, %v", decision, err)
			}
			response := f.request(t, http.MethodPut, "/v1/me/agents/"+f.target.ID+"/grants", `{"permissions":["auth.members:read"],"scope":"group","anchor_group_id":"grp_admin_documents"}`)
			if response.Code != http.StatusOK {
				t.Fatalf("non-owner administrator narrowing = %d %s", response.Code, response.Body.String())
			}
			decision, _, err = remoteAuthz.Check(ctx, request)
			if err != nil || decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
				t.Fatalf("cached child authority after administrator narrowing = %+v, %v", decision, err)
			}
			var live bool
			if err := f.store.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, f.original.ID).Scan(&live); err != nil || live {
				t.Fatalf("administrator replacement did not revoke old grant: %t %v", live, err)
			}
			var recorded bool
			credentialType, userID := "agent_access_token", ""
			if actorKind == "human" {
				credentialType, userID = "user_access_token", "usr_principal_actor"
			}
			if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_logs
				WHERE action = 'grant.replace' AND actor_id = $1 AND member_id = $2
				AND space_id = $3 AND resource_group_id = $4 AND credential_type = $5
				AND COALESCE(user_id, '') = $6 AND plane = 'principal'
				AND owner_chain @> jsonb_build_array(jsonb_build_object('member_id', $7::text)))`,
				f.actorID, f.target.ID, f.spaceID, f.target.HomeGroupID, credentialType, userID, f.target.OwnerMemberID).Scan(&recorded); err != nil || !recorded {
				t.Fatalf("administrator grant audit lost the subject or caller identity: recorded=%t err=%v", recorded, err)
			}
		})
	}
}

func TestNonOwnerAdministratorHTTPRejectsScopeAndPolicyBypasses(t *testing.T) {
	for _, condition := range []string{"outside_group", "disabled", "principal_kind", "token_scope", "owner_permission", "owner_inactive", "group_envelope", "group_inactive", "target_multiple_groups", "foreign_space"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			f := newAgentAdministrationFixture(t, "agent")
			target := f.target
			want := "SCOPE_OUT_OF_BOUNDS"
			var err error
			switch condition {
			case "outside_group":
				target = f.outside
			case "disabled":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key IN ('auth.grants:assign','auth.groups:manage')`)
				want = "PERMISSION_DISABLED"
			case "principal_kind":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human"]'::jsonb WHERE key IN ('auth.grants:assign','auth.groups:manage')`)
				want = "PRINCIPAL_KIND_NOT_ALLOWED"
			case "token_scope":
				var issued session.Tokens
				issued, err = f.sessions.CreateAgentDelegatedAccess(ctx, f.actorID, f.spaceID, security.DefaultApplicationAudience, f.ownerID, []string{"self:read"}, 0)
				f.token = issued.AccessToken
				want = "TOKEN_SCOPE_EXCLUDED"
			case "owner_permission":
				_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_scoped_agent_administrator'`)
				want = "OWNER_ENVELOPE_EXCLUDED"
			case "owner_inactive":
				_, err = f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.ownerID)
				want = "OWNER_INACTIVE"
			case "group_envelope":
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ($1)`, f.target.HomeGroupID)
				want = "ENVELOPE_EXCLUDED"
			case "group_inactive":
				_, err = f.store.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, f.target.HomeGroupID)
				want = "OWNER_INACTIVE"
			case "target_multiple_groups":
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id) VALUES ('grp_admin_documents', $1, $2)`, f.target.ID, f.spaceID)
			case "foreign_space":
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_agent_admin_foreign', 'Foreign', 'agent-admin-foreign')`)
				if err == nil {
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind) VALUES ('grp_agent_admin_foreign', 'spc_agent_admin_foreign', 'Foreign', 'standard')`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			body := `{"permissions":["auth.members:read"],"scope":"group","anchor_group_id":"grp_admin_documents"}`
			if condition == "foreign_space" {
				body = `{"permissions":["auth.members:read"],"scope":"group","anchor_group_id":"grp_agent_admin_foreign"}`
				want = "SCOPE_OUT_OF_BOUNDS"
			}
			response := f.request(t, http.MethodPut, "/v1/me/agents/"+target.ID+"/grants", body)
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"`+want+`"`) {
				t.Fatalf("administrator grant bypass = %d %s, want %s", response.Code, response.Body.String(), want)
			}
			var live bool
			if err := f.store.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, f.original.ID).Scan(&live); err != nil || !live {
				t.Fatalf("denied administrator write replaced the grant: %t %v", live, err)
			}
			if condition != "target_multiple_groups" && condition != "foreign_space" {
				readWant := want
				if condition == "group_inactive" {
					// Grant replacement rejects an inactive target Agent before
					// management authorization; listing checks the resource group.
					readWant = "RESOURCE_GROUP_INACTIVE"
				}
				response = f.request(t, http.MethodGet, "/v1/spaces/"+f.spaceID+"/groups/"+target.HomeGroupID+"/members", "")
				if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"`+readWant+`"`) || strings.Contains(response.Body.String(), target.Name) {
					t.Fatalf("administrator read bypass = %d %s, want %s", response.Code, response.Body.String(), readWant)
				}
			}
		})
	}
}

func TestNonOwnerAdministratorHTTPRequiresAssignmentCoverageForPositiveDelta(t *testing.T) {
	f := newAgentAdministrationFixture(t, "human")
	ctx := context.Background()
	body := fmt.Sprintf(`{"permissions":["auth.members:read"],"scope":"space","anchor_space_id":%q}`, f.spaceID)
	response := f.request(t, http.MethodPut, "/v1/me/agents/"+f.target.ID+"/grants", body)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"AUTHORITY_DELTA_NOT_COVERED"`) {
		t.Fatalf("uncovered administrator delta = %d %s", response.Code, response.Body.String())
	}
	var live bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, f.original.ID).Scan(&live); err != nil || !live {
		t.Fatalf("uncovered delta replaced original grant: %t %v", live, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	response = f.request(t, http.MethodPut, "/v1/me/agents/"+f.target.ID+"/grants", body)
	if response.Code != http.StatusOK {
		t.Fatalf("covered administrator Space delta = %d %s", response.Code, response.Body.String())
	}
	decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: f.target.ID, Permission: "auth.members:read", ResourceSpace: f.spaceID})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("administrator Space grant = %+v, %v", decision, err)
	}
}

func TestNonOwnerAdministratorHTTPAuditFailureRollsBackNarrowing(t *testing.T) {
	f := newAgentAdministrationFixture(t, "human")
	ctx := context.Background()
	var memberVersion, spaceVersion int64
	if err := f.store.Pool.QueryRow(ctx, `SELECT m.version, s.policy_version FROM members m JOIN spaces s ON s.id = m.space_id WHERE m.id = $1`, f.target.ID).Scan(&memberVersion, &spaceVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_admin_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'grant.replace' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_admin_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_admin_grant_audit()`); err != nil {
		t.Fatal(err)
	}
	response := f.request(t, http.MethodPut, "/v1/me/agents/"+f.target.ID+"/grants", `{"permissions":["auth.members:read"],"scope":"group","anchor_group_id":"grp_admin_documents"}`)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"UNAVAILABLE"`) || strings.Contains(response.Body.String(), "audit unavailable") {
		t.Fatalf("audit failure = %d %s", response.Code, response.Body.String())
	}
	var currentMember, currentSpace int64
	var live bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT m.version, s.policy_version, g.revoked_at IS NULL
		FROM members m JOIN spaces s ON s.id = m.space_id JOIN authorization_grants g ON g.id = $2 WHERE m.id = $1`, f.target.ID, f.original.ID).Scan(&currentMember, &currentSpace, &live); err != nil {
		t.Fatal(err)
	}
	if !live || currentMember != memberVersion || currentSpace != spaceVersion {
		t.Fatalf("audit failure changed authority: live=%t member=%d/%d Space=%d/%d", live, currentMember, memberVersion, currentSpace, spaceVersion)
	}
}

func TestAgentAdministratorRevalidatesAuthenticatedUserInGrantTransaction(t *testing.T) {
	for _, scope := range []string{"space", "group"} {
		for _, condition := range []string{"revoked_binding", "expired_binding", "inactive_user"} {
			t.Run(scope+"/"+condition, func(t *testing.T) {
				f := newAgentAdministrationFixture(t, "human")
				ctx := authorization.WithHumanActor(context.Background(), f.actorID, "usr_principal_actor")
				var err error
				switch condition {
				case "revoked_binding":
					_, err = f.store.Pool.Exec(ctx, `UPDATE user_members SET revoked_at = now() WHERE user_id = 'usr_principal_actor' AND member_id = $1`, f.actorID)
				case "expired_binding":
					_, err = f.store.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 second' WHERE user_id = 'usr_principal_actor' AND member_id = $1`, f.actorID)
				case "inactive_user":
					_, err = f.store.Pool.Exec(ctx, `UPDATE users SET status = 'suspended' WHERE id = 'usr_principal_actor'`)
				}
				if err != nil {
					t.Fatal(err)
				}
				if scope == "space" {
					_, err = f.authz.ReplaceAgentGrants(ctx, f.actorID, f.spaceID, f.target.ID, []string{"auth.members:read"}, scope, f.spaceID)
				} else {
					_, err = f.authz.ReplaceAgentGroupGrants(ctx, f.actorID, f.spaceID, f.target.ID, []string{"auth.members:read"}, scope, "grp_admin_documents")
				}
				assertPrincipalError(t, err, "UNAUTHENTICATED")
				var live bool
				if err := f.store.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, f.original.ID).Scan(&live); err != nil || !live {
					t.Fatalf("invalid account retained administrator mutation: %t %v", live, err)
				}
			})
		}
	}
}

func TestSpaceMemberListHTTPFiltersTypesAndKeepsManagementScope(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "listed Agent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id, space_id, name, type, kind)
		VALUES ('mem_listed_application', $1, 'Listed application', 'application', 'service')`, spaceID); err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}).Register(humago.New(mux, route.HumaConfig("member filter test", "1.0.0")))
	f := agentAdministrationFixture{handler: route.Middleware(route.Principal, mux), token: issued.AccessToken}
	for kind, ids := range map[string][]string{"": {owner.ID, created.ID, "mem_listed_application"}, "human": {owner.ID}, "agent": {created.ID}, "application": {"mem_listed_application"}} {
		response := f.request(t, http.MethodGet, "/v1/spaces/"+spaceID+"/members?type="+kind, "")
		if response.Code != http.StatusOK {
			t.Fatalf("member type filter %q = %d %s", kind, response.Code, response.Body.String())
		}
		var result struct{ Data []authorization.Member }
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, member := range result.Data {
			if kind != "" && member.Kind != kind {
				t.Fatalf("filter %s returned %s", kind, member.Kind)
			}
			got = append(got, member.ID)
		}
		slices.Sort(got)
		slices.Sort(ids)
		if !slices.Equal(got, ids) {
			t.Fatalf("member filter %q = %v, want %v", kind, got, ids)
		}
	}
	response := f.request(t, http.MethodGet, "/v1/spaces/"+spaceID+"/members?type=unknown", "")
	if response.Code < 400 || response.Code >= 500 || !strings.Contains(response.Body.String(), `"code":"VALIDATION_FAILED"`) {
		t.Fatalf("unknown type = %d %s", response.Code, response.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_list_group_only', $1, '["auth.members:read"]'::jsonb, $2, 'group_tree', $3, $2)`, spaceID, owner.ID, created.HomeGroupID); err != nil {
		t.Fatal(err)
	}
	response = f.request(t, http.MethodGet, "/v1/spaces/"+spaceID+"/members?type=agent", "")
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"SCOPE_OUT_OF_BOUNDS"`) || strings.Contains(response.Body.String(), created.ID) {
		t.Fatalf("type filter bypassed whole-Space scope: %d %s", response.Code, response.Body.String())
	}
}

func TestGroupMemberListHTTPRejectsWrongSpaceAndReturnsEmptyArray(t *testing.T) {
	f := newAgentAdministrationFixture(t, "human")
	ctx := context.Background()
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_group_list_foreign', 'Foreign', 'group-list-foreign');
		INSERT INTO groups (id, space_id, name, kind) VALUES ('grp_group_list_foreign', 'spc_group_list_foreign', 'Foreign', 'standard')`); err != nil {
		t.Fatal(err)
	}
	for _, groupID := range []string{"grp_group_list_foreign", "grp_does_not_exist"} {
		response := f.request(t, http.MethodGet, "/v1/spaces/"+f.spaceID+"/groups/"+groupID+"/members", "")
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"NOT_FOUND"`) {
			t.Fatalf("incorrect group/Space = %d %s", response.Code, response.Body.String())
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, parent_id)
		VALUES ('grp_empty_admin_child', $1, 'Empty', 'standard', 'grp_admin_documents')`, f.spaceID); err != nil {
		t.Fatal(err)
	}
	// A plain group is used for the empty case; an Agent-owned group cannot
	// receive manual child groups under the documented structure rules.
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET anchor_group_id = 'grp_admin_documents'
		WHERE id = 'grt_scoped_agent_administrator'`); err != nil {
		t.Fatal(err)
	}
	response := f.request(t, http.MethodGet, fmt.Sprintf("/v1/spaces/%s/groups/grp_empty_admin_child/members", f.spaceID), "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"data":[]`) {
		t.Fatalf("empty group list = %d %s", response.Code, response.Body.String())
	}
}
