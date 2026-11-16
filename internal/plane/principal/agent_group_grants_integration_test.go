package principal

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
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestAgentGroupDelegationHTTPNarrowsResourcesAndRevokesCachedDescendants(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	for _, group := range []struct{ id, parent string }{{"grp_documents", ""}, {"grp_documents_a", "grp_documents"}, {"grp_documents_nested", "grp_documents_a"}, {"grp_documents_b", "grp_documents"}} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, parent_id)
			VALUES ($1, $2, $1, 'standard', NULLIF($3, ''))`, group.id, spaceID, group.parent); err != nil {
			t.Fatal(err)
		}
	}
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "group-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "group-child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	sibling, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "independent", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	// The ordinary management grant and assignment rights are deliberately
	// absent: the owner's documented system assignment right must suffice.
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_document_owner', $1, '["auth.members:read"]'::jsonb, $2, 'group_tree', 'grp_documents', $2)`, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	human, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	parentToken, err := sessions.CreateAgentAccess(ctx, parent.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}).Register(humago.New(mux, route.HumaConfig("group delegation test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	replace := func(token, target, scope, group string, status int) authorization.Grant {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/v1/me/agents/"+target+"/grants", strings.NewReader(fmt.Sprintf(`{"permissions":["auth.members:read"],"scope":%q,"anchor_group_id":%q}`, scope, group)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != status {
			t.Fatalf("group grant = %d %s, want %d", response.Code, response.Body.String(), status)
		}
		if status != http.StatusOK {
			if !strings.Contains(response.Body.String(), `"code":"AUTHORITY_DELTA_NOT_COVERED"`) {
				t.Fatalf("out-of-scope replacement = %s", response.Body.String())
			}
			return authorization.Grant{}
		}
		var result struct{ Data authorization.Grant }
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Data.AnchorGroupID != group || result.Data.AnchorSpaceID != "" || result.Data.Scope != scope {
			t.Fatalf("persisted group boundary = %+v", result.Data)
		}
		return result.Data
	}
	replace(human.AccessToken, parent.ID, "group_tree", "grp_documents_a", http.StatusOK)
	childGrant := replace(parentToken.AccessToken, child.ID, "group", "grp_documents_nested", http.StatusOK)
	replace(human.AccessToken, sibling.ID, "group_tree", "grp_documents_b", http.StatusOK)
	remote, err := store.Open(ctx, st.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)
	remoteAuthz := &authorization.Service{Store: remote}
	check := func(service *authorization.Service, id, group string, want engine.Effect, code string) {
		t.Helper()
		decision, _, err := service.Check(ctx, authorization.CheckRequest{MemberID: id, Permission: "auth.members:read", ResourceSpace: spaceID, ResourceGroup: group})
		if err != nil || decision.Effect != want || code != "" && decision.Code != code {
			t.Fatalf("group authorization = %+v, %v, want %s %s", decision, err, want, code)
		}
	}
	check(remoteAuthz, child.ID, "grp_documents_nested", engine.Allow, "allowed")
	check(remoteAuthz, child.ID, "grp_documents_a", engine.Deny, "SCOPE_OUT_OF_BOUNDS")
	check(remoteAuthz, child.ID, "grp_documents_b", engine.Deny, "SCOPE_OUT_OF_BOUNDS")
	check(remoteAuthz, sibling.ID, "grp_documents_b", engine.Allow, "allowed")
	// A parent can narrow the target to a descendant, but cannot broaden its
	// child's scope to an ancestor or another branch. Failure retains the grant.
	replace(parentToken.AccessToken, child.ID, "group_tree", "grp_documents", http.StatusForbidden)
	replace(parentToken.AccessToken, child.ID, "group", "grp_documents_b", http.StatusForbidden)
	var originalLive bool
	if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, childGrant.ID).Scan(&originalLive); err != nil || !originalLive {
		t.Fatalf("failed replacement revoked the prior grant: %t %v", originalLive, err)
	}
	replace(human.AccessToken, parent.ID, "group", "grp_documents_a", http.StatusOK)
	for _, service := range []*authorization.Service{authz, remoteAuthz} {
		check(service, child.ID, "grp_documents_nested", engine.Deny, "OWNER_ENVELOPE_EXCLUDED")
		check(service, sibling.ID, "grp_documents_b", engine.Allow, "allowed")
	}
}

func TestAgentGroupDelegationHTTPRejectsAmbiguousOrMissingAnchors(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, _, sessions, signer := newPrincipalFixture(t)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "group-input"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}).Register(humago.New(mux, route.HumaConfig("group input test", "1.0.0")))
	for _, body := range []string{
		`{"permissions":["auth.members:read"],"scope":"group"}`,
		`{"permissions":["auth.members:read"],"scope":"space","anchor_group_id":"grp_any"}`,
		`{"permissions":["auth.members:read"],"scope":"group","anchor_group_id":"grp_any","anchor_space_id":"spc_any"}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/v1/me/agents/"+created.ID+"/grants", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, req)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"VALIDATION_FAILED"`) {
			t.Fatalf("invalid group anchor = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestSharedMemberAgentGrantHTTPRequiresCreatorOrAdministrator(t *testing.T) {
	for _, scope := range []string{"space", "group_tree"} {
		t.Run(scope, func(t *testing.T) {
			ctx := context.Background()
			st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind)
				VALUES ('grp_shared_agent_resource', $1, 'Shared resource', 'standard')`, spaceID); err != nil {
				t.Fatal(err)
			}
			agents := &agent.Service{Store: st}
			created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "shared-owned"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE members SET binding_policy = 'shared' WHERE id = $1`, owner.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
				VALUES ('usr_other_shared_owner', 'other-shared@example.test', 'other-shared@example.test', 'test-password-hash', 'active')`); err != nil {
				t.Fatal(err)
			}
			if err := authz.BindUser(ctx, owner.ID, spaceID, owner.ID, "usr_other_shared_owner"); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, owner.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
				(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
				VALUES ('grt_shared_owner_read', $1, '["auth.members:read"]'::jsonb, $2, 'space', $1, $2)`, spaceID, owner.ID); err != nil {
				t.Fatal(err)
			}
			creator, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			other, err := sessions.CreateForMember(ctx, "usr_other_shared_owner", owner.ID, nil, "test", 1)
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: agents}).Register(humago.New(mux, route.HumaConfig("shared grant test", "1.0.0")))
			body := fmt.Sprintf(`{"permissions":["auth.members:read"],"scope":%q,"anchor_space_id":%q}`, scope, spaceID)
			if scope == "group_tree" {
				body = `{"permissions":["auth.members:read"],"scope":"group_tree","anchor_group_id":"grp_shared_agent_resource"}`
			}
			replace := func(token string, status int, code string) authorization.Grant {
				t.Helper()
				req := httptest.NewRequest(http.MethodPut, "/v1/me/agents/"+created.ID+"/grants", strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, req)
				if response.Code != status || code != "" && !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
					t.Fatalf("shared owner grant = %d %s, want %d %s", response.Code, response.Body.String(), status, code)
				}
				var result struct{ Data authorization.Grant }
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				return result.Data
			}
			original := replace(creator.AccessToken, http.StatusOK, "")
			replace(other.AccessToken, http.StatusForbidden, "NO_MATCHING_PERMISSION")
			var live bool
			if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM authorization_grants WHERE id = $1`, original.ID).Scan(&live); err != nil || !live {
				t.Fatalf("non-creator replaced the grant: live=%t %v", live, err)
			}
			if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
				(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
				VALUES ('grt_shared_owner_administrator', $1, '["auth.grants:assign"]'::jsonb, $2, 'space', $1, $2)`, spaceID, owner.ID); err != nil {
				t.Fatal(err)
			}
			replace(other.AccessToken, http.StatusOK, "")
		})
	}
}
