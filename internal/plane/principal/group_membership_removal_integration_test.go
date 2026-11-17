package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type groupRemovalFixture struct {
	store          *store.Store
	authz          *authorization.Service
	owner, target  authorization.Member
	spaceID, token string
	sessions       *session.Service
	handler        http.Handler
}

func newGroupRemovalFixture(t *testing.T) groupRemovalFixture {
	t.Helper()
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Project member", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id, status) VALUES ('usr_principal_actor', $1, 'active')`, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id)
		VALUES ('grp_remove_root', $1, 'Projects', NULL), ('grp_remove_a', $1, 'Project A', 'grp_remove_root'),
		       ('grp_remove_b', $1, 'Project B', 'grp_remove_root')`, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_group_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_remove_a', $1, '["auth.members:read"]', 'grp_remove_a', 'group_tree', 'grp_remove_a', $2),
		       ('grt_remove_b', $1, '["auth.audit:read"]', 'grp_remove_b', 'group_tree', 'grp_remove_b', $2)`, spaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"grp_remove_a", "grp_remove_b"} {
		if err := authz.AddMemberToGroup(ctx, owner.ID, spaceID, group, target.ID); err != nil {
			t.Fatal(err)
		}
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.audit:read")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}).Register(humago.New(mux, route.HumaConfig("group removal", "1.0.0")))
	return groupRemovalFixture{store: st, authz: authz, owner: owner, target: target, spaceID: spaceID,
		token: tokens.AccessToken, sessions: sessions, handler: route.Middleware(route.Principal, mux)}
}

func (f groupRemovalFixture) remove(token, groupID, memberID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/spaces/"+f.spaceID+"/groups/"+groupID+"/members/"+memberID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func TestGroupMembershipRemovalRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	(&API{}).Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "groups.members.remove" {
			continue
		}
		if spec.Method != http.MethodDelete || spec.Path != "/v1/spaces/{id}/groups/{group_id}/members/{mid}" || spec.Permission != "auth.groups:manage" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("group removal route = %+v, want DELETE H/A auth.groups:manage authoritative check", spec)
		}
		return
	}
	t.Fatal("group removal route was not registered")
}

func TestGroupMembershipRemovalRevokesDelegatedAuthorityAcrossInstances(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	agents := &agent.Service{Store: f.store}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.target.ID, CreatedByUser: "usr_principal_actor", Name: "project-parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "project-child", ExpiresAt: time.Now().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	sibling, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "independent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []struct{ owner, member string }{{f.target.ID, parent.ID}, {parent.ID, child.ID}, {f.owner.ID, sibling.ID}} {
		if _, err := f.authz.ReplaceAgentGroupGrants(ctx, in.owner, f.spaceID, in.member, []string{"auth.members:read"}, "group_tree", "grp_remove_a"); err != nil {
			t.Fatal(err)
		}
	}
	remote, err := store.Open(ctx, f.store.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remote.Close)
	services := []*authorization.Service{f.authz, {Store: remote}}
	check := func(memberID, permission, group string, allow bool) {
		t.Helper()
		for _, authz := range services {
			decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: permission, ResourceSpace: f.spaceID, ResourceGroup: group})
			if err != nil || (decision.Effect == engine.Allow) != allow {
				t.Fatalf("group authority = %s/%s error=%v", decision.Effect, decision.Code, err)
			}
			if !allow && memberID != f.target.ID && decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
				t.Fatalf("delegated denial did not preserve the owner boundary: %s", decision.Code)
			}
		}
	}
	for _, id := range []string{f.target.ID, parent.ID, child.ID, sibling.ID} {
		check(id, "auth.members:read", "grp_remove_a", true)
	}
	if out := f.remove(f.token, "grp_remove_a", f.target.ID); out.Code != http.StatusOK {
		t.Fatalf("remove project member: %d %s", out.Code, out.Body.String())
	}
	for _, id := range []string{f.target.ID, parent.ID, child.ID} {
		check(id, "auth.members:read", "grp_remove_a", false)
	}
	check(f.target.ID, "auth.audit:read", "grp_remove_b", true)
	check(sibling.ID, "auth.members:read", "grp_remove_a", true)
	req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+f.spaceID+"/audit-logs?member_id="+f.target.ID+"&action=group.member.remove", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	var response struct{ Data []audit.Event }
	if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil || out.Code != http.StatusOK || len(response.Data) != 1 {
		t.Fatalf("group removal audit: status=%d count=%d error=%v", out.Code, len(response.Data), err)
	}
	event := response.Data[0]
	if event.ActorID != f.owner.ID || event.MemberID != f.target.ID || event.UserID != "usr_principal_actor" || event.ResourceGroupID != "grp_remove_a" || event.SpaceID != f.spaceID || strings.Contains(out.Body.String(), f.token) {
		t.Fatal("group removal audit lost its verified actor, affected member or resource")
	}
}

func TestGroupMembershipRemovalUsesUnifiedHumanAgentAuthorization(t *testing.T) {
	for _, kind := range []string{"human", "agent"} {
		for _, scenario := range []string{"allow", "outside_scope", "envelope", "disabled", "principal_kind", "owner_excluded", "owner_inactive", "token_scope"} {
			if kind == "human" && strings.HasPrefix(scenario, "owner_") || kind == "human" && scenario == "token_scope" {
				continue
			}
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				ctx := context.Background()
				f := newGroupRemovalFixture(t)
				actorID, token := f.owner.ID, f.token
				if kind == "agent" {
					created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "project-manager"})
					if err != nil {
						t.Fatal(err)
					}
					actorID = created.ID
					var tokens session.Tokens
					if scenario == "token_scope" {
						tokens, err = f.sessions.CreateAgentDelegatedAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience, f.owner.ID, []string{"self:read"}, 0)
					} else {
						tokens, err = f.sessions.CreateAgentAccess(ctx, actorID, f.spaceID, security.DefaultApplicationAudience)
					}
					if err != nil {
						t.Fatal(err)
					}
					token = tokens.AccessToken
				}
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				actors := []string{f.owner.ID}
				if actorID != f.owner.ID {
					actors = append(actors, actorID)
				}
				for _, memberID := range actors {
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
						VALUES ($1, $2, '["auth.groups:manage"]', $3, 'group_tree', 'grp_remove_a', $4)`, "grt_remove_manage_"+memberID, f.spaceID, memberID, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				}
				groupID := "grp_remove_a"
				var scopes []string
				switch scenario {
				case "outside_scope":
					groupID = "grp_remove_b"
				case "envelope":
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_remove_a')`); err != nil {
						t.Fatal(err)
					}
				case "disabled":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.groups:manage'`); err != nil {
						t.Fatal(err)
					}
				case "principal_kind":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["application"]' WHERE key = 'auth.groups:manage'`); err != nil {
						t.Fatal(err)
					}
				case "owner_excluded":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				case "owner_inactive":
					if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				case "token_scope":
					scopes = []string{"self:read"}
				}
				decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: "auth.groups:manage", ResourceSpace: f.spaceID, ResourceGroup: groupID, TokenScopes: scopes})
				if err != nil {
					t.Fatal(err)
				}
				out := f.remove(token, groupID, f.target.ID)
				if scenario == "allow" {
					if decision.Effect != engine.Allow || out.Code != http.StatusOK {
						t.Fatalf("allowed group removal diverged: engine=%s status=%d", decision.Code, out.Code)
					}
				} else if decision.Effect != engine.Deny || out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), decision.Code) {
					t.Fatalf("group removal diverged: engine=%s status=%d body=%s", decision.Code, out.Code, out.Body.String())
				}
				var count int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1 AND member_id = $2`, groupID, f.target.ID).Scan(&count); err != nil || (count == 0) != (scenario == "allow") {
					t.Fatalf("group removal persistence: count=%d error=%v", count, err)
				}
			})
		}
	}
}

func TestGroupMembershipRemovalRollsBackAuditAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	var version int64
	if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.spaceID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_group_removal_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'group.member.remove' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_group_removal_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_group_removal_audit()`); err != nil {
		t.Fatal(err)
	}
	if out := f.remove(f.token, "grp_remove_a", f.target.ID); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("unaudited group removal: status=%d", out.Code)
	}
	var count int
	var unchanged bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM group_members WHERE group_id = 'grp_remove_a' AND member_id = $1),
		(SELECT policy_version = $3 FROM spaces WHERE id = $2)`, f.target.ID, f.spaceID, version).Scan(&count, &unchanged); err != nil || count != 1 || !unchanged {
		t.Fatalf("audit failure did not restore membership and version: count=%d version_unchanged=%v error=%v", count, unchanged, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_group_removal_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { results <- f.remove(f.token, "grp_remove_a", f.target.ID) }()
	}
	for range 2 {
		if out := <-results; out.Code != http.StatusOK {
			t.Fatalf("concurrent idempotent removal: status=%d", out.Code)
		}
	}
	var audits int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'group.member.remove' AND member_id = $1`, f.target.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("idempotent removal duplicated audit: count=%d error=%v", audits, err)
	}
}

func TestGroupMembershipRemovalProtectsAgentHomeGroupAndSpaceBoundaries(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "home-protected"})
	if err != nil {
		t.Fatal(err)
	}
	var home string
	if err := f.store.Pool.QueryRow(ctx, `SELECT home_group_id FROM members WHERE id = $1`, created.ID).Scan(&home); err != nil {
		t.Fatal(err)
	}
	if out := f.remove(f.token, home, created.ID); out.Code != http.StatusForbidden {
		t.Fatalf("Agent was removed from its ownership group: status=%d", out.Code)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_remove_foreign', 'Foreign', 'remove-foreign');
		INSERT INTO groups (id, space_id, name) VALUES ('grp_remove_foreign', 'spc_remove_foreign', 'Foreign');
		INSERT INTO members (id, space_id, name, type) VALUES ('mem_remove_foreign', 'spc_remove_foreign', 'Foreign', 'human')`); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		group, member, code string
		status              int
	}{
		{"grp_remove_foreign", f.target.ID, "RESOURCE_GROUP_NOT_FOUND", http.StatusForbidden},
		{"grp_remove_a", "mem_remove_foreign", "NOT_FOUND", http.StatusNotFound},
		{"grp_remove_missing", f.target.ID, "RESOURCE_GROUP_NOT_FOUND", http.StatusForbidden},
	} {
		if out := f.remove(f.token, target.group, target.member); out.Code != target.status || !strings.Contains(out.Body.String(), target.code) {
			t.Fatalf("foreign or missing membership (%s, %s): status=%d body=%s", target.group, target.member, out.Code, out.Body.String())
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.target.ID); err != nil {
		t.Fatal(err)
	}
	if out := f.remove(f.token, "grp_remove_a", f.target.ID); out.Code != http.StatusOK {
		t.Fatalf("could not revoke a suspended member's ordinary group membership: status=%d", out.Code)
	}
}
