package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func installationGroups(t *testing.T, st *store.Store, spaceID string) {
	t.Helper()
	if _, err := st.Pool.Exec(context.Background(), `INSERT INTO groups (id, space_id, name, parent_id)
		VALUES ('grp_install_space', $1, 'Space groups', NULL),
		       ('grp_install_root', $1, 'Install root', 'grp_install_space'),
		       ('grp_install_child', $1, 'Install child', 'grp_install_root'),
		       ('grp_install_other', $1, 'Install other', 'grp_install_space')`, spaceID); err != nil {
		t.Fatal(err)
	}
}

func installationHTTP(t *testing.T, handler http.Handler, token, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func TestGroupApplicationInstallationHTTPScopes(t *testing.T) {
	for _, visibility := range []string{"private", "public"} {
		for _, scope := range []string{"group", "group_tree"} {
			t.Run(visibility+"/"+scope, func(t *testing.T) {
				ctx := context.Background()
				st, authz, _, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
				if visibility == "public" {
					if _, err := st.Pool.Exec(ctx, `UPDATE applications SET visibility = 'public', review_status = 'approved' WHERE id = $1`, appID); err != nil {
						t.Fatal(err)
					}
					customer, owner, err := authz.CreateSpace(ctx, "usr_principal_actor", "Group customer", "group-customer")
					if err != nil {
						t.Fatal(err)
					}
					actorID, spaceID = owner.ID, customer.ID
					seedTestInlineGrant(t, st, spaceID, actorID, actorID, "auth.applications:manage")
				}
				installationGroups(t, st, spaceID)
				tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
				if err != nil {
					t.Fatal(err)
				}
				body := map[string]any{"application_id": appID, "scope": scope, "anchor_group_id": "grp_install_root"}
				path := "/v1/spaces/" + spaceID + "/installations"
				seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
					"space_id": spaceID, "application_id": appID, "scope": scope, "anchor_group_id": "grp_install_other",
				})
				if out := installationHTTP(t, handler, tokens.AccessToken, http.MethodPost, path, body); out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "STEP_UP_REQUIRED") {
					t.Fatalf("step-up accepted a different anchor: %d %s", out.Code, out.Body.String())
				}
				seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
					"space_id": spaceID, "application_id": appID, "scope": scope, "anchor_group_id": "grp_install_root",
				})
				created := installationHTTP(t, handler, tokens.AccessToken, http.MethodPost, path, body)
				if created.Code != http.StatusOK {
					t.Fatalf("group installation = %d %s", created.Code, created.Body.String())
				}
				var result struct {
					Data application.Installation `json:"data"`
				}
				if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				installed := result.Data
				if installed.Scope != scope || installed.AnchorGroupID != "grp_install_root" || len(installed.ApprovedPermissions) != 1 {
					t.Fatalf("installation did not preserve its scope: %+v", installed)
				}
				for _, groupID := range []string{"grp_install_root", "grp_install_child", "grp_install_other", ""} {
					decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: installed.MemberID, Permission: "auth.authz:check", ResourceSpace: spaceID, ResourceGroup: groupID})
					want := groupID == "grp_install_root" || (scope == "group_tree" && groupID == "grp_install_child")
					if err != nil || (decision.Effect == engine.Allow) != want {
						t.Fatalf("%s resource %q = %s/%s, %v", scope, groupID, decision.Effect, decision.Code, err)
					}
				}
				var kind, anchor string
				var managed, spaceAnchor bool
				if err := st.Pool.QueryRow(ctx, `SELECT m.type, r.managed, g.anchor_group_id, g.anchor_space_id IS NOT NULL
					FROM application_installations i JOIN members m ON m.id = i.member_id
					JOIN roles r ON r.id = i.role_id JOIN authorization_grants g ON g.role_id = r.id WHERE i.id = $1`, installed.ID).Scan(&kind, &managed, &anchor, &spaceAnchor); err != nil || kind != "application" || !managed || anchor != installed.AnchorGroupID || spaceAnchor {
					t.Fatalf("managed installation facts: kind=%s managed=%v anchor=%s space_anchor=%v error=%v", kind, managed, anchor, spaceAnchor, err)
				}
				listed := installationHTTP(t, handler, tokens.AccessToken, http.MethodGet, path, nil)
				if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"anchor_group_id":"grp_install_root"`) {
					t.Fatalf("group installation listing = %d %s", listed.Code, listed.Body.String())
				}
				var audits int
				if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.install' AND resource_id = $1
					AND space_id = $2 AND resource_group_id = 'grp_install_root' AND application_id = $3 AND member_id = $4`, installed.ID, spaceID, appID, actorID).Scan(&audits); err != nil || audits != 1 {
					t.Fatalf("installation audit facts=%d error=%v", audits, err)
				}
			})
		}
	}
}

func TestGroupApplicationInstallationRejectsIncompleteManifest(t *testing.T) {
	for _, scenario := range []string{"excluded", "use_only", "group_right_only", "no_descendants", "foreign_group", "inactive_ancestor", "disabled", "deprecated", "principal_kind"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			st, _, apps, actorID, spaceID, _, _, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
			installationGroups(t, st, spaceID)
			anchor, code := "grp_install_root", "AUTHORITY_DELTA_NOT_COVERED"
			var err error
			switch scenario {
			case "excluded", "use_only":
				_, err = st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_install_root');
					INSERT INTO group_envelope_entries (group_id, permission_id, mode)
					SELECT 'grp_install_root', id, 'delegate' FROM permissions WHERE key IN ('auth.applications:manage','auth.authz:check')`)
				if err == nil && scenario == "use_only" {
					_, err = st.Pool.Exec(ctx, `INSERT INTO group_envelope_entries (group_id, permission_id, mode)
						SELECT 'grp_install_root', id, 'use' FROM permissions WHERE key = 'auth.tokens:introspect'`)
				}
			case "group_right_only":
				_, err = st.Pool.Exec(ctx, `UPDATE assign_rights SET anchor_space_id = NULL, anchor_group_id = 'grp_install_root' WHERE holder_member_id = $1`, actorID)
			case "no_descendants":
				_, err = st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = false WHERE holder_member_id = $1`, actorID)
			case "foreign_group":
				_, err = st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_install_foreign', 'Foreign', 'install-foreign');
					INSERT INTO groups (id, space_id, name) VALUES ('grp_install_foreign', 'spc_install_foreign', 'Foreign')`)
				anchor, code = "grp_install_foreign", "RESOURCE_GROUP_NOT_FOUND"
			case "inactive_ancestor":
				_, err = st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = 'grp_install_root'`)
				anchor, code = "grp_install_child", "RESOURCE_GROUP_INACTIVE"
			case "disabled":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.tokens:introspect'`)
			case "deprecated":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET status = 'deprecated' WHERE key = 'auth.tokens:introspect'`)
			case "principal_kind":
				_, err = st.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human", "agent"]'::jsonb WHERE key = 'auth.tokens:introspect'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = apps.Install(ctx, actorID, appID, spaceID, "group_tree", anchor)
			assertPrincipalError(t, err, code)
			var count int
			if err := st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM application_installations WHERE application_id = $1)
				+ (SELECT count(*) FROM members WHERE type = 'application' AND space_id = $2)
				+ (SELECT count(*) FROM roles WHERE managed AND space_id = $2 AND name LIKE 'application:ins_%')`, appID, spaceID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed installation left managed state=%d error=%v", count, err)
			}
		})
	}
}

func TestGroupInstallationLifecycleAndManifestUseTargetNode(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installationGroups(t, st, spaceID)
	installed, err := apps.Install(ctx, actorID, appID, spaceID, "group_tree", "grp_install_root")
	if err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group_tree', anchor_space_id = NULL,
		anchor_group_id = 'grp_install_root' WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, actorID); err != nil {
		t.Fatal(err)
	}
	path := "/v1/spaces/" + spaceID + "/installations/" + installed.ID
	for _, action := range []string{"suspend", "resume"} {
		out := installationHTTP(t, handler, token, http.MethodPost, path+"/"+action, nil)
		if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"anchor_group_id":"grp_install_root"`) {
			t.Fatalf("group-scoped manager %s = %d %s", action, out.Code, out.Body.String())
		}
	}
	// Fixture the publisher's expanded manifest; customer approval still uses the public HTTP route.
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET manifest_permissions = '["auth.authz:check","auth.tokens:introspect"]'::jsonb WHERE id = $1`, appID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ('grp_install_root');
		INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT 'grp_install_root', id, 'delegate' FROM permissions WHERE key IN ('auth.applications:manage','auth.authz:check')`); err != nil {
		t.Fatal(err)
	}
	denied := installationHTTP(t, handler, token, http.MethodPut, path+"/approvals", nil)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") || !strings.Contains(denied.Body.String(), "auth.tokens:introspect") {
		t.Fatalf("partial manifest approved through excluded envelope: %d %s", denied.Code, denied.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT 'grp_install_root', id, 'assign' FROM permissions WHERE key = 'auth.tokens:introspect'`); err != nil {
		t.Fatal(err)
	}
	if out := installationHTTP(t, handler, token, http.MethodPut, path+"/approvals", nil); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "auth.tokens:introspect") {
		t.Fatalf("covered group manifest approval = %d %s", out.Code, out.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET anchor_group_id = 'grp_install_other'
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, actorID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"suspend", "resume", "uninstall"} {
		if out := installationHTTP(t, handler, token, http.MethodPost, path+"/"+action, nil); out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "SCOPE_OUT_OF_BOUNDS") {
			t.Fatalf("sibling manager %s = %d %s", action, out.Code, out.Body.String())
		}
	}
	if out := installationHTTP(t, handler, token, http.MethodPut, path+"/approvals", nil); out.Code != http.StatusForbidden {
		t.Fatalf("sibling manager approved installation: %d %s", out.Code, out.Body.String())
	}
}

func TestAgentGroupInstallationUsesOwnerAuthority(t *testing.T) {
	ctx := context.Background()
	st, _, _, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installationGroups(t, st, spaceID)
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "group-installer", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_group_agent_install', $1, '["auth.applications:manage"]', $2, 'group_tree', 'grp_install_root', $3)`, spaceID, created.ID, ownerID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, ownerID, created.ID, "auth.grants:assign")
	if _, err := st.Pool.Exec(ctx, `INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, source)
		VALUES ('ar_group_agent_install', $1, '["auth.authz:check"]', $2, true, 'system')`, created.ID, spaceID); err != nil {
		t.Fatal(err)
	}
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/spaces/" + spaceID + "/installations"
	body := map[string]any{"application_id": appID, "scope": "group_tree", "anchor_group_id": "grp_install_root"}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group', anchor_space_id = NULL, anchor_group_id = 'grp_install_other'
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, ownerID); err != nil {
		t.Fatal(err)
	}
	out := installationHTTP(t, handler, access.AccessToken, http.MethodPost, path, body)
	if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent installed outside owner scope: %d %s", out.Code, out.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET anchor_group_id = 'grp_install_root'
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, ownerID); err != nil {
		t.Fatal(err)
	}
	out = installationHTTP(t, handler, access.AccessToken, http.MethodPost, path, body)
	if out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("Agent bypassed owner's assignment rights: %d %s", out.Code, out.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, ownerID); err != nil {
		t.Fatal(err)
	}
	out = installationHTTP(t, handler, access.AccessToken, http.MethodPost, path, body)
	if out.Code != http.StatusOK {
		t.Fatalf("covered Agent installation = %d %s", out.Code, out.Body.String())
	}
	var installed struct {
		Data application.Installation `json:"data"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &installed); err != nil {
		t.Fatal(err)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id = $1 AND action = 'application.install'
		AND member_id = $2 AND member_type = 'agent' AND jsonb_array_length(owner_chain) = 1 AND resource_group_id = 'grp_install_root'`, installed.Data.ID, created.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("Agent installation owner audit=%d error=%v", audits, err)
	}
}

func TestGroupInstallationValidatesAnchorAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, _, _, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installationGroups(t, st, spaceID)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/spaces/" + spaceID + "/installations"
	for _, body := range []map[string]any{
		{"application_id": appID, "scope": "group"},
		{"application_id": appID, "scope": "group_tree"},
		{"application_id": appID, "scope": "space", "anchor_group_id": "grp_install_root"},
		{"application_id": appID, "scope": "space_tree", "anchor_group_id": "grp_install_root"},
	} {
		out := installationHTTP(t, handler, tokens.AccessToken, http.MethodPost, path, body)
		if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "VALIDATION_FAILED") {
			t.Fatalf("invalid anchor combination=%v: %d %s", body, out.Code, out.Body.String())
		}
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": spaceID, "application_id": appID, "scope": "group_tree", "anchor_group_id": "grp_install_root",
	})
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_group_install_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.install' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_group_install_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_group_install_audit()`); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"application_id": appID, "scope": "group_tree", "anchor_group_id": "grp_install_root"}
	if out := installationHTTP(t, handler, tokens.AccessToken, http.MethodPost, path, body); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("installation committed without audit: %d %s", out.Code, out.Body.String())
	}
	var count int
	var proofRemains bool
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE type = 'application' AND space_id = $1`, spaceID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit rollback left application members=%d error=%v", count, err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT step_up_operation = 'installations.create' FROM sessions WHERE id = $1`, tokens.SessionID).Scan(&proofRemains); err != nil || !proofRemains {
		t.Fatalf("failed installation consumed step-up: remains=%v error=%v", proofRemains, err)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_group_install_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if out := installationHTTP(t, handler, tokens.AccessToken, http.MethodPost, path, body); out.Code != http.StatusOK {
		t.Fatalf("retry with same proof after rollback = %d %s", out.Code, out.Body.String())
	}
}

func TestGroupInstallationOverlapIsSerialized(t *testing.T) {
	for _, otherScope := range []string{"space", "space_tree", "group", "group_tree"} {
		t.Run(otherScope, func(t *testing.T) {
			ctx := context.Background()
			st, _, apps, actorID, spaceID, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
			installationGroups(t, st, spaceID)
			otherAnchor := ""
			if otherScope == "group" || otherScope == "group_tree" {
				otherAnchor = "grp_install_other"
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, input := range []struct{ scope, anchor string }{{"group_tree", "grp_install_root"}, {otherScope, otherAnchor}} {
				go func() {
					<-start
					_, err := apps.Install(ctx, actorID, appID, spaceID, input.scope, input.anchor)
					results <- err
				}()
			}
			close(start)
			first, second := <-results, <-results
			if (first == nil) == (second == nil) {
				t.Fatalf("concurrent installations: first=%v second=%v", first, second)
			}
			if first != nil {
				assertPrincipalError(t, first, "CONFLICT")
			} else {
				assertPrincipalError(t, second, "CONFLICT")
			}
			var installations, members, roles int
			if err := st.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM application_installations WHERE application_id = $1),
				(SELECT count(*) FROM members WHERE space_id = $2 AND type = 'application'),
				(SELECT count(*) FROM roles WHERE space_id = $2 AND name LIKE 'application:ins_%')`, appID, spaceID).Scan(&installations, &members, &roles); err != nil || installations != 1 || members != 1 || roles != 1 {
				t.Fatalf("concurrent install left installations=%d members=%d roles=%d error=%v", installations, members, roles, err)
			}
		})
	}
}

func TestAncestorTreeInstallationExcludesDescendantGroupInstallation(t *testing.T) {
	for _, firstScope := range []string{"group", "group_tree", "space_tree"} {
		t.Run(firstScope, func(t *testing.T) {
			ctx := context.Background()
			st, authz, apps, parentActor, parentSpace, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
			child, childActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Group child", "group-install-child")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, parentSpace, child.ID); err != nil {
				t.Fatal(err)
			}
			seedTestInlineGrant(t, st, child.ID, childActor.ID, childActor.ID, "auth.applications:manage")
			installationGroups(t, st, child.ID)
			if firstScope == "space_tree" {
				if _, err := apps.Install(ctx, parentActor, appID, parentSpace, "space_tree", ""); err != nil {
					t.Fatal(err)
				}
				for _, scope := range []string{"group", "group_tree"} {
					_, err := apps.Install(ctx, childActor.ID, appID, child.ID, scope, "grp_install_root")
					assertPrincipalError(t, err, "CONFLICT")
				}
			} else {
				if _, err := apps.Install(ctx, childActor.ID, appID, child.ID, firstScope, "grp_install_root"); err != nil {
					t.Fatal(err)
				}
				_, err := apps.Install(ctx, parentActor, appID, parentSpace, "space_tree", "")
				assertPrincipalError(t, err, "CONFLICT")
			}
		})
	}
}
