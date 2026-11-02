package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func manifestChildInstallation(t *testing.T, st *store.Store, authz *authorization.Service, apps *application.Service, appID, parentSpace string) (string, string, application.Installation) {
	t.Helper()
	ctx := context.Background()
	child, actor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Manifest child", "manifest-child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, parentSpace, child.ID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, child.ID, actor.ID, actor.ID, "auth.applications:manage")
	installed, err := apps.InstallPrivateSpace(ctx, actor.ID, appID, child.ID)
	if err != nil {
		t.Fatal(err)
	}
	return child.ID, actor.ID, installed
}

func manifestToken(t *testing.T, sessions *session.Service, memberID string) string {
	t.Helper()
	tokens, err := sessions.CreateForMember(context.Background(), "usr_principal_actor", memberID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	return tokens.AccessToken
}

func patchApplication(t *testing.T, handler http.Handler, appID, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPatch, "/v1/applications/"+appID, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func approveManifest(t *testing.T, handler http.Handler, spaceID, installationID, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/v1/spaces/"+spaceID+"/installations/"+installationID+"/approvals", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestManifestShrinkImmediatelyNarrowsEveryInstallationAndKey(t *testing.T) {
	ctx := context.Background()
	const checkPermission, introspectPermission = "auth.authz:check", "auth.tokens:introspect"
	st, authz, apps, actorID, rootSpace, sessions, handler, appID := installationFixture(t, []string{checkPermission, introspectPermission})
	rootInstallation, err := apps.InstallPrivateSpace(ctx, actorID, appID, rootSpace)
	if err != nil {
		t.Fatal(err)
	}
	childSpace, _, childInstallation := manifestChildInstallation(t, st, authz, apps, appID, rootSpace)
	expires := time.Now().Add(time.Hour)
	key, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "manifest-key", Grants: []string{checkPermission, introspectPermission}, ExpiresAt: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeVersions := map[string]int64{}
	for _, spaceID := range []string{rootSpace, childSpace} {
		var version int64
		if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&version); err != nil {
			t.Fatal(err)
		}
		beforeVersions[spaceID] = version
	}
	token := manifestToken(t, sessions, actorID)
	shrunk := patchApplication(t, handler, appID, token, `{"manifest_permissions":["auth.authz:check"]}`)
	if shrunk.Code != http.StatusOK || !strings.Contains(shrunk.Body.String(), `"manifest_permissions":["auth.authz:check"]`) {
		t.Fatalf("manifest shrink = %d %s", shrunk.Code, shrunk.Body.String())
	}
	for _, item := range []struct {
		spaceID      string
		installation application.Installation
	}{
		{rootSpace, rootInstallation}, {childSpace, childInstallation},
	} {
		decision, _, err := authz.Check(ctx, authorization.CheckRequest{
			MemberID: item.installation.MemberID, Permission: introspectPermission, ResourceSpace: item.spaceID,
		})
		if err != nil || decision.Effect != engine.Deny {
			t.Fatalf("shrunk installation at %s still held permission: %+v, %v", item.spaceID, decision, err)
		}
		installed, err := apps.ListInstallations(ctx, item.spaceID)
		if err != nil || len(installed) != 1 || !strings.EqualFold(strings.Join(installed[0].ApprovedPermissions, ","), checkPermission) {
			t.Fatalf("installation approval after shrink at %s = %+v, %v", item.spaceID, installed, err)
		}
		var rolePermissions int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp
			JOIN application_installations i ON i.role_id = rp.role_id WHERE i.id = $1`, item.installation.ID).Scan(&rolePermissions); err != nil {
			t.Fatal(err)
		}
		if rolePermissions != 1 {
			t.Fatalf("installation role at %s retained %d permissions", item.spaceID, rolePermissions)
		}
		var version int64
		if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, item.spaceID).Scan(&version); err != nil || version <= beforeVersions[item.spaceID] {
			t.Fatalf("policy version at %s = %d, before %d, error %v", item.spaceID, version, beforeVersions[item.spaceID], err)
		}
	}
	keys, err := apps.ListManagedKeys(ctx, actorID, appID)
	if err != nil || len(keys) != 1 || !slices.Equal(keys[0].Grants, []string{checkPermission}) || keys[0].ID != key.ID {
		t.Fatalf("key grants after shrink = %+v, %v", keys, err)
	}
	expanded := patchApplication(t, handler, appID, token, `{"manifest_permissions":["auth.authz:check","auth.tokens:introspect"]}`)
	if expanded.Code != http.StatusOK {
		t.Fatalf("manifest expansion = %d %s", expanded.Code, expanded.Body.String())
	}
	for _, item := range []struct {
		spaceID      string
		installation application.Installation
	}{
		{rootSpace, rootInstallation}, {childSpace, childInstallation},
	} {
		decision, _, err := authz.Check(ctx, authorization.CheckRequest{
			MemberID: item.installation.MemberID, Permission: introspectPermission, ResourceSpace: item.spaceID,
		})
		if err != nil || decision.Effect != engine.Deny {
			t.Fatalf("manifest expansion revived unapproved authority at %s: %+v, %v", item.spaceID, decision, err)
		}
	}
	keys, err = apps.ListManagedKeys(ctx, actorID, appID)
	if err != nil || !slices.Equal(keys[0].Grants, []string{checkPermission}) {
		t.Fatalf("manifest expansion revived key grants: %+v, %v", keys, err)
	}
}

func TestManifestExpansionRequiresEachInstallationApprovalAndCoverage(t *testing.T) {
	ctx := context.Background()
	const checkPermission, introspectPermission = "auth.authz:check", "auth.tokens:introspect"
	st, authz, apps, actorID, rootSpace, sessions, handler, appID := installationFixture(t, []string{checkPermission})
	rootInstallation, err := apps.InstallPrivateSpace(ctx, actorID, appID, rootSpace)
	if err != nil {
		t.Fatal(err)
	}
	childSpace, childActor, childInstallation := manifestChildInstallation(t, st, authz, apps, appID, rootSpace)
	rootToken := manifestToken(t, sessions, actorID)
	childToken := manifestToken(t, sessions, childActor)
	if updated := patchApplication(t, handler, appID, rootToken, `{"manifest_permissions":["auth.authz:check","auth.tokens:introspect"]}`); updated.Code != http.StatusOK {
		t.Fatalf("manifest expansion = %d %s", updated.Code, updated.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	denied := approveManifest(t, handler, rootSpace, rootInstallation.ID, rootToken)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("uncovered approval = %d %s", denied.Code, denied.Body.String())
	}
	var approved []byte
	if err := st.Pool.QueryRow(ctx, `SELECT approved_permissions FROM application_installations WHERE id = $1`, rootInstallation.ID).Scan(&approved); err != nil {
		t.Fatal(err)
	}
	if string(approved) != `["auth.authz:check"]` {
		t.Fatalf("failed approval changed installation: %s", approved)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if approved := approveManifest(t, handler, rootSpace, rootInstallation.ID, rootToken); approved.Code != http.StatusOK {
		t.Fatalf("root approval = %d %s", approved.Code, approved.Body.String())
	}
	for _, item := range []struct {
		spaceID, memberID string
		want              engine.Effect
	}{
		{rootSpace, rootInstallation.MemberID, engine.Allow},
		{childSpace, childInstallation.MemberID, engine.Deny},
	} {
		decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: item.memberID, Permission: introspectPermission, ResourceSpace: item.spaceID})
		if err != nil || decision.Effect != item.want {
			t.Fatalf("approval authority at %s = %+v, %v, want %s", item.spaceID, decision, err, item.want)
		}
	}
	if wrongSpace := approveManifest(t, handler, rootSpace, childInstallation.ID, rootToken); wrongSpace.Code != http.StatusNotFound {
		t.Fatalf("approval accepted mismatched Space: %d %s", wrongSpace.Code, wrongSpace.Body.String())
	}
	if approved := approveManifest(t, handler, childSpace, childInstallation.ID, childToken); approved.Code != http.StatusOK {
		t.Fatalf("child approval = %d %s", approved.Code, approved.Body.String())
	}
	if repeated := approveManifest(t, handler, childSpace, childInstallation.ID, childToken); repeated.Code != http.StatusOK {
		t.Fatalf("repeated approval = %d %s", repeated.Code, repeated.Body.String())
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: childInstallation.MemberID, Permission: introspectPermission, ResourceSpace: childSpace})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("child approval did not add authority: %+v, %v", decision, err)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.installation.approve' AND resource_id IN ($1, $2)`, rootInstallation.ID, childInstallation.ID).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("approval audit count=%d error=%v", audits, err)
	}
}

func TestManifestUpdateAndApprovalAuditFailuresRollBack(t *testing.T) {
	ctx := context.Background()
	const checkPermission, introspectPermission = "auth.authz:check", "auth.tokens:introspect"
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{checkPermission, introspectPermission})
	installed, err := apps.InstallPrivateSpace(ctx, actorID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if _, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "rollback-key", Grants: []string{checkPermission, introspectPermission}, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	var versionBefore int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_manifest_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action IN ('application.update', 'application.installation.approve') THEN
				RAISE EXCEPTION 'audit rejected';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_manifest_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_manifest_audit();
	`); err != nil {
		t.Fatal(err)
	}
	shrunk := patchApplication(t, handler, appID, token, `{"manifest_permissions":["auth.authz:check"]}`)
	if shrunk.Code < 500 {
		t.Fatalf("manifest shrink committed despite audit failure: %d %s", shrunk.Code, shrunk.Body.String())
	}
	var manifest, approved, keyGrants []byte
	var roleCount int
	var versionAfter int64
	if err := st.Pool.QueryRow(ctx, `SELECT manifest_permissions FROM applications WHERE id = $1`, appID).Scan(&manifest); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT approved_permissions FROM application_installations WHERE id = $1`, installed.ID).Scan(&approved); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT scopes FROM api_keys WHERE application_id = $1`, appID).Scan(&keyGrants); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp JOIN application_installations i ON i.role_id = rp.role_id WHERE i.id = $1`, installed.ID).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionAfter); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), introspectPermission) || !strings.Contains(string(approved), introspectPermission) ||
		!strings.Contains(string(keyGrants), introspectPermission) || roleCount != 2 || versionAfter != versionBefore {
		t.Fatalf("audit failure changed manifest=%s approved=%s key=%s role_count=%d policy=%d (before %d)",
			manifest, approved, keyGrants, roleCount, versionAfter, versionBefore)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_manifest_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"manifest_permissions":["auth.authz:check"]}`,
		`{"manifest_permissions":["auth.authz:check","auth.tokens:introspect"]}`,
	} {
		if response := patchApplication(t, handler, appID, token, body); response.Code != http.StatusOK {
			t.Fatalf("preparing approval audit test = %d %s", response.Code, response.Body.String())
		}
	}
	if _, err := st.Pool.Exec(ctx, `CREATE TRIGGER reject_manifest_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_manifest_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	approval := approveManifest(t, handler, spaceID, installed.ID, token)
	if approval.Code < 500 {
		t.Fatalf("installation approval committed despite audit failure: %d %s", approval.Code, approval.Body.String())
	}
	if err := st.Pool.QueryRow(ctx, `SELECT approved_permissions FROM application_installations WHERE id = $1`, installed.ID).Scan(&approved); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp JOIN application_installations i ON i.role_id = rp.role_id WHERE i.id = $1`, installed.ID).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionAfter); err != nil {
		t.Fatal(err)
	}
	if string(approved) != `["auth.authz:check"]` || roleCount != 1 || versionAfter != versionBefore {
		t.Fatalf("approval audit failure changed approved=%s role_count=%d policy=%d (before %d)", approved, roleCount, versionAfter, versionBefore)
	}
}

func TestApplicationMetadataPatchValidatesFieldsAndAuthority(t *testing.T) {
	ctx := context.Background()
	st, _, _, actorID, _, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	token := manifestToken(t, sessions, actorID)
	updated := patchApplication(t, handler, appID, token, `{"name":"Updated Billing","redirect_uris":["https://client.example/callback"]}`)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"name":"Updated Billing"`) ||
		!strings.Contains(updated.Body.String(), `"redirect_uris":["https://client.example/callback"]`) {
		t.Fatalf("metadata patch = %d %s", updated.Code, updated.Body.String())
	}
	if empty := patchApplication(t, handler, appID, token, `{}`); empty.Code != http.StatusBadRequest {
		t.Fatalf("empty metadata patch = %d %s", empty.Code, empty.Body.String())
	}
	if badRedirect := patchApplication(t, handler, appID, token, `{"redirect_uris":["http://external.example/callback"]}`); badRedirect.Code != http.StatusBadRequest {
		t.Fatalf("unsafe redirect patch = %d %s", badRedirect.Code, badRedirect.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1 AND permission_keys @> '["auth.applications:manage"]'::jsonb`, actorID); err != nil {
		t.Fatal(err)
	}
	if denied := patchApplication(t, handler, appID, token, `{"name":"Unauthorized"}`); denied.Code != http.StatusForbidden {
		t.Fatalf("metadata patch without authority = %d %s", denied.Code, denied.Body.String())
	}
	var name string
	if err := st.Pool.QueryRow(ctx, `SELECT name FROM applications WHERE id = $1`, appID).Scan(&name); err != nil || name != "Updated Billing" {
		t.Fatalf("denied patch changed name=%q error=%v", name, err)
	}
}

func TestAgentApplicationUpdateUsesOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, _, _, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{
		OwnerMemberID: ownerID, Name: "manifest-agent", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, ownerID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if updated := patchApplication(t, handler, appID, access.AccessToken, `{"name":"Agent managed"}`); updated.Code != http.StatusOK {
		t.Fatalf("Agent application update = %d %s", updated.Code, updated.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1 AND permission_keys @> '["auth.applications:manage"]'::jsonb`, ownerID); err != nil {
		t.Fatal(err)
	}
	denied := patchApplication(t, handler, appID, access.AccessToken, `{"name":"Owner excluded"}`)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent updated outside owner envelope: %d %s", denied.Code, denied.Body.String())
	}
}

func TestManifestShrinkSerializesConcurrentKeyCreation(t *testing.T) {
	ctx := context.Background()
	_, _, apps, actorID, _, _, _, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
	manifest := []string{"auth.authz:check"}
	start := make(chan struct{})
	updateResult := make(chan error, 1)
	keyResult := make(chan error, 1)
	go func() {
		<-start
		_, err := apps.UpdatePrivate(ctx, actorID, appID, application.UpdateInput{ManifestPermissions: &manifest})
		updateResult <- err
	}()
	go func() {
		<-start
		_, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
			Name: "concurrent-key", Grants: []string{"auth.tokens:introspect"}, ExpiresAt: time.Now().Add(time.Hour),
		})
		keyResult <- err
	}()
	close(start)
	if err := <-updateResult; err != nil {
		t.Fatalf("concurrent manifest shrink: %v", err)
	}
	if err := <-keyResult; err != nil {
		assertPrincipalError(t, err, "GRANT_EXCEEDS_OWNER")
	}
	keys, err := apps.ListManagedKeys(ctx, actorID, appID)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if slices.Contains(key.Grants, "auth.tokens:introspect") {
			t.Fatalf("concurrent key retained permission removed from manifest: %+v", key)
		}
	}
}

func TestSpaceTreeManifestApprovalRequiresSubtreeAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallPrivate(ctx, actorID, appID, spaceID, "space_tree")
	if err != nil {
		t.Fatal(err)
	}
	childSpace := "spc_manifest_tree_child"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id) VALUES ($1, 'Manifest tree child', 'manifest-tree-child', $2)`, childSpace, spaceID); err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	if expanded := patchApplication(t, handler, appID, token, `{"manifest_permissions":["auth.authz:check","auth.tokens:introspect"]}`); expanded.Code != http.StatusOK {
		t.Fatalf("tree manifest expansion = %d %s", expanded.Code, expanded.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = false WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	denied := approveManifest(t, handler, spaceID, installed.ID, token)
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("tree approval without subtree right = %d %s", denied.Code, denied.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = true WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if approved := approveManifest(t, handler, spaceID, installed.ID, token); approved.Code != http.StatusOK {
		t.Fatalf("tree approval with subtree right = %d %s", approved.Code, approved.Body.String())
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{
		MemberID: installed.MemberID, Permission: "auth.tokens:introspect", ResourceSpace: childSpace,
	})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("tree approval did not cover child Space: %+v, %v", decision, err)
	}
}
