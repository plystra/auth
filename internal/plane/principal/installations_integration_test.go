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
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func installationFixture(t *testing.T, manifest []string) (*store.Store, *authorization.Service, *application.Service, string, string, *session.Service, http.Handler, string) {
	t.Helper()
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, actor.ID, actor.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions, HMACKeys: [][]byte{[]byte(strings.Repeat("k", 32))}}
	registered, err := apps.Register(ctx, actor.ID, application.RegisterInput{
		SpaceID: spaceID, Name: "Billing", ManifestPermissions: manifest,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("installation test", "1.0.0")))
	return st, authz, apps, actor.ID, spaceID, sessions, route.Middleware(route.Principal, mux), registered.ID
}

func postInstallation(t *testing.T, handler http.Handler, spaceID, appID, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/installations", strings.NewReader(`{"application_id":"`+appID+`"}`))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestPrivateApplicationInstallationCreatesCoveredMemberAndSystemRole(t *testing.T) {
	ctx := context.Background()
	st, authz, _, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	missingProof := postInstallation(t, handler, spaceID, appID, tokens.AccessToken)
	if missingProof.Code != http.StatusForbidden || !strings.Contains(missingProof.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("installation without step-up = %d %s", missingProof.Code, missingProof.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": spaceID, "application_id": appID, "scope": "space",
	})
	created := postInstallation(t, handler, spaceID, appID, tokens.AccessToken)
	if created.Code != http.StatusOK {
		t.Fatalf("private application installation = %d %s", created.Code, created.Body.String())
	}
	var result struct {
		Data application.Installation `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Data.ID, "ins_") || !strings.HasPrefix(result.Data.MemberID, "mem_") || result.Data.Scope != "space" ||
		result.Data.Status != "active" || len(result.Data.ApprovedPermissions) != 1 {
		t.Fatalf("installation = %+v", result.Data)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{
		MemberID: result.Data.MemberID, Permission: "auth.authz:check", ResourceSpace: spaceID,
	})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("installed application member authorization = %+v, %v", decision, err)
	}
	var kind string
	var managed bool
	if err := st.Pool.QueryRow(ctx, `
		SELECT m.type, r.managed FROM application_installations i
		JOIN members m ON m.id = i.member_id JOIN roles r ON r.id = i.role_id
		WHERE i.id = $1
	`, result.Data.ID).Scan(&kind, &managed); err != nil {
		t.Fatal(err)
	}
	if kind != "application" || !managed {
		t.Fatalf("installation member kind=%q managed role=%v", kind, managed)
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+spaceID+"/installations", nil)
	list.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), result.Data.ID) {
		t.Fatalf("installation listing = %d %s", listed.Code, listed.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": spaceID, "application_id": appID, "scope": "space",
	})
	duplicate := postInstallation(t, handler, spaceID, appID, tokens.AccessToken)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate installation = %d %s", duplicate.Code, duplicate.Body.String())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, appID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("installation count=%d error=%v", count, err)
	}
}

func TestPrivateApplicationInstallationRejectsUncoveredDeltaAndIneligiblePermission(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.InstallSpace(ctx, actorID, appID, spaceID); err == nil {
		t.Fatal("uncovered application installation was allowed")
	} else {
		assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, appID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("uncovered installation committed: count=%d error=%v", count, err)
	}
	st2, _, apps2, actor2, space2, _, _, ineligibleApp := installationFixture(t, []string{"auth.applications:manage"})
	if _, err := apps2.InstallSpace(ctx, actor2, ineligibleApp, space2); err == nil {
		t.Fatal("application received a human and Agent-only permission")
	} else {
		assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
	if err := st2.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, ineligibleApp).Scan(&count); err != nil || count != 0 {
		t.Fatalf("ineligible permission installation committed: count=%d error=%v", count, err)
	}
}

func TestPrivateApplicationInstallationStaysInPublisherTreeAndRollsBackAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, publisherSpace, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	otherSpace, otherActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Other publisher", "other-publisher")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, otherSpace.ID, otherActor.ID, otherActor.ID, "auth.applications:manage")
	if _, err := apps.InstallSpace(ctx, otherActor.ID, appID, otherSpace.ID); err == nil {
		t.Fatal("private application was installed outside its publisher tree")
	} else {
		assertPrincipalError(t, err, "NOT_FOUND")
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_application_install_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.install' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_application_install_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_application_install_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.InstallSpace(ctx, actorID, appID, publisherSpace); err == nil {
		t.Fatal("installation committed despite audit failure")
	}
	var installations, members, roles int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, appID).Scan(&installations); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM members WHERE type = 'application' AND space_id = $1`, publisherSpace).Scan(&members); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE name LIKE 'application:ins_%' AND space_id = $1`, publisherSpace).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if installations != 0 || members != 0 || roles != 0 {
		t.Fatalf("audit failure left installation=%d member=%d role=%d", installations, members, roles)
	}
}

func TestPrivateSpaceTreeInstallationCoversDescendantsAndRejectsOverlaps(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, rootSpace, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	child, childActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Install tree child", "install-tree-child")
	if err != nil {
		t.Fatal(err)
	}
	childSpace, grandchildSpace := child.ID, "spc_install_tree_grandchild"
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, rootSpace, childSpace); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
		VALUES ($1, 'Grandchild', 'install-tree-grandchild', $2)`, grandchildSpace, childSpace); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, childSpace, childActor.ID, childActor.ID, "auth.applications:manage")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	postTree := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+rootSpace+"/installations",
			strings.NewReader(`{"application_id":"`+appID+`","scope":"space_tree"}`))
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": rootSpace, "application_id": appID, "scope": "space",
	})
	if wrongProof := postTree(); wrongProof.Code != http.StatusForbidden || !strings.Contains(wrongProof.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("space-only step-up accepted tree installation: %d %s", wrongProof.Code, wrongProof.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": rootSpace, "application_id": appID, "scope": "space_tree",
	})
	created := postTree()
	if created.Code != http.StatusOK {
		t.Fatalf("tree installation = %d %s", created.Code, created.Body.String())
	}
	var result struct {
		Data application.Installation `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.Scope != "space_tree" || result.Data.SpaceID != rootSpace {
		t.Fatalf("tree installation = %+v", result.Data)
	}
	expires := time.Now().Add(time.Hour)
	raw, err := apps.CreateKey(ctx, appID, "tree", []string{"auth.authz:check"}, &expires)
	if err != nil {
		t.Fatal(err)
	}
	key, err := apps.AuthenticateKey(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{rootSpace, childSpace, grandchildSpace} {
		memberID, code, err := apps.ResolveKeyInstallation(ctx, key, target)
		if err != nil || code != "" || memberID != result.Data.MemberID {
			t.Fatalf("tree installation at %s resolved member=%q code=%q error=%v", target, memberID, code, err)
		}
		decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: "auth.authz:check", ResourceSpace: target})
		if err != nil || decision.Effect != engine.Allow {
			t.Fatalf("tree installation authority at %s = %+v, %v", target, decision, err)
		}
	}
	if _, err := apps.InstallSpace(ctx, childActor.ID, appID, childSpace); err == nil {
		t.Fatal("child installation overlapped ancestor tree installation")
	} else {
		assertPrincipalError(t, err, "CONFLICT")
	}
	if _, err := apps.ChangeInstallationStatus(ctx, actorID, rootSpace, result.Data.ID, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.InstallSpace(ctx, childActor.ID, appID, childSpace); err != nil {
		t.Fatalf("tombstoned ancestor installation still blocked child: %v", err)
	}
}

func TestPrivateSpaceTreeInstallationRejectsUncoveredAndExistingChild(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, rootSpace, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = false WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Install(ctx, actorID, appID, rootSpace, "space_tree"); err == nil {
		t.Fatal("tree installation ignored descendant assignment coverage")
	} else {
		assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, appID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("uncovered tree installation committed count=%d error=%v", count, err)
	}
	child, childActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Install child", "install-existing-child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, rootSpace, child.ID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, child.ID, childActor.ID, childActor.ID, "auth.applications:manage")
	if _, err := apps.InstallSpace(ctx, childActor.ID, appID, child.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET covers_subtree = true WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.Install(ctx, actorID, appID, rootSpace, "space_tree"); err == nil {
		t.Fatal("tree installation overlapped existing child installation")
	} else {
		assertPrincipalError(t, err, "CONFLICT")
	}
	if _, err := apps.InstallSpace(ctx, actorID, appID, rootSpace); err != nil {
		t.Fatalf("space-only parent installation should coexist with child: %v", err)
	}
}

func TestPrivateInstallationOverlapIsSerializedAcrossScopes(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, rootActor, rootSpace, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	child, childActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Concurrent child", "concurrent-install-child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, rootSpace, child.ID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, child.ID, childActor.ID, childActor.ID, "auth.applications:manage")
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, installErr := apps.Install(ctx, rootActor, appID, rootSpace, "space_tree")
		results <- installErr
	}()
	go func() {
		<-start
		_, installErr := apps.InstallSpace(ctx, childActor.ID, appID, child.ID)
		results <- installErr
	}()
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("concurrent overlapping installations: first=%v second=%v", first, second)
	}
	if first != nil {
		assertPrincipalError(t, first, "CONFLICT")
	} else {
		assertPrincipalError(t, second, "CONFLICT")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1 AND status <> 'uninstalled'`, appID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("concurrent installations left count=%d error=%v", count, err)
	}
}

func TestInstallationLifecycleHTTPRevokesAndRestoresApplicationAuthority(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallSpace(ctx, actorID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	raw, err := apps.CreateKey(ctx, appID, "lifecycle", []string{"auth.authz:check"}, &expires)
	if err != nil {
		t.Fatal(err)
	}
	key, err := apps.AuthenticateKey(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	assertKeyInstallation := func(wantCode string) {
		t.Helper()
		memberID, code, err := apps.ResolveKeyInstallation(ctx, key, spaceID)
		if err != nil || code != wantCode || (wantCode == "" && memberID == "") {
			t.Fatalf("resolved installation member=%q code=%q error=%v, want code %q", memberID, code, err, wantCode)
		}
	}
	assertKeyInstallation("")
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	post := func(action, targetSpace string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/v1/spaces/" + targetSpace + "/installations/" + installed.ID + "/" + action
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if mismatched := post("suspend", "spc_other"); mismatched.Code != http.StatusNotFound {
		t.Fatalf("installation lifecycle accepted a mismatched Space: %d %s", mismatched.Code, mismatched.Body.String())
	}
	if suspended := post("suspend", spaceID); suspended.Code != http.StatusOK || !strings.Contains(suspended.Body.String(), `"status":"suspended"`) {
		t.Fatalf("suspend installation = %d %s", suspended.Code, suspended.Body.String())
	}
	assertKeyInstallation("APPLICATION_NOT_INSTALLED")
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: installed.MemberID, Permission: "auth.authz:check", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Deny || decision.Code != "ACTOR_MEMBER_INACTIVE" {
		t.Fatalf("suspended application member still held authority: %+v, %v", decision, err)
	}
	if repeated := post("suspend", spaceID); repeated.Code != http.StatusOK {
		t.Fatalf("repeated suspend = %d %s", repeated.Code, repeated.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET status = 'suspended' WHERE id = $1`, appID); err != nil {
		t.Fatal(err)
	}
	if blocked := post("resume", spaceID); blocked.Code != http.StatusConflict {
		t.Fatalf("resume while application is suspended = %d %s", blocked.Code, blocked.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET status = 'active' WHERE id = $1`, appID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	deniedResume := post("resume", spaceID)
	if deniedResume.Code != http.StatusForbidden || !strings.Contains(deniedResume.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("resume without assignment coverage = %d %s", deniedResume.Code, deniedResume.Body.String())
	}
	assertKeyInstallation("APPLICATION_NOT_INSTALLED")
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	if resumed := post("resume", spaceID); resumed.Code != http.StatusOK || !strings.Contains(resumed.Body.String(), `"status":"active"`) {
		t.Fatalf("resume installation = %d %s", resumed.Code, resumed.Body.String())
	}
	assertKeyInstallation("")
	if removed := post("uninstall", spaceID); removed.Code != http.StatusOK || !strings.Contains(removed.Body.String(), `"status":"uninstalled"`) {
		t.Fatalf("uninstall installation = %d %s", removed.Code, removed.Body.String())
	}
	assertKeyInstallation("APPLICATION_NOT_INSTALLED")
	if resumed := post("resume", spaceID); resumed.Code != http.StatusNotFound {
		t.Fatalf("uninstalled application was resumed: %d %s", resumed.Code, resumed.Body.String())
	}
	if repeated := post("uninstall", spaceID); repeated.Code != http.StatusOK {
		t.Fatalf("repeated uninstall = %d %s", repeated.Code, repeated.Body.String())
	}
	var memberStatus string
	var activeGrants int
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, installed.MemberID).Scan(&memberStatus); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, installed.MemberID).Scan(&activeGrants); err != nil {
		t.Fatal(err)
	}
	if memberStatus != "removed" || activeGrants != 0 {
		t.Fatalf("uninstalled member status=%q active_grants=%d", memberStatus, activeGrants)
	}
	listed, err := apps.ListInstallations(ctx, spaceID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("uninstalled installation remained listed: %+v, %v", listed, err)
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id = $1 AND action LIKE 'application.installation.%'`, installed.ID).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("lifecycle audit rows=%d error=%v, want 3", audits, err)
	}
	reinstalled, err := apps.InstallSpace(ctx, actorID, appID, spaceID)
	if err != nil || reinstalled.ID == installed.ID || reinstalled.MemberID == installed.MemberID {
		t.Fatalf("fresh installation after uninstall = %+v, %v", reinstalled, err)
	}
	assertKeyInstallation("")
}

func TestInstallationLifecycleAuditFailureRollsBackState(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallSpace(ctx, actorID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actorID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_installation_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action IN ('application.installation.suspend', 'application.installation.resume') THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_installation_lifecycle_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_installation_lifecycle_audit();
	`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/installations/"+installed.ID+"/suspend", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code < 500 {
		t.Fatalf("suspension committed despite audit failure: %d %s", response.Code, response.Body.String())
	}
	var installationStatus, memberStatus string
	if err := st.Pool.QueryRow(ctx, `SELECT i.status, m.status FROM application_installations i JOIN members m ON m.id = i.member_id WHERE i.id = $1`, installed.ID).Scan(&installationStatus, &memberStatus); err != nil {
		t.Fatal(err)
	}
	if installationStatus != "active" || memberStatus != "active" {
		t.Fatalf("audit failure left installation=%q member=%q", installationStatus, memberStatus)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_installation_lifecycle_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if _, err := apps.ChangeInstallationStatus(ctx, actorID, spaceID, installed.ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE TRIGGER reject_installation_lifecycle_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_installation_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}
	resumeRequest := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/installations/"+installed.ID+"/resume", nil)
	resumeRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resumeResponse := httptest.NewRecorder()
	handler.ServeHTTP(resumeResponse, resumeRequest)
	if resumeResponse.Code < 500 {
		t.Fatalf("resume committed despite audit failure: %d %s", resumeResponse.Code, resumeResponse.Body.String())
	}
	if err := st.Pool.QueryRow(ctx, `SELECT i.status, m.status FROM application_installations i JOIN members m ON m.id = i.member_id WHERE i.id = $1`, installed.ID).Scan(&installationStatus, &memberStatus); err != nil {
		t.Fatal(err)
	}
	if installationStatus != "suspended" || memberStatus != "suspended" {
		t.Fatalf("resume audit failure left installation=%q member=%q", installationStatus, memberStatus)
	}
}

func TestInstallationResumeWithEmptyDeltaDoesNotRequireAssignmentRight(t *testing.T) {
	ctx := context.Background()
	st, authz, apps, actorID, spaceID, _, _, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallSpace(ctx, actorID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apps.ChangeInstallationStatus(ctx, actorID, spaceID, installed.ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, installed.MemberID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actorID); err != nil {
		t.Fatal(err)
	}
	resumed, err := apps.ChangeInstallationStatus(ctx, actorID, spaceID, installed.ID, "resume")
	if err != nil || resumed.Status != "active" {
		t.Fatalf("empty-delta resume = %+v, %v", resumed, err)
	}
	decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: installed.MemberID, Permission: "auth.authz:check", ResourceSpace: spaceID})
	if err != nil || decision.Effect != engine.Deny {
		t.Fatalf("empty-delta resume restored revoked authority: %+v, %v", decision, err)
	}
}

func TestAgentInstallationLifecycleUsesOwnerEnvelope(t *testing.T) {
	ctx := context.Background()
	st, _, apps, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallSpace(ctx, ownerID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "install-agent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, ownerID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	post := func(action string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/installations/"+installed.ID+"/"+action, nil)
		req.Header.Set("Authorization", "Bearer "+access.AccessToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if suspended := post("suspend"); suspended.Code != http.StatusOK {
		t.Fatalf("Agent suspension = %d %s", suspended.Code, suspended.Body.String())
	}
	if uncovered := post("resume"); uncovered.Code != http.StatusForbidden {
		t.Fatalf("Agent resumed installation without assignment coverage: %d %s", uncovered.Code, uncovered.Body.String())
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = $1 AND permission_keys @> '["auth.applications:manage"]'::jsonb`, ownerID); err != nil {
		t.Fatal(err)
	}
	if denied := post("resume"); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent resumed after owner lost governance permission: %d %s", denied.Code, denied.Body.String())
	}
	var status string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM application_installations WHERE id = $1`, installed.ID).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("owner envelope denial left installation status=%q error=%v", status, err)
	}
}
