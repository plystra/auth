package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func installationFixture(t *testing.T, manifest []string) (*store.Store, *authorization.Service, *application.Service, string, string, *session.Service, http.Handler, string) {
	t.Helper()
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, actor.ID, actor.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions, HMACKeys: [][]byte{[]byte(strings.Repeat("k", 32))}}
	registered, err := apps.RegisterPrivate(ctx, actor.ID, application.RegisterInput{
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
	if _, err := apps.InstallPrivateSpace(ctx, actorID, appID, spaceID); err == nil {
		t.Fatal("uncovered application installation was allowed")
	} else {
		assertPrincipalError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM application_installations WHERE application_id = $1`, appID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("uncovered installation committed: count=%d error=%v", count, err)
	}
	st2, _, apps2, actor2, space2, _, _, ineligibleApp := installationFixture(t, []string{"auth.applications:manage"})
	if _, err := apps2.InstallPrivateSpace(ctx, actor2, ineligibleApp, space2); err == nil {
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
	if _, err := apps.InstallPrivateSpace(ctx, otherActor.ID, appID, otherSpace.ID); err == nil {
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
	if _, err := apps.InstallPrivateSpace(ctx, actorID, appID, publisherSpace); err == nil {
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
