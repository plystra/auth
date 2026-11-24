package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/stepup"
)

func TestSSORoleMappingUpdatePreservesIndependentAssignmentAuthority(t *testing.T) {
	f := newJITMappingFixture(t, false)
	ctx := t.Context()
	const updaterUser = "usr_sso_mapping_updater"
	if _, err := f.st.Pool.Exec(ctx, `INSERT INTO users(id,email,email_normalized,password_hash,status)
		VALUES ($1,'mapping-updater@example.test','mapping-updater@example.test','unused','active')`, updaterUser); err != nil {
		t.Fatal(err)
	}
	updater, err := f.st.Queries().CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
		ID: "mem_sso_mapping_updater", SpaceID: f.space, Name: "Mapping updater", Type: "human", BindingPolicy: "single",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Queries().LinkUserMember(ctx, db.LinkUserMemberParams{UserID: updaterUser, MemberID: updater.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `INSERT INTO authorization_grants(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_sso_mapping_updater',$1,'["auth.connections:manage","auth.grants:assign"]',$2,'space',$1,$3)`, f.space, updater.ID, f.owner); err != nil {
		t.Fatal(err)
	}
	const op = enterprise.SSOConnectionUpdateOperation
	oldTag := f.connection.ETag()
	initial := f.login(t, "existing-before-mapping-change", "engineering")
	f.svc.StepUp = f.svc.Sessions
	admin, err := f.svc.Sessions.CreateForMember(ctx, updaterUser, updater.ID, nil, "SSO mapping management", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&principal.API{Authorization: f.svc.Authorization, Sessions: f.svc.Sessions, Enterprise: f.svc}).Register(
		humago.New(mux, route.HumaConfig("Enterprise mapping management", "1")))
	host := httptest.NewTLSServer(route.Middleware(route.Principal, mux))
	t.Cleanup(host.Close)
	client := employeeLifecycleClient{server: host}
	proved := func(tag string, mappings map[string]string) {
		t.Helper()
		digest, err := stepup.DigestValue(enterprise.SSORoleMappingUpdateRequest(f.space, f.connection.ID, tag, mappings))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2, step_up_digest=$3,
			step_up_method='totp', step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, admin.SessionID, op, digest); err != nil {
			t.Fatal(err)
		}
	}
	patch := func(tag string, mappings map[string]string) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPatch, "/v1/spaces/"+f.space+"/sso-connections/"+f.connection.ID,
			admin.AccessToken, "application/json", tag, map[string]any{"role_mappings": mappings})
	}
	mappings := map[string]string{"engineering": f.role, "platform": f.role, "managed-update": f.role}
	proved(oldTag, mappings)
	patch(oldTag, map[string]string{"engineering": f.role}).requireStatus(t, http.StatusForbidden)
	patch(oldTag, mappings).requireError(t, http.StatusForbidden, "AUTHORITY_DELTA_NOT_COVERED")
	right, err := f.svc.Authorization.CreateAssignmentRight(ctx, f.owner, f.space, updater.ID, []string{"auth.members:read"}, f.space, "", false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `CREATE FUNCTION reject_sso_mapping_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='sso.connection.role_mappings.update' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_sso_mapping_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_sso_mapping_audit()`); err != nil {
		t.Fatal(err)
	}
	patch(oldTag, mappings).requireStatus(t, http.StatusServiceUnavailable)
	if _, err := f.st.Pool.Exec(ctx, `DROP TRIGGER reject_sso_mapping_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{}, 1)
	defer close(release)
	inFlight := f.startWithExchange(t, "in-flight-before-mapping-change", []string{"engineering"}, func(ctx context.Context) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	callbackCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	completed := make(chan error, 1)
	go func() {
		_, err := f.svc.Callback(callbackCtx, inFlight)
		completed <- err
	}()
	select {
	case <-entered:
	case <-callbackCtx.Done():
		t.Fatal("the in-flight login did not reach its upstream exchange")
	}
	beforeUpdate := f.counts(t)
	updated := patch(oldTag, mappings)
	connection := employeeLifecycleData[enterprise.Connection](t, updated)
	if updated.etag == oldTag || updated.etag == "" || connection.ID != f.connection.ID || connection.RoleMappings["managed-update"] != f.role {
		t.Fatal("updating the mapping did not return the current connection and version")
	}
	release <- struct{}{}
	select {
	case err := <-completed:
		f.assertDenied(t, err, "conflict", beforeUpdate)
	case <-callbackCtx.Done():
		t.Fatal("the in-flight login did not finish after the mapping update")
	}
	proved(oldTag, mappings)
	patch(oldTag, mappings).requireStatus(t, http.StatusPreconditionFailed)
	if member := f.login(t, "new-mapping-member", "engineering", "managed-update"); f.grantCount(t, member) != 1 {
		t.Fatal("two matched sources duplicated the same role grant")
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at=now() WHERE id=$1`, right.ID); err != nil {
		t.Fatal(err)
	}
	if member := f.login(t, "original-source-still-valid", "engineering"); f.grantCount(t, member) != 1 {
		t.Fatal("the update replaced the source of an unchanged mapping")
	}
	in := f.start(t, "changed-source-revoked", "engineering", "managed-update")
	before := f.counts(t)
	_, err = f.svc.Callback(ctx, in)
	f.assertDenied(t, err, "AUTHORITY_DELTA_NOT_COVERED", before)
	cleared := map[string]string{}
	proved(updated.etag, cleared)
	final := employeeLifecycleData[enterprise.Connection](t, patch(updated.etag, cleared))
	if len(final.RoleMappings) != 0 || f.grantCount(t, initial) != 1 {
		t.Fatal("clearing mappings changed already granted roles")
	}
	if member := f.login(t, "future-without-mapping", "engineering", "managed-update"); f.grantCount(t, member) != 0 {
		t.Fatal("a removed mapping granted a role")
	}
	var auditCount int
	if err := f.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='sso.connection.role_mappings.update'
		AND resource_id=$1 AND member_id=$2 AND metadata::text NOT LIKE '%managed-update%'`, f.connection.ID, updater.ID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("expected two attributed audit records without group names, records=%d err=%v", auditCount, err)
	}
}
