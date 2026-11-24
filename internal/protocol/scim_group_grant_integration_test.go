package protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/pquerna/otp/totp"
)

func TestDirectoryGroupRoleGrantAuthorizesFutureSCIMMembership(t *testing.T) {
	const adminUser = "usr_sso_http_owner"
	const permission = "auth.audit:read"
	const jsonType = "application/json"
	const scimType = "application/scim+json"
	ctx := t.Context()
	st, authz, svc, owner, spaceID, _ := newSSOHTTPFixture(t)
	sessions := svc.Sessions
	sessions.Factors = &factor.Service{Store: st, DataKey: svc.DataKey}
	authz.StepUp = sessions
	adminCtx := authorization.WithHumanActor(ctx, owner.ID, adminUser)
	directory, err := svc.CreateDirectory(adminCtx, owner.ID, spaceID, enterprise.DirectoryInput{Name: "Workforce"})
	if err != nil {
		t.Fatal(err)
	}
	role, err := authz.CreateRole(adminCtx, owner.ID, spaceID, "Directory audit viewer", "", []string{permission})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sessions.CreateForMember(ctx, adminUser, owner.ID, nil, "directory grant test", 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := sessions.Factors.BeginTOTP(ctx, adminUser, "sso-http-owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&principal.API{Authorization: authz, Sessions: sessions, Enterprise: svc}).Register(humago.New(mux, route.HumaConfig("Directory grants", "1")))
	(HTTP{Enterprise: svc}).Register(mux)
	host := httptest.NewTLSServer(route.Middleware(route.Principal, mux))
	t.Cleanup(host.Close)
	client := employeeLifecycleClient{server: host}
	spacePath := "/v1/spaces/" + spaceID
	scimPath := "/scim/v2/" + directory.ID
	provision := func(kind string, in map[string]any) scimTestResource {
		t.Helper()
		response := client.send(t, http.MethodPost, scimPath+"/"+kind, directory.Token.Value(), scimType, "", in)
		response.requireStatus(t, http.StatusCreated)
		var resource scimTestResource
		if err := json.Unmarshal(response.body, &resource); err != nil || resource.ID == "" {
			t.Fatal("directory did not return the created resource")
		}
		return resource
	}
	group := provision("Groups", map[string]any{"externalId": "audit", "displayName": "Directory Audit"})
	user := provision("Users", map[string]any{"externalId": "worker", "userName": "worker@example.test", "active": true})
	var groupID, userID, memberID string
	if err := st.Pool.QueryRow(ctx, `SELECT group_id FROM directory_groups WHERE id=$1`, group.ID).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT user_id,member_id FROM directory_users WHERE id=$1`, user.ID).Scan(&userID, &memberID); err != nil {
		t.Fatal(err)
	}
	grantPath := spacePath + "/directories/" + directory.ID + "/groups/" + group.ID + "/grants"
	grant := func(payload map[string]string) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPost, grantPath, admin.AccessToken, jsonType, "", payload)
	}
	body := map[string]string{"role_id": role.ID}
	grant(body).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	client.send(t, http.MethodPost, spacePath+"/grants", admin.AccessToken, jsonType, "", map[string]any{
		"grantee": map[string]string{"group_id": groupID}, "role_id": role.ID,
	}).requireError(t, http.StatusBadRequest, "VALIDATION_FAILED")
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	client.send(t, http.MethodPost, "/v1/auth/step-up", admin.AccessToken, jsonType, "", map[string]any{
		"operation": authorization.DirectoryGroupGrantOperation, "mfa_code": code,
		"request": authorization.DirectoryGroupGrantRequest(spaceID, directory.ID, group.ID, authorization.GrantInput{RoleID: role.ID}),
	}).requireStatus(t, http.StatusOK)
	grant(map[string]string{"role_id": role.ID, "scope": "self"}).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$1`, owner.ID)
	grant(body).requireError(t, http.StatusForbidden, "AUTHORITY_DELTA_NOT_COVERED")
	exec(`UPDATE assign_rights SET revoked_at=NULL WHERE holder_member_id=$1`, owner.ID)
	exec(`CREATE FUNCTION deny_directory_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='directory.group.grant.create' THEN RAISE EXCEPTION 'owned test fault'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER deny_directory_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION deny_directory_grant_audit()`)
	grant(body).requireStatus(t, http.StatusServiceUnavailable)
	var leakedGrants int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_group_id=$1`, groupID).Scan(&leakedGrants); err != nil || leakedGrants != 0 {
		t.Fatal("failed directory grant changed persisted authority")
	}
	exec(`DROP TRIGGER deny_directory_grant_audit ON audit_logs`)
	created := employeeLifecycleData[authorization.Grant](t, grant(body))
	if created.GranteeGroupID != groupID || created.RoleID != role.ID || created.Scope != "space" {
		t.Fatal("directory role did not bind to the exact native group")
	}
	grant(body).requireError(t, http.StatusForbidden, "STEP_UP_REQUIRED")
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='directory.group.grant.create'
		AND outcome='success' AND resource_id=$1 AND metadata->>'directory_id'=$2`, created.ID, directory.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("directory role grant did not commit its own audit event")
	}
	worker, err := sessions.CreateForMember(ctx, userID, memberID, nil, "directory worker test", 1)
	if err != nil {
		t.Fatal(err)
	}
	canReadAudit := func(status int) {
		t.Helper()
		client.send(t, http.MethodGet, spacePath+"/audit-logs", worker.AccessToken, "", "", nil).requireStatus(t, status)
	}
	canReadAudit(http.StatusForbidden)
	patch := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]string{{"value": user.ID}}}},
	}
	updateGroup := func(version string, status int) employeeLifecycleResponse {
		t.Helper()
		response := client.send(t, http.MethodPatch, scimPath+"/Groups/"+group.ID, directory.Token.Value(), scimType, version, patch)
		response.requireStatus(t, status)
		return response
	}
	exec(`UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$1`, owner.ID)
	updateGroup(group.Meta.Version, http.StatusForbidden)
	canReadAudit(http.StatusForbidden)
	exec(`UPDATE assign_rights SET revoked_at=NULL WHERE holder_member_id=$1`, owner.ID)
	updateGroup(group.Meta.Version, http.StatusOK)
	canReadAudit(http.StatusOK)
	client.send(t, http.MethodDelete, spacePath+"/grants/"+created.ID, admin.AccessToken, "", "", nil).requireStatus(t, http.StatusOK)
	canReadAudit(http.StatusForbidden)
}
