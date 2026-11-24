//go:build interop

package protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/pquerna/otp/totp"
)

func TestKeycloakDirectoryGroupControlsEmployeeSessionAccess(t *testing.T) {
	const adminID = "usr_sso_http_owner"
	const email = "employee@workforce.example.test"
	const jsonType = "application/json"
	const scimType = "application/scim+json"
	ctx := t.Context()
	st, authz, svc, owner, spaceID, _ := newSSOHTTPFixture(t)
	sessions := svc.Sessions
	sessions.Factors = &factor.Service{Store: st, DataKey: svc.DataKey}
	sessions.SpaceSignInPolicy = svc
	svc.StepUp, authz.StepUp = sessions, sessions
	mux := http.NewServeMux()
	(&principal.API{Authorization: authz, Sessions: sessions, Enterprise: svc}).Register(
		humago.New(mux, route.HumaConfig("Directory-authorized workforce", "1")))
	(HTTP{Enterprise: svc}).Register(mux)
	host := httptest.NewTLSServer(route.Middleware(route.Principal, mux))
	t.Cleanup(host.Close)
	callback := host.URL + "/oidc/return"
	issuer, transport := keycloakFixture(t, callback)
	t.Cleanup(transport.CloseIdleConnections)
	svc.HTTPClient = &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	admin := authorization.WithHumanActor(ctx, owner.ID, adminID)
	connection, err := svc.CreateConnection(admin, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Keycloak Workforce", Provider: "oidc", Issuer: issuer,
		ClientID: keycloakClientID, ClientSecret: keycloakClientSecret, RedirectURI: callback,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := svc.CreateDirectory(admin, owner.ID, spaceID, enterprise.DirectoryInput{
		Name: "Workforce", SSOConnectionID: connection.ID, SSOIdentityClaim: "sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	role, err := authz.CreateRole(admin, owner.ID, spaceID, "Audit readers", "", []string{"auth.audit:read"})
	if err != nil {
		t.Fatal(err)
	}

	client := employeeLifecycleClient{server: host}
	scim := "/scim/v2/" + directory.ID
	provision := func(collection string, payload map[string]any) scimTestResource {
		t.Helper()
		response := client.send(t, http.MethodPost, scim+collection, directory.Token.Value(), scimType, "", payload)
		response.requireStatus(t, http.StatusCreated)
		var resource scimTestResource
		if err := json.Unmarshal(response.body, &resource); err != nil || resource.ID == "" || resource.Meta.Version == "" {
			t.Fatal("SCIM did not return a versioned resource")
		}
		return resource
	}
	employee := provision("/Users", map[string]any{"externalId": keycloakEmployeeID, "userName": email, "active": true})
	group := provision("/Groups", map[string]any{"externalId": "audit-readers", "displayName": "Audit readers"})

	adminSession, err := sessions.CreateForMember(ctx, adminID, owner.ID, nil, "directory membership test", 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := sessions.Factors.BeginTOTP(ctx, adminID, "sso-http-owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request := authorization.DirectoryGroupGrantRequest(spaceID, directory.ID, group.ID, authorization.GrantInput{RoleID: role.ID})
	client.send(t, http.MethodPost, "/v1/auth/step-up", adminSession.AccessToken, jsonType, "", map[string]any{
		"operation": authorization.DirectoryGroupGrantOperation, "request": request, "mfa_code": code,
	}).requireStatus(t, http.StatusOK)
	space := "/v1/spaces/" + spaceID
	grantPath := space + "/directories/" + directory.ID + "/groups/" + group.ID + "/grants"
	client.send(t, http.MethodPost, grantPath, adminSession.AccessToken, jsonType, "", map[string]string{
		"role_id": role.ID,
	}).requireStatus(t, http.StatusOK)

	login := "/v1/sso/" + connection.ID
	start := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, login+"/start", "", "", "", nil))
	returned := keycloakAuthorize(t, transport, start.AuthorizationURL, callback, "original")
	signedIn := employeeLifecycleData[account.AuthResult](t, client.send(t, http.MethodPost, login+"/callback", "", jsonType, "", map[string]string{
		"state": returned.Get("state"), "code": returned.Get("code"), "redirect_uri": callback,
	}))
	if signedIn.Tokens == nil || signedIn.User.Email != email {
		t.Fatal("Keycloak login did not establish the SCIM-provisioned identity")
	}
	checkAccess := func(want int) {
		t.Helper()
		client.send(t, http.MethodGet, space+"/audit-logs", signedIn.Tokens.AccessToken, "", "", nil).requireStatus(t, want)
	}
	updateGroup := func(version string, want int, operations ...map[string]any) employeeLifecycleResponse {
		t.Helper()
		response := client.send(t, http.MethodPatch, scim+"/Groups/"+group.ID, directory.Token.Value(), scimType, version, map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": operations,
		})
		response.requireStatus(t, want)
		return response
	}
	checkAccess(http.StatusForbidden)
	add := map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"Value": employee.ID, "Type": "user"}}}
	nested := map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"value": employee.ID, "type": "Group"}}}
	updateGroup(group.Meta.Version, http.StatusBadRequest, add, nested)
	checkAccess(http.StatusForbidden)
	admitted := updateGroup(group.Meta.Version, http.StatusOK, add)
	if admitted.etag == "" || admitted.etag == group.Meta.Version {
		t.Fatal("admission did not advance the directory group version")
	}
	checkAccess(http.StatusOK)
	remove := map[string]any{"op": "remove", "path": "members[value eq " + strconv.Quote(employee.ID) + "]"}
	updateGroup(group.Meta.Version, http.StatusPreconditionFailed, remove)
	checkAccess(http.StatusOK)
	updateGroup(admitted.etag, http.StatusOK, remove)
	checkAccess(http.StatusForbidden)
	client.send(t, http.MethodGet, "/v1/me/members", signedIn.Tokens.AccessToken, "", "", nil).requireStatus(t, http.StatusOK)

	var updates int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='scim.group.update'
		AND actor_id=$1 AND resource_id=$2 AND outcome='success'`, directory.ID, group.ID).Scan(&updates); err != nil || updates != 2 {
		t.Fatalf("expected admission and removal audit events, got %d: %v", updates, err)
	}
}
