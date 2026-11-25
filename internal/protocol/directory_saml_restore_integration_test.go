package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"golang.org/x/oauth2"
)

func TestDirectoryEmployeeSAMLRestorePreservesOffboarding(t *testing.T) {
	ctx := t.Context()
	st, authz, sso, owner, spaceID, _ := newSSOHTTPFixture(t)
	sessions := sso.Sessions
	sso.Issuer, sessions.SpaceSignInPolicy = sessions.Signer.Issuer(), sso
	sessions.Settings = func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: 5 * time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}
	wrappingKey := bytes.Repeat([]byte{17}, 32)
	if _, err := st.InitializeSigningKeys(ctx, sessions.Signer, wrappingKey); err != nil {
		t.Fatal(err)
	}
	sessions.LoadSigner = func(ctx context.Context, q *db.Queries) (*security.Signer, error) {
		return store.LoadSigningKeys(ctx, q, sso.Issuer, wrappingKey)
	}
	client := startEmployeeLifecycleEndpoint(t, &account.Service{
		Store: st, Passwords: sso.Passwords, Sessions: sessions, Authorization: authz, SignInPolicy: sso,
	}, sso)
	metadata, signing := newSAMLTestIssuer(t)
	admin := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	connection, err := sso.CreateConnection(admin, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Workforce SAML recovery", Provider: "saml",
		SAMLMetadata: strings.Replace(metadata, "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1),
		RedirectURI:  sso.Issuer + "/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	const externalID, email, claim = "saml-recovery-employee", "saml-employee@example.test", "employee_id"
	directory, err := sso.CreateDirectory(admin, owner.ID, spaceID, enterprise.DirectoryInput{
		Name: "Workforce", SSOConnectionID: connection.ID, SSOIdentityClaim: claim,
	})
	if err != nil {
		t.Fatal(err)
	}
	const scim = "application/scim+json"
	users := "/scim/v2/" + directory.ID + "/Users"
	created := client.send(t, http.MethodPost, users, directory.Token.Value(), scim, "", map[string]any{
		"externalId": externalID, "userName": email, "active": true,
	})
	created.requireStatus(t, http.StatusCreated)
	var employee scimTestResource
	if err := json.Unmarshal(created.body, &employee); err != nil || employee.ID == "" || !employee.Active || created.etag != employee.Meta.Version {
		t.Fatal("invalid provisioned employee or SCIM version")
	}
	userPath := users + "/" + employee.ID
	setActive := func(current employeeLifecycleClient, active bool, version string) employeeLifecycleResponse {
		t.Helper()
		result := current.send(t, http.MethodPatch, userPath, directory.Token.Value(), scim, version, map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
		})
		result.requireStatus(t, http.StatusOK)
		if result.etag == "" || result.etag == version {
			t.Fatal("the directory version did not advance")
		}
		return result
	}
	samlLogin := func(current employeeLifecycleClient) employeeLifecycleResponse {
		t.Helper()
		path := "/v1/sso/" + connection.ID
		start := employeeLifecycleData[enterprise.StartResult](t, current.send(t, http.MethodGet, path+"/start", "", "", "", nil))
		var request struct {
			ID string `xml:"ID,attr"`
		}
		encoded, err := base64.StdEncoding.DecodeString(start.SAMLRequest)
		if err != nil || xml.Unmarshal(encoded, &request) != nil || request.ID == "" || start.AuthorizationMethod != http.MethodPost {
			t.Fatal("the SAML start did not return its bound POST request")
		}
		assertion := signedSAMLTestResponse(t, signing, connection, request.ID, "saml-workforce-subject", []samlTestAttribute{{name: claim, value: externalID}}, false)
		return current.send(t, http.MethodPost, path+"/callback", "", "application/x-www-form-urlencoded", "", url.Values{
			"RelayState": {start.State}, "SAMLResponse": {assertion},
		})
	}
	first := employeeLifecycleData[account.AuthResult](t, samlLogin(client))
	second := employeeLifecycleData[account.AuthResult](t, samlLogin(client))
	if first.Tokens == nil || second.Tokens == nil || first.User.ID == "" || first.User.Email != email || second.User.ID != first.User.ID {
		t.Fatal("SAML did not sign in the provisioned employee")
	}
	claims, err := sessions.VerifyAccess(ctx, first.Tokens.AccessToken)
	if err != nil || claims.MemberID == "" || claims.SpaceID != spaceID {
		t.Fatal("the employee session did not bind the original workforce member")
	}
	_, independentMember, err := authz.CreateSpace(ctx, first.User.ID, "Independent team", "independent-saml-team")
	if err != nil {
		t.Fatal(err)
	}
	refresh := func(current employeeLifecycleClient, tokens session.Tokens, member string) employeeLifecycleResponse {
		t.Helper()
		return current.send(t, http.MethodPost, "/v1/auth/refresh", "", "application/json", "", map[string]string{
			"refresh_token": tokens.RefreshToken, "member_id": member,
		})
	}
	switched := employeeLifecycleData[session.Tokens](t, refresh(client, *second.Tokens, independentMember.ID))
	if switchedClaims, err := sessions.VerifyAccess(ctx, switched.AccessToken); err != nil || switchedClaims.MemberID != independentMember.ID {
		t.Fatal("the SAML session did not switch memberships before offboarding")
	}
	password := oauth2.GenerateVerifier()
	hash, err := sso.Passwords.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE users SET password_hash=$1 WHERE id=$2", hash, first.User.ID); err != nil {
		t.Fatal(err)
	}
	challenge := employeeLifecycleData[account.SignInChallenge](t, client.send(t, http.MethodPost, "/v1/auth/sign-in", "", "application/json", "",
		map[string]string{"email": email, "space_id": independentMember.SpaceID}))
	local := employeeLifecycleData[account.AuthResult](t, client.send(t, http.MethodPost, "/v1/auth/sign-in/"+challenge.AttemptID, "", "application/json", "",
		map[string]string{"password": password}))
	if local.Tokens == nil || local.User.ID != first.User.ID {
		t.Fatal("the employee could not establish an independent password session")
	}
	suspended := setActive(client, false, created.etag)
	recovered := restoreEmployeeDatabase(t, st)
	replica := openEmployeeLifecycleReplica(t, recovered.AppURL, sso)
	assertRevoked := func() {
		t.Helper()
		for _, revoked := range []session.Tokens{*first.Tokens, switched} {
			replica.send(t, http.MethodGet, "/v1/me/members", revoked.AccessToken, "", "", nil).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
			refresh(replica, revoked, "").requireError(t, http.StatusBadRequest, "invalid_grant")
		}
	}
	members := employeeLifecycleData[[]authorization.Member](t, replica.send(t, http.MethodGet, "/v1/me/members", local.Tokens.AccessToken, "", "", nil))
	if len(members) != 1 || members[0].ID != independentMember.ID {
		t.Fatal("the restored password session did not retain only the independent membership")
	}
	refresh(replica, *local.Tokens, independentMember.ID).requireStatus(t, http.StatusOK)
	assertRevoked()
	record := replica.send(t, http.MethodGet, userPath, directory.Token.Value(), scim, "", nil)
	record.requireStatus(t, http.StatusOK)
	var restored scimTestResource
	if err := json.Unmarshal(record.body, &restored); err != nil || restored.ID != employee.ID || restored.Active || record.etag != suspended.etag || record.etag != restored.Meta.Version {
		t.Fatal("SCIM identity, deactivation or revision changed during restore")
	}
	samlLogin(replica).requireError(t, http.StatusBadRequest, "invalid_grant")
	setActive(replica, true, suspended.etag)
	newLogin := employeeLifecycleData[account.AuthResult](t, samlLogin(replica))
	if newLogin.Tokens == nil || newLogin.User.ID != first.User.ID || newLogin.Tokens.SessionID == first.Tokens.SessionID {
		t.Fatal("rehire did not create a fresh SAML session for the original employee")
	}
	newClaims, err := sessions.VerifyAccess(ctx, newLogin.Tokens.AccessToken)
	if err != nil || newClaims.MemberID != claims.MemberID || newClaims.SpaceID != claims.SpaceID {
		t.Fatal("rehire replaced the original workforce membership")
	}
	replica.send(t, http.MethodGet, "/v1/me/members", newLogin.Tokens.AccessToken, "", "", nil).requireStatus(t, http.StatusOK)
	assertRevoked()
}
