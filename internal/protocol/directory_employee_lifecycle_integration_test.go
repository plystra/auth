package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp/totp"
)

func TestDirectoryEmployeeOIDCSessionFromProvisioningThroughOffboarding(t *testing.T) {
	ctx := t.Context()
	st, authz, enterpriseSvc, owner, spaceID, provider := newSSOHTTPFixture(t)
	sessions := enterpriseSvc.Sessions
	sessions.Factors = &factor.Service{Store: st, DataKey: enterpriseSvc.DataKey}
	sessions.SpaceSignInPolicy = enterpriseSvc
	enterpriseSvc.StepUp = sessions
	accounts := &account.Service{Store: st, Passwords: enterpriseSvc.Passwords, Sessions: sessions, Authorization: authz, SignInPolicy: enterpriseSvc}
	client := startEmployeeLifecycleEndpoint(t, accounts, enterpriseSvc)

	wrappingKey := bytes.Repeat([]byte{17}, 32)
	issuer := sessions.Signer.Issuer()
	if _, err := st.InitializeSigningKeys(ctx, sessions.Signer, wrappingKey); err != nil {
		t.Fatal(err)
	}
	loadSigner := func(ctx context.Context, q *db.Queries) (*security.Signer, error) {
		return store.LoadSigningKeys(ctx, q, issuer, wrappingKey)
	}
	sessions.LoadSigner = loadSigner
	openReplica := func(t *testing.T, dsn string) employeeLifecycleClient {
		t.Helper()
		replicaStore, err := store.Open(t.Context(), dsn)
		if err != nil {
			t.Fatal("open the replica's database pool")
		}
		t.Cleanup(replicaStore.Close)
		replicaSigner, err := loadSigner(t.Context(), replicaStore.Queries())
		if err != nil {
			t.Fatal(err)
		}
		replicaAuthz := &authorization.Service{Store: replicaStore}
		replicaSessions := &session.Service{
			Store: replicaStore, Signer: replicaSigner, LoadSigner: loadSigner, HMACKeys: sessions.HMACKeys, Settings: sessions.Settings,
		}
		replicaSSO := &enterprise.Service{
			Store: replicaStore, Authorization: replicaAuthz, Sessions: replicaSessions, StepUp: replicaSessions,
			DataKey: enterpriseSvc.DataKey, Passwords: enterpriseSvc.Passwords, HTTPClient: provider.server.Client(),
		}
		replicaSessions.SpaceSignInPolicy = replicaSSO
		return startEmployeeLifecycleEndpoint(t, &account.Service{
			Store: replicaStore, Passwords: replicaSSO.Passwords, Sessions: replicaSessions, Authorization: replicaAuthz, SignInPolicy: replicaSSO,
		}, replicaSSO)
	}
	peer := openReplica(t, st.Pool.Config().ConnString())

	const adminID = "usr_sso_http_owner"
	admin, err := sessions.CreateForMember(ctx, adminID, owner.ID, nil, "workforce fixture", 1)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := sessions.Factors.BeginTOTP(ctx, adminID, "sso-http-owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	// Use consecutive accepted TOTP steps so the second step-up never replays a code.
	stepTime := time.Now().UTC().Truncate(30 * time.Second)
	stepUp := func(operation string, request map[string]any) {
		t.Helper()
		code, err := totp.GenerateCode(enrollment.Secret.Value(), stepTime)
		if err != nil {
			t.Fatal(err)
		}
		stepTime = stepTime.Add(30 * time.Second)
		client.send(t, http.MethodPost, "/v1/auth/step-up", admin.AccessToken, "application/json", "",
			map[string]any{"operation": operation, "request": request, "mfa_code": code}).requireStatus(t, http.StatusOK)
	}
	const idpClientSecret = "workforce-fixture-client-secret"
	const authMethod = "client_secret_basic"
	const redirectURI = "https://auth.test/v1/sso/{connection_id}/callback"
	secretDigest, metadataDigest := sha256.Sum256([]byte(idpClientSecret)), sha256.Sum256(nil)
	stepUp("sso_connections.create", map[string]any{
		"operation": "sso_connections.create", "space_id": spaceID, "name": "Workforce OIDC", "provider": "oidc",
		"issuer": provider.issuer, "client_id": "workforce", "redirect_uri": redirectURI, "groups_claim": "", "role_mappings": nil,
		"client_secret_digest": hex.EncodeToString(secretDigest[:]), "saml_metadata_digest": hex.EncodeToString(metadataDigest[:]), "covers_subtree": false,
		"token_endpoint_auth_method": authMethod,
	})
	spacePath := "/v1/spaces/" + spaceID
	connection := employeeLifecycleData[enterprise.Connection](t, client.send(t, http.MethodPost, spacePath+"/sso-connections", admin.AccessToken, "application/json", "",
		map[string]any{"name": "Workforce OIDC", "provider": "oidc", "issuer": provider.issuer, "client_id": "workforce", "client_secret": idpClientSecret,
			"redirect_uri": redirectURI, "token_endpoint_auth_method": authMethod}))
	if connection.TokenEndpointAuthMethod != authMethod {
		t.Fatal("connection registration omitted the approved token endpoint authentication method")
	}
	stepUp("directories.create", map[string]any{
		"operation": "directories.create", "space_id": spaceID, "name": "Workforce", "sso_connection_id": connection.ID, "sso_identity_claim": "oid",
	})
	directory := employeeLifecycleData[enterprise.Directory](t, client.send(t, http.MethodPost, spacePath+"/directories", admin.AccessToken, "application/json", "",
		map[string]any{"name": "Workforce", "sso_connection_id": connection.ID, "sso_identity_claim": "oid"}))
	const externalID, email = "stable-employee-id", "employee@example.test"
	const scimContentType = "application/scim+json"
	usersPath := "/scim/v2/" + directory.ID + "/Users"
	provisioned := client.send(t, http.MethodPost, usersPath, directory.Token.Value(), scimContentType, "",
		map[string]any{"externalId": externalID, "userName": email, "displayName": "Workforce Employee", "active": true})
	provisioned.requireStatus(t, http.StatusCreated)
	var employee scimTestResource
	if err := json.Unmarshal(provisioned.body, &employee); err != nil || employee.ID == "" || !employee.Active || provisioned.etag != employee.Meta.Version {
		t.Fatalf("SCIM provisioning returned an invalid active resource or version: %v", err)
	}
	userPath := usersPath + "/" + employee.ID
	updateActive := func(active bool, version string) string {
		t.Helper()
		value := "False"
		if active {
			value = "True"
		}
		payload := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "Replace", "path": "active", "value": value}},
		}
		response := client.send(t, http.MethodPatch, userPath, directory.Token.Value(), scimContentType, version, payload)
		response.requireStatus(t, http.StatusOK)
		var resource scimTestResource
		if err := json.Unmarshal(response.body, &resource); err != nil || resource.ID != employee.ID || resource.Active != active ||
			response.etag == "" || response.etag == version || response.etag != resource.Meta.Version {
			t.Fatalf("SCIM update returned an invalid active value or version: %v", err)
		}
		return response.etag
	}

	login := func() employeeLifecycleResponse {
		t.Helper()
		path := "/v1/sso/" + connection.ID
		start := employeeLifecycleData[enterprise.StartResult](t, client.send(t, http.MethodGet, path+"/start", "", "", "", nil))
		authorizationURL, err := url.Parse(start.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		provider.addCode(start.State, oidcTestCode{nonce: authorizationURL.Query().Get("nonce"), subject: "employee-oidc-subject",
			email: "employee-upstream@example.test", emailVerified: true, extra: map[string]any{"oid": externalID}})
		return peer.send(t, http.MethodPost, path+"/callback", "", "application/json", "",
			map[string]string{"state": start.State, "code": start.State, "redirect_uri": connection.RedirectURI})
	}
	result := employeeLifecycleData[account.AuthResult](t, login())
	if result.User.ID == "" || result.User.Email != email || result.Tokens == nil {
		t.Fatal("SSO login did not reuse the provisioned employee identity")
	}
	employeeUserID := result.User.ID
	initial := *result.Tokens
	initialClaims, err := sessions.VerifyAccess(ctx, initial.AccessToken)
	if err != nil || initialClaims.MemberID == "" || initialClaims.SpaceID != spaceID {
		t.Fatal("SSO login did not issue an access token bound to the workforce Space")
	}
	assertBoundSession := func(tokens session.Tokens, memberID, authenticationMethod string) {
		t.Helper()
		claims, err := sessions.VerifyAccess(ctx, tokens.AccessToken)
		if err != nil || claims.Subject != employeeUserID || claims.MemberID != memberID || claims.SessionID != tokens.SessionID ||
			!slices.Equal(claims.AMR, []string{authenticationMethod}) || tokens.RefreshToken == "" {
			t.Fatal("issued session did not preserve the employee, current membership, or authentication method")
		}
	}
	refresh := func(tokens session.Tokens, memberID string) employeeLifecycleResponse {
		t.Helper()
		return peer.send(t, http.MethodPost, "/v1/auth/refresh", "", "application/json", "",
			map[string]string{"refresh_token": tokens.RefreshToken, "member_id": memberID})
	}
	members := func(tokens session.Tokens) employeeLifecycleResponse {
		t.Helper()
		return peer.send(t, http.MethodGet, "/v1/me/members", tokens.AccessToken, "", "", nil)
	}
	assertBoundSession(initial, initialClaims.MemberID, "oidc")
	initialMembers := employeeLifecycleData[[]authorization.Member](t, members(initial))
	if !slices.ContainsFunc(initialMembers, func(member authorization.Member) bool { return member.ID == initialClaims.MemberID }) {
		t.Fatal("the signed-in employee cannot read the workforce membership")
	}
	current := employeeLifecycleData[session.Tokens](t, refresh(initial, ""))
	assertBoundSession(current, initialClaims.MemberID, "oidc")
	if current.SessionID != initial.SessionID || current.RefreshToken == initial.RefreshToken {
		t.Fatal("successful employee renewal did not rotate its refresh credential")
	}

	// Give the same account another legitimate membership and independent password credential.
	_, otherMember, err := authz.CreateSpace(ctx, employeeUserID, "Independent team", "independent-employee-team")
	if err != nil {
		t.Fatal(err)
	}
	const password = "workforce-fixture-independent-password"
	passwordHash, err := accounts.Passwords.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, "UPDATE users SET password_hash = $1 WHERE id = $2", passwordHash, employeeUserID); err != nil {
		t.Fatal(err)
	}
	challenge := employeeLifecycleData[account.SignInChallenge](t, client.send(t, http.MethodPost, "/v1/auth/sign-in", "", "application/json", "", map[string]string{"email": email}))
	passwordLogin := employeeLifecycleData[account.AuthResult](t, client.send(t, http.MethodPost, "/v1/auth/sign-in/"+challenge.AttemptID, "", "application/json", "",
		map[string]string{"password": password}))
	if passwordLogin.Tokens == nil {
		t.Fatal("independent password authentication did not issue a session")
	}
	independent := employeeLifecycleData[session.Tokens](t, refresh(*passwordLogin.Tokens, otherMember.ID))
	assertBoundSession(independent, otherMember.ID, "pwd")

	startPassword := func(target string) account.SignInChallenge {
		t.Helper()
		return employeeLifecycleData[account.SignInChallenge](t, client.send(t, http.MethodPost, "/v1/auth/sign-in", "", "application/json", "",
			map[string]string{"email": email, "space_id": target}))
	}
	completePassword := func(attempt account.SignInChallenge) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodPost, "/v1/auth/sign-in/"+attempt.AttemptID, "", "application/json", "",
			map[string]string{"password": password})
	}
	legacyLocal := employeeLifecycleData[account.AuthResult](t, completePassword(startPassword(spaceID)))
	if legacyLocal.Tokens == nil {
		t.Fatal("password authentication before enforcement did not issue a managed-Space session")
	}
	assertBoundSession(*legacyLocal.Tokens, initialClaims.MemberID, "pwd")
	members(*legacyLocal.Tokens).requireStatus(t, http.StatusOK)
	openAttempt := startPassword(spaceID)
	unbound, err := sessions.CreateForMember(ctx, employeeUserID, "", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	// The test IdP login did not make this ordinary local session an SSO session.
	members(unbound).requireStatus(t, http.StatusOK)
	adminContext := authorization.WithHumanActor(ctx, owner.ID, adminID)
	otherConnection, err := enterpriseSvc.CreateConnection(adminContext, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Other OIDC Connection", Provider: "oidc", Issuer: provider.issuer, ClientID: "other-workforce",
		ClientSecret: idpClientSecret, RedirectURI: redirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := sessions.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wrongConnection session.Tokens
	if err := st.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: employeeUserID}); err != nil {
			return err
		}
		var err error
		wrongConnection, err = sessions.CreateForSSOTx(ctx, q, settings, employeeUserID, initialClaims.MemberID, otherConnection.ID, "oidc", time.Time{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	members(wrongConnection).requireStatus(t, http.StatusOK)
	forced, err := enterpriseSvc.CreateDomain(adminContext, owner.ID, spaceID,
		enterprise.DomainInput{Domain: "example.test", ConnectionID: connection.ID, ForceSSO: true})
	if err != nil {
		t.Fatal(err)
	}
	enterpriseSvc.DNSResolver = employeeDomainResolver{forced.VerificationToken}
	if err := enterpriseSvc.VerifyDomain(adminContext, owner.ID, spaceID, forced.ID); err != nil {
		t.Fatal(err)
	}
	t.Run("verified policy requires the enterprise connection online", func(t *testing.T) {
		completePassword(openAttempt).requireError(t, http.StatusBadRequest, "invalid_grant")
		if routed := startPassword(spaceID); routed.NextStep != "sso" || routed.SSOConnectionID != connection.ID {
			t.Fatal("managed-Space sign-in did not route to the configured provider")
		}
		members(*legacyLocal.Tokens).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
		refresh(*legacyLocal.Tokens, "").requireError(t, http.StatusForbidden, "PERMISSION_DENIED")
		members(wrongConnection).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
		refresh(wrongConnection, "").requireError(t, http.StatusForbidden, "PERMISSION_DENIED")
		refresh(independent, initialClaims.MemberID).requireError(t, http.StatusForbidden, "PERMISSION_DENIED")
		client.send(t, http.MethodGet, spacePath, unbound.AccessToken, "", "", nil).
			requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
		members(independent).requireStatus(t, http.StatusOK)
		unrelated := employeeLifecycleData[account.AuthResult](t, completePassword(startPassword(otherMember.SpaceID)))
		if unrelated.Tokens == nil {
			t.Fatal("explicit independent Space login did not issue a password session")
		}
		assertBoundSession(*unrelated.Tokens, otherMember.ID, "pwd")
		members(current).requireStatus(t, http.StatusOK)
	})
	delegation := issueEmployeeDelegation(t, client, peer, enterpriseSvc, owner, current, initialClaims, email)
	delegation.assertOnline(t, true)

	second := employeeLifecycleData[account.AuthResult](t, login())
	third := employeeLifecycleData[account.AuthResult](t, login())
	if second.Tokens == nil || third.Tokens == nil {
		t.Fatal("employee could not create additional independent SSO sessions")
	}
	switched := employeeLifecycleData[session.Tokens](t, refresh(*second.Tokens, otherMember.ID))
	assertBoundSession(switched, otherMember.ID, "oidc")
	members(*third.Tokens).requireStatus(t, http.StatusOK)
	members(switched).requireStatus(t, http.StatusOK)

	suspendedVersion := updateActive(false, provisioned.etag)
	delegation.assertOnline(t, false)
	delegation.assertExchangeRevoked(t, peer)
	login().requireStatus(t, http.StatusBadRequest)
	for _, family := range []struct {
		name        string
		tokens      session.Tokens
		requestedID string
	}{
		{name: "current workforce membership", tokens: current},
		{name: "switched before offboarding", tokens: switched, requestedID: otherMember.ID},
		{name: "switch requested after offboarding", tokens: *third.Tokens, requestedID: otherMember.ID},
	} {
		t.Run(family.name, func(t *testing.T) {
			members(family.tokens).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
			refresh(family.tokens, family.requestedID).requireError(t, http.StatusBadRequest, "invalid_grant")
		})
	}
	remainingMembers := employeeLifecycleData[[]authorization.Member](t, members(independent))
	if len(remainingMembers) != 1 || remainingMembers[0].ID != otherMember.ID {
		t.Fatal("the independent session still sees the revoked membership or lost its own membership")
	}
	retained := employeeLifecycleData[session.Tokens](t, refresh(independent, ""))
	assertBoundSession(retained, otherMember.ID, "pwd")

	t.Run("logical_restore_preserves_offboarding", func(t *testing.T) {
		recoveryCtx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		recovery, err := testdb.Start(recoveryCtx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = recovery.Close(context.Background()) })
		restored, err := protocolDB.RestoreSnapshot(recoveryCtx, st.Pool.Config().ConnConfig.Database, recovery)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = restored.Close(context.Background()) })
		restoreReplica := openReplica(t, restored.AppURL)
		originalClient, originalPeer := client, peer
		client, peer = restoreReplica, restoreReplica
		defer func() { client, peer = originalClient, originalPeer }()

		// A still-valid control session establishes that signing and HMAC keys were
		// recovered and that the revoked tokens fail because of restored state.
		members(retained).requireStatus(t, http.StatusOK)
		refresh(retained, "").requireStatus(t, http.StatusOK)
		for _, revoked := range []session.Tokens{current, switched, *third.Tokens} {
			members(revoked).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
			refresh(revoked, "").requireError(t, http.StatusBadRequest, "invalid_grant")
		}
		record := client.send(t, http.MethodGet, userPath, directory.Token.Value(), scimContentType, "", nil)
		record.requireStatus(t, http.StatusOK)
		var restoredEmployee scimTestResource
		if err := json.Unmarshal(record.body, &restoredEmployee); err != nil ||
			restoredEmployee.ID != employee.ID || restoredEmployee.Active || record.etag != suspendedVersion {
			t.Fatal("the restored SCIM resource lost its identifier, inactive state or version")
		}
		login().requireStatus(t, http.StatusBadRequest)
		updateActive(true, suspendedVersion)
		rejoined := employeeLifecycleData[account.AuthResult](t, login())
		if rejoined.Tokens == nil || rejoined.User.ID != employeeUserID {
			t.Fatal("the restored deployment did not sign the reprovisioned employee into the original account")
		}
		assertBoundSession(*rejoined.Tokens, initialClaims.MemberID, "oidc")
		members(*rejoined.Tokens).requireStatus(t, http.StatusOK)
		refresh(current, "").requireError(t, http.StatusBadRequest, "invalid_grant")
	})

	updateActive(true, suspendedVersion)
	t.Run("reactivation never revives the old family", func(t *testing.T) {
		members(current).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
		refresh(current, "").requireError(t, http.StatusBadRequest, "invalid_grant")
	})
	fresh := employeeLifecycleData[account.AuthResult](t, login())
	if fresh.Tokens == nil || fresh.Tokens.SessionID == current.SessionID {
		t.Fatal("reactivated employee did not get a fresh session")
	}
	assertBoundSession(*fresh.Tokens, initialClaims.MemberID, "oidc")
	members(*fresh.Tokens).requireStatus(t, http.StatusOK)
	members(retained).requireStatus(t, http.StatusOK)
	delegation.assertOnline(t, false)
	delegation.assertExchangeRevoked(t, peer)
	var suspensionAudited bool
	if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM audit_logs suspension JOIN audit_logs change ON change.request_id = suspension.request_id
		WHERE suspension.action = 'agent.binding.suspend' AND suspension.actor_type = 'directory'
		  AND suspension.actor_id = $1 AND suspension.member_id = $2 AND suspension.space_id = $3
		  AND suspension.resource_id = $2 AND suspension.owner_chain->0->>'member_id' = $5
		  AND change.action = 'scim.user.update' AND change.resource_id = $4
		  AND change.policy_version = suspension.policy_version AND change.metadata->>'active' = 'false'
	)`, directory.ID, delegation.parentID, spaceID, employee.ID, initialClaims.MemberID).Scan(&suspensionAudited); err != nil || !suspensionAudited {
		t.Fatal("directory deactivation and delegated subtree suspension were not correlated in the audit")
	}

	if err := enterpriseSvc.DisableConnection(adminContext, owner.ID, spaceID, connection.ID); err != nil {
		t.Fatal(err)
	}
	members(*fresh.Tokens).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
	refresh(*fresh.Tokens, "").requireError(t, http.StatusForbidden, "PERMISSION_DENIED")
	members(retained).requireStatus(t, http.StatusOK)
}

const employeeDelegationAudience = "employee-delegation-rp"

type employeeDelegation struct {
	relyingParty employeeLifecycleClient
	key          string
	spaceID      string
	parentID     string
	parentKey    string
	parentAccess string
	childKey     string
	childAccess  string
	parentTicket string
}

func issueEmployeeDelegation(t *testing.T, client, peer employeeLifecycleClient, enterpriseSvc *enterprise.Service,
	owner authorization.Member, tokens session.Tokens, employee security.Claims, email string) employeeDelegation {
	t.Helper()
	ctx := t.Context()
	st := enterpriseSvc.Store
	const applicationID = "app_employee_delegation"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id, manifest_permissions)
		VALUES ($1, $2, 'Employee relying party', $3, '["auth.authz:check", "auth.tokens:introspect"]')`, applicationID, owner.SpaceID, employeeDelegationAudience); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by) VALUES
		('grt_employee_delegate', $1, '["auth.agents:create", "auth.members:read"]', $2, 'space', $1, $3),
		('grt_employee_rp_manage', $1, '["auth.applications:manage"]', $3, 'space', $1, $3)`,
		owner.SpaceID, employee.MemberID, owner.ID); err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: enterpriseSvc.Authorization, HMACKeys: enterpriseSvc.Sessions.HMACKeys}
	admin := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	if _, err := apps.InstallSpace(admin, owner.ID, applicationID, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	keyExpiry := time.Now().UTC().Add(time.Hour)
	key, err := apps.CreateKey(ctx, applicationID, "employee-rp", []string{"auth.authz:check", "auth.tokens:introspect"}, &keyExpiry)
	if err != nil {
		t.Fatal(err)
	}
	replicaStore, err := store.Open(ctx, st.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replicaStore.Close)
	replicaAuthz := &authorization.Service{Store: replicaStore}
	replicaSessions := &session.Service{Store: replicaStore, LoadSigner: enterpriseSvc.Sessions.LoadSigner, HMACKeys: apps.HMACKeys}
	replicaSessions.SpaceSignInPolicy = &enterprise.Service{Store: replicaStore}
	serverMux := http.NewServeMux()
	(&server.API{
		Applications: &application.Service{Store: replicaStore, HMACKeys: apps.HMACKeys}, Authorization: replicaAuthz, Sessions: replicaSessions,
		Agents: &agent.Service{Store: replicaStore, HMACKeys: apps.HMACKeys},
	}).Register(humago.New(serverMux, route.HumaConfig("Employee relying party", "1.0.0")))
	relyingParty := httptest.NewTLSServer(route.Middleware(route.Server, serverMux))
	t.Cleanup(relyingParty.Close)

	enrollment, err := enterpriseSvc.Sessions.Factors.BeginTOTP(ctx, employee.Subject, email)
	if err != nil {
		t.Fatal(err)
	}
	mfaCode, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	create := map[string]any{"name": "Employee workspace", "expires_at": expiry, "source": "manual"}
	client.send(t, http.MethodPost, "/v1/auth/step-up", tokens.AccessToken, "application/json", "",
		map[string]any{"operation": "me.agents.create", "request": create, "mfa_code": mfaCode}).requireStatus(t, http.StatusOK)
	type createdAgent struct {
		Agent agent.Agent `json:"agent"`
		Key   string      `json:"agent_key"`
	}
	parent := employeeLifecycleData[createdAgent](t, client.send(t, http.MethodPost, "/v1/me/agents", tokens.AccessToken, "application/json", "", create))
	grant := func(actor, target string, permissions ...string) {
		t.Helper()
		client.send(t, http.MethodPut, "/v1/me/agents/"+target+"/grants", actor, "application/json", "",
			map[string]any{"permissions": permissions, "scope": "space"}).requireStatus(t, http.StatusOK)
	}
	grant(tokens.AccessToken, parent.Agent.ID, "auth.agents:create", "auth.members:read")
	ticket := exchangeEmployeeAgent(t, peer, employeeAgentKeyGrant(parent.Key, security.DefaultApplicationAudience))
	child := employeeLifecycleData[createdAgent](t, client.send(t, http.MethodPost, "/v1/me/agents", ticket, "application/json", "",
		map[string]any{"name": "Employee delegate", "source": "delegation", "expires_at": expiry.Add(-time.Minute)}))
	grant(ticket, child.Agent.ID, "auth.members:read")
	delegation := employeeDelegation{relyingParty: employeeLifecycleClient{server: relyingParty}, key: key, spaceID: owner.SpaceID,
		parentID: parent.Agent.ID, parentKey: parent.Key, childKey: child.Key, parentTicket: ticket}
	delegation.parentAccess = exchangeEmployeeAgent(t, peer, employeeAgentKeyGrant(parent.Key, employeeDelegationAudience))
	delegation.childAccess = exchangeEmployeeAgent(t, peer, delegation.childGrant())
	return delegation
}

func employeeAgentKeyGrant(key, audience string) url.Values {
	return url.Values{"grant_type": {"agent_key"}, "agent_key": {key}, "resource": {audience}}
}

func (d employeeDelegation) childGrant() url.Values {
	return url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {d.parentTicket},
		"actor_token": {d.childKey}, "scope": {"auth.members:read"}, "resource": {employeeDelegationAudience}}
}

func exchangeEmployeeAgent(t *testing.T, client employeeLifecycleClient, grant url.Values) string {
	t.Helper()
	response := client.send(t, http.MethodPost, "/oauth/token", "", "application/x-www-form-urlencoded", "", grant)
	var out session.Tokens
	if response.status != http.StatusOK || json.Unmarshal(response.body, &out) != nil || out.AccessToken == "" {
		t.Fatalf("Agent token exchange returned HTTP %d", response.status)
	}
	return out.AccessToken
}

func (d employeeDelegation) assertOnline(t *testing.T, active bool) {
	t.Helper()
	post := func(path string, payload any) employeeLifecycleResponse {
		t.Helper()
		return d.relyingParty.send(t, http.MethodPost, "/server/v1/"+path, d.key, "application/json", "", payload)
	}
	for _, credential := range []string{d.parentKey, d.childKey, d.parentAccess, d.childAccess} {
		identity := employeeLifecycleData[server.IntrospectIdentity](t, post("tokens/introspect", map[string]string{"token": credential}))
		if identity.Active != active {
			t.Fatalf("Agent credential active = %t, want %t", identity.Active, active)
		}
		if !active && (identity.Subject != "" || identity.MemberID != "" || len(identity.OwnerChain) > 0) {
			t.Fatal("revoked Agent credential exposed identity or ownership information")
		}
	}
	result := post("authz/check", server.CheckBody{Subject: server.CheckSubject{Token: d.childAccess}, Action: "auth.members:read",
		Resource: server.CheckResource{Type: "space", ID: d.spaceID, SpaceID: d.spaceID}})
	if active {
		if decision := employeeLifecycleData[server.CheckDecision](t, result); decision.Decision != "allow" {
			t.Fatal("the relying party could not authorize the active delegated Agent")
		}
	} else {
		result.requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
	}
}

func (d employeeDelegation) assertExchangeRevoked(t *testing.T, client employeeLifecycleClient) {
	t.Helper()
	for _, grant := range []url.Values{employeeAgentKeyGrant(d.parentKey, employeeDelegationAudience), employeeAgentKeyGrant(d.childKey, employeeDelegationAudience), d.childGrant()} {
		client.send(t, http.MethodPost, "/oauth/token", "", "application/x-www-form-urlencoded", "", grant).
			requireError(t, http.StatusBadRequest, "invalid_grant")
	}
}

func startEmployeeLifecycleEndpoint(t *testing.T, accounts *account.Service, enterpriseSvc *enterprise.Service) employeeLifecycleClient {
	t.Helper()
	mux := http.NewServeMux()
	sessions := enterpriseSvc.Sessions
	agents := &agent.Service{Store: enterpriseSvc.Store, HMACKeys: sessions.HMACKeys, StepUp: sessions}
	(&principal.API{
		Accounts: accounts, Authorization: enterpriseSvc.Authorization, Sessions: sessions, Signer: sessions.Signer, Enterprise: enterpriseSvc, Agents: agents,
	}).Register(humago.New(mux, route.HumaConfig("Enterprise employee lifecycle", "1.0.0")))
	(HTTP{Enterprise: enterpriseSvc, Agents: agents, Sessions: sessions, Authorization: enterpriseSvc.Authorization}).Register(mux)
	host := httptest.NewTLSServer(route.Middleware(route.Principal, mux))
	t.Cleanup(host.Close)
	return employeeLifecycleClient{server: host}
}

type employeeDomainResolver struct{ verificationToken string }

func (r employeeDomainResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{r.verificationToken}, nil
}

type employeeLifecycleClient struct{ server *httptest.Server }

type employeeLifecycleResponse struct {
	status int
	body   []byte
	etag   string
	method string
	path   string
}

func (c employeeLifecycleClient) send(t *testing.T, method, path, bearer, contentType, ifMatch string, payload any) employeeLifecycleResponse {
	t.Helper()
	var body []byte
	if form, ok := payload.(url.Values); ok {
		body = []byte(form.Encode())
	} else if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, c.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	res, err := c.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return employeeLifecycleResponse{status: res.StatusCode, body: data, etag: res.Header.Get("ETag"), method: method, path: path}
}

func (r employeeLifecycleResponse) requireStatus(t *testing.T, want int) {
	t.Helper()
	if r.status != want {
		var problem struct {
			Error struct{ Code string }
		}
		_ = json.Unmarshal(r.body, &problem)
		t.Errorf("%s %s returned status %d with code %q, want %d", r.method, r.path, r.status, problem.Error.Code, want)
	}
}

func (r employeeLifecycleResponse) requireError(t *testing.T, status int, code string) {
	t.Helper()
	if r.status != status {
		r.requireStatus(t, status)
		return
	}
	var problem struct {
		Error struct{ Code string }
		Data  json.RawMessage
	}
	if err := json.Unmarshal(r.body, &problem); err != nil || problem.Error.Code != code || len(problem.Data) != 0 {
		t.Errorf("HTTP %d did not return %q without success data: code=%q, err=%v", r.status, code, problem.Error.Code, err)
	}
}

func employeeLifecycleData[T any](t *testing.T, r employeeLifecycleResponse) T {
	t.Helper()
	if r.status != http.StatusOK {
		r.requireStatus(t, http.StatusOK)
		t.FailNow()
	}
	var out struct{ Data T }
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Data
}
