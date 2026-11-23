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
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
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
	mux := http.NewServeMux()
	(&principal.API{Accounts: accounts, Authorization: authz, Sessions: sessions, Signer: sessions.Signer, Enterprise: enterpriseSvc}).Register(
		humago.New(mux, route.HumaConfig("Enterprise employee lifecycle", "1.0.0")))
	(HTTP{Enterprise: enterpriseSvc}).Register(mux)
	httpServer := httptest.NewServer(route.Middleware(route.Principal, mux))
	t.Cleanup(httpServer.Close)
	client := employeeLifecycleClient{server: httpServer}

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
	const redirectURI = "https://auth.test/v1/sso/{connection_id}/callback"
	secretDigest, metadataDigest := sha256.Sum256([]byte(idpClientSecret)), sha256.Sum256(nil)
	stepUp("sso_connections.create", map[string]any{
		"operation": "sso_connections.create", "space_id": spaceID, "name": "Workforce OIDC", "provider": "oidc",
		"issuer": provider.issuer, "client_id": "workforce", "redirect_uri": redirectURI, "groups_claim": "", "role_mappings": nil,
		"client_secret_digest": hex.EncodeToString(secretDigest[:]), "saml_metadata_digest": hex.EncodeToString(metadataDigest[:]), "covers_subtree": false,
	})
	spacePath := "/v1/spaces/" + spaceID
	connection := employeeLifecycleData[enterprise.Connection](t, client.send(t, http.MethodPost, spacePath+"/sso-connections", admin.AccessToken, "application/json", "",
		map[string]any{"name": "Workforce OIDC", "provider": "oidc", "issuer": provider.issuer, "client_id": "workforce", "client_secret": idpClientSecret, "redirect_uri": redirectURI}))
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
		payload := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
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
		return client.send(t, http.MethodPost, path+"/callback", "", "application/json", "",
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
		return client.send(t, http.MethodPost, "/v1/auth/refresh", "", "application/json", "",
			map[string]string{"refresh_token": tokens.RefreshToken, "member_id": memberID})
	}
	members := func(tokens session.Tokens) employeeLifecycleResponse {
		t.Helper()
		return client.send(t, http.MethodGet, "/v1/me/members", tokens.AccessToken, "", "", nil)
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

	second := employeeLifecycleData[account.AuthResult](t, login())
	third := employeeLifecycleData[account.AuthResult](t, login())
	if second.Tokens == nil || third.Tokens == nil {
		t.Fatal("employee could not create additional independent SSO sessions")
	}
	switched := employeeLifecycleData[session.Tokens](t, refresh(*second.Tokens, otherMember.ID))
	assertBoundSession(switched, otherMember.ID, "oidc")
	members(switched).requireStatus(t, http.StatusOK)

	suspendedVersion := updateActive(false, provisioned.etag)
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

	if err := enterpriseSvc.DisableConnection(adminContext, owner.ID, spaceID, connection.ID); err != nil {
		t.Fatal(err)
	}
	members(*fresh.Tokens).requireError(t, http.StatusUnauthorized, "UNAUTHENTICATED")
	refresh(*fresh.Tokens, "").requireError(t, http.StatusForbidden, "PERMISSION_DENIED")
	members(retained).requireStatus(t, http.StatusOK)
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
}

func (c employeeLifecycleClient) send(t *testing.T, method, path, bearer, contentType, ifMatch string, payload any) employeeLifecycleResponse {
	t.Helper()
	var body []byte
	if payload != nil {
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
	return employeeLifecycleResponse{status: res.StatusCode, body: data, etag: res.Header.Get("ETag")}
}

func (r employeeLifecycleResponse) requireStatus(t *testing.T, want int) {
	t.Helper()
	if r.status != want {
		var problem struct {
			Error struct{ Code string }
		}
		_ = json.Unmarshal(r.body, &problem)
		t.Errorf("HTTP status = %d with code %q, want %d", r.status, problem.Error.Code, want)
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
