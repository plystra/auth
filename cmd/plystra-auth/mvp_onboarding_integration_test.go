package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/credential"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/plane/ops"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/protocol"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
	"github.com/pquerna/otp/totp"
)

func TestEmptyDeploymentCreatesBusinessPermissionsThroughPublicEntrypoints(t *testing.T) {
	ctx := context.Background()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", database.AppURL)
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", database.OwnerURL)
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.example.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("h", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))))

	initialize := initCommand()
	initialize.SetOut(io.Discard)
	initialize.SetErr(io.Discard)
	if err := initialize.ExecuteContext(ctx); err != nil {
		t.Fatalf("deployment init: %v", err)
	}
	bootstrap := operatorCommand()
	bootstrap.SetArgs([]string{"bootstrap", "--email", "operator@example.test", "--password-stdin"})
	bootstrap.SetIn(strings.NewReader("a-long-bootstrap-password\n"))
	var bootstrapOutput bytes.Buffer
	bootstrap.SetOut(&bootstrapOutput)
	bootstrap.SetErr(io.Discard)
	if err := bootstrap.ExecuteContext(ctx); err != nil {
		t.Fatalf("operator bootstrap: %v", err)
	}
	const secretLabel = "operator TOTP secret (shown once): "
	secretLine, found := strings.CutPrefix(bootstrapOutput.String(), "operator created: ")
	if !found {
		t.Fatal("operator bootstrap omitted its result")
	}
	_, secretLine, found = strings.Cut(secretLine, secretLabel)
	if !found {
		t.Fatal("operator bootstrap omitted TOTP enrollment")
	}
	secretValue, _, found := strings.Cut(secretLine, "\n")
	if !found || secretValue == "" {
		t.Fatal("operator bootstrap returned an invalid TOTP enrollment")
	}

	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key := []byte(strings.Repeat("h", 32))
	service, err := operator.New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	settings := &space.Service{Store: st}
	mux := http.NewServeMux()
	(&ops.API{Operators: service, Settings: settings}).Register(humago.New(mux, route.HumaConfig("MVP onboarding", "1.0.0")))
	handler := route.Middleware(route.Ops, mux)
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	lastTOTPSteps := map[string]int64{}
	nextTOTP := func(totpSecret string) string {
		t.Helper()
		for {
			current := time.Now().UTC().Unix() / 30
			step := current
			if step <= lastTOTPSteps[totpSecret] {
				step = lastTOTPSteps[totpSecret] + 1
			}
			if step > current+1 {
				time.Sleep(time.Until(time.Unix((step-1)*30, 0)))
				continue
			}
			code, err := totp.GenerateCode(totpSecret, time.Unix(step*30, 0))
			if err != nil {
				t.Fatal(err)
			}
			lastTOTPSteps[totpSecret] = step
			return code
		}
	}
	loginBody, err := json.Marshal(map[string]string{
		"email": "operator@example.test", "password": "a-long-bootstrap-password", "mfa_code": nextTOTP(secretValue),
	})
	if err != nil {
		t.Fatal(err)
	}
	login := request(http.MethodPost, "/ops/v1/auth/sign-in", "", string(loginBody))
	if login.Code != http.StatusOK {
		t.Fatalf("operator sign-in = %d %s", login.Code, login.Body.String())
	}
	var loginResult struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginResult); err != nil || loginResult.Data.AccessToken == "" {
		t.Fatal("operator sign-in omitted access token")
	}

	for _, item := range []struct {
		body, key, approval string
	}{
		{`{"key":"invoice:read"}`, "invoice:read", "none"},
		{`{"key":"invoice:approve","risk":"critical","principal_kinds":["human","agent","application"]}`, "invoice:approve", "required"},
	} {
		var catalogRequest map[string]any
		if err := json.Unmarshal([]byte(item.body), &catalogRequest); err != nil {
			t.Fatal(err)
		}
		stepBody, err := json.Marshal(map[string]any{
			"mfa_code": nextTOTP(secretValue), "operation": "ops.permissions.create", "request": catalogRequest,
		})
		if err != nil {
			t.Fatal(err)
		}
		stepUp := request(http.MethodPost, "/ops/v1/auth/step-up", loginResult.Data.AccessToken, string(stepBody))
		if stepUp.Code != http.StatusOK {
			t.Fatalf("permission %s step-up = %d %s", item.key, stepUp.Code, stepUp.Body.String())
		}
		created := request(http.MethodPost, "/ops/v1/permissions", loginResult.Data.AccessToken, item.body)
		if created.Code != http.StatusOK {
			t.Fatalf("permission %s creation = %d %s", item.key, created.Code, created.Body.String())
		}
		var result struct {
			Data operator.Permission `json:"data"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || result.Data.Key != item.key || result.Data.AgentApproval != item.approval || result.Data.Status != "active" {
			t.Fatalf("permission %s has incorrect catalog state", item.key)
		}
	}
	listed := request(http.MethodGet, "/ops/v1/permissions", loginResult.Data.AccessToken, "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"key":"invoice:read"`) || !strings.Contains(listed.Body.String(), `"key":"invoice:approve"`) {
		t.Fatalf("permission catalog listing = %d %s", listed.Code, listed.Body.String())
	}
	var audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'ops.permission.create' AND outcome = 'success'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("permission creation audit count = %d, error = %v", audits, err)
	}

	signer, err := security.GenerateSigner("https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, HMACKeys: [][]byte{key}}
	sessions.Settings = func(ctx context.Context) (session.Settings, error) {
		current, err := settings.Get(ctx)
		if err != nil {
			return session.Settings{}, err
		}
		return session.Settings{AccessTTL: current.AccessTokenTTL, RefreshTTL: current.RefreshTokenTTL, RefreshIdleTTL: current.RefreshIdleTTL}, nil
	}
	authz := &authorization.Service{Store: st}
	accounts := &account.Service{Store: st, Passwords: security.DefaultPasswordHasher(), Sessions: sessions, Settings: settings, Authorization: authz}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	authz.StepUp = sessions
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions, HMACKeys: [][]byte{key}}
	agents := &agent.Service{Store: st, StepUp: sessions, HMACKeys: [][]byte{key}}
	approvals := &approval.Service{Store: st, Authorization: authz, StepUp: sessions}
	validator := credential.Validator{
		Principal: credential.PrincipalParser{Sessions: sessions},
		Server:    credential.ServerParser{Applications: apps},
	}
	validateCredential := func(ctx context.Context, plane, raw string) error {
		if raw == "" {
			return nil
		}
		return validator.Validate(ctx, plane, raw)
	}
	principalMux := http.NewServeMux()
	(&principal.API{Accounts: accounts, Sessions: sessions, Signer: signer, Authorization: authz, Factors: factors, Applications: apps, Agents: agents, Approvals: approvals}).Register(
		humago.New(principalMux, route.HumaConfig("MVP onboarding principal", "1.0.0")))
	(protocol.HTTP{Issuer: "https://auth.example.test", Agents: agents, Accounts: accounts, Applications: apps, Sessions: sessions, Authorization: authz}).Register(principalMux)
	registerJWKS(principalMux, signer)
	principalHandler := route.MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAuditAndRateLimit(route.Principal, principalMux, nil, st, validateCredential, nil, nil)
	principalRequest := func(path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		principalHandler.ServeHTTP(response, req)
		return response
	}
	const publisherSignUp = `{"email":"publisher@example.test","password":"a-long-publisher-password"}`
	if denied := principalRequest("/v1/auth/sign-up", "", publisherSignUp); denied.Code != http.StatusForbidden {
		t.Fatalf("registration before policy change = %d %s", denied.Code, denied.Body.String())
	}
	policy := map[string]any{"registration_mode": "open", "require_email_verification": false, "access_token_ttl": 5 * time.Minute}
	stepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(secretValue), "operation": "ops.settings.update", "request": policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := request(http.MethodPost, "/ops/v1/auth/step-up", loginResult.Data.AccessToken, string(stepBody)); stepped.Code != http.StatusOK {
		t.Fatalf("registration policy step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	policyBody, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if changed := request(http.MethodPatch, "/ops/v1/settings", loginResult.Data.AccessToken, string(policyBody)); changed.Code != http.StatusOK || !strings.Contains(changed.Body.String(), `"registration_mode":"open"`) {
		t.Fatalf("registration policy update = %d %s", changed.Code, changed.Body.String())
	}
	type onboardedActor struct{ token, spaceID, memberID string }
	var publisher, customer onboardedActor
	for _, actor := range []struct {
		name, slug, signUp string
		out                *onboardedActor
	}{
		{"Publisher", "publisher", publisherSignUp, &publisher},
		{"Customer", "customer", `{"email":"customer@example.test","password":"a-long-customer-password"}`, &customer},
	} {
		signedUp := principalRequest("/v1/auth/sign-up", "", actor.signUp)
		if signedUp.Code != http.StatusOK {
			t.Fatalf("%s sign-up = %d %s", actor.name, signedUp.Code, signedUp.Body.String())
		}
		var identity struct {
			Data struct {
				Tokens struct {
					AccessToken  string `json:"access_token"`
					RefreshToken string `json:"refresh_token"`
				} `json:"tokens"`
			} `json:"data"`
		}
		if err := json.Unmarshal(signedUp.Body.Bytes(), &identity); err != nil || identity.Data.Tokens.AccessToken == "" || identity.Data.Tokens.RefreshToken == "" {
			t.Fatalf("%s sign-up omitted session tokens", actor.name)
		}
		spaceBody, err := json.Marshal(map[string]string{"name": actor.name, "slug": actor.slug})
		if err != nil {
			t.Fatal(err)
		}
		created := principalRequest("/v1/spaces", identity.Data.Tokens.AccessToken, string(spaceBody))
		if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"slug":"`+actor.slug+`"`) {
			t.Fatalf("%s Space creation = %d %s", actor.name, created.Code, created.Body.String())
		}
		var createdSpace struct {
			Data struct {
				Space struct {
					ID string `json:"id"`
				} `json:"space"`
				Member struct {
					ID string `json:"id"`
				} `json:"member"`
			} `json:"data"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &createdSpace); err != nil || createdSpace.Data.Space.ID == "" || createdSpace.Data.Member.ID == "" {
			t.Fatalf("%s Space creation omitted identifiers", actor.name)
		}
		refreshBody, err := json.Marshal(map[string]string{
			"refresh_token": identity.Data.Tokens.RefreshToken, "member_id": createdSpace.Data.Member.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		refreshed := principalRequest("/v1/auth/refresh", "", string(refreshBody))
		if refreshed.Code != http.StatusOK {
			t.Fatalf("%s member selection = %d %s", actor.name, refreshed.Code, refreshed.Body.String())
		}
		var memberSession struct {
			Data struct {
				AccessToken string `json:"access_token"`
			} `json:"data"`
		}
		if err := json.Unmarshal(refreshed.Body.Bytes(), &memberSession); err != nil || memberSession.Data.AccessToken == "" {
			t.Fatalf("%s member selection omitted access token", actor.name)
		}
		*actor.out = onboardedActor{token: memberSession.Data.AccessToken, spaceID: createdSpace.Data.Space.ID, memberID: createdSpace.Data.Member.ID}
	}
	if publisher.spaceID == customer.spaceID || publisher.memberID == customer.memberID {
		t.Fatal("publisher and customer identities were not isolated")
	}
	grantBody, err := json.Marshal(map[string]any{
		"grantee": map[string]string{"member_id": publisher.memberID}, "permissions": []string{"auth.applications:manage"},
		"scope": "space", "anchor_space_id": publisher.spaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := principalRequest("/v1/spaces/"+publisher.spaceID+"/grants", publisher.token, string(grantBody))
	if grant.Code != http.StatusOK {
		t.Fatalf("publisher application management grant = %d %s", grant.Code, grant.Body.String())
	}
	firstFactorStep := principalRequest("/v1/auth/step-up", publisher.token,
		`{"password":"a-long-publisher-password","operation":"me.factors.create","request":{"kind":"totp","name":"publisher"}}`)
	if firstFactorStep.Code != http.StatusOK {
		t.Fatalf("publisher first factor step-up = %d %s", firstFactorStep.Code, firstFactorStep.Body.String())
	}
	createdFactor := principalRequest("/v1/me/factors", publisher.token, `{"kind":"totp","name":"publisher"}`)
	if createdFactor.Code != http.StatusOK {
		t.Fatalf("publisher factor enrollment = %d %s", createdFactor.Code, createdFactor.Body.String())
	}
	var factorResult struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(createdFactor.Body.Bytes(), &factorResult); err != nil || factorResult.Data.Secret == "" {
		t.Fatal("publisher factor enrollment omitted its one-time secret")
	}
	manifest := []string{"auth.authz:check", "auth.authz:explain", "auth.tokens:introspect", "auth.audit:write", "invoice:read", "invoice:approve"}
	appRequest := map[string]any{
		"space_id": publisher.spaceID, "name": "Invoice SaaS", "visibility": "public",
		"redirect_uris":        []string{"https://saas.example.test/callback"},
		"manifest_permissions": manifest,
	}
	appStepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(factorResult.Data.Secret), "operation": "applications.register", "request": appRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	appStep := principalRequest("/v1/auth/step-up", publisher.token, string(appStepBody))
	if appStep.Code != http.StatusOK {
		t.Fatalf("public application step-up = %d %s", appStep.Code, appStep.Body.String())
	}
	appBody, err := json.Marshal(map[string]any{
		"name": appRequest["name"], "visibility": appRequest["visibility"],
		"redirect_uris": appRequest["redirect_uris"], "manifest_permissions": appRequest["manifest_permissions"],
	})
	if err != nil {
		t.Fatal(err)
	}
	registered := principalRequest("/v1/spaces/"+publisher.spaceID+"/applications", publisher.token, string(appBody))
	if registered.Code != http.StatusOK || !strings.Contains(registered.Body.String(), `"review_status":"pending"`) || !strings.Contains(registered.Body.String(), `"manifest_permissions":[]`) {
		t.Fatalf("pending public application = %d %s", registered.Code, registered.Body.String())
	}
	var appResult struct {
		Data struct {
			ID       string `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &appResult); err != nil || appResult.Data.ID == "" || appResult.Data.ClientID == "" {
		t.Fatal("public registration omitted application identity")
	}
	customerGrantBody, err := json.Marshal(map[string]any{
		"grantee": map[string]string{"member_id": customer.memberID}, "permissions": []string{"auth.applications:manage"},
		"scope": "space", "anchor_space_id": customer.spaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	customerGrant := principalRequest("/v1/spaces/"+customer.spaceID+"/grants", customer.token, string(customerGrantBody))
	if customerGrant.Code != http.StatusOK {
		t.Fatalf("customer application management grant = %d %s", customerGrant.Code, customerGrant.Body.String())
	}
	customerFirstStep := principalRequest("/v1/auth/step-up", customer.token,
		`{"password":"a-long-customer-password","operation":"me.factors.create","request":{"kind":"totp","name":"customer"}}`)
	if customerFirstStep.Code != http.StatusOK {
		t.Fatalf("customer first factor step-up = %d %s", customerFirstStep.Code, customerFirstStep.Body.String())
	}
	customerFactor := principalRequest("/v1/me/factors", customer.token, `{"kind":"totp","name":"customer"}`)
	if customerFactor.Code != http.StatusOK {
		t.Fatalf("customer factor enrollment = %d %s", customerFactor.Code, customerFactor.Body.String())
	}
	var customerFactorResult struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(customerFactor.Body.Bytes(), &customerFactorResult); err != nil || customerFactorResult.Data.Secret == "" {
		t.Fatal("customer factor enrollment omitted its one-time secret")
	}
	installRequest := map[string]any{"space_id": customer.spaceID, "application_id": appResult.Data.ID, "scope": "space"}
	installStepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(customerFactorResult.Data.Secret), "operation": "installations.create", "request": installRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := principalRequest("/v1/auth/step-up", customer.token, string(installStepBody)); stepped.Code != http.StatusOK {
		t.Fatalf("customer installation step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	installBody, err := json.Marshal(map[string]string{"application_id": appResult.Data.ID})
	if err != nil {
		t.Fatal(err)
	}
	installPath := "/v1/spaces/" + customer.spaceID + "/installations"
	if denied := principalRequest(installPath, customer.token, string(installBody)); denied.Code != http.StatusNotFound {
		t.Fatalf("unapproved public application installation = %d %s", denied.Code, denied.Body.String())
	}
	reviewRequest := map[string]any{"application_id": appResult.Data.ID, "manifest_permissions": manifest}
	reviewStepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(secretValue), "operation": "ops.applications.approve", "request": reviewRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := request(http.MethodPost, "/ops/v1/auth/step-up", loginResult.Data.AccessToken, string(reviewStepBody)); stepped.Code != http.StatusOK {
		t.Fatalf("public application review step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	reviewBody, err := json.Marshal(map[string]any{"manifest_permissions": manifest})
	if err != nil {
		t.Fatal(err)
	}
	approved := request(http.MethodPost, "/ops/v1/applications/"+appResult.Data.ID+"/approve", loginResult.Data.AccessToken, string(reviewBody))
	if approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), `"review_status":"approved"`) {
		t.Fatalf("public application approval = %d %s", approved.Code, approved.Body.String())
	}
	installed := principalRequest(installPath, customer.token, string(installBody))
	if installed.Code != http.StatusOK || !strings.Contains(installed.Body.String(), `"invoice:read"`) || !strings.Contains(installed.Body.String(), `"invoice:approve"`) {
		t.Fatalf("approved public application installation = %d %s", installed.Code, installed.Body.String())
	}
	var installationResult struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(installed.Body.Bytes(), &installationResult); err != nil || installationResult.Data.ID == "" {
		t.Fatal("approved installation omitted its ID")
	}
	resourceGrantBody, err := json.Marshal(map[string]any{
		"grantee": map[string]string{"member_id": customer.memberID}, "permissions": []string{"invoice:read"},
		"scope": "space", "anchor_space_id": customer.spaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceGrant := principalRequest("/v1/spaces/"+customer.spaceID+"/grants", customer.token, string(resourceGrantBody))
	if resourceGrant.Code != http.StatusOK {
		t.Fatalf("customer resource grant = %d %s", resourceGrant.Code, resourceGrant.Body.String())
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	restrictTo := []application.KeyRestriction{{SpaceID: customer.spaceID}}
	keyScopes := []string{"auth.authz:check", "auth.authz:explain", "auth.tokens:introspect", "auth.audit:write"}
	keyRequest := map[string]any{
		"application_id": appResult.Data.ID, "name": "saas-server", "grants": keyScopes,
		"restrict_to": restrictTo, "expires_at": expiresAt, "allow_subject_assertion": true,
	}
	keyStepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(factorResult.Data.Secret), "operation": "applications.keys.create", "request": keyRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := principalRequest("/v1/auth/step-up", publisher.token, string(keyStepBody)); stepped.Code != http.StatusOK {
		t.Fatalf("application key step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	keyBody, err := json.Marshal(map[string]any{
		"name": "saas-server", "grants": keyScopes, "restrict_to": restrictTo,
		"expires_at": expiresAt, "allow_subject_assertion": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyPath := "/v1/applications/" + appResult.Data.ID + "/api-keys"
	createdKey := principalRequest(keyPath, publisher.token, string(keyBody))
	if createdKey.Code != http.StatusOK {
		t.Fatalf("application server key = %d %s", createdKey.Code, createdKey.Body.String())
	}
	var keyResult struct {
		Data struct {
			Key    application.ManagedKey `json:"key"`
			Secret string                 `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(createdKey.Body.Bytes(), &keyResult); err != nil || !strings.HasPrefix(keyResult.Data.Secret, "ply_sk_") {
		t.Fatal("application key creation omitted its one-time secret")
	}
	overreach := map[string]any{
		"name": "overreach", "grants": []string{"auth.audit:read"}, "expires_at": expiresAt,
	}
	overreachStep, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(factorResult.Data.Secret), "operation": "applications.keys.create", "request": map[string]any{
			"application_id": appResult.Data.ID, "name": "overreach", "grants": []string{"auth.audit:read"}, "expires_at": expiresAt,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := principalRequest("/v1/auth/step-up", publisher.token, string(overreachStep)); stepped.Code != http.StatusOK {
		t.Fatalf("out-of-manifest key step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	overreachBody, err := json.Marshal(overreach)
	if err != nil {
		t.Fatal(err)
	}
	if denied := principalRequest(keyPath, publisher.token, string(overreachBody)); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "GRANT_EXCEEDS_OWNER") {
		t.Fatalf("key grant outside application manifest = %d %s", denied.Code, denied.Body.String())
	}
	unrestricted := map[string]any{"name": "unrestricted", "grants": []string{"auth.authz:check"}, "expires_at": expiresAt, "allow_subject_assertion": true}
	unrestrictedStep, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(factorResult.Data.Secret), "operation": "applications.keys.create", "request": map[string]any{
			"application_id": appResult.Data.ID, "name": "unrestricted", "grants": []string{"auth.authz:check"},
			"restrict_to": nil, "expires_at": expiresAt, "allow_subject_assertion": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stepped := principalRequest("/v1/auth/step-up", publisher.token, string(unrestrictedStep)); stepped.Code != http.StatusOK {
		t.Fatalf("unrestricted key step-up = %d %s", stepped.Code, stepped.Body.String())
	}
	unrestrictedBody, err := json.Marshal(unrestricted)
	if err != nil {
		t.Fatal(err)
	}
	unrestrictedKey := principalRequest(keyPath, publisher.token, string(unrestrictedBody))
	if unrestrictedKey.Code != http.StatusOK {
		t.Fatalf("unrestricted application key = %d %s", unrestrictedKey.Code, unrestrictedKey.Body.String())
	}
	var unrestrictedResult struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(unrestrictedKey.Body.Bytes(), &unrestrictedResult); err != nil || !strings.HasPrefix(unrestrictedResult.Data.Secret, "ply_sk_") {
		t.Fatal("unrestricted key creation omitted its one-time secret")
	}
	serverMux := http.NewServeMux()
	(&server.API{Applications: apps, Members: &member.Service{Store: st}, Authorization: authz, Sessions: sessions, Agents: agents, Approvals: approvals}).Register(
		humago.New(serverMux, route.HumaConfig("MVP onboarding server", "1.0.0")))
	serverHandler := route.MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAuditAndRateLimit(route.Server, serverMux, nil, st, validateCredential, nil, nil)
	t.Run("ServerKeyDiscovery", func(t *testing.T) {
		get := func(path string) *httptest.ResponseRecorder {
			t.Helper()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+keyResult.Data.Secret)
			response := httptest.NewRecorder()
			serverHandler.ServeHTTP(response, req)
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("SaaS discovery %s = %d %s", path, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), keyResult.Data.Secret) || strings.Contains(response.Body.String(), "secret_hash") {
				t.Fatal("SaaS discovery leaked key material")
			}
			return response
		}
		var identity struct {
			Data struct {
				ID            string                       `json:"id"`
				ApplicationID string                       `json:"application_id"`
				SpaceID       string                       `json:"space_id"`
				RestrictTo    []application.KeyRestriction `json:"restrict_to"`
			} `json:"data"`
		}
		if err := json.Unmarshal(get("/server/v1/key").Body.Bytes(), &identity); err != nil {
			t.Fatal(err)
		}
		if identity.Data.ID != keyResult.Data.Key.ID || identity.Data.ApplicationID != appResult.Data.ID || identity.Data.SpaceID != publisher.spaceID ||
			len(identity.Data.RestrictTo) != 1 || identity.Data.RestrictTo[0].SpaceID != customer.spaceID {
			t.Fatalf("SaaS server key identified the wrong publisher or customer: %+v", identity.Data)
		}
		var installations struct {
			Data       []application.Installation `json:"data"`
			NextCursor string                     `json:"next_cursor"`
		}
		if err := json.Unmarshal(get("/server/v1/installations?limit=1").Body.Bytes(), &installations); err != nil {
			t.Fatal(err)
		}
		if len(installations.Data) != 1 || installations.Data[0].ID != installationResult.Data.ID || installations.Data[0].SpaceID != customer.spaceID || installations.NextCursor != "" {
			t.Fatalf("SaaS discovery omitted its customer installation: %+v", installations)
		}
	})
	check := func(keySecret, subjectMemberID, spaceID, action string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"subject": map[string]string{"member_id": subjectMemberID}, "action": action,
			"resource": map[string]string{"type": "invoice", "id": "inv_123", "space_id": spaceID},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+keySecret)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		serverHandler.ServeHTTP(response, req)
		return response
	}
	if allowed := check(keyResult.Data.Secret, customer.memberID, customer.spaceID, "invoice:read"); allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"decision":"allow"`) {
		t.Fatalf("installed SaaS authorization = %d %s", allowed.Code, allowed.Body.String())
	}
	if allowed := check(keyResult.Data.Secret, customer.memberID, "", "invoice:read"); allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"decision":"allow"`) {
		t.Fatalf("SaaS authorization with subject Space default = %d %s", allowed.Code, allowed.Body.String())
	}
	if denied := check(keyResult.Data.Secret, publisher.memberID, publisher.spaceID, "invoice:read"); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"KEY_SCOPE_EXCLUDED"`) {
		t.Fatalf("key scope outside customer = %d %s", denied.Code, denied.Body.String())
	}
	if denied := check(unrestrictedResult.Data.Secret, publisher.memberID, publisher.spaceID, "invoice:read"); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"APPLICATION_NOT_INSTALLED"`) {
		t.Fatalf("uninstalled publisher Space = %d %s", denied.Code, denied.Body.String())
	}
	if denied := check(keyResult.Data.Secret, customer.memberID, customer.spaceID, "invoice:approve"); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"deny_code":"NO_MATCHING_PERMISSION"`) {
		t.Fatalf("customer permission outside grant = %d %s", denied.Code, denied.Body.String())
	}
	if denied := principalRequest("/v1/spaces", keyResult.Data.Secret, `{"name":"Wrong plane","slug":"wrong-plane"}`); denied.Code != http.StatusUnauthorized || !strings.Contains(denied.Body.String(), "CREDENTIAL_PLANE_MISMATCH") {
		t.Fatalf("server key on principal plane = %d %s", denied.Code, denied.Body.String())
	}
	approvalGrantBody, err := json.Marshal(map[string]any{
		"grantee": map[string]string{"member_id": customer.memberID}, "permissions": []string{"invoice:approve"},
		"scope": "space", "anchor_space_id": customer.spaceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if granted := principalRequest("/v1/spaces/"+customer.spaceID+"/grants", customer.token, string(approvalGrantBody)); granted.Code != http.StatusOK {
		t.Fatalf("customer approval permission = %d %s", granted.Code, granted.Body.String())
	}
	verifier := "mvp-onboarding-pkce-verifier-123456789"
	challenge := sha256.Sum256([]byte(verifier))
	authorizeQuery := url.Values{
		"response_type":         {"code"},
		"client_id":             {appResult.Data.ClientID},
		"redirect_uri":          {"https://saas.example.test/callback"},
		"scope":                 {"invoice:read invoice:approve"},
		"resource":              {appResult.Data.ClientID},
		"state":                 {"mvp-state"},
		"nonce":                 {"mvp-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	uninstalledQuery, err := url.ParseQuery(authorizeQuery.Encode())
	if err != nil {
		t.Fatal(err)
	}
	uninstalledRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+uninstalledQuery.Encode(), nil)
	uninstalledRequest.Header.Set("Authorization", "Bearer "+publisher.token)
	uninstalled := httptest.NewRecorder()
	principalHandler.ServeHTTP(uninstalled, uninstalledRequest)
	if uninstalled.Code != http.StatusOK {
		t.Fatalf("OAuth request before consent = %d %s", uninstalled.Code, uninstalled.Body.String())
	}
	var uninstalledBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(uninstalled.Body.Bytes(), &uninstalledBody); err != nil {
		t.Fatal(err)
	}
	consent := func(token, requestID, memberID string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"request_id": requestID, "decision": "approve", "member_id": memberID, "permissions": []string{"invoice:read", "invoice:approve"}})
		request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		principalHandler.ServeHTTP(response, request)
		return response
	}
	uninstalledConsent := consent(publisher.token, uninstalledBody.RequestID, publisher.memberID)
	if uninstalledConsent.Code != http.StatusBadRequest || !strings.Contains(uninstalledConsent.Body.String(), "application is not installed") {
		t.Fatalf("OAuth authorization without installation = %d %s", uninstalledConsent.Code, uninstalledConsent.Body.String())
	}
	authorizeRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery.Encode(), nil)
	authorizeRequest.Header.Set("Authorization", "Bearer "+customer.token)
	authorized := httptest.NewRecorder()
	principalHandler.ServeHTTP(authorized, authorizeRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("customer OAuth authorization = %d %s", authorized.Code, authorized.Body.String())
	}
	var authorizedBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(authorized.Body.Bytes(), &authorizedBody); err != nil {
		t.Fatal(err)
	}
	oauthApproved := consent(customer.token, authorizedBody.RequestID, customer.memberID)
	if oauthApproved.Code != http.StatusOK {
		t.Fatalf("customer OAuth consent = %d %s", oauthApproved.Code, oauthApproved.Body.String())
	}
	var approvedBody struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(oauthApproved.Body.Bytes(), &approvedBody); err != nil {
		t.Fatal(err)
	}
	callback, err := url.Parse(approvedBody.RedirectTo)
	if err != nil || callback.Query().Get("code") == "" || callback.Query().Get("state") != "mvp-state" {
		t.Fatal("OAuth callback omitted a bound authorization code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {appResult.Data.ClientID},
		"redirect_uri":  {"https://saas.example.test/callback"},
		"code":          {callback.Query().Get("code")},
		"code_verifier": {verifier},
		"resource":      {appResult.Data.ClientID},
	}
	tokenRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse := httptest.NewRecorder()
	principalHandler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("customer OAuth token exchange = %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var oauthToken struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &oauthToken); err != nil || oauthToken.AccessToken == "" || oauthToken.RefreshToken == "" {
		t.Fatal("OAuth token exchange omitted its credentials")
	}
	claims, active, err := sessions.Introspect(ctx, oauthToken.AccessToken, appResult.Data.ClientID)
	if err != nil || !active || claims.Type != "agent" || claims.SpaceID != customer.spaceID {
		t.Fatalf("customer OAuth Agent claims = %+v active=%v err=%v", claims, active, err)
	}
	oauthAgent, err := agents.OAuthAgent(ctx, customer.memberID, appResult.Data.ClientID)
	if err != nil || oauthAgent.ID != claims.Subject {
		t.Fatalf("customer OAuth Agent identity = %+v err=%v", oauthAgent, err)
	}
	t.Run("BusinessAudit", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{
			"subject": map[string]string{"token": oauthToken.AccessToken}, "action": "invoice.approve", "outcome": "deny",
			"resource":       map[string]string{"type": "invoice", "id": "inv_business_report", "space_id": customer.spaceID},
			"request_digest": strings.Repeat("ab", 32),
		})
		if err != nil {
			t.Fatal(err)
		}
		post := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/server/v1/audit/events", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+keyResult.Data.Secret)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", "mvp-business-audit")
			response := httptest.NewRecorder()
			serverHandler.ServeHTTP(response, req)
			return response
		}
		written := mvpData[audit.BusinessReceipt](t, post())
		if replayed := mvpData[audit.BusinessReceipt](t, post()); replayed.ID != written.ID {
			t.Fatal("public SaaS audit retry created another event")
		}
		query := "/v1/spaces/" + customer.spaceID + "/audit-logs?" + url.Values{
			"member_id": {customer.memberID}, "action": {"invoice.approve"},
		}.Encode()
		response := mvpJSON(t, principalHandler, http.MethodGet, query, customer.token, nil)
		events := mvpData[[]audit.Event](t, response)
		if len(events) != 1 || events[0].ID != written.ID || events[0].MemberID != oauthAgent.ID ||
			events[0].ApplicationID != appResult.Data.ID || len(events[0].OwnerChain) != 1 || events[0].OwnerChain[0].MemberID != customer.memberID ||
			events[0].ResourceID != "inv_business_report" || !strings.Contains(string(events[0].Metadata), "application_reported") || events[0].DecisionID != "" {
			t.Fatal("public SaaS business audit lost its provenance, resource or owner chain")
		}
		for _, credential := range []string{keyResult.Data.Secret, oauthToken.AccessToken, oauthToken.RefreshToken} {
			if strings.Contains(response.Body.String(), credential) {
				t.Fatal("public business audit leaked a credential")
			}
		}
	})
	t.Run("OAuthCredentialAuditContext", func(t *testing.T) {
		customerClaims, active, err := sessions.Introspect(ctx, customer.token, security.DefaultApplicationAudience)
		if err != nil || !active || customerClaims.Type != "user" {
			t.Fatal("customer audit reader is not an active user")
		}
		path := "/v1/spaces/" + customer.spaceID + "/audit-logs?" + url.Values{
			"member_id": {oauthAgent.ID}, "action": {"agent.oauth_refresh.create"},
			"request_id": {tokenResponse.Header().Get("X-Request-ID")},
		}.Encode()
		query := func(token string) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			principalHandler.ServeHTTP(response, request)
			return response
		}
		response := query(customer.token)
		if response.Code != http.StatusOK {
			t.Fatalf("OAuth credential audit query status = %d", response.Code)
		}
		var page struct {
			Data []audit.Event `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Data) != 1 {
			t.Fatal("OAuth credential audit is not uniquely correlated to token exchange")
		}
		event := page.Data[0]
		if event.MemberID != oauthAgent.ID || event.MemberType != "agent" || event.ActorID != oauthAgent.ID || event.UserID != customerClaims.Subject || event.ApplicationID != appResult.Data.ID || event.SpaceID != customer.spaceID || event.ResourceGroupID != oauthAgent.HomeGroupID || event.Plane != "principal" || event.CredentialType != "oauth_authorization_code" || event.RequestID == "" || len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != customer.memberID {
			t.Fatal("OAuth credential audit lost its verified identity, application, request, or owner chain")
		}
		if other := query(publisher.token); other.Code == http.StatusOK || strings.Contains(other.Body.String(), event.ID) {
			t.Fatal("publisher could read the customer's OAuth credential audit")
		}
		for _, credential := range []string{oauthToken.AccessToken, oauthToken.RefreshToken, customer.token, keyResult.Data.Secret, callback.Query().Get("code"), verifier, authorizedBody.RequestID} {
			var leaked bool
			if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_logs WHERE to_jsonb(audit_logs)::text LIKE '%' || $1 || '%')`, credential).Scan(&leaked); err != nil {
				t.Fatal(err)
			}
			if leaked || strings.Contains(response.Body.String(), credential) {
				t.Fatal("OAuth credential audit leaked a credential")
			}
		}
	})
	t.Run("OAuthAgentBusinessApproval", func(t *testing.T) {
		serverPost := func(path string, body any) *httptest.ResponseRecorder {
			t.Helper()
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
			request.Header.Set("Authorization", "Bearer "+keyResult.Data.Secret)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			serverHandler.ServeHTTP(response, request)
			return response
		}
		getInbox := func(token string) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodGet, "/v1/approvals", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			principalHandler.ServeHTTP(response, request)
			return response
		}
		body := map[string]any{
			"subject": map[string]string{"token": oauthToken.AccessToken}, "action": "invoice:approve",
			"resource": map[string]string{"type": "invoice", "id": "inv_approval", "space_id": customer.spaceID},
		}
		if denied := serverPost("/server/v1/authz/check", body); denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), "APPROVAL_REQUIRED") {
			t.Fatalf("high-risk OAuth action without approval = %d %s", denied.Code, denied.Body.String())
		}
		digest := sha256.Sum256([]byte(`{"invoice_id":"inv_approval","operation":"approve"}`))
		created := serverPost("/server/v1/approvals", map[string]any{
			"subject": body["subject"], "action": body["action"], "resource": body["resource"],
			"request_digest": hex.EncodeToString(digest[:]), "reason": "Approve the customer invoice",
		})
		if created.Code != http.StatusOK {
			t.Fatalf("OAuth business approval creation = %d %s", created.Code, created.Body.String())
		}
		var approvalBody struct {
			Data approval.Request `json:"data"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &approvalBody); err != nil || approvalBody.Data.ID == "" {
			t.Fatal("business approval creation omitted the request ID")
		}
		if pending := serverPost("/server/v1/authz/check", body); pending.Code != http.StatusOK || !strings.Contains(pending.Body.String(), "APPROVAL_PENDING") {
			t.Fatalf("pending OAuth approval = %d %s", pending.Code, pending.Body.String())
		}
		var inbox struct {
			Data []approval.InboxRequest `json:"data"`
		}
		response := getInbox(customer.token)
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &inbox) != nil || len(inbox.Data) != 1 {
			t.Fatalf("customer approval inbox = %d %s", response.Code, response.Body.String())
		}
		item := inbox.Data[0]
		if item.ID != approvalBody.Data.ID || item.RequestDigest != hex.EncodeToString(digest[:]) || item.Reason != "Approve the customer invoice" || item.Resource.ID != "inv_approval" || len(item.DelegationChain) != 2 || item.DelegationChain[0].ID != oauthAgent.ID || item.DelegationChain[0].Source != "oauth" || item.DelegationChain[0].OAuthClientID != appResult.Data.ClientID || item.DelegationChain[1].ID != customer.memberID {
			t.Fatal("approval inbox omitted the request or its OAuth delegation context")
		}
		other := getInbox(publisher.token)
		if other.Code != http.StatusOK || strings.Contains(other.Body.String(), item.ID) || strings.Contains(other.Body.String(), oauthAgent.ID) {
			t.Fatal("publisher could see the customer's approval context")
		}
		approvePath := "/v1/approvals/" + item.ID + "/approve"
		if denied := principalRequest(approvePath, customer.token, ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "STEP_UP_REQUIRED") {
			t.Fatalf("approval without step-up = %d %s", denied.Code, denied.Body.String())
		}
		if denied := principalRequest(approvePath, publisher.token, ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "PERMISSION_DENIED") {
			t.Fatalf("approval by another user = %d %s", denied.Code, denied.Body.String())
		}
		step, err := json.Marshal(map[string]any{
			"mfa_code": nextTOTP(customerFactorResult.Data.Secret), "operation": "approvals.approve", "request": map[string]string{"approval_id": item.ID},
		})
		if err != nil {
			t.Fatal(err)
		}
		if stepped := principalRequest("/v1/auth/step-up", customer.token, string(step)); stepped.Code != http.StatusOK {
			t.Fatalf("customer approval step-up = %d %s", stepped.Code, stepped.Body.String())
		}
		if approved := principalRequest(approvePath, customer.token, ""); approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), `"status":"approved"`) {
			t.Fatalf("customer approval = %d %s", approved.Code, approved.Body.String())
		}
		wrongTarget := serverPost("/server/v1/authz/check", map[string]any{
			"subject": body["subject"], "action": body["action"],
			"resource": map[string]string{"type": "invoice", "id": "inv_other", "space_id": customer.spaceID},
		})
		if wrongTarget.Code != http.StatusOK || !strings.Contains(wrongTarget.Body.String(), "APPROVAL_REQUIRED") {
			t.Fatalf("approval applied to another resource = %d %s", wrongTarget.Code, wrongTarget.Body.String())
		}
		const attempts = 4
		responses := make(chan *httptest.ResponseRecorder, attempts)
		var requests sync.WaitGroup
		for range attempts {
			requests.Go(func() { responses <- serverPost("/server/v1/authz/check", body) })
		}
		requests.Wait()
		close(responses)
		allowed := 0
		for response := range responses {
			if response.Code != http.StatusOK {
				t.Fatalf("concurrent approval check status = %d", response.Code)
			}
			if strings.Contains(response.Body.String(), `"decision":"allow"`) {
				allowed++
			} else if !strings.Contains(response.Body.String(), "APPROVAL_REQUIRED") {
				t.Fatalf("unexpected concurrent approval decision = %s", response.Body.String())
			}
		}
		if allowed != 1 {
			t.Fatalf("approval allowed %d concurrent requests, want one", allowed)
		}
		if replayed := serverPost("/server/v1/authz/check", body); replayed.Code != http.StatusOK || !strings.Contains(replayed.Body.String(), "APPROVAL_REQUIRED") {
			t.Fatalf("replayed approval = %d %s", replayed.Code, replayed.Body.String())
		}
		var consumedAudits int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'approval.consume' AND resource_id = $1`, item.ID).Scan(&consumedAudits); err != nil || consumedAudits != 1 {
			t.Fatalf("approval consumption audits = %d, error = %v", consumedAudits, err)
		}
		for _, action := range []string{"approval.create", "approval.approved", "approval.consume"} {
			request := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+customer.spaceID+"/audit-logs?"+url.Values{
				"member_id": {oauthAgent.ID}, "action": {action},
			}.Encode(), nil)
			request.Header.Set("Authorization", "Bearer "+customer.token)
			response := httptest.NewRecorder()
			principalHandler.ServeHTTP(response, request)
			var page struct{ Data []audit.Event }
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Data) != 1 {
				t.Fatalf("public %s audit query status=%d records=%d", action, response.Code, len(page.Data))
			}
			event := page.Data[0]
			if event.MemberID != oauthAgent.ID || event.ResourceID != item.ID || event.SpaceID != customer.spaceID || event.ResourceGroupID != "" ||
				event.PermissionKey != "invoice:approve" || event.RequestID == "" || len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != customer.memberID ||
				!strings.Contains(string(event.Metadata), hex.EncodeToString(digest[:])) {
				t.Fatalf("%s audit lost its resource or delegation context", action)
			}
			if action == "approval.approved" {
				if event.UserID == "" || event.UserID != event.ActorID || event.Plane != "principal" || event.CredentialType != "user_access_token" {
					t.Fatal("approval decision audit lost the authenticated human")
				}
			} else if event.ApplicationID != appResult.Data.ID || event.Plane != "server" || event.CredentialType != "application_api_key" ||
				keyResult.Data.Key.ID == "" || !strings.Contains(string(event.Metadata), keyResult.Data.Key.ID) {
				t.Fatal("approval audit lost the authenticated application and key")
			}
			for _, credential := range []string{oauthToken.AccessToken, oauthToken.RefreshToken, keyResult.Data.Secret, customer.token, customerFactorResult.Data.Secret} {
				if strings.Contains(response.Body.String(), credential) {
					t.Fatal("public approval audit leaked a credential")
				}
			}
		}
	})
	t.Run("NativeAgentDelegationAndRevocation", func(t *testing.T) {
		businessDatabase, err := harness.CloneEmpty(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = businessDatabase.Close(context.Background()) })
		runNativeAgentDelegationScenario(t, mvpDelegationScenario{
			Principal: principalHandler, Server: serverHandler,
			Observer: newMVPObserver(t, database.AppURL, signer, key, sessions.Settings), Signer: signer,
			UserToken: customer.token, UserMemberID: customer.memberID, SpaceID: customer.spaceID,
			ClientID: appResult.Data.ClientID, ServerKey: keyResult.Data.Secret, ControlToken: oauthToken.AccessToken,
			MFACode:             func() string { return nextTOTP(customerFactorResult.Data.Secret) },
			BusinessDatabaseURL: businessDatabase.URL,
		})
	})
	defaultSpaceBody, err := json.Marshal(map[string]any{
		"subject": map[string]string{"token": oauthToken.AccessToken}, "action": "invoice:read",
		"resource": map[string]string{"type": "invoice", "id": "inv_default_customer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defaultSpaceRequest := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", bytes.NewReader(defaultSpaceBody))
	defaultSpaceRequest.Header.Set("Authorization", "Bearer "+keyResult.Data.Secret)
	defaultSpaceRequest.Header.Set("Content-Type", "application/json")
	defaultSpaceResponse := httptest.NewRecorder()
	serverHandler.ServeHTTP(defaultSpaceResponse, defaultSpaceRequest)
	if defaultSpaceResponse.Code != http.StatusOK || !strings.Contains(defaultSpaceResponse.Body.String(), `"decision":"allow"`) {
		t.Fatalf("OAuth SaaS authorization with omitted resource Space = %d %s", defaultSpaceResponse.Code, defaultSpaceResponse.Body.String())
	}
	repeatQuery, err := url.ParseQuery(authorizeQuery.Encode())
	if err != nil {
		t.Fatal(err)
	}
	repeatQuery.Set("state", "mvp-repeat")
	repeatRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+repeatQuery.Encode(), nil)
	repeatRequest.Header.Set("Authorization", "Bearer "+customer.token)
	repeated := httptest.NewRecorder()
	principalHandler.ServeHTTP(repeated, repeatRequest)
	if repeated.Code != http.StatusOK {
		t.Fatalf("repeat OAuth authorization = %d %s", repeated.Code, repeated.Body.String())
	}
	var repeatedBody struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(repeated.Body.Bytes(), &repeatedBody); err != nil {
		t.Fatal(err)
	}
	repeatConsent := consent(customer.token, repeatedBody.RequestID, customer.memberID)
	if repeatConsent.Code != http.StatusOK {
		t.Fatalf("repeat OAuth consent = %d %s", repeatConsent.Code, repeatConsent.Body.String())
	}
	var repeatConsentBody struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.Unmarshal(repeatConsent.Body.Bytes(), &repeatConsentBody); err != nil {
		t.Fatal(err)
	}
	repeatCallback, err := url.Parse(repeatConsentBody.RedirectTo)
	if err != nil || repeatCallback.Query().Get("code") == "" {
		t.Fatal("repeat OAuth callback omitted its code")
	}
	reusedAgent, err := agents.OAuthAgent(ctx, customer.memberID, appResult.Data.ClientID)
	if err != nil || reusedAgent.ID != oauthAgent.ID {
		t.Fatalf("repeat OAuth authorization created another Agent: %+v err=%v", reusedAgent, err)
	}
	t.Run("PublicManifestReviewAndCustomerReapproval", func(t *testing.T) {
		patchPath := "/v1/applications/" + appResult.Data.ID
		approvalPath := "/ops/v1/applications/" + appResult.Data.ID + "/approve"
		installationsPath := "/v1/spaces/" + customer.spaceID + "/installations"
		installation := func() application.Installation {
			t.Helper()
			items := mvpData[[]application.Installation](t, mvpJSON(t, principalHandler, http.MethodGet, installationsPath, customer.token, nil))
			for _, item := range items {
				if item.ID == installationResult.Data.ID {
					return item
				}
			}
			t.Fatal("customer installation disappeared during manifest review")
			return application.Installation{}
		}
		publish := func(permissions []string) {
			t.Helper()
			step := map[string]any{
				"mfa_code": nextTOTP(secretValue), "operation": "ops.applications.approve",
				"request": map[string]any{"application_id": appResult.Data.ID, "manifest_permissions": permissions},
			}
			mvpData[struct{ Accepted bool }](t, mvpJSON(t, handler, http.MethodPost, "/ops/v1/auth/step-up", loginResult.Data.AccessToken, step))
			approved := mvpData[operator.PublicApplicationReview](t, mvpJSON(t, handler, http.MethodPost, approvalPath, loginResult.Data.AccessToken,
				map[string]any{"manifest_permissions": permissions}))
			if !slices.Equal(approved.ManifestPermissions, permissions) {
				t.Fatal("public manifest approval returned a different scope")
			}
		}
		shrunk := slices.DeleteFunc(slices.Clone(manifest), func(key string) bool { return key == "invoice:approve" })
		slices.Sort(shrunk)
		pending := mvpData[application.PublishedApplication](t, mvpJSON(t, principalHandler, http.MethodPatch, patchPath, publisher.token,
			map[string]any{"manifest_permissions": shrunk}))
		if pending.ReviewStatus != "approved" || !slices.Contains(pending.ManifestPermissions, "invoice:approve") ||
			!slices.Equal(pending.PendingManifestPermissions, shrunk) || !slices.Contains(installation().ApprovedPermissions, "invoice:approve") {
			t.Fatal("unreviewed public update changed the live customer scope")
		}
		publish(shrunk)
		if slices.Contains(installation().ApprovedPermissions, "invoice:approve") {
			t.Fatal("approved manifest shrink did not reach the customer installation")
		}
		removedScope := url.Values{
			"response_type": {"code"}, "client_id": {appResult.Data.ClientID}, "redirect_uri": {"https://saas.example.test/callback"},
			"scope": {"invoice:approve"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
			"state": {"manifest-removed"}, "nonce": {"manifest-removed-nonce"},
		}
		removedRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+removedScope.Encode(), nil)
		removedResponse := httptest.NewRecorder()
		principalHandler.ServeHTTP(removedResponse, removedRequest)
		if removedResponse.Code != http.StatusBadRequest || !strings.Contains(removedResponse.Body.String(), "invalid_scope") {
			t.Fatalf("removed OAuth scope still authorized: status=%d", removedResponse.Code)
		}
		expanded := slices.Clone(manifest)
		slices.Sort(expanded)
		mvpData[application.PublishedApplication](t, mvpJSON(t, principalHandler, http.MethodPatch, patchPath, publisher.token,
			map[string]any{"manifest_permissions": expanded}))
		publish(expanded)
		if slices.Contains(installation().ApprovedPermissions, "invoice:approve") {
			t.Fatal("operator approval expanded a customer installation without its approval")
		}
		approved := mvpData[application.Installation](t, mvpJSON(t, principalHandler, http.MethodPut,
			installationsPath+"/"+installationResult.Data.ID+"/approvals", customer.token, nil))
		if !slices.Equal(approved.ApprovedPermissions, expanded) {
			t.Fatal("customer reapproval did not restore the explicitly approved scope")
		}
		events := mvpData[[]audit.Event](t, mvpJSON(t, principalHandler, http.MethodGet,
			"/v1/spaces/"+customer.spaceID+"/audit-logs?action=application.installation.manifest.narrow", customer.token, nil))
		if len(events) != 1 || events[0].ApplicationID != appResult.Data.ID || events[0].MemberID != approved.MemberID {
			t.Fatal("customer cannot correlate its public manifest narrowing audit")
		}
	})
	suspended := principalRequest("/v1/spaces/"+customer.spaceID+"/installations/"+installationResult.Data.ID+"/suspend", customer.token, "")
	if suspended.Code != http.StatusOK {
		t.Fatalf("customer application suspension = %d %s", suspended.Code, suspended.Body.String())
	}
	form.Set("code", repeatCallback.Query().Get("code"))
	staleRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	staleRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	staleToken := httptest.NewRecorder()
	principalHandler.ServeHTTP(staleToken, staleRequest)
	if staleToken.Code != http.StatusBadRequest || !strings.Contains(staleToken.Body.String(), "invalid_grant") {
		t.Fatalf("OAuth code after installation suspension = %d %s", staleToken.Code, staleToken.Body.String())
	}
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {appResult.Data.ClientID},
		"refresh_token": {oauthToken.RefreshToken},
		"resource":      {appResult.Data.ClientID},
	}
	refreshRequest := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	staleRefresh := httptest.NewRecorder()
	principalHandler.ServeHTTP(staleRefresh, refreshRequest)
	if staleRefresh.Code != http.StatusBadRequest || !strings.Contains(staleRefresh.Body.String(), "invalid_grant") {
		t.Fatalf("OAuth refresh after installation suspension = %d %s", staleRefresh.Code, staleRefresh.Body.String())
	}
	t.Run("GlobalOAuthClientSuspension", func(t *testing.T) {
		resumePath := "/v1/spaces/" + customer.spaceID + "/installations/" + installationResult.Data.ID + "/resume"
		mvpData[application.Installation](t, mvpJSON(t, principalHandler, http.MethodPost, resumePath, customer.token, nil))
		observer := newMVPObserver(t, database.AppURL, signer, key, sessions.Settings)
		check := map[string]any{
			"subject": map[string]string{"token": oauthToken.AccessToken}, "action": "invoice:read",
			"resource": map[string]string{"type": "invoice", "id": "inv_client_stop", "space_id": customer.spaceID},
		}
		for _, surface := range []http.Handler{serverHandler, observer} {
			decision := mvpData[server.CheckDecision](t, mvpJSON(t, surface, http.MethodPost, "/server/v1/authz/check", keyResult.Data.Secret, check))
			if decision.Decision != "allow" {
				t.Fatalf("active OAuth client decision=%s code=%s", decision.Decision, decision.DenyCode)
			}
		}
		pendingRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery.Encode(), nil)
		pendingResponse := httptest.NewRecorder()
		principalHandler.ServeHTTP(pendingResponse, pendingRequest)
		var pending struct {
			RequestID string `json:"request_id"`
		}
		if pendingResponse.Code != http.StatusOK || json.Unmarshal(pendingResponse.Body.Bytes(), &pending) != nil || pending.RequestID == "" {
			t.Fatal("could not prepare an authorization request before global suspension")
		}
		var issuedCode struct {
			RedirectTo string `json:"redirect_to"`
		}
		consented := consent(customer.token, pending.RequestID, customer.memberID)
		if consented.Code != http.StatusOK || json.Unmarshal(consented.Body.Bytes(), &issuedCode) != nil {
			t.Fatal("could not issue an authorization code before global suspension")
		}
		callback, err := url.Parse(issuedCode.RedirectTo)
		if err != nil || callback.Query().Get("code") == "" {
			t.Fatal("authorization omitted the pending code")
		}
		step := map[string]any{
			"mfa_code": nextTOTP(secretValue), "operation": "ops.applications.suspend",
			"request": map[string]string{"application_id": appResult.Data.ID},
		}
		mvpData[struct{ Accepted bool }](t, mvpJSON(t, handler, http.MethodPost, "/ops/v1/auth/step-up", loginResult.Data.AccessToken, step))
		mvpData[struct{ Accepted bool }](t, mvpJSON(t, handler, http.MethodPost, "/ops/v1/applications/"+appResult.Data.ID+"/suspend", loginResult.Data.AccessToken, nil))
		for _, surface := range []http.Handler{serverHandler, observer} {
			for path, body := range map[string]any{
				"/server/v1/authz/check":       check,
				"/server/v1/tokens/introspect": map[string]string{"token": oauthToken.AccessToken},
				"/server/v1/key":               nil,
			} {
				method := http.MethodPost
				if body == nil {
					method = http.MethodGet
				}
				got := mvpJSON(t, surface, method, path, keyResult.Data.Secret, body)
				if got.Code != http.StatusUnauthorized {
					t.Fatalf("stopped application credential at %s status=%d", path, got.Code)
				}
			}
		}
		if got := mvpToken(t, principalHandler, refreshForm); got.Code != http.StatusUnauthorized || !strings.Contains(got.Body.String(), "invalid_client") {
			t.Fatalf("globally stopped client refreshed OAuth credential status=%d", got.Code)
		}
		codeForm := url.Values{
			"grant_type": {"authorization_code"}, "client_id": {appResult.Data.ClientID},
			"code": {callback.Query().Get("code")}, "redirect_uri": {"https://saas.example.test/callback"},
			"code_verifier": {form.Get("code_verifier")}, "resource": {appResult.Data.ClientID},
		}
		if got := mvpToken(t, principalHandler, codeForm); got.Code != http.StatusUnauthorized || !strings.Contains(got.Body.String(), "invalid_client") {
			t.Fatalf("globally stopped client exchanged an existing code status=%d", got.Code)
		}
		authorizationRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery.Encode(), nil)
		stoppedAuthorization := httptest.NewRecorder()
		principalHandler.ServeHTTP(stoppedAuthorization, authorizationRequest)
		if stoppedAuthorization.Code != http.StatusBadRequest || !strings.Contains(stoppedAuthorization.Body.String(), "invalid_request") {
			t.Fatalf("globally stopped client began consent status=%d", stoppedAuthorization.Code)
		}
	})
}
