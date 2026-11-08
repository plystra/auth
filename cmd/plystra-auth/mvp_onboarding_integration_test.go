package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/plane/ops"
	"github.com/plystra/auth/internal/plane/principal"
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
	lastTOTPStep := int64(0)
	nextTOTP := func() string {
		t.Helper()
		for {
			current := time.Now().UTC().Unix() / 30
			step := current
			if step <= lastTOTPStep {
				step = lastTOTPStep + 1
			}
			if step > current+1 {
				time.Sleep(time.Until(time.Unix((step-1)*30, 0)))
				continue
			}
			code, err := totp.GenerateCode(secretValue, time.Unix(step*30, 0))
			if err != nil {
				t.Fatal(err)
			}
			lastTOTPStep = step
			return code
		}
	}
	loginBody, err := json.Marshal(map[string]string{
		"email": "operator@example.test", "password": "a-long-bootstrap-password", "mfa_code": nextTOTP(),
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
		{`{"key":"invoice:approve","risk":"critical","principal_kinds":["human","agent"]}`, "invoice:approve", "required"},
	} {
		var catalogRequest map[string]any
		if err := json.Unmarshal([]byte(item.body), &catalogRequest); err != nil {
			t.Fatal(err)
		}
		stepBody, err := json.Marshal(map[string]any{
			"mfa_code": nextTOTP(), "operation": "ops.permissions.create", "request": catalogRequest,
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
	principalMux := http.NewServeMux()
	(&principal.API{Accounts: accounts, Sessions: sessions, Signer: signer, Authorization: authz, Factors: factors, Applications: apps}).Register(
		humago.New(principalMux, route.HumaConfig("MVP onboarding principal", "1.0.0")))
	principalHandler := route.Middleware(route.Principal, principalMux)
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
	policy := map[string]any{"registration_mode": "open", "require_email_verification": false}
	stepBody, err := json.Marshal(map[string]any{
		"mfa_code": nextTOTP(), "operation": "ops.settings.update", "request": policy,
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
	appRequest := map[string]any{
		"space_id": publisher.spaceID, "name": "Invoice SaaS", "visibility": "public",
		"redirect_uris":        []string{"https://saas.example.test/callback"},
		"manifest_permissions": []string{"auth.authz:check", "invoice:read", "invoice:approve"},
	}
	appCode, err := totp.GenerateCode(factorResult.Data.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	appStepBody, err := json.Marshal(map[string]any{
		"mfa_code": appCode, "operation": "applications.register", "request": appRequest,
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
}
