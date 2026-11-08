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
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/plane/ops"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
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
	mux := http.NewServeMux()
	(&ops.API{Operators: service}).Register(humago.New(mux, route.HumaConfig("MVP onboarding", "1.0.0")))
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
}
