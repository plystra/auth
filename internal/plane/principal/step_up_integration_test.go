package principal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/pquerna/otp/totp"
)

func TestPrincipalStepUpAcceptsApplicationAndInvitationOperations(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "step-up operations test", 1)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}).Register(
		humago.New(mux, route.HumaConfig("step-up operations test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	for _, operation := range []string{
		"applications.register", "applications.update", "applications.keys.create", "applications.keys.rotate",
		"installations.create", "invitations.create",
	} {
		t.Run(operation, func(t *testing.T) {
			enrollment, err := factors.EnrollTOTPForUser(ctx, "usr_principal_actor", "actor@example.test", operation)
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{
				"mfa_code": code, "operation": operation, "request": map[string]any{"target": operation},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/step-up", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"accepted":true`) {
				t.Fatalf("step-up operation %s returned status %d", operation, response.Code)
			}
		})
	}
}

func TestPrincipalStepUpEndpointBindsProofToManagementRequest(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, actor.ID, "", spaceID, "step-up target", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_step_up_target', 'step-up-target@example.test', 'step-up-target@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions.Factors = factors
	authz.StepUp = sessions
	enrollment, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"space_id": spaceID, "member_id": target.ID, "user_id": "usr_step_up_target"}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Agents: &agent.Service{Store: st}}
	step := &StepUpInput{Authorization: "Bearer " + tokens.AccessToken}
	step.Body.Code = code
	step.Body.Operation = "members.bindings.create"
	step.Body.Request = requestJSON
	if _, err := api.stepUp(ctx, step); err != nil {
		t.Fatalf("POST /v1/auth/step-up = %v", err)
	}
	bind := &bindUserInput{Authorization: "Bearer " + tokens.AccessToken, ID: spaceID, MemberID: target.ID}
	bind.Body.UserID = "usr_step_up_target"
	if _, err := api.bindUser(ctx, bind); err != nil {
		t.Fatalf("bound management request = %v", err)
	}
	if _, err := api.bindUser(ctx, bind); err == nil {
		t.Fatal("management request reused a step-up proof")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "STEP_UP_REQUIRED" {
			t.Fatalf("missing step-up error = %v, want STEP_UP_REQUIRED", err)
		}
	}
}

func TestPrincipalStepUpRouteRequiresUserAccount(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name == "auth.step_up" {
			if spec.Subjects[0] != route.User || spec.Path != "/v1/auth/step-up" {
				t.Fatalf("step-up route = %+v", spec)
			}
			return
		}
	}
	t.Fatal("step-up route was not registered")
}

func TestBackupCodeFactorEndpointRequiresStepUpAndReturnsCodesOnce(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions.Factors = factors
	factors.StepUp = sessions
	authz.StepUp = sessions
	enrollment, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	create := &FactorsInput{Authorization: "Bearer " + tokens.AccessToken}
	create.Body.Kind = "backup_code"
	create.Body.Count = 5
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("backup codes were generated without step-up")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
	factors.StepUp = nil
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("backup codes were generated without a step-up verifier")
	} else {
		assertPrincipalError(t, err, "UNAVAILABLE")
	}
	factors.StepUp = sessions
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(map[string]any{"kind": "backup_code", "count": 5})
	if err != nil {
		t.Fatal(err)
	}
	step := &StepUpInput{Authorization: create.Authorization}
	step.Body.Code = code
	step.Body.Operation = "me.factors.create"
	step.Body.Request = request
	if _, err := api.stepUp(ctx, step); err != nil {
		t.Fatal(err)
	}
	created, err := api.createFactor(ctx, create)
	if err != nil {
		t.Fatalf("backup code creation failed: %v", err)
	}
	if len(created.Body.Data.Codes) != 5 {
		t.Fatalf("backup code count = %d, want 5", len(created.Body.Data.Codes))
	}
	listed, err := api.listFactors(ctx, &BearerInput{Authorization: create.Authorization})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Body.Data) != 6 {
		t.Fatalf("factor listing count = %d, want TOTP and five backup codes", len(listed.Body.Data))
	}
	encoded, err := json.Marshal(listed.Body.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), created.Body.Data.Codes[0]) || strings.Contains(string(encoded), enrollment.Secret.Value()) {
		t.Fatal("factor listing leaked a secret")
	}
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("backup code creation reused step-up proof")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
}

func TestBackupCodeFactorHTTPRoutesUseDocumentedUserSurface(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "me.factors.create", map[string]any{"kind": "backup_code"})
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := httptest.NewRequest(http.MethodPost, "/v1/me/factors", strings.NewReader(`{"kind":"backup_code"}`))
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("POST /v1/me/factors status = %d, want 200", response.Code)
	}
	var created struct {
		Data struct {
			Codes []string `json:"codes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Data.Codes) != 10 {
		t.Fatalf("default backup code count = %d, want 10", len(created.Data.Codes))
	}
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/me/factors", nil)
	listRequest.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, listRequest)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), created.Data.Codes[0]) {
		t.Fatalf("GET /v1/me/factors status = %d or disclosed a backup code", listed.Code)
	}
}

func TestFirstTOTPEnrollmentPasswordStepUpHTTPFlow(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	password := "a sufficiently long current password"
	hash, err := security.DefaultPasswordHasher().Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = 'usr_principal_actor'`, hash); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	stepBody := `{"password":"a sufficiently long current password","operation":"me.factors.create","request":{"kind":"totp","name":"phone"}}`
	wrong := request(http.MethodPost, "/v1/auth/step-up", `{"password":"wrong password","operation":"me.factors.create","request":{"kind":"totp","name":"phone"}}`)
	if wrong.Code != http.StatusUnauthorized || !strings.Contains(wrong.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("wrong password step-up status=%d", wrong.Code)
	}
	other := request(http.MethodPost, "/v1/auth/step-up", `{"password":"a sufficiently long current password","operation":"me.agents.create","request":{"kind":"totp","name":"phone"}}`)
	if other.Code != http.StatusBadRequest {
		t.Fatalf("password proof accepted for another operation: status=%d", other.Code)
	}
	step := request(http.MethodPost, "/v1/auth/step-up", stepBody)
	if step.Code != http.StatusOK {
		t.Fatalf("first TOTP step-up status=%d", step.Code)
	}
	created := request(http.MethodPost, "/v1/me/factors", `{"kind":"totp","name":"phone"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("first TOTP enrollment status=%d", created.Code)
	}
	var enrollment struct {
		Data struct {
			ID     string `json:"factor_id"`
			Secret string `json:"secret"`
			URI    string `json:"otpauth_uri"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	if enrollment.Data.ID == "" || enrollment.Data.Secret == "" || !strings.HasPrefix(enrollment.Data.URI, "otpauth://totp/") {
		t.Fatal("first TOTP enrollment did not return the factor and one-time secret")
	}
	listed := request(http.MethodGet, "/v1/me/factors", "")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), enrollment.Data.Secret) || strings.Contains(listed.Body.String(), enrollment.Data.URI) {
		t.Fatalf("factor listing status=%d or disclosed the enrollment secret", listed.Code)
	}
	if again := request(http.MethodPost, "/v1/me/factors", `{"kind":"totp","name":"phone"}`); again.Code != http.StatusForbidden {
		t.Fatalf("password step-up proof was reused: status=%d", again.Code)
	}
	if after := request(http.MethodPost, "/v1/auth/step-up", stepBody); after.Code != http.StatusForbidden || !strings.Contains(after.Body.String(), "MFA_REQUIRED") {
		t.Fatalf("password was accepted after TOTP enrollment: status=%d", after.Code)
	}
}

func TestPasswordStepUpProofInvalidatedWhenAnotherTOTPIsEnrolled(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	password := "a sufficiently long current password"
	hash, err := security.DefaultPasswordHasher().Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = 'usr_principal_actor'`, hash); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	step := &StepUpInput{Authorization: "Bearer " + tokens.AccessToken}
	step.Body.Password = secret.New(password)
	step.Body.Operation = "me.factors.create"
	step.Body.Request = json.RawMessage(`{"kind":"totp","name":"phone"}`)
	if _, err := api.stepUp(ctx, step); err != nil {
		t.Fatal(err)
	}
	if _, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test"); err != nil {
		t.Fatal(err)
	}
	create := &FactorsInput{Authorization: step.Authorization}
	create.Body.Kind = "totp"
	create.Body.Name = "phone"
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("password proof survived another TOTP enrollment")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
}

func TestFirstTOTPPasswordStepUpLimitsFailuresAcrossRequests(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	hash, err := security.DefaultPasswordHasher().Hash("a sufficiently long current password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = 'usr_principal_actor'`, hash); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer}
	step := &StepUpInput{Authorization: "Bearer " + tokens.AccessToken}
	step.Body.Operation = "me.factors.create"
	step.Body.Request = json.RawMessage(`{"kind":"totp","name":"phone"}`)
	step.Body.Password = secret.New("wrong password")
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := api.stepUp(ctx, step); err == nil {
			t.Fatal("wrong password issued a step-up proof")
		} else {
			assertPrincipalError(t, err, "UNAUTHENTICATED")
		}
	}
	step.Body.Password = secret.New("a sufficiently long current password")
	if _, err := api.stepUp(ctx, step); err == nil {
		t.Fatal("correct password bypassed the failed-attempt limit")
	} else {
		assertPrincipalError(t, err, "rate_limited")
	}
}

func TestTOTPFactorEnrollmentRequiresStepUpAndReturnsSecretOnce(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	authz.StepUp = sessions
	if _, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test"); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{
		Accounts:      &account.Service{Store: st},
		Authorization: authz,
		Sessions:      sessions,
		Signer:        signer,
		Factors:       factors,
	}
	create := &FactorsInput{Authorization: "Bearer " + tokens.AccessToken}
	create.Body.Kind = "totp"
	create.Body.Name = "laptop"
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("TOTP enrollment succeeded without step-up")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
	request := map[string]any{"kind": "totp", "name": "laptop"}
	seedStepUpProof(t, st, tokens.SessionID, "me.factors.create", request)
	created, err := api.createFactor(ctx, create)
	if err != nil {
		t.Fatalf("TOTP enrollment failed: %v", err)
	}
	if created.Body.Data.FactorID == "" || created.Body.Data.Secret == "" || !strings.HasPrefix(created.Body.Data.URI, "otpauth://totp/") {
		t.Fatalf("incomplete TOTP enrollment response: %+v", created.Body.Data)
	}
	var ciphertext []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_ciphertext FROM factors WHERE id = $1`, created.Body.Data.FactorID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || strings.Contains(string(ciphertext), created.Body.Data.Secret) {
		t.Fatal("TOTP secret was not encrypted at rest")
	}
	listed, err := api.listFactors(ctx, &BearerInput{Authorization: create.Authorization})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(listed.Body.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), created.Body.Data.Secret) || strings.Contains(string(encoded), created.Body.Data.URI) {
		t.Fatal("factor listing disclosed TOTP enrollment secret")
	}
	if _, err := api.createFactor(ctx, create); err == nil {
		t.Fatal("TOTP enrollment reused step-up proof")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
}

func TestFactorDeletionRequiresStepUpAndAuditsTheMutation(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions}
	sessions.Factors = factors
	authz.StepUp = sessions
	enrollment, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: &account.Service{Store: st}, Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	input := &FactorPathInput{Authorization: "Bearer " + tokens.AccessToken, ID: enrollment.FactorID}
	if _, err := api.deleteFactor(ctx, input); err == nil {
		t.Fatal("factor deletion succeeded without step-up")
	} else {
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
	}
	seedStepUpProof(t, st, tokens.SessionID, "me.factors.delete", map[string]any{"factor_id": enrollment.FactorID})
	deleted, err := api.deleteFactor(ctx, input)
	if err != nil {
		t.Fatalf("factor deletion failed: %v", err)
	}
	if !deleted.Body.Data.Deleted {
		t.Fatal("factor deletion did not report deleted=true")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM factors WHERE id = $1`, enrollment.FactorID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("deleted factor count = %d, want 0", count)
	}
	var auditCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'factor.delete' AND resource_id = $1`, enrollment.FactorID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("factor deletion audit count = %d, want 1", auditCount)
	}
}

func TestPrincipalSignInRequiresTOTPAfterPassword(t *testing.T) {
	ctx := context.Background()
	st, authz, _, _, sessions, signer := newPrincipalFixture(t)
	passwords := security.DefaultPasswordHasher()
	hash, err := passwords.Hash("a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = 'usr_principal_actor'`, hash); err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := factors.BeginTOTP(ctx, "usr_principal_actor", "principal-actor@example.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions.Factors = factors
	accounts := &account.Service{Store: st, Passwords: passwords, Sessions: sessions, Authorization: authz}
	api := &API{Accounts: accounts, Sessions: sessions, Signer: signer, Authorization: authz}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	started := post("/v1/auth/sign-in", `{"email":"principal-actor@example.test"}`)
	if started.Code != http.StatusOK {
		t.Fatalf("sign-in start status = %d", started.Code)
	}
	var challenge struct {
		Data struct {
			AttemptID string `json:"attempt_id"`
			NextStep  string `json:"next_step"`
		} `json:"data"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Data.AttemptID == "" || challenge.Data.NextStep != "password" {
		t.Fatal("sign-in start did not return the password step")
	}
	path := "/v1/auth/sign-in/" + challenge.Data.AttemptID
	password := post(path, `{"password":"a sufficiently long password"}`)
	if password.Code != http.StatusOK || strings.Contains(password.Body.String(), "access_token") {
		t.Fatalf("password step status = %d or disclosed a token", password.Code)
	}
	var next struct {
		Data struct {
			NextStep string `json:"next_step"`
		} `json:"data"`
	}
	if err := json.Unmarshal(password.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.Data.NextStep != "totp" {
		t.Fatalf("next sign-in step = %q, want totp", next.Data.NextStep)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	finished := post(path, `{"mfa_code":"`+code+`"}`)
	if finished.Code != http.StatusOK {
		t.Fatalf("TOTP step status = %d", finished.Code)
	}
	var authenticated struct {
		Data struct {
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(finished.Body.Bytes(), &authenticated); err != nil {
		t.Fatal(err)
	}
	if authenticated.Data.Tokens.AccessToken == "" {
		t.Fatal("TOTP step did not issue an access token")
	}
	claims, err := sessions.VerifyAccess(authenticated.Data.Tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Assurance != 2 || len(claims.AMR) != 2 || claims.AMR[1] != "otp" {
		t.Fatalf("HTTP sign-in assurance=%d AMR=%v", claims.Assurance, claims.AMR)
	}
}
