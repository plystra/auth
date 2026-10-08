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
	"github.com/pquerna/otp/totp"
)

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
