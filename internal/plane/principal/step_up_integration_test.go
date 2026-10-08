package principal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
