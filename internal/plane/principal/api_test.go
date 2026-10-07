package principal

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestLogoutRejectsAgentAccessTokenWithUserAccountRequired(t *testing.T) {
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := signer.Sign(security.Claims{
		Issuer: signer.Issuer(), Subject: "mem_agent", MemberID: "mem_agent",
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt: now.Unix(), JWTID: "jti_test", Type: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Signer: signer}
	_, err = api.logout(context.Background(), &LogoutInput{Authorization: "Bearer " + token})
	var public *apierr.Error
	if !strings.Contains(err.Error(), "user account") || !errors.As(err, &public) || public.Code != "USER_ACCOUNT_REQUIRED" {
		t.Fatalf("logout error = %v, want USER_ACCOUNT_REQUIRED", err)
	}
}

func TestSignOutRouteDeclaresUserAccountSubject(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "auth.sign_out" {
			continue
		}
		if len(spec.Subjects) != 1 || spec.Subjects[0] != route.User || spec.Permission != "" {
			t.Fatalf("sign-out route = %+v, want U subject without member permission", spec)
		}
		return
	}
	t.Fatal("sign-out route was not registered")
}

func TestAssignmentRightsRoutesDeclareHumanAgentAndMutationGuards(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	want := map[string]struct {
		method string
		path   string
		stepUp bool
		delta  bool
	}{
		"assignment_rights.list":   {"GET", "/v1/spaces/{id}/assign-rights", true, false},
		"assignment_rights.create": {"POST", "/v1/spaces/{id}/assign-rights", true, true},
		"assignment_rights.revoke": {"DELETE", "/v1/spaces/{id}/assign-rights/{ar_id}", true, false},
	}
	for _, spec := range route.Specs() {
		expected, ok := want[spec.Name]
		if !ok {
			continue
		}
		if spec.Method != expected.method || spec.Path != expected.path || spec.Permission != "auth.assign_rights:manage" || spec.StepUp != expected.stepUp || spec.AuthoritativeCheck != expected.delta || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("assignment-right route %q = %+v, want method=%s path=%s H/A step_up=%v delta=%v", spec.Name, spec, expected.method, expected.path, expected.stepUp, expected.delta)
		}
		delete(want, spec.Name)
	}
	if len(want) != 0 {
		t.Fatalf("assignment-right routes missing: %v", want)
	}
}
