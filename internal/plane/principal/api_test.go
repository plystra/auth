package principal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

func TestMultiStepSignInRoutesAndOpenAPIContract(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	want := map[string]struct {
		method string
		path   string
	}{
		"auth.sign_in":         {method: http.MethodPost, path: "/v1/auth/sign-in"},
		"auth.sign_in_attempt": {method: http.MethodPost, path: "/v1/auth/sign-in/{attempt_id}"},
	}
	for _, spec := range route.Specs() {
		expected, ok := want[spec.Name]
		if !ok {
			continue
		}
		if spec.Method != expected.method || spec.Path != expected.path || len(spec.Subjects) != 1 || spec.Subjects[0] != route.Public || spec.Permission != "" {
			t.Fatalf("sign-in route %q = %+v, want public %s %s", spec.Name, spec, expected.method, expected.path)
		}
		delete(want, spec.Name)
	}
	if len(want) != 0 {
		t.Fatalf("multi-step sign-in routes missing: %v", want)
	}

	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	documentBytes, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "../../../openapi/principal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document.Paths["/v1/auth/sign-in"]["post"]; !ok {
		t.Fatal("generated OpenAPI is missing POST /v1/auth/sign-in")
	}
	if _, ok := document.Paths["/v1/auth/sign-in/{attempt_id}"]["post"]; !ok {
		t.Fatal("generated OpenAPI is missing POST /v1/auth/sign-in/{attempt_id}")
	}
	start := document.Components.Schemas["SignInStartInputBody"]
	if _, ok := start.Properties["email"]; !ok || len(start.Required) != 1 || start.Required[0] != "email" {
		t.Fatalf("sign-in start schema = %+v, want only required email", start)
	}
	attempt := document.Components.Schemas["SignInAttemptInputBody"]
	if _, ok := attempt.Properties["password"]; !ok || len(attempt.Required) != 1 || attempt.Required[0] != "password" {
		t.Fatalf("sign-in attempt schema = %+v, want only required password", attempt)
	}
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

func TestGroupMembershipRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "groups.members.add" {
			continue
		}
		if spec.Method != http.MethodPut || spec.Path != "/v1/spaces/{id}/groups/{group_id}/members/{mid}" || spec.Permission != "auth.groups:manage" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("group membership route = %+v, want PUT H/A auth.groups:manage authoritative check", spec)
		}
		return
	}
	t.Fatal("group membership route was not registered")
}

func TestGroupCreationRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "groups.create" {
			continue
		}
		if spec.Method != http.MethodPost || spec.Path != "/v1/spaces/{id}/groups" || spec.Permission != "auth.groups:manage" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("group creation route = %+v, want POST H/A auth.groups:manage authoritative check", spec)
		}
		return
	}
	t.Fatal("group creation route was not registered")
}

func TestGroupMoveRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "groups.move" {
			continue
		}
		if spec.Method != http.MethodPost || spec.Path != "/v1/spaces/{id}/groups/{group_id}/move" || spec.Permission != "auth.groups:manage" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("group move route = %+v, want POST H/A auth.groups:manage authoritative check", spec)
		}
		return
	}
	t.Fatal("group move route was not registered")
}

func TestRoleUpdateRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "roles.update" {
			continue
		}
		if spec.Method != http.MethodPatch || spec.Path != "/v1/spaces/{id}/roles/{role_id}" || spec.Permission != "auth.roles:manage" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
			t.Fatalf("role update route = %+v, want PATCH H/A auth.roles:manage authoritative check", spec)
		}
		return
	}
	t.Fatal("role update route was not registered")
}
