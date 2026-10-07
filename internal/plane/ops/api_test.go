package ops

import (
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/route"
)

func TestUserDispositionRoutesDeclareHumanOperatorStepUpAndCapability(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("ops test", "1.0.0")))
	want := map[string]struct {
		method string
		path   string
	}{
		"ops.users.suspend":                {"POST", "/ops/v1/users/{id}/suspend"},
		"ops.users.sign_out_all":           {"POST", "/ops/v1/users/{id}/sign-out-all"},
		"ops.users.require_password_reset": {"POST", "/ops/v1/users/{id}/require-password-reset"},
	}
	for _, spec := range route.Specs() {
		expected, ok := want[spec.Name]
		if !ok {
			continue
		}
		if spec.Method != expected.method || spec.Path != expected.path || spec.Permission != "ops:users:manage" || !spec.StepUp || len(spec.Subjects) != 1 || spec.Subjects[0] != route.Human {
			t.Fatalf("user disposition route %q = %+v", spec.Name, spec)
		}
		delete(want, spec.Name)
	}
	if len(want) != 0 {
		t.Fatalf("user disposition routes missing: %v", want)
	}
}
