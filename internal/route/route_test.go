package route

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

func TestServerMiddlewareRejectsBrowserOrigin(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodGet, "http://auth.test/server/v1/authz/check", nil)
	req.Header.Set("Origin", "https://app.test")
	res := httptest.NewRecorder()

	Middleware(Server, next).ServeHTTP(res, req)

	if called {
		t.Fatal("server handler ran for a browser-origin request")
	}
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
	if !strings.Contains(res.Body.String(), "BROWSER_ORIGIN_REJECTED") {
		t.Fatalf("response = %s, want BROWSER_ORIGIN_REJECTED", res.Body.String())
	}
}

func TestPrincipalCORSUsesExplicitOriginPolicy(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	policy := func(_ context.Context, origin string) (bool, error) { return origin == "https://app.test", nil }
	handler := MiddlewareWithOriginPolicy(Principal, next, policy)

	denied := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	denied.Header.Set("Origin", "https://evil.test")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || !strings.Contains(deniedResponse.Body.String(), "CORS_ORIGIN_REJECTED") {
		t.Fatalf("denied CORS response = (%d, %s), want 403 CORS_ORIGIN_REJECTED", deniedResponse.Code, deniedResponse.Body.String())
	}
	if nextCalled {
		t.Fatal("principal handler ran for a disallowed origin")
	}

	preflight := httptest.NewRequest(http.MethodOptions, "http://auth.test/v1/me", nil)
	preflight.Header.Set("Origin", "https://app.test")
	preflightResponse := httptest.NewRecorder()
	handler.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent || preflightResponse.Header().Get("Access-Control-Allow-Origin") != "https://app.test" || preflightResponse.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allowed preflight = (%d, %v), want explicit CORS headers", preflightResponse.Code, preflightResponse.Header())
	}

	allowed := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	allowed.Header.Set("Origin", "https://app.test")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusNoContent || allowedResponse.Header().Get("Access-Control-Allow-Origin") != "https://app.test" {
		t.Fatalf("allowed CORS response = (%d, %v), want explicit origin", allowedResponse.Code, allowedResponse.Header())
	}
}

func TestMiddlewarePreservesValidRequestIDAndReplacesOversizedID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	valid := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	valid.Header.Set("X-Request-Id", "req_client_123")
	validResponse := httptest.NewRecorder()
	Middleware(Principal, next).ServeHTTP(validResponse, valid)
	if got := validResponse.Header().Get("X-Request-Id"); got != "req_client_123" {
		t.Fatalf("valid request ID = %q, want caller value", got)
	}

	oversized := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	oversized.Header.Set("X-Request-Id", strings.Repeat("x", 129))
	oversizedResponse := httptest.NewRecorder()
	Middleware(Principal, next).ServeHTTP(oversizedResponse, oversized)
	if got := oversizedResponse.Header().Get("X-Request-Id"); got == "" || len(got) > 128 || got == strings.Repeat("x", 129) {
		t.Fatalf("oversized request ID = %q, want a generated bounded ID", got)
	}
}

func TestUserOnlyRouteMayOmitMemberPermission(t *testing.T) {
	if !userOnly([]Subject{User}) {
		t.Fatal("a user-account route should be allowed without a member permission")
	}
	if userOnly([]Subject{User, Human}) || userOnly([]Subject{Human}) || userOnly(nil) {
		t.Fatal("only an exact U-only subject set may omit a member permission")
	}
}

func TestRouteRegistrationRejectsIncompleteSpecs(t *testing.T) {
	valid := Spec{
		Name: "route.test", Method: http.MethodGet, Path: "/test",
		Plane: Principal, Permission: "self:read", Subjects: []Subject{Human},
	}
	cases := []struct {
		name   string
		mutate func(*Spec)
	}{
		{name: "name", mutate: func(spec *Spec) { spec.Name = "" }},
		{name: "method", mutate: func(spec *Spec) { spec.Method = "" }},
		{name: "path", mutate: func(spec *Spec) { spec.Path = "" }},
		{name: "plane", mutate: func(spec *Spec) { spec.Plane = "" }},
		{name: "subjects", mutate: func(spec *Spec) { spec.Subjects = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := valid
			tc.mutate(&spec)
			assertRoutePanic(t, func() {
				Register[struct{}, struct{}](nil, spec, nil)
			})
		})
	}

	assertRoutePanic(t, func() {
		RegisterNonJSON(http.NewServeMux(), Spec{NonJSON: true}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	})
}

func assertRoutePanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("route registration did not reject an incomplete spec")
		}
	}()
	fn()
}

func TestRegisterMapsInternalErrorsToUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, HumaConfig("route test", "1.0.0"))
	Register(api, Spec{
		Name: "route.internal-error", Method: http.MethodGet, Path: "/internal-error",
		Plane: Principal, Permission: "self:read", Subjects: []Subject{Human},
	}, func(context.Context, *struct{}) (*struct{}, error) {
		return nil, errors.New("database connection details must not escape")
	})

	req := httptest.NewRequest(http.MethodGet, "/internal-error", nil)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusServiceUnavailable)
	}
	body := res.Body.String()
	if !strings.Contains(body, `"code":"UNAVAILABLE"`) || strings.Contains(body, "database connection details") {
		t.Fatalf("response = %s, want sanitized UNAVAILABLE error", body)
	}
}
