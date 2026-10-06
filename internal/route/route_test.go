package route

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
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

func TestRegisterMapsInternalErrorsToUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("route test", "1.0.0"))
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
