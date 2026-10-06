package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/idempotency"
)

type fakeIdempotencyStore struct {
	id           string
	requestHash  []byte
	completed    bool
	statusCode   int
	responseBody []byte
	headers      map[string][]string
}

func (f *fakeIdempotencyStore) Reserve(_ context.Context, _ string, _ string, _ string, _ string, requestHash []byte) (idempotency.Reservation, error) {
	if f.id == "" {
		f.id = "idk_test"
		f.requestHash = append([]byte(nil), requestHash...)
		return idempotency.Reservation{ID: f.id}, nil
	}
	if !bytes.Equal(f.requestHash, requestHash) {
		return idempotency.Reservation{Conflict: true}, nil
	}
	if f.completed {
		return idempotency.Reservation{Replay: true, StatusCode: f.statusCode, Headers: f.headers, Body: f.responseBody}, nil
	}
	return idempotency.Reservation{InProgress: true}, nil
}

func (f *fakeIdempotencyStore) Complete(_ context.Context, id string, statusCode int, headers map[string][]string, body []byte) error {
	if id != f.id {
		return errors.New("unknown reservation")
	}
	f.completed = true
	f.statusCode = statusCode
	f.headers = headers
	f.responseBody = append([]byte(nil), body...)
	return nil
}

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

func TestIdempotencyKeyReplaysResponseAndRejectsChangedRequest(t *testing.T) {
	var store fakeIdempotencyStore
	calls := 0
	handler := MiddlewareWithIdempotency(Principal, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}), &store)
	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://auth.test/v1/members", strings.NewReader(body))
		req.Header.Set("Idempotency-Key", "create-member-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	first := request(`{"name":"one"}`)
	if first.Code != http.StatusCreated || first.Body.String() != `{"name":"one"}` || calls != 1 {
		t.Fatalf("first response = (%d, %q), calls=%d", first.Code, first.Body.String(), calls)
	}
	second := request(`{"name":"one"}`)
	if second.Code != http.StatusCreated || second.Body.String() != first.Body.String() || second.Header().Get("Idempotency-Replayed") != "true" || calls != 1 {
		t.Fatalf("replayed response = (%d, %q, replay=%q), calls=%d", second.Code, second.Body.String(), second.Header().Get("Idempotency-Replayed"), calls)
	}
	third := request(`{"name":"two"}`)
	if third.Code != http.StatusConflict || !strings.Contains(third.Body.String(), "IDEMPOTENCY_KEY_REUSED") || calls != 1 {
		t.Fatalf("changed request response = (%d, %q), calls=%d", third.Code, third.Body.String(), calls)
	}
}
