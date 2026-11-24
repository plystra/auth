package route

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/idempotency"
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

func TestDirectSAMLFormNavigationDoesNotGrantCORSOrReplay(t *testing.T) {
	const callback = "/v1/sso/sso_fixture/callback"
	const form = "application/x-www-form-urlencoded; charset=utf-8"
	for _, test := range []struct {
		name, method, path, mediaType string
		idempotency                   bool
		status                        int
		code                          string
	}{
		{name: "form", method: http.MethodPost, path: callback, mediaType: form, status: http.StatusNoContent},
		{name: "multipart", method: http.MethodPost, path: callback, mediaType: "multipart/form-data; boundary=fixture", status: http.StatusNoContent},
		{name: "form replay key", method: http.MethodPost, path: callback, mediaType: form, idempotency: true, status: http.StatusBadRequest, code: "VALIDATION_FAILED"},
		{name: "json", method: http.MethodPost, path: callback, mediaType: "application/json", status: http.StatusForbidden, code: "CORS_ORIGIN_REJECTED"},
		{name: "another route", method: http.MethodPost, path: callback + "/other", mediaType: form, status: http.StatusForbidden, code: "CORS_ORIGIN_REJECTED"},
		{name: "preflight", method: http.MethodOptions, path: callback, mediaType: form, status: http.StatusForbidden, code: "CORS_ORIGIN_REJECTED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "https://auth.test"+test.path, nil)
			req.Header.Set("Origin", "https://idp.test")
			req.Header.Set("Content-Type", test.mediaType)
			if test.idempotency {
				req.Header.Set("Idempotency-Key", "saml-navigation")
			}
			res := httptest.NewRecorder()
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			Middleware(Principal, next).ServeHTTP(res, req)
			if res.Code != test.status || !strings.Contains(res.Body.String(), test.code) ||
				res.Header().Get("Access-Control-Allow-Origin") != "" || res.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected response status or security headers: HTTP %d", res.Code)
			}
		})
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

func TestPlaneRateLimitsAreIndependentAndExhaustionIsIsolated(t *testing.T) {
	counts := make(map[string]int)
	rateLimit := func(_ context.Context, key string, limit int, _ time.Duration) (bool, error) {
		counts[key]++
		if limit == 0 {
			t.Fatal("plane rate limit was not configured")
		}
		return counts[key] <= 1, nil
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	request := func(handler http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}

	principal := MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAuditAndRateLimit(Principal, next, nil, nil, nil, nil, rateLimit)
	server := MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAuditAndRateLimit(Server, next, nil, nil, nil, nil, rateLimit)
	if got := request(principal).Code; got != http.StatusNoContent {
		t.Fatalf("first principal request = %d, want %d", got, http.StatusNoContent)
	}
	if got := request(principal).Code; got != http.StatusTooManyRequests {
		t.Fatalf("exhausted principal request = %d, want %d", got, http.StatusTooManyRequests)
	}
	if got := request(server).Code; got != http.StatusNoContent {
		t.Fatalf("server request after principal exhaustion = %d, want %d", got, http.StatusNoContent)
	}
	if len(counts) != 2 {
		t.Fatalf("rate-limit keys = %d, want one independent key per plane", len(counts))
	}
	for key := range counts {
		if strings.Contains(key, "192.0.2.1") || strings.Contains(key, "principal") || strings.Contains(key, "server") {
			t.Fatalf("rate-limit key %q leaks raw transport identity or plane", key)
		}
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
	cases := []struct {
		name string
		spec Spec
	}{
		{name: "name", spec: NewSpec("", http.MethodGet, "/test", Principal, "self:read", []Subject{Human})},
		{name: "method", spec: NewSpec("route.test", "", "/test", Principal, "self:read", []Subject{Human})},
		{name: "path", spec: NewSpec("route.test", http.MethodGet, "", Principal, "self:read", []Subject{Human})},
		{name: "plane", spec: NewSpec("route.test", http.MethodGet, "/test", "", "self:read", []Subject{Human})},
		{name: "subjects", spec: NewSpec("route.test", http.MethodGet, "/test", Principal, "self:read", nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRoutePanic(t, func() {
				Register[struct{}, struct{}](nil, tc.spec, nil)
			})
		})
	}

	assertRoutePanic(t, func() {
		RegisterNonJSON(http.NewServeMux(), NewSpec("", "", "", "", "", nil, WithNonJSON()), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	})
}

func TestNewSpecExposesCompleteDeclarationSnapshot(t *testing.T) {
	spec := NewSpec("route.complete", http.MethodPost, "/complete", Server, "auth.test:write", []Subject{HumanAgent}, WithStepUp(), WithAuthoritativeCheck(), WithMaxBodyBytes(1234))
	declaration, ok := getDeclaration(spec)
	if !ok || declaration.Name != "route.complete" || declaration.Method != http.MethodPost || declaration.Path != "/complete" || declaration.Plane != Server || declaration.Permission != "auth.test:write" || len(declaration.Subjects) != 1 || !declaration.StepUp || !declaration.AuthoritativeCheck || declaration.MaxBodyBytes != 1234 {
		t.Fatalf("declaration = %+v, want complete constructor snapshot", declaration)
	}
}

func TestMuxRejectsHandlersOutsideRouteRegistry(t *testing.T) {
	mux := NewMux()
	mux.Handle("GET /unregistered", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := Validate(mux); err == nil || !strings.Contains(err.Error(), "GET /unregistered") {
		t.Fatalf("Validate error = %v, want unregistered handler failure", err)
	}
}

func TestMuxAcceptsDeclaredJSONAndNonJSONHandlers(t *testing.T) {
	mux := NewMux()
	api := humago.New(mux, HumaConfig("route mux test", "1.0.0"))
	Register(api, NewSpec("route.mux.json", http.MethodGet, "/mux-json", Principal, "self:read", []Subject{Human}), func(context.Context, *struct{}) (*struct{}, error) { return &struct{}{}, nil })
	RegisterNonJSON(mux, NewSpec("route.mux.protocol", http.MethodGet, "/mux-protocol", Principal, "", []Subject{Public}, WithNonJSON()), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := Validate(mux); err != nil {
		t.Fatalf("Validate returned error for declared handlers: %v", err)
	}
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
	Register(api, NewSpec("route.internal-error", http.MethodGet, "/internal-error", Principal, "self:read", []Subject{Human}), func(context.Context, *struct{}) (*struct{}, error) {
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

type fakeIdempotencyManager struct {
	mu           sync.Mutex
	hash         []byte
	completed    *idempotency.Response
	reservations int
}

type fakeIdempotencyTx struct {
	manager *fakeIdempotencyManager
	closed  bool
}

func (m *fakeIdempotencyManager) BeginIdempotency(context.Context) (idempotency.Transaction, error) {
	return &fakeIdempotencyTx{manager: m}, nil
}

func (t *fakeIdempotencyTx) Context(ctx context.Context) context.Context { return ctx }

func (t *fakeIdempotencyTx) Reserve(_ context.Context, in idempotency.Request) (idempotency.Reservation, error) {
	t.manager.mu.Lock()
	defer t.manager.mu.Unlock()
	if t.manager.hash == nil {
		t.manager.hash = append([]byte(nil), in.RequestHash...)
		t.manager.reservations++
		return idempotency.Reservation{ID: "idk_test"}, nil
	}
	if !bytes.Equal(t.manager.hash, in.RequestHash) {
		return idempotency.Reservation{Conflict: true}, nil
	}
	if t.manager.completed != nil {
		return idempotency.Reservation{Replay: true, StatusCode: t.manager.completed.StatusCode, Headers: t.manager.completed.Headers, Body: t.manager.completed.Body}, nil
	}
	return idempotency.Reservation{InProgress: true}, nil
}

func (t *fakeIdempotencyTx) Complete(_ context.Context, _ string, response idempotency.Response) error {
	t.manager.mu.Lock()
	defer t.manager.mu.Unlock()
	copyResponse := response
	copyResponse.Body = append([]byte(nil), response.Body...)
	t.manager.completed = &copyResponse
	return nil
}

func (t *fakeIdempotencyTx) Commit(context.Context) error   { t.closed = true; return nil }
func (t *fakeIdempotencyTx) Rollback(context.Context) error { t.closed = true; return nil }

func TestIdempotencyValidatesCredentialBeforeReplayAndReusesCommittedResponse(t *testing.T) {
	manager := &fakeIdempotencyManager{}
	calls := 0
	validate := func(_ context.Context, _ string, raw string) error {
		if raw != "Bearer valid" {
			return apierr.New("UNAUTHENTICATED", "credential is inactive")
		}
		return nil
	}
	handler := MiddlewareWithIdempotency(Principal, managerHandler(&calls), manager, validate)
	request := func(body, authorization string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://auth.test/v1/members", strings.NewReader(body))
		req.Header.Set("Idempotency-Key", "member-create-1")
		req.Header.Set("Authorization", authorization)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	first := request(`{"name":"one"}`, "Bearer valid")
	if first.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("first response = (%d, calls=%d), want created and one call", first.Code, calls)
	}
	replay := request(`{"name":"one"}`, "Bearer valid")
	if replay.Code != http.StatusCreated || replay.Header().Get("Idempotency-Replayed") != "true" || calls != 1 {
		t.Fatalf("replay = (%d, replay=%q, calls=%d)", replay.Code, replay.Header().Get("Idempotency-Replayed"), calls)
	}
	invalid := request(`{"name":"one"}`, "Bearer revoked")
	if invalid.Code != http.StatusUnauthorized || !strings.Contains(invalid.Body.String(), "UNAUTHENTICATED") || calls != 1 {
		t.Fatalf("invalid credential replay = (%d, %s, calls=%d)", invalid.Code, invalid.Body.String(), calls)
	}
	conflict := request(`{"name":"two"}`, "Bearer valid")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "IDEMPOTENCY_KEY_REUSED") || calls != 1 {
		t.Fatalf("changed request = (%d, %s, calls=%d)", conflict.Code, conflict.Body.String(), calls)
	}
}

func TestCredentialValidationRunsBeforeEveryRoute(t *testing.T) {
	called := 0
	validated := 0
	validate := func(_ context.Context, plane, raw string) error {
		validated++
		if plane != string(Principal) || raw != "Bearer valid" {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "credential is not accepted on this plane")
		}
		return nil
	}
	handler := MiddlewareWithIdempotency(Principal, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }), nil, validate)
	invalid := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	invalid.Header.Set("Authorization", "Bearer wrong")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusUnauthorized || called != 0 || validated != 1 {
		t.Fatalf("invalid credential = (%d, called=%d, validated=%d), want pre-route rejection", invalidResponse.Code, called, validated)
	}
	valid := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	valid.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(httptest.NewRecorder(), valid)
	if called != 1 || validated != 2 {
		t.Fatalf("valid credential did not reach route: called=%d validated=%d", called, validated)
	}
}

func TestProtocolCredentialsAreRoutedOnlyToTheirOwnEndpoint(t *testing.T) {
	for _, tc := range []struct {
		plane          Plane
		method, path   string
		basic, handled bool
	}{
		{Principal, "GET", "/oauth/userinfo", false, true},
		{Principal, "POST", "/oauth/token", true, true},
		{Principal, "POST", "/oauth/userinfo", false, false},
		{Principal, "GET", "/oauth/userinfo/", false, false},
		{Principal, "POST", "/oauth/token", false, false},
		{Principal, "GET", "/oauth/userinfo", true, false},
		{Principal, "GET", "/v1/me", false, false},
		{Principal, "POST", "/oauth/authorize", true, false},
		{Server, "GET", "/oauth/userinfo", false, false},
		{Ops, "POST", "/oauth/token", true, false},
	} {
		t.Run(string(tc.plane)+tc.method+tc.path, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			validate := func(context.Context, string, string) error {
				return apierr.New("UNAUTHENTICATED", "a session is required")
			}
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.basic {
				r.SetBasicAuth("test-client", "test-secret")
			} else {
				r.Header.Set("Authorization", "Bearer oui_test")
			}
			w := httptest.NewRecorder()
			MiddlewareWithIdempotency(tc.plane, next, nil, validate).ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if tc.handled {
				want = http.StatusNoContent
			}
			if w.Code != want {
				t.Fatalf("status=%d, want %d", w.Code, want)
			}
		})
	}
}

func TestCredentialMismatchIsAuditedWithoutSecret(t *testing.T) {
	var gotPlane Plane
	var gotType, gotCode string
	called := false
	validate := func(context.Context, string, string) error {
		return apierr.New("CREDENTIAL_PLANE_MISMATCH", "wrong plane")
	}
	auditFailure := func(_ context.Context, plane Plane, credentialType, code string) error {
		gotPlane, gotType, gotCode = plane, credentialType, code
		return nil
	}
	handler := MiddlewareWithCredentialAudit(Principal, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), validate, auditFailure)
	request := httptest.NewRequest(http.MethodGet, "http://auth.test/v1/me", nil)
	request.Header.Set("Authorization", "Bearer ply_sk_public-prefix.secret-value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("response = %d, called=%v, want audited rejection", response.Code, called)
	}
	if gotPlane != Principal || gotType != "application_api_key" || gotCode != "CREDENTIAL_PLANE_MISMATCH" {
		t.Fatalf("audit = (%s, %s, %s), want principal/application_api_key/CREDENTIAL_PLANE_MISMATCH", gotPlane, gotType, gotCode)
	}
}

func TestIdempotencyRejectsInvalidKeyAndOversizedBody(t *testing.T) {
	manager := &fakeIdempotencyManager{}
	calls := 0
	handler := MiddlewareWithIdempotency(Principal, managerHandler(&calls), manager, nil)
	invalid := httptest.NewRequest(http.MethodPost, "http://auth.test/v1/members", strings.NewReader(`{}`))
	invalid.Header.Set("Idempotency-Key", "bad\nkey")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusBadRequest || !strings.Contains(invalidResponse.Body.String(), "IDEMPOTENCY_KEY_INVALID") {
		t.Fatalf("invalid key response = (%d, %s)", invalidResponse.Code, invalidResponse.Body.String())
	}
	oversized := httptest.NewRequest(http.MethodPost, "http://auth.test/v1/members", strings.NewReader(strings.Repeat("x", maxIdempotencyBody+1)))
	oversized.Header.Set("Idempotency-Key", "large-body")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge || !strings.Contains(oversizedResponse.Body.String(), "REQUEST_BODY_TOO_LARGE") {
		t.Fatalf("oversized body response = (%d, %s)", oversizedResponse.Code, oversizedResponse.Body.String())
	}
	if calls != 0 || manager.reservations != 0 {
		t.Fatalf("handler/reservation ran for invalid idempotency input: calls=%d reservations=%d", calls, manager.reservations)
	}
}

func managerHandler(calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created":true}`))
	})
}
