package route

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
