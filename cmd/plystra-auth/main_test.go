package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plystra/auth/internal/security"
)

func TestJWKSWellKnownEndpointPublishesSigningKey(t *testing.T) {
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	registerJWKS(&mux, signer)
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Code)
	}
	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) != 1 || body.Keys[0]["alg"] != "ES256" || body.Keys[0]["use"] != "sig" {
		t.Fatalf("JWKS = %+v, want one ES256 signing key", body.Keys)
	}
}

func TestHealthEndpointsReportLivenessAndReadiness(t *testing.T) {
	var mux http.ServeMux
	registerHealth(&mux, func(context.Context) error { return nil })

	res := httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if res.Code != http.StatusOK || res.Body.String() != `{"status":"ok"}` {
		t.Fatalf("healthz = (%d, %q), want (200, ok)", res.Code, res.Body.String())
	}

	res = httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if res.Code != http.StatusOK || res.Body.String() != `{"status":"ready"}` {
		t.Fatalf("readyz = (%d, %q), want (200, ready)", res.Code, res.Body.String())
	}
}

func TestReadyEndpointReportsDependencyFailure(t *testing.T) {
	var mux http.ServeMux
	registerHealth(&mux, func(context.Context) error { return errors.New("database unavailable") })

	res := httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if res.Code != http.StatusServiceUnavailable || res.Body.String() != `{"status":"not_ready"}`+"\n" {
		t.Fatalf("readyz failure = (%d, %q), want (503, not_ready)", res.Code, res.Body.String())
	}
}
