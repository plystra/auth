package main

import (
	"encoding/json"
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
