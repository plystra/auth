package protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWellKnownMetadataEndpoints(t *testing.T) {
	var mux http.ServeMux
	(HTTP{Issuer: "https://auth.test"}).Register(&mux)
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
	} {
		t.Run(path, func(t *testing.T) {
			res := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			mux.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", res.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{
				"issuer":                 "https://auth.test",
				"authorization_endpoint": "https://auth.test/oauth/authorize",
				"token_endpoint":         "https://auth.test/oauth/token",
				"jwks_uri":               "https://auth.test/.well-known/jwks.json",
			} {
				if body[key] != want {
					t.Fatalf("%s = %v, want %s", key, body[key], want)
				}
			}
		})
	}
}
