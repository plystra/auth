package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/config"
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

func TestReadinessChecksDatabaseMigrationsAndSigningKey(t *testing.T) {
	ctx := context.Background()
	calls := make([]string, 0, 3)
	err := checkReadiness(ctx,
		func(context.Context) error { calls = append(calls, "database"); return nil },
		func(context.Context) error { calls = append(calls, "migrations"); return nil },
		func() error { calls = append(calls, "signing_key"); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(calls, ","), "database,migrations,signing_key"; got != want {
		t.Fatalf("readiness checks = %q, want %q", got, want)
	}
}

func TestReadinessRejectsMigrationFailure(t *testing.T) {
	calledSigningKey := false
	err := checkReadiness(context.Background(),
		func(context.Context) error { return nil },
		func(context.Context) error { return errors.New("migration is behind") },
		func() error { calledSigningKey = true; return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "migration is behind") {
		t.Fatalf("readiness error = %v, want migration failure", err)
	}
	if calledSigningKey {
		t.Fatal("signing key check ran after migration failure")
	}
}

func TestReadinessRejectsSigningKeyFailure(t *testing.T) {
	err := checkReadiness(context.Background(),
		func(context.Context) error { return nil },
		func(context.Context) error { return nil },
		func() error { return errors.New("signing key unavailable") },
	)
	if err == nil || !strings.Contains(err.Error(), "signing key unavailable") {
		t.Fatalf("readiness error = %v, want signing key failure", err)
	}
}

func TestPlaneServersBindDistinctListeners(t *testing.T) {
	addresses := make([]string, 4)
	for i := range addresses {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = listener.Addr().String()
		_ = listener.Close()
	}
	servers := planeServers(config.Config{HTTPAddr: addresses[0], ServerAddr: addresses[1], OpsAddr: addresses[2]}, addresses[3], http.NewServeMux(), http.NewServeMux(), http.NewServeMux(), http.NewServeMux())
	if len(servers) != len(addresses) {
		t.Fatalf("server count = %d, want %d", len(servers), len(addresses))
	}
	listeners := make([]net.Listener, 0, len(servers))
	t.Cleanup(func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if server.Handler == nil {
			t.Fatal("plane server has no handler")
		}
		if _, ok := seen[server.Addr]; ok {
			t.Fatalf("duplicate listener address %q", server.Addr)
		}
		seen[server.Addr] = struct{}{}
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			t.Fatalf("listen on %q: %v", server.Addr, err)
		}
		listeners = append(listeners, listener)
	}
}
