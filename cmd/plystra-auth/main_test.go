package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestWarnSharedPublicOpsListener(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	warnSharedPublicOpsListener(logger, config.Config{HTTPAddr: ":8080", OpsAddr: ":8080"})
	if !strings.Contains(output.String(), "operations listener shares public listener address") || !strings.Contains(output.String(), "addr=:8080") {
		t.Fatalf("shared listener warning = %q", output.String())
	}
	output.Reset()
	warnSharedPublicOpsListener(logger, config.Config{HTTPAddr: ":8080", OpsAddr: ":8082"})
	if output.Len() != 0 {
		t.Fatalf("unexpected warning for distinct listeners: %q", output.String())
	}
}

func TestShutdownServersHonorsTimeoutForInFlightRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}))
	defer server.Close()
	done := make(chan struct{})
	go func() {
		_, _ = http.Get(server.URL)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	err := shutdownServers([]*http.Server{server.Config}, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("in-flight request did not finish after release")
	}
}

func TestShutdownServersWaitsForInFlightRequestsBeforeTimeout(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- shutdownServers([]*http.Server{server.Config}, time.Second) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not wait for the in-flight request")
	}
	if err := <-requestDone; err != nil {
		t.Fatalf("in-flight request error = %v", err)
	}
}
