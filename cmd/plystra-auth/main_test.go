package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/config"
	"github.com/plystra/auth/internal/jobs"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

func TestOperatorBootstrapRequiresExclusiveIdentityFlags(t *testing.T) {
	for _, args := range [][]string{
		{"bootstrap"},
		{"bootstrap", "--email", "first@example.test"},
		{"bootstrap", "--user-id", "usr_existing", "--password-stdin"},
		{"bootstrap", "--user-id", "usr_existing", "--email", "first@example.test", "--password-stdin"},
	} {
		cmd := operatorCommand()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "provide either --user-id or --email with --password-stdin") {
			t.Fatalf("flags %v returned %v", args, err)
		}
	}
}

func TestReadBootstrapPasswordAcceptsOneLineWithoutChangingItsContent(t *testing.T) {
	for _, input := range []string{"a password with spaces\n", "a password with spaces\r\n", "a password with spaces"} {
		password, err := readBootstrapPassword(strings.NewReader(input))
		if err != nil || password != "a password with spaces" {
			t.Fatalf("password input was not read as one line: %v", err)
		}
	}
	for _, input := range []string{"", "first\nsecond\n", strings.Repeat("x", security.MaxPasswordBytes+1)} {
		if _, err := readBootstrapPassword(strings.NewReader(input)); err == nil {
			t.Fatal("invalid password input was accepted")
		}
	}
}

func TestOperatorBootstrapCLIEnrollsFirstOperatorFromMigratedDatabase(t *testing.T) {
	ctx := context.Background()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", database.AppURL)
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", database.OwnerURL)
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.example.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("h", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32))))
	initialize := initCommand()
	var initOutput bytes.Buffer
	initialize.SetOut(&initOutput)
	initialize.SetErr(io.Discard)
	if err := initialize.ExecuteContext(ctx); err != nil {
		t.Fatalf("deployment init: %v", err)
	}
	if !strings.Contains(initOutput.String(), "default application:") {
		t.Fatal("deployment init did not report the default application")
	}
	bootstrap := operatorCommand()
	bootstrap.SetArgs([]string{"bootstrap", "--email", " First.Operator@Example.Test ", "--password-stdin"})
	bootstrap.SetIn(strings.NewReader("a-long-bootstrap-password\n"))
	var output bytes.Buffer
	bootstrap.SetOut(&output)
	bootstrap.SetErr(io.Discard)
	if err := bootstrap.ExecuteContext(ctx); err != nil {
		t.Fatalf("operator bootstrap CLI: %v", err)
	}
	if !strings.Contains(output.String(), "operator created: usr_") || !strings.Contains(output.String(), "operator TOTP secret (shown once):") || !strings.Contains(output.String(), "bootstrap API key (shown once): ply_sk_") || strings.Contains(output.String(), "a-long-bootstrap-password") {
		t.Fatal("operator bootstrap CLI output omitted credentials or exposed the password")
	}
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	var operators int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM operators o JOIN users u ON u.id = o.user_id WHERE u.email_normalized = 'first.operator@example.test'`).Scan(&operators); err != nil {
		t.Fatal(err)
	}
	if operators != 1 {
		t.Fatalf("operator bootstrap created %d operators, want one", operators)
	}
}

func TestJWKSWellKnownEndpointPublishesSigningKey(t *testing.T) {
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	registerJWKS(&mux, &session.Service{Signer: signer})
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

func TestPlaneCredentialPrefixesRejectCrossPlaneKeys(t *testing.T) {
	for _, test := range []struct {
		name  string
		plane route.Plane
		raw   string
	}{
		{name: "application on principal", plane: route.Principal, raw: "ply_sk_prefix.secret"},
		{name: "operator on principal", plane: route.Principal, raw: "ply_ops_secret"},
		{name: "agent on server", plane: route.Server, raw: "ply_ag_prefix.secret"},
		{name: "application on ops", plane: route.Ops, raw: "ply_sk_prefix.secret"},
		{name: "agent on ops", plane: route.Ops, raw: "ply_ag_prefix.secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := rejectCredentialPlane(test.plane, test.raw)
			if err == nil || !strings.Contains(err.Error(), "CREDENTIAL_PLANE_MISMATCH") {
				t.Fatalf("rejectCredentialPlane(%s, %q) = %v, want CREDENTIAL_PLANE_MISMATCH", test.plane, test.raw, err)
			}
		})
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

func TestPlaneMaintenanceDoesNotAffectOtherPlanes(t *testing.T) {
	addresses := make([]string, 3)
	listeners := make([]net.Listener, 0, len(addresses))
	for i := range addresses {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = listener.Addr().String()
		listeners = append(listeners, listener)
	}
	servers := planeServers(
		config.Config{HTTPAddr: addresses[0], ServerAddr: addresses[1], OpsAddr: addresses[2]},
		"127.0.0.1:0",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
		}),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		http.NewServeMux(),
	)
	for i, listener := range listeners {
		go func(i int, listener net.Listener) {
			if err := servers[i].Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("plane %d serve: %v", i, err)
			}
		}(i, listener)
	}
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Close()
		}
	})
	for _, test := range []struct {
		name string
		url  string
		want int
	}{
		{name: "principal", url: "http://" + addresses[0], want: http.StatusOK},
		{name: "server maintenance", url: "http://" + addresses[1], want: http.StatusServiceUnavailable},
		{name: "operations", url: "http://" + addresses[2], want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			deadline := time.Now().Add(time.Second)
			for {
				response, err := http.Get(test.url)
				if err == nil {
					defer func() { _ = response.Body.Close() }()
					if response.StatusCode != test.want {
						t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
			}
		})
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
	err := shutdownServers([]*http.Server{server.Config}, jobs.New(context.Background()), 20*time.Millisecond)
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
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- shutdownServers([]*http.Server{server.Config}, jobs.New(context.Background()), time.Second)
	}()
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

func TestShutdownServersWaitsForInFlightTasks(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	tasks := jobs.New(context.Background())
	if !tasks.Start(func(ctx context.Context) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
	}) {
		t.Fatal("task was not accepted before shutdown")
	}
	<-started
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- shutdownServers(nil, tasks, time.Second) }()
	time.Sleep(20 * time.Millisecond)
	close(release)
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("shutdown error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not wait for the in-flight task")
	}
	if tasks.Start(func(context.Context) {}) {
		t.Fatal("task started after shutdown")
	}
}

func TestShutdownServersHonorsTaskTimeout(t *testing.T) {
	tasks := jobs.New(context.Background())
	release := make(chan struct{})
	if !tasks.Start(func(context.Context) { <-release }) {
		t.Fatal("task was not accepted before shutdown")
	}
	err := shutdownServers(nil, tasks, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error = %v, want deadline exceeded", err)
	}
	close(release)
}
