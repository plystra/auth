//go:build interop

package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/plystra/auth/internal/security"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/oauth2"
)

const workforceUpstreamHost = "idp.workforce.test"

type workforceProcessProxy struct {
	front  *httptest.Server
	active atomic.Pointer[httputil.ReverseProxy]
}

func newWorkforceProcessProxy(t *testing.T) *workforceProcessProxy {
	t.Helper()
	proxy := &workforceProcessProxy{}
	proxy.front = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if active := proxy.active.Load(); active != nil {
			active.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	// The TLS fixture client routes this certificate-valid domain locally.
	proxy.front.URL = "https://auth.example.com"
	t.Cleanup(proxy.front.Close)
	return proxy
}

func (p *workforceProcessProxy) start(t *testing.T, rp *humanRP, idp keycloakInstance) func() {
	t.Helper()
	ctx := t.Context()
	binary := filepath.Join(t.TempDir(), "plystra-auth")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, "./cmd/plystra-auth")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Auth service: %v\n%s", err, out)
	}
	var dbHost string
	var dbPort int
	if err := rp.st.Pool.QueryRow(ctx, "SELECT host(inet_server_addr()), inet_server_port()").Scan(&dbHost, &dbPort); err != nil {
		t.Fatal("read disposable database network binding", err)
	}
	databaseURL := func(raw string) string {
		t.Helper()
		uri, err := url.Parse(raw)
		if err != nil {
			t.Fatal("invalid fixture database URL")
		}
		uri.Host = net.JoinHostPort(dbHost, strconv.Itoa(dbPort))
		return uri.String()
	}
	var wrappingKey [32]byte
	_, _ = rand.Read(wrappingKey[:])
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := security.EncryptSigningKeyPEM(signer, wrappingKey[:])
	if err != nil {
		t.Fatal(err)
	}
	start := func() (testcontainers.Container, *httputil.ReverseProxy) {
		t.Helper()
		process, err := testcontainers.Run(ctx, "alpine:3.22",
			testcontainers.WithImagePlatform("linux/"+runtime.GOARCH),
			testcontainers.WithCmd("/usr/local/bin/plystra-auth", "serve"),
			testcontainers.WithFiles(
				testcontainers.ContainerFile{HostFilePath: binary, ContainerFilePath: "/usr/local/bin/plystra-auth", FileMode: 0555},
				testcontainers.ContainerFile{Reader: bytes.NewReader(encrypted), ContainerFilePath: "/run/issuer.pem", FileMode: 0400},
				testcontainers.ContainerFile{Reader: bytes.NewReader(idp.certPEM), ContainerFilePath: "/run/idp.pem", FileMode: 0444},
			),
			testcontainers.WithEnv(map[string]string{
				"PLYSTRA_AUTH_DATABASE_URL":               databaseURL(rp.database.AppURL),
				"PLYSTRA_AUTH_MIGRATION_DATABASE_URL":     databaseURL(rp.database.OwnerURL),
				"PLYSTRA_AUTH_ISSUER":                     p.front.URL,
				"PLYSTRA_AUTH_SESSION_HMAC_KEYS":          strings.Repeat("k", 32),
				"PLYSTRA_AUTH_DATA_KEY":                   base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))),
				"PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString(wrappingKey[:]),
				"PLYSTRA_AUTH_SIGNING_KEY_FILE":           "/run/issuer.pem",
				"SSL_CERT_FILE":                           "/run/idp.pem",
			}),
			testcontainers.WithHostConfigModifier(func(cfg *container.HostConfig) {
				cfg.ExtraHosts = append(cfg.ExtraHosts, workforceUpstreamHost+":"+idp.ip)
				cfg.PortBindings = network.PortMap{network.MustParsePort("8080/tcp"): {{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"}}}
			}),
			testcontainers.WithExposedPorts("8080/tcp"),
			testcontainers.WithWaitStrategy(wait.ForHTTP("/.well-known/openid-configuration").WithPort("8080/tcp")),
		)
		if process != nil {
			t.Cleanup(func() { _ = process.Terminate(context.Background()) })
		}
		if err != nil {
			t.Fatal("start independent Auth service", err)
		}
		endpoint, err := process.PortEndpoint(ctx, "8080/tcp", "http")
		if err != nil {
			t.Fatal(err)
		}
		target, err := url.Parse(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		return process, httputil.NewSingleHostReverseProxy(target)
	}
	primary, first := start()
	_, peer := start()
	p.active.Store(first)
	rp.provider, err = oidc.NewProvider(oidc.ClientContext(ctx, p.front.Client()), p.front.URL)
	if err != nil {
		t.Fatal("discover the public process issuer", err)
	}
	rp.config.Endpoint = rp.provider.Endpoint()
	rp.config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return func() {
		t.Helper()
		if p.active.Load() != first {
			t.Fatal("the pending upstream callback must have started at the primary")
		}
		timeout := time.Duration(0)
		if err := primary.Stop(ctx, &timeout); err != nil {
			t.Fatal("stop the primary Auth process", err)
		}
		state, err := primary.State(ctx)
		if err != nil || state.Running || state.Status != "exited" {
			t.Fatal("the primary Auth process did not exit", err)
		}
		p.active.Store(peer)
	}
}
