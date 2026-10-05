package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/config"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/plane/ops"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/plane/server"
	"github.com/plystra/auth/internal/protocol"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
)

func main() {
	root := &cobra.Command{Use: "plystra-auth", Short: "Plystra Auth identity and authorization service"}
	root.AddCommand(serveCommand(), migrateCommand(), doctorCommand(), verifyCommand(), operatorCommand(), permissionsCommand(), policyCommand())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func loadConfig() (config.Config, error) { return config.Load() }
func serveCommand() *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "run the HTTP service", RunE: func(cmd *cobra.Command, args []string) error { return serve(cmd.Context()) }}
}
func migrateCommand() *cobra.Command {
	return &cobra.Command{Use: "migrate", Short: "apply forward-only PostgreSQL migrations", RunE: func(cmd *cobra.Command, args []string) error {
		c, e := loadConfig()
		if e != nil {
			return e
		}
		return store.Migrate(cmd.Context(), c.DatabaseURL)
	}}
}
func doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "check configuration and database connectivity", RunE: func(cmd *cobra.Command, args []string) error {
		c, e := loadConfig()
		if e != nil {
			return e
		}
		s, e := store.Open(cmd.Context(), c.DatabaseURL)
		if e != nil {
			return e
		}
		defer s.Close()
		fmt.Println("database: ok")
		return nil
	}}
}
func verifyCommand() *cobra.Command {
	return &cobra.Command{Use: "verify", Short: "verify route declarations and configuration", RunE: func(cmd *cobra.Command, args []string) error {
		for _, s := range route.Specs() {
			if s.Name == "" || s.Path == "" {
				return errors.New("invalid route declaration")
			}
		}
		fmt.Printf("routes: %d\n", len(route.Specs()))
		return nil
	}}
}
func operatorCommand() *cobra.Command {
	var email, password string
	cmd := &cobra.Command{Use: "operator", Short: "manage deployment operators"}
	bootstrap := &cobra.Command{Use: "bootstrap", Short: "create the first operator through the local CLI", RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(email) == "" || password == "" {
			return errors.New("--email and --password are required")
		}
		c, e := loadConfig()
		if e != nil {
			return e
		}
		st, e := store.Open(cmd.Context(), c.DatabaseURL)
		if e != nil {
			return e
		}
		defer st.Close()
		var created, apiKey string
		e = st.InTx(cmd.Context(), func(q *db.Queries) error {
			count, e := q.CountOperators(cmd.Context())
			if e != nil {
				return e
			}
			if count != 0 {
				return errors.New("an operator already exists; use the operations plane")
			}
			normalized := strings.ToLower(strings.TrimSpace(email))
			hash, e := security.DefaultPasswordHasher().Hash(password)
			if e != nil {
				return e
			}
			u, e := q.CreateUser(cmd.Context(), db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: normalized, EmailNormalized: normalized, PasswordHash: hash})
			if e != nil {
				return e
			}
			m, e := q.CreateMember(cmd.Context(), db.CreateMemberParams{ID: string(ids.New[ids.MemberID]("mem")), SpaceID: account.DefaultSpaceID, Name: normalized, Kind: "user"})
			if e != nil {
				return e
			}
			if e = q.LinkUserMember(cmd.Context(), db.LinkUserMemberParams{UserID: u.ID, MemberID: m.ID}); e != nil {
				return e
			}
			caps, _ := json.Marshal([]string{"*"})
			rawKey, prefix, keyHash, keyErr := application.GenerateSecret()
			if keyErr != nil {
				return keyErr
			}
			apiKey = rawKey
			if _, e = q.CreateAPIKey(cmd.Context(), db.CreateAPIKeyParams{ID: string(ids.New[ids.APIKeyID]("key")), ApplicationID: "app_01h00000000000000000000000", Name: "bootstrap", Prefix: prefix, SecretHash: keyHash, Scopes: []byte(`["authz:check","tokens:introspect"]`)}); e != nil {
				return e
			}
			if e = q.CreateOperator(cmd.Context(), db.CreateOperatorParams{UserID: u.ID, Capabilities: caps}); e != nil {
				return e
			}
			created = u.ID
			return nil
		})
		if e != nil {
			return e
		}
		fmt.Printf("operator created: %s\\nbootstrap API key (shown once): %s\\n", created, apiKey)
		return nil
	}}
	bootstrap.Flags().StringVar(&email, "email", "", "operator email")
	bootstrap.Flags().StringVar(&password, "password", "", "operator password")
	cmd.AddCommand(bootstrap)
	return cmd
}
func permissionsCommand() *cobra.Command {
	return &cobra.Command{Use: "permissions", Short: "permission catalog operations"}
}
func policyCommand() *cobra.Command {
	return &cobra.Command{Use: "policy", Short: "authorization policy operations"}
}
func serve(ctx context.Context) error {
	c, e := loadConfig()
	if e != nil {
		return e
	}
	st, e := store.Open(ctx, c.DatabaseURL)
	if e != nil {
		return e
	}
	defer st.Close()
	var signer *security.Signer
	if c.SigningKeyFile != "" {
		signer, e = security.NewSigner(c.SigningKeyFile, c.Issuer)
	} else {
		signer, e = security.GenerateSigner(c.Issuer)
	}
	if e != nil {
		return e
	}
	settings := &space.Service{Store: st}
	sessionSvc := &session.Service{Store: st, Signer: signer, HMACKeys: parseKeys(c.SessionHMACKeys)}
	sessionSvc.Settings = func(ctx context.Context) (session.Settings, error) {
		v, e := settings.Get(ctx)
		if e != nil {
			return session.Settings{}, e
		}
		return session.Settings{AccessTTL: v.AccessTokenTTL, RefreshTTL: v.RefreshTokenTTL, RefreshIdleTTL: v.RefreshIdleTTL}, nil
	}
	limiter := &store.RateLimiter{Store: st}
	accounts := &account.Service{Store: st, Passwords: security.DefaultPasswordHasher(), Sessions: sessionSvc, Settings: settings, Limiter: limiter}
	apps := &application.Service{Store: st}
	principalAPI := &principal.API{Accounts: accounts, Sessions: sessionSvc, Signer: signer}
	serverAPI := &server.API{Applications: apps, Members: &member.Service{Store: st}, Sessions: sessionSvc}
	opsAPI := &ops.API{Settings: settings, Signer: signer}
	principalMux := http.NewServeMux()
	serverMux := http.NewServeMux()
	opsMux := http.NewServeMux()
	pcfg := huma.DefaultConfig("Plystra Auth principal", "1.0.0")
	pcfg.Info.Description = "User and agent authentication"
	scfg := huma.DefaultConfig("Plystra Auth server", "1.0.0")
	ocfg := huma.DefaultConfig("Plystra Auth operations", "1.0.0")
	principalAPI.Register(humago.New(principalMux, pcfg))
	protocol.HTTP{Issuer: c.Issuer}.Register(principalMux)
	serverAPI.Register(humago.New(serverMux, scfg))
	opsAPI.Register(humago.New(opsMux, ocfg))
	route.RegisterNonJSON(principalMux, route.Spec{Name: "jwks", Method: "GET", Path: "/.well-known/jwks.json", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signer.JWKS())
	}))
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	health.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if e := st.Pool.Ping(r.Context()); e != nil {
			http.Error(w, `{"status":"not_ready"}`, 503)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	servers := []*http.Server{{Addr: c.HTTPAddr, Handler: otelhttp.NewHandler(route.Middleware(route.Principal, principalMux), "principal")}, {Addr: c.ServerAddr, Handler: otelhttp.NewHandler(route.Middleware(route.Server, serverMux), "server")}, {Addr: c.OpsAddr, Handler: otelhttp.NewHandler(route.Middleware(route.Ops, opsMux), "ops")}, {Addr: ":8090", Handler: health}}
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) { slog.Info("starting listener", "addr", srv.Addr); errs <- srv.ListenAndServe() }(srv)
	}
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-sigCtx.Done():
	case e := <-errs:
		if !errors.Is(e, http.ErrServerClosed) {
			return e
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), c.ShutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	return nil
}
func parseKeys(v string) [][]byte {
	var out [][]byte
	for _, part := range strings.Split(v, ",") {
		if strings.TrimSpace(part) != "" {
			out = append(out, []byte(strings.TrimSpace(part)))
		}
	}
	return out
}
func randomID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

var _ = sha256.Sum256
var _ = time.Second
