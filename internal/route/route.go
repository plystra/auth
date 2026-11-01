package route

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/idempotency"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
)

type Plane string

const (
	Principal Plane = "principal"
	Server    Plane = "server"
	Ops       Plane = "ops"
)

type Subject string

const (
	Public     Subject = "public"
	Human      Subject = "H"
	HumanAgent Subject = "H/A"
	User       Subject = "U"
)

// Declaration is the immutable metadata snapshot exposed by Specs. Callers
// create route declarations through NewSpec so all required fields are
// present at compile time.
type Declaration struct {
	Name                  string
	Method                string
	Path                  string
	Plane                 Plane
	Permission            string
	ConditionalPermission string
	Subjects              []Subject
	StepUp                bool
	AuthoritativeCheck    bool
	MaxBodyBytes          int64
	NonJSON               bool
}

// Spec can only be created by NewSpec. Its unexported method prevents callers
// from constructing a partial declaration or implementing the contract
// outside this package.
type Spec interface {
	declaration() Declaration
}

type declaredSpec struct{ value Declaration }

func (s declaredSpec) declaration() Declaration { return s.value }

type SpecOption func(*Declaration)

func WithStepUp() SpecOption {
	return func(spec *Declaration) { spec.StepUp = true }
}

func WithConditionalPermission(permission string) SpecOption {
	return func(spec *Declaration) { spec.ConditionalPermission = permission }
}

func WithAuthoritativeCheck() SpecOption {
	return func(spec *Declaration) { spec.AuthoritativeCheck = true }
}

func WithMaxBodyBytes(size int64) SpecOption {
	return func(spec *Declaration) { spec.MaxBodyBytes = size }
}

func WithNonJSON() SpecOption {
	return func(spec *Declaration) { spec.NonJSON = true }
}

func NewSpec(name, method, path string, plane Plane, permission string, subjects []Subject, options ...SpecOption) Spec {
	value := Declaration{
		Name: name, Method: method, Path: path, Plane: plane,
		Permission: permission, Subjects: append([]Subject(nil), subjects...),
	}
	for _, option := range options {
		if option != nil {
			option(&value)
		}
	}
	return declaredSpec{value: value}
}

type Handler func(http.ResponseWriter, *http.Request)
type HandlerMux interface {
	Handle(string, http.Handler)
}

// Mux records every handler installed on an interaction-plane mux. Production
// startup validates the recorded patterns against route.Spec declarations so
// a protocol handler cannot bypass the route registry.
type Mux struct {
	*http.ServeMux
	mu       sync.RWMutex
	patterns map[string]struct{}
}

func NewMux() *Mux {
	return &Mux{ServeMux: http.NewServeMux(), patterns: make(map[string]struct{})}
}

func (m *Mux) Handle(pattern string, handler http.Handler) {
	m.record(pattern)
	m.ServeMux.Handle(pattern, handler)
}

func (m *Mux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.record(pattern)
	m.ServeMux.HandleFunc(pattern, handler)
}

func (m *Mux) record(pattern string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patterns[pattern] = struct{}{}
}

// Validate rejects handlers installed without a corresponding route.Spec.
// It is intentionally called after all JSON and protocol registrations for a
// plane have completed.
func Validate(mux *Mux) error {
	if mux == nil {
		return errors.New("route: nil mux")
	}
	declared := make(map[string]struct{})
	registry.RLock()
	for _, spec := range registry.specs {
		declared[spec.Method+" "+spec.Path] = struct{}{}
	}
	registry.RUnlock()
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	for pattern := range mux.patterns {
		if _, ok := declared[pattern]; !ok {
			return fmt.Errorf("route: handler %q has no route.Spec declaration", pattern)
		}
	}
	return nil
}

type OriginPolicy func(context.Context, string) (bool, error)
type CredentialFailureAuditor func(context.Context, Plane, string, string) error
type RateLimitFunc func(context.Context, string, int, time.Duration) (bool, error)

// PlaneRateLimit returns the default transport budgets. The budgets are
// intentionally independent so a noisy public request stream cannot consume
// the server or operations plane's capacity.
func PlaneRateLimit(p Plane) (int, time.Duration) {
	switch p {
	case Principal:
		return 600, time.Minute
	case Server:
		return 1200, time.Minute
	case Ops:
		return 300, time.Minute
	default:
		return 0, 0
	}
}

var registry struct {
	sync.RWMutex
	specs []Declaration
}

func Specs() []Declaration {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]Declaration, len(registry.specs))
	copy(out, registry.specs)
	for i := range out {
		out[i].Subjects = append([]Subject(nil), out[i].Subjects...)
	}
	return out
}
func Register[I, O any](api huma.API, spec Spec, handler func(context.Context, *I) (*O, error)) {
	declaration, ok := getDeclaration(spec)
	if !ok || declaration.Name == "" || declaration.Method == "" || declaration.Path == "" || declaration.Plane == "" || len(declaration.Subjects) == 0 {
		panic("route: incomplete route.Spec")
	}
	if declaration.Permission == "" && !contains(declaration.Subjects, Public) && !userOnly(declaration.Subjects) {
		panic("route: non-public route requires permission")
	}
	registry.Lock()
	registry.specs = append(registry.specs, declaration)
	registry.Unlock()
	maxBodyBytes := declaration.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = 64 * 1024
	}
	huma.Register(api, huma.Operation{OperationID: declaration.Name, Method: declaration.Method, Path: declaration.Path, Summary: declaration.Name, MaxBodyBytes: maxBodyBytes}, func(ctx context.Context, input *I) (*O, error) {
		out, err := handler(ctx, input)
		if err == nil {
			return out, nil
		}
		var public *apierr.Error
		if !errors.As(err, &public) {
			public = apierr.New("UNAVAILABLE", "The service is temporarily unavailable.")
		}
		return nil, apierr.WithRequestID(public, requestinfo.Get(ctx).ID)
	})
}
func RegisterNonJSON(mux HandlerMux, spec Spec, handler http.Handler) {
	declaration, ok := getDeclaration(spec)
	if !ok || !declaration.NonJSON {
		panic("route: non-json route must set NonJSON")
	}
	if declaration.Name == "" || declaration.Method == "" || declaration.Path == "" || declaration.Plane == "" {
		panic("route: incomplete route.Spec")
	}
	registry.Lock()
	registry.specs = append(registry.specs, declaration)
	registry.Unlock()
	mux.Handle(declaration.Method+" "+declaration.Path, handler)
}

func getDeclaration(spec Spec) (Declaration, bool) {
	if spec == nil {
		return Declaration{}, false
	}
	return spec.declaration(), true
}
func contains(ss []Subject, want Subject) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func userOnly(subjects []Subject) bool {
	return len(subjects) == 1 && subjects[0] == User
}

type planeKey struct{}

func ContextPlane(ctx context.Context) Plane { p, _ := ctx.Value(planeKey{}).(Plane); return p }
func WithPlane(ctx context.Context, p Plane) context.Context {
	return context.WithValue(ctx, planeKey{}, p)
}
func Middleware(p Plane, next http.Handler) http.Handler {
	return middleware(p, next, nil, nil, nil)
}

func MiddlewareWithOriginPolicy(p Plane, next http.Handler, policy OriginPolicy) http.Handler {
	return middleware(p, next, policy, nil, nil)
}

func MiddlewareWithIdempotency(p Plane, next http.Handler, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) http.Handler {
	return middleware(p, next, nil, manager, validate)
}

func MiddlewareWithCredentialAudit(p Plane, next http.Handler, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor) http.Handler {
	return middlewareWithAudit(p, next, nil, nil, validate, auditFailure, nil)
}

func MiddlewareWithOriginPolicyAndIdempotency(p Plane, next http.Handler, policy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) http.Handler {
	return middleware(p, next, policy, manager, validate)
}

func MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAudit(p Plane, next http.Handler, policy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor) http.Handler {
	return middlewareWithAudit(p, next, policy, manager, validate, auditFailure, nil)
}

func MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAuditAndRateLimit(p Plane, next http.Handler, policy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor, rateLimit RateLimitFunc) http.Handler {
	return middlewareWithAudit(p, next, policy, manager, validate, auditFailure, rateLimit)
}

func middleware(p Plane, next http.Handler, originPolicy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) http.Handler {
	return middlewareWithAudit(p, next, originPolicy, manager, validate, nil, nil)
}

func middlewareWithAudit(p Plane, next http.Handler, originPolicy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor, rateLimit RateLimitFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if id == "" || len(id) > 128 {
			id = string(ids.New[ids.ID]("req"))
		}
		w.Header().Set("X-Request-Id", id)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ctx := requestinfo.With(WithPlane(r.Context(), p), requestinfo.Info{ID: id, Plane: string(p), IP: net.ParseIP(host)})
		if p == Server && r.Header.Get("Origin") != "" {
			apierr.Write(w, apierr.WithRequestID(apierr.New("BROWSER_ORIGIN_REJECTED", "service endpoints do not accept browser origins"), id))
			return
		}
		if p == Principal && r.Header.Get("Origin") != "" {
			origin := r.Header.Get("Origin")
			allowed := false
			var err error
			if originPolicy != nil {
				allowed, err = originPolicy(ctx, origin)
			}
			if err != nil {
				apierr.Write(w, apierr.WithRequestID(apierr.New("UNAVAILABLE", "origin policy is temporarily unavailable"), id))
				return
			}
			if !allowed {
				apierr.Write(w, apierr.WithRequestID(apierr.New("CORS_ORIGIN_REJECTED", "the origin is not allowed"), id))
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key, X-Request-Id")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		if rateLimit != nil && r.Method != http.MethodOptions {
			limit, window := PlaneRateLimit(p)
			if limit > 0 {
				key := transportRateLimitKey(p, requestinfo.Get(ctx).IP)
				allowed, err := rateLimit(ctx, key, limit, window)
				if err != nil {
					writeRouteError(w, ctx, apierr.New("UNAVAILABLE", "request rate limiting is temporarily unavailable"))
					return
				}
				if !allowed {
					writeRouteError(w, ctx, apierr.New("rate_limited", "too many requests"))
					return
				}
			}
		}
		request := r.WithContext(ctx)
		if validate != nil && strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			if err := validate(ctx, string(p), r.Header.Get("Authorization")); err != nil {
				if auditFailure != nil {
					if auditErr := auditFailure(ctx, p, credentialType(r.Header.Get("Authorization")), credentialErrorCode(err)); auditErr != nil {
						writeRouteError(w, ctx, apierr.New("UNAVAILABLE", "credential audit is temporarily unavailable"))
						return
					}
				}
				writeRouteError(w, ctx, err)
				return
			}
		}
		if manager != nil && isWriteMethod(r.Method) {
			serveIdempotent(w, request, next, p, manager, nil)
			return
		}
		next.ServeHTTP(w, request)
	})
}

func transportRateLimitKey(p Plane, ip net.IP) string {
	identity := "unknown"
	if len(ip) > 0 {
		identity = ip.String()
	}
	digest := sha256.Sum256([]byte("plystra-auth:plane-rate:" + string(p) + ":" + identity))
	return "plane:" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func credentialType(value string) string {
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return "unknown"
	}
	switch {
	case strings.HasPrefix(parts[1], "ply_sk_"):
		return "application_api_key"
	case strings.HasPrefix(parts[1], "ply_ag_"):
		return "agent_key"
	case strings.HasPrefix(parts[1], "ply_ops_"):
		return "operator_session"
	case strings.HasPrefix(parts[1], "ply_rt_"):
		return "refresh_token"
	default:
		return "access_token"
	}
}

func credentialErrorCode(err error) string {
	var public *apierr.Error
	if errors.As(err, &public) && public.Code != "" {
		return public.Code
	}
	return "UNAUTHENTICATED"
}
