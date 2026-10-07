package route

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

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

type Spec struct {
	Name               string
	Method             string
	Path               string
	Plane              Plane
	Permission         string
	Subjects           []Subject
	StepUp             bool
	AuthoritativeCheck bool
	MaxBodyBytes       int64
	NonJSON            bool
}
type Handler func(http.ResponseWriter, *http.Request)
type OriginPolicy func(context.Context, string) (bool, error)
type CredentialFailureAuditor func(context.Context, Plane, string, string) error

var registry struct {
	sync.RWMutex
	specs []Spec
}

func Specs() []Spec {
	registry.RLock()
	defer registry.RUnlock()
	out := make([]Spec, len(registry.specs))
	copy(out, registry.specs)
	return out
}
func Register[I, O any](api huma.API, spec Spec, handler func(context.Context, *I) (*O, error)) {
	if spec.Name == "" || spec.Method == "" || spec.Path == "" || spec.Plane == "" || len(spec.Subjects) == 0 {
		panic("route: incomplete route.Spec")
	}
	if spec.Permission == "" && !contains(spec.Subjects, Public) && !userOnly(spec.Subjects) {
		panic("route: non-public route requires permission")
	}
	registry.Lock()
	registry.specs = append(registry.specs, spec)
	registry.Unlock()
	maxBodyBytes := spec.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = 64 * 1024
	}
	huma.Register(api, huma.Operation{OperationID: spec.Name, Method: spec.Method, Path: spec.Path, Summary: spec.Name, MaxBodyBytes: maxBodyBytes}, func(ctx context.Context, input *I) (*O, error) {
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
func RegisterNonJSON(mux *http.ServeMux, spec Spec, handler http.Handler) {
	if !spec.NonJSON {
		panic("route: non-json route must set NonJSON")
	}
	if spec.Name == "" || spec.Method == "" || spec.Path == "" || spec.Plane == "" {
		panic("route: incomplete route.Spec")
	}
	registry.Lock()
	registry.specs = append(registry.specs, spec)
	registry.Unlock()
	mux.Handle(spec.Method+" "+spec.Path, handler)
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
	return middlewareWithAudit(p, next, nil, nil, validate, auditFailure)
}

func MiddlewareWithOriginPolicyAndIdempotency(p Plane, next http.Handler, policy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) http.Handler {
	return middleware(p, next, policy, manager, validate)
}

func MiddlewareWithOriginPolicyAndIdempotencyAndCredentialAudit(p Plane, next http.Handler, policy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor) http.Handler {
	return middlewareWithAudit(p, next, policy, manager, validate, auditFailure)
}

func middleware(p Plane, next http.Handler, originPolicy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator) http.Handler {
	return middlewareWithAudit(p, next, originPolicy, manager, validate, nil)
}

func middlewareWithAudit(p Plane, next http.Handler, originPolicy OriginPolicy, manager idempotency.TransactionManager, validate idempotency.CredentialValidator, auditFailure CredentialFailureAuditor) http.Handler {
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
