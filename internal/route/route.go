package route

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/danielgtaylor/huma/v2"
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
	NonJSON            bool
}
type Handler func(http.ResponseWriter, *http.Request)

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
	if spec.Permission == "" && !contains(spec.Subjects, Public) {
		panic("route: non-public route requires permission")
	}
	registry.Lock()
	registry.specs = append(registry.specs, spec)
	registry.Unlock()
	huma.Register(api, huma.Operation{OperationID: spec.Name, Method: spec.Method, Path: spec.Path, Summary: spec.Name}, handler)
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
func ContextPlane(ctx context.Context) Plane { p, _ := ctx.Value(planeKey{}).(Plane); return p }

type planeKey struct{}

func WithPlane(ctx context.Context, p Plane) context.Context {
	return context.WithValue(ctx, planeKey{}, p)
}
func Middleware(p Plane, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithPlane(r.Context(), p)))
	})
}

var _ = fmt.Sprintf
