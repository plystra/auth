package observability

import (
	"context"
	"errors"
	"net/http"

	"github.com/plystra/auth/internal/route"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Provider struct {
	MeterProvider  *sdkmetric.MeterProvider
	TracerProvider *sdktrace.TracerProvider
	Registry       *prometheus.Registry
	requests       metric.Int64Counter
}

func New() (*Provider, error) {
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, err
	}
	meters := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	traces := NewTracerProvider()
	requests, err := meters.Meter("github.com/plystra/auth").Int64Counter(
		"plystra.auth.http.requests",
		metric.WithDescription("HTTP requests handled by each interaction plane."),
	)
	if err != nil {
		_ = meters.Shutdown(context.Background())
		_ = traces.Shutdown(context.Background())
		return nil, err
	}
	otel.SetMeterProvider(meters)
	otel.SetTracerProvider(traces)
	return &Provider{MeterProvider: meters, TracerProvider: traces, Registry: registry, requests: requests}, nil
}

func NewTracerProvider(options ...sdktrace.TracerProviderOption) *sdktrace.TracerProvider {
	options = append(options, sdktrace.WithSpanProcessor(planeSpanProcessor{}))
	return sdktrace.NewTracerProvider(options...)
}

type planeSpanProcessor struct{}

func (planeSpanProcessor) OnStart(ctx context.Context, span sdktrace.ReadWriteSpan) {
	if plane := route.ContextPlane(ctx); plane != "" {
		span.SetAttributes(attribute.String("plane", string(plane)))
	}
}

func (planeSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)      {}
func (planeSpanProcessor) Shutdown(context.Context) error   { return nil }
func (planeSpanProcessor) ForceFlush(context.Context) error { return nil }

func (p *Provider) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(p.Registry, promhttp.HandlerOpts{})
}

func (p *Provider) HTTP(plane string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := p.TracerProvider.Tracer("github.com/plystra/auth").Start(
			r.Context(), "auth.http", trace.WithAttributes(attribute.String("plane", plane)),
		)
		defer span.End()
		p.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("plane", plane)))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	return errors.Join(p.MeterProvider.Shutdown(ctx), p.TracerProvider.Shutdown(ctx))
}
