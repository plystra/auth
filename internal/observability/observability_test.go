package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestHTTPMetricsExposePlaneAttribute(t *testing.T) {
	provider, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = provider.Shutdown(t.Context()) }()
	handler := provider.HTTP("principal", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	response := httptest.NewRecorder()
	provider.MetricsHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "plystra_auth_http_requests_total{") || !strings.Contains(body, `plane="principal"`) {
		t.Fatalf("metrics response = (%d, %s), want principal counter", response.Code, body)
	}
}

func TestHTTPTraceCarriesPlaneAttribute(t *testing.T) {
	provider, err := New()
	if err != nil {
		t.Fatal(err)
	}
	exporter := tracetest.NewInMemoryExporter()
	provider.TracerProvider = trace.NewTracerProvider(trace.WithSyncer(exporter))
	defer func() { _ = provider.Shutdown(t.Context()) }()
	provider.HTTP("ops", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/ops/v1/settings", nil))
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want one HTTP span", len(spans))
	}
	for _, attr := range spans[0].Attributes {
		if string(attr.Key) == "plane" {
			if got := attr.Value.AsString(); got != "ops" {
				t.Fatalf("plane attribute = %q, want ops", got)
			}
			return
		}
	}
	t.Fatal("trace did not contain plane attribute")
}
