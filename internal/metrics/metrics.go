// Package metrics provides an optional OpenTelemetry metrics surface for CrabTrap,
// exposed over a Prometheus scrape endpoint.
//
// The package is designed so every call site is safe against a nil Registry, which
// is what callers get when observability is disabled in config. This keeps the
// hot-path instrumentation branch-free and removes the need for per-call feature
// flags.
package metrics

import (
	"context"
	"net/http"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Registry is the central holder for all instruments. A nil *Registry is valid:
// every recording method is a no-op on it. Disabled observability therefore
// costs a single nil check per instrumentation site.
type Registry struct {
	provider *sdkmetric.MeterProvider
	reg      *promclient.Registry

	rateLimitHits         metric.Int64Counter
	circuitBreakerTrips   metric.Int64Counter
	approvalDecisions     metric.Int64Counter
}

// New creates a Registry backed by an OTel MeterProvider with a Prometheus
// bridge exporter. Callers should pass the returned Registry to the components
// they want to instrument. The returned Handler serves `/metrics` in Prometheus
// text format.
func New() (*Registry, error) {
	reg := promclient.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, err
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter("github.com/brexhq/CrabTrap")

	rateLimitHits, err := meter.Int64Counter(
		"crabtrap_rate_limit_hits_total",
		metric.WithDescription("Requests rejected by the per-IP rate limiter."),
	)
	if err != nil {
		return nil, err
	}

	cbTrips, err := meter.Int64Counter(
		"crabtrap_llm_circuit_breaker_trips_total",
		metric.WithDescription("Times an LLM adapter's circuit breaker tripped open."),
	)
	if err != nil {
		return nil, err
	}

	approvals, err := meter.Int64Counter(
		"crabtrap_approval_decisions_total",
		metric.WithDescription("Approval decisions, labelled by outcome and approval mode."),
	)
	if err != nil {
		return nil, err
	}

	return &Registry{
		provider:            provider,
		reg:                 reg,
		rateLimitHits:       rateLimitHits,
		circuitBreakerTrips: cbTrips,
		approvalDecisions:   approvals,
	}, nil
}

// Handler returns an http.Handler that serves the Prometheus scrape endpoint.
// Returns a 503 handler for a nil Registry so callers can mount unconditionally.
func (r *Registry) Handler() http.Handler {
	if r == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics disabled", http.StatusServiceUnavailable)
		})
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Shutdown flushes and releases the underlying MeterProvider. Safe on nil.
func (r *Registry) Shutdown(ctx context.Context) error {
	if r == nil || r.provider == nil {
		return nil
	}
	return r.provider.Shutdown(ctx)
}

// RecordRateLimitHit increments the rate-limit-rejection counter.
func (r *Registry) RecordRateLimitHit(ctx context.Context) {
	if r == nil {
		return
	}
	r.rateLimitHits.Add(ctx, 1)
}

// RecordCircuitBreakerTrip increments the circuit-breaker-trip counter, labelled
// by provider name (e.g. "bedrock", "anthropic", "openai").
func (r *Registry) RecordCircuitBreakerTrip(ctx context.Context, provider string) {
	if r == nil {
		return
	}
	r.circuitBreakerTrips.Add(ctx, 1, metric.WithAttributes(
		attribute.String("provider", provider),
	))
}

// RecordApprovalDecision increments the approval-decisions counter, labelled
// by outcome ("allow" | "deny") and mode ("llm" | "passthrough").
func (r *Registry) RecordApprovalDecision(ctx context.Context, outcome, mode string) {
	if r == nil {
		return
	}
	r.approvalDecisions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
		attribute.String("mode", mode),
	))
}
