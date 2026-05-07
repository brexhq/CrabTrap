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
	"sync"
	"time"

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

	// Counters
	rateLimitHits       metric.Int64Counter
	circuitBreakerTrips metric.Int64Counter
	approvalDecisions   metric.Int64Counter
	alertDenialsBuffered   metric.Int64Counter
	alertNotificationsSent metric.Int64Counter
	alertFlushErrors       metric.Int64Counter

	// Histograms
	judgeLatency    metric.Float64Histogram
	approvalLatency metric.Float64Histogram

	// Gauges — circuit-breaker state is an observable gauge backed by an
	// internal provider-keyed map. Per-provider state writes go through
	// setCircuitBreakerState, which the observable callback reads during
	// scrape. Using an observable gauge keeps the "state at scrape time"
	// semantics correct under concurrent transitions without exposing a
	// register/unregister API.
	cbStateMu    sync.RWMutex
	cbStateByKey map[string]int64

	// Build info is emitted as an observable gauge with a constant value of 1
	// and the version/commit/go_version as labels. Standard Prometheus pattern.
	buildInfoMu   sync.RWMutex
	buildInfoAttr []attribute.KeyValue
}

// New creates a Registry backed by an OTel MeterProvider with a Prometheus
// bridge exporter. Callers should pass the returned Registry to the components
// they want to instrument. The returned Handler serves `/metrics` in Prometheus
// text format.
//
// New is atomic: if any instrument registration fails, it returns (nil, err) —
// a partially-populated Registry never reaches a call site. This is what makes
// the `if r == nil { return }` guard in every Record* method sufficient.
func New() (*Registry, error) {
	reg := promclient.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, err
	}

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter("github.com/brexhq/CrabTrap")

	r := &Registry{
		provider:     provider,
		reg:          reg,
		cbStateByKey: make(map[string]int64),
	}

	if r.rateLimitHits, err = meter.Int64Counter(
		"crabtrap_rate_limit_hits_total",
		metric.WithDescription("Requests rejected by the per-IP rate limiter."),
	); err != nil {
		return nil, err
	}

	if r.circuitBreakerTrips, err = meter.Int64Counter(
		"crabtrap_llm_circuit_breaker_trips_total",
		metric.WithDescription("Times an LLM adapter's circuit breaker tripped open, labelled by provider."),
	); err != nil {
		return nil, err
	}

	if r.approvalDecisions, err = meter.Int64Counter(
		"crabtrap_approval_decisions_total",
		metric.WithDescription("Approval decisions, labelled by outcome and approval mode."),
	); err != nil {
		return nil, err
	}

	if r.alertDenialsBuffered, err = meter.Int64Counter(
		"crabtrap_alerting_denials_buffered_total",
		metric.WithDescription("Denials written to the alerting buffer."),
	); err != nil {
		return nil, err
	}

	if r.alertNotificationsSent, err = meter.Int64Counter(
		"crabtrap_alerting_notifications_sent_total",
		metric.WithDescription("Denial alert notifications sent, labelled by channel type."),
	); err != nil {
		return nil, err
	}

	if r.alertFlushErrors, err = meter.Int64Counter(
		"crabtrap_alerting_flush_errors_total",
		metric.WithDescription("Errors during alerting flush (summarize or send failures)."),
	); err != nil {
		return nil, err
	}

	if r.judgeLatency, err = meter.Float64Histogram(
		"crabtrap_judge_latency_seconds",
		metric.WithDescription("LLM judge call latency in seconds, labelled by provider and model."),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}

	if r.approvalLatency, err = meter.Float64Histogram(
		"crabtrap_approval_latency_seconds",
		metric.WithDescription("End-to-end approval pipeline latency in seconds, labelled by mode and outcome."),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}

	if _, err = meter.Int64ObservableGauge(
		"crabtrap_llm_circuit_breaker_state",
		metric.WithDescription("Circuit breaker state per LLM provider: 0 = closed, 1 = open."),
		metric.WithInt64Callback(func(_ context.Context, obs metric.Int64Observer) error {
			r.cbStateMu.RLock()
			defer r.cbStateMu.RUnlock()
			for provider, state := range r.cbStateByKey {
				obs.Observe(state, metric.WithAttributes(attribute.String("provider", provider)))
			}
			return nil
		}),
	); err != nil {
		return nil, err
	}

	if _, err = meter.Int64ObservableGauge(
		"crabtrap_build_info",
		metric.WithDescription("Build identification with constant value 1; labels carry the payload."),
		metric.WithInt64Callback(func(_ context.Context, obs metric.Int64Observer) error {
			r.buildInfoMu.RLock()
			defer r.buildInfoMu.RUnlock()
			if len(r.buildInfoAttr) == 0 {
				return nil
			}
			obs.Observe(1, metric.WithAttributes(r.buildInfoAttr...))
			return nil
		}),
	); err != nil {
		return nil, err
	}

	return r, nil
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

// RecordCircuitBreakerState updates the per-provider circuit-breaker state gauge.
// open == true → 1 (open), open == false → 0 (closed).
func (r *Registry) RecordCircuitBreakerState(_ context.Context, provider string, open bool) {
	if r == nil {
		return
	}
	r.cbStateMu.Lock()
	defer r.cbStateMu.Unlock()
	if open {
		r.cbStateByKey[provider] = 1
	} else {
		r.cbStateByKey[provider] = 0
	}
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

// RecordJudgeLatency records the duration of an LLM judge call.
func (r *Registry) RecordJudgeLatency(ctx context.Context, provider, model string, d time.Duration) {
	if r == nil {
		return
	}
	r.judgeLatency.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("provider", provider),
		attribute.String("model", model),
	))
}

// RecordApprovalLatency records the end-to-end approval pipeline duration.
func (r *Registry) RecordApprovalLatency(ctx context.Context, mode, outcome string, d time.Duration) {
	if r == nil {
		return
	}
	r.approvalLatency.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("mode", mode),
		attribute.String("outcome", outcome),
	))
}

// RecordBuildInfo sets the labels for the crabtrap_build_info gauge. Called once
// at startup. Labels are empty strings if not supplied; the gauge emits nothing
// until RecordBuildInfo has been called.
//
// buildDate is the build timestamp (typically RFC3339 UTC) injected via
// `-ldflags -X main.buildDate=...` so operators can correlate metric anomalies
// with the release that produced them.
func (r *Registry) RecordBuildInfo(version, commit, goVersion, buildDate string) {
	if r == nil {
		return
	}
	r.buildInfoMu.Lock()
	defer r.buildInfoMu.Unlock()
	r.buildInfoAttr = []attribute.KeyValue{
		attribute.String("version", version),
		attribute.String("commit", commit),
		attribute.String("go_version", goVersion),
		attribute.String("build_date", buildDate),
	}
}

// RecordAlertDenialBuffered increments the buffered denial counter.
func (r *Registry) RecordAlertDenialBuffered(ctx context.Context) {
	if r == nil {
		return
	}
	r.alertDenialsBuffered.Add(ctx, 1)
}

// RecordAlertNotificationSent increments the notification-sent counter.
func (r *Registry) RecordAlertNotificationSent(ctx context.Context, channelType string) {
	if r == nil {
		return
	}
	r.alertNotificationsSent.Add(ctx, 1, metric.WithAttributes(
		attribute.String("channel_type", channelType),
	))
}

// RecordAlertFlushError increments the flush-error counter.
func (r *Registry) RecordAlertFlushError(ctx context.Context, reason string) {
	if r == nil {
		return
	}
	r.alertFlushErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}
