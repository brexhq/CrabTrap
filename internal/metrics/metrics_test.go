package metrics

import (
	"context"
	"io"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNilRegistryIsNoOp(t *testing.T) {
	var r *Registry
	ctx := context.Background()

	// None of these should panic on a nil registry.
	r.RecordRateLimitHit(ctx)
	r.RecordCircuitBreakerTrip(ctx, "bedrock")
	r.RecordCircuitBreakerState(ctx, "bedrock", true)
	r.RecordApprovalDecision(ctx, "allow", "llm")
	r.RecordJudgeLatency(ctx, "bedrock", "claude-sonnet-4", 42*time.Millisecond)
	r.RecordApprovalLatency(ctx, "llm", "allow", 17*time.Millisecond)
	r.RecordBuildInfo("v0.0.0", "deadbeef", runtime.Version(), "2026-04-25T00:00:00Z")

	if err := r.Shutdown(ctx); err != nil {
		t.Fatalf("nil Shutdown returned error: %v", err)
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("nil Handler returned %d, want 503", rec.Code)
	}
}

func TestHandlerExposesAllInstruments(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()

	ctx := context.Background()
	r.RecordRateLimitHit(ctx)
	r.RecordRateLimitHit(ctx)
	r.RecordCircuitBreakerTrip(ctx, "bedrock")
	r.RecordCircuitBreakerState(ctx, "bedrock", true)
	r.RecordCircuitBreakerState(ctx, "openai", false)
	r.RecordApprovalDecision(ctx, "allow", "llm")
	r.RecordApprovalDecision(ctx, "deny", "llm")
	r.RecordJudgeLatency(ctx, "bedrock", "claude-opus-4-5", 42*time.Millisecond)
	r.RecordJudgeLatency(ctx, "bedrock", "claude-opus-4-5", 137*time.Millisecond)
	r.RecordApprovalLatency(ctx, "llm", "allow", 58*time.Millisecond)
	r.RecordBuildInfo("v1.2.3", "abc1234", "go1.26.0", "2026-04-24T18:30:00Z")

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("handler returned %d, want 200", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	text := string(body)

	// Every metric name + at least one label assertion per instrument so
	// registration regressions and label-path regressions both surface here.
	for _, want := range []string{
		// Counters
		"crabtrap_rate_limit_hits_total",
		"crabtrap_llm_circuit_breaker_trips_total",
		"crabtrap_approval_decisions_total",
		// Histograms -- prom format suffixes histograms with _bucket/_sum/_count
		"crabtrap_judge_latency_seconds_bucket",
		"crabtrap_judge_latency_seconds_sum",
		"crabtrap_judge_latency_seconds_count",
		"crabtrap_approval_latency_seconds_bucket",
		// Gauges
		"crabtrap_llm_circuit_breaker_state",
		"crabtrap_build_info",
		// Label values
		`provider="bedrock"`,
		`provider="openai"`,
		`outcome="allow"`,
		`outcome="deny"`,
		`mode="llm"`,
		`model="claude-opus-4-5"`,
		`version="v1.2.3"`,
		`commit="abc1234"`,
		`go_version="go1.26.0"`,
		`build_date="2026-04-24T18:30:00Z"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestCircuitBreakerStateTracksTransitions(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()
	ctx := context.Background()

	r.RecordCircuitBreakerState(ctx, "bedrock", true)
	if got := readGauge(t, r, "bedrock"); got != 1 {
		t.Fatalf("after trip, bedrock state = %d, want 1", got)
	}

	r.RecordCircuitBreakerState(ctx, "bedrock", false)
	if got := readGauge(t, r, "bedrock"); got != 0 {
		t.Fatalf("after reset, bedrock state = %d, want 0", got)
	}
}

// readGauge scrapes the handler and returns the current value of the
// circuit_breaker_state gauge for the given provider. Zero if not present.
func readGauge(t *testing.T, r *Registry, provider string) int {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	needle := `crabtrap_llm_circuit_breaker_state{otel_scope_name="github.com/brexhq/CrabTrap"`
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, needle) {
			continue
		}
		if !strings.Contains(line, `provider="`+provider+`"`) {
			continue
		}
		// Last space-separated token is the value.
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if parts[len(parts)-1] == "1" {
			return 1
		}
		return 0
	}
	return 0
}
