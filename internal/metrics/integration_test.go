package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMetricsEndpointEndToEnd exercises the Prometheus scrape endpoint after
// simulated traffic in every instrumented layer:
//   - rate-limit rejections
//   - circuit-breaker transitions
//   - approval decisions (allow + deny)
//   - judge latency on two models
//   - approval latency
//   - build info
//
// The test runs against a real httptest.Server, scrapes the endpoint over HTTP,
// and parses the response text for each expected series. This is the contract
// an operator's Prometheus scrape job will see.
func TestMetricsEndpointEndToEnd(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()

	r.RecordBuildInfo("v1.2.3", "abc123def", "go1.26.2", "2026-04-25T12:34:56Z")

	mux := http.NewServeMux()
	mux.Handle("/metrics", r.Handler())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()

	// Simulate 3 rate-limit rejections.
	for i := 0; i < 3; i++ {
		r.RecordRateLimitHit(ctx)
	}

	// Simulate a bedrock circuit-breaker trip followed by a reset.
	r.RecordCircuitBreakerTrip(ctx, "bedrock")
	r.RecordCircuitBreakerState(ctx, "bedrock", true)
	r.RecordCircuitBreakerState(ctx, "bedrock", false)

	// Simulate a concurrent burst of approval decisions through the registry.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome := "allow"
			if i%3 == 0 {
				outcome = "deny"
			}
			r.RecordApprovalDecision(ctx, outcome, "llm")
			r.RecordApprovalLatency(ctx, "llm", outcome, time.Duration(20+i*5)*time.Millisecond)
		}(i)
	}
	wg.Wait()

	// Simulate judge latency across two models.
	for _, sample := range []struct {
		provider, model string
		d               time.Duration
	}{
		{"bedrock", "claude-opus-4-5", 92 * time.Millisecond},
		{"bedrock", "claude-opus-4-5", 134 * time.Millisecond},
		{"openai", "gpt-4o", 58 * time.Millisecond},
	} {
		r.RecordJudgeLatency(ctx, sample.provider, sample.model, sample.d)
	}

	// Scrape over real HTTP.
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("scrape returned %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	for _, want := range []struct {
		name  string
		check string
	}{
		{"rate-limit counter present", "crabtrap_rate_limit_hits_total"},
		{"rate-limit counter reached 3", `crabtrap_rate_limit_hits_total{otel_scope_name="github.com/brexhq/CrabTrap",otel_scope_schema_url="",otel_scope_version=""} 3`},
		{"circuit-breaker trip counter", `crabtrap_llm_circuit_breaker_trips_total{otel_scope_name="github.com/brexhq/CrabTrap",otel_scope_schema_url="",otel_scope_version="",provider="bedrock"} 1`},
		{"circuit-breaker state gauge for bedrock (reset to closed)", `crabtrap_llm_circuit_breaker_state{otel_scope_name="github.com/brexhq/CrabTrap",otel_scope_schema_url="",otel_scope_version="",provider="bedrock"} 0`},
		{"approval decisions counter present", "crabtrap_approval_decisions_total"},
		{"approval decisions mode label", `mode="llm"`},
		{"approval decisions allow outcome", `outcome="allow"`},
		{"approval decisions deny outcome", `outcome="deny"`},
		{"approval latency histogram", "crabtrap_approval_latency_seconds_bucket"},
		{"judge latency histogram", "crabtrap_judge_latency_seconds_bucket"},
		{"judge latency bedrock label", `provider="bedrock"`},
		{"judge latency openai label", `provider="openai"`},
		{"judge latency model label", `model="claude-opus-4-5"`},
		{"build info with version", `version="v1.2.3"`},
		{"build info with commit", `commit="abc123def"`},
		{"build info with go_version", `go_version="go1.26.2"`},
		{"build info with build_date", `build_date="2026-04-25T12:34:56Z"`},
	} {
		if !strings.Contains(text, want.check) {
			t.Errorf("%s: not found\nlooked for: %q", want.name, want.check)
		}
	}

	// Sanity-check: approval-decisions total == 10.
	if !containsLineWithSum(text, "crabtrap_approval_decisions_total", 10) {
		t.Errorf("approval_decisions_total across all labels should sum to 10; body:\n%s", text)
	}
}

// containsLineWithSum verifies that the sum of values for all labelled series
// of `metric` equals `want`. This is how a scrape consumer would verify the
// total regardless of label fan-out.
func containsLineWithSum(text, metric string, want int) bool {
	var total int
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, metric) {
			continue
		}
		// Skip HELP / TYPE descriptor lines.
		if strings.HasPrefix(line, "# ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// Last field is the value.
		v := parts[len(parts)-1]
		// Simple int parse; Prometheus counters come out as integers when
		// whole. Skip non-integer values.
		n := 0
		for _, ch := range v {
			if ch < '0' || ch > '9' {
				n = -1
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n >= 0 {
			total += n
		}
	}
	return total == want
}
