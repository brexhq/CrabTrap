package metrics

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNilRegistryIsNoOp(t *testing.T) {
	var r *Registry
	ctx := context.Background()

	// None of these should panic on a nil registry.
	r.RecordRateLimitHit(ctx)
	r.RecordCircuitBreakerTrip(ctx, "bedrock")
	r.RecordApprovalDecision(ctx, "allow", "llm")

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

func TestHandlerExposesRecordedMetrics(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Shutdown(context.Background()) }()

	ctx := context.Background()
	r.RecordRateLimitHit(ctx)
	r.RecordRateLimitHit(ctx)
	r.RecordCircuitBreakerTrip(ctx, "bedrock")
	r.RecordApprovalDecision(ctx, "allow", "llm")
	r.RecordApprovalDecision(ctx, "deny", "llm")

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("handler returned %d, want 200", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	text := string(body)

	// Spot-check that each metric surfaces. Prometheus text format includes
	// HELP+TYPE headers followed by labelled samples; substring matches are
	// enough to catch registration regressions.
	for _, want := range []string{
		"crabtrap_rate_limit_hits_total",
		"crabtrap_llm_circuit_breaker_trips_total",
		"crabtrap_approval_decisions_total",
		`provider="bedrock"`,
		`outcome="allow"`,
		`outcome="deny"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output missing %q\nbody:\n%s", want, text)
		}
	}
}
