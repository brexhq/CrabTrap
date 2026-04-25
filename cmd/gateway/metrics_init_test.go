package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/config"
	"github.com/brexhq/CrabTrap/internal/metrics"
)

// TestInitMetricsDisabledReturnsNil makes sure initMetrics is a no-op when
// observability is off.
func TestInitMetricsDisabledReturnsNil(t *testing.T) {
	r := initMetrics(config.MetricsConfig{Enabled: false}, "v0", "abc", "now")
	if r != nil {
		t.Fatalf("disabled metrics should return nil, got %+v", r)
	}
}

// TestInitMetricsContinuesOnFactoryFailure confirms the gateway data plane
// stays up when metrics initialisation fails. A failed metrics.New() must log
// and return nil — never abort the process — so the LLM trust-boundary proxy
// is not blocked by an observability subsystem error.
func TestInitMetricsContinuesOnFactoryFailure(t *testing.T) {
	saved := metricsRegistryFactory
	t.Cleanup(func() { metricsRegistryFactory = saved })

	metricsRegistryFactory = func() (*metrics.Registry, error) {
		return nil, errors.New("simulated init failure")
	}

	r := initMetrics(
		config.MetricsConfig{Enabled: true, Listen: "127.0.0.1:0"},
		"v0", "abc", "2026-04-25T00:00:00Z",
	)
	if r != nil {
		t.Fatalf("init failure should return nil registry, got %+v", r)
	}
}

// TestStartMetricsServerServesScrape exercises the standalone metrics
// listener: it serves /metrics without auth, returns 200, and binds to the
// configured address. This is the contract Prometheus scrapers depend on.
func TestStartMetricsServerServesScrape(t *testing.T) {
	r, err := metrics.New()
	if err != nil {
		t.Fatalf("metrics.New: %v", err)
	}
	t.Cleanup(func() { _ = r.Shutdown(context.Background()) })

	// Bind to an ephemeral port; SplitHostPort lets us pick it up after Listen.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	srv := startMetricsServer(addr, r.Handler())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// Give the goroutine a moment to bind. Polling avoids a flaky sleep.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + addr + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("scrape never succeeded: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape returned %d, want 200", resp.StatusCode)
	}

	// Confirm only /metrics is mounted — any other path returns 404.
	other, err := http.Get("http://" + addr + "/admin/health")
	if err != nil {
		t.Fatalf("probe other path: %v", err)
	}
	defer other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("non-metrics path returned %d, want 404", other.StatusCode)
	}
}
