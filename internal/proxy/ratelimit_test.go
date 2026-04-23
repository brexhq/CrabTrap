package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestIPRateLimiter_AllowWithinLimit(t *testing.T) {
	rl := newIPRateLimiter(10, 10) // 10 req/s, burst 10

	// First 10 requests (burst) should all be allowed.
	for i := 0; i < 10; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Fatalf("Request %d should have been allowed", i+1)
		}
	}
}

func TestIPRateLimiter_RejectsOverBurst(t *testing.T) {
	rl := newIPRateLimiter(1, 5) // 1 req/s, burst 5

	// Exhaust the burst.
	for i := 0; i < 5; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Fatalf("Request %d within burst should be allowed", i+1)
		}
	}

	// Next request should be rejected (no tokens left, refill is slow).
	if rl.Allow("10.0.0.1") {
		t.Fatal("Request after burst exhaustion should be rejected")
	}
}

func TestIPRateLimiter_PerIPIsolation(t *testing.T) {
	rl := newIPRateLimiter(1, 2) // 1 req/s, burst 2

	// Exhaust burst for IP-A.
	rl.Allow("ip-a")
	rl.Allow("ip-a")
	if rl.Allow("ip-a") {
		t.Fatal("ip-a should be rate limited after exhausting burst")
	}

	// IP-B should be completely unaffected.
	if !rl.Allow("ip-b") {
		t.Fatal("ip-b should not be rate limited; it has its own bucket")
	}
	if !rl.Allow("ip-b") {
		t.Fatal("ip-b second request should also be allowed (within burst)")
	}
}

func TestIPRateLimiter_TokenRefill(t *testing.T) {
	// High rate so tokens refill quickly in a test.
	rl := newIPRateLimiter(1000, 1) // 1000 req/s, burst 1

	// Use the one burst token.
	if !rl.Allow("refill-ip") {
		t.Fatal("First request should be allowed")
	}
	if rl.Allow("refill-ip") {
		t.Fatal("Second immediate request should be rejected (burst=1)")
	}

	// Wait for a token to refill (at 1000/s, 2ms is plenty).
	time.Sleep(5 * time.Millisecond)

	if !rl.Allow("refill-ip") {
		t.Fatal("Request after token refill should be allowed")
	}
}

func TestIPRateLimiter_LRUEviction(t *testing.T) {
	rl := &ipRateLimiter{
		cache: newLRUCache[*rate.Limiter](3),
		rate:  1000,
		burst: 1000,
	}

	// Fill the cache to capacity.
	rl.Allow("ip-a")
	rl.Allow("ip-b")
	rl.Allow("ip-c")
	if rl.Len() != 3 {
		t.Fatalf("Expected 3 tracked IPs, got %d", rl.Len())
	}

	// Adding a 4th IP should evict the least recently used (ip-a).
	rl.Allow("ip-d")
	if rl.Len() != 3 {
		t.Fatalf("Cache should not grow beyond maxEntries, got %d", rl.Len())
	}

	// ip-a should have been evicted and get a fresh limiter.
	// ip-b, ip-c, ip-d should still be cached.
	for _, ip := range []string{"ip-b", "ip-c", "ip-d"} {
		if _, ok := rl.cache.Get(ip); !ok {
			t.Fatalf("Expected %q to still be in cache", ip)
		}
	}
}

func TestIPRateLimiter_LRUEvictionPreservesActive(t *testing.T) {
	rl := &ipRateLimiter{
		cache: newLRUCache[*rate.Limiter](3),
		rate:  1000,
		burst: 2,
	}

	rl.Allow("ip-a")
	rl.Allow("ip-b")
	rl.Allow("ip-c")

	// Access ip-a to make it most recently used.
	rl.Allow("ip-a")

	// Adding ip-d should evict ip-b (now least recently used), not ip-a.
	rl.Allow("ip-d")

	if _, ok := rl.cache.Get("ip-b"); ok {
		t.Fatal("Expected ip-b to be evicted")
	}
	if _, ok := rl.cache.Get("ip-a"); !ok {
		t.Fatal("Expected ip-a to survive eviction (recently used)")
	}
}

func TestIPRateLimiter_MaxEntriesBoundsMemory(t *testing.T) {
	rl := &ipRateLimiter{
		cache: newLRUCache[*rate.Limiter](5),
		rate:  1000,
		burst: 1000,
	}

	// Add more IPs than capacity.
	for i := 0; i < 20; i++ {
		rl.Allow(fmt.Sprintf("ip-%d", i))
	}

	if rl.Len() != 5 {
		t.Fatalf("Expected cache to be capped at 5 entries, got %d", rl.Len())
	}
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		expected   string
	}{
		{"192.168.1.1:12345", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"10.0.0.5:0", "10.0.0.5"},
		{"bare-addr-no-port", "bare-addr-no-port"}, // graceful fallback
	}
	for _, tt := range tests {
		r := &http.Request{RemoteAddr: tt.remoteAddr}
		got := extractClientIP(r)
		if got != tt.expected {
			t.Errorf("extractClientIP(%q) = %q, want %q", tt.remoteAddr, got, tt.expected)
		}
	}
}

func TestRateLimitMiddleware_Passes(t *testing.T) {
	rl := newIPRateLimiter(100, 100)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	limited := rateLimitMiddleware(rl, w, r)
	if limited {
		t.Fatal("Request within limit should not be rate-limited")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_Returns429WithHeaders(t *testing.T) {
	rl := newIPRateLimiter(1, 1) // 1 req/s, burst 1

	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	// Exhaust burst.
	w1 := httptest.NewRecorder()
	rateLimitMiddleware(rl, w1, r)

	// Second request should get 429 with proper headers.
	w2 := httptest.NewRecorder()
	limited := rateLimitMiddleware(rl, w2, r)
	if !limited {
		t.Fatal("Request exceeding limit should be rate-limited")
	}
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") != "1" {
		t.Errorf("Expected Retry-After: 1, got %q", w2.Header().Get("Retry-After"))
	}
	if w2.Header().Get("Connection") != "close" {
		t.Errorf("Expected Connection: close, got %q", w2.Header().Get("Connection"))
	}
}

func TestRateLimitMiddleware_NilLimiter(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "1.2.3.4:5678"

	limited := rateLimitMiddleware(nil, w, r)
	if limited {
		t.Fatal("Nil limiter should not rate-limit anything")
	}
}

type countingObserver struct {
	hits int
}

func (c *countingObserver) OnRateLimitHit() { c.hits++ }

func TestRateLimitMiddleware_NotifiesObserverOnReject(t *testing.T) {
	rl := newIPRateLimiter(1, 1)
	obs := &countingObserver{}
	rl.setObserver(obs)

	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "9.9.9.9:1000"

	// Exhaust the burst — this is allowed, so no observer call expected.
	rateLimitMiddleware(rl, httptest.NewRecorder(), r)
	if obs.hits != 0 {
		t.Fatalf("observer should not fire on allowed request, got %d hits", obs.hits)
	}

	// Next request hits the limit; observer should fire exactly once.
	rateLimitMiddleware(rl, httptest.NewRecorder(), r)
	if obs.hits != 1 {
		t.Fatalf("observer should fire once on rejection, got %d hits", obs.hits)
	}
}
