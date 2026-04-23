package proxy

import (
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/time/rate"
)

const defaultMaxEntries = 100_000

// RateLimitObserver is called once per request that the per-IP limiter
// rejects. Implementations must be safe for concurrent use. The hook is
// optional: a nil observer disables recording. Kept as a small interface
// here (instead of depending on internal/metrics directly) so ratelimit
// stays testable without pulling in the OTel stack.
type RateLimitObserver interface {
	OnRateLimitHit()
}

// ipRateLimiter implements per-source-IP rate limiting using token buckets.
// Each unique client IP gets its own rate.Limiter stored in an LRU cache.
// When the cache is at capacity, the least recently seen IP's limiter is
// evicted to bound memory.
type ipRateLimiter struct {
	cache    *lruCache[*rate.Limiter]
	rate     rate.Limit
	burst    int
	observer RateLimitObserver
}

// newIPRateLimiter creates a per-IP rate limiter with the given rate (requests/sec)
// and burst size. The LRU cache bounds memory to maxEntries IPs.
func newIPRateLimiter(r float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		cache: newLRUCache[*rate.Limiter](defaultMaxEntries),
		rate:  rate.Limit(r),
		burst: burst,
	}
}

// setObserver attaches a RateLimitObserver. Safe to call once during wiring;
// not intended for dynamic reconfiguration.
func (rl *ipRateLimiter) setObserver(obs RateLimitObserver) {
	rl.observer = obs
}

// Allow checks whether a request from the given IP should be allowed.
// Returns true if the request is within the rate limit, false if it should
// be rejected with 429.
func (rl *ipRateLimiter) Allow(ip string) bool {
	limiter := rl.cache.GetOrCreate(ip, func() *rate.Limiter {
		return rate.NewLimiter(rl.rate, rl.burst)
	})
	return limiter.Allow()
}

// Len returns the number of tracked IPs (used in tests).
func (rl *ipRateLimiter) Len() int {
	return rl.cache.Len()
}

// extractClientIP extracts the IP address from an http.Request's RemoteAddr.
// RemoteAddr is typically "IP:port" for TCP connections.
func extractClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port (unusual but handle gracefully).
		return r.RemoteAddr
	}
	return host
}

// rateLimitMiddleware checks the per-IP rate limiter and returns 429 if exceeded.
// Returns true if the request was rate-limited (caller should stop processing).
func rateLimitMiddleware(rl *ipRateLimiter, w http.ResponseWriter, r *http.Request) bool {
	if rl == nil {
		return false
	}
	ip := extractClientIP(r)
	if !rl.Allow(ip) {
		slog.Debug("rate-limited request", "ip", ip, "method", r.Method, "host", r.Host)
		if rl.observer != nil {
			rl.observer.OnRateLimitHit()
		}
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Connection", "close")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return true
	}
	return false
}
