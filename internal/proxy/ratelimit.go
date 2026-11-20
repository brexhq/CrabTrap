package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxCachedLimiters = 100_000
	// Displaced buckets are extra state keyed by attacker-chosen IPs, so their
	// number is kept well below the live cache.
	defaultEvictedCap = maxCachedLimiters / 4
	// A displaced bucket is kept this long so a returning client resumes its
	// remaining tokens instead of getting a fresh full bucket.
	evictedLimiterTTL = 10 * time.Minute
	// Full scans of the evicted map are amortized; evictions can occur per request.
	evictedPruneInterval = time.Minute
)

// RateLimitObserver is called once per request that the per-IP limiter
// rejects. Implementations must be safe for concurrent use. The hook is
// optional: a nil observer disables recording. Kept as a small interface
// here (instead of depending on internal/metrics directly) so ratelimit
// stays testable without pulling in the OTel stack.
type RateLimitObserver interface {
	OnRateLimitHit()
}

// evictedLimiter holds a bucket displaced from the LRU so its token state can
// be restored when that client returns.
type evictedLimiter struct {
	limiter *rate.Limiter
	at      time.Time
}

// ipRateLimiter implements per-source-IP rate limiting using token buckets.
// Each unique client IP gets its own rate.Limiter stored in an LRU cache.
// When the cache is at capacity, the least recently seen IP's limiter is
// moved to evicted so its bucket state survives until the client returns.
type ipRateLimiter struct {
	cache    *lruCache[*rate.Limiter]
	rate     rate.Limit
	burst    int
	observer RateLimitObserver
	// evicted is guarded by cache.mu: both the eviction hook and create
	// callback run under that lock.
	evicted          map[string]evictedLimiter
	evictedOrder     []string // eviction keys in insertion order; stale keys are skipped on eviction
	nextEvictedPrune time.Time
	// evictedCap bounds displaced buckets; zero means defaultEvictedCap.
	evictedCap int
}

// newIPRateLimiter creates a per-IP rate limiter with the given rate (requests/sec)
// and burst size. The LRU cache bounds memory to maxEntries IPs.
func newIPRateLimiter(r float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		cache:      newLRUCache[*rate.Limiter](maxCachedLimiters),
		rate:       rate.Limit(r),
		burst:      burst,
		evictedCap: defaultEvictedCap,
	}
}

// evictedLimit returns the effective cap on displaced buckets.
func (rl *ipRateLimiter) evictedLimit() int {
	if rl.evictedCap > 0 {
		return rl.evictedCap
	}
	return defaultEvictedCap
}

// setObserver attaches a RateLimitObserver. Safe to call once during wiring;
// not intended for dynamic reconfiguration.
func (rl *ipRateLimiter) setObserver(obs RateLimitObserver) {
	rl.observer = obs
}

// pruneEvicted drops state old enough that its bucket would have refilled
// anyway. Caller holds cache.mu. Scans are rate-limited so IP churn cannot
// turn eviction into an O(map) pass on every request.
func (rl *ipRateLimiter) pruneEvicted(now time.Time) {
	if now.Before(rl.nextEvictedPrune) {
		return
	}
	for ip, e := range rl.evicted {
		if now.Sub(e.at) > evictedLimiterTTL {
			delete(rl.evicted, ip)
		}
	}
	// Restores and the deletes above shrink the map without touching the
	// order slice, so drop its stale keys here or it grows without bound.
	rl.compactEvictedOrder()
	rl.nextEvictedPrune = now.Add(evictedPruneInterval)
}

// compactEvictedOrder drops keys no longer in evicted and duplicate entries.
// Caller holds cache.mu.
func (rl *ipRateLimiter) compactEvictedOrder() {
	seen := make(map[string]struct{}, len(rl.evicted))
	live := rl.evictedOrder[:0]
	for _, ip := range rl.evictedOrder {
		if _, ok := rl.evicted[ip]; !ok {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		live = append(live, ip)
	}
	rl.evictedOrder = live
}

// oldestEvicted returns the next eviction victim in FIFO order, skipping keys
// that prune or a cache hit already removed. Keys seeded straight into the map
// (tests) are untracked, so they fall back to a timestamp scan. Caller holds
// cache.mu.
func (rl *ipRateLimiter) oldestEvicted() string {
	if len(rl.evictedOrder) >= len(rl.evicted) {
		for len(rl.evictedOrder) > 0 {
			ip := rl.evictedOrder[0]
			rl.evictedOrder = rl.evictedOrder[1:]
			if _, ok := rl.evicted[ip]; ok {
				return ip
			}
		}
	}
	var oldestIP string
	var oldestAt time.Time
	first := true
	for ip, e := range rl.evicted {
		if first || e.at.Before(oldestAt) {
			oldestIP, oldestAt, first = ip, e.at, false
		}
	}
	return oldestIP
}

// Allow checks whether a request from the given IP should be allowed.
// Returns true if the request is within the rate limit, false if it should
// be rejected with 429.
func (rl *ipRateLimiter) Allow(ip string) bool {
	now := time.Now()
	limiter := rl.cache.GetOrCreateWithEvict(ip, func() *rate.Limiter {
		if e, ok := rl.evicted[ip]; ok && now.Sub(e.at) <= evictedLimiterTTL {
			delete(rl.evicted, ip)
			return e.limiter
		}
		return rate.NewLimiter(rate.Limit(rl.rate), rl.burst)
	}, func(evictedIP string, old *rate.Limiter) {
		if rl.evicted == nil {
			rl.evicted = make(map[string]evictedLimiter)
		}
		rl.evicted[evictedIP] = evictedLimiter{limiter: old, at: now}
		rl.evictedOrder = append(rl.evictedOrder, evictedIP)
		// Prunes are amortized (once a minute), so bound the order slice
		// between them or per-request eviction grows it without limit.
		if len(rl.evictedOrder) > 2*len(rl.evicted)+64 {
			rl.compactEvictedOrder()
		}
		limit := rl.evictedLimit()
		for len(rl.evicted) > limit {
			victim := rl.oldestEvicted()
			if victim == "" {
				break
			}
			delete(rl.evicted, victim)
		}
		rl.pruneEvicted(now)
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
