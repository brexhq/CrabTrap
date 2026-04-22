package llm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Default concurrency and circuit breaker settings.
const (
	DefaultMaxConcurrency          = 100
	DefaultCircuitBreakerThreshold = 5
	DefaultCircuitBreakerCooldown  = 10 * time.Second
)

// Resilience provides concurrency limiting (semaphore) and circuit breaker
// behaviour that can be embedded in any Adapter implementation.
type Resilience struct {
	// Concurrency semaphore: limits the number of parallel API calls.
	semaphore chan struct{}

	// Circuit breaker state, protected by cbMu.
	cbMu                sync.Mutex
	consecutiveFailures int
	cbThreshold         int           // trip after this many consecutive failures
	cbCooldown          time.Duration // how long to stay open
	cbOpenedAt          time.Time     // when the circuit was tripped
}

// ResilienceOption configures optional Resilience parameters.
type ResilienceOption func(*Resilience)

// WithMaxConcurrency sets the maximum number of parallel API calls.
func WithMaxConcurrency(n int) ResilienceOption {
	return func(r *Resilience) {
		if n > 0 {
			r.semaphore = make(chan struct{}, n)
		}
	}
}

// WithCircuitBreaker configures the circuit breaker threshold and cooldown.
func WithCircuitBreaker(threshold int, cooldown time.Duration) ResilienceOption {
	return func(r *Resilience) {
		if threshold > 0 {
			r.cbThreshold = threshold
		}
		if cooldown > 0 {
			r.cbCooldown = cooldown
		}
	}
}

// NewResilience creates a Resilience with the given options and sensible defaults.
func NewResilience(opts ...ResilienceOption) *Resilience {
	r := &Resilience{
		semaphore:   make(chan struct{}, DefaultMaxConcurrency),
		cbThreshold: DefaultCircuitBreakerThreshold,
		cbCooldown:  DefaultCircuitBreakerCooldown,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Acquire checks the circuit breaker and acquires a semaphore slot.
// The caller must call Release when the API call is complete (typically via defer).
// providerName is used in error messages (e.g. "bedrock", "anthropic", "openai").
func (r *Resilience) Acquire(ctx context.Context, providerName string) error {
	if r.circuitBreakerOpen() {
		return fmt.Errorf("%s circuit breaker open: too many consecutive failures, cooling down", providerName)
	}

	select {
	case r.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees the semaphore slot acquired by Acquire.
func (r *Resilience) Release() {
	<-r.semaphore
}

// RecordSuccess resets the consecutive failure counter.
func (r *Resilience) RecordSuccess() {
	r.cbMu.Lock()
	defer r.cbMu.Unlock()
	r.consecutiveFailures = 0
	r.cbOpenedAt = time.Time{}
}

// RecordFailure increments the consecutive failure counter and trips the
// circuit if the threshold is reached.
func (r *Resilience) RecordFailure() {
	r.cbMu.Lock()
	defer r.cbMu.Unlock()
	r.consecutiveFailures++
	if r.consecutiveFailures >= r.cbThreshold && r.cbOpenedAt.IsZero() {
		r.cbOpenedAt = time.Now()
	}
}

// IsOpen reports whether the circuit breaker is currently tripped. It is a
// read-only observer intended for telemetry / audit: it does not advance the
// half-open timer, so repeated calls never admit a probe request.
func (r *Resilience) IsOpen() bool {
	r.cbMu.Lock()
	defer r.cbMu.Unlock()
	if r.consecutiveFailures < r.cbThreshold {
		return false
	}
	return time.Since(r.cbOpenedAt) < r.cbCooldown
}

// circuitBreakerOpen checks if the circuit breaker is currently open (tripped).
// If the cooldown has elapsed, it half-opens the circuit (resets state) and
// returns false, allowing a single probe request through.
func (r *Resilience) circuitBreakerOpen() bool {
	r.cbMu.Lock()
	defer r.cbMu.Unlock()

	if r.consecutiveFailures < r.cbThreshold {
		return false
	}
	// Circuit is tripped — check if cooldown has elapsed.
	if time.Since(r.cbOpenedAt) >= r.cbCooldown {
		// Half-open: allow one probe request through. Reset the cooldown
		// timer so concurrent callers still see the circuit as open until
		// the probe completes and calls RecordSuccess/RecordFailure.
		r.cbOpenedAt = time.Now()
		return false
	}
	return true
}
