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

// ResilienceObserver is notified about circuit-breaker transitions and judge
// call latency. Implementations must be safe for concurrent use. Kept as a
// small interface here to avoid a dependency on internal/metrics from the
// adapter packages.
//
// OnCircuitBreakerTrip fires exactly once per closed-to-open transition. It
// does NOT re-fire while the breaker is already open.
//
// OnCircuitBreakerStateChange fires on every visible transition. `open == true`
// means the breaker is rejecting new calls; `open == false` means it is
// accepting them (either newly closed after success, or freshly half-opened to
// admit a probe).
//
// OnJudgeLatency fires after every judge call regardless of success or
// failure, so tail-latency alerts continue to work when a provider is
// degrading.
type ResilienceObserver interface {
	OnCircuitBreakerTrip(provider string)
	OnCircuitBreakerStateChange(provider string, open bool)
	OnJudgeLatency(provider, model string, d time.Duration)
}

// Resilience provides concurrency limiting (semaphore) and circuit breaker
// behaviour that can be embedded in any Adapter implementation.
type Resilience struct {
	// Concurrency semaphore: limits the number of parallel API calls.
	semaphore chan struct{}

	// Circuit breaker state, protected by cbMu.
	cbMu                     sync.Mutex
	consecutiveFailures      int
	cbThreshold              int           // trip after this many consecutive failures
	cbCooldown               time.Duration // how long to stay open
	cbOpenedAt               time.Time     // when the circuit was tripped (zero = closed)
	halfOpenProbeOutstanding bool          // set when circuitBreakerOpen hands out a probe; cleared on next Record{Success,Failure}

	provider string             // identifies this adapter in observer callbacks
	observer ResilienceObserver // optional; nil means no metrics emitted
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

// WithObserver attaches a ResilienceObserver and a provider label used when
// reporting circuit-breaker transitions. A nil observer is equivalent to not
// setting one; an empty provider falls back to "unknown" in callbacks.
func WithObserver(obs ResilienceObserver, provider string) ResilienceOption {
	return func(r *Resilience) {
		r.observer = obs
		if provider != "" {
			r.provider = provider
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

// RecordSuccess resets the consecutive failure counter. If the breaker was
// open, observers are notified of the open->closed transition. A successful
// half-open probe takes this path too: the half-open call already fired
// state=false, so we only fire again on the rare "tripped but not yet
// half-opened" success (which happens in tests exercising direct call flow).
func (r *Resilience) RecordSuccess() {
	r.cbMu.Lock()
	// If a half-open probe succeeded, its state=false was already fired.
	// Suppress the redundant event.
	probeSucceeded := r.halfOpenProbeOutstanding
	wasTripped := !r.cbOpenedAt.IsZero()
	r.consecutiveFailures = 0
	r.cbOpenedAt = time.Time{}
	r.halfOpenProbeOutstanding = false
	r.cbMu.Unlock()

	if wasTripped && !probeSucceeded && r.observer != nil {
		r.observer.OnCircuitBreakerStateChange(r.providerLabel(), false)
	}
}

// RecordFailure increments the consecutive failure counter and trips the
// circuit if the threshold is reached. Observers are notified exactly once on
// the closed-to-open edge.
//
// Handles two distinct "tripped" edges:
//   - closed -> open: fresh trip, fires OnCircuitBreakerTrip + state=true
//   - half-open-probe-failed -> open: the optimistic state=false fired by
//     circuitBreakerOpen's half-open path turned out to be wrong, so re-fire
//     state=true to correct the gauge. Does NOT increment the trip counter —
//     this is the same underlying trip, not a new one.
func (r *Resilience) RecordFailure() {
	r.cbMu.Lock()
	r.consecutiveFailures++
	tripped := false
	reconfirmedOpen := false
	if r.consecutiveFailures >= r.cbThreshold {
		if r.cbOpenedAt.IsZero() {
			r.cbOpenedAt = time.Now()
			tripped = true
		} else if r.halfOpenProbeOutstanding {
			// A prior half-open handed out a probe and fired state=false;
			// the probe just failed. Re-assert the open state so the gauge
			// reflects reality. The trip counter does not increment — the
			// breaker was already tripped from the original transition.
			r.halfOpenProbeOutstanding = false
			reconfirmedOpen = true
		}
	}
	r.cbMu.Unlock()

	if r.observer == nil {
		return
	}
	provider := r.providerLabel()
	if tripped {
		r.observer.OnCircuitBreakerTrip(provider)
		r.observer.OnCircuitBreakerStateChange(provider, true)
	} else if reconfirmedOpen {
		r.observer.OnCircuitBreakerStateChange(provider, true)
	}
}

// RecordJudgeLatency forwards a judge call duration to the observer.
func (r *Resilience) RecordJudgeLatency(model string, d time.Duration) {
	if r == nil || r.observer == nil {
		return
	}
	r.observer.OnJudgeLatency(r.providerLabel(), model, d)
}

// providerLabel returns the configured provider or "unknown" if unset.
func (r *Resilience) providerLabel() string {
	if r.provider == "" {
		return "unknown"
	}
	return r.provider
}

// circuitBreakerOpen checks if the circuit breaker is currently open (tripped).
// If the cooldown has elapsed, it half-opens the circuit (resets the cooldown
// timer) and returns false, allowing a single probe request through. Other
// callers that arrive before the probe completes still see the breaker as
// open because cbOpenedAt was reset to now.
func (r *Resilience) circuitBreakerOpen() bool {
	r.cbMu.Lock()
	if r.consecutiveFailures < r.cbThreshold {
		r.cbMu.Unlock()
		return false
	}
	// Circuit is tripped — check if cooldown has elapsed.
	if time.Since(r.cbOpenedAt) >= r.cbCooldown {
		// Half-open: reset the cooldown timer so concurrent callers still
		// see the circuit as open until the probe completes and calls
		// RecordSuccess/RecordFailure. Only the first caller in this window
		// takes the probe — subsequent callers see halfOpenProbeOutstanding
		// already set and do not re-fire state=false.
		firstProbe := !r.halfOpenProbeOutstanding
		r.cbOpenedAt = time.Now()
		r.halfOpenProbeOutstanding = true
		r.cbMu.Unlock()
		// State-change fires outside the lock to avoid holding cbMu across
		// an external callback. Only the first probe in this window emits
		// state=false; if the probe fails, RecordFailure will re-fire
		// state=true via the reconfirmedOpen path.
		if firstProbe && r.observer != nil {
			r.observer.OnCircuitBreakerStateChange(r.providerLabel(), false)
		}
		return false
	}
	r.cbMu.Unlock()
	return true
}
