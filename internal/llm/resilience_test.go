package llm

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Test: Semaphore limits concurrency ---

func TestSemaphoreLimitsConcurrency(t *testing.T) {
	const maxConcurrency = 3
	const totalCalls = 10

	r := NewResilience(WithMaxConcurrency(maxConcurrency))

	var currentConcurrency atomic.Int32
	var maxObserved atomic.Int32
	gate := make(chan struct{}) // blocks all goroutines until we release them

	var wg sync.WaitGroup
	for i := 0; i < totalCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := r.Acquire(context.Background(), "test"); err != nil {
				return
			}

			cur := currentConcurrency.Add(1)
			defer func() {
				currentConcurrency.Add(-1)
				r.Release()
			}()

			// Track the max concurrency observed.
			for {
				old := maxObserved.Load()
				if cur <= old || maxObserved.CompareAndSwap(old, cur) {
					break
				}
			}

			// Wait for the gate to open.
			<-gate
		}()
	}

	// Give goroutines time to hit the semaphore.
	time.Sleep(100 * time.Millisecond)

	// Release all blocked calls.
	close(gate)
	wg.Wait()

	if max := int(maxObserved.Load()); max > maxConcurrency {
		t.Errorf("observed concurrency %d exceeded limit %d", max, maxConcurrency)
	}
	if max := int(maxObserved.Load()); max < maxConcurrency {
		t.Errorf("expected to reach concurrency limit %d, but only observed %d", maxConcurrency, max)
	}
}

// --- Test: Circuit breaker trips after consecutive failures ---

func TestCircuitBreakerTripsAndRecovers(t *testing.T) {
	const threshold = 3
	cooldown := 200 * time.Millisecond

	r := NewResilience(WithCircuitBreaker(threshold, cooldown), WithMaxConcurrency(10))

	// Record `threshold` failures.
	for i := 0; i < threshold; i++ {
		if err := r.Acquire(context.Background(), "test"); err != nil {
			t.Fatalf("call %d: unexpected acquire error: %v", i, err)
		}
		r.RecordFailure()
		r.Release()
	}

	// The next acquire should be rejected by the circuit breaker.
	err := r.Acquire(context.Background(), "test")
	if err == nil {
		r.Release()
		t.Fatal("expected circuit breaker error, got nil")
	}

	// Wait for the cooldown to expire.
	time.Sleep(cooldown + 50*time.Millisecond)

	// The circuit should now be half-open, allowing a call through.
	if err := r.Acquire(context.Background(), "test"); err != nil {
		t.Fatalf("expected half-open probe to succeed, got: %v", err)
	}
	r.RecordFailure()
	r.Release()
}

func TestCircuitBreakerResetsOnSuccess(t *testing.T) {
	const threshold = 3
	cooldown := 10 * time.Second // long cooldown — we should never hit it

	r := NewResilience(WithCircuitBreaker(threshold, cooldown), WithMaxConcurrency(10))

	// Make threshold-1 failures.
	for i := 0; i < threshold-1; i++ {
		if err := r.Acquire(context.Background(), "test"); err != nil {
			t.Fatalf("call %d: unexpected acquire error: %v", i, err)
		}
		r.RecordFailure()
		r.Release()
	}

	// A success should reset the counter.
	if err := r.Acquire(context.Background(), "test"); err != nil {
		t.Fatalf("unexpected acquire error: %v", err)
	}
	r.RecordSuccess()
	r.Release()

	// We should be able to make threshold-1 more failures without tripping.
	for i := 0; i < threshold-1; i++ {
		if err := r.Acquire(context.Background(), "test"); err != nil {
			t.Fatalf("call %d: circuit breaker tripped prematurely: %v", i, err)
		}
		r.RecordFailure()
		r.Release()
	}

	// One more should still be allowed (we're at threshold-1 again).
	// Actually, the next failure would be #threshold, which trips.
	// But Acquire itself should still succeed (it checks before incrementing).
	if err := r.Acquire(context.Background(), "test"); err != nil {
		t.Fatalf("expected acquire to succeed at threshold boundary: %v", err)
	}
	r.RecordFailure()
	r.Release()

	// NOW the circuit should be open.
	err := r.Acquire(context.Background(), "test")
	if err == nil {
		r.Release()
		t.Fatal("expected circuit breaker error after re-tripping")
	}
}

// --- Test: Half-open state allows only one probe ---

func TestCircuitBreakerHalfOpenSingleProbe(t *testing.T) {
	const threshold = 3
	cooldown := 200 * time.Millisecond

	r := NewResilience(WithCircuitBreaker(threshold, cooldown), WithMaxConcurrency(50))

	// Trip the circuit.
	for i := 0; i < threshold; i++ {
		if err := r.Acquire(context.Background(), "test"); err != nil {
			t.Fatalf("call %d: unexpected acquire error: %v", i, err)
		}
		r.RecordFailure()
		r.Release()
	}

	// Wait for cooldown to expire.
	time.Sleep(cooldown + 50*time.Millisecond)

	// Launch several goroutines simultaneously in the half-open window.
	const concurrent = 10
	var wg sync.WaitGroup
	var acquired atomic.Int32
	var rejected atomic.Int32

	// Use a gate to prevent acquired goroutines from releasing before we count.
	gate := make(chan struct{})

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.Acquire(context.Background(), "test")
			if err != nil {
				rejected.Add(1)
				return
			}
			acquired.Add(1)
			<-gate
			r.RecordFailure()
			r.Release()
		}()
	}

	// Give goroutines time to attempt Acquire.
	time.Sleep(100 * time.Millisecond)

	// Only ONE goroutine should have acquired (the half-open probe).
	// The rest should be rejected by the circuit breaker.
	if got := int(acquired.Load()); got != 1 {
		t.Errorf("expected exactly 1 probe call in half-open state, got %d", got)
	}

	close(gate)
	wg.Wait()
}

// --- Test: Context cancellation while waiting for semaphore ---

func TestContextCancelledWhileWaitingForSemaphore(t *testing.T) {
	r := NewResilience(WithMaxConcurrency(1))

	// Acquire the only slot.
	if err := r.Acquire(context.Background(), "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to acquire with a short-lived context.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := r.Acquire(ctx, "test")
	if err == nil {
		r.Release()
		t.Fatal("expected context error, got nil")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got: %v", err)
	}

	// Release the first slot.
	r.Release()
}

// --- Test: Error message includes provider name ---

func TestCircuitBreakerErrorIncludesProviderName(t *testing.T) {
	r := NewResilience(WithCircuitBreaker(1, 10*time.Second))

	if err := r.Acquire(context.Background(), "myProvider"); err != nil {
		t.Fatal(err)
	}
	r.RecordFailure()
	r.Release()

	err := r.Acquire(context.Background(), "myProvider")
	if err == nil {
		r.Release()
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "myProvider") {
		t.Errorf("expected error to contain provider name, got %q", err.Error())
	}
}

// --- Test: Observer fires exactly once on the trip edge ---

type stateRecorder struct {
	mu        sync.Mutex
	trips     []string
	states    []stateChange
	latencies []latencySample
}

type stateChange struct {
	provider string
	open     bool
}

type latencySample struct {
	provider, model string
	d               time.Duration
}

func (s *stateRecorder) OnCircuitBreakerTrip(provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trips = append(s.trips, provider)
}

func (s *stateRecorder) OnCircuitBreakerStateChange(provider string, open bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states = append(s.states, stateChange{provider, open})
}

func (s *stateRecorder) OnJudgeLatency(provider, model string, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latencies = append(s.latencies, latencySample{provider, model, d})
}

func (s *stateRecorder) tripCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.trips)
}

func (s *stateRecorder) stateSequence() []stateChange {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stateChange, len(s.states))
	copy(out, s.states)
	return out
}

func TestObserverFiresOnceOnCircuitBreakerTrip(t *testing.T) {
	const threshold = 3
	obs := &stateRecorder{}

	r := NewResilience(
		WithCircuitBreaker(threshold, 10*time.Second),
		WithObserver(obs, "bedrock"),
	)

	// Record enough failures to trip the breaker, then a few more — the
	// observer should only see the edge transition, not every failure.
	for i := 0; i < threshold+2; i++ {
		r.RecordFailure()
	}

	if got := obs.tripCount(); got != 1 {
		t.Fatalf("observer trips = %d, want 1 (only on trip edge)", got)
	}
	if obs.trips[0] != "bedrock" {
		t.Errorf("observer got provider %q, want %q", obs.trips[0], "bedrock")
	}
	// Exactly one state-change on trip: closed -> open.
	seq := obs.stateSequence()
	if len(seq) != 1 || !seq[0].open || seq[0].provider != "bedrock" {
		t.Errorf("state sequence = %+v, want one {bedrock open=true}", seq)
	}
}

func TestObserverNotFiredBelowThreshold(t *testing.T) {
	obs := &stateRecorder{}
	r := NewResilience(
		WithCircuitBreaker(5, 10*time.Second),
		WithObserver(obs, "openai"),
	)

	for i := 0; i < 4; i++ {
		r.RecordFailure()
	}

	if got := obs.tripCount(); got != 0 {
		t.Fatalf("observer trips = %d, want 0 before threshold", got)
	}
	if got := len(obs.stateSequence()); got != 0 {
		t.Fatalf("state changes = %d, want 0 before threshold", got)
	}
}

func TestStateChangeSequenceTripAndReset(t *testing.T) {
	obs := &stateRecorder{}
	r := NewResilience(
		WithCircuitBreaker(2, 10*time.Second),
		WithObserver(obs, "bedrock"),
	)

	// Trip it.
	r.RecordFailure()
	r.RecordFailure()
	// Reset it via a success.
	r.RecordSuccess()

	seq := obs.stateSequence()
	want := []stateChange{
		{"bedrock", true},
		{"bedrock", false},
	}
	if len(seq) != len(want) {
		t.Fatalf("state sequence = %+v, want %+v", seq, want)
	}
	for i, s := range seq {
		if s != want[i] {
			t.Errorf("state[%d] = %+v, want %+v", i, s, want[i])
		}
	}
}

func TestStateGaugeReflectsRealityWhenProbeFails(t *testing.T) {
	// Regression: half-open optimistically fires state=false, so if the
	// probe fails the gauge needs to flip back to true. Otherwise operators
	// see "closed" on a breaker that is rejecting calls until the next
	// cooldown elapses.
	obs := &stateRecorder{}
	r := NewResilience(
		WithCircuitBreaker(1, 50*time.Millisecond),
		WithObserver(obs, "bedrock"),
	)

	// Trip it.
	r.RecordFailure()
	// Wait past cooldown, half-open the breaker.
	time.Sleep(75 * time.Millisecond)
	if r.circuitBreakerOpen() {
		t.Fatal("cooldown elapsed; circuitBreakerOpen should return false")
	}
	// Probe fails.
	r.RecordFailure()

	// Expected sequence: open -> closed (half-open) -> open (probe failed).
	seq := obs.stateSequence()
	if len(seq) != 3 {
		t.Fatalf("state sequence = %+v, want 3 entries (trip, half-open, reconfirm)", seq)
	}
	if seq[0] != (stateChange{"bedrock", true}) {
		t.Errorf("state[0] = %+v, want {bedrock open=true}", seq[0])
	}
	if seq[1] != (stateChange{"bedrock", false}) {
		t.Errorf("state[1] = %+v, want {bedrock open=false} (half-open)", seq[1])
	}
	if seq[2] != (stateChange{"bedrock", true}) {
		t.Errorf("state[2] = %+v, want {bedrock open=true} (probe failed)", seq[2])
	}
}

func TestStateChangeOnHalfOpen(t *testing.T) {
	obs := &stateRecorder{}
	r := NewResilience(
		WithCircuitBreaker(1, 50*time.Millisecond),
		WithObserver(obs, "bedrock"),
	)

	r.RecordFailure() // trips immediately
	// Drain the trip -> open state change
	if seq := obs.stateSequence(); len(seq) != 1 || !seq[0].open {
		t.Fatalf("after trip, sequence = %+v, want [{open=true}]", seq)
	}

	// Wait past cooldown — the next circuitBreakerOpen call half-opens.
	time.Sleep(75 * time.Millisecond)
	if r.circuitBreakerOpen() {
		t.Fatal("after cooldown, circuitBreakerOpen should return false (half-open probe window)")
	}

	// Expect an open -> closed state change on half-open.
	seq := obs.stateSequence()
	if len(seq) != 2 {
		t.Fatalf("after half-open, sequence = %+v, want 2 entries", seq)
	}
	if seq[1].open {
		t.Errorf("half-open state change = %+v, want open=false", seq[1])
	}
}

func TestRecordJudgeLatencyFiresObserver(t *testing.T) {
	obs := &stateRecorder{}
	r := NewResilience(WithObserver(obs, "bedrock"))

	r.RecordJudgeLatency("claude-sonnet-4", 42*time.Millisecond)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.latencies) != 1 {
		t.Fatalf("latencies = %d, want 1", len(obs.latencies))
	}
	got := obs.latencies[0]
	if got.provider != "bedrock" || got.model != "claude-sonnet-4" || got.d != 42*time.Millisecond {
		t.Errorf("latency = %+v, want {bedrock, claude-sonnet-4, 42ms}", got)
	}
}

func TestConcurrentRecordFailureFiresObserverExactlyOnce(t *testing.T) {
	const N = 100
	const threshold = 3
	obs := &stateRecorder{}
	r := NewResilience(
		WithCircuitBreaker(threshold, 10*time.Second),
		WithObserver(obs, "openai"),
	)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			r.RecordFailure()
		}()
	}
	wg.Wait()

	if got := obs.tripCount(); got != 1 {
		t.Fatalf("concurrent trips = %d, want exactly 1 (edge-fire invariant)", got)
	}
}
