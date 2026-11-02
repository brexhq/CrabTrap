package judge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// testJevModel stands in for the configured llm_judge.jev.model.
const testJevModel = "jev-1.13.0"

// f64ptr returns a pointer to v, for building jevAnswer literals whose Noul
// field is now *float64 (so a missing "noul" field in a real response can be
// distinguished from an explicit 0.0).
func f64ptr(v float64) *float64 { return &v }

func newTestJevEvaluator(t *testing.T, serverURL string) *JevEvaluator {
	t.Helper()
	j, err := NewJevEvaluator("test-key", testJevModel, 5*time.Second)
	if err != nil {
		t.Fatalf("NewJevEvaluator: %v", err)
	}
	j.SetBaseURL(serverURL)
	return j
}

func TestJevEvaluator_Score(t *testing.T) {
	var capturedAuth string
	var capturedBody jevRequest
	var decodeErr error

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		decodeErr = json.NewDecoder(r.Body).Decode(&capturedBody)
		resp := jevResponse{
			Model:   testJevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.05)}},
			Usage:   jevUsage{InputTokens: 100, OutputTokens: 10},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	result, err := j.Score(context.Background(), "GET", "https://example.com/api", http.Header{}, "", types.LLMPolicy{Prompt: "allow all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decodeErr != nil {
		t.Fatalf("decode request body: %v", decodeErr)
	}
	if got := capturedAuth; got != "Bearer test-key" {
		t.Errorf("Authorization header = %q, want Bearer test-key", got)
	}
	if capturedBody.Model != testJevModel {
		t.Errorf("Model = %q, want %q", capturedBody.Model, testJevModel)
	}
	if !strings.Contains(capturedBody.State, "allow all") {
		t.Errorf("State should contain policy prompt, got: %s", capturedBody.State)
	}
	q, ok := capturedBody.Questions[jevViolatesQuestionKey]
	if !ok {
		t.Fatalf("request missing question %q", jevViolatesQuestionKey)
	}
	if q.Type != "noul" {
		t.Errorf("Questions[%q].Type = %q, want %q", jevViolatesQuestionKey, q.Type, "noul")
	}

	if result.Score == nil || *result.Score != 0.05 {
		t.Errorf("Score = %v, want 0.05", result.Score)
	}
	if result.InputTokens != 100 || result.OutputTokens != 10 {
		t.Errorf("token counts not populated: %+v", result)
	}
	if result.Reason == "" {
		t.Error("Reason should be synthesized from the probability")
	}
}

func TestJevEvaluator_ScoreIsNotAnApprovalDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jevResponse{
			Model:   testJevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.93)}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	result, err := j.Score(context.Background(), "POST", "https://example.com/api", http.Header{}, `{"x":1}`, types.LLMPolicy{Prompt: "deny writes"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "" {
		t.Errorf("Decision = %v, want no approval decision", result.Decision)
	}
}

func TestJevEvaluator_DurationIncludesSlowBody(t *testing.T) {
	const bodyDelay = 200 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send headers immediately, then delay the body.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(bodyDelay)
		json.NewEncoder(w).Encode(jevResponse{
			Model:   testJevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.05)}},
		})
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	result, err := j.Score(context.Background(), "GET", "https://example.com/api", http.Header{}, "", types.LLMPolicy{Prompt: "allow all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := time.Duration(result.DurationMs) * time.Millisecond; got < bodyDelay {
		t.Errorf("DurationMs = %v, want at least the %v body delay", got, bodyDelay)
	}
}

func TestJevEvaluator_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key","state":"secret-policy Authorization: Bearer sk-live"}`))
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	// The error is logged by the cascade, so it must not echo the upstream
	// body (which can contain the policy and request headers/body).
	if strings.Contains(err.Error(), "secret-policy") || strings.Contains(err.Error(), "sk-live") {
		t.Fatalf("error leaks upstream body: %v", err)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("error = %v, want status code", err)
	}
}

// 5xx, 429, and authentication failures trip the breaker. Other 4xx are
// request-specific and must not disable Jev for everyone.
func TestJevEvaluator_BreakerCountsOnlyServerSideStatuses(t *testing.T) {
	for _, tc := range []struct {
		status    int
		wantTrips bool
	}{
		{http.StatusBadRequest, false},
		{http.StatusNotFound, false},
		{http.StatusRequestEntityTooLarge, false},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusServiceUnavailable, true},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			var visits int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				atomic.AddInt32(&visits, 1)
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			j, err := NewJevEvaluator("k", testJevModel, time.Second, llm.WithCircuitBreaker(1, time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			j.SetBaseURL(srv.URL)
			for i := 0; i < 2; i++ {
				_, _ = j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			}
			_, err = j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			if tripped := errors.Is(err, ErrJevUnavailable); tripped != tc.wantTrips {
				t.Fatalf("status %d: breaker tripped=%v, want %v (err=%v visits=%d)", tc.status, tripped, tc.wantTrips, err, visits)
			}
		})
	}
}

func TestJevEvaluator_MissingAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jevResponse{Model: testJevModel, Answers: map[string]jevAnswer{}})
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil {
		t.Fatal("expected error when answer is missing")
	}
}

// TestJevEvaluator_MissingNoulField ensures a well-formed answer that is
// missing the "noul" field (or carries the wrong answer type) is treated as
// an error rather than silently zero-valuing to a confident ALLOW.
func TestJevEvaluator_MissingNoulField(t *testing.T) {
	tests := []struct {
		name   string
		answer jevAnswer
	}{
		{"nil noul", jevAnswer{Type: "noul", Noul: nil}},
		{"wrong type", jevAnswer{Type: "bool", Noul: f64ptr(0.05)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jevResponse{
					Model:   testJevModel,
					Answers: map[string]jevAnswer{jevViolatesQuestionKey: tt.answer},
				})
			}))
			defer srv.Close()

			j := newTestJevEvaluator(t, srv.URL)
			_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			if err == nil {
				t.Fatal("expected error for invalid noul answer, got nil (would silently become ALLOW)")
			}
		})
	}
}

func TestJevEvaluator_RejectsOutOfRangeScore(t *testing.T) {
	for _, score := range []float64{-0.01, 1.01} {
		t.Run(fmt.Sprintf("%v", score), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jevResponse{
					Model:   testJevModel,
					Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(score)}},
				})
			}))
			defer srv.Close()

			j := newTestJevEvaluator(t, srv.URL)
			_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			if err == nil {
				t.Fatal("expected error for out-of-range score")
			}
		})
	}
}

func TestNewJevEvaluator_RequiresAPIKey(t *testing.T) {
	if _, err := NewJevEvaluator("", testJevModel, time.Second); err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestNewJevEvaluator_RequiresPositiveTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if _, err := NewJevEvaluator("k", testJevModel, timeout); err == nil {
			t.Fatalf("expected error for timeout %v", timeout)
		}
	}
}

func TestJevEvaluatorHonorsResilienceOptions(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		http.Error(w, "upstream failure", http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer releaseHandler()

	j, err := NewJevEvaluator("test-key", testJevModel, time.Second,
		llm.WithMaxConcurrency(1),
		llm.WithCircuitBreaker(1, time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(srv.URL)

	firstDone := make(chan error, 1)
	go func() {
		_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first call did not reach Jev")
	}

	// With the only slot taken, a second call must fail fast instead of
	// queueing, so the cascade can escalate to the LLM without added latency.
	type scoreOutcome struct{ err error }
	secondDone := make(chan scoreOutcome, 1)
	go func() {
		_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
		secondDone <- scoreOutcome{err: err}
	}()
	select {
	case outcome := <-secondDone:
		err = outcome.err
	case <-time.After(2 * time.Second):
		t.Fatal("second call queued behind a busy Jev slot")
	}
	if err == nil || !strings.Contains(err.Error(), "max concurrency") {
		t.Fatalf("second call error = %v, want max concurrency", err)
	}
	select {
	case <-started:
		t.Fatal("second call reached Jev despite max concurrency of one")
	default:
	}

	releaseHandler()
	if err := <-firstDone; err == nil {
		t.Fatal("first call should return the upstream error")
	}
	_, err = j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Fatalf("third call error = %v, want circuit breaker open", err)
	}
}

// The configured model is sent as-is and recorded on the result.
func TestJevEvaluator_UsesConfiguredModel(t *testing.T) {
	var sentModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jevRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		sentModel = req.Model
		json.NewEncoder(w).Encode(jevResponse{
			Model:   "jev-1.14.0",
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.2)}},
		})
	}))
	defer srv.Close()

	j, err := NewJevEvaluator("test-key", "jev-latest", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(srv.URL)
	result, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if sentModel != "jev-latest" {
		t.Errorf("sent model = %q, want jev-latest", sentModel)
	}
	if result.Model != "jev-latest" {
		t.Errorf("result model = %q, want jev-latest", result.Model)
	}
}

// healthyJevServer answers with a valid score and counts the requests it sees.
func healthyJevServer(t *testing.T, visits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(visits, 1)
		_ = json.NewEncoder(w).Encode(jevResponse{
			Model:   testJevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.5)}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A burst of client disconnects must not open Jev's breaker: the caller going
// away says nothing about Jev's health.
func TestJevEvaluator_CancelledCallerDoesNotTripBreaker(t *testing.T) {
	var visits int32
	hang := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hang }))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(hang) })

	j, err := NewJevEvaluator("k", testJevModel, time.Minute, llm.WithCircuitBreaker(1, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(slow.URL)

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		if _, err := j.Score(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err == nil {
			t.Fatal("expected an error from the cancelled call")
		}
	}

	healthy := healthyJevServer(t, &visits)
	j.SetBaseURL(healthy.URL)
	res, err := j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil || res.Score == nil || atomic.LoadInt32(&visits) != 1 {
		t.Fatalf("breaker opened after caller cancels: err=%v visits=%d", err, visits)
	}
}

func TestJevEvaluator_CancelledRecoveryProbeRestoresGauge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		cancel() // Cancel only once the recovery probe reaches the server.
	}))
	t.Cleanup(slow.Close)

	const cooldown = 30 * time.Millisecond
	obs := &jevObs{}
	j, err := NewJevEvaluator("k", testJevModel, time.Second,
		llm.WithCircuitBreaker(1, cooldown), llm.WithObserver(obs, "jev"))
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(slow.URL)
	j.RecordFailure()
	time.Sleep(2 * cooldown)
	if _, err := j.Score(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err == nil {
		t.Fatal("expected canceled recovery probe")
	}
	obs.mu.Lock()
	states := strings.Join(obs.stateChg, ",")
	trips, samples := len(obs.trips), len(obs.latency)
	obs.mu.Unlock()
	if states != "jev:true,jev:false,jev:true" || trips != 1 || samples != 0 {
		t.Fatalf("after cancellation: states=%s trips=%d latency samples=%d", states, trips, samples)
	}

	var visits int32
	j.SetBaseURL(healthyJevServer(t, &visits).URL)
	time.Sleep(2 * cooldown)
	for i := 0; i < 2; i++ {
		if _, err := j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err != nil {
			t.Fatalf("call after cooldown: %v", err)
		}
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if strings.Join(obs.stateChg, ",") != "jev:true,jev:false,jev:true,jev:false" || len(obs.trips) != 1 || len(obs.latency) != 2 {
		t.Fatalf("after recovery: states=%v trips=%v latency=%v", obs.stateChg, obs.trips, obs.latency)
	}
}

type latencyObserver struct{ calls int32 }

func (o *latencyObserver) OnCircuitBreakerTrip(string)              {}
func (o *latencyObserver) OnCircuitBreakerStateChange(string, bool) {}
func (o *latencyObserver) OnJudgeLatency(_, _ string, _ time.Duration) {
	atomic.AddInt32(&o.calls, 1)
}

// A cancelled caller also must not add a sample to the latency histogram, but
// a completed call still does.
func TestJevEvaluator_CancelledCallerSkipsLatencySample(t *testing.T) {
	hang := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hang }))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(hang) })

	obs := &latencyObserver{}
	j, err := NewJevEvaluator("k", testJevModel, time.Minute, llm.WithObserver(obs, "jev"))
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(slow.URL)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := j.Score(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err == nil {
		t.Fatal("expected an error from the cancelled call")
	}
	if n := atomic.LoadInt32(&obs.calls); n != 0 {
		t.Fatalf("latency recorded for a cancelled call: %d samples", n)
	}

	var visits int32
	j.SetBaseURL(healthyJevServer(t, &visits).URL)
	if _, err := j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&obs.calls); n != 1 {
		t.Fatalf("want 1 latency sample for a completed call, got %d", n)
	}
}

// Our own timeout is a real Jev failure and must still count.
func TestJevEvaluator_OwnTimeoutStillTripsBreaker(t *testing.T) {
	hang := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-hang }))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(hang) })

	j, err := NewJevEvaluator("k", testJevModel, 20*time.Millisecond, llm.WithCircuitBreaker(1, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(slow.URL)

	if _, err := j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err == nil {
		t.Fatal("expected a timeout error")
	}
	_, err = j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Fatalf("err=%v, want the breaker to be open after Jev's own timeout", err)
	}
}

type jevObs struct {
	mu       sync.Mutex
	latency  []string
	trips    []string
	stateChg []string
}

func (o *jevObs) OnCircuitBreakerTrip(p string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.trips = append(o.trips, p)
}
func (o *jevObs) OnCircuitBreakerStateChange(p string, open bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stateChg = append(o.stateChg, fmt.Sprintf("%s:%v", p, open))
}
func (o *jevObs) OnJudgeLatency(p, model string, _ time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.latency = append(o.latency, p+"/"+model)
}

func TestJevEvaluator_ReportsLatencyAndBreakerToObserver(t *testing.T) {
	obs := &jevObs{}
	var visits int32
	ok := healthyJevServer(t, &visits)
	j, err := NewJevEvaluator("k", testJevModel, time.Second, llm.WithCircuitBreaker(1, time.Minute), llm.WithObserver(obs, "jev"))
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(ok.URL)
	if _, err := j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err != nil {
		t.Fatal(err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) }))
	t.Cleanup(bad.Close)
	j.SetBaseURL(bad.URL)
	_, _ = j.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})

	obs.mu.Lock()
	defer obs.mu.Unlock()
	wantLatency := "jev/" + testJevModel
	if len(obs.latency) != 2 || obs.latency[0] != wantLatency || obs.latency[1] != wantLatency {
		t.Fatalf("latency=%v, want two %q samples (success and failure)", obs.latency, wantLatency)
	}
	if len(obs.trips) != 1 || obs.trips[0] != "jev" {
		t.Fatalf("trips=%v, want one trip labelled jev", obs.trips)
	}
}
