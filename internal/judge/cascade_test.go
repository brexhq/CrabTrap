package judge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

type cascadeObs struct{ last atomic.Value }

func (o *cascadeObs) OnJevCascade(outcome string) { o.last.Store(outcome) }

func (o *cascadeObs) get() string {
	v, _ := o.last.Load().(string)
	return v
}

func countingLLM(decision string, calls *int32) Evaluator {
	return NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		atomic.AddInt32(calls, 1)
		body, _ := json.Marshal(map[string]string{"decision": decision, "reason": "llm-reason"})
		return llm.Response{Text: string(body)}, nil
	}})
}

func jevServer(t *testing.T, noul float64) *JevEvaluator {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jevResponse{
			Model: testJevModel,
			Answers: map[string]jevAnswer{
				jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
			},
		})
	}))
	t.Cleanup(srv.Close)
	ev, err := NewJevEvaluator("test-key", testJevModel, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ev.SetBaseURL(srv.URL)
	return ev
}

func TestJevCascade_AllowBelowShortCircuits(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: jevServer(t, 0.10), Secondary: countingLLM("DENY", &llmCalls),
		AllowBelow: 0.3, DenyAbove: 0.7, Observer: obs,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionAllow || res.DecidedBy != "jev" {
		t.Fatalf("decision=%s decided_by=%s", res.Decision, res.DecidedBy)
	}
	if atomic.LoadInt32(&llmCalls) != 0 {
		t.Fatalf("LLM calls=%d, want 0", llmCalls)
	}
	if got := obs.get(); got != JevCascadeAllow {
		t.Fatalf("outcome=%q", got)
	}
}

func TestJevCascade_NilPrimaryUsesLLM(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{Secondary: countingLLM("DENY", &llmCalls), AllowBelow: 0, DenyAbove: 0.7, Observer: obs}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || res.DecidedBy != "" || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s decided_by=%q llm_calls=%d", res.Decision, res.DecidedBy, llmCalls)
	}
	if got := obs.get(); got != JevCascadeSkipped {
		t.Fatalf("outcome=%q, want %q", got, JevCascadeSkipped)
	}
}

func TestJevCascade_NilSecondaryErrors(t *testing.T) {
	c := &JevCascadeEvaluator{Primary: jevServer(t, 0.9), DenyAbove: 0.7}
	if _, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"}); err == nil {
		t.Fatal("expected an error for a nil Secondary")
	}
}

func TestJevCascade_ZeroAllowBelowUsesLLM(t *testing.T) {
	var llmCalls int32
	c := &JevCascadeEvaluator{
		Primary: jevServer(t, 0), Secondary: countingLLM("DENY", &llmCalls),
		AllowBelow: 0, DenyAbove: 0.7,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s llm_calls=%d", res.Decision, llmCalls)
	}
}

func TestJevCascade_DenyAboveShortCircuits(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: jevServer(t, 0.92), Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.3, DenyAbove: 0.7, Observer: obs,
	}
	res, err := c.Evaluate(context.Background(), "POST", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || res.DecidedBy != "jev" {
		t.Fatalf("decision=%s decided_by=%s", res.Decision, res.DecidedBy)
	}
	if atomic.LoadInt32(&llmCalls) != 0 {
		t.Fatalf("LLM calls=%d, want 0", llmCalls)
	}
	if got := obs.get(); got != JevCascadeDeny {
		t.Fatalf("outcome=%q", got)
	}
}

func TestJevCascade_UncertainBandUsesLLM(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: jevServer(t, 0.55), Secondary: countingLLM("DENY", &llmCalls),
		AllowBelow: 0.3, DenyAbove: 0.7, Observer: obs,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s llm_calls=%d", res.Decision, llmCalls)
	}
	if got := obs.get(); got != JevCascadeEscalate {
		t.Fatalf("outcome=%q", got)
	}
}

func TestJevCascade_ThresholdEquality(t *testing.T) {
	for _, tc := range []struct {
		name      string
		score     float64
		decision  types.DecisionType
		decidedBy string
		llmCalls  int32
		outcome   string
	}{
		{"allow threshold escalates", 0.2, types.DecisionDeny, JevCascadeDecidedBy, 1, JevCascadeEscalate},
		{"deny threshold denies", 0.7, types.DecisionDeny, "jev", 0, JevCascadeDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var llmCalls int32
			obs := &cascadeObs{}
			c := &JevCascadeEvaluator{
				Primary: jevServer(t, tc.score), Secondary: countingLLM("DENY", &llmCalls),
				AllowBelow: 0.2, DenyAbove: 0.7, Observer: obs,
			}
			res, err := c.Evaluate(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
			if err != nil {
				t.Fatal(err)
			}
			if res.Decision != tc.decision || res.DecidedBy != tc.decidedBy || atomic.LoadInt32(&llmCalls) != tc.llmCalls || obs.get() != tc.outcome {
				t.Fatalf("result=%+v llm_calls=%d outcome=%q", res, llmCalls, obs.get())
			}
		})
	}
}

func TestJevCascade_TimeoutFallsBackAndReleasesSlot(t *testing.T) {
	for _, tc := range []struct {
		name         string
		flushHeaders bool
	}{
		{"before headers", false},
		{"after headers", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var visits int32
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&visits, 1) == 1 {
					if tc.flushHeaders {
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
					}
					<-release
					return
				}
				noul := 0.9
				_ = json.NewEncoder(w).Encode(jevResponse{
					Model: testJevModel,
					Answers: map[string]jevAnswer{
						jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
					},
				})
			}))
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(release) })
			primary, err := NewJevEvaluator("test-key", testJevModel, 25*time.Millisecond, llm.WithMaxConcurrency(1))
			if err != nil {
				t.Fatal(err)
			}
			primary.SetBaseURL(srv.URL)
			var llmCalls int32
			c := &JevCascadeEvaluator{
				Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
				AllowBelow: 0.2, DenyAbove: 0.7,
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			res, err := c.Evaluate(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
			if err != nil || res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != 1 {
				t.Fatalf("fallback result=%+v err=%v llm_calls=%d", res, err, llmCalls)
			}
			res, err = c.Evaluate(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
			if err != nil || res.Decision != types.DecisionDeny || res.DecidedBy != "jev" || atomic.LoadInt32(&llmCalls) != 1 {
				t.Fatalf("next result=%+v err=%v llm_calls=%d visits=%d", res, err, llmCalls, visits)
			}
		})
	}
}

func TestJevCascade_SaturationLeavesLLMAvailable(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	released := false
	releaseHandler := func() {
		if !released {
			close(release)
			released = true
		}
	}
	var visits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&visits, 1) == 1 {
			close(started)
			<-release
		}
		noul := 0.9
		_ = json.NewEncoder(w).Encode(jevResponse{
			Model: testJevModel,
			Answers: map[string]jevAnswer{
				jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
			},
		})
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(releaseHandler)
	primary, err := NewJevEvaluator("test-key", testJevModel, time.Second, llm.WithMaxConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	primary.SetBaseURL(srv.URL)
	firstDone := make(chan error, 1)
	go func() {
		_, err := primary.Score(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach Jev")
	}
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.2, DenyAbove: 0.7, Observer: obs,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := c.Evaluate(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil || res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != 1 || atomic.LoadInt32(&visits) != 1 {
		t.Fatalf("result=%+v err=%v llm_calls=%d jev_visits=%d", res, err, llmCalls, visits)
	}
	// Jev never ran, so the result is a plain LLM decision, not a Jev error.
	if got := obs.get(); got != JevCascadeSkipped {
		t.Fatalf("outcome=%q, want %q", got, JevCascadeSkipped)
	}
	if res.DecidedBy != "" || res.Model != "test" {
		t.Fatalf("decided_by=%q model=%q, want an unmarked LLM result", res.DecidedBy, res.Model)
	}
	releaseHandler()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first Jev request: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Jev request did not finish")
	}
}

func TestJevCascade_OpenBreakerLeavesLLMAvailable(t *testing.T) {
	var visits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&visits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	primary, err := NewJevEvaluator("test-key", testJevModel, time.Second, llm.WithCircuitBreaker(1, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	primary.SetBaseURL(srv.URL)
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.2, DenyAbove: 0.7, Observer: obs,
	}
	wantOutcome := map[int]string{1: JevCascadeError, 2: JevCascadeSkipped}
	for i := 1; i <= 2; i++ {
		res, err := c.Evaluate(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
		if err != nil || res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != int32(i) || atomic.LoadInt32(&visits) != 1 {
			t.Fatalf("call %d result=%+v err=%v llm_calls=%d jev_visits=%d", i, res, err, llmCalls, visits)
		}
		if got := obs.get(); got != wantOutcome[i] {
			t.Fatalf("call %d outcome=%q, want %q", i, got, wantOutcome[i])
		}
	}
}

func TestJevCascade_ErrorUsesLLM(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	primary, err := NewJevEvaluator("test-key", testJevModel, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	primary.SetBaseURL(srv.URL)
	c := &JevCascadeEvaluator{
		Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.3, DenyAbove: 0.7, Observer: obs,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s llm_calls=%d", res.Decision, llmCalls)
	}
	if got := obs.get(); got != JevCascadeError {
		t.Fatalf("outcome=%q", got)
	}
}

type fakeScorer struct {
	res JudgeResult
	err error
}

func (f fakeScorer) Score(context.Context, string, string, http.Header, string, types.LLMPolicy) (JudgeResult, error) {
	return f.res, f.err
}

// A scorer that returns no score and no error is treated as a Jev error.
func TestJevCascade_NilScoreEscalates(t *testing.T) {
	var llmCalls int32
	obs := &cascadeObs{}
	c := &JevCascadeEvaluator{
		Primary: fakeScorer{}, Secondary: countingLLM("DENY", &llmCalls),
		AllowBelow: 0.1, DenyAbove: 0.7, Observer: obs,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || res.DecidedBy != JevCascadeDecidedBy || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s decided_by=%q llm_calls=%d", res.Decision, res.DecidedBy, llmCalls)
	}
	if got := obs.get(); got != JevCascadeError {
		t.Fatalf("outcome=%q", got)
	}
}

func costedLLM(decision string, durationMs, in, out int) Evaluator {
	return NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		body, _ := json.Marshal(map[string]string{"decision": decision, "reason": "llm-reason"})
		return llm.Response{Text: string(body), DurationMs: durationMs, InputTokens: in, OutputTokens: out}, nil
	}})
}

func TestJevCascade_EscalationKeepsJevCostAndMarksCascade(t *testing.T) {
	score := 0.55
	c := &JevCascadeEvaluator{
		Primary:    fakeScorer{res: JudgeResult{Model: testJevModel, DurationMs: 40, InputTokens: 7, OutputTokens: 1, Score: &score}},
		Secondary:  costedLLM("DENY", 300, 100, 20),
		AllowBelow: 0.3, DenyAbove: 0.7,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != types.DecisionDeny || res.Reason != "llm-reason" {
		t.Fatalf("decision=%s reason=%q, want the LLM's decision and reason", res.Decision, res.Reason)
	}
	if res.DecidedBy != JevCascadeDecidedBy {
		t.Fatalf("decided_by=%q, want %q", res.DecidedBy, JevCascadeDecidedBy)
	}
	if want := testJevModel + " + test"; res.Model != want {
		t.Fatalf("model=%q, want %q", res.Model, want)
	}
	if res.DurationMs != 340 || res.InputTokens != 107 || res.OutputTokens != 21 {
		t.Fatalf("duration=%d in=%d out=%d, want 340/107/21 (LLM + Jev)", res.DurationMs, res.InputTokens, res.OutputTokens)
	}
	if !strings.HasPrefix(res.RawOutput, "jev noul p(violates)=0.5500, escalated to llm\n") || !strings.Contains(res.RawOutput, `"decision":"DENY"`) {
		t.Fatalf("raw_output=%q, want Jev score line followed by the LLM output", res.RawOutput)
	}
}

func TestJevCascade_JevErrorKeepsJevCostAndMarksCascade(t *testing.T) {
	c := &JevCascadeEvaluator{
		Primary:    fakeScorer{res: JudgeResult{Model: testJevModel, DurationMs: 5000}, err: errors.New("jev request failed: deadline exceeded")},
		Secondary:  costedLLM("ALLOW", 300, 100, 20),
		AllowBelow: 0.3, DenyAbove: 0.7,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if res.DecidedBy != JevCascadeDecidedBy || res.DurationMs != 5300 {
		t.Fatalf("decided_by=%q duration=%d, want %q and 5300 (the request waited for Jev's timeout)", res.DecidedBy, res.DurationMs, JevCascadeDecidedBy)
	}
	if !strings.HasPrefix(res.RawOutput, "jev: error, escalated to llm\n") {
		t.Fatalf("raw_output=%q", res.RawOutput)
	}
	if strings.Contains(res.RawOutput, "deadline exceeded") {
		t.Fatalf("raw_output=%q must not carry the Jev error text", res.RawOutput)
	}
}

func TestJevCascade_LLMErrorAfterJevStillCarriesJevCost(t *testing.T) {
	score := 0.55
	failing := NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		return llm.Response{DurationMs: 300}, errors.New("boom")
	}})
	c := &JevCascadeEvaluator{
		Primary:    fakeScorer{res: JudgeResult{Model: testJevModel, DurationMs: 40, Score: &score}},
		Secondary:  failing,
		AllowBelow: 0.3, DenyAbove: 0.7,
	}
	res, err := c.Evaluate(context.Background(), "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err == nil {
		t.Fatal("expected the LLM error to propagate")
	}
	if res.Model != testJevModel+" + test" || res.DurationMs != 340 {
		t.Fatalf("model=%q duration=%d, want combined model and 340ms so the manager records the cost on the error path", res.Model, res.DurationMs)
	}
}

// A caller that disconnects while Jev runs must not count as a Jev error or
// reach the LLM, whose adapter would record the cancelled call as a failure.
func TestJevCascade_CancelledCallerSkipsLLM(t *testing.T) {
	score := 0.5
	cases := []struct {
		name   string
		scorer fakeScorer
		want   string // observed outcome
	}{
		{"jev error", fakeScorer{err: context.Canceled}, ""},
		{"uncertain score", fakeScorer{res: JudgeResult{Score: &score}}, JevCascadeEscalate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var llmCalls int32
			obs := &cascadeObs{}
			c := &JevCascadeEvaluator{
				Primary: tc.scorer, Secondary: countingLLM("ALLOW", &llmCalls),
				AllowBelow: 0.1, DenyAbove: 0.7, Observer: obs,
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err := c.Evaluate(ctx, "GET", "https://api.github.com/", nil, "", types.LLMPolicy{Prompt: "p"})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v, want context.Canceled", err)
			}
			if n := atomic.LoadInt32(&llmCalls); n != 0 {
				t.Fatalf("llm_calls=%d, want 0", n)
			}
			if got := obs.get(); got != tc.want {
				t.Fatalf("outcome=%q, want %q", got, tc.want)
			}
		})
	}
}
