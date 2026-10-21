package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			Model: JevDefaultModel,
			Answers: map[string]jevAnswer{
				jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
			},
		})
	}))
	t.Cleanup(srv.Close)
	ev, err := NewJevEvaluator("test-key", 0)
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
		{"allow threshold escalates", 0.2, types.DecisionDeny, "", 1, JevCascadeEscalate},
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
					Model: JevDefaultModel,
					Answers: map[string]jevAnswer{
						jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
					},
				})
			}))
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(release) })
			primary, err := NewJevEvaluator("test-key", 25*time.Millisecond, llm.WithMaxConcurrency(1))
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
			Model: JevDefaultModel,
			Answers: map[string]jevAnswer{
				jevViolatesQuestionKey: {Type: "noul", Noul: &noul},
			},
		})
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(releaseHandler)
	primary, err := NewJevEvaluator("test-key", time.Second, llm.WithMaxConcurrency(1))
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
	c := &JevCascadeEvaluator{
		Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.2, DenyAbove: 0.7,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := c.Evaluate(ctx, "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
	if err != nil || res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != 1 || atomic.LoadInt32(&visits) != 1 {
		t.Fatalf("result=%+v err=%v llm_calls=%d jev_visits=%d", res, err, llmCalls, visits)
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
	primary, err := NewJevEvaluator("test-key", time.Second, llm.WithCircuitBreaker(1, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	primary.SetBaseURL(srv.URL)
	var llmCalls int32
	c := &JevCascadeEvaluator{
		Primary: primary, Secondary: countingLLM("ALLOW", &llmCalls),
		AllowBelow: 0.2, DenyAbove: 0.7,
	}
	for i := 1; i <= 2; i++ {
		res, err := c.Evaluate(context.Background(), "GET", "https://example.com/", nil, "", types.LLMPolicy{Prompt: "p"})
		if err != nil || res.Decision != types.DecisionAllow || atomic.LoadInt32(&llmCalls) != int32(i) || atomic.LoadInt32(&visits) != 1 {
			t.Fatalf("call %d result=%+v err=%v llm_calls=%d jev_visits=%d", i, res, err, llmCalls, visits)
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
	primary, err := NewJevEvaluator("test-key", 0)
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

// A scorer that returns no score and no error must escalate, not decide.
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
	if res.Decision != types.DecisionDeny || res.DecidedBy != "" || atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("decision=%s decided_by=%q llm_calls=%d", res.Decision, res.DecidedBy, llmCalls)
	}
	if got := obs.get(); got != JevCascadeError {
		t.Fatalf("outcome=%q", got)
	}
}
