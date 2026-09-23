package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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
			Model: jevModel,
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
