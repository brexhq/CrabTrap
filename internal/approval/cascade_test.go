package approval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func cascadeWithNoul(t *testing.T, noul float64, llmDecision string, llmCalls *int32) *Manager {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"model": "jev-latest",
			"answers": map[string]interface{}{
				"violates_policy": map[string]interface{}{"type": "noul", "noul": noul},
			},
		})
	}))
	t.Cleanup(srv.Close)

	jev, err := judge.NewJevEvaluator("test-key", "jev-1.13.0", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	jev.SetBaseURL(srv.URL)

	secondary := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		atomic.AddInt32(llmCalls, 1)
		body, _ := json.Marshal(map[string]string{"decision": llmDecision, "reason": "from-llm"})
		return llm.Response{Text: string(body)}, nil
	}})

	m := NewManager()
	m.SetJudge(&judge.JevCascadeEvaluator{
		Primary: jev, Secondary: secondary,
		AllowBelow: 0.3, DenyAbove: 0.7,
	}, "llm", "deny")
	return m
}

func TestJevCascade_ShortCircuitUsesJevDecision(t *testing.T) {
	var llmCalls int32
	m := cascadeWithNoul(t, 0.05, "DENY", &llmCalls)
	req, _ := http.NewRequest("GET", "https://api.github.com/", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req_cascade_allow", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Fatalf("decision=%s", decision.Decision)
	}
	if decision.ApprovedBy != "jev" {
		t.Fatalf("ApprovedBy=%q want jev", decision.ApprovedBy)
	}
	if atomic.LoadInt32(&llmCalls) != 0 {
		t.Fatalf("LLM calls=%d", llmCalls)
	}
}

func TestJevCascade_UncertainUsesLLM(t *testing.T) {
	var llmCalls int32
	m := cascadeWithNoul(t, 0.5, "DENY", &llmCalls)
	req, _ := http.NewRequest("POST", "https://api.github.com/x", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req_cascade_uncertain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != judge.JevCascadeDecidedBy {
		t.Fatalf("decision=%s approved_by=%s", decision.Decision, decision.ApprovedBy)
	}
	if atomic.LoadInt32(&llmCalls) != 1 {
		t.Fatalf("LLM calls=%d", llmCalls)
	}
	// The persisted response must show both evaluators and Jev's score.
	lr := decision.LLMResponse
	if lr == nil || !strings.Contains(lr.Model, " + ") || !strings.HasPrefix(lr.RawOutput, "jev noul p(violates)=0.5000, escalated to llm\n") {
		t.Fatalf("llm_response=%+v, want combined model and Jev score in raw output", lr)
	}
}

func TestJevCascade_EmptyLLMOutputPreservesError(t *testing.T) {
	var llmCalls int32
	m := cascadeWithNoul(t, 0.5, "DENY", &llmCalls)
	m.judge.(*judge.JevCascadeEvaluator).Secondary = judge.NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		return llm.Response{}, nil
	}})

	req, _ := http.NewRequest("GET", "https://api.github.com/", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req_cascade_empty_llm", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm-fallback" {
		t.Fatalf("decision=%s approved_by=%s, want DENY via llm-fallback", decision.Decision, decision.ApprovedBy)
	}
	lr := decision.LLMResponse
	if lr == nil || lr.Result != "error" {
		t.Fatalf("llm_response=%+v, want an error response", lr)
	}
	if !strings.HasPrefix(lr.RawOutput, "jev noul p(violates)=0.5000, escalated to llm\n") ||
		!strings.Contains(lr.RawOutput, "failed to parse decision JSON from model output: unexpected end of JSON input") {
		t.Fatalf("raw_output=%q, want both Jev's score and the LLM parse error", lr.RawOutput)
	}
}

func TestJevCascade_StaticRuleStillWins(t *testing.T) {
	var llmCalls int32
	m := cascadeWithNoul(t, 0.99, "ALLOW", &llmCalls)
	rules := []types.StaticRule{{
		Methods: []string{"GET"}, URLPattern: "https://api.example.com/",
		MatchType: "prefix", Action: "allow",
	}}
	ctx := policyCtxWithRules("pol", "p", rules)
	req, _ := http.NewRequest("GET", "https://api.example.com/ok", nil)
	decision, _, err := m.CheckApproval(ctx, req, "req_cascade_static", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm-static-rule" {
		t.Fatalf("decision=%s approvedBy=%s", decision.Decision, decision.ApprovedBy)
	}
	if atomic.LoadInt32(&llmCalls) != 0 {
		t.Fatalf("LLM calls=%d", llmCalls)
	}
}
