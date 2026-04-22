package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/probes"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// probeResponseBody builds an OpenAI-compatible chat completion with the
// given scores map. Matches backend/api/schemas.py:ChatCompletion.
func probeResponseBody(scores map[string][]float64) []byte {
	resp := map[string]interface{}{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   "test-model",
		"choices": []map[string]interface{}{{
			"index":         0,
			"message":       map[string]interface{}{"role": "assistant", "content": "..."},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     10,
			"completion_tokens": 3,
			"total_tokens":      13,
		},
		"scores": scores,
	}
	b, _ := json.Marshal(resp)
	return b
}

// newProbeRunnerServer returns a runner whose probe-demo backend is an
// httptest.Server returning the fixed scores map. Caller must Close() the
// returned server.
func newProbeRunnerServer(t *testing.T, specs []probes.Spec, scores map[string][]float64) (*probes.Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeResponseBody(scores))
	}))
	client := probes.NewClient(server.URL, "test-model", 5*time.Second, 32)
	return probes.NewRunner(client, specs, 0), server
}

// newProbeRunnerErrorServer returns a runner whose server always returns 500.
func newProbeRunnerErrorServer(t *testing.T, specs []probes.Spec) (*probes.Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	client := probes.NewClient(server.URL, "test-model", 1*time.Second, 32)
	return probes.NewRunner(client, specs, 0), server
}

// --- Matrix cells ---

// Cell: mode=passthrough × probes=off. Should hit the fast path.
func TestProbes_Passthrough_ProbesOff_ReturnsPassthroughAllow(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, body, err := m.CheckApproval(context.Background(), req, "req1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "passthrough" {
		t.Errorf("expected passthrough ALLOW, got %+v", decision)
	}
	if body != nil {
		t.Error("passthrough fast path should not read body")
	}
	if decision.ProbeScores != nil {
		t.Error("probe fields should be unset when probes are off")
	}
}

// Cell: mode=passthrough × probes=on (under threshold). Probes approve.
func TestProbes_Passthrough_ProbesUnderThreshold_AllowsViaProbes(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.1, 0.2}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(context.Background(), req, "req2", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probes" {
		t.Errorf("expected approvedBy=probes, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if decision.ProbeScores["exfiltration"] != 0.2 {
		t.Errorf("expected aggregated score 0.2, got %v", decision.ProbeScores)
	}
}

// Cell: mode=passthrough × probes=on (over threshold). Probes DENY.
func TestProbes_Passthrough_ProbesOverThreshold_Denies(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.1, 0.9}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("POST", "https://example.com/steal", bytes.NewReader([]byte(`{"x":1}`)))
	decision, _, err := m.CheckApproval(context.Background(), req, "req3", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probe:exfiltration" {
		t.Errorf("expected approvedBy=probe:exfiltration, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "probe" {
		t.Errorf("expected channel=probe, got %q", decision.Channel)
	}
	if decision.ProbeTripped != "exfiltration" {
		t.Errorf("expected ProbeTripped=exfiltration, got %q", decision.ProbeTripped)
	}
	if !strings.Contains(decision.Reason, "tripped") {
		t.Errorf("reason should describe the trip: %q", decision.Reason)
	}
}

// Cell: mode=passthrough × probes=on (error). Probe failure non-fatal,
// passthrough ALLOW with probe error logged.
func TestProbes_Passthrough_ProbeError_StillAllows(t *testing.T) {
	m := NewManager()
	m.SetMode("passthrough")

	runner, server := newProbeRunnerErrorServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(context.Background(), req, "req4", nil)
	if err != nil {
		t.Fatalf("probe errors should be non-fatal, got err %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW (probe error, passthrough mode), got %v", decision.Decision)
	}
	if decision.ApprovedBy != "passthrough" {
		t.Errorf("probe error should fall back to passthrough, got approvedBy=%q", decision.ApprovedBy)
	}
}

// Cell: mode=llm × probes=off. Regression check — judge decides alone.
func TestProbes_LLM_ProbesOff_JudgeAllow(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req5", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected llm ALLOW, got %+v", decision)
	}
	if decision.ProbeScores != nil {
		t.Error("probe fields should be unset when probes are off")
	}
}

// Cell: mode=llm × probes=on, probe under threshold, judge ALLOW.
// Judge's ALLOW stands and probe audit fields populated.
func TestProbes_LLM_ProbesUnderThreshold_JudgeAllowStands(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "jailbreak", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"jailbreak": {0.1}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("POST", "https://example.com/api", bytes.NewReader([]byte(`{"k":"v"}`)))
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req6", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW to stand, got %+v", decision)
	}
	if decision.ProbeScores["jailbreak"] != 0.1 {
		t.Errorf("expected probe score audit field, got %v", decision.ProbeScores)
	}
	if decision.ProbeTripped != "" {
		t.Errorf("expected no trip, got %q", decision.ProbeTripped)
	}
}

// Cell: mode=llm × probes=on, probe trip, judge ALLOW.
// Probe DENY beats judge ALLOW.
func TestProbes_LLM_ProbeTripWinsOverJudgeAllow(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
		map[string][]float64{"exfiltration": {0.95}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com/x", nil)
	decision, _, err := m.CheckApproval(policyCtx("permissive policy"), req, "req7", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("probe trip should DENY despite judge ALLOW, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "probe:exfiltration" {
		t.Errorf("expected approvedBy=probe:exfiltration, got %q", decision.ApprovedBy)
	}
	// Judge still ran — its response should be attached for audit.
	if decision.LLMResponse == nil {
		t.Error("expected LLMResponse attached when judge ran alongside probe trip")
	}
}

// Cell: mode=llm × probes=on, probe error, judge ALLOW.
// Probe error falls through; judge ALLOW stands.
func TestProbes_LLM_ProbeError_JudgeAllowStands(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	runner, server := newProbeRunnerErrorServer(t,
		[]probes.Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req8", nil)
	if err != nil {
		t.Fatalf("probe errors should be non-fatal, got err %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW to stand when probe errors, got %+v", decision)
	}
}

// Cell: mode=llm × probes=on, judge DENY + probes pass → judge DENY stands.
func TestProbes_LLM_JudgeDenyWithProbesPass(t *testing.T) {
	m := newLLMManager(t, denyJudge(), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "jailbreak", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"jailbreak": {0.1}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("strict policy"), req, "req9", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge DENY to stand, got %+v", decision)
	}
	if decision.ProbeScores["jailbreak"] != 0.1 {
		t.Errorf("probe scores should still be recorded for audit, got %v", decision.ProbeScores)
	}
}

// Cell: static rule deny short-circuits before probes or judge run.
func TestProbes_StaticRuleDenyShortCircuits(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")
	// If probes ran, this would trip and return DENY via probe. But static rule
	// deny must short-circuit first — observed via channel=llm (not probe).
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "x", Threshold: 0.1, Aggregation: "max"}},
		map[string][]float64{"x": {0.9}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	policy := &types.LLMPolicy{
		ID:     "llmpol_static",
		Prompt: "policy",
		StaticRules: []types.StaticRule{
			{URLPattern: "https://blocked.example.com", Action: "deny", MatchType: "prefix"},
		},
	}
	ctx := context.WithValue(context.Background(), ContextKeyLLMPolicy, policy)

	req, _ := http.NewRequest("GET", "https://blocked.example.com/x", nil)
	decision, _, err := m.CheckApproval(ctx, req, "req10", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.ApprovedBy != "llm-static-rule" {
		t.Errorf("expected static-rule short-circuit, got approvedBy=%q", decision.ApprovedBy)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	// Probe fields should not be set — probes never ran.
	if decision.ProbeScores != nil {
		t.Error("static-rule short-circuit should skip probe evaluation")
	}
}

// Cell: probes circuit open → no trip, judge still runs.
func TestProbes_LLM_CircuitOpen_FallsThroughToJudge(t *testing.T) {
	m := newLLMManager(t, allowJudge(), "deny")

	// Trip the breaker by failing 3 calls directly on the client.
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errServer.Close()
	client := probes.NewClient(errServer.URL, "test-model", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)
	for i := 0; i < 3; i++ {
		client.Complete(context.Background(), "sys", "user") //nolint:errcheck
	}
	if !client.IsOpen() {
		t.Fatal("precondition: breaker should be open")
	}
	runner := probes.NewRunner(client, []probes.Spec{{Name: "x", Threshold: 0.5, Aggregation: "max"}}, 0)
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req11", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow || decision.ApprovedBy != "llm" {
		t.Errorf("expected judge ALLOW when breaker open, got %+v", decision)
	}
	if !decision.ProbeCircuitOpen {
		t.Error("expected ProbeCircuitOpen=true in audit")
	}
}

// Cell: judge error with probe pass → fallback path keeps probe fields.
func TestProbes_LLM_JudgeErrorWithProbePass_FallbackKeepsProbeFields(t *testing.T) {
	m := newLLMManager(t, errorJudge(errors.New("judge call failed")), "deny")
	runner, server := newProbeRunnerServer(t,
		[]probes.Spec{{Name: "x", Threshold: 0.8, Aggregation: "max"}},
		map[string][]float64{"x": {0.2}},
	)
	defer server.Close()
	m.SetProbeRunner(runner)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	decision, _, err := m.CheckApproval(policyCtx("policy"), req, "req12", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "llm-fallback" {
		t.Errorf("expected fallback DENY when judge errors, got %+v", decision)
	}
	if decision.ProbeScores["x"] != 0.2 {
		t.Errorf("probe fields should still be populated on judge error path, got %v", decision.ProbeScores)
	}
}
