package approval

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/brexhq/CrabTrap/internal/config"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
	"gopkg.in/yaml.v3"
)

func TestJevZeroThresholdFromConfig(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers":{"violates_policy":{"type":"noul","noul":0}}}`))
	}))
	defer server.Close()
	checkJevZeroThresholdFromConfig(t, "test-key", server.URL)
	if calls.Load() != 1 {
		t.Fatalf("Jev calls=%d, want 1", calls.Load())
	}
}

func TestJevZeroThresholdLive(t *testing.T) {
	if os.Getenv("JEV_INJECTION_EVAL") != "1" || os.Getenv("TYPESAFE_API_KEY") == "" {
		t.Skip("set JEV_INJECTION_EVAL=1 and TYPESAFE_API_KEY to run the live Jev check")
	}
	checkJevZeroThresholdFromConfig(t, "${TYPESAFE_API_KEY}", "")
}

func checkJevZeroThresholdFromConfig(t *testing.T, apiKey, baseURL string) {
	t.Helper()
	data, err := os.ReadFile("../../config/gateway.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	var template config.Config
	if err := yaml.Unmarshal(data, &template); err != nil {
		t.Fatal(err)
	}
	zero := 0.0
	template.Database.URL = "postgres://localhost/unused"
	template.LLMJudge.Jev = config.JevConfig{
		Enabled: true, APIKey: apiKey, BaseURL: baseURL,
		AllowBelow: &zero, DenyAbove: &zero,
	}
	data, err = yaml.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	jc := cfg.LLMJudge.Jev
	primary, err := judge.NewJevEvaluator(jc.APIKey, jc.Model, jc.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	if jc.BaseURL != "" {
		primary.SetBaseURL(jc.BaseURL)
	}
	var llmCalls atomic.Int32
	secondary := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		llmCalls.Add(1)
		return llm.Response{Text: `{"decision":"ALLOW","reason":"unexpected escalation"}`}, nil
	}})
	manager := NewManager()
	manager.SetJudge(&judge.JevCascadeEvaluator{
		Primary: primary, Secondary: secondary,
		AllowBelow: *jc.AllowBelow, DenyAbove: *jc.DenyAbove,
	}, cfg.Approval.Mode, cfg.LLMJudge.FallbackMode)
	req, err := http.NewRequest("GET", "https://api.example.com/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	decision, _, err := manager.CheckApproval(policyCtx("Allow ordinary health checks."), req, "zero-threshold-check", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != types.DecisionDeny || decision.ApprovedBy != "jev" || llmCalls.Load() != 0 {
		t.Fatalf("decision=%s approved_by=%s LLM calls=%d; want DENY by Jev without LLM", decision.Decision, decision.ApprovedBy, llmCalls.Load())
	}
	if decision.LLMResponse == nil {
		t.Fatal("missing Jev response")
	}
	t.Logf("model=%s, %s; DENY by Jev, no LLM call", decision.LLMResponse.Model, decision.LLMResponse.RawOutput)
}
