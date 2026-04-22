package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/brexhq/CrabTrap/internal/judgeprompt"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// JudgeResult holds the parsed outcome of one LLM judge call.
type JudgeResult struct {
	Decision     types.DecisionType
	Reason       string
	Model        string // actual model ID used
	DurationMs   int
	InputTokens  int
	OutputTokens int
	RawOutput    string // raw model text before parsing
}

// LLMJudge evaluates HTTP requests against an LLM policy via an Adapter.
type LLMJudge struct{ adapter llm.Adapter }

// NewLLMJudge constructs an LLMJudge backed by the given adapter.
func NewLLMJudge(adapter llm.Adapter) *LLMJudge {
	return &LLMJudge{adapter: adapter}
}

// Evaluate calls the adapter and returns ALLOW or DENY.
// On error, the returned JudgeResult still has Model and DurationMs populated.
func (j *LLMJudge) Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error) {
	partial := JudgeResult{Model: j.adapter.ModelID()}

	userMsg := judgeprompt.BuildUserMessage(method, rawURL, headers, body, judgeprompt.DefaultMaxBodyBytes)
	resp, err := j.adapter.Complete(ctx, llm.Request{
		System:            buildSystemPrompt(policy.Prompt),
		Messages:          []llm.Message{{Role: "user", Content: userMsg}},
		MaxTokens:         512,
		CacheSystemPrompt: true,
	})
	partial.DurationMs = resp.DurationMs
	if err != nil {
		partial.RawOutput = fmt.Sprintf("adapter complete failed: %v", err)
		return partial, fmt.Errorf("adapter complete failed: %w", err)
	}

	partial.InputTokens = resp.InputTokens
	partial.OutputTokens = resp.OutputTokens
	partial.RawOutput = resp.Text

	type decisionJSON struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	var d decisionJSON
	if err := json.Unmarshal([]byte(llm.StripCodeFences(resp.Text)), &d); err != nil {
		return partial, fmt.Errorf("failed to parse decision JSON from model output: %w (response: %s)", err, resp.Text)
	}

	partial.Reason = d.Reason
	d.Decision = strings.ToUpper(strings.TrimSpace(d.Decision))
	switch types.DecisionType(d.Decision) {
	case types.DecisionAllow:
		partial.Decision = types.DecisionAllow
		return partial, nil
	case types.DecisionDeny:
		partial.Decision = types.DecisionDeny
		return partial, nil
	default:
		return partial, fmt.Errorf("unknown decision %q from model", d.Decision)
	}
}

// buildSystemPrompt constructs the system prompt for the judge.
//
// The policy is embedded as a JSON-escaped value inside a structured JSON object.
// This prevents prompt injection via policy content — any special characters,
// delimiters, or instruction-like text in the policy are safely escaped by
// json.Marshal rather than concatenated as raw text.
func buildSystemPrompt(policyPrompt string) string {
	policyJSON, _ := json.Marshal(policyPrompt)
	return `You are a security policy enforcement agent. You will receive an HTTP request as a structured JSON object and must decide whether it is ALLOWED or DENIED.

The policy to enforce is provided below as a JSON-encoded string. Parse the string value to read the policy:
{"policy":` + string(policyJSON) + `}

Respond ONLY with valid JSON in this exact format (no other text):
{"decision":"ALLOW","reason":"brief explanation"}
or
{"decision":"DENY","reason":"brief explanation"}`
}
