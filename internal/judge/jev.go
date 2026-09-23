package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const (
	jevDefaultBaseURL      = "https://api.typesafe.ai/v1/systemone"
	jevModel               = "jev-latest"
	jevViolatesQuestionKey = "violates_policy"
	jevInstructions        = "Given the security policy and the HTTP request described in the state, does this request violate the policy? Answer true if the request should be DENIED, false if it should be ALLOWED."
)

// JevEvaluator obtains TypeSafe Jev classifier scores for HTTP requests.
type JevEvaluator struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	timeout    time.Duration

	*llm.Resilience
}

// NewJevEvaluator creates a JevEvaluator backed by the TypeSafe AI API.
func NewJevEvaluator(apiKey string, timeout time.Duration, opts ...llm.ResilienceOption) (*JevEvaluator, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("jev API key is required")
	}
	return &JevEvaluator{
		httpClient: &http.Client{},
		apiKey:     apiKey,
		baseURL:    jevDefaultBaseURL,
		timeout:    timeout,
		Resilience: llm.NewResilience(opts...),
	}, nil
}

// SetBaseURL overrides the TypeSafe API base URL (useful for testing).
func (j *JevEvaluator) SetBaseURL(url string) { j.baseURL = url }

type jevQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

type jevRequest struct {
	State     string                 `json:"state"`
	Model     string                 `json:"model"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevAnswer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul"`
}

type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type jevResponse struct {
	Model   string               `json:"model"`
	Answers map[string]jevAnswer `json:"answers"`
	Usage   jevUsage             `json:"usage"`
}

// jevStateJSON bundles the policy and the serialized request into the single
// "state" string Jev evaluates. The policy is JSON-escaped (via json.Marshal)
// to prevent prompt injection — the same defense buildSystemPrompt uses for
// the generative LLM judge.
type jevStateJSON struct {
	Policy  string          `json:"policy"`
	Request json.RawMessage `json:"request"`
}

// buildJevState reuses the existing request-JSON serialization (truncation,
// header capping, multipart summaries) from llm_judge.go so Jev gets the
// same prompt-injection defenses as the generative judge.
func buildJevState(policyPrompt, method, rawURL string, headers http.Header, body string) string {
	contentType := headers.Get("Content-Type")
	reqJSON := buildUserMessage(method, rawURL, headers, body, contentType)
	state := jevStateJSON{
		Policy:  policyPrompt,
		Request: json.RawMessage(reqJSON),
	}
	out, _ := json.Marshal(state)
	return string(out)
}

// Score calls the Jev API and returns its "violates policy" probability.
// Jev never explains its reasoning, so Reason is synthesized from the score.
func (j *JevEvaluator) Score(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error) {
	partial := JudgeResult{Model: jevModel}

	// Non-blocking: when Jev is saturated the cascade escalates to the LLM
	// right away rather than queueing in front of it.
	if err := j.TryAcquire("jev"); err != nil {
		return partial, err
	}
	defer j.Release()

	reqBody := jevRequest{
		State: buildJevState(policy.Prompt, method, rawURL, headers, body),
		Model: jevModel,
		Questions: map[string]jevQuestion{
			jevViolatesQuestionKey: {Type: "noul", Instructions: jevInstructions},
		},
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return partial, fmt.Errorf("failed to marshal jev request: %w", err)
	}

	timeout := j.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, j.baseURL, bytes.NewReader(reqBytes))
	if err != nil {
		return partial, fmt.Errorf("failed to create jev request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+j.apiKey)

	start := time.Now()
	httpResp, err := j.httpClient.Do(httpReq)
	partial.DurationMs = int(time.Since(start).Milliseconds())
	if err != nil {
		j.RecordFailure()
		return partial, fmt.Errorf("jev request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		j.RecordFailure()
		// Drain a bounded amount so the connection can be reused, but never
		// surface the body: it may echo the state (policy, request headers and
		// body), and this error is logged.
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 4<<10))
		return partial, fmt.Errorf("jev API error (status %d)", httpResp.StatusCode)
	}

	var respBody jevResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&respBody); err != nil {
		j.RecordFailure()
		return partial, fmt.Errorf("failed to parse jev response: %w", err)
	}
	partial.InputTokens = respBody.Usage.InputTokens
	partial.OutputTokens = respBody.Usage.OutputTokens

	answer, ok := respBody.Answers[jevViolatesQuestionKey]
	if !ok {
		j.RecordFailure()
		return partial, fmt.Errorf("jev response missing answer for %q", jevViolatesQuestionKey)
	}
	if answer.Type != "noul" || answer.Noul == nil {
		j.RecordFailure()
		return partial, fmt.Errorf("jev answer for %q is not a valid noul answer (type=%q)", jevViolatesQuestionKey, answer.Type)
	}
	noul := *answer.Noul
	if noul < 0 || noul > 1 {
		j.RecordFailure()
		return partial, fmt.Errorf("jev answer for %q has score outside [0,1]: %v", jevViolatesQuestionKey, noul)
	}
	partial.Score = &noul
	partial.RawOutput = fmt.Sprintf("jev noul p(violates)=%.4f", noul)
	partial.Reason = fmt.Sprintf("jev: p(violates)=%.2f", noul)

	j.RecordSuccess()
	return partial, nil
}
