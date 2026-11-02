package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const (
	jevDefaultBaseURL      = "https://api.typesafe.ai/v1/systemone"
	jevViolatesQuestionKey = "violates_policy"
	jevInstructions        = "Given the security policy and the HTTP request described in the state, does this request violate the policy? Answer true if the request should be DENIED, false if it should be ALLOWED."
)

// ErrJevUnavailable means Jev was not called: every slot was busy or its
// circuit breaker was open.
var ErrJevUnavailable = errors.New("jev unavailable")

// JevEvaluator obtains TypeSafe Jev classifier scores for HTTP requests.
type JevEvaluator struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	model      string
	timeout    time.Duration

	*llm.Resilience
}

// NewJevEvaluator creates a JevEvaluator backed by the TypeSafe AI API. model
// should be a pinned version: aliases like jev-latest move when TypeSafe ships
// a new release, which silently shifts scores under calibrated thresholds.
func NewJevEvaluator(apiKey, model string, timeout time.Duration, opts ...llm.ResilienceOption) (*JevEvaluator, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("jev API key is required")
	}
	// A zero timeout would expire every call immediately and trip the breaker.
	if timeout <= 0 {
		return nil, fmt.Errorf("jev timeout must be positive (got %v)", timeout)
	}
	res := llm.NewResilience(opts...)
	// The default transport keeps only 2 idle connections per host, so most
	// concurrent calls would pay for a fresh TLS handshake.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = res.MaxConcurrency()
	return &JevEvaluator{
		httpClient: &http.Client{Transport: transport},
		apiKey:     apiKey,
		baseURL:    jevDefaultBaseURL,
		model:      model,
		timeout:    timeout,
		Resilience: res,
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
// "state" string Jev evaluates. The policy and request are JSON-escaped (via
// json.Marshal), the same serialization the generative LLM judge uses. That
// only keeps attacker-controlled text from breaking out of its JSON string
// fields. Jev gets no system prompt telling it to resist injection, so a body
// can still try to push its score down. See docs/jev-cascade.md.
type jevStateJSON struct {
	Policy  string          `json:"policy"`
	Request json.RawMessage `json:"request"`
}

// buildJevState reuses the existing request-JSON serialization (truncation,
// header capping, multipart summaries) from llm_judge.go, so Jev sees the
// request in the same shape as the generative judge. The system-prompt
// hardening in buildSystemPrompt does not apply to Jev.
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
	partial := JudgeResult{Model: j.model}

	// Non-blocking: when Jev is saturated the cascade escalates to the LLM
	// right away rather than queueing in front of it.
	if err := j.TryAcquire("jev"); err != nil {
		return partial, fmt.Errorf("%w: %v", ErrJevUnavailable, err)
	}
	defer j.Release()

	reqBody := jevRequest{
		State: buildJevState(policy.Prompt, method, rawURL, headers, body),
		Model: j.model,
		Questions: map[string]jevQuestion{
			jevViolatesQuestionKey: {Type: "noul", Instructions: jevInstructions},
		},
	}
	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return partial, fmt.Errorf("failed to marshal jev request: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, j.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, j.baseURL, bytes.NewReader(reqBytes))
	if err != nil {
		return partial, fmt.Errorf("failed to create jev request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+j.apiKey)

	start := time.Now()
	elapsedMs := func() int { return int(time.Since(start).Milliseconds()) }
	// A cancelled caller context (client disconnect, aborted upstream request)
	// says nothing about Jev's health, so it must not count toward the breaker
	// or the latency histogram. Our own callCtx timeout and real transport
	// errors still do.
	defer func() {
		if ctx.Err() == nil {
			j.RecordJudgeLatency(j.model, time.Since(start))
		}
	}()
	recordTransportFailure := func() {
		if ctx.Err() == nil {
			j.RecordFailure()
		} else {
			j.RecordCancellation()
		}
	}
	httpResp, err := j.httpClient.Do(httpReq)
	partial.DurationMs = elapsedMs()
	if err != nil {
		recordTransportFailure()
		return partial, fmt.Errorf("jev request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// 5xx and 429 say Jev itself is in trouble, and 401/403 mean the key is
		// bad, which fails every request the same way. Other 4xx responses come
		// from this request, so they must not trip the breaker for everyone
		// else; they count as neither failure nor success.
		switch code := httpResp.StatusCode; {
		case code >= 500, code == http.StatusTooManyRequests,
			code == http.StatusUnauthorized, code == http.StatusForbidden:
			j.RecordFailure()
		default:
			j.RecordCancellation()
		}
		// Drain a bounded amount so the connection can be reused, but never
		// surface the body: it may echo the state (policy, request headers and
		// body), and this error is logged.
		_, _ = io.Copy(io.Discard, io.LimitReader(httpResp.Body, 4<<10))
		partial.DurationMs = elapsedMs()
		return partial, fmt.Errorf("jev API error (status %d)", httpResp.StatusCode)
	}

	var respBody jevResponse
	err = json.NewDecoder(httpResp.Body).Decode(&respBody)
	// Do returns once headers arrive, so measure through the body read to
	// include a slow response body in the recorded duration. The deferred
	// latency sample above also runs after the body read, so the histogram
	// matches the persisted DurationMs.
	partial.DurationMs = elapsedMs()
	if err != nil {
		recordTransportFailure()
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
