package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// DefaultTimeout is the per-request timeout for probe-demo calls.
const DefaultTimeout = 10 * time.Second

// DefaultMaxTokens is the OpenAI max_tokens we request. Probes only need a
// few continuation tokens to activate; generation cost is mostly overhead.
const DefaultMaxTokens = 32

// ClientResponse holds the parsed probe-demo completion, including per-token
// activation scores keyed by probe name.
type ClientResponse struct {
	Scores       map[string][]float64
	DurationMs   int
	InputTokens  int
	OutputTokens int
}

// Client posts chat completions to a probe-demo server (OpenAI-compatible)
// with the `include_scores: true` extension.
type Client struct {
	httpClient *http.Client
	endpoint   string // probe-demo base URL, e.g. http://localhost:8000
	model      string
	timeout    time.Duration
	maxTokens  int

	*llm.Resilience
}

// NewClient constructs a probe-demo client pointing at endpoint (no trailing
// slash required). A zero timeout falls back to DefaultTimeout; a zero
// maxTokens falls back to DefaultMaxTokens.
func NewClient(endpoint, model string, timeout time.Duration, maxTokens int, opts ...llm.ResilienceOption) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}
	return &Client{
		httpClient: &http.Client{},
		endpoint:   endpoint,
		model:      model,
		timeout:    timeout,
		maxTokens:  maxTokens,
		Resilience: llm.NewResilience(opts...),
	}
}

// chatMessage mirrors probe-demo's ChatMessage schema.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatRequest mirrors probe-demo's ChatCompletionRequest. probe_path is
// omitted so probe-demo returns scores for every probe loaded server-side
// via PROBE_PATH.
type chatRequest struct {
	Model         string        `json:"model"`
	Messages      []chatMessage `json:"messages"`
	Stream        bool          `json:"stream"`
	MaxTokens     int           `json:"max_tokens"`
	IncludeScores bool          `json:"include_scores"`
}

// chatUsage mirrors probe-demo's CompletionUsage.
type chatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// chatResponse mirrors probe-demo's ChatCompletion with only the fields we
// care about. Per-token scores arrive in the top-level Scores map.
type chatResponse struct {
	Usage  chatUsage            `json:"usage"`
	Scores map[string][]float64 `json:"scores"`
}

// Complete posts (system, user) to /v1/chat/completions and returns the
// per-probe per-token scores. Circuit-breaker state is respected via the
// embedded Resilience; when the breaker is open, Complete returns an error
// without hitting the network and callers should inspect IsOpen().
func (c *Client) Complete(ctx context.Context, system, user string) (ClientResponse, error) {
	if err := c.Acquire(ctx, "probes"); err != nil {
		return ClientResponse{}, err
	}
	defer c.Release()

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Stream:        false,
		MaxTokens:     c.maxTokens,
		IncludeScores: true,
	})
	if err != nil {
		return ClientResponse{}, fmt.Errorf("failed to marshal probe request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ClientResponse{}, fmt.Errorf("failed to create probe request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	start := time.Now()
	httpResp, err := c.httpClient.Do(httpReq)
	durationMs := int(time.Since(start).Milliseconds())
	if err != nil {
		c.RecordFailure()
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("probe request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		c.RecordFailure()
		errBody, _ := io.ReadAll(httpResp.Body)
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("probe API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	var parsed chatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&parsed); err != nil {
		c.RecordFailure()
		return ClientResponse{DurationMs: durationMs}, fmt.Errorf("failed to decode probe response: %w", err)
	}

	c.RecordSuccess()
	return ClientResponse{
		Scores:       parsed.Scores,
		DurationMs:   durationMs,
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}, nil
}
