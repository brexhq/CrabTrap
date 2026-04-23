package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	anthropicAPIVersion     = "2023-06-01"
)

// AnthropicAdapter calls Anthropic models via the direct Messages API.
type AnthropicAdapter struct {
	httpClient *http.Client
	apiKey     string
	model      string
	baseURL    string
	timeout    time.Duration

	*Resilience
}

// NewAnthropicAdapter creates an AnthropicAdapter for the direct Anthropic Messages API.
func NewAnthropicAdapter(model, apiKey string, timeout time.Duration, opts ...ResilienceOption) (*AnthropicAdapter, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("anthropic API key is required")
	}

	return &AnthropicAdapter{
		httpClient: &http.Client{},
		apiKey:     apiKey,
		model:      model,
		baseURL:    defaultAnthropicBaseURL,
		timeout:    timeout,
		Resilience: NewResilience(opts...),
	}, nil
}

// SetBaseURL overrides the Anthropic API base URL (useful for testing).
func (a *AnthropicAdapter) SetBaseURL(url string) { a.baseURL = url }

func (a *AnthropicAdapter) ModelID() string { return a.model }

// Complete sends req to the Anthropic Messages API and returns the model's response.
func (a *AnthropicAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	if err := a.Acquire(ctx, "anthropic"); err != nil {
		return Response{}, err
	}
	defer a.Release()

	timeout := a.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 512
	}

	// Build messages.
	msgs := make([]map[string]interface{}, 0, len(req.Messages))
	for _, m := range req.Messages {
		msg, err := buildAnthropicMessage(m)
		if err != nil {
			return Response{}, fmt.Errorf("build message: %w", err)
		}
		msgs = append(msgs, msg)
	}

	body := map[string]interface{}{
		"model":      a.model,
		"max_tokens": maxTokens,
		"messages":   msgs,
	}
	if req.System != "" {
		if req.CacheSystemPrompt {
			body["system"] = []map[string]interface{}{{
				"type":          "text",
				"text":          req.System,
				"cache_control": map[string]string{"type": "ephemeral"},
			}}
		} else {
			body["system"] = req.System
		}
	}
	if len(req.Tools) > 0 {
		body["tools"] = buildAnthropicTools(req.Tools)
	}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, a.baseURL+"/v1/messages", bytes.NewReader(reqBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	start := time.Now()
	httpResp, err := a.httpClient.Do(httpReq)
	elapsed := time.Since(start)
	durationMs := int(elapsed.Milliseconds())
	a.RecordJudgeLatency(a.model, elapsed)
	if err != nil {
		a.RecordFailure()
		return Response{DurationMs: durationMs}, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		a.RecordFailure()
		errBody, _ := io.ReadAll(httpResp.Body)
		return Response{DurationMs: durationMs}, fmt.Errorf("anthropic API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	resp, parseErr := parseAnthropicResponseStream(httpResp.Body)
	if parseErr != nil {
		a.RecordFailure()
		resp.DurationMs = durationMs
		return resp, parseErr
	}

	a.RecordSuccess()
	resp.DurationMs = durationMs
	return resp, nil
}
