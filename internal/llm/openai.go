package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultOpenAIBaseURL = "https://api.openai.com"

// OpenAIAdapter calls models via the OpenAI Chat Completions API.
type OpenAIAdapter struct {
	httpClient *http.Client
	apiKey     string
	model      string
	baseURL    string
	timeout    time.Duration

	*Resilience
}

// NewOpenAIAdapter creates an OpenAIAdapter for the OpenAI Chat Completions API.
func NewOpenAIAdapter(model, apiKey string, timeout time.Duration, opts ...ResilienceOption) (*OpenAIAdapter, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("openai API key is required")
	}

	return &OpenAIAdapter{
		httpClient: &http.Client{},
		apiKey:     apiKey,
		model:      model,
		baseURL:    defaultOpenAIBaseURL,
		timeout:    timeout,
		Resilience: NewResilience(opts...),
	}, nil
}

// SetBaseURL overrides the OpenAI API base URL (useful for testing).
func (a *OpenAIAdapter) SetBaseURL(url string) { a.baseURL = url }

func (a *OpenAIAdapter) ModelID() string { return a.model }

// Complete sends req to the OpenAI Chat Completions API and returns the model's response.
func (a *OpenAIAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	if err := a.Acquire(ctx, "openai"); err != nil {
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

	body := map[string]interface{}{
		"model":                 a.model,
		"max_completion_tokens": maxTokens,
		"messages":              buildOpenAIMessages(req.System, req.Messages),
	}
	if len(req.Tools) > 0 {
		body["tools"] = buildOpenAITools(req.Tools)
	}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, a.baseURL+"/v1/chat/completions", bytes.NewReader(reqBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

	start := time.Now()
	httpResp, err := a.httpClient.Do(httpReq)
	elapsed := time.Since(start)
	durationMs := int(elapsed.Milliseconds())
	a.RecordJudgeLatency(a.model, elapsed)
	if err != nil {
		a.RecordFailure()
		return Response{DurationMs: durationMs}, fmt.Errorf("openai request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		a.RecordFailure()
		errBody, _ := io.ReadAll(httpResp.Body)
		return Response{DurationMs: durationMs}, fmt.Errorf("openai API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	resp, parseErr := parseOpenAIResponseStream(httpResp.Body)
	if parseErr != nil {
		a.RecordFailure()
		resp.DurationMs = durationMs
		return resp, parseErr
	}

	a.RecordSuccess()
	resp.DurationMs = durationMs
	return resp, nil
}

// --- OpenAI format helpers ---

// buildOpenAIMessages converts generic Messages to OpenAI chat format.
// The system prompt becomes a message with role "system" (or "developer" for
// newer models, but "system" is universally supported).
func buildOpenAIMessages(system string, msgs []Message) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(msgs)+1)

	if system != "" {
		result = append(result, map[string]interface{}{
			"role":    "system",
			"content": system,
		})
	}

	for _, m := range msgs {
		result = append(result, buildOpenAIMessage(m))
	}
	return result
}

// buildOpenAIMessage converts a single generic Message to OpenAI chat format.
func buildOpenAIMessage(m Message) map[string]interface{} {
	// Tool result message.
	if m.ToolResult != nil {
		return map[string]interface{}{
			"role":         "tool",
			"tool_call_id": m.ToolResult.ToolCallID,
			"content":      m.ToolResult.Content,
		}
	}

	// Assistant message with tool calls.
	if len(m.ToolCalls) > 0 {
		toolCalls := make([]map[string]interface{}, len(m.ToolCalls))
		for i, tc := range m.ToolCalls {
			// OpenAI expects function.arguments as a JSON string.
			toolCalls[i] = map[string]interface{}{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]interface{}{
					"name":      tc.Name,
					"arguments": string(tc.Input),
				},
			}
		}
		msg := map[string]interface{}{
			"role":       "assistant",
			"tool_calls": toolCalls,
		}
		if m.Content != "" {
			msg["content"] = m.Content
		}
		return msg
	}

	// Plain text message.
	return map[string]interface{}{
		"role":    m.Role,
		"content": m.Content,
	}
}

// buildOpenAITools converts generic Tool definitions to OpenAI function calling format.
func buildOpenAITools(tools []Tool) []map[string]interface{} {
	result := make([]map[string]interface{}, len(tools))
	for i, t := range tools {
		result[i] = map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.InputSchema,
			},
		}
	}
	return result
}

// mapOpenAIStopReason maps OpenAI finish_reason to the generic stop reason format.
func mapOpenAIStopReason(reason string) string {
	switch reason {
	case "stop":
		return "end_turn"
	case "tool_calls":
		return "tool_use"
	case "length":
		return "max_tokens"
	default:
		return reason
	}
}

// parseOpenAIResponseStream decodes an OpenAI Chat Completions response directly
// from a reader into a generic Response, without buffering the entire body.
func parseOpenAIResponseStream(r io.Reader) (Response, error) {
	type functionCall struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	type openAIToolCall struct {
		ID       string       `json:"id"`
		Type     string       `json:"type"`
		Function functionCall `json:"function"`
	}
	type choiceMessage struct {
		Content   string           `json:"content"`
		ToolCalls []openAIToolCall `json:"tool_calls"`
	}
	type choice struct {
		Message      choiceMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	}
	type usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	}
	type respBody struct {
		Choices []choice `json:"choices"`
		Usage   usage    `json:"usage"`
	}

	var resp respBody
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("failed to parse openai response: %w", err)
	}

	if len(resp.Choices) == 0 {
		return Response{}, fmt.Errorf("empty choices in openai response")
	}

	msg := resp.Choices[0].Message
	text := strings.TrimSpace(msg.Content)

	var toolCalls []ToolCall
	for _, tc := range msg.ToolCalls {
		toolCalls = append(toolCalls, ToolCall{
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(tc.Function.Arguments),
		})
	}

	if text == "" && len(toolCalls) == 0 {
		return Response{}, fmt.Errorf("empty content in openai response")
	}

	return Response{
		Text:         text,
		ToolCalls:    toolCalls,
		StopReason:   mapOpenAIStopReason(resp.Choices[0].FinishReason),
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}, nil
}
