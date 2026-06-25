package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOpenAIContextLengthClassification(t *testing.T) {
	// 400 context_length_exceeded -> ErrContextLength.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"This model's maximum context length is 128000 tokens, however you requested 200000.","type":"invalid_request_error","code":"context_length_exceeded"}}`))
	}))
	defer srv.Close()
	a := newTestOpenAIAdapter(t, "gpt-4o", "test-key", srv.URL)
	if _, err := a.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}}); !errors.Is(err, ErrContextLength) {
		t.Errorf("expected ErrContextLength for context_length_exceeded, got %v", err)
	}

	// 429 rate-limit mentioning tokens -> NOT ErrContextLength.
	srv429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"message":"Rate limit reached: 30000 tokens per min.","type":"tokens","code":"rate_limit_exceeded"}}`))
	}))
	defer srv429.Close()
	a2 := newTestOpenAIAdapter(t, "gpt-4o", "test-key", srv429.URL)
	_, err := a2.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}})
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if errors.Is(err, ErrContextLength) {
		t.Errorf("429 rate-limit must not match ErrContextLength: %v", err)
	}
}

func openAISuccessResponse() []byte {
	resp := map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": "Hello from OpenAI!",
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     20,
			"completion_tokens": 10,
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// newTestOpenAIAdapter creates an OpenAIAdapter pointed at a test server.
func newTestOpenAIAdapter(t *testing.T, model, apiKey string, serverURL string) *OpenAIAdapter {
	t.Helper()
	adapter, err := NewOpenAIAdapter(model, apiKey, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	adapter.SetBaseURL(serverURL)
	return adapter
}

// --- Test: Basic completion ---

func TestOpenAIBasicCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAISuccessResponse())
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "Hello from OpenAI!" {
		t.Errorf("expected text 'Hello from OpenAI!', got %q", resp.Text)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", resp.StopReason)
	}
	if resp.InputTokens != 20 {
		t.Errorf("expected 20 input tokens, got %d", resp.InputTokens)
	}
	if resp.OutputTokens != 10 {
		t.Errorf("expected 10 output tokens, got %d", resp.OutputTokens)
	}
}

// --- Test: Auth header ---

func TestOpenAIAuthHeader(t *testing.T) {
	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAISuccessResponse())
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "sk-test-key-456", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := capturedHeaders.Get("Authorization"); got != "Bearer sk-test-key-456" {
		t.Errorf("expected Authorization 'Bearer sk-test-key-456', got %q", got)
	}
	if got := capturedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", got)
	}
}

// --- Test: Request body structure ---

func TestOpenAIRequestBody(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAISuccessResponse())
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		System:   "You are helpful.",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify model.
	if model, ok := capturedBody["model"].(string); !ok || model != "gpt-4o" {
		t.Errorf("expected model 'gpt-4o', got %v", capturedBody["model"])
	}

	// Verify system prompt is a message, not a top-level field.
	msgs := capturedBody["messages"].([]interface{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(msgs))
	}
	sysMsg := msgs[0].(map[string]interface{})
	if sysMsg["role"] != "system" {
		t.Errorf("expected first message role 'system', got %v", sysMsg["role"])
	}
	if sysMsg["content"] != "You are helpful." {
		t.Errorf("expected system content 'You are helpful.', got %v", sysMsg["content"])
	}
}

// --- Test: Tool use round-trip ---

func TestOpenAIToolUse(t *testing.T) {
	toolResp, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"role":    "assistant",
					"content": nil,
					"tool_calls": []map[string]interface{}{
						{
							"id":   "call_abc123",
							"type": "function",
							"function": map[string]interface{}{
								"name":      "get_weather",
								"arguments": `{"city":"SF"}`,
							},
						},
					},
				},
				"finish_reason": "tool_calls",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     30,
			"completion_tokens": 15,
		},
	})

	var capturedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(toolResp)
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "weather in SF?"}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "Get weather for a city",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}}}`),
		}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify response.
	if resp.StopReason != "tool_use" {
		t.Errorf("expected stop_reason 'tool_use', got %q", resp.StopReason)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
	tc := resp.ToolCalls[0]
	if tc.ID != "call_abc123" {
		t.Errorf("expected tool call ID 'call_abc123', got %q", tc.ID)
	}
	if tc.Name != "get_weather" {
		t.Errorf("expected tool name 'get_weather', got %q", tc.Name)
	}

	// Verify the tool input can be unmarshaled.
	var input map[string]string
	if err := json.Unmarshal(tc.Input, &input); err != nil {
		t.Fatalf("failed to unmarshal tool input: %v", err)
	}
	if input["city"] != "SF" {
		t.Errorf("expected city 'SF', got %q", input["city"])
	}

	// Verify request body tools format.
	reqTools := capturedBody["tools"].([]interface{})
	if len(reqTools) != 1 {
		t.Fatalf("expected 1 tool in request, got %d", len(reqTools))
	}
	toolDef := reqTools[0].(map[string]interface{})
	if toolDef["type"] != "function" {
		t.Errorf("expected tool type 'function', got %v", toolDef["type"])
	}
	fn := toolDef["function"].(map[string]interface{})
	if fn["name"] != "get_weather" {
		t.Errorf("expected function name 'get_weather', got %v", fn["name"])
	}
}

// --- Test: Tool result message format ---

func TestOpenAIToolResultMessage(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAISuccessResponse())
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{
			{Role: "user", Content: "weather?"},
			{
				Role: "assistant",
				ToolCalls: []ToolCall{{
					ID:    "call_123",
					Name:  "get_weather",
					Input: json.RawMessage(`{"city":"NYC"}`),
				}},
			},
			{
				Role: "tool",
				ToolResult: &ToolResult{
					ToolCallID: "call_123",
					Content:    "72°F and sunny",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := capturedBody["messages"].([]interface{})
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	// Check assistant message with tool calls.
	assistantMsg := msgs[1].(map[string]interface{})
	if assistantMsg["role"] != "assistant" {
		t.Errorf("expected role 'assistant', got %v", assistantMsg["role"])
	}
	toolCallsArr := assistantMsg["tool_calls"].([]interface{})
	if len(toolCallsArr) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(toolCallsArr))
	}

	// Check tool result message.
	toolMsg := msgs[2].(map[string]interface{})
	if toolMsg["role"] != "tool" {
		t.Errorf("expected role 'tool', got %v", toolMsg["role"])
	}
	if toolMsg["tool_call_id"] != "call_123" {
		t.Errorf("expected tool_call_id 'call_123', got %v", toolMsg["tool_call_id"])
	}
	if toolMsg["content"] != "72°F and sunny" {
		t.Errorf("expected content '72°F and sunny', got %v", toolMsg["content"])
	}
}

// --- Test: Stop reason mapping ---

func TestOpenAIStopReasonMapping(t *testing.T) {
	tests := []struct {
		openAI   string
		expected string
	}{
		{"stop", "end_turn"},
		{"tool_calls", "tool_use"},
		{"length", "max_tokens"},
		{"content_filter", "content_filter"}, // unknown reasons pass through
	}

	for _, tt := range tests {
		t.Run(tt.openAI, func(t *testing.T) {
			got := mapOpenAIStopReason(tt.openAI)
			if got != tt.expected {
				t.Errorf("mapOpenAIStopReason(%q) = %q, want %q", tt.openAI, got, tt.expected)
			}
		})
	}
}

// --- Test: API error response ---

func TestOpenAIAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}`))
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
}

// --- Test: Empty choices ---

func TestOpenAIEmptyChoices(t *testing.T) {
	emptyResp, _ := json.Marshal(map[string]interface{}{
		"choices": []map[string]interface{}{},
		"usage":   map[string]int{"prompt_tokens": 0, "completion_tokens": 0},
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(emptyResp)
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
}

// --- Test: Missing API key ---

func TestOpenAIMissingAPIKey(t *testing.T) {
	_, err := NewOpenAIAdapter("gpt-4o", "", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
}

// --- Test: ModelID ---

func TestOpenAIModelID(t *testing.T) {
	adapter, err := NewOpenAIAdapter("gpt-4o", "test-key", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	if got := adapter.ModelID(); got != "gpt-4o" {
		t.Errorf("expected model ID 'gpt-4o', got %q", got)
	}
}

// --- Test: No system prompt ---

func TestOpenAINoSystemPrompt(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAISuccessResponse())
	}))
	defer server.Close()

	adapter := newTestOpenAIAdapter(t, "gpt-4o", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs := capturedBody["messages"].([]interface{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (no system), got %d", len(msgs))
	}
	if msgs[0].(map[string]interface{})["role"] != "user" {
		t.Errorf("expected first message role 'user', got %v", msgs[0].(map[string]interface{})["role"])
	}
}
