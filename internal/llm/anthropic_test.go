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

func anthropicSuccessResponse() []byte {
	resp := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": "Hello from Anthropic!"},
		},
		"usage":       map[string]int{"input_tokens": 15, "output_tokens": 8},
		"stop_reason": "end_turn",
	}
	b, _ := json.Marshal(resp)
	return b
}

// newTestAnthropicAdapter creates an AnthropicAdapter pointed at a test server.
func newTestAnthropicAdapter(t *testing.T, model, apiKey string, serverURL string) *AnthropicAdapter {
	t.Helper()
	adapter, err := NewAnthropicAdapter(model, apiKey, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	adapter.SetBaseURL(serverURL)
	return adapter
}

// --- Test: Basic completion ---

func TestAnthropicBasicCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(anthropicSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "Hello from Anthropic!" {
		t.Errorf("expected text 'Hello from Anthropic!', got %q", resp.Text)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", resp.StopReason)
	}
	if resp.InputTokens != 15 {
		t.Errorf("expected 15 input tokens, got %d", resp.InputTokens)
	}
	if resp.OutputTokens != 8 {
		t.Errorf("expected 8 output tokens, got %d", resp.OutputTokens)
	}
}

// --- Test: API key header ---

func TestAnthropicAPIKeyHeader(t *testing.T) {
	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write(anthropicSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "sk-ant-test-key-123", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := capturedHeaders.Get("x-api-key"); got != "sk-ant-test-key-123" {
		t.Errorf("expected x-api-key 'sk-ant-test-key-123', got %q", got)
	}
	if got := capturedHeaders.Get("anthropic-version"); got != anthropicAPIVersion {
		t.Errorf("expected anthropic-version %q, got %q", anthropicAPIVersion, got)
	}
	if got := capturedHeaders.Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", got)
	}
}

// --- Test: Request body includes model ---

func TestAnthropicRequestBodyModel(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(anthropicSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-opus-4-20250514", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if model, ok := capturedBody["model"].(string); !ok || model != "claude-opus-4-20250514" {
		t.Errorf("expected model 'claude-opus-4-20250514', got %v", capturedBody["model"])
	}
	// Direct API should NOT have anthropic_version in body (it's in the header).
	if _, ok := capturedBody["anthropic_version"]; ok {
		t.Error("expected no anthropic_version in request body (should be in header)")
	}
}

// --- Test: Tool use round-trip ---

func TestAnthropicToolUse(t *testing.T) {
	toolResp, _ := json.Marshal(map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type":  "tool_use",
				"id":    "toolu_abc123",
				"name":  "search",
				"input": map[string]string{"query": "Go concurrency"},
			},
		},
		"usage":       map[string]int{"input_tokens": 25, "output_tokens": 12},
		"stop_reason": "tool_use",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(toolResp)
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "test-key", server.URL)

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "search for Go concurrency"}},
		Tools: []Tool{{
			Name:        "search",
			Description: "Search the web",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
		}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StopReason != "tool_use" {
		t.Errorf("expected stop_reason 'tool_use', got %q", resp.StopReason)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
	tc := resp.ToolCalls[0]
	if tc.ID != "toolu_abc123" {
		t.Errorf("expected tool call ID 'toolu_abc123', got %q", tc.ID)
	}
	if tc.Name != "search" {
		t.Errorf("expected tool name 'search', got %q", tc.Name)
	}
}

// --- Test: System prompt caching ---

func TestAnthropicSystemPromptCaching(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write(anthropicSuccessResponse())
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		System:            "You are a helpful assistant.",
		Messages:          []Message{{Role: "user", Content: "hi"}},
		CacheSystemPrompt: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sysArr, ok := capturedBody["system"].([]interface{})
	if !ok {
		t.Fatalf("expected system to be array, got %T", capturedBody["system"])
	}
	if len(sysArr) != 1 {
		t.Fatalf("expected 1 system block, got %d", len(sysArr))
	}
	block := sysArr[0].(map[string]interface{})
	if block["type"] != "text" {
		t.Errorf("expected type 'text', got %v", block["type"])
	}
	cc, ok := block["cache_control"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cache_control block")
	}
	if cc["type"] != "ephemeral" {
		t.Errorf("expected cache_control type 'ephemeral', got %v", cc["type"])
	}
}

// --- Test: API error response ---

func TestAnthropicAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}`))
	}))
	defer server.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "test-key", server.URL)

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
	// A 429 rate-limit must not be classified as a context overflow.
	if errors.Is(err, ErrContextLength) {
		t.Errorf("429 rate-limit must not match ErrContextLength: %v", err)
	}
}

func TestAnthropicContextLengthClassification(t *testing.T) {
	// 400 invalid_request_error "prompt is too long" -> ErrContextLength.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum"}}`))
	}))
	defer srv.Close()

	adapter := newTestAnthropicAdapter(t, "claude-sonnet-4-20250514", "test-key", srv.URL)
	_, err := adapter.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}})
	if !errors.Is(err, ErrContextLength) {
		t.Errorf("expected ErrContextLength for 400 prompt-too-long, got %v", err)
	}
}

// --- Test: Missing API key ---

func TestAnthropicMissingAPIKey(t *testing.T) {
	_, err := NewAnthropicAdapter("claude-sonnet-4-20250514", "", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for empty API key")
	}
}

// --- Test: ModelID ---

func TestAnthropicModelID(t *testing.T) {
	adapter, err := NewAnthropicAdapter("claude-opus-4-20250514", "test-key", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	if got := adapter.ModelID(); got != "claude-opus-4-20250514" {
		t.Errorf("expected model ID 'claude-opus-4-20250514', got %q", got)
	}
}
