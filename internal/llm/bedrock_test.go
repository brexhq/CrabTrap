package llm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func TestBedrockContextLengthClassification(t *testing.T) {
	// ValidationException with a too-long message -> ErrContextLength.
	ve := newTestAdapter(func(ctx context.Context, in *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		return nil, &bedrocktypes.ValidationException{Message: aws.String("input is too long for requested model")}
	})
	if _, err := ve.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}}); !errors.Is(err, ErrContextLength) {
		t.Errorf("expected ErrContextLength for ValidationException too-long, got %v", err)
	}

	// ThrottlingException (429) mentioning tokens -> NOT ErrContextLength.
	thr := newTestAdapter(func(ctx context.Context, in *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		return nil, &bedrocktypes.ThrottlingException{Message: aws.String("Too many tokens, please retry")}
	})
	_, err := thr.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}})
	if err == nil {
		t.Fatal("expected error for throttling")
	}
	if errors.Is(err, ErrContextLength) {
		t.Errorf("ThrottlingException must not match ErrContextLength: %v", err)
	}
}

// newTestAdapter creates a BedrockAdapter wired to a stub invoker for unit tests.
// It bypasses NewBedrockAdapter (which needs real AWS creds) and builds the struct
// directly, which is acceptable because the struct fields are internal to this package.
func newTestAdapter(fn func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error), opts ...ResilienceOption) *BedrockAdapter {
	a := &BedrockAdapter{
		model:      "test-model",
		timeout:    5 * time.Second,
		invokeFunc: fn,
		Resilience: NewResilience(opts...),
	}
	return a
}

// successBody returns a minimal valid Bedrock response body.
func successBody() []byte {
	resp := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": "ok"},
		},
		"usage":       map[string]int{"input_tokens": 10, "output_tokens": 5},
		"stop_reason": "end_turn",
	}
	b, _ := json.Marshal(resp)
	return b
}

// --- Test: Basic completion ---

func TestBedrockBasicCompletion(t *testing.T) {
	adapter := newTestAdapter(func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		return &bedrockruntime.InvokeModelOutput{Body: successBody()}, nil
	})

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("expected text 'ok', got %q", resp.Text)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason 'end_turn', got %q", resp.StopReason)
	}
	if resp.InputTokens != 10 {
		t.Errorf("expected 10 input tokens, got %d", resp.InputTokens)
	}
	if resp.OutputTokens != 5 {
		t.Errorf("expected 5 output tokens, got %d", resp.OutputTokens)
	}
}

// --- Test: Tool use response ---

func TestBedrockToolUseResponse(t *testing.T) {
	respBytes, _ := json.Marshal(map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type":  "tool_use",
				"id":    "call_123",
				"name":  "get_weather",
				"input": map[string]string{"city": "SF"},
			},
		},
		"usage":       map[string]int{"input_tokens": 20, "output_tokens": 10},
		"stop_reason": "tool_use",
	})

	adapter := newTestAdapter(func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		return &bedrockruntime.InvokeModelOutput{Body: respBytes}, nil
	})

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "weather?"}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "Get weather",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}}}`),
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
	if resp.ToolCalls[0].Name != "get_weather" {
		t.Errorf("expected tool name 'get_weather', got %q", resp.ToolCalls[0].Name)
	}
}

// --- Test: Request body includes system prompt caching ---

func TestBedrockSystemPromptCaching(t *testing.T) {
	var capturedBody map[string]interface{}

	adapter := newTestAdapter(func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		json.Unmarshal(input.Body, &capturedBody)
		return &bedrockruntime.InvokeModelOutput{Body: successBody()}, nil
	})

	_, err := adapter.Complete(context.Background(), Request{
		System:            "You are helpful.",
		Messages:          []Message{{Role: "user", Content: "hi"}},
		CacheSystemPrompt: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// System should be an array with cache_control, not a plain string.
	sysVal, ok := capturedBody["system"]
	if !ok {
		t.Fatal("expected 'system' in request body")
	}
	sysArr, ok := sysVal.([]interface{})
	if !ok {
		t.Fatalf("expected system to be array, got %T", sysVal)
	}
	if len(sysArr) != 1 {
		t.Fatalf("expected 1 system block, got %d", len(sysArr))
	}
	block := sysArr[0].(map[string]interface{})
	if block["type"] != "text" {
		t.Errorf("expected type 'text', got %v", block["type"])
	}
	if block["text"] != "You are helpful." {
		t.Errorf("expected system text, got %v", block["text"])
	}
	cc, ok := block["cache_control"].(map[string]interface{})
	if !ok {
		t.Fatal("expected cache_control block")
	}
	if cc["type"] != "ephemeral" {
		t.Errorf("expected cache_control type 'ephemeral', got %v", cc["type"])
	}
}

// --- Test: Empty response is an error ---

func TestBedrockEmptyResponseError(t *testing.T) {
	emptyResp, _ := json.Marshal(map[string]interface{}{
		"content":     []map[string]interface{}{},
		"usage":       map[string]int{"input_tokens": 0, "output_tokens": 0},
		"stop_reason": "end_turn",
	})

	adapter := newTestAdapter(func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		return &bedrockruntime.InvokeModelOutput{Body: emptyResp}, nil
	})

	_, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

// --- Test: DurationMs is set even on error ---

func TestBedrockDurationMsOnError(t *testing.T) {
	adapter := newTestAdapter(func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
		time.Sleep(10 * time.Millisecond)
		return nil, context.DeadlineExceeded
	})

	resp, err := adapter.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if resp.DurationMs == 0 {
		t.Error("expected DurationMs > 0 on error")
	}
}
