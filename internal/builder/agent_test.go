package builder

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// stubReader is a TrafficReader that returns fixed data.
type stubReader struct {
	groups  []PathGroup
	samples []RequestSample
}

func (r *stubReader) AggregatePathGroups(_ string, _, _ time.Time) []PathGroup {
	return r.groups
}
func (r *stubReader) SampleRequestsForPath(_, _, _ string, _, _ time.Time, _ int) []RequestSample {
	return r.samples
}


func TestPolicyAgent_NoTools_ReturnsTextDirectly(t *testing.T) {
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "Your policy looks fine.", StopReason: "end_turn"}, nil
	}}
	agent := NewPolicyAgent(&stubReader{}, nil, thinking)

	result, err := agent.Run(context.Background(), "", "allow all", nil, nil, nil, "Is this policy ok?", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Message != "Your policy looks fine." {
		t.Errorf("message = %q", result.Message)
	}
	if result.PolicyUpdated {
		t.Error("policy should not be updated")
	}
}

func TestPolicyAgent_UpdatePolicy_Tool(t *testing.T) {
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{
				"policy_prompt":     "Allow read-only access.",
				"static_rules": []map[string]interface{}{{"url_pattern": "https://api.example.com/", "methods": []string{"GET"}, "match_type": "prefix"}},
			})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls: []llm.ToolCall{{ID: "call1", Name: "update_policy", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Policy updated.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "Set a read-only policy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.PolicyUpdated {
		t.Error("expected PolicyUpdated = true")
	}
	if result.PolicyPrompt != "Allow read-only access." {
		t.Errorf("prompt = %q", result.PolicyPrompt)
	}
	if len(result.StaticRules) != 1 {
		t.Errorf("expected 1 static rule, got %d", len(result.StaticRules))
	}
}

func TestPolicyAgent_AnalyzeTraffic_Tool(t *testing.T) {
	reader := &stubReader{
		groups: []PathGroup{
			{Method: "GET", PathPattern: "/v1/apps/{id}", Count: 50},
		},
		samples: []RequestSample{{URL: "https://api.example.com/v1/apps/123"}},
	}
	fast := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "Fetches an application by ID."}, nil
	}}

	var toolResultContent string
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]string{
				"user_id":    "alice",
				"start_date": "2024-01-01T00:00:00Z",
				"end_date":   "2024-03-31T00:00:00Z",
			})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: input}},
			}, nil
		}
		// Capture the tool result message to verify it contains the summary.
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				toolResultContent = msg.ToolResult.Content
			}
		}
		return llm.Response{Text: "Analysis complete.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(reader, fast, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "Analyze alice's traffic for Q1 2024", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(toolResultContent, "/v1/apps/{id}") {
		t.Errorf("tool result missing endpoint pattern; got: %q", toolResultContent)
	}
	if len(result.NewSummaries) != 1 {
		t.Errorf("expected 1 new summary, got %d", len(result.NewSummaries))
	}
	if result.Message != "Analysis complete." {
		t.Errorf("message = %q", result.Message)
	}
}

func TestPolicyAgent_MultiTool_AccumulatesSummaries(t *testing.T) {
	reader := &stubReader{
		groups:  []PathGroup{{Method: "POST", PathPattern: "/v1/jobs", Count: 10}},
		samples: []RequestSample{},
	}
	fast := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "Creates a job."}, nil
	}}

	existing := []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/apps/{id}", Count: 50, Description: "Fetches an app."},
	}

	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		switch callN {
		case 1:
			input, _ := json.Marshal(map[string]string{"user_id": "bob", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-02-01T00:00:00Z"})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: input}}}, nil
		case 2:
			return llm.Response{Text: "Done.", StopReason: "end_turn"}, nil
		}
		return llm.Response{Text: "Done.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(reader, fast, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, existing, nil, "Analyze bob's traffic", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have existing 1 + new 1 = 2 summaries
	if len(result.NewSummaries) != 2 {
		t.Errorf("expected 2 accumulated summaries, got %d", len(result.NewSummaries))
	}
}

func TestPolicyAgent_ThinkingAdapterError(t *testing.T) {
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{}, errors.New("model unavailable")
	}}
	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	_, err := agent.Run(context.Background(), "", "", nil, nil, nil, "hello", nil)
	if err == nil {
		t.Error("expected error from adapter failure")
	}
}

func TestPolicyAgent_MaxIterationsExceeded(t *testing.T) {
	// Always return a tool call → agent loops until max iterations.
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		input, _ := json.Marshal(map[string]interface{}{
			"policy_prompt": "p", "static_rules": []interface{}{},
		})
		return llm.Response{
			StopReason: "tool_use",
			ToolCalls:  []llm.ToolCall{{ID: "c", Name: "update_policy", Input: input}},
		}, nil
	}}
	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	_, err := agent.Run(context.Background(), "", "", nil, nil, nil, "keep updating", nil)
	if err == nil {
		t.Error("expected max iterations error")
	}
	if !strings.Contains(err.Error(), "maximum iterations") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPolicyAgent_OnEventCalledForTools(t *testing.T) {
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{"policy_prompt": "p", "static_rules": []interface{}{}})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "update_policy", Input: input}}}, nil
		}
		return llm.Response{Text: "done", StopReason: "end_turn"}, nil
	}}

	var events []string
	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	agent.Run(context.Background(), "", "", nil, nil, nil, "update", func(eventType string, _ interface{}) { //nolint:errcheck
		events = append(events, eventType)
	})

	if len(events) < 2 {
		t.Errorf("expected at least tool_start and tool_done events, got %v", events)
	}
	if events[0] != "tool_start" {
		t.Errorf("first event = %q, want tool_start", events[0])
	}
	hasDone := false
	for _, e := range events {
		if e == "tool_done" {
			hasDone = true
			break
		}
	}
	if !hasDone {
		t.Errorf("expected tool_done event, got %v", events)
	}
}

func TestPolicyAgent_UpdateName_Tool(t *testing.T) {
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]string{"name": "Google Calendar Policy"})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_name", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Name updated.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "old name", "", nil, nil, nil, "rename this policy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NewName != "Google Calendar Policy" {
		t.Errorf("NewName = %q, want 'Google Calendar Policy'", result.NewName)
	}
	if result.PolicyUpdated {
		t.Error("PolicyUpdated should be false when only name was changed")
	}
}

func TestPolicyAgent_UpdateName_EmptyName_ReturnsToolError(t *testing.T) {
	callN := 0
	var toolResultIsError bool
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]string{"name": ""})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_name", Input: input}},
			}, nil
		}
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				toolResultIsError = msg.ToolResult.IsError
			}
		}
		return llm.Response{Text: "Handled.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	_, err := agent.Run(context.Background(), "", "", nil, nil, nil, "rename to empty", nil)
	if err != nil {
		t.Fatalf("agent should not fail on tool error: %v", err)
	}
	if !toolResultIsError {
		t.Error("expected tool result to be marked as error for empty name")
	}
}

func TestPolicyAgent_RemoveEndpoints_Tool(t *testing.T) {
	existing := []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/apps/{id}", Count: 100, Description: "Fetches an app."},
		{Method: "GET", PathPattern: "https://registry.npmjs.org/", Count: 50, Description: "NPM registry."},
		{Method: "POST", PathPattern: "/v1/jobs", Count: 20, Description: "Creates a job."},
	}

	callN := 0
	var summariesUpdatedFired bool
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{"patterns": []string{"npmjs.org"}})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "remove_endpoints", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Removed.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, existing, nil, "remove npm endpoints", func(event string, _ interface{}) {
		if event == "summaries_updated" {
			summariesUpdatedFired = true
		}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.NewSummaries) != 2 {
		t.Errorf("expected 2 summaries after removal, got %d", len(result.NewSummaries))
	}
	for _, s := range result.NewSummaries {
		if strings.Contains(strings.ToLower(s.PathPattern), "npmjs") {
			t.Errorf("NPM summary not removed: %s", s.PathPattern)
		}
	}
	if !summariesUpdatedFired {
		t.Error("expected summaries_updated event to fire after remove_endpoints")
	}
}

func TestPolicyAgent_RemoveEndpoints_AllRemoved_EmptySliceNotNil(t *testing.T) {
	existing := []types.PolicyEndpointSummary{
		{Method: "GET", PathPattern: "/v1/items", Count: 5, Description: "Lists items."},
	}

	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{"patterns": []string{"/v1/items"}})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "remove_endpoints", Input: input}},
			}, nil
		}
		return llm.Response{Text: "All removed.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, existing, nil, "remove all", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must be empty slice (not nil) so the API handler persists the cleared state to DB.
	if result.NewSummaries == nil {
		t.Error("NewSummaries should be an empty slice, not nil, so the cleared state is persisted")
	}
	if len(result.NewSummaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(result.NewSummaries))
	}
}

func TestPolicyAgent_AnalyzeTraffic_EmptyGroups(t *testing.T) {
	// Reader returns no groups — tool should return a meaningful message, not error.
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN := 0
		_ = callN
		return llm.Response{}, nil // will be replaced below
	}}
	callN := 0
	var capturedToolResult string
	thinkingReal := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]string{
				"user_id": "nobody", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-02-01T00:00:00Z",
			})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: input}}}, nil
		}
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				capturedToolResult = msg.ToolResult.Content
			}
		}
		return llm.Response{Text: "No traffic found.", StopReason: "end_turn"}, nil
	}}
	_ = thinking

	agent := NewPolicyAgent(&stubReader{groups: nil}, nil, thinkingReal)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "analyze nobody", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedToolResult, "No traffic found") {
		t.Errorf("expected 'No traffic found' in tool result, got: %q", capturedToolResult)
	}
	if len(result.NewSummaries) != 0 {
		t.Errorf("expected 0 summaries for empty traffic, got %d", len(result.NewSummaries))
	}
}

func TestPolicyAgent_AnalyzeTraffic_InvalidDate(t *testing.T) {
	// Agent calls analyze_traffic with a bad date — tool returns error, agent receives it as a tool error result.
	callN := 0
	var toolResultIsError bool
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]string{
				"user_id": "alice", "start_date": "not-a-date", "end_date": "also-not-a-date",
			})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: input}}}, nil
		}
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				toolResultIsError = msg.ToolResult.IsError
			}
		}
		return llm.Response{Text: "Got an error.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	_, err := agent.Run(context.Background(), "", "", nil, nil, nil, "bad dates", nil)
	if err != nil {
		t.Fatalf("unexpected error (agent should handle tool errors gracefully): %v", err)
	}
	if !toolResultIsError {
		t.Error("expected tool result to be marked as error for invalid dates")
	}
}

func TestPolicyAgent_UpdatePolicy_InvalidJSON(t *testing.T) {
	callN := 0
	var toolResultIsError bool
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_policy", Input: json.RawMessage(`{not valid json`)}},
			}, nil
		}
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				toolResultIsError = msg.ToolResult.IsError
			}
		}
		return llm.Response{Text: "Handled error.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	_, err := agent.Run(context.Background(), "", "", nil, nil, nil, "bad input", nil)
	if err != nil {
		t.Fatalf("agent should not fail on tool input error: %v", err)
	}
	if !toolResultIsError {
		t.Error("expected tool result to be marked as error for invalid JSON input")
	}
}

func TestPolicyAgent_SystemPromptContainsPolicyState(t *testing.T) {
	var capturedSystem string
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		capturedSystem = req.System
		return llm.Response{Text: "ok", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	agent.Run(context.Background(), "", //nolint:errcheck
		"Allow read-only access only.",
		[]types.StaticRule{{URLPattern: "https://api.example.com/", MatchType: "prefix"}},
		nil, nil, "refine the policy", nil,
	)

	if !strings.Contains(capturedSystem, "Allow read-only access only.") {
		t.Errorf("system prompt missing current policy prompt; got:\n%s", capturedSystem)
	}
	if !strings.Contains(capturedSystem, "https://api.example.com/") {
		t.Errorf("system prompt missing static rule; got:\n%s", capturedSystem)
	}
}

func TestPolicyAgent_SummariesReachModelViaToolHistory(t *testing.T) {
	// Summaries from a prior analyze_traffic call are no longer injected into the
	// system prompt — they reach the model as tool result messages in history.
	analyzeInput, _ := json.Marshal(map[string]string{
		"user_id": "alice", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-03-31T00:00:00Z",
	})
	history := []ChatMessage{
		{Role: "user", Content: "analyze alice's traffic"},
		{Role: "assistant", ToolCalls: []types.ToolCallRecord{{ID: "c1", Name: "analyze_traffic", Input: analyzeInput}}},
		{Role: "tool", ToolResult: &types.ToolResultRecord{ToolCallID: "c1", Content: "Found 1 endpoint: GET /v1/jobs/{id} (42 calls): Fetches a job by ID."}},
		{Role: "assistant", Content: "I found 1 endpoint."},
	}

	var capturedMessages []llm.Message
	var capturedSystem string
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		capturedMessages = req.Messages
		capturedSystem = req.System
		return llm.Response{Text: "ok", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	agent.Run(context.Background(), "", "", nil, nil, history, "now write the policy", nil) //nolint:errcheck

	// Summary must NOT be in the system prompt.
	if strings.Contains(capturedSystem, "/v1/jobs/{id}") {
		t.Errorf("system prompt should not contain summaries; got:\n%s", capturedSystem)
	}

	// Summary MUST be in the tool result message in history.
	found := false
	for _, msg := range capturedMessages {
		if msg.ToolResult != nil && strings.Contains(msg.ToolResult.Content, "/v1/jobs/{id}") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /v1/jobs/{id} in tool result messages, got: %+v", capturedMessages)
	}
}

func TestPolicyAgent_HistoryPassedToModel(t *testing.T) {
	var capturedMessages []llm.Message
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		capturedMessages = req.Messages
		return llm.Response{Text: "ok", StopReason: "end_turn"}, nil
	}}

	history := []ChatMessage{
		{Role: "user", Content: "What endpoints does alice use?"},
		{Role: "assistant", Content: "Alice primarily calls the Greenhouse API."},
	}
	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	agent.Run(context.Background(), "", "", nil, nil, history, "make it stricter", nil) //nolint:errcheck

	// Expect: history[0], history[1], new user message = 3 messages total
	if len(capturedMessages) != 3 {
		t.Fatalf("expected 3 messages (2 history + 1 new), got %d", len(capturedMessages))
	}
	if capturedMessages[0].Content != "What endpoints does alice use?" {
		t.Errorf("history[0] = %q", capturedMessages[0].Content)
	}
	if capturedMessages[1].Content != "Alice primarily calls the Greenhouse API." {
		t.Errorf("history[1] = %q", capturedMessages[1].Content)
	}
	if capturedMessages[2].Content != "make it stricter" {
		t.Errorf("new message = %q", capturedMessages[2].Content)
	}
}

func TestPolicyAgent_NewMessages_PopulatedWithFullTurn(t *testing.T) {
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{
				"policy_prompt":     "Allow read-only access.",
				"static_rules": []interface{}{},
			})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_policy", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Policy updated.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "set a read-only policy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// NewMessages: user msg, assistant w/ tool call, tool result, final assistant reply.
	if len(result.NewMessages) != 4 {
		t.Fatalf("expected 4 new messages, got %d: %+v", len(result.NewMessages), result.NewMessages)
	}
	if result.NewMessages[0].Role != "user" || result.NewMessages[0].Content != "set a read-only policy" {
		t.Errorf("NewMessages[0] = %+v", result.NewMessages[0])
	}
	if result.NewMessages[1].Role != "assistant" || len(result.NewMessages[1].ToolCalls) != 1 {
		t.Errorf("NewMessages[1] should be assistant with tool call, got %+v", result.NewMessages[1])
	}
	if result.NewMessages[1].ToolCalls[0].Name != "update_policy" {
		t.Errorf("NewMessages[1].ToolCalls[0].Name = %q", result.NewMessages[1].ToolCalls[0].Name)
	}
	if result.NewMessages[2].Role != "tool" || result.NewMessages[2].ToolResult == nil {
		t.Errorf("NewMessages[2] should be tool result, got %+v", result.NewMessages[2])
	}
	if result.NewMessages[2].ToolResult.ToolCallID != "c1" {
		t.Errorf("NewMessages[2].ToolResult.ToolCallID = %q", result.NewMessages[2].ToolResult.ToolCallID)
	}
	if result.NewMessages[3].Role != "assistant" || result.NewMessages[3].Content != "Policy updated." {
		t.Errorf("NewMessages[3] = %+v", result.NewMessages[3])
	}
}

func TestPolicyAgent_ToolCallHistoryReplayedToModel(t *testing.T) {
	// Simulate a second turn where the first turn's tool calls are in history.
	toolInput, _ := json.Marshal(map[string]string{
		"user_id": "alice", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-03-31T00:00:00Z",
	})
	history := []ChatMessage{
		{Role: "user", Content: "analyze alice's traffic"},
		{
			Role:      "assistant",
			ToolCalls: []types.ToolCallRecord{{ID: "c1", Name: "analyze_traffic", Input: toolInput}},
		},
		{
			Role:       "tool",
			ToolResult: &types.ToolResultRecord{ToolCallID: "c1", Content: "Found 2 endpoints.", IsError: false},
		},
		{Role: "assistant", Content: "I found 2 endpoints for Alice."},
	}

	var capturedMessages []llm.Message
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		capturedMessages = req.Messages
		return llm.Response{Text: "ok", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	agent.Run(context.Background(), "", "", nil, nil, history, "now write the policy", nil) //nolint:errcheck

	// Expect 5 messages: 4 history + 1 new user message.
	if len(capturedMessages) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(capturedMessages))
	}
	// The assistant tool-call message must have ToolCalls replayed.
	if len(capturedMessages[1].ToolCalls) != 1 || capturedMessages[1].ToolCalls[0].Name != "analyze_traffic" {
		t.Errorf("capturedMessages[1].ToolCalls not replayed: %+v", capturedMessages[1].ToolCalls)
	}
	// The tool result message must have ToolResult replayed.
	if capturedMessages[2].ToolResult == nil || capturedMessages[2].ToolResult.ToolCallID != "c1" {
		t.Errorf("capturedMessages[2].ToolResult not replayed: %+v", capturedMessages[2].ToolResult)
	}
	if capturedMessages[2].ToolResult.Content != "Found 2 endpoints." {
		t.Errorf("tool result content = %q", capturedMessages[2].ToolResult.Content)
	}
}


func TestPolicyAgent_UpdatePolicy_NilMethodsNormalized(t *testing.T) {
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			// LLM omits methods field entirely — produces null after unmarshal
			input := json.RawMessage(`{"policy_prompt":"p","static_rules":[{"url_pattern":"https://example.com/","match_type":"prefix","action":"allow"}]}`)
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_policy", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Done.", StopReason: "end_turn"}, nil
	}}

	agent := NewPolicyAgent(&stubReader{}, nil, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "create policy", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.StaticRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result.StaticRules))
	}
	if result.StaticRules[0].Methods == nil {
		t.Error("Methods should be normalized to empty slice, not nil")
	}
	b, _ := json.Marshal(result.StaticRules[0].Methods)
	if string(b) != "[]" {
		t.Errorf("Methods should serialize as [], got %s", string(b))
	}
}

func TestPathPrefixFromPattern(t *testing.T) {
	cases := []struct{ pattern, want string }{
		{"/v1/applications/{id}", "/v1/applications/"},
		{"/v1/users/{uuid}/profile", "/v1/users/"},
		{"/v1/items", "/v1/items"},
		{"/{id}", "/"},
	}
	for _, tc := range cases {
		got := PathPrefixFromPattern(tc.pattern)
		if got != tc.want {
			t.Errorf("PathPrefixFromPattern(%q) = %q, want %q", tc.pattern, got, tc.want)
		}
	}
}
