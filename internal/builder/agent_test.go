package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func (r *stubReader) AggregatePathGroups(_ string, _, _ time.Time, hostFilter, pathPrefix string) []PathGroup {
	if hostFilter == "" && pathPrefix == "" {
		return r.groups
	}
	// Honor the filters so pagination/drill-down tests are meaningful. pathPrefix
	// is a literal prefix match, mirroring the reader's starts_with() in SQL.
	var out []PathGroup
	for _, g := range r.groups {
		if hostFilter != "" && hostFromPattern(g.PathPattern) != hostFilter {
			continue
		}
		if pathPrefix != "" && !strings.HasPrefix(pathFromPattern(g.PathPattern), pathPrefix) {
			continue
		}
		out = append(out, g)
	}
	return out
}

// pathFromPattern returns the URL path (with leading slash) from a normalized
// pattern, mirroring how the reader strips scheme+host before the prefix match.
func pathFromPattern(pattern string) string {
	rest := pattern
	if i := strings.Index(pattern, "://"); i >= 0 {
		rest = pattern[i+3:]
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j:]
	}
	return "/"
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
			input, _ := json.Marshal(map[string]interface{}{
				"user_id":    "alice",
				"start_date": "2024-01-01T00:00:00Z",
				"end_date":   "2024-03-31T00:00:00Z",
				"group_by":   "endpoint",
				"summarize":  true,
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

// analyzeViaThinking drives one analyze_traffic call through the agent and
// returns the resulting tool-result content and the final agent result. It
// keeps the cap/limit tests focused on behaviour rather than plumbing.
func analyzeViaThinking(t *testing.T, reader *stubReader, input map[string]interface{}) (string, AgentResult) {
	t.Helper()
	fast := &llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		return llm.Response{Text: "desc"}, nil
	}}
	var toolResultContent string
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			raw, _ := json.Marshal(input)
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: raw}}}, nil
		}
		for _, msg := range req.Messages {
			if msg.ToolResult != nil {
				toolResultContent = msg.ToolResult.Content
			}
		}
		return llm.Response{Text: "done", StopReason: "end_turn"}, nil
	}}
	agent := NewPolicyAgent(reader, fast, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "analyze", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return toolResultContent, result
}

// makeEndpointGroups builds n endpoint groups on a single host, counts descending.
func makeEndpointGroups(host string, n int) []PathGroup {
	groups := make([]PathGroup, n)
	for i := range groups {
		groups[i] = PathGroup{
			Method:      "GET",
			PathPattern: fmt.Sprintf("https://%s/v1/items/%d", host, i),
			Count:       n - i,
		}
	}
	return groups
}

// makeMultiHostGroups builds groups spread across numHosts hosts, perHost each.
// Host h0 has the most traffic, h1 next, etc., so host ordering is deterministic.
func makeMultiHostGroups(numHosts, perHost int) []PathGroup {
	var groups []PathGroup
	for h := 0; h < numHosts; h++ {
		host := fmt.Sprintf("h%d.example.com", h)
		base := (numHosts - h) * 1000 // h0 highest
		for e := 0; e < perHost; e++ {
			groups = append(groups, PathGroup{
				Method:      "GET",
				PathPattern: fmt.Sprintf("https://%s/p%d", host, e),
				Count:       base - e,
			})
		}
	}
	return groups
}

func baseInput(extra map[string]interface{}) map[string]interface{} {
	in := map[string]interface{}{
		"user_id":    "alice",
		"start_date": "2024-01-01T00:00:00Z",
		"end_date":   "2024-03-31T00:00:00Z",
	}
	for k, v := range extra {
		in[k] = v
	}
	return in
}

func TestAnalyzeTraffic_HostMode_DefaultIsBreadthNoSummaries(t *testing.T) {
	// Default (no group_by) is host breadth: lists hosts with counts, runs no
	// fast-model calls, and persists no endpoint summaries.
	reader := &stubReader{groups: makeMultiHostGroups(5, 3)}
	toolResult, result := analyzeViaThinking(t, reader, baseInput(nil))

	if !strings.Contains(toolResult, "5 distinct hosts") {
		t.Errorf("expected host count in result; got: %q", toolResult)
	}
	if !strings.Contains(toolResult, "h0.example.com (") {
		t.Errorf("expected hosts listed with counts; got: %q", toolResult)
	}
	if strings.Contains(toolResult, "/p0") {
		t.Errorf("host mode should not list endpoint paths; got: %q", toolResult)
	}
	if len(result.NewSummaries) != 0 {
		t.Errorf("host mode should persist no summaries, got %d", len(result.NewSummaries))
	}
}

func TestAnalyzeTraffic_EndpointPaginationReportsTotalAndRemaining(t *testing.T) {
	reader := &stubReader{groups: makeEndpointGroups("api.example.com", 30)}
	toolResult, result := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"group_by": "endpoint", "limit": 10,
	}))

	if !strings.Contains(toolResult, "Showing endpoints 1-10 of 30") {
		t.Errorf("expected pagination header; got: %q", toolResult)
	}
	if !strings.Contains(toolResult, "20 more") {
		t.Errorf("expected remaining count; got: %q", toolResult)
	}
	// summarize defaults to false → no summaries, no descriptions.
	if len(result.NewSummaries) != 0 {
		t.Errorf("expected no summaries without summarize=true, got %d", len(result.NewSummaries))
	}
}

func TestAnalyzeTraffic_LimitClampedToMax(t *testing.T) {
	reader := &stubReader{groups: makeEndpointGroups("api.example.com", maxAnalyzeLimit+50)}
	toolResult, _ := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"group_by": "endpoint", "limit": 9999,
	}))
	if !strings.Contains(toolResult, fmt.Sprintf("Showing endpoints 1-%d of %d", maxAnalyzeLimit, maxAnalyzeLimit+50)) {
		t.Errorf("expected limit clamped to %d; got: %q", maxAnalyzeLimit, toolResult)
	}
}

func TestAnalyzeTraffic_CountsOnlyWhenLimitZero(t *testing.T) {
	reader := &stubReader{groups: makeMultiHostGroups(4, 2)}
	toolResult, _ := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"limit": 0,
	}))
	if !strings.Contains(toolResult, "4 distinct hosts") {
		t.Errorf("expected totals reported; got: %q", toolResult)
	}
	if !strings.Contains(toolResult, "counts only") {
		t.Errorf("expected counts-only note; got: %q", toolResult)
	}
	if strings.Contains(toolResult, "- h") {
		t.Errorf("limit=0 should list nothing; got: %q", toolResult)
	}
}

func TestAnalyzeTraffic_HostFilterDrillDownSummarizesOnlyThatHost(t *testing.T) {
	reader := &stubReader{
		groups:  makeMultiHostGroups(3, 4), // 3 hosts × 4 endpoints
		samples: []RequestSample{{URL: "https://h1.example.com/p0"}},
	}
	toolResult, result := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"group_by": "endpoint", "host": "h1.example.com", "summarize": true,
	}))

	if !strings.Contains(toolResult, "4 distinct endpoints") {
		t.Errorf("expected only the filtered host's endpoints; got: %q", toolResult)
	}
	if strings.Contains(toolResult, "h0.example.com") || strings.Contains(toolResult, "h2.example.com") {
		t.Errorf("host filter leaked other hosts; got: %q", toolResult)
	}
	if len(result.NewSummaries) != 4 {
		t.Errorf("expected 4 summaries for the filtered host, got %d", len(result.NewSummaries))
	}
}

func TestAnalyzeTraffic_PathPrefixFilterIsLiteral(t *testing.T) {
	host := "api.example.com"
	reader := &stubReader{groups: []PathGroup{
		{Method: "GET", PathPattern: "https://" + host + "/v1/users/{id}", Count: 12},
		{Method: "GET", PathPattern: "https://" + host + "/v1/users/{id}/roles", Count: 8},
		{Method: "GET", PathPattern: "https://" + host + "/v1/orders/{id}", Count: 5},
		{Method: "GET", PathPattern: "https://" + host + "/v1/user_settings", Count: 3}, // underscore sibling
	}}
	toolResult, _ := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"group_by": "endpoint", "host": host, "path_prefix": "/v1/users/",
	}))
	if !strings.Contains(toolResult, "2 distinct endpoints") {
		t.Errorf("expected only the 2 /v1/users/ endpoints; got: %q", toolResult)
	}
	// Literal prefix (starts_with, not LIKE): the underscore sibling and the
	// orders family must be excluded rather than wildcard-matched.
	if strings.Contains(toolResult, "user_settings") || strings.Contains(toolResult, "/v1/orders/") {
		t.Errorf("path_prefix should match literally; got: %q", toolResult)
	}
}

func TestAnalyzeTraffic_SummarizationBoundedToPage(t *testing.T) {
	// Even with 60 endpoints, summarize must only run over the requested page.
	reader := &stubReader{
		groups:  makeEndpointGroups("api.example.com", 60),
		samples: []RequestSample{{URL: "https://api.example.com/v1/items/0"}},
	}
	_, result := analyzeViaThinking(t, reader, baseInput(map[string]interface{}{
		"group_by": "endpoint", "summarize": true, "limit": 5,
	}))
	if len(result.NewSummaries) != 5 {
		t.Errorf("expected summarization bounded to the 5-row page, got %d", len(result.NewSummaries))
	}
}

func TestAnalyzeTraffic_RecoversFromContextError(t *testing.T) {
	// First thinking call after the tool returns fails with a context-length error;
	// the loop must shrink the oversized tool result and succeed on retry.
	reader := &stubReader{groups: makeEndpointGroups("api.example.com", 30)}
	fast := &llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) { return llm.Response{Text: "d"}, nil }}
	call := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		call++
		switch call {
		case 1:
			in, _ := json.Marshal(baseInput(map[string]interface{}{"group_by": "endpoint", "limit": 30}))
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: in}}}, nil
		case 2:
			// Mirror how an adapter surfaces a context overflow: the provider error
			// wrapping llm.ErrContextLength.
			return llm.Response{}, fmt.Errorf("bedrock invoke failed: %s: %w", "ValidationException: input is too long for requested model", llm.ErrContextLength)
		default:
			return llm.Response{Text: "recovered", StopReason: "end_turn"}, nil
		}
	}}
	agent := NewPolicyAgent(reader, fast, thinking)
	result, err := agent.Run(context.Background(), "", "", nil, nil, nil, "analyze", nil)
	if err != nil {
		t.Fatalf("expected graceful recovery, got error: %v", err)
	}
	if result.Message != "recovered" {
		t.Errorf("expected loop to retry and succeed, got message: %q", result.Message)
	}
}

func TestIsContextLengthError(t *testing.T) {
	// Only errors wrapping llm.ErrContextLength (set by the adapters after a
	// status-code/exception-type gate) count — regardless of message text.
	wrapped := fmt.Errorf("anthropic API error (status 400): prompt is too long: %w", llm.ErrContextLength)
	if !isContextLengthError(wrapped) {
		t.Error("expected wrapped llm.ErrContextLength to be detected")
	}
	if !isContextLengthError(fmt.Errorf("agent call failed: %w", wrapped)) {
		t.Error("expected detection through an extra wrap layer")
	}
	// Crucially, a message that merely *looks* like a context error but does NOT
	// wrap the sentinel must not match — this is what prevents 429 rate-limit
	// errors ("rate_limit_exceeded ... tokens per minute") from being swallowed.
	for _, m := range []string{
		"rate_limit_exceeded: 30000 tokens per minute exceeded",
		"ValidationException: input is too long for requested model", // no sentinel -> not ours
		"model unavailable",
		"connection reset",
	} {
		if isContextLengthError(errors.New(m)) {
			t.Errorf("did not expect context-length error for unwrapped %q", m)
		}
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
			input, _ := json.Marshal(map[string]interface{}{"user_id": "bob", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-02-01T00:00:00Z", "group_by": "endpoint", "summarize": true})
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
