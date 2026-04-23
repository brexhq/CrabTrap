package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const maxAgentIterations = 10
const agentConcurrency = 10

// ---- Types ----

// PathGroup is a normalized path pattern with its total request count.
type PathGroup struct {
	Method      string
	PathPattern string
	Count       int
}

// RequestSample is a single raw request captured from the audit log.
type RequestSample struct {
	URL  string
	Body string
}

// EndpointSummary is the fast-model description of one endpoint group.
type EndpointSummary struct {
	Method      string
	PathPattern string
	Count       int
	Description string
}

// ChatMessage is an alias kept for backward compatibility within this package.
type ChatMessage = types.ChatMessage

// TrafficReader fetches observed traffic for use by the analyze_traffic tool.
// Implemented by *admin.PGAuditReader.
type TrafficReader interface {
	AggregatePathGroups(userID string, start, end time.Time) []PathGroup
	SampleRequestsForPath(userID, method, pathPrefix string, start, end time.Time, limit int) []RequestSample
}

// AgentResult is the outcome of a PolicyAgent.Run call.
type AgentResult struct {
	Message          string                        // final text response to show the user
	PolicyUpdated    bool                          // true if update_policy was called
	PolicyPrompt     string                        // latest prompt (whether or not updated)
	StaticRules      []types.StaticRule            // latest rules (whether or not updated)
	NewSummaries     []types.PolicyEndpointSummary // accumulated from all analyze_traffic calls
	NewName          string                        // set when update_name was called
	NewMessages      []ChatMessage                 // all messages from this turn (user msg + tool calls/results + final reply)
}

// ---- PolicyAgent ----

// PolicyAgent runs an agentic loop for interactive policy authoring.
// Tools: analyze_traffic (uses fastAdapter to summarise endpoints) and update_policy.
type PolicyAgent struct {
	reader          TrafficReader
	fastAdapter     llm.Adapter // Haiku — per-endpoint summarisation inside analyze_traffic
	thinkingAdapter llm.Adapter // main model — drives the agent loop
}

// NewPolicyAgent creates a PolicyAgent.
func NewPolicyAgent(reader TrafficReader, fast, thinking llm.Adapter) *PolicyAgent {
	return &PolicyAgent{reader: reader, fastAdapter: fast, thinkingAdapter: thinking}
}

// Run executes the agent loop for one conversation turn.
// existingSummaries are endpoint summaries already stored in the draft's metadata
// (from previous analyze_traffic calls) and are injected into the system prompt.
// onEvent is called for each tool invocation so callers can stream progress; it may be nil.
func (a *PolicyAgent) Run(
	ctx context.Context,
	currentName string,
	currentPrompt string,
	currentRules []types.StaticRule,
	existingSummaries []types.PolicyEndpointSummary,
	history []ChatMessage,
	userMessage string,
	onEvent func(eventType string, data interface{}),
) (AgentResult, error) {
	state := &agentState{
		currentName:   currentName,
		currentPrompt: currentPrompt,
		currentRules:  currentRules,
		summaries:     existingSummaries,
	}

	systemPrompt := buildAgentSystemPrompt(state)
	messages := buildAgentMessages(history, userMessage)
	userMsgIdx := len(messages) - 1 // index of the new user message; everything from here is new

	notify := func(t string, d interface{}) {
		if onEvent != nil {
			onEvent(t, d)
		}
	}

	for i := 0; i < maxAgentIterations; i++ {
		resp, err := a.thinkingAdapter.Complete(ctx, llm.Request{
			System:    systemPrompt,
			Messages:  messages,
			Tools:     agentTools,
			MaxTokens: 4096,
		})
		if err != nil {
			return AgentResult{}, fmt.Errorf("agent call failed: %w", err)
		}

		if resp.StopReason == "end_turn" || len(resp.ToolCalls) == 0 {
			newMsgs := collectNewMessages(messages, userMsgIdx, resp.Text)
			return AgentResult{
				Message:          resp.Text,
				PolicyUpdated:    state.policyUpdated,
				PolicyPrompt:     state.currentPrompt,
				StaticRules:   state.currentRules,
				NewSummaries:     state.summaries,
				NewName:          state.currentName,
				NewMessages:      newMsgs,
			}, nil
		}

		messages = append(messages, llm.Message{
			Role:      "assistant",
			Content:   resp.Text,
			ToolCalls: resp.ToolCalls,
		})

		for _, call := range resp.ToolCalls {
			notify("tool_start", map[string]interface{}{"tool": call.Name, "input": call.Input})

			result, toolErr := a.executeTool(ctx, call, state, notify)
			isError := toolErr != nil
			content := result
			if toolErr != nil {
				content = "Error: " + toolErr.Error()
			}

			notify("tool_done", map[string]interface{}{"tool": call.Name, "result": content})

			if toolErr == nil {
				switch call.Name {
				case "update_policy":
					notify("policy_updated", map[string]interface{}{
						"policy_prompt":    state.currentPrompt,
						"static_rules":  state.currentRules,
					})
				case "update_name":
					notify("name_updated", map[string]interface{}{"name": state.currentName})
				}
			}

			messages = append(messages, llm.Message{
				Role: "tool",
				ToolResult: &llm.ToolResult{
					ToolCallID: call.ID,
					Content:    content,
					IsError:    isError,
				},
			})
		}
	}

	return AgentResult{}, fmt.Errorf("agent exceeded maximum iterations (%d)", maxAgentIterations)
}

type agentState struct {
	currentName   string
	currentPrompt string
	currentRules  []types.StaticRule
	summaries     []types.PolicyEndpointSummary
	policyUpdated bool
}

func (a *PolicyAgent) executeTool(ctx context.Context, call llm.ToolCall, state *agentState, notify func(string, interface{})) (string, error) {
	switch call.Name {
	case "analyze_traffic":
		return a.toolAnalyzeTraffic(ctx, call.Input, state, notify)
	case "remove_endpoints":
		return a.toolRemoveEndpoints(call.Input, state, notify)
	case "update_policy":
		return a.toolUpdatePolicy(call.Input, state)
	case "update_name":
		return a.toolUpdateName(call.Input, state)
	default:
		return "", fmt.Errorf("unknown tool: %s", call.Name)
	}
}

func (a *PolicyAgent) toolAnalyzeTraffic(ctx context.Context, input json.RawMessage, state *agentState, notify func(string, interface{})) (string, error) {
	var params struct {
		UserID    string `json:"user_id"`
		StartDate string `json:"start_date"`
		EndDate   string `json:"end_date"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid analyze_traffic input: %w", err)
	}

	start, err := time.Parse(time.RFC3339, params.StartDate)
	if err != nil {
		return "", fmt.Errorf("invalid start_date: %w", err)
	}
	end, err := time.Parse(time.RFC3339, params.EndDate)
	if err != nil {
		return "", fmt.Errorf("invalid end_date: %w", err)
	}

	groups := a.reader.AggregatePathGroups(params.UserID, start, end)
	if len(groups) == 0 {
		return "No traffic found for this user in the specified date range.", nil
	}

	type indexed struct {
		idx int
		sum EndpointSummary
	}
	results := make([]EndpointSummary, len(groups))
	ch := make(chan indexed, len(groups))
	sem := make(chan struct{}, agentConcurrency)

	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Add(1)
		go func(idx int, group PathGroup) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			samples := a.reader.SampleRequestsForPath(params.UserID, group.Method, PathPrefixFromPattern(group.PathPattern), start, end, 200)
			desc := summarizeEndpoint(ctx, a.fastAdapter, group.Method, group.PathPattern, group.Count, samples)
			ch <- indexed{idx, EndpointSummary{Method: group.Method, PathPattern: group.PathPattern, Count: group.Count, Description: desc}}
		}(i, g)
	}
	go func() { wg.Wait(); close(ch) }()

	completed := 0
	for r := range ch {
		results[r.idx] = r.sum
		completed++
		notify("tool_progress", map[string]interface{}{
			"message":   fmt.Sprintf("Summarized %s %s (%d/%d)", r.sum.Method, r.sum.PathPattern, completed, len(groups)),
			"completed": completed,
			"total":     len(groups),
		})
	}

	for _, s := range results {
		state.summaries = append(state.summaries, types.PolicyEndpointSummary{
			Method:      s.Method,
			PathPattern: s.PathPattern,
			Count:       s.Count,
			Description: s.Description,
		})
	}

	notify("summaries_updated", state.summaries)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d distinct endpoint patterns:\n", len(results)))
	for _, s := range results {
		sb.WriteString(fmt.Sprintf("- %s %s (%d calls): %s\n", s.Method, s.PathPattern, s.Count, s.Description))
	}
	return sb.String(), nil
}

func (a *PolicyAgent) toolRemoveEndpoints(input json.RawMessage, state *agentState, notify func(string, interface{})) (string, error) {
	var params struct {
		Patterns []string `json:"patterns"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid remove_endpoints input: %w", err)
	}

	before := len(state.summaries)
	kept := state.summaries[:0]
	for _, s := range state.summaries {
		key := strings.ToLower(s.Method + " " + s.PathPattern)
		matched := false
		for _, p := range params.Patterns {
			if strings.Contains(key, strings.ToLower(p)) {
				matched = true
				break
			}
		}
		if !matched {
			kept = append(kept, s)
		}
	}
	state.summaries = kept

	notify("summaries_updated", state.summaries)

	removed := before - len(state.summaries)
	return fmt.Sprintf("Removed %d endpoint patterns. %d remain.", removed, len(state.summaries)), nil
}

func (a *PolicyAgent) toolUpdateName(input json.RawMessage, state *agentState) (string, error) {
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid update_name input: %w", err)
	}
	if params.Name == "" {
		return "", fmt.Errorf("name must not be empty")
	}
	state.currentName = params.Name
	return fmt.Sprintf("Policy name updated to %q.", params.Name), nil
}

func (a *PolicyAgent) toolUpdatePolicy(input json.RawMessage, state *agentState) (string, error) {
	var params struct {
		PolicyPrompt string             `json:"policy_prompt"`
		StaticRules  []types.StaticRule `json:"static_rules"`
	}
	if err := json.Unmarshal(input, &params); err != nil {
		return "", fmt.Errorf("invalid update_policy input: %w", err)
	}
	if params.StaticRules == nil {
		params.StaticRules = []types.StaticRule{}
	}
	types.NormalizeStaticRules(params.StaticRules)
	state.currentPrompt = params.PolicyPrompt
	state.currentRules = params.StaticRules
	state.policyUpdated = true
	return "Policy updated successfully.", nil
}

// summarizeEndpoint calls the fast adapter for one endpoint group.
// Returns a fallback description on error so the pipeline continues.
func summarizeEndpoint(ctx context.Context, fast llm.Adapter, method, pathPattern string, count int, samples []RequestSample) string {
	var sb strings.Builder
	for _, s := range samples {
		sb.WriteString("URL: ")
		sb.WriteString(s.URL)
		if s.Body != "" {
			sb.WriteString("\nBody: ")
			sb.WriteString(s.Body)
		}
		sb.WriteString("\n---\n")
	}

	resp, err := fast.Complete(ctx, llm.Request{
		System: "You are analyzing HTTP traffic for an AI agent.",
		Messages: []llm.Message{{
			Role: "user",
			Content: fmt.Sprintf(
				"Below are up to 200 real requests to the endpoint %s %s.\n"+
					"Each entry shows the full URL (including query params) and request body.\n\n"+
					"Respond in this exact markdown format (no other text):\n"+
					"**Summary:** one sentence describing what this endpoint does.\n\n"+
					"**Query params:** bullet list of observed params and their value types, or \"none\".\n\n"+
					"**Request body:** bullet list of observed body fields, or \"none\".\n\n"+
					"Requests:\n%s",
				method, pathPattern, sb.String(),
			),
		}},
		MaxTokens: 256,
	})
	if err != nil {
		return fmt.Sprintf("%s %s (%d calls)", method, pathPattern, count)
	}
	return strings.TrimSpace(resp.Text)
}

// ---- Helpers ----

func buildAgentSystemPrompt(state *agentState) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("The current date and time is %s UTC.\n\n", time.Now().UTC().Format("2006-01-02T15:04:05Z")))
	sb.WriteString(`You are a security policy author for an AI agent proxy gateway.
Your job is to create and refine LLM policies that control what HTTP requests an AI agent may make.

Guidelines:
- policy_prompt is the system prompt for an LLM judge that evaluates each request in real-time.
  Write it in the second person ("The agent may only..."). Be specific about allowed domains and operations.
- static_rules bypass the LLM judge entirely and make an immediate allow or deny decision.
  Use action="allow" for safe, idempotent, read-only patterns that need no LLM review
  (e.g. GET /v1/users/{id} on a known safe API).
  Use action="deny" for known-dangerous patterns that should always be blocked regardless of context
  (e.g. DELETE on a critical resource, or any request to a disallowed domain).
  Deny rules take priority: if both an allow and a deny rule match, deny wins.
- Consolidate static allow rules: do not create one rule per endpoint. Instead, group related endpoints
  under a single prefix or glob rule (e.g. one rule for "https://api.example.com/" covers all GET calls
  to that host). Prefer prefix match_type for a base URL over listing individual paths.
  Use glob match_type (e.g. "https://api.example.com/v1/*/read") only when a prefix is too broad.
  The final list should have as few rules as possible while still being accurate.
- When in doubt, require LLM review rather than a static allow rule.
- Always call update_policy after forming your policy — don't just describe it.
- The policy_prompt is only evaluated for requests that do NOT match any static rule.
  Do not mention static-rule endpoints in the policy_prompt — they are already handled automatically.
  The policy_prompt should only describe what the LLM judge should allow or deny for everything else.
- Call analyze_traffic at most once per user/date-range combination. Do not call it multiple times for the same user and period.
- Never call remove_endpoints unless the user explicitly asks you to remove specific endpoints. Every endpoint in the traffic context — including health checks, auth callbacks, and anything that looks like noise — may need to be reflected in static rules or the policy prompt. Removing endpoints without being asked destroys context needed for an accurate policy.
- Respond in plain text. Do not use markdown, headers, bullet points, tables, or code fences in your replies.

`)
	sb.WriteString("Current draft policy:\n")
	if state.currentPrompt != "" {
		sb.WriteString("Prompt: ")
		sb.WriteString(state.currentPrompt)
		sb.WriteString("\n")
	} else {
		sb.WriteString("Prompt: (empty)\n")
	}
	rulesJSON, _ := json.Marshal(state.currentRules)
	sb.WriteString("Static rules: ")
	sb.Write(rulesJSON)
	sb.WriteString("\n")

	return sb.String()
}

func buildAgentMessages(history []ChatMessage, userMessage string) []llm.Message {
	msgs := make([]llm.Message, 0, len(history)+1)
	for _, h := range history {
		msgs = append(msgs, chatMsgToLLM(h))
	}
	msgs = append(msgs, llm.Message{Role: "user", Content: userMessage})
	return msgs
}

// chatMsgToLLM converts a stored ChatMessage back to an llm.Message for replay.
func chatMsgToLLM(h ChatMessage) llm.Message {
	msg := llm.Message{Role: h.Role, Content: h.Content}
	for _, tc := range h.ToolCalls {
		msg.ToolCalls = append(msg.ToolCalls, llm.ToolCall{ID: tc.ID, Name: tc.Name, Input: tc.Input})
	}
	if h.ToolResult != nil {
		msg.ToolResult = &llm.ToolResult{
			ToolCallID: h.ToolResult.ToolCallID,
			Content:    h.ToolResult.Content,
			IsError:    h.ToolResult.IsError,
		}
	}
	return msg
}

// llmMsgToChat converts an llm.Message to a ChatMessage for persistence.
func llmMsgToChat(m llm.Message) ChatMessage {
	cm := ChatMessage{Role: m.Role, Content: m.Content}
	for _, tc := range m.ToolCalls {
		cm.ToolCalls = append(cm.ToolCalls, types.ToolCallRecord{ID: tc.ID, Name: tc.Name, Input: tc.Input})
	}
	if m.ToolResult != nil {
		cm.ToolResult = &types.ToolResultRecord{
			ToolCallID: m.ToolResult.ToolCallID,
			Content:    m.ToolResult.Content,
			IsError:    m.ToolResult.IsError,
		}
	}
	return cm
}

// collectNewMessages assembles the ChatMessages for this turn: the user message,
// all tool-call/result messages from the loop, and the final assistant reply.
func collectNewMessages(messages []llm.Message, userMsgIdx int, finalText string) []ChatMessage {
	newMsgs := make([]ChatMessage, 0, len(messages)-userMsgIdx+1)
	for _, m := range messages[userMsgIdx:] {
		newMsgs = append(newMsgs, llmMsgToChat(m))
	}
	if finalText != "" {
		newMsgs = append(newMsgs, ChatMessage{Role: "assistant", Content: finalText})
	}
	return newMsgs
}

// PathPrefixFromPattern returns the static URL prefix before the first placeholder.
// E.g. "/v1/applications/{id}" → "/v1/applications/".
func PathPrefixFromPattern(pattern string) string {
	idx := strings.Index(pattern, "{")
	if idx < 0 {
		return pattern
	}
	lastSlash := strings.LastIndex(pattern[:idx], "/")
	if lastSlash < 0 {
		return "/"
	}
	return pattern[:lastSlash+1]
}

var agentTools = []llm.Tool{
	{
		Name:        "analyze_traffic",
		Description: "Analyze observed HTTP traffic for a user over a date range to understand what API endpoints the agent accesses. Returns a list of endpoint patterns with call counts and descriptions. Call this before writing a policy.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"user_id":     {"type": "string", "description": "The user ID to analyze traffic for"},
				"start_date":  {"type": "string", "description": "Start of date range in RFC3339 format (e.g. 2024-01-01T00:00:00Z)"},
				"end_date":    {"type": "string", "description": "End of date range in RFC3339 format"}
			},
			"required": ["user_id", "start_date", "end_date"]
		}`),
	},
	{
		Name:        "remove_endpoints",
		Description: "Remove specific endpoint patterns from the traffic analysis context. Only call this when the user explicitly asks to remove specific endpoints by name or pattern. Never call proactively — all endpoints, including health checks and auth, may be needed for an accurate policy.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"patterns": {
					"type": "array",
					"items": {"type": "string"},
					"description": "Substrings to match against 'METHOD path_pattern'. Case-insensitive. Any endpoint containing any pattern is removed."
				}
			},
			"required": ["patterns"]
		}`),
	},
	{
		Name:        "update_name",
		Description: "Update the policy's display name.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name": {"type": "string", "description": "The new display name for the policy."}
			},
			"required": ["name"]
		}`),
	},
	{
		Name:        "update_policy",
		Description: "Apply a new policy prompt and static rules to the draft policy. Always call this after deciding on the policy content.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"policy_prompt": {
					"type": "string",
					"description": "The LLM judge system prompt. Describes what the agent may and may not do."
				},
				"static_rules": {
					"type": "array",
					"description": "Rules for making immediate allow/deny decisions without LLM review.",
					"items": {
						"type": "object",
						"properties": {
							"methods":     {"type": "array", "items": {"type": "string"}, "description": "HTTP methods (empty = all)"},
							"url_pattern": {"type": "string"},
							"match_type":  {"type": "string", "enum": ["prefix", "exact", "glob"]},
							"action":      {"type": "string", "enum": ["allow", "deny"], "description": "allow = auto-approve, deny = auto-block. Defaults to allow."}
						},
						"required": ["url_pattern"]
					}
				}
			},
			"required": ["policy_prompt", "static_rules"]
		}`),
	},
}
