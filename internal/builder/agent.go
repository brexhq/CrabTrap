package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const maxAgentIterations = 10
const agentConcurrency = 10

// analyze_traffic pagination bounds. Every call returns at most maxAnalyzeLimit
// rows regardless of what the agent asks for, so a single call can never explode
// the agent's context window (the failure that otherwise surfaces as a generic
// "network error"). The agent pages through results with limit/offset and drills
// down with the host/path_prefix filters instead of receiving everything at once.
const (
	defaultAnalyzeLimit = 50  // page size when the agent does not specify one
	maxAnalyzeLimit     = 100 // hard ceiling on rows (and, when summarizing, on fast-model calls) per call
)

// maxContextRecoveries bounds how many times the agent loop will shrink an
// oversized tool result and retry after a context-length error before giving up.
const maxContextRecoveries = 4

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

// hostGroup is the request volume and distinct-endpoint count for one host,
// derived from the path groups. Used by analyze_traffic's group_by="host" mode
// to give the agent the breadth of egress destinations cheaply (no fast-model
// calls), which is the natural starting point for authoring a per-domain policy.
type hostGroup struct {
	host          string
	count         int // total requests to this host
	endpointCount int // distinct (method, path pattern) groups on this host
}

// ChatMessage is an alias kept for backward compatibility within this package.
type ChatMessage = types.ChatMessage

// TrafficReader fetches observed traffic for use by the analyze_traffic tool.
// Implemented by *admin.PGAuditReader.
type TrafficReader interface {
	// AggregatePathGroups returns every normalized (method, path pattern) group for
	// the user in the window, sorted by request count descending. hostFilter and
	// pathPrefix optionally narrow the scan: hostFilter matches a host exactly,
	// pathPrefix matches the start of the URL path. Empty strings mean no filter.
	AggregatePathGroups(userID string, start, end time.Time, hostFilter, pathPrefix string) []PathGroup
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
		resp, err := a.completeWithContextRecovery(ctx, systemPrompt, messages, notify)
		if err != nil {
			// A context-length error that recovery could not resolve is reported back
			// to the user as guidance rather than a fatal error, and the turn's
			// (now-compacted) messages are preserved so the conversation can continue.
			if isContextLengthError(err) {
				msg := "I gathered more traffic detail than fits in my working context. " +
					"Please narrow the request — use a shorter date range, focus on a specific " +
					"domain (group_by=\"endpoint\" with a host filter), or ask for a high-level " +
					"breakdown first (group_by=\"host\") — and I'll continue from there."
				return AgentResult{
					Message:       msg,
					PolicyUpdated: state.policyUpdated,
					PolicyPrompt:  state.currentPrompt,
					StaticRules:   state.currentRules,
					NewSummaries:  state.summaries,
					NewName:       state.currentName,
					NewMessages:   collectNewMessages(messages, userMsgIdx, msg),
				}, nil
			}
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

// completeWithContextRecovery calls the thinking model and, if it fails because
// the request exceeded the model's context window, shrinks the single largest
// tool result in the conversation to a short notice and retries — up to
// maxContextRecoveries times. The tool result is mutated in place (via its
// pointer), so the compaction also persists into the messages the caller keeps.
// Non-context errors, and context errors with nothing left to shrink, are
// returned unchanged for the caller to handle.
func (a *PolicyAgent) completeWithContextRecovery(
	ctx context.Context, system string, messages []llm.Message, notify func(string, interface{}),
) (llm.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := a.thinkingAdapter.Complete(ctx, llm.Request{
			System:    system,
			Messages:  messages,
			Tools:     agentTools,
			MaxTokens: 4096,
		})
		if err == nil {
			return resp, nil
		}
		if !isContextLengthError(err) || attempt >= maxContextRecoveries {
			return llm.Response{}, err
		}
		if !compactLargestToolResult(messages) {
			return llm.Response{}, err // nothing left to shrink
		}
		notify("context_recovery", map[string]interface{}{
			"message": "Previous tool output exceeded the context window; discarded it and retrying.",
			"attempt": attempt + 1,
		})
	}
}

// compactedResultNotice prefixes a tool result whose content we discarded to fit
// the context window. The agent sees this in place of the original output.
const compactedResultNotice = "[Tool output discarded: it was too large for the context window.]"

// compactLargestToolResult replaces the content of the largest not-yet-compacted
// tool result with a short notice and marks it as an error, so the model knows
// the data is gone and can re-request it more narrowly. Returns false when there
// is no further tool result worth shrinking.
func compactLargestToolResult(messages []llm.Message) bool {
	idx, maxLen := -1, 0
	for i := range messages {
		tr := messages[i].ToolResult
		if tr == nil || strings.HasPrefix(tr.Content, compactedResultNotice) {
			continue
		}
		if len(tr.Content) > maxLen {
			idx, maxLen = i, len(tr.Content)
		}
	}
	// Only bother if the candidate is large enough that shrinking it could matter.
	if idx < 0 || maxLen < 1000 {
		return false
	}
	messages[idx].ToolResult.Content = fmt.Sprintf(
		"%s (~%d characters omitted). Re-run the tool with a narrower scope: add a host or "+
			"path_prefix filter, set summarize=false, or use a smaller limit.",
		compactedResultNotice, maxLen)
	messages[idx].ToolResult.IsError = true
	return true
}

// isContextLengthError reports whether err is a provider rejecting the request
// because it exceeded the model's context window. The adapters classify this by
// HTTP status / exception type (never a 429) and wrap llm.ErrContextLength, so a
// rate-limit error is not misclassified as context overflow.
func isContextLengthError(err error) bool {
	return errors.Is(err, llm.ErrContextLength)
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
		UserID     string `json:"user_id"`
		StartDate  string `json:"start_date"`
		EndDate    string `json:"end_date"`
		GroupBy    string `json:"group_by"`
		Host       string `json:"host"`
		PathPrefix string `json:"path_prefix"`
		Summarize  bool   `json:"summarize"`
		Limit      *int   `json:"limit"`
		Offset     int    `json:"offset"`
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

	groupBy := params.GroupBy
	if groupBy == "" {
		groupBy = "host"
	}
	if groupBy != "host" && groupBy != "endpoint" {
		return "", fmt.Errorf("invalid group_by %q: must be \"host\" or \"endpoint\"", params.GroupBy)
	}

	// Resolve the page size. A nil limit means "use the default"; an explicit 0
	// means "counts only, no list"; anything else is clamped to [0, maxAnalyzeLimit]
	// so a single call can never overflow the agent's context.
	limit := defaultAnalyzeLimit
	if params.Limit != nil {
		limit = *params.Limit
		switch {
		case limit < 0:
			limit = 0
		case limit > maxAnalyzeLimit:
			limit = maxAnalyzeLimit
		}
	}
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}

	groups := a.reader.AggregatePathGroups(params.UserID, start, end, params.Host, params.PathPrefix)
	if len(groups) == 0 {
		return "No traffic found for " + describeScope(params.UserID, params.Host, params.PathPrefix) +
			" in the specified date range.", nil
	}

	if groupBy == "host" {
		return a.analyzeByHost(groups, params.Host, params.PathPrefix, offset, limit), nil
	}
	return a.analyzeByEndpoint(ctx, params.UserID, start, end, groups,
		params.Host, params.PathPrefix, params.Summarize, offset, limit, state, notify), nil
}

// analyzeByHost rolls the path groups up to per-host counts and returns one
// paginated page. No fast-model calls — this is the cheap "breadth of egress
// destinations" view the agent uses to orient before drilling into endpoints.
func (a *PolicyAgent) analyzeByHost(groups []PathGroup, hostFilter, pathPrefix string, offset, limit int) string {
	type acc struct{ count, endpoints int }
	byHost := map[string]*acc{}
	order := make([]string, 0)
	totalRequests := 0
	for _, g := range groups {
		h := hostFromPattern(g.PathPattern)
		totalRequests += g.Count
		cur, ok := byHost[h]
		if !ok {
			cur = &acc{}
			byHost[h] = cur
			order = append(order, h)
		}
		cur.count += g.Count
		cur.endpoints++
	}
	hosts := make([]hostGroup, 0, len(order))
	for _, h := range order {
		hosts = append(hosts, hostGroup{host: h, count: byHost[h].count, endpointCount: byHost[h].endpoints})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].count > hosts[j].count })

	page := paginate(len(hosts), offset, limit)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d requests across %d distinct hosts%s.\n",
		totalRequests, len(hosts), scopeSuffix(hostFilter, pathPrefix)))
	writePageHeader(&sb, "hosts", offset, page, len(hosts),
		"increase offset, or use group_by=\"endpoint\" with host=\"<host>\" to drill into one host's endpoints")
	for _, hg := range hosts[page.start:page.end] {
		sb.WriteString(fmt.Sprintf("- %s (%d requests, %d endpoints)\n", hg.host, hg.count, hg.endpointCount))
	}
	return sb.String()
}

// analyzeByEndpoint returns one paginated page of (method, path pattern) groups,
// optionally with a fast-model description per endpoint. Summarization runs only
// over the page (bounded by maxAnalyzeLimit), and summaries are persisted so the
// draft's traffic context accumulates as the agent drills in.
func (a *PolicyAgent) analyzeByEndpoint(
	ctx context.Context, userID string, start, end time.Time, groups []PathGroup,
	hostFilter, pathPrefix string, summarize bool, offset, limit int,
	state *agentState, notify func(string, interface{}),
) string {
	totalRequests := 0
	for _, g := range groups {
		totalRequests += g.Count
	}
	page := paginate(len(groups), offset, limit)
	pageGroups := groups[page.start:page.end]

	var descriptions map[int]string
	if summarize && len(pageGroups) > 0 {
		descriptions = a.summarizePage(ctx, userID, start, end, pageGroups, notify)
		for i, g := range pageGroups {
			appendSummary(state, types.PolicyEndpointSummary{
				Method: g.Method, PathPattern: g.PathPattern, Count: g.Count, Description: descriptions[i],
			})
		}
		notify("summaries_updated", state.summaries)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d requests across %d distinct endpoints%s.\n",
		totalRequests, len(groups), scopeSuffix(hostFilter, pathPrefix)))
	hint := "increase offset, or narrow with host/path_prefix"
	if !summarize {
		hint = "set summarize=true for a description of each endpoint; " + hint
	}
	writePageHeader(&sb, "endpoints", offset, page, len(groups), hint)
	for i, g := range pageGroups {
		if summarize {
			sb.WriteString(fmt.Sprintf("- %s %s (%d calls): %s\n", g.Method, g.PathPattern, g.Count, descriptions[i]))
		} else {
			sb.WriteString(fmt.Sprintf("- %s %s (%d calls)\n", g.Method, g.PathPattern, g.Count))
		}
	}
	return sb.String()
}

// summarizePage runs the fast model over one page of endpoint groups concurrently
// and returns descriptions keyed by their index within pageGroups.
func (a *PolicyAgent) summarizePage(
	ctx context.Context, userID string, start, end time.Time, pageGroups []PathGroup, notify func(string, interface{}),
) map[int]string {
	type indexed struct {
		idx  int
		desc string
	}
	ch := make(chan indexed, len(pageGroups))
	sem := make(chan struct{}, agentConcurrency)
	var wg sync.WaitGroup
	for i, g := range pageGroups {
		wg.Add(1)
		go func(idx int, group PathGroup) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			samples := a.reader.SampleRequestsForPath(userID, group.Method, PathPrefixFromPattern(group.PathPattern), start, end, 200)
			ch <- indexed{idx, summarizeEndpoint(ctx, a.fastAdapter, group.Method, group.PathPattern, group.Count, samples)}
		}(i, g)
	}
	go func() { wg.Wait(); close(ch) }()

	out := make(map[int]string, len(pageGroups))
	completed := 0
	for r := range ch {
		out[r.idx] = r.desc
		completed++
		notify("tool_progress", map[string]interface{}{
			"message":   fmt.Sprintf("Summarized %d/%d endpoints", completed, len(pageGroups)),
			"completed": completed,
			"total":     len(pageGroups),
		})
	}
	return out
}

// pageRange is a half-open slice range [start, end).
type pageRange struct{ start, end int }

// paginate clamps offset/limit to a slice of length n. limit==0 yields an empty
// page (counts-only); limit>0 yields up to limit rows starting at offset.
func paginate(n, offset, limit int) pageRange {
	if offset > n {
		offset = n
	}
	if limit <= 0 {
		return pageRange{offset, offset}
	}
	end := offset + limit
	if end > n {
		end = n
	}
	return pageRange{offset, end}
}

// writePageHeader emits the "Showing X–Y of N ..." line (and the more-available
// hint) for a page, or a counts-only / past-the-end note when nothing is listed.
func writePageHeader(sb *strings.Builder, unit string, offset int, page pageRange, total int, moreHint string) {
	shown := page.end - page.start
	if shown == 0 {
		if offset >= total && total > 0 {
			sb.WriteString(fmt.Sprintf("(offset %d is past the end; %d %s total.)\n", offset, total, unit))
		} else {
			sb.WriteString(fmt.Sprintf("(counts only — set limit>0 to list %s.)\n", unit))
		}
		return
	}
	sb.WriteString(fmt.Sprintf("Showing %s %d-%d of %d by request count.", unit, page.start+1, page.end, total))
	if remaining := total - page.end; remaining > 0 {
		sb.WriteString(fmt.Sprintf(" %d more — %s.", remaining, moreHint))
	}
	sb.WriteString("\n")
}

// scopeSuffix renders the active host/path_prefix filters for a header line.
func scopeSuffix(host, pathPrefix string) string {
	parts := make([]string, 0, 2)
	if host != "" {
		parts = append(parts, "host="+host)
	}
	if pathPrefix != "" {
		parts = append(parts, "path_prefix="+pathPrefix)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (filtered: " + strings.Join(parts, ", ") + ")"
}

// describeScope renders the user + active filters for the no-traffic message.
func describeScope(userID, host, pathPrefix string) string {
	return "user " + userID + scopeSuffix(host, pathPrefix)
}

// hostFromPattern extracts the host (with port) from a normalized URL pattern.
// Hosts are not altered by NormalizeURL (its regexes exclude dotted/TLD segments),
// so the host portion of the pattern is reliable.
func hostFromPattern(pattern string) string {
	rest := pattern
	if i := strings.Index(pattern, "://"); i >= 0 {
		rest = pattern[i+3:]
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}

// appendSummary upserts an endpoint summary into state by (method, path pattern),
// so paging/re-running analyze_traffic does not duplicate the traffic context.
func appendSummary(state *agentState, s types.PolicyEndpointSummary) {
	for i := range state.summaries {
		if state.summaries[i].Method == s.Method && state.summaries[i].PathPattern == s.PathPattern {
			state.summaries[i] = s
			return
		}
	}
	state.summaries = append(state.summaries, s)
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
- Use analyze_traffic to explore observed traffic before writing a policy. It is paginated and capped, so it
  will never overwhelm your context; explore iteratively rather than trying to pull everything at once:
  - Start broad: group_by="host" (the default) to see every destination domain with request and endpoint counts.
  - Drill down: group_by="endpoint" with host="<domain>" (optionally path_prefix) to see a domain's specific
    endpoints. Add summarize=true on a focused page when you need to know what each endpoint does.
  - Page with limit/offset; each result tells you the totals and how many rows remain. Set limit=0 for counts only.
  - Survey the hosts first, then drill into the ones that need their own rules. Do not assume the first page is
    everything — check the reported totals and page further or filter when it matters for an accurate policy.
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
		Name: "analyze_traffic",
		Description: "Explore a user's observed HTTP traffic over a date range to understand what the agent accesses, before writing a policy. " +
			"Results are always ordered by request count and PAGINATED (capped per call) so they never overflow your context. " +
			"Start broad with group_by=\"host\" to see every destination domain with request and endpoint counts, then drill in " +
			"with group_by=\"endpoint\" plus host/path_prefix filters. Use summarize=true only on a focused page to get a description " +
			"of each endpoint. Page through results with limit/offset; each result reports the totals and how many rows remain. " +
			"You may call this multiple times to page and drill down.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"user_id":     {"type": "string", "description": "The user ID to analyze traffic for"},
				"start_date":  {"type": "string", "description": "Start of date range in RFC3339 format (e.g. 2024-01-01T00:00:00Z)"},
				"end_date":    {"type": "string", "description": "End of date range in RFC3339 format"},
				"group_by":    {"type": "string", "enum": ["host", "endpoint"], "description": "Aggregation level. \"host\" (default) lists destination hosts with request and distinct-endpoint counts — use it for breadth. \"endpoint\" lists individual (method, path) patterns — use it for depth, usually with a host filter."},
				"host":        {"type": "string", "description": "Optional. Restrict to a single host (e.g. \"api.example.com\"). Combine with group_by=\"endpoint\" to drill into one domain."},
				"path_prefix": {"type": "string", "description": "Optional. Restrict to URLs whose path starts with this prefix (e.g. \"/v1/users\")."},
				"summarize":   {"type": "boolean", "description": "Optional, group_by=\"endpoint\" only. When true, add a fast-model description of each returned endpoint (slower). Default false. Use on a focused page, not a broad scan."},
				"limit":       {"type": "integer", "description": "Optional. Max rows to return this call. Default 50, hard-capped at 100. Set 0 to return only the totals (no list)."},
				"offset":      {"type": "integer", "description": "Optional. Number of rows to skip, for paging through results. Default 0."}
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
