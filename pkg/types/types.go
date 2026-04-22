package types

import (
	"encoding/json"
	"net/http"
	"time"
)

// SummaryDetail represents a key-value pair for human-readable request details
type SummaryDetail struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// APIInfo contains API-specific information extracted from requests
type APIInfo struct {
	Provider  string          `json:"provider"`
	Service   string          `json:"service"`
	Operation string          `json:"operation"`
	Endpoint  string          `json:"endpoint"`
	Scopes    []string        `json:"scopes,omitempty"`
	Title     string          `json:"title,omitempty"`
	Details   []SummaryDetail `json:"details,omitempty"`
}

// EventData is the sealed interface implemented by all notification event payload types.
// The unexported method prevents external types from satisfying it accidentally.
type EventData interface {
	eventData()
}

func (*ApprovalRequest)      eventData() {}
func (*ApprovalDecisionData) eventData() {}

// ApprovalDecisionData is the SSE broadcast payload for EventApprovalDecided.
type ApprovalDecisionData struct {
	ID         string       `json:"id"`
	Decision   DecisionType `json:"decision"`
	ApprovedBy string       `json:"approved_by,omitempty"`
	Channel    string       `json:"channel,omitempty"`
}
func (*AuditEntry)           eventData() {}

// OperationType defines the type of operation being performed
type OperationType string

const (
	OperationRead  OperationType = "READ"
	OperationWrite OperationType = "WRITE"
	OperationAdmin OperationType = "ADMIN"
)

// DecisionType represents the approval decision
type DecisionType string

const (
	DecisionAllow   DecisionType = "ALLOW"
	DecisionDeny    DecisionType = "DENY"
	DecisionTimeout DecisionType = "TIMEOUT"
)

// ApprovalRequest represents a request pending approval
type ApprovalRequest struct {
	ID             string                 `json:"id"`
	UserID         string                 `json:"user_id,omitempty"` // Gateway user ID
	Hash           string                 `json:"hash"`
	Method         string                 `json:"method"`
	URL            string                 `json:"url"`
	Headers        http.Header            `json:"headers"`
	Body           string                 `json:"body"`
	Status         string                 `json:"status"`
	CreatedAt      time.Time              `json:"created_at"`
	TimeoutSeconds int                    `json:"timeout_seconds"` // Timeout in seconds
	ApprovedBy     string                 `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time             `json:"approved_at,omitempty"`
	APIInfo *APIInfo `json:"api_info,omitempty"`
}

// ApprovalDecision contains the decision for an approval request
type ApprovalDecision struct {
	Decision    DecisionType
	ApprovedBy  string
	Reason      string
	Channel     string       // Channel used for approval (web, cli, cache, llm, etc.)
	LLMPolicyID string       // Set when Channel="llm"; the policy that made the decision
	LLMResponse *LLMResponse // Set when the judge actually ran (success or error)

	// Probe evaluation results; populated when the probe runner ran (success or error).
	ProbeScores      map[string]float64 // aggregated score per probe name
	ProbeTripped     string             // name of the first probe that exceeded threshold; empty if none
	ProbeAggregation string             // aggregation method that produced ProbeScores (e.g. "max", "mean")
	ProbeCircuitOpen bool               // true if the probe circuit breaker rejected the call
}

// LLMResponse holds the raw result of one LLM judge call.
// ID and CreatedAt are populated when reading from the DB; leave empty when creating.
type LLMResponse struct {
	ID           string    `json:"id,omitempty"`
	Model        string    `json:"model"`
	DurationMs   int       `json:"duration_ms"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
	Result       string    `json:"result"`            // "success" | "error"
	Decision     string    `json:"decision,omitempty"` // "ALLOW" | "DENY" | "" on error
	Reason       string    `json:"reason,omitempty"`
	RawOutput    string    `json:"raw_output,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
}

// CachedApproval represents a cached approval entry
type CachedApproval struct {
	Hash       string
	ApprovedAt time.Time
	ExpiresAt  time.Time
	Uses       int
	MaxUses    int
}

// StaticRule makes a static allow/deny decision for matching requests, bypassing the LLM judge.
type StaticRule struct {
	Methods    []string `json:"methods"`     // empty = all methods
	URLPattern string   `json:"url_pattern"`
	MatchType  string   `json:"match_type"`  // "prefix" (default) | "exact" | "glob"
	Action     string   `json:"action"`      // "allow" (default) | "deny"
}

// ToolCallRecord records a tool invocation made by the assistant.
type ToolCallRecord struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// ToolResultRecord records the result of a tool call.
type ToolResultRecord struct {
	ToolCallID string `json:"tool_call_id"`
	Content    string `json:"content"`
	IsError    bool   `json:"is_error,omitempty"`
}

// ChatMessage is a single turn in the policy editing conversation.
// Plain text turns set Role and Content.
// Assistant turns with tool calls also set ToolCalls.
// Tool result turns set Role="tool" and ToolResult.
type ChatMessage struct {
	Role       string            `json:"role"`
	Content    string            `json:"content,omitempty"`
	ToolCalls  []ToolCallRecord  `json:"tool_calls,omitempty"`
	ToolResult *ToolResultRecord `json:"tool_result,omitempty"`
}

// PolicyEndpointSummary is a compact description of one observed endpoint group,
// stored in PolicyMetadata so AI-assisted editing has traffic context.
type PolicyEndpointSummary struct {
	Method      string `json:"method"`
	PathPattern string `json:"path_pattern"`
	Count       int    `json:"count"`
	Description string `json:"description"`
}

// PolicyMetadata records how a draft policy was created, what traffic context
// was used, and the conversation history with the AI agent.
type PolicyMetadata struct {
	Source            string                  `json:"source"` // "suggest" | "fork" | "manual"
	AnalyzedUserID    string                  `json:"analyzed_user_id,omitempty"`
	AnalyzedStart     *time.Time              `json:"analyzed_start,omitempty"`
	AnalyzedEnd       *time.Time              `json:"analyzed_end,omitempty"`
	EndpointSummaries []PolicyEndpointSummary `json:"endpoint_summaries,omitempty"`
	ChatHistory       []ChatMessage           `json:"chat_history,omitempty"`
}

// LLMPolicy configures the LLM judge for a user.
// Draft policies are mutable; publishing is one-way and makes the record immutable.
type LLMPolicy struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Prompt           string           `json:"prompt"`
	Provider         string           `json:"provider"`         // "" = use gateway default
	Model            string           `json:"model"`            // "" = use gateway default
	Status           string           `json:"status"`           // "draft" | "published"
	ForkedFrom       string           `json:"forked_from,omitempty"`
	StaticRules []StaticRule `json:"static_rules"`
	Metadata         *PolicyMetadata  `json:"metadata,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	DeletedAt        *time.Time       `json:"deleted_at,omitempty"`
}

// AuditEntry represents a log entry for audit trail
type AuditEntry struct {
	ID              string      `json:"id,omitempty"` // audit_log primary key; populated on read
	Timestamp       time.Time   `json:"timestamp"`
	UserID          string      `json:"user_id,omitempty"` // Gateway user ID; empty for ADMIN ops
	RequestID       string      `json:"request_id"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Operation       string      `json:"operation"`
	Decision        string      `json:"decision"`
	CacheHit        bool        `json:"cache_hit"`
	ApprovedBy      string      `json:"approved_by,omitempty"`
	ApprovedAt      string      `json:"approved_at,omitempty"`
	Channel         string      `json:"channel,omitempty"` // Channel used for approval (web, cli, cache, llm, etc.)
	ResponseStatus  int         `json:"response_status"`
	DurationMs      int64       `json:"duration_ms"`
	Error           string      `json:"error,omitempty"`
	RequestHeaders  http.Header `json:"request_headers,omitempty"`
	RequestBody     string      `json:"request_body,omitempty"`
	ResponseHeaders http.Header `json:"response_headers,omitempty"`
	ResponseBody    string      `json:"response_body,omitempty"`
	APIInfo          *APIInfo    `json:"api_info,omitempty"`
	LLMReason        string      `json:"llm_reason,omitempty"`       // Populated on read via JOIN to llm_responses; not stored
	LLMResponseID    string      `json:"llm_response_id,omitempty"`  // FK to llm_responses; set when channel="llm"
	LLMPolicyID      string      `json:"llm_policy_id,omitempty"`    // Policy that evaluated this request (set when channel="llm")

	// Probe evaluator results; present when the global probe runner ran.
	ProbeScores      map[string]float64 `json:"probe_scores,omitempty"`
	ProbeTripped     string             `json:"probe_tripped,omitempty"`
	ProbeAggregation string             `json:"probe_aggregation,omitempty"`
	ProbeCircuitOpen bool               `json:"probe_circuit_open,omitempty"`
}
