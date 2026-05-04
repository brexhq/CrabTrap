export interface AuditEntry {
  id?: string
  user_id?: string
  timestamp: string
  request_id: string
  method: string
  url: string
  operation: string
  decision: string
  cache_hit: boolean
  approved_by?: string
  approved_at?: string
  channel?: string
  response_status: number
  duration_ms: number
  error?: string
  request_headers?: Record<string, string[]>
  request_body?: string
  response_headers?: Record<string, string[]>
  response_body?: string
  llm_reason?: string         // populated on read via JOIN to llm_responses
  llm_response_id?: string    // FK to llm_responses
  llm_policy_id?: string
}

export interface SSEEvent {
  type: 'audit_entry' | 'connected'
  data: AuditEntry
  channel?: string
}

// ---- LLM Policy types ----

export interface StaticRule {
  methods: string[] | null  // empty/null = all methods
  url_pattern: string
  match_type?: 'prefix' | 'exact' | 'glob'  // default "prefix"
  action?: 'allow' | 'deny'                  // default "allow"
}

export interface PolicyStatsApprover {
  approved_by: string
  count: number
  avg_duration_ms: number
}

export interface PolicyDecisionStats {
  count: number
  avg_duration_ms: number
  p50_duration_ms: number
  p95_duration_ms: number
  p99_duration_ms: number
  by_approver: PolicyStatsApprover[]
}

export interface TimeSeriesBucket {
  bucket: string
  total: number
  approved: number
  denied: number
  timeout: number
  avg_duration_ms: number
}

export interface PolicyStats {
  total: number
  avg_duration_ms: number
  p50_duration_ms: number
  p95_duration_ms: number
  p99_duration_ms: number
  by_decision: Record<string, PolicyDecisionStats>
  time_series: TimeSeriesBucket[]
}

export interface PolicyEndpointSummary {
  method: string
  path_pattern: string
  count: number
  description: string
}

export interface PolicyMetadata {
  source: 'suggest' | 'fork' | 'manual'
  analyzed_user_id?: string
  analyzed_start?: string
  analyzed_end?: string
  endpoint_summaries?: PolicyEndpointSummary[]
  chat_history?: ChatMessage[]
}

export interface LLMPolicy {
  id: string
  name: string
  prompt: string
  provider: string
  model: string
  status: 'draft' | 'published'
  forked_from?: string
  static_rules?: StaticRule[]
  metadata?: PolicyMetadata
  created_at: string
  deleted_at?: string
}

export interface ToolCallRecord {
  id: string
  name: string
  input: unknown
}

export interface ToolResultRecord {
  tool_call_id: string
  content: string
  is_error?: boolean
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'tool'
  content?: string
  tool_calls?: ToolCallRecord[]
  tool_result?: ToolResultRecord
}

// ---- User management types ----

export type UserRole = 'admin' | 'manager' | 'user'

export interface UserSummary {
  id: string
  role: UserRole
  is_admin: boolean
  llm_policy_id?: string
  created_at: string
  channel_count: number
}

export interface UserChannelInfo {
  id: string
  channel_type: string
  web_token?: string
  gateway_auth_token?: string
}

export interface UserDetail extends Omit<UserSummary, 'channel_count' | 'llm_policy_id'> {
  llm_policy_id?: string
  updated_at: string
  channels: UserChannelInfo[]
}

export interface CreateUserRequest {
  id: string
  role?: UserRole
  is_admin?: boolean
  llm_policy_id?: string
  web_token?: string
  gateway_auth_token?: string
}

export interface UpdateUserRequest {
  role?: UserRole
  is_admin?: boolean
  llm_policy_id?: string | null
  web_token?: string
  gateway_auth_token?: string
}

// ---- Eval types ----

export interface EvalRun {
  id: string
  policy_id: string
  policy_name?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'canceled'
  error?: string
  created_at: string
  completed_at?: string
  total_entries: number  // expected total; 0 = unknown
  total: number
  agreed: number
  disagreed: number
  errored: number
  labeled: number
}

export interface EvalResult {
  id: string
  run_id: string
  entry_id: string
  replay_decision: string     // "ALLOW" | "DENY" | "ERROR"
  approved_by?: string        // "llm" | "llm-static-rule"
  llm_response_id?: string
  replayed_at: string
  replay_reason?: string      // populated on read via JOIN to llm_responses
  method?: string
  url?: string
  original_decision?: string
  label_decision?: string
  label_note?: string
}

export interface LLMResponse {
  id: string
  model: string
  duration_ms: number
  input_tokens?: number
  output_tokens?: number
  result: 'success' | 'error'
  decision?: string
  reason?: string
  raw_output?: string
  created_at: string
}

export interface AuditLabel {
  id: string
  entry_id: string
  decision: string
  note?: string
  labeled_by?: string
  created_at: string
}

// SSE events emitted by GET /admin/users/{id}/suggest-policy
export type SuggestProgressEvent =
  | { type: 'progress'; stage: string; message: string; completed?: number; total?: number; pattern_count?: number }
  | { type: 'result'; suggested_prompt: string; static_rules: StaticRule[]; rationale: string; pattern_count: number }
  | { type: 'error'; message: string }
  | { type: 'done' }
