import type {
  AuditEntry, LLMPolicy, PolicyStats,
  UserSummary, UserDetail,
  CreateUserRequest, UpdateUserRequest,
  EvalRun, EvalResult, AuditLabel, LLMResponse, StaticRule, ChatMessage,
} from '../types'

const API_BASE = '/admin'

// Returns the stored web token from localStorage, or null if not set.
export function getStoredToken(): string | null {
  return localStorage.getItem('web_token')
}

// Helper function for API requests
async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken()
  const authHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders,
      ...options?.headers,
    },
  })

  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`)
  }

  if (response.status === 204 || response.headers.get('Content-Length') === '0') {
    return undefined as unknown as T
  }

  return response.json()
}

// Get the current authenticated user (returns { user_id, is_admin } or throws on 401/403).
export async function getCurrentUser(token: string): Promise<{ user_id: string; is_admin: boolean }> {
  const response = await fetch(`${API_BASE}/me`, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  })
  if (!response.ok) {
    throw new Error(`Unauthorized`)
  }
  return response.json()
}

// Query audit log
export interface AuditQuery {
  user_id?: string
  decision?: string
  approved_by?: string
  cache_hit?: boolean
  channel?: string
  method?: string
  policy_id?: string
  start_time?: string
  end_time?: string
  limit?: number
  offset?: number
}

export interface AuditResponse {
  entries: AuditEntry[]
  offset: number
  limit: number
  has_more?: boolean
}

export async function getAuditLog(query: AuditQuery = {}): Promise<AuditResponse> {
  const params = new URLSearchParams()

  if (query.user_id) params.append('user_id', query.user_id)
  if (query.decision) params.append('decision', query.decision)
  if (query.approved_by) params.append('approved_by', query.approved_by)
  if (query.cache_hit !== undefined) params.append('cache_hit', String(query.cache_hit))
  if (query.channel) params.append('channel', query.channel)
  if (query.method) params.append('method', query.method)
  if (query.policy_id) params.append('policy_id', query.policy_id)
  if (query.start_time) params.append('start_time', query.start_time)
  if (query.end_time) params.append('end_time', query.end_time)
  if (query.limit) params.append('limit', String(query.limit))
  if (query.offset) params.append('offset', String(query.offset))

  const queryString = params.toString()
  return fetchAPI<AuditResponse>(`/audit${queryString ? '?' + queryString : ''}`)
}

// ---- LLM Policy API ----

export async function getPolicies(): Promise<LLMPolicy[]> {
  return fetchAPI<LLMPolicy[]>('/llm-policies')
}

export async function getPolicy(id: string): Promise<LLMPolicy> {
  return fetchAPI<LLMPolicy>(`/llm-policies/${id}`)
}

export async function createPolicy(req: { name: string; prompt?: string; provider?: string; model?: string; status?: 'draft' | 'published'; static_rules?: StaticRule[] }): Promise<LLMPolicy> {
  return fetchAPI<LLMPolicy>('/llm-policies', { method: 'POST', body: JSON.stringify(req) })
}

export async function updateDraftPolicy(id: string, req: { name: string; prompt: string; provider: string; model: string; static_rules: StaticRule[] }): Promise<LLMPolicy> {
  return fetchAPI<LLMPolicy>(`/llm-policies/${id}`, { method: 'PUT', body: JSON.stringify(req) })
}

export async function publishPolicy(id: string): Promise<LLMPolicy> {
  return fetchAPI<LLMPolicy>(`/llm-policies/${id}/publish`, { method: 'POST' })
}

export async function forkPolicy(id: string, req: { name: string }): Promise<LLMPolicy> {
  return fetchAPI<LLMPolicy>(`/llm-policies/${id}/fork`, { method: 'POST', body: JSON.stringify(req) })
}

// runAgentStream sends a message to the policy agent and streams SSE events back via fetch().
// onEvent is called for each parsed event. Resolves when the stream ends.
export async function runAgentStream(
  policyId: string,
  message: string,
  history: ChatMessage[],
  onEvent: (type: string, data: unknown) => void,
): Promise<void> {
  const token = getStoredToken() ?? ''
  const response = await fetch(`${API_BASE}/llm-policies/${policyId}/agent`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ message, history }),
  })
  if (!response.ok) throw new Error(`Agent request failed: ${response.statusText}`)
  if (!response.body) return

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  let curEvent = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (line.startsWith('event: ')) {
        curEvent = line.slice(7).trim()
      } else if (line.startsWith('data: ') && curEvent) {
        try { onEvent(curEvent, JSON.parse(line.slice(6))) } catch { /* ignore parse errors */ }
        curEvent = ''
      }
    }
  }
}

export async function getPolicyMetadata(id: string): Promise<import('../types').PolicyMetadata> {
  return fetchAPI(`/llm-policies/${id}/metadata`)
}

export async function getPolicyStats(id: string): Promise<PolicyStats> {
  return fetchAPI<PolicyStats>(`/llm-policies/${id}/stats`)
}

export async function deletePolicy(id: string): Promise<void> {
  await fetchAPI(`/llm-policies/${id}`, { method: 'DELETE' })
}

// ---- User management API ----

export async function getUsers(): Promise<UserSummary[]> {
  return fetchAPI<UserSummary[]>('/users')
}

export async function getUser(id: string): Promise<UserDetail> {
  return fetchAPI<UserDetail>(`/users/${encodeURIComponent(id)}`)
}

export async function createUser(req: CreateUserRequest): Promise<UserDetail> {
  return fetchAPI<UserDetail>('/users', { method: 'POST', body: JSON.stringify(req) })
}

export async function updateUser(id: string, req: UpdateUserRequest): Promise<UserDetail> {
  return fetchAPI<UserDetail>(`/users/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(req) })
}

export async function deleteUser(id: string): Promise<void> {
  await fetchAPI(`/users/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

// ---- Eval API ----

export interface EvalFilter {
  limit?: number
  decision?: string
  user_id?: string
  start_time?: string
  end_time?: string
}

export async function createEvalRun(policyId: string, filter: EvalFilter = {}): Promise<EvalRun> {
  return fetchAPI<EvalRun>('/evals', { method: 'POST', body: JSON.stringify({ policy_id: policyId, filter }) })
}

export async function listEvalRuns(policyId?: string, limit = 50, offset = 0): Promise<EvalRun[]> {
  const params = new URLSearchParams()
  if (policyId) params.append('policy_id', policyId)
  params.append('limit', String(limit))
  params.append('offset', String(offset))
  return fetchAPI<EvalRun[]>(`/evals?${params.toString()}`)
}

export async function getEvalRun(id: string): Promise<EvalRun> {
  return fetchAPI<EvalRun>(`/evals/${id}`)
}

export async function cancelEvalRun(id: string): Promise<void> {
  await fetchAPI(`/evals/${id}/cancel`, { method: 'POST' })
}

export interface EvalApproverStats {
  approved_by: string
  total: number
  agreed: number
  disagreed: number
  errored: number
  p50_ms?: number
  p95_ms?: number
  p99_ms?: number
}

export interface EvalLabeledStats {
  approved_by: string
  labeled: number
  labeled_agreed: number
  labeled_disagreed: number
  p50_ms?: number
  p95_ms?: number
  p99_ms?: number
}

export interface EvalRunStats {
  by_approved_by: EvalApproverStats[]
  overall: EvalApproverStats
  labeled_by_approved_by: EvalLabeledStats[]
  labeled_overall: EvalLabeledStats
}

export async function getEvalRunStats(id: string): Promise<EvalRunStats> {
  return fetchAPI<EvalRunStats>(`/evals/${id}/stats`)
}

export interface EvalResultFilter {
  approved_by?: string
  replay_decision?: string
  has_label?: boolean
  matched?: boolean
  url?: string
}

export interface EvalResultsResponse {
  results: EvalResult[]
  total: number
}

export async function listEvalResults(runId: string, limit = 100, offset = 0, filter: EvalResultFilter = {}): Promise<EvalResultsResponse> {
  const params = new URLSearchParams()
  params.append('limit', String(limit))
  params.append('offset', String(offset))
  if (filter.approved_by) params.append('approved_by', filter.approved_by)
  if (filter.replay_decision) params.append('replay_decision', filter.replay_decision)
  if (filter.has_label !== undefined) params.append('has_label', String(filter.has_label))
  if (filter.matched !== undefined) params.append('matched', String(filter.matched))
  if (filter.url) params.append('url', filter.url)
  return fetchAPI<EvalResultsResponse>(`/evals/${runId}/results?${params.toString()}`)
}

export async function getAuditEntry(id: string): Promise<AuditEntry> {
  return fetchAPI<AuditEntry>(`/audit/${encodeURIComponent(id)}`)
}

export async function getLLMResponse(id: string): Promise<LLMResponse> {
  return fetchAPI<LLMResponse>(`/llm-responses/${encodeURIComponent(id)}`)
}

export async function upsertLabel(entryId: string, decision: string, note = ''): Promise<AuditLabel> {
  return fetchAPI<AuditLabel>(`/audit/${encodeURIComponent(entryId)}/label`, {
    method: 'PUT',
    body: JSON.stringify({ decision, note }),
  })
}

export async function deleteLabel(entryId: string): Promise<void> {
  await fetchAPI(`/audit/${encodeURIComponent(entryId)}/label`, { method: 'DELETE' })
}
