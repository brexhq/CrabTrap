import { useState, useEffect, useRef, useMemo } from 'react'
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import {
  getPolicy, getPolicyStats, getPolicyMetadata, getAuditLog, forkPolicy,
  listEvalRuns, createEvalRun, deletePolicy, getUsers,
  updateDraftPolicy, publishPolicy, runAgentStream,
} from '../api/client'
import type { EvalFilter } from '../api/client'
import { parseDatetimeLocal } from '../lib/utils'
import { useAuth } from '../contexts/AuthContext'
import type {
  LLMPolicy, PolicyStats, AuditEntry, TimeSeriesBucket, EvalRun,
  UserSummary, StaticRule, ChatMessage,
} from '../types'
import { format } from 'date-fns'

const inputClass = 'w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500'
const btnPrimary = 'px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnSecondary = 'px-4 py-2 border border-gray-300 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50'

// ---- Shared: StaticRulesEditor ----

const emptyRule = (): StaticRule => ({ methods: [], url_pattern: '', match_type: 'prefix', action: 'allow' })

function StaticRulesEditor({ rules, onChange, readOnly }: {
  rules: StaticRule[]
  onChange?: (rules: StaticRule[]) => void
  readOnly?: boolean
}) {
  const updateRule = (i: number, patch: Partial<StaticRule>) => {
    if (!onChange) return
    onChange(rules.map((r, idx) => idx === i ? { ...r, ...patch } : r))
  }
  const removeRule = (i: number) => onChange?.(rules.filter((_, idx) => idx !== i))

  if (readOnly) {
    return (
      <div className="space-y-1">
        {rules.map((rule, i) => {
          const isDeny = rule.action === 'deny'
          return (
            <div key={i} className={`flex items-center gap-2 text-xs font-mono rounded px-3 py-1.5 border ${isDeny ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-100'}`}>
              <span className={`font-semibold px-1.5 py-0.5 rounded text-xs ${isDeny ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'}`}>{isDeny ? 'deny' : 'allow'}</span>
              <span className="text-blue-600 font-semibold">{rule.methods && rule.methods.length > 0 ? rule.methods.join(' ') : '*'}</span>
              <span className="text-gray-700 flex-1 truncate">{rule.url_pattern}</span>
              <span className="text-gray-400">{rule.match_type ?? 'prefix'}</span>
            </div>
          )
        })}
        {rules.length === 0 && <p className="text-gray-400 text-xs italic">No static rules</p>}
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {rules.map((rule, i) => {
        const isDeny = rule.action === 'deny'
        return (
          <div key={i} className={`flex gap-2 items-start p-2 rounded-lg border ${isDeny ? 'border-red-200 bg-red-50' : 'border-gray-100 bg-gray-50'}`}>
            <select
              className={`rounded px-2 py-1.5 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500 border ${isDeny ? 'border-red-300 bg-red-100 text-red-700' : 'border-gray-300 bg-blue-50 text-blue-700'}`}
              value={rule.action ?? 'allow'}
              onChange={(e) => updateRule(i, { action: e.target.value as StaticRule['action'] })}
            >
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
            <input
              className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs w-24 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
              value={(rule.methods ?? []).join(',')}
              onChange={(e) => updateRule(i, { methods: e.target.value ? e.target.value.split(',').map(m => m.trim().toUpperCase()).filter(Boolean) : [] })}
              placeholder="GET,POST"
            />
            <input
              className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs flex-1 focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
              value={rule.url_pattern}
              onChange={(e) => updateRule(i, { url_pattern: e.target.value })}
              placeholder="https://api.example.com/"
            />
            <select
              className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
              value={rule.match_type ?? 'prefix'}
              onChange={(e) => updateRule(i, { match_type: e.target.value as StaticRule['match_type'] })}
            >
              <option value="prefix">prefix</option>
              <option value="exact">exact</option>
              <option value="glob">glob</option>
            </select>
            <button type="button" onClick={() => removeRule(i)} className="text-gray-400 hover:text-red-500 text-lg leading-none px-1">&times;</button>
          </div>
        )
      })}
      <button type="button" onClick={() => onChange?.([...rules, emptyRule()])} className="text-xs text-blue-600 hover:underline">
        + Add rule
      </button>
    </div>
  )
}

// Converts persisted ChatMessage history back to display events.
// Tool call messages become tool events (done=true); tool result messages are used
// to populate the result field and otherwise skipped.
function historyToAgentEvents(history: ChatMessage[]): AgentEvent[] {
  // Build tool_call_id → result content map from tool result messages.
  const toolResults: Record<string, string> = {}
  for (const msg of history) {
    if (msg.tool_result) {
      toolResults[msg.tool_result.tool_call_id] = msg.tool_result.content
    }
  }

  const events: AgentEvent[] = []
  for (const msg of history) {
    if (msg.role === 'user' && msg.content) {
      events.push({ kind: 'user', content: msg.content })
    } else if (msg.role === 'assistant' && msg.tool_calls && msg.tool_calls.length > 0) {
      for (const tc of msg.tool_calls) {
        events.push({ kind: 'tool', tool: tc.name, done: true, input: tc.input, result: toolResults[tc.id] })
      }
    } else if (msg.role === 'assistant' && msg.content) {
      events.push({ kind: 'assistant', content: msg.content })
    }
    // role='tool' messages are consumed via toolResults above; not rendered directly.
  }
  return events
}

// ---- Draft editor ----


// AgentEvent represents one item in the agent conversation display.
// Tool events are updated in place as progress arrives and when the tool completes.
type AgentEvent =
  | { kind: 'user'; content: string }
  | { kind: 'assistant'; content: string }
  | { kind: 'tool'; tool: string; done: boolean; input?: unknown; result?: string; progressMessage?: string; completed?: number; total?: number }
  | { kind: 'error'; message: string }

function DraftEditor({ policy, metadata, onSaved, onPublished, onDeleted, initialMessage }: {
  policy: LLMPolicy
  metadata: import('../types').PolicyMetadata | null
  onSaved: (p: LLMPolicy) => void
  onPublished: (p: LLMPolicy) => void
  onDeleted: () => void
  initialMessage?: string
}) {
  const navigate = useNavigate()
  const location = useLocation()

  // Track left panel height so the right panel can match it exactly.
  const leftPanelRef = useRef<HTMLDivElement>(null)
  const [leftHeight, setLeftHeight] = useState<number | null>(null)
  useEffect(() => {
    const el = leftPanelRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setLeftHeight(el.offsetHeight))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const [name, setName] = useState(policy.name)
  const [prompt, setPrompt] = useState(policy.prompt)
  const [provider, setProvider] = useState(policy.provider)
  const [model, setModel] = useState(policy.model)
  const [rules, setRules] = useState<StaticRule[]>(
    (policy.static_rules ?? []).map(r => ({ ...r, methods: r.methods ?? [] }))
  )
  const [saving, setSaving] = useState(false)
  const [saveErr, setSaveErr] = useState<string | null>(null)
  const [publishing, setPublishing] = useState(false)
  const [deleting, setDeleting] = useState(false)

  // Live endpoint summaries — initialized from metadata, updated by summaries_updated events.
  const [summaries, setSummaries] = useState<import('../types').PolicyEndpointSummary[]>(
    metadata?.endpoint_summaries ?? []
  )

  // Agent conversation state.
  // chatHistory is the source of truth (persisted to DB, sent with each request).
  // streamingEvents holds only the current in-progress turn (user msg + live tool calls);
  // it is cleared when the turn completes and chatHistory is updated with new_messages.
  const savedHistory = metadata?.chat_history ?? []
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>(savedHistory)
  const [streamingEvents, setStreamingEvents] = useState<AgentEvent[]>([])
  const displayEvents = useMemo(
    () => [...historyToAgentEvents(chatHistory), ...streamingEvents],
    [chatHistory, streamingEvents],
  )
  const [agentInput, setAgentInput] = useState('')
  const [agentRunning, setAgentRunning] = useState(false)
  const conversationEndRef = useRef<HTMLDivElement>(null)
  const chatContainerRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = chatContainerRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [displayEvents])

  // Auto-send initial message (e.g. from "Suggest Policy" on user detail page).
  const didAutoSend = useRef(false)
  useEffect(() => {
    if (initialMessage && !didAutoSend.current) {
      didAutoSend.current = true
      // Clear router state so a page refresh doesn't retrigger the auto-send.
      navigate(location.pathname, { replace: true, state: null })
      setAgentInput(initialMessage)
      // Defer one tick so state is set before handleAgentSend reads it.
      setTimeout(() => {
        setAgentInput('')
        setAgentRunning(true)
        setStreamingEvents([{ kind: 'user', content: initialMessage }])
        let gotResult = false
        const wrappedHandleEvent = (type: string, data: unknown) => {
          if (type === 'result') gotResult = true
          handleAgentEvent(type, data)
        }
        runAgentStream(policy.id, initialMessage, [], wrappedHandleEvent)
          .then(() => { if (gotResult) setStreamingEvents([]) })
          .catch((err) => {
            setStreamingEvents((prev) => [...prev, { kind: 'error', message: err instanceof Error ? err.message : 'Request failed' }])
          })
          .finally(() => setAgentRunning(false))
      }, 0)
    }
  }, []) // run once on mount

  const handleSave = async () => {
    setSaving(true)
    setSaveErr(null)
    try {
      const updated = await updateDraftPolicy(policy.id, { name, prompt, provider, model, static_rules: rules })
      onSaved(updated)
    } catch (err) {
      setSaveErr(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const handlePublish = async () => {
    if (!window.confirm('Publish this policy? It will become immutable.')) return
    setPublishing(true)
    try {
      await updateDraftPolicy(policy.id, { name, prompt, provider, model, static_rules: rules })
      const published = await publishPolicy(policy.id)
      onPublished(published)
    } catch (err) {
      setSaveErr(err instanceof Error ? err.message : 'Failed to publish')
    } finally {
      setPublishing(false)
    }
  }

  const handleDelete = async () => {
    if (!window.confirm(`Delete draft "${policy.name}"?`)) return
    setDeleting(true)
    try {
      await deletePolicy(policy.id)
      onDeleted()
    } catch (err) {
      setSaveErr(err instanceof Error ? err.message : 'Failed to delete')
      setDeleting(false)
    }
  }

  const handleAgentEvent = (type: string, data: unknown) => {
    const d = data as Record<string, unknown>
    switch (type) {
      case 'tool_start':
        setStreamingEvents((prev) => [...prev, { kind: 'tool', tool: d.tool as string, done: false, input: d.input }])
        break
      case 'tool_progress':
        setStreamingEvents((prev) => {
          const idx = [...prev].reverse().findIndex((e) => e.kind === 'tool' && !e.done)
          if (idx === -1) return prev
          const realIdx = prev.length - 1 - idx
          const updated = { ...prev[realIdx] as Extract<AgentEvent, { kind: 'tool' }>, progressMessage: d.message as string, completed: d.completed as number, total: d.total as number }
          return [...prev.slice(0, realIdx), updated, ...prev.slice(realIdx + 1)]
        })
        break
      case 'tool_done':
        setStreamingEvents((prev) => {
          const idx = [...prev].reverse().findIndex((e) => e.kind === 'tool' && !e.done)
          if (idx === -1) return prev
          const realIdx = prev.length - 1 - idx
          const updated = { ...prev[realIdx] as Extract<AgentEvent, { kind: 'tool' }>, done: true, result: d.result as string }
          return [...prev.slice(0, realIdx), updated, ...prev.slice(realIdx + 1)]
        })
        break
      case 'policy_updated': {
        const r = d as { policy_prompt: string; static_rules: StaticRule[] }
        setPrompt(r.policy_prompt)
        setRules((r.static_rules ?? []).map(rule => ({ ...rule, methods: rule.methods ?? [] })))
        break
      }
      case 'name_updated':
        setName(d.name as string)
        break
      case 'result': {
        const r = d as { new_messages?: ChatMessage[] }
        if (r.new_messages && r.new_messages.length > 0) {
          setChatHistory((h) => [...h, ...r.new_messages!])
        }
        break
      }
      case 'summaries_updated':
        setSummaries(data as import('../types').PolicyEndpointSummary[])
        break
      case 'error':
        setStreamingEvents((prev) => [...prev, { kind: 'error', message: d.message as string }])
        break
    }
  }

  const handleAgentSend = async () => {
    const message = agentInput.trim()
    if (!message || agentRunning) return
    setAgentInput('')
    setAgentRunning(true)
    setStreamingEvents([{ kind: 'user', content: message }])
    let gotResult = false
    const wrappedHandleEvent = (type: string, data: unknown) => {
      if (type === 'result') gotResult = true
      handleAgentEvent(type, data)
    }
    try {
      await runAgentStream(policy.id, message, chatHistory, wrappedHandleEvent)
      // Only clear transient streaming state if we got a result (messages committed to chatHistory).
      // If no result arrived (e.g. backend sent an error event), keep streaming events visible.
      if (gotResult) setStreamingEvents([])
    } catch (err) {
      setStreamingEvents((prev) => [...prev, { kind: 'error', message: err instanceof Error ? err.message : 'Request failed' }])
    } finally {
      setAgentRunning(false)
    }
  }


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={() => navigate('/policies')} className={btnSecondary}>← Back</button>
        <input
          className="text-xl font-semibold text-gray-900 flex-1 border-0 border-b border-transparent hover:border-gray-300 focus:border-blue-500 focus:outline-none bg-transparent py-0.5 px-1"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-xs font-semibold shrink-0">Draft</span>
        <button onClick={handleSave} disabled={saving} className={btnSecondary}>{saving ? 'Saving…' : 'Save'}</button>
        <button onClick={handlePublish} disabled={publishing || saving} className={btnPrimary}>{publishing ? 'Publishing…' : 'Publish'}</button>
        <button onClick={handleDelete} disabled={deleting}
          className="px-4 py-2 border border-red-300 text-red-600 text-sm font-medium rounded-lg hover:bg-red-50 disabled:opacity-40">
          {deleting ? '…' : 'Delete'}
        </button>
      </div>

      {saveErr && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
          {saveErr}
          <button className="ml-3 text-red-500 hover:text-red-700" onClick={() => setSaveErr(null)}>&times;</button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left: editable policy fields — observed for height */}
        <div ref={leftPanelRef} className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
          <p className="text-xs text-gray-400">Fields update automatically when the agent calls <span className="font-mono">update_policy</span>. Click Save to persist.</p>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="block text-sm font-medium text-gray-700">Provider</label>
              <input className={inputClass} value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="gateway default" />
            </div>
            <div className="space-y-1">
              <label className="block text-sm font-medium text-gray-700">Model</label>
              <input className={inputClass} value={model} onChange={(e) => setModel(e.target.value)} placeholder="gateway default" />
            </div>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Prompt</label>
            <textarea className={inputClass} value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={6}
              placeholder="Describe what the AI agent is and is not allowed to do..." />
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Static Rules</label>
            <StaticRulesEditor rules={rules} onChange={setRules} />
          </div>
        </div>

        {/* Right: height explicitly matches left panel so chat scrolls within it */}
        <div
          className="bg-white rounded-xl border border-gray-200 p-5 flex flex-col gap-4 overflow-hidden"
          style={leftHeight ? { height: leftHeight } : undefined}
        >
          <div>
            <h3 className="text-base font-semibold text-gray-900">AI Agent</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Ask the agent to analyze traffic, refine the policy, or explain its reasoning. It can run multiple analyses and call <span className="font-mono">update_policy</span> automatically.
            </p>
          </div>

          {/* Conversation history */}
          <div ref={chatContainerRef} className="flex-1 space-y-2 overflow-y-auto min-h-0">
            {displayEvents.length === 0 && (
              <p className="text-xs text-gray-400 italic">
                Try: "Analyze alice's traffic from last week and build a policy" or "Make write operations require LLM review"
              </p>
            )}
            {displayEvents.map((ev, i) => {
              if (ev.kind === 'user') return (
                <div key={i} className="text-sm bg-blue-50 text-blue-900 rounded-lg px-3 py-2 ml-8">{ev.content}</div>
              )
              if (ev.kind === 'assistant') return (
                <div key={i} className="text-sm text-gray-800 rounded-lg px-3 py-2 mr-8 whitespace-pre-wrap leading-relaxed">{ev.content}</div>
              )
              if (ev.kind === 'tool') {
                const isAnalyze = ev.tool === 'analyze_traffic'
                const inp = ev.input as Record<string, string> | undefined
                return (
                  <div key={i} className="text-xs px-2 space-y-1">
                    {/* Tool name + status */}
                    <div className="flex items-center gap-1.5 text-gray-500">
                      {ev.done
                        ? <span className="text-green-500">✓</span>
                        : <div className="animate-spin rounded-full h-2.5 w-2.5 border-b border-blue-500 shrink-0" />
                      }
                      <span className={`font-mono ${ev.done ? 'text-gray-400' : 'text-blue-600'}`}>{ev.tool}</span>
                    </div>

                    {/* Input params (analyze_traffic only) */}
                    {isAnalyze && inp && (
                      <div className="pl-4 text-gray-400 font-mono">
                        {inp.user_id} · {inp.start_date?.slice(0, 16).replace('T', ' ')} → {inp.end_date?.slice(0, 16).replace('T', ' ')}
                      </div>
                    )}

                    {/* Progress while running */}
                    {!ev.done && ev.progressMessage && (
                      <div className="pl-4 text-gray-400 space-y-0.5">
                        <div>{ev.progressMessage}</div>
                        {ev.completed != null && ev.total != null && (
                          <div className="w-full bg-gray-200 rounded-full h-0.5">
                            <div className="bg-blue-400 h-0.5 rounded-full transition-all duration-200" style={{ width: `${Math.round((ev.completed / ev.total) * 100)}%` }} />
                          </div>
                        )}
                      </div>
                    )}

                  </div>
                )
              }
              if (ev.kind === 'error') return (
                <div key={i} className="text-xs text-red-600 bg-red-50 rounded px-2 py-1">{ev.message}</div>
              )
              return null
            })}
            {agentRunning && (
              <div className="flex items-center gap-2 text-xs text-gray-500 px-2">
                <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-blue-500" />
                Thinking...
              </div>
            )}
            <div ref={conversationEndRef} />
          </div>

          {/* Input */}
          <div className="flex gap-2">
            <input
              className={inputClass + ' text-sm'}
              value={agentInput}
              onChange={(e) => setAgentInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleAgentSend() } }}
              placeholder="Ask the agent..."
            />
            <button onClick={handleAgentSend} disabled={agentRunning || !agentInput.trim()} className={btnPrimary + ' shrink-0'}>
              Send
            </button>
          </div>
        </div>
      </div>

      {/* Endpoint traffic context */}
      <EndpointViewer summaries={summaries} />
    </div>
  )
}

function EndpointViewer({ summaries }: { summaries: import('../types').PolicyEndpointSummary[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold text-gray-900">
          Traffic Context
          <span className="ml-2 text-sm font-normal text-gray-400">{summaries.length} endpoints</span>
        </h3>
        <p className="text-xs text-gray-400">Ask the agent to "remove [pattern]" to exclude endpoints</p>
      </div>
      {summaries.length === 0 && (
        <p className="text-xs text-gray-400 italic">
          No traffic analyzed yet. Ask the agent to analyze traffic for a user.
        </p>
      )}
      <div className="divide-y divide-gray-100">
        {summaries.map((s, i) => (
          <div key={i}>
            <button
              className="w-full flex items-center gap-3 py-2 text-xs text-left hover:bg-gray-50 rounded px-2 -mx-2 transition-colors"
              onClick={() => setExpanded(expanded === i ? null : i)}
            >
              <span className="font-mono font-semibold text-blue-600 w-14 shrink-0">{s.method}</span>
              <span className="font-mono text-gray-600 flex-1 truncate">{s.path_pattern}</span>
              <span className="text-gray-400 shrink-0 tabular-nums">{s.count.toLocaleString()} calls</span>
              <span className="text-gray-300 shrink-0">{expanded === i ? '▴' : '▾'}</span>
            </button>
            {expanded === i && (
              <div className="text-xs text-gray-600 px-2 pb-3 prose prose-xs max-w-none
                [&_p]:my-1 [&_ul]:my-1 [&_ul]:pl-4 [&_li]:my-0.5
                [&_strong]:font-semibold [&_strong]:text-gray-700">
                <ReactMarkdown>{s.description}</ReactMarkdown>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ---- Published view sub-components (unchanged from before) ----

function StatCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4">
      <div className={`text-2xl font-bold ${color ?? 'text-gray-900'}`}>{value}</div>
      <div className="text-sm text-gray-500 mt-0.5">{label}</div>
    </div>
  )
}

const DECISION_COLORS: Record<string, { bar: string; badge: string; text: string }> = {
  approved: { bar: 'bg-green-500', badge: 'bg-green-100 text-green-700', text: 'text-green-600' },
  denied:   { bar: 'bg-red-400',   badge: 'bg-red-100 text-red-700',     text: 'text-red-500'   },
  timeout:  { bar: 'bg-yellow-400', badge: 'bg-yellow-100 text-yellow-700', text: 'text-yellow-600' },
}

function DecisionSection({ decision, stats, total }: {
  decision: string
  stats: { count: number; avg_duration_ms: number; p50_duration_ms: number; p95_duration_ms: number; p99_duration_ms: number; by_approver: { approved_by: string; count: number; avg_duration_ms: number }[] }
  total: number
}) {
  const colors = DECISION_COLORS[decision] ?? { bar: 'bg-gray-400', badge: 'bg-gray-100 text-gray-700', text: 'text-gray-600' }
  const pct = total > 0 ? Math.round((stats.count / total) * 100) : 0
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize ${colors.badge}`}>{decision}</span>
          <span className={`text-xl font-bold ${colors.text}`}>{stats.count}</span>
          <span className="text-sm text-gray-400">({pct}%)</span>
        </div>
        <div className="flex items-center gap-3 text-sm text-gray-500">
          <span>avg {stats.avg_duration_ms}ms</span>
          <span className="text-gray-300">|</span>
          <span>p50 {stats.p50_duration_ms}ms</span>
          <span>p95 {stats.p95_duration_ms}ms</span>
          <span>p99 {stats.p99_duration_ms}ms</span>
        </div>
      </div>
      <div className="h-1.5 rounded-full bg-gray-100">
        <div className={`h-full rounded-full ${colors.bar}`} style={{ width: `${pct}%` }} />
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-gray-400 border-b border-gray-100">
            <th className="text-left pb-1 font-medium">Approver</th>
            <th className="text-right pb-1 font-medium">Count</th>
            <th className="text-right pb-1 font-medium">Avg duration</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {stats.by_approver.map((a) => (
            <tr key={a.approved_by || '—'}>
              <td className="py-1 text-gray-700 font-mono">{a.approved_by || <em className="text-gray-400 not-italic">—</em>}</td>
              <td className="py-1 text-right text-gray-700">{a.count}</td>
              <td className="py-1 text-right text-gray-500">{a.avg_duration_ms}ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TimeSeriesChart({ data }: { data: TimeSeriesBucket[] }) {
  if (data.length === 0) return <p className="text-gray-400 text-sm italic">No time-series data in the last 30 days.</p>
  const chartHeight = 120
  const maxTotal = Math.max(...data.map((d) => d.total), 1)
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-4">
      <div className="flex items-end gap-px" style={{ height: chartHeight }}>
        {data.map((d) => {
          const barH = (d.total / maxTotal) * chartHeight
          const approvedH = d.total > 0 ? (d.approved / d.total) * barH : 0
          const deniedH = d.total > 0 ? (d.denied / d.total) * barH : 0
          const timeoutH = d.total > 0 ? (d.timeout / d.total) * barH : 0
          const otherH = Math.max(0, barH - approvedH - deniedH - timeoutH)
          return (
            <div key={d.bucket} className="flex-1 flex flex-col justify-end group relative" style={{ minWidth: 0 }}>
              <div className="absolute bottom-full mb-1 left-1/2 -translate-x-1/2 hidden group-hover:block z-10 bg-gray-800 text-white text-xs rounded px-2 py-1 whitespace-nowrap">
                {format(new Date(d.bucket), 'MMM dd')} — {d.total} req, avg {d.avg_duration_ms}ms
              </div>
              {otherH > 0 && <div className="bg-gray-300 rounded-t-sm" style={{ height: otherH }} />}
              {timeoutH > 0 && <div className="bg-yellow-400" style={{ height: timeoutH }} />}
              {deniedH > 0 && <div className="bg-red-400" style={{ height: deniedH }} />}
              {approvedH > 0 && <div className="bg-green-500 rounded-b-sm" style={{ height: approvedH }} />}
            </div>
          )
        })}
      </div>
      <div className="flex justify-between text-xs text-gray-400 mt-1">
        <span>{format(new Date(data[0].bucket), 'MMM dd')}</span>
        <span>{format(new Date(data[data.length - 1].bucket), 'MMM dd')}</span>
      </div>
      <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
        <span className="flex items-center gap-1"><span className="inline-block w-2 h-2 rounded-sm bg-green-500" /> Approved</span>
        <span className="flex items-center gap-1"><span className="inline-block w-2 h-2 rounded-sm bg-red-400" /> Denied</span>
        <span className="flex items-center gap-1"><span className="inline-block w-2 h-2 rounded-sm bg-yellow-400" /> Timeout</span>
      </div>
    </div>
  )
}

function RecentDecisions({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) return <p className="text-gray-400 text-sm italic">No LLM reasoning recorded yet.</p>
  return (
    <div className="space-y-2">
      {entries.map((e, i) => {
        const colors = DECISION_COLORS[e.decision] ?? { badge: 'bg-gray-100 text-gray-700' }
        return (
          <div key={i} className="rounded-lg border border-gray-100 bg-gray-50 p-3 text-sm">
            <div className="flex items-center gap-2 mb-1">
              <span className={`px-1.5 py-0.5 rounded text-xs font-semibold ${colors.badge}`}>{e.decision}</span>
              <span className="text-gray-500 text-xs font-mono truncate max-w-sm">{e.method} {e.url}</span>
              <span className="ml-auto text-gray-400 text-xs shrink-0">{format(new Date(e.timestamp), 'MMM dd HH:mm')}</span>
            </div>
            {e.llm_reason && <p className="text-gray-700 text-xs leading-relaxed">{e.llm_reason}</p>}
          </div>
        )
      })}
    </div>
  )
}

const evalStatusPillClass: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  running: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  failed: 'bg-red-100 text-red-700',
}

function RecentEvalRuns({ policyId }: { policyId: string }) {
  const [runs, setRuns] = useState<EvalRun[]>([])
  const navigate = useNavigate()
  useEffect(() => { listEvalRuns(policyId, 3, 0).then(setRuns).catch(() => {}) }, [policyId])
  if (runs.length === 0) return <p className="text-sm text-gray-400 italic">No runs yet.</p>
  return (
    <table className="w-full text-sm">
      <tbody className="divide-y divide-gray-100">
        {runs.map((run) => (
          <tr key={run.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => navigate(`/evals/${run.id}`)}>
            <td className="py-2 pr-4">
              <span className={`px-2 py-0.5 rounded text-xs font-semibold ${evalStatusPillClass[run.status] ?? 'bg-gray-100 text-gray-700'}`}>{run.status}</span>
            </td>
            <td className="py-2 pr-4 text-gray-700">{run.total} total · {run.agreed} agreed</td>
            <td className="py-2 text-gray-400 text-xs">{format(new Date(run.created_at), 'MMM dd HH:mm')}</td>
            <td className="py-2 pl-4 text-gray-400 text-xs">→</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

const toDatetimeLocal = (d: Date) => {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function RunEvalModal({ policyId, policyName, onClose, onCreated }: {
  policyId: string; policyName: string; onClose: () => void; onCreated: (runId: string) => void
}) {
  const [users, setUsers] = useState<UserSummary[]>([])
  const [decision, setDecision] = useState('')
  const [userId, setUserId] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endTime, setEndTime] = useState('')
  const [limit, setLimit] = useState(1000)
  const [submitting, setSubmitting] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => { getUsers().then(setUsers).catch(() => {}) }, [])
  const applyRange = (days: number) => {
    const now = new Date()
    const end = new Date(now.getTime() + 60_000)
    const start = new Date(now)
    if (days === 0) start.setHours(0, 0, 0, 0)
    else start.setDate(start.getDate() - days)
    setStartTime(toDatetimeLocal(start))
    setEndTime(toDatetimeLocal(end))
  }
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setErr(null)
    try {
      const filter: EvalFilter = { limit }
      if (decision) filter.decision = decision
      if (userId) filter.user_id = userId
      if (startTime) filter.start_time = parseDatetimeLocal(startTime).toISOString()
      if (endTime) filter.end_time = parseDatetimeLocal(endTime).toISOString()
      const run = await createEvalRun(policyId, filter)
      onCreated(run.id)
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create eval run')
      setSubmitting(false)
    }
  }
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">Run Eval</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none">&times;</button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Policy</label>
            <div className="px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm text-gray-700">{policyName}</div>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Decision filter</label>
            <select className={inputClass} value={decision} onChange={(e) => setDecision(e.target.value)}>
              <option value="">All</option>
              <option value="approved">Approved only</option>
              <option value="denied">Denied only</option>
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">User (optional)</label>
            <select className={inputClass} value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">All users</option>
              {users.map((u) => <option key={u.id} value={u.id}>{u.id}</option>)}
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Date range</label>
            <div className="flex flex-wrap gap-1 mb-2">
              {[{ label: 'Today', days: 0 }, { label: 'Last 3 days', days: 3 }, { label: 'Last 7 days', days: 7 }, { label: 'Last 30 days', days: 30 }].map(({ label, days }) => (
                <button key={label} type="button" onClick={() => applyRange(days)} className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 text-gray-600">{label}</button>
              ))}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <input type="datetime-local" className={inputClass} value={startTime} onChange={(e) => setStartTime(e.target.value)} />
              <input type="datetime-local" className={inputClass} value={endTime} onChange={(e) => setEndTime(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-gray-700">Limit</label>
            <input type="number" className={inputClass} value={limit} min={1} max={100000} onChange={(e) => setLimit(Number(e.target.value))} />
          </div>
          {err && <p className="text-red-600 text-sm">{err}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className={btnSecondary} onClick={onClose}>Cancel</button>
            <button type="submit" className={btnPrimary} disabled={submitting}>{submitting ? 'Creating…' : 'Run Eval'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- Published view ----

function PublishedView({ policy, onDeleted }: { policy: LLMPolicy; onDeleted: () => void }) {
  const navigate = useNavigate()
  const { allUsers: users } = useAuth()
  const [stats, setStats] = useState<PolicyStats | null>(null)
  const [recentEntries, setRecentEntries] = useState<AuditEntry[]>([])
  const [showRunEval, setShowRunEval] = useState(false)
  const [forking, setForking] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      getPolicyStats(policy.id),
      getAuditLog({ policy_id: policy.id, channel: 'llm', limit: 20 }),
    ]).then(([s, audit]) => {
      setStats(s)
      setRecentEntries(audit.entries)
    }).catch(() => {})
  }, [policy.id])

  const assignedUsers = users.filter((u) => u.llm_policy_id === policy.id)

  const handleForkAsDraft = async () => {
    setForking(true)
    try {
      const draft = await forkPolicy(policy.id, { name: `${policy.name} (draft)` })
      navigate(`/policies/${draft.id}`)
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to fork')
    } finally {
      setForking(false)
    }
  }

  const handleDelete = async () => {
    if (!window.confirm(`Delete policy "${policy.name}"? This cannot be undone.`)) return
    try {
      await deletePolicy(policy.id)
      onDeleted()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to delete policy')
    }
  }

  const decisionOrder = ['approved', 'denied', 'timeout']
  const sortedDecisions = stats ? [
    ...decisionOrder.filter((d) => stats.by_decision[d]),
    ...Object.keys(stats.by_decision).filter((d) => !decisionOrder.includes(d)),
  ] : []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate('/policies')} className={btnSecondary}>← Back</button>
        <h2 className="text-xl font-semibold text-gray-900 flex-1">{policy.name}</h2>
        <button onClick={handleForkAsDraft} disabled={forking} className={btnSecondary}>
          {forking ? 'Forking…' : 'Fork as Draft'}
        </button>
        <button
          onClick={handleDelete}
          disabled={assignedUsers.length > 0}
          title={assignedUsers.length > 0 ? 'Unassign users before deleting' : 'Delete policy'}
          className="px-4 py-2 border border-red-300 text-red-600 text-sm font-medium rounded-lg hover:bg-red-50 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Delete
        </button>
      </div>

      {deleteError && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
          {deleteError}
          <button className="ml-3 text-red-500 hover:text-red-700" onClick={() => setDeleteError(null)}>&times;</button>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Provider</span>
            <div className="font-medium mt-0.5">{policy.provider || <em className="text-gray-400 font-normal">gateway default</em>}</div>
          </div>
          <div>
            <span className="text-gray-500">Model</span>
            <div className="font-medium mt-0.5">{policy.model || <em className="text-gray-400 font-normal">gateway default</em>}</div>
          </div>
          <div>
            <span className="text-gray-500">Created</span>
            <div className="font-medium mt-0.5">{format(new Date(policy.created_at), 'MMM dd, yyyy')}</div>
          </div>
          {policy.forked_from && (
            <div>
              <span className="text-gray-500">Forked from</span>
              <div className="font-mono text-xs mt-0.5 text-gray-700">{policy.forked_from}</div>
            </div>
          )}
          {assignedUsers.length > 0 && (
            <div className="col-span-2">
              <span className="text-gray-500">Assigned users</span>
              <div className="mt-0.5 flex flex-wrap gap-1">
                {assignedUsers.map((u) => (
                  <span key={u.id} className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs font-mono">{u.id}</span>
                ))}
              </div>
            </div>
          )}
        </div>
        {policy.prompt && (
          <div>
            <div className="text-sm text-gray-500 mb-1">Prompt</div>
            <pre className="bg-gray-50 rounded-lg p-3 text-xs text-gray-800 whitespace-pre-wrap leading-relaxed border border-gray-100 max-h-48 overflow-y-auto">{policy.prompt}</pre>
          </div>
        )}
        {policy.static_rules && policy.static_rules.length > 0 && (
          <div>
            <div className="text-sm text-gray-500 mb-1">Static Rules</div>
            <StaticRulesEditor rules={policy.static_rules} readOnly />
          </div>
        )}
      </div>

      {stats && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatCard label="Total Requests" value={stats.total} />
            <StatCard label="Avg Duration" value={`${stats.avg_duration_ms}ms`} />
            <StatCard label="p50 Latency" value={`${stats.p50_duration_ms}ms`} />
            <StatCard label="p95 Latency" value={`${stats.p95_duration_ms}ms`} />
            <StatCard label="p99 Latency" value={`${stats.p99_duration_ms}ms`} />
            {sortedDecisions.map((d) => (
              <StatCard key={d} label={d.charAt(0).toUpperCase() + d.slice(1)} value={stats.by_decision[d].count} color={DECISION_COLORS[d]?.text} />
            ))}
          </div>
          {stats.total > 0 && (
            <div className="space-y-3">
              <h3 className="text-base font-semibold text-gray-800">Breakdown</h3>
              {sortedDecisions.map((d) => (
                <DecisionSection key={d} decision={d} stats={stats.by_decision[d]} total={stats.total} />
              ))}
            </div>
          )}
          {stats.time_series?.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-base font-semibold text-gray-800">Daily Volume (last 30 days)</h3>
              <TimeSeriesChart data={stats.time_series} />
            </div>
          )}
        </>
      )}

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold text-gray-800">Recent LLM Decisions</h3>
          <button onClick={() => navigate(`/audit?policy_id=${policy.id}`)} className="text-sm text-blue-600 hover:underline">View all →</button>
        </div>
        <RecentDecisions entries={recentEntries} />
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-gray-900">Eval Runs</h3>
            <p className="text-sm text-gray-500">Replay historical requests to measure policy quality.</p>
          </div>
          <button onClick={() => setShowRunEval(true)} className={btnPrimary}>Run Eval</button>
        </div>
        <RecentEvalRuns policyId={policy.id} />
        <Link to={`/evals?policy_id=${policy.id}`} className="text-sm text-blue-600 hover:underline">View all runs →</Link>
      </div>

      {showRunEval && (
        <RunEvalModal
          policyId={policy.id}
          policyName={policy.name}
          onClose={() => setShowRunEval(false)}
          onCreated={(runId) => navigate(`/evals/${runId}`)}
        />
      )}
    </div>
  )
}

// ---- Main component ----

export function PolicyDetail() {
  const { id: policyId } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const [policy, setPolicy] = useState<LLMPolicy | null>(null)
  const [metadata, setMetadata] = useState<import('../types').PolicyMetadata | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!policyId) return
    setLoading(true)
    getPolicy(policyId)
      .then((p) => {
        setPolicy(p)
        // Load metadata in series so the editor mounts only after both are ready.
        if (p.status === 'draft') {
          return getPolicyMetadata(policyId).then(setMetadata).catch(() => {})
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load policy'))
      .finally(() => setLoading(false))
  }, [policyId])

  const initialMessage = (location.state as { startAgentMessage?: string } | null)?.startAgentMessage

  if (loading) {
    return <div className="flex justify-center py-12"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" /></div>
  }
  if (error || !policy) {
    return <p className="text-red-600 text-sm">{error ?? 'Policy not found'}</p>
  }

  if (policy.status === 'draft') {
    return (
      <DraftEditor
        key={policy.id}
        policy={policy}
        metadata={metadata}
        initialMessage={initialMessage ?? undefined}
        onSaved={setPolicy}
        onPublished={setPolicy}
        onDeleted={() => navigate('/policies')}
      />
    )
  }

  return (
    <PublishedView
      policy={policy}
      onDeleted={() => navigate('/policies')}
    />
  )
}
