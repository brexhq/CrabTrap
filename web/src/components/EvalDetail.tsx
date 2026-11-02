import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { getEvalRun, listEvalResults, upsertLabel, deleteLabel, getPolicy, getAuditEntry, getLLMResponse, getEvalRunStats, cancelEvalRun } from '../api/client'
import { RunEvalModal } from './EvalsPanel'
import type { SavedEvalFilter } from './EvalsPanel'
import type { EvalResultFilter, EvalRunStats } from '../api/client'
import type { EvalRun, EvalResult, LLMPolicy, AuditEntry, LLMResponse } from '../types'
import { format } from 'date-fns'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'

const btnPrimary = 'px-3 py-1 bg-blue-600 text-white text-xs font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnSecondary = 'px-3 py-1 border border-gray-300 text-gray-700 text-xs font-medium rounded-lg hover:bg-gray-50'

function StatusPill({ status }: { status: EvalRun['status'] }) {
  if (status === 'pending') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-700">pending</span>
  if (status === 'running') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-blue-100 text-blue-700">
      <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
      running
    </span>
  )
  if (status === 'completed') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-700">completed</span>
  if (status === 'canceled') return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-100 text-orange-700">canceled</span>
  return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">failed</span>
}

function MethodBadge({ method }: { method?: string }) {
  if (!method) return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-600">—</span>
  const colors: Record<string, string> = {
    POST: 'bg-blue-100 text-blue-800',
    PUT: 'bg-yellow-100 text-yellow-800',
    PATCH: 'bg-orange-100 text-orange-800',
    DELETE: 'bg-red-100 text-red-800',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${colors[method] ?? 'bg-gray-100 text-gray-800'}`}>
      {method}
    </span>
  )
}

// ---- Inline Label Editor ----

function LabelEditor({
  result,
  onLabelChanged,
}: {
  result: EvalResult
  onLabelChanged: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [selectedDecision, setSelectedDecision] = useState<'ALLOW' | 'DENY' | ''>('')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)

  const hasLabel = !!result.label_decision

  const startEdit = () => {
    setSelectedDecision((result.label_decision as 'ALLOW' | 'DENY') ?? '')
    setNote(result.label_note ?? '')
    setEditing(true)
  }

  const save = async () => {
    if (!selectedDecision) return
    setSaving(true)
    try {
      await upsertLabel(result.entry_id, selectedDecision, note)
      onLabelChanged()
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    setSaving(true)
    try {
      await deleteLabel(result.entry_id)
      onLabelChanged()
    } finally {
      setSaving(false)
    }
  }

  if (editing) {
    return (
      <div className="flex items-center gap-1 flex-wrap">
        <button
          onClick={() => setSelectedDecision('ALLOW')}
          className={`px-2 py-0.5 rounded text-xs font-semibold border ${selectedDecision === 'ALLOW' ? 'bg-green-600 text-white border-green-600' : 'border-gray-300 text-gray-700 hover:bg-gray-50'}`}
        >
          Allow
        </button>
        <button
          onClick={() => setSelectedDecision('DENY')}
          className={`px-2 py-0.5 rounded text-xs font-semibold border ${selectedDecision === 'DENY' ? 'bg-red-600 text-white border-red-600' : 'border-gray-300 text-gray-700 hover:bg-gray-50'}`}
        >
          Deny
        </button>
        <input
          className="border border-gray-300 rounded px-2 py-0.5 text-xs w-32 focus:outline-none focus:ring-1 focus:ring-blue-500"
          placeholder="note (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <button className={btnPrimary} onClick={save} disabled={saving || !selectedDecision}>Save</button>
        <button className={btnSecondary} onClick={() => setEditing(false)}>Cancel</button>
      </div>
    )
  }

  if (hasLabel) {
    const isAllow = result.label_decision === 'ALLOW'
    return (
      <div className="inline-flex items-center gap-1 group">
        <Tooltip>
          <TooltipTrigger asChild>
            <span className={`px-2 py-0.5 rounded text-xs font-semibold cursor-default ${isAllow ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              {isAllow ? '✓ ALLOW' : '✓ DENY'}
            </span>
          </TooltipTrigger>
          {result.label_note && (
            <TooltipContent>
              {result.label_note}
            </TooltipContent>
          )}
        </Tooltip>
        <button
          className="text-xs text-blue-600 hover:underline opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={startEdit}
        >
          Edit
        </button>
        <button
          className="text-xs text-red-500 hover:underline opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={remove}
          disabled={saving}
        >
          ×
        </button>
      </div>
    )
  }

  return (
    <button
      className="text-xs text-blue-600 hover:underline whitespace-nowrap"
      onClick={startEdit}
    >
      + Label
    </button>
  )
}

// ---- AuditEntryPanel ----

function LLMResponseMeta({ lr }: { lr: LLMResponse }) {
  const parts = [lr.model, `${lr.duration_ms}ms`]
  if (lr.input_tokens) parts.push(`${lr.input_tokens} in / ${lr.output_tokens} out tokens`)
  return <span className="text-xs italic text-gray-400 font-normal">({parts.join(' · ')})</span>
}

function AuditEntryPanel({ entryId, result }: { entryId: string; result: EvalResult }) {
  const [entry, setEntry] = useState<AuditEntry | null>(null)
  const [origLLM, setOrigLLM] = useState<LLMResponse | null>(null)
  const [evalLLM, setEvalLLM] = useState<LLMResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    getAuditEntry(entryId)
      .then(e => {
        setEntry(e)
        if (e.llm_response_id) {
          getLLMResponse(e.llm_response_id).then(setOrigLLM).catch(() => {})
        }
      })
      .catch(() => setEntry(null))
      .finally(() => setLoading(false))
    if (result.llm_response_id) {
      getLLMResponse(result.llm_response_id).then(setEvalLLM).catch(() => {})
    }
  }, [entryId, result.llm_response_id])

  if (loading) return <div className="py-4 text-center text-xs text-gray-400">Loading…</div>
  if (!entry) return <div className="py-4 text-center text-xs text-red-400">Failed to load entry.</div>

  const fmtBody = (body?: string) => {
    if (!body) return <span className="text-gray-400">(empty)</span>
    if (body.trim().startsWith('{') || body.trim().startsWith('[')) {
      try {
        return <pre className="text-xs overflow-x-auto">{JSON.stringify(JSON.parse(body), null, 2)}</pre>
      } catch {}
    }
    return <pre className="text-xs overflow-x-auto whitespace-pre-wrap break-words">{body}</pre>
  }

  const fmtHeaders = (h?: Record<string, string[]>) => {
    if (!h || Object.keys(h).length === 0) return <span className="text-gray-400">(none)</span>
    return Object.entries(h).map(([k, vs]) => (
      <div key={k} className="mb-0.5">
        <span className="font-semibold text-gray-700">{k}:</span>{' '}
        <span className="text-gray-600">{vs.join(', ')}</span>
      </div>
    ))
  }

  const originalDecisionIsAllow = entry.decision === 'approved'
  const replayIsAllow = result.replay_decision === 'ALLOW'
  const replayIsError = result.replay_decision === 'ERROR'

  return (
    <div className="bg-gray-50 border-t border-gray-100 px-4 py-4 space-y-4 text-sm">
      {/* Metadata */}
      <div className="text-xs text-gray-500 space-y-1.5">
        <div className="font-mono break-all"><span className="font-medium text-gray-700 font-sans">URL:</span> {entry.url}</div>
        <div className="flex gap-6">
          <div><span className="font-medium text-gray-700">User:</span> {entry.user_id || '—'}</div>
          <div><span className="font-medium text-gray-700">Duration:</span> {entry.duration_ms}ms</div>
          <div><span className="font-medium text-gray-700">Request ID:</span> <span className="font-mono">{entry.request_id}</span></div>
        </div>
      </div>

      {/* Request */}
      <div className="space-y-2">
        <div className="text-xs font-semibold text-gray-700">Request</div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="text-xs text-gray-500 mb-1">Headers</div>
            <div className="bg-white border border-gray-200 rounded p-2 max-h-36 overflow-y-auto text-xs">
              {fmtHeaders(entry.request_headers)}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 mb-1">Body</div>
            <div className="bg-white border border-gray-200 rounded p-2 max-h-36 overflow-y-auto">
              {fmtBody(entry.request_body)}
            </div>
          </div>
        </div>
      </div>

      {/* Decision comparison */}
      <div className="grid grid-cols-2 gap-4">
        {/* Original decision */}
        <div className="bg-white border border-gray-200 rounded-lg p-3 space-y-2">
          <div className="text-xs font-semibold text-gray-700">Original Decision</div>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${originalDecisionIsAllow ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              {originalDecisionIsAllow ? 'ALLOW' : 'DENY'}
            </span>
            {entry.approved_by && (
              <span className="text-xs text-gray-500">via <span className="font-medium">{entry.approved_by}</span></span>
            )}
          </div>
          {origLLM && <div className="mt-0.5"><LLMResponseMeta lr={origLLM} /></div>}
          {entry.approved_by === 'jev' && !result.label_decision && (
            <p className="text-xs text-amber-700">Decided by Jev. Agreement compares the replay against Jev's decision. Replay checks static rules first, then uses the LLM if no rule matches.</p>
          )}
          {(entry.llm_reason || origLLM?.reason) ? (
            <p className="text-xs text-gray-600 leading-relaxed">{entry.llm_reason || origLLM?.reason}</p>
          ) : (
            <p className="text-xs text-gray-400 italic">No LLM reasoning recorded.</p>
          )}
        </div>

        {/* Eval replay decision */}
        <div className="bg-white border border-gray-200 rounded-lg p-3 space-y-2">
          <div className="text-xs font-semibold text-gray-700">Eval Replay Decision</div>
          <div className="flex items-center gap-1.5">
            {replayIsError
              ? <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-600">ERROR</span>
              : replayIsAllow
                ? <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-700">ALLOW</span>
                : <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">DENY</span>
            }
            {result.approved_by === 'llm-static-rule' && (
              <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-600">static rule</span>
            )}
          </div>
          {evalLLM && <div className="mt-0.5"><LLMResponseMeta lr={evalLLM} /></div>}
          {result.approved_by === 'llm-static-rule' ? (
            <p className="text-xs text-gray-500 italic">Decided by static rule rule — no LLM evaluation needed.</p>
          ) : (result.replay_reason || evalLLM?.reason) ? (
            <p className="text-xs text-gray-600 leading-relaxed">{result.replay_reason || evalLLM?.reason}</p>
          ) : evalLLM?.raw_output ? (
            <details className="text-xs text-gray-500">
              <summary className="cursor-pointer italic text-gray-400 hover:text-gray-600 select-none">Error — expand for raw output</summary>
              <pre className="mt-1 bg-gray-50 rounded p-2 text-xs font-mono whitespace-pre-wrap break-all border border-gray-200">{evalLLM.raw_output}</pre>
            </details>
          ) : (
            <p className="text-xs text-gray-400 italic">
              No reasoning recorded.
              {!result.llm_response_id && ' (LLM was not called — check gateway logs for eval.RunEval errors)'}
            </p>
          )}
        </div>
      </div>

    </div>
  )
}

// ---- EvalDetail ----

export function EvalDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const [run, setRun] = useState<EvalRun | null>(null)
  const [policy, setPolicy] = useState<LLMPolicy | null>(null)
  const [results, setResults] = useState<EvalResult[]>([])
  const [filteredTotal, setFilteredTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [filter, setFilter] = useState<EvalResultFilter>({})
  const [urlInput, setUrlInput] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<EvalRunStats | null>(null)
  const [showRepeatModal, setShowRepeatModal] = useState(false)
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null)
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const PAGE = 100

  const fetchRun = useCallback(async () => {
    if (!id) return null
    try {
      const r = await getEvalRun(id)
      setRun(r)
      return r
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load eval run')
      return null
    }
  }, [id])

  const fetchResults = useCallback(async (f: EvalResultFilter = {}) => {
    if (!id) return
    try {
      const resp = await listEvalResults(id, PAGE, 0, f)
      setResults(resp.results)
      setFilteredTotal(resp.total)
      setOffset(resp.results.length)
    } catch {}
  }, [id])

  // Refresh stats every 10s while running
  useEffect(() => {
    if (!id || !run) return
    if (run.status !== 'pending' && run.status !== 'running') return
    const interval = setInterval(() => {
      getEvalRunStats(id).then(setStats).catch(() => {})
    }, 5_000)
    return () => clearInterval(interval)
  }, [id, run?.status])

  // Poll while running/pending; re-fetch results when run completes
  useEffect(() => {
    if (!run) return
    if (run.status !== 'pending' && run.status !== 'running') return

    const poll = async () => {
      const [updated] = await Promise.all([fetchRun(), fetchResults(filter)])
      if (!updated) return
      if (updated.status === 'pending' || updated.status === 'running') {
        pollTimerRef.current = setTimeout(poll, 2000)
      } else if (updated.status === 'completed' && id) {
        getEvalRunStats(id).then(setStats).catch(() => {})
      }
    }
    pollTimerRef.current = setTimeout(poll, 2000)

    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
    }
  }, [run?.status, fetchRun, fetchResults, filter])

  // Initial load
  useEffect(() => {
    if (!id) return
    let cancelled = false
    const load = async () => {
      setLoading(true)
      try {
        const r = await getEvalRun(id)
        if (cancelled) return
        setRun(r)
        const [pol, resp, runStats] = await Promise.all([
          getPolicy(r.policy_id).catch(() => null),
          listEvalResults(id, PAGE, 0, {}),
          getEvalRunStats(id).catch(() => null),
        ])
        if (cancelled) return
        setPolicy(pol)
        setResults(resp.results)
        setFilteredTotal(resp.total)
        setOffset(resp.results.length)
        if (runStats) setStats(runStats)
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [id])

  // Debounce URL input into the filter (300ms)
  useEffect(() => {
    const t = setTimeout(() => {
      const newFilter = { ...filter, url: urlInput || undefined }
      setFilter(newFilter)
      setExpandedEntryId(null)
      fetchResults(newFilter)
    }, 300)
    return () => clearTimeout(t)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlInput])

  // Re-fetch when non-URL filter changes
  const applyFilter = (newFilter: EvalResultFilter) => {
    setFilter(newFilter)
    setExpandedEntryId(null)
    fetchResults(newFilter)
  }

  const clearFilter = () => {
    setUrlInput('')
    applyFilter({})
  }

  const hasActiveFilter = Object.values(filter).some((v) => v !== undefined) || urlInput !== ''

  const loadMore = async () => {
    if (!id) return
    setLoadingMore(true)
    try {
      const resp = await listEvalResults(id, PAGE, offset, filter)
      setResults((prev) => [...prev, ...resp.results])
      setFilteredTotal(resp.total)
      setOffset((prev) => prev + resp.results.length)
    } finally {
      setLoadingMore(false)
    }
  }

  const refreshRun = () => {
    if (id) fetchRun()
  }

  const refreshResult = (entryId: string, updates: Partial<EvalResult>) => {
    setResults((prev) =>
      prev.map((r) => (r.entry_id === entryId ? { ...r, ...updates } : r))
    )
    refreshRun()
  }

  const handleLabelChanged = (result: EvalResult) => async () => {
    // Re-fetch the result to get latest label info
    if (!id) return
    try {
      const resp = await listEvalResults(id, PAGE, 0, filter)
      const updated = resp.results.find((r) => r.entry_id === result.entry_id)
      if (updated) {
        refreshResult(result.entry_id, { label_decision: updated.label_decision, label_note: updated.label_note })
      } else {
        refreshResult(result.entry_id, { label_decision: undefined, label_note: undefined })
      }
    } catch {}
    fetchRun()
  }

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  if (error || !run) {
    return <p className="text-red-600 text-sm">{error ?? 'Eval run not found'}</p>
  }

  const isRunning = run.status === 'pending' || run.status === 'running'
  const progressPct = isRunning && run.total_entries > 0
    ? Math.round((run.total / run.total_entries) * 100)
    : null

  const nonErrored = run.total - run.errored
  const agreePct = nonErrored > 0 ? Math.round((run.agreed / nonErrored) * 100) : 0
  const disagreePct = nonErrored > 0 ? Math.round((run.disagreed / nonErrored) * 100) : 0
  const errorPct = run.total > 0 ? Math.round((run.errored / run.total) * 100) : 0
  const labeledPct = run.total > 0 ? Math.round((run.labeled / run.total) * 100) : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <button onClick={() => navigate('/evals')} className="px-4 py-2 border border-gray-300 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50">
          ← Back
        </button>
        <div className="flex-1 min-w-0 flex items-center gap-3 flex-wrap">
          <span className="text-sm text-gray-500">Policy:</span>
          {policy && !policy.deleted_at ? (
            <Link to={`/policies/${run.policy_id}`} className="text-sm text-blue-600 hover:underline font-medium">
              {policy.name}
            </Link>
          ) : (
            <span className="text-sm font-medium text-gray-600">
              {policy?.name || run.policy_name || run.policy_id}
              <span className="ml-1.5 px-1.5 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-500">deleted</span>
            </span>
          )}
          <StatusPill status={run.status} />
        </div>
        <span className="text-xs text-gray-400">{format(new Date(run.created_at), 'MMM dd, yyyy HH:mm')}</span>
        {isRunning && (
          <button
            onClick={() => cancelEvalRun(run.id).catch(() => {})}
            className="px-3 py-1 border border-red-300 text-red-600 text-xs font-medium rounded-lg hover:bg-red-50"
          >
            ■ Stop
          </button>
        )}
        <button onClick={() => setShowRepeatModal(true)} className={btnSecondary}>
          ↺ Repeat
        </button>
      </div>

      {showRepeatModal && (() => {
        let savedFilter: SavedEvalFilter | undefined
        try {
          const raw = localStorage.getItem(`eval-filter-${run.id}`)
          if (raw) savedFilter = JSON.parse(raw)
        } catch {}
        return (
          <RunEvalModal
            policyId={run.policy_id}
            policyName={policy?.name || run.policy_name}
            initialFilter={savedFilter}
            onClose={() => setShowRepeatModal(false)}
            onCreated={(newRunId) => { setShowRepeatModal(false); navigate(`/evals/${newRunId}`) }}
          />
        )
      })()}

      {run.error && (
        <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-sm text-red-700">
          {run.error}
        </div>
      )}

      {/* Summary card */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 text-center">
          <div>
            <div className="text-3xl font-bold text-gray-900">
              {isRunning && run.total_entries > 0
                ? <>{run.total}<span className="text-xl font-medium text-gray-400"> / {run.total_entries}</span></>
                : run.total}
            </div>
            <div className="text-xs text-gray-500 mt-0.5">
              {progressPct !== null ? `${progressPct}% complete` : 'Total'}
            </div>
          </div>
          <div>
            <div className="text-3xl font-bold text-green-600">{run.agreed}</div>
            <div className="text-xs text-gray-500 mt-0.5">Agreed ({agreePct}%)</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-red-500">{run.disagreed}</div>
            <div className="text-xs text-gray-500 mt-0.5">Disagreed ({disagreePct}%)</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-gray-400">{run.errored}</div>
            <div className="text-xs text-gray-500 mt-0.5">Errored ({errorPct}%)</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-blue-600">{run.labeled}</div>
            <div className="text-xs text-gray-500 mt-0.5">Labeled ({labeledPct}%)</div>
          </div>
        </div>
      </div>

      {/* Stats tables — shown whenever stats are loaded */}
      {stats && (() => {
        const fmtLat = (ms?: number) => ms != null ? `${ms}ms` : '—'
        const statsCols = 'px-3 py-2 text-right text-xs'
        const statsHead = 'px-3 py-2 text-right text-xs font-medium text-gray-500'

        return (
          <div className="space-y-4">
            {/* Table 1: breakdown by approver */}
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-100">
                <h3 className="text-sm font-semibold text-gray-700">Breakdown by approver</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Approver</th>
                      <th className={statsHead}>Total</th>
                      <th className={statsHead}>Agreed</th>
                      <th className={statsHead}>Disagreed</th>
                      <th className={statsHead}>Errored</th>
                      <th className={statsHead}>p50</th>
                      <th className={statsHead}>p95</th>
                      <th className={statsHead}>p99</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {stats.by_approved_by.map((row) => (
                      <tr key={row.approved_by} className="hover:bg-gray-50">
                        <td className="px-4 py-2 text-xs font-mono text-gray-700">{row.approved_by}</td>
                        <td className={statsCols}>{row.total}</td>
                        <td className={`${statsCols} text-green-700`}>{row.agreed}</td>
                        <td className={`${statsCols} text-red-600`}>{row.disagreed}</td>
                        <td className={`${statsCols} text-gray-400`}>{row.errored}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p50_ms)}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p95_ms)}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p99_ms)}</td>
                      </tr>
                    ))}
                    <tr className="bg-gray-50 font-semibold border-t border-gray-200">
                      <td className="px-4 py-2 text-xs text-gray-700">Total</td>
                      <td className={statsCols}>{stats.overall.total}</td>
                      <td className={`${statsCols} text-green-700`}>{stats.overall.agreed}</td>
                      <td className={`${statsCols} text-red-600`}>{stats.overall.disagreed}</td>
                      <td className={`${statsCols} text-gray-400`}>{stats.overall.errored}</td>
                      <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.overall.p50_ms)}</td>
                      <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.overall.p95_ms)}</td>
                      <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.overall.p99_ms)}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Table 2: labeled entries */}
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-100">
                <h3 className="text-sm font-semibold text-gray-700">Labeled entries</h3>
                <p className="text-xs text-gray-400 mt-0.5">Agreement measured against human labels</p>
              </div>
              {stats.labeled_overall.labeled === 0 ? (
                <div className="py-8 text-center text-sm text-gray-400">No labeled entries — label results using the + Label button in the table below.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500">Approver</th>
                        <th className={statsHead}>Labeled</th>
                        <th className={statsHead}>Agreed w/ label</th>
                        <th className={statsHead}>Disagreed w/ label</th>
                        <th className={statsHead}>p50</th>
                        <th className={statsHead}>p95</th>
                        <th className={statsHead}>p99</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {stats.labeled_by_approved_by.map((row) => (
                        <tr key={row.approved_by} className="hover:bg-gray-50">
                          <td className="px-4 py-2 text-xs font-mono text-gray-700">{row.approved_by}</td>
                          <td className={statsCols}>{row.labeled}</td>
                          <td className={`${statsCols} text-green-700`}>{row.labeled_agreed}</td>
                          <td className={`${statsCols} text-red-600`}>{row.labeled_disagreed}</td>
                          <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p50_ms)}</td>
                          <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p95_ms)}</td>
                          <td className={`${statsCols} text-gray-600`}>{fmtLat(row.p99_ms)}</td>
                        </tr>
                      ))}
                      <tr className="bg-gray-50 font-semibold border-t border-gray-200">
                        <td className="px-4 py-2 text-xs text-gray-700">Total</td>
                        <td className={statsCols}>{stats.labeled_overall.labeled}</td>
                        <td className={`${statsCols} text-green-700`}>{stats.labeled_overall.labeled_agreed}</td>
                        <td className={`${statsCols} text-red-600`}>{stats.labeled_overall.labeled_disagreed}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.labeled_overall.p50_ms)}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.labeled_overall.p95_ms)}</td>
                        <td className={`${statsCols} text-gray-600`}>{fmtLat(stats.labeled_overall.p99_ms)}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )
      })()}

      {/* Filter bar */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 flex flex-wrap items-end gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Approved By</label>
          <select
            value={filter.approved_by ?? ''}
            onChange={(e) => applyFilter({ ...filter, approved_by: e.target.value || undefined })}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="llm">LLM</option>
            <option value="llm-static-rule">Static rule</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Replay Decision</label>
          <select
            value={filter.replay_decision ?? ''}
            onChange={(e) => applyFilter({ ...filter, replay_decision: e.target.value || undefined })}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Label</label>
          <select
            value={filter.has_label === undefined ? '' : String(filter.has_label)}
            onChange={(e) => applyFilter({ ...filter, has_label: e.target.value === '' ? undefined : e.target.value === 'true' })}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="true">Labeled</option>
            <option value="false">Unlabeled</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Match</label>
          <select
            value={filter.matched === undefined ? '' : String(filter.matched)}
            onChange={(e) => applyFilter({ ...filter, matched: e.target.value === '' ? undefined : e.target.value === 'true' })}
            className="border border-gray-300 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="true">Agreed</option>
            <option value="false">Disagreed</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">URL</label>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Search URL…"
            className="border border-gray-300 rounded px-2 py-1.5 text-sm w-48 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
        {hasActiveFilter && (
          <button onClick={clearFilter} className={btnSecondary}>
            Clear
          </button>
        )}
        {filteredTotal > 0 && (
          <span className="ml-auto text-xs text-gray-400">{filteredTotal} result{filteredTotal !== 1 ? 's' : ''}</span>
        )}
      </div>

      {/* Results table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {results.length === 0 && run.status === 'completed' ? (
          <div className="py-10 text-center text-sm text-gray-400">No results.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="text-left px-4 py-3 font-medium text-gray-600">Method</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-600">URL</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-600">Original</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-600">Replay</th>
                  <th className="text-center px-4 py-3 font-medium text-gray-600">Match</th>
                  <th className="text-left px-4 py-3 font-medium text-gray-600">Label</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {results.map((r) => {
                  const originalIsAllow = r.original_decision === 'approved'
                  const replayIsAllow = r.replay_decision === 'ALLOW'
                  const replayIsError = r.replay_decision === 'ERROR'
                  const matched = !replayIsError && (
                    (originalIsAllow && replayIsAllow) ||
                    (!originalIsAllow && !replayIsAllow && !replayIsError)
                  )
                  const isExpanded = expandedEntryId === r.entry_id

                  return (
                    <>
                      <tr
                        key={r.id}
                        className={`cursor-pointer ${isExpanded ? 'bg-blue-50' : 'hover:bg-gray-50'}`}
                        onClick={() => setExpandedEntryId(isExpanded ? null : r.entry_id)}
                      >
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <MethodBadge method={r.method} />
                        </td>
                        <td className="px-4 py-2.5 text-gray-700 font-mono text-xs break-all">
                          {r.url ? r.url.split('?')[0] : '—'}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          {r.original_decision ? (
                            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${r.original_decision === 'approved' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                              {r.original_decision === 'approved' ? 'Allow' : 'Deny'}
                            </span>
                          ) : <span className="text-gray-400 text-xs">—</span>}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            {replayIsError
                              ? <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-600">ERROR</span>
                              : replayIsAllow
                                ? <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-100 text-green-700">ALLOW</span>
                                : <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">DENY</span>
                            }
                            {r.approved_by === 'llm-static-rule' && (
                              <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-600">static rule</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2.5 text-center">
                          {replayIsError
                            ? <span className="text-gray-400 text-sm">—</span>
                            : matched
                              ? <span className="text-green-600 font-bold">✓</span>
                              : <span className="text-red-500 font-bold">✗</span>
                          }
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <LabelEditor
                            result={r}
                            onLabelChanged={handleLabelChanged(r)}
                          />
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${r.id}-expanded`}>
                          <td colSpan={6} className="p-0">
                            <AuditEntryPanel entryId={r.entry_id} result={r} />
                          </td>
                        </tr>
                      )}
                    </>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {results.length < filteredTotal && (
          <div className="px-4 py-3 border-t border-gray-100 text-center">
            <button
              className="text-sm text-blue-600 hover:underline disabled:opacity-50"
              onClick={loadMore}
              disabled={loadingMore}
            >
              {loadingMore ? 'Loading…' : 'Load more'}
            </button>
          </div>
        )}

        {run.status === 'running' && results.length === 0 && (
          <div className="py-8 text-center text-sm text-gray-400">
            <div className="inline-flex items-center gap-2">
              <svg className="animate-spin h-4 w-4 text-blue-600" viewBox="0 0 24 24" fill="none"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
              Running eval…
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
