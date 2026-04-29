import { useState, useEffect, useRef, useCallback, Fragment } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuditLog } from '../hooks/useAuditLog'
import { getUsers, getPolicies, getLLMResponse, getAuditEntry } from '../api/client'
import { format } from 'date-fns'
import type { AuditEntry, UserSummary, LLMPolicy, LLMResponse } from '../types'

function LLMResponseBlock({ llmResponseId, fallbackReason }: { llmResponseId: string; fallbackReason?: string }) {
  const [llmResp, setLlmResp] = useState<LLMResponse | null>(null)

  useEffect(() => {
    getLLMResponse(llmResponseId).then(setLlmResp).catch(() => {})
  }, [llmResponseId])

  const reason = llmResp?.reason ?? fallbackReason

  return (
    <div className="mb-4 p-3 bg-purple-50 border border-purple-200 rounded">
      <div className="mb-1">
        <h4 className="text-sm font-semibold text-purple-900">
          LLM Judge{llmResp && (() => {
            const parts = [llmResp.model, `${llmResp.duration_ms}ms`]
            if (llmResp.input_tokens) parts.push(`${llmResp.input_tokens} in / ${llmResp.output_tokens} out tokens`)
            if (llmResp.result === 'error') parts.push('error')
            return <span className="text-xs italic font-normal text-purple-600 ml-1">({parts.join(' · ')})</span>
          })()}
        </h4>
      </div>
      {reason ? (
        <p className="text-xs text-purple-800 leading-relaxed">{reason}</p>
      ) : llmResp?.result === 'error' && llmResp.raw_output ? (
        <p className="text-xs text-red-700 font-mono leading-relaxed">{llmResp.raw_output}</p>
      ) : null}
    </div>
  )
}

const DEFAULT_COL_PCTS = [14, 14, 7, 30, 9, 18, 8]
const MIN_COL_WIDTH = 50

const toDatetimeLocal = (d: Date) => {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const quickRanges = [
  { label: 'Today', days: 0 },
  { label: '3 days', days: 3 },
  { label: '7 days', days: 7 },
  { label: '30 days', days: 30 },
]

export function AuditTrail() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const { entries, filters, loadedCount, loading, error, setFilters, loadMore, hasMore } = useAuditLog()
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [entryDetails, setEntryDetails] = useState<Record<string, AuditEntry>>({})
  const [detailLoading, setDetailLoading] = useState<Record<string, boolean>>({})
  const [detailErrors, setDetailErrors] = useState<Record<string, string>>({})
  const [users, setUsers] = useState<UserSummary[]>([])
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [columnWidths, setColumnWidths] = useState<number[]>([])
  const tableContainerRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef<{ colIndex: number; startX: number; startWidths: number[] } | null>(null)

  useEffect(() => {
    getUsers().then(setUsers).catch(() => {})
    getPolicies().then(setPolicies).catch(() => {})
  }, [])

  // Sync all URL params → Zustand store whenever the URL changes.
  useEffect(() => {
    setFilters({
      userId:     searchParams.get('user_id')     ?? undefined,
      method:     searchParams.get('method')      ?? undefined,
      decision:   searchParams.get('decision')    ?? undefined,
      approvedBy: searchParams.get('approved_by') ?? undefined,
      policyId:   searchParams.get('policy_id')   ?? undefined,
      startTime:  searchParams.get('start_time')  ?? undefined,
      endTime:    searchParams.get('end_time')     ?? undefined,
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams])

  const setParam = (key: string, value: string | undefined) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    }, { replace: true })
  }

  const clearAllParams = () => setSearchParams({}, { replace: true })

  const toggleExpanded = (entry: AuditEntry, rowId: string) => {
    if (expandedId === rowId) {
      setExpandedId(null)
      return
    }

    setExpandedId(rowId)
    const detailKey = entry.id ?? rowId
    if (!entry.id || entryDetails[detailKey] || detailLoading[detailKey]) return

    setDetailLoading(prev => ({ ...prev, [detailKey]: true }))
    setDetailErrors(prev => {
      const next = { ...prev }
      delete next[detailKey]
      return next
    })
    getAuditEntry(entry.id)
      .then(detail => {
        setEntryDetails(prev => ({ ...prev, [detailKey]: detail }))
      })
      .catch(err => {
        setDetailErrors(prev => ({
          ...prev,
          [detailKey]: err instanceof Error ? err.message : 'Failed to load audit entry',
        }))
      })
      .finally(() => {
        setDetailLoading(prev => ({ ...prev, [detailKey]: false }))
      })
  }

  useEffect(() => {
    if (tableContainerRef.current && columnWidths.length === 0) {
      const containerWidth = tableContainerRef.current.offsetWidth
      setColumnWidths(DEFAULT_COL_PCTS.map(pct => Math.round(containerWidth * pct / 100)))
    }
  }, [columnWidths.length])

  const onResizeStart = useCallback((e: React.MouseEvent, colIndex: number) => {
    e.preventDefault()
    e.stopPropagation()

    dragRef.current = { colIndex, startX: e.clientX, startWidths: [...columnWidths] }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'

    const onMouseMove = (ev: MouseEvent) => {
      if (!dragRef.current) return
      const { colIndex: ci, startX, startWidths } = dragRef.current
      const diff = ev.clientX - startX
      const nextCol = ci + 1

      const newWidth = Math.max(MIN_COL_WIDTH, startWidths[ci] + diff)
      const consumed = newWidth - startWidths[ci]

      setColumnWidths(prev => {
        const next = [...prev]
        next[ci] = newWidth
        if (nextCol < next.length) {
          next[nextCol] = Math.max(MIN_COL_WIDTH, startWidths[nextCol] - consumed)
        }
        return next
      })
    }

    const onMouseUp = () => {
      dragRef.current = null
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [columnWidths])

  const formatTimestamp = (timestamp: string) => {
    try {
      return format(new Date(timestamp), 'MMM dd, yyyy HH:mm:ss')
    } catch {
      return timestamp
    }
  }

  const getDecisionBadge = (decision: string, cacheHit: boolean) => {
    if (cacheHit) {
      return <span className="px-2 py-1 rounded text-xs font-semibold bg-green-100 text-green-800">Cache Hit</span>
    }

    switch (decision) {
      case 'approved':
        return <span className="px-2 py-1 rounded text-xs font-semibold bg-green-100 text-green-800">Approved</span>
      case 'denied':
        return <span className="px-2 py-1 rounded text-xs font-semibold bg-red-100 text-red-800">Denied</span>
      case 'timeout':
        return <span className="px-2 py-1 rounded text-xs font-semibold bg-yellow-100 text-yellow-800">Timeout</span>
      default:
        return <span className="px-2 py-1 rounded text-xs font-semibold bg-gray-100 text-gray-800">{decision}</span>
    }
  }

  const getMethodBadge = (method: string) => {
    const colors: Record<string, string> = {
      POST: 'bg-blue-100 text-blue-800',
      PUT: 'bg-yellow-100 text-yellow-800',
      PATCH: 'bg-orange-100 text-orange-800',
      DELETE: 'bg-red-100 text-red-800',
    }

    return (
      <span className={`px-2 py-1 rounded text-xs font-semibold ${colors[method] || 'bg-gray-100 text-gray-800'}`}>
        {method}
      </span>
    )
  }

  const formatHeaders = (headers?: Record<string, string[]>) => {
    if (!headers) return null
    return Object.entries(headers).map(([key, values]) => (
      <div key={key} className="mb-1">
        <span className="font-semibold text-gray-700">{key}:</span>{' '}
        <span className="text-gray-600">{values.join(', ')}</span>
      </div>
    ))
  }

  const formatBody = (body?: string, contentType?: string) => {
    if (!body) return <span className="text-gray-500">(empty)</span>

    // Check if it's JSON based on content type or try to parse
    const isJson = contentType?.toLowerCase().includes('application/json')

    if (isJson || body.trim().startsWith('{') || body.trim().startsWith('[')) {
      try {
        const parsed = JSON.parse(body)
        return <pre className="text-xs overflow-x-auto">{JSON.stringify(parsed, null, 2)}</pre>
      } catch {
        // Not valid JSON, display as-is
      }
    }

    return <pre className="text-xs overflow-x-auto whitespace-pre-wrap break-words">{body}</pre>
  }

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Audit Trail</h2>
        <p className="text-gray-600 mt-1">
          Complete history of all requests ({loadedCount}{hasMore ? '+' : ''} shown)
        </p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-6 flex flex-wrap items-end gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">User</label>
          <select
            value={filters.userId || ''}
            onChange={(e) => setParam('user_id', e.target.value || undefined)}
            className="border border-gray-300 rounded px-3 py-2 text-sm"
          >
            <option value="">All users</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>{u.id}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Method</label>
          <select
            value={filters.method || ''}
            onChange={(e) => setParam('method', e.target.value || undefined)}
            className="border border-gray-300 rounded px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Decision</label>
          <select
            value={filters.decision || ''}
            onChange={(e) => setParam('decision', e.target.value || undefined)}
            className="border border-gray-300 rounded px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="approved">Approved</option>
            <option value="denied">Denied</option>
            <option value="timeout">Timeout</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Approver</label>
          <select
            value={filters.approvedBy || ''}
            onChange={(e) => setParam('approved_by', e.target.value || undefined)}
            className="border border-gray-300 rounded px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <optgroup label="Automated">
              <option value="llm">LLM</option>
              <option value="llm-static-rule">LLM Static Rule</option>
              <option value="llm-fallback">LLM Fallback</option>
              <option value="auto">Auto</option>
              <option value="cache">Cache</option>
              <option value="passthrough">Passthrough (legacy)</option>
            </optgroup>
            <optgroup label="Users">
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.id}</option>
              ))}
            </optgroup>
          </select>
        </div>
        {policies.length > 0 && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Policy</label>
            <select
              value={filters.policyId || ''}
              onChange={(e) => setParam('policy_id', e.target.value || undefined)}
              className="border border-gray-300 rounded px-3 py-2 text-sm"
            >
              <option value="">All</option>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
        )}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Date range</label>
          <div className="flex flex-wrap gap-1 mb-1">
            {quickRanges.map(({ label, days }) => (
              <button
                key={label}
                type="button"
                onClick={() => {
                  const now = new Date()
                  const end = new Date(now.getTime() + 60_000)
                  const start = new Date(now)
                  if (days === 0) start.setHours(0, 0, 0, 0)
                  else start.setDate(start.getDate() - days)
                  setSearchParams(prev => {
                    const next = new URLSearchParams(prev)
                    next.set('start_time', toDatetimeLocal(start))
                    next.set('end_time', toDatetimeLocal(end))
                    return next
                  }, { replace: true })
                }}
                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 text-gray-600"
              >
                {label}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            <input
              type="datetime-local"
              value={filters.startTime ?? ''}
              onChange={(e) => setParam('start_time', e.target.value || undefined)}
              className="border border-gray-300 rounded px-2 py-2 text-xs"
            />
            <input
              type="datetime-local"
              value={filters.endTime ?? ''}
              onChange={(e) => setParam('end_time', e.target.value || undefined)}
              className="border border-gray-300 rounded px-2 py-2 text-xs"
            />
          </div>
        </div>
        {searchParams.size > 0 && (
          <button onClick={clearAllParams} className="text-sm text-blue-600 hover:text-blue-800 pb-2">
            Clear all
          </button>
        )}
      </div>

      {/* Table */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
          <p className="text-red-800">Error: {error}</p>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden" ref={tableContainerRef}>
        <div className="overflow-x-auto">
          <table className="w-full table-fixed divide-y divide-gray-200" style={columnWidths.length ? { minWidth: columnWidths.reduce((a, b) => a + b, 0) } : undefined}>
            <colgroup>
              {columnWidths.length > 0
                ? columnWidths.map((w, i) => <col key={i} style={{ width: w }} />)
                : DEFAULT_COL_PCTS.map((pct, i) => <col key={i} style={{ width: `${pct}%` }} />)
              }
            </colgroup>
            <thead className="bg-gray-50">
              <tr>
                {['Timestamp', 'User', 'Method', 'URL', 'Decision', 'Approver', 'Duration'].map((label, i) => (
                  <th key={label} className="relative px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider select-none">
                    {label}
                    {i < 6 && (
                      <span
                        className="absolute right-0 top-0 h-full w-1.5 cursor-col-resize hover:bg-blue-400/50 active:bg-blue-500/50"
                        onMouseDown={(e) => onResizeStart(e, i)}
                      />
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {entries.map((entry, index) => {
                const rowId = `${entry.request_id}-${entry.timestamp}-${index}`
                const detailKey = entry.id ?? rowId
                const isExpanded = expandedId === rowId
                const detailEntry = entryDetails[detailKey] ?? entry
                const requestContentType = detailEntry.request_headers?.['Content-Type']?.[0] || detailEntry.request_headers?.['content-type']?.[0]
                const responseContentType = detailEntry.response_headers?.['Content-Type']?.[0] || detailEntry.response_headers?.['content-type']?.[0]

                return (
                  <Fragment key={rowId}>
                    <tr
                      className={`hover:bg-gray-50 cursor-pointer ${
                        entry.cache_hit ? 'bg-green-50' : ''
                      } ${isExpanded ? 'bg-blue-50' : ''}`}
                      onClick={() => toggleExpanded(entry, rowId)}
                    >
                      <td className="px-4 py-4 text-sm text-gray-900 whitespace-nowrap">
                        {formatTimestamp(entry.timestamp)}
                      </td>
                      <td className="px-4 py-4 text-sm text-gray-600 break-words">
                        {entry.user_id || <span className="text-gray-400">—</span>}
                        {entry.llm_policy_id && (
                          <div className="mt-1">
                            <button
                              onClick={(e) => { e.stopPropagation(); navigate(`/policies/${entry.llm_policy_id}`) }}
                              className="inline-block px-1.5 py-0.5 rounded text-xs bg-purple-100 text-purple-700 font-mono hover:bg-purple-200 transition-colors"
                            >
                              {entry.llm_policy_id.slice(0, 14)}…
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        {getMethodBadge(entry.method)}
                      </td>
                      <td className="px-4 py-4 text-sm text-gray-900 break-all">
                        {entry.url}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap">
                        {getDecisionBadge(entry.decision, entry.cache_hit)}
                      </td>
                      <td className="px-4 py-4 text-sm text-gray-900 break-words">
                        {entry.approved_by ? (
                          <>
                            {entry.approved_by}
                            {entry.cache_hit ? (
                              <span className="text-gray-400 ml-1">via Cache</span>
                            ) : entry.channel && entry.channel !== 'auto' && (
                              <span className="text-gray-400 ml-1">via <span className="capitalize">{entry.channel}</span></span>
                            )}
                          </>
                        ) : '-'}
                      </td>
                      <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900">
                        {entry.duration_ms}ms
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${rowId}-expanded`}>
                        <td colSpan={7} className="px-6 py-4 bg-gray-50">
                          {/* LLM Judge */}
                          {detailLoading[detailKey] && (
                            <div className="mb-4 text-sm text-gray-600">Loading audit entry details…</div>
                          )}
                          {detailErrors[detailKey] && (
                            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                              {detailErrors[detailKey]}
                            </div>
                          )}

                          {detailEntry.channel === 'llm' && detailEntry.llm_response_id && (
                            <LLMResponseBlock
                              llmResponseId={detailEntry.llm_response_id}
                              fallbackReason={detailEntry.llm_reason}
                            />
                          )}
                          {detailEntry.channel === 'llm' && !detailEntry.llm_response_id && detailEntry.llm_reason && (
                            <div className="mb-4 p-3 bg-purple-50 border border-purple-200 rounded">
                              <h4 className="text-sm font-semibold text-purple-900 mb-1">LLM Judge Reasoning</h4>
                              <p className="text-xs text-purple-800">{detailEntry.llm_reason}</p>
                            </div>
                          )}

                          <div className="grid grid-cols-2 gap-6">
                            {/* Request Details */}
                            <div>
                              <h4 className="text-sm font-semibold text-gray-900 mb-3">Request Details</h4>

                              <div className="mb-4">
                                <p className="text-xs font-medium text-gray-700 mb-2">Headers:</p>
                                <div className="bg-white p-3 rounded border border-gray-200 max-h-48 overflow-y-auto text-xs">
                                  {formatHeaders(detailEntry.request_headers)}
                                </div>
                              </div>

                              <div>
                                <p className="text-xs font-medium text-gray-700 mb-2">Body:</p>
                                <div className="bg-white p-3 rounded border border-gray-200 max-h-48 overflow-y-auto">
                                  {formatBody(detailEntry.request_body, requestContentType)}
                                </div>
                              </div>
                            </div>

                            {/* Response Details */}
                            <div>
                              <h4 className="text-sm font-semibold text-gray-900 mb-3">Response Details</h4>

                              <div className="mb-4">
                                <p className="text-xs font-medium text-gray-700 mb-2">Status: <span className="font-normal">{detailEntry.response_status}</span></p>
                              </div>

                              <div className="mb-4">
                                <p className="text-xs font-medium text-gray-700 mb-2">Headers:</p>
                                <div className="bg-white p-3 rounded border border-gray-200 max-h-48 overflow-y-auto text-xs">
                                  {formatHeaders(detailEntry.response_headers)}
                                </div>
                              </div>

                              <div>
                                <p className="text-xs font-medium text-gray-700 mb-2">Body:</p>
                                <div className="bg-white p-3 rounded border border-gray-200 max-h-48 overflow-y-auto">
                                  {formatBody(detailEntry.response_body, responseContentType)}
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Additional Metadata */}
                          <div className="mt-4 pt-4 border-t border-gray-200 text-xs text-gray-600">
                            <div className="grid grid-cols-4 gap-4">
                              <div><span className="font-semibold">Request ID:</span> {detailEntry.request_id}</div>
                              <div><span className="font-semibold">Operation:</span> {detailEntry.operation}</div>
                              {detailEntry.error && <div className="col-span-2"><span className="font-semibold text-red-600">Error:</span> {detailEntry.error}</div>}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>

        {loading && (
          <div className="text-center py-4">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          </div>
        )}

        {!loading && entries.length === 0 && (
          <div className="text-center py-12">
            <p className="text-gray-500">No audit entries found</p>
          </div>
        )}

        {!loading && hasMore && (
          <div className="text-center py-4 border-t border-gray-200">
            <button
              onClick={loadMore}
              className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Load More
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
