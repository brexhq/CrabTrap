import { useEffect, useState } from 'react'
import { useAuditStore } from '../stores/auditStore'
import { getAuditLog } from '../api/client'
import { getSSEClient } from '../api/sse'
import { parseDatetimeLocal } from '../lib/utils'
import type { AuditEntry } from '../types'

export function useAuditLog() {
  const { entries, filters, offset, limit, hasMore, setEntries, addEntry, setFilters, clearFilters } = useAuditStore()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Fetch audit log when filters change. offset is intentionally excluded from
  // deps — pagination is driven by loadMore() directly, not by the effect.
  useEffect(() => {
    let cancelled = false

    const fetchAuditLog = async () => {
      try {
        setLoading(true)
        const data = await getAuditLog({
          user_id: filters.userId,
          method: filters.method,
          decision: filters.decision,
          approved_by: filters.approvedBy,
          policy_id: filters.policyId,
          start_time: filters.startTime ? parseDatetimeLocal(filters.startTime).toISOString() : undefined,
          end_time: filters.endTime ? parseDatetimeLocal(filters.endTime).toISOString() : undefined,
          limit,
          offset: 0,
        })
        if (cancelled) return
        setEntries(data.entries, data.offset, data.limit, data.has_more ?? false)
        setError(null)
      } catch (err) {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Failed to fetch audit log')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    fetchAuditLog()
    return () => { cancelled = true }
  }, [filters, limit, setEntries])

  // Listen to SSE for new audit entries, respecting the active user filter.
  useEffect(() => {
    const sseClient = getSSEClient()
    sseClient.connect()

    const unsubscribe = sseClient.on('audit_entry', (event) => {
      const entry = event.data as AuditEntry
      if (filters.userId && entry.user_id !== filters.userId) return
      if (filters.method && entry.method !== filters.method) return
      if (filters.decision && entry.decision.toLowerCase() !== filters.decision) return
      if (filters.approvedBy && entry.approved_by !== filters.approvedBy) return
      if (filters.policyId && entry.llm_policy_id !== filters.policyId) return
      if (filters.startTime && new Date(entry.timestamp) < parseDatetimeLocal(filters.startTime)) return
      if (filters.endTime && new Date(entry.timestamp) > parseDatetimeLocal(filters.endTime)) return
      addEntry(entry)
    })

    return unsubscribe
  }, [filters.userId, filters.method, filters.decision, filters.approvedBy, filters.policyId, filters.startTime, filters.endTime])

  // Load more entries
  const loadMore = async () => {
    try {
      setLoading(true)
      const data = await getAuditLog({
        user_id: filters.userId,
        method: filters.method,
        decision: filters.decision,
        approved_by: filters.approvedBy,
        policy_id: filters.policyId,
        start_time: filters.startTime ? parseDatetimeLocal(filters.startTime).toISOString() : undefined,
        end_time: filters.endTime ? parseDatetimeLocal(filters.endTime).toISOString() : undefined,
        limit,
        offset: offset + limit,
      })

      // Append to existing entries
      setEntries([...entries, ...data.entries], data.offset, data.limit, data.has_more ?? false)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load more entries')
    } finally {
      setLoading(false)
    }
  }

  return {
    entries,
    filters,
    loadedCount: entries.length,
    loading,
    error,
    setFilters,
    clearFilters,
    loadMore,
    hasMore,
  }
}
