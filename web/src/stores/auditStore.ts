import { create } from 'zustand'
import type { AuditEntry } from '../types'

interface AuditFilter {
  userId?: string
  method?: string
  decision?: string
  approvedBy?: string
  policyId?: string
  startTime?: string
  endTime?: string
}

interface AuditStore {
  entries: AuditEntry[]
  filters: AuditFilter
  offset: number
  limit: number
  hasMore: boolean
  setEntries: (entries: AuditEntry[], offset: number, limit: number, hasMore: boolean) => void
  addEntry: (entry: AuditEntry) => void
  setFilters: (filters: AuditFilter) => void
  clearFilters: () => void
}

function auditEntryKey(entry: AuditEntry): string {
  return entry.id || `${entry.request_id}-${entry.timestamp}`
}

function uniqueAuditEntries(entries: AuditEntry[]): AuditEntry[] {
  const seen = new Set<string>()
  const unique: AuditEntry[] = []
  for (const entry of entries) {
    const key = auditEntryKey(entry)
    if (seen.has(key)) continue
    seen.add(key)
    unique.push(entry)
  }
  return unique
}

export const useAuditStore = create<AuditStore>((set) => ({
  entries: [],
  filters: {},
  offset: 0,
  limit: 100,
  hasMore: false,

  setEntries: (entries, offset, limit, hasMore) =>
    set({
      entries: uniqueAuditEntries(entries).sort((a, b) => {
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      }),
      offset,
      limit,
      hasMore,
    }),

  addEntry: (entry) =>
    set((state) => {
      console.log('Store: addEntry called', entry.request_id, entry.timestamp)
      // Check if entry already exists
      const key = auditEntryKey(entry)
      if (state.entries.some(e => auditEntryKey(e) === key)) {
        console.log('Store: entry already exists, skipping', entry.request_id)
        return state // Don't add duplicates
      }
      // Add entry and sort by timestamp descending (newest first)
      const allEntries = [entry, ...state.entries]
      const sortedEntries = [...allEntries].sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime()
        const timeB = new Date(b.timestamp).getTime()
        return timeB - timeA  // Descending order (newest first)
      })
      return {
        entries: sortedEntries,
      }
    }),

  setFilters: (filters) =>
    set({ filters, offset: 0 }), // Reset offset when filters change

  clearFilters: () =>
    set({ filters: {}, offset: 0 }),
}))
