import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useUsers } from '../hooks/useUsers'
import { useAuth } from '../contexts/AuthContext'
import { getPolicies, assignManager, unassignManager, getNotificationChannels, createNotificationChannel, deleteNotificationChannel, updateNotificationChannel, testNotificationChannel } from '../api/client'
import type {
  LLMPolicy, UserChannelInfo, UserDetail, ManagerAssignment, NotificationChannel,
  CreateUserRequest, UpdateUserRequest,
} from '../types'

// ---- Helpers ----

function newGatewayAuthToken(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return 'gat_' + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-xl leading-none">&times;</button>
        </div>
        {children}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-gray-700">{label}</label>
      {children}
    </div>
  )
}

/** Masked secret field with show/hide toggle and copy button. */
function SecretField({ value, placeholder }: { value: string; placeholder?: string }) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)

  if (!value) return <em className="text-gray-400 text-xs">{placeholder ?? 'not set'}</em>

  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
      <span className="break-all">{revealed ? value : '••••••••••••'}</span>
      <button onClick={() => setRevealed((v) => !v)} className="text-blue-500 hover:text-blue-700 shrink-0">
        {revealed ? 'hide' : 'show'}
      </button>
      <button onClick={copy} className="text-gray-400 hover:text-gray-600 shrink-0">
        {copied ? '✓' : '⎘'}
      </button>
    </span>
  )
}

const inputClass = 'w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500'
const btnPrimary = 'px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50'
const btnSecondary = 'px-4 py-2 border border-gray-300 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50'
const btnDanger = 'px-3 py-1.5 bg-red-600 text-white text-xs font-medium rounded-lg hover:bg-red-700'

// ---- Create User Modal ----

function CreateUserModal({ onClose, onSave }: { onClose: () => void; onSave: (req: CreateUserRequest) => Promise<unknown> }) {
  const { isAdmin } = useAuth()
  const [form, setForm] = useState<CreateUserRequest>({ id: '', role: 'user', web_token: '' })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [policies, setPolicies] = useState<LLMPolicy[]>([])

  useEffect(() => {
    getPolicies().then(setPolicies).catch(() => {})
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setErr(null)
    try {
      await onSave(form)
      onClose()
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to create user')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Create User" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-3">
        <Field label="Email (ID)">
          <input className={inputClass} value={form.id} onChange={(e) => setForm({ ...form, id: e.target.value })} required placeholder="user@example.com" />
        </Field>
        {policies.filter((p) => p.status === 'published').length > 0 && (
          <Field label="LLM Policy">
            <select
              className={inputClass}
              value={form.llm_policy_id ?? ''}
              onChange={(e) => setForm({ ...form, llm_policy_id: e.target.value || undefined })}
            >
              <option value="">None</option>
              {policies.filter((p) => p.status === 'published').map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Web Token">
          <input className={inputClass} value={form.web_token ?? ''} onChange={(e) => setForm({ ...form, web_token: e.target.value })} placeholder="optional" />
        </Field>
        <Field label="Gateway Auth Token">
          <div className="flex gap-2">
            <input
              className={inputClass}
              value={form.gateway_auth_token ?? ''}
              onChange={(e) => setForm({ ...form, gateway_auth_token: e.target.value })}
              placeholder="auto-generated if empty"
            />
            <button
              type="button"
              className={btnSecondary + ' shrink-0'}
              onClick={() => setForm({ ...form, gateway_auth_token: newGatewayAuthToken() })}
            >
              Generate
            </button>
          </div>
        </Field>
        {isAdmin && (
          <Field label="Role">
            <select className={inputClass} value={form.role ?? 'user'} onChange={(e) => setForm({ ...form, role: e.target.value as 'admin' | 'manager' | 'user' })}>
              <option value="user">User</option>
              <option value="manager">Manager</option>
              <option value="admin">Admin</option>
            </select>
          </Field>
        )}
        {err && <p className="text-red-600 text-sm">{err}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className={btnSecondary} onClick={onClose}>Cancel</button>
          <button type="submit" className={btnPrimary} disabled={saving}>{saving ? 'Creating…' : 'Create'}</button>
        </div>
      </form>
    </Modal>
  )
}

// ---- Edit User Modal ----

function EditUserModal({
  initial, onClose, onSave,
}: {
  initial: UpdateUserRequest & { id: string; role?: string; llm_policy_id?: string }
  onClose: () => void
  onSave: (req: UpdateUserRequest) => Promise<unknown>
}) {
  const { isAdmin } = useAuth()
  const [form, setForm] = useState<UpdateUserRequest>({
    role: (initial.role as 'admin' | 'manager' | 'user') ?? (initial.is_admin ? 'admin' : 'user'),
    llm_policy_id: initial.llm_policy_id,
    web_token: initial.web_token,
    gateway_auth_token: initial.gateway_auth_token,
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [policies, setPolicies] = useState<LLMPolicy[]>([])

  useEffect(() => {
    getPolicies().then(setPolicies).catch(() => {})
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setErr(null)
    try {
      await onSave(form)
      onClose()
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed to update user')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title={`Edit ${initial.id}`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-3">
        {policies.filter((p) => p.status === 'published').length > 0 && (
          <Field label="LLM Policy">
            <select
              className={inputClass}
              value={form.llm_policy_id ?? ''}
              onChange={(e) => setForm({ ...form, llm_policy_id: e.target.value })}
            >
              <option value="">None</option>
              {policies.filter((p) => p.status === 'published').map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Web Token">
          <input className={inputClass} value={form.web_token ?? ''} onChange={(e) => setForm({ ...form, web_token: e.target.value })} placeholder="empty = remove channel" />
        </Field>
        <Field label="Gateway Auth Token">
          <div className="flex gap-2">
            <input
              className={inputClass}
              value={form.gateway_auth_token ?? ''}
              onChange={(e) => setForm({ ...form, gateway_auth_token: e.target.value })}
              placeholder="empty = remove channel"
            />
            <button
              type="button"
              className={btnSecondary + ' shrink-0'}
              title="Generate a new random token"
              onClick={() => setForm({ ...form, gateway_auth_token: newGatewayAuthToken() })}
            >
              Rotate
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">Rotating invalidates the current token immediately.</p>
        </Field>
        {isAdmin && (
          <Field label="Role">
            <select className={inputClass} value={form.role ?? 'user'} onChange={(e) => setForm({ ...form, role: e.target.value as 'admin' | 'manager' | 'user' })}>
              <option value="user">User</option>
              <option value="manager">Manager</option>
              <option value="admin">Admin</option>
            </select>
          </Field>
        )}
        {err && <p className="text-red-600 text-sm">{err}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className={btnSecondary} onClick={onClose}>Cancel</button>
          <button type="submit" className={btnPrimary} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
        </div>
      </form>
    </Modal>
  )
}

// ---- Channels section ----

const CHANNEL_LABELS: Record<string, string> = {
  web: 'Web',
  gateway_auth: 'Gateway Auth',
}

function ChannelsSection({ channels, onEdit }: { channels: UserChannelInfo[]; onEdit: () => void }) {
  const webCh = channels.find((c) => c.channel_type === 'web')
  const gatewayCh = channels.find((c) => c.channel_type === 'gateway_auth')

  const rows: Array<{ label: string; content: React.ReactNode }> = [
    {
      label: 'Web Token',
      content: <SecretField value={webCh?.web_token ?? ''} placeholder="not set" />,
    },
    {
      label: 'Gateway Auth Token',
      content: (
        <div className="space-y-1">
          <SecretField value={gatewayCh?.gateway_auth_token ?? ''} placeholder="not set" />
          {gatewayCh?.gateway_auth_token && (
            <p className="text-xs text-gray-400">
              HTTP_PROXY=http://{gatewayCh.gateway_auth_token}:@&lt;host&gt;:&lt;port&gt;
            </p>
          )}
        </div>
      ),
    },
  ]

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-base font-semibold text-gray-800">Channels</h3>
        <button onClick={onEdit} className={btnSecondary + ' text-xs'}>Edit Channels</button>
      </div>
      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
        {rows.map(({ label, content }) => (
          <div key={label} className="px-4 py-3 flex items-start gap-4 text-sm">
            <span className="text-gray-500 w-36 shrink-0">{label}</span>
            <span className="flex-1 min-w-0">{content}</span>
          </div>
        ))}
        {channels.filter((c) => !['web', 'gateway_auth'].includes(c.channel_type)).map((ch) => (
          <div key={ch.id} className="px-4 py-3 flex items-start gap-4 text-sm">
            <span className="text-gray-500 w-36 shrink-0">{CHANNEL_LABELS[ch.channel_type] ?? ch.channel_type}</span>
            <span className="font-mono text-xs text-gray-700">id: {ch.id}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

// ---- Managers section ----

function ManagersSection({ managers, botId, allUsers, onAssign, onUnassign }: {
  managers: ManagerAssignment[]
  botId: string
  allUsers: { id: string; role: string }[]
  onAssign: (managerId: string) => Promise<void>
  onUnassign: (managerId: string) => Promise<void>
}) {
  const { isAdmin } = useAuth()
  const [adding, setAdding] = useState(false)
  const [selectedManager, setSelectedManager] = useState('')
  const [busy, setBusy] = useState(false)

  const assignedIds = new Set(managers.map((m) => m.manager_id))
  const availableManagers = allUsers.filter(
    (u) => (u.role === 'manager' || u.role === 'admin') && u.id !== botId && !assignedIds.has(u.id)
  )

  const [error, setError] = useState<string | null>(null)

  const handleAssign = async () => {
    if (!selectedManager) return
    setBusy(true)
    setError(null)
    try {
      await onAssign(selectedManager)
      setSelectedManager('')
      setAdding(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to assign manager')
    } finally {
      setBusy(false)
    }
  }

  const handleUnassign = async (managerId: string) => {
    if (!confirm(`Remove ${managerId} as manager?`)) return
    setError(null)
    try {
      await onUnassign(managerId)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove manager')
    }
  }

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-base font-semibold text-gray-800">Managers</h3>
        {isAdmin && !adding && (
          <button onClick={() => setAdding(true)} className={btnSecondary + ' text-xs'}>
            Add Manager
          </button>
        )}
      </div>
      {error && <p className="text-red-600 text-sm mb-2">{error}</p>}
      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
        {managers.length === 0 && !adding && (
          <div className="px-4 py-3 text-sm text-gray-400">No managers assigned</div>
        )}
        {managers.map((m) => (
          <div key={m.id} className="px-4 py-3 flex items-center gap-4 text-sm">
            <span className="flex-1 font-medium text-gray-700">{m.manager_id}</span>
            <span className="text-xs text-gray-400">{new Date(m.created_at).toLocaleDateString()}</span>
            {isAdmin && (
              <button onClick={() => handleUnassign(m.manager_id)} className="text-xs text-red-600 hover:underline">
                Remove
              </button>
            )}
          </div>
        ))}
        {adding && (
          <div className="px-4 py-3 flex items-center gap-2">
            <select
              value={selectedManager}
              onChange={(e) => setSelectedManager(e.target.value)}
              className="flex-1 px-2 py-1 border border-gray-300 rounded text-sm"
            >
              <option value="">Select a manager…</option>
              {availableManagers.map((u) => (
                <option key={u.id} value={u.id}>{u.id}</option>
              ))}
            </select>
            <button onClick={handleAssign} disabled={!selectedManager || busy} className={btnSecondary + ' text-xs'}>
              {busy ? 'Adding…' : 'Add'}
            </button>
            <button onClick={() => setAdding(false)} className="text-xs text-gray-500 hover:underline">
              Cancel
            </button>
          </div>
        )}
      </div>
    </section>
  )
}

// ---- Notification Channels section ----

function NotificationChannelsSection({ botId, onRefresh }: {
  botId: string
  onRefresh?: () => void
}) {
  const [channels, setChannels] = useState<NotificationChannel[]>([])
  const [adding, setAdding] = useState(false)
  const [channelType, setChannelType] = useState('slack')
  const [destination, setDestination] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [testingId, setTestingId] = useState<string | null>(null)

  useEffect(() => {
    getNotificationChannels(botId).then(setChannels).catch((err) => {
      setError(err instanceof Error ? err.message : 'Failed to load notification channels')
    })
  }, [botId])

  const handleAdd = async () => {
    if (!destination) return
    setBusy(true)
    setError(null)
    try {
      const ch = await createNotificationChannel({ bot_id: botId, channel_type: channelType, destination })
      setChannels((prev) => [ch, ...prev])
      setDestination('')
      setAdding(false)
      onRefresh?.()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create channel')
    } finally {
      setBusy(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this notification channel?')) return
    setError(null)
    try {
      await deleteNotificationChannel(id)
      setChannels((prev) => prev.filter((ch) => ch.id !== id))
      onRefresh?.()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete channel')
    }
  }

  const handleToggle = async (ch: NotificationChannel) => {
    try {
      const updated = await updateNotificationChannel(ch.id, { enabled: !ch.enabled })
      setChannels((prev) => prev.map((c) => c.id === ch.id ? updated : c))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update channel')
    }
  }

  const handleTest = async (id: string) => {
    setTestingId(id)
    setError(null)
    try {
      await testNotificationChannel(id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test send failed')
    } finally {
      setTestingId(null)
    }
  }

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-base font-semibold text-gray-800">Notification Channels</h3>
        {!adding && (
          <button onClick={() => setAdding(true)} className={btnSecondary + ' text-xs'}>
            Add Channel
          </button>
        )}
      </div>
      {error && <p className="text-red-600 text-sm mb-2">{error}</p>}
      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
        {channels.length === 0 && !adding && (
          <div className="px-4 py-3 text-sm text-gray-400">No notification channels configured</div>
        )}
        {channels.map((ch) => (
          <div key={ch.id} className="px-4 py-3 flex items-center gap-3 text-sm">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
              {ch.channel_type}
            </span>
            <span className="flex-1 font-mono text-gray-700">{ch.destination}</span>
            <button
              onClick={() => handleToggle(ch)}
              className={`text-xs ${ch.enabled ? 'text-green-600' : 'text-gray-400'}`}
            >
              {ch.enabled ? 'Enabled' : 'Disabled'}
            </button>
            <button
              onClick={() => handleTest(ch.id)}
              disabled={testingId === ch.id}
              className="text-xs text-blue-600 hover:underline disabled:opacity-50"
            >
              {testingId === ch.id ? 'Sending...' : 'Test'}
            </button>
            <button onClick={() => handleDelete(ch.id)} className="text-xs text-red-600 hover:underline">
              Remove
            </button>
          </div>
        ))}
        {adding && (
          <div className="px-4 py-3 flex items-center gap-2">
            <select
              value={channelType}
              onChange={(e) => setChannelType(e.target.value)}
              className="px-2 py-1 border border-gray-300 rounded text-sm"
            >
              <option value="slack">Slack</option>
            </select>
            <input
              type="text"
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              placeholder={channelType === 'slack' ? '#channel-name' : 'https://...'}
              className="flex-1 px-2 py-1 border border-gray-300 rounded text-sm"
            />
            <button onClick={handleAdd} disabled={!destination || busy} className={btnSecondary + ' text-xs'}>
              {busy ? 'Adding...' : 'Add'}
            </button>
            <button onClick={() => { setAdding(false); setDestination('') }} className="text-xs text-gray-500 hover:underline">
              Cancel
            </button>
          </div>
        )}
      </div>
    </section>
  )
}

// ---- Detail view ----

export function UserDetailView({
  user, onBack, policies,
  onEditUser, onDeleteUser,
  onSuggestPolicy, onRefreshUser,
  allUsers,
}: {
  user: UserDetail | null
  onBack: () => void
  policies: LLMPolicy[]
  onEditUser: (req: UpdateUserRequest) => Promise<unknown>
  onDeleteUser: () => Promise<unknown>
  onSuggestPolicy?: () => void
  onRefreshUser?: () => void
  allUsers?: { id: string; role: string }[]
}) {
  const navigate = useNavigate()
  const [showEdit, setShowEdit] = useState(false)
  const [deleting, setDeleting] = useState(false)

  if (!user) return null

  const handleDelete = async () => {
    if (!confirm(`Delete user ${user.id}? This is irreversible.`)) return
    setDeleting(true)
    try { await onDeleteUser() }
    finally { setDeleting(false) }
  }

  const handleAssignManager = async (managerId: string) => {
    await assignManager(user.id, managerId)
    await onRefreshUser?.()
  }

  const handleUnassignManager = async (managerId: string) => {
    await unassignManager(user.id, managerId)
    await onRefreshUser?.()
  }

  const webChannel = user.channels.find((c) => c.channel_type === 'web')
  const gatewayChannel = user.channels.find((c) => c.channel_type === 'gateway_auth')
  const assignedPolicy = user.llm_policy_id ? policies.find((p) => p.id === user.llm_policy_id) : undefined

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button onClick={onBack} className={btnSecondary}>← Back</button>
        <h2 className="text-xl font-semibold text-gray-900 flex-1">{user.id}</h2>
        {onSuggestPolicy && (
          <button onClick={onSuggestPolicy} className={btnSecondary}>Suggest Policy</button>
        )}
        <button onClick={() => setShowEdit(true)} className={btnSecondary}>Edit User</button>
        <button onClick={handleDelete} disabled={deleting} className={btnDanger}>
          {deleting ? 'Deleting…' : 'Delete User'}
        </button>
      </div>

      {/* User Info */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 grid grid-cols-2 gap-3 text-sm">
        <div><span className="text-gray-500">Role:</span> <span className="font-medium capitalize">{user.role || (user.is_admin ? 'admin' : 'user')}</span></div>
        <div><span className="text-gray-500">Created:</span> {new Date(user.created_at).toLocaleString()}</div>
        <div><span className="text-gray-500">Updated:</span> {new Date(user.updated_at).toLocaleString()}</div>
        {user.llm_policy_id && (
          <div className="flex items-center gap-2">
            <span className="text-gray-500">LLM Policy:</span>{' '}
            <span className="text-sm">{assignedPolicy?.name ?? user.llm_policy_id}</span>
            <button
              onClick={() => navigate(`/policies/${user.llm_policy_id}`)}
              className="text-xs text-blue-600 hover:underline"
            >
              View policy →
            </button>
          </div>
        )}
      </div>

      {/* Channels */}
      <ChannelsSection
        channels={user.channels}
        onEdit={() => setShowEdit(true)}
      />

      {/* Managers (only for bot users) */}
      {user.role === 'user' && (
        <ManagersSection
          managers={user.managers ?? []}
          botId={user.id}
          allUsers={allUsers ?? []}
          onAssign={handleAssignManager}
          onUnassign={handleUnassignManager}
        />
      )}

      {/* Notification Channels (only for bot users) */}
      {user.role === 'user' && (
        <NotificationChannelsSection botId={user.id} onRefresh={onRefreshUser} />
      )}

      {showEdit && (
        <EditUserModal
          initial={{
            id: user.id,
            role: user.role || (user.is_admin ? 'admin' : 'user'),
            llm_policy_id: user.llm_policy_id,
            web_token: webChannel?.web_token ?? '',
            gateway_auth_token: gatewayChannel?.gateway_auth_token ?? '',
          }}
          onClose={() => setShowEdit(false)}
          onSave={onEditUser}
        />
      )}

    </div>
  )
}

// ---- Main panel ----

export function UsersPanel() {
  const navigate = useNavigate()
  const { users, loading, error, createUser } = useUsers()

  const [showCreate, setShowCreate] = useState(false)
  const [policies, setPolicies] = useState<LLMPolicy[]>([])

  useEffect(() => {
    getPolicies().then(setPolicies).catch(() => {})
  }, [])

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  if (error) return <p className="text-red-600 text-sm">{error}</p>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-800">Users</h2>
        <button onClick={() => setShowCreate(true)} className={btnPrimary}>+ Create User</button>
      </div>

      {users.length === 0 ? (
        <p className="text-gray-500 text-sm bg-white rounded-lg border border-dashed border-gray-200 p-8 text-center">
          No users found
        </p>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Email</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Role</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">LLM Policy</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Channels</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Created</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map((u) => (
                <tr
                  key={u.id}
                  className="hover:bg-blue-50 cursor-pointer"
                  onClick={() => navigate(`/users/${encodeURIComponent(u.id)}`)}
                >
                  <td className="px-4 py-3 font-mono text-blue-600">{u.id}</td>
                  <td className="px-4 py-3">
                    {u.role === 'admin' && (
                      <span className="px-2 py-0.5 bg-purple-100 text-purple-800 rounded-full text-xs font-medium">admin</span>
                    )}
                    {u.role === 'manager' && (
                      <span className="px-2 py-0.5 bg-blue-100 text-blue-800 rounded-full text-xs font-medium">manager</span>
                    )}
                    {(u.role === 'user' || !u.role) && (
                      <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full text-xs font-medium">user</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-600 text-sm">
                    {u.llm_policy_id ? (
                      <button
                        onClick={(e) => { e.stopPropagation(); navigate(`/policies/${u.llm_policy_id}`) }}
                        className="text-blue-600 hover:underline text-xs"
                      >
                        {policies.find((p) => p.id === u.llm_policy_id)?.name ?? u.llm_policy_id}
                      </button>
                    ) : (
                      <em className="text-gray-400">—</em>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {u.channel_count}
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">{new Date(u.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <button
                      className="text-blue-600 hover:underline text-xs"
                      onClick={(e) => { e.stopPropagation(); navigate(`/users/${encodeURIComponent(u.id)}`) }}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onSave={createUser}
        />
      )}
    </div>
  )
}
