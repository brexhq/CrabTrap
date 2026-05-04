import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  getUser, getPolicies,
  updateUser, deleteUser,
  createPolicy,
} from '../api/client'
import type {
  LLMPolicy, UserDetail,
  UpdateUserRequest,
} from '../types'
import { UserDetailView } from './UsersPanel'
import { useAuth } from '../contexts/AuthContext'

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { allUsers } = useAuth()
  const [user, setUser] = useState<UserDetail | null>(null)
  const [policies, setPolicies] = useState<LLMPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [creatingDraft, setCreatingDraft] = useState(false)

  const loadUser = useCallback(() => {
    if (!id) return Promise.resolve()
    return getUser(id).then(setUser).catch((err) => setError(err instanceof Error ? err.message : 'Failed to refresh user'))
  }, [id])

  useEffect(() => {
    if (!id) return
    setLoading(true)
    Promise.all([getUser(id), getPolicies()])
      .then(([u, p]) => { setUser(u); setPolicies(p) })
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load user'))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }
  if (error) return <p className="text-red-600 text-sm">{error}</p>

  const handleEditUser = async (req: UpdateUserRequest) => {
    if (!id) return
    const updated = await updateUser(id, req)
    setUser(updated)
  }

  const handleDeleteUser = async () => {
    if (!id) return
    await deleteUser(id)
    navigate('/users')
  }

  const handleSuggestPolicy = async () => {
    if (!id) return
    setCreatingDraft(true)
    try {
      const draft = await createPolicy({ name: `${id} policy`, status: 'draft' })
      const end = new Date().toISOString()
      const start = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
      const message = `Analyze traffic for ${id} from ${start} to ${end}. Based on what you find, build a complete policy.`
      navigate(`/policies/${draft.id}`, { state: { startAgentMessage: message } })
    } catch {
      navigate('/policies')
    } finally {
      setCreatingDraft(false)
    }
  }

  return (
    <UserDetailView
      user={user}
      onBack={() => navigate('/users')}
      policies={policies}
      onEditUser={handleEditUser}
      onDeleteUser={handleDeleteUser}
      onSuggestPolicy={creatingDraft ? undefined : handleSuggestPolicy}
      onRefreshUser={loadUser}
      allUsers={allUsers}
    />
  )
}
