import { useEffect, useState } from 'react'
import { useUserStore } from '../stores/userStore'
import {
  getUsers, getUser, createUser as apiCreateUser, updateUser as apiUpdateUser, deleteUser as apiDeleteUser,
} from '../api/client'
import type {
  UserDetail, CreateUserRequest, UpdateUserRequest,
} from '../types'

export function useUsers() {
  const { users, setUsers, addUser, updateUser, removeUser } = useUserStore()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null)

  useEffect(() => {
    const fetch = async () => {
      try {
        setLoading(true)
        const data = await getUsers()
        setUsers(data)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch users')
      } finally {
        setLoading(false)
      }
    }
    fetch()
  }, [setUsers])

  const selectUser = async (id: string) => {
    try {
      const detail = await getUser(id)
      setSelectedUser(detail)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch user')
    }
  }

  const clearSelectedUser = () => setSelectedUser(null)

  const createUser = async (req: CreateUserRequest) => {
    const detail = await apiCreateUser(req)
    addUser({
      id: detail.id,
      role: detail.role,
      is_admin: detail.is_admin,
      created_at: detail.created_at,
      channel_count: detail.channels.length,
    })
    return detail
  }

  const editUser = async (id: string, req: UpdateUserRequest) => {
    const detail = await apiUpdateUser(id, req)
    updateUser(id, {
      role: detail.role,
      is_admin: detail.is_admin,
      channel_count: detail.channels.length,
    })
    if (selectedUser?.id === id) setSelectedUser(detail)
    return detail
  }

  const removeUserById = async (id: string) => {
    await apiDeleteUser(id)
    removeUser(id)
    if (selectedUser?.id === id) setSelectedUser(null)
  }

  return {
    users, loading, error,
    selectedUser, selectUser, clearSelectedUser,
    createUser, editUser, removeUserById,
  }
}
