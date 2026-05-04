import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import { getStoredToken, getUsers } from '../api/client'
import { getSSEClient, resetSSEClient } from '../api/sse'
import { serverLogin, serverLogout } from '../api/cookie'
import type { UserSummary, UserRole } from '../types'

interface AuthContextValue {
  userID: string | null
  role: UserRole
  isAdmin: boolean
  isManager: boolean
  authChecked: boolean
  allUsers: UserSummary[]
  login: (uid: string, role: UserRole) => void
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [userID, setUserID] = useState<string | null>(null)
  const [role, setRole] = useState<UserRole>('user')
  const [authChecked, setAuthChecked] = useState(false)
  const [allUsers, setAllUsers] = useState<UserSummary[]>([])

  const isAdmin = role === 'admin'
  const isManager = role === 'manager'

  // Restore auth from localStorage on mount.
  useEffect(() => {
    const restore = async () => {
      const token = getStoredToken()
      if (token) {
        try {
          // Re-login via the server endpoint so the HttpOnly cookie is
          // refreshed (e.g. after a page reload or cookie expiry).
          const data = await serverLogin(token)
          setUserID(data.user_id)
          const rawRole = data.role ?? (data.is_admin ? 'admin' : 'user')
          setRole(rawRole === 'admin' || rawRole === 'manager' ? rawRole : 'user')
        } catch {
          localStorage.removeItem('web_token')
        }
      }
      setAuthChecked(true)
    }
    restore()
  }, [])

  // Load users list and connect SSE once logged in.
  useEffect(() => {
    if (!userID) return
    getUsers().then(setAllUsers).catch(() => {})

    const sseClient = getSSEClient()
    sseClient.connect()

    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }

    return () => { sseClient.disconnect() }
  }, [userID])

  const login = (uid: string, r: UserRole) => {
    resetSSEClient()
    setUserID(uid)
    setRole(r)
  }

  const logout = async () => {
    localStorage.removeItem('web_token')
    // Clear the HttpOnly cookie via the server endpoint, and also
    // clear any legacy non-HttpOnly cookie client-side.
    try {
      await serverLogout()
    } catch {
      console.warn('Failed to clear server session cookie — it may persist until expiry.')
    }
    resetSSEClient()
    setUserID(null)
    setRole('user')
  }

  return (
    <AuthContext.Provider value={{ userID, role, isAdmin, isManager, authChecked, allUsers, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
