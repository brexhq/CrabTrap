import { useState } from 'react'
import { serverLogin } from '../api/cookie'
import { useAuth } from '../contexts/AuthContext'

export function LoginPage() {
  const { login } = useAuth()
  const [token, setToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!token.trim()) return

    setLoading(true)
    setError(null)

    try {
      // POST /admin/login sets an HttpOnly cookie server-side.
      const data = await serverLogin(token.trim())
      const role = data.role ?? (data.is_admin ? 'admin' : 'user')
      if (role !== 'admin' && role !== 'manager') {
        setError('Access denied: admin or manager privileges required.')
        return
      }
      // Keep token in localStorage for Bearer header on non-cookie requests.
      localStorage.setItem('web_token', token.trim())
      login(data.user_id, role)
    } catch {
      setError('Invalid token. Please check your web token and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 w-full max-w-md">
        <h1 className="text-2xl font-bold text-gray-900 mb-2">CrabTrap</h1>
        <p className="text-gray-500 mb-6 text-sm">Enter your web token to access the dashboard.</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="token" className="block text-sm font-medium text-gray-700 mb-1">
              Web Token
            </label>
            <input
              id="token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="your-web-token-here"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              autoFocus
            />
          </div>

          {error && <p className="text-red-600 text-sm">{error}</p>}

          <button
            type="submit"
            disabled={loading || !token.trim()}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
