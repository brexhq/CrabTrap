// cookie.ts — server-side auth cookie management.
//
// Auth cookies are now set by the server via Set-Cookie with HttpOnly,
// SameSite=Strict, and (in production) Secure flags. JavaScript cannot
// read or write HttpOnly cookies, which mitigates XSS token theft.
//
// These helpers call the server login/logout endpoints which manage the
// cookie lifecycle. The browser automatically sends the HttpOnly cookie
// with same-origin requests (including EventSource/SSE connections).

const API_BASE = '/admin'

/**
 * Calls POST /admin/login to validate the token and set an HttpOnly
 * auth cookie. Returns the user identity on success.
 */
export async function serverLogin(token: string): Promise<{ user_id: string; role?: string; is_admin: boolean }> {
  const response = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  if (!response.ok) {
    throw new Error('Unauthorized')
  }
  return response.json()
}

/**
 * Calls POST /admin/logout to clear the HttpOnly auth cookie.
 */
export async function serverLogout(): Promise<void> {
  const response = await fetch(`${API_BASE}/logout`, { method: 'POST' })
  if (!response.ok) {
    throw new Error('Logout failed')
  }
}

