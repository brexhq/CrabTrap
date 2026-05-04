import { createHashRouter, RouterProvider, Navigate, Outlet } from 'react-router-dom'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { Layout } from './components/Layout'
import { AuditTrail } from './components/AuditTrail'
import { UsersPanel } from './components/UsersPanel'
import { UserDetailPage } from './components/UserDetailPage'
import { PoliciesPanel } from './components/PoliciesPanel'
import { PolicyDetail } from './components/PolicyDetail'
import { LoginPage } from './components/LoginPage'
import { EvalsPanel } from './components/EvalsPanel'
import { EvalDetail } from './components/EvalDetail'
import { TooltipProvider } from './components/ui/tooltip'

// Auth gate — renders children only when logged in as admin or manager.
function RequireAuth() {
  const { userID, role, authChecked, logout } = useAuth()

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    )
  }

  if (!userID) return <LoginPage />

  if (role !== 'admin' && role !== 'manager') {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 text-center max-w-sm">
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Not Authorized</h2>
          <p className="text-gray-500 text-sm mb-4">Your account does not have admin or manager access.</p>
          <button onClick={logout} className="text-sm text-blue-600 hover:underline">Sign out</button>
        </div>
      </div>
    )
  }

  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

const router = createHashRouter([
  {
    path: '/',
    element: <RequireAuth />,
    children: [
      { index: true, element: <AuditTrail /> },
      { path: 'users', element: <UsersPanel /> },
      { path: 'users/:id', element: <UserDetailPage /> },
      { path: 'policies', element: <PoliciesPanel /> },
      { path: 'policies/:id', element: <PolicyDetail /> },
      { path: 'evals', element: <EvalsPanel /> },
      { path: 'evals/:id', element: <EvalDetail /> },
    ],
  },
  { path: '*', element: <Navigate to="/" replace /> },
])

export default function App() {
  return (
    <AuthProvider>
      <TooltipProvider delayDuration={0}>
        <RouterProvider router={router} />
      </TooltipProvider>
    </AuthProvider>
  )
}
