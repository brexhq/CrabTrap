# CrabTrap Web UI

A React dashboard for audit monitoring, LLM policy management, user management, and evaluation runs for the CrabTrap.

## Quick Start

### Development Mode (Recommended)

Start both backend and frontend with hot module reload:

```bash
# From repository root
make dev
```

- Backend API: http://localhost:8081
- Frontend UI: **http://localhost:3000** <- Use this!
- Changes to `web/src/` files update instantly

### Production Build

Build the production binary and the web UI (served from `web/dist` on disk):

```bash
# From repository root
make build
./gateway
```

Access at: http://localhost:8081

## Development Workflows

There are **three ways** to develop with the web UI:

### Option 1: Full Dev Mode with HMR (Recommended)

**Best for**: Active frontend development with instant feedback

```bash
make dev
```

**What happens:**
- Backend runs on `http://localhost:8081` (serves from filesystem)
- Frontend dev server runs on `http://localhost:3000` (Vite with HMR)
- Frontend proxies API requests to backend
- **Real-time updates**: Edit files in `web/src/` and see changes instantly!

---

### Option 2: Backend Dev Mode Only

**Best for**: Backend development without frontend changes

```bash
# Build frontend once
make build-web

# Run backend in dev mode (serves from web/dist/)
make dev-backend
```

---

### Option 3: Production Mode

**Best for**: Testing the production build

```bash
make build
./gateway
```

---

## Tech Stack

### Frontend
- **React 18** - UI framework
- **TypeScript** - Type-safe development
- **Vite** - Fast build tool with HMR
- **Tailwind CSS** - Utility-first styling
- **Zustand** - Lightweight state management
- **react-router-dom** - Client-side routing
- **react-markdown** - Markdown rendering
- **@radix-ui/react-tooltip** - Tooltip primitives
- **date-fns** - Date formatting

### Backend Integration
- **Server-Sent Events (SSE)** - Real-time updates
- **REST API** - Audit, policy, user, and eval management
- **Filesystem serving** - Frontend served from `web/dist` on disk

## Project Structure

```
web/
├── src/
│   ├── components/       # React components
│   │   ├── Dashboard.tsx        # Stats overview
│   │   ├── AuditTrail.tsx       # Audit history table
│   │   ├── PoliciesPanel.tsx    # LLM policy list
│   │   ├── PolicyDetail.tsx     # Policy detail/edit view
│   │   ├── UsersPanel.tsx       # User management
│   │   ├── UserDetailPage.tsx   # User detail view
│   │   ├── EvalsPanel.tsx       # Evaluation runs list
│   │   ├── EvalDetail.tsx       # Eval run detail/results
│   │   ├── LoginPage.tsx        # Token login form
│   │   ├── Layout.tsx           # App layout & navigation
│   │   └── ui/                  # Shared UI primitives
│   ├── contexts/        # React contexts
│   │   └── AuthContext.tsx      # Auth state & token management
│   ├── hooks/           # React hooks
│   │   ├── useAuditLog.ts       # Audit queries
│   │   └── useUsers.ts          # User data
│   ├── stores/          # Zustand state management
│   │   ├── auditStore.ts        # Audit entries & filters
│   │   └── userStore.ts         # User list
│   ├── api/             # API clients
│   │   ├── client.ts            # REST API wrapper
│   │   └── sse.ts               # SSE client with reconnection
│   ├── types/           # TypeScript types
│   │   └── index.ts             # Interfaces matching Go structs
│   ├── lib/             # Utilities
│   │   └── utils.ts             # Class name helpers
│   ├── App.tsx          # Root component with router
│   └── main.tsx         # Entry point
├── dist/                # Build output (gitignored)
├── package.json         # NPM dependencies
├── vite.config.ts       # Vite configuration
├── tailwind.config.js   # Tailwind configuration
├── postcss.config.js    # PostCSS configuration
└── tsconfig.json        # TypeScript configuration
```

## Features

### Dashboard
- Overview stats: pending count, cache size, connected SSE clients
- Polls health endpoint every 5 seconds

### Audit Trail
- **Searchable History**: Filter by user, method, decision, approver, policy, and date range
- **Expandable Rows**: Click to see full request/response details
- **JSON Formatting**: Pretty-printed JSON bodies
- **Pagination**: Load more entries on demand

### LLM Policies
- Create, edit, fork, and publish policies
- Policy versioning with immutable published versions
- AI agent chat for policy synthesis
- Per-policy traffic stats and metadata

### Users
- List, create, update, delete users
- Assign LLM policies to users
- Manage gateway auth tokens

### Evaluations
- Create eval runs against policies
- View per-entry results (agreed / disagreed / errored)
- Aggregate accuracy statistics
- Cancel running evals

### Authentication
- Token-based auth via `GET /admin/me`
- Token stored in localStorage; HttpOnly `token` cookie set server-side via `POST /admin/login` (server accepts `Authorization: Bearer` header or cookie)
- Admin-only access enforced

## API Endpoints

The frontend communicates with these backend endpoints:

### Auth
- `POST /admin/login` - Validate token and set HttpOnly auth cookie
- `POST /admin/logout` - Clear auth cookie
- `GET /admin/me` - Validate token, get user info

### Audit
- `GET /admin/audit` - Query audit log with filters
- `GET /admin/audit/{id}` - Get single audit entry
- `PUT/DELETE /admin/audit/{id}/label` - Set/remove ground-truth label

### Users
- `GET/POST /admin/users` - List / create users
- `GET/PUT/DELETE /admin/users/{email}` - Get / update / delete user

### LLM Policies
- `GET/POST /admin/llm-policies` - List / create policies
- `GET/PUT/DELETE /admin/llm-policies/{id}` - Get / update / delete policy
- `POST /admin/llm-policies/{id}/publish` - Publish draft
- `POST /admin/llm-policies/{id}/fork` - Fork a version
- `POST /admin/llm-policies/{id}/agent` - AI agent chat

### Evaluations
- `GET/POST /admin/evals` - List / create eval runs
- `GET /admin/evals/{id}` - Get eval run with stats
- `GET /admin/evals/{id}/results` - Get eval results
- `POST /admin/evals/{id}/cancel` - Cancel running eval

### Real-time Updates
- `GET /admin/events` - SSE stream (`audit_entry` and `connected` events)

### Health
- `GET /admin/health` - Health status (pending count, cache size, SSE clients)

## State Management

**Zustand Stores:**
- `auditStore`: Manages audit entries and filters
- `userStore`: Manages user list

**React Hooks:**
- `useAuditLog`: Queries audit log with filters
- `useUsers`: Manages user data

**SSE Client:**
- Auto-reconnection with exponential backoff
- Heartbeat every 30s
- Handles `audit_entry` and `connected` events

## Common Commands

```bash
# DEVELOPMENT
make dev              # Backend + Frontend with HMR (recommended)
make dev-backend      # Backend only (serves from filesystem)
make dev-web          # Frontend dev server only

# BUILDING
make build-web        # Build frontend only
make build            # Build everything (production binary)

# CLEANING
make clean            # Remove all build artifacts
```

## Troubleshooting

### Frontend changes not showing

**In `make dev` mode:**
- Should update automatically
- Check Vite terminal for errors
- Try hard refresh (Cmd+Shift+R)

**In `make dev-backend` mode:**
```bash
make build-web  # Rebuild frontend
# Refresh browser
```

### Port already in use

```bash
lsof -ti:8081 | xargs kill -9  # Backend
lsof -ti:3000 | xargs kill -9  # Frontend dev server
```

### TypeScript errors

```bash
cd web
npm install  # Reinstall dependencies
npm run build  # Check for build errors
```

### Debugging Vite Proxy

If frontend can't reach backend:
1. Check backend is running: `curl http://localhost:8081/admin/health`
2. Check Vite proxy config in `vite.config.ts`
3. Look for proxy errors in Vite terminal output

## Production Deployment

For production, build the binary and ship `web/dist` next to it — the UI is served from disk only, looked up in the working directory and beside the executable:

```bash
make build
sudo mkdir -p /opt/crabtrap
sudo cp gateway /opt/crabtrap/
sudo cp -r web/dist /opt/crabtrap/
sudo /opt/crabtrap/gateway -config config/gateway.yaml
```

The binary serves the UI from `web/dist` on disk — the directory must be present at runtime.

---

**Need help?**
- Quick start: See [QUICKSTART.md](../QUICKSTART.md)
- Gateway docs: See [README.md](../README.md)
- Architecture: See [DESIGN.md](../DESIGN.md)
