# Implementation Summary

What has been built, and what remains.

**For architecture and design, see [DESIGN.md](DESIGN.md)**

---

## Phases

### Phase 1 — Core Proxy & Approval System ✅
- HTTP/HTTPS MITM proxy with TLS interception and custom CA
- Request classification (READ vs WRITE by HTTP method) for audit purposes
- SHA-256 request hashing with body/query normalization
- JSON audit log to stdout or file
- YAML configuration with sensible defaults

### Phase 2 — Multi-Channel Architecture & Web UI ✅
- Central notification dispatcher (fan-out to all registered channels)
- SSE channel for real-time browser updates with auto-reconnect
- React + TypeScript + Tailwind web UI
- Expandable audit trail with full request/response details, JSON formatting, filters
- Production binary serving UI from `web/dist` on disk; dev mode with Vite HMR

### Phase 3 — LLM Judge & Per-User Policies ✅
- LLM-as-judge approval: all requests evaluated against user's policy via AWS Bedrock
- Per-user LLM policy management with versioning (fork/publish model)
- Static rules (allow/deny by URL pattern) evaluated before LLM judge
- Sealed `EventData` interface: compile-time enforcement of valid event payload types
- Per-user SSE filtering: each authenticated browser session sees only its own events
- Web token auth: static pre-shared token per user stored in PostgreSQL; passed as `Authorization: Bearer` header or HttpOnly `token` cookie (set server-side via `POST /admin/login`)
- `GET /admin/me` endpoint for token validation
- Gateway auth tokens (`gat_` prefix) for proxy authentication

### Phase 4 — Persistent Storage & Evaluation ✅
- PostgreSQL-backed storage for all runtime state (audit log, users, policies)
- Database migrations managed via `internal/db/migrations/`
- Evaluation system: replay audit log entries against policies to measure accuracy
- LLM response metadata persistence (`llm_responses` table)
- Configurable log level (`log_level` config) with slog-based structured logging

### Phase 5 — Real Authentication ❌ Pending
- SSO/SAML/OIDC integration (replace static web tokens)
- Token rotation and expiry
- RBAC beyond admin/non-admin

---

## What Is Implemented

### Proxy & Approval

- **`internal/proxy/proxy.go`, `handler.go`** — Full HTTP/HTTPS MITM proxy, TLS interception, keep-alive, graceful shutdown; request/response payload logging at debug level via slog
- **`internal/proxy/tls.go`** — Custom CA, per-host certificate generation, in-memory cert cache
- **`internal/approval/manager.go`** — Orchestrates approval flow: mode check → static rule matching → LLM judge evaluation; reads user ID and LLM policy from context

### LLM Judge & Policies

- **`internal/judge/llm_judge.go`** — LLM evaluation interface; builds prompts from request context and policy
- **`internal/llm/bedrock.go`** — AWS Bedrock adapter for Anthropic models with prompt caching
- **`internal/llmpolicy/pg_store.go`** — PostgreSQL policy store with CRUD, fork, publish, soft-delete
- **`internal/builder/`** — Policy agent with agentic AI loop for policy synthesis
- **`internal/eval/`** — Evaluation runner: replays audit entries against policies, tracks results and stats

### Notification System

- **`internal/notifications/dispatcher.go`** — Fans out `Event` to all registered channels in parallel
- **`internal/notifications/types.go`** — `Event{Type, Data types.EventData, Channel}`; `EventData` is a sealed interface from `pkg/types`
- **`internal/notifications/sse.go`** — SSE channel; `SSEClient` with `userID`; `TargetUserID`-based event routing; `ServeHTTPForUser` for authenticated clients

### Admin API

- **`internal/admin/api.go`** — `WebTokenValidator` interface; token extraction (Bearer → cookie); `GET /admin/me`; user/policy/eval/audit endpoints; SSE serving
- **`internal/admin/pg_audit_reader.go`** — PostgreSQL-backed audit reader with filtering and pagination
- **`internal/admin/pg_user_store.go`** — User CRUD, gateway auth token management, policy assignment

### Database

- **`internal/db/pool.go`** — PostgreSQL connection pool via pgx
- **`internal/db/migrations/`** — Sequential SQL migrations (001–023)
- **`internal/dbtest/`** — Test helpers for database setup

### Audit

- **`internal/audit/logger.go`** — JSON structured logging; captures request headers and body; broadcasts `*types.AuditEntry` to dispatcher

### Web UI

- **`web/src/App.tsx`** — Hash router with `AuthProvider` and `RequireAuth` guard
- **`web/src/contexts/AuthContext.tsx`** — Auth state machine: restore token from localStorage → validate via `POST /admin/login` (sets HttpOnly cookie for SSE) → `LoginPage` or audit trail
- **`web/src/components/LoginPage.tsx`** — Token input form
- **`web/src/components/AuditTrail.tsx`** — Searchable history, expandable rows, request/response side-by-side view (landing page)
- **`web/src/components/PoliciesPanel.tsx`, `PolicyDetail.tsx`** — LLM policy list, detail, fork, publish, agent chat
- **`web/src/components/UsersPanel.tsx`, `UserDetailPage.tsx`** — User management, policy assignment
- **`web/src/components/EvalsPanel.tsx`, `EvalDetail.tsx`** — Evaluation runs and results
- **`web/src/components/Layout.tsx`** — Navigation, signed-in user + sign-out
- **`web/src/api/client.ts`** — REST client with auth headers
- **`web/src/api/sse.ts`** — SSE client with auto-reconnect and exponential backoff

### Wiring

- **`cmd/gateway/main.go`** — Wires proxy, user resolver, dispatcher, SSE, audit logger, admin API, LLM judge, policy agent; configures slog log level
- **`cmd/gateway/web_handler.go`** — Serves web UI from `web/dist` on disk
- **`cmd/gateway/cmd_create_admin_user.go`** — CLI subcommand to bootstrap admin users

---

## What Is Pending

### Real Authentication

The current web token auth is a static pre-shared secret per user stored in PostgreSQL. This is sufficient for a single-user or trusted-team deployment but is not production auth:

- No token rotation or expiry
- No SSO/SAML/OIDC integration
- No RBAC beyond admin/non-admin (all admins can manage all resources)
- No multi-tenant isolation

The `admin.WebTokenValidator` interface is the abstraction point for swapping in a real auth provider.
