# CrabTrap - Design Document

## Overview

The CrabTrap is a security mesh that intercepts all external API calls from AI agent instances (e.g. AI agents), providing centralized control over write operations and audit logging.

Two core security guarantees:
1. **Write Operation Safety** — No agent can modify external systems (send emails, create calendar events, delete documents) without passing the LLM policy judge.
2. **Data Exfiltration Prevention** — All outbound traffic is visible and controllable.

The gateway is transparent to agents: they configure it as an HTTP proxy.

---

## Architecture Overview

```
┌─────────────────────┐
│   AI Agent          │  (configured with HTTP_PROXY=localhost:8080)
│   (AI agents, etc.)  │
└────────┬────────────┘
         │ HTTP(S)
         ▼
┌────────────────────────────────────────────────────┐
│              HTTP/HTTPS MITM Proxy                 │
│                  (port 8080)                       │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  1. TLS Interception (custom CA cert)        │  │
│  └──────────────────┬───────────────────────────┘  │
│                     │                              │
│  ┌──────────────────▼───────────────────────────┐  │
│  │  2. Approval Manager (all methods)           │  │
│  └──────────────────┬───────────────────────────┘  │
│                     │                              │
│              ┌──────▼──────┐                       │
│              │ Static rules│                       │
│              │ (if any)    │                       │
│              └──────┬──────┘                       │
│            ┌────────┴────────┐                     │
│            │ Matched         │ No match            │
│            ▼                 ▼                     │
│       Allow / Deny    Check LLM policy             │
│                              │                     │
│                   ┌──────────┴────────────┐        │
│                   │ Policy assigned?       │        │
│                   └──────────┬─────────────┘        │
│                LLM judge     │ No policy:           │
│                decision      │ deny/passthru        │
│                   │          ▼                     │
│                   │    Deny or allow               │
│                   │    (per fallback_mode)          │
│                   │         │                     │
│                   └────┬────┘                     │
│                        │ Allow / Deny /            │
│                        │ Timeout                   │
└──────────────────────────────┼────────────────────┘
         │                     │
         ▼                     ▼
  External APIs         Audit Log (PostgreSQL)

         ┌──────────────────────────────────────┐
         │  Admin Web UI (port 8081)             │
         │  • Audit trail                        │
         │  • LLM policy management              │
         │  • Evaluation runs                    │
         │  • User management                    │
         └──────────────────────────────────────┘

         ┌──────────────────────────────────────┐
         │  Evaluation System (offline path)     │
         │  • Replay audit_log entries           │
         │  • Score against LLM policy           │
         │  • Agreed / disagreed / errored       │
         └──────────────────────────────────────┘
```

---

## Component Design

### 1. HTTP Proxy Layer

A Go MITM proxy that intercepts all HTTP and HTTPS traffic.

- **TLS interception**: CONNECT tunneling with per-host certificate generation signed by a custom CA. The CA cert must be installed on the agent machine.
- **Keep-alive**: Connections are held with standard HTTP keep-alive.
- **Configurable log level**: Set `log_level: debug` to log full request/response headers and bodies via slog.

### 2. Request Classification

All requests — regardless of HTTP method — pass through the approval manager. The LLM judge (or static rules / fallback mode) decides whether each request is allowed or denied.

HTTP methods are classified as READ (`GET`, `HEAD`, `OPTIONS`) or WRITE (`POST`, `PUT`, `PATCH`, `DELETE`) **for audit logging only**; this label does not affect the approval flow.

### 3. Approval Flow

**LLM policy check**: The approval manager checks whether the requesting user has an active LLM policy:
- If a policy is assigned: the judge is invoked and its decision (approve/deny) is applied directly.
- If no policy is assigned: the request is denied or passed through (configurable via `fallback_mode`).
- On judge error: deny the request, or pass through (configurable).

### 4. Notification System

A central `Dispatcher` fans out `Event` values to all registered `Channel` implementations in parallel.

**Event types**:
- `EventAuditEntry` — data: `*types.AuditEntry`

`Event.Data` is typed as the sealed interface `types.EventData`, which the concrete payload types implement. This is enforced at compile time.

**SSE channel**:
- All SSE clients must be authenticated as admins
- `EventAuditEntry` is broadcast to all connected clients

### 5. Admin API (port 8081)

**Authentication**: Each user has a static `web_token` stored in their `user_channels` row (channel_type='web'). The token is passed as `Authorization: Bearer <token>` header or `token` cookie (HttpOnly, SameSite=Strict, optionally Secure via `admin.secure_cookie` config).

**Endpoints**:
| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/login` | Validate token and set HttpOnly auth cookie |
| `POST` | `/admin/logout` | Clear auth cookie |
| `GET` | `/admin/me` | Return `{user_id, is_admin}` for the current token, or 401 |
| `GET` | `/admin/audit` | Query audit log (filters: decision, method, user, time range) |
| `GET` | `/admin/audit/{id}` | Get single audit entry |
| `PUT/DELETE` | `/admin/audit/{id}/label` | Set / remove ground-truth label on audit entry |
| `GET` | `/admin/events` | SSE stream (filtered to the authenticated user's requests) |
| `GET` | `/admin/health` | Health check (returns `{"status": "ok"}`) |
| `GET/POST` | `/admin/users` | List / create users |
| `GET/PUT/DELETE` | `/admin/users/{email}` | Get / update / delete user |
| `GET/POST` | `/admin/llm-policies` | List / create LLM policies |
| `GET/PUT/DELETE` | `/admin/llm-policies/{id}` | Get / update / soft-delete policy |
| `POST` | `/admin/llm-policies/{id}/publish` | Publish a draft policy |
| `POST` | `/admin/llm-policies/{id}/fork` | Fork a policy version |
| `POST` | `/admin/llm-policies/{id}/agent` | AI agent editing loop |
| `GET` | `/admin/llm-policies/{id}/metadata` | Get policy metadata |
| `GET` | `/admin/llm-policies/{id}/stats` | Get policy traffic stats |
| `GET/POST` | `/admin/evals` | List / create eval runs |
| `GET` | `/admin/evals/{id}` | Get eval run with aggregate stats |
| `GET` | `/admin/evals/{id}/results` | Get eval results |
| `GET` | `/admin/evals/{id}/stats` | Get eval run stats by approver |
| `POST` | `/admin/evals/{id}/cancel` | Cancel a running eval |
| `GET` | `/admin/llm-responses/{id}` | Get LLM judge call metadata |
`approvedBy` is derived from the web token on the server side — the frontend does not send it.

### 6. Web UI

React + TypeScript + Tailwind, served from `web/dist` on disk (not embedded in the Go binary).

**Auth flow**: On load, the client checks localStorage for a saved token. If found, it calls `POST /admin/login` to validate the token and set an HttpOnly cookie for SSE requests, then proceeds to the audit trail. If invalid or missing, show `LoginPage`.

**Views**:
- **Audit Trail**: Searchable history with expandable rows showing full request/response, JSON formatting, filters, date range (landing page)
- **LLM Policies**: Create policies, fork versions, assign to users
- **Evaluations**: Create eval runs, view per-entry results and accuracy stats
- **Users**: User management panel (list, create, manage channels)

### 7. Audit Logging

Every request is logged to PostgreSQL (`audit_log` table). Each entry includes: timestamp, request ID, method, URL, operation type, decision, approved by, channel, response status, duration, full request headers/body, full response headers/body, LLM policy ID (if evaluated), LLM response ID (if evaluated).

The `audit.output` config option may additionally write entries to stderr (default), stdout, or a file.

---

## Storage

| Data | Storage | Persistence |
|---|---|---|
| Users & channels | PostgreSQL `users`, `user_channels` | Yes |
| Audit log | PostgreSQL `audit_log` | Yes |
| LLM policies | PostgreSQL `llm_policies` | Yes |
| Eval runs & results | PostgreSQL `eval_runs`, `eval_results` | Yes |
| LLM judge call metadata | PostgreSQL `llm_responses` | Yes |
| Audit ground-truth labels | PostgreSQL `audit_labels` | Yes |

---

## Security Properties

- **Per-user web isolation** — SSE stream is authenticated; admin-only access

---

## Section 10: LLM Judge

The LLM Judge enables automated evaluation of write requests against a policy prompt, reducing reliance on human reviewers for well-understood workloads.

### Integration

- **Provider**: AWS Bedrock with Anthropic models
- **Policy storage**: `llm_policies` table; immutable versioned records — editing always forks a new version
- **Per-user assignment**: Each user row has an optional `llm_policy_id` foreign key

### Modes

| Mode | Behavior |
|---|---|
| `llm` (default) | Judge is invoked; its decision is applied directly |
| `passthrough` | All requests are allowed through without evaluation |

### Error Handling

If the judge returns an error:
- **Deny**: reject the request with a 403 (safe default)
- **Passthrough**: allow the request through

The fallback mode is configurable per deployment (`deny` or `passthrough`).

### No header or body redaction

The LLM judge receives the full HTTP request verbatim — headers and body are not sanitized or redacted. This is a deliberate design decision:

- **CrabTrap is a MiTM proxy.** It terminates TLS and already sees all traffic in cleartext, including credentials. The audit log records full request metadata. Redacting content before LLM evaluation does not reduce the trust boundary — it is already inside it.
- **Redaction cannot be done correctly.** APIs do not use consistent headers for authentication. Credentials appear in `Authorization`, `Cookie`, `X-Api-Key`, custom headers, query parameters, and request bodies. Any blocklist will be incomplete and give a false sense of security.
- **Redaction degrades policy decisions.** The judge needs full context to make accurate allow/deny decisions. Stripping headers or body content makes the LLM blind to signals it may need.

The appropriate controls are on the LLM provider side (data processing agreements, retention policies) and on access to the CrabTrap deployment itself (network isolation, admin authentication).

### Request body decompression

When a request carries a `Content-Encoding` header, the proxy decompresses the body before passing it to the LLM judge so the policy is evaluated against plaintext, not binary. The original compressed body is forwarded to the upstream unchanged.

**Supported encodings:**

| Encoding | Notes |
|---|---|
| `gzip`, `x-gzip` | Standard gzip (RFC 1952) |
| `deflate` | Tries zlib (RFC 1950) first, falls back to raw DEFLATE (RFC 1951) |
| `br` | Brotli, via `github.com/andybalholm/brotli` |

Stacked encodings (e.g. `Content-Encoding: gzip, deflate` or multiple header lines) are supported: layers are removed in reverse order per RFC 7230 §4.2.3.

On successful decompression, `Content-Encoding` and `Content-Length` are stripped from the eval headers so the judge sees a consistent request shape (decompressed body without stale compressed-size metadata).

**Unsupported or failed encodings:** If the encoding is not listed above, or if decompression fails (corrupt data, unknown format), the original compressed body and all headers — including `Content-Encoding` — are passed to the judge as-is. This lets the LLM see that the body is still encoded and factor that into its decision.

**Truncated compressed streams:** Request bodies are buffered up to 10 MB before decompression. If the compressed payload exceeds this limit, decompression proceeds on the buffered prefix. Any plaintext produced before the stream error is returned to the judge (partial decompression), so early content is still inspectable. Decompressed output is itself capped at 10 MB, and the judge consumes only the first 4 KB of body text.

### Metadata

Each judge invocation writes a row to `llm_responses` containing:
- Model ID
- Input and output token counts
- Wall-clock duration
- Decision (approve / deny)
- Reason (the model's explanation)
- Referenced by the `audit_log` entry via `llm_response_id` foreign key

---

## Section 11: Evaluation System

The evaluation system replays historical `audit_log` entries through an LLM policy to measure how well the policy matches prior human decisions.

### How It Works

1. An operator creates an eval run via `POST /admin/evals`, specifying a policy ID and an optional filter (date range, user, etc.).
2. A worker pool fetches matching audit entries and submits each to the judge.
3. Each result is written to `eval_results` with:
   - `replay_decision`: the judge's decision (ALLOW / DENY / ERROR)
   - `approved_by`: how it was approved (e.g., `llm`, `llm-static-rule`)
   - The judge's reason
4. Aggregate stats (agreed %, disagreed %, errored %) are computed on read by comparing `replay_decision` to the original audit entry's decision.

### Ground-Truth Labels

Audit entries can be manually labeled (e.g., `correct`, `incorrect`) to provide ground-truth annotations that go beyond the original human decision. Admins set a label via `PUT /admin/audit/{id}/label` and remove it via `DELETE /admin/audit/{id}/label`. Labels are one-per-entry and persist in the `audit_labels` table, so they are reused across all eval runs rather than being tied to a specific evaluation. Evaluation results can be filtered or scored against these labels.

### Worker Pool

Eval runs are processed asynchronously with a configurable concurrency level. Progress and status (`pending`, `running`, `completed`, `failed`) are tracked in the `eval_runs` table.

---

**For implementation status, see [IMPLEMENTATION.md](IMPLEMENTATION.md)**
