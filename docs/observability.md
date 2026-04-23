# Observability

CrabTrap emits an optional OpenTelemetry metric surface, served as Prometheus scrape text on the admin HTTP port. This document is the operator reference: metric catalog, network-exposure guidance, and alert suggestions.

## Enabling

In `config/gateway.yaml`:

```yaml
observability:
  metrics:
    enabled: true                  # default: false
    auth: cookie                   # cookie | none (default: cookie when enabled)
    i_know_this_is_public: false   # required when auth == "none"
```

When enabled, the gateway serves `GET /metrics` on the admin port (default `8081`) in Prometheus text format.

### Build-time metadata

CrabTrap surfaces build identification via `crabtrap_build_info`. Values come from `-ldflags -X` at link time:

```bash
go build -ldflags " \
  -X main.version=$(git describe --tags --always) \
  -X main.commit=$(git rev-parse HEAD) \
  -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/gateway
```

When not set, these default to `dev` / `unknown`.

## Authentication

| `auth` value | Behavior | Recommended for |
|-------------|----------|-----------------|
| `cookie` (default when `enabled: true`) | `/metrics` requires a valid admin session cookie — the same cookie that gates `/admin/*`. Unauthenticated scrapes return 401. | Shared-cluster deployments, public networks, anywhere admin auth is already the trust boundary. |
| `none` + `i_know_this_is_public: true` | `/metrics` is served with no auth. Startup logs a warning. | Private-network-only deployments where the admin port is constrained by firewall rules or bind-address config. |

### Label values are operational signal

The metric surface does not include per-user or per-request labels. Cardinality is bounded by configured providers, models, approval modes, and outcome categories — all of which come from config, not request input.

However, the label *values* themselves reveal operational posture:

- `crabtrap_approval_decisions_total{outcome, mode}` shows your allow/deny ratio
- `crabtrap_llm_circuit_breaker_state{provider}` reveals which LLM providers you have configured
- `crabtrap_approval_latency_seconds` reveals LLM judge SLA

Treat the `/metrics` endpoint as operational intelligence. Do not expose the admin port (default 8081) to untrusted networks without a compensating control (firewall rule, loopback bind, service mesh auth).

## Prometheus scrape config

Basic example (admin port on a private network, `auth: none`):

```yaml
scrape_configs:
  - job_name: crabtrap
    static_configs:
      - targets: ['crabtrap-admin:8081']
    metrics_path: /metrics
    scrape_interval: 15s
    scrape_timeout: 5s
```

With cookie auth, provision an admin token for your scraper and set it via the `Cookie` header:

```yaml
scrape_configs:
  - job_name: crabtrap
    static_configs:
      - targets: ['crabtrap-admin:8081']
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
    authorization: {}
    # Pass the admin auth cookie; store the token in a file that Prometheus can read.
    http_headers:
      Cookie:
        values: ['token=YOUR_SCRAPER_ADMIN_TOKEN']
```

## Metric catalog

### Counters

| Name | Labels | Description |
|------|--------|-------------|
| `crabtrap_rate_limit_hits_total` | — | Requests rejected by the per-IP rate limiter (HTTP 429). |
| `crabtrap_llm_circuit_breaker_trips_total` | `provider` | Times an LLM adapter's circuit breaker tripped from closed to open. Fires exactly once per transition. |
| `crabtrap_approval_decisions_total` | `outcome` (`allow`\|`deny`), `mode` (`llm`\|`passthrough`) | Every approval decision emitted by the approval pipeline. |

### Histograms (seconds)

| Name | Labels | Description |
|------|--------|-------------|
| `crabtrap_judge_latency_seconds` | `provider`, `model` | Duration of each LLM judge call (the single HTTP round trip, excluding semaphore wait). |
| `crabtrap_approval_latency_seconds` | `mode`, `outcome` | End-to-end duration of `CheckApproval` — static rules, LLM judge, fallback, all paths. |

Histograms use OpenTelemetry's default exponential bucket layout, which covers sub-millisecond to ~10 seconds.

### Gauges

| Name | Labels | Description |
|------|--------|-------------|
| `crabtrap_llm_circuit_breaker_state` | `provider` | `1` = open (rejecting calls), `0` = closed or half-open probe window. |
| `crabtrap_build_info` | `version`, `commit`, `go_version` | Constant value `1`; labels carry the payload. |

## Suggested alerts

These are starting points — tune thresholds to your deployment. All examples use PromQL.

```promql
# Any circuit-breaker trip in the last 5 minutes — usually a provider incident.
- alert: CrabTrapCircuitBreakerTripped
  expr: rate(crabtrap_llm_circuit_breaker_trips_total[5m]) > 0
  for: 1m

# Circuit breaker has been open for 2+ minutes — provider is down or upstream is flapping.
- alert: CrabTrapCircuitBreakerOpen
  expr: crabtrap_llm_circuit_breaker_state == 1
  for: 2m

# Judge latency p95 exceeds threshold — provider is slow even if not erroring.
- alert: CrabTrapJudgeLatencyHigh
  expr: histogram_quantile(0.95, sum(rate(crabtrap_judge_latency_seconds_bucket[5m])) by (provider, le)) > 2.5
  for: 5m

# Deny rate spike — policy change or attack.
- alert: CrabTrapDenyRateSpike
  expr: |
    (
      rate(crabtrap_approval_decisions_total{outcome="deny"}[5m])
      / rate(crabtrap_approval_decisions_total[5m])
    ) > 0.5
  for: 10m

# No scrape in 2 minutes — gateway is down or metrics endpoint is misconfigured.
- alert: CrabTrapScrapeDown
  expr: up{job="crabtrap"} == 0
  for: 2m
```

## Cardinality notes

- `provider` is drawn from config (`llm_judge.provider`), bounded to one of `bedrock-anthropic`, `anthropic`, `openai`.
- `model` comes from the adapter's configured model ID (typically a small set per provider).
- `outcome` has two values: `allow`, `deny`.
- `mode` has two values: `llm`, `passthrough`.
- No label value is ever derived from request paths, headers, or bodies.

Upper bound on combined series count: ~`providers × models × outcomes × modes × buckets` per histogram, which remains below 1 000 for any realistic deployment. No cardinality blowout risk from user traffic.

## Operational lifecycle

- **Enabling in prod**: start with `auth: cookie`, verify scrape succeeds against a test token, then either keep cookie auth or move to `auth: none` behind a firewall.
- **Rotating**: changing `observability.metrics.*` requires a gateway restart. No hot-reload.
- **Disabling**: set `enabled: false`. The `/metrics` route is not registered; scrapes return 404 via the catch-all.

## What's not here (yet)

- OpenTelemetry traces (separate feature, different exporter choices)
- `pprof` profiling endpoint (different security posture, deserves its own flag)
- Per-user or per-request metrics (cardinality risk)

Contributions welcome for any of these via a follow-up PR.
