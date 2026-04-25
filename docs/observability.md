# Observability

CrabTrap emits an optional OpenTelemetry metric surface, served as Prometheus scrape text on a dedicated HTTP listener. This document is the operator reference: metric catalog, network-exposure guidance, and alert suggestions.

## Enabling

In `config/gateway.yaml`:

```yaml
observability:
  metrics:
    enabled: true                  # default: false
    listen: "127.0.0.1:9090"       # bind address for the metrics listener (default)
```

When enabled, the gateway runs a separate HTTP listener that serves `GET /metrics` in Prometheus text format. Nothing else is mounted on this listener — the admin and proxy ports are unaffected.

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

## Network exposure

The metrics listener is unauthenticated by design — Prometheus scrapers should not need to manage admin credentials. Network exposure is controlled by the `listen` bind address, not by an auth toggle.

| `listen` value | Behavior | Recommended for |
|-----------------|----------|-----------------|
| `127.0.0.1:9090` (default) | Listener binds to loopback only. Reachable from the gateway host but not from another machine. | Single-host deployments where Prometheus scrapes from a sidecar or local agent. The default. |
| `<private-iface-ip>:9090` | Listener binds to a private interface (e.g. `10.0.1.42:9090`). Reachable inside the private network only. | Cluster deployments where Prometheus runs on a separate node within the trust boundary. |
| `0.0.0.0:9090` | Listener binds to all interfaces. Reachable from anywhere routable. | Only behind firewall rules or service-mesh auth that gate access externally. |

### Label values are operational signal

The metric surface does not include per-user or per-request labels. Cardinality is bounded by configured providers, models, approval modes, and outcome categories — all of which come from config, not request input.

However, the label *values* themselves reveal operational posture:

- `crabtrap_approval_decisions_total{outcome, mode}` shows your allow/deny ratio
- `crabtrap_llm_circuit_breaker_state{provider}` reveals which LLM providers you have configured
- `crabtrap_approval_latency_seconds` reveals LLM judge SLA

Treat the `/metrics` endpoint as operational intelligence. Do not bind the listener to a public interface without a compensating control (firewall rule, service mesh auth, reverse proxy).

## Prometheus scrape config

Basic example (loopback bind, scraper running on the same host):

```yaml
scrape_configs:
  - job_name: crabtrap
    static_configs:
      - targets: ['127.0.0.1:9090']
    metrics_path: /metrics
    scrape_interval: 15s
    scrape_timeout: 5s
```

For a remote scraper, set `listen` to a private interface address and target that host from Prometheus:

```yaml
scrape_configs:
  - job_name: crabtrap
    static_configs:
      - targets: ['crabtrap-host.internal:9090']
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
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
| `crabtrap_build_info` | `version`, `commit`, `go_version`, `build_date` | Constant value `1`; labels carry the payload. `build_date` is the build timestamp injected via `-ldflags -X main.buildDate`. |

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

- **Enabling in prod**: keep the default loopback bind, verify a local scrape succeeds, then move `listen` to a private interface address as your scrape topology requires.
- **Rotating**: changing `observability.metrics.*` requires a gateway restart. No hot-reload.
- **Disabling**: set `enabled: false`. The metrics listener is not started; scrapes against the configured port fail with connection refused.

## What's not here (yet)

- OpenTelemetry traces (separate feature, different exporter choices)
- `pprof` profiling endpoint (different security posture, deserves its own flag)
- Per-user or per-request metrics (cardinality risk)

Contributions welcome for any of these via a follow-up PR.
