# Jev cascade (experimental, default off)

Optional pre-filter: static rules → Jev → LLM (only if uncertain or Jev errors).

```yaml
llm_judge:
  provider: openai          # still required — escalate target
  eval_model: gpt-4o-mini
  openai_api_key: ${OPENAI_API_KEY}
  jev:
    enabled: true
    api_key: ${TYPESAFE_API_KEY}
    model: jev-1.13.0       # pinned; see below
    allow_below: 0.2        # noul < this → ALLOW
    deny_above: 0.7         # noul >= this → DENY
```

Jev answers each question with a **noul** score: its probability, in [0, 1],
that the answer is true. CrabTrap asks "does this request violate the policy?",
so the score is p(violates).

Pin a versioned `model`. Aliases such as `jev-latest` move to new releases,
which can shift scores under thresholds you already calibrated. Short-circuit
audits record the configured `model`.

- Admin evals stay LLM-only.
- Policy builder still needs a generative LLM.
- Short-circuit audits use `ApprovedBy: jev` (`Channel` stays `llm`, same as static rules).
- Jev never queues: if all `max_concurrency` slots are busy or its circuit breaker is open, the request goes straight to the LLM. Worst-case latency on escalation is `jev.timeout` plus the LLM call.
- Jev reuses `llm_judge.max_concurrency` and the circuit-breaker settings (separate instance, same numbers).
- Metric: `crabtrap_jev_decisions_total{outcome=allow|deny|escalate|error}`.

The default `allow_below: 0.2` is a starting point, not a calibrated value. In a public smoke test (synthetic HTTP attack traffic, one generic policy) benign requests mostly scored 0.1 to 0.3 and the lowest-scoring attack scored 0.26. At 0.1 almost every benign request still escalated, which made the cascade cost more than the LLM alone on benign-heavy traffic. Scores shift with the policy text and the Jev version, so recalibrate when either changes. A lower value is safer, and `allow_below: 0` (with `deny_above` also set) disables direct ALLOWs entirely; a higher one saves more LLM calls but lets more requests skip the LLM.
