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
    allow_below: 0.1        # noul < this → ALLOW
    deny_above: 0.7         # noul >= this → DENY
```

- Admin evals stay LLM-only.
- Policy builder still needs a generative LLM.
- Short-circuit audits use `ApprovedBy: jev` (`Channel` stays `llm`, same as static rules).
- Jev never queues: if all `max_concurrency` slots are busy or its circuit breaker is open, the request goes straight to the LLM. Worst-case latency on escalation is `jev.timeout` plus the LLM call.
- Jev reuses `llm_judge.max_concurrency` and the circuit-breaker settings (separate instance, same numbers).
- Metric: `crabtrap_jev_decisions_total{outcome=allow|deny|escalate|error}`.

The default uses a narrow direct-ALLOW band. Calibrate it against your own labeled evidence before widening it.
