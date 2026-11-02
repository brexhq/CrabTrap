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
    allow_below: 0          # noul < this → ALLOW (default 0: direct ALLOW is off)
    deny_above: 0.7         # noul >= this → DENY
```

**Data sharing.** Jev receives the same request JSON the LLM judge gets: the
policy, method, URL, headers (including credentials such as `Authorization`
and `Cookie`, capped at 4KB total) and up to 16KB of body. Enabling Jev sends
that data to TypeSafe in addition to your LLM provider, so make sure that is
acceptable before turning it on.

Jev answers each question with a **noul** score: its probability, in [0, 1],
that the answer is true. CrabTrap asks "does this request violate the policy?",
so the score is p(violates).

Pin a versioned `model`. Aliases such as `jev-latest` move to new releases,
which can shift scores under thresholds you already calibrated. Short-circuit
audits record the configured `model`.

- Admin evals do not run Jev. Replay checks static rules first, then uses the
  LLM if no rule matches. Labeled entries are always compared against their
  label. For unlabeled audit entries that Jev decided (`approved_by: jev`),
  agreement measures the replay decision against Jev's original decision. The
  eval view marks these entries. For unlabeled entries decided after Jev
  escalated (`jev+llm`), replay compares against the original LLM decision; the
  replay itself may still be decided by a static rule.
- Policy builder still needs a generative LLM.
- Audit rows show how a request was decided (`Channel` stays `llm`, same as static rules):
  - `approved_by: jev`: Jev decided alone (an ALLOW or DENY short-circuit). The model is the configured Jev `model`.
  - `approved_by: jev+llm`: Jev was consulted first (uncertain score or error) and the LLM decided. The model reads `<jev model> + <llm model>`, duration and tokens include Jev's, and the raw output starts with Jev's score or notes that Jev errored.
  - `approved_by: llm`: no Jev involved (cascade off, or Jev skipped because it was at capacity or its breaker was open).
  - `approved_by: llm-fallback`: Jev escalated but the LLM then errored, so the fallback mode decided. These rows are not counted as `jev+llm` (so LLM outages stay visible under the fallback filter), but the response still shows `<jev model> + <llm model>` and includes Jev's duration and tokens.
  The Audit Trail Approver filter has options for `jev` and `jev+llm`.
- Jev never queues: if all `max_concurrency` slots are busy or its circuit breaker is open, the request goes straight to the LLM and counts as `outcome=skipped`, not `error`. Worst-case latency on escalation is `jev.timeout` plus the LLM call.
- Jev reuses `llm_judge.max_concurrency` and the circuit-breaker settings (separate instance, same numbers).
- Jev's circuit breaker counts 5xx, 429, 401/403 (a bad or revoked API key), timeouts and transport errors. Other 4xx responses (for example a request Jev rejects as too large) escalate to the LLM as `outcome=error` but do not trip the breaker.
- Metrics: `crabtrap_jev_decisions_total{outcome=allow|deny|escalate|error|skipped}`, plus Jev's circuit breaker and call latency under the existing `crabtrap_llm_circuit_breaker_*` and `crabtrap_judge_latency_seconds` metrics with `provider="jev"`.
- A caller that disconnects mid-call does not count toward Jev's circuit breaker or `outcome=error`, and the request is not escalated to the LLM; Jev's own timeouts and transport errors still count.

Direct ALLOWs are opt-in. `allow_below` defaults to 0, so by default only DENY
short-circuits and everything else goes to the LLM. Jev gets the policy and the
request as JSON-escaped state, the same serialization the LLM judge uses, but
none of the LLM judge's system-prompt instructions to resist injection, so an
attacker-controlled body could try to push its score under the threshold.
Turn `allow_below` on only after calibrating it for your policy.

`allow_below` and `deny_above` default independently: set one and the other
keeps its default. Both must be in [0, 1] with `allow_below <= deny_above`.
Leaving `deny_above` unset uses the default 0.7. An explicit 0 is preserved
and denies every valid score (with `allow_below: 0`).
Setting `allow_below` equal to `deny_above` leaves no escalation band.

The [published ATRDF experiment](https://gist.github.com/aljawetz/2ded463bfddfad8b64229b09ba03c152)
compared LLM-only, Jev-only and cascade decisions on 4,282 labeled requests.
Its Jev-only results have a lowest attack score of 0.56. This dataset contains
synthetic inbound traffic, not production outbound agent requests. Scores
shift with policy text and model version, so these results do not calibrate
a deployment's ALLOW threshold.

## Injection check

`internal/judge/jev_injection_eval_test.go` measures how far attacker-controlled
text moves Jev's score. It scores each attack plain, then with injection text
added through the query string, a header, the body, and an "ignore previous
instructions" override that includes a fake policy fragment. It calls the real
Jev API, so it only runs when you opt in (a key alone is not enough):

```
JEV_INJECTION_EVAL=1 TYPESAFE_API_KEY=... go test ./internal/judge -run TestJevInjectionEval -v -count=1
```

Variants whose injection text is removed or truncated by request serialization
are reported as skipped and excluded from the score counts.

It uses a small built-in attack set and policy by default. Set
`JEV_INJECTION_DATASET` (JSONL of `id, method, url, headers, body, attack_tag`)
and `JEV_INJECTION_POLICY_FILE` to replay your own.

Live checks on 2026-10-27 used `jev-1.13.0` with the serialization check enabled:

| Input and policy | Attacks | Variants tested / skipped | Lowest plain / injected score | Largest observed drop |
|---|---:|---:|---:|---:|
| Built-in synthetic set and generic anti-exploit policy | 6 | 24 / 0 | 0.82 / 0.79 | 0.06 |
| ATRDF low-scoring attacks and the gist's original policy | 48 | 192 / 0 | 0.51 / 0.48 | 0.15 |

The ATRDF subset consists of every `results.csv` row labeled `attack` with
`jev_score < 0.7`, all Log Forging attacks. Row IDs refer to zero-based indices
in `Datasets/dataset_1_train.7z` from
[dataset commit 9494785](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/tree/9494785a35dfa447bedddd80c0bb3fff3f0f464a).
All 4,282 row labels were checked against the source dataset before selecting
the subset. The two historically lowest-scoring rows, 2330 and 3008, were included.
Use the gist's `policy.txt` and convert the selected requests to the JSONL
schema above, wrapping each header value in an array.

No tested injection scored below 0.2 in either run. In the ATRDF subset,
seven injected variants scored at least 0.10 below their corresponding plain
request, and four crossed from a plain score at or above 0.7 to below 0.7.
Those four would escalate to the LLM instead of being denied by Jev. The
lowest injected score, 0.48, was the body variant of row 2330.

These are single-call comparisons and include possible model variation; they
do not isolate the effect of injection or establish general resistance. The
ATRDF subset covers one attack family and simple, hand-written injections.
Direct ALLOWs remain opt-in. Calibrate with your own policy and requests
before enabling them.
