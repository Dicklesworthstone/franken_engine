# Swarm Autopilot Operator Intent Policy

`scripts/swarm_autopilot_operator_intent_policy.sh` compiles declarative
operator intents into deterministic swarm-control policy JSON. It verifies the
policy against the evidence warehouse and brownout forecaster before the policy
can influence future recommendations.

Machine-readable contract: `docs/swarm_autopilot_operator_intent_policy_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh`

Fixture cases: `scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json`

## Inputs

Required inputs:

- `intent_json`
- `evidence_warehouse_json`
- `forecaster_json`

Supported declarative intents:

- `reserve_urgent_rch_slack`
- `cap_nonurgent_heavy_fanout`
- `protect_p1_latency`
- `prefer_warm_cache_reuse`
- `avoid_drained_or_probe_workers`
- `bound_per_agent_fairness_skew`
- `safe_mode_on_degraded`

## Artifacts

Every run emits:

- `operator_intent_policy.json`
- `verification_report.json`
- `counterexamples.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The compiled policy preserves thresholds, precedence order, conflict
diagnostics, fallback behavior, worker exclusions, verification summaries,
artifact paths, and mutation policy.

## Truth Rules

- Schema drift in intents, warehouse evidence, or forecaster evidence fails
  closed.
- Stale warehouse or forecaster evidence fails closed.
- Non-pass warehouse evidence fails closed.
- Conflicting latency, utilization, or RCH slack intents fail closed with
  bounded counterexamples.
- Fairness precedence outranks warm-cache reuse when both are present.
- Safe mode is deterministic fallback behavior: it defers nonurgent heavy lanes,
  preserves urgent RCH slack, and requires remote-only evidence.

Fail-closed policies do not influence downstream recommendations. Safe-mode
policies may be consumed because their fallback actions are explicit and
conservative.

The compiler is proof-only and fixture-fed. It does not mutate beads, reassign
work, release reservations, send Agent Mail, run Cargo, run RCH, mutate workers,
pin workers, or change live queue policy. It only writes under its output
directory.

## Proof Cases

The checked-in fixtures cover:

- `valid_policy_compilation`
- `conflicting_latency_vs_utilization`
- `stale_evidence_rejection`
- `fairness_precedence`
- `safe_mode_fallback`

## Validation

```bash
bash -n scripts/swarm_autopilot_operator_intent_policy.sh scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh
shellcheck -x scripts/swarm_autopilot_operator_intent_policy.sh scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh
jq empty docs/swarm_autopilot_operator_intent_policy_contract_v1.json scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json
bash scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh check
bash scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_OPERATOR_INTENT_POLICY.md docs/swarm_autopilot_operator_intent_policy_contract_v1.json scripts/swarm_autopilot_operator_intent_policy.sh scripts/e2e/swarm_autopilot_operator_intent_policy_smoke.sh scripts/testdata/swarm_autopilot_operator_intent_policy/cases.json
```
