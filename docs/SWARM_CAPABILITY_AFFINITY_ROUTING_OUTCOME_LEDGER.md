# SWARM_CAPABILITY_AFFINITY_ROUTING_OUTCOME_LEDGER

`scripts/swarm_capability_affinity_routing_outcome_ledger.sh` is the
SWARM-SCALE-IV-D fixture-fed ledger that records planned versus observed
capability-affinity routing outcomes.

The ledger is evidence-only and advisory-only. It does not update beads,
release reservations, send Agent Mail, run Cargo or RCH, mutate remote
workers, reroute live tasks automatically, or change the live queue policy.

Machine-readable child contract:
`docs/swarm_capability_affinity_routing_outcome_ledger_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh`.

## Inputs

Required preserved inputs:

- `--capability-affinity-routing-advisory-json FILE`
- `--routing-outcome-samples-json FILE`

Missing required advisory or routing-outcome evidence fails closed. `local fallback contamination fails closed`
and must not be promoted as a healthy match receipt.

## Artifacts

Each run emits:

- `swarm_capability_affinity_routing_outcome_ledger.json`
- `swarm_capability_affinity_routing_outcome_sources.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The ledger records:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- `reason_codes`
- `matched_task_ids`
- `mismatched_task_ids`
- `capability_gap_task_ids`
- `toolchain_drift_task_ids`
- `contamination_task_ids`
- per-task outcome rows that preserve recommended and observed workers

## Decisions

- `pass` / `confirmed`: observed routing matched the advisory cohort and no
  mismatch, capability gap, toolchain drift, or contamination was recorded.
- `degraded` / `degraded`: the ledger is coherent, but broader-cohort fallback,
  exclusion reasons, or non-contaminating route mismatch reduces confidence.
- `blocked` / `blocked`: the advisory or observed outcomes record unsupported
  capability coverage or toolchain drift that prevents a safe healthy outcome.
- `fail_closed` / `contaminated`: contaminated advisory input or observed local
  fallback invalidates remote-only routing truth.

`toolchain drift receipts block the outcome ledger`, and observed capability
gaps do the same even if the advisory was otherwise replayable.

## Proof Cases

The checked-in fixtures cover the required SWARM-SCALE-IV-D proof categories:

- `successful_cohort_match`
- `degraded_exclusion_reason_recorded`
- `blocked_toolchain_drift_receipt`
- `blocked_capability_gap_receipt`
- `contaminated_local_fallback`

`degraded_exclusion_reason_recorded` proves that broader-cohort fallback and
other exclusion reasons remain evidence-first degraded receipts instead of
being silently upgraded into healthy confirmation.

## Upstream Evidence Notes

The ledger is grounded in current shipped evidence shapes:

- the planner advisory already preserves advised workers, routing mode, reason
  codes, capability coverage, toolchain parity, and explicit mutation-policy
  guarantees
- routing-outcome samples preserve task-level recommended and observed workers
  plus observed outcome classifications
- rehabilitation receipts already cite `rch workers capabilities --refresh --json`
  as an operator evidence refresh command

## Validation

```bash
bash -n scripts/swarm_capability_affinity_routing_outcome_ledger.sh
bash -n scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh
shellcheck -x scripts/swarm_capability_affinity_routing_outcome_ledger.sh scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh
jq empty docs/swarm_capability_affinity_routing_outcome_ledger_contract_v1.json scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json
bash scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh check
bash scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh selftest
git diff --check -- docs/SWARM_CAPABILITY_AFFINITY_ROUTING_OUTCOME_LEDGER.md docs/swarm_capability_affinity_routing_outcome_ledger_contract_v1.json scripts/swarm_capability_affinity_routing_outcome_ledger.sh scripts/e2e/swarm_capability_affinity_routing_outcome_ledger_smoke.sh scripts/testdata/swarm_capability_affinity_routing_outcome_ledger/fixtures.json
```
