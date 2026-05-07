# SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER

`scripts/swarm_topology_aware_queue_fidelity_ledger.sh` is the
SWARM-SCALE-III-D fixture-fed locality fidelity and cache-reuse outcome ledger.

It compares the shipped topology-aware queue advisory against the emitted queue
artifact, the bottleneck report, the later placement evidence ledger, and the
checked-in locality outcome samples. It is advisory-only. It does not update
beads, release reservations, send Agent Mail, run Cargo or RCH, mutate remote
workers, or change live queue policy.

Machine-readable child contract:
`docs/swarm_topology_aware_queue_fidelity_ledger_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh`.

## Inputs

Required preserved inputs:

- `--queue-advisory-bundle-json FILE`
- `--placement-evidence-ledger-json FILE`
- `--queue-artifact-json FILE`
- `--bottleneck-report-json FILE`
- `--locality-outcome-samples-json FILE`

Missing required inputs fail closed. The ledger must distinguish missing evidence from contradictory evidence so later tuning work is not trained on partial or contaminated outcomes.

## Artifacts

Each run emits:

- `swarm_topology_aware_queue_fidelity_receipt.json`
- `swarm_topology_aware_queue_drift_ledger.json`
- `swarm_topology_aware_queue_fidelity_sources.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The receipt preserves:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- `reason_codes`
- `matched_task_ids`
- `cache_cold_no_reuse_credit_task_ids`
- `cache_reuse_confirmed_task_ids`
- `cache_reuse_missed_task_ids`
- `locality_drift_task_ids`
- `drained_worker_avoidance_task_ids`
- `excluded_worker_violation_task_ids`
- `missing_outcome_task_ids`
- aggregate locality, cache, contradiction, and completeness metrics
- per-task outcome rows for later replay or tuning review

## Truth Rules

- Local fallback contamination fails closed.
- Contradictory locality or receipt evidence blocks the ledger.
- Cache-cold fallback must not receive false cache-reuse credit.
- Missing task-level outcome evidence degrades confidence instead of being
  silently treated as a match.
- Drained-worker avoidance success remains degraded when the upstream advisory
  was already conservative, but observed use of an excluded worker blocks the
  ledger.
- The ledger must not claim it changed the live queue, pinned workers, or
  repaired worker placement automatically.

## Proof Cases

The checked-in fixtures cover:

- `healthy_locality_match`
- `cache_cold_fallback_no_false_reuse_credit`
- `blocked_locality_drift`
- `degraded_drained_worker_avoidance_success`
- `blocked_drained_worker_avoidance_failure`
- `contaminated_local_fallback`

## Validation

```bash
bash -n scripts/swarm_topology_aware_queue_fidelity_ledger.sh
bash -n scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh
shellcheck -x scripts/swarm_topology_aware_queue_fidelity_ledger.sh scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh
jq empty docs/swarm_topology_aware_queue_fidelity_ledger_contract_v1.json scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json
bash scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh check
bash scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER.md docs/swarm_topology_aware_queue_fidelity_ledger_contract_v1.json scripts/swarm_topology_aware_queue_fidelity_ledger.sh scripts/e2e/swarm_topology_aware_queue_fidelity_ledger_smoke.sh scripts/testdata/swarm_topology_aware_queue_fidelity_ledger/fixtures.json
```
