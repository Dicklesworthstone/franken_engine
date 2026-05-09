# Swarm Proof Batch Planner

`bd-ua5n2.5`

`scripts/swarm_proof_batch_planner.sh` recommends advisory proof scheduling
actions from captured proof requests, equivalence decisions, artifact-index
freshness, worker posture, fairness debt, and operator intent. It never runs
Cargo or RCH, mutates live queues, mutates workers, or creates/deletes target
directories.
It never runs Cargo or RCH.

## Actions

- `coalesce`: merge duplicate proof requests behind one evidence row.
- `reuse`: use a fresh reusable artifact-index row.
- `rerun_now`: schedule a proof now, optionally with warm-cache guidance.
- `rerun_later`: defer until stale or incomplete evidence is refreshed.
- `keep_isolated`: avoid batching because target isolation is required.
- `human_review`: conflicting operator intent or unclear policy.

Warm-cache recommendations are advisory only. Every recommendation includes
evidence paths, a rollback note, and remediation text.

## Validation

```bash
jq empty docs/swarm_proof_batch_planner_contract_v1.json scripts/testdata/swarm_proof_batch_planner/cases.json
bash -n scripts/swarm_proof_batch_planner.sh
bash -n scripts/e2e/swarm_proof_batch_planner_smoke.sh
bash scripts/e2e/swarm_proof_batch_planner_smoke.sh check
bash scripts/e2e/swarm_proof_batch_planner_smoke.sh selftest
git diff --check -- scripts/swarm_proof_batch_planner.sh docs/SWARM_PROOF_BATCH_PLANNER.md docs/swarm_proof_batch_planner_contract_v1.json scripts/testdata/swarm_proof_batch_planner/cases.json scripts/e2e/swarm_proof_batch_planner_smoke.sh
```
