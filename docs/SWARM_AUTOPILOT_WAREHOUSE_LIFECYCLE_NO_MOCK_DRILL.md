# SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_NO_MOCK_DRILL

`bd-gra1z.6`

This drill composes the shipped warehouse lifecycle producers into one
deterministic, no-mock proof surface.

The lifecycle boundary covers:

- `scripts/swarm_autopilot_warehouse_retention_planner.sh`
- `scripts/swarm_autopilot_promotion_candidate_miner.sh`
- `scripts/swarm_autopilot_anomaly_cohort_packer.sh`
- an operator-status lifecycle projection emitted by this drill
- `scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh`

## Truth

- The drill supports fixture, replay, and live modes.
- Fixture mode runs the real shipped lifecycle producer scripts against
  preserved upstream warehouse and hindsight inputs.
- Replay mode verifies a pinned complete bundle without rerunning producers.
- Live mode can consume a supplied real evidence warehouse and hindsight bundle.
- The drill does not run Cargo or RCH work directly.
- Retention pressure degrades trust without hiding replay-preserve artifacts.
- Contradictory hindsight, missing replay paths, stale warehouse evidence, and
  local fallback contamination fail closed.
- The lifecycle drill does not mutate beads, reservations, Agent Mail, workers,
  or live queue policy.

## Required Outputs

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `warehouse.json`
- `retention_plan.json`
- `storage_budget_ledger.json`
- `promotion_candidates.json`
- `promotion_candidate_receipts.json`
- `anomaly_cohorts.json`
- `replay_index.json`
- `operator_status_bundle.json`
- `truth_gate_report.json`

## Coverage

- `healthy_lifecycle`
- `retention_pressure_degradation`
- `promotion_contradiction_block`
- `anomaly_cohort_replay_success`
- `local_fallback_contamination`

## Validation

```bash
jq empty docs/swarm_autopilot_warehouse_lifecycle_no_mock_drill_contract_v1.json scripts/testdata/swarm_autopilot_warehouse_lifecycle_no_mock_drill/cases.json
bash -n scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill_smoke.sh
shellcheck -x scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill_smoke.sh
bash scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill_smoke.sh check
bash scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_NO_MOCK_DRILL.md docs/swarm_autopilot_warehouse_lifecycle_no_mock_drill_contract_v1.json scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_truth_gate.sh scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill_smoke.sh scripts/testdata/swarm_autopilot_warehouse_lifecycle_no_mock_drill/cases.json
```
