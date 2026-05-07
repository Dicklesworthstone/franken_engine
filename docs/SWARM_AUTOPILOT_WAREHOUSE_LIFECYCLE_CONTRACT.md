# SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_CONTRACT

`docs/swarm_autopilot_warehouse_lifecycle_contract_v1.json` defines the
contract-only summary bundle for warehouse retention planning, promotion
candidate review, and replay-ready anomaly cohort packaging built on top of the
autopilot evidence warehouse.

It depends on the shipped warehouse ingestion contract:

- `docs/swarm_autopilot_evidence_warehouse_contract_v1.json`
- `docs/SWARM_AUTOPILOT_EVIDENCE_WAREHOUSE.md`

The planned producer chain is:

- `scripts/swarm_autopilot_warehouse_retention_planner.sh`
- `scripts/swarm_autopilot_promotion_candidate_miner.sh`
- `scripts/swarm_autopilot_anomaly_cohort_packer.sh`
- `scripts/e2e/swarm_autopilot_warehouse_lifecycle_no_mock_drill.sh`

This contract is advisory only and proof only.

## Required Inputs

The lifecycle summary is rooted in the warehouse output:

- `evidence_warehouse_json`

Optional supporting snapshots may be present when later lifecycle surfaces need
more context:

- `historical_budget_baseline_json`
- `operator_snapshot_json`
- `hindsight_bundle_json`

Missing optional warehouse lifecycle snapshots degrade trust.

## Lifecycle Summary Bundle

The contract fixes a single operator-facing lifecycle summary bundle with:

- `warehouse_lifecycle_id`
- `truth_state`
- `retention_decision`
- `promotion_decision`
- `cohort_decision`
- `storage_pressure_state`
- `local_fallback_contamination`
- `required_input_status`
- `optional_snapshot_health`
- `contradiction_count`
- `error_codes`
- `retention_classes`
- `artifact_paths`

The summary bundle points at future derived artifacts without claiming those
surfaces already mutate live state:

- `retention_plan_json`
- `storage_budget_ledger_json`
- `promotion_candidates_json`
- `anomaly_cohorts_json`
- `replay_index_json`
- `operator_summary_json`

## Truth States

- `confirmed`: warehouse input is present, no contradictions are observed, no
  local fallback contamination is present, and optional lifecycle snapshots are
  complete
- `degraded`: warehouse input is present, no contradictions are observed, no
  local fallback contamination is present, but optional lifecycle snapshots are
  incomplete
- `blocked`: required warehouse lifecycle evidence is missing or contradictory
  hindsight prevents a truthful promotion or replay claim
- `contaminated`: local fallback contamination is present and must fail closed
  even if the other summary fields appear internally consistent

`contaminated` is stricter than `blocked`: the evidence exists, but it is no
longer safe to present as warehouse lifecycle truth.

## Fail-Closed Rules

- Missing required warehouse lifecycle evidence fails closed.
- Contradictory hindsight must fail closed.
- Missing replay-preserve artifact paths must fail closed.
- Local fallback contamination must fail closed.
- The lifecycle surfaces must not mutate beads, reservations, Agent Mail, workers, or live queue policy.
- The lifecycle surfaces must not claim automatic promotion, automatic replay
  approval, automatic worker mutation, automatic queue mutation, Cargo
  execution, or RCH execution.

## Fixture Cases

The contract-only smoke harness proves these summary cases:

- `healthy_lifecycle`
- `degraded_missing_optional_snapshot`
- `blocked_contradictory_hindsight`
- `contaminated_local_fallback`

## Validation

```bash
jq empty docs/swarm_autopilot_warehouse_lifecycle_contract_v1.json
bash -n scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh
bash scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh check
bash scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_WAREHOUSE_LIFECYCLE_CONTRACT.md docs/swarm_autopilot_warehouse_lifecycle_contract_v1.json scripts/e2e/swarm_autopilot_warehouse_lifecycle_contract_smoke.sh
```
