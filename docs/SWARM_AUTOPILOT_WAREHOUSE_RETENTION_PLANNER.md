# SWARM_AUTOPILOT_WAREHOUSE_RETENTION_PLANNER

`scripts/swarm_autopilot_warehouse_retention_planner.sh` is the proof-only
retention and storage-budget planner that consumes the autopilot evidence
warehouse and decides which evidence should remain hot, be compacted, or be
preserved for replay.

Machine-readable contract:
`docs/swarm_autopilot_warehouse_retention_planner_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_warehouse_retention_planner/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh`.

The planner is advisory only and proof only.

## Inputs

Required:

- `--evidence-warehouse-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

The planner trusts the shipped warehouse contract fields:

- `artifact_rows`
- `retention_classes`
- `fail_closed_reasons`
- `hash_basis.warehouse_hash`
- `artifact_paths`

## Outputs

Each run emits:

- `swarm_autopilot_warehouse_retention_plan.json`
- `swarm_autopilot_storage_budget_ledger.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The retention plan preserves:

- storage pressure state
- replay-preserve exemptions
- compaction candidates
- fail-closed reasons
- remediation commands
- source artifact paths

The storage budget ledger preserves:

- total estimated bytes
- per-class totals
- action totals
- replay-preserve counts
- compaction candidate counts

## Decision Rules

- Healthy warehouse evidence yields `decision=pass`.
- Storage pressure may degrade the plan without upgrading it to fail_closed.
- Replay-preserve exemptions must not be compacted.
- Stale warehouse evidence must fail closed.
- Local fallback contamination must fail closed.
- Unknown retention classes must fail closed.

The planner never deletes files, mutates the warehouse, mutates beads, releases
reservations, sends Agent Mail, runs Cargo, runs RCH, or changes live queue
policy. It only emits planning artifacts under its output directory.

## Proof Cases

The checked-in fixtures cover:

- `healthy_bounded_retention`
- `storage_pressure_degradation`
- `replay_preserve_exemption`
- `stale_warehouse_fail_closed`
- `contaminated_evidence_refusal`

## Validation

```bash
bash -n scripts/swarm_autopilot_warehouse_retention_planner.sh
bash -n scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh
shellcheck -x scripts/swarm_autopilot_warehouse_retention_planner.sh scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh
jq empty docs/swarm_autopilot_warehouse_retention_planner_contract_v1.json scripts/testdata/swarm_autopilot_warehouse_retention_planner/cases.json
bash scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh check
bash scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_WAREHOUSE_RETENTION_PLANNER.md docs/swarm_autopilot_warehouse_retention_planner_contract_v1.json scripts/swarm_autopilot_warehouse_retention_planner.sh scripts/e2e/swarm_autopilot_warehouse_retention_planner_smoke.sh scripts/testdata/swarm_autopilot_warehouse_retention_planner/cases.json
```
