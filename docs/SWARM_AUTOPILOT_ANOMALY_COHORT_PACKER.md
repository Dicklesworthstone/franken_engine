# SWARM_AUTOPILOT_ANOMALY_COHORT_PACKER

`scripts/swarm_autopilot_anomaly_cohort_packer.sh` packages repeated warehouse
rows into replay-oriented anomaly cohorts so operators can audit repeated swarm
pathologies without manually hunting artifacts.

Machine-readable contract:
`docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_anomaly_cohort_packer/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh`.

The packer is advisory only and proof only.

## Inputs

Required:

- `--evidence-warehouse-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

The packer trusts the shipped warehouse contract fields:

- `artifact_rows`
- `artifact_paths`
- `fail_closed_reasons`
- `hash_basis.warehouse_hash`

## Outputs

Each run emits:

- `swarm_autopilot_anomaly_cohorts.json`
- `swarm_autopilot_replay_index.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each cohort preserves:

- cohort classification
- worker/toolchain/topology grouping hints
- source ids
- normalized fingerprints
- raw artifact paths
- remediation commands

## Classification Rules

Each cohort is exactly one of:

- `reference`
- `degraded`
- `blocked`
- `contaminated`

Healthy reference cohorts remain distinct from degraded, blocked, and contaminated cohorts.

Blocked locality contradiction cohorts remain grouped as blocked evidence
instead of pretending they are healthy replay baselines.

Fallback-contaminated cohorts remain isolated from healthy reference cohorts.

## Fail-Closed Rules

- Missing raw artifact references fail closed.
- Schema drift in warehouse evidence fails closed.
- Stale warehouse timestamps or freshness markers fail closed.
- Contradictory cohort membership fails closed.
- Local fallback contamination must fail closed.

The packer never mutates the warehouse, mutates beads, releases reservations,
sends Agent Mail, runs Cargo, runs RCH, mutates workers, or changes live queue
policy. It only emits cohort and replay index artifacts under its output
directory.

## Proof Cases

The checked-in fixtures cover:

- `healthy_reference_cohort_creation`
- `blocked_locality_contradiction`
- `fallback_contaminated_isolation`
- `contradictory_cohort_rejection`
- `stale_reference_fail_closed`

## Validation

```bash
bash -n scripts/swarm_autopilot_anomaly_cohort_packer.sh
bash -n scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh
shellcheck -x scripts/swarm_autopilot_anomaly_cohort_packer.sh scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh
jq empty docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json scripts/testdata/swarm_autopilot_anomaly_cohort_packer/cases.json
bash scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh check
bash scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_ANOMALY_COHORT_PACKER.md docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json scripts/swarm_autopilot_anomaly_cohort_packer.sh scripts/e2e/swarm_autopilot_anomaly_cohort_packer_smoke.sh scripts/testdata/swarm_autopilot_anomaly_cohort_packer/cases.json
```
