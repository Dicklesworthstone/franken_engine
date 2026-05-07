# SWARM_AUTOPILOT_COHORT_DIFF_COMPARATOR

`scripts/swarm_autopilot_cohort_diff_comparator.sh` compares a healthy anomaly
cohort baseline against degraded, blocked, or contaminated cohort material and
emits deterministic forensic diff receipts plus a fingerprint delta plan.

Machine-readable contract:
`docs/swarm_autopilot_cohort_diff_comparator_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_cohort_diff_comparator/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh`.

The comparator is advisory only and proof only.

## Inputs

Required:

- `--reference-anomaly-cohorts-json FILE`
- `--comparison-anomaly-cohorts-json FILE`
- `--reference-replay-index-json FILE`
- `--comparison-replay-index-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

The comparator consumes anomaly cohort bundles and replay indexes emitted by
`scripts/swarm_autopilot_anomaly_cohort_packer.sh`.

## Outputs

Each run emits:

- `swarm_autopilot_cohort_diff_receipts.json`
- `swarm_autopilot_fingerprint_delta_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each diff receipt preserves:

- reference and comparison cohort ids
- classification transition
- added, removed, and changed source fingerprints
- worker, toolchain, and topology deltas
- raw artifact paths for the cohort bundles and replay indexes
- remote-truth validity for the compared material

## Diff Rules

Healthy reference cohorts remain distinct from blocked, degraded, and contaminated comparison cohorts.

Blocked locality drift must preserve worker, toolchain, topology, raw artifact, and fingerprint deltas.

Fallback-contaminated comparison cohorts remain isolated from healthy reference material and cannot become a reference baseline.

## Fail-Closed Rules

- Stale reference or comparison material fails closed.
- Missing raw artifact paths fail closed.
- Contradictory cohort identity fails closed.
- Contaminated reference material fails closed.
- Schema drift in cohort or replay-index material fails closed.

The comparator never mutates beads, releases reservations, sends Agent Mail,
runs Cargo, runs RCH, mutates workers, changes live queue policy, approves
replay automatically, or promotes evidence automatically. It only emits diff
receipts and fingerprint delta plans under its output directory.

## Proof Cases

The checked-in fixtures cover:

- `healthy_vs_blocked_locality_drift`
- `healthy_vs_contaminated_fallback_separation`
- `stale_reference_fail_closed`
- `contradictory_cohort_identity_rejection`

## Validation

```bash
bash -n scripts/swarm_autopilot_cohort_diff_comparator.sh
bash -n scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh
shellcheck -x scripts/swarm_autopilot_cohort_diff_comparator.sh scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh
jq empty docs/swarm_autopilot_cohort_diff_comparator_contract_v1.json scripts/testdata/swarm_autopilot_cohort_diff_comparator/cases.json
bash scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh check
bash scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_COHORT_DIFF_COMPARATOR.md docs/swarm_autopilot_cohort_diff_comparator_contract_v1.json scripts/swarm_autopilot_cohort_diff_comparator.sh scripts/e2e/swarm_autopilot_cohort_diff_comparator_smoke.sh scripts/testdata/swarm_autopilot_cohort_diff_comparator/cases.json
```
