# SWARM_AUTOPILOT_FORENSIC_DIFF_CONTRACT

`docs/swarm_autopilot_forensic_diff_contract_v1.json` defines the
contract-only comparison surface for warehouse forensic diff, counterexample
replay, hypothesis scoring, and operator forensic bundles.

It builds on shipped warehouse and cohort contracts:

- `docs/swarm_autopilot_evidence_warehouse_contract_v1.json`
- `docs/swarm_autopilot_anomaly_cohort_packer_contract_v1.json`

The planned producer chain is:

- `scripts/swarm_autopilot_cohort_diff_comparator.sh`
- `scripts/swarm_autopilot_replay_recipe_composer.sh`
- `scripts/swarm_autopilot_forensic_hypothesis_scorer.sh`
- `scripts/e2e/swarm_autopilot_forensic_diff_no_mock_drill.sh`

This contract is advisory only and proof only.

## Required Inputs

The comparison surface requires replayable anomaly cohort material on both
sides of a comparison:

- `reference_anomaly_cohorts_json`
- `comparison_anomaly_cohorts_json`
- `reference_replay_index_json`
- `comparison_replay_index_json`

Optional supporting snapshots may enrich confidence and operator context:

- `warehouse_retention_plan_json`
- `storage_budget_ledger_json`
- `operator_status_snapshot_json`
- `hindsight_outcome_bundle_json`

Missing optional forensic snapshots degrade trust. Required cohort or replay
inputs that are absent, stale, or missing raw paths fail closed.

## Derived Artifacts

The control plane produces four derived artifact families:

- cohort diff receipts
- replay recipe bundles
- forensic hypothesis summaries
- operator forensic bundles

Cohort diff receipts preserve source fingerprints, classification transitions,
worker deltas, toolchain deltas, topology deltas, and raw artifact paths.

Replay recipe bundles preserve the diff receipt id, replay class, evidence
paths, expected classification, safe rerun instructions, and whether the recipe
is valid remote truth.

Forensic hypothesis summaries preserve the top failure pivot, confidence band,
supporting source ids, counterevidence source ids, and remediation suggestions
without claiming certainty from sparse evidence.

Operator forensic bundles are summaries only. They surface advisory comparison
readiness, top cohort deltas, replay-ready recipe ids, blocked reason codes, and
artifact paths.

## Truth States

- `confirmed`: required reference and comparison inputs are present, raw paths
  are preserved, no contradictions are observed, no local fallback
  contamination is present, and optional snapshots are complete
- `degraded`: required inputs and raw paths are present, no contradictions are
  observed, no local fallback contamination is present, but optional snapshots
  are incomplete
- `blocked`: required inputs, raw paths, or cohort identity are contradictory or
  incomplete enough to block a truthful comparison
- `contaminated`: local fallback contamination is present and must fail closed
  even if other comparison fields appear internally consistent

## Fail-Closed Rules

- Missing required cohort or replay-index inputs fail closed.
- Stale references must fail closed.
- Missing raw artifact paths must fail closed.
- Contradictory cohort identity must fail closed.
- Local fallback contamination must fail closed.
- Unsupported mutation claims must fail closed.
- Contaminated evidence must not be selected as a remote-only baseline.
- Automatic replay approval and automatic promotion are forbidden.

Exact operator wording is fixed as advisory only, proof only, no automatic replay approval, no automatic promotion, no worker mutation, and no queue mutation.

The forensic surfaces must not mutate beads, reservations, Agent Mail, workers, or live queue policy. They must not run Cargo or RCH.

## Fixture Cases

The contract-only smoke harness proves these comparison cases:

- `healthy_reference_comparison`
- `degraded_optional_snapshot`
- `blocked_contradictory_cohort`
- `contaminated_local_fallback`

## Validation

```bash
jq empty docs/swarm_autopilot_forensic_diff_contract_v1.json
bash -n scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh
bash scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh check
bash scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_FORENSIC_DIFF_CONTRACT.md docs/swarm_autopilot_forensic_diff_contract_v1.json scripts/e2e/swarm_autopilot_forensic_diff_contract_smoke.sh
```
