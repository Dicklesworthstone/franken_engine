# SWARM_AUTOPILOT_FORENSIC_HYPOTHESIS_SCORER

`scripts/swarm_autopilot_forensic_hypothesis_scorer.sh` ranks bounded
root-cause hypotheses from cohort diff receipts and evidence warehouse rows.

Machine-readable contract:
`docs/swarm_autopilot_forensic_hypothesis_scorer_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_forensic_hypothesis_scorer/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh`.

The forensic hypothesis scorer is advisory only and proof only.

## Inputs

Required:

- `--cohort-diff-receipts-json FILE`
- `--evidence-warehouse-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

## Outputs

Each run emits:

- `swarm_autopilot_forensic_hypothesis_summary.json`
- `swarm_autopilot_forensic_hypothesis_evidence.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each hypothesis preserves confidence band, counterevidence, supporting source ids, supporting receipts, and remediation suggestion.

## Scoring Rules

Topology drift is promoted only when topology deltas are present in coherent diff receipts.

Toolchain skew is promoted only when toolchain deltas are present in coherent diff receipts.

Low-evidence cases degrade instead of overclaiming certainty.

Contaminated evidence is suppressed and cannot support promoted hypotheses.

## Fail-Closed Rules

- Stale evidence fails closed.
- Contradictory evidence fails closed.
- Contaminated evidence fails closed.
- Schema drift in diff or warehouse material fails closed.

The scorer never mutates beads, releases reservations, sends Agent Mail, runs
Cargo, runs RCH, mutates workers, changes live queue policy, or promotes
hypotheses automatically. It only emits hypothesis summaries and evidence
bundles under its output directory.

## Proof Cases

The checked-in fixtures cover:

- `topology_drift_explanation`
- `contaminated_evidence_suppression`
- `low_evidence_degradation`
- `contradictory_hypothesis_fail_closed`

## Validation

```bash
bash -n scripts/swarm_autopilot_forensic_hypothesis_scorer.sh
bash -n scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh
shellcheck -x scripts/swarm_autopilot_forensic_hypothesis_scorer.sh scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh
jq empty docs/swarm_autopilot_forensic_hypothesis_scorer_contract_v1.json scripts/testdata/swarm_autopilot_forensic_hypothesis_scorer/cases.json
bash scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh check
bash scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_FORENSIC_HYPOTHESIS_SCORER.md docs/swarm_autopilot_forensic_hypothesis_scorer_contract_v1.json scripts/swarm_autopilot_forensic_hypothesis_scorer.sh scripts/e2e/swarm_autopilot_forensic_hypothesis_scorer_smoke.sh scripts/testdata/swarm_autopilot_forensic_hypothesis_scorer/cases.json
```
