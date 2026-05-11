# IDEA-WIZARD-IV Operator Status Truth Gate

`bd-ks5p4` exposes the saturation convergence control plane as operator-facing
status without overstating proof state. The gate consumes a preserved
`saturation_convergence_report.json`, scans selected docs for claim-sensitive
language, and emits a concise status bundle suitable for bead comments during
degraded coordination.

The status language is intentionally narrow:

- The control plane is advisory and proof-only.
- Green status requires the required artifacts from the child packets and the
  zero-ready replay bundle.
- Heavy validation remains RCH-backed and must use
  `rch exec -- env CARGO_TARGET_DIR=`.
- Degraded Agent Mail or coordination health is reported as a limitation, not
  automatically repaired.
- The gate does not mutate beads, repair Agent Mail, run Cargo, run RCH, or
  prove project-wide completion without evidence.

## Artifacts

Each run emits:

- `operator_truth_gate_report.json`
- `operator_status.md`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `report.md`

`scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh` validates a
preserved operator-status bundle without rerunning the scanner.

## Validation

```bash
bash -n scripts/idea_wizard_iv_operator_status_truth_gate.sh
bash -n scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh
bash -n scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh
bash scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh check
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_OPERATOR_STATUS_TRUTH_GATE.md scripts/idea_wizard_iv_operator_status_truth_gate.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
