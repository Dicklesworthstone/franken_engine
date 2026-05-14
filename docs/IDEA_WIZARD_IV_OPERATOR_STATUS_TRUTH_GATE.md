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
- Zero-ready handoff status is derived from the closed-bead proof report and
  the IDEA-WIZARD-XII source-gap picker when those artifacts are supplied.
- Heavy validation remains RCH-backed and must use
  `rch exec -- env CARGO_TARGET_DIR=`.
- Degraded Agent Mail or coordination health is reported as a limitation, not
  automatically repaired.
- The gate does not mutate beads, repair Agent Mail, run Cargo, run RCH, or
  prove project-wide completion without evidence.

## Zero-Ready Truth States

When passed `--closed-bead-proof-json` and `--source-gap-picker-json`, the gate
adds `zero_ready_truth` to `operator_truth_gate_report.json` and a "Next
Commands" section to `operator_status.md`.

| State | Meaning |
| --- | --- |
| `true_saturation` | Preserved proof artifacts show no closed-bead semantic contradiction and the source-gap picker found no actionable marker. |
| `source_gap_found` | Closed-bead proof or source-gap picker output found surviving source evidence that should become a bounded follow-up bead. |
| `degraded_unknown` | Required scan artifacts are missing or insufficient; the handoff must ask the next operator to regenerate them. |

Reason codes include missing source-gap scans, semantic contradictions,
source-gap proposals, and degraded coordination. This keeps Agent Mail
corruption and stale/absent scan artifacts visible without implying automatic
repair.

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
shellcheck -x scripts/idea_wizard_iv_operator_status_truth_gate.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_OPERATOR_STATUS_TRUTH_GATE.md scripts/idea_wizard_iv_operator_status_truth_gate.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_replay.sh scripts/e2e/idea_wizard_iv_operator_status_truth_gate_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
