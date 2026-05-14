# IDEA-WIZARD-XII Zero-Ready Validation Truth No-Mock Drill

`bd-n51l8.6` adds a read-only drill that composes the zero-ready truth lane
across concrete surfaces:

- `scripts/rch_policy_compliance_gate.sh`
- `scripts/idea_wizard_iv_closed_bead_proof_integrity.sh`
- `scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh`
- `scripts/idea_wizard_iv_operator_status_truth_gate.sh`

The drill writes real `.beads/issues.jsonl`-shaped fixtures, real shell-script
fixtures, and source-marker fixtures into its run bundle. It then runs each
surface against those files and preserves a top-level transcript and aggregate
report. It does not repair Agent Mail, mutate beads, run Cargo, run RCH, query
workers, or mutate git.

## Proved Cases

The fixture run asserts:

- trusted RCH wrapper scripts pass policy;
- true bare Cargo scripts fail policy with `bare_cargo`;
- the pending-promise closed-bead contradiction is reported;
- the source-gap picker proposes the bounded pending-promise follow-up;
- the operator handoff renders `source_gap_found`;
- the clean zero-ready bundle remains `true_saturation`;
- command transcripts do not execute local heavy Cargo;
- suggested heavy validation uses `rch exec -- env CARGO_TARGET_DIR=`.

## Artifacts

Each fixture run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `source_inputs.json`
- `zero_ready_validation_truth_no_mock_drill_report.json`
- `operator_summary.md`
- child `steps/` directories with the composed surface artifacts

The replay mode validates those preserved artifacts without rerunning child
scripts.

## Validation

```bash
bash -n scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.sh
bash -n scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh
bash scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh check
bash scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh selftest
shellcheck -x scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.sh scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XII_ZERO_READY_VALIDATION_TRUTH_NO_MOCK_DRILL.md scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.sh scripts/e2e/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill_smoke.sh scripts/testdata/goldens/idea_wizard_xii_zero_ready_validation_truth_no_mock_drill.golden
```
