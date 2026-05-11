# IDEA-WIZARD-IV Acceptance Suite

`bd-w06ui` composes the final IDEA-WIZARD-IV acceptance manifest. It verifies
that every child surface has tracked artifacts, validation commands, replay
coverage, and RCH-wrapped heavy validation guidance before the parent wave is
closed.

The suite is source-only by default. It can run the lightweight smoke gates, but
it does not execute Cargo or RCH. Heavy validation remains emitted guidance:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_acceptance CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine saturation_convergence
```

## Artifacts

Each run emits:

- `acceptance_manifest.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `report.md`

The manifest includes `child_beads`, `child_artifacts`,
`validation_commands`, `acceptance_decision`, `residual_risks`,
`fail_closed_reasons`, and closeout instructions for future agents.

## Closeout Instructions

Future agents should close the parent IDEA-WIZARD-IV bead only after:

- this suite reports `acceptance_decision=green`
- all child beads are closed in `br`
- no required child artifact is missing
- any heavy Cargo validation transcript is RCH-wrapped and contains no local
  fallback marker
- the preserved zero-ready and operator truth-gate replay wrappers pass

## Validation

```bash
bash -n scripts/idea_wizard_iv_acceptance_suite.sh
bash -n scripts/e2e/idea_wizard_iv_acceptance_suite_smoke.sh
bash scripts/e2e/idea_wizard_iv_acceptance_suite_smoke.sh check
bash scripts/e2e/idea_wizard_iv_saturation_convergence_contract_smoke.sh check
git diff --check -- docs/IDEA_WIZARD_IV_ACCEPTANCE_SUITE.md scripts/idea_wizard_iv_acceptance_suite.sh scripts/e2e/idea_wizard_iv_acceptance_suite_smoke.sh docs/idea_wizard_iv_saturation_convergence_v1.json
```
