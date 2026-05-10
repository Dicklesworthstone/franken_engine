# IDEA-WIZARD-III Operator Workflow

`bd-99t7y` documents the operator path for the proof-economy and degraded
coordination wave. The truth contract is
[`docs/idea_wizard_iii_operator_runbook_truth_contract_v1.json`](./idea_wizard_iii_operator_runbook_truth_contract_v1.json).

This workflow is advisory-only and proof-only.

- does not mutate live queues
- does not claim, close, reopen, or reassign beads
- does not send Agent Mail
- does not repair the Agent Mail database
- does not run local heavy Cargo validation
- does not start `rch`
- does not mutate remote workers
- does not delete or overwrite target directories

## Operator Sequence

1. Capture current coordination state with read-only commands:

```bash
br ready --json
br list --status=in_progress --json
bv --recipe actionable --robot-plan
```

2. Run cheap source-only checks before any heavy proof:

```bash
bash -n scripts/high_core_validation_pressure_dashboard.sh scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh
jq empty docs/high_core_validation_pressure_dashboard_contract_v2.json scripts/testdata/high_core_validation_pressure_dashboard/cases.json
git diff --check -- docs/HIGH_CORE_VALIDATION_PRESSURE_DASHBOARD.md docs/high_core_validation_pressure_dashboard_contract_v2.json scripts/high_core_validation_pressure_dashboard.sh scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh scripts/testdata/high_core_validation_pressure_dashboard/cases.json
```

3. Use fixture replay surfaces for degraded coordination:

```bash
./scripts/e2e/swarm_handoff_capsule_generator_smoke.sh selftest
./scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh selftest
```

4. If a heavy Rust proof is actually required, use direct RCH with an explicit
target directory:

```bash
RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch-target-franken-engine-idea-wizard-iii CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' CARGO_BUILD_JOBS=1 cargo check --all-targets
```

Local heavy Cargo validation is not green proof for this workflow.

## Check

The runbook truth gate checks this document, the truth contract, and referenced
machine contracts:

```bash
./scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh check
```

## Replay

Replay uses the committed fixture bundles:

```bash
./scripts/e2e/idea_wizard_iii_operator_runbook_truth_gate.sh selftest
./scripts/e2e/swarm_handoff_capsule_generator_smoke.sh selftest
./scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh selftest
```

## Preserved-Bundle Replay

Preserved bundles must be supplied explicitly. This keeps replay deterministic
and prevents the gate from reading live Agent Mail, live workers, or live
process tables:

```bash
PRESERVED_BUNDLE=/tmp/franken-engine-preserved-idea-wizard-iii
HIGH_CORE_VALIDATION_PRESSURE_FIXTURES="${PRESERVED_BUNDLE}/high_core_validation_pressure_dashboard/cases.json" ./scripts/e2e/high_core_validation_pressure_dashboard_smoke.sh selftest
SWARM_HANDOFF_CAPSULE_FIXTURES="${PRESERVED_BUNDLE}/swarm_handoff_capsule_generator/cases.json" ./scripts/e2e/swarm_handoff_capsule_generator_smoke.sh selftest
```

## Failure Posture

The workflow fails closed when docs or help text imply live mutation, automatic
Agent Mail repair, bare local Cargo proof, missing `CARGO_TARGET_DIR`, missing
referenced contracts, or non-replayable preserved-bundle instructions.

When Agent Mail is red or corrupt, the workflow records degraded coordination
and uses `br` assignee/status as the visible soft lock. It does not claim that
reservations, acknowledgements, or Agent Mail repairs succeeded.
