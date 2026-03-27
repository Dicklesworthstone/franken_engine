# RGC CLI and Operator Workflow Verification Pack V1

Status: active  
Primary bead: `bd-1lsy.11.11`  
Machine-readable contract: `docs/rgc_cli_operator_workflow_verification_pack_v1.json`

## Scope

This contract defines deterministic CLI and operator workflow verification for
RGC onboarding and diagnostics flows, with explicit golden-path and failure-path
coverage.

The pack is evidence-first:

- validates workflow readiness and actionable diagnostics output,
- verifies machine-readable scorecard structure and artifact completeness,
- enforces failure-path clarity for common operator misconfigurations,
- emits replay-stable run-manifest/event/command artifacts.

## Contract Version

- `schema_version`: `franken-engine.rgc-cli-operator-workflow-verification-pack.v1`
- `contract_version`: `1.3.0`
- `policy_id`: `policy-rgc-cli-operator-workflow-verification-pack-v1`

## Workflow Stages

The operator workflow stage set is fixed and versioned:

- `init`
- `compile`
- `run`
- `verify`
- `benchmark`
- `replay`
- `triage`

Stage coverage in this pack focuses on runtime diagnostics onboarding and
operator triage quality:

- `run` + `verify`: `runtime_diagnostics onboarding-scorecard ...`
- `triage`: summary + reproducible command guidance from scorecard output
- failure-path triage: deterministic missing-input and invalid-signals diagnostics

## Golden-Path and Failure-Path Matrix

Golden path:

- clean input emits `readiness=ready`
- summary includes reproducible commands
- output bundle writes preflight report, onboarding scorecard, rollout decision,
  and doctor report artifacts

Failure paths:

- missing input file fails with deterministic actionable error text
- invalid signals JSON fails with deterministic parse diagnostics
- blocked scorecard path produces actionable next steps and replay command links

## Structured Logging Contract

Every gate completion event must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `path_type`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_cli_operator_workflow_verification_pack.sh`

Replay wrapper:

- `scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh`

Modes:

- `check`, `test`, `clippy`, `ci`

Strict mode is fail-closed and requires remote execution for heavy cargo
operations (`rch` only, no local fallback).

The generic `frankenctl` workflow surface under test also preserves an exact
bundle replay command:

- `FRANKENCTL_CLI_WORKFLOW_REPLAY_RUN_DIR=artifacts/frankenctl_cli_workflow/<timestamp> ./scripts/e2e/frankenctl_cli_workflow.sh ci`

That explicit replay mode fails closed on incomplete bundles and short-circuits
before creating a new run directory or requiring `rch`, so operators can replay
preserved evidence without accidentally rerunning the heavy workflow.

## Required Artifacts

Each gate run emits:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/step_*.log`

under `artifacts/rgc_cli_operator_workflow_verification_pack/<UTC_TIMESTAMP>/`.

The verified CLI workflow under test emits:

- `support_bundle/preflight_report.json`
- `support_bundle/onboarding_scorecard.json`
- `support_bundle/rollout_decision_artifact.json`
- `support_bundle/frankenctl_doctor_report.json`

Operators inspect those workflow artifacts under
`artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/` after running
the generic `frankenctl` workflow command in the verification sequence below.

The replay wrapper resolves the latest complete artifact bundle, warns when a
newer run directory is incomplete, and prints the selected manifest, trace IDs,
events, commands, and first step log for operator replay and triage.

## Operator Verification

```bash
jq empty docs/rgc_cli_operator_workflow_verification_pack_v1.json

rch exec -- env CARGO_TARGET_DIR=$PWD/target_rch_rgc_cli_operator_workflow_verification_pack_verify \
  cargo test -p frankenengine-engine --test rgc_cli_operator_workflow_verification_pack

./scripts/run_rgc_cli_operator_workflow_verification_pack.sh ci
./scripts/e2e/rgc_cli_operator_workflow_verification_pack_replay.sh ci
./scripts/e2e/frankenctl_cli_workflow.sh ci
cat artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/preflight_report.json
cat artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/onboarding_scorecard.json
cat artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/rollout_decision_artifact.json
cat artifacts/frankenctl_cli_workflow/<timestamp>/support_bundle/frankenctl_doctor_report.json
FRANKENCTL_CLI_WORKFLOW_REPLAY_RUN_DIR=artifacts/frankenctl_cli_workflow/<timestamp> ./scripts/e2e/frankenctl_cli_workflow.sh ci
cat artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/trace_ids.json
cat artifacts/rgc_cli_operator_workflow_verification_pack/<timestamp>/step_logs/step_000.log
```
