# RGC Statistical Validation Pipeline V1

Status: active  
Primary bead: `bd-1lsy.8.2`  
Machine-readable contract: `docs/rgc_statistical_validation_pipeline_v1.json`

## Scope

This contract defines deterministic statistical validation for benchmark
promotion decisions. It ensures variance, confidence, and effect-size controls
are enforced before release-facing performance claims proceed.

The pipeline is fail-closed:

- rejects incomplete benchmark metadata,
- quarantines high-variance and low-confidence runs,
- fails on significant regression threshold breaches,
- emits replay-stable artifacts for each gate run.

## Contract Version

- `schema_version`: `franken-engine.rgc-statistical-validation-pipeline.v1`
- `contract_version`: `1.0.0`
- `policy_id`: `policy-rgc-statistical-validation-pipeline-v1`

## Threshold Contract

Validation policy includes:

- `max_cv_millionths`
- `warning_regression_millionths`
- `fail_regression_millionths`
- `max_p_value_millionths`
- `min_effect_size_millionths`
- `confidence_level_millionths`

All thresholds are deterministic and enforced in millionths to avoid float-only
policy ambiguity.

## Structured Logging Contract

Each workload evaluation emits an event with stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `scenario_id`
- `workload_id`
- `outcome`
- `error_code`

## Replay and Execution

Gate entrypoint:

- `scripts/run_rgc_statistical_validation_pipeline.sh`

Replay wrapper:

- `scripts/e2e/rgc_statistical_validation_pipeline_replay.sh`

Modes:

- `check`, `test`, `clippy`, `ci`

Strict mode is fail-closed and requires remote execution for heavy cargo
operations (`rch` only, no local fallback).

## Required Artifacts

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `summary.md`
- `env.json`
- `repro.lock`
- `step_logs/`
- `support_bundle/stats_verdict_report.json`

under `artifacts/rgc_statistical_validation_pipeline/<UTC_TIMESTAMP>/`.

## Operator Verification

```bash
jq empty docs/rgc_statistical_validation_pipeline_v1.json

rch exec -- env CARGO_TARGET_DIR="$PWD/target_rch_rgc_statistical_validation_pipeline_verify" \
  cargo test -p frankenengine-engine --test rgc_statistical_validation_pipeline

./scripts/run_rgc_statistical_validation_pipeline.sh ci
./scripts/e2e/rgc_statistical_validation_pipeline_replay.sh ci
```
