# RGC Cold-Start Compilation Lane V1

## Purpose

`bd-1lsy.7.10` is the parent acceptance lane for the cold-start and AOT program.
It stitches the existing persistent-cache, AOT entrygraph, runtime-image, and
cold-start governance modules into one deterministic operator bundle so startup
claims can be replayed and audited from one place.

This lane is intentionally a composition surface, not a replacement for the
child beads:

- `bd-1lsy.7.10.1` persistent cache contract
- `bd-1lsy.7.10.2` AOT entrygraph compilation
- `bd-1lsy.7.10.3` cold-start governance
- `bd-1lsy.7.10.4` runtime-image / warm-start contract

## Component Inputs

The parent lane consumes the following engine modules:

- `crates/franken-engine/src/persistent_cache_contract.rs`
- `crates/franken-engine/src/aot_entrygraph_compiler.rs`
- `crates/franken-engine/src/runtime_image_contract.rs`
- `crates/franken-engine/src/cold_start_aot_governance.rs`
- `crates/franken-engine/src/cold_start_compilation_lane.rs`

The lane is emitted through:

- `crates/franken-engine/src/bin/franken_cold_start_compilation_lane.rs`

## Bundle Artifacts

The bundle emitted under `artifacts/rgc_cold_start_compilation_lane/<timestamp>/`
must contain:

- `cold_start_compilation_report.json`
- `cold_start_observability_delta.json`
- `aot_bundle_compilation_report.json`
- `runtime_image_manifest.json`
- `trace_ids.json`
- `summary.md`
- `persistent_cache_contract/persistent_cache_contract.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/`

The parent report is the summary artifact that downstream rollout and supremacy
work can consume directly. The subordinate artifacts preserve enough detail for
replay, differential triage, and operator forensics.

## Gate Runner

Use the rch-backed gate runner:

```bash
./scripts/run_rgc_cold_start_compilation_lane.sh ci
```

Supported modes:

- `check`
- `test`
- `clippy`
- `run`
- `ci`

Every cargo build/test/clippy/run step in this lane is executed through `rch`.

## Operator Verification

Representative verification commands:

```bash
jq '.aggregate_benchmark_verdict,.aggregate_speedup_millionths' \
  artifacts/.../cold_start_compilation_report.json

jq '.rows[] | {mode_id,preserves_claim,speedup_millionths}' \
  artifacts/.../cold_start_observability_delta.json

jq '.best_warm_start_image_id,.best_warm_start_mode' \
  artifacts/.../runtime_image_manifest.json

jq '.batch_report.total_graphs,.batch_report.usable_graphs' \
  artifacts/.../aot_bundle_compilation_report.json

jq '.receipts | length' \
  artifacts/.../persistent_cache_contract/persistent_cache_contract.json
```

## Replay Workflow

Use the replay wrapper to rerun the lane and print the latest complete bundle:

```bash
./scripts/e2e/rgc_cold_start_compilation_lane_replay.sh ci
```

The replay wrapper refuses incomplete newest directories and falls back to the
latest complete run directory instead.
