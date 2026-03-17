# RGC React Parity Gate V1

## Purpose

`bd-1lsy.9.7` is the parent React-specific verification gate that ties the
compile, execution, and mismatch-catalog lanes together into one deterministic
artifact surface. The goal is to prevent React support claims from depending on
isolated green module tests without a replayable shipped-path gate.

## Scope

This gate is intentionally parent-level only. It does not replace the child
implementation beads; it consumes their focused integration surfaces and emits a
bundle that downstream docs, advisories, and benchmark claims can reference
directly.

## Child Reports

The gate emits the following machine-readable child artifacts:

- `react_compile_parity_report.json` for `bd-1lsy.9.7.1` / `RGC-807A`
- `react_ssr_client_parity_report.json` for `bd-1lsy.9.7.2` / `RGC-807B`
- `react_mismatch_catalog.json` for `bd-1lsy.9.7.3` / `RGC-807C`
- `react_parity_gate_index.json` as the parent `bd-1lsy.9.7` index tying the
  child reports into one replayable gate output

Each child report is owner-routed back to the bead that owns the underlying
verification surface so downstream consumers do not need tribal knowledge to
interpret a mismatch.

## Gate Runner

The canonical gate runner is:

- `./scripts/run_rgc_react_parity_gate.sh [check|test|clippy|ci]`

Heavy cargo operations must remain fail-closed and `rch`-backed. The runner
uses focused test targets only:

- `react_compile_verification_integration`
- `react_ssr_verification_integration`
- `react_mismatch_catalog_integration`
- `rgc_react_parity_gate`

The canonical replay wrapper is:

- `./scripts/e2e/rgc_react_parity_gate_replay.sh [check|test|clippy|ci]`

## Structured Logging And Artifacts

The gate emits:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `react_parity_gate_index.json`
- `react_compile_parity_report.json`
- `react_ssr_client_parity_report.json`
- `react_mismatch_catalog.json`
- `rgc_react_parity_gate_v1.json`
- `step_logs/step_000.log`

The log/event surface must keep the following fields stable:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `runtime_lane`
- `seed`
- `outcome`
- `error_code`

## Operator Verification

1. `jq empty docs/rgc_react_parity_gate_v1.json`
2. `bash -n scripts/run_rgc_react_parity_gate.sh`
3. `bash -n scripts/e2e/rgc_react_parity_gate_replay.sh`
4. `./scripts/run_rgc_react_parity_gate.sh ci`
5. `env CARGO_TARGET_DIR=/data/projects/franken_engine/target_rch_rgc_react_parity_gate_verify rch exec -- cargo test -p frankenengine-engine --test rgc_react_parity_gate`
6. `./scripts/e2e/rgc_react_parity_gate_replay.sh ci`
