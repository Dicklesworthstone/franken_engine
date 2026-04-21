# RGC React Repro Triage V1

## Purpose

`bd-1lsy.5.7.3` packages the already-landed
`minimized_repro_extraction` and `react_repro_triage` library surfaces into a
deterministic, replayable artifact contract. The goal is to turn React
ecosystem failures into one narrow lane with explicit owner routing, severity
classification, and preserved repro commands instead of leaving the behavior
implicit in module-local tests.

This wrapper lane intentionally stays narrow. It does not claim the broader
React product surface is complete. It exists so downstream advisories, doctor
flows, and support surfaces can consume one stable truth source for minimized
repros and triage routing while dependent beads continue closing.

## Scope

This contract covers:

- the library modules
  `crates/franken-engine/src/minimized_repro_extraction.rs` and
  `crates/franken-engine/src/react_repro_triage.rs`
- deterministic wrapper artifacts for React failure classification, severity,
  and owner routing
- `rch`-only verification for the wrapper contract plus the focused
  integration and enrichment tests already shipping the lane

This contract explicitly does not replace:

- `bd-1lsy.5.7.2` SSR and hydration parity ownership
- `bd-1lsy.3.6.1` and `bd-1lsy.3.6.2` React lowering and JSX transform ownership
- `bd-1lsy.10.12.2` React doctor/preflight operator guidance

## Failure Class Routing

Every unresolved React ecosystem failure must map to a concrete owner bead and
team instead of a generic “React issue” bucket:

- `transform_bug` -> `bd-1lsy.3.6.1` / `jsx-transform`
- `resolver_bug` -> `bd-1lsy.5.8.2` / `module-resolution`
- `runtime_semantic_gap` -> `bd-1lsy.4.9.1` / `runtime-semantics`
- `unsupported_environment` -> `bd-1lsy.5.9.2` / `environment-compat`
- `package_misuse` -> `bd-1lsy.5.7.3` / `docs-triage`
- `hook_invariant_violation` -> `bd-1lsy.3.6.2` / `react-lowering`
- `hydration_mismatch` -> `bd-1lsy.5.7.2` / `ssr-hydration`
- `suspense_divergence` -> `bd-1lsy.3.6.2` / `react-lowering`
- `error_boundary_failure` -> `bd-1lsy.3.6.2` / `react-lowering`
- `unclassified` -> `bd-1lsy.5.7.3` / `triage`

Severity is explicit and stable:

- `critical` -> blocks a core React workflow
- `high` -> breaks a common workflow without a clean workaround
- `medium` -> engine bug with a known workaround
- `low` -> environment or package issue that does not require engine work
- `info` -> diagnostic-only edge case

## Required Artifacts

Every deterministic gate run must emit:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `react_repro_catalog.json`
- `rgc_react_repro_triage_v1.json`
- `step_logs/step_000.log`

`react_repro_catalog.json` is the operator-facing stitched artifact for this
lane. It records routed React failures, the severity-weighted backlog summary,
and the minimized-repro extraction summary that explains how much of the
original failing workload was preserved in the replayable triage artifact.

## Gate Runner

The canonical gate runner is:

- `./scripts/run_rgc_react_repro_triage.sh [check|test|clippy|ci]`

The runner is fail-closed and `rch`-only for heavy Rust work. It validates the
contract JSON locally, then offloads focused verification for:

- `rgc_react_repro_triage`
- `minimized_repro_extraction_integration`
- `minimized_repro_extraction_enrichment_integration`
- `react_repro_triage_integration`
- `react_repro_triage_enrichment_integration`

The canonical replay wrapper is:

- `./scripts/e2e/rgc_react_repro_triage_replay.sh [check|test|clippy|ci]`

By default, the replay wrapper reruns the selected lane and then prints the
latest complete artifact bundle (`run_manifest.json`, `trace_ids.json`,
`events.jsonl`, `commands.txt`, `react_repro_catalog.json`,
`rgc_react_repro_triage_v1.json`, and `step_logs/step_000.log`). If the newest
artifact directory is incomplete, it warns and falls back to the latest
complete directory; if no complete bundle exists, it fails non-zero instead of
presenting a partial run as trustworthy. If the rerun itself fails, the wrapper
explicitly states whether the printed bundle came from the current failed
invocation or from an older complete directory, so operators do not mistake
stale evidence for the failed run's output.

To replay a specific preserved bundle without rerunning the lane, point the
wrapper at an exact complete run directory:

```bash
RGC_REACT_REPRO_TRIAGE_REPLAY_RUN_DIR=artifacts/rgc_react_repro_triage/<timestamp> \
./scripts/e2e/rgc_react_repro_triage_replay.sh ci
```

The explicit run directory must already contain a complete bundle
(`run_manifest.json`, `trace_ids.json`, `events.jsonl`, `commands.txt`,
`react_repro_catalog.json`, `rgc_react_repro_triage_v1.json`, and
`step_logs/step_000.log`) or the wrapper fails closed.

## Structured Logging Contract

The event surface must keep these keys stable:

- `schema_version`
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `seed`
- `scenario_id`
- `failure_class`
- `severity`
- `owner_bead`

## Operator Verification

1. `jq empty docs/rgc_react_repro_triage_v1.json`
2. `bash -n scripts/run_rgc_react_repro_triage.sh`
3. `bash -n scripts/e2e/rgc_react_repro_triage_replay.sh`
4. `./scripts/run_rgc_react_repro_triage.sh ci`
5. `env CARGO_TARGET_DIR=$PWD/target_rch_rgc_react_repro_triage_verify rch exec -- cargo test -p frankenengine-engine --test rgc_react_repro_triage`
6. `./scripts/e2e/rgc_react_repro_triage_replay.sh ci`
7. `RGC_REACT_REPRO_TRIAGE_REPLAY_RUN_DIR=artifacts/rgc_react_repro_triage/<timestamp> ./scripts/e2e/rgc_react_repro_triage_replay.sh ci`
