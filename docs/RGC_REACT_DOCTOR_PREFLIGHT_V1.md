# RGC React Doctor Preflight V1

## Purpose

`bd-1lsy.10.12.2` packages the already-landed
`react_doctor_preflight` library surface into a deterministic, replayable
support contract. The goal is to make React doctor/preflight guidance auditable
through one narrow artifact lane instead of leaving the behavior implicit in
module-local tests.

This wrapper lane is intentionally narrow. It does not claim the full React
CLI/operator surface is closed. It exists so downstream docs, advisories, and
support flows can reference a concrete artifact contract while the broader
React productization beads continue closing.

## Scope

This contract covers:

- the library module `crates/franken-engine/src/react_doctor_preflight.rs`
- deterministic wrapper artifacts for React-specific doctor/preflight guidance
- owner-routed repro linkage consumed from upstream React mismatch and repro
  lanes
- `rch`-only verification for the contract, integration, and enrichment tests

This contract explicitly does not replace:

- `bd-1lsy.9.7.3` / `RGC-807C` React mismatch catalog ownership
- `bd-1lsy.5.7.3` / `RGC-405C` minimized repro extraction ownership
- `bd-1lsy.10.12.1` / `bd-1lsy.10.12.3` broader shipped React operator workflows

## Upstream Evidence Inputs

The doctor/preflight wrapper consumes two upstream evidence lanes directly:

- `bd-1lsy.9.7.3` / `RGC-807C` / `react_mismatch_catalog`
  Required fields:
  `entry_id`, `domain`, `severity`, `target`, `reproduction`, `advisory`,
  `react_version_range`
- `bd-1lsy.5.7.3` / `RGC-405C` / `minimized_repro_extraction`
  Required fields:
  `input_id`, `category`, `owner`, `severity`, `repro_hash`,
  `recommended_action`

The wrapper bead must not fork either upstream schema. It only indexes those
inputs into operator-facing support artifacts.

## Verdict And Guidance Contract

The wrapper exposes two explicit verdict classes:

- `pass`
  Build/compile may proceed. Non-blocking advisories still emit guidance and
  repro linkage when available.
- `fail`
  Build/compile must stop. Blocking findings emit routed guidance, owner-lane
  linkage, and minimized repro pointers.

The canonical emitted machine-readable artifacts are:

- `react_doctor_support_contract.json`
- `react_support_repro_index.json`

`react_doctor_support_contract.json` is the summary surface for report hashes,
preflight verdict state, blocker/advisory counts, support-bundle categories,
and upstream dependency routes.

`react_support_repro_index.json` is the stitched index that maps unresolved
doctor findings back to minimized repro commands and owner-routed triage lanes.

## Required Artifacts

Every deterministic gate run must emit:

- `run_manifest.json`
- `trace_ids.json`
- `events.jsonl`
- `commands.txt`
- `react_doctor_support_contract.json`
- `react_support_repro_index.json`
- `rgc_react_doctor_preflight_v1.json`
- `step_logs/step_000.log`

## Gate Runner

The canonical gate runner is:

- `./scripts/run_rgc_react_doctor_preflight.sh [check|test|clippy|ci]`

The runner is fail-closed and `rch`-only for heavy Rust work. It validates the
contract JSON locally, then offloads focused verification for:

- `rgc_react_doctor_preflight`
- `react_doctor_preflight_integration`
- `react_doctor_preflight_enrichment_integration`

The canonical replay wrapper is:

- `./scripts/e2e/rgc_react_doctor_preflight_replay.sh [check|test|clippy|ci]`

## Structured Logging Contract

The event surface must keep these keys stable:

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

1. `jq empty docs/rgc_react_doctor_preflight_v1.json`
2. `bash -n scripts/run_rgc_react_doctor_preflight.sh`
3. `bash -n scripts/e2e/rgc_react_doctor_preflight_replay.sh`
4. `./scripts/run_rgc_react_doctor_preflight.sh ci`
5. `env CARGO_TARGET_DIR=$PWD/target_rch_rgc_react_doctor_preflight_verify rch exec -- cargo test -p frankenengine-engine --test rgc_react_doctor_preflight`
6. `./scripts/e2e/rgc_react_doctor_preflight_replay.sh ci`
