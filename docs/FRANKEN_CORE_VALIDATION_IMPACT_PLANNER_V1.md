# Franken-Core Validation Impact Planner V1

Status: active
Primary bead: `bd-4w7h9.3`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_validation_impact_planner_v1.json`

## Scope

This planner maps future franken-core graduation changes to the cheapest
trustworthy validation commands. It specializes the IDEA-WIZARD-IV validation
impact concept for the franken-core graduation lane and remains advisory only.
It does not run Cargo, run RCH, mutate git, change workspace membership, or
claim that franken-core workspace inclusion is complete.

## Covered Change Classes

| Change class | Examples | Decision |
| --- | --- | --- |
| `docs_only` | `docs/**`, `README.md`, `AGENTS.md`, `.beads/issues.jsonl` | focused local checks |
| `script_only` | `scripts/**` | shell syntax and local text checks |
| `franken_core_only` | `crates/franken-core/**` | standalone franken-core RCH proofs |
| `franken_engine_api_adjacent` | `crates/franken-engine/**` | engine package RCH proofs |
| `extension_host_adjacent` | `crates/franken-extension-host/**` | extension-host RCH proofs |
| `cargo_topology` | root `Cargo.toml`, crate manifests | fail closed; full RCH gates and separate topology bead required |
| `unknown_path` | any unmapped path | fail closed to full AGENTS.md gates |

Standalone franken-core validation is useful evidence, but it is never
sufficient to claim workspace inclusion. Workspace inclusion requires the final
acceptance suite (`bd-4w7h9.8`) and a separate explicit topology change.

## RCH Policy

Every heavy Rust recommendation must start with:

```bash
rch exec -- env CARGO_TARGET_DIR=
```

Missing target dirs, bare heavy Cargo examples, and local fallback transcripts
are not green proof.

## Command Examples

RCH smoke for standalone franken-core changes:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_franken_core_smoke CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --manifest-path crates/franken-core/Cargo.toml --all-targets
```

Focused package checks for API-adjacent changes:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_api_adjacent CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-engine --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_extension_host CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-extension-host --all-targets
```

Final all-target gates for topology-sensitive or unknown changes:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_final_gates CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check --all-targets
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_final_gates CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_final_gates CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test
```

## Outputs

`scripts/franken_core_validation_impact_planner.sh` writes:

- `validation_impact_plan.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/franken_core_validation_impact_planner_v1.json
bash -n scripts/franken_core_validation_impact_planner.sh
bash -n scripts/e2e/franken_core_validation_impact_planner_smoke.sh
bash scripts/e2e/franken_core_validation_impact_planner_smoke.sh check
bash scripts/e2e/franken_core_validation_impact_planner_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_VALIDATION_IMPACT_PLANNER_V1.md docs/franken_core_validation_impact_planner_v1.json scripts/franken_core_validation_impact_planner.sh scripts/e2e/franken_core_validation_impact_planner_smoke.sh
```
