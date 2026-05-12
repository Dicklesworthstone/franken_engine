# Franken-Core No-Mock Graduation Drill V1

Status: active
Primary bead: `bd-4w7h9.4`
Parent wave: `bd-4w7h9`
Machine-readable contract: `docs/franken_core_no_mock_graduation_drill_v1.json`

## Scope

This drill exercises the real `crates/franken-core` graduation surfaces before
any workspace topology mutation is attempted. It reads live manifests and source
files by default:

- root `Cargo.toml`
- `crates/franken-core/Cargo.toml`
- `crates/franken-core/src/lib.rs`
- `crates/franken-engine/src/lib.rs`
- selected core and engine module source files
- current graduation/status docs

It is read-only. It does not edit `Cargo.toml`, add workspace members, run Cargo,
run RCH, or claim that workspace inclusion is approved.

## Current Expected State

The only passing live state for this bead is:

- root `Cargo.toml` excludes `crates/franken-core`
- `crates/franken-core/Cargo.toml` names package `frankenengine-core`
- selected modules are exported by both `franken-core` and `franken-engine`
- selected module source files exist in both crates
- docs do not claim workspace-ready or included membership
- every heavy proof command listed by the drill is RCH-wrapped with an explicit
  `CARGO_TARGET_DIR`

## Selected Source Surface

The drill checks these selected modules as representative import/export seams:

- `object_model`
- `promise_model`
- `profiling`
- `control_plane`
- `capability`

This is not the final API parity proof. The full parity ledger remains
`docs/franken_core_api_parity_ledger_v1.json`; this drill proves the real source
and manifest seams are readable and internally coherent.

## Proofs Still Needed Before Workspace Inclusion

The drill report names these required future proofs:

- validation impact planner stays green for the changed paths
- status truth gate stays green against live docs and manifests
- staged-inclusion rehearsal models topology blast radius without mutating root
  `Cargo.toml`
- golden artifacts cover graduation reports
- final acceptance suite `bd-4w7h9.8` passes
- final heavy Rust gates are run through `rch exec -- env CARGO_TARGET_DIR=...`

## Outputs

`scripts/franken_core_no_mock_graduation_drill.sh` writes:

- `graduation_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/franken_core_no_mock_graduation_drill_v1.json
bash -n scripts/franken_core_no_mock_graduation_drill.sh
bash -n scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh
bash scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh check
bash scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh negative
git diff --check -- docs/FRANKEN_CORE_NO_MOCK_GRADUATION_DRILL_V1.md docs/franken_core_no_mock_graduation_drill_v1.json scripts/franken_core_no_mock_graduation_drill.sh scripts/e2e/franken_core_no_mock_graduation_drill_smoke.sh
```
