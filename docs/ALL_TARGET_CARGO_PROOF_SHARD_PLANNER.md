# All-Target Cargo Proof Shard Planner

`bd-j3lwi` adds a fixture-fed planner that turns preserved Cargo metadata into
RCH-wrapped proof command shards. It is intended to prevent long all-target runs
from discovering one stale target or lint at a time.

Machine-readable contract:
[`docs/all_target_cargo_proof_shard_planner_contract_v1.json`](./all_target_cargo_proof_shard_planner_contract_v1.json).

Implementation:
`scripts/all_target_cargo_proof_shard_planner.sh`.

## Boundary

The planner is advisory-only and proof-only. It never runs Cargo, never invokes
`rch exec`, never mutates `br`, never sends Agent Mail, never changes workers or
queue policy, and never creates or deletes target directories.

It emits command templates only. Operators or later proof runners decide whether
to execute them.

## Inputs

Required:

- `--cargo-metadata-json`: preserved Cargo metadata JSON.

Optional:

- `--prior-rch-failures-json`: prior RCH failure or stale target evidence.
- `--package`: restricts planning to one package.
- `--target-dir-prefix`: changes the emitted off-repo target directory prefix.

## Lanes

The planner emits these lanes when the metadata supports them:

- `check`: package-scoped `cargo check --all-targets`
- `clippy`: package-scoped `cargo clippy --all-targets -- -D warnings`
- `lib_test`: `cargo test --lib`
- `bin_test`: one shard per binary target
- `integration_test`: one shard per integration test target
- `doctest`: `cargo test --doc`

Every heavy command template uses direct RCH with an explicit target directory:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_all_target_shards_check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p frankenengine-engine --all-targets
```

Bare Cargo, missing `CARGO_TARGET_DIR`, shell wrappers that can fall open into
local execution, and local-fallback transcripts fail closed as proof evidence.

## Outputs

- `shard_manifest.json`
- `commands.txt`
- `commands.jsonl`
- `stale_target_diagnostics.jsonl`
- `events.jsonl`
- `report.md`

The manifest records `decision`, package and target counts, emitted shards,
stale target diagnostics, and a non-mutating policy.

## Decisions

- `pass`: metadata is valid and no stale prior targets were found.
- `degraded`: prior RCH failure evidence references stale targets that are not
  present in current metadata.
- `fail_closed`: Cargo metadata is malformed.

## Validation

```bash
jq empty docs/all_target_cargo_proof_shard_planner_contract_v1.json scripts/testdata/all_target_cargo_proof_shard_planner/cases.json
bash -n scripts/all_target_cargo_proof_shard_planner.sh scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh
bash scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh check
bash scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh selftest
git diff --check -- docs/ALL_TARGET_CARGO_PROOF_SHARD_PLANNER.md docs/all_target_cargo_proof_shard_planner_contract_v1.json scripts/all_target_cargo_proof_shard_planner.sh scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh scripts/testdata/all_target_cargo_proof_shard_planner/cases.json
```
