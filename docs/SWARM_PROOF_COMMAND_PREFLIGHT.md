# Swarm Proof Command Preflight

`bd-ua5n2.9`

`scripts/swarm_proof_command_preflight.sh` classifies command text before the
proof broker schedules, deduplicates, or reuses a proof. It is advisory-only and
never executes the command under inspection.

## Decisions

- `proof_safe`: direct `rch exec -- env ... cargo ...` proof with an isolated
  `CARGO_TARGET_DIR`, only allowlisted env names, and required visibility
  context when requested.
- `proof_unsafe`: a command shape that must not be used as proof evidence.
- `needs_human_review`: a command shape outside the cheap classifier contract.
- `non_heavy_read_only`: lightweight gates such as `jq`, `bash -n`, `shellcheck`,
  or `git diff --check`.

Unsafe and human-review decisions exit `42`. Safe and read-only decisions exit
`0`.

## Rejections

The preflight rejects:

- shell-wrapped Cargo or RCH commands such as `bash -lc "rch exec -- cargo ..."`
- bare local Cargo
- heavy RCH Cargo commands without `CARGO_TARGET_DIR=...`
- heavy RCH Cargo commands whose `CARGO_TARGET_DIR` cannot be correlated with
  the supplied bead id after safe-token normalization
- unsupported env leakage inside `rch exec -- env`
- missing `RCH_VISIBILITY=...` when captured evidence requires visibility
- unrecognized heavy command shapes

Every rejection includes remediation text and, when possible, a pasteable direct
RCH command with `/tmp/rch_target_franken_engine_<safe_bead_id>`.

## Warm Target Matrix

The checked-in machine-readable matrix lives in
`docs/swarm_proof_command_preflight_contract_v1.json` under
`warm_target_command_matrix`. It defines these proof classes:

| Class | Canonical use | Target-dir policy |
| --- | --- | --- |
| `source_only` | `rustfmt --check`, `git diff --check`, `jq empty`, `bash -n` | no target dir; never cite as compile/runtime proof |
| `focused_lib_test` | one `cargo test --lib <filter>` regression | `/tmp/rch_target_franken_engine_<safe_bead_id>_<intent>` |
| `focused_integration_test` | one `cargo test --test <target> <filter>` regression | `/tmp/rch_target_franken_engine_<safe_bead_id>_<test_name>` |
| `package_all_targets` | `cargo check --all-targets` branch/package proof | `/tmp/rch_target_franken_engine_<safe_bead_id>_all_targets` |
| `clippy_all_targets` | `cargo clippy --all-targets -- -D warnings` lint gate | `/tmp/rch_target_franken_engine_<safe_bead_id>_clippy_all_targets` |
| `release_gate` | release-grade cargo proof or reproduce gate | `/tmp/rch_target_franken_engine_<safe_bead_id>_release` |

For heavy Cargo proof, the target dir must encode the bead id. The preflight
normalizes both values to alphanumeric/underscore tokens before comparing them,
so either dash or underscore separators are acceptable, but unrelated names such
as `/tmp/rch_target_franken_engine_shared` are rejected.

Prefer a narrower proof when a focused lib or integration test covers the
touched behavior, when the change is source-only, or when an all-targets RCH job
is already active for another bead.

Focused unit example:

```bash
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_7eefz_async_gen CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine --lib async_generator_next_fails_closed_for_suspended_body -- --nocapture
```

All-targets example:

```bash
rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd_zy517_all_targets CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' CARGO_BUILD_JOBS=1 cargo check --all-targets
```

## Inputs

```bash
./scripts/swarm_proof_command_preflight.sh --command 'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd cargo test -p frankenengine-engine --lib'
```

`--command-json` expects one command object with `command`, optional `case_id`,
and optional `context` fields such as `bead_id` and
`evidence_requires_visibility`. The smoke harness feeds each checked-in fixture
case to the script individually.

## Artifacts

Each run emits:

- `preflight_report.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable contract is
`docs/swarm_proof_command_preflight_contract_v1.json`.

## Validation

```bash
jq empty docs/swarm_proof_command_preflight_contract_v1.json scripts/testdata/swarm_proof_command_preflight/cases.json
bash -n scripts/swarm_proof_command_preflight.sh
bash -n scripts/e2e/swarm_proof_command_preflight_smoke.sh
bash scripts/e2e/swarm_proof_command_preflight_smoke.sh check
bash scripts/e2e/swarm_proof_command_preflight_smoke.sh selftest
git diff --check -- scripts/swarm_proof_command_preflight.sh docs/SWARM_PROOF_COMMAND_PREFLIGHT.md docs/swarm_proof_command_preflight_contract_v1.json scripts/testdata/swarm_proof_command_preflight/cases.json scripts/e2e/swarm_proof_command_preflight_smoke.sh
```
