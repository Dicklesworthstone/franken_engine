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

Each shard also emits a preflight contract:

- `preflight.diagnose_command`: the `rch diagnose --json -- ... cargo ...`
  command shape that must run before `rch exec`.
- `preflight.worker_status_command`: `rch --json status --workers --jobs`.
- `preflight.selected_worker_json_path`: where the selected worker id must be
  read from diagnose output.
- `preflight.fail_closed_pressure_states`: pressure states that make the shard
  inadmissible before Cargo starts.
- `preflight.required_artifacts`: the minimum evidence files a shard execution
  must preserve.

Broad-baseline runners must reject shards before remote Cargo starts when the
selected worker is missing from the status snapshot or has critical pressure.

## Shard Runner

`scripts/rch_all_target_cargo_proof_shard_runner.sh` consumes one shard from a
manifest and preserves the admission and execution receipts for that shard:

```bash
scripts/rch_all_target_cargo_proof_shard_runner.sh \
  --manifest artifacts/<bead>/<run>/shards/shard_manifest.json \
  --shard-id cargo-proof-lib_test_frankenengine_engine_all \
  --output-dir artifacts/<bead>/<run>/lib-test \
  --execute
```

Without `--execute`, the runner performs admission only. With `--execute`, it
runs the shard command after admission passes, then fails closed on execution worker drift,
RCH local fallback markers, missing selected-worker evidence, and missing Rust
test-execution markers for test lanes. Execution results preserve the selected
worker, observed execution worker, pressure snapshot, cargo log path, and
`rch_build_id` when RCH emits a build id in the transcript. Timeout and
termination exits are classified separately from ordinary remote command
failures.

Execution preserves the `rch exec -- env ... cargo ...` command shape. Operators
may opt into `--remote-keepalive-seconds N`, which injects the runner as
`RUSTC_WORKSPACE_WRAPPER` and asks it to emit progress while a workspace
`rustc` invocation is otherwise silent. This keeps dependency compilation on the
normal Cargo/rustc path while surfacing long final-crate compiles to RCH.
`commands.txt` records both the manifest
`execute_command` and, when keepalive instrumentation is enabled, the actual
`executed_command`. Keepalive output is not proof of success: test lanes still
require real Rust test execution markers before the runner can pass.

The runner preserves `rch_build_id` from either explicit RCH build lines or
worker-scoped `job-<id>` target paths. Remote failures are classified as command
failure, timeout, termination, `remote_command_stalled_live_hook`, or
worker environment failures such as `remote_worker_toolchain_unavailable` and
`remote_worker_native_dependency_unavailable`, or remote worker resource
failures such as `remote_worker_resource_exhausted`.

By default the runner polls `rch --json status --workers --jobs` every 15
seconds during execution. If RCH reports the shard build with stale progress
while the hook is alive and heartbeats remain fresh, the runner preserves
`stale-live-hook-status.json` plus `stale-live-hook-detection.json`. A later
timeout or termination for that build is classified as
`remote_command_stalled_live_hook` so the receipt distinguishes an RCH
live-hook progress stall from ordinary command failure. More specific terminal
failures, such as a remote rustc kill with exit status 137, keep their resource
classification instead. Use
`--status-poll-seconds 0` only for fixtures that need polling disabled.

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
bash -n scripts/rch_all_target_cargo_proof_shard_runner.sh scripts/e2e/rch_all_target_cargo_proof_shard_runner_smoke.sh
bash scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh check
bash scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh selftest
bash scripts/e2e/rch_all_target_cargo_proof_shard_runner_smoke.sh
git diff --check -- docs/ALL_TARGET_CARGO_PROOF_SHARD_PLANNER.md docs/all_target_cargo_proof_shard_planner_contract_v1.json scripts/all_target_cargo_proof_shard_planner.sh scripts/e2e/all_target_cargo_proof_shard_planner_smoke.sh scripts/rch_all_target_cargo_proof_shard_runner.sh scripts/e2e/rch_all_target_cargo_proof_shard_runner_smoke.sh scripts/testdata/all_target_cargo_proof_shard_planner/cases.json
```
