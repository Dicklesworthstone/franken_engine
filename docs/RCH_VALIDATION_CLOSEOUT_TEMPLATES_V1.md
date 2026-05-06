# RCH Validation Closeout Templates V1

`bd-n04l9` defines copy-ready Agent Mail and `br close` templates for RCH
validation outcomes. The templates align with
`scripts/rch_validation_run_artifacts.sh` and use the same evidence vocabulary.

Every closeout must include:

- `worker_id=...`
- `command=rch exec -- ...`
- `target_dir=...`
- `component_toolchain=...`
- `final_verdict=...`
- `reason_code=...`
- `next_action=...`

Only `final_verdict=source_pass` and `final_verdict=source_failure` are source
evidence. Toolchain blockers, SSH timeouts, local fallback refusal, and missing
proof must explicitly say `not source evidence`.

## Examples

### Cargo-Clippy Missing

Agent Mail subject:

```text
[rch-validation] cargo-clippy missing on worker vmi1293453
```

Closeout reason:

```text
RCH validation blocker: final_verdict=toolchain_blocker reason_code=missing_cargo_clippy worker_id=vmi1293453 command=rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-clippy CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo clippy --all-targets -- -D warnings target_dir=/data/tmp/franken_engine-clippy component_toolchain=cargo-clippy missing on nightly-2026-04-30-x86_64-unknown-linux-gnu next_action=reroute to worker with cargo-clippy, then rerun same rch command; not source evidence.
```

### SSH Timeout

Closeout reason:

```text
RCH validation blocker: final_verdict=transport_timeout reason_code=ssh_timeout_no_final_verdict worker_id=vmi1149989 command=rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-test CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo test -p frankenengine-engine --test array_every_map_callbacks target_dir=/data/tmp/franken_engine-test component_toolchain=nightly worker reachable but SSH command timed out next_action=split target or salvage remote artifacts before rerun; not source evidence.
```

### Full Cargo Test Timed Out

Closeout reason:

```text
RCH validation blocker: final_verdict=transport_timeout reason_code=ssh_timeout_no_final_verdict worker_id=vmi1149989 command=rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-test CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo test target_dir=/data/tmp/franken_engine-test component_toolchain=nightly worker timed out during full workspace test next_action=rerun narrower package or test target through rch exec --; not source evidence.
```

### All-Targets Check Pass

Closeout reason:

```text
RCH validation source evidence: final_verdict=source_pass reason_code=remote_command_exit_zero worker_id=vmi1293453 command=rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo check --all-targets target_dir=/data/tmp/franken_engine-check component_toolchain=cargo/rustc/rustfmt/cargo-clippy present on nightly-2026-04-30-x86_64-unknown-linux-gnu next_action=record commit and close validation bead.
```

### Source Diagnostic Failure

Closeout reason:

```text
RCH validation source failure: final_verdict=source_failure reason_code=remote_source_diagnostic worker_id=vmi1293453 command=rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 cargo check --all-targets target_dir=/data/tmp/franken_engine-check component_toolchain=cargo/rustc present on nightly-2026-04-30-x86_64-unknown-linux-gnu next_action=fix touched target or cite unrelated source diagnostic.
```

The checker is:

```bash
scripts/e2e/rch_validation_closeout_templates_smoke.sh
```
