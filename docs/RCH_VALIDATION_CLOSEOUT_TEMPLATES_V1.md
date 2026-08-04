# RCH Validation Closeout Templates V1

`bd-n04l9` defines copy-ready Agent Mail and `br close` templates for RCH
validation outcomes. The templates align with
`scripts/rch_validation_run_artifacts.sh` and use the same evidence vocabulary.

Every closeout must include:

- `worker_id=...`
- `build_id=...` when RCH reported one
- `diagnose_command=...` when the observation came from
  `rch diagnose --dry-run --json`
- `command=rch exec -- ...`
- `target_dir=...`
- `component_toolchain=...`
- `final_verdict=...`
- `reason_code=...`
- `next_action=...`

Only `final_verdict=source_pass` and `final_verdict=source_failure` are source
evidence. Toolchain blockers, SSH timeouts, remote progress-stale no-verdicts,
pre-admission dry-run refusals, local fallback refusal, and missing proof must
explicitly say `not source evidence`.

Pre-admission dry-run refusal is distinct from remote no-verdict evidence:

- `final_verdict=admission_refused` means `rch diagnose --dry-run --json`
  classified the command as interceptable but did not admit any worker, so Cargo
  never executed remotely.
- `final_verdict=transport_stall` means a remote build was admitted and started,
  but no compiler/test/bench verdict was preserved.
- `reason_code=dependency_preflight_code_mismatch` or the `RCH-E324`/`RCH-E410`
  family belongs to the dependency-preflight blocker lane, not the generic
  no-admissible-worker receipt.

A pre-admission refusal receipt should preserve:

- `diagnose_command`: exact `rch diagnose --dry-run --json -- ...` invocation.
- `normalized_cargo_command`: command after the `--`, including env and target
  directory.
- `would_intercept` and `would_offload`.
- `reason_counts`: parsed counts such as `critical_pressure=1`,
  `health_below_fallback=6`, `hard_preflight=2`, and
  `active_project_exclusion=1`.
- `worker_denials`: per-worker denial reasons when the JSON includes them.
- `active_project_exclusion`: worker/build hints when an active project job is
  the immediate reason.
- `operator_category`: one of `wait_for_active_project`,
  `worker_health_or_capacity`, `worker_preflight_or_toolchain`, or
  `mixed_no_admissible_workers`.
- `next_action`: the first useful action before another heavy Cargo attempt.

This contract composes with `bd-xs1x2`, which covers post-admission remote
stale/no-verdict artifact closeout, and `bd-d6t8d`, which covers the
dependency-preflight `RCH-E324`/`RCH-E410` diagnostic-code deployment blocker.

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

### Remote Progress Stale With No Verdict

Use this when the remote command was admitted and started, but RCH never emitted
a compiler/test/bench success line or a Rust diagnostic. This is not the same as
a source failure.

Agent Mail subject:

```text
[rch-validation] remote no-verdict on worker vmi1167313
```

Closeout reason:

```text
RCH validation blocker: final_verdict=transport_stall reason_code=remote_stale_no_verdict worker_id=vmi1167313 build_id=29890796996001815 command=rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_TARGET_DIR=/tmp/rch_target_example CARGO_ENCODED_RUSTFLAGS=-Clinker=cc cargo check -p frankenengine-engine --bench evidence_ledger_batch target_dir=/tmp/rch_target_example component_toolchain=cargo/rustc present heartbeat_phase=execute heartbeat_detail=remote_exec_start detector_progress_stale=true progress_age_secs=174 no compiler/test/bench verdict emitted after reaching frankenengine-engine next_action=cancel only the stale build if still active, preserve queue/status evidence, retry later on a healthy worker or split the target; not source evidence.
```

### Dry-Run Admission Refused Before Worker Start

Use this when `rch diagnose --dry-run --json` reports
`would_intercept=true` and `would_offload=false`, so the heavy Cargo command is
eligible for interception but no worker is currently admissible. This is a
pre-admission blocker, not a remote no-verdict run.
Cargo never executed remotely.

Agent Mail subject:

```text
[rch-validation] admission refused before worker start
```

Closeout reason:

```text
RCH validation blocker: final_verdict=admission_refused reason_code=no_admissible_workers worker_id=not_admitted diagnose_command=rch diagnose --dry-run --json -- env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_example cargo check -p frankenengine-engine --bin frankenctl command=rch exec -- env CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_ENCODED_RUSTFLAGS=-Clinker=cc CARGO_TARGET_DIR=/tmp/rch_target_example cargo check -p frankenengine-engine --bin frankenctl target_dir=/tmp/rch_target_example component_toolchain=not evaluated; dry-run admission refused before worker execution would_intercept=true would_offload=false reason_counts=critical_pressure=1,health_below_fallback=6,hard_preflight=2,active_project_exclusion=1 operator_category=mixed_no_admissible_workers next_action=wait for active project exclusion and worker pressure to clear, repair hard-preflight/toolchain blockers if owned, then rerun rch diagnose before rch exec; not source evidence.
```

Beads comment template:

```text
RCH admission-refusal blocker: bead=<bead-id> final_verdict=admission_refused reason_code=no_admissible_workers would_intercept=true would_offload=false first_blocker="no admissible workers: <reason_counts>" diagnose_command="<exact rch diagnose --dry-run --json -- ...>" command="<pending rch exec -- ... cargo ...>" target_dir="<CARGO_TARGET_DIR>" operator_category=<category> next_action="<wait/repair/rerun diagnose before exec>" pending_validation="<cargo command that did not execute>" not_source_evidence=true cargo_executed=false
```

Agent Mail body template:

```text
RCH admission-refusal blocker for <bead-id>.

Cargo did not execute and no worker was admitted.

diagnose_command=<exact rch diagnose --dry-run --json -- ...>
command=<pending rch exec -- ... cargo ...>
target_dir=<CARGO_TARGET_DIR>
would_intercept=true
would_offload=false
first_blocker=no admissible workers: <reason_counts>
operator_category=<wait_for_active_project|worker_health_or_capacity|worker_preflight_or_toolchain|mixed_no_admissible_workers>
active_project_exclusion=<worker/build hint or none>
pending_validation=<what remains unproved>
next_action=<wait, repair owned preflight/toolchain blockers, then rerun diagnose before exec>

This is not source evidence.
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
