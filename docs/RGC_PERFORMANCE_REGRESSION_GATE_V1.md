# RGC Performance Regression Gate V1

Machine-readable contract: `docs/rgc_performance_regression_gate_v1.json`

## Scope

`bd-1lsy.8.3` defines a deterministic gate that:

- classifies benchmark regressions with stable severity labels,
- fails closed on unresolved high/critical regressions,
- ranks likely culprits deterministically for operator triage,
- enforces waiver expiry semantics for blocking findings.

## Contract Version

- `schema_version`: `franken-engine.rgc-performance-regression-gate.contract.v1`
- `report_schema_version`: `franken-engine.rgc-performance-regression-gate.v1`

## Regression Classification

- `warning`: regression exceeds warning threshold but below fail threshold.
- `high`: regression exceeds fail threshold or significance confidence is insufficient.
- `critical`: baseline missing/zero or regression exceeds critical threshold.

Blocking policy:

- Gate blocks when any active finding has severity `high` or `critical`.
- Waived findings do not block unless the waiver is expired.
- Expired waivers are fail-closed (`FE-RGC-703-WAIVER-0006`).

## Structured Log Contract

Every emitted event includes stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code` (nullable)
- `workload_id` (nullable)

## Required Artifacts

Gate runs publish deterministic artifacts under
`artifacts/rgc_performance_regression_gate/<UTC_TIMESTAMP>/`:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `regression_report.json`

## Replay and Execution

```bash
./scripts/run_rgc_performance_regression_gate.sh ci
./scripts/e2e/rgc_performance_regression_gate_replay.sh ci
```

All heavy Rust build/test/lint commands are executed via `rch`.
Use `RCH_EXEC_TIMEOUT_SECONDS` and `RCH_BUILD_TIMEOUT_SECONDS` to raise the
outer and remote cargo timeouts together when a cold worker needs more headroom.
If `rch` still reports a wrapped `timeout_secs` value below the requested
`RCH_BUILD_TIMEOUT_*` value, the gate fails closed with
`rch-timeout-mismatch-<reported>-lt-<requested>`.

If you set `RCH_PROGRESS_STALL_SECONDS` to a value greater than `0`, the gate
will fail closed with a `failed_command` marker shaped like
`rch-stalled-no-progress-<seconds>s` when `rch` reaches remote execution and
then stops emitting output for longer than that window. The default is `0`
(disabled) because healthy `cargo` compiles can be silent for several minutes.

## Operator Verification

```bash
./scripts/run_rgc_performance_regression_gate.sh ci
cat artifacts/rgc_performance_regression_gate/<timestamp>/run_manifest.json
cat artifacts/rgc_performance_regression_gate/<timestamp>/events.jsonl
cat artifacts/rgc_performance_regression_gate/<timestamp>/commands.txt
cat artifacts/rgc_performance_regression_gate/<timestamp>/regression_report.json
./scripts/e2e/rgc_performance_regression_gate_replay.sh ci
```
