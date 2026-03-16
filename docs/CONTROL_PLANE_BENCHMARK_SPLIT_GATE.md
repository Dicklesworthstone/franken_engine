# Control-Plane Benchmark Split Gate (`bd-1rdj`)

Deterministic benchmark gate for Section 10.13 item 17.

This gate enforces that control-plane integrations remain bounded while VM hot-loop
performance stays decoupled from control-plane overhead.

## Split Model

Required benchmark splits:

- `baseline`: VM hot-loop with control-plane adapter stubbed out.
- `cx_threading`: baseline + Cx propagation.
- `decision_contracts`: Cx + decision contract checks on high-impact actions.
- `evidence_emission`: Cx + decision contracts + evidence emission.
- `full_integration`: all control-plane features enabled.

## Reported Metrics

Each split records:

- throughput (`throughput_ops_per_sec`)
- latency (`p50_ns`, `p95_ns`, `p99_ns`)
- memory overhead (`peak_rss_delta_bytes`, delta from baseline)

## Default Thresholds

| Check | Limit |
| --- | ---: |
| Baseline stability CV | `< 5%` (50,000 ppm) across at least 10 runs |
| Cx throughput regression vs baseline | `< 1%` (10,000 ppm) |
| Decision latency regression vs Cx (p95/p99) | `< 5%` (50,000 ppm) |
| Evidence throughput regression vs decision | `< 2%` (20,000 ppm) |
| Full integration throughput regression vs baseline | `< 5%` (50,000 ppm) |

Failing any threshold sets `rollback_required=true`.

## Regression Detection

The evaluator compares candidate split metrics to a previous benchmark snapshot and
fails on threshold breaches using structured failure codes.

Core failure codes:

- `missing_split_metrics`
- `insufficient_baseline_runs`
- `baseline_variance_exceeded`
- `invalid_metric`
- `throughput_regression_exceeded`
- `latency_regression_exceeded`
- `memory_overhead_exceeded`
- `previous_run_regression_exceeded`

## Structured Logs

Decision output emits stable log fields:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Events include:

- `baseline_stability_check`
- `split_evaluation`
- `benchmark_split_decision`

## Test Coverage

Implemented tests include:

- baseline stability gate: 10-run CV checks and insufficient-run rejection
- adapter sleep regression detection: induced latency/throughput regression triggers rollback
- split isolation: disabling evidence emission restores decision-level throughput
- workflow assertion: CI workflow must run the benchmark split gate suite

## RCH Runner

All heavy Rust commands are offloaded through `rch` in the suite runner:

```bash
./scripts/run_control_plane_benchmark_split_gate_suite.sh ci
./scripts/e2e/control_plane_benchmark_split_gate_replay.sh test
```

The runner is fail-closed for heavy commands:

- `rch` is required; there is no local fallback path for Cargo-heavy verification.
- default remote target dirs are repo-local and namespaced, for example:

```bash
env CARGO_TARGET_DIR="$PWD/target_rch_control_plane_benchmark_split_gate_verify" \
  ./scripts/run_control_plane_benchmark_split_gate_suite.sh test
```

Supported modes:

- `check`
- `test`
- `clippy`
- `ci`

## Reproducibility Artifacts

Each run writes:

- `artifacts/control_plane_benchmark_split_gate/<timestamp>/commands.txt`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/events.jsonl`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/run_manifest.json`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/step_logs/step_*.log`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/env.json`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/summary.md`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/repro.lock`
- `artifacts/control_plane_benchmark_split_gate/<timestamp>/trace_ids`

`run_manifest.json` includes operator verification commands and artifact pointers.
The replay wrapper prefers the suite entrypoint directly:

```bash
./scripts/e2e/control_plane_benchmark_split_gate_replay.sh test
cat artifacts/control_plane_benchmark_split_gate/<timestamp>/step_logs/step_000.log
```
