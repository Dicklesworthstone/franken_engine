# RGC-701 Benchmark Harness Method v1

This document defines the operator-facing methodology and replay metadata contract for `bd-1lsy.8.1`.

## Scope

The benchmark harness compares FrankenEngine extension-heavy workloads under a fixed fairness contract and emits machine-readable evidence bundles.

## Runtime Pin Contract

Pinned runtime identifiers are emitted in `benchmark_env_manifest.json`:

- `franken_engine`
- `node_lts`
- `bun_stable`

Pins must be non-empty. Empty pin values are rejected by harness contract validation.

## Fairness Guardrails

The harness enforces explicit guardrails:

- `warmup_runs >= 1`
- `sample_count >= 3`
- `case_timeout_ms >= 1`

These guardrails are serialized into `benchmark_env_manifest.json` and `run_manifest.json`.

## Artifact Contract

A report run must emit all of:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `benchmark_env_manifest.json`
- `raw_results_archive.json`
- `benchmark_evidence.jsonl`
- `benchmark_summary.json`

## rch-backed Execution

All CPU-intensive commands are run through `rch` via:

```bash
./scripts/run_benchmark_e2e_suite.sh ci
```

Mode options:

- `check`
- `test`
- `clippy`
- `report`
- `ci`

`report` executes integration artifact emission with:

```bash
FRANKEN_BENCH_E2E_OUTPUT_DIR=<artifact_dir> \
  cargo test -p frankenengine-engine --test benchmark_e2e_integration \
  benchmark_e2e_script_emits_artifacts_to_env_dir -- --exact --nocapture
```

## Replay Checklist

1. Run `./scripts/run_benchmark_e2e_suite.sh ci`.
2. Open the latest `artifacts/benchmark_e2e_suite/<timestamp>/suite_run_manifest.json`.
3. Verify the benchmark artifact pointers in `artifacts` exist, including `benchmark_evidence.jsonl` and `benchmark_summary.json`.
4. Inspect `benchmark_env_manifest.json` for runtime pins and fairness policy.
5. Re-run the command transcript in `commands.txt` if independent verification is required.
