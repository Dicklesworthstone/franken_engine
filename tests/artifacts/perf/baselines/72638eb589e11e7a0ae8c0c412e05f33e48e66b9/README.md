# Performance Baseline: 72638eb589e11e7a0ae8c0c412e05f33e48e66b9

Generated: 2026-11-11 15:32:02 UTC

## Conditions

- Git SHA: 72638eb589e11e7a0ae8c0c412e05f33e48e66b9
- Git branch: main
- Working directory: dirty
- Rust version: rustc 1.100.0-nightly (bba531001 2026-09-20)
- Target: x86_64-unknown-linux-gnu
- Hostname: hetzner2

## Benchmark Results

This baseline captures Criterion estimates for 8 benchmark functions from the `hot_paths` benchmark suite:

- parser_arena_materialization
- lowering_pipeline_ir3
- baseline_interpreter_eval
- baseline_value_string_clone
- iterator_protocol_trace
- scheduler_queue_commit
- evidence_ledger_bundle
- transport_certificate_serialization

## Files

- `criterion_*_estimates.json`: Individual function estimates from Criterion
- `baseline_summary.json`: Metadata about this baseline
- `fingerprint.json`: Build and environment fingerprint
- `README.md`: This documentation

## Usage

Performance regression gates can compare current benchmark results against this baseline to detect significant performance changes.
