# Runtime Comparison Benchmarks

This directory contains the official FrankenEngine runtime-comparison corpus used for
publishable performance evidence. The manifest runs the same JavaScript workload files
through FrankenEngine, Node.js LTS, and Bun stable, then records raw timings,
environment metadata, command transcripts, and behavioral parity evidence.

## Operator Workflow

Run the artifact-producing comparison suite with:

```bash
frankenctl benchmark compare \
  --manifest benchmarks/runtime_comparison/manifest.json \
  --run-id runtime-comparison-$(date -u +%Y%m%dT%H%M%SZ) \
  --run-date $(date -u +%F) \
  --out-dir artifacts/runtime_comparison
```

Build the `frankenctl` binary into a shared target directory, then run the
focused Cargo bench wrappers for subprocess timing:

```bash
rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine_runtime_comparison_target \
  CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
  cargo build -p frankenengine-engine --bin frankenctl --release

rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine_runtime_comparison_target \
  CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
  cargo bench -p frankenengine-engine --bench comparative_node -- --noplot

rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine_runtime_comparison_target \
  CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
  cargo bench -p frankenengine-engine --bench comparative_bun -- --noplot
```

The Node Cargo bench materializes numeric-loop, basic-arithmetic, and JSON
round-trip workloads. The Bun Cargo bench materializes numeric-loop,
JSON-round-trip, and array-indexing workloads. Each bench executes the workload
through `frankenctl run` and the peer runtime, verifies matching observable
output before timing, and lets Criterion report per-runtime wall-clock
distributions inside the same benchmark group.

## Methodology

- Workloads are standalone JavaScript programs so each runtime receives the same
  source file.
- FrankenEngine is invoked through `frankenctl run --input <workload>` to include
  the operator-visible CLI/orchestrator path.
- Node.js is invoked through the configured `node` binary with the same workload
  path; Bun is invoked through the configured `bun` binary with the same
  workload path.
- The artifact suite uses the manifest fairness policy: two warmups, thirty
  measured samples, and a thirty-second per-case timeout.
- The Cargo bench uses Criterion with ten samples per runtime/workload to keep
  local iteration practical; use the artifact suite for release evidence.
- `frankenctl` is resolved from `FRANKENCTL`, Cargo's bin env var, the shared
  target directory, or PATH. The peer runtimes can be overridden with `NODE` and
  `BUN`.
- Runtime ratios are valid for this subprocess methodology only. They must not be
  presented as broad VM throughput claims without the emitted artifact bundle.
