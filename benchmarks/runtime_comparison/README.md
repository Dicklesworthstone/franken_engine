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

Run the focused Cargo bench wrapper for FrankenEngine-vs-Node subprocess timing with:

```bash
cargo bench -p frankenengine-engine --bench comparative_node
```

The Cargo bench materializes three representative workloads: numeric loops, basic
arithmetic, and JSON round trips. It executes each workload through `frankenctl run`
and `node`, verifies matching observable output before timing, and lets Criterion
report per-runtime wall-clock distributions inside the same benchmark group.

## Methodology

- Workloads are standalone JavaScript programs so each runtime receives the same
  source file.
- FrankenEngine is invoked through `frankenctl run --input <workload>` to include
  the operator-visible CLI/orchestrator path.
- Node.js is invoked through the configured `node` binary with the same workload
  path.
- The artifact suite uses the manifest fairness policy: two warmups, thirty
  measured samples, and a thirty-second per-case timeout.
- The Cargo bench uses Criterion with ten samples per runtime/workload to keep
  local iteration practical; use the artifact suite for release evidence.
- Runtime ratios are valid for this subprocess methodology only. They must not be
  presented as broad VM throughput claims without the emitted artifact bundle.
