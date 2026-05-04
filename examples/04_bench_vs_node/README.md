# Bench Vs Node

This example runs the same parser-light integer-summing workload through
FrankenEngine's `frankenctl run` path and plain Node, then compares the printed
sum. For repeatable timing runs, use the Criterion benchmark in
`crates/franken-engine/benches/comparative_node.rs`.

From the repository root:

```bash
bench_dir=/tmp/bench_$$
mkdir -p "$bench_dir"

/usr/bin/time -p -o "$bench_dir/frankenengine.time" \
  cargo run --quiet -p frankenengine-engine --bin frankenctl -- \
  run examples/04_bench_vs_node/workload.js \
  > "$bench_dir/frankenengine.txt"

if command -v node >/dev/null 2>&1; then
  /usr/bin/time -p -o "$bench_dir/node.time" \
    node examples/04_bench_vs_node/workload.js \
    > "$bench_dir/node.txt"
else
  printf 'node not found; skipped\n' > "$bench_dir/node.txt"
fi

diff -u "$bench_dir/frankenengine.txt" "$bench_dir/node.txt"
```

## What The Output Means

Successful runs print `499500` into `frankenengine.txt`. If Node is installed,
`node.txt` should print the same value and `diff -u` should produce no output.
If Node is not installed, `node.txt` will contain a skip marker instead.

`frankenengine.time` and `node.time` capture the wall-clock timings for this
single run. They are useful as a quick sanity check, not as publishable
benchmark evidence.

## Criterion Benchmark

The repository benchmark is the evidence-oriented path:

```bash
rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine_comparative_node_target \
  CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
  cargo build -p frankenengine-engine --bin frankenctl --release

rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine_comparative_node_target \
  CARGO_INCREMENTAL=0 RUSTFLAGS='-C linker=cc' \
  cargo bench -p frankenengine-engine --bench comparative_node -- --noplot
```

The bench materializes shared JavaScript workloads, verifies that Node stdout
matches FrankenEngine's `frankenctl run` JSON output, then times both runtimes as
subprocesses. The reported ratios apply to that CLI/subprocess methodology only;
they should not be used as broad VM throughput claims without the larger
benchmark evidence bundle. `frankenctl` is resolved from `FRANKENCTL`,
Cargo's bin env var, the shared benchmark target directory, or PATH.

## Caveats

- `frankenctl run` here is FrankenEngine's interpreter-mode execution path.
- Node executes the same file through its JIT/runtime stack.
- The workload is intentionally tiny and interpreter-stress-heavy, so it does
  not justify broad throughput claims on its own.
- First-run FrankenEngine timing can include local compile cost if the binary is
  not already built.
