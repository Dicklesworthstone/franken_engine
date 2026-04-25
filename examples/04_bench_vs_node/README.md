# Bench Vs Node

This example runs the same parser-light integer-summing workload through
FrankenEngine's `frankenctl run` path and plain Node, then compares the printed
sum.

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

`frankenengine.time` and `node.time` capture the wall-clock timings for this
single run. They are useful as a quick sanity check, not as publishable
benchmark evidence.

## Caveats

- `frankenctl run` here is FrankenEngine's interpreter-mode execution path.
- Node executes the same file through its JIT/runtime stack.
- The workload is intentionally tiny and interpreter-stress-heavy, so it does
  not justify broad throughput claims on its own.
- First-run FrankenEngine timing can include local compile cost if the binary is
  not already built.
