# Bench Vs Node

This example compares the same tiny integer-summing workload under `frankenctl run` and Node.

From the repository root, capture both outputs into a disposable benchmark directory:

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
  diff -u "$bench_dir/frankenengine.txt" "$bench_dir/node.txt"
else
  echo "node not found; skipped Node comparison"
fi
```

`frankenengine.txt` and `node.txt` should both contain `499500`.

Interpret the result carefully:

- `frankenctl run` is an interpreter-mode path through FrankenEngine's native evaluation pipeline.
- Node runs the same JavaScript file through its JIT/runtime stack.
- This is only a tiny parser-light sanity benchmark. It is useful for matching observable output and rough timing, not for making broad performance claims.
