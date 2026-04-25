# Hello World

This is the smallest end-to-end `frankenctl run` example in the repository.

From the repository root, run:

```bash
cargo run -p frankenengine-engine --bin frankenctl -- \
  run \
  --input examples/01_hello_world/hello.js \
  --extension-id hello-world-demo \
  --out examples/01_hello_world/run_report.json
```

If `frankenctl` is already installed on your `PATH`, the equivalent command is:

```bash
frankenctl run \
  --input examples/01_hello_world/hello.js \
  --extension-id hello-world-demo \
  --out examples/01_hello_world/run_report.json
```

Verify the captured console output:

```bash
jq -r '.console_output[].message' examples/01_hello_world/run_report.json
```

The command above should print the contents of `expected_output.txt`:

```text
Hello, FrankenEngine!
```
