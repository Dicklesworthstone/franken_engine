# React Compile Demo

This example documents the shipped `frankenctl react compile` operator surface. The command accepts a TSX input, emits a machine-readable React CLI report, and currently fails closed with exit code `25` because automatic-runtime TSX compile support is still marked `deferred` in [`docs/rgc_react_capability_contract_v1.json`](../../docs/rgc_react_capability_contract_v1.json).

## Files

- `sample.tsx`: minimal TSX input passed to `frankenctl react compile`.
- `demo.sh`: runs the CLI with fixed trace/decision/policy IDs, tolerates the expected blocked exit code, and prints the captured JSON report.
- `verify.sh`: reruns the same command and asserts the structured report fields that define the current React compile contract.

## Run

From the repository root:

```bash
./examples/12_frankenctl_react_demo/demo.sh
./examples/12_frankenctl_react_demo/verify.sh
```

## Notes

- The demo uses `--source-form tsx --runtime automatic`, which maps to capability row `tsx-automatic-runtime-compile`.
- `support_status="deferred"` and `blocked=true` are the expected current behavior.
- `verify.sh` checks the emitted schema version, capability ID, fail-closed diagnostic code, and request metadata rather than diffing a checked-in output file because the temporary output path changes per run.
