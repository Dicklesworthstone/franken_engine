# Capability-Typed Rejection Boundary Demo

This example verifies the rejection boundary on the current shipped `frankenctl run` path. It does not claim to verify a granted `fs_read` success path.

- [`pure_compute.js`](./pure_compute.js) stays inside pure computation and evaluates successfully.
- [`requires_capability.js`](./requires_capability.js) reaches for host authority through `require("fs")`, which the current runtime rejects fail-closed with a capability error before any file read happens.

## Run

From the repository root:

```bash
cargo run -p frankenengine-engine --bin frankenctl -- \
  run examples/06_capability_typed/pure_compute.js
```

That prints:

```text
42
```

The host-facing example fails closed:

```bash
cargo run -p frankenengine-engine --bin frankenctl -- \
  run examples/06_capability_typed/requires_capability.js
```

The error surface currently includes `eval.capability.denied` and `module:require`.

## What This Demonstrates

- `pure_compute.js` is the ambient-authority-free baseline: deterministic arithmetic with no host dependency.
- `requires_capability.js` is the capability-shaped boundary case: the source tries to cross into host authority, and the runtime blocks it rather than silently granting ambient access.
- The checked proof surface is rejection-only: the verifier asserts that ambient `require("fs")` is denied on the shipped CLI path.

## Future Work

The current `frankenctl run` surface does not expose a way to supply an explicit capability grant, and the baseline interpreter does not yet return real filesystem bytes on the shipped path. Because of that, this example demonstrates the rejection boundary concretely, while the "same program succeeds once granted `fs_read`" half remains conceptual until the CLI/runtime grows first-class capability manifests or grant injection.
