# Signed Decision Receipt

This example turns the `franken-decision-demo` binary into a user-runnable receipt workflow.

From the repository root, run:

```bash
cargo run --bin franken-decision-demo
```

The binary prints a JSON receipt like [`sample_receipt.json`](./sample_receipt.json).

Use [`verify.sh`](./verify.sh) to run the demo and assert the receipt contract with `jq`:

```bash
./examples/02_signed_decision_receipt/verify.sh
```

## Field Guide

- `decision`: the guardplane verdict chosen after replaying the modeled hostcall sequence.
- `rationale`: a human-readable explanation of how the normal and anomalous events drove that verdict.
- `posterior_after_millionths`: the posterior maliciousness estimate after all five events, encoded on a `0..=1_000_000` scale.
- `replay_seed`: the deterministic seed that lets operators rerun the same scenario and preserve the receipt's replay story.
- `signature_hex`: a 64-character hex authenticity hash produced by `AuthenticityHash::compute_keyed`, binding the decision payload to a cryptographic provenance check.
