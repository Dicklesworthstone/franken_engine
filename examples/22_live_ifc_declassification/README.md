# Live IFC/Declassification Source-to-Sink Example

This example demonstrates live Information Flow Control (IFC) with declassification and signed receipts for bead **bd-dpfvh**.

## Purpose

Provides concrete evidence of FrankenEngine's IFC/declassification system:
1. **Flow control** - blocks confidential data flowing to public sinks without authorization
2. **Declassification pipeline** - provides controlled downgrade with policy evaluation
3. **Signed receipts** - generates cryptographic proof of authorized declassifications
4. **Provenance trace** - captures complete source-to-sink flow with replay linkage

## Files

- [`verify.sh`](./verify.sh) - runs the live example below and fails unless its artifacts re-verify
- [`../live_ifc_declassification_example.rs`](../live_ifc_declassification_example.rs) - the live example: real `FlowPolicy` flow checks, the real `DeclassificationPipeline`, Ed25519-signed receipts, and a disk-only re-verifier (`verify <dir>` mode)
- [`source_confidential.txt`](./source_confidential.txt), [`denied_flow.js`](./denied_flow.js), [`allowed_flow.js`](./allowed_flow.js) - illustrative inputs only: nothing executes them, and the example's sources are built in Rust (`ClassifiedDataSource`)

## What this does and does not exercise

It exercises the IFC library surfaces directly: policy signing, `FlowPolicy::is_flow_allowed`, the declassification pipeline's route and loss checks, and receipt signing. It does **not** run JavaScript through the parser/lowering/interpreter path, so it says nothing about label propagation inside guest code (that is covered by the IFC tests under `crates/franken-engine/tests/`).

## Fixture Boundary

The checked-in source file is a deterministic fixture for replayable proof artifacts. It is not a production classifier.

Production integrations should feed the IFC runtime a classification envelope from a policy-backed source adapter before any sink write is attempted:

```json
{
  "source_uri": "otel://service/api-gateway/latency-window",
  "content_sha256": "sha256:<hash-of-current-payload>",
  "label": "confidential",
  "label_authority": "policy://franken-ifc-policy-v1",
  "classification_reason": "service telemetry contains tenant and capacity signals",
  "decision_contract_id": "franken-ifc-decision-contract",
  "freshness_window_ms": 300000
}
```

The adapter is responsible for deriving `label` and `classification_reason` from live metadata such as tenant scope, incident state, source system, and policy epoch. This example keeps those values fixed only so the denied and allowed flows produce stable artifacts for replay.

## IFC Label Lattice

```
TopSecret (level 4)
    ↑
Secret (level 3) 
    ↑
Confidential (level 2)  ← source data
    ↑
Internal (level 1)
    ↑
Public (level 0)       ← sink destination
```

Information may only flow **downward** in the lattice, and downward flows across multiple levels require explicit declassification.

## Run

From the repository root:

```bash
./examples/22_live_ifc_declassification/verify.sh
```

The example runs two scenarios: confidential API metrics to a public incident report (a declassification route exists, so it is approved and a signed receipt is issued) and internal debug data to public logs (no route, so it is denied). It writes its artifacts, re-reads them from disk and verifies them. Only then does it print an `IFC_DEMO_VERDICT {...}` line. `verify.sh` then:

1. exits with the example's own exit status if the example fails;
2. requires the verdict line to show at least one approved flow under a verified receipt and at least one denied flow;
3. when the artifacts are visible locally, checks `report.json` directly and re-verifies every published Ed25519 signature with PyNaCl, an implementation independent of the engine's (skipped, and reported as skipped, when PyNaCl is not installed).

To re-verify a previous run's artifacts without re-running it:

```bash
cargo run -p frankenengine-engine --example live_ifc_declassification_example -- verify <artifact-dir>/live
```

A flipped signature bit, a receipt field rewritten after signing, a denied flow reported as completed, or a substituted verification key each make that command fail. These are the tamper cases in the example's own unit tests.

## Artifacts (all written by the example)

- `report.json` / `report.md` - per-scenario flow-check result, loss assessment, pipeline events, approval, receipt hash
- `declassification_receipts.json` - each issued receipt, the exact preimage its signature covers, and the signature
- `verification_key.json` - the run's Ed25519 verification key (the signing key is fresh per run)
- `manifest.json`, `events.jsonl`, `commands.txt`

`verify.sh` adds only `live_ifc_stdout.log`, `live_ifc_stderr.log` and `command_transcript.log` (the command it ran and its exit code).

## IFC vs Traditional Systems

**Node.js/Bun**: No runtime-native information flow control. Applications must implement label tracking and declassification manually.

**FrankenEngine**: Information flow control is a first-class runtime feature with policy evaluation and signed declassification receipts; this example shows the policy/pipeline/receipt half of that, not in-guest label propagation.
