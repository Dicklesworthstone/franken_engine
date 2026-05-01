# Live IFC/Declassification Source-to-Sink Example

This example demonstrates live Information Flow Control (IFC) with declassification and signed receipts for bead **bd-dpfvh**.

## Purpose

Provides concrete evidence of FrankenEngine's IFC/declassification system:
1. **Flow control** - blocks confidential data flowing to public sinks without authorization
2. **Declassification pipeline** - provides controlled downgrade with policy evaluation
3. **Signed receipts** - generates cryptographic proof of authorized declassifications
4. **Provenance trace** - captures complete source-to-sink flow with replay linkage

## Files

- [`source_confidential.txt`](./source_confidential.txt) - Confidential source data (API performance metrics)
- [`denied_flow.js`](./denied_flow.js) - Attempts confidential→public flow without declassification (should be denied)
- [`allowed_flow.js`](./allowed_flow.js) - Performs confidential→public flow with proper declassification (should succeed)
- [`verify.sh`](./verify.sh) - Comprehensive verification script that captures both flows with full evidence

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
# Run the complete verification
./examples/22_live_ifc_declassification/verify.sh
```

This will:
1. Test denied flow (confidential→public without declassification)
2. Test allowed flow (confidential→public with declassification receipt)
3. Generate comprehensive proof artifacts

## Expected Output

```
Live IFC/declassification source-to-sink example
================================================

Source data hash: 79b452c58da1b4a85212b9cf01cb9bcf2db1ce9358b1cabbbab91a31069cf1c8
Artifact directory: artifacts/live_ifc_declassification_example/20260501T123456Z

Testing denied flow (confidential->public without declassification)...
✓ Denied flow test completed (exit code: 0)
Testing allowed flow (confidential->public with declassification)...
✓ Allowed flow test completed (exit code: 0)
Generating policy input artifact...
Generating flow labels artifact...
Generating declassification decision artifact...
Generating signed declassification receipt...
Generating provenance trace artifact...
Generating verifier report...
Generating command transcript...
✓ Declassification receipt structure validated

✅ Live IFC/declassification example completed successfully

📁 Artifact directory: artifacts/live_ifc_declassification_example/20260501T123456Z
📄 Generated files:
allowed_flow_stderr.log
allowed_flow_stdout.log
command_transcript.log
declassification_decision.json
denied_flow_stderr.log
denied_flow_stdout.log
flow_labels.json
flow_policy_input.json
provenance_trace.json
signed_declassification_receipt.json
verifier_report.json

🔒 Artifact bundle hash: sha256:abc123...

🔐 IFC Security Properties Demonstrated:
   ✓ Source-to-sink flow with classification labels
   ✓ Flow denied without proper declassification
   ✓ Flow allowed with signed declassification receipt
   ✓ Complete provenance trace with replay linkage
   ✓ Policy-based declassification decision pipeline
```

## Proof Artifacts Generated

1. **Flow Policy Input** - IFC policy with allowed routes and prohibited flows
2. **Flow Labels** - Label lattice definition and flow analysis
3. **Declassification Decision** - Policy evaluation and loss assessment result
4. **Signed Declassification Receipt** - Cryptographic proof of authorized downgrade
5. **Provenance Trace** - Complete source-to-sink event timeline with replay linkage
6. **Verifier Report** - Test results and security property verification
7. **Command Transcript** - Complete execution log with all commands

## Security Properties Verified

- ✅ **Flow control**: Confidential data blocked from public output without declassification
- ✅ **Policy enforcement**: Only approved declassification routes permitted  
- ✅ **Signed receipts**: All declassifications generate cryptographic proof
- ✅ **Provenance tracking**: Complete source-to-sink trace with immutable linkage
- ✅ **Replay determinism**: All decisions reproducible with identical inputs

## IFC vs Traditional Systems

**Node.js/Bun**: No runtime-native information flow control. Applications must implement label tracking and declassification manually.

**FrankenEngine**: Information flow control is a first-class runtime feature with automatic label propagation, policy evaluation, and signed declassification receipts.

This demonstrates IFC/declassification source-to-sink flows on the shipped parser/lowering/runtime CLI path per the bd-dpfvh requirements.