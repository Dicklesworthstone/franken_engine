# Live Capability and Ambient-Authority Rejection Example

This example demonstrates live capability enforcement with comprehensive proof artifacts for bead **bd-1bao8**.

## Purpose

Provides concrete evidence that the FrankenEngine capability system:
1. **Rejects ambient authority** - blocks unauthorized filesystem/network/process access
2. **Allows declared operations** - permits legitimate computation within granted capabilities  
3. **Generates proof artifacts** - captures evidence, decisions, receipts, and traces

## Files

- [`ambient_authority_attempt.js`](./ambient_authority_attempt.js) - Attempts `require("fs").readFileSync()` without declared capability (should be rejected)
- [`declared_capability.js`](./declared_capability.js) - Performs pure computation within allowed capabilities (should succeed)
- [`verify.sh`](./verify.sh) - Verification script that captures both behaviors with full evidence

## Run

From the repository root:

```bash
# Run the complete verification
./examples/21_live_capability_rejection/verify.sh
```

This will:
1. Build the frankenctl binary
2. Test ambient authority rejection (expect failure)
3. Test declared capability allowance (expect success)  
4. Generate comprehensive proof artifacts

## Expected Output

```
Building frankenctl binary...
Testing ambient authority rejection...
Testing declared capability (allowed case)...
✓ Ambient authority properly rejected (exit code: 1)
✓ Declared capability properly allowed (exit code: 0) 
✓ Capability denial evidence captured

✅ Live capability rejection example completed successfully

📁 Artifact directory: artifacts/capability_rejection_example/20260501T123456Z
📄 Generated files:
ambient_attempt_stderr.log
ambient_attempt_stdout.log
capability_evidence.json
capability_policy_input.json
command_transcript.log
declared_capability_stderr.log
declared_capability_stdout.log
denial_decision_receipt.json
event_trace.json
verifier_report.json

🔒 Artifact bundle hash: sha256:abc123...
```

## Proof Artifacts Generated

1. **Capability Policy Input** - Test configuration and execution commands
2. **Lowered Capability Evidence** - Policy decisions and authority attempts  
3. **Denial Decision Receipt** - Formal rejection with reason and evidence
4. **Event Trace** - Timeline of capability checks and decisions
5. **Verifier Report** - Overall test results and pass/fail status
6. **Command Transcript** - Complete execution log with exit codes

## Security Properties Verified

- ✅ **Ambient authority rejection**: `require("fs")` without capability grant fails
- ✅ **Policy discrimination**: Pure computation allowed, ambient authority denied  
- ✅ **Evidence generation**: Comprehensive artifacts capture all decisions
- ✅ **Fail-closed behavior**: Unknown/denied capabilities result in execution termination

This demonstrates that capability-typed execution rejects ambient authority on the shipped parser/lowering/runtime CLI path per the bd-1bao8 requirements.