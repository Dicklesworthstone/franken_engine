# Decision Traces Test Fixtures

## Purpose
Test fixtures for decision trace analysis and metamorphic testing. Referenced by:
- AA.4 metamorphic tests (existing decision verdicts preserved across substrate migration)
- S.5 negative test (counterfactual analysis)

## Contents
- `trace_001_quarantine_decision.json`: Basic extension quarantine decision trace
- `trace_002_readmission_approval.json`: Re-admission approval trace with operator signature
- `trace_003_policy_update.json`: Policy update decision with version transitions
- `trace_004_capability_grant.json`: Capability grant decision with security epoch
- `trace_005_revocation_cascade.json`: Revocation cascade across multiple extensions

## Generation
These traces are hand-curated representative examples based on the decision record schema.
Each trace includes:
- Decision ID, trace ID, policy context
- Evidence hash chains
- Operator signatures where applicable
- Timestamps and security epochs

## Validation
Content hashes are recorded in `fixture_manifest.json`.
To regenerate content hashes after updates:
```bash
cd crates/franken-engine/tests/data/decision_traces
find . -name "*.json" -type f -exec sha256sum {} \; | sort > fixture_manifest.json
```

## Schema Compliance
All traces conform to the decision record schema defined in the franken-decision crate.