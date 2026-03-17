# IFC Release Gate (`bd-eke`)

Deterministic release gate for Information Flow Control (IFC) exfiltration protection and declassification audit coverage.

All CPU-intensive Rust commands are executed through `rch`.

## Scope

This gate certifies the following release-blocking conditions over the published IFC conformance corpus:

- Unauthorized exfiltration attempts are blocked (`0` unauthorized successes).
- Benign workloads are not incorrectly blocked (`0` false positives).
- Direct and indirect exfil paths cannot bypass enforcement (`0` direct/indirect false negatives).
- Approved declassification flows emit declassification-receipt evidence.
- Gate decisions are deterministic under identical manifest + policy inputs.
- Structured log fields required for auditability are present:
  - `trace_id`, `decision_id`, `policy_id`, `component`, `event`, `outcome`, `error_code`.

## Pass/Fail Thresholds

| Metric | Threshold | Rationale |
|---|---|---|
| `ci_blocking_failures` | `0` | Hard release blocker: any CI-blocking IFC miss fails closed. |
| `false_positive_count` | `0` | Benign capability use must not be disrupted in release candidate. |
| `false_negative_direct_indirect_count` | `0` | Most exploitable exfil classes must have zero bypasses. |
| `benign_total` | `>= 100` | Minimum benign-corpus coverage for confidence. |
| `exfil_total` | `>= 80` | Minimum exfil-corpus coverage for confidence. |
| `declassify_total` | `>= 30` | Minimum approved-exception coverage for auditability. |

## Deterministic Runbook

Run from repo root (`/data/projects/franken_engine`):

```bash
# compile-only validation for gate assets
./scripts/run_ifc_release_gate.sh check

# run integration test gate assertions
./scripts/run_ifc_release_gate.sh test

# execute corpus and apply release thresholds
./scripts/run_ifc_release_gate.sh gate

# replay the latest complete gate bundle while re-running the selected mode
./scripts/e2e/ifc_release_gate_replay.sh gate

# full lane (check + test + gate + clippy)
./scripts/run_ifc_release_gate.sh ci
```

Primary artifacts are emitted under:

- `artifacts/ifc_release_gate/<timestamp>/run_manifest.json`
- `artifacts/ifc_release_gate/<timestamp>/ifc_release_gate_events.jsonl`
- `artifacts/ifc_release_gate/<timestamp>/ifc_conformance/<run_id>/ifc_conformance_evidence.jsonl`

## Failure Semantics

- `FE-IFCR-1001`: threshold validation failed (release blocked).
- `FE-IFCR-1002`: IFC evidence summary parse/lookup failed (release blocked, fail-closed).
- `FE-IFCR-1003`: command execution failure (release blocked, fail-closed).

Any non-zero script exit code is a release-blocking result.

`INT`/`TERM` interruptions emit fail-closed manifest and event artifacts with
`FE-IFCR-1003` rather than leaving a misleading pass bundle behind.

## Rollback/Fallback Activation

Activate fallback when gate fails and release cannot satisfy thresholds in the active window:

```bash
# keep candidate in non-promoted state and rerun diagnostic gate lane
./scripts/run_ifc_release_gate.sh gate

# inspect event + manifest bundle for exact blocking reason
cat artifacts/ifc_release_gate/<timestamp>/ifc_release_gate_events.jsonl
cat artifacts/ifc_release_gate/<timestamp>/run_manifest.json
```

Operational rollback criteria:

1. `ci_blocking_failures > 0` OR `false_negative_direct_indirect_count > 0`.
2. Missing declassification receipt evidence for approved exception workloads.
3. Missing structured audit fields in conformance logs.

Recovery must produce a fresh passing gate bundle before release promotion is re-enabled.
