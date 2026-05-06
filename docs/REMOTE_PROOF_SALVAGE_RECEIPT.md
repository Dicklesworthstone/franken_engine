# Remote Proof Salvage Receipt

`scripts/remote_proof_salvage_receipt.sh` turns resident bundle receipts,
incident packets, and worker-truth parity evidence into one operational salvage
artifact for remote-proof recovery.

## Purpose

Transport failure and live remote work often diverge. A timed-out `rch` command
may still have a hot `rustc` on the worker; a canceled run may leave orphaned
processes; a clean finished bundle should not be quarantined accidentally. This
receipt compresses those upstream facts into one deterministic recommendation.

## Usage

```bash
./scripts/remote_proof_salvage_receipt.sh \
  --bundle-report-json artifacts/resident_bundle/bundle_report.json \
  --incident-packet-json artifacts/rch/incident_packet.json \
  --worker-truth-report-json artifacts/rch/worker_truth_report.json \
  --output-dir /tmp/remote-proof-salvage
```

Required upstream artifacts:

- resident bundle report:
  `franken-engine.resident-remote-proof-bundle.v1`
- incident packet:
  `franken-engine.rch-incident-packet.v1`
- worker truth parity report:
  `franken-engine.rch-worker-truth-parity-report.v1`

## Receipt Contract

The emitted `salvage_receipt.json` uses schema version
`franken-engine.remote-proof-salvage-receipt.v1`.

Key fields:

- `salvage_id`
- `bundle_id`
- `workflow_state`
- `recovery_recommendation`
- `reason`
- `operator_actions[]`
- `bundle_decision`
- `incident_status`
- `incident_failure_kind`
- `worker_truth_decision`
- `expected_worker_id`
- `expected_target_dir`
- `observed_process_truth`
- `parity_findings`
- `upstream_artifact_paths`
- `bundle_artifact_paths`
- `artifact_paths`

`observed_process_truth` records:

- `live_remote_compile`
- `orphaned_process_detected`
- `worker_reachable`
- `recoverable_artifact_set`

## Workflow States

- `clean_finished`
  - recommendation: `no_salvage_needed`
- `live_compile_salvageable`
  - recommendation: `wait_then_salvage_artifacts`
- `orphan_reconciliation_required`
  - recommendation: `clear_orphan_before_retry`
- `worker_unreachable_degraded`
  - recommendation: `quarantine_worker_and_reroute`
- `manual_review_required`
  - recommendation: `manual_classification_required`

Every non-clean state is intentionally fail-closed with exit code `42`.

## Artifacts

Each run emits:

- `salvage_receipt.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Proof

The smoke harness is:

```bash
./scripts/e2e/remote_proof_salvage_receipt_smoke.sh check
./scripts/e2e/remote_proof_salvage_receipt_smoke.sh selftest
```

Required fixtures:

- timeout with live compile salvage
- canceled bundle with orphaned rustc reconciliation
- clean finished bundle requiring no salvage
- unreachable worker degraded salvage
