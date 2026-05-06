# SWARM-CTRL-V Operator Runbook

This runbook is the operator-facing workflow for the SWARM-CTRL-V composition
lane. It composes the shipped resident-proof surfaces into one truthful,
bounded shell drill without adding any new live `rch` behavior.

## Composed Surfaces

The runbook depends on these shipped scripts:

- `./scripts/resident_remote_proof_bundle_executor.sh`
- `./scripts/remote_proof_artifact_mirror_packer.sh`
- `./scripts/warm_target_roi_eviction_ledger.sh`
- `./scripts/remote_proof_salvage_receipt.sh`
- `./scripts/locality_aware_remote_proof_batch_packer.sh`
- `./scripts/e2e/resident_remote_proof_no_mock_drill.sh`
- `./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh`

The operator drill must publish and inspect these artifacts:

- `bundle_report.json`
- `retrieval_verification_report.json`
- `warm_target_roi_ledger.json`
- `salvage_receipt.json`
- `batch_manifest.json`
- `resident_remote_proof_no_mock_drill_report.json`

Heavy proof examples stay in this form:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_ctrl_v cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture
```

## Operator Flow

1. Validate the runbook and drill surfaces before using them:

```bash
./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh selftest
```

2. Validate the composed drill itself:

```bash
./scripts/e2e/resident_remote_proof_no_mock_drill.sh check
./scripts/e2e/resident_remote_proof_no_mock_drill.sh selftest
```

3. Read the resulting composed drill report:

```bash
cat /tmp/franken-engine-resident-remote-proof-no-mock-drill*/run/resident_remote_proof_no_mock_drill_report.json
cat /tmp/franken-engine-resident-remote-proof-no-mock-drill*/run/report.md
```

## What The Drill Must Prove

The drill is shell and JSON only. It does not run heavy Cargo. It composes the
actual SWARM-CTRL-V scripts and fails closed if any child surface drifts.

The report must show:

- resident bundle reuse from `bundle_report.json` plus `warm_target_roi_ledger.json`
- bounded replay retrieval from `retrieval_verification_report.json`
- locality-aware batching from `batch_manifest.json`
- orphan handling from `salvage_receipt.json`

The three required scenario outcomes are:

- successful resident bundle reuse on one worker and one warm target
- bounded artifact retrieval plus one shared-locality batch
- salvage/orphan handling with `workflow_state = orphan_reconciliation_required`

## Interpreting Outputs

Use these fields when reviewing the final report:

- `drill_decision`
- `scenarios.resident_bundle_reuse.status`
- `scenarios.bounded_retrieval_and_batching.status`
- `scenarios.bounded_retrieval_and_batching.batch_manifest_id`
- `scenarios.salvage_orphan_handling.status`
- `scenarios.salvage_orphan_handling.workflow_state`

The drill is truthful only when all three scenarios pass and the artifact paths
point at the emitted `bundle_report.json`, `retrieval_verification_report.json`,
`warm_target_roi_ledger.json`, `salvage_receipt.json`, `batch_manifest.json`,
and `resident_remote_proof_no_mock_drill_report.json`.

## Truth Gate

Run the truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples that are not `rch exec -- env CARGO_TARGET_DIR=` wrapped
- missing references to `bundle_report.json`
- missing references to `retrieval_verification_report.json`
- missing references to `warm_target_roi_ledger.json`
- missing references to `salvage_receipt.json`
- missing references to `batch_manifest.json`
- missing references to `resident_remote_proof_no_mock_drill_report.json`
- missing references to `./scripts/e2e/resident_remote_proof_no_mock_drill.sh selftest`
