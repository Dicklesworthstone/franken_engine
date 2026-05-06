# SWARM-CTRL-VI Operator Runbook

This runbook is the operator-facing workflow for the SWARM-CTRL-VI archive
retention, restore, and storage-pressure control plane. It composes the shipped
VI shell surfaces into one truthful, bounded drill without adding any new live
`rch` behavior.

## Composed Surfaces

The runbook depends on these shipped scripts:

- `./scripts/remote_proof_retention_class_ledger.sh`
- `./scripts/remote_proof_compaction_planner.sh`
- `./scripts/remote_proof_archive_exporter.sh`
- `./scripts/remote_proof_gc_guard.sh`
- `./scripts/remote_proof_archive_pressure_scoreboard.sh`
- `./scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh`
- `./scripts/e2e/swarm_ctrl_vi_runbook_truth_gate.sh`

The operator drill must publish and inspect these artifacts:

- `retention_class_ledger.json`
- `evidence_residency_manifest.json`
- `remote_proof_compaction_plan.json`
- `archive_pack.json`
- `restore_verification_report.json`
- `remote_proof_gc_guard_report.json`
- `remote_proof_archive_pressure_scoreboard.json`
- `remote_proof_archive_lifecycle_no_mock_drill_report.json`

Heavy proof examples stay in this form:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_ctrl_vi cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture
```

## Operator Flow

1. Validate the runbook and drill surfaces before using them:

```bash
./scripts/e2e/swarm_ctrl_vi_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_vi_runbook_truth_gate.sh selftest
```

2. Validate the composed drill itself:

```bash
./scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh check
./scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh selftest
```

3. Read the resulting composed drill report:

```bash
cat /tmp/franken-engine-remote-proof-archive-lifecycle-no-mock-drill*/run/remote_proof_archive_lifecycle_no_mock_drill_report.json
cat /tmp/franken-engine-remote-proof-archive-lifecycle-no-mock-drill*/run/report.md
```

## What The Drill Must Prove

The drill is shell and JSON only. It does not run heavy Cargo. It composes the
actual SWARM-CTRL-VI scripts and fails closed if any child surface drifts.

The report must show:

- retained resident bundle export and restore from `archive_pack.json` plus
  `restore_verification_report.json`
- duplicate artifact compaction through `remote_proof_compaction_plan.json`
  before archive export
- bounded GC classification through `remote_proof_gc_guard_report.json`
- archive-pressure advisory publication through
  `remote_proof_archive_pressure_scoreboard.json`

The three required scenario outcomes are:

- successful resident bundle export and restore while the pressure surface
  preserves active evidence instead of evicting it
- duplicate artifact compaction before archive export
- salvage-pinned evidence blocking GC and forcing a fail-closed advisory

## Workflow Truth Claims

- Duplicate artifact compaction must happen before archive export when `compacted_groups` is non-empty.
- Salvage-pinned evidence blocks GC even when a cold archive exists.
- Cold-archive eviction is honest only after `restore_verification_report.json` is `verified`.

## Interpreting Outputs

Use these fields when reviewing the final report:

- `drill_decision`
- `scenarios.resident_bundle_export_restore.status`
- `scenarios.resident_bundle_export_restore.pressure_summary.advisory`
- `scenarios.duplicate_compaction_before_export.compaction_summary.compacted_group_count`
- `scenarios.duplicate_compaction_before_export.pressure_summary.advisory`
- `scenarios.salvage_pinned_gc_block.gc_guard_summary.guard_decision`
- `scenarios.salvage_pinned_gc_block.pressure_summary.advisory`

The drill is truthful only when all three scenarios pass and the artifact paths
point at the emitted `retention_class_ledger.json`,
`evidence_residency_manifest.json`, `remote_proof_compaction_plan.json`,
`archive_pack.json`, `restore_verification_report.json`,
`remote_proof_gc_guard_report.json`,
`remote_proof_archive_pressure_scoreboard.json`, and
`remote_proof_archive_lifecycle_no_mock_drill_report.json`.

## Truth Gate

Run the truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_vi_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_vi_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples that are not `rch exec -- env CARGO_TARGET_DIR=`
  wrapped
- missing references to `retention_class_ledger.json`
- missing references to `evidence_residency_manifest.json`
- missing references to `remote_proof_compaction_plan.json`
- missing references to `archive_pack.json`
- missing references to `restore_verification_report.json`
- missing references to `remote_proof_gc_guard_report.json`
- missing references to `remote_proof_archive_pressure_scoreboard.json`
- missing references to
  `remote_proof_archive_lifecycle_no_mock_drill_report.json`
- stale workflow claims about compaction ordering, salvage pinning, or restore
  verification
