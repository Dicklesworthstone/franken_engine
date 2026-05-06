# SWARM-CTRL-VIII Operator Runbook

This runbook is the operator-facing workflow for the SWARM-CTRL-VIII
predictive admission and lease-exchange control plane. It composes the shipped
admission drill, predictive orchestration proof, and archive-pressure drill
into one truthful, bounded no-mock proof surface.

This drill is proof-only. `scripts/swarm_operator_status_report.sh` remains the only predictive dashboard producer in `franken_engine`.

## Composed Surfaces

The runbook depends on these shipped scripts:

- `./scripts/e2e/swarm_admission_drill.sh`
- `./scripts/e2e/swarm_predictive_orchestration_e2e.sh`
- `./scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh`
- `./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh`
- `./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh`

The operator drill must publish and inspect these artifacts:

- `swarm_predictive_admission_no_mock_drill_report.json`
- `swarm_admission_drill_report.json`
- `predictive/wrapper/report.json`
- `predictive/operator-status/status.json`
- `predictive/operator-status/report.md`
- `swarm_capacity_forecast.json`
- `swarm_admission_budget_plan.json`
- `lease_exchange_salvage_simulation.json`
- `warm_target_prefetch_roi_advisory.json`
- `remote_proof_archive_lifecycle_no_mock_drill_report.json`

Heavy proof examples stay in this form:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_swarm_ctrl_viii cargo test -p frankenengine-engine --test swarm_validation_control_plane_e2e -- --nocapture
```

## Operator Flow

1. Validate the runbook and truth-gate surfaces before using them:

```bash
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh selftest
```

2. Validate the composed drill itself:

```bash
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh check
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh selftest
```

3. Read the resulting composed drill report:

```bash
cat /tmp/franken-engine-swarm-predictive-admission-no-mock-drill/*/swarm_predictive_admission_no_mock_drill_report.json
cat /tmp/franken-engine-swarm-predictive-admission-no-mock-drill/*/report.md
```

## What The Drill Must Prove

The drill is shell and JSON only. It does not run heavy Cargo. It reuses the
published child drills directly and fails closed if any child surface drifts.

The report must show:

- one SWARM-CTRL-III admission drill report proving contact-first stale-lock
  handling and protected-priority budget behavior
- one predictive orchestration wrapper proving reserved-overlap conflict,
  stale proof freshness, degraded `rch`, and low-confidence forecast handling
- one operator status report linking the predictive dashboard back to its child
  artifacts
- one archive lifecycle drill report showing compaction-first and
  salvage-pinned fail-closed pressure behavior

The required combined outcomes are:

- Low-confidence or stale forecast evidence must keep the composed predictive
  admission drill fail-closed instead of upgrading to admit.
- Lease exchange or salvage remains manual-confirmation only when stale locks,
  degraded rch, or archive pressure remain unresolved.
- Archive pressure must keep warm-target prefetch advisory-only and negative
  until compaction or preserve-pinned evidence clears.
- The drill does not mutate live worker state, leases, queue entries, or
  archive bundles.

## Workflow Truth Claims

- Low-confidence or stale forecast evidence must keep the composed predictive admission drill fail-closed instead of upgrading to admit.
- Lease exchange or salvage remains manual-confirmation only when stale locks, degraded rch, or archive pressure remain unresolved.
- Archive pressure must keep warm-target prefetch advisory-only and negative until compaction or preserve-pinned evidence clears.
- The drill does not mutate live worker state, leases, queue entries, or archive bundles.

## Interpreting Outputs

Use these fields when reviewing the final report:

- `summary.forecast_decision`
- `summary.forecast_confidence_band`
- `summary.admission_budget_profile`
- `summary.lease_exchange_decision`
- `summary.prefetch_advisory`
- `summary.archive_pressure_advisory`
- `assertions.stale_lock_contact_first`
- `assertions.degraded_rch_fail_closed`
- `assertions.archive_pressure_blocks_prefetch_promotion`

The drill is truthful only when all reuse assertions are `true` and the child
artifact paths point at the emitted `swarm_admission_drill_report.json`,
`predictive/wrapper/report.json`, `predictive/operator-status/status.json`,
`predictive/operator-status/report.md`, `swarm_capacity_forecast.json`,
`swarm_admission_budget_plan.json`, `lease_exchange_salvage_simulation.json`,
`warm_target_prefetch_roi_advisory.json`, and
`remote_proof_archive_lifecycle_no_mock_drill_report.json`.

## Truth Gate

Run the truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples that are not `rch exec -- env CARGO_TARGET_DIR=`
  wrapped
- missing references to `swarm_predictive_admission_no_mock_drill_report.json`
- missing references to `swarm_admission_drill_report.json`
- missing references to `predictive/wrapper/report.json`
- missing references to `predictive/operator-status/status.json`
- missing references to `predictive/operator-status/report.md`
- missing references to `swarm_capacity_forecast.json`
- missing references to `swarm_admission_budget_plan.json`
- missing references to `lease_exchange_salvage_simulation.json`
- missing references to `warm_target_prefetch_roi_advisory.json`
- missing references to `remote_proof_archive_lifecycle_no_mock_drill_report.json`
- stale workflow claims about stale-forecast fail-closed behavior,
  manual-confirmation salvage, or archive-pressure prefetch limits
- duplicate predictive dashboard producer claims
- any claim of live worker mutation
