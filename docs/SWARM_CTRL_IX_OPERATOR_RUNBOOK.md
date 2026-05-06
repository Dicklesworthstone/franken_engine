# SWARM-CTRL-IX Operator Runbook

This runbook composes the shipped SWARM-CTRL-IX surfaces into one deterministic,
no-mock drill over checked-in fixtures and replay artifacts. The drill reuses:

- `scripts/swarm_telemetry_snapshot_normalizer.sh`
- `scripts/swarm_high_core_slo_scenario_matrix.sh`
- `scripts/swarm_slo_calibrator.sh`
- `scripts/swarm_high_core_chaos_conformance_gate.sh`
- `scripts/swarm_operator_slo_tuning_advisory.sh`

The composed entrypoint is:

```bash
./scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh check
./scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh run
./scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh selftest
./scripts/e2e/swarm_high_core_slo_calibration_no_mock_drill.sh replay --artifact-dir /tmp/franken-engine-swarm-high-core-slo-calibration-no-mock-drill/EXAMPLE
```

## Evidence Sources

The baseline pass path uses checked-in replay fixtures from
`scripts/testdata/swarm_high_core_slo_calibration_drill` plus the checked-in
scenario matrix and golden:

- `scripts/testdata/swarm_high_core_slo/scenario_matrix.json`
- `scripts/testdata/goldens/swarm_high_core_slo_scenario_matrix.golden`

The high-core truth branch intentionally reuses the current checked-in evidence
that is not yet fully `rch`-traceable:

- `artifacts/stress_concurrency/20260222T072317Z/suite_run_manifest.json`
- `artifacts/rgc_tail_latency_control_plane/20260319T183341Z/latency_control_plane_report.json`
- `artifacts/rgc_fault_injection_chaos_verification_pack/20260303T075226Z/chaos_verification_report.json`
- `docs/rgc_swarm_responsiveness_claim_map_v1.json`

## Output Bundle

`run` and `selftest` emit a deterministic bundle under the selected output dir:

- `swarm_high_core_slo_calibration_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`
- `telemetry/swarm_capacity_snapshot.json`
- `telemetry/swarm_slo_input_snapshot.json`
- `scenario-matrix/swarm_high_core_scenario_matrix_report.json`
- `threshold-receipt/swarm_slo_threshold_receipt.json`
- `chaos-conformance/swarm_high_core_chaos_conformance_report.json`
- `operator-advisory/swarm_operator_slo_tuning_advisory.json`
- `high-core-traceability/swarm_capacity_snapshot.json`
- `high-core-traceability/swarm_slo_input_snapshot.json`

## Workflow Truth Claims

- The composed drill does not execute live high-core stress; it reuses checked-in fixtures and replay artifacts only.
- The checked-in high-core evidence path must fail closed when traceability is not fully `rch`-backed.
- The operator advisory remains a downstream handoff only; it does not mutate live worker state, queue entries, leases, or archive bundles.
- Scenario matrix output must still match `scripts/testdata/goldens/swarm_high_core_slo_scenario_matrix.golden` before downstream IX artifacts are trusted.

## Interpreting Outputs

Review these fields first in `swarm_high_core_slo_calibration_no_mock_drill_report.json`:

- `summary.baseline_capacity_decision`
- `summary.threshold_decision`
- `summary.chaos_decision`
- `summary.advisory_decision`
- `summary.high_core_traceability_failure_count`
- `assertions.scenario_golden_matches`
- `assertions.high_core_traceability_fail_closed`

The bundle is truthful only when:

- `assertions.checked_in_fixture_inputs == true`
- `assertions.scenario_golden_matches == true`
- `assertions.high_core_traceability_fail_closed == true`
- `assertions.no_live_worker_mutation_claims == true`

## Truth Gate

Run the runbook truth gate whenever this runbook or the composed drill changes:

```bash
./scripts/e2e/swarm_ctrl_ix_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_ix_runbook_truth_gate.sh selftest
```

The truth gate rejects:

- bare heavy Cargo examples that are not `rch exec -- env CARGO_TARGET_DIR=` wrapped
- missing references to `swarm_high_core_slo_calibration_no_mock_drill_report.json`
- missing references to `swarm_capacity_snapshot.json`
- missing references to `swarm_slo_input_snapshot.json`
- missing references to `swarm_high_core_scenario_matrix_report.json`
- missing references to `swarm_slo_threshold_receipt.json`
- missing references to `swarm_high_core_chaos_conformance_report.json`
- missing references to `swarm_operator_slo_tuning_advisory.json`
- claims that the drill mutates live worker state or executes live high-core stress
- stale claims that checked-in high-core traceability failures are already safe to ignore
