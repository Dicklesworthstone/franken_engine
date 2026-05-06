# Swarm Predictive Dashboard Contract

This document defines the machine-readable feed produced by
`scripts/swarm_operator_status_report.sh` for future swarm dashboard rendering.
The feed is a contract and fixture surface only.

FrankenEngine does not ship a local TUI renderer for this contract.
Rich interactive rendering belongs in `/dp/frankentui`, following
`docs/adr/ADR-0003-frankentui-reuse-scope.md`.

## Producer

- Script: `scripts/swarm_operator_status_report.sh`
- Status schema: `franken-engine.swarm-operator-status-report.v1`
- Dashboard schema: `franken-engine.swarm-predictive-dashboard.v1`
- Static contract: `docs/swarm_predictive_dashboard_contract_v1.json`

The producer only reads explicit JSON snapshots. It does not claim beads, query
Agent Mail, run `rch`, execute Cargo, or mutate tracker state.
It remains the only predictive dashboard producer in `franken_engine`.
scripts/swarm_operator_status_report.sh remains the only predictive dashboard producer in `franken_engine`.

The predictive dashboard contract also has a pre-dashboard telemetry snapshot
extension:

- Script: `scripts/swarm_telemetry_snapshot_normalizer.sh`
- Snapshot schema: `franken-engine.swarm-capacity-snapshot.v1`
- High-core SLO schema: `franken-engine.swarm-slo-input-snapshot.v1`
- Static contract: `docs/swarm_telemetry_snapshot_contract_v1.json`

That normalizer reuses admission, archive, and proof-economy artifacts directly
and stays fixture-only. It does not replace `scripts/swarm_operator_status_report.sh`
and must not be described as a live scheduling control surface.
When SWARM-CTRL-IX inputs are supplied, the same normalizer also emits a
dedicated SLO input snapshot that summarizes checked-in stress, tail-latency,
chaos, and swarm-responsiveness evidence for downstream calibration lanes. That
extension is still report-only and must not be described as live tuning or
worker mutation.

The SWARM-CTRL-IX calibration track also adds a standalone reviewed golden
surface:

- Script: `scripts/swarm_high_core_slo_scenario_matrix.sh`
- Matrix schema: `franken-engine.swarm-high-core-scenario-matrix.v1`
- Report schema: `franken-engine.swarm-high-core-scenario-matrix-report.v1`
- Static contract: `docs/swarm_high_core_scenario_matrix_contract_v1.json`

That matrix replays deterministic high-core calibration scenarios through the
telemetry snapshot normalizer and freezes scrubbed representative outputs as
reviewed goldens. It is not another dashboard producer and must not be
described as live scheduler tuning, live worker execution, or automatic worker
mutation.

The same SWARM-CTRL-IX chain also adds a standalone advisory threshold receipt:

- Script: `scripts/swarm_slo_calibrator.sh`
- Receipt schema: `franken-engine.swarm-slo-threshold-receipt.v1`
- Static contract: `docs/swarm_slo_threshold_receipt_contract_v1.json`

That calibrator composes the reviewed scenario matrix, one normalized telemetry
snapshot, the archive pressure scoreboard, and the warm-target ROI advisory into
deterministic threshold families. It is advisory-only and must not be
described as live scheduler tuning, worker mutation, or automatic
resource-governor reconfiguration.

The telemetry snapshot also feeds a standalone predictive capacity forecaster:

- Script: `scripts/swarm_capacity_forecaster.sh`
- Forecast schema: `franken-engine.swarm-capacity-forecast.v1`
- Static contract: `docs/swarm_capacity_forecaster_contract_v1.json`

That forecaster publishes deterministic confidence-banded risk categories for
compile pressure, disk and memory pressure, `rch` degradation, target-dir heat,
proof availability, and coordination pressure. The operator status report
integrates that forecast as advisory snapshot evidence only. It must not be
described as live admission control or automatic worker mutation.

The forecast can then feed a standalone admission budget planner:

- Script: `scripts/swarm_admission_budget_planner.sh`
- Plan schema: `franken-engine.swarm-admission-budget-plan.v1`
- Static contract: `docs/swarm_admission_budget_planner_contract_v1.json`

That planner publishes deterministic per-priority and per-agent dry-run
admission budgets. The operator status report integrates it as advisory snapshot
evidence only. It must not be described as live worker allocation, queue
mutation, or automatic bead claiming.

The same reviewed SWARM-CTRL-IX chain now also publishes a standalone operator
SLO tuning handoff:

- Script: `scripts/swarm_operator_slo_tuning_advisory.sh`
- Advisory schema: `franken-engine.swarm-operator-slo-tuning-advisory.v1`
- Static contract: `docs/swarm_operator_slo_tuning_advisory_contract_v1.json`

That advisory composes the reviewed threshold receipt, capacity forecast, chaos
conformance report, admission budget plan, lease exchange / salvage simulation,
and warm-target ROI advisory into bounded operator recommendations. It is a
future dashboard handoff only. It is not another predictive dashboard
producer, it does not ship a local TUI renderer, and any future rich renderer
must still live in `/dp/frankentui`.

The same operator report now integrates two more advisory-only child producers:

- Script: `scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh`
- Simulation schema: `franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1`
- Static contract: `docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json`

- Script: `scripts/swarm_warm_target_prefetch_roi_advisory.sh`
- Advisory schema: `franken-engine.swarm-warm-target-prefetch-roi-advisory.v1`
- Static contract: `docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json`

Those sections remain report-only. They must not be described as automatic
ownership transfer, cancellation, target warming, or archive mutation.

The same operator report now also integrates a starvation-rescue handoff:

- Script: `scripts/swarm_starvation_rescue_planner.sh`
- Plan schema: `franken-engine.swarm-starvation-rescue-plan.v1`
- Static contract: `docs/swarm_starvation_rescue_planner_contract_v1.json`

- Script: `scripts/swarm_starvation_rescue_conformance_gate.sh`
- Report schema: `franken-engine.swarm-starvation-rescue-conformance-report.v1`
- Static contract: `docs/swarm_starvation_rescue_conformance_gate_contract_v1.json`

That handoff carries ordered rescue recommendations, escalation bands, and
unresolved-risk rows into the existing `scripts/swarm_operator_status_report.sh`
producer. It is advisory-only. It must not be described as live bead reopen
automation, automatic ownership transfer, or a second predictive dashboard
producer.

The SWARM-CTRL-VIII no-mock composition surface is also proof-only:

- Script: `scripts/e2e/swarm_predictive_admission_no_mock_drill.sh`
- Truth gate: `scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh`

That composed drill reuses `scripts/e2e/swarm_admission_drill.sh`,
`scripts/e2e/swarm_predictive_orchestration_e2e.sh`, and
`scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh` directly. It is
not another dashboard producer and must not be described as live worker, lease,
queue, or archive mutation.

## Dashboard Sections

The `predictive_dashboard` object contains bounded sections for renderer
consumption:

| Section | Source snapshot | Purpose |
| --- | --- | --- |
| `predictive_cost` | `swarm-validation-plan.v1` commands and proof-cost budgets | Show high-cost or unknown-cost validation before an agent starts a run. |
| `collision_risk` | `swarm-validation-collision-receipt.v1` or equivalent validation-plan fields | Show reservation, dirty-file, and in-progress bead overlap risk. |
| `proof_freshness` | `proof-freshness-decay-report.v1` | Show whether prior proof evidence can be reused for the current source state. |
| `rch_incidents` | `rch-incident-packet.v1` | Show remote execution failure kind, retry safety, and next action. |
| `resource_leases` | `swarm-resource-lease-plan.v1` | Show resource-admission decision, lease severity, worker assignment, and remediation commands. |
| `proof_cache` | `proof-reuse-cache-plan.v1` | Show cache-hit, partial-refresh, refresh-required, and fail-closed proof reuse decisions. |
| `qos_batches` | `build-storm-batch-plan.v1` | Show admitted and deferred validation work, fairness reason, retry delay, and bounded command rows. |
| `stale_lock_recommendations` | `stale-lock-recommendations.v1` | Show safe-to-reopen and contact-first bead recommendations with operator command strings. |
| `telemetry_quality` | `swarm-capacity-forecast.v1` | Show telemetry completeness, confidence band, missing inputs, and whether the forecast can be trusted as advisory evidence. |
| `slo_calibration` | `swarm-slo-threshold-receipt.v1` | Show reviewed high-core threshold bands, confidence class, and whether current evidence is accepted, downgraded, or rejected. |
| `capacity_forecast` | `swarm-capacity-forecast.v1` | Show bounded forecast state, blocked and degraded categories, and per-category recommended operator actions. |
| `admission_budgets` | `swarm-admission-budget-plan.v1` | Show budget profile, admitted vs deferred work, protected-request counts, and bounded per-request recommendations. |
| `slo_tuning_advisory` | `swarm-operator-slo-tuning-advisory.v1` (handoff only) | Carry reviewed evidence quality, claim support, and bounded admit/narrow/defer/prewarm/archive/salvage/coordination recommendations for a future renderer. |
| `lease_exchange_salvage` | `swarm-lease-exchange-cancellation-salvage-simulation.v1` | Show whether lease exchange, salvage promotion, or manual review is appropriate before reassigning work. |
| `prefetch_roi` | `swarm-warm-target-prefetch-roi-advisory.v1` | Show whether warm-target or archive prefetch has enough bounded ROI to recommend, plus target-dir and proof-cache posture. |
| `starvation_rescue` | `swarm-starvation-rescue-plan.v1` plus `swarm-starvation-rescue-conformance-report.v1` | Show ordered rescue actions, escalation band, and unresolved rescue risks without creating a second dashboard producer. |
| `staged_contamination` | `staged-ownership-report.v1` | Show staged ownership guard pass/degraded/fail-closed decision and offending paths. |

Each section must remain JSON-first so `/dp/frankentui` can render it without
adding a parallel TUI framework inside `franken_engine`.
Every integrated section must also preserve a deterministic source artifact path
so the dashboard JSON and markdown report can be traced back to their child
producer outputs.

If any SWARM-CTRL-III admission artifact is absent, the producer still emits
the corresponding section with `artifact_status: "missing"` and adds a
degraded component. That makes missing control-plane evidence visible to
operators instead of silently publishing an incomplete dashboard feed.

## Fixture Cases

The smoke test publishes deterministic goldens for:

- `healthy`
- `degraded`
- `stale_proof`
- `high_cost`
- `collision_risk`
- `overloaded`
- `forecast_low_confidence`

These fixtures are the handoff payloads for a later `/dp/frankentui` renderer.
They are not evidence that an interactive renderer exists in this repository.
The smoke harness also freezes the markdown operator report so summary bullets
and source-artifact references stay stable.

The standalone high-core scenario matrix publishes a separate reviewed golden
set for:

- `healthy_64plus_admission`
- `disk_pressure_memory_headroom`
- `degraded_worker_pool_local_fallback`
- `manual_confirmation_lock_pressure`
- `proof_cache_hit`
- `proof_cache_stale_miss`
- `chaos_recovery_saturated_queue`

Those are calibration fixtures and downstream SWARM-CTRL-IX handoff payloads.
They are not evidence that the current predictive dashboard producer already
renders or consumes the matrix directly.

The standalone SWARM-CTRL-IX threshold receipt is also a downstream handoff
payload. It is not evidence that the current predictive dashboard producer
already renders or consumes the calibrator directly.

The standalone operator SLO tuning advisory is another downstream handoff
payload. It is not evidence that the current predictive dashboard producer
already renders or consumes the advisory directly.

The starvation rescue planner and conformance gate are different: the current
predictive dashboard producer does integrate their handoff directly, but only
as advisory snapshot evidence. That does not make the dashboard a live reopen
controller or an automatic ownership-transfer surface.

## Truth Constraints

- `dashboard_contract.renderer.provider` must be `/dp/frankentui`.
- `dashboard_contract.renderer.shipped_in_franken_engine` must be `false`.
- `dashboard_contract.renderer.local_renderer` must be `false`.
- The docs must name `scripts/swarm_operator_status_report.sh` as the only
  predictive dashboard producer in `franken_engine`.
- The docs must describe the high-core scenario matrix as a reviewed fixture
  and golden surface only, not as a live tuning or worker-mutation control
  plane.
- The docs must describe the SWARM-CTRL-IX threshold receipt as advisory-only
  threshold evidence, not as live scheduler tuning or automatic
  resource-governor mutation.
- The docs must describe the operator SLO tuning advisory as a future handoff
  only, not as a second predictive dashboard producer or a shipped local TUI.
- The docs must describe the starvation rescue handoff as integrated advisory
  snapshot evidence, not as live bead reopen automation, automatic ownership
  transfer, or a second predictive dashboard producer.
- The docs must name the integrated advisory child producers and their contract
  JSON files.
- The docs must not describe the composed SWARM-CTRL-VIII no-mock drill as a
  second predictive dashboard producer.
- The docs must not describe any integrated section as a live control plane,
  automatic ownership transfer, or automatic target warming surface.
- Documentation must not describe an interactive dashboard as available from
  `franken_engine` until a frankentui-backed implementation exists.

## Validation

Run the smoke test after changing the producer, fixtures, or this contract:

```bash
bash -n scripts/swarm_operator_status_report.sh
bash -n scripts/e2e/swarm_operator_status_report_smoke.sh
./scripts/e2e/swarm_operator_status_report_smoke.sh check
./scripts/e2e/swarm_operator_status_report_smoke.sh selftest
jq empty docs/swarm_predictive_dashboard_contract_v1.json
```

When changing the capacity forecaster extension, also run:

```bash
bash -n scripts/swarm_capacity_forecaster.sh
bash -n scripts/e2e/swarm_capacity_forecaster_smoke.sh
./scripts/e2e/swarm_capacity_forecaster_smoke.sh check
./scripts/e2e/swarm_capacity_forecaster_smoke.sh selftest
jq empty docs/swarm_capacity_forecaster_contract_v1.json
```

When changing the admission budget planner extension, also run:

```bash
bash -n scripts/swarm_admission_budget_planner.sh
bash -n scripts/e2e/swarm_admission_budget_planner_smoke.sh
./scripts/e2e/swarm_admission_budget_planner_smoke.sh check
./scripts/e2e/swarm_admission_budget_planner_smoke.sh selftest
jq empty docs/swarm_admission_budget_planner_contract_v1.json
```

When changing the lease-exchange or prefetch-advisory integration, also run:

```bash
bash -n scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh
bash -n scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh
./scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh check
./scripts/e2e/swarm_lease_exchange_cancellation_salvage_simulator_smoke.sh selftest
jq empty docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json
bash -n scripts/swarm_warm_target_prefetch_roi_advisory.sh
bash -n scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh
./scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh check
./scripts/e2e/swarm_warm_target_prefetch_roi_advisory_smoke.sh selftest
jq empty docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json
```

When changing the SWARM-CTRL-VIII composed predictive-admission proof surface,
also run:

```bash
bash -n scripts/e2e/swarm_predictive_admission_no_mock_drill.sh
bash -n scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh check
./scripts/e2e/swarm_predictive_admission_no_mock_drill.sh selftest
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh check
./scripts/e2e/swarm_ctrl_viii_runbook_truth_gate.sh selftest
```

When changing the SWARM-CTRL-IX high-core scenario matrix, also run:

```bash
bash -n scripts/swarm_high_core_slo_scenario_matrix.sh
bash -n scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh
./scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh check
./scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh selftest
jq empty docs/swarm_high_core_scenario_matrix_contract_v1.json
```

When changing the SWARM-CTRL-IX threshold calibrator, also run:

```bash
bash -n scripts/swarm_slo_calibrator.sh
bash -n scripts/e2e/swarm_slo_calibrator_smoke.sh
./scripts/e2e/swarm_slo_calibrator_smoke.sh check
./scripts/e2e/swarm_slo_calibrator_smoke.sh selftest
jq empty docs/swarm_slo_threshold_receipt_contract_v1.json
```

When changing the SWARM-CTRL-IX operator SLO tuning advisory, also run:

```bash
bash -n scripts/swarm_operator_slo_tuning_advisory.sh
bash -n scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh
./scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh check
./scripts/e2e/swarm_operator_slo_tuning_advisory_smoke.sh selftest
jq empty docs/swarm_operator_slo_tuning_advisory_contract_v1.json
```
