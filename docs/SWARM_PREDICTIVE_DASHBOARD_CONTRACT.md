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

The predictive dashboard contract also has a pre-dashboard telemetry snapshot
extension:

- Script: `scripts/swarm_telemetry_snapshot_normalizer.sh`
- Snapshot schema: `franken-engine.swarm-capacity-snapshot.v1`
- Static contract: `docs/swarm_telemetry_snapshot_contract_v1.json`

That normalizer reuses admission, archive, and proof-economy artifacts directly
and stays fixture-only. It does not replace `scripts/swarm_operator_status_report.sh`
and must not be described as a live scheduling control surface.

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

The same operator report now integrates two more advisory-only child producers:

- Script: `scripts/swarm_lease_exchange_cancellation_salvage_simulator.sh`
- Simulation schema: `franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1`
- Static contract: `docs/swarm_lease_exchange_cancellation_salvage_simulator_contract_v1.json`

- Script: `scripts/swarm_warm_target_prefetch_roi_advisory.sh`
- Advisory schema: `franken-engine.swarm-warm-target-prefetch-roi-advisory.v1`
- Static contract: `docs/swarm_warm_target_prefetch_roi_advisory_contract_v1.json`

Those sections remain report-only. They must not be described as automatic
ownership transfer, cancellation, target warming, or archive mutation.

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
| `capacity_forecast` | `swarm-capacity-forecast.v1` | Show bounded forecast state, blocked and degraded categories, and per-category recommended operator actions. |
| `admission_budgets` | `swarm-admission-budget-plan.v1` | Show budget profile, admitted vs deferred work, protected-request counts, and bounded per-request recommendations. |
| `lease_exchange_salvage` | `swarm-lease-exchange-cancellation-salvage-simulation.v1` | Show whether lease exchange, salvage promotion, or manual review is appropriate before reassigning work. |
| `prefetch_roi` | `swarm-warm-target-prefetch-roi-advisory.v1` | Show whether warm-target or archive prefetch has enough bounded ROI to recommend, plus target-dir and proof-cache posture. |
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

## Truth Constraints

- `dashboard_contract.renderer.provider` must be `/dp/frankentui`.
- `dashboard_contract.renderer.shipped_in_franken_engine` must be `false`.
- `dashboard_contract.renderer.local_renderer` must be `false`.
- The docs must name `scripts/swarm_operator_status_report.sh` as the only
  predictive dashboard producer in `franken_engine`.
- The docs must name the integrated advisory child producers and their contract
  JSON files.
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
