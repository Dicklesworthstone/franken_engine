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

The predictive dashboard contract also has a pre-dashboard telemetry snapshot
extension:

- Script: `scripts/swarm_telemetry_snapshot_normalizer.sh`
- Snapshot schema: `franken-engine.swarm-capacity-snapshot.v1`
- Static contract: `docs/swarm_telemetry_snapshot_contract_v1.json`

That normalizer reuses admission, archive, and proof-economy artifacts directly
and stays fixture-only. It does not replace `scripts/swarm_operator_status_report.sh`
and must not be described as a live scheduling control surface.

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
| `staged_contamination` | `staged-ownership-report.v1` | Show staged ownership guard pass/degraded/fail-closed decision and offending paths. |

Each section must remain JSON-first so `/dp/frankentui` can render it without
adding a parallel TUI framework inside `franken_engine`.

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

These fixtures are the handoff payloads for a later `/dp/frankentui` renderer.
They are not evidence that an interactive renderer exists in this repository.

## Truth Constraints

- `dashboard_contract.renderer.provider` must be `/dp/frankentui`.
- `dashboard_contract.renderer.shipped_in_franken_engine` must be `false`.
- `dashboard_contract.renderer.local_renderer` must be `false`.
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
