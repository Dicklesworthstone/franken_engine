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

## Dashboard Sections

The `predictive_dashboard` object contains four bounded sections for renderer
consumption:

| Section | Source snapshot | Purpose |
| --- | --- | --- |
| `predictive_cost` | `swarm-validation-plan.v1` commands and proof-cost budgets | Show high-cost or unknown-cost validation before an agent starts a run. |
| `collision_risk` | `swarm-validation-collision-receipt.v1` or equivalent validation-plan fields | Show reservation, dirty-file, and in-progress bead overlap risk. |
| `proof_freshness` | `proof-freshness-decay-report.v1` | Show whether prior proof evidence can be reused for the current source state. |
| `rch_incidents` | `rch-incident-packet.v1` | Show remote execution failure kind, retry safety, and next action. |

Each section must remain JSON-first so `/dp/frankentui` can render it without
adding a parallel TUI framework inside `franken_engine`.

## Fixture Cases

The smoke test publishes deterministic goldens for:

- `healthy`
- `degraded`
- `stale_proof`
- `high_cost`
- `collision_risk`

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
