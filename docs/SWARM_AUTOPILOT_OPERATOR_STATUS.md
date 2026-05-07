# Swarm Autopilot Operator Status

`scripts/swarm_autopilot_operator_status_bundle.sh` publishes operator-status
style autopilot state and a frankentui-compatible panel bundle from preserved
advisory artifacts only.

Machine-readable contract:
`docs/swarm_autopilot_operator_status_contract_v1.json`

Smoke gate:
`scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh`

Fixture cases:
`scripts/testdata/swarm_autopilot_operator_status/cases.json`

## Inputs

Required inputs:

- `operator_intent_policy_json`
- `brownout_forecaster_json`
- `resource_lease_plan_json`
- `resource_scarcity_receipts_json`
- `recommendation_bundle_json`
- `dashboard_projection_json`
- `hindsight_chaos_scenarios_json`
- `hindsight_chaos_replay_index_json`

## Artifacts

Every run emits:

- `swarm_autopilot_operator_status.json`
- `swarm_autopilot_frankentui_panels.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The operator-status bundle preserves:

- `operator_status_id`
- `decision`
- `truth_state`
- `summary.overall_state`
- `summary.top_action`
- `summary.safe_mode_active`
- `summary.degraded_panel_count`
- `summary.fail_closed_panel_count`
- `sections`
- `artifact_paths`
- `mutation_policy`

The frankentui panel bundle preserves:

- `panel_bundle_id`
- `decision`
- `renderer_contract.provider`
- `renderer_contract.no_local_tui_runtime`
- `status_bar.summary.panel_count`
- `panels[].panel_id`
- `panels[].display_state`
- `panels[].semantic_theme_token`
- `panels[].focus_order`
- `panels[].aria_label`
- `panels[].supports_tiny_layout`
- `panels[].visible_reasons`

## Truth Rules

- The operator-status producer is advisory only and proof only.
- The future rich renderer provider is `/dp/frankentui`; no local renderer ships in `franken_engine`.
- Hidden panel state or missing evidence links fail closed.
- Fail-closed policy conflicts stay visibly fail-closed in both operator status and panel projection.
- Safe-mode recommendations stay visible as conservative operator guidance and do not claim live mutation authority.
- Degraded forecast, policy, lease, recommendation, or chaos replay evidence must remain visibly degraded in the emitted panels.
- The producer must not claim it changed live queue policy, worker state, bead ownership, reservations, Agent Mail, Cargo, or RCH.

## Proof Cases

The checked-in fixtures cover:

- `healthy_autopilot`
- `degraded_forecast`
- `fail_closed_policy_conflict`
- `safe_mode_recommendation`
- `frankentui_panel_projection`

## Validation

```bash
bash -n scripts/swarm_autopilot_operator_status_bundle.sh
bash -n scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh
shellcheck -x scripts/swarm_autopilot_operator_status_bundle.sh scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh
jq empty docs/swarm_autopilot_operator_status_contract_v1.json scripts/testdata/swarm_autopilot_operator_status/cases.json
bash scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh check
bash scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_OPERATOR_STATUS.md docs/swarm_autopilot_operator_status_contract_v1.json scripts/swarm_autopilot_operator_status_bundle.sh scripts/e2e/swarm_autopilot_operator_status_bundle_smoke.sh scripts/testdata/swarm_autopilot_operator_status/cases.json
```
