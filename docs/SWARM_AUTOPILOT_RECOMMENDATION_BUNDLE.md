# Swarm Autopilot Recommendation Bundle

`scripts/swarm_autopilot_recommendation_bundle.sh` composes operator intent
policy, brownout forecast, resource lease allocations, scarcity receipts, and
control-plane context into deterministic operator-facing autopilot
recommendations.

Machine-readable contract:
`docs/swarm_autopilot_recommendation_bundle_contract_v1.json`

Smoke gate:
`scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh`

Fixture cases:
`scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json`

## Inputs

Required inputs:

- `operator_intent_policy_json`
- `brownout_forecaster_json`
- `resource_lease_plan_json`
- `resource_scarcity_receipts_json`
- `control_plane_context_json`

## Artifacts

Every run emits:

- `swarm_autopilot_recommendation_bundle.json`
- `swarm_autopilot_dashboard_projection.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The recommendation bundle preserves:

- `recommendation_bundle_id`
- `decision`
- `truth_state`
- `summary.overall_state`
- `summary.top_action`
- `summary.recommendation_count`
- `summary.safe_mode_active`
- `summary.human_review_required`
- `recommendations`
- `resolved_inputs`
- `fail_closed_reasons`
- `artifact_paths`
- `mutation_policy`

Every recommendation preserves:

- `recommendation_id`
- `priority`
- `action`
- `lane_id`
- `summary`
- `deterministic_decision_id`
- `reason_codes`
- `evidence_paths`
- `rollback_command`
- `remediation_command`

The dashboard projection preserves:

- `dashboard_projection_id`
- `decision`
- `overall_state`
- `top_action`
- `summary_cards`
- `top_recommendations`

## Truth Rules

- The bundle is advisory only and proof only.
- Safe mode defers nonurgent admissions until telemetry and coordination evidence recover.
- Local fallback contamination fails closed.
- Human-review conflicts stay advisory and never auto-mutate beads, workers, or reservations.
- The dashboard projection preserves decision, overall state, top action, and evidence freshness.
- Stale policy, forecast, lease, receipts, or control-plane evidence fails closed.
- Fail-closed upstream policy, forecast, or lease inputs must not be promoted into recommendations.
- The producer must not claim it changed live queue policy, worker state, bead ownership, reservations, Agent Mail, Cargo, or RCH.

## Proof Cases

The checked-in fixtures cover:

- `normal_admit_defer_mix`
- `degraded_safe_mode`
- `fail_closed_contaminated_evidence`
- `human_review_conflict`
- `operator_dashboard_projection`

## Validation

```bash
bash -n scripts/swarm_autopilot_recommendation_bundle.sh
bash -n scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh
shellcheck -x scripts/swarm_autopilot_recommendation_bundle.sh scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh
jq empty docs/swarm_autopilot_recommendation_bundle_contract_v1.json scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json
bash scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh check
bash scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_RECOMMENDATION_BUNDLE.md docs/swarm_autopilot_recommendation_bundle_contract_v1.json scripts/swarm_autopilot_recommendation_bundle.sh scripts/e2e/swarm_autopilot_recommendation_bundle_smoke.sh scripts/testdata/swarm_autopilot_recommendation_bundle/cases.json
```
