# Swarm Autopilot Brownout Forecaster

`scripts/swarm_autopilot_brownout_forecaster.sh` builds a deterministic,
fixture-fed brownout and saturation forecast for the swarm autopilot.

It consumes the autopilot evidence warehouse plus SWARM-SCALE queue/locality
signals, locality fidelity outcomes, and a checked-in hindsight bundle. The
forecaster emits bounded near-term brownout advice before admission pressure is
obvious to operators.

Machine-readable contract:
`docs/swarm_autopilot_brownout_forecaster_contract_v1.json`

Smoke gate:
`scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh`

Fixture cases:
`scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json`

## Inputs

Required inputs:

- `evidence_warehouse_json`
- `queue_signal_input_json`
- `queue_fidelity_receipt_json`
- `hindsight_bundle_json`

Optional supporting inputs:

- `operator_intent_policy_json`

## Artifacts

Every run emits:

- `swarm_autopilot_brownout_forecast.json`
- `swarm_autopilot_brownout_hindsight_comparison.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The forecast preserves:

- `forecast_id`
- `decision`
- `truth_state`
- `summary.overall_state`
- `summary.brownout_state`
- `summary.deterministic_replay_hash_basis`
- `validated_horizon_seconds`
- `resolved_inputs`
- `fail_closed_reasons`
- six category forecasts with bounded uncertainty and source evidence
- `artifact_paths`
- `mutation_policy`

The hindsight comparison preserves predicted versus actual states for:

- `admitted_heavy_lane_pressure`
- `rch_slot_exhaustion`
- `target_dir_pressure`
- `stale_progress_risk`
- `proof_cache_pressure`
- `fairness_starvation_window`

## Truth Rules

- The forecaster is advisory only and proof only.
- Local fallback contamination fails closed.
- Incomplete or contradictory evidence fails closed.
- Forecasts stay bounded by the validated horizon.
- The forecaster compares predicted states against actual hindsight bundle outcomes.
- Stale warehouse, queue-signal, fidelity, or hindsight evidence fails closed.
- The producer must not claim it changed live queue policy, worker state, bead
  ownership, reservations, Agent Mail, Cargo, or RCH.

## Proof Cases

The checked-in fixtures cover:

- `green_low_pressure`
- `imminent_rch_slot_brownout`
- `proof_cache_pressure_escalation`
- `stale_progress_risk`
- `contradictory_evidence_fail_closed`

## Validation

```bash
bash -n scripts/swarm_autopilot_brownout_forecaster.sh
bash -n scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh
shellcheck -x scripts/swarm_autopilot_brownout_forecaster.sh scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh
jq empty docs/swarm_autopilot_brownout_forecaster_contract_v1.json scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json
bash scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh check
bash scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_BROWNOUT_FORECASTER.md docs/swarm_autopilot_brownout_forecaster_contract_v1.json scripts/swarm_autopilot_brownout_forecaster.sh scripts/e2e/swarm_autopilot_brownout_forecaster_smoke.sh scripts/testdata/swarm_autopilot_brownout_forecaster/cases.json
```
