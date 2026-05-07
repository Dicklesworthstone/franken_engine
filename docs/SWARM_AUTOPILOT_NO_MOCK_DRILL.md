# SWARM AUTOPILOT No-Mock Drill

`bd-khg2d`

This drill composes the shipped SWARM AUTOPILOT control-plane surfaces into one
deterministic lifecycle proof.

The current lifecycle boundary covers the shipped evidence warehouse,
brownout forecaster, operator intent policy, resource lease allocator,
recommendation bundle, dashboard projection, and hindsight chaos replay index.

## Truth

- The drill supports live, fixture, and replay modes.
- Live mode runs the real SWARM-OPS capture and autopilot evidence warehouse path against the local repository state.
- Fixture mode composes the shipped producers against preserved upstream inputs and preserves raw and normalized stage inputs for every stage.
- Replay mode verifies a pinned bundle or the latest complete bundle without re-running live capture.
- The drill does not run Cargo or RCH work directly.
- Stale SWARM-OPS sync, stale RCH progress, local fallback contamination, contradictory queue or locality evidence, and bare Cargo contamination fail closed.

## Required outputs

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `evidence_warehouse.json`
- `forecast.json`
- `policy.json`
- `lease_receipts.json`
- `recommendations.json`
- `dashboard_projection.json`
- `chaos_scenarios.json`
- `chaos_replay_index.json`
- `truth_gate_report.json`

## Coverage

- `healthy_autopilot`
- `forecast_brownout`
- `policy_conflict`
- `stale_rch_progress_not_upgraded`
- `local_fallback_contamination`
- `replay_verification`
