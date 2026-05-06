# Swarm Capacity Forecaster

`scripts/swarm_capacity_forecaster.sh` is the SWARM-CTRL-VIII predictive
capacity forecaster. It consumes a normalized
`franken-engine.swarm-capacity-snapshot.v1` snapshot plus the snapshot's
normalized child artifacts and publishes deterministic forecast categories with
confidence bands.

The forecaster is fixture-fed only. It does not claim beads, query Agent Mail,
contact `rch`, execute Cargo, or mutate tracker state.

## Producer

- Script: `scripts/swarm_capacity_forecaster.sh`
- Forecast schema: `franken-engine.swarm-capacity-forecast.v1`
- Static contract: `docs/swarm_capacity_forecaster_contract_v1.json`
- Upstream snapshot: `scripts/swarm_telemetry_snapshot_normalizer.sh`

## Inputs

Required:

- `--telemetry-snapshot-json`

Optional:

- `--source-revision`
- `--now-epoch-seconds`
- `--stale-after-seconds`
- `--output-dir`

The forecaster resolves required child telemetry from the snapshot itself. A
truthful pass requires the snapshot to point at replayable normalized inputs
for:

- validation plan
- resource decision
- stale-lock recommendations
- proof freshness
- admission drill report
- predictive wrapper report
- archive lifecycle drill report
- proof-economy scheduler replay drill report

The forecaster also requires the predictive wrapper and admission drill reports
to resolve their child artifacts for:

- operator status report
- `rch` incident packet
- resource lease plan
- proof cache plan
- build-storm QoS batch plan

## Forecast Categories

The `forecasts` object contains six deterministic categories:

| Category | Purpose |
| --- | --- |
| `compile_pressure` | Heavy-validation contention, high-cost command load, and brownout state. |
| `disk_memory_pressure` | Disk, memory, and worker-capacity pressure from the resource governor and lease planner. |
| `rch_degradation` | Remote execution risk, including timeout and local-fallback fail-closed states. |
| `target_dir_heat` | Warm-target churn, cache refresh pressure, and target-dir contention. |
| `proof_availability` | Proof freshness, proof-cache reuse, and archive-lifecycle availability. |
| `coordination_pressure` | Active-owner, contradiction, stale-lock, and manual-confirmation pressure. |

Each category publishes:

- `state`
- `risk_level`
- `confidence_band`
- `confidence_score_millionths`
- `assumptions`
- `evidence`
- `recommended_action`

The coordination category also publishes:

- `auto_reopen_allowed`
- `lease_exchange_allowed`

## Fail-Closed Rules

The producer returns exit `42` and marks the forecast `decision: "fail_closed"`
when any of the following hold:

- the telemetry snapshot is already fail-closed
- required telemetry is missing, malformed, or stale
- forecast confidence for any required category collapses to `low`
- contradictory active-owner telemetry remains unresolved

This is intentional. The forecaster is not allowed to interpolate missing
control-plane evidence with speculative heuristics.

## Fixture Cases

The smoke harness proves:

- `normal`
- `degraded`
- `brownout`
- `contradictory_telemetry`
- `active_owner_manual_confirmation`
- `stale_required_telemetry`

## Validation

```bash
bash -n scripts/swarm_capacity_forecaster.sh
bash -n scripts/e2e/swarm_capacity_forecaster_smoke.sh
shellcheck -x scripts/swarm_capacity_forecaster.sh scripts/e2e/swarm_capacity_forecaster_smoke.sh
jq empty docs/swarm_capacity_forecaster_contract_v1.json
./scripts/e2e/swarm_capacity_forecaster_smoke.sh check
./scripts/e2e/swarm_capacity_forecaster_smoke.sh selftest
```
