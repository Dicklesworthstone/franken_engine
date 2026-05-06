# Swarm SLO Calibrator

`scripts/swarm_slo_calibrator.sh` composes the standalone telemetry snapshot,
the reviewed high-core scenario matrix, and advisory archive / warm-target
surfaces into one deterministic threshold receipt for SWARM-CTRL-IX.

The calibrator is fixture-fed and report-only. It does not run benchmarks, tune
workers, mutate resource-governor defaults, or execute Cargo.

## Inputs

Required:

- `--telemetry-snapshot-json`
- `--scenario-matrix-report-json`
- `--archive-pressure-scoreboard-json`
- `--warm-target-prefetch-roi-advisory-json`

Compatibility surfaces:

- `franken-engine.swarm-capacity-snapshot.v1`
- `franken-engine.swarm-high-core-scenario-matrix-report.v1`
- `franken-engine.remote-proof-archive-pressure-scoreboard.v1`
- `franken-engine.swarm-warm-target-prefetch-roi-advisory.v1`

The calibrator exists to bind those already-shipped artifacts into advisory
threshold families instead of inventing another live control loop.

## Output

- `swarm_slo_threshold_receipt.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable receipt schema is
`franken-engine.swarm-slo-threshold-receipt.v1`.

## Threshold Families

The receipt publishes one threshold family for each required SWARM-CTRL-IX
advisory domain:

- `queue_wait_budget_band`
- `validation_latency_band`
- `rch_fallback_rate_tolerance`
- `starvation_brownout_guardrails`
- `proof_cache_freshness_and_warm_target_roi`
- `archive_salvage_pressure_thresholds`

Each family carries:

- `status`: `accepted`, `downgraded`, or `rejected`
- `reason`
- `confidence_class`
- threshold-specific bounds or current-band details

The global receipt also records:

- `decision`
- `confidence_class`
- `assumptions`
- `evidence_hashes`

## Fail-Closed Rules

The calibrator exits `42` and emits `decision: "fail_closed"` when:

- the telemetry snapshot is already fail-closed
- the scenario matrix has mismatches or is missing required scenario classes
- any current high-core surface is not `rch`-traceable
- the archive pressure scoreboard is fail-closed
- the warm-target ROI advisory is fail-closed

This is intentional. The calibrator may downgrade thresholds under reviewed
pressure, but it must reject them when evidence is insufficient or
contradictory.

## Truth Constraints

- The receipt is advisory only. It must not mutate scheduler or worker state.
- The scenario matrix remains the reviewed source of truth for healthy,
  degraded-worker, manual-confirmation, proof-cache, and chaos high-core cases.
- Warm-target ROI thresholds must stay bounded by the standalone ROI advisory;
  the calibrator must not claim that prefetch already happened.
- Archive or salvage pressure that is already fail-closed must stay rejected in
  the threshold receipt rather than being softened into a synthetic pass.

## Validation

```bash
bash -n scripts/swarm_slo_calibrator.sh
bash -n scripts/e2e/swarm_slo_calibrator_smoke.sh
shellcheck -x scripts/swarm_slo_calibrator.sh scripts/e2e/swarm_slo_calibrator_smoke.sh
./scripts/e2e/swarm_slo_calibrator_smoke.sh check
./scripts/e2e/swarm_slo_calibrator_smoke.sh selftest
jq empty docs/swarm_slo_threshold_receipt_contract_v1.json
```
