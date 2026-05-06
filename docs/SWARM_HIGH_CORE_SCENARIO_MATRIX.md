# SWARM High-Core Scenario Matrix

`scripts/swarm_high_core_slo_scenario_matrix.sh` composes
`scripts/swarm_telemetry_snapshot_normalizer.sh` over a deterministic
high-core scenario matrix and emits scrubbed representative outputs for golden
comparison.

This surface exists to freeze SWARM-CTRL-IX calibration inputs before the
threshold calibrator and chaos conformance gate consume them. It is fixture-fed
only. It must not be described as live benchmark execution, live scheduler
tuning, or automatic worker mutation.

## Inputs

- Fixture matrix JSON: `scripts/testdata/swarm_high_core_slo/scenario_matrix.json`
- Static contract: `docs/swarm_high_core_scenario_matrix_contract_v1.json`
- Upstream high-core input normalizer: `scripts/swarm_telemetry_snapshot_normalizer.sh`

Each matrix case carries explicit fixture payloads for:

- ready and in-progress bead snapshots
- validation-plan and resource-governor decisions
- reservation and stale-lock snapshots
- proof-freshness evidence
- stress, tail-latency, chaos, and swarm-responsiveness high-core evidence
- expected capacity decision, SLO decision, exit code, and traceability labels

## Required Scenario Classes

- `healthy_64plus_admission`
- `disk_pressure_memory_headroom`
- `degraded_worker_pool_local_fallback`
- `manual_confirmation_lock_pressure`
- `proof_cache_hit`
- `proof_cache_stale_miss`
- `chaos_recovery_saturated_queue`

These are the minimum reviewed calibration surfaces. If the matrix grows, new
cases must stay deterministic and must extend the checked-in golden only after
review.

## Artifacts

The generator emits:

- `swarm_high_core_scenario_matrix_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each case also keeps the raw per-scenario normalizer outputs under `cases/`,
but the reviewed golden freezes the scrubbed aggregate report rather than the
raw temp-root-specific artifact paths.

## Golden Workflow

The smoke harness compares the generated report against the checked-in scrubbed
golden:

- Smoke harness: `scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh`
- Checked-in golden: `scripts/testdata/goldens/swarm_high_core_scenario_matrix.golden`

Update command:

```bash
UPDATE_GOLDENS=1 bash scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh selftest
```

Diff checklist before accepting an update:

1. Review the diff for `scripts/testdata/goldens/swarm_high_core_scenario_matrix.golden`.
2. Reject any unexpected decision or traceability drift unless the SWARM-CTRL-IX contract intentionally changed.
3. Confirm `source_revision`, `snapshot_id`, `parent_snapshot_id`, and `artifact_paths` remain scrubbed placeholders.
4. Reject any new bare cargo or local-fallback command unless the scenario intentionally models fail-closed degraded-worker behavior.

## Truth Constraints

- The matrix must remain fixture-fed. No live stress, live tail-latency, or
  live chaos execution belongs here.
- The degraded-worker case must remain fail-closed when high-core evidence is
  only local or otherwise non-`rch`-traceable.
- The report must stay platform-independent. Do not freeze temp roots, host
  worker aliases, or live output directories into the checked-in golden.

## Validation

```bash
bash -n scripts/swarm_high_core_slo_scenario_matrix.sh
bash -n scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh
./scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh check
./scripts/e2e/swarm_high_core_scenario_matrix_smoke.sh selftest
jq empty docs/swarm_high_core_scenario_matrix_contract_v1.json
```
