# SWARM_CHECKPOINT_BUNDLE_PACKER

`scripts/swarm_checkpoint_bundle_packer.sh` composes the current SWARM-CTRL
artifacts into one deterministic checkpoint bundle for later restore planning.

It is fixture-fed only. The packer does not query live `br`, Agent Mail, `rch`,
or Cargo, and it does not mutate tracker or worker state.

## Required Inputs

- `--swarm-capacity-snapshot-json`
- `--swarm-capacity-forecast-json`
- `--swarm-admission-budget-plan-json`
- `--remote-proof-archive-pressure-scoreboard-json`
- `--stale-lock-recommendations-json`
- `--swarm-lease-exchange-cancellation-salvage-simulation-json`
- `--swarm-starvation-rescue-plan-json`
- `--swarm-operator-status-report-json`

## Optional Inputs

- `--swarm-high-core-scenario-matrix-report-json`
- `--swarm-operator-slo-tuning-advisory-json`
- `--proof-economy-replay-trace-json`
- `--source-revision`
- `--now-epoch-seconds`
- `--stale-after-seconds`
- `--output-dir`

## Artifacts

- `checkpoint_bundle.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`
- normalized child artifacts under the chosen output directory

## Decision Rules

The packer emits one of three checkpoint states:

- `captured`: all required evidence is fresh and replayable, and optional
  enrichments do not introduce degraded trust
- `captured_degraded`: required evidence remains replayable, but optional
  evidence is missing or some required signals still demand manual review
- `fail_closed`: stale, contradictory, blocked, unknown, or local-fallback
  evidence prevents a trusted checkpoint

Local-fallback heavy-proof evidence must fail closed. Contradictory ownership
or reservation evidence must fail closed. Missing or stale required timestamps
must fail closed. Manual-review salvage pressure keeps the bundle advisory-only.

## Example

```bash
./scripts/swarm_checkpoint_bundle_packer.sh \
  --swarm-capacity-snapshot-json /tmp/swarm_capacity_snapshot.json \
  --swarm-capacity-forecast-json /tmp/swarm_capacity_forecast.json \
  --swarm-admission-budget-plan-json /tmp/swarm_admission_budget_plan.json \
  --remote-proof-archive-pressure-scoreboard-json /tmp/remote_proof_archive_pressure_scoreboard.json \
  --stale-lock-recommendations-json /tmp/stale_lock_recommendations.json \
  --swarm-lease-exchange-cancellation-salvage-simulation-json /tmp/swarm_lease_exchange_cancellation_salvage_simulation.json \
  --swarm-starvation-rescue-plan-json /tmp/swarm_starvation_rescue_plan.json \
  --swarm-operator-status-report-json /tmp/swarm_operator_status_report.json \
  --swarm-high-core-scenario-matrix-report-json /tmp/swarm_high_core_scenario_matrix_report.json \
  --swarm-operator-slo-tuning-advisory-json /tmp/swarm_operator_slo_tuning_advisory.json \
  --proof-economy-replay-trace-json /tmp/proof_economy_replay_trace.json \
  --now-epoch-seconds 2000 \
  --stale-after-seconds 1800
```

## Validation

```bash
bash -n scripts/swarm_checkpoint_bundle_packer.sh
bash -n scripts/e2e/swarm_checkpoint_bundle_packer_smoke.sh
shellcheck -x scripts/swarm_checkpoint_bundle_packer.sh scripts/e2e/swarm_checkpoint_bundle_packer_smoke.sh
bash scripts/e2e/swarm_checkpoint_bundle_packer_smoke.sh check
bash scripts/e2e/swarm_checkpoint_bundle_packer_smoke.sh selftest
git diff --check -- scripts/swarm_checkpoint_bundle_packer.sh scripts/e2e/swarm_checkpoint_bundle_packer_smoke.sh docs/SWARM_CHECKPOINT_BUNDLE_PACKER.md
```
