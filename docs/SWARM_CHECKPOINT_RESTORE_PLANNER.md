# SWARM_CHECKPOINT_RESTORE_PLANNER

`scripts/swarm_checkpoint_restore_planner.sh` turns a checkpoint bundle plus
optional current-state comparison fixtures into a bounded restore decision.

It is fixture-fed only. The planner does not query live `br`, Agent Mail,
`rch`, or Cargo, and it does not reopen beads, transfer ownership, or release
reservations.

## Required Input

- `--checkpoint-bundle-json`

## Optional Current-State Comparison Inputs

- `--current-swarm-capacity-snapshot-json`
- `--current-swarm-capacity-forecast-json`
- `--current-remote-proof-archive-pressure-scoreboard-json`
- `--current-stale-lock-recommendations-json`
- `--current-swarm-lease-exchange-cancellation-salvage-simulation-json`
- `--current-swarm-operator-status-report-json`
- `--now-epoch-seconds`
- `--max-restore-age-seconds`
- `--source-revision`
- `--output-dir`

## Artifacts

- `swarm_checkpoint_restore_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Decision Rules

The planner emits one of three restore states:

- `resume`: the checkpoint is still fresh, it was captured as `captured` with
  `restore_readiness_hint=candidate`, and every current comparison input stays
  within the explicit safe bounds
- `advisory_manual_review`: the checkpoint is still replayable, but current
  drift, missing current comparisons, or checkpoint/manual-review pressure still
  requires operator review before any reopen or rebalance
- `fail_closed`: the checkpoint is stale, contradictory, blocked, or disproved
  by current ownership/archive/salvage truth

Missing current comparisons must keep restore advisory-only. Ownership drift,
contradictory ownership, archive fail-closed evidence, salvage fail-closed
evidence, and local-fallback checkpoint truth must fail closed.

## Example

```bash
./scripts/swarm_checkpoint_restore_planner.sh \
  --checkpoint-bundle-json /tmp/checkpoint_bundle.json \
  --current-swarm-capacity-snapshot-json /tmp/current_swarm_capacity_snapshot.json \
  --current-swarm-capacity-forecast-json /tmp/current_swarm_capacity_forecast.json \
  --current-remote-proof-archive-pressure-scoreboard-json /tmp/current_remote_proof_archive_pressure_scoreboard.json \
  --current-stale-lock-recommendations-json /tmp/current_stale_lock_recommendations.json \
  --current-swarm-lease-exchange-cancellation-salvage-simulation-json /tmp/current_swarm_lease_exchange_cancellation_salvage_simulation.json \
  --current-swarm-operator-status-report-json /tmp/current_swarm_operator_status_report.json \
  --now-epoch-seconds 2000
```

## Validation

```bash
bash -n scripts/swarm_checkpoint_restore_planner.sh
bash -n scripts/e2e/swarm_checkpoint_restore_planner_smoke.sh
shellcheck -x scripts/swarm_checkpoint_restore_planner.sh scripts/e2e/swarm_checkpoint_restore_planner_smoke.sh
jq empty docs/swarm_checkpoint_restore_planner_contract_v1.json
bash scripts/e2e/swarm_checkpoint_restore_planner_smoke.sh check
bash scripts/e2e/swarm_checkpoint_restore_planner_smoke.sh selftest
git diff --check -- docs/SWARM_CHECKPOINT_RESTORE_PLANNER.md docs/swarm_checkpoint_restore_planner_contract_v1.json scripts/swarm_checkpoint_restore_planner.sh scripts/e2e/swarm_checkpoint_restore_planner_smoke.sh
```
