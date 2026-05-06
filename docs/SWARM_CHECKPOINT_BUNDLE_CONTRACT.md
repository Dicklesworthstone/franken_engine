# SWARM_CHECKPOINT_BUNDLE_CONTRACT

`docs/swarm_checkpoint_bundle_contract_v1.json` defines the contract-only
checkpoint bundle and evidence ledger for SWARM-CTRL-XI.

This bead does not ship the packer yet. Later beads must implement
`scripts/swarm_checkpoint_bundle_packer.sh` against this contract.

It is advisory evidence only. The checkpoint bundle must not be described as a
live reopen surface, ownership-transfer surface, reservation mutation surface,
or remote-worker mutation surface.

## Required Evidence Ledger Entries

- `swarm_capacity_snapshot` (`franken-engine.swarm-capacity-snapshot.v1`)
- `swarm_capacity_forecast` (`franken-engine.swarm-capacity-forecast.v1`)
- `swarm_admission_budget_plan` (`franken-engine.swarm-admission-budget-plan.v1`)
- `remote_proof_archive_pressure_scoreboard`
  (`franken-engine.remote-proof-archive-pressure-scoreboard.v1`)
- `stale_lock_recommendations`
  (`franken-engine.stale-lock-recommendations.v1`)
- `swarm_lease_exchange_cancellation_salvage_simulation`
  (`franken-engine.swarm-lease-exchange-cancellation-salvage-simulation.v1`)
- `swarm_starvation_rescue_plan`
  (`franken-engine.swarm-starvation-rescue-plan.v1`)
- `swarm_operator_status_report`
  (`franken-engine.swarm-operator-status-report.v1`)

Each required ledger entry must preserve:

- the upstream schema version
- the artifact path used during capture
- a trust state
- a freshness state
- whether the artifact was required for restore truth

## Optional Evidence Ledger Entries

- `swarm_high_core_scenario_matrix_report`
  (`franken-engine.swarm-high-core-scenario-matrix-report.v1`)
- `swarm_operator_slo_tuning_advisory`
  (`franken-engine.swarm-operator-slo-tuning-advisory.v1`)
- `proof_economy_replay_trace`
  (`franken-engine.proof-economy-replay-trace.v1`)

Optional evidence may remain `missing` or `degraded`. Missing optional evidence
must not upgrade checkpoint trust or silently turn a blocked restore into a
candidate restore.

## Expected Bundle Fields

The checkpoint bundle must preserve these top-level fields:

- `checkpoint_id`
- `capture_decision`
- `restore_readiness_hint`
- `captured_epoch_seconds`
- `stale_after_seconds`
- `upstream_evidence`
- `artifact_ledger`
- `blockers`
- `artifact_paths.checkpoint_bundle_json`
- `artifact_paths.events_jsonl`
- `artifact_paths.commands_txt`
- `artifact_paths.summary_md`

Expected enumerations:

- `capture_decision`: `captured`, `captured_degraded`, or `fail_closed`
- `restore_readiness_hint`: `candidate`, `manual_review`, or `blocked`

## Fail-Closed Restore Blockers

- Missing or invalid required evidence must fail closed.
- Required evidence older than the configured freshness window must fail closed.
- Contradictory ownership or reservation evidence must fail closed.
- local-fallback heavy-proof evidence must fail closed rather than being treated
  as replayable remote proof truth.
- Manual-review salvage pressure must keep the restore hint at
  `manual_review` or `blocked`; it must not be silently downgraded away.
- Missing artifact links for required evidence must fail closed.

## Expected Outputs

When the future packer lands, it must emit at least:

- `checkpoint_bundle.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The contract does not yet require a restore plan artifact. That arrives in the
later restore-planner bead.

## Validation

```bash
jq empty docs/swarm_checkpoint_bundle_contract_v1.json
bash -n scripts/e2e/swarm_checkpoint_bundle_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_checkpoint_bundle_contract_smoke.sh
bash scripts/e2e/swarm_checkpoint_bundle_contract_smoke.sh check
bash scripts/e2e/swarm_checkpoint_bundle_contract_smoke.sh selftest
git diff --check -- docs/SWARM_CHECKPOINT_BUNDLE_CONTRACT.md docs/swarm_checkpoint_bundle_contract_v1.json scripts/e2e/swarm_checkpoint_bundle_contract_smoke.sh
```
