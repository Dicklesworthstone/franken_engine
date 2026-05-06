# SWARM_EXECUTION_QUEUE_HINDSIGHT_CONTRACT

SWARM-CTRL-XIII adds a hindsight layer for the SWARM-CTRL-XII execution queue.
The lane is advisory evidence only: it compares prior queue advice with what
actually happened afterward, then emits fidelity, drift, confidence, and tuning
evidence for operators. It does not update beads, reopen work, reassign owners,
release reservations, send Agent Mail, warm targets, or mutate remote workers.

Machine-readable contract:
`docs/swarm_execution_queue_hindsight_contract_v1.json`.

## Purpose

The execution queue now emits `normalized_input.json`,
`execution_queue_artifact.json`, `risk_budget_receipt.json`,
`bottleneck_report.json`, `run_manifest.json`, and operator-status handoff
artifacts. Hindsight joins those advisory artifacts with later bead, owner,
reservation, proof, and checkpoint-restore evidence so operators can answer:

- which recommended starts actually started,
- which deferred rows were correctly deferred,
- which owner or reservation friction changed the outcome,
- which proof or restore pressure overrode the queue,
- whether queue advice was accurate, stale, too conservative, or under-evidenced,
- which counterfactual tuning candidates should be tried in replay.

## Required Inputs

Required queue inputs:

- `queue_artifact_json`
- `queue_run_manifest_json`
- `normalized_queue_input_json`
- `risk_budget_receipt_json`
- `bottleneck_report_json`

Required aftermath inputs:

- `bead_status_snapshot_json`
- `bead_timing_snapshot_json`
- `owner_contact_snapshot_json`
- `reservation_friction_snapshot_json`
- `proof_outcome_snapshot_json`
- `checkpoint_restore_state_json`

Each required input must include a schema version, capture timestamp, source
revision, artifact path, and content hash. Missing required evidence fails
closed. Optional notes may be attached as degraded evidence, but optional notes
must not replace a missing required input.

## Timestamp Policy

All timestamps use UTC epoch seconds plus optional nanoseconds:

- `queue_issued_epoch_seconds`
- `observation_epoch_seconds`
- `actual_started_epoch_seconds`
- `actual_closed_epoch_seconds`
- `owner_last_contact_epoch_seconds`

The observation timestamp must be greater than or equal to the queue-issued
timestamp. Actual start and close timestamps must not precede the queue issue
unless an explicit `preexisting_work` outcome is recorded. Ambiguous, missing,
or contradictory required timestamps fail closed instead of being guessed.

## Evidence Ledger

Every artifact consumed by hindsight must appear in an evidence ledger row:

- `artifact_id`
- `schema_version`
- `path`
- `content_hash_hex`
- `source_revision`
- `captured_epoch_seconds`
- `trust_state`
- `freshness_state`
- `required`

`trust_state` is one of `primary`, `degraded`, or `rejected`.
`freshness_state` is one of `fresh`, `stale`, or `unknown`. Required rows with
`rejected`, `stale`, or `unknown` freshness fail closed unless the contract
explicitly marks the source as optional.

## Output Rows

The hindsight report emits one row per queued task:

- `task_id`
- `recommended_rank`
- `recommended_wave`
- `recommended_first_action`
- `actual_outcome`
- `actual_start_delta_seconds`
- `actual_close_delta_seconds`
- `rank_delta`
- `defer_reason`
- `override_reason`
- `owner_friction_outcome`
- `reservation_friction_outcome`
- `proof_outcome`
- `checkpoint_restore_outcome`
- `fidelity_class`
- `drift_class`
- `confidence_band`
- `counterfactual_candidate`

`actual_outcome` is one of `started`, `closed`, `deferred`, `blocked`,
`preexisting_work`, or `not_observed`.

`fidelity_class` is one of `matched`, `delayed_match`, `justified_override`,
`stale_advice`, `unsafe_to_score`, or `insufficient_evidence`.

`drift_class` is one of `none`, `timing_drift`, `ownership_drift`,
`reservation_drift`, `proof_drift`, `restore_drift`, `ranking_drift`, or
`data_gap`.

`confidence_band` is one of `high`, `medium`, `low`, or
`insufficient_evidence`.

## Counterfactual Tuning Inputs

Hindsight may emit tuning candidates for later counterfactual replay:

- `candidate_id`
- `task_id`
- `reason`
- `proposed_weight_delta`
- `expected_fidelity_gain_millionths`
- `risk`
- `required_replay_inputs`

Candidates are advisory. They do not alter the active queue and must be replayed
through a later counterfactual runner before any policy change is trusted.

## Fail-Closed Rules

- Missing required inputs fail closed.
- Missing or contradictory required timestamps fail closed.
- Unknown task references fail closed.
- Duplicate task IDs in queue or aftermath snapshots fail closed.
- Queue rows without `first_action` fail closed.
- Inconsistent owner identity or reservation-holder evidence fails closed.
- Proof outcomes that report local-rch fallback as healthy proof completion fail closed.
- Checkpoint restore blocked or manual-review evidence must remain visible in
  every row it affects.
- Any docs, contract, or smoke output claiming live mutation or automatic queue
  actuation fails closed.

## Validation

```bash
jq empty docs/swarm_execution_queue_hindsight_contract_v1.json
bash -n scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh
bash scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh check
bash scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh selftest
git diff --check -- docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_CONTRACT.md docs/swarm_execution_queue_hindsight_contract_v1.json scripts/e2e/swarm_execution_queue_hindsight_contract_smoke.sh
```
