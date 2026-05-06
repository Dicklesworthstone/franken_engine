# SWARM_EXECUTION_QUEUE_HINDSIGHT_NORMALIZER

`scripts/swarm_execution_queue_hindsight_normalizer.sh` is the SWARM-CTRL-XIII
fixture bridge between SWARM-CTRL-XII queue advice and later aftermath evidence.
It is advisory-only. It emits hindsight input, report, evidence ledger, and
counterfactual candidate artifacts, but it does not update beads, reassign
owners, release reservations, send Agent Mail, run Cargo, mutate workers, or
change the active queue.

Machine-readable contract:
`docs/swarm_execution_queue_hindsight_input_contract_v1.json`.

## Inputs

Required queue artifacts:

- `--queue-artifact-json FILE`
- `--queue-run-manifest-json FILE`
- `--normalized-queue-input-json FILE`
- `--risk-budget-receipt-json FILE`
- `--bottleneck-report-json FILE`

Required aftermath snapshots:

- `--bead-status-snapshot-json FILE`
- `--bead-timing-snapshot-json FILE`
- `--owner-contact-snapshot-json FILE`
- `--reservation-friction-snapshot-json FILE`
- `--proof-outcome-snapshot-json FILE`
- `--checkpoint-restore-state-json FILE`

Each input must include `schema_version`, `captured_epoch_seconds`,
`source_revision`, `artifact_path`, `content_hash_hex`, `trust_state`, and
`freshness_state`. Required evidence marked stale, rejected, or missing required
metadata fails closed.

## Artifacts

Each run emits:

- `hindsight_input.json`
- `hindsight_report.json`
- `evidence_ledger.json`
- `counterfactual_candidates.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`hindsight_report.json` has one row per queued task. Rows preserve recommended
rank, recommended wave, recommended first action, actual outcome, timing deltas,
rank delta, owner friction, reservation friction, proof outcome,
checkpoint-restore outcome, fidelity class, drift class, confidence band, and
counterfactual candidacy.

## Decisions

- `pass`: required evidence is fresh and trusted, queue rows have first actions,
  and aftermath evidence matches the original queue advice.
- `degraded`: evidence remains replayable, but owner friction, reservation
  friction, proof brownout, checkpoint-restore attention, delayed starts, or
  missing observed outcomes require operator caution.
- `fail_closed`: required evidence is malformed, stale, or rejected; required
  timestamps are missing or contradictory; queue or aftermath task IDs are
  duplicated; aftermath references unknown queued tasks; queue rows lack
  `first_action`; owner identity evidence is contradictory; reservation holder
  evidence is contradictory; or local-rch fallback fails because it was promoted
  as healthy proof completion.

## Validation

```bash
bash -n scripts/swarm_execution_queue_hindsight_normalizer.sh
bash -n scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh
shellcheck -x scripts/swarm_execution_queue_hindsight_normalizer.sh scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh
jq empty docs/swarm_execution_queue_hindsight_input_contract_v1.json scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json
bash scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_hindsight_normalizer.sh scripts/e2e/swarm_execution_queue_hindsight_normalizer_smoke.sh docs/SWARM_EXECUTION_QUEUE_HINDSIGHT_NORMALIZER.md docs/swarm_execution_queue_hindsight_input_contract_v1.json scripts/testdata/swarm_execution_queue/hindsight_normalizer_fixtures.json
```
