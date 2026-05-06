# SWARM_EXECUTION_QUEUE_INPUT_NORMALIZER

`scripts/swarm_execution_queue_input_normalizer.sh` is the SWARM-CTRL-XII-B
fixture bridge between captured operator snapshots and the execution queue input
contract from `docs/swarm_execution_queue_contract_v1.json`.

The normalizer is advisory-only. It ranks and annotates the work that an
operator or future queue runner should inspect next, but it does not update
beads, reassign owners, release reservations, send Agent Mail, run cargo, or
mutate remote workers.

## Inputs

Required snapshots:

- `--br-ready-json FILE`
- `--br-list-json FILE`
- `--bv-actionable-plan-json FILE`

Optional snapshots:

- `--agent-mail-activity-json FILE`
- `--file-reservations-json FILE`
- `--stale-lock-recommendations-json FILE`
- `--proof-transport-health-json FILE`

Missing optional snapshots are recorded as degraded evidence. Malformed required
`br` or `bv` shapes produce a fail-closed artifact.

## Artifacts

Each run emits:

- `normalized_input.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The normalized input includes every task field required by
`franken-engine.swarm-execution-queue-input.v1`: dependency lists, owner
freshness, reservation pressure, proof transport state, millionth-scale scores,
`fallback_trigger`, and a non-empty `first_action`.

## Decisions

- `pass`: required snapshots are well formed and no degraded or fail-closed
  signal was found.
- `degraded`: the graph is replayable, but optional evidence is missing or a
  stale owner, reservation conflict, or proof brownout requires operator
  caution.
- `fail_closed`: the graph is empty, malformed, cyclic, references unknown
  dependencies, lacks first actions, attempts to treat local-rch fallback as
  successful proof health, or contains a contradictory `bv` actionable item
  that is still blocked and absent from `br ready`.

## Validation

```bash
bash -n scripts/swarm_execution_queue_input_normalizer.sh
bash -n scripts/e2e/swarm_execution_queue_input_normalizer_smoke.sh
jq empty docs/swarm_execution_queue_input_contract_v1.json
bash scripts/e2e/swarm_execution_queue_input_normalizer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_input_normalizer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_input_normalizer.sh scripts/e2e/swarm_execution_queue_input_normalizer_smoke.sh docs/SWARM_EXECUTION_QUEUE_INPUT_NORMALIZER.md docs/swarm_execution_queue_input_contract_v1.json
```
