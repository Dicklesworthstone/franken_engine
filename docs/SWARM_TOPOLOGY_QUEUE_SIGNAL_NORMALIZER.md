# SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER

`scripts/swarm_topology_queue_signal_normalizer.sh` is the SWARM-SCALE-III-B
fixture-fed bridge between execution-queue readiness, topology-placement
advice, and RCH rehabilitation state.

The normalizer is advisory-only. It does not update beads, release
reservations, send Agent Mail, run Cargo or RCH, mutate remote workers, pin
workers automatically, or change the live queue policy.

Machine-readable child contract:
`docs/swarm_topology_queue_signal_input_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh`.

## Inputs

Required snapshots:

- `--execution-queue-input-json FILE`
- `--topology-placement-input-json FILE`
- `--rehabilitation-ledger-json FILE`

Optional snapshots:

- `--placement-adoption-history-json FILE`
- `--operator-status-snapshot-json FILE`

Missing optional snapshots remain visible degraded evidence. Required queue,
topology, or rehabilitation inputs that are malformed fail closed. A blocked
or contradictory locality input stays blocked instead of silently promoting a
confident queue-bias claim. `local fallback contamination fails closed` and
must not be promoted as healthy queue locality proof.

## Artifacts

Each run emits:

- `swarm_topology_queue_signal_input.json`
- `swarm_topology_queue_signal_sources.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The normalized input records:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- queue-context summary and proof transport state
- locality and warm-cache summary
- rehabilitation exclusions and rehab candidates
- queue signal hints, including rank-bias mode and usable preferred workers
- degraded, blocked, and fail-closed reasons
- explicit mutation-policy guarantees

## Decisions

- `pass` / `confirmed`: queue, topology, and rehabilitation evidence agree and
  hot-cache or NUMA preference can be expressed safely.
- `degraded` / `degraded`: required evidence is coherent, but optional support
  is missing or worker exclusions reduce confidence.
- `blocked` / `blocked`: topology or locality evidence is contradictory enough
  that ranking bias must not be trusted.
- `fail_closed` / `contaminated`: local fallback contamination or malformed
  required evidence invalidates remote-only queue locality truth.

## Proof Cases

The checked-in fixtures cover the required SWARM-SCALE-III-B proof categories:

- `healthy_hot_cache`
- `degraded_missing_optional_support`
- `blocked_contradictory_locality`
- `contaminated_local_fallback`
- `drain_exclusion`

`drain_exclusion` proves that a `drain_recommended` worker is removed from
preferred queue advice instead of silently remaining a hot-cache target.

## Validation

```bash
bash -n scripts/swarm_topology_queue_signal_normalizer.sh
bash -n scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh
shellcheck -x scripts/swarm_topology_queue_signal_normalizer.sh scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh
jq empty docs/swarm_topology_queue_signal_input_contract_v1.json scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json
bash scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh check
bash scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER.md docs/swarm_topology_queue_signal_input_contract_v1.json scripts/swarm_topology_queue_signal_normalizer.sh scripts/e2e/swarm_topology_queue_signal_normalizer_smoke.sh scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json
```
