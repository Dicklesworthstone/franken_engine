# SWARM_TOPOLOGY_AWARE_PLACEMENT_NORMALIZER

`scripts/swarm_topology_placement_normalizer.sh` is the SWARM-SCALE-II-B
fixture-fed bridge between preserved topology/locality evidence and the
advisory placement input contract from
`docs/swarm_topology_aware_placement_contract_v1.json`.

The normalizer is advisory-only. It does not update beads, reassign owners,
release reservations, send Agent Mail, run Cargo or RCH, mutate remote
workers, pin workers automatically, or rebind hosts automatically.

Machine-readable child contract:
`docs/swarm_topology_aware_placement_input_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_topology_placement_normalizer_smoke.sh`.

## Inputs

Required snapshots:

- `--host-topology-json FILE`
- `--numa-evidence-json FILE`
- `--worker-inventory-json FILE`

Optional snapshots:

- `--cache-residency-json FILE`
- `--resource-envelope-json FILE`
- `--execution-queue-input-json FILE`
- `--tail-latency-evidence-json FILE`

Missing optional snapshots remain visible degraded evidence. Required topology
or worker evidence that is malformed, missing a parseable observed timestamp,
or stale beyond the accepted window fails closed. Contradictory host/NUMA/cache
identity stays blocked instead of silently promoting a confident placement
claim.

## Artifacts

Each run emits:

- `swarm_topology_placement_input.json`
- `swarm_topology_placement_sources.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The normalized input records:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- host identity and topology summary
- NUMA locality summary and preferred nodes
- worker inventory summary
- warm-cache residency state and hot-worker hints
- queue/resource/tail-latency context
- deterministic placement hints
- degraded, blocked, and fail-closed reasons
- explicit mutation-policy guarantees

## Decisions

- `pass` / `confirmed`: required topology evidence is fresh and coherent, and
  optional locality context is present without contamination.
- `degraded` / `degraded`: required topology evidence is coherent, but one or
  more optional cache, queue, envelope, or tail-latency inputs are missing,
  stale, or untrusted.
- `blocked` / `blocked`: topology evidence is present but locality
  contradictions or blocking context prevent confident placement advice.
- `fail_closed` / `blocked` or `contaminated`: malformed required topology,
  stale required topology, hot-cache claims without residency evidence, or
  local-fallback contamination invalidate remote-only placement truth.

## Proof Cases

The checked-in fixtures cover the required SWARM-SCALE-II-B proof categories:

- `healthy_confirmed`
- `degraded_missing_cache_residency`
- `blocked_contradictory_locality`
- `contaminated_local_fallback`
- `fail_closed_malformed_topology`

`blocked_contradictory_locality` proves the blocked truth path without mutating
anything live. `contaminated_local_fallback` proves that local fallback
contamination fails closed instead of masquerading as healthy locality proof.

## Validation

```bash
bash -n scripts/swarm_topology_placement_normalizer.sh
bash -n scripts/e2e/swarm_topology_placement_normalizer_smoke.sh
shellcheck -x scripts/swarm_topology_placement_normalizer.sh scripts/e2e/swarm_topology_placement_normalizer_smoke.sh
jq empty docs/swarm_topology_aware_placement_input_contract_v1.json scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json
bash scripts/e2e/swarm_topology_placement_normalizer_smoke.sh check
bash scripts/e2e/swarm_topology_placement_normalizer_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_NORMALIZER.md docs/swarm_topology_aware_placement_input_contract_v1.json scripts/swarm_topology_placement_normalizer.sh scripts/e2e/swarm_topology_placement_normalizer_smoke.sh scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json
```
