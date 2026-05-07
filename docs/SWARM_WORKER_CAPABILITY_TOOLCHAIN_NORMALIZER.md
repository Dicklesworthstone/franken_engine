# SWARM_WORKER_CAPABILITY_TOOLCHAIN_NORMALIZER

`scripts/swarm_worker_capability_toolchain_normalizer.sh` is the
SWARM-SCALE-IV-B fixture-fed bridge between queue readiness, topology-aware
queue signals, rehabilitation state, remote-stall contamination evidence, and
worker capability/toolchain snapshots.

The normalizer is advisory-only. It does not update beads, release
reservations, send Agent Mail, run Cargo or RCH, mutate remote workers,
reroute live tasks automatically, or change the live queue policy.

Machine-readable child contract:
`docs/swarm_worker_capability_toolchain_input_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_worker_capability_toolchain/worker_capability_toolchain_fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh`.

## Inputs

Required snapshots:

- `--execution-queue-input-json FILE`
- `--topology-queue-signal-input-json FILE`
- `--rehabilitation-ledger-json FILE`
- `--rch-remote-compile-stall-bundle-json FILE`
- `--worker-capability-snapshot-json FILE`
- `--worker-toolchain-snapshot-json FILE`

Optional snapshots:

- `--resource-envelope-json FILE`
- `--operator-status-snapshot-json FILE`

Missing optional snapshots remain visible degraded evidence. Required queue,
topology, rehabilitation, stall, capability, or toolchain inputs that are
malformed fail closed. `local fallback contamination fails closed` and must not
be promoted as healthy worker-affinity proof.

## Artifacts

Each run emits:

- `swarm_worker_capability_toolchain_input.json`
- `swarm_worker_capability_toolchain_sources.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The normalized input records:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- queue-context summary and proof transport state
- topology routing context and preferred-worker subject
- rehabilitation exclusions and watch/rehab-candidate state
- capability coverage context
- toolchain parity context
- routing hints, including routing mode and advised worker IDs
- degraded, blocked, and fail-closed reasons
- explicit mutation-policy guarantees

## Decisions

- `pass` / `confirmed`: queue, topology, rehabilitation, capability, toolchain,
  and stall evidence agree and the preferred worker cohort is safe.
- `degraded` / `degraded`: required evidence is coherent, but optional support
  is missing or broader-cohort fallback was needed because preferred workers
  were excluded.
- `blocked` / `blocked`: required evidence is coherent enough to explain the
  failure, but capability coverage or toolchain parity prevents safe preferred
  routing.
- `fail_closed` / `contaminated`: local fallback contamination, contaminated
  remote-stall truth, or malformed required evidence invalidates remote-only
  capability-routing truth.

`toolchain fingerprint mismatch blocks routing advice`, and missing required
capability coverage does the same even if topology/locality evidence was
otherwise healthy.

## Proof Cases

The checked-in fixtures cover the required SWARM-SCALE-IV-B proof categories:

- `healthy_capability_parity`
- `degraded_missing_optional_telemetry`
- `blocked_toolchain_mismatch`
- `blocked_missing_required_capability`
- `contaminated_local_fallback`

`degraded_missing_optional_telemetry` also proves the
`broader_cohort_fallback` path: a drained preferred worker is excluded and a
broader non-preferred cohort remains advisory-only and degraded instead of
being silently upgraded.

## Upstream Evidence Notes

The normalizer is grounded in current shipped evidence shapes:

- queue input already preserves task IDs, proof-transport state, and local
  fallback markers
- topology queue signal already preserves preferred worker IDs and rank-bias
  mode
- rehabilitation receipts already cite `rch workers capabilities --refresh --json`
  as an operator evidence refresh command
- the remote stall bundle already preserves `local_fallback_observed`,
  `worker_id`, `build_id`, and heartbeat/progress evidence
- multiple shipped RCH wrappers and manifests already preserve explicit
  `toolchain` or `toolchain_fingerprint` fields

## Validation

```bash
bash -n scripts/swarm_worker_capability_toolchain_normalizer.sh
bash -n scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh
shellcheck -x scripts/swarm_worker_capability_toolchain_normalizer.sh scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh
jq empty docs/swarm_worker_capability_toolchain_input_contract_v1.json scripts/testdata/swarm_worker_capability_toolchain/worker_capability_toolchain_fixtures.json
bash scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh check
bash scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh selftest
git diff --check -- docs/SWARM_WORKER_CAPABILITY_TOOLCHAIN_NORMALIZER.md docs/swarm_worker_capability_toolchain_input_contract_v1.json scripts/swarm_worker_capability_toolchain_normalizer.sh scripts/e2e/swarm_worker_capability_toolchain_normalizer_smoke.sh scripts/testdata/swarm_worker_capability_toolchain/worker_capability_toolchain_fixtures.json
```
