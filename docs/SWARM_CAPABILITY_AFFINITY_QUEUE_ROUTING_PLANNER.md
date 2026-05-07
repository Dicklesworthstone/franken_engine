# SWARM_CAPABILITY_AFFINITY_QUEUE_ROUTING_PLANNER

`scripts/swarm_capability_affinity_queue_routing_planner.sh` is the
SWARM-SCALE-IV-C fixture-fed advisory planner that turns the normalized
worker-capability/toolchain input bundle into deterministic capability-affinity
queue-routing advice.

The planner is advisory-only. It does not update beads, release reservations,
send Agent Mail, run Cargo or RCH, mutate remote workers, reroute live tasks
automatically, or change the live queue policy.

Machine-readable child contract:
`docs/swarm_capability_affinity_queue_routing_planner_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json`.

Smoke harness:
`scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh`.

## Inputs

Required input:

- `--worker-capability-toolchain-input-json FILE`

Optional supporting input:

- `--routing-outcome-samples-json FILE`

Missing optional routing-outcome samples remain visible degraded evidence.
Malformed required input fails closed. `local fallback contamination fails closed`
and must not be promoted as healthy worker-affinity proof.

## Artifacts

Each run emits:

- `capability_affinity_queue_routing_advisory.json`
- `capability_affinity_queue_routing_sources.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The advisory records:

- `truth_state`: `confirmed`, `degraded`, `blocked`, or `contaminated`
- `decision`: `pass`, `degraded`, `blocked`, or `fail_closed`
- `routing_mode` copied from the normalized worker-capability/toolchain input
- `reason_codes`
- preferred and advisory cohort scoring across capability coverage,
  toolchain parity, locality compatibility, and rehabilitation exclusions
- capability-coverage, toolchain-parity, and affinity summaries
- source artifacts and explicit mutation-policy guarantees

## Decisions

- `pass` / `confirmed`: the preferred cohort is still safe, capability/toolchain
  coverage is complete, and optional routing-outcome evidence does not weaken
  the advice.
- `degraded` / `degraded`: required evidence is coherent, but broader-cohort
  fallback, watch-state workers, rehab-candidate workers, missing optional
  routing-outcome samples, or observed routing mismatch reduces confidence.
- `blocked` / `blocked`: required evidence is coherent enough to explain the
  failure, but capability coverage or toolchain parity prevents safe preferred
  routing.
- `fail_closed` / `contaminated`: upstream contamination or malformed input
  invalidates remote-only capability-affinity routing truth.

`toolchain fingerprint mismatch blocks routing advice`, and missing required
capability coverage does the same even if locality and rehabilitation evidence
were otherwise healthy.

## Proof Cases

The checked-in fixtures cover the required SWARM-SCALE-IV-C proof categories:

- `healthy_confirmed`
- `degraded_missing_optional_support`
- `blocked_toolchain_fingerprint_mismatch`
- `blocked_missing_required_capability`
- `contaminated_local_fallback`

`degraded_missing_optional_support` also proves the
`broader_cohort_fallback` path: a broader non-preferred cohort remains
advisory-only and degraded instead of being silently upgraded.

## Upstream Evidence Notes

The planner is grounded in current shipped evidence shapes:

- the worker capability/toolchain normalizer already preserves preferred worker
  IDs, excluded workers, advised workers, required capabilities, required
  toolchain fingerprints, broader-cohort fallback tasks, and upstream reason
  codes
- the upstream bundle already preserves explicit mutation-policy guarantees that
  this planner must not weaken
- checked-in routing-outcome samples, when present, only refine confidence and
  must not be described as live queue mutation proof
- rehabilitation receipts already cite `rch workers capabilities --refresh --json`
  as an operator evidence refresh command

## Validation

```bash
bash -n scripts/swarm_capability_affinity_queue_routing_planner.sh
bash -n scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh
shellcheck -x scripts/swarm_capability_affinity_queue_routing_planner.sh scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh
jq empty docs/swarm_capability_affinity_queue_routing_planner_contract_v1.json scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json
bash scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh check
bash scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh selftest
git diff --check -- docs/SWARM_CAPABILITY_AFFINITY_QUEUE_ROUTING_PLANNER.md docs/swarm_capability_affinity_queue_routing_planner_contract_v1.json scripts/swarm_capability_affinity_queue_routing_planner.sh scripts/e2e/swarm_capability_affinity_queue_routing_planner_smoke.sh scripts/testdata/swarm_capability_affinity_queue_routing_planner/fixtures.json
```
