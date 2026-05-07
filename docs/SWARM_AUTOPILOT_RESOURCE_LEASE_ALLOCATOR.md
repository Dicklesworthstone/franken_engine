# Swarm Autopilot Resource Lease Allocator

`scripts/swarm_autopilot_resource_lease_allocator.sh` composes operator intent
policy, brownout forecast, queue/locality advisory, and RCH rehabilitation
classifications into deterministic scarcity advice for the swarm autopilot.

It allocates bounded advisory leases for scarce CPU, memory, RCH slots, warm
target reuse, proof-cache cooldown, and fairness recovery. It never mutates
live queues or workers.

Machine-readable contract:
`docs/swarm_autopilot_resource_lease_allocator_contract_v1.json`

Smoke gate:
`scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh`

Fixture cases:
`scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json`

## Inputs

Required inputs:

- `operator_intent_policy_json`
- `brownout_forecaster_json`
- `queue_advisory_bundle_json`
- `rch_rehabilitation_ledger_json`

## Artifacts

Every run emits:

- `swarm_autopilot_resource_lease_plan.json`
- `swarm_autopilot_resource_scarcity_receipts.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The lease plan preserves:

- `allocation_id`
- `decision`
- `truth_state`
- `summary.overall_state`
- `summary.admit_count`
- `summary.reserve_count`
- `summary.defer_count`
- `summary.rebalance_count`
- `summary.cool_count`
- `lease_allocations`
- `resolved_inputs`
- `fail_closed_reasons`
- `artifact_paths`
- `mutation_policy`

Every scarcity receipt preserves:

- `receipt_id`
- `lane_id`
- `decision`
- `resource_class`
- `lease_duration_seconds`
- `reason_codes`
- `evidence_paths`
- `rollback_command`
- `remediation_command`

## Truth Rules

- The allocator is advisory only and proof only.
- Local fallback contamination fails closed.
- Contradictory queue or locality evidence fails closed.
- Urgent RCH slack protection outranks nonurgent heavy fanout.
- Every scarcity receipt includes reason codes, evidence paths, lease duration, and rollback or remediation guidance.
- Stale policy, forecast, queue advisory, or rehab evidence fails closed.
- Missing worker pressure telemetry fails closed.
- The allocator must not claim it changed live queue policy, worker state,
  bead ownership, reservations, Agent Mail, Cargo, or RCH.

## Proof Cases

The checked-in fixtures cover:

- `healthy_balanced_allocation`
- `urgent_lane_protection`
- `fairness_recovery`
- `rch_brownout_deferral`
- `proof_cache_cooling`
- `contradictory_locality_fail_closed`

## Validation

```bash
bash -n scripts/swarm_autopilot_resource_lease_allocator.sh
bash -n scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh
shellcheck -x scripts/swarm_autopilot_resource_lease_allocator.sh scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh
jq empty docs/swarm_autopilot_resource_lease_allocator_contract_v1.json scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json
bash scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh check
bash scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_RESOURCE_LEASE_ALLOCATOR.md docs/swarm_autopilot_resource_lease_allocator_contract_v1.json scripts/swarm_autopilot_resource_lease_allocator.sh scripts/e2e/swarm_autopilot_resource_lease_allocator_smoke.sh scripts/testdata/swarm_autopilot_resource_lease_allocator/cases.json
```
