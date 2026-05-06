# SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT

The SWARM-SCALE-II placement contract defines the advisory-only, proof-only
control plane for topology-aware placement and warm-cache residency on large
swarm hosts.

Machine-readable contract:
`docs/swarm_topology_aware_placement_contract_v1.json`.

Smoke gate:
`scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh`.

## Source Inventory

This track reuses existing explicit evidence surfaces instead of querying live
workers or inventing a second scheduler:

- `scripts/swarm_execution_queue_input_normalizer.sh` and
  `docs/swarm_execution_queue_input_contract_v1.json`
  for readiness, owner, reservation, and remote-proof queue context.
- `scripts/swarm_resource_envelope_normalizer.sh` and
  `docs/swarm_resource_envelope_contract_v1.json`
  for host identity, CPU, NUMA, disk, target-dir, and capacity evidence.
- `scripts/swarm_operator_status_report.sh`,
  `scripts/e2e/swarm_operator_status_report_smoke.sh`,
  `docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md`, and
  `docs/swarm_predictive_dashboard_contract_v1.json`
  for the final operator-facing advisory handoff.
- `crates/franken-engine/src/metadata_locality_governance_gate.rs`
  for current locality-governance terminology and fail-closed reasoning.
- `crates/franken-engine/src/tail_latency_control_plane.rs` and
  `scripts/run_rgc_tail_latency_control_plane.sh`
  for existing high-core scheduling and locality-sensitive replay evidence.

Missing optional topology or cache-warmth inputs must stay visible degraded
evidence. Contradictory locality claims, missing required host identity, stale
required topology, or contaminated local-fallback markers must block or fail
closed instead of inventing confident placement advice.

## Required End State

Later SWARM-SCALE-II producers must preserve one deterministic advisory chain:

- `swarm_topology_placement_input.json`
- `swarm_topology_placement_plan.json`
- `swarm_topology_placement_evidence_ledger.json`
- `swarm_topology_placement_receipt.json`
- `swarm_topology_placement_handoff.json`
- `swarm_topology_placement_no_mock_drill_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The planner layer must stay explicitly advisory-only. It may recommend topology
classes, NUMA-aware worker targets, hot-cache reuse opportunities, and bounded
fallback actions, but it must not claim that live worker pinning, queue
mutation, host rebinding, reservation release, or automatic bead reassignment
already happened.

The operator status report remains the only predictive dashboard producer in
franken_engine.

## Proof Categories

The first complete SWARM-SCALE-II chain is not truthful until it proves all
four required categories:

- `healthy_topology_aware_planning`: coherent host topology and warm-cache
  evidence produce a confident advisory placement plan.
- `degraded_partial_topology`: optional topology or cache inputs are missing,
  but the plan remains explicitly degraded instead of silently healthy.
- `blocked_contradictory_locality`: inconsistent NUMA, host, or locality
  evidence blocks advisory placement rather than overclaiming certainty.
- `contaminated_local_fallback`: local fallback or equivalent contamination in
  the reused remote-proof chain fails closed and stays visible in the placement
  output.

## Mutation Boundary

The SWARM-SCALE-II placement contract is proof-only and advisory-only. It
never:

- does not update, reopen, close, or reassign beads
- does not release file reservations
- does not send Agent Mail
- does not query live Agent Mail
- does not run Cargo or RCH
- does not mutate remote workers
- does not change active queue policy
- does not pin workers automatically
- does not rebind hosts automatically
- does not repair target directories automatically

## Planned Producers

Later child beads define the exact producer chain:

- `scripts/swarm_topology_placement_normalizer.sh`
- `scripts/e2e/swarm_topology_placement_normalizer_smoke.sh`
- `scripts/swarm_topology_placement_planner.sh`
- `scripts/e2e/swarm_topology_placement_planner_smoke.sh`
- `scripts/swarm_topology_placement_receipt_ledger.sh`
- `scripts/e2e/swarm_topology_placement_receipt_ledger_smoke.sh`
- `scripts/swarm_operator_status_report.sh`
- `scripts/e2e/swarm_operator_status_report_smoke.sh`
- `scripts/e2e/swarm_topology_placement_no_mock_drill.sh`
- `scripts/e2e/swarm_topology_placement_truth_gate.sh`

## Fail-Closed Classes

The contract fixes these first-class fail-closed reasons for later producers:

- `missing_required_host_identity`
- `missing_required_topology_snapshot`
- `stale_required_topology_snapshot`
- `malformed_topology_snapshot`
- `contradictory_locality_evidence`
- `warm_cache_claim_without_residency_evidence`
- `rch_local_fallback_contaminates_locality`
- `unsafe_live_mutation_claim`

## Validation

```bash
jq empty docs/swarm_topology_aware_placement_contract_v1.json
bash -n scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh
bash scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh check
bash scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT.md docs/swarm_topology_aware_placement_contract_v1.json scripts/e2e/swarm_topology_aware_placement_contract_smoke.sh
```
