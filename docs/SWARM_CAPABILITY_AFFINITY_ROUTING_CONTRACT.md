# SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT

`docs/swarm_capability_affinity_routing_contract_v1.json` defines the
contract-only truth surface for capability-aware worker affinity and
toolchain-safe queue routing.

This bundle exists to bridge already-shipped queue, topology, and remote-stall
surfaces without pretending that the live queue or worker fleet was mutated:

- `crates/franken-engine/src/swarm_control_loop.rs`
- `crates/franken-engine/src/seqlock_candidate_inventory.rs`
- `scripts/swarm_execution_queue_input_normalizer.sh`
- `scripts/swarm_topology_queue_signal_normalizer.sh`
- `scripts/swarm_rch_stall_rehabilitation_ledger.sh`
- `scripts/rch_remote_compile_stall_bundle_capture.sh`
- `scripts/swarm_operator_status_report.sh`

It is evidence-only and advisory-only. The contract must not be described as a
live queue-policy mutator, automatic rerouting surface, worker mutation
surface, reservation mutation surface, Agent Mail mutation surface, or remote
worker repair surface.

## Required Preserved Inputs

The future routing advisory bundle must preserve six required upstream inputs:

- `execution_queue_input_json`
- `topology_queue_signal_input_json`
- `rehabilitation_ledger_json`
- `rch_remote_compile_stall_bundle_json`
- `worker_capability_snapshot_json`
- `worker_toolchain_snapshot_json`

Together these sources must preserve the minimum advisory subject:

- `task_id`
- `candidate_worker_ids`
- `required_capabilities`
- `observed_capabilities`
- `required_toolchain_fingerprint`
- `observed_toolchain_fingerprint`
- `rehabilitation_state`
- `proof_transport_state`
- `local_fallback_detected`
- `reason_codes`

Missing required preserved inputs fail closed.

## Optional Preserved Inputs

Optional supporting inputs may remain absent without erasing the advisory claim,
but they must degrade trust instead of silently upgrading it:

- `resource_envelope_json`
- `operator_status_snapshot_json`
- `routing_outcome_samples_json`

## Truth States

- `confirmed`: required routing, capability, toolchain, and rehabilitation
  evidence are present and mutually coherent, and no contamination is observed
- `degraded`: the required advisory subject is present, but one or more
  optional supporting inputs are missing or degraded
- `blocked`: required inputs are coherent enough to explain the failure, but
  capability coverage gaps, toolchain mismatch, or rehabilitation exclusions
  prevent safe preferred-worker routing
- `contaminated`: local fallback or similarly disqualifying contamination was
  observed, so the advisory is not valid remote-only routing truth

## Decision Language

- `pass`: healthy capability-aware routing advice is safe to interpret as
  advisory
- `degraded`: advice is still readable, but confidence is reduced
- `blocked`: coherent evidence shows that the preferred route is unsafe or
  unsupported
- `fail_closed`: malformed or contaminated evidence invalidates the advisory

The contract must preserve explicit reason codes for at least:

- `capability_coverage_confirmed`
- `missing_required_capability`
- `toolchain_parity_confirmed`
- `toolchain_fingerprint_mismatch`
- `rehabilitation_excluded_worker`
- `broader_cohort_fallback`
- `remote_stall_contaminated`
- `local_fallback_contaminated`
- `unsupported_toolchain`

## Fail-Closed Rules

- Missing required preserved inputs fail closed.
- Contradictory worker capability or toolchain snapshots fail closed.
- `local fallback contamination fails closed` and invalidates remote-only queue
  routing advice.
- A contaminated remote-stall bundle must fail closed instead of being promoted
  as healthy worker affinity evidence.
- The contract must not claim it changed the live queue, rerouted tasks, or
  repaired workers automatically.

## Blocked Routing Rules

- Missing required capability coverage blocks routing advice.
- `toolchain fingerprint mismatch blocks routing advice`.
- A drained or probe-required worker remains excluded from preferred routing.

## Expected Outputs

Downstream implementation beads must eventually preserve at least:

- `capability_affinity_routing_advisory.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The future advisory bundle is expected to expose:

- `routing_advisory_id`
- `truth_state`
- `decision`
- `source_artifacts`
- `reason_codes`
- `worker_affinity_summary`
- `toolchain_parity_summary`
- `capability_coverage_summary`
- `artifact_paths`

## Proof Cases

The contract language is written to support at least these downstream proof
cases:

- `healthy_confirmed`
- `degraded_missing_optional_support`
- `blocked_missing_required_capability`
- `blocked_toolchain_fingerprint_mismatch`
- `contaminated_local_fallback`
- `rehabilitation_excluded_cohort`

These cases must stay advisory-only and must not imply worker mutation, live
queue mutation, or automatic rerouting.

## Upstream Evidence Notes

The routing contract is grounded in current shipped evidence shapes:

- rehabilitation receipts already cite
  `rch workers capabilities --refresh --json` as an operator command form
- the remote stall bundle already preserves `local_fallback_observed`,
  `worker_id`, `build_id`, and progress/heartbeat evidence
- queue and topology surfaces already preserve preferred worker sets,
  proof-transport state, and degraded/blocked/contaminated truth
- multiple shipped RCH wrappers already preserve explicit `toolchain` or
  `toolchain_fingerprint` fields in their artifact manifests

## Validation

```bash
jq empty docs/swarm_capability_affinity_routing_contract_v1.json
bash -n scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh
bash scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh check
bash scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh selftest
git diff --check -- docs/SWARM_CAPABILITY_AFFINITY_ROUTING_CONTRACT.md docs/swarm_capability_affinity_routing_contract_v1.json scripts/e2e/swarm_capability_affinity_routing_contract_smoke.sh
```
