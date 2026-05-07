# SWARM_TOPOLOGY_AWARE_QUEUE_ADVISORY_CONTRACT

`docs/swarm_topology_aware_queue_advisory_contract_v1.json` defines the
contract-only truth surface for topology-aware execution-queue ranking and
locality feedback.

This bundle exists to bridge already-shipped surfaces without pretending that
the queue was mutated live:

- `crates/franken-engine/src/swarm_control_loop.rs`
- `scripts/swarm_execution_queue_input_normalizer.sh`
- `scripts/swarm_topology_placement_normalizer.sh`
- `scripts/swarm_rch_stall_rehabilitation_ledger.sh`
- `scripts/swarm_operator_status_report.sh`

It is evidence-only and advisory-only. The contract must not be described as a
live queue-policy mutator, worker pinning surface, remote worker mutation
surface, Agent Mail mutation surface, or bead mutation surface.

## Required Preserved Inputs

The future advisory bundle must preserve six required upstream inputs:

- `execution_queue_input_json`
- `topology_placement_input_json`
- `rehabilitation_ledger_json`
- `queue_artifact_json`
- `bottleneck_report_json`
- `locality_outcome_samples_json`

Together these sources must preserve the minimum advisory subject:

- `task_id`
- `rank`
- `preferred_worker_ids`
- `preferred_numa_nodes`
- `worker_exclusion_state`
- `hot_cache_reuse_confidence`
- `queue_risk_budget_state`
- `proof_transport_state`
- `local_fallback_detected`
- `reason_codes`

Missing required preserved inputs fail closed.

## Optional Preserved Inputs

Optional supporting inputs may remain absent without erasing the advisory claim,
but they must degrade trust instead of silently upgrading it:

- `placement_adoption_history_json`
- `operator_status_snapshot_json`
- `resource_envelope_json`
- `tail_latency_locality_json`

## Truth States

- `confirmed`: required queue, locality, and rehab evidence are present and
  mutually coherent, and no contamination is observed
- `degraded`: the required advisory subject is present, but one or more
  optional supporting inputs are missing or stale
- `blocked`: required inputs are contradictory or incomplete enough that queue
  locality advice cannot be trusted
- `contaminated`: local fallback or similarly disqualifying contamination was
  observed, so the advisory is not valid remote-only queue truth

## Decision Language

- `pass`: healthy locality-aware queue advice is safe to interpret as advisory
- `degraded`: advice is still readable, but confidence is reduced
- `blocked`: contradictory evidence prevents confident advice
- `fail_closed`: malformed or contaminated evidence invalidates the advisory

The contract must preserve explicit reason codes for at least:

- `hot_cache_reuse_preferred`
- `numa_locality_preferred`
- `drained_worker_excluded`
- `probe_required_worker_excluded`
- `contradictory_locality`
- `telemetry_gap`
- `local_fallback_contaminated`
- `cache_reuse_outcome_confirmed`
- `cache_reuse_outcome_missed`

## Fail-Closed Rules

- Missing required preserved inputs fail closed.
- Contradictory queue, locality, or rehabilitation evidence fails closed.
- `local fallback contamination fails closed` and invalidates remote-only queue
  locality advice.
- A drained or probe-required worker must not be promoted as preferred-locality
  advice.
- The contract must not claim it changed the live queue or pinned workers.

## Expected Outputs

Downstream implementation beads must eventually preserve at least:

- `queue_advisory_bundle.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`

The future advisory bundle is expected to expose:

- `queue_advisory_id`
- `truth_state`
- `decision`
- `source_artifacts`
- `reason_codes`
- `worker_exclusions`
- `locality_bias_summary`
- `risk_budget_summary`
- `artifact_paths`

## Proof Cases

The contract language is written to support at least these downstream proof
cases:

- `healthy_confirmed`
- `degraded_missing_locality_support`
- `blocked_contradictory_locality`
- `contaminated_local_fallback`
- `drained_worker_exclusion`
- `cache_reuse_feedback`

These cases must stay advisory-only and must not imply worker mutation or live
queue mutation.

## Validation

```bash
jq empty docs/swarm_topology_aware_queue_advisory_contract_v1.json
bash -n scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh
bash scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh check
bash scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh selftest
git diff --check -- docs/SWARM_TOPOLOGY_AWARE_QUEUE_ADVISORY_CONTRACT.md docs/swarm_topology_aware_queue_advisory_contract_v1.json scripts/e2e/swarm_topology_aware_queue_advisory_contract_smoke.sh
```
