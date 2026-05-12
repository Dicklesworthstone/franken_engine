# SWARM_TOPOLOGY_ADMISSION_REUSE_INVENTORY

Inventory for `bd-r99ig.1`. This is the handoff for the
`bd-r99ig.2` through `bd-r99ig.6` topology-aware admission chain.

## Finding

Topology-aware admission is not a greenfield lane. The repository already has
advisory-only topology placement, topology queue signaling, topology-aware
queue scoring, fidelity ledgers, operator-status handoff, and no-mock truth
gates.

Later beads in this track should extend or compose those surfaces. They should
not create a parallel scheduler, a second predictive dashboard, a live worker
mutation path, or a new root contract that bypasses the shipped topology queue
and placement contracts.

## Existing Topology Surfaces

These are the primary surfaces to reuse:

| Role | Existing files | Reuse rule |
| --- | --- | --- |
| Resource envelope for large hosts | `docs/SWARM_RESOURCE_ENVELOPE.md`, `docs/swarm_resource_envelope_contract_v1.json`, `scripts/swarm_resource_envelope_normalizer.sh`, `scripts/e2e/swarm_resource_envelope_no_mock_drill.sh` | Use this for host identity, CPU topology, NUMA count, memory pressure, disk pressure, target-dir pressure, RCH slots, and required fail-closed capacity policy. |
| Topology placement input | `docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_NORMALIZER.md`, `docs/swarm_topology_aware_placement_input_contract_v1.json`, `scripts/swarm_topology_placement_normalizer.sh`, `scripts/testdata/swarm_topology_placement/topology_placement_fixtures.json` | Reuse this as the topology snapshot contract. Add missing fixture fields here instead of inventing a detached snapshot schema. |
| Topology placement plan | `docs/SWARM_TOPOLOGY_AWARE_PLACEMENT_CONTRACT.md`, `docs/swarm_topology_aware_placement_contract_v1.json`, `scripts/swarm_topology_placement_planner.sh`, `scripts/swarm_topology_placement_receipt_ledger.sh` | Use this for NUMA/warm-cache placement advice, recommended worker targets, placement receipts, and fail-closed placement evidence. |
| Topology queue signal | `docs/SWARM_TOPOLOGY_QUEUE_SIGNAL_NORMALIZER.md`, `docs/swarm_topology_queue_signal_input_contract_v1.json`, `scripts/swarm_topology_queue_signal_normalizer.sh`, `scripts/testdata/swarm_topology_queue_signal/queue_signal_fixtures.json` | Use this to normalize execution queue, placement input, rehabilitation, and adoption history into queue-local topology signals. |
| Topology-aware queue scorer | `docs/SWARM_TOPOLOGY_AWARE_QUEUE_SCORER.md`, `docs/swarm_topology_aware_queue_scorer_contract_v1.json`, `docs/swarm_topology_aware_queue_advisory_contract_v1.json`, `scripts/swarm_topology_aware_queue_scorer.sh`, `scripts/testdata/swarm_topology_aware_queue_scorer/cases.json` | Reuse this as the admission advisor for pass, degraded, blocked, and fail_closed topology-aware queue advice. |
| Topology queue fidelity | `docs/SWARM_TOPOLOGY_AWARE_QUEUE_FIDELITY_LEDGER.md`, `docs/swarm_topology_aware_queue_fidelity_ledger_contract_v1.json`, `scripts/swarm_topology_aware_queue_fidelity_ledger.sh` | Use this to compare advisory intent against observed queue/locality outcomes and fail closed on contamination. |
| Topology no-mock drill | `docs/SWARM_TOPOLOGY_AWARE_QUEUE_NO_MOCK_DRILL.md`, `docs/swarm_topology_aware_queue_no_mock_drill_contract_v1.json`, `scripts/e2e/swarm_topology_aware_queue_no_mock_drill.sh`, `scripts/e2e/swarm_topology_aware_queue_truth_gate.sh` | Use this as the final truth gate family for the new track. Extend cases only when the existing drill cannot express the new evidence. |
| Operator status handoff | `scripts/swarm_operator_status_report.sh`, `scripts/e2e/swarm_operator_status_report_smoke.sh`, `docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md` | Keep this as the single operator-facing dashboard/status surface. Feed topology advice into it; do not add a parallel renderer. |

## Existing Resource And RCH Surfaces

The topology chain depends on these existing admission and proof surfaces:

| Role | Existing files | Reuse rule |
| --- | --- | --- |
| Scalar resource admission | `scripts/swarm_resource_governor.sh`, `scripts/e2e/swarm_resource_governor_smoke.sh` | Keep scalar pressure checks here: target-dir presence, target-dir writability, memory headroom, RCH status, local fallback, dirty state, and ownership state. |
| Validation command planning | `scripts/swarm_validation_planner.sh`, `scripts/e2e/swarm_validation_planner_smoke.sh` | Preserve exact `rch exec -- env CARGO_TARGET_DIR=... cargo ...` command construction and fail-closed unknown path mapping. |
| Target-dir heat map | `scripts/swarm_rch_target_dir_heatmap.sh`, `scripts/e2e/swarm_rch_target_dir_heatmap_smoke.sh` | Reuse for warm target, cold target, stale target evidence, saturated workers, and local-fallback target-dir contamination. |
| Worker truth parity | `docs/RCH_WORKER_TRUTH_PARITY_LEDGER.md`, `docs/rch_worker_truth_parity_contract_v1.json`, `scripts/rch_worker_truth_parity_ledger.sh` | Reuse for daemon/probe/queue worker drift, drained-worker disappearance, and ghost-job fail-closed evidence. |
| Proof-cache locality | `scripts/swarm_proof_cache_locality_optimizer.sh`, `scripts/e2e/swarm_proof_cache_locality_optimizer_smoke.sh`, `scripts/testdata/swarm_proof_cache_locality_optimizer/cases.json` | Reuse for cache-locality planning that already consumes topology placement plan, receipt, and ledger evidence. |
| Build-storm QoS | `docs/BUILD_STORM_QOS_BATCH_PLANNER.md`, `scripts/build_storm_qos_batch_planner.sh`, `scripts/e2e/build_storm_qos_batch_planner_smoke.sh` | Reuse for fairness, worker-capacity throttling, pending validation request admission, and deferred-request explanations. |
| Source-local RCH admission | `scripts/source_local_rch_validation_admission.sh`, `scripts/e2e/source_local_rch_admission_no_mock_proof.sh` | Reuse for remote-only proof contamination, explicit target-dir policy, broadening refusal, and exact command identity. |

## Remaining Gaps

The shipped surfaces already express most of the proposed topology admission
track. The useful remaining work is narrower:

1. Align `bd-r99ig.2` with the existing placement and resource-envelope
   contracts instead of creating a detached topology snapshot schema.
2. Add any missing fixture cases to the existing fixture bundles, especially
   dual-NUMA 64-core/256GB, single-node small host, stale telemetry,
   contradictory memory pressure, and local-fallback contamination when those
   exact cases are absent from the current cases.
3. Make the topology-aware queue scorer consume enough resource-envelope and
   worker-truth evidence to distinguish `admit`, `narrow`, `defer`, and
   `fail_closed` operator wording without changing its advisory-only mutation
   boundary.
4. Keep `scripts/swarm_validation_planner.sh` as the source for executable
   command shapes. Topology advice can recommend lanes and target-dir policy,
   but it must not manufacture broad Cargo commands or execute RCH.
5. Extend the existing no-mock drill and truth gate only after the contract and
   scorer changes prove a real coverage gap.

## Required Field Targets

If later work needs more topology evidence, add it to the existing resource or
placement inputs with stable names and fail-closed semantics:

- `host_identity.host_id`
- `host_identity.worker_id`
- `cpu_topology.logical_cpus`
- `cpu_topology.physical_cores`
- `cpu_topology.sockets`
- `cpu_topology.numa_nodes`
- `cpu_topology.smt_threads_per_core`
- `cpu_topology.llc_groups`
- `memory_pressure.total_bytes`
- `memory_pressure.available_bytes`
- `memory_pressure.numa_available_bytes`
- `target_dir_pressure.target_dirs`
- `rch_slots.workers`
- `source_revision`
- `observed_at`
- `telemetry_freshness_seconds`
- `mutation_policy.advisory_only`
- `mutation_policy.runs_cargo`
- `mutation_policy.runs_rch`
- `mutation_policy.mutates_remote_workers`
- `mutation_policy.changes_live_queue_policy`
- local-fallback contamination flags

Missing required host identity, stale required topology, contradictory CPU or
memory capacity, unsafe mutation wording, or local fallback in a claimed remote
proof path must remain `fail_closed`. Optional evidence gaps may degrade only
when core topology and remote-execution truth are still coherent.

## Do Not Create

The next beads should not create:

- a new live scheduler
- a second operator dashboard or report renderer
- a script that queries or mutates live Agent Mail, `br`, RCH workers, or queue
  policy
- an advisor that runs Cargo or RCH
- a new topology root contract that bypasses
  `docs/swarm_topology_aware_placement_contract_v1.json`,
  `docs/swarm_topology_aware_queue_advisory_contract_v1.json`, or
  `docs/swarm_resource_envelope_contract_v1.json`
- a broad validation command generator separate from
  `scripts/swarm_validation_planner.sh`

## Validation For This Inventory

This inventory is docs-only. Validate it with:

```bash
rg -n 'swarm_resource_governor|swarm_validation_planner|swarm_rch_target_dir_heatmap|rch_worker_truth_parity_ledger|swarm_proof_cache_locality_optimizer|build_storm_qos_batch_planner|swarm_operator_status_report|swarm_topology_aware_queue_scorer|swarm_topology_placement_planner' docs/SWARM_TOPOLOGY_ADMISSION_REUSE_INVENTORY.md
git diff --check -- docs/SWARM_TOPOLOGY_ADMISSION_REUSE_INVENTORY.md
```
