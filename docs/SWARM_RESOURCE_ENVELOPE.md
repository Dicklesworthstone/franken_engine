# SWARM_RESOURCE_ENVELOPE

The swarm resource envelope is the SWARM-SCALE-I evidence contract for turning
host, worker, proof-cache, RCH, bead, and reservation snapshots into one
deterministic capacity record for massive agent swarms.

The first surface is fixture-fed, proof-only, and advisory-only. It helps an
operator decide how many script, proof, and build lanes can safely run on a
64+ core / 256GB+ host without confusing stale evidence, disk pressure, local
RCH fallback, or worker-slot contradictions for safe capacity. It does not query
live services or mutate `br`, Agent Mail, reservations, target directories, RCH,
Cargo, queue policy, or workers.

Machine-readable contract:
`docs/swarm_resource_envelope_contract_v1.json`.

## Source Inventory

The resource envelope accepts preserved snapshots from existing operator
workflows:

- `host topology`: CPU core/thread count, NUMA node count, architecture, and
  observed host identifier.
- `memory pressure`: total, available, swap, pressure stall, and OOM-kill
  indicators where available.
- `disk and target-dir pressure`: free bytes, inode headroom, target-dir roots,
  warm target reuse state, and archive pressure scoreboards.
- `RCH queue and worker slots`: remote queue status, worker IDs, build IDs,
  heartbeat phase/detail, last progress timestamp, local fallback markers, and
  active/exclusive build slots.
- `proof cache and prefetch`: proof-cache plan, warm-target prefetch ROI
  advisory, replay trace, and archive pressure state.
- `bead and queue plan`: `br ready --json`, `br list --status=in_progress
  --json`, `br sync --status --json`, and `bv --recipe actionable --robot-plan`.
- `Agent Mail reservations`: active file reservations and holders for planned
  write sets.
- `causal trace summary`: optional
  `predictive_dashboard.swarm_agent_causal_trace` or graph/anomaly artifacts
  from the causal trace spine.
- `validation cost hints`: validation-plan or command-cost snapshots that mark
  heavy Cargo/RCH proof work.

Missing optional snapshots must be visible degraded evidence. Contradictory slot
counts, stale timestamps for critical capacity inputs, local RCH fallback in a
remote proof path, unsafe mutation claims, or missing required host identity must
fail closed or block admission rather than silently admit more work.

## Envelope Fields

Downstream producers should normalize every source into a stable
`swarm_resource_envelope.json` with:

- `schema_version`
- `source_revision`
- `envelope_id`
- `observed_at`
- `decision`
- `readiness`
- `host_identity`
- `cpu_topology`
- `memory_pressure`
- `disk_pressure`
- `target_dir_pressure`
- `rch_slots`
- `proof_cache`
- `queue_pressure`
- `reservation_pressure`
- `causal_trace_pressure`
- `validation_cost_pressure`
- `capacity_budget`
- `degraded_reasons`
- `blocked_reasons`
- `fail_closed_reasons`
- `artifact_paths`
- `mutation_policy`

The envelope should use deterministic ordering and stable hashes for source
snapshots so repeated fixture runs produce identical output.

## Decision Policy

- `pass`: required host identity, CPU, memory, disk, target-dir, and RCH slot
  snapshots are fresh and internally consistent.
- `degraded`: optional proof-cache, reservation, causal-trace, or validation
  cost hints are missing, but core host capacity evidence is still coherent.
- `blocked`: capacity is trustworthy but saturated or below configured safety
  thresholds, so heavy work should be deferred or narrowed.
- `fail_closed`: required evidence is missing, contradictory, stale beyond the
  accepted window, locally executed while remote proof is claimed, or contains
  unsafe automation wording.

## Mutation Boundary

The resource envelope is proof-only. It never:

- does not update, reopen, close, or reassign beads
- does not release file reservations
- does not send Agent Mail
- does not query live Agent Mail
- does not start RCH or Cargo commands
- does not change live queue policy
- does not mutate workers
- does not delete target directories or build artifacts
- does not repair stalled builds automatically

Operator remediation remains manual or agent-executed outside this artifact and
must be reported through the normal bead and Agent Mail workflow.

## Fail-Closed Classes

The first implementation track must preserve these anomaly classes:

- `missing_required_host_identity`
- `stale_required_capacity_snapshot`
- `contradictory_cpu_or_memory_capacity`
- `target_dir_pressure_exceeds_safe_budget`
- `rch_local_fallback_contaminates_capacity`
- `rch_slot_snapshot_contradiction`
- `reservation_pressure_without_write_set`
- `causal_trace_contamination_blocks_admission`
- `heavy_command_missing_budget`
- `unsafe_live_mutation_claim`

## Planned Producers

SWARM-SCALE-I child beads define the producer chain:

- `scripts/swarm_resource_envelope_normalizer.sh`
- `scripts/e2e/swarm_resource_envelope_normalizer_smoke.sh`
- `scripts/swarm_fair_share_batch_planner.sh`
- `scripts/e2e/swarm_fair_share_batch_planner_smoke.sh`
- `scripts/swarm_operator_status_report.sh`
- `scripts/e2e/swarm_operator_status_report_smoke.sh`
- `scripts/e2e/swarm_resource_envelope_no_mock_drill.sh`
- `scripts/e2e/swarm_resource_envelope_runbook_truth_gate.sh`

## Required Artifacts

The normalizer layer should emit:

- `swarm_resource_envelope_input.json`
- `swarm_resource_envelope_sources.json`
- `swarm_resource_envelope.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The fair-share planner layer should emit:

- `swarm_fair_share_batch_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The no-mock drill should emit a final receipt plus all composed producer
artifacts:

- `swarm_resource_envelope_receipt.json`
- `swarm_resource_envelope.json`
- `swarm_fair_share_batch_plan.json`
- `status.json`
- `commands.txt`
- `events.jsonl`
- `report.md`

## Required Fixture Cases

- `healthy_high_core_host`: 64+ cores, 256GB+ RAM, safe disk pressure, remote
  RCH slots, and no contaminated causal trace.
- `missing_optional_host_telemetry`: optional pressure telemetry is absent and
  remains degraded, not complete.
- `blocked_saturated_capacity`: CPU, memory, disk, or RCH slots are saturated
  with fresh evidence, producing defer guidance rather than fail-closed.
- `contaminated_local_rch_fallback`: local fallback marker invalidates claimed
  remote capacity proof.
- `contradictory_slot_or_memory_evidence`: source snapshots disagree on worker
  slots, memory totals, or target-dir pressure and fail closed.
- `unsafe_mutation_wording`: docs or generated runbook output claim live worker,
  queue, RCH, Cargo, reservation, or bead mutation.

## Validation

```bash
jq empty docs/swarm_resource_envelope_contract_v1.json
bash scripts/rch_policy_compliance_gate.sh docs/SWARM_RESOURCE_ENVELOPE.md docs/swarm_resource_envelope_contract_v1.json
git diff --check -- docs/SWARM_RESOURCE_ENVELOPE.md docs/swarm_resource_envelope_contract_v1.json
```
