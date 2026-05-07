# SWARM_CONTROL_SURFACE_CATALOG

`bd-45vka` defines the V1 source contract for the SWARM-CTRL-XVII control-surface catalog.
The catalog exists because the repo now has many swarm-control, swarm-scale, and
swarm-autopilot scripts with overlapping symptoms and operator entry points. The
catalog is the stable inventory layer that future normalizers, routers, drift
gates, and intake guards can consume without guessing which surface owns a
particular decision.

The contract is machine-readable in
[`docs/swarm_control_surface_catalog_contract_v1.json`](./swarm_control_surface_catalog_contract_v1.json).

This surface is advisory only and proof only. It does not query live `br`, Agent
Mail, RCH, git, or workers. It does not mutate beads, release reservations, send
mail, run Cargo, run RCH, change queue policy, or replace
`scripts/swarm_operator_status_report.sh`.

## Catalog Row Contract

Every catalog row must define these fields:

- `surface_id`
- `track`
- `purpose`
- `intent_tags`
- `symptom_tags`
- `required_inputs`
- `emitted_artifacts`
- `implementation_script`
- `smoke_script`
- `runbook_doc`
- `contract_json`
- `owning_bead_id`
- `upstream_surface_ids`
- `downstream_surface_ids`
- `mutation_policy`
- `rch_policy`
- `source_freshness_policy`
- `operator_status_section`
- `failure_reason_codes`
- `validation_commands`

Missing scripts, smoke gates, docs, or contracts must not be silently accepted.
The future normalizer must classify missing required sources as `fail_closed`
with a stable reason code. Optional sources may degrade only when the row names
the optional source and the consumer can still produce truthful advisory output.

## Initial Inventory Classes

The V1 catalog starts with these classes so future work can route against known
surfaces instead of creating duplicate control planes:

| Class | Representative surface | Primary entry point |
| --- | --- | --- |
| actionability truth | `swarm_actionability_truth_gate` | `scripts/swarm_actionability_truth_gate.sh` |
| resource envelope | `swarm_resource_envelope` | `scripts/swarm_resource_envelope_normalizer.sh` |
| fair-share/admission | `swarm_admission_budget_planner` | `scripts/swarm_admission_budget_planner.sh` |
| RCH validation/stall rehab | `swarm_rch_stall_rehabilitation_ledger` | `scripts/swarm_rch_stall_rehabilitation_ledger.sh` |
| proof cache/locality | `swarm_proof_cache_locality_optimizer` | `scripts/swarm_proof_cache_locality_optimizer.sh` |
| execution queue tuning/adoption | `swarm_execution_queue_tuning_policy_bundle` | `scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh` |
| high-core SLO | `swarm_high_core_scenario_matrix` | `scripts/swarm_high_core_slo_scenario_matrix.sh` |
| causal trace | `swarm_agent_causal_trace_spine` | `scripts/swarm_agent_causal_trace_graph.sh` |
| autopilot recommendation/warehouse | `swarm_autopilot_recommendation_bundle` | `scripts/swarm_autopilot_recommendation_bundle.sh` |
| capability affinity | `swarm_capability_affinity_routing` | `scripts/swarm_capability_affinity_queue_routing_planner.sh` |
| topology placement/queue | `swarm_topology_aware_placement` | `scripts/swarm_topology_placement_normalizer.sh` |
| checkpoint/restore | `swarm_checkpoint_restore_planner` | `scripts/swarm_checkpoint_restore_planner.sh` |
| shadow daemon | `swarm_autopilot_shadow_daemon` | `scripts/swarm_autopilot_shadow_source_watchers.sh` |

## RCH Policy

Catalog rows may mention heavy Rust validation only as advisory command evidence.
Any heavy Cargo example must start with `rch exec -- env CARGO_TARGET_DIR=`.
Bare `cargo check`, `cargo clippy`, `cargo test`, or `cargo run` examples are
catalog drift and must fail closed unless the row explicitly models a
local-fallback contamination fixture.

The catalog producer itself must not run Cargo or RCH. Its validation is limited
to JSON shape checks, markdown whitespace checks, and future shell smoke checks
for catalog consumers.

## Operator Status Boundary

The catalog may name the operator status section that should display a surface,
but `scripts/swarm_operator_status_report.sh` remains the single operator-status
producer. Catalog and router artifacts can be handed to that producer in later
beads; this contract does not create another dashboard or claim automatic
remediation.

## Required Fail-Closed Reasons

- `FE-SWARM-CATALOG-MISSING-SCRIPT`
- `FE-SWARM-CATALOG-MISSING-SMOKE`
- `FE-SWARM-CATALOG-MISSING-DOC`
- `FE-SWARM-CATALOG-MISSING-CONTRACT`
- `FE-SWARM-CATALOG-MALFORMED-CONTRACT`
- `FE-SWARM-CATALOG-DUPLICATE-SURFACE`
- `FE-SWARM-CATALOG-DUPLICATE-INTENT`
- `FE-SWARM-CATALOG-UNSAFE-MUTATION`
- `FE-SWARM-CATALOG-BARE-HEAVY-CARGO`
- `FE-SWARM-CATALOG-STALE-SOURCE`

## Validation

For this contract-only bead:

```bash
jq empty docs/swarm_control_surface_catalog_contract_v1.json
jq -e '.required_surface_fields | index("surface_id") and index("validation_commands")' docs/swarm_control_surface_catalog_contract_v1.json
jq -e '.source_inventory | length >= 13' docs/swarm_control_surface_catalog_contract_v1.json
git diff --check -- docs/SWARM_CONTROL_SURFACE_CATALOG.md docs/swarm_control_surface_catalog_contract_v1.json
```
