# Optimization Promotion-Control Contract

The optimization promotion-control contract is advisory only and proof only.

It defines the V1 source of truth for the `bd-xg3d6` promotion-control lane. The lane consumes existing optimization, rollback, safe-mode, cross-workload, and real hot-path evidence surfaces. It does not introduce a new optimizer, benchmark suite, scheduler, dashboard, or live mutation path.

The contract consumes existing optimization, rollback, safe-mode, cross-workload, and real hot-path evidence surfaces.

Promotion states are observe, promote, pin, demote, quarantine, and fail_closed.

## Required Surfaces

- `proof_specialization_receipt`
- `specialization_lane_gate`
- `specialization_rollback_gate`
- `performance_regression_gate`
- `safe_mode_fallback`
- `cross_workload_transfer`
- `real_hot_path_evidence`

Each surface must be present, fresh, and tied to an artifact path or module path. Missing or stale surfaces fail closed because promotion decisions must not rely on assumed optimization evidence.

## Evidence Families

The contract requires these evidence families before any downstream composer can decide whether to observe, promote, pin, demote, quarantine, or fail closed:

- `real_hot_path_evidence`
- `proof_specialization_receipt`
- `semantic_parity`
- `rollback_health`
- `safe_mode_fallback`
- `cross_workload_transfer`
- `performance_regression`

Synthetic-only evidence and contradictory evidence fail closed.

## Mutation Policy

The contract never mutates runtime policy, br, Agent Mail, reservations, workers, Cargo, RCH, or benchmark claims. It reads a saved JSON input, emits a deterministic report, emits a surface inventory, and records a command transcript. Any later Rust/Cargo validation named by child beads must run through `rch` and reject local fallback.

## Artifacts

`scripts/optimization_promotion_control_contract.sh` emits:

- `optimization_promotion_control_contract.json`
- `optimization_promotion_surface_inventory.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The smoke harness is `scripts/e2e/optimization_promotion_control_contract_smoke.sh`.
