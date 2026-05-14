# Optimization Transfer Guard

The optimization transfer guard is advisory only and proof only.

It consumes saved cross-workload transfer, workload-manifold, performance-regression, and real hot-path evidence. It emits an `optimization_transfer_guard.json` receipt without mutating runtime policy.

The guard distinguishes same-regime promotion, transferable cross-regime evidence, refused cross-regime evidence, and fail_closed evidence.

Workload identity must be unambiguous before promotion side conditions can pass.

Cold-start-only and warmed-cache-only wins are refused outside their measured regimes unless additional proof is listed.

Every next validation command is rch-wrapped.

Missing transfer evidence, contradictory regime labels, ambiguous workload identity, or synthetic-only evidence fails closed.

## Artifacts

`scripts/optimization_transfer_guard.sh` emits:

- `optimization_transfer_guard.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The smoke harness is `scripts/e2e/optimization_transfer_guard_smoke.sh`.
