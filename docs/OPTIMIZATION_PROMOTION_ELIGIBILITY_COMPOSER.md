# Optimization Promotion Eligibility Composer

The optimization promotion eligibility composer is advisory only and proof only.

It consumes the `bd-sisok` optimization promotion-control contract plus saved evidence snapshots for real hot-path proof, proof-specialization receipts, semantic parity, rollback readiness, safe-mode readiness, performance regression health, support-surface truth, and source revision. It emits observe, promote, pin, or fail_closed recommendations without mutating runtime policy.

Promote and pin recommendations require semantic parity, fresh proof inputs, tail-budget health, rollback readiness, safe-mode readiness, support-surface truth, and source-revision alignment.

Every next validation command is rch-wrapped. The composer writes commands as evidence and never executes them.

Synthetic contamination, stale evidence, semantic divergence, tail regression, or rollback-unready evidence fails closed.

## Artifacts

`scripts/optimization_promotion_eligibility_composer.sh` emits:

- `optimization_promotion_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The smoke harness is `scripts/e2e/optimization_promotion_eligibility_composer_smoke.sh`.
