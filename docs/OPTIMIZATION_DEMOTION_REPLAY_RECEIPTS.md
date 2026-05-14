# Optimization Demotion Replay Receipts

The optimization demotion replay receipt producer is advisory only and proof only.

It consumes saved promotion-control evidence for proof-specialization receipts, policy epoch alignment, semantic parity, rollback readiness, safe-mode fallback readiness, performance regression health, and source revision. It emits keep_observed, demote_now, quarantine_candidate, or fail_closed receipts without mutating runtime policy.

Demote and quarantine receipts require a rollback token and a safe-mode replay command before they can pass.

The receipt preserves source evidence hashes and emits a minimal counterexample bundle for incident support.

Every replay and next validation command is rch-wrapped.

Stale proof receipts, policy epoch drift, semantic divergence, or tail regression produce demotion or quarantine receipts when rollback and safe-mode evidence are ready.

Missing rollback tokens or unready safe-mode fallback evidence fails closed when demotion or quarantine is required.

## Artifacts

`scripts/optimization_demotion_replay_receipts.sh` emits:

- `optimization_demotion_receipt.json`
- `optimization_demotion_counterexample_bundle.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The smoke harness is `scripts/e2e/optimization_demotion_replay_receipts_smoke.sh`.
