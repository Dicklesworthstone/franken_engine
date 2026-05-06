# SWARM-CTRL-XIII Operator Runbook

SWARM-CTRL-XIII turns execution queue aftermath into advisory-only hindsight
evidence. It does not change the active queue, does not apply retuning
automatically, and does not claim beads, send Agent Mail, release reservations,
or mutate remote workers.

Policy summary: does not apply retuning automatically.

## Capture Evidence

Start from the SWARM-CTRL-XII queue artifacts and explicit aftermath snapshots:

- `execution_queue_artifact.json`
- `risk_budget_receipt.json`
- `bottleneck_report.json`
- `run_manifest.json`
- bead status, timing, owner contact, reservation friction, proof outcome, and
  checkpoint restore snapshots

Run `scripts/swarm_execution_queue_hindsight_normalizer.sh` and preserve:

- `hindsight/hindsight_report.json`
- `hindsight/hindsight_input.json`
- `hindsight/evidence_ledger.json`
- `hindsight/counterfactual_candidates.json`

If the normalizer reports stale, missing, or contradictory source evidence,
stop and quote the fail-closed reason. Do not rewrite aftermath data to make a
queue decision look better.

## Score Fidelity

Run `scripts/swarm_execution_queue_fidelity_scorer.sh` against the normalized
hindsight bundle. Preserve:

- `fidelity/fidelity_score_receipt.json`
- `fidelity/drift_ledger.json`

Use `drift_ledger.json` as the source of drift classes:

- `owner recency contradiction`: fail closed and reconcile owner/contact truth
  before trusting any queue hindsight.
- `checkpoint restore fail-closed`: keep restore remediation ahead of queue
  interpretation in `operator-status/status.json`.
- `proof brownout misprediction`: reject local fallback proof evidence as unsafe
  and raise proof-health scrutiny before rerunning broad proof work.
- `counterfactual candidate disagreement`: keep manual review when different
  candidates improve different mismatch classes.

## Plan Counterfactuals

Run `scripts/swarm_execution_queue_counterfactual_planner.sh` and preserve:

- `counterfactual/counterfactual_backtest_report.json`
- `counterfactual/tuning_plan.json`
- `counterfactual/frontier.json`

The frontier is review evidence only. A recommended candidate is not permission
to retune a scheduler, reopen a bead, reassign ownership, or update queue
weights. Any proposal with missing aftermath evidence stays manual-review.

## Publish Status

Publish one operator-status handoff with `scripts/swarm_operator_status_report.sh`
and preserve:

- `operator-status/status.json`
- `operator-status/report.md`

The `predictive_dashboard.queue_fidelity` section must include the trust level,
drift class, highest-severity mismatch, top tuning recommendation, frontier,
mutation policy, and artifact paths. It composes with checkpoint restore,
starvation rescue, proof economy, and execution queue advisory sections instead
of overriding them.

## No-Mock Drill

Run the composed drill:

```bash
bash scripts/e2e/swarm_execution_queue_hindsight_no_mock_drill.sh check
bash scripts/e2e/swarm_execution_queue_hindsight_no_mock_drill.sh selftest
```

The drill covers healthy hindsight, owner recency contradiction, checkpoint
restore fail-closed, proof brownout misprediction, and counterfactual candidate
disagreement. Its report records child artifact paths, event logs, command
logs, and an explicit mutation policy showing that the drill remains
advisory-only.

## Truth Gate

Run the runbook truth gate:

```bash
bash scripts/e2e/swarm_ctrl_xiii_runbook_truth_gate.sh check
bash scripts/e2e/swarm_ctrl_xiii_runbook_truth_gate.sh selftest
```

The gate rejects missing artifact references, automatic queue actuation claims,
stale hindsight claims that skip evidence refresh, bare heavy Cargo examples,
and any statement that permits local proof fallback promotion.

reject local fallback proof evidence for this lane. Use script-only checks
or an `rch exec -- env CARGO_TARGET_DIR=... cargo ...` proof when a Rust runner
surface actually changes.
