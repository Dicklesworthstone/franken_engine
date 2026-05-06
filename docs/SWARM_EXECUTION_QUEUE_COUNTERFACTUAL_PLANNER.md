# SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_PLANNER

`scripts/swarm_execution_queue_counterfactual_planner.sh` builds an
advisory-only counterfactual backtest and tuning plan from the queue fidelity
receipt and drift ledger. It proposes replay candidates for queue weights and
conservative-mode settings, but it does not change live scheduler semantics,
update beads, rewrite historical outcomes, send Agent Mail, run Cargo, mutate
workers, or apply retuning automatically.

Machine-readable contract:
`docs/swarm_execution_queue_counterfactual_planner_contract_v1.json`.

## Inputs

Required artifacts:

- `--fidelity-score-receipt-json FILE`
- `--drift-ledger-json FILE`

The planner consumes the receipt and ledger emitted by
`scripts/swarm_execution_queue_fidelity_scorer.sh`. Upstream fail-closed
evidence stays fail-closed. Rows with missing candidate fields, contradictory
evidence, or automatic live-retuning claims are rejected.

## Artifacts

Each run emits:

- `counterfactual_backtest_report.json`
- `tuning_plan.json`
- `frontier.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The tuning plan class is one of `no_improvement`, `one_clear_improvement`,
`conflicting_improvements`, `insufficient_evidence`, or `fail_closed`.

## Validation

```bash
bash -n scripts/swarm_execution_queue_counterfactual_planner.sh
bash -n scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh
shellcheck -x scripts/swarm_execution_queue_counterfactual_planner.sh scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh
jq empty docs/swarm_execution_queue_counterfactual_planner_contract_v1.json scripts/testdata/swarm_execution_queue/counterfactual_planner_fixtures.json
bash scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh check
bash scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_counterfactual_planner.sh scripts/e2e/swarm_execution_queue_counterfactual_planner_smoke.sh docs/SWARM_EXECUTION_QUEUE_COUNTERFACTUAL_PLANNER.md docs/swarm_execution_queue_counterfactual_planner_contract_v1.json scripts/testdata/swarm_execution_queue/counterfactual_planner_fixtures.json
```
