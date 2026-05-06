# SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR

`scripts/swarm_execution_queue_tuning_rollback_comparator.sh` compares a
candidate queue tuning bundle and manual-approval rollout plan against the
currently acknowledged queue policy state. It emits rollback readiness and a
canary verdict ledger without mutating live scheduler state.

Machine-readable contract:
`docs/swarm_execution_queue_tuning_rollback_comparator_contract_v1.json`.

## Inputs

Required inputs:

- `--candidate-bundle-json FILE`
- `--rollout-plan-json FILE`
- `--current-policy-state-json FILE`

The comparator requires supporting hindsight, fidelity, counterfactual, tuning,
and frontier evidence links in the bundle. It fails closed when rollback
references do not match the current policy bundle, when rollback material is
missing, when evidence is stale, or when any input implies autonomous retuning.

## Verdicts

The comparator emits one of:

- `better_than_current`: candidate delta is large enough for bounded canary
  comparison.
- `worse_than_current`: candidate is expected to underperform the current
  policy, so rollback is recommended.
- `ambiguous_verdict`: evidence is complete but delta is too small for a clear
  result.
- `fail_closed`: required evidence or rollback linkage is missing or unsafe.

The canary verdict ledger records exact cause-and-effect explanations, candidate
deltas, rollback triggers, and recommended action. It is an advisory-only planning artifact. It never changes active queue settings, never applies live
retuning, never mutates `br`, never sends Agent Mail, never mutates remote
workers, and never rewrites historical outcomes. The comparator must reject local fallback proof evidence.

## Artifacts

Each run emits:

- `rollback_comparator_receipt.json`
- `canary_verdict_ledger.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
bash -n scripts/swarm_execution_queue_tuning_rollback_comparator.sh
bash -n scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh
shellcheck -x scripts/swarm_execution_queue_tuning_rollback_comparator.sh scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh
jq empty docs/swarm_execution_queue_tuning_rollback_comparator_contract_v1.json
bash scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh check
bash scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_tuning_rollback_comparator.sh scripts/e2e/swarm_execution_queue_tuning_rollback_comparator_smoke.sh docs/SWARM_EXECUTION_QUEUE_TUNING_ROLLBACK_COMPARATOR.md docs/swarm_execution_queue_tuning_rollback_comparator_contract_v1.json
```
