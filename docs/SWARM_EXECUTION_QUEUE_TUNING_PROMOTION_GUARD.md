# SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD

`scripts/swarm_execution_queue_tuning_promotion_guard.sh` compares a packed
queue tuning policy bundle with the currently acknowledged queue policy state
and emits a manual-approval rollout plan. It is an advisory-only planning artifact, not an authority for queue mutation.

Machine-readable contract:
`docs/swarm_execution_queue_tuning_promotion_guard_contract_v1.json`.

## Inputs

Required inputs:

- `--candidate-bundle-json FILE`
- `--current-policy-state-json FILE`

The candidate bundle must follow
`docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json`. The current
policy state records the acknowledged policy bundle id, evidence freshness,
provenance state, rollback material availability, and observational mutation
policy.

## Decisions

The guard emits one of:

- `safe_noop`: the candidate does not improve the frontier or the bundle class is
  `no_improvement`.
- `eligible_canary`: preconditions are satisfied and the candidate may proceed to
  manual approval and bounded canary planning.
- `reject`: the guard fails closed.

Reject causes include stale evidence, missing rollback material, contradictory
queue-policy provenance, missing manual approval requirements, mismatched
rollback references, unsafe mutation policies, and automatic live-retuning
claims. The guard must reject local fallback proof evidence.

## Artifacts

Each run emits:

- `promotion_guard_receipt.json`
- `manual_approval_rollout_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The guard never changes active queue settings, never applies live retuning,
never mutates `br`, never sends Agent Mail, never mutates remote workers, and
never rewrites historical outcomes. Human approval is required before any later
rollout or canary work can use an eligible candidate.

## Validation

```bash
bash -n scripts/swarm_execution_queue_tuning_promotion_guard.sh
bash -n scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh
shellcheck -x scripts/swarm_execution_queue_tuning_promotion_guard.sh scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh
jq empty docs/swarm_execution_queue_tuning_promotion_guard_contract_v1.json
bash scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh check
bash scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_tuning_promotion_guard.sh scripts/e2e/swarm_execution_queue_tuning_promotion_guard_smoke.sh docs/SWARM_EXECUTION_QUEUE_TUNING_PROMOTION_GUARD.md docs/swarm_execution_queue_tuning_promotion_guard_contract_v1.json
```
