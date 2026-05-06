# SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_CONTRACT

The execution queue tuning policy bundle is an advisory-only planning artifact
for promoting one queue policy candidate from hindsight, fidelity, and
counterfactual evidence. It packages the candidate, its evidence ledger, manual
approval requirements, canary constraints, rollback references, and mutation
policy disclaimers for operator review.

Machine-readable contract:
`docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json`.

Smoke gate:
`scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh`.

## Scope

The bundle never changes active queue settings, never applies live retuning,
never mutates `br`, never sends Agent Mail, and never mutates remote workers.
Manual approval is required before any operator can use the recommendation as
input to a later implementation bead.

The smoke gate must reject missing evidence links, absent manual approval,
missing rollback references, unsafe canary constraints, automatic retuning
claims, and reject local fallback proof evidence.

## Required Bundle Fields

Each bundle must include:

- `schema_version`
- `bundle_id`
- `source_revision`
- `generated_at`
- `promoted_candidate`
- `evidence_links`
- `manual_approval`
- `canary_constraints`
- `rollback_references`
- `mutation_policy`
- `fail_closed_rules`

`promoted_candidate` records the candidate id, expected fidelity delta,
confidence band, safety status, and the source counterfactual tuning plan.

`evidence_links` must point to the supporting artifacts:

- `fidelity_score_receipt_json`
- `drift_ledger_json`
- `counterfactual_backtest_report_json`
- `tuning_plan_json`
- `frontier_json`
- `operator_status_json`

Each evidence link must include a non-empty path and a sha256 digest.

## Manual Approval

`manual_approval.required` must be `true`. The bundle may record a pending
approval artifact path, but it is still not a live mutation surface. Approval
lets an operator decide whether a future packer/canary bead may proceed.

## Canary Constraints

Canary constraints must be explicit and bounded. Required fields are:

- `enabled`
- `observation_window_seconds`
- `max_queue_depth_delta`
- `max_candidate_weight_delta_millionths`
- `rollback_on_drift_classes`
- `stop_on_missing_evidence`

`stop_on_missing_evidence` must be `true`. Drift classes that trigger rollback
must include `proof_drift`, `ownership_drift`, and `restore_drift`.

## Rollback References

Rollback references must include the prior policy bundle id, prior frontier
artifact, rollback comparator report path, and canary verdict ledger path. The
bundle fails closed when rollback evidence is missing.

## Validation

```bash
bash -n scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh
jq empty docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json
bash scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh check
bash scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh selftest
git diff --check -- docs/SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_CONTRACT.md docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json scripts/e2e/swarm_execution_queue_tuning_policy_bundle_contract_smoke.sh
```
