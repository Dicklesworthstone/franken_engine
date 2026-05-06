# SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_CONTRACT

The execution queue policy adoption receipt is an advisory operator record for
the post-promotion queue tuning lifecycle. It records that a human operator
approved a specific queue tuning policy bundle for adoption, ties that decision
to rollout and canary evidence, preserves evidence hashes, and defines the
observation window that later drift-forensics beads must monitor.

Machine-readable contract:
`docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json`.

Smoke gate:
`scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh`.

## Scope

The receipt is an adoption receipt audit artifact, not an autonomous retuning mechanism. The
contract never changes active queue settings, never applies live retuning,
never mutates `br`, never sends Agent Mail, never mutates remote workers, and never
rewrites historical outcomes. A later writer may persist a valid receipt, but
downstream status surfaces must not imply that the active queue changed unless a
valid adoption receipt is present.

The receipt is not a sustained-gain proof. It records adoption intent and the
evidence available at adoption time; later scoring must decide whether the
adopted policy helped, regressed, expired, or was superseded.

## Required Receipt Fields

Each adoption receipt must include:

- `schema_version`
- `adoption_receipt_id`
- `adopted_policy_bundle_id`
- `source_revision`
- `generated_at`
- `operator_decision`
- `adopted_candidate`
- `evidence_links`
- `observation_window`
- `supersession`
- `mutation_policy`
- `non_claim_boundaries`
- `fail_closed_rules`

`operator_decision` records the human approver, approval time, approval artifact
path, decision reason, and explicit adoption state. manual operator approval is
always required.

`evidence_links` must point to the supporting artifacts:

- `candidate_bundle_json`
- `promotion_guard_receipt_json`
- `rollout_plan_json`
- `rollback_comparator_receipt_json`
- `canary_verdict_ledger_json`
- `operator_decision_json`

Each evidence link must include a non-empty path and a sha256 digest.

## Observation Window

The receipt must define an expected observation window before any later
sustained-gain or drift-forensics bead can claim the policy is working. Required
fields are:

- `starts_at`
- `duration_seconds`
- `minimum_sample_count`
- `monitored_metrics`
- `stop_on_missing_evidence`

`stop_on_missing_evidence` must be `true`.

## Supersession

Supersession metadata must be explicit even when there is no prior adopted
policy. Required fields are:

- `supersedes_adoption_receipt_id`
- `supersedes_policy_bundle_id`
- `supersession_reason`
- `previous_policy_retention`
- `expiry_policy`

The receipt must preserve enough previous-policy identity for rollback,
forensics, and audit history. Missing supersession metadata fails closed.

## Non-Claim Boundaries

The receipt must explicitly state that it does not prove sustained gain, does
not prove canary success beyond linked evidence, does not authorize automatic
live retuning, and does not mutate scheduler behavior by itself. Automatic
adoption claims, missing operator approval, missing evidence hashes, missing
observation windows, missing supersession metadata, and unsupported proof
fallback claims fail closed. The contract must reject local fallback proof evidence.

## Validation

```bash
bash -n scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh
shellcheck -x scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh
jq empty docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json
bash scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh check
bash scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh selftest
git diff --check -- docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_CONTRACT.md docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json scripts/e2e/swarm_execution_queue_policy_adoption_receipt_contract_smoke.sh
```
