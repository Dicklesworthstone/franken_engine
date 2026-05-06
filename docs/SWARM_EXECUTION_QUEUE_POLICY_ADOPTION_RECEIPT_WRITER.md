# SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_WRITER

`scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh` consumes the
SWARM-CTRL-XIV queue tuning promotion artifacts plus a human operator decision
and emits a canonical adopted-policy receipt with a deterministic snapshot
bundle for later drift analysis.

Machine-readable writer contract:
`docs/swarm_execution_queue_policy_adoption_receipt_writer_contract_v1.json`.

Receipt contract:
`docs/swarm_execution_queue_policy_adoption_receipt_contract_v1.json`.

## Inputs

Required inputs:

- `--candidate-bundle-json FILE`
- `--promotion-guard-receipt-json FILE`
- `--rollout-plan-json FILE`
- `--rollback-comparator-receipt-json FILE`
- `--canary-verdict-ledger-json FILE`
- `--operator-decision-json FILE`

The operator decision must be a manual approval artifact. It must include the
approver, approval timestamp, approval artifact path, decision reason, adoption
state, observation window, and supersession metadata.

## Artifacts

Each run emits:

- `adoption_receipt.json`
- `adoption_snapshot_bundle.json`
- `evidence_hashes.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The writer is deterministic for fixed inputs, source revision, and generated
timestamp. Receipt and snapshot identifiers are content-derived. Evidence links
preserve each source path and sha256 hash.

## Fail-Closed Behavior

The writer fails closed when inputs are incomplete, malformed, contradictory, or
claim unsafe behavior. Rejections include missing operator approval, bundle ids
that disagree across artifacts, non-eligible promotion guard decisions,
rollback comparator verdicts that are not better than current, canary actions
that do not recommend continuation, missing observation windows, missing
supersession metadata, automatic adoption claims, live retuning claims, and
sustained-gain claims.

The writer is a receipt/snapshot surface only. It never changes active queue settings,
never applies live retuning, never mutates `br`, never sends Agent Mail, never
mutates remote workers, and never rewrites historical outcomes. The
receipt records adoption evidence; later beads must score sustained gain,
expiry, supersession, and drift forensics.

## Validation

```bash
bash -n scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh
bash -n scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh
shellcheck -x scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh
jq empty docs/swarm_execution_queue_policy_adoption_receipt_writer_contract_v1.json
bash scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh scripts/e2e/swarm_execution_queue_policy_adoption_receipt_writer_smoke.sh docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_RECEIPT_WRITER.md docs/swarm_execution_queue_policy_adoption_receipt_writer_contract_v1.json
```
