# SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_PACKER

`scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh` packages the
SWARM-CTRL-XIII hindsight, fidelity, counterfactual, and operator-status
artifacts into one advisory-only tuning policy bundle plus a deterministic
policy frontier export.

Machine-readable contract:
`docs/swarm_execution_queue_tuning_policy_bundle_packer_contract_v1.json`.

The output bundle follows
`docs/swarm_execution_queue_tuning_policy_bundle_contract_v1.json`.

## Inputs

Required artifacts:

- `--fidelity-score-receipt-json FILE`
- `--drift-ledger-json FILE`
- `--counterfactual-backtest-report-json FILE`
- `--tuning-plan-json FILE`
- `--frontier-json FILE`
- `--operator-status-json FILE`

Required rollback references:

- `--prior-policy-bundle-id ID`
- `--prior-frontier-json PATH`
- `--rollback-comparator-report-json PATH`
- `--canary-verdict-ledger-json PATH`

The packer hashes each evidence artifact, preserves each path in
`evidence_links`, and fails closed when upstream evidence is fail-closed,
malformed, contradictory, missing a promoted candidate, missing frontier rows,
or claims automatic live retuning.

## Artifacts

Each run emits:

- `tuning_policy_bundle.json`
- `policy_frontier_export.json`
- `evidence_hashes.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The bundle is an advisory-only planning artifact. The packer never changes active queue settings.
It never applies live retuning, never mutates `br`, never sends Agent Mail,
never mutates remote workers, and never rewrites historical outcomes.
Manual approval is always required before any later bead can use the packed
candidate as a rollout input.

The frontier export keeps stable candidate ordering and explains why each
candidate is promoted, retained for manual review, or discarded. The packer must
reject local fallback proof evidence.

## Validation

```bash
bash -n scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh
bash -n scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh
shellcheck -x scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh
jq empty docs/swarm_execution_queue_tuning_policy_bundle_packer_contract_v1.json
bash scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh check
bash scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_tuning_policy_bundle_packer.sh scripts/e2e/swarm_execution_queue_tuning_policy_bundle_packer_smoke.sh docs/SWARM_EXECUTION_QUEUE_TUNING_POLICY_BUNDLE_PACKER.md docs/swarm_execution_queue_tuning_policy_bundle_packer_contract_v1.json
```
