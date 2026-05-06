# SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL

`scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh`
is the SWARM-CTRL-XV no-mock lifecycle drill. It uses deterministic fixture
inputs, but it invokes the real shipped producers:

- `scripts/swarm_execution_queue_policy_adoption_receipt_writer.sh`
- `scripts/swarm_execution_queue_policy_sustained_gain_scorer.sh`
- `scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh`
- `scripts/swarm_operator_status_report.sh`

The drill proves that an adopted queue policy can flow from manual adoption
receipt to sustained-gain scoring, expiry/supersession advisory planning, and
operator-status lifecycle reporting without mocks or replacement harnesses.

Machine-readable contract:
`docs/swarm_execution_queue_policy_adoption_lifecycle_drill_contract_v1.json`.

## Artifacts

Each selftest run emits:

- `adoption_lifecycle_drill_receipt.json`
- `commands.txt`
- `report.md`
- child artifact directories for adoption, sustained-gain, expiry/supersession,
  and operator-status report outputs

## Boundaries

This is a no-mock E2E proof surface only. It never changes active queue settings
and never applies live retuning. It never mutates `br`, never sends
Agent Mail, never mutates remote workers, and never rewrites historical
outcomes. The lifecycle output is advisory-only: expiry and supersession
recommendations are not treated as executed retirement or executed
supersession.

The paired truth gate,
`scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh`,
fails closed if the runbook or contract claims automatic adoption, automatic
promotion, live queue retuning, executed retirement, executed supersession, or
anything other than reject local fallback proof evidence.

## Validation

```bash
bash -n scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh
bash -n scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh
shellcheck -x scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh
jq empty docs/swarm_execution_queue_policy_adoption_lifecycle_drill_contract_v1.json
bash scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh check
bash scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh check
bash scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh selftest
git diff --check -- scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_no_mock_drill.sh scripts/e2e/swarm_execution_queue_policy_adoption_lifecycle_runbook_truth_gate.sh docs/SWARM_EXECUTION_QUEUE_POLICY_ADOPTION_LIFECYCLE_DRILL.md docs/swarm_execution_queue_policy_adoption_lifecycle_drill_contract_v1.json
```
