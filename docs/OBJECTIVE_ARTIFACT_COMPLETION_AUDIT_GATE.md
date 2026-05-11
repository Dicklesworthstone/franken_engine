# Objective Artifact Completion Audit Gate

`bd-w8jfe` adds a fixture-fed audit gate for broad operator objectives. It
maps each deliverable to concrete artifacts, command receipts, closed beads,
and proof receipts before completion can be claimed.

Machine-readable contract:
[`docs/objective_artifact_completion_audit_gate_contract_v1.json`](./objective_artifact_completion_audit_gate_contract_v1.json).

Implementation:
`scripts/objective_artifact_completion_audit_gate.sh`.

## Boundary

The gate is advisory-only and proof-only. It does not run Cargo, invoke `rch`,
mutate `br`, close beads, send Agent Mail, mutate workers, or change queue
policy.

Passing tests, complete manifests, green-looking summaries, or memory-only notes
are not accepted as completion unless they cover every required deliverable with
the concrete evidence named by the objective.

## Inputs

Required:

- `--objective-json`: deliverables and required evidence ids.
- `--evidence-json`: observed artifacts, commands, beads, proof receipts,
  manifests, and memory notes.

## Outputs

- `completion_audit_report.json`
- `missing_evidence.jsonl`
- `events.jsonl`
- `commands.txt`
- `report.md`

The report always includes `satisfied`, `missing`, `weakly_verified`, and
`deferred` sections.

## Validation

```bash
jq empty docs/objective_artifact_completion_audit_gate_contract_v1.json scripts/testdata/objective_artifact_completion_audit_gate/cases.json
bash -n scripts/objective_artifact_completion_audit_gate.sh scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh
bash scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh check
bash scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh selftest
git diff --check -- docs/OBJECTIVE_ARTIFACT_COMPLETION_AUDIT_GATE.md docs/objective_artifact_completion_audit_gate_contract_v1.json scripts/objective_artifact_completion_audit_gate.sh scripts/e2e/objective_artifact_completion_audit_gate_smoke.sh scripts/testdata/objective_artifact_completion_audit_gate/cases.json
```
