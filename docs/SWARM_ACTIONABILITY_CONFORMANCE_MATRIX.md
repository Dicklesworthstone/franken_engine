# SWARM_ACTIONABILITY_CONFORMANCE_MATRIX

`bd-l28cd` records spec-derived conformance coverage for the V1 actionability
report contract.

This is a fixture and expected-output conformance layer.
It does not prove live guard execution.
Live capture and replay stay in the no-mock drill lane.

## Scope

Specification inputs:

- `docs/swarm_actionability_truth_gate_contract_v1.json`
- `scripts/testdata/swarm_actionability_truth_gate_contract/cases.json`
- `scripts/testdata/swarm_actionability_golden_reports/reports.json`

The matrix checks that golden reports cover the contract fixture cases, required
decisions, fail-closed reason codes, scrubbed source revisions, required output
shape, and advisory-only mutation policy.

## Coverage

| Area | Requirement Level | Coverage |
| --- | --- | --- |
| case coverage | MUST | 6 of 6 contract cases have golden reports |
| decision vocabulary | MUST | `safe_to_claim`, `defer`, `fail_closed`, `observe_only` |
| fail-closed reasons | MUST | blocked, in-progress, stale-export, dirty-overlap, missing-source |
| source revision stability | MUST | all dynamic fields use scrubbed markers |
| mutation policy | MUST | all mutation flags are false, advisory/proof flags are true |
| required outputs | MUST | matrix asserts report fields corresponding to V1 output contract |

Known boundary: the matrix intentionally does not claim runtime conformance for
`scripts/swarm_actionability_truth_gate.sh`.
