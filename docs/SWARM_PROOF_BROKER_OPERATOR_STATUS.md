# Swarm Proof Broker Operator Status

`bd-ua5n2.6`

`scripts/swarm_proof_broker_operator_status.sh` turns proof-broker advisory
inputs into an operator-status bundle and a `frankentui` panel contract. It
shows pending proof requests, reusable verdicts, reuse refusals, stale or
contaminated proofs, fairness debt, duplicate coalescing, and recommended next
actions.

The script never runs Cargo or RCH, mutates br, sends Agent Mail, mutates remote
workers, or claims live mutation authority. The rich panel renderer boundary is
`/dp/frankentui`; this repository only emits the JSON contract consumed by that
future renderer.

## Fail-Closed Rules

- A panel claiming live mutation authority fails closed.
- A panel hiding stale evidence fails closed.
- A panel omitting refusal reasons fails closed.
- Fail-closed bundles use `overall_status: "blocked"` and never hide a green
  status behind advisory language.

Every displayed row links to source evidence and exact command text. Fairness
rows use `not_applicable` for command text because they represent scheduling
debt rather than a proof command.

## Validation

```bash
jq empty docs/swarm_proof_broker_operator_status_contract_v1.json scripts/testdata/swarm_proof_broker_operator_status/cases.json
bash -n scripts/swarm_proof_broker_operator_status.sh
bash -n scripts/e2e/swarm_proof_broker_operator_status_smoke.sh
bash scripts/e2e/swarm_proof_broker_operator_status_smoke.sh check
bash scripts/e2e/swarm_proof_broker_operator_status_smoke.sh selftest
git diff --check -- docs/swarm_proof_broker_operator_status_contract_v1.json docs/SWARM_PROOF_BROKER_OPERATOR_STATUS.md scripts/swarm_proof_broker_operator_status.sh scripts/testdata/swarm_proof_broker_operator_status/cases.json scripts/e2e/swarm_proof_broker_operator_status_smoke.sh
```
