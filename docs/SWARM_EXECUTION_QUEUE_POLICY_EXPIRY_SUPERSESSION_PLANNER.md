# SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_PLANNER

`scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh` evaluates
an adopted execution queue policy after sustained-gain scoring and emits an
advisory expiry or supersession plan. It compares the adoption receipt, the
sustained-gain receipt, the post-adoption drift ledger, and newer candidate
bundle evidence to decide whether the adopted policy should be retained,
expired, or superseded.

Machine-readable contract:
`docs/swarm_execution_queue_policy_expiry_supersession_planner_contract_v1.json`.

## Inputs

Required inputs:

- `--adoption-receipt-json FILE`
- `--sustained-gain-receipt-json FILE`
- `--post-adoption-drift-ledger-json FILE`
- `--newer-candidate-bundle-json FILE`
- `--evidence-ownership-json FILE`

The adoption receipt supplies the active policy identity, adopted candidate,
observation window, and supersession metadata. The sustained-gain receipt and
post-adoption drift ledger supply the hindsight verdict. The newer candidate
bundle supplies replacement evidence. The ownership artifact proves that all
evidence is owned, fresh, accepted, and unambiguous.

## Artifacts

Each run emits:

- `expiry_supersession_plan.json`
- `expiry_supersession_ledger.json`
- `evidence_hashes.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The plan identifier is content-derived. The planner preserves all input paths
and sha256 hashes in the emitted evidence ledger.

## Decisions

The planner emits one of:

- `retain_adopted_policy`: sustained-gain evidence supports retention, or
  post-adoption evidence is inconclusive and no superior newer candidate is
  available.
- `expire_adopted_policy`: regression or rollback-relevant drift requires
  retiring the adopted policy, but no eligible newer candidate is available.
- `supersede_adopted_policy`: a newer eligible candidate bundle improves on the
  adopted candidate and the plan should route operator review toward
  supersession.
- `fail_closed`: required evidence is malformed, stale, ambiguously owned, or
  contradictory.

This is an advisory-only planning artifact. It never changes active queue settings
and never applies live retuning. It never mutates `br`, never sends Agent Mail,
never mutates remote workers, and never rewrites historical outcomes. It also
does not claim that retirement or supersession has already been executed; emitted
plans mark execution state as not executed by this planner unless an explicit
future evidence surface proves otherwise.

The planner must fail closed on bad schemas, non-admitted adoption receipts,
upstream fail-closed sustained-gain receipts, stale or rejected ownership rows,
ambiguous evidence ownership, conflicting candidate prior-policy references,
automatic retuning claims, executed-retirement claims, and reject local fallback proof evidence.

## Validation

```bash
bash -n scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh
bash -n scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh
shellcheck -x scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh
jq empty docs/swarm_execution_queue_policy_expiry_supersession_planner_contract_v1.json
bash scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh check
bash scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh selftest
git diff --check -- scripts/swarm_execution_queue_policy_expiry_supersession_planner.sh scripts/e2e/swarm_execution_queue_policy_expiry_supersession_planner_smoke.sh docs/SWARM_EXECUTION_QUEUE_POLICY_EXPIRY_SUPERSESSION_PLANNER.md docs/swarm_execution_queue_policy_expiry_supersession_planner_contract_v1.json
```
