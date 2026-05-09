# SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS

`scripts/swarm_native_dependency_operator_status.sh` turns native dependency
routing and ABI cache evidence into operator-readable status text.

The surface is advisory-only and evidence-only. It does not mutate workers,
install packages, delete target directories, reroute live tasks, update beads,
or send Agent Mail. It emits copy-ready text for those workflows so the human or
agent taking action can preserve the distinction between:

- source compile or test failures
- worker native package gaps
- stale or contradictory worker probe evidence
- local fallback contamination
- ABI/cache proof reuse quarantine

The intended closeout wording for native dependency blockers is:

> Validation environment blocker: required native dependency evidence is missing
> or unsafe for the selected worker. This is not evidence that the source patch failed.

## Inputs

- `native_dependency_routing_advisory.json`
- `native_dependency_abi_cache_ledger.json`

## Outputs

- `native_dependency_operator_status.md`
- `agent_mail_handoff.md`
- `br_closeout_snippet.md`
- `native_dependency_operator_status.json`
- `events.jsonl`
- `commands.txt`

## Required Cases

- compatible route with reusable ABI cache
- missing native dependency worker rejected while another worker is compatible
- stale worker evidence fail-closed
- all workers incompatible because required native dependency evidence is absent

## Validation

```bash
jq empty scripts/testdata/swarm_native_dependency_operator_status/cases.json
bash -n scripts/swarm_native_dependency_operator_status.sh
bash -n scripts/e2e/swarm_native_dependency_operator_status_smoke.sh
bash scripts/e2e/swarm_native_dependency_operator_status_smoke.sh check
bash scripts/e2e/swarm_native_dependency_operator_status_smoke.sh selftest
git diff --check -- docs/SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS.md scripts/swarm_native_dependency_operator_status.sh scripts/e2e/swarm_native_dependency_operator_status_smoke.sh scripts/testdata/swarm_native_dependency_operator_status/cases.json
```
