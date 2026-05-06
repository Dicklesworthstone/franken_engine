# SWARM_STARVATION_RESCUE_PLANNER

`scripts/swarm_starvation_rescue_planner.sh` consumes the normalized
starvation-rescue input surface plus the approved scenario-matrix report and
emits a dry-run rescue/arbitration receipt.

It is report-only. The planner never mutates beads, releases reservations, or
changes worker state.

## Inputs

Required:

- `--starvation-rescue-input-json`
- `--scenario-matrix-report-json`

Optional:

- `--source-revision`
- `--output-dir`

## Artifacts

- `swarm_starvation_rescue_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Decision Modes

- `advisory`
- `manual_review_required`
- `fail_closed`

## Validation

```bash
bash -n scripts/swarm_starvation_rescue_planner.sh
bash -n scripts/e2e/swarm_starvation_rescue_planner_smoke.sh
shellcheck -x scripts/swarm_starvation_rescue_planner.sh scripts/e2e/swarm_starvation_rescue_planner_smoke.sh
jq empty docs/swarm_starvation_rescue_planner_contract_v1.json
bash scripts/e2e/swarm_starvation_rescue_planner_smoke.sh check
bash scripts/e2e/swarm_starvation_rescue_planner_smoke.sh selftest
git diff --check -- scripts/swarm_starvation_rescue_planner.sh scripts/e2e/swarm_starvation_rescue_planner_smoke.sh docs/SWARM_STARVATION_RESCUE_PLANNER.md docs/swarm_starvation_rescue_planner_contract_v1.json
```
