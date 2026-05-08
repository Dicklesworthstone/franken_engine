# SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER

`crates/franken-engine/src/shadow_decision_composer.rs` and
`scripts/swarm_autopilot_shadow_decision_composer.sh` compose normalized shadow
evidence journal events into advisory operator artifacts for `bd-djejh.4`.

The composer is advisory only and proof only. It reads JSON/JSONL artifacts,
writes only to its output directory, and never mutates beads, Agent Mail,
reservations, rch, git, workers, or live queue policy.

## Inputs

- `--journal-events-jsonl`: normalized source snapshot or journal-event lines.
- `--existing-autopilot-json`: optional existing autopilot output artifacts.

The required source families are `br_queue`, `bv_robot_plan`, `agent_mail`,
`rch_status`, `git_state`, and `artifact_bundles`.

## Outputs

- `shadow_status.json`
- `recommendations.json`
- `operator_notice.md`
- `events.jsonl`
- `commands.txt`
- `report.md`

Every recommendation preserves source event ids, content hashes, collection
timestamps, degradation state, and a separate operator command. The daemon does
not execute those commands.

## Fail-Closed Signals

- missing or stale required sources
- contradictory bead ownership
- unsupported mutation claims
- rch local fallback contamination
- dirty shared worktree ambiguity
- stalled in-progress beads
- stale reservations
- missing no-mock proof artifacts

## Validation

```bash
jq empty docs/swarm_autopilot_shadow_decision_composer_contract_v1.json scripts/testdata/swarm_autopilot_shadow_decision_composer/cases.json
bash -n scripts/swarm_autopilot_shadow_decision_composer.sh scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh
shellcheck -x scripts/swarm_autopilot_shadow_decision_composer.sh scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh
bash scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh check
bash scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_SHADOW_DECISION_COMPOSER.md docs/swarm_autopilot_shadow_decision_composer_contract_v1.json scripts/swarm_autopilot_shadow_decision_composer.sh scripts/e2e/swarm_autopilot_shadow_decision_composer_smoke.sh scripts/testdata/swarm_autopilot_shadow_decision_composer/cases.json
```
