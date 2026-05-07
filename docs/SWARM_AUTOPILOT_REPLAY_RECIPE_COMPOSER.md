# SWARM_AUTOPILOT_REPLAY_RECIPE_COMPOSER

`scripts/swarm_autopilot_replay_recipe_composer.sh` composes deterministic
replay recipes from cohort diff receipts, anomaly cohort bundles, and replay
indexes.

Machine-readable contract:
`docs/swarm_autopilot_replay_recipe_composer_contract_v1.json`.

Checked-in fixture bundle:
`scripts/testdata/swarm_autopilot_replay_recipe_composer/cases.json`.

Smoke harness:
`scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh`.

The replay recipe composer is advisory only and proof only.

## Inputs

Required:

- `--cohort-diff-receipts-json FILE`
- `--anomaly-cohorts-json FILE`
- `--replay-index-json FILE`

Optional:

- `--source-revision REV`
- `--output-dir DIR`

## Outputs

Each run emits:

- `swarm_autopilot_replay_recipe_bundle.json`
- `swarm_autopilot_replay_recipe_index.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each recipe preserves:

- source diff receipt id
- replay mode
- reference and comparison cohort ids
- expected classification
- comparison pivots
- raw evidence paths
- safe rerun instruction

## Replay Rules

Reference baseline replay remains distinct from blocked or degraded counterexample replay.

Blocked counterexample replay must preserve comparison pivots and raw replay evidence paths.

Contaminated evidence cannot be selected as a remote-only replay baseline.

Missing replay-index evidence prevents replay recipe promotion.

## Fail-Closed Rules

- Stale diff receipts fail closed.
- Incomplete replay indexes fail closed.
- Contaminated remote-only baselines fail closed.
- Missing raw evidence paths fail closed.
- Schema drift in diff, cohort, or replay-index material fails closed.

The composer never mutates beads, releases reservations, sends Agent Mail, runs
Cargo, runs RCH, mutates workers, changes live queue policy, approves replay
automatically, or promotes evidence automatically. It only emits replay recipe
bundles and indexes under its output directory.

## Proof Cases

The checked-in fixtures cover:

- `healthy_reference_replay`
- `blocked_counterexample_replay`
- `contaminated_replay_refusal`
- `missing_replay_index_fail_closed`
- `stale_diff_fail_closed`

## Validation

```bash
bash -n scripts/swarm_autopilot_replay_recipe_composer.sh
bash -n scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh
shellcheck -x scripts/swarm_autopilot_replay_recipe_composer.sh scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh
jq empty docs/swarm_autopilot_replay_recipe_composer_contract_v1.json scripts/testdata/swarm_autopilot_replay_recipe_composer/cases.json
bash scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh check
bash scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_REPLAY_RECIPE_COMPOSER.md docs/swarm_autopilot_replay_recipe_composer_contract_v1.json scripts/swarm_autopilot_replay_recipe_composer.sh scripts/e2e/swarm_autopilot_replay_recipe_composer_smoke.sh scripts/testdata/swarm_autopilot_replay_recipe_composer/cases.json
```
