# SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS

`scripts/swarm_autopilot_shadow_source_watchers.sh` normalizes one-shot source
snapshots for the shadow-daemon track.

This is an advisory input surface for `bd-djejh.3`. It prepares evidence for
the journal and decision-composer beads, but it does not write the journal and
does not mutate beads, Agent Mail, rch, git, workers, or live queue policy.

## Sources

The watcher emits one normalized snapshot for each required source kind:

- `br_queue_snapshot_json`
- `bv_robot_plan_json`
- `agent_mail_snapshot_json`
- `rch_status_snapshot_json`
- `git_state_snapshot_json`
- `artifact_bundle_snapshot_json`

`br_queue_snapshot_json` represents the combined br ready, in-progress, and
blocked queue view. The script accepts a pre-composed fixture file through
`--br-queue-json`; live-lite collection may also collect read-only br queue
commands into that shape.

Agent Mail and rch status are input snapshots for this script. Missing,
degraded, or read-only states are recorded as source facts rather than hidden
success. Heavy Cargo work is never run.

## Outputs

The watcher writes these artifacts to `--output-dir`:

- `source_snapshots.jsonl`
- `source_snapshot_summary.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

Each source snapshot preserves source id, source kind, schema version, content
hash, collection timestamp, freshness window, freshness/degradation flags, raw
payload reference, local-fallback contamination state, and error codes.

## Decisions

- `pass`: all required sources are present, fresh, and non-degraded
- `degraded`: all required sources are present, but one or more report a
  degraded state that remains usable for advisory output
- `fail_closed`: a source is missing, stale, contradictory, malformed, or
  contaminated by rch local fallback

The watcher uses the exit 42 path after writing artifacts when the summary
decision is `fail_closed`.

## Validation

```bash
jq empty docs/swarm_autopilot_shadow_source_watchers_contract_v1.json scripts/testdata/swarm_autopilot_shadow_source_watchers/cases.json
bash -n scripts/swarm_autopilot_shadow_source_watchers.sh scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh
shellcheck -x scripts/swarm_autopilot_shadow_source_watchers.sh scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh
bash scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh check
bash scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh selftest
git diff --check -- docs/SWARM_AUTOPILOT_SHADOW_SOURCE_WATCHERS.md docs/swarm_autopilot_shadow_source_watchers_contract_v1.json scripts/swarm_autopilot_shadow_source_watchers.sh scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh scripts/testdata/swarm_autopilot_shadow_source_watchers/cases.json
```
