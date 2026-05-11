# Degraded Coordination No-Mock Drill

This drill composes the Agent Mail outage bridge, handoff capsule, objective
completion auditor, and high-core validation pressure dashboard under one
degraded coordination scenario.

The scenario is fixture-fed from preserved snapshots:

- Agent Mail health is red/corrupt.
- `br` has no ready beads for proof admission.
- The worktree snapshot contains both owned and unrelated dirty paths.
- RCH has an active remote proof job, but the drill does not start another one.
- The operator objective is broad enough to require concrete artifacts from all
  four component surfaces.

The drill is intentionally read-only. It does not repair Agent Mail, send Agent
Mail, claim or close beads, query live workers, run Cargo, run `rch exec`, or
mutate queue state. Component commands are invoked against checked-in snapshots
and their emitted artifacts are audited as the proof surface.

## Outputs

Each run emits:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `drill_report.json`
- `scenarios/<scenario_id>/steps/*/{stdout.log,stderr.log}`

Replay mode validates those artifacts without re-running component capture or
component commands. It checks JSON shape, the aggregate decision, component
artifact presence, and forbidden command patterns.

## Expected Decision

The default scenario must finish as `degraded_continue_source_only`: coordination
is degraded but safe, heavy proof admission is deferred, and source-only checks
remain allowed. The report must show:

- bridge decision `degraded`
- handoff decision `degraded`
- dashboard recommendation `split_file_blocker_bead`
- objective completion audit decision `complete`
- no executed Cargo, RCH, Agent Mail mutation, worker mutation, or Agent Mail DB
  repair command in the drill transcript
