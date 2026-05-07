# SWARM Saturation Replay Drill

Machine-readable contract: `docs/swarm_saturation_replay_drill_contract_v1.json`

Smoke gate: `scripts/e2e/swarm_saturation_replay_drill_smoke.sh`

Fixture cases: `scripts/testdata/swarm_saturation_replay_drill/cases.json`

`scripts/swarm_saturation_replay_drill.sh` replays deterministic many-agent
admission scenarios for SWARM-OPS. It is fixture-fed and advisory-only.

## Purpose

The drill freezes a reproducible answer to a common operator question: how
should the swarm admit mixed heavy proof lanes, script checks, docs work, stale
ownership lanes, and urgent work when a host is saturated?

The report records before/after lane decisions, fairness accounting, proof
fanout caps, urgent slack preservation, local-fallback contamination handling,
and a stable replay hash.

## Fixture Coverage

The checked-in fixture bundle covers:

- `large_64c_256gb`: a 64-core/256GB class host admitting many concurrent lanes.
- `mid_size_mixed_fairness`: a mid-size host that defers repeated heavy work
  from the same agent before exceeding the fairness cap.
- `constrained_stale_ownership`: a constrained host that caps heavy fanout while
  still admitting script/docs lanes and surfacing stale or blocked ownership.
- `local_fallback_contaminated`: fail-closed local-fallback evidence with zero
  admitted lanes.

## Artifacts

Each run writes:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `saturation_replay_report.json`
- `trace_ids.json`

The replay hash is computed from the report after removing output-directory
paths, so repeated fixture runs are stable.

## Non-Mutation Policy

The drill does not execute build commands, invoke RCH, query live workers,
change beads, release reservations, send Agent Mail, change queue policy, mutate
remote workers, or repair target directories.

The optional live collection path is intentionally not implemented in this
bead. Any future live mode must keep heavy validation routed through the
repository RCH workflow and preserve this fixture replay surface.
