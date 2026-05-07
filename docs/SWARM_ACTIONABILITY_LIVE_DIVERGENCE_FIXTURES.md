# SWARM_ACTIONABILITY_LIVE_DIVERGENCE_FIXTURES

`bd-30x14` preserves the live br/bv divergence observed after the V1
actionability contract landed.

Replay evidence only.
This fixture does not implement `scripts/swarm_actionability_truth_gate.sh`, does
not claim work, and does not change queue policy.

## Captured State

The fixture was captured on 2026-05-07T05:37:51Z in `/data/projects/franken_engine`.
`br sync --status --json` reported `db_newer=false` and `jsonl_newer=false`, so
the exported JSONL state was not stale.

`br ready` returned an empty array.
`bv --recipe actionable --robot-plan` still emitted four tracks:

- `bd-l4mya` as `in_progress`
- `bd-30x14` as `in_progress`
- `bd-5oef0` as `blocked`
- `bd-djejh.2` as `blocked`

The expected aggregate decision is `fail_closed`. In-progress candidates must
carry `FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE`; blocked candidates
must carry `FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE`.

## Artifacts

- `scripts/testdata/swarm_actionability_live_divergence/current_divergence.json`
- `scripts/e2e/swarm_actionability_live_divergence_fixture_smoke.sh`

The smoke gate checks source freshness, candidate status coverage, expected
reason codes, advisory-only mutation policy, and command capture hygiene.
