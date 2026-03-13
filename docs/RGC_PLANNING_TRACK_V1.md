# RGC Planning Track V1

Status: active
Primary bead: bd-1lsy.1
Track id: RGC-010
Machine-readable contract: `docs/rgc_planning_track_v1.json`

## Purpose

`RGC-010` is the planning control plane for the Reality Gap Closure program.
Its job is to freeze scope, define milestone stop or go rules, keep risk
acceptance explicit, and prevent wave handoffs from drifting into ambiguous
ownership.

This planning layer is executable by design:

- it emits the epic-level artifact filenames promised by `bd-1lsy.1`,
- it links every top-level planning artifact back to the already-versioned child
  planning contracts,
- it records structured transition events for scope, risk, milestone, and wave
  decisions,
- it fails closed when review freshness or `rch` cargo execution guarantees are
  violated.

## Input Contracts

The planning-track aggregate consumes four existing source contracts:

- `docs/rgc_executable_compatibility_target_matrix_v1.json`
- `docs/rgc_milestone_gatebook_v1.json`
- `docs/rgc_risk_register_v1.json`
- `docs/RGC_EXECUTION_WAVE_PROTOCOL.md` plus
  `docs/frx_handoff_packet_schema_v1.json`

Those artifacts remain the child-lane sources of truth. The planning-track
bundle does not replace them; it normalizes them into the parent-bead artifact
surface.

## Emitted Artifacts

The bundle emits the following files:

- `scope_contract_snapshot.json`
- `milestone_gatebook.json`
- `risk_acceptance_ledger.json`
- `wave_handoff_matrix.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `summary.md`
- `trace_ids`

The canonical replay wrapper is:

```bash
./scripts/e2e/run_rgc_planning_track.sh /tmp/rgc_planning_track_artifacts
```

## Fail-Closed Policies

Planning execution must fail closed under the following conditions:

- open-scope bead ordering becomes unsorted or duplicated,
- milestone order drifts away from `M1 -> M5`,
- any cargo-bearing gate or rollback command is not wrapped by `rch`,
- a risk acceptance entry is past `next_review_due_utc`,
- the wave handoff contract loses its artifact triad or target-wave next step.

The risk ledger treats `next_review_due_utc` as the acceptance expiry source of
truth. Once that timestamp is behind the bundle generation time, the
corresponding entry becomes `expired` and the ledger reports non-current state.

## Transition Logging

The structured transition event stream includes:

- `scope_contract_snapshot_built`
- `milestone_gatebook_verified`
- `risk_acceptance_review`
- `wave_handoff_validated`
- `planning_track_bundle_written`

Each event includes `trace_id`, `decision_id`, `policy_id`, `component`,
`event`, `outcome`, and optional `error_code`.

## Operator Verification

```bash
jq empty docs/rgc_planning_track_v1.json

rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_planning_track \
  cargo test -p frankenengine-engine --test rgc_planning_track_integration

./scripts/e2e/run_rgc_planning_track.sh /tmp/rgc_planning_track_artifacts
```
