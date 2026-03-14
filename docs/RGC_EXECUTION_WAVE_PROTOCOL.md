# RGC Execution Wave Protocol v1

Status: active
Primary beads: `bd-1lsy.1.4`, `bd-1lsy.1.5`

## Purpose

Define deterministic multi-agent execution waves for the Reality Gap Closure
(RGC) program so work can proceed in parallel without overlap, deadlock, or
coordination stall.

This protocol codifies:

1. Wave-by-wave ownership and hard dependency boundaries.
2. File reservation and mailbox response timing rules.
3. Anti-stall escalation triggers.
4. Standardized handoff package format between waves.

## Wave Map

| Wave | Focus | Parallel lanes | Hard serial dependencies |
| --- | --- | --- | --- |
| `wave_0` | Program contract + coordination bootstrap | `bd-1lsy.1.1`, `bd-1lsy.1.4`, `bd-1lsy.1.5` | `bd-1lsy.1.2`, `bd-1lsy.1.3` |
| `wave_1` | Frontend language lanes | `bd-1lsy.2.1`, `bd-1lsy.3.1`, `bd-1lsy.2.2` | `bd-1lsy.2.4` |
| `wave_2` | Runtime/module/security core | `bd-1lsy.4.1`, `bd-1lsy.5.1`, `bd-1lsy.6.1` | `bd-1lsy.4.6` |
| `wave_3` | Performance + GA evidence | `bd-1lsy.7.1`, `bd-1lsy.8.1`, `bd-1lsy.10.4` | `bd-1lsy.10.9` |

Wave gating is strict: `wave_n` cannot enter until the prior wave handoff
packet is accepted.
Serialized protocol tags also use `wave_0`/`wave_1`/`wave_2`/`wave_3` exactly.

## File Reservation Protocol

1. Reserve files before edits.
2. Use exclusive reservations by default for source/test/script paths.
3. Minimum reservation TTL: `3600s`.
4. Renew reservations before `900s` remain.
5. Maximum paths per claim: `12`.
6. Publish claim + path scope in Agent Mail before first edit.

## Agent Mail Protocol

1. Poll inbox at least every `120s`.
2. Poll urgent queue at least every `30s`.
3. Acknowledge `ack_required=true` messages within `300s`.
4. Include bead ID in coordination subjects when possible.
5. Reply with concrete claim/path updates, not generic status-only messages.

## Anti-Stall Escalation Loop

Idle timer thresholds from last concrete progress event:

1. `warn` at `900s`.
2. `escalate` at `1800s`.
3. `reassign` at `2700s`.
4. `split` at `3600s`.

Escalation behavior:

1. `warn`: ask owner for precise blocker and ETA.
2. `escalate`: notify wave lead + adjacent lane owners.
3. `reassign`: transfer bead ownership with explicit handoff package.
4. `split`: split bead into unblockable sub-beads and requeue.

## Handoff Package Contract

Required fields:

1. `wave`
2. `from_owner`
3. `to_owner`
4. `changed_beads` (non-empty)
5. `artifact_links` (non-empty)
6. `open_risks`
7. `next_steps` (non-empty)

Minimum handoff quality rules (enforced by validator):

1. `from_owner` and `to_owner` must differ.
2. `changed_beads` must be unique and owned by the source wave
   (`wave_(n-1)` -> `wave_n`, or `wave_0` bootstrap for wave 0 handoff checks).
3. `artifact_links` must include the reproducibility triad:
   - `run_manifest.json`
   - `events.jsonl`
   - `commands.txt`
4. `next_steps` must include at least one explicit bead ID from the target wave.

## Message Templates

Claim template:

```text
Claimed <bead-id>, set in_progress, reserved paths: <path list>,
expected first update: <timestamp>
```

Conflict template:

```text
Conflict on <path/bead>. Holder: <agent>. Proposed resolution:
wait | share | split. Decision ETA: <timestamp>
```

Handoff template:

```text
Wave handoff <wave_x -> wave_y>
changed_beads: ...
artifacts: ...
open_risks: ...
next_steps: ...
```

## Deterministic Validation

Protocol + dry-run validation is implemented in:

- `crates/franken-engine/src/rgc_execution_waves.rs`
- `crates/franken-engine/tests/rgc_execution_waves_integration.rs`
- `crates/franken-engine/tests/rgc_execution_waves_enrichment_integration.rs`

Run gate (`rch` backed):

```bash
./scripts/run_rgc_execution_waves_coordination_suite.sh ci
```

The runner defaults heavy `CARGO_TARGET_DIR` output to the repo-local path
`.rch_target/rgc_execution_waves_uid<uid>_<mode>_<timestamp>_<pid>` rather than
shared `/tmp` state or a timestamp-only namespace, so parallel agent runs do
not collide on the same second.

Replay wrapper:

```bash
./scripts/e2e/rgc_execution_waves_coordination_replay.sh ci
```

Artifacts are emitted to:

- `artifacts/rgc_execution_waves_coordination/<timestamp>/run_manifest.json`
- `artifacts/rgc_execution_waves_coordination/<timestamp>/events.jsonl`
- `artifacts/rgc_execution_waves_coordination/<timestamp>/commands.txt`
- `artifacts/rgc_execution_waves_coordination/<timestamp>/step_logs/step_*.log`
