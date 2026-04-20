# Stateful Fuzzing Manifest

## State Machine Model

Stateful fuzzing targets transition-rich behavior by modeling execution as a deterministic
state machine over long-lived engine objects:

- `Idle`: no active campaign, ready to consume next seed and fixture corpus.
- `Seeded`: corpus entry selected and stateful preconditions captured.
- `Mutated`: deterministic transformation applied to input stream or state mutation schedule.
- `Run`: engine executes the mutation against a tracked runtime state snapshot.
- `Observed`: verdicts, telemetry, and state deltas sampled from instrumentation.
- `Reduced`: failing cases minimized to a minimal replay sequence.
- `Archived`: failing traces, environment, and minimized bundle committed to artifact storage.

Transitions are explicit and logged with: seed id, action id, previous state checksum,
next-state checksum, wall-clock and deterministic schedule stamps.

## Transition Coverage

Campaigns must cover transitions across:

- `Idle → Seeded` using all corpus partitions (valid, boundary, adversarial, replay-only).
- `Seeded → Mutated` for every mutation operator family in use.
- `Mutated → Run` over all supported execution lanes (parser, runtime, host, policy).
- `Run → Observed` where every execution path records at least one state diff.
- `Observed → Reduced` for every unique crash signature and invariant violation.
- `Observed → Archived` only with complete provenance metadata.
- Backward recovery `Observed/Reduced/Archived → Idle` to prevent cross-test state leakage.

Transition coverage metric is computed per tuple
`(source_state, target_state, lane, mutation_class)` and must include every supported
state-lane pair at least once in a weekly campaign.

## Invariant Monitors

Invariant monitoring is attached to state snapshots and event streams:

- Deterministic replay identity: same seed + same lane + same mutations yields identical run ids.
- State budget monotonicity: resource counters never increase after hard budget exhaustion.
- Isolation monotonicity: state visibility boundaries never expand across extension boundaries.
- Capability containment: revocation events remain terminal for descendants.
- Evidence invariance: replay logs, crash IDs, and state-diff hashes are stable under re-run.

Monitors emit structured violations with monitor name, transition context, witness
artifact id, and serialized counterexample before triage.

## Crash Taxonomy

All crashes are tagged into one primary taxonomy:

- `panic` — Rust-level unwinds and panic payloads with optional state-diff evidence.
- `assert` — invariant/assertion failures with violation traces and expected value snapshots.
- `panic_timeout` — scheduler or execution timeout producing incomplete but replayable state.
- `resource_violation` — OOM, budget overrun, queue starvation, or throughput collapse.
- `capability_breach` — state transition that violates access isolation or revocation semantics.
- `evidence_gap` — incomplete trace or missing checksum artifacts preventing replay.

Each crash record must include crash class, first-seen revision, reproducer seed, replay
command, and minimal transition prefix causing failure.

## Replay Bundle

Every campaign exports a replay bundle at campaign end:

- `MANIFEST.toml`: campaign metadata, seed schedule, mutation graph, and wall-clock schedule.
- `transitions.ndjson`: one row per observed transition and monitor probe.
- `state_diffs/`: canonical before/after state hashes and serialized deltas.
- `seed_map.csv`: deterministic mapping from failures to minimized seed sequence.
- `failures.json`: crash taxonomy summary plus first-reproducible witnesses.
- `replay.sh`: exact command sequence for rebuilding and re-running each archived failure.

Bundles are immutable after archiving and must remain downloadable for at least one full
release cycle.

## Replication Instructions

- **Prerequisites**: Record exact `git rev`, runtime, OS image, and compiler versions.
- **Reproducibility settings**: pin `CARGO_TARGET_DIR` and run with `CARGO_INCREMENTAL=0`.
- **Procedure**: Re-run the artifact generation and verification workflow from the same commit, capturing command output and logs.
- **Validation**: Compare generated artifacts to listed expectations and note environment drift with mitigation notes.
