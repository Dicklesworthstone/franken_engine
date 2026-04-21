# Concurrency Audit 2026-04-20

Scope:

- `crates/franken-engine/src/obligation_channel.rs`
- `crates/franken-engine/src/seqlock_fastpath.rs`
- `crates/franken-engine/src/monitor_scheduler.rs`
- `crates/franken-engine/src/epoch_barrier.rs`
- `crates/franken-engine/src/extension_host_lifecycle.rs`
- `crates/franken-engine/src/extension_lifecycle_manager.rs`

Method:

- Applied the `deadlock-finder-and-fixer` static audit guidance.
- Searched the targeted surfaces for locks, atomics, spin loops, channels, async awaits, database locks, and lifecycle state transitions.
- Filed only findings with a concrete interleaving or failure path.

## Findings

### `bd-9plq1` - HIGH - EpochBarrier permits duplicate guard release

`EpochGuard` derives `Clone`, but `EpochBarrier::release_guard` only checks that the guard epoch matches the current epoch and that `in_flight_count` is non-zero. The release path does not check `guard_id` uniqueness or mark a guard as consumed.

Evidence:

- `crates/franken-engine/src/epoch_barrier.rs:150` derives `Clone` for `EpochGuard`.
- `crates/franken-engine/src/epoch_barrier.rs:319` releases by borrowed guard without consuming it.
- `crates/franken-engine/src/epoch_barrier.rs:324` checks only aggregate count before decrementing.
- `crates/franken-engine/src/epoch_barrier.rs:384` and `crates/franken-engine/src/epoch_barrier.rs:392` allow transition completion when the aggregate count reaches zero.

Concrete interleaving:

1. Enter critical sections `g1` and `g2`; `in_flight_count == 2`.
2. Clone `g1`.
3. Begin epoch transition.
4. Release `g1`, then release the cloned `g1`.
5. `in_flight_count` reaches zero while `g2` is still executing under the old epoch.
6. `complete_transition` can advance the epoch, violating the no mixed-epoch critical-operation contract.

Fix direction: make epoch guards single-use and non-`Clone`, or track live guard IDs and reject duplicate releases. Add a regression test that duplicate release during `Draining` cannot complete a transition while another guard remains live.

### `bd-1ca9b` - HIGH - Extension host unload/cancel can clear sessions after failed session cancellation

`unload_extension` and `cancel_extension` attempt to cancel session cells before cancelling the extension cell, but the session loop silently ignores missing cells, non-running cells, and `cancel_cell` errors. The extension is then marked unloaded and the session set is cleared.

Evidence:

- `crates/franken-engine/src/extension_host_lifecycle.rs:285` starts the unload session cancellation loop.
- `crates/franken-engine/src/extension_host_lifecycle.rs:289` to `crates/franken-engine/src/extension_host_lifecycle.rs:294` only archives a session if lookup, state check, and cancellation all succeed.
- `crates/franken-engine/src/extension_host_lifecycle.rs:319` clears session bookkeeping after extension cancellation.
- `crates/franken-engine/src/extension_host_lifecycle.rs:509` repeats the same pattern in `cancel_extension`.
- `crates/franken-engine/src/extension_host_lifecycle.rs:543` clears session bookkeeping after generic cancellation.

Concrete failure path:

1. An extension has one or more tracked sessions.
2. A session cell is missing, not in `Running`, or returns an error from `cancel_cell`.
3. The loop records no error and does not archive that session cell.
4. The extension cell is cancelled and archived.
5. The extension record is marked unloaded and `sessions.clear()` removes the only bookkeeping for the failed session.

This violates the documented quiescent close ordering of draining in-flight work, awaiting quiescence, finalizing, and only then destroying lifecycle state.

Fix direction: fail closed or aggregate per-session cancellation errors before clearing bookkeeping. Add regression tests for a failing session cancellation and a missing session cell.

### `bd-1tkmh` - MEDIUM - SnapshotFastPath hook can self-deadlock on reentrant publish

`SnapshotFastPath::publish_with_hook` is `pub(crate)` and accepts an arbitrary `FnOnce`. It holds the non-recursive `writer_gate` mutex while invoking that callback. A crate-local caller can pass a hook that re-enters `publish` or `publish_with_hook` on the same `SnapshotFastPath`, causing the same thread to block forever trying to reacquire `writer_gate`.

Evidence:

- `crates/franken-engine/src/seqlock_fastpath.rs:154` exposes `publish_with_hook` at crate visibility.
- `crates/franken-engine/src/seqlock_fastpath.rs:158` acquires the writer gate.
- `crates/franken-engine/src/seqlock_fastpath.rs:170` invokes the callback before the writer guard is dropped.

Concrete interleaving:

1. A caller invokes `publish_with_hook` on a fast path.
2. `publish_with_hook` acquires `writer_gate` and marks the sequence odd.
3. The hook calls `publish` on the same fast path.
4. `publish` calls `publish_with_hook`, which attempts to acquire `writer_gate`.
5. The same thread waits on its own non-recursive mutex. Readers observe writer pressure until the blocked hook unwinds, which it never does.

Fix direction: restrict the hook to tests, enforce/document non-reentrancy, or move hook execution outside the writer-gate critical section. Add a regression guard for reentrant publish behavior.

## Clean Areas

- `obligation_channel.rs`: no locks, async waits, database calls, or channels in the audited implementation; state transitions require `&mut self`.
- `monitor_scheduler.rs`: no locks, async waits, database calls, or channels in the audited implementation; scheduling state is guarded by `&mut self`.
- `extension_lifecycle_manager.rs`: no locks, async waits, database calls, or channels in the audited implementation; lifecycle state transitions require `&mut self`.
- Targeted audit found no SQLite/database lock surfaces and no await-holding-lock patterns in the requested files.

## Beads Created

- `bd-9plq1`: `EpochBarrier permits duplicate guard release to undercount in-flight work`
- `bd-1ca9b`: `Extension host unload/cancel can clear sessions after failed session cancellation`
- `bd-1tkmh`: `SnapshotFastPath publish_with_hook can self-deadlock on reentrant publish`
