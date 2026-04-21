# Concurrency Audit Round 2 - 2026-04-21

## Scope

Applied `/deadlock-finder-and-fixer` to non-baseline runtime surfaces, focusing on async-style cancellation semantics, channel senders/receivers, mutex patterns, and extension-host lifecycle hooks. This pass inspected:

- `crates/franken-engine/src/execution_cell.rs`
- `crates/franken-engine/src/extension_host_lifecycle.rs`
- `crates/franken-engine/src/cancellation_lifecycle.rs`
- `crates/franken-engine/src/session_hostcall_channel.rs`
- `crates/franken-engine/src/guardplane_adapter.rs`
- `crates/franken-engine/src/seqlock_fastpath.rs`

The audit favored concrete interleavings and ownership/lifecycle mismatches over broad grep findings.

## Findings Filed

### bd-20s7d - extension-host binding unload leaves session cells active

`ExtensionHostBinding::start_session` creates a child region under the extension and also inserts a separate manager cell keyed by raw `session_id` (`execution_cell.rs:812`, `execution_cell.rs:836`). `ExtensionHostBinding::unload_extension` then closes only the parent `extension_id` through `CellManager::close_cell` (`execution_cell.rs:857`, `execution_cell.rs:878`), and `CellManager::close_cell` removes only that requested key (`execution_cell.rs:619`, `execution_cell.rs:630`).

Concrete failure mode: load extension, start one or more sessions, call targeted `unload_extension("ext")`. The parent region's cloned child regions close, but the separately registered session cells remain in `CellManager`, so session work can outlive the parent extension lifecycle boundary.

Expected fix: track session ids per extension or derive them from manager state, close/archive child session cells before parent unload, and add a regression asserting no active cells remain after load + sessions + unload.

### bd-13887 - extension-host binding session ids collide across extensions

`ExtensionHostBinding::start_session` accepts a caller-provided `session_id` and inserts the session cell under that raw key (`execution_cell.rs:812`, `execution_cell.rs:836`). `CellManager::insert_cell` rejects duplicate active keys (`execution_cell.rs:581`, `execution_cell.rs:587`). The newer `ExtensionHostLifecycleManager` avoids this by deriving `{extension_id}::session::{session_id}` (`extension_host_lifecycle.rs:643`).

Concrete failure mode: two active extensions both start `sess-1`; one fails with `CellAlreadyExists`, and lifecycle operations against raw session ids lack an extension ownership boundary.

Expected fix: derive extension-scoped session cell IDs in `ExtensionHostBinding`, return/record the actual cell id, and add coexistence/unload regressions for two extensions using the same local session id.

### bd-3o4po - cancellation manager idempotency skips reused live cell ids

`CancellationManager::cancel_cell` returns synthetic success when `cancelled_cells` already contains the `cell_id`, before inspecting the current live cell (`cancellation_lifecycle.rs:338`). `CellManager::archive_cell` removes the active cell (`execution_cell.rs:603`), and `create_extension_cell` permits the same id again once inactive (`execution_cell.rs:552`). `cancel_managed_cell` still archives the current manager cell after receiving the idempotent outcome (`cancellation_lifecycle.rs:503`, `cancellation_lifecycle.rs:518`).

Concrete failure mode: cancel and archive `ext-1`, recreate a fresh `ext-1` with the same `CancellationManager`, then cancel it. The second cancellation reports `was_idempotent=true` and success without executing lifecycle effects, drain, or finalize for the new cell. Pending obligations can be hidden behind the synthetic close result.

Expected fix: key idempotency by cell generation/epoch or clear replacement state when a new generation is registered. Add a regression that recreates the same id with a pending obligation and verifies the second cancellation is non-idempotent.

### bd-2ra3d - session hostcall control signals verify after close and can replay

`SessionHostcallChannel::close_session` sets `SessionState::Closed` but leaves the session record (`session_hostcall_channel.rs:923`, `session_hostcall_channel.rs:944`). `authenticated_backpressure_signal` signs an envelope at `session.next_sequence` without incrementing or reserving that sequence (`session_hostcall_channel.rs:973`, `session_hostcall_channel.rs:998`). `verify_authenticated_signal` checks only `session_id` and MAC (`session_hostcall_channel.rs:1011`, `session_hostcall_channel.rs:1022`), with no `Established` state check, extension/host binding check, sequence consumption, or replay window.

Concrete failure mode: create an authenticated backpressure/control envelope, close the session, then verify the stale envelope repeatedly. Verification still succeeds, leaving a control-channel replay path across cancellation/lifecycle boundaries.

Expected fix: require `Established` state for verification, validate `extension_id` and `host_id`, consume/check a monotonic signal sequence or nonce, and add close+replay regressions.

## Notes

No code was changed in this audit. `guardplane_adapter` and `seqlock_fastpath` use mutexes, but this pass did not find a concrete lock-order deadlock or await-holding-lock issue in those surfaces. The actionable issues are lifecycle and channel-state bugs that become concurrency failures when extension/session work is interleaved across unload, cancellation, and control-message verification.
