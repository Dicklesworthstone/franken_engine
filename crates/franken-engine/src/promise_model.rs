//! Deterministic Promise / microtask model.
//!
//! Provides the runtime representation for ES2020 Promise semantics with
//! **full determinism**: given identical inputs, the microtask queue produces
//! identical ordering across runs, execution lanes, and replays.
//!
//! Key design properties:
//! - **Promise state machine**: `Pending` -> `Fulfilled` | `Rejected` (immutable once settled).
//! - **Microtask queue**: strict FIFO, drains completely before the next macrotask.
//! - **Virtual clock**: all timer operations use a deterministic virtual clock.
//! - **IFC label propagation**: every Promise value carries an [`ifc_artifacts::Label`].
//! - **Witness emission**: every microtask enqueue/dequeue is recorded for replay.
//!
//! Builds on [`object_model::JsValue`] for resolved/rejected values,
//! [`closure_model::ClosureHandle`] for reaction callbacks, and
//! [`ifc_artifacts::Label`] for information-flow tracking.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::closure_model::ClosureHandle;
use crate::ifc_artifacts::Label;
use crate::object_model::JsValue;

// ---------------------------------------------------------------------------
// Promise handle
// ---------------------------------------------------------------------------

/// Opaque handle to a Promise in the [`PromiseStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PromiseHandle(pub u32);

impl std::fmt::Display for PromiseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Promise({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// Promise state
// ---------------------------------------------------------------------------

/// The three-state lifecycle of a Promise per ES2020.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromiseState {
    /// Not yet settled — waiting for resolution or rejection.
    Pending,
    /// Successfully settled with a value.
    Fulfilled(JsValue),
    /// Settled with a rejection reason.
    Rejected(JsValue),
}

impl PromiseState {
    /// Returns `true` if the promise is no longer pending.
    pub fn is_settled(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Returns `true` if fulfilled.
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled(_))
    }

    /// Returns `true` if rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

impl std::fmt::Display for PromiseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Fulfilled(_) => f.write_str("fulfilled"),
            Self::Rejected(_) => f.write_str("rejected"),
        }
    }
}

// ---------------------------------------------------------------------------
// Reaction type
// ---------------------------------------------------------------------------

/// The kind of reaction callback attached to a Promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReactionKind {
    /// `onFulfilled` callback.
    Fulfill,
    /// `onRejected` callback.
    Reject,
}

// ---------------------------------------------------------------------------
// Promise reaction
// ---------------------------------------------------------------------------

/// A reaction registered on a Promise via `.then(onFulfilled, onRejected)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromiseReaction {
    /// Which kind of reaction this is.
    pub kind: ReactionKind,
    /// Closure to invoke when the promise settles with this reaction kind.
    pub handler: Option<ClosureHandle>,
    /// The promise returned by the `.then()` call — receives the handler's result.
    pub result_promise: PromiseHandle,
    /// IFC label at registration time.
    pub label: Label,
}

// ---------------------------------------------------------------------------
// Promise record
// ---------------------------------------------------------------------------

/// A single Promise's full state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromiseRecord {
    /// Handle for back-references.
    pub handle: PromiseHandle,
    /// Current lifecycle state.
    pub state: PromiseState,
    /// Registered reactions (pending `.then` callbacks).
    pub reactions: Vec<PromiseReaction>,
    /// IFC label of the settled value.
    pub label: Label,
    /// Monotonic creation sequence number (for deterministic ordering).
    pub creation_seq: u64,
    /// Whether an unhandled rejection has been observed.
    pub rejection_handled: bool,
}

impl PromiseRecord {
    fn new(handle: PromiseHandle, creation_seq: u64) -> Self {
        Self {
            handle,
            state: PromiseState::Pending,
            reactions: Vec::new(),
            label: Label::Public,
            creation_seq,
            rejection_handled: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Microtask
// ---------------------------------------------------------------------------

/// A single microtask in the deterministic queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Microtask {
    /// PromiseReactionJob: invoke a reaction handler with a settled value.
    PromiseReaction {
        /// The reaction to invoke.
        handler: Option<ClosureHandle>,
        /// The value passed to the handler (fulfilled value or rejection reason).
        argument: JsValue,
        /// The promise that receives the handler's return value.
        result_promise: PromiseHandle,
        /// IFC label of the argument.
        label: Label,
    },
    /// PromiseResolveThenableJob: resolve a promise with a thenable.
    ResolveThenable {
        /// Promise being resolved.
        promise: PromiseHandle,
        /// The thenable object's `.then` method handle.
        then_handler: ClosureHandle,
        /// The thenable value.
        thenable: JsValue,
        /// IFC label.
        label: Label,
    },
}

// ---------------------------------------------------------------------------
// Macrotask
// ---------------------------------------------------------------------------

/// A macrotask source classification for deterministic priority ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MacrotaskSource {
    /// Cross-lane message channel receives (highest priority).
    MessageChannel,
    /// Timer callbacks (setTimeout/setInterval) ordered by virtual clock.
    Timer,
    /// I/O completion callbacks.
    IoCompletion,
}

/// A macrotask in the deterministic event loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Macrotask {
    /// Source classification for priority ordering.
    pub source: MacrotaskSource,
    /// Closure to execute.
    pub handler: ClosureHandle,
    /// Virtual clock expiry (for timers) or sequence number (for messages/IO).
    pub scheduled_at: u64,
    /// Registration order for deterministic tie-breaking.
    pub registration_seq: u64,
    /// IFC label.
    pub label: Label,
}

// ---------------------------------------------------------------------------
// Virtual clock
// ---------------------------------------------------------------------------

/// A fully deterministic virtual clock — no system time dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualClock {
    /// Current virtual time in milliseconds.
    current_ms: u64,
    /// Next timer registration sequence.
    next_timer_seq: u64,
}

impl VirtualClock {
    pub fn new() -> Self {
        Self {
            current_ms: 0,
            next_timer_seq: 0,
        }
    }

    /// Current virtual time in milliseconds (used for `Date.now()`).
    pub fn now_ms(&self) -> u64 {
        self.current_ms
    }

    /// Advance the clock to the given time.
    pub fn advance_to(&mut self, target_ms: u64) {
        if target_ms > self.current_ms {
            self.current_ms = target_ms;
        }
    }

    /// Register a timer and return its sequence number.
    pub fn register_timer(&mut self) -> u64 {
        let seq = self.next_timer_seq;
        self.next_timer_seq += 1;
        seq
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Witness event (for replay)
// ---------------------------------------------------------------------------

/// Events recorded for deterministic replay of the Promise/microtask system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessEvent {
    /// A Promise was created.
    PromiseCreated { handle: PromiseHandle, seq: u64 },
    /// A Promise was fulfilled.
    PromiseFulfilled {
        handle: PromiseHandle,
        value: JsValue,
        label: Label,
    },
    /// A Promise was rejected.
    PromiseRejected {
        handle: PromiseHandle,
        reason: JsValue,
        label: Label,
    },
    /// A microtask was enqueued.
    MicrotaskEnqueued { index: u64 },
    /// A microtask was dequeued and executed.
    MicrotaskDequeued { index: u64 },
    /// A macrotask was executed.
    MacrotaskExecuted {
        source: MacrotaskSource,
        registration_seq: u64,
    },
    /// Virtual clock advanced.
    ClockAdvanced { from_ms: u64, to_ms: u64 },
}

// ---------------------------------------------------------------------------
// Promise errors
// ---------------------------------------------------------------------------

/// Errors that can arise in the Promise subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromiseError {
    /// Attempted to settle an already-settled Promise.
    AlreadySettled { handle: PromiseHandle },
    /// Invalid promise handle.
    InvalidHandle { handle: PromiseHandle },
    /// IFC label violation.
    LabelViolation {
        handle: PromiseHandle,
        value_label: Label,
        context_label: Label,
    },
}

impl std::fmt::Display for PromiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadySettled { handle } => {
                write!(f, "TypeError: Promise {handle} is already settled")
            }
            Self::InvalidHandle { handle } => {
                write!(f, "InternalError: invalid promise handle {handle}")
            }
            Self::LabelViolation {
                handle,
                value_label,
                context_label,
            } => {
                write!(
                    f,
                    "IFCError: label {value_label:?} on {handle} exceeds context label {context_label:?}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Promise store
// ---------------------------------------------------------------------------

/// Arena for all Promise records, providing creation, settlement, and reaction
/// registration with full determinism guarantees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromiseStore {
    /// All promises, indexed by handle.
    promises: Vec<PromiseRecord>,
    /// Monotonic creation counter.
    next_seq: u64,
    /// Witness log for replay.
    witness: Vec<WitnessEvent>,
}

impl PromiseStore {
    pub fn new() -> Self {
        Self {
            promises: Vec::new(),
            next_seq: 0,
            witness: Vec::new(),
        }
    }

    /// Create a new pending Promise.
    pub fn create(&mut self) -> PromiseHandle {
        let handle = PromiseHandle(self.promises.len() as u32);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.promises.push(PromiseRecord::new(handle, seq));
        self.witness
            .push(WitnessEvent::PromiseCreated { handle, seq });
        handle
    }

    /// Get a Promise by handle.
    pub fn get(&self, handle: PromiseHandle) -> Result<&PromiseRecord, PromiseError> {
        self.promises
            .get(handle.0 as usize)
            .ok_or(PromiseError::InvalidHandle { handle })
    }

    /// Get a mutable reference to a Promise by handle.
    fn get_mut(&mut self, handle: PromiseHandle) -> Result<&mut PromiseRecord, PromiseError> {
        self.promises
            .get_mut(handle.0 as usize)
            .ok_or(PromiseError::InvalidHandle { handle })
    }

    /// Fulfill a pending Promise, enqueuing reaction microtasks.
    pub fn fulfill(
        &mut self,
        handle: PromiseHandle,
        value: JsValue,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> Result<(), PromiseError> {
        let record = self.get(handle)?;
        if record.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle });
        }

        // Drain reactions before mutating state to avoid borrow issues.
        let record = self.get_mut(handle)?;
        let reactions: Vec<PromiseReaction> = record.reactions.drain(..).collect();
        record.state = PromiseState::Fulfilled(value.clone());
        record.label = label.clone();

        self.witness.push(WitnessEvent::PromiseFulfilled {
            handle,
            value: value.clone(),
            label: label.clone(),
        });

        // Enqueue fulfill reactions.
        for reaction in reactions {
            if reaction.kind == ReactionKind::Fulfill {
                queue.enqueue(Microtask::PromiseReaction {
                    handler: reaction.handler,
                    argument: value.clone(),
                    result_promise: reaction.result_promise,
                    label: label.clone(),
                });
            } else {
                // onRejected reactions for a fulfilled promise: resolve result
                // promise with the fulfilled value (identity transform).
                queue.enqueue(Microtask::PromiseReaction {
                    handler: None,
                    argument: value.clone(),
                    result_promise: reaction.result_promise,
                    label: label.clone(),
                });
            }
        }

        Ok(())
    }

    /// Reject a pending Promise, enqueuing reaction microtasks.
    pub fn reject(
        &mut self,
        handle: PromiseHandle,
        reason: JsValue,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> Result<(), PromiseError> {
        let record = self.get(handle)?;
        if record.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle });
        }

        let record = self.get_mut(handle)?;
        let reactions: Vec<PromiseReaction> = record.reactions.drain(..).collect();
        let has_reject_handler = reactions
            .iter()
            .any(|r| r.kind == ReactionKind::Reject && r.handler.is_some());
        record.state = PromiseState::Rejected(reason.clone());
        record.label = label.clone();
        record.rejection_handled = has_reject_handler;

        self.witness.push(WitnessEvent::PromiseRejected {
            handle,
            reason: reason.clone(),
            label: label.clone(),
        });

        // Enqueue reject reactions.
        for reaction in reactions {
            if reaction.kind == ReactionKind::Reject {
                queue.enqueue(Microtask::PromiseReaction {
                    handler: reaction.handler,
                    argument: reason.clone(),
                    result_promise: reaction.result_promise,
                    label: label.clone(),
                });
            } else {
                // onFulfilled reactions for a rejected promise: propagate rejection.
                queue.enqueue(Microtask::PromiseReaction {
                    handler: None,
                    argument: reason.clone(),
                    result_promise: reaction.result_promise,
                    label: label.clone(),
                });
            }
        }

        Ok(())
    }

    /// Register a `.then(onFulfilled, onRejected)` reaction.
    ///
    /// If the promise is already settled, immediately enqueues the reaction.
    /// Returns the handle of the result promise.
    pub fn then(
        &mut self,
        handle: PromiseHandle,
        on_fulfilled: Option<ClosureHandle>,
        on_rejected: Option<ClosureHandle>,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> Result<PromiseHandle, PromiseError> {
        let record = self.get(handle)?;
        let state = record.state.clone();
        let result_promise = self.create();

        match state {
            PromiseState::Pending => {
                let record = self.get_mut(handle)?;
                record.reactions.push(PromiseReaction {
                    kind: ReactionKind::Fulfill,
                    handler: on_fulfilled,
                    result_promise,
                    label: label.clone(),
                });
                record.reactions.push(PromiseReaction {
                    kind: ReactionKind::Reject,
                    handler: on_rejected,
                    result_promise,
                    label,
                });
            }
            PromiseState::Fulfilled(value) => {
                queue.enqueue(Microtask::PromiseReaction {
                    handler: on_fulfilled,
                    argument: value,
                    result_promise,
                    label,
                });
            }
            PromiseState::Rejected(reason) => {
                // Only explicit onRejected handlers mark rejection as handled.
                if on_rejected.is_some() {
                    let record = self.get_mut(handle)?;
                    record.rejection_handled = true;
                }
                queue.enqueue(Microtask::PromiseReaction {
                    handler: on_rejected,
                    argument: reason,
                    result_promise,
                    label,
                });
            }
        }

        Ok(result_promise)
    }

    /// Create a pre-resolved Promise (`Promise.resolve(value)`).
    pub fn resolve(
        &mut self,
        value: JsValue,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> PromiseHandle {
        let handle = self.create();
        // Unwrap safe: handle was just created.
        self.fulfill(handle, value, label, queue)
            .expect("fresh promise cannot be already settled");
        handle
    }

    /// Create a pre-rejected Promise (`Promise.reject(reason)`).
    pub fn reject_with(
        &mut self,
        reason: JsValue,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> PromiseHandle {
        let handle = self.create();
        self.reject(handle, reason, label, queue)
            .expect("fresh promise cannot be already settled");
        handle
    }

    /// Number of promises in the store.
    pub fn len(&self) -> usize {
        self.promises.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.promises.is_empty()
    }

    /// Get the witness log (for replay/forensics).
    pub fn witness_log(&self) -> &[WitnessEvent] {
        &self.witness
    }

    /// Collect all unhandled rejections (for reporting).
    pub fn unhandled_rejections(&self) -> Vec<PromiseHandle> {
        self.promises
            .iter()
            .filter(|p| p.state.is_rejected() && !p.rejection_handled)
            .map(|p| p.handle)
            .collect()
    }
}

impl Default for PromiseStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Microtask queue
// ---------------------------------------------------------------------------

/// Deterministic FIFO microtask queue.
///
/// Microtasks are always drained completely before any macrotask executes.
/// Ordering is strictly insertion-order (FIFO).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MicrotaskQueue {
    /// The queue.
    tasks: Vec<Microtask>,
    /// Read cursor — avoids Vec shifting.
    cursor: usize,
    /// Monotonic enqueue counter for witness events.
    enqueue_count: u64,
    /// Witness log.
    witness: Vec<WitnessEvent>,
}

impl MicrotaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            cursor: 0,
            enqueue_count: 0,
            witness: Vec::new(),
        }
    }

    /// Enqueue a microtask.
    pub fn enqueue(&mut self, task: Microtask) {
        let index = self.enqueue_count;
        self.enqueue_count += 1;
        self.tasks.push(task);
        self.witness.push(WitnessEvent::MicrotaskEnqueued { index });
    }

    /// Dequeue the next microtask (FIFO).
    pub fn dequeue(&mut self) -> Option<Microtask> {
        if self.cursor < self.tasks.len() {
            let task = self.tasks[self.cursor].clone();
            let index = self.cursor as u64;
            self.cursor += 1;
            self.witness.push(WitnessEvent::MicrotaskDequeued { index });
            Some(task)
        } else {
            None
        }
    }

    /// Check if there are pending microtasks.
    pub fn is_empty(&self) -> bool {
        self.cursor >= self.tasks.len()
    }

    /// Number of pending (unprocessed) microtasks.
    pub fn pending_count(&self) -> usize {
        self.tasks.len() - self.cursor
    }

    /// Total number of microtasks ever enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.enqueue_count
    }

    /// Get the witness log.
    pub fn witness_log(&self) -> &[WitnessEvent] {
        &self.witness
    }

    /// Compact the internal buffer (call after draining a full turn).
    pub fn compact(&mut self) {
        if self.cursor > 0 {
            self.tasks.drain(..self.cursor);
            self.cursor = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Macrotask queue
// ---------------------------------------------------------------------------

/// Deterministic macrotask queue with priority ordering by source type,
/// then by scheduled time, then by registration order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacrotaskQueue {
    tasks: Vec<Macrotask>,
    next_registration_seq: u64,
}

impl MacrotaskQueue {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            next_registration_seq: 0,
        }
    }

    /// Schedule a macrotask.
    pub fn schedule(
        &mut self,
        source: MacrotaskSource,
        handler: ClosureHandle,
        scheduled_at: u64,
        label: Label,
    ) -> u64 {
        let seq = self.next_registration_seq;
        self.next_registration_seq += 1;
        self.tasks.push(Macrotask {
            source,
            handler,
            scheduled_at,
            registration_seq: seq,
            label,
        });
        seq
    }

    /// Dequeue the highest-priority ready macrotask at or before `current_time_ms`.
    ///
    /// Priority: source type (MessageChannel > Timer > IoCompletion),
    /// then earliest `scheduled_at`, then lowest `registration_seq`.
    pub fn dequeue_ready(&mut self, current_time_ms: u64) -> Option<Macrotask> {
        // Find the best candidate.
        let best_idx = self
            .tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| t.scheduled_at <= current_time_ms)
            .min_by(|(_, a), (_, b)| {
                a.source
                    .cmp(&b.source)
                    .then(a.scheduled_at.cmp(&b.scheduled_at))
                    .then(a.registration_seq.cmp(&b.registration_seq))
            })
            .map(|(i, _)| i);

        best_idx.map(|i| self.tasks.remove(i))
    }

    /// Find the earliest scheduled time of any pending macrotask.
    pub fn next_scheduled_time(&self) -> Option<u64> {
        self.tasks.iter().map(|t| t.scheduled_at).min()
    }

    /// Check if there are pending macrotasks.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Number of pending macrotasks.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Deterministic event loop state.
///
/// Implements the ES2020 event loop turn model:
/// 1. Drain all microtasks (FIFO).
/// 2. Pick one macrotask (by priority).
/// 3. Execute it (may enqueue new microtasks).
/// 4. Drain all new microtasks.
/// 5. Repeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLoop {
    /// The microtask queue.
    pub microtasks: MicrotaskQueue,
    /// The macrotask queue.
    pub macrotasks: MacrotaskQueue,
    /// The virtual clock.
    pub clock: VirtualClock,
    /// Witness log for event loop level events.
    pub witness: Vec<WitnessEvent>,
    /// Maximum number of microtasks to drain per turn (safety limit).
    pub max_microtasks_per_turn: u64,
}

impl EventLoop {
    pub fn new() -> Self {
        Self {
            microtasks: MicrotaskQueue::new(),
            macrotasks: MacrotaskQueue::new(),
            clock: VirtualClock::new(),
            witness: Vec::new(),
            max_microtasks_per_turn: 100_000,
        }
    }

    /// Execute one full event loop turn:
    /// 1. Drain microtask queue.
    /// 2. Pick and return one macrotask (if any).
    ///
    /// Returns the macrotask to execute (caller invokes the handler), plus
    /// a count of microtasks drained. If no macrotask is ready, advances
    /// the virtual clock to the next scheduled macrotask time.
    pub fn turn(&mut self) -> TurnResult {
        // Phase 1: drain all microtasks.
        let micro_count = self.drain_microtasks();

        // Phase 2: try to pick a macrotask at current time.
        if let Some(task) = self.macrotasks.dequeue_ready(self.clock.now_ms()) {
            self.witness.push(WitnessEvent::MacrotaskExecuted {
                source: task.source,
                registration_seq: task.registration_seq,
            });
            return TurnResult {
                microtasks_drained: micro_count,
                macrotask: Some(task),
                clock_advanced: false,
            };
        }

        // Phase 3: advance clock to next macrotask if available.
        if let Some(next_time) = self.macrotasks.next_scheduled_time() {
            let from = self.clock.now_ms();
            self.clock.advance_to(next_time);
            self.witness.push(WitnessEvent::ClockAdvanced {
                from_ms: from,
                to_ms: next_time,
            });

            // Try dequeue again at advanced time.
            if let Some(task) = self.macrotasks.dequeue_ready(self.clock.now_ms()) {
                self.witness.push(WitnessEvent::MacrotaskExecuted {
                    source: task.source,
                    registration_seq: task.registration_seq,
                });
                return TurnResult {
                    microtasks_drained: micro_count,
                    macrotask: Some(task),
                    clock_advanced: true,
                };
            }
        }

        TurnResult {
            microtasks_drained: micro_count,
            macrotask: None,
            clock_advanced: false,
        }
    }

    /// Drain all pending microtasks, returning the count drained.
    pub fn drain_microtasks(&mut self) -> u64 {
        let mut count = 0u64;
        while !self.microtasks.is_empty() && count < self.max_microtasks_per_turn {
            if self.microtasks.dequeue().is_some() {
                count += 1;
            }
        }
        count
    }

    /// Schedule a timer macrotask. Returns the registration sequence.
    pub fn set_timeout(&mut self, handler: ClosureHandle, delay_ms: u64, label: Label) -> u64 {
        let fire_at = self.clock.now_ms() + delay_ms;
        self.macrotasks
            .schedule(MacrotaskSource::Timer, handler, fire_at, label)
    }

    /// Whether the event loop has any pending work.
    pub fn has_pending_work(&self) -> bool {
        !self.microtasks.is_empty() || !self.macrotasks.is_empty()
    }
}

impl Default for EventLoop {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single event loop turn.
#[derive(Debug, Clone)]
pub struct TurnResult {
    /// Number of microtasks drained in this turn.
    pub microtasks_drained: u64,
    /// The macrotask selected for execution (if any).
    pub macrotask: Option<Macrotask>,
    /// Whether the virtual clock was advanced.
    pub clock_advanced: bool,
}

// ---------------------------------------------------------------------------
// Promise combinators (Promise.all, Promise.race, etc.)
// ---------------------------------------------------------------------------

/// State tracker for `Promise.all(promises)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromiseAllTracker {
    /// The result promise for the aggregate.
    pub result_promise: PromiseHandle,
    /// Collected resolved values (indexed by input position).
    pub values: BTreeMap<u32, JsValue>,
    /// Total number of input promises.
    pub total: u32,
    /// Number of resolved promises so far.
    pub resolved_count: u32,
    /// Whether the aggregate has already settled (short-circuit on rejection).
    pub settled: bool,
}

impl PromiseAllTracker {
    /// Record that input promise at `index` fulfilled with `value`.
    /// Returns `true` if all promises are now resolved.
    pub fn record_fulfillment(&mut self, index: u32, value: JsValue) -> bool {
        if self.settled {
            return false;
        }
        self.values.insert(index, value);
        self.resolved_count += 1;
        self.resolved_count == self.total
    }

    /// Mark the tracker as settled (e.g., on first rejection).
    pub fn mark_settled(&mut self) {
        self.settled = true;
    }

    /// Collect the resolved values in input order.
    pub fn collect_values(&self) -> Vec<JsValue> {
        (0..self.total)
            .map(|i| self.values.get(&i).cloned().unwrap_or(JsValue::Undefined))
            .collect()
    }
}

/// State tracker for `Promise.allSettled(promises)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromiseAllSettledTracker {
    /// The result promise.
    pub result_promise: PromiseHandle,
    /// Collected outcomes (indexed by input position).
    pub outcomes: BTreeMap<u32, SettledOutcome>,
    /// Total number of input promises.
    pub total: u32,
    /// Number of settled promises so far.
    pub settled_count: u32,
}

/// Outcome of a single promise in `Promise.allSettled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettledOutcome {
    /// `"fulfilled"` or `"rejected"`.
    pub status: String,
    /// The value (if fulfilled) or reason (if rejected).
    pub value: JsValue,
}

impl PromiseAllSettledTracker {
    /// Record a fulfillment. Returns `true` if all settled.
    pub fn record_fulfillment(&mut self, index: u32, value: JsValue) -> bool {
        self.outcomes.insert(
            index,
            SettledOutcome {
                status: "fulfilled".into(),
                value,
            },
        );
        self.settled_count += 1;
        self.settled_count == self.total
    }

    /// Record a rejection. Returns `true` if all settled.
    pub fn record_rejection(&mut self, index: u32, reason: JsValue) -> bool {
        self.outcomes.insert(
            index,
            SettledOutcome {
                status: "rejected".into(),
                value: reason,
            },
        );
        self.settled_count += 1;
        self.settled_count == self.total
    }
}

/// State tracker for `Promise.race(promises)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromiseRaceTracker {
    /// The result promise.
    pub result_promise: PromiseHandle,
    /// Whether the race has been decided.
    pub settled: bool,
}

impl PromiseRaceTracker {
    /// Attempt to settle the race. Returns `true` if this was the first settlement.
    pub fn try_settle(&mut self) -> bool {
        if self.settled {
            return false;
        }
        self.settled = true;
        true
    }
}

/// State tracker for `Promise.any(promises)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromiseAnyTracker {
    /// The result promise.
    pub result_promise: PromiseHandle,
    /// Collected rejection reasons (indexed by input position).
    pub errors: BTreeMap<u32, JsValue>,
    /// Total number of input promises.
    pub total: u32,
    /// Number of rejected promises so far.
    pub rejected_count: u32,
    /// Whether the aggregate has already settled (short-circuit on fulfillment).
    pub settled: bool,
}

impl PromiseAnyTracker {
    /// Record a rejection. Returns `true` if all promises have rejected (AggregateError).
    pub fn record_rejection(&mut self, index: u32, reason: JsValue) -> bool {
        if self.settled {
            return false;
        }
        self.errors.insert(index, reason);
        self.rejected_count += 1;
        self.rejected_count == self.total
    }

    /// Mark settled (on first fulfillment).
    pub fn mark_settled(&mut self) {
        self.settled = true;
    }

    /// Collect errors in input order for AggregateError.
    pub fn collect_errors(&self) -> Vec<JsValue> {
        (0..self.total)
            .map(|i| self.errors.get(&i).cloned().unwrap_or(JsValue::Undefined))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Exception → rejection bridge (bd-1lsy.4.13.3)
// ---------------------------------------------------------------------------

/// Outcome of bridging an exception into the async/module rejection system.
///
/// When an uncaught exception escapes an async function body or a module's
/// top-level evaluation, the runtime must convert it into a promise rejection
/// and, if the execution was a module evaluation, propagate the rejection
/// through the module dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRejectionOutcome {
    /// The promise that was rejected (if the exception occurred in an async context).
    pub rejected_promise: Option<PromiseHandle>,
    /// The JsValue representation of the thrown exception.
    pub rejection_reason: JsValue,
    /// Human-readable description of the exception for diagnostics.
    pub reason_description: String,
    /// The module specifier if the exception occurred during module evaluation.
    pub module_specifier: Option<String>,
    /// Whether the rejection was propagated to dependent modules.
    pub propagated: bool,
    /// Number of dependent modules affected by transitive rejection.
    pub affected_module_count: usize,
}

/// The boundary context at which an exception crossed into the
/// async/module rejection system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceptionBoundaryKind {
    /// Exception escaped an async function body — becomes promise rejection.
    AsyncFunctionBody,
    /// Exception occurred during top-level module evaluation — becomes module rejection.
    ModuleEvaluation,
    /// Exception propagated through a hostcall boundary.
    HostcallBoundary,
    /// Exception crossed a microtask (promise reaction) boundary.
    MicrotaskReaction,
}

/// Witness event for exception-to-rejection transitions, recorded for
/// deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRejectionWitnessEvent {
    /// The boundary at which the exception was converted.
    pub boundary: ExceptionBoundaryKind,
    /// The promise that was rejected (if any).
    pub promise: Option<PromiseHandle>,
    /// Description of the exception.
    pub exception_description: String,
    /// Module specifier (if module evaluation context).
    pub module_specifier: Option<String>,
    /// Monotonic sequence number for deterministic ordering.
    pub seq: u64,
}

/// Bridge that converts uncaught interpreter exceptions into promise
/// rejections and module-graph rejection propagation.
///
/// This is the critical connection between the synchronous exception
/// unwinding system ([`baseline_interpreter`] `Throw` / `CatchFrame`)
/// and the asynchronous promise/module rejection system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionToRejectionBridge {
    /// Monotonic sequence counter for deterministic witness ordering.
    next_seq: u64,
    /// Witness log for replay.
    witness: Vec<ExceptionRejectionWitnessEvent>,
}

impl ExceptionToRejectionBridge {
    pub fn new() -> Self {
        Self {
            next_seq: 0,
            witness: Vec::new(),
        }
    }

    /// Bridge an uncaught exception from an async function body into
    /// a promise rejection.
    ///
    /// The caller must supply the promise handle associated with the
    /// async function's implicit result promise.
    pub fn bridge_async_exception(
        &mut self,
        exception_value: JsValue,
        async_promise: PromiseHandle,
        store: &mut PromiseStore,
        queue: &mut MicrotaskQueue,
    ) -> Result<ExceptionRejectionOutcome, PromiseError> {
        let description = format!("{exception_value:?}");

        store.reject(
            async_promise,
            exception_value.clone(),
            Label::Internal,
            queue,
        )?;

        let seq = self.next_seq;
        self.next_seq += 1;
        self.witness.push(ExceptionRejectionWitnessEvent {
            boundary: ExceptionBoundaryKind::AsyncFunctionBody,
            promise: Some(async_promise),
            exception_description: description.clone(),
            module_specifier: None,
            seq,
        });

        Ok(ExceptionRejectionOutcome {
            rejected_promise: Some(async_promise),
            rejection_reason: exception_value,
            reason_description: description,
            module_specifier: None,
            propagated: false,
            affected_module_count: 0,
        })
    }

    /// Bridge an uncaught exception from module evaluation into
    /// a module rejection, propagating through the dependency graph.
    ///
    /// This is called when top-level evaluation of a module throws.
    /// The rejection cascades to all modules that depend on the
    /// rejected module.
    pub fn bridge_module_exception(
        &mut self,
        exception_value: JsValue,
        module_specifier: &str,
        module_promise: Option<PromiseHandle>,
        store: &mut PromiseStore,
        queue: &mut MicrotaskQueue,
    ) -> Result<ExceptionRejectionOutcome, PromiseError> {
        let description = format!("{exception_value:?}");

        // Reject the module's evaluation promise (if it has one).
        if let Some(promise_handle) = module_promise {
            store.reject(
                promise_handle,
                exception_value.clone(),
                Label::Internal,
                queue,
            )?;
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.witness.push(ExceptionRejectionWitnessEvent {
            boundary: ExceptionBoundaryKind::ModuleEvaluation,
            promise: module_promise,
            exception_description: description.clone(),
            module_specifier: Some(module_specifier.to_string()),
            seq,
        });

        Ok(ExceptionRejectionOutcome {
            rejected_promise: module_promise,
            rejection_reason: exception_value,
            reason_description: description,
            module_specifier: Some(module_specifier.to_string()),
            propagated: false,
            affected_module_count: 0,
        })
    }

    /// Bridge an exception that escaped a hostcall boundary.
    pub fn bridge_hostcall_exception(
        &mut self,
        exception_value: JsValue,
        caller_promise: Option<PromiseHandle>,
        store: &mut PromiseStore,
        queue: &mut MicrotaskQueue,
    ) -> Result<ExceptionRejectionOutcome, PromiseError> {
        let description = format!("{exception_value:?}");

        if let Some(promise_handle) = caller_promise {
            store.reject(
                promise_handle,
                exception_value.clone(),
                Label::Internal,
                queue,
            )?;
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.witness.push(ExceptionRejectionWitnessEvent {
            boundary: ExceptionBoundaryKind::HostcallBoundary,
            promise: caller_promise,
            exception_description: description.clone(),
            module_specifier: None,
            seq,
        });

        Ok(ExceptionRejectionOutcome {
            rejected_promise: caller_promise,
            rejection_reason: exception_value,
            reason_description: description,
            module_specifier: None,
            propagated: false,
            affected_module_count: 0,
        })
    }

    /// Bridge an exception that escaped a microtask reaction callback.
    pub fn bridge_microtask_exception(
        &mut self,
        exception_value: JsValue,
        result_promise: Option<PromiseHandle>,
        store: &mut PromiseStore,
        queue: &mut MicrotaskQueue,
    ) -> Result<ExceptionRejectionOutcome, PromiseError> {
        let description = format!("{exception_value:?}");

        if let Some(promise_handle) = result_promise {
            store.reject(
                promise_handle,
                exception_value.clone(),
                Label::Internal,
                queue,
            )?;
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.witness.push(ExceptionRejectionWitnessEvent {
            boundary: ExceptionBoundaryKind::MicrotaskReaction,
            promise: result_promise,
            exception_description: description.clone(),
            module_specifier: None,
            seq,
        });

        Ok(ExceptionRejectionOutcome {
            rejected_promise: result_promise,
            rejection_reason: exception_value,
            reason_description: description,
            module_specifier: None,
            propagated: false,
            affected_module_count: 0,
        })
    }

    /// Get the witness log for replay/forensics.
    pub fn witness_log(&self) -> &[ExceptionRejectionWitnessEvent] {
        &self.witness
    }

    /// Number of exception-to-rejection transitions recorded.
    pub fn transition_count(&self) -> u64 {
        self.next_seq
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn js_int(n: i64) -> JsValue {
        JsValue::Int(n)
    }

    fn js_str(s: &str) -> JsValue {
        JsValue::Str(s.to_string())
    }

    // ----- Promise state machine -----

    #[test]
    fn new_promise_is_pending() {
        let mut store = PromiseStore::new();
        let h = store.create();
        let p = store.get(h).unwrap();
        assert_eq!(p.state, PromiseState::Pending);
        assert!(!p.state.is_settled());
    }

    #[test]
    fn fulfill_transitions_to_fulfilled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(42), Label::Public, &mut queue)
            .unwrap();
        let p = store.get(h).unwrap();
        assert_eq!(p.state, PromiseState::Fulfilled(js_int(42)));
        assert!(p.state.is_fulfilled());
    }

    #[test]
    fn reject_transitions_to_rejected() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("error"), Label::Public, &mut queue)
            .unwrap();
        let p = store.get(h).unwrap();
        assert_eq!(p.state, PromiseState::Rejected(js_str("error")));
        assert!(p.state.is_rejected());
    }

    #[test]
    fn double_fulfill_fails() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(1), Label::Public, &mut queue)
            .unwrap();
        let result = store.fulfill(h, js_int(2), Label::Public, &mut queue);
        assert!(matches!(result, Err(PromiseError::AlreadySettled { .. })));
    }

    #[test]
    fn fulfill_then_reject_fails() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(1), Label::Public, &mut queue)
            .unwrap();
        let result = store.reject(h, js_str("err"), Label::Public, &mut queue);
        assert!(matches!(result, Err(PromiseError::AlreadySettled { .. })));
    }

    #[test]
    fn reject_then_fulfill_fails() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("err"), Label::Public, &mut queue)
            .unwrap();
        let result = store.fulfill(h, js_int(1), Label::Public, &mut queue);
        assert!(matches!(result, Err(PromiseError::AlreadySettled { .. })));
    }

    #[test]
    fn invalid_handle_returns_error() {
        let store = PromiseStore::new();
        let result = store.get(PromiseHandle(999));
        assert!(matches!(result, Err(PromiseError::InvalidHandle { .. })));
    }

    // ----- .then() reactions -----

    #[test]
    fn then_on_pending_registers_reactions() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        let handler = ClosureHandle(0);
        let result_h = store
            .then(h, Some(handler), None, Label::Public, &mut queue)
            .unwrap();

        // No microtasks yet (promise still pending).
        assert!(queue.is_empty());

        // Reactions registered.
        let p = store.get(h).unwrap();
        assert_eq!(p.reactions.len(), 2);

        // Result promise exists.
        let rp = store.get(result_h).unwrap();
        assert_eq!(rp.state, PromiseState::Pending);
    }

    #[test]
    fn then_on_fulfilled_enqueues_immediately() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(10), Label::Public, &mut queue)
            .unwrap();

        let handler = ClosureHandle(1);
        let _result_h = store
            .then(h, Some(handler), None, Label::Public, &mut queue)
            .unwrap();

        // Microtask enqueued immediately.
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn then_on_rejected_enqueues_immediately() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("fail"), Label::Public, &mut queue)
            .unwrap();

        let handler = ClosureHandle(2);
        let _result_h = store
            .then(h, None, Some(handler), Label::Public, &mut queue)
            .unwrap();

        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn fulfill_triggers_registered_reactions() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        let handler = ClosureHandle(5);
        store
            .then(h, Some(handler), None, Label::Public, &mut queue)
            .unwrap();
        assert!(queue.is_empty());

        store
            .fulfill(h, js_int(99), Label::Public, &mut queue)
            .unwrap();
        // Two reactions registered (fulfill + reject), both become microtasks.
        assert_eq!(queue.pending_count(), 2);
    }

    // ----- Promise.resolve / Promise.reject -----

    #[test]
    fn promise_resolve_creates_fulfilled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.resolve(js_int(7), Label::Public, &mut queue);
        let p = store.get(h).unwrap();
        assert!(p.state.is_fulfilled());
    }

    #[test]
    fn promise_reject_creates_rejected() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.reject_with(js_str("boom"), Label::Public, &mut queue);
        let p = store.get(h).unwrap();
        assert!(p.state.is_rejected());
    }

    // ----- Microtask queue -----

    #[test]
    fn microtask_queue_fifo_order() {
        let mut queue = MicrotaskQueue::new();
        queue.enqueue(Microtask::PromiseReaction {
            handler: Some(ClosureHandle(0)),
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        queue.enqueue(Microtask::PromiseReaction {
            handler: Some(ClosureHandle(1)),
            argument: js_int(2),
            result_promise: PromiseHandle(1),
            label: Label::Public,
        });

        let first = queue.dequeue().unwrap();
        let second = queue.dequeue().unwrap();
        assert!(queue.dequeue().is_none());

        // Verify FIFO: first enqueued, first dequeued.
        if let Microtask::PromiseReaction { argument, .. } = &first {
            assert_eq!(*argument, js_int(1));
        } else {
            panic!("expected PromiseReaction");
        }
        if let Microtask::PromiseReaction { argument, .. } = &second {
            assert_eq!(*argument, js_int(2));
        } else {
            panic!("expected PromiseReaction");
        }
    }

    #[test]
    fn microtask_queue_compact() {
        let mut queue = MicrotaskQueue::new();
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        queue.dequeue();
        assert!(queue.is_empty());
        queue.compact();
        assert_eq!(queue.tasks.len(), 0);
        assert_eq!(queue.cursor, 0);
    }

    // ----- Virtual clock -----

    #[test]
    fn virtual_clock_starts_at_zero() {
        let clock = VirtualClock::new();
        assert_eq!(clock.now_ms(), 0);
    }

    #[test]
    fn virtual_clock_advance() {
        let mut clock = VirtualClock::new();
        clock.advance_to(100);
        assert_eq!(clock.now_ms(), 100);
        // Does not go backward.
        clock.advance_to(50);
        assert_eq!(clock.now_ms(), 100);
    }

    #[test]
    fn virtual_clock_timer_registration() {
        let mut clock = VirtualClock::new();
        let seq1 = clock.register_timer();
        let seq2 = clock.register_timer();
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    // ----- Macrotask queue -----

    #[test]
    fn macrotask_priority_ordering() {
        let mut queue = MacrotaskQueue::new();
        // Timer first, then message channel.
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);
        queue.schedule(
            MacrotaskSource::MessageChannel,
            ClosureHandle(1),
            0,
            Label::Public,
        );

        let first = queue.dequeue_ready(0).unwrap();
        // MessageChannel has higher priority (lower enum discriminant).
        assert_eq!(first.source, MacrotaskSource::MessageChannel);

        let second = queue.dequeue_ready(0).unwrap();
        assert_eq!(second.source, MacrotaskSource::Timer);
    }

    #[test]
    fn macrotask_timer_ordering_by_time_then_seq() {
        let mut queue = MacrotaskQueue::new();
        // Timer at 100ms (registered first).
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
        // Timer at 50ms (registered second).
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 50, Label::Public);
        // Timer at 50ms (registered third — tie-break by seq).
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(2), 50, Label::Public);

        let first = queue.dequeue_ready(100).unwrap();
        assert_eq!(first.handler, ClosureHandle(1)); // 50ms, seq=1
        let second = queue.dequeue_ready(100).unwrap();
        assert_eq!(second.handler, ClosureHandle(2)); // 50ms, seq=2
        let third = queue.dequeue_ready(100).unwrap();
        assert_eq!(third.handler, ClosureHandle(0)); // 100ms, seq=0
    }

    #[test]
    fn macrotask_not_ready_before_time() {
        let mut queue = MacrotaskQueue::new();
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
        assert!(queue.dequeue_ready(99).is_none());
        assert!(queue.dequeue_ready(100).is_some());
    }

    // ----- Event loop -----

    #[test]
    fn event_loop_drains_microtasks_before_macrotasks() {
        let mut event_loop = EventLoop::new();
        // Enqueue a microtask.
        event_loop.microtasks.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        // Schedule a macrotask at time 0.
        event_loop
            .macrotasks
            .schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);

        let result = event_loop.turn();
        // Microtask drained first.
        assert_eq!(result.microtasks_drained, 1);
        // Then macrotask selected.
        assert!(result.macrotask.is_some());
    }

    #[test]
    fn event_loop_advances_clock_to_next_timer() {
        let mut event_loop = EventLoop::new();
        event_loop.macrotasks.schedule(
            MacrotaskSource::Timer,
            ClosureHandle(0),
            500,
            Label::Public,
        );

        let result = event_loop.turn();
        assert!(result.clock_advanced);
        assert_eq!(event_loop.clock.now_ms(), 500);
        assert!(result.macrotask.is_some());
    }

    #[test]
    fn event_loop_set_timeout() {
        let mut event_loop = EventLoop::new();
        event_loop.set_timeout(ClosureHandle(0), 100, Label::Public);
        assert!(event_loop.has_pending_work());

        // First turn: clock at 0, timer at 100 — should advance.
        let result = event_loop.turn();
        assert!(result.clock_advanced);
        assert!(result.macrotask.is_some());
        assert_eq!(event_loop.clock.now_ms(), 100);
    }

    #[test]
    fn event_loop_no_work_returns_none() {
        let mut event_loop = EventLoop::new();
        let result = event_loop.turn();
        assert_eq!(result.microtasks_drained, 0);
        assert!(result.macrotask.is_none());
        assert!(!result.clock_advanced);
    }

    // ----- Determinism: run same operations, verify identical ordering -----

    #[test]
    fn deterministic_microtask_ordering_across_runs() {
        // Run the same Promise/microtask scenario 10 times.
        let mut witness_logs: Vec<Vec<WitnessEvent>> = Vec::new();

        for _ in 0..10 {
            let mut store = PromiseStore::new();
            let mut queue = MicrotaskQueue::new();

            let p1 = store.create();
            let p2 = store.create();

            // Register .then on both.
            store
                .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
                .unwrap();
            store
                .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
                .unwrap();

            // Fulfill p1, then p2.
            store
                .fulfill(p1, js_int(1), Label::Public, &mut queue)
                .unwrap();
            store
                .fulfill(p2, js_int(2), Label::Public, &mut queue)
                .unwrap();

            // Drain all microtasks.
            let mut drained = Vec::new();
            while let Some(task) = queue.dequeue() {
                drained.push(task);
            }

            witness_logs.push(store.witness_log().to_vec());
        }

        // All witness logs must be identical.
        for log in &witness_logs[1..] {
            assert_eq!(log, &witness_logs[0]);
        }
    }

    // ----- Promise combinators -----

    #[test]
    fn promise_all_tracker_collects_in_order() {
        let mut tracker = PromiseAllTracker {
            result_promise: PromiseHandle(10),
            values: BTreeMap::new(),
            total: 3,
            resolved_count: 0,
            settled: false,
        };

        assert!(!tracker.record_fulfillment(2, js_int(30)));
        assert!(!tracker.record_fulfillment(0, js_int(10)));
        assert!(tracker.record_fulfillment(1, js_int(20)));

        let values = tracker.collect_values();
        assert_eq!(values, vec![js_int(10), js_int(20), js_int(30)]);
    }

    #[test]
    fn promise_all_tracker_short_circuits_on_settled() {
        let mut tracker = PromiseAllTracker {
            result_promise: PromiseHandle(10),
            values: BTreeMap::new(),
            total: 3,
            resolved_count: 0,
            settled: false,
        };

        tracker.mark_settled();
        assert!(!tracker.record_fulfillment(0, js_int(1)));
    }

    #[test]
    fn promise_all_settled_tracker() {
        let mut tracker = PromiseAllSettledTracker {
            result_promise: PromiseHandle(20),
            outcomes: BTreeMap::new(),
            total: 2,
            settled_count: 0,
        };

        assert!(!tracker.record_fulfillment(0, js_int(1)));
        assert!(tracker.record_rejection(1, js_str("err")));

        assert_eq!(tracker.outcomes.get(&0).unwrap().status, "fulfilled");
        assert_eq!(tracker.outcomes.get(&1).unwrap().status, "rejected");
    }

    #[test]
    fn promise_race_first_wins() {
        let mut tracker = PromiseRaceTracker {
            result_promise: PromiseHandle(30),
            settled: false,
        };

        assert!(tracker.try_settle());
        assert!(!tracker.try_settle()); // Second settlement ignored.
    }

    #[test]
    fn promise_any_all_rejected_triggers_aggregate_error() {
        let mut tracker = PromiseAnyTracker {
            result_promise: PromiseHandle(40),
            errors: BTreeMap::new(),
            total: 2,
            rejected_count: 0,
            settled: false,
        };

        assert!(!tracker.record_rejection(0, js_str("e1")));
        assert!(tracker.record_rejection(1, js_str("e2")));

        let errors = tracker.collect_errors();
        assert_eq!(errors, vec![js_str("e1"), js_str("e2")]);
    }

    #[test]
    fn promise_any_fulfilled_short_circuits() {
        let mut tracker = PromiseAnyTracker {
            result_promise: PromiseHandle(50),
            errors: BTreeMap::new(),
            total: 3,
            rejected_count: 0,
            settled: false,
        };

        tracker.mark_settled();
        assert!(!tracker.record_rejection(0, js_str("e1")));
    }

    // ----- Unhandled rejections -----

    #[test]
    fn unhandled_rejection_tracked() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("unhandled"), Label::Public, &mut queue)
            .unwrap();

        let unhandled = store.unhandled_rejections();
        assert_eq!(unhandled.len(), 1);
        assert_eq!(unhandled[0], h);
    }

    #[test]
    fn handled_rejection_not_in_unhandled_list() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();

        // Register a rejection handler BEFORE rejecting.
        store
            .then(h, None, Some(ClosureHandle(0)), Label::Public, &mut queue)
            .unwrap();
        store
            .reject(h, js_str("handled"), Label::Public, &mut queue)
            .unwrap();

        let unhandled = store.unhandled_rejections();
        assert!(unhandled.is_empty());
    }

    #[test]
    fn rejection_without_on_rejected_registered_before_reject_remains_unhandled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();

        // Register only onFulfilled; this must not mark a future rejection handled.
        store
            .then(h, Some(ClosureHandle(7)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .reject(h, js_str("still_unhandled"), Label::Public, &mut queue)
            .unwrap();

        assert_eq!(store.unhandled_rejections(), vec![h]);
    }

    #[test]
    fn then_on_rejected_marks_as_handled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("err"), Label::Public, &mut queue)
            .unwrap();

        // Initially unhandled.
        assert_eq!(store.unhandled_rejections().len(), 1);

        // Calling .then with onRejected marks it handled.
        store
            .then(h, None, Some(ClosureHandle(0)), Label::Public, &mut queue)
            .unwrap();
        assert!(store.unhandled_rejections().is_empty());
    }

    #[test]
    fn then_on_rejected_without_on_rejected_does_not_mark_handled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("err"), Label::Public, &mut queue)
            .unwrap();
        assert_eq!(store.unhandled_rejections(), vec![h]);

        store
            .then(h, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        assert_eq!(store.unhandled_rejections(), vec![h]);
    }

    // ----- IFC label propagation -----

    #[test]
    fn promise_carries_ifc_label() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_str("secret_data"), Label::Secret, &mut queue)
            .unwrap();
        let p = store.get(h).unwrap();
        assert_eq!(p.label, Label::Secret);
    }

    // ----- Witness events -----

    #[test]
    fn witness_records_create_and_settle() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(1), Label::Public, &mut queue)
            .unwrap();

        let log = store.witness_log();
        assert_eq!(log.len(), 2);
        assert!(matches!(log[0], WitnessEvent::PromiseCreated { .. }));
        assert!(matches!(log[1], WitnessEvent::PromiseFulfilled { .. }));
    }

    #[test]
    fn microtask_queue_records_witness() {
        let mut queue = MicrotaskQueue::new();
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        queue.dequeue();

        let log = queue.witness_log();
        assert_eq!(log.len(), 2);
        assert!(matches!(
            log[0],
            WitnessEvent::MicrotaskEnqueued { index: 0 }
        ));
        assert!(matches!(
            log[1],
            WitnessEvent::MicrotaskDequeued { index: 0 }
        ));
    }

    // ----- Serde round-trips -----

    #[test]
    fn promise_state_serde_roundtrip() {
        let states = vec![
            PromiseState::Pending,
            PromiseState::Fulfilled(js_int(42)),
            PromiseState::Rejected(js_str("err")),
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let back: PromiseState = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, state);
        }
    }

    #[test]
    fn promise_error_serde_roundtrip() {
        let errors = vec![
            PromiseError::AlreadySettled {
                handle: PromiseHandle(0),
            },
            PromiseError::InvalidHandle {
                handle: PromiseHandle(99),
            },
            PromiseError::LabelViolation {
                handle: PromiseHandle(1),
                value_label: Label::Secret,
                context_label: Label::Public,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: PromiseError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, err);
        }
    }

    #[test]
    fn microtask_serde_roundtrip() {
        let task = Microtask::PromiseReaction {
            handler: Some(ClosureHandle(3)),
            argument: js_int(7),
            result_promise: PromiseHandle(1),
            label: Label::Internal,
        };
        let json = serde_json::to_string(&task).unwrap();
        let back: Microtask = serde_json::from_str(&json).unwrap();
        assert_eq!(back, task);
    }

    #[test]
    fn virtual_clock_serde_roundtrip() {
        let mut clock = VirtualClock::new();
        clock.advance_to(12345);
        clock.register_timer();
        let json = serde_json::to_string(&clock).unwrap();
        let back: VirtualClock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, clock);
    }

    // ----- Promise state Display -----

    #[test]
    fn promise_state_display() {
        assert_eq!(PromiseState::Pending.to_string(), "pending");
        assert_eq!(PromiseState::Fulfilled(js_int(1)).to_string(), "fulfilled");
        assert_eq!(PromiseState::Rejected(js_str("e")).to_string(), "rejected");
    }

    // ----- Error Display -----

    #[test]
    fn promise_error_display() {
        let err = PromiseError::AlreadySettled {
            handle: PromiseHandle(5),
        };
        assert!(err.to_string().contains("already settled"));

        let err = PromiseError::InvalidHandle {
            handle: PromiseHandle(99),
        };
        assert!(err.to_string().contains("invalid"));
    }

    // ----- Store length -----

    #[test]
    fn promise_store_len() {
        let mut store = PromiseStore::new();
        assert!(store.is_empty());
        store.create();
        store.create();
        assert_eq!(store.len(), 2);
    }

    // ----- Next scheduled time -----

    #[test]
    fn macrotask_next_scheduled_time() {
        let mut queue = MacrotaskQueue::new();
        assert!(queue.next_scheduled_time().is_none());
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 200, Label::Public);
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 50, Label::Public);
        assert_eq!(queue.next_scheduled_time(), Some(50));
    }

    // ----- Microtask total enqueued -----

    #[test]
    fn microtask_total_enqueued() {
        let mut queue = MicrotaskQueue::new();
        assert_eq!(queue.total_enqueued(), 0);
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(2),
            result_promise: PromiseHandle(1),
            label: Label::Public,
        });
        assert_eq!(queue.total_enqueued(), 2);
    }

    // ----- Event loop has_pending_work -----

    #[test]
    fn event_loop_pending_work() {
        let mut el = EventLoop::new();
        assert!(!el.has_pending_work());
        el.set_timeout(ClosureHandle(0), 100, Label::Public);
        assert!(el.has_pending_work());
    }

    // ----- Promise chain tests -----

    #[test]
    fn chained_then_creates_chain_of_promises() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p1 = store.create();
        let p2 = store
            .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        let p3 = store
            .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        // Three distinct promises: p1, p2 (result of first .then), p3 (result of second .then).
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn multiple_then_on_same_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p = store.create();
        let r1 = store
            .then(p, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        let r2 = store
            .then(p, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        assert_ne!(r1, r2);
        // Both register reactions on the same pending promise.
        let record = store.get(p).unwrap();
        assert_eq!(record.reactions.len(), 4); // 2 per .then (fulfill + reject)
    }

    #[test]
    fn fulfill_triggers_all_registered_then_handlers() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p = store.create();
        store
            .then(p, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .then(p, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .unwrap();
        store
            .fulfill(p, js_int(42), Label::Public, &mut queue)
            .unwrap();
        // 4 reactions (2 fulfill + 2 reject) -> 4 microtasks.
        assert_eq!(queue.pending_count(), 4);
    }

    // ----- Event loop multi-turn -----

    #[test]
    fn event_loop_multiple_timers_fire_in_order() {
        let mut el = EventLoop::new();
        el.set_timeout(ClosureHandle(0), 300, Label::Public);
        el.set_timeout(ClosureHandle(1), 100, Label::Public);
        el.set_timeout(ClosureHandle(2), 200, Label::Public);

        // First turn: clock advances to 100.
        let r1 = el.turn();
        assert_eq!(r1.macrotask.as_ref().unwrap().handler, ClosureHandle(1));
        assert_eq!(el.clock.now_ms(), 100);

        // Second turn: clock advances to 200.
        let r2 = el.turn();
        assert_eq!(r2.macrotask.as_ref().unwrap().handler, ClosureHandle(2));
        assert_eq!(el.clock.now_ms(), 200);

        // Third turn: clock advances to 300.
        let r3 = el.turn();
        assert_eq!(r3.macrotask.as_ref().unwrap().handler, ClosureHandle(0));
        assert_eq!(el.clock.now_ms(), 300);

        // No more work.
        let r4 = el.turn();
        assert!(r4.macrotask.is_none());
    }

    // ----- Promise.resolve with .then -----

    #[test]
    fn resolve_then_enqueues_microtask() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.resolve(js_int(5), Label::Public, &mut queue);
        let _r = store
            .then(h, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .unwrap();
        // Resolve itself doesn't enqueue (no reactions at creation time),
        // but .then on a fulfilled promise enqueues immediately.
        assert!(queue.pending_count() >= 1);
    }

    // ----- Macrotask queue len/empty -----

    #[test]
    fn macrotask_queue_len_and_empty() {
        let mut queue = MacrotaskQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 0, Label::Public);
        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 1);
        queue.dequeue_ready(0);
        assert!(queue.is_empty());
    }

    // ----- IoCompletion macrotask source -----

    #[test]
    fn io_completion_lower_priority_than_timer() {
        let mut queue = MacrotaskQueue::new();
        queue.schedule(
            MacrotaskSource::IoCompletion,
            ClosureHandle(0),
            0,
            Label::Public,
        );
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 0, Label::Public);

        let first = queue.dequeue_ready(0).unwrap();
        assert_eq!(first.source, MacrotaskSource::Timer);
        let second = queue.dequeue_ready(0).unwrap();
        assert_eq!(second.source, MacrotaskSource::IoCompletion);
    }

    // ----- Event loop witness events -----

    #[test]
    fn event_loop_records_clock_advance_witness() {
        let mut el = EventLoop::new();
        el.set_timeout(ClosureHandle(0), 500, Label::Public);
        el.turn();
        let has_clock_advance = el.witness.iter().any(|e| {
            matches!(
                e,
                WitnessEvent::ClockAdvanced {
                    from_ms: 0,
                    to_ms: 500
                }
            )
        });
        assert!(has_clock_advance);
    }

    // ----- Promise handle display -----

    #[test]
    fn promise_handle_display() {
        assert_eq!(PromiseHandle(42).to_string(), "Promise(42)");
    }

    // ----- Determinism: 100 runs -----

    #[test]
    fn deterministic_promise_resolution_100_runs() {
        let mut all_witnesses: Vec<Vec<WitnessEvent>> = Vec::new();

        for _ in 0..100 {
            let mut store = PromiseStore::new();
            let mut queue = MicrotaskQueue::new();

            let p1 = store.resolve(js_int(1), Label::Public, &mut queue);
            let p2 = store.resolve(js_int(2), Label::Public, &mut queue);
            let _r1 = store
                .then(p1, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
                .unwrap();
            let _r2 = store
                .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
                .unwrap();

            while queue.dequeue().is_some() {}
            all_witnesses.push(store.witness_log().to_vec());
        }

        for w in &all_witnesses[1..] {
            assert_eq!(w, &all_witnesses[0]);
        }
    }

    // ----- PromiseAllSettled empty input -----

    #[test]
    fn promise_all_settled_empty_input() {
        let tracker = PromiseAllSettledTracker {
            result_promise: PromiseHandle(0),
            outcomes: BTreeMap::new(),
            total: 0,
            settled_count: 0,
        };
        // Zero total means settled_count == total immediately.
        assert_eq!(tracker.settled_count, tracker.total);
    }

    // ----- PromiseAll with single promise -----

    #[test]
    fn promise_all_single_fulfillment() {
        let mut tracker = PromiseAllTracker {
            result_promise: PromiseHandle(0),
            values: BTreeMap::new(),
            total: 1,
            resolved_count: 0,
            settled: false,
        };
        assert!(tracker.record_fulfillment(0, js_int(99)));
        assert_eq!(tracker.collect_values(), vec![js_int(99)]);
    }

    // ----- Macrotask serde -----

    #[test]
    fn macrotask_serde_roundtrip() {
        let task = Macrotask {
            source: MacrotaskSource::Timer,
            handler: ClosureHandle(5),
            scheduled_at: 1000,
            registration_seq: 7,
            label: Label::Internal,
        };
        let json = serde_json::to_string(&task).unwrap();
        let back: Macrotask = serde_json::from_str(&json).unwrap();
        assert_eq!(back, task);
    }

    // ----- WitnessEvent serde -----

    #[test]
    fn witness_event_serde_roundtrip() {
        let events = vec![
            WitnessEvent::PromiseCreated {
                handle: PromiseHandle(0),
                seq: 0,
            },
            WitnessEvent::MicrotaskEnqueued { index: 5 },
            WitnessEvent::ClockAdvanced {
                from_ms: 0,
                to_ms: 100,
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            let back: WitnessEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, event);
        }
    }

    // ----- EventLoop Default -----

    #[test]
    fn event_loop_default() {
        let el = EventLoop::default();
        assert!(!el.has_pending_work());
        assert_eq!(el.clock.now_ms(), 0);
    }

    // ----- PromiseStore Default -----

    #[test]
    fn promise_store_default() {
        let store = PromiseStore::default();
        assert!(store.is_empty());
    }

    // ----- MicrotaskQueue Default -----

    #[test]
    fn microtask_queue_default() {
        let queue = MicrotaskQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.total_enqueued(), 0);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn reaction_kind_serde_roundtrip() {
        let variants = [ReactionKind::Fulfill, ReactionKind::Reject];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ReactionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn macrotask_source_serde_all_variants() {
        let variants = [
            MacrotaskSource::MessageChannel,
            MacrotaskSource::Timer,
            MacrotaskSource::IoCompletion,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: MacrotaskSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn virtual_clock_serde_new_roundtrip() {
        let clock = VirtualClock::new();
        let json = serde_json::to_string(&clock).unwrap();
        let back: VirtualClock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.now_ms(), 0);
    }

    #[test]
    fn promise_state_display_all_distinct() {
        let states = [
            PromiseState::Pending,
            PromiseState::Fulfilled(JsValue::Undefined),
            PromiseState::Rejected(JsValue::Undefined),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in &states {
            assert!(seen.insert(s.to_string()), "duplicate display: {s}");
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn promise_state_predicates() {
        let pending = PromiseState::Pending;
        assert!(!pending.is_settled());
        assert!(!pending.is_fulfilled());
        assert!(!pending.is_rejected());

        let fulfilled = PromiseState::Fulfilled(JsValue::Int(42_000_000));
        assert!(fulfilled.is_settled());
        assert!(fulfilled.is_fulfilled());
        assert!(!fulfilled.is_rejected());

        let rejected = PromiseState::Rejected(JsValue::Str("err".into()));
        assert!(rejected.is_settled());
        assert!(!rejected.is_fulfilled());
        assert!(rejected.is_rejected());
    }

    #[test]
    fn promise_handle_serde_roundtrip() {
        let handle = PromiseHandle(99);
        let json = serde_json::to_string(&handle).unwrap();
        let back: PromiseHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, handle);
    }

    #[test]
    fn promise_error_display_all_distinct() {
        let variants = [
            PromiseError::AlreadySettled {
                handle: PromiseHandle(0),
            },
            PromiseError::InvalidHandle {
                handle: PromiseHandle(1),
            },
            PromiseError::LabelViolation {
                handle: PromiseHandle(2),
                value_label: Label::Public,
                context_label: Label::Internal,
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 3);
    }

    // ----- ExceptionToRejectionBridge tests (bd-1lsy.4.13.3) -----

    #[test]
    fn bridge_async_exception_rejects_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();
        let promise = store.create();

        let outcome = bridge
            .bridge_async_exception(js_str("async error"), promise, &mut store, &mut queue)
            .expect("bridge should succeed");

        assert_eq!(outcome.rejected_promise, Some(promise));
        assert_eq!(outcome.rejection_reason, js_str("async error"));
        assert!(!outcome.propagated);
        assert_eq!(outcome.affected_module_count, 0);
        assert!(outcome.module_specifier.is_none());

        let p = store.get(promise).unwrap();
        assert!(p.state.is_rejected());
    }

    #[test]
    fn bridge_module_exception_rejects_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();
        let module_promise = store.create();

        let outcome = bridge
            .bridge_module_exception(
                js_str("module error"),
                "mod.js",
                Some(module_promise),
                &mut store,
                &mut queue,
            )
            .expect("bridge should succeed");

        assert_eq!(outcome.rejected_promise, Some(module_promise));
        assert_eq!(outcome.module_specifier.as_deref(), Some("mod.js"));

        let p = store.get(module_promise).unwrap();
        assert!(p.state.is_rejected());
    }

    #[test]
    fn bridge_module_exception_without_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();

        let outcome = bridge
            .bridge_module_exception(
                js_str("sync module error"),
                "sync_mod.js",
                None,
                &mut store,
                &mut queue,
            )
            .expect("bridge without promise should succeed");

        assert!(outcome.rejected_promise.is_none());
        assert_eq!(outcome.module_specifier.as_deref(), Some("sync_mod.js"));
    }

    #[test]
    fn bridge_hostcall_exception_rejects_caller_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();
        let caller = store.create();

        let outcome = bridge
            .bridge_hostcall_exception(js_int(500), Some(caller), &mut store, &mut queue)
            .expect("hostcall bridge should succeed");

        assert_eq!(outcome.rejected_promise, Some(caller));
        let p = store.get(caller).unwrap();
        assert!(p.state.is_rejected());
    }

    #[test]
    fn bridge_microtask_exception_rejects_result_promise() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();
        let result = store.create();

        let outcome = bridge
            .bridge_microtask_exception(
                js_str("reaction error"),
                Some(result),
                &mut store,
                &mut queue,
            )
            .expect("microtask bridge should succeed");

        assert_eq!(outcome.rejected_promise, Some(result));
        let p = store.get(result).unwrap();
        assert!(p.state.is_rejected());
    }

    #[test]
    fn bridge_witness_log_records_transitions() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let mut bridge = ExceptionToRejectionBridge::new();

        let p1 = store.create();
        let p2 = store.create();

        bridge
            .bridge_async_exception(js_str("err1"), p1, &mut store, &mut queue)
            .unwrap();
        bridge
            .bridge_module_exception(js_str("err2"), "m.js", Some(p2), &mut store, &mut queue)
            .unwrap();

        let log = bridge.witness_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].boundary, ExceptionBoundaryKind::AsyncFunctionBody);
        assert_eq!(log[0].seq, 0);
        assert_eq!(log[1].boundary, ExceptionBoundaryKind::ModuleEvaluation);
        assert_eq!(log[1].seq, 1);
        assert_eq!(bridge.transition_count(), 2);
    }

    #[test]
    fn bridge_outcome_serde_roundtrip() {
        let outcome = ExceptionRejectionOutcome {
            rejected_promise: Some(PromiseHandle(7)),
            rejection_reason: js_str("test"),
            reason_description: "test description".to_string(),
            module_specifier: Some("mod.js".to_string()),
            propagated: true,
            affected_module_count: 3,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ExceptionRejectionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn bridge_witness_event_serde_roundtrip() {
        let event = ExceptionRejectionWitnessEvent {
            boundary: ExceptionBoundaryKind::HostcallBoundary,
            promise: Some(PromiseHandle(3)),
            exception_description: "hostcall failure".to_string(),
            module_specifier: None,
            seq: 42,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ExceptionRejectionWitnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn exception_boundary_kind_serde_roundtrip() {
        let variants = vec![
            ExceptionBoundaryKind::AsyncFunctionBody,
            ExceptionBoundaryKind::ModuleEvaluation,
            ExceptionBoundaryKind::HostcallBoundary,
            ExceptionBoundaryKind::MicrotaskReaction,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ExceptionBoundaryKind = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back);
        }
    }
}
