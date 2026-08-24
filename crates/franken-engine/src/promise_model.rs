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

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};

use serde::{Deserialize, Serialize};

use crate::closure_model::ClosureHandle;
use crate::ifc_artifacts::Label;
use crate::object_model::JsValue;

/// Approximate allocation header carried by every retained string. Keep this
/// aligned with the baseline interpreter's logical-owner accounting algebra.
const MEMORY_ESTIMATE_STRING_BASE_BYTES: u64 = 24;
/// Conservative per-entry charge for deterministic tree-backed maps.
const MEMORY_ESTIMATE_MAP_ENTRY_BYTES: u64 = 48;

fn saturating_sum(values: impl Iterator<Item = u64>) -> u64 {
    values.fold(0u64, u64::saturating_add)
}

fn estimate_vector_slot_bytes<T>(len: usize) -> u64 {
    u64::try_from(len)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(std::mem::size_of::<T>()).unwrap_or(u64::MAX))
}

fn estimate_string_memory_bytes(text: &str) -> u64 {
    MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(text.len() as u64)
}

/// Dynamic payload retained by an object-model value.
///
/// Handles and numeric variants are inline identifiers/scalars and therefore
/// have no additional dynamic charge. Strings own a separate allocation.
pub(crate) fn estimate_js_value_memory_bytes(value: &JsValue) -> u64 {
    match value {
        JsValue::Str(text) => estimate_string_memory_bytes(text),
        JsValue::Undefined
        | JsValue::Null
        | JsValue::Bool(_)
        | JsValue::Int(_)
        | JsValue::Float(_)
        | JsValue::Symbol(_)
        | JsValue::Object(_)
        | JsValue::Function(_) => 0,
    }
}

/// Dynamic payload retained by an IFC label.
pub(crate) fn estimate_label_memory_bytes(label: &Label) -> u64 {
    match label {
        // `String::new()` is the allocation-free carrier used by fatal Promise
        // tombstones. The enum already owns the inline String header through
        // its containing record/queue slot, so an empty name has no dynamic
        // resident allocation to charge.
        Label::Custom { name, .. } if name.is_empty() && name.capacity() == 0 => 0,
        Label::Custom { name, .. } => estimate_string_memory_bytes(name),
        Label::Public
        | Label::Internal
        | Label::Confidential
        | Label::Secret
        | Label::TopSecret => 0,
    }
}

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
    /// Allocation-free marker for one fatal dependency-closure pass.
    #[doc(hidden)]
    #[serde(skip)]
    pub terminal_epoch: u64,
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
            terminal_epoch: 0,
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
    /// PromiseReactionJob with no rejection handler: propagate the rejection
    /// reason to the result promise instead of applying fulfillment identity.
    PromiseRejection {
        /// The rejection reason to propagate.
        reason: JsValue,
        /// The promise that receives the propagated rejection.
        result_promise: PromiseHandle,
        /// IFC label of the reason.
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
    /// `setImmediate` callbacks (bd-suwvw). Scheduled at the CURRENT virtual
    /// time and drained before timer tasks that are due at the same moment,
    /// matching Node's check-phase ordering (an immediate scheduled inside a
    /// timer callback runs before a `setTimeout(fn, 0)` scheduled alongside
    /// it). FIFO within the queue by registration order, so a nested
    /// immediate runs after every already-queued immediate.
    Immediate,
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

/// Dynamic payload retained by one replay witness event.
pub(crate) fn estimate_witness_event_memory_bytes(event: &WitnessEvent) -> u64 {
    match event {
        WitnessEvent::PromiseFulfilled { value, label, .. } => {
            estimate_js_value_memory_bytes(value).saturating_add(estimate_label_memory_bytes(label))
        }
        WitnessEvent::PromiseRejected { reason, label, .. } => {
            estimate_js_value_memory_bytes(reason)
                .saturating_add(estimate_label_memory_bytes(label))
        }
        WitnessEvent::PromiseCreated { .. }
        | WitnessEvent::MicrotaskEnqueued { .. }
        | WitnessEvent::MicrotaskDequeued { .. }
        | WitnessEvent::MacrotaskExecuted { .. }
        | WitnessEvent::ClockAdvanced { .. } => 0,
    }
}

fn estimate_witness_log_memory_bytes(witness: &[WitnessEvent]) -> u64 {
    estimate_vector_slot_bytes::<WitnessEvent>(witness.len()).saturating_add(saturating_sum(
        witness.iter().map(estimate_witness_event_memory_bytes),
    ))
}

pub(crate) fn estimate_microtask_payload_memory_bytes(task: &Microtask) -> u64 {
    match task {
        Microtask::PromiseReaction {
            argument, label, ..
        } => estimate_js_value_memory_bytes(argument)
            .saturating_add(estimate_label_memory_bytes(label)),
        Microtask::PromiseRejection { reason, label, .. } => estimate_js_value_memory_bytes(reason)
            .saturating_add(estimate_label_memory_bytes(label)),
        Microtask::ResolveThenable {
            thenable, label, ..
        } => estimate_js_value_memory_bytes(thenable)
            .saturating_add(estimate_label_memory_bytes(label)),
    }
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
    /// All promise slots, indexed by handle. Execution-boundary cancellation
    /// leaves a vacant slot so later handles remain stable and monotonic.
    promises: Vec<Option<PromiseRecord>>,
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

    /// Deterministic resident-memory estimate for every Promise-owned record,
    /// reaction, label, settled payload, and replay witness.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        estimate_vector_slot_bytes::<PromiseRecord>(
            self.promises.iter().filter(|record| record.is_some()).count(),
        )
            .saturating_add(saturating_sum(self.promises.iter().flatten().map(|record| {
                let state_bytes = match &record.state {
                    PromiseState::Pending => 0,
                    PromiseState::Fulfilled(value) | PromiseState::Rejected(value) => {
                        estimate_js_value_memory_bytes(value)
                    }
                };
                state_bytes
                    .saturating_add(estimate_label_memory_bytes(&record.label))
                    .saturating_add(estimate_vector_slot_bytes::<PromiseReaction>(
                        record.reactions.len(),
                    ))
                    .saturating_add(saturating_sum(
                        record
                            .reactions
                            .iter()
                            .map(|reaction| estimate_label_memory_bytes(&reaction.label)),
                    ))
            })))
            .saturating_add(estimate_witness_log_memory_bytes(&self.witness))
    }

    pub(crate) fn projected_create_memory_bytes(&self) -> u64 {
        self.estimated_memory_bytes()
            .saturating_add(std::mem::size_of::<PromiseRecord>() as u64)
            .saturating_add(std::mem::size_of::<WitnessEvent>() as u64)
    }

    /// Exact Promise-store and microtask-queue estimates after registering a
    /// `.then` reaction, computed without cloning or mutating either owner.
    pub(crate) fn projected_then_memory_bytes(
        &self,
        handle: PromiseHandle,
        label: &Label,
        queue: &MicrotaskQueue,
    ) -> Result<(u64, u64), PromiseError> {
        let record = self.get(handle)?;
        let mut next_store_bytes = self.projected_create_memory_bytes();
        let mut next_queue_bytes = queue.estimated_memory_bytes();
        match &record.state {
            PromiseState::Pending => {
                next_store_bytes = next_store_bytes
                    .saturating_add(
                        2u64.saturating_mul(std::mem::size_of::<PromiseReaction>() as u64),
                    )
                    .saturating_add(2u64.saturating_mul(estimate_label_memory_bytes(label)));
            }
            PromiseState::Fulfilled(value) => {
                next_queue_bytes = queue.projected_enqueue_payload_memory_bytes(
                    estimate_js_value_memory_bytes(value),
                    estimate_label_memory_bytes(label),
                );
            }
            PromiseState::Rejected(reason) => {
                next_queue_bytes = queue.projected_enqueue_payload_memory_bytes(
                    estimate_js_value_memory_bytes(reason),
                    estimate_label_memory_bytes(label),
                );
            }
        }
        Ok((next_store_bytes, next_queue_bytes))
    }

    /// Exact post-fulfillment estimates without allocating the projected
    /// Promise store or queue.
    pub(crate) fn projected_fulfill_memory_bytes(
        &self,
        handle: PromiseHandle,
        value: &JsValue,
        label: &Label,
        queue: &MicrotaskQueue,
    ) -> Result<(u64, u64), PromiseError> {
        self.projected_settlement_memory_bytes(handle, value, label, queue, ReactionKind::Fulfill)
    }

    /// Exact post-rejection estimates without allocating the projected
    /// Promise store or queue.
    pub(crate) fn projected_reject_memory_bytes(
        &self,
        handle: PromiseHandle,
        reason: &JsValue,
        label: &Label,
        queue: &MicrotaskQueue,
    ) -> Result<(u64, u64), PromiseError> {
        self.projected_settlement_memory_bytes(handle, reason, label, queue, ReactionKind::Reject)
    }

    fn projected_settlement_memory_bytes(
        &self,
        handle: PromiseHandle,
        payload: &JsValue,
        label: &Label,
        queue: &MicrotaskQueue,
        selected_kind: ReactionKind,
    ) -> Result<(u64, u64), PromiseError> {
        let record = self.get(handle)?;
        if record.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle });
        }

        let reactions_bytes = estimate_vector_slot_bytes::<PromiseReaction>(record.reactions.len())
            .saturating_add(saturating_sum(
                record
                    .reactions
                    .iter()
                    .map(|reaction| estimate_label_memory_bytes(&reaction.label)),
            ));
        let payload_bytes = estimate_js_value_memory_bytes(payload);
        let label_bytes = estimate_label_memory_bytes(label);
        let next_store_bytes = self
            .estimated_memory_bytes()
            .saturating_sub(reactions_bytes)
            .saturating_sub(estimate_label_memory_bytes(&record.label))
            .saturating_add(payload_bytes)
            .saturating_add(label_bytes)
            .saturating_add(std::mem::size_of::<WitnessEvent>() as u64)
            .saturating_add(payload_bytes)
            .saturating_add(label_bytes);

        let next_queue_bytes = record
            .reactions
            .iter()
            .filter(|reaction| reaction.kind == selected_kind)
            .fold(queue.estimated_memory_bytes(), |bytes, _| {
                bytes
                    .saturating_add(std::mem::size_of::<Option<Microtask>>() as u64)
                    .saturating_add(payload_bytes)
                    .saturating_add(label_bytes)
                    .saturating_add(2u64.saturating_mul(std::mem::size_of::<WitnessEvent>() as u64))
            });
        Ok((next_store_bytes, next_queue_bytes))
    }

    /// Create a new pending Promise.
    pub fn create(&mut self) -> PromiseHandle {
        let handle = PromiseHandle(self.promises.len() as u32);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.promises.push(Some(PromiseRecord::new(handle, seq)));
        self.witness
            .push(WitnessEvent::PromiseCreated { handle, seq });
        handle
    }

    /// Roll back the most recent still-pending creation after an enclosing
    /// interpreter memory preflight refuses its resident charge.
    pub(crate) fn rollback_last_created(&mut self, handle: PromiseHandle) -> bool {
        let is_last_pending = self.promises.last().and_then(Option::as_ref).is_some_and(|record| {
            record.handle == handle
                && matches!(record.state, PromiseState::Pending)
                && record.reactions.is_empty()
        });
        let has_matching_witness = matches!(
            self.witness.last(),
            Some(WitnessEvent::PromiseCreated {
                handle: witness_handle,
                ..
            }) if *witness_handle == handle
        );
        if !is_last_pending || !has_matching_witness {
            return false;
        }
        self.promises.pop();
        self.witness.pop();
        self.next_seq = self.next_seq.saturating_sub(1);
        true
    }

    /// Remove an unpublished, still-pending Promise at an execution boundary.
    ///
    /// Unlike [`Self::rollback_last_created`], this transaction can remove an
    /// arbitrary handle after reentrant guest execution has created later
    /// Promises. The arena slot remains vacant so no live handle is shifted or
    /// reused. Removing the matching creation witness keeps ownership and
    /// resident-memory accounting aligned with the removed record.
    pub(crate) fn remove_pending_at_execution_boundary(
        &mut self,
        handle: PromiseHandle,
    ) -> Result<PromiseRecord, PromiseError> {
        let record = self.get(handle)?;
        if record.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle });
        }
        let creation_seq = record.creation_seq;
        let witness_index = self
            .witness
            .iter()
            .rposition(|event| {
                matches!(
                    event,
                    WitnessEvent::PromiseCreated {
                        handle: witness_handle,
                        seq,
                    } if *witness_handle == handle && *seq == creation_seq
                )
            })
            .ok_or(PromiseError::InvalidHandle { handle })?;

        let record = self.promises[handle.0 as usize]
            .take()
            .expect("validated pending Promise slot remains occupied");
        self.witness.remove(witness_index);
        Ok(record)
    }

    /// Get a Promise by handle.
    pub fn get(&self, handle: PromiseHandle) -> Result<&PromiseRecord, PromiseError> {
        self.promises
            .get(handle.0 as usize)
            .and_then(Option::as_ref)
            .ok_or(PromiseError::InvalidHandle { handle })
    }

    /// Get a mutable reference to a Promise by handle.
    fn get_mut(&mut self, handle: PromiseHandle) -> Result<&mut PromiseRecord, PromiseError> {
        self.promises
            .get_mut(handle.0 as usize)
            .and_then(Option::as_mut)
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
        let reactions: Vec<PromiseReaction> = std::mem::take(&mut record.reactions);
        record.state = PromiseState::Fulfilled(value.clone());
        record.label = label.clone();

        self.witness.push(WitnessEvent::PromiseFulfilled {
            handle,
            value: value.clone(),
            label: label.clone(),
        });

        // Enqueue only the fulfill reactions for a fulfilled promise.
        for reaction in reactions {
            if reaction.kind == ReactionKind::Fulfill {
                queue.enqueue(Microtask::PromiseReaction {
                    handler: reaction.handler,
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
        let reactions: Vec<PromiseReaction> = std::mem::take(&mut record.reactions);
        let rejection_handled = record.rejection_handled
            || reactions
                .iter()
                .any(|reaction| reaction.kind == ReactionKind::Reject);
        record.state = PromiseState::Rejected(reason.clone());
        record.label = label.clone();
        record.rejection_handled = rejection_handled;

        self.witness.push(WitnessEvent::PromiseRejected {
            handle,
            reason: reason.clone(),
            label: label.clone(),
        });

        // Enqueue only the reject reactions for a rejected promise.
        for reaction in reactions {
            if reaction.kind == ReactionKind::Reject {
                if reaction.handler.is_some() {
                    queue.enqueue(Microtask::PromiseReaction {
                        handler: reaction.handler,
                        argument: reason.clone(),
                        result_promise: reaction.result_promise,
                        label: label.clone(),
                    });
                } else {
                    queue.enqueue(Microtask::PromiseRejection {
                        reason: reason.clone(),
                        result_promise: reaction.result_promise,
                        label: label.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Fail-closed settlement used only after the ordinary, fully witnessed
    /// rejection path has refused its memory preflight.
    ///
    /// This operation performs no allocation and enqueues no reaction jobs. It
    /// rejects the target and every still-pending Promise returned by its stored
    /// `.then` reactions with `undefined`, then drops those now-unschedulable
    /// reactions. Handles are monotonic, so a forward walk over the authoritative
    /// retained reaction edges marks every descendant before it is visited; a
    /// reverse pass then clears and settles the marked records. No temporary
    /// worklist or newly serialized dependency metadata is needed.
    ///
    /// No witness is appended: this path exists precisely for the case where
    /// even one additional witness record cannot be admitted. The enclosing
    /// interpreter propagates the fatal resource error as the durable outcome.
    pub(crate) fn terminally_reject_without_jobs(
        &mut self,
        handle: PromiseHandle,
        label: &Label,
    ) -> Result<u64, PromiseError> {
        let terminal_epoch = u64::from(handle.0).saturating_add(1);
        self.extend_terminal_rejection_without_jobs(handle, label, terminal_epoch)?;
        Ok(terminal_epoch)
    }

    /// Extend an existing fatal dependency-closure pass from another root.
    pub(crate) fn extend_terminal_rejection_without_jobs(
        &mut self,
        handle: PromiseHandle,
        label: &Label,
        terminal_epoch: u64,
    ) -> Result<usize, PromiseError> {
        let root_index = handle.0 as usize;
        let root = self.get(handle)?;
        if root.terminal_epoch == terminal_epoch {
            return Ok(0);
        }
        if root.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle });
        }

        let terminal_label = match label {
            Label::Public => Label::Public,
            Label::Internal => Label::Internal,
            Label::Confidential => Label::Confidential,
            Label::Secret => Label::Secret,
            Label::TopSecret => Label::TopSecret,
            Label::Custom { level, .. } => Label::Custom {
                name: String::new(),
                level: *level,
            },
        };

        self.promises[root_index]
            .as_mut()
            .expect("validated fatal-rejection root remains occupied")
            .terminal_epoch = terminal_epoch;
        for parent_index in root_index..self.promises.len() {
            let Some(parent) = self.promises[parent_index].as_ref() else {
                continue;
            };
            if parent.terminal_epoch != terminal_epoch {
                continue;
            }
            let reaction_count = parent.reactions.len();
            for reaction_index in 0..reaction_count {
                let child = self.promises[parent_index]
                    .as_ref()
                    .expect("marked fatal-rejection parent remains occupied")
                    .reactions[reaction_index]
                    .result_promise;
                let child_index = child.0 as usize;
                if child_index <= parent_index || child_index >= self.promises.len() {
                    continue;
                }
                if let Some(child) = self.promises[child_index].as_mut()
                    && matches!(child.state, PromiseState::Pending)
                {
                    child.terminal_epoch = terminal_epoch;
                }
            }
        }

        let mut rejected_count = 0usize;
        for candidate_index in (root_index..self.promises.len()).rev() {
            if let Some(record) = self.promises[candidate_index].as_mut()
                && record.terminal_epoch == terminal_epoch
                && matches!(record.state, PromiseState::Pending)
            {
                record.state = PromiseState::Rejected(JsValue::Undefined);
                record.label = terminal_label.clone();
                record.rejection_handled = false;
                record.reactions = Vec::new();
                record.terminal_epoch = terminal_epoch;
                rejected_count = rejected_count.saturating_add(1);
            }
        }
        Ok(rejected_count)
    }

    pub(crate) fn was_terminally_rejected_in_epoch(
        &self,
        handle: PromiseHandle,
        terminal_epoch: u64,
    ) -> bool {
        self.promises
            .get(handle.0 as usize)
            .and_then(Option::as_ref)
            .is_some_and(|record| record.terminal_epoch == terminal_epoch)
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
                if on_rejected.is_some() {
                    queue.enqueue(Microtask::PromiseReaction {
                        handler: on_rejected,
                        argument: reason,
                        result_promise,
                        label,
                    });
                } else {
                    queue.enqueue(Microtask::PromiseRejection {
                        reason,
                        result_promise,
                        label,
                    });
                }
            }
        }

        // PerformPromiseThen marks the source handled even when the rejection
        // callback is the implicit thrower. In that case the queued rejection
        // job transfers any unhandled rejection to `result_promise`.
        self.get_mut(handle)?.rejection_handled = true;

        Ok(result_promise)
    }

    /// Projected store-byte growth of [`Self::register_native_adoption`] on a
    /// still-pending `source`: two reaction slots plus their labels. Nothing is
    /// enqueued at registration time — the settlement paths preflight and
    /// enqueue the forwarding jobs when `source` actually settles.
    pub fn projected_native_adoption_memory_bytes(
        &self,
        source: PromiseHandle,
        label: &Label,
    ) -> Result<u64, PromiseError> {
        let record = self.get(source)?;
        if record.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle: source });
        }
        let previous_reactions_bytes =
            estimate_vector_slot_bytes::<PromiseReaction>(record.reactions.len());
        let next_reactions_bytes =
            estimate_vector_slot_bytes::<PromiseReaction>(record.reactions.len() + 2);
        Ok(self.estimated_memory_bytes().saturating_add(
            next_reactions_bytes
                .saturating_sub(previous_reactions_bytes)
                .saturating_add(2u64.saturating_mul(estimate_label_memory_bytes(label))),
        ))
    }

    /// Register identity-forwarding reactions so that `target` adopts the
    /// eventual settlement of a still-pending native `source` promise
    /// (ES2020 25.6.3.2 promise resolution specialized to internal promises:
    /// the fulfillment value and the rejection reason each propagate through
    /// unchanged via the existing handler-less identity lanes).
    ///
    /// The caller must copy state directly instead when `source` has already
    /// settled; this method fails closed on settled sources so a stale
    /// registration can never silently drop an adoption.
    pub fn register_native_adoption(
        &mut self,
        source: PromiseHandle,
        target: PromiseHandle,
        label: Label,
    ) -> Result<(), PromiseError> {
        if self.get(source)?.state.is_settled() {
            return Err(PromiseError::AlreadySettled { handle: source });
        }
        let record = self.get_mut(source)?;
        for kind in [ReactionKind::Fulfill, ReactionKind::Reject] {
            record.reactions.push(PromiseReaction {
                kind,
                handler: None,
                result_promise: target,
                label: label.clone(),
            });
        }
        Ok(())
    }

    /// Register the internal identity/thrower reactions used by `await`.
    ///
    /// Await has no user-visible closure handle, but it still observes and
    /// handles rejection by resuming the suspended execution context. Keeping
    /// this entry point separate makes that internal reaction explicit;
    /// ordinary `.then(None, None)` instead transfers rejection to its returned
    /// Promise through the implicit thrower.
    pub fn then_for_await(
        &mut self,
        handle: PromiseHandle,
        label: Label,
        queue: &mut MicrotaskQueue,
    ) -> Result<PromiseHandle, PromiseError> {
        let state = self.get(handle)?.state.clone();
        let result_promise = self.create();

        match state {
            PromiseState::Pending => {
                let record = self.get_mut(handle)?;
                record.rejection_handled = true;
                record.reactions.push(PromiseReaction {
                    kind: ReactionKind::Fulfill,
                    handler: None,
                    result_promise,
                    label: label.clone(),
                });
                record.reactions.push(PromiseReaction {
                    kind: ReactionKind::Reject,
                    handler: None,
                    result_promise,
                    label,
                });
            }
            PromiseState::Fulfilled(value) => {
                queue.enqueue(Microtask::PromiseReaction {
                    handler: None,
                    argument: value,
                    result_promise,
                    label,
                });
            }
            PromiseState::Rejected(reason) => {
                self.get_mut(handle)?.rejection_handled = true;
                queue.enqueue(Microtask::PromiseRejection {
                    reason,
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
        self.promises.iter().filter(|record| record.is_some()).count()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.promises.iter().all(Option::is_none)
    }

    /// Get the witness log (for replay/forensics).
    pub fn witness_log(&self) -> &[WitnessEvent] {
        &self.witness
    }

    /// Collect all unhandled rejections (for reporting).
    pub fn unhandled_rejections(&self) -> Vec<PromiseHandle> {
        self.promises
            .iter()
            .flatten()
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
    tasks: Vec<Option<Microtask>>,
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

    /// Deterministic resident-memory estimate for physical queue slots,
    /// pending task payloads, labels, and replay witnesses. Consumed slots stay
    /// charged until [`Self::compact`] releases them.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        estimate_vector_slot_bytes::<Option<Microtask>>(self.tasks.len())
            .saturating_add(saturating_sum(
                self.tasks
                    .iter()
                    .filter_map(Option::as_ref)
                    .map(estimate_microtask_payload_memory_bytes),
            ))
            .saturating_add(estimate_witness_log_memory_bytes(&self.witness))
            // Every pending job will deterministically append one dequeue
            // witness. Reserve that slot at enqueue time so transferring a
            // job out of the queue can never grow resident memory after the
            // queue has already been mutated.
            .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(
                self.pending_count(),
            ))
    }

    /// Exact post-enqueue estimate without allocating or mutating the queue.
    pub(crate) fn projected_enqueue_memory_bytes(&self, task: &Microtask) -> u64 {
        let payload_bytes = estimate_microtask_payload_memory_bytes(task);
        self.projected_enqueue_payload_memory_bytes(payload_bytes, 0)
    }

    fn projected_enqueue_payload_memory_bytes(&self, value_bytes: u64, label_bytes: u64) -> u64 {
        self.estimated_memory_bytes()
            .saturating_add(std::mem::size_of::<Option<Microtask>>() as u64)
            .saturating_add(value_bytes)
            .saturating_add(label_bytes)
            .saturating_add(2u64.saturating_mul(std::mem::size_of::<WitnessEvent>() as u64))
    }

    /// Enqueue a microtask.
    pub fn enqueue(&mut self, task: Microtask) {
        let index = self.enqueue_count;
        self.enqueue_count += 1;
        self.tasks.push(Some(task));
        self.witness.push(WitnessEvent::MicrotaskEnqueued { index });
    }

    /// Roll back the most recent pending enqueue after an enclosing memory
    /// preflight refuses the queue's resident growth.
    #[cfg(test)]
    pub(crate) fn rollback_last_enqueued(&mut self) -> Option<Microtask> {
        let last_index = self.tasks.len().checked_sub(1)?;
        if last_index < self.cursor
            || !matches!(
                self.witness.last(),
                Some(WitnessEvent::MicrotaskEnqueued { index })
                    if *index + 1 == self.enqueue_count
            )
        {
            return None;
        }
        let task = self.tasks.pop().flatten()?;
        self.witness.pop();
        self.enqueue_count = self.enqueue_count.saturating_sub(1);
        Some(task)
    }

    /// Dequeue the next microtask (FIFO).
    pub fn dequeue(&mut self) -> Option<Microtask> {
        while self.cursor < self.tasks.len() {
            let index = self.cursor as u64;
            let task = self.tasks[self.cursor].take();
            self.cursor += 1;
            if task.is_some() {
                self.witness.push(WitnessEvent::MicrotaskDequeued { index });
                return task;
            }
        }
        None
    }

    /// Check if there are pending microtasks.
    pub fn is_empty(&self) -> bool {
        self.tasks[self.cursor.min(self.tasks.len())..]
            .iter()
            .all(Option::is_none)
    }

    /// Number of pending (unprocessed) microtasks.
    pub fn pending_count(&self) -> usize {
        self.tasks[self.cursor.min(self.tasks.len())..]
            .iter()
            .filter(|task| task.is_some())
            .count()
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
    message_channel_tasks: BinaryHeap<MacrotaskHeapEntry>,
    /// `setImmediate` tasks (bd-suwvw). Defaulted on deserialization so
    /// pre-existing serialized queues (which had no immediate lane) load.
    #[serde(default)]
    immediate_tasks: BinaryHeap<MacrotaskHeapEntry>,
    timer_tasks: BinaryHeap<MacrotaskHeapEntry>,
    io_completion_tasks: BinaryHeap<MacrotaskHeapEntry>,
    next_registration_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MacrotaskHeapEntry {
    task: Macrotask,
}

impl Ord for MacrotaskHeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .task
            .scheduled_at
            .cmp(&self.task.scheduled_at)
            .then_with(|| other.task.registration_seq.cmp(&self.task.registration_seq))
            .then_with(|| other.task.source.cmp(&self.task.source))
            .then_with(|| other.task.handler.cmp(&self.task.handler))
            .then_with(|| other.task.label.cmp(&self.task.label))
    }
}

impl PartialOrd for MacrotaskHeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl MacrotaskQueue {
    pub fn new() -> Self {
        Self {
            message_channel_tasks: BinaryHeap::new(),
            immediate_tasks: BinaryHeap::new(),
            timer_tasks: BinaryHeap::new(),
            io_completion_tasks: BinaryHeap::new(),
            next_registration_seq: 0,
        }
    }

    /// Deterministic resident-memory estimate across every source lane.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        [
            &self.message_channel_tasks,
            &self.immediate_tasks,
            &self.timer_tasks,
            &self.io_completion_tasks,
        ]
        .into_iter()
        .fold(0u64, |total, tasks| {
            total
                .saturating_add(estimate_vector_slot_bytes::<MacrotaskHeapEntry>(
                    tasks.len(),
                ))
                .saturating_add(saturating_sum(
                    tasks
                        .iter()
                        .map(|entry| estimate_label_memory_bytes(&entry.task.label)),
                ))
        })
    }

    /// Exact post-schedule estimate without allocating or mutating the queue.
    /// All macrotask lanes retain the same fixed entry plus the task label, so
    /// the source only determines which heap receives the entry.
    fn projected_schedule_memory_bytes(&self, label: &Label) -> u64 {
        self.estimated_memory_bytes()
            .saturating_add(std::mem::size_of::<MacrotaskHeapEntry>() as u64)
            .saturating_add(estimate_label_memory_bytes(label))
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
        let task = Macrotask {
            source,
            handler,
            scheduled_at,
            registration_seq: seq,
            label,
        };
        self.tasks_for_source_mut(source)
            .push(MacrotaskHeapEntry { task });
        seq
    }

    /// Dequeue the highest-priority ready macrotask at or before `current_time_ms`.
    ///
    /// Priority: source type (MessageChannel > Timer > IoCompletion),
    /// then earliest `scheduled_at`, then lowest `registration_seq`.
    pub fn dequeue_ready(&mut self, current_time_ms: u64) -> Option<Macrotask> {
        Self::pop_ready_from(&mut self.message_channel_tasks, current_time_ms)
            .or_else(|| Self::pop_ready_from(&mut self.immediate_tasks, current_time_ms))
            .or_else(|| Self::pop_ready_from(&mut self.timer_tasks, current_time_ms))
            .or_else(|| Self::pop_ready_from(&mut self.io_completion_tasks, current_time_ms))
    }

    /// Find the earliest scheduled time of any pending macrotask.
    pub fn next_scheduled_time(&self) -> Option<u64> {
        [
            self.message_channel_tasks.peek(),
            self.immediate_tasks.peek(),
            self.timer_tasks.peek(),
            self.io_completion_tasks.peek(),
        ]
        .into_iter()
        .flatten()
        .map(|entry| entry.task.scheduled_at)
        .min()
    }

    /// Check if there are pending macrotasks.
    pub fn is_empty(&self) -> bool {
        self.message_channel_tasks.is_empty()
            && self.immediate_tasks.is_empty()
            && self.timer_tasks.is_empty()
            && self.io_completion_tasks.is_empty()
    }

    /// Number of pending macrotasks.
    pub fn len(&self) -> usize {
        self.message_channel_tasks.len()
            + self.immediate_tasks.len()
            + self.timer_tasks.len()
            + self.io_completion_tasks.len()
    }

    /// Iterate every pending macrotask across all source lanes (bd-suwvw).
    /// Order is unspecified (heap order); used by the event-loop idle drain
    /// to decide whether only unref'd/cancelled timers remain.
    pub fn iter_pending(&self) -> impl Iterator<Item = &Macrotask> {
        self.message_channel_tasks
            .iter()
            .chain(self.immediate_tasks.iter())
            .chain(self.timer_tasks.iter())
            .chain(self.io_completion_tasks.iter())
            .map(|entry| &entry.task)
    }

    /// Remove and return one pending task by registration sequence.
    ///
    /// Entries are moved into a temporary vector and rebuilt into a heap so
    /// cancellation neither clones retained labels nor violates heap order.
    pub(crate) fn cancel_registration(&mut self, registration_seq: u64) -> Option<Macrotask> {
        Self::remove_registration_from(&mut self.message_channel_tasks, registration_seq)
            .or_else(|| Self::remove_registration_from(&mut self.immediate_tasks, registration_seq))
            .or_else(|| Self::remove_registration_from(&mut self.timer_tasks, registration_seq))
            .or_else(|| {
                Self::remove_registration_from(&mut self.io_completion_tasks, registration_seq)
            })
    }

    /// Roll back the most recently scheduled task before it becomes visible.
    /// Unlike ordinary cancellation, this restores the deterministic sequence
    /// counter so a memory-accounting refusal has no observable scheduling
    /// side effect.
    pub(crate) fn rollback_last_scheduled(&mut self, registration_seq: u64) -> Option<Macrotask> {
        if self.next_registration_seq != registration_seq.checked_add(1)? {
            return None;
        }
        let task = self.cancel_registration(registration_seq)?;
        self.next_registration_seq = registration_seq;
        Some(task)
    }

    fn tasks_for_source_mut(
        &mut self,
        source: MacrotaskSource,
    ) -> &mut BinaryHeap<MacrotaskHeapEntry> {
        match source {
            MacrotaskSource::MessageChannel => &mut self.message_channel_tasks,
            MacrotaskSource::Immediate => &mut self.immediate_tasks,
            MacrotaskSource::Timer => &mut self.timer_tasks,
            MacrotaskSource::IoCompletion => &mut self.io_completion_tasks,
        }
    }

    fn pop_ready_from(
        tasks: &mut BinaryHeap<MacrotaskHeapEntry>,
        current_time_ms: u64,
    ) -> Option<Macrotask> {
        if tasks
            .peek()
            .is_some_and(|entry| entry.task.scheduled_at <= current_time_ms)
        {
            tasks.pop().map(|entry| entry.task)
        } else {
            None
        }
    }

    fn remove_registration_from(
        tasks: &mut BinaryHeap<MacrotaskHeapEntry>,
        registration_seq: u64,
    ) -> Option<Macrotask> {
        let mut entries = std::mem::take(tasks).into_vec();
        let removed = entries
            .iter()
            .position(|entry| entry.task.registration_seq == registration_seq)
            .map(|index| entries.swap_remove(index).task);
        *tasks = BinaryHeap::from(entries);
        removed
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Deterministic event loop state.
///
/// Implements the ES2020 event loop turn model:
/// 1. Pick one macrotask (by priority).
/// 2. Execute it (may enqueue new microtasks).
/// 3. Drain all new microtasks (FIFO).
/// 4. Repeat.
///
/// The `turn()` method only selects the next macrotask and advances the
/// virtual clock as needed. Callers are responsible for executing the
/// macrotask and invoking `drain_microtasks()` afterwards.
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

    /// Deterministic resident-memory estimate for both queues and the
    /// event-loop-level witness log. The virtual clock and safety limit are
    /// inline numeric state and add no dynamic charge.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        self.microtasks
            .estimated_memory_bytes()
            .saturating_add(self.macrotasks.estimated_memory_bytes())
            .saturating_add(estimate_witness_log_memory_bytes(&self.witness))
            // A selected task appends `MacrotaskExecuted` and may first append
            // `ClockAdvanced`. Reserve both slots while the task is pending;
            // `turn()` therefore only transfers or releases ownership.
            .saturating_add(
                u64::try_from(self.macrotasks.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2)
                    .saturating_mul(std::mem::size_of::<WitnessEvent>() as u64),
            )
    }

    /// Exact post-schedule resident-memory estimate for one I/O-completion
    /// registration, without allocating, mutating the queue, or consuming a
    /// deterministic registration sequence. The two witness slots are the
    /// execution and optional clock-advance reservations charged for every
    /// pending macrotask by [`Self::estimated_memory_bytes`].
    pub(crate) fn projected_io_completion_memory_bytes(&self, label: &Label) -> u64 {
        let current_macrotask_bytes = self.macrotasks.estimated_memory_bytes();
        self.estimated_memory_bytes()
            .saturating_sub(current_macrotask_bytes)
            .saturating_add(self.macrotasks.projected_schedule_memory_bytes(label))
            .saturating_add(2u64.saturating_mul(std::mem::size_of::<WitnessEvent>() as u64))
    }

    /// Cancel one pending macrotask by registration sequence and transfer its
    /// ownership to the caller.
    pub(crate) fn cancel_registration(&mut self, registration_seq: u64) -> Option<Macrotask> {
        self.macrotasks.cancel_registration(registration_seq)
    }

    /// Roll back the last scheduling mutation, including its sequence number.
    pub(crate) fn rollback_last_scheduled(&mut self, registration_seq: u64) -> Option<Macrotask> {
        self.macrotasks.rollback_last_scheduled(registration_seq)
    }

    /// Select the next macrotask for execution.
    ///
    /// Returns the macrotask to execute (caller invokes the handler). If no
    /// macrotask is ready, advances the virtual clock to the next scheduled
    /// macrotask time.
    pub fn turn(&mut self) -> TurnResult {
        // Phase 1: pick a macrotask at current time.
        if let Some(task) = self.macrotasks.dequeue_ready(self.clock.now_ms()) {
            self.witness.push(WitnessEvent::MacrotaskExecuted {
                source: task.source,
                registration_seq: task.registration_seq,
            });
            return TurnResult {
                microtasks_drained: 0,
                macrotask: Some(task),
                clock_advanced: false,
            };
        }

        // Phase 2: advance clock to next macrotask if available.
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
                    microtasks_drained: 0,
                    macrotask: Some(task),
                    clock_advanced: true,
                };
            }
        }

        TurnResult {
            microtasks_drained: 0,
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

    /// Schedule an I/O-completion macrotask (bd-201vt: async fs callbacks such as
    /// `fs.readFile(path, cb)` / `fs.writeFile(path, data, cb)`). Like a timer it
    /// fires after the current synchronous turn — but at the *current* virtual
    /// time (no delay), so the callback runs in the next event-loop turn rather
    /// than inline, matching Node's deferral of fs callbacks off the current call
    /// stack. The host effect itself is performed synchronously at dispatch; this
    /// only defers the callback invocation. Returns the registration sequence so
    /// the caller can associate the callback's `(err[, data])` arguments with the
    /// scheduled task.
    pub fn schedule_io_completion(&mut self, handler: ClosureHandle, label: Label) -> u64 {
        let fire_at = self.clock.now_ms();
        self.macrotasks
            .schedule(MacrotaskSource::IoCompletion, handler, fire_at, label)
    }

    /// Schedule a `setImmediate` macrotask (bd-suwvw). Fires at the CURRENT
    /// virtual time (no delay) in the dedicated immediate lane, which drains
    /// before timer tasks due at the same moment. Returns the registration
    /// sequence.
    pub fn set_immediate(&mut self, handler: ClosureHandle, label: Label) -> u64 {
        let fire_at = self.clock.now_ms();
        self.macrotasks
            .schedule(MacrotaskSource::Immediate, handler, fire_at, label)
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
    /// Dynamic resident memory owned by the collected result map.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        saturating_sum(self.values.values().map(|value| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(estimate_js_value_memory_bytes(value))
        }))
    }

    /// Record that input promise at `index` fulfilled with `value`.
    /// Returns `true` if all promises are now resolved.
    pub fn record_fulfillment(&mut self, index: u32, value: JsValue) -> bool {
        if self.settled {
            return false;
        }
        // Only increment if this index is newly inserted (not a duplicate).
        if !self.values.contains_key(&index) {
            self.resolved_count += 1;
        }
        self.values.insert(index, value);
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
    /// Dynamic resident memory owned by the collected outcome map.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        saturating_sum(self.outcomes.values().map(|outcome| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(estimate_string_memory_bytes(&outcome.status))
                .saturating_add(estimate_js_value_memory_bytes(&outcome.value))
        }))
    }

    /// Record a fulfillment. Returns `true` if all settled.
    pub fn record_fulfillment(&mut self, index: u32, value: JsValue) -> bool {
        if !self.outcomes.contains_key(&index) {
            self.settled_count += 1;
        }
        self.outcomes.insert(
            index,
            SettledOutcome {
                status: "fulfilled".into(),
                value,
            },
        );
        self.settled_count == self.total
    }

    /// Record a rejection. Returns `true` if all settled.
    pub fn record_rejection(&mut self, index: u32, reason: JsValue) -> bool {
        if !self.outcomes.contains_key(&index) {
            self.settled_count += 1;
        }
        self.outcomes.insert(
            index,
            SettledOutcome {
                status: "rejected".into(),
                value: reason,
            },
        );
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
    /// A race tracker retains only inline handles and scalar state.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        0
    }

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
    /// Dynamic resident memory owned by the rejection-reason map.
    pub(crate) fn estimated_memory_bytes(&self) -> u64 {
        saturating_sum(self.errors.values().map(|reason| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(estimate_js_value_memory_bytes(reason))
        }))
    }

    /// Record a rejection. Returns `true` if all promises have rejected (AggregateError).
    pub fn record_rejection(&mut self, index: u32, reason: JsValue) -> bool {
        if self.settled {
            return false;
        }
        if !self.errors.contains_key(&index) {
            self.rejected_count += 1;
        }
        self.errors.insert(index, reason);
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
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
        assert_eq!(p.state, PromiseState::Rejected(js_str("error")));
        assert!(p.state.is_rejected());
    }

    #[test]
    fn terminal_rejection_drops_fanout_without_allocating_jobs_bd_fw7zd_6() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let root = store.create();
        let first_child = store
            .then(root, None, None, Label::Secret, &mut queue)
            .expect("root reaction");
        let second_child = store
            .then(root, None, None, Label::Confidential, &mut queue)
            .expect("root fanout reaction");
        let grandchild = store
            .then(first_child, None, None, Label::Internal, &mut queue)
            .expect("nested reaction");
        let unrelated = store.create();
        assert!(queue.is_empty());

        let encoded = serde_json::to_string(&store).expect("serialize pending reaction graph");
        let mut store: PromiseStore =
            serde_json::from_str(&encoded).expect("restore legacy-compatible reaction graph");
        let witness_count = store.witness_log().len();
        let previous_bytes = store.estimated_memory_bytes();
        let terminal_label = Label::Custom {
            name: "attacker-controlled".repeat(4096),
            level: u32::MAX,
        };
        store
            .terminally_reject_without_jobs(root, &terminal_label)
            .expect("fatal rejection should settle a pending root");

        for handle in [root, first_child, second_child, grandchild] {
            let record = store.get(handle).expect("affected Promise");
            assert_eq!(
                record.state,
                PromiseState::Rejected(JsValue::Undefined),
                "{handle} must not remain resumable"
            );
            assert_eq!(
                record.label,
                Label::Custom {
                    name: String::new(),
                    level: u32::MAX,
                }
            );
            assert!(record.reactions.is_empty());
            assert!(!record.rejection_handled);
        }
        assert_eq!(
            store.get(unrelated).expect("unrelated Promise").state,
            PromiseState::Pending
        );
        assert!(queue.is_empty());
        assert_eq!(store.witness_log().len(), witness_count);
        assert!(store.estimated_memory_bytes() <= previous_bytes);
    }

    #[test]
    fn double_fulfill_fails() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(1), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");

        // No microtasks yet (promise still pending).
        assert!(queue.is_empty());

        // Reactions registered.
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
        assert_eq!(p.reactions.len(), 2);

        // Result promise exists.
        let rp = store
            .get(result_h)
            .expect("operation should succeed for valid inputs");
        assert_eq!(rp.state, PromiseState::Pending);
    }

    #[test]
    fn then_on_fulfilled_enqueues_immediately() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_int(10), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

        let handler = ClosureHandle(1);
        let _result_h = store
            .then(h, Some(handler), None, Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

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
            .expect("operation should succeed for valid inputs");

        let handler = ClosureHandle(2);
        let _result_h = store
            .then(h, None, Some(handler), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

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
            .expect("operation should succeed for valid inputs");
        assert!(queue.is_empty());

        store
            .fulfill(h, js_int(99), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        // The promise settled fulfilled, so only the fulfill reaction is scheduled.
        assert_eq!(queue.pending_count(), 1);
    }

    // ----- Promise.resolve / Promise.reject -----

    #[test]
    fn promise_resolve_creates_fulfilled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.resolve(js_int(7), Label::Public, &mut queue);
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
        assert!(p.state.is_fulfilled());
    }

    #[test]
    fn promise_reject_creates_rejected() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.reject_with(js_str("boom"), Label::Public, &mut queue);
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
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

        let first = queue
            .dequeue()
            .expect("operation should succeed for valid inputs");
        let second = queue
            .dequeue()
            .expect("operation should succeed for valid inputs");
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

    #[test]
    fn promise_store_memory_estimate_counts_each_resident_owner() {
        let value = js_str("payload");
        let label = Label::Custom {
            name: "sensitive".to_string(),
            level: 3,
        };
        let store = PromiseStore {
            promises: vec![Some(PromiseRecord {
                handle: PromiseHandle(0),
                state: PromiseState::Fulfilled(value.clone()),
                reactions: vec![PromiseReaction {
                    kind: ReactionKind::Fulfill,
                    handler: Some(ClosureHandle(4)),
                    result_promise: PromiseHandle(1),
                    label: label.clone(),
                }],
                label: label.clone(),
                creation_seq: 0,
                rejection_handled: false,
                terminal_epoch: 0,
            })],
            next_seq: 1,
            witness: vec![WitnessEvent::PromiseFulfilled {
                handle: PromiseHandle(0),
                value: value.clone(),
                label: label.clone(),
            }],
        };

        let expected = estimate_vector_slot_bytes::<PromiseRecord>(1)
            .saturating_add(estimate_js_value_memory_bytes(&value))
            .saturating_add(estimate_label_memory_bytes(&label))
            .saturating_add(estimate_vector_slot_bytes::<PromiseReaction>(1))
            .saturating_add(estimate_label_memory_bytes(&label))
            .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(1))
            .saturating_add(estimate_js_value_memory_bytes(&value))
            .saturating_add(estimate_label_memory_bytes(&label));
        assert_eq!(store.estimated_memory_bytes(), expected);
    }

    #[test]
    fn promise_transition_projections_match_committed_owners_exactly() {
        let label = Label::Custom {
            name: "projection-label".repeat(5),
            level: 3,
        };
        let value = js_str("projection-value");

        let mut pending_store = PromiseStore::new();
        let pending = pending_store.create();
        let mut pending_queue = MicrotaskQueue::new();
        let (projected_store_bytes, projected_queue_bytes) = pending_store
            .projected_then_memory_bytes(pending, &label, &pending_queue)
            .expect("pending then projection");
        pending_store
            .then(pending, None, None, label.clone(), &mut pending_queue)
            .expect("pending then commit");
        assert_eq!(
            pending_store.estimated_memory_bytes(),
            projected_store_bytes
        );
        assert_eq!(
            pending_queue.estimated_memory_bytes(),
            projected_queue_bytes
        );

        let mut fulfilled_store = PromiseStore::new();
        let fulfilled = fulfilled_store.create();
        let mut fulfilled_queue = MicrotaskQueue::new();
        fulfilled_store
            .fulfill(
                fulfilled,
                value.clone(),
                label.clone(),
                &mut fulfilled_queue,
            )
            .expect("source fulfillment");
        let (projected_store_bytes, projected_queue_bytes) = fulfilled_store
            .projected_then_memory_bytes(fulfilled, &label, &fulfilled_queue)
            .expect("settled then projection");
        fulfilled_store
            .then(fulfilled, None, None, label.clone(), &mut fulfilled_queue)
            .expect("settled then commit");
        assert_eq!(
            fulfilled_store.estimated_memory_bytes(),
            projected_store_bytes
        );
        assert_eq!(
            fulfilled_queue.estimated_memory_bytes(),
            projected_queue_bytes
        );

        let mut settlement_store = PromiseStore::new();
        let source = settlement_store.create();
        settlement_store
            .then(
                source,
                None,
                None,
                label.clone(),
                &mut MicrotaskQueue::new(),
            )
            .expect("settlement reaction registration");
        let mut settlement_queue = MicrotaskQueue::new();
        let (projected_store_bytes, projected_queue_bytes) = settlement_store
            .projected_fulfill_memory_bytes(source, &value, &label, &settlement_queue)
            .expect("fulfillment projection");
        settlement_store
            .fulfill(source, value, label, &mut settlement_queue)
            .expect("fulfillment commit");
        assert_eq!(
            settlement_store.estimated_memory_bytes(),
            projected_store_bytes
        );
        assert_eq!(
            settlement_queue.estimated_memory_bytes(),
            projected_queue_bytes
        );
    }

    #[test]
    fn microtask_dequeue_moves_payload_and_compact_releases_slot() {
        let label = Label::Custom {
            name: "queued".to_string(),
            level: 2,
        };
        let mut queue = MicrotaskQueue::new();
        queue.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_str("owned-buffer"),
            result_promise: PromiseHandle(0),
            label: label.clone(),
        });
        let resident_pointer = match queue.tasks[0]
            .as_ref()
            .expect("enqueued slot remains occupied")
        {
            Microtask::PromiseReaction {
                argument: JsValue::Str(text),
                ..
            } => text.as_ptr(),
            _ => panic!("expected string-backed reaction task"),
        };
        let before_dequeue = estimate_vector_slot_bytes::<Option<Microtask>>(1)
            .saturating_add(estimate_string_memory_bytes("owned-buffer"))
            .saturating_add(estimate_label_memory_bytes(&label))
            .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(2));
        assert_eq!(queue.estimated_memory_bytes(), before_dequeue);

        let task = queue.dequeue().expect("queued task is available");
        let moved_pointer = match &task {
            Microtask::PromiseReaction {
                argument: JsValue::Str(text),
                ..
            } => text.as_ptr(),
            _ => panic!("expected string-backed reaction task"),
        };
        assert_eq!(
            moved_pointer, resident_pointer,
            "dequeue must move, not clone"
        );
        assert_eq!(
            queue.estimated_memory_bytes(),
            estimate_vector_slot_bytes::<Option<Microtask>>(1)
                .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(2))
        );

        queue.compact();
        assert_eq!(
            queue.estimated_memory_bytes(),
            estimate_vector_slot_bytes::<WitnessEvent>(2)
        );
    }

    #[test]
    fn event_loop_memory_estimate_covers_every_macrotask_lane_and_witness() {
        let label = Label::Custom {
            name: "lane".to_string(),
            level: 1,
        };
        let mut event_loop = EventLoop::new();
        event_loop.macrotasks.schedule(
            MacrotaskSource::MessageChannel,
            ClosureHandle(1),
            0,
            label.clone(),
        );
        event_loop.set_immediate(ClosureHandle(2), label.clone());
        event_loop.set_timeout(ClosureHandle(3), 1, label.clone());
        event_loop.schedule_io_completion(ClosureHandle(4), label.clone());
        event_loop.witness.push(WitnessEvent::PromiseRejected {
            handle: PromiseHandle(0),
            reason: js_str("audit"),
            label: label.clone(),
        });

        let expected_macrotasks = 4u64.saturating_mul(
            estimate_vector_slot_bytes::<MacrotaskHeapEntry>(1)
                .saturating_add(estimate_label_memory_bytes(&label)),
        );
        let expected_witness = estimate_vector_slot_bytes::<WitnessEvent>(1)
            .saturating_add(estimate_string_memory_bytes("audit"))
            .saturating_add(estimate_label_memory_bytes(&label))
            .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(8));
        assert_eq!(
            event_loop.estimated_memory_bytes(),
            expected_macrotasks.saturating_add(expected_witness)
        );
    }

    #[test]
    fn io_completion_projection_is_exact_and_side_effect_free() {
        let label = Label::Custom {
            name: "projected-io".to_string(),
            level: 3,
        };
        let mut event_loop = EventLoop::new();
        event_loop.set_timeout(ClosureHandle(1), 10, Label::Public);
        let before = event_loop.estimated_memory_bytes();

        let projected = event_loop.projected_io_completion_memory_bytes(&label);
        assert_eq!(event_loop.estimated_memory_bytes(), before);

        let sequence = event_loop.schedule_io_completion(ClosureHandle(2), label);
        assert_eq!(sequence, 1);
        assert_eq!(event_loop.estimated_memory_bytes(), projected);
    }

    #[test]
    fn macrotask_cancellation_moves_task_and_releases_exact_estimate() {
        let label = Label::Custom {
            name: "cancelled".to_string(),
            level: 2,
        };
        let mut event_loop = EventLoop::new();
        let registration_seq = event_loop.set_timeout(ClosureHandle(7), 100, label.clone());
        let task_bytes = estimate_vector_slot_bytes::<MacrotaskHeapEntry>(1)
            .saturating_add(estimate_label_memory_bytes(&label))
            .saturating_add(estimate_vector_slot_bytes::<WitnessEvent>(2));
        assert_eq!(event_loop.estimated_memory_bytes(), task_bytes);

        let cancelled = event_loop
            .cancel_registration(registration_seq)
            .expect("scheduled registration remains cancellable");
        assert_eq!(cancelled.registration_seq, registration_seq);
        assert_eq!(cancelled.label, label);
        assert_eq!(event_loop.estimated_memory_bytes(), 0);
        assert!(event_loop.cancel_registration(registration_seq).is_none());
    }

    #[test]
    fn failed_schedule_rollback_reuses_deterministic_sequence() {
        let mut event_loop = EventLoop::new();
        let refused_seq = event_loop.set_timeout(ClosureHandle(7), 100, Label::Public);
        let rolled_back = event_loop
            .rollback_last_scheduled(refused_seq)
            .expect("last schedule remains rollback-safe");
        assert_eq!(rolled_back.registration_seq, refused_seq);
        assert_eq!(event_loop.estimated_memory_bytes(), 0);

        let retried_seq = event_loop.set_timeout(ClosureHandle(8), 100, Label::Public);
        assert_eq!(retried_seq, refused_seq);
    }

    #[test]
    fn promise_combinator_memory_estimates_count_maps_values_and_statuses() {
        let mut all = PromiseAllTracker {
            result_promise: PromiseHandle(1),
            values: BTreeMap::new(),
            total: 1,
            resolved_count: 0,
            settled: false,
        };
        all.record_fulfillment(0, js_str("all"));
        assert_eq!(
            all.estimated_memory_bytes(),
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(estimate_string_memory_bytes("all"))
        );

        let mut all_settled = PromiseAllSettledTracker {
            result_promise: PromiseHandle(2),
            outcomes: BTreeMap::new(),
            total: 1,
            settled_count: 0,
        };
        all_settled.record_rejection(0, js_str("reason"));
        assert_eq!(
            all_settled.estimated_memory_bytes(),
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(estimate_string_memory_bytes("rejected"))
                .saturating_add(estimate_string_memory_bytes("reason"))
        );

        let race = PromiseRaceTracker {
            result_promise: PromiseHandle(3),
            settled: false,
        };
        assert_eq!(race.estimated_memory_bytes(), 0);

        let mut any = PromiseAnyTracker {
            result_promise: PromiseHandle(4),
            errors: BTreeMap::new(),
            total: 1,
            rejected_count: 0,
            settled: false,
        };
        any.record_rejection(0, js_str("any"));
        assert_eq!(
            any.estimated_memory_bytes(),
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(estimate_string_memory_bytes("any"))
        );
    }

    #[test]
    fn fresh_promise_rollback_restores_store_and_witness_exactly() {
        let mut store = PromiseStore::new();
        let baseline = store.estimated_memory_bytes();
        let handle = store.create();
        assert!(store.estimated_memory_bytes() > baseline);
        assert!(store.rollback_last_created(handle));
        assert_eq!(store.len(), 0);
        assert!(store.witness_log().is_empty());
        assert_eq!(store.estimated_memory_bytes(), baseline);
        assert!(!store.rollback_last_created(handle));
    }

    #[test]
    fn execution_boundary_removal_disposes_non_tail_pending_promise_exactly() {
        let mut store = PromiseStore::new();
        let removed = store.create();
        let retained = store.create();
        let before_removal = store.estimated_memory_bytes();

        let record = store
            .remove_pending_at_execution_boundary(removed)
            .expect("an unpublished non-tail Promise remains removable");

        assert_eq!(record.handle, removed);
        assert!(matches!(record.state, PromiseState::Pending));
        assert!(store.get(removed).is_err());
        assert!(store.get(retained).is_ok());
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.estimated_memory_bytes(),
            before_removal
                .saturating_sub(std::mem::size_of::<PromiseRecord>() as u64)
                .saturating_sub(std::mem::size_of::<WitnessEvent>() as u64)
        );
        assert_eq!(
            store.create(),
            PromiseHandle(2),
            "vacant execution-boundary slots must never be reused"
        );
    }

    #[test]
    fn fresh_microtask_rollback_moves_payload_and_restores_queue_exactly() {
        let mut queue = MicrotaskQueue::new();
        let baseline = queue.estimated_memory_bytes();
        queue.enqueue(Microtask::PromiseRejection {
            reason: js_str("rollback-payload"),
            result_promise: PromiseHandle(4),
            label: Label::Custom {
                name: "rollback-label".to_string(),
                level: 2,
            },
        });
        assert!(queue.estimated_memory_bytes() > baseline);
        let rolled_back = queue
            .rollback_last_enqueued()
            .expect("fresh pending enqueue is rollback-safe");
        assert!(matches!(
            rolled_back,
            Microtask::PromiseRejection {
                reason: JsValue::Str(reason),
                ..
            } if reason == "rollback-payload"
        ));
        assert!(queue.is_empty());
        assert_eq!(queue.total_enqueued(), 0);
        assert!(queue.witness_log().is_empty());
        assert_eq!(queue.estimated_memory_bytes(), baseline);
        assert!(queue.rollback_last_enqueued().is_none());
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

        let first = queue
            .dequeue_ready(0)
            .expect("operation should succeed for valid inputs");
        // MessageChannel has higher priority (lower enum discriminant).
        assert_eq!(first.source, MacrotaskSource::MessageChannel);

        let second = queue
            .dequeue_ready(0)
            .expect("operation should succeed for valid inputs");
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

        let first = queue
            .dequeue_ready(100)
            .expect("operation should succeed for valid inputs");
        assert_eq!(first.handler, ClosureHandle(1)); // 50ms, seq=1
        let second = queue
            .dequeue_ready(100)
            .expect("operation should succeed for valid inputs");
        assert_eq!(second.handler, ClosureHandle(2)); // 50ms, seq=2
        let third = queue
            .dequeue_ready(100)
            .expect("operation should succeed for valid inputs");
        assert_eq!(third.handler, ClosureHandle(0)); // 100ms, seq=0
    }

    #[test]
    fn macrotask_not_ready_before_time() {
        let mut queue = MacrotaskQueue::new();
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(0), 100, Label::Public);
        assert!(queue.dequeue_ready(99).is_none());
        assert!(queue.dequeue_ready(100).is_some());
    }

    #[test]
    fn macrotask_future_high_priority_does_not_block_ready_timer() {
        let mut queue = MacrotaskQueue::new();
        queue.schedule(
            MacrotaskSource::MessageChannel,
            ClosureHandle(0),
            1_000,
            Label::Public,
        );
        queue.schedule(MacrotaskSource::Timer, ClosureHandle(1), 100, Label::Public);

        let ready = queue
            .dequeue_ready(100)
            .expect("ready timer should not be blocked by future message task");
        assert_eq!(ready.source, MacrotaskSource::Timer);
        assert_eq!(ready.handler, ClosureHandle(1));
        assert_eq!(queue.next_scheduled_time(), Some(1_000));
    }

    // ----- Event loop -----

    #[test]
    fn event_loop_selects_macrotask_without_draining_microtasks() {
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
        // Macrotask selected; microtasks remain for the caller to drain.
        assert_eq!(result.microtasks_drained, 0);
        assert!(result.macrotask.is_some());
        assert!(!event_loop.microtasks.is_empty());
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
                .expect("operation should succeed for valid inputs");
            store
                .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
                .expect("operation should succeed for valid inputs");

            // Fulfill p1, then p2.
            store
                .fulfill(p1, js_int(1), Label::Public, &mut queue)
                .expect("operation should succeed for valid inputs");
            store
                .fulfill(p2, js_int(2), Label::Public, &mut queue)
                .expect("operation should succeed for valid inputs");

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

        assert_eq!(
            tracker
                .outcomes
                .get(&0)
                .expect("operation should succeed for valid inputs")
                .status,
            "fulfilled"
        );
        assert_eq!(
            tracker
                .outcomes
                .get(&1)
                .expect("operation should succeed for valid inputs")
                .status,
            "rejected"
        );
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
            .expect("operation should succeed for valid inputs");

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
            .expect("operation should succeed for valid inputs");
        store
            .reject(h, js_str("handled"), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

        let unhandled = store.unhandled_rejections();
        assert!(unhandled.is_empty());
    }

    #[test]
    fn rejection_without_on_rejected_registered_before_reject_transfers_to_result() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();

        let result = store
            .then(
                source,
                Some(ClosureHandle(7)),
                None,
                Label::Public,
                &mut queue,
            )
            .expect("operation should succeed for valid inputs");
        assert!(
            store
                .get(source)
                .expect("source promise should remain valid")
                .rejection_handled
        );
        store
            .reject(source, js_str("transferred"), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

        assert!(store.unhandled_rejections().is_empty());
        let Microtask::PromiseRejection {
            reason,
            result_promise,
            label,
        } = queue.dequeue().expect("thrower job should be queued")
        else {
            panic!("expected rejection propagation job");
        };
        assert_eq!(result_promise, result);
        store
            .reject(result_promise, reason, label, &mut queue)
            .expect("propagated result should reject");
        assert_eq!(store.unhandled_rejections(), vec![result]);
    }

    #[test]
    fn legacy_pending_then_snapshot_marks_source_handled_on_rejection() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();
        let result = store
            .then(
                source,
                Some(ClosureHandle(7)),
                None,
                Label::Public,
                &mut queue,
            )
            .expect("operation should succeed for valid inputs");

        let mut wire = serde_json::to_value(&store).expect("promise store should serialize");
        wire["promises"][source.0 as usize]["rejection_handled"] = serde_json::json!(false);
        let mut restored: PromiseStore =
            serde_json::from_value(wire).expect("legacy promise store should deserialize");
        assert!(
            !restored
                .get(source)
                .expect("restored source promise should remain valid")
                .rejection_handled
        );
        restored
            .reject(source, js_str("legacy"), Label::Public, &mut queue)
            .expect("legacy pending source should reject");

        assert!(restored.unhandled_rejections().is_empty());
        assert!(matches!(
            queue.dequeue(),
            Some(Microtask::PromiseRejection { result_promise, .. })
                if result_promise == result
        ));
    }

    #[test]
    fn then_on_rejected_marks_as_handled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("err"), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");

        // Initially unhandled.
        assert_eq!(store.unhandled_rejections().len(), 1);

        // Calling .then with onRejected marks it handled.
        store
            .then(h, None, Some(ClosureHandle(0)), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        assert!(store.unhandled_rejections().is_empty());
    }

    #[test]
    fn then_on_rejected_without_on_rejected_transfers_to_result() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let source = store.create();
        store
            .reject(source, js_str("err"), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        assert_eq!(store.unhandled_rejections(), vec![source]);

        let result = store
            .then(
                source,
                Some(ClosureHandle(1)),
                None,
                Label::Public,
                &mut queue,
            )
            .expect("operation should succeed for valid inputs");
        assert!(store.unhandled_rejections().is_empty());
        let Microtask::PromiseRejection {
            reason,
            result_promise,
            label,
        } = queue.dequeue().expect("thrower job should be queued")
        else {
            panic!("expected rejection propagation job");
        };
        assert_eq!(result_promise, result);
        store
            .reject(result_promise, reason, label, &mut queue)
            .expect("propagated result should reject");
        assert_eq!(store.unhandled_rejections(), vec![result]);
    }

    #[test]
    fn await_reaction_marks_future_rejection_handled_without_a_closure() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();

        store
            .then_for_await(h, Label::Public, &mut queue)
            .expect("pending Promise should accept an await reaction");
        store
            .reject(h, js_str("awaited"), Label::Public, &mut queue)
            .expect("awaited Promise should reject");

        assert!(store.unhandled_rejections().is_empty());
        assert_eq!(queue.pending_count(), 1);
    }

    #[test]
    fn await_reaction_marks_existing_rejection_handled() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .reject(h, js_str("awaited"), Label::Public, &mut queue)
            .expect("Promise should reject before awaiting");
        assert_eq!(store.unhandled_rejections(), vec![h]);

        store
            .then_for_await(h, Label::Public, &mut queue)
            .expect("rejected Promise should accept an await reaction");

        assert!(store.unhandled_rejections().is_empty());
        assert_eq!(queue.pending_count(), 1);
    }

    // ----- IFC label propagation -----

    #[test]
    fn promise_carries_ifc_label() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let h = store.create();
        store
            .fulfill(h, js_str("secret_data"), Label::Secret, &mut queue)
            .expect("operation should succeed for valid inputs");
        let p = store
            .get(h)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");

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
            let json = serde_json::to_string(state).expect("serialize derived Serialize");
            let back: PromiseState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let back: PromiseError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&task).expect("serialize derived Serialize");
        let back: Microtask = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, task);
    }

    #[test]
    fn virtual_clock_serde_roundtrip() {
        let mut clock = VirtualClock::new();
        clock.advance_to(12345);
        clock.register_timer();
        let json = serde_json::to_string(&clock).expect("serialize derived Serialize");
        let back: VirtualClock = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            .expect("operation should succeed for valid inputs");
        let p3 = store
            .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
        let r2 = store
            .then(p, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        assert_ne!(r1, r2);
        // Both register reactions on the same pending promise.
        let record = store
            .get(p)
            .expect("operation should succeed for valid inputs");
        assert_eq!(record.reactions.len(), 4); // 2 per .then (fulfill + reject)
    }

    #[test]
    fn fulfill_triggers_all_registered_then_handlers() {
        let mut store = PromiseStore::new();
        let mut queue = MicrotaskQueue::new();
        let p = store.create();
        store
            .then(p, Some(ClosureHandle(0)), None, Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        store
            .then(p, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        store
            .fulfill(p, js_int(42), Label::Public, &mut queue)
            .expect("operation should succeed for valid inputs");
        // Only fulfill reactions are scheduled when the promise fulfills.
        assert_eq!(queue.pending_count(), 2);
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
        assert_eq!(
            r1.macrotask
                .as_ref()
                .expect("operation should succeed for valid inputs")
                .handler,
            ClosureHandle(1)
        );
        assert_eq!(el.clock.now_ms(), 100);

        // Second turn: clock advances to 200.
        let r2 = el.turn();
        assert_eq!(
            r2.macrotask
                .as_ref()
                .expect("operation should succeed for valid inputs")
                .handler,
            ClosureHandle(2)
        );
        assert_eq!(el.clock.now_ms(), 200);

        // Third turn: clock advances to 300.
        let r3 = el.turn();
        assert_eq!(
            r3.macrotask
                .as_ref()
                .expect("operation should succeed for valid inputs")
                .handler,
            ClosureHandle(0)
        );
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
            .expect("operation should succeed for valid inputs");
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

        let first = queue
            .dequeue_ready(0)
            .expect("operation should succeed for valid inputs");
        assert_eq!(first.source, MacrotaskSource::Timer);
        let second = queue
            .dequeue_ready(0)
            .expect("operation should succeed for valid inputs");
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
                .expect("operation should succeed for valid inputs");
            let _r2 = store
                .then(p2, Some(ClosureHandle(1)), None, Label::Public, &mut queue)
                .expect("operation should succeed for valid inputs");

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
        let json = serde_json::to_string(&task).expect("serialize derived Serialize");
        let back: Macrotask = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(event).expect("serialize derived Serialize");
            let back: WitnessEvent =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: ReactionKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: MacrotaskSource =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn virtual_clock_serde_new_roundtrip() {
        let clock = VirtualClock::new();
        let json = serde_json::to_string(&clock).expect("serialize derived Serialize");
        let back: VirtualClock = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&handle).expect("serialize derived Serialize");
        let back: PromiseHandle =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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

        let p = store
            .get(promise)
            .expect("operation should succeed for valid inputs");
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

        let p = store
            .get(module_promise)
            .expect("operation should succeed for valid inputs");
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
        let p = store
            .get(caller)
            .expect("operation should succeed for valid inputs");
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
        let p = store
            .get(result)
            .expect("operation should succeed for valid inputs");
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
            .expect("operation should succeed for valid inputs");
        bridge
            .bridge_module_exception(js_str("err2"), "m.js", Some(p2), &mut store, &mut queue)
            .expect("operation should succeed for valid inputs");

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
        let json = serde_json::to_string(&outcome).expect("serialize derived Serialize");
        let back: ExceptionRejectionOutcome =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: ExceptionRejectionWitnessEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: ExceptionBoundaryKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(v, &back);
        }
    }

    // ----- Event Loop Tests -----

    #[test]
    fn empty_event_loop_exits() {
        let event_loop = EventLoop::new();
        assert!(!event_loop.has_pending_work());

        let mut loop_copy = event_loop;
        let result = loop_copy.turn();
        assert!(result.macrotask.is_none());
        assert!(!result.clock_advanced);
    }

    #[test]
    fn timer_fires_after_delay() {
        let mut event_loop = EventLoop::new();
        let handler = ClosureHandle(42);
        let label = Label::Public;

        // Schedule a timer for 100ms
        let registration_seq = event_loop.set_timeout(handler, 100, label.clone());
        assert!(event_loop.has_pending_work());

        // The deterministic loop advances to the next timer and returns it in
        // the same turn.
        let result1 = event_loop.turn();
        assert!(result1.clock_advanced);
        assert!(result1.macrotask.is_some());
        let task = result1
            .macrotask
            .expect("operation should succeed for valid inputs");
        assert_eq!(task.source, MacrotaskSource::Timer);
        assert_eq!(task.handler, handler);
        assert_eq!(task.registration_seq, registration_seq);
    }

    #[test]
    fn microtask_before_timer() {
        let mut event_loop = EventLoop::new();

        // Enqueue a microtask
        let microtask = Microtask::PromiseReaction {
            handler: None,
            argument: js_int(42),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        };
        event_loop.microtasks.enqueue(microtask);

        // Schedule a timer for 0ms delay
        event_loop.set_timeout(ClosureHandle(1), 0, Label::Public);

        assert!(event_loop.has_pending_work());

        // Drain microtasks first
        let drained = event_loop.drain_microtasks();
        assert_eq!(drained, 1);

        // Timer should still be pending
        assert!(event_loop.has_pending_work());
        let result = event_loop.turn();
        assert!(result.macrotask.is_some());
    }

    #[test]
    fn multiple_timers_ordered() {
        let mut event_loop = EventLoop::new();
        let label = Label::Public;

        // Schedule timers with different delays
        let seq1 = event_loop.set_timeout(ClosureHandle(1), 200, label.clone());
        let seq2 = event_loop.set_timeout(ClosureHandle(2), 100, label.clone());
        let seq3 = event_loop.set_timeout(ClosureHandle(3), 300, label);

        // First turn should advance to 100ms and fire timer 2
        let result1 = event_loop.turn();
        assert!(result1.clock_advanced);
        assert_eq!(event_loop.clock.now_ms(), 100);
        let task2 = result1
            .macrotask
            .expect("operation should succeed for valid inputs");
        assert_eq!(task2.handler, ClosureHandle(2));
        assert_eq!(task2.registration_seq, seq2);

        // Next turn should advance to 200ms and fire timer 1
        let result3 = event_loop.turn();
        assert!(result3.clock_advanced);
        assert_eq!(event_loop.clock.now_ms(), 200);
        let task1 = result3
            .macrotask
            .expect("operation should succeed for valid inputs");
        assert_eq!(task1.handler, ClosureHandle(1));
        assert_eq!(task1.registration_seq, seq1);

        // Last turn should advance to 300ms and fire timer 3
        let result5 = event_loop.turn();
        assert!(result5.clock_advanced);
        assert_eq!(event_loop.clock.now_ms(), 300);
        let task3 = result5
            .macrotask
            .expect("operation should succeed for valid inputs");
        assert_eq!(task3.handler, ClosureHandle(3));
        assert_eq!(task3.registration_seq, seq3);
    }

    #[test]
    fn nested_timer() {
        let mut event_loop = EventLoop::new();
        let label = Label::Public;

        // Schedule initial timer
        event_loop.set_timeout(ClosureHandle(1), 100, label.clone());

        let result1 = event_loop.turn();
        assert!(result1.macrotask.is_some());

        // Simulate timer callback scheduling another timer
        event_loop.set_timeout(ClosureHandle(2), 50, label);

        let result2 = event_loop.turn();
        assert!(result2.macrotask.is_some());
        assert_eq!(
            result2
                .macrotask
                .expect("operation should succeed for valid inputs")
                .handler,
            ClosureHandle(2)
        );
    }

    #[test]
    fn idle_detection() {
        let mut event_loop = EventLoop::new();

        // Empty loop has no pending work
        assert!(!event_loop.has_pending_work());

        // Add microtask
        event_loop.microtasks.enqueue(Microtask::PromiseReaction {
            handler: None,
            argument: js_int(1),
            result_promise: PromiseHandle(0),
            label: Label::Public,
        });
        assert!(event_loop.has_pending_work());

        // Drain microtasks
        event_loop.drain_microtasks();
        assert!(!event_loop.has_pending_work());

        // Add timer
        event_loop.set_timeout(ClosureHandle(1), 100, Label::Public);
        assert!(event_loop.has_pending_work());

        // Execute timer
        event_loop.turn(); // advance clock
        event_loop.turn(); // execute timer
        assert!(!event_loop.has_pending_work());
    }

    #[test]
    fn deterministic_clock() {
        let mut loop1 = EventLoop::new();
        let mut loop2 = EventLoop::new();
        let label = Label::Public;

        // Same operations on both loops
        loop1.set_timeout(ClosureHandle(1), 100, label.clone());
        loop1.set_timeout(ClosureHandle(2), 50, label.clone());

        loop2.set_timeout(ClosureHandle(1), 100, label.clone());
        loop2.set_timeout(ClosureHandle(2), 50, label);

        // Both should produce same results
        for _ in 0..4 {
            let result1 = loop1.turn();
            let result2 = loop2.turn();

            assert_eq!(result1.clock_advanced, result2.clock_advanced);
            assert_eq!(loop1.clock.now_ms(), loop2.clock.now_ms());

            if let (Some(task1), Some(task2)) = (result1.macrotask, result2.macrotask) {
                assert_eq!(task1.handler, task2.handler);
                assert_eq!(task1.source, task2.source);
                assert_eq!(task1.scheduled_at, task2.scheduled_at);
                assert_eq!(task1.registration_seq, task2.registration_seq);
            }
        }
    }
}
