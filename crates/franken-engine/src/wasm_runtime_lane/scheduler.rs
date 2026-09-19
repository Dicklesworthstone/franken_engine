//! Bounded, deterministic round-robin execution of resolver-backed Wasm calls.
//!
//! This is a synchronous scheduler: the embedder drives each turn and supplies
//! the current policy. No thread, timer, ambient authority or cached grant is
//! installed. One turn resumes at most one invocation; a pending invocation
//! rejoins the tail, so an infinite guest cannot monopolize subsequent turns.
//! Quanta are soft, just like `WasmNativeCall::resume`: native providers and
//! individual bulk operations must still bound their own work.

use std::collections::VecDeque;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};

use serde::{Deserialize, Serialize};

use crate::checkpoint::CancellationToken;
use crate::module_resolver::{CapabilityPolicyHook, ResolutionContext};

use super::numeric::WasmNumericExecution;
use super::{WasmNativeCall, WasmNativeCallStep, WasmNativeLoadError};

pub const WASM_NATIVE_SCHEDULER_COMPONENT: &str = "wasm_native_scheduler";

/// An identity issued once by a scheduler. IDs are never reused, including
/// after cancellation, completion or removal. An ID is not execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WasmTaskId(u64);

impl WasmTaskId {
    pub fn get(self) -> u64 { self.0 }
}

/// A cancellation request for exactly one submitted invocation, not its entire
/// instance. The token is intentionally private: resetting it or attaching it
/// to another task is not part of this interface. Clones share the same request.
#[derive(Debug, Clone)]
pub struct WasmTaskHandle {
    id: WasmTaskId,
    cancellation: CancellationToken,
}

impl WasmTaskHandle {
    pub fn id(&self) -> WasmTaskId { self.id }

    /// Observed before the next turn and after a successful slice. This does
    /// not interrupt a running native callback or undo a slice's effects. Use
    /// the instance's execution-cancellation subscription for opcode polling.
    pub fn cancel(&self) { self.cancellation.cancel(); }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmTaskAdmissionErrorKind {
    QueueFull,
    IdSpaceExhausted,
    AllocationFailed,
}

/// Rejected admission returns ownership of the still-unexecuted continuation.
/// The caller can retry elsewhere or explicitly cancel it; no task disappears
/// merely because the queue is full.
#[derive(Debug)]
pub struct WasmTaskAdmissionError<'call, 'vm> {
    kind: WasmTaskAdmissionErrorKind,
    call: WasmNativeCall<'call, 'vm>,
}

impl<'call, 'vm> WasmTaskAdmissionError<'call, 'vm> {
    pub fn kind(&self) -> WasmTaskAdmissionErrorKind { self.kind }
    pub fn into_call(self) -> WasmNativeCall<'call, 'vm> { self.call }
}

impl fmt::Display for WasmTaskAdmissionError<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            WasmTaskAdmissionErrorKind::QueueFull => f.write_str("wasm scheduler is at its task limit"),
            WasmTaskAdmissionErrorKind::IdSpaceExhausted => f.write_str("wasm scheduler task identities exhausted"),
            WasmTaskAdmissionErrorKind::AllocationFailed => f.write_str("cannot allocate a wasm scheduler task slot"),
        }
    }
}

impl std::error::Error for WasmTaskAdmissionError<'_, '_> {}

#[derive(Debug)]
struct Task<'call, 'vm> {
    handle: WasmTaskHandle,
    call: WasmNativeCall<'call, 'vm>,
}

#[derive(Debug)]
pub enum WasmTaskOutcome {
    Pending,
    Complete(WasmNumericExecution),
    Failed(WasmNativeLoadError),
    Cancelled,
}

/// One event per returned turn, not an unbounded scheduler-owned audit buffer.
/// Failed calls retain their original typed error in the accompanying outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmScheduleEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub task_id: WasmTaskId,
    pub work_before: u64,
    /// The existing consuming resume API does not return its meter on failure.
    /// None means unknown, NOT zero work and NOT a refunded invocation budget.
    pub work_after: Option<u64>,
}

#[derive(Debug)]
#[must_use = "consume the task outcome and its scheduling event"]
pub struct WasmScheduledTurn {
    pub task_id: WasmTaskId,
    pub outcome: WasmTaskOutcome,
    pub event: WasmScheduleEvent,
}

/// Ready invocations from independently instantiated modules. Each continuation
/// keeps its exclusive instance borrow and cumulative VM meter across turns.
/// Completed results/errors leave the scheduler immediately, freeing capacity;
/// the embedder owns any longer-lived result retention and backpressure.
#[derive(Debug)]
pub struct WasmNativeScheduler<'call, 'vm> {
    ready: VecDeque<Task<'call, 'vm>>,
    max_tasks: NonZeroUsize,
    next_id: Option<NonZeroU64>,
}

impl<'call, 'vm> WasmNativeScheduler<'call, 'vm> {
    pub fn new(max_tasks: NonZeroUsize) -> Self {
        Self { ready: VecDeque::new(), max_tasks, next_id: NonZeroU64::new(1) }
    }

    pub fn len(&self) -> usize { self.ready.len() }
    pub fn is_empty(&self) -> bool { self.ready.is_empty() }
    pub fn capacity_limit(&self) -> usize { self.max_tasks.get() }

    /// Inspect the next identity so the embedder can select its current policy
    /// and trace context. This does not consume, reorder or authorize the call.
    pub fn next_task(&self) -> Option<WasmTaskId> {
        self.ready.front().map(|task| task.handle.id)
    }

    pub fn submit(
        &mut self,
        call: WasmNativeCall<'call, 'vm>,
    ) -> Result<WasmTaskHandle, Box<WasmTaskAdmissionError<'call, 'vm>>> {
        let refusal = if self.ready.len() >= self.max_tasks.get() {
            Some(WasmTaskAdmissionErrorKind::QueueFull)
        } else if self.next_id.is_none() {
            Some(WasmTaskAdmissionErrorKind::IdSpaceExhausted)
        } else if self.ready.try_reserve(1).is_err() {
            Some(WasmTaskAdmissionErrorKind::AllocationFailed)
        } else { None };
        if let Some(kind) = refusal {
            return Err(Box::new(WasmTaskAdmissionError { kind, call }));
        }
        let id = self.next_id.expect("admitted scheduler identity").get();
        self.next_id = id.checked_add(1).and_then(NonZeroU64::new);
        let handle = WasmTaskHandle { id: WasmTaskId(id), cancellation: CancellationToken::new() };
        self.ready.push_back(Task { handle: handle.clone(), call });
        Ok(handle)
    }

    /// Transfer an unfinished call back to its embedder without executing it.
    /// Removing a task also removes its queue position. Its old handle cannot
    /// cancel any subsequent submission, even if the same call is resubmitted.
    /// A cancelled task stays queued for its terminal cancellation event; it
    /// cannot be rescued by transferring its continuation to a fresh signal.
    pub fn take(&mut self, id: WasmTaskId) -> Option<WasmNativeCall<'call, 'vm>> {
        let index = self.ready.iter().position(|task| task.handle.id == id)?;
        if self.ready[index].handle.cancellation.is_cancelled() { return None; }
        Some(self.ready.remove(index)?.call)
    }

    /// Execute exactly one ready task's slice using the supplied current
    /// resolver policy. Policy denial, VM traps and cancellation retire only
    /// that invocation, never the other ready tasks. A pending call rejoins
    /// the tail without allocating: popping it already freed one queue slot.
    pub fn run_next(
        &mut self,
        work: NonZeroU64,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Option<WasmScheduledTurn> {
        let task = self.ready.pop_front()?;
        let id = task.handle.id;
        let before = task.call.instructions_executed();
        let (outcome, after) = if task.handle.cancellation.is_cancelled() {
            task.call.cancel();
            (WasmTaskOutcome::Cancelled, Some(before))
        } else {
            match task.call.resume(work, context, policy) {
                Ok(WasmNativeCallStep::Pending(call)) => {
                    let after = call.instructions_executed();
                    if task.handle.cancellation.is_cancelled() {
                        call.cancel();
                        (WasmTaskOutcome::Cancelled, Some(after))
                    } else {
                        self.ready.push_back(Task { handle: task.handle, call });
                        (WasmTaskOutcome::Pending, Some(after))
                    }
                }
                Ok(WasmNativeCallStep::Complete(execution)) => {
                    let after = execution.instructions_executed;
                    if task.handle.cancellation.is_cancelled() {
                        (WasmTaskOutcome::Cancelled, Some(after))
                    } else { (WasmTaskOutcome::Complete(execution), Some(after)) }
                }
                Err(error) => (WasmTaskOutcome::Failed(error), None),
            }
        };
        let (label, code) = match &outcome {
            WasmTaskOutcome::Pending => ("yield", "none"),
            WasmTaskOutcome::Complete(_) => ("complete", "none"),
            WasmTaskOutcome::Cancelled => ("cancel", "FE-WASMSCHED-0001"),
            WasmTaskOutcome::Failed(WasmNativeLoadError::Resolution(_)) => ("deny", "FE-WASMSCHED-0002"),
            WasmTaskOutcome::Failed(_) => ("error", "FE-WASMSCHED-0003"),
        };
        Some(WasmScheduledTurn {
            task_id: id,
            event: WasmScheduleEvent {
                trace_id: context.trace_id.clone(), decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(), component: WASM_NATIVE_SCHEDULER_COMPONENT.into(),
                event: "wasm_schedule_turn".into(), outcome: label.into(), error_code: code.into(),
                task_id: id, work_before: before, work_after: after,
            },
            outcome,
        })
    }
}
