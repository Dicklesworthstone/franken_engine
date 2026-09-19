//! Bounded, deterministic round-robin execution of Wasm startup and exports.
//!
//! This is a synchronous scheduler: the embedder drives each turn and supplies
//! the current policy. No thread, timer, ambient authority or cached grant is
//! installed. One turn resumes at most one invocation; a pending invocation
//! rejoins the tail, so an infinite guest cannot monopolize subsequent turns.
//! Quanta are soft, just like `WasmNativeCall::resume`: native providers and
//! individual bulk operations must still bound their own work. Startup shares
//! the same ready queue and admission limit, not a priority or unbounded lane.

use std::collections::VecDeque;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};

use serde::{Deserialize, Serialize};

use crate::checkpoint::CancellationToken;
use crate::module_resolver::{CapabilityPolicyHook, ResolutionContext};

use super::numeric::WasmNumericExecution;
use super::{WasmNativeCall, WasmNativeCallStep, WasmNativeInstance, WasmNativeLoadError};

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
    work: TaskWork<'call, 'vm>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmTaskKind { Call, Startup }

#[derive(Debug)]
enum TaskWork<'call, 'vm> {
    Call(WasmNativeCall<'call, 'vm>),
    Startup(WasmStartupTask<'vm>),
}

enum TaskStep<'call, 'vm> {
    Pending(TaskWork<'call, 'vm>),
    Complete(WasmTaskOutcome<'vm>, u64),
}

impl<'call, 'vm> TaskWork<'call, 'vm> {
    fn kind(&self) -> WasmTaskKind {
        match self { Self::Call(_) => WasmTaskKind::Call, Self::Startup(_) => WasmTaskKind::Startup }
    }

    fn instructions_executed(&self) -> u64 {
        match self {
            Self::Call(call) => call.instructions_executed(),
            Self::Startup(startup) => startup.instructions_executed(),
        }
    }

    fn resume(
        self, work: NonZeroU64, context: &ResolutionContext, policy: &CapabilityPolicyHook,
    ) -> Result<TaskStep<'call, 'vm>, WasmNativeLoadError> {
        Ok(match self {
            Self::Call(call) => match call.resume(work, context, policy)? {
                WasmNativeCallStep::Pending(call) => TaskStep::Pending(Self::Call(call)),
                WasmNativeCallStep::Complete(execution) => {
                    let after = execution.instructions_executed;
                    TaskStep::Complete(WasmTaskOutcome::Complete(execution), after)
                }
            },
            Self::Startup(startup) => match startup.resume(work, context, policy)? {
                WasmStartupStep::Pending(startup) => TaskStep::Pending(Self::Startup(startup)),
                WasmStartupStep::Complete(instance) => {
                    let after = instance.start_execution(context, policy)?
                        .map_or(0, |execution| execution.instructions_executed);
                    TaskStep::Complete(WasmTaskOutcome::Initialized(instance), after)
                }
            },
        })
    }
}

#[derive(Debug)]
pub enum WasmTaskOutcome<'vm> {
    /// Startup alone publishes an instance. Export results use Complete.
    Initialized(WasmNativeInstance<'vm>),
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
pub struct WasmScheduledTurn<'vm> {
    pub task_id: WasmTaskId,
    pub kind: WasmTaskKind,
    pub outcome: WasmTaskOutcome<'vm>,
    pub event: WasmScheduleEvent,
}

/// Ready startup attempts and export invocations share one bounded FIFO queue.
/// Startup owns unpublished state; export calls exclusively borrow their instance.
/// Each continuation keeps its cumulative VM meter across turns.
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

    /// Report the next phase without authorizing or reordering its work.
    pub fn next_task_kind(&self) -> Option<WasmTaskKind> {
        self.ready.front().map(|task| task.work.kind())
    }

    fn reserve_slot(&mut self) -> Result<WasmTaskHandle, WasmTaskAdmissionErrorKind> {
        if self.ready.len() >= self.max_tasks.get() {
            return Err(WasmTaskAdmissionErrorKind::QueueFull);
        }
        let id = self.next_id.ok_or(WasmTaskAdmissionErrorKind::IdSpaceExhausted)?.get();
        self.ready.try_reserve(1).map_err(|_| WasmTaskAdmissionErrorKind::AllocationFailed)?;
        self.next_id = id.checked_add(1).and_then(NonZeroU64::new);
        Ok(WasmTaskHandle { id: WasmTaskId(id), cancellation: CancellationToken::new() })
    }

    pub fn submit(
        &mut self,
        call: WasmNativeCall<'call, 'vm>,
    ) -> Result<WasmTaskHandle, Box<WasmTaskAdmissionError<'call, 'vm>>> {
        let handle = match self.reserve_slot() {
            Ok(handle) => handle,
            Err(kind) => return Err(Box::new(WasmTaskAdmissionError { kind, call })),
        };
        self.ready.push_back(Task { handle: handle.clone(), work: TaskWork::Call(call) });
        Ok(handle)
    }

    /// Admit initialization without linking, allocating guest state or executing
    /// its start function. Startup and exports consume the SAME queue capacity
    /// and get the SAME FIFO turn ordering. Rejection returns the original task,
    /// including any work already completed before submission to this scheduler.
    pub fn submit_startup(
        &mut self,
        startup: WasmStartupTask<'vm>,
    ) -> Result<WasmTaskHandle, Box<WasmStartupAdmissionError<'vm>>> {
        let handle = match self.reserve_slot() {
            Ok(handle) => handle,
            Err(kind) => return Err(Box::new(WasmStartupAdmissionError { kind, startup })),
        };
        self.ready.push_back(Task { handle: handle.clone(), work: TaskWork::Startup(startup) });
        Ok(handle)
    }

    /// Transfer an unfinished call back to its embedder without executing it.
    /// Removing a task also removes its queue position. Its old handle cannot
    /// cancel any subsequent submission, even if the same call is resubmitted.
    /// A cancelled task stays queued for its terminal cancellation event; it
    /// cannot be rescued by transferring its continuation to a fresh signal.
    pub fn take(&mut self, id: WasmTaskId) -> Option<WasmNativeCall<'call, 'vm>> {
        let index = self.ready.iter().position(|task| task.handle.id == id)?;
        if self.ready[index].handle.cancellation.is_cancelled()
            || !matches!(&self.ready[index].work, TaskWork::Call(_)) { return None; }
        match self.ready.remove(index)?.work {
            TaskWork::Call(call) => Some(call),
            TaskWork::Startup(_) => unreachable!("checked task kind"),
        }
    }

    /// Withdraw only startup work. A wrong-kind or cancelled ID does not remove
    /// or reorder anything. Cancellation observed before withdrawal cannot be
    /// erased by transferring a task into a fresh scheduler scope.
    pub fn take_startup(&mut self, id: WasmTaskId) -> Option<WasmStartupTask<'vm>> {
        let index = self.ready.iter().position(|task| task.handle.id == id)?;
        if self.ready[index].handle.cancellation.is_cancelled()
            || !matches!(&self.ready[index].work, TaskWork::Startup(_)) { return None; }
        match self.ready.remove(index)?.work {
            TaskWork::Startup(startup) => Some(startup),
            TaskWork::Call(_) => unreachable!("checked task kind"),
        }
    }

    /// Execute exactly one ready task's slice using the supplied current
    /// resolver policy. Policy denial, VM traps and cancellation retire only
    /// that task, never the other ready tasks. Pending work rejoins the tail
    /// without allocation. No-start initialization reports zero startup work.
    /// Successful startup returns Initialized only after the post-slice task
    /// cancellation check; cancellation never leaks a ready partial instance.
    pub fn run_next(
        &mut self,
        work: NonZeroU64,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Option<WasmScheduledTurn<'vm>> {
        let task = self.ready.pop_front()?;
        let id = task.handle.id;
        let kind = task.work.kind();
        let before = task.work.instructions_executed();
        let (outcome, after) = if task.handle.cancellation.is_cancelled() {
            drop(task.work);
            (WasmTaskOutcome::Cancelled, Some(before))
        } else {
            match task.work.resume(work, context, policy) {
                Ok(TaskStep::Pending(work)) => {
                    let after = work.instructions_executed();
                    if task.handle.cancellation.is_cancelled() {
                        drop(work);
                        (WasmTaskOutcome::Cancelled, Some(after))
                    } else {
                        self.ready.push_back(Task { handle: task.handle, work });
                        (WasmTaskOutcome::Pending, Some(after))
                    }
                }
                Ok(TaskStep::Complete(outcome, after)) => {
                    if task.handle.cancellation.is_cancelled() {
                        // A startup may have just finished. Its state must not
                        // escape after this invocation was cancelled by a host.
                        drop(outcome);
                        (WasmTaskOutcome::Cancelled, Some(after))
                    } else { (outcome, Some(after)) }
                }
                Err(error) => (WasmTaskOutcome::Failed(error), None),
            }
        };
        let (label, code) = match &outcome {
            WasmTaskOutcome::Pending => ("yield", "none"),
            WasmTaskOutcome::Complete(_) => ("complete", "none"),
            WasmTaskOutcome::Initialized(_) => ("initialized", "none"),
            WasmTaskOutcome::Cancelled => ("cancel", "FE-WASMSCHED-0001"),
            WasmTaskOutcome::Failed(WasmNativeLoadError::Resolution(_)) => ("deny", "FE-WASMSCHED-0002"),
            WasmTaskOutcome::Failed(_) => ("error", "FE-WASMSCHED-0003"),
        };
        Some(WasmScheduledTurn {
            task_id: id,
            kind,
            event: WasmScheduleEvent {
                trace_id: context.trace_id.clone(), decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(), component: WASM_NATIVE_SCHEDULER_COMPONENT.into(),
                event: match kind {
                    WasmTaskKind::Call => "wasm_schedule_turn",
                    WasmTaskKind::Startup => "wasm_startup_turn",
                }.into(), outcome: label.into(), error_code: code.into(),
                task_id: id, work_before: before, work_after: after,
            },
            outcome,
        })
    }
}

// Type erasure is confined to this scheduling seam; only the resolver can
// construct a driver. It owns one numeric startup state machine, not a second
// evaluator or a caller-provided arbitrary Future with an unenforced quantum.
type StartupAdvance<'vm> = dyn FnMut(
    NonZeroU64, &ResolutionContext, &CapabilityPolicyHook,
) -> Result<(u64, Option<WasmNativeInstance<'vm>>), WasmNativeLoadError> + Send + Sync + 'vm;

/// Lazy, resolver-created initialization. Preparing a task neither allocates
/// guest memory nor enters a provider. Each consuming resume needs the current
/// policy snapshot. Completed/failed attempts cannot be resumed or cloned.
///
/// Only Complete exposes an instance; Pending grants no memory/global/export
/// access. Drop discards unpublished guest state, never completed external I/O.
#[must_use = "resume the startup task or explicitly drop it to cancel"]
pub struct WasmStartupTask<'vm> {
    advance: Box<StartupAdvance<'vm>>,
    instructions: u64,
}

impl fmt::Debug for WasmStartupTask<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmStartupTask")
            .field("instructions_executed", &self.instructions)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[must_use = "retain pending initialization or consume the completed instance"]
pub enum WasmStartupStep<'vm> {
    Pending(WasmStartupTask<'vm>),
    Complete(WasmNativeInstance<'vm>),
}

impl<'vm> WasmStartupTask<'vm> {
    pub(crate) fn new<F>(advance: F) -> Self
    where
        F: FnMut(NonZeroU64, &ResolutionContext, &CapabilityPolicyHook)
            -> Result<(u64, Option<WasmNativeInstance<'vm>>), WasmNativeLoadError> + Send + Sync + 'vm,
    {
        Self { advance: Box::new(advance), instructions: 0 }
    }

    /// Run one soft quantum using the caller's current policy, including first
    /// allocation and no-start publication. The original startup hard budget
    /// spans all slices. Setup, bulk instructions and native callbacks remain
    /// indivisible; this is not native-code preemption or a wall-clock deadline.
    /// Use live execution/host controls for cancellation within a running slice.
    pub fn resume(
        mut self,
        work: NonZeroU64,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmStartupStep<'vm>, WasmNativeLoadError> {
        let (instructions, instance) = (self.advance)(work, context, policy)?;
        self.instructions = instructions;
        Ok(match instance {
            Some(instance) => WasmStartupStep::Complete(instance),
            None => WasmStartupStep::Pending(self),
        })
    }

    /// Charged startup work, not allocation/copying outside guest execution.
    pub fn instructions_executed(&self) -> u64 { self.instructions }

    /// Discard unfinished initialization; completed host effects remain real.
    pub fn cancel(self) {}
}

/// Rejected startup admission returns its exact owned initialization, not a
/// new attempt. A caller may retry it without repeating any previous effects.
#[derive(Debug)]
pub struct WasmStartupAdmissionError<'vm> {
    kind: WasmTaskAdmissionErrorKind,
    startup: WasmStartupTask<'vm>,
}

impl<'vm> WasmStartupAdmissionError<'vm> {
    pub fn kind(&self) -> WasmTaskAdmissionErrorKind { self.kind }
    pub fn into_startup(self) -> WasmStartupTask<'vm> { self.startup }
}

impl fmt::Display for WasmStartupAdmissionError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            WasmTaskAdmissionErrorKind::QueueFull => f.write_str("wasm scheduler is at its task limit"),
            WasmTaskAdmissionErrorKind::IdSpaceExhausted => f.write_str("wasm scheduler task identities exhausted"),
            WasmTaskAdmissionErrorKind::AllocationFailed => f.write_str("cannot allocate a wasm scheduler task slot"),
        }
    }
}

impl std::error::Error for WasmStartupAdmissionError<'_> {}
