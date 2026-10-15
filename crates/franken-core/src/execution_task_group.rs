//! Bounded ownership of prepaid native workers and their uncollected results.
//!
//! This is a host-side owner of the existing `ExecutionTask`, not a second VM
//! or a replacement for the constitutional control-plane scheduler. A private
//! child work pool isolates cancellation and irreversibly prepays the group's
//! instruction allowance. Task capacity includes finished, uncollected results:
//! neither detached workers nor an unbounded completion queue hide behind it.
//!
//! Closing first revokes the entire group, then joins every worker under ONE
//! deadline. Timeouts retain all handles and all results for a later retry.
//! Successful joining is not successful guest execution; collect each outcome.
//! `close_and_join` establishes only native worker/synchronous-hook completion.
//! With a configured host-effect scope, `close_and_drain` also waits for admitted
//! provider calls under the same deadline. Neither proves retained-child reaping
//! or journal finalization. Drop requests cancellation but may detach workers.

use std::fmt;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::baseline_interpreter::{ExecutionResult, InterpreterConfig, InterpreterHook};
use crate::execution_work_budget::{
    ExecutionAdmission, ExecutionTask, ExecutionTaskControl, ExecutionTaskJoinError,
    ExecutionTaskStartError,
    ExecutionWorkPool, WorkBudgetError,
};
use crate::host_effect_budget::HostEffectWorkPool;
use crate::ir_contract::Ir3Module;

mod effects;
pub use effects::{ExecutionGroupDrainError, ExecutionHostBindings};

/// Monotonic identity local to one group. Never reused after result collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionTaskId(u64);

/// Native outcome inside an independently reported worker-join outcome.
pub type ExecutionTaskOutcome =
    Result<Result<ExecutionResult, WorkBudgetError>, ExecutionTaskJoinError>;

/// Cancel-only authority. Clones cannot mint work, reset the scope, or revoke
/// the parent instruction pool or a sibling group. A configured effect scope
/// is also revoked, including its aliases. Supply a dedicated effect partition
/// when sibling groups need independent cancellation. This does not prove drain.
#[derive(Clone)]
pub struct ExecutionGroupControl {
    pool: ExecutionWorkPool,
    effects: Option<HostEffectWorkPool>,
}

impl ExecutionGroupControl {
    pub fn cancel(&self) {
        // Stop new effects before asking workers to leave. Both requests are
        // irreversible and idempotent, not an atomic multi-resource operation.
        if let Some(effects) = &self.effects {
            effects.revoke();
        }
        self.pool.revoke();
    }

    pub fn is_cancelled(&self) -> bool {
        self.pool.is_revoked()
            || self.effects.as_ref().is_some_and(HostEffectWorkPool::is_revoked)
    }
}

impl fmt::Debug for ExecutionGroupControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionGroupControl")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum ExecutionGroupStartError {
    Closed,
    HostEffectsUnconfigured,
    Capacity {
        limit: usize,
    },
    Allocation,
    IdentityExhausted,
    Admission(WorkBudgetError),
    Preparation(WorkBudgetError),
    Worker(ExecutionTaskStartError),
}

impl fmt::Display for ExecutionGroupStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("native execution group is closed"),
            Self::HostEffectsUnconfigured => f.write_str("native group has no host-effect scope"),
            Self::Capacity { limit } => write!(f, "native execution group task capacity is {limit}"),
            Self::Allocation => f.write_str("native execution group could not reserve task storage"),
            Self::IdentityExhausted => f.write_str("native execution group task identities exhausted"),
            Self::Admission(error) => write!(f, "native execution group admission: {error}"),
            Self::Preparation(error) => write!(f, "native execution group preparation: {error}"),
            Self::Worker(error) => write!(f, "native execution group worker: {error}"),
        }
    }
}

impl std::error::Error for ExecutionGroupStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) | Self::Preparation(error) => Some(error),
            Self::Worker(error) => Some(error),
            _ => None,
        }
    }
}

struct Entry {
    id: ExecutionTaskId,
    task: ExecutionTask,
    outcome: Option<ExecutionTaskOutcome>,
}

/// A non-cloneable owner of at most `capacity` native tasks/results.
///
/// All starts go through the prepaid native admission path. No task or pool
/// accessor permits untracked dispatch. This is a count bound, not an aggregate
/// byte/CPU bound: per-execution memory limits and provider policies still apply.
/// Completion readiness depends on host scheduling; IDs/order are not a replay
/// transcript. An external dispatcher must record its scheduling decisions.
#[must_use = "retain and explicitly join/drain this owner; Drop only requests cancellation"]
pub struct ExecutionTaskGroup {
    pool: ExecutionWorkPool,
    effects: Option<HostEffectWorkPool>,
    capacity: usize,
    next_id: u64,
    entries: Vec<Entry>,
}

impl fmt::Debug for ExecutionTaskGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format source, trace IDs, hooks, configuration or guest results.
        f.debug_struct("ExecutionTaskGroup")
            .field("capacity", &self.capacity)
            .field("retained", &self.entries.len())
            .field("pending", &self.pending())
            .field("closed", &self.is_closed())
            .field("host_effect_scope", &self.effects.is_some())
            .finish_non_exhaustive()
    }
}

impl ExecutionTaskGroup {
    /// Irreversibly partition the parent allowance into this group's private
    /// scope. Dropping it never refunds the parent. Zero capacity admits no work.
    /// Construction allocates no task array or threads; storage grows fallibly.
    pub fn new(
        parent: &ExecutionWorkPool,
        instruction_limit: u64,
        capacity: usize,
    ) -> Result<Self, WorkBudgetError> {
        Ok(Self {
            pool: parent.partition(instruction_limit)?,
            effects: None,
            capacity,
            next_id: 0,
            entries: Vec::new(),
        })
    }

    pub fn control(&self) -> ExecutionGroupControl {
        ExecutionGroupControl {
            pool: self.pool.clone(),
            effects: self.effects.clone(),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.pool.is_revoked()
            || self.effects.as_ref().is_some_and(HostEffectWorkPool::is_revoked)
    }

    /// Permanently deny new starts and request cancellation of ALL workers
    /// before any joining begins. A configured effect scope is also revoked;
    /// its parent/siblings remain untouched when it is a dedicated partition.
    pub fn close(&self) {
        self.control().cancel();
    }

    pub fn remaining_instructions(&self) -> u64 {
        self.pool.remaining()
    }

    /// Running workers plus retained, joined outcomes.
    pub fn retained(&self) -> usize {
        self.entries.len()
    }

    /// Workers not yet joined, including finished-but-not-yet-polled workers.
    pub fn pending(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.outcome.is_none())
            .count()
    }

    pub fn task_control(&self, id: ExecutionTaskId) -> Option<ExecutionTaskControl> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.task.control())
    }

    pub fn spawn(
        &mut self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        self.spawn_with_hook(module, current_config, trace_id, None)
    }

    /// Configuration and policy hooks are supplied at dispatch, not cached from
    /// enqueue time. Capacity/storage failures precede debit and VM creation.
    /// Once admitted, startup failures and panics never refund instruction work.
    pub fn spawn_with_hook(
        &mut self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        current_hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        self.spawn_with_preparation(module, current_config, trace_id, |_, _| Ok(current_hook))
    }

    /// Prepare host bindings against the EXACT admission the worker will consume.
    /// This trusted, synchronous host callback runs only after storage and quota
    /// admission and before spawning any thread. It may install the existing
    /// admission-bound I/O/process decorators in the current configuration or
    /// returned policy hook. A borrowed admission cannot start another VM.
    ///
    /// The native dispatcher still clamps any changed instruction limit to the
    /// prepaid ceiling and preserves current capabilities/caller cancellation.
    /// Preparation failure consumes quota and closes escaped admission controls;
    /// unwinding also closes this group, cancelling other group workers without
    /// revoking parent/sibling groups. Revocation during preparation is rechecked
    /// by native spawn. Completed external effects are not rolled back here.
    /// This callback is not guest code and must enforce its own blocking limits.
    pub fn spawn_with_preparation(
        &mut self,
        module: Ir3Module,
        mut current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        prepare: impl FnOnce(
            &ExecutionAdmission,
            &mut InterpreterConfig,
        ) -> Result<Option<Arc<dyn InterpreterHook>>, WorkBudgetError>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        if self.is_closed() {
            return Err(ExecutionGroupStartError::Closed);
        }
        if self.entries.len() >= self.capacity {
            return Err(ExecutionGroupStartError::Capacity {
                limit: self.capacity,
            });
        }
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ExecutionGroupStartError::IdentityExhausted)?;
        // No allocation may fail between starting a worker and retaining it.
        self.entries
            .try_reserve(1)
            .map_err(|_| ExecutionGroupStartError::Allocation)?;
        let trace_id = trace_id.into();
        let admission = self
            .pool
            .reserve(current_config.instruction_budget)
            .map_err(ExecutionGroupStartError::Admission)?;
        if admission.task_control().is_cancelled() {
            return Err(ExecutionGroupStartError::Admission(WorkBudgetError::Revoked));
        }
        let current_hook = {
            // A caught setup panic must not leave sibling work running against
            // potentially interrupted shared host state. Drop never waits.
            let _guard = PreparationUnwindGuard(self.control());
            prepare(&admission, &mut current_config)
                .map_err(ExecutionGroupStartError::Preparation)?
        };
        // Effect-scope revocation is independent of instruction revocation.
        // A setup callback may have revoked an externally held effect alias.
        // Close native authority too so spawn's existing refusal path applies.
        if self.is_closed() {
            self.close();
        }
        let task = admission
            .spawn_with_hook(module, current_config, trace_id, current_hook)
            .map_err(ExecutionGroupStartError::Worker)?;
        let id = ExecutionTaskId(self.next_id);
        self.next_id = next_id;
        self.entries.push(Entry {
            id,
            task,
            outcome: None,
        });
        Ok(id)
    }

    /// Join every currently finished worker without blocking on another one.
    /// Panics and native failures are retained like successes. Polling does not
    /// free capacity: the consumer must take the outcome, so results stay bounded.
    pub fn poll(&mut self) -> usize {
        let mut joined = 0;
        for entry in &mut self.entries {
            if entry.outcome.is_none() && entry.task.is_finished() {
                match entry.task.join_timeout(Duration::ZERO) {
                    Err(ExecutionTaskJoinError::TimedOut) => {}
                    outcome => {
                        entry.outcome = Some(outcome);
                        joined += 1;
                    }
                }
            }
        }
        joined
    }

    /// Nonblocking collection. None means unknown/already-collected identity or
    /// a worker still pending. Only collecting a joined outcome frees capacity.
    pub fn take_result(&mut self, id: ExecutionTaskId) -> Option<ExecutionTaskOutcome> {
        self.poll();
        let index = self.entries.iter().position(|entry| entry.id == id)?;
        self.entries[index].outcome.as_ref()?;
        self.entries.remove(index).outcome
    }

    /// Revoke all workers, then join under a single monotonic deadline. Retry on
    /// timeout with this SAME owner; handles, failures and successes are retained.
    /// Ok means every worker was joined, not that every guest succeeded. Collect
    /// each result explicitly. Even an invalid timeout leaves the group closed.
    /// A configured effect scope is revoked but NOT waited here; use
    /// `close_and_drain` to wait for both native workers and provider dispatch.
    pub fn close_and_join(&mut self, timeout: Duration) -> Result<(), ExecutionTaskJoinError> {
        let started = Instant::now();
        self.close();
        let deadline = started
            .checked_add(timeout)
            .ok_or(ExecutionTaskJoinError::InvalidTimeout)?;
        self.join_until(deadline)
    }

    // Reuse the exact deadline when a supervisor also has provider work to drain.
    fn join_until(&mut self, deadline: Instant) -> Result<(), ExecutionTaskJoinError> {
        loop {
            self.poll();
            if self.pending() == 0 {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExecutionTaskJoinError::TimedOut);
            }
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }
}

impl Drop for ExecutionTaskGroup {
    fn drop(&mut self) {
        // Request every cancellation before any individual task is dropped.
        // This cannot certify shutdown: ExecutionTask::drop can detach a worker.
        self.close();
    }
}

struct PreparationUnwindGuard(ExecutionGroupControl);

impl Drop for PreparationUnwindGuard {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.cancel();
        }
    }
}

#[cfg(test)]
mod tests;
