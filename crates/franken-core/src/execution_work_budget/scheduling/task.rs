//! Host-owned worker lifecycle for one prepaid native execution.
//!
//! Joining this worker establishes that its interpreter and synchronous hooks
//! have returned and been dropped. It does not certify detached provider tasks,
//! retained child processes, or an external journal's finalization.

use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::ExecutionAdmission;
use crate::baseline_interpreter::{ExecutionResult, InterpreterConfig, InterpreterHook};
use crate::checkpoint::CancellationToken;
use crate::execution_work_budget::WorkBudgetError;
use crate::ir_contract::Ir3Module;

/// Irreversible cancellation of one admission, not its parent or siblings.
/// This handle deliberately exposes neither a reset nor the underlying token.
#[derive(Clone)]
pub struct ExecutionTaskControl {
    scope: CancellationToken,
}

impl ExecutionTaskControl {
    pub fn cancel(&self) {
        self.scope.cancel();
    }

    /// True after cancellation, ancestor revocation, or worker scope exit.
    /// This signal alone is not evidence that the worker has been joined.
    pub fn is_cancelled(&self) -> bool {
        self.scope.is_cancelled()
    }
}

impl fmt::Debug for ExecutionTaskControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionTaskControl")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum ExecutionTaskStartError {
    Admission(WorkBudgetError),
    ThreadSpawn(std::io::Error),
}

impl fmt::Display for ExecutionTaskStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(f, "execution task admission: {error}"),
            Self::ThreadSpawn(_) => f.write_str("native execution worker could not be started"),
        }
    }
}

impl std::error::Error for ExecutionTaskStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::ThreadSpawn(error) => Some(error),
        }
    }
}

/// Join failures are distinct from the unchanged native execution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTaskJoinError {
    TimedOut,
    InvalidTimeout,
    AlreadyJoined,
    /// The worker was joined after unwinding. Its panic payload is not exposed.
    Panicked,
}

impl fmt::Display for ExecutionTaskJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "native execution worker has not finished before the join deadline",
            Self::InvalidTimeout => "native execution join deadline is not representable",
            Self::AlreadyJoined => "native execution worker was already joined",
            Self::Panicked => "native execution worker panicked",
        })
    }
}

impl std::error::Error for ExecutionTaskJoinError {}

/// Exactly one native execution with an owned join handle and cancel-only scope.
///
/// Timeouts retain this owner and the eventual result. Only a successful join
/// (including a reported worker panic) consumes the join handle. Cancellation is
/// cooperative at the existing native checkpoints; blocking host callbacks can
/// delay it. Hosts must retain this task and retry joining after a timeout.
/// Dropping it requests cancellation but detaches an unfinished worker, and is
/// therefore NOT a successful shutdown or a substitute for `cancel_and_join`.
#[must_use = "retain and join this task; dropping only requests cancellation"]
pub struct ExecutionTask {
    control: ExecutionTaskControl,
    worker: Option<JoinHandle<Result<ExecutionResult, WorkBudgetError>>>,
}

impl fmt::Debug for ExecutionTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not format the trace, source, hook, configuration or native result.
        f.debug_struct("ExecutionTask")
            .field("control", &self.control)
            .field("joined", &self.worker.is_none())
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl ExecutionTask {
    pub fn control(&self) -> ExecutionTaskControl {
        self.control.clone()
    }

    /// An observation only. Call `join_timeout` to collect the result and join.
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Wait for and join the actual native worker without cancelling it.
    ///
    /// One monotonic deadline bounds polling; a timeout neither discards the
    /// worker/result nor refunds admission. Zero is an immediate finished probe.
    /// Scheduling and the final OS thread join are not a hard real-time SLA.
    pub fn join_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Result<ExecutionResult, WorkBudgetError>, ExecutionTaskJoinError> {
        if self.worker.is_none() {
            return Err(ExecutionTaskJoinError::AlreadyJoined);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ExecutionTaskJoinError::InvalidTimeout)?;
        while !self.is_finished() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExecutionTaskJoinError::TimedOut);
            }
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
        self.worker
            .take()
            .ok_or(ExecutionTaskJoinError::AlreadyJoined)?
            .join()
            .map_err(|_| ExecutionTaskJoinError::Panicked)
    }

    /// Request irreversible admission-local cancellation before the bounded join.
    /// Even an invalid timeout leaves cancellation requested and ownership intact.
    pub fn cancel_and_join(
        &mut self,
        timeout: Duration,
    ) -> Result<Result<ExecutionResult, WorkBudgetError>, ExecutionTaskJoinError> {
        self.control.cancel();
        self.join_timeout(timeout)
    }
}

impl Drop for ExecutionTask {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

// Captured before spawn: even rejected startup or a dropped spawn closure closes
// this admission. Declared before the VM call so the interpreter is dropped
// before normal scope exit; unwinding also always requests cancellation.
struct CloseScope(ExecutionTaskControl);

impl Drop for CloseScope {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl ExecutionAdmission {
    /// Obtain cancel-only authority for this queued admission before spawning.
    /// Every clone and admission-bound provider observes the same scope. Neither
    /// cancelling this handle nor closing the worker revokes parent/sibling work.
    pub fn task_control(&self) -> ExecutionTaskControl {
        ExecutionTaskControl {
            scope: self.scope.clone(),
        }
    }

    /// Start one worker from this single-use reservation, without charging again.
    /// Configuration is supplied at dispatch, with its ceiling attenuated by the
    /// prepaid limit. No new capability is granted and no raw VM is exposed.
    pub fn spawn(
        self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
    ) -> Result<ExecutionTask, ExecutionTaskStartError> {
        self.spawn_with_hook(module, current_config, trace_id, None)
    }

    pub fn spawn_with_hook(
        self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        current_hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionTask, ExecutionTaskStartError> {
        let control = self.task_control();
        let close_scope = CloseScope(control.clone());
        if control.is_cancelled() {
            return Err(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked));
        }
        if current_config.instruction_budget == 0 {
            return Err(ExecutionTaskStartError::Admission(
                WorkBudgetError::ZeroInstructionBudget,
            ));
        }
        let trace_id = trace_id.into();
        let worker = thread::Builder::new()
            .name("franken-native-execution".into())
            .spawn(move || {
                let _close_scope = close_scope;
                self.execute_with_hook(&module, current_config, trace_id, current_hook)
            })
            .map_err(ExecutionTaskStartError::ThreadSpawn)?;
        Ok(ExecutionTask {
            control,
            worker: Some(worker),
        })
    }
}

#[cfg(test)]
mod tests;
