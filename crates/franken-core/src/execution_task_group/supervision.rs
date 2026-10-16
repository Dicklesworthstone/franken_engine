//! Explicit fail-fast batch supervision over the existing native owners.
//!
//! Failure observation is separate from completion. A failed worker requests
//! sibling cancellation, but neither cancellation nor a wait timeout certifies
//! a worker join or provider drain. Original outcomes remain individually owned.

use super::{
    ExecutionGroupDrainError, ExecutionTaskGroup, ExecutionTaskId, ExecutionTaskJoinError,
    ExecutionTaskOutcome,
};
use crate::baseline_interpreter::HookAction;
use crate::host_effect_budget::HostEffectSnapshot;
use std::fmt;
use std::thread;
use std::time::{Duration, Instant};

/// Failure of a supervised native batch. `join_error: None` means all workers
/// were joined after the failure, NOT that execution succeeded. The task's
/// original outcome is retained until explicitly collected by its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBatchError {
    Wait(ExecutionTaskJoinError),
    TaskFailed {
        task: ExecutionTaskId,
        join_error: Option<ExecutionTaskJoinError>,
    },
}
impl fmt::Display for ExecutionBatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wait(error) => write!(f, "native batch wait: {error}"),
            Self::TaskFailed { task, join_error } => {
                write!(f, "native batch task {task:?} failed")?;
                if let Some(error) = join_error {
                    write!(f, "; worker drain: {error}")?;
                }
                Ok(())
            }
        }
    }
}
impl std::error::Error for ExecutionBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Wait(error)
            | Self::TaskFailed {
                join_error: Some(error),
                ..
            } => Some(error),
            Self::TaskFailed {
                join_error: None, ..
            } => None,
        }
    }
}

/// Preserve both the initiating task and a subsequent cleanup failure. A failed
/// task stays failed even after its native workers and admitted effects drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBatchDrainError {
    Drain(ExecutionGroupDrainError),
    TaskFailed {
        task: ExecutionTaskId,
        drain_error: Option<ExecutionGroupDrainError>,
    },
}
impl fmt::Display for ExecutionBatchDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drain(error) => write!(f, "native batch drain: {error}"),
            Self::TaskFailed { task, drain_error } => {
                write!(f, "native batch task {task:?} failed")?;
                if let Some(error) = drain_error {
                    write!(f, "; cleanup: {error}")?;
                }
                Ok(())
            }
        }
    }
}
impl std::error::Error for ExecutionBatchDrainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Drain(error)
            | Self::TaskFailed {
                drain_error: Some(error),
                ..
            } => Some(error),
            Self::TaskFailed {
                drain_error: None, ..
            } => None,
        }
    }
}

pub(super) fn outcome_failed(outcome: &ExecutionTaskOutcome) -> bool {
    match outcome {
        Ok(Ok(result)) => !matches!(result.requested_hook_action, None | Some(HookAction::Allow)),
        _ => true,
    }
}

impl ExecutionTaskGroup {
    /// First failed, panicked or contained task observed by polling. Ties in one
    /// poll use admission order, not a claimed wall-clock completion ordering.
    /// This identity survives result collection and never changes. Reading it
    /// does not poll, seal, cancel, or grant access to a discarded guest result.
    pub fn first_failure(&self) -> Option<ExecutionTaskId> {
        self.first_failure
    }

    /// Seal the batch and join healthy workers without cancelling them. The
    /// first observed execution error, panic or non-Allow containment action
    /// revokes BOTH configured scopes before waiting for the remaining workers.
    /// Existing caller cancellation and per-job deadlines remain effective.
    ///
    /// One absolute deadline covers observation and cleanup. A healthy timeout
    /// leaves work live for retry; a timeout AFTER failure retains cancellation,
    /// the initiating task ID, all handles and all outcomes. Invalid durations
    /// only seal admission. No path refunds spent work or discards a result.
    ///
    /// This joins native workers and synchronous hooks only. Use
    /// `finish_and_drain_fail_fast` for the configured provider-call frontier.
    /// Call from the supervising host, never from a worker being joined.
    pub fn finish_and_join_fail_fast(
        &mut self,
        timeout: Duration,
    ) -> Result<(), ExecutionBatchError> {
        let started = Instant::now();
        self.seal();
        let deadline = started
            .checked_add(timeout)
            .ok_or(ExecutionBatchError::Wait(
                ExecutionTaskJoinError::InvalidTimeout,
            ))?;
        self.supervise_until(deadline)
    }

    /// Supervise workers, then drain their configured provider frontier using
    /// the SAME deadline. Healthy workers retain authority until native joining
    /// finishes; an observed task failure revokes that authority immediately.
    /// Failure plus cleanup timeout reports BOTH, and is retryable with this
    /// same owner even after the initiating task's result has been collected.
    ///
    /// An unconfigured effect scope or invalid timeout seals but does not cancel
    /// work. Successful drain covers admitted dispatch, not detached work, live
    /// children after spawn, compensating cleanup or journal finalization.
    pub fn finish_and_drain_fail_fast(
        &mut self,
        timeout: Duration,
    ) -> Result<HostEffectSnapshot, ExecutionBatchDrainError> {
        let started = Instant::now();
        self.seal();
        let deadline = started
            .checked_add(timeout)
            .ok_or(ExecutionBatchDrainError::Drain(
                ExecutionGroupDrainError::InvalidTimeout,
            ))?;
        let effects = self.effects.clone().ok_or(ExecutionBatchDrainError::Drain(
            ExecutionGroupDrainError::HostEffectsUnconfigured,
        ))?;
        let failed = match self.supervise_until(deadline) {
            Ok(()) => None,
            Err(ExecutionBatchError::Wait(error)) => {
                return Err(ExecutionBatchDrainError::Drain(
                    ExecutionGroupDrainError::Tasks(error),
                ));
            }
            Err(ExecutionBatchError::TaskFailed {
                task,
                join_error: Some(error),
            }) => {
                return Err(ExecutionBatchDrainError::TaskFailed {
                    task,
                    drain_error: Some(ExecutionGroupDrainError::Tasks(error)),
                });
            }
            Err(ExecutionBatchError::TaskFailed {
                task,
                join_error: None,
            }) => Some(task),
        };
        self.close();
        let drain = effects
            .revoke_and_drain_until(deadline)
            .map_err(ExecutionGroupDrainError::Effects);
        if let Some(task) = failed {
            return Err(ExecutionBatchDrainError::TaskFailed {
                task,
                drain_error: drain.err(),
            });
        }
        drain.map_err(ExecutionBatchDrainError::Drain)
    }

    fn supervise_until(&mut self, deadline: Instant) -> Result<(), ExecutionBatchError> {
        loop {
            self.poll();
            if let Some(task) = self.first_failure {
                self.close();
                return Err(ExecutionBatchError::TaskFailed {
                    task,
                    join_error: self.join_until(deadline).err(),
                });
            }
            if self.pending() == 0 {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ExecutionBatchError::Wait(ExecutionTaskJoinError::TimedOut));
            }
            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }
}
