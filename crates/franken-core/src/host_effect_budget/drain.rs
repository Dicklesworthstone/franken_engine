//! Stop admission, then wait for the real shared provider-call frontier.
//!
//! This is the drain phase for a HostEffectWorkPool, not a second effect
//! protocol. Native results, first errors, journaling and compensating child
//! cleanup remain with the existing execution-cell/orchestrator owners.

use std::fmt;
use std::time::{Duration, Instant};

use super::{HostEffectSnapshot, HostEffectWorkPool};

/// A failed drain never means that an active provider call has been stopped.
/// Revocation remains permanent after every error, and work is never refunded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEffectDrainError {
    /// Calls were still admitted when the shared wait deadline was observed.
    TimedOut { in_flight: usize },
    /// The host supplied a duration that cannot form a monotonic deadline.
    InvalidTimeout,
    /// Accounting cannot safely certify an idle frontier, even if it reads zero.
    AccountingPoisoned,
}

impl HostEffectDrainError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TimedOut { .. } => "HOST_EFFECT_DRAIN_TIMED_OUT",
            Self::InvalidTimeout => "HOST_EFFECT_DRAIN_INVALID_TIMEOUT",
            Self::AccountingPoisoned => "HOST_EFFECT_ACCOUNTING_POISONED",
        }
    }
}

impl fmt::Display for HostEffectDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { in_flight } => {
                write!(f, "{}: {in_flight} provider calls remain", self.code())
            }
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for HostEffectDrainError {}

impl HostEffectWorkPool {
    /// Permanently revoke this pool and wait for all its admitted provider calls
    /// to return or unwind. I/O and process bindings, including every clone,
    /// share the same frontier, including all descendant partitions. Draining
    /// a child leaves parent and sibling authority intact. Admission that races
    /// with revocation either fails or remains counted until its permits exit.
    ///
    /// A successful snapshot has `in_flight == 0`, and no subsequent ordinary
    /// request can enter through a binding to this pool. Timeout or poisoned
    /// accounting is an error, NOT synthetic completion: held permits and
    /// committed credits remain intact. A later call can retry the wait without
    /// resetting authority. Zero timeout is an immediate, revoking idle probe.
    /// Even an invalid timeout revokes first.
    ///
    /// The timeout bounds condition-variable waiting using one monotonic
    /// deadline; spurious wakeups do not renew it. OS scheduling and mutex
    /// reacquisition can delay the caller, so this is not a hard real-time SLA.
    /// No provider, control, journal or guest callback runs under the lock.
    /// Call this from the supervising host, not inside a call holding one of the
    /// permits being drained (which would wait for itself until timeout).
    ///
    /// # Lifecycle boundary
    ///
    /// This drains ADMITTED DISPATCH, not the interpreter, detached provider
    /// workers, retained children, or the outer journal's commit/finalize phase.
    /// In particular, `Spawned` returns a child handle and releases its dispatch
    /// permit before that child exits. After dispatch drain, the cell owner must
    /// finish its journal and perform/record engine-owned `cleanup_handle` for
    /// retained children. Cleanup intentionally remains possible after revoke;
    /// neither it nor pure preflight/preparation consumes an admission permit.
    /// Do not publish this snapshot as proof of whole-cell quiescent close.
    pub fn revoke_and_drain(
        &self,
        timeout: Duration,
    ) -> Result<HostEffectSnapshot, HostEffectDrainError> {
        let started = Instant::now();
        self.revoke();
        let deadline = started
            .checked_add(timeout)
            .ok_or(HostEffectDrainError::InvalidTimeout)?;
        let mut accounting = self
            .state
            .accounting
            .lock()
            .map_err(|_| HostEffectDrainError::AccountingPoisoned)?;
        loop {
            // Check under admission's mutex, including after every wakeup.
            // A notification alone is never evidence that work has finished.
            if self.has_poisoned_accounting() {
                return Err(HostEffectDrainError::AccountingPoisoned);
            }
            if accounting.in_flight == 0 {
                return Ok(HostEffectSnapshot {
                    remaining_operations: accounting.remaining,
                    committed_operations: self.state.limits.operations - accounting.remaining,
                    in_flight: 0,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HostEffectDrainError::TimedOut {
                    in_flight: accounting.in_flight,
                });
            }
            let (next, _) = self
                .state
                .idle
                .wait_timeout(accounting, remaining)
                .map_err(|_| HostEffectDrainError::AccountingPoisoned)?;
            accounting = next;
        }
    }
}

#[cfg(test)]
mod tests;
