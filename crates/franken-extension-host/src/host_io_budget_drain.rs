//! Terminal, bounded drain for the synchronous live-I/O admission boundary.

use std::fmt;
use std::time::{Duration, Instant};

use super::{HostIoBudgetSnapshot, HostIoWorkBudget};

/// A failed drain never restores authority or refunds work. In particular,
/// timeout means live calls remain possible; it must not be treated as a
/// successful workload teardown. Retry the drain after those calls return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIoDrainError {
    DeadlineOverflow,
    AccountingPoisoned,
    TimedOut { in_flight: usize },
}

impl HostIoDrainError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DeadlineOverflow => "HOST_IO_DRAIN_DEADLINE_OVERFLOW",
            Self::AccountingPoisoned => "HOST_IO_DRAIN_ACCOUNTING_POISONED",
            Self::TimedOut { .. } => "HOST_IO_DRAIN_TIMEOUT",
        }
    }
}

impl fmt::Display for HostIoDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { in_flight } => {
                write!(f, "{}: {in_flight} provider calls remain", self.code())
            }
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for HostIoDrainError {}

impl HostIoWorkBudget {
    /// Permanently revoke this scope and wait for its admitted synchronous
    /// provider calls, including every descendant, to return or unwind.
    ///
    /// Success observes zero in-flight calls under the same mutex admission
    /// uses. Because revocation is sticky and admission checks it while holding
    /// that mutex, no later call can enter this scope after successful drain.
    /// Ancestor permits include descendants, including prepaid children whose
    /// parents have no uncommitted request credits left.
    ///
    /// A zero timeout is a nonblocking drain observation. All failures leave
    /// the scope revoked. The monotonic deadline is shared across wakeups; it
    /// is never restarted by progress, spurious wakeups or another closer.
    /// Concurrent/repeated closes are safe and do not consume or refund work.
    ///
    /// This is NOT an execution-cell finalization certificate. It says nothing
    /// about unwrapped providers, open file handles, spawned processes, guest
    /// CPU work, journal finalization or work a custom provider detached before
    /// returning. Cooperative network controls can interrupt native waiting;
    /// an uninterruptible filesystem syscall can cause an explicit timeout.
    /// Call from the owning supervisor, not from an admitted provider callback.
    pub fn revoke_and_drain(
        &self,
        timeout: Duration,
    ) -> Result<HostIoBudgetSnapshot, HostIoDrainError> {
        // Even an invalid deadline must stop new effects, not leave authority
        // live while the caller handles a shutdown error.
        self.revoke();
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HostIoDrainError::DeadlineOverflow)?;
        let mut balance = self
            .shared
            .balance
            .lock()
            .map_err(|_| HostIoDrainError::AccountingPoisoned)?;
        loop {
            // A poisoned ancestor makes the hierarchy's accounting uncertain.
            // Never turn poison recovery into a positive drain assertion.
            if self
                .shared
                .ancestors
                .iter()
                .any(|scope| scope.balance.is_poisoned())
            {
                return Err(HostIoDrainError::AccountingPoisoned);
            }
            if balance.in_flight == 0 {
                return Ok(HostIoBudgetSnapshot {
                    remaining_requests: balance.requests,
                    remaining_request_bytes: balance.request_bytes,
                    in_flight: 0,
                    revoked: true,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HostIoDrainError::TimedOut {
                    in_flight: balance.in_flight,
                });
            }
            let (next, _) = self
                .shared
                .drained
                .wait_timeout(balance, remaining)
                .map_err(|_| HostIoDrainError::AccountingPoisoned)?;
            balance = next;
        }
    }
}

#[cfg(test)]
#[path = "host_io_budget_drain_tests.rs"]
mod tests;
