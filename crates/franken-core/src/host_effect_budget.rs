//! Shared, non-refundable admission for live host effects.
//!
//! Instruction fuel does not account for a blocked network call or many native
//! effects across separately admitted executions. This pool adds a lifetime
//! operation allowance and an in-flight ceiling at the actual provider seam.
//! Clones and providers share one balance. Failed effects and unwinding consume
//! their admission; only the in-flight slot is released. No guest callback is
//! invoked while accounting state is locked.
//!
//! This is an effect-admission bound, not a CPU, byte, disk-space, or elapsed-time
//! bound. Native provider policies, byte caps and deadlines remain necessary.
//! Construction is a trusted host operation. Snapshots below are observations,
//! not serializable authority or restorable allowances. Concurrent admission
//! follows host scheduling; deterministic replay must preserve that ordering.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
    HostIoProvider, HostIoRequest, UnrestrictedHostIoControl,
};

use crate::execution_work_budget::{ExecutionWorkPool, WorkScopeRevocation};

mod drain;
mod process;
pub use drain::HostEffectDrainError;
pub use process::BudgetedProcessSpawn;

#[cfg(test)]
mod tests;

/// Trusted-host limits shared across every provider bound to this pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEffectLimits {
    pub operations: u64,
    pub max_in_flight: usize,
}

/// Atomic accounting observation. Completed and failed effects are committed;
/// `in_flight` is the number of provider calls currently holding admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEffectSnapshot {
    pub remaining_operations: u64,
    pub committed_operations: u64,
    pub in_flight: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEffectBudgetError {
    Revoked,
    Exhausted,
    ConcurrencyLimit,
    AccountingPoisoned,
}

impl HostEffectBudgetError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Revoked => "HOST_EFFECT_SCOPE_REVOKED",
            Self::Exhausted => "HOST_EFFECT_BUDGET_EXHAUSTED",
            Self::ConcurrencyLimit => "HOST_EFFECT_CONCURRENCY_LIMIT",
            Self::AccountingPoisoned => "HOST_EFFECT_ACCOUNTING_POISONED",
        }
    }

    fn host_io(self) -> HostIoError {
        HostIoError::Denied {
            reason: self.code().to_string(),
        }
    }
}

impl fmt::Display for HostEffectBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for HostEffectBudgetError {}

#[derive(Debug)]
struct Accounting {
    remaining: u64,
    in_flight: usize,
}

#[derive(Debug)]
struct PoolState {
    limits: HostEffectLimits,
    accounting: Mutex<Accounting>,
    idle: Condvar,
    revoked: AtomicBool,
}

/// One live allowance; cloning never creates new credits or concurrency slots.
#[derive(Debug, Clone)]
pub struct HostEffectWorkPool {
    state: Arc<PoolState>,
}

impl HostEffectWorkPool {
    /// Either zero limit creates a pool that admits no effects.
    pub fn new(limits: HostEffectLimits) -> Self {
        Self {
            state: Arc::new(PoolState {
                limits,
                accounting: Mutex::new(Accounting {
                    remaining: limits.operations,
                    in_flight: 0,
                }),
                idle: Condvar::new(),
                revoked: AtomicBool::new(false),
            }),
        }
    }

    pub fn limits(&self) -> HostEffectLimits {
        self.state.limits
    }

    pub fn snapshot(&self) -> Result<HostEffectSnapshot, HostEffectBudgetError> {
        let accounting = self
            .state
            .accounting
            .lock()
            .map_err(|_| HostEffectBudgetError::AccountingPoisoned)?;
        Ok(HostEffectSnapshot {
            remaining_operations: accounting.remaining,
            committed_operations: self.state.limits.operations - accounting.remaining,
            in_flight: accounting.in_flight,
        })
    }

    /// Permanently stop all providers bound to this pool. Active cooperative
    /// native I/O observes this through the forwarded operation control.
    /// Revocation neither refunds credits nor proves drain/finalize completed.
    /// Use [`Self::revoke_and_drain`] to wait for admitted provider calls.
    pub fn revoke(&self) {
        self.state.revoked.store(true, Ordering::Release);
    }

    pub fn is_revoked(&self) -> bool {
        self.state.revoked.load(Ordering::Acquire)
    }

    /// Installable directly in the interpreter's existing host-I/O provider
    /// slot. The provider observes this pool AND the instruction work scope;
    /// revoking one child scope cannot revoke a sibling sharing the provider.
    /// The wrapped provider is deliberately not exposed by the returned owner.
    pub fn bind_host_io(
        &self,
        provider: Arc<dyn HostIoProvider>,
        execution: &ExecutionWorkPool,
    ) -> BudgetedHostIo {
        BudgetedHostIo {
            provider,
            pool: self.clone(),
            scope: execution.revocation_signal(),
        }
    }

    fn admit(&self) -> Result<EffectPermit, HostEffectBudgetError> {
        if self.is_revoked() {
            return Err(HostEffectBudgetError::Revoked);
        }
        let mut accounting = self
            .state
            .accounting
            .lock()
            .map_err(|_| HostEffectBudgetError::AccountingPoisoned)?;
        if self.is_revoked() {
            return Err(HostEffectBudgetError::Revoked);
        }
        if accounting.remaining == 0 {
            return Err(HostEffectBudgetError::Exhausted);
        }
        if accounting.in_flight >= self.state.limits.max_in_flight {
            return Err(HostEffectBudgetError::ConcurrencyLimit);
        }
        accounting.remaining -= 1;
        accounting.in_flight += 1;
        Ok(EffectPermit {
            state: Arc::clone(&self.state),
        })
    }
}

struct EffectPermit {
    state: Arc<PoolState>,
}

impl Drop for EffectPermit {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.state.revoked.store(true, Ordering::Release);
        }
        // Cleanup must not panic during unwinding. Poison remains visible to
        // future admission; recovering here only releases the held slot.
        let mut accounting = self
            .state
            .accounting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        accounting.in_flight -= 1;
        if accounting.in_flight == 0 {
            // The predicate and notification use the same mutex as admission
            // and drain. Wake every closer, including on a provider unwind.
            self.state.idle.notify_all();
        }
    }
}

/// Live provider decorator. Capability checks, error provenance, typed requests
/// and native controls are preserved, not replaced by admission accounting.
#[derive(Clone)]
pub struct BudgetedHostIo {
    provider: Arc<dyn HostIoProvider>,
    pool: HostEffectWorkPool,
    scope: WorkScopeRevocation,
}

impl fmt::Debug for BudgetedHostIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not format custom providers, requests, or caller controls: they
        // may retain secret paths, payloads, tokens and policy diagnostics.
        f.debug_struct("BudgetedHostIo")
            .field("limits", &self.pool.limits())
            .field("revoked", &(self.pool.is_revoked() || self.scope.is_revoked()))
            .finish_non_exhaustive()
    }
}

struct EffectControl {
    pool: HostEffectWorkPool,
    scope: WorkScopeRevocation,
    caller: Arc<dyn HostIoControl>,
    refused: AtomicBool,
}

impl fmt::Debug for EffectControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostEffectControl").finish_non_exhaustive()
    }
}

impl HostIoControl for EffectControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        if !self.refused.load(Ordering::Acquire)
            && (self.pool.is_revoked()
                || self.pool.state.accounting.is_poisoned()
                || self.scope.is_revoked()
                || self.caller.checkpoint().is_err())
        {
            self.refused.store(true, Ordering::Release);
        }
        if self.refused.load(Ordering::Acquire) {
            // Never turn custom-control diagnostics into catchable filesystem
            // errors or leak their potentially sensitive text to the guest.
            Err(HostEffectBudgetError::Revoked.host_io())
        } else {
            Ok(())
        }
    }
}

impl HostIoProvider for BudgetedHostIo {
    fn name(&self) -> &str {
        self.provider.name()
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.provider.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.perform_controlled(request, granted, Arc::new(UnrestrictedHostIoControl))
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        caller: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        let control = Arc::new(EffectControl {
            pool: self.pool.clone(),
            scope: self.scope.clone(),
            caller,
            refused: AtomicBool::new(false),
        });
        control.checkpoint()?;
        if !granted.contains(&request.required_capability()) {
            return Err(HostIoError::CapabilityMissing {
                capability: request.required_capability(),
            });
        }
        let _permit = self.pool.admit().map_err(HostEffectBudgetError::host_io)?;
        // A racing revocation may consume admission; it never refunds it.
        control.checkpoint()?;
        let outcome = self.provider.perform_controlled(request, granted, control.clone());
        control.checkpoint()?;
        outcome
    }
}
