//! Prepaid tenant isolation for the existing shared I/O/process admission pool.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex};

use super::{Accounting, HostEffectBudgetError, HostEffectLimits, HostEffectWorkPool, PoolState};

/// Maximum partitions below the root; bounds retained ancestry and polling work.
pub const MAX_HOST_EFFECT_POOL_DEPTH: usize = 64;

impl HostEffectWorkPool {
    /// Permanently reserve a tenant's operation credits from this scope.
    ///
    /// Siblings cannot consume this reservation. Locally admitted work and
    /// delegation compete for the same parent balance under one mutex. Unused,
    /// exhausted, dropped or revoked children never refund or renew authority.
    /// A child's concurrency limit cannot exceed its parent's, and every child
    /// dispatch also holds a permit at each ancestor. Creating more children
    /// therefore cannot multiply global concurrency or operation credits.
    ///
    /// Empty partitions are allowed but cannot dispatch. Limits never grant
    /// capabilities or bypass the configured provider's native policy. Explicit
    /// revocation flows down only; a provider unwind quarantines the entire
    /// family because the native provider may be shared across tenant bindings.
    ///
    /// Validation failures do not debit the parent. Revocation racing with the
    /// irreversible debit can discard credits but never publish a usable child.
    /// Construction is a trusted host operation, not a guest-callable allocator.
    pub fn partition(&self, limits: HostEffectLimits) -> Result<Self, HostEffectBudgetError> {
        self.check_active()?;
        if self.state.ancestors.len() >= MAX_HOST_EFFECT_POOL_DEPTH {
            return Err(HostEffectBudgetError::HierarchyDepthExceeded);
        }
        if limits.max_in_flight > self.state.limits.max_in_flight {
            return Err(HostEffectBudgetError::ConcurrencyLimitBroadened);
        }
        // Finish fallible allocation before debit; neither this child nor any
        // capability is published while it is being constructed.
        let mut ancestors = self.state.ancestors.to_vec();
        ancestors.push(Arc::clone(&self.state));
        let child = Self {
            state: Arc::new(PoolState {
                limits,
                accounting: Mutex::new(Accounting {
                    remaining: limits.operations,
                    in_flight: 0,
                }),
                idle: Condvar::new(),
                revoked: AtomicBool::new(false),
                ancestors: ancestors.into(),
            }),
        };
        let mut accounting = self
            .state
            .accounting
            .lock()
            .map_err(|_| HostEffectBudgetError::AccountingPoisoned)?;
        self.check_active()?;
        if limits.operations > accounting.remaining {
            return Err(HostEffectBudgetError::Exhausted);
        }
        accounting.remaining -= limits.operations;
        drop(accounting);
        child.check_active()?;
        Ok(child)
    }
}

#[cfg(test)]
mod tests;
