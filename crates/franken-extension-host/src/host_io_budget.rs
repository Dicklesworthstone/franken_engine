//! Shared, non-renewable admission for real extension-host I/O.
//!
//! A per-call transfer cap does not bound a workload that repeatedly calls the
//! provider or clones it across execution lanes. This membrane admits each
//! request exactly once before dispatch, charges its owned string/payload bytes,
//! and holds a shared concurrency permit until the provider returns or unwinds.
//! Failures, cancellation and unwinding never refund committed work.
//!
//! This is an admission budget, not a measurement of disk space, response bytes,
//! syscalls or elapsed time. Keep the sandbox's per-operation byte limits, native
//! deadlines, capability checks, destination policy and replay journal in place.
//! Construct budgets at trusted workload boundaries; neither budgets nor permits
//! are serializable, and there is no reset or access to the wrapped provider.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

#[path = "host_io_budget_drain.rs"]
mod drain;
pub use drain::HostIoDrainError;

use crate::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance, HostIoOutcome,
    HostIoProvider, HostIoRequest, SandboxedHostIo, UnrestrictedHostIoControl,
};

/// Explicit host-selected limits for one workload. Zero in any dimension is
/// valid; zero requests or concurrency denies all dispatch. Zero request bytes
/// still permits requests without owned string/payload bytes, such as entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIoBudgetLimits {
    pub requests: u64,
    pub request_bytes: u64,
    pub max_in_flight: usize,
}

/// An observation, never an authority that can restore or replenish a budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIoBudgetSnapshot {
    pub remaining_requests: u64,
    pub remaining_request_bytes: u64,
    pub in_flight: usize,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIoBudgetError {
    Revoked,
    Poisoned,
    RequestsExhausted,
    RequestBytesExhausted,
    TooManyInFlight,
    RequestSizeOverflow,
    HierarchyDepthExceeded,
    ConcurrencyLimitBroadened,
}

impl HostIoBudgetError {
    /// Stable, payload-free diagnostics for the host-effect journal.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Revoked => "HOST_IO_BUDGET_REVOKED",
            Self::Poisoned => "HOST_IO_BUDGET_POISONED",
            Self::RequestsExhausted => "HOST_IO_REQUEST_BUDGET_EXHAUSTED",
            Self::RequestBytesExhausted => "HOST_IO_REQUEST_BYTES_EXHAUSTED",
            Self::TooManyInFlight => "HOST_IO_CONCURRENCY_EXHAUSTED",
            Self::RequestSizeOverflow => "HOST_IO_REQUEST_SIZE_OVERFLOW",
            Self::HierarchyDepthExceeded => "HOST_IO_BUDGET_DEPTH_EXCEEDED",
            Self::ConcurrencyLimitBroadened => "HOST_IO_CONCURRENCY_LIMIT_BROADENED",
        }
    }

    fn host_error(self) -> HostIoError {
        HostIoError::Denied {
            reason: self.code().to_string(),
        }
    }
}

impl fmt::Display for HostIoBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for HostIoBudgetError {}

#[derive(Debug)]
struct Balance {
    requests: u64,
    request_bytes: u64,
    in_flight: usize,
}

#[derive(Debug)]
struct SharedBudget {
    limits: HostIoBudgetLimits,
    balance: Mutex<Balance>,
    // Paired only with this scope's balance; descendants hold an ancestor
    // permit until their synchronous provider dispatch returns or unwinds.
    drained: Condvar,
    revoked: AtomicBool,
    // Root-to-parent order. Every descendant admission must hold a permit at
    // each ancestor, not just its own local semaphore.
    ancestors: Arc<[Arc<SharedBudget>]>,
}

/// Bound retained ancestry, checkpoint polling and permit acquisition work.
pub const MAX_HOST_IO_BUDGET_DEPTH: usize = 64;

/// Clones share one balance, one concurrency limit and one irreversible revoke
/// signal. Creating a new budget is a trusted host operation, not a guest API.
#[derive(Clone)]
pub struct HostIoWorkBudget {
    shared: Arc<SharedBudget>,
}

impl fmt::Debug for HostIoWorkBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The ancestry is a shared DAG. Recursively formatting it would expand
        // common prefixes exponentially, even with a bounded nesting depth.
        f.debug_struct("HostIoWorkBudget")
            .field("limits", &self.shared.limits)
            .field("depth", &self.shared.ancestors.len())
            .field("revoked", &self.is_revoked())
            .finish_non_exhaustive()
    }
}

impl HostIoWorkBudget {
    pub fn new(limits: HostIoBudgetLimits) -> Self {
        Self {
            shared: Arc::new(SharedBudget {
                limits,
                balance: Mutex::new(Balance {
                    requests: limits.requests,
                    request_bytes: limits.request_bytes,
                    in_flight: 0,
                }),
                drained: Condvar::new(),
                revoked: AtomicBool::new(false),
                ancestors: Arc::default(),
            }),
        }
    }

    pub fn limits(&self) -> HostIoBudgetLimits {
        self.shared.limits
    }

    /// Stop future admission and cooperatively cancel admitted network work at
    /// the native provider's existing checkpoints. This does not undo effects,
    /// interrupt a synchronous filesystem syscall, or certify quiescent close.
    /// Use [`Self::revoke_and_drain`] to wait for admitted provider calls.
    pub fn revoke(&self) {
        self.shared.revoked.store(true, Ordering::Release);
    }

    pub fn is_revoked(&self) -> bool {
        self.shared.revoked.load(Ordering::Acquire)
            || self
                .shared
                .ancestors
                .iter()
                .any(|scope| scope.revoked.load(Ordering::Acquire))
    }

    /// Permanently delegate work credits to a tenant or cell. Siblings cannot
    /// spend the child's balance. Unused or revoked children never refund their
    /// parent. A child's concurrency limit attenuates the parent limit; all
    /// descendant effects also occupy an ancestor permit while in flight.
    /// Revocation flows downward only, including after an ancestor owner drops.
    /// This is trusted host setup, not a mechanism for guest-created budgets.
    pub fn partition(&self, limits: HostIoBudgetLimits) -> Result<Self, HostIoBudgetError> {
        self.check_active()?;
        if self.shared.ancestors.len() >= MAX_HOST_IO_BUDGET_DEPTH {
            return Err(HostIoBudgetError::HierarchyDepthExceeded);
        }
        if limits.max_in_flight > self.shared.limits.max_in_flight {
            return Err(HostIoBudgetError::ConcurrencyLimitBroadened);
        }
        // Allocate the child before the irreversible debit. Construction does
        // not publish the child or invoke a provider.
        let mut ancestors = self.shared.ancestors.to_vec();
        ancestors.push(Arc::clone(&self.shared));
        let child = Self {
            shared: Arc::new(SharedBudget {
                limits,
                balance: Mutex::new(Balance {
                    requests: limits.requests,
                    request_bytes: limits.request_bytes,
                    in_flight: 0,
                }),
                drained: Condvar::new(),
                revoked: AtomicBool::new(false),
                ancestors: ancestors.into(),
            }),
        };
        let mut balance = self
            .shared
            .balance
            .lock()
            .map_err(|_| HostIoBudgetError::Poisoned)?;
        self.check_active()?;
        if limits.requests > balance.requests {
            return Err(HostIoBudgetError::RequestsExhausted);
        }
        if limits.request_bytes > balance.request_bytes {
            return Err(HostIoBudgetError::RequestBytesExhausted);
        }
        balance.requests -= limits.requests;
        balance.request_bytes -= limits.request_bytes;
        drop(balance);
        // A racing revocation may consume delegated credits but cannot publish
        // usable authority. As with ordinary admission, there is no refund.
        child.check_active()?;
        Ok(child)
    }

    /// Uncommitted credits, after both live admission and child delegation.
    /// in_flight includes effects running through descendant scopes.
    pub fn snapshot(&self) -> Result<HostIoBudgetSnapshot, HostIoBudgetError> {
        let balance = self
            .shared
            .balance
            .lock()
            .map_err(|_| HostIoBudgetError::Poisoned)?;
        Ok(HostIoBudgetSnapshot {
            remaining_requests: balance.requests,
            remaining_request_bytes: balance.request_bytes,
            in_flight: balance.in_flight,
            revoked: self.is_revoked(),
        })
    }

    fn check_active(&self) -> Result<(), HostIoBudgetError> {
        if self.is_revoked() {
            Err(HostIoBudgetError::Revoked)
        } else if self.shared.balance.is_poisoned()
            || self
                .shared
                .ancestors
                .iter()
                .any(|scope| scope.balance.is_poisoned())
        {
            Err(HostIoBudgetError::Poisoned)
        } else {
            // Exhausting admission does NOT revoke an already-admitted call.
            Ok(())
        }
    }

    fn admit(&self, request: &HostIoRequest) -> Result<Admission, HostIoBudgetError> {
        self.check_active()?;
        let bytes = request_bytes(request)?;
        // Preallocate before acquiring any permit so allocation failure cannot
        // leave an untracked in-flight increment. Depth is bounded at setup.
        let mut admission = Admission {
            budget: self.clone(),
            scopes: Vec::with_capacity(self.shared.ancestors.len() + 1),
        };
        for scope in self
            .shared
            .ancestors
            .iter()
            .chain(std::iter::once(&self.shared))
        {
            let mut balance = scope
                .balance
                .lock()
                .map_err(|_| HostIoBudgetError::Poisoned)?;
            self.check_active()?;
            if balance.in_flight >= scope.limits.max_in_flight {
                return Err(HostIoBudgetError::TooManyInFlight);
            }
            balance.in_flight += 1;
            admission.scopes.push(Arc::clone(scope));
            // Never hold two scope locks at once, and never hold one across
            // provider dispatch. Partial acquisition rolls back through Drop.
        }
        let mut balance = self
            .shared
            .balance
            .lock()
            .map_err(|_| HostIoBudgetError::Poisoned)?;
        self.check_active()?;
        if balance.requests == 0 {
            return Err(HostIoBudgetError::RequestsExhausted);
        }
        if bytes > balance.request_bytes {
            return Err(HostIoBudgetError::RequestBytesExhausted);
        }
        // Work was delegated before child construction, so charge only this
        // leaf. Charging ancestors again would double-spend prepaid credits.
        // All work dimensions are validated atomically under the leaf lock.
        balance.requests -= 1;
        balance.request_bytes -= bytes;
        drop(balance);
        Ok(admission)
    }
}

struct Admission {
    budget: HostIoWorkBudget,
    scopes: Vec<Arc<SharedBudget>>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.budget.revoke();
        }
        for scope in self.scopes.iter().rev() {
            let mut balance = scope
                .balance
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Poison recovery releases capacity only. New admission remains
            // fail-closed and committed/delegated work is never refunded.
            balance.in_flight = balance.in_flight.saturating_sub(1);
            let drained = balance.in_flight == 0;
            drop(balance);
            if drained {
                // Notify every waiter, including a root waiting on descendant
                // effects. The balance mutex closes the check/wait race.
                scope.drained.notify_all();
            }
        }
    }
}

/// Exact logical bytes submitted across the typed request boundary: every
/// owned path, endpoint, metadata argument and byte payload, counted once.
/// Integer fields and response sizes are not input payloads. An exhaustive
/// match forces new request variants to choose an accounting rule.
fn request_bytes(request: &HostIoRequest) -> Result<u64, HostIoBudgetError> {
    let add = |total: u64, len: usize| {
        let len = u64::try_from(len).map_err(|_| HostIoBudgetError::RequestSizeOverflow)?;
        total
            .checked_add(len)
            .ok_or(HostIoBudgetError::RequestSizeOverflow)
    };
    match request {
        HostIoRequest::FsRead { path } => add(0, path.len()),
        HostIoRequest::FsWrite { path, data } => add(add(0, path.len())?, data.len()),
        HostIoRequest::FsMeta {
            path,
            arguments,
            data,
            ..
        } => {
            let mut bytes = add(add(0, path.len())?, data.len())?;
            for argument in arguments {
                bytes = add(bytes, argument.len())?;
            }
            Ok(bytes)
        }
        HostIoRequest::NetworkSend { endpoint, payload }
        | HostIoRequest::NetworkRequest {
            endpoint, payload, ..
        } => add(add(0, endpoint.len())?, payload.len()),
        HostIoRequest::NetworkRecv { endpoint, .. } => add(0, endpoint.len()),
        HostIoRequest::RandomRead { .. } => Ok(0),
    }
}

/// Install around the final live I/O provider at a workload boundary. Sharing
/// this wrapper (or its budget) across lanes cannot multiply the allowance.
/// Keep the effect journal outside the membrane so replay consumes recorded
/// outcomes rather than performing or re-admitting live effects.
#[derive(Debug, Clone)]
pub struct BudgetedHostIo {
    inner: Arc<dyn HostIoProvider>,
    budget: HostIoWorkBudget,
}

impl BudgetedHostIo {
    pub fn new(inner: Arc<dyn HostIoProvider>, budget: HostIoWorkBudget) -> Self {
        Self { inner, budget }
    }

    pub fn budget(&self) -> &HostIoWorkBudget {
        &self.budget
    }
}

#[derive(Debug)]
struct BudgetControl {
    budget: HostIoWorkBudget,
    supervisor: Arc<dyn HostIoControl>,
    refused: AtomicBool,
}

impl HostIoControl for BudgetControl {
    fn checkpoint(&self) -> Result<(), HostIoError> {
        self.budget
            .check_active()
            .map_err(HostIoBudgetError::host_error)?;
        if !self.refused.load(Ordering::Acquire) && self.supervisor.checkpoint().is_err() {
            self.refused.store(true, Ordering::Release);
        }
        if self.refused.load(Ordering::Acquire) {
            // A custom supervisor's diagnostic may contain secrets, and an Fs
            // error must not make cancellation catchable by guest JavaScript.
            Err(HostIoError::Denied {
                reason: "HOST_IO_EXECUTION_CANCELLED".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

impl HostIoProvider for BudgetedHostIo {
    fn name(&self) -> &str {
        // Preserve mechanism identity, notably DenyAllHostIo's fail-closed name.
        self.inner.name()
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.perform_controlled(request, granted, Arc::new(UnrestrictedHostIoControl))
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        let required = request.required_capability();
        if !granted.contains(&required) {
            return Err(HostIoError::CapabilityMissing {
                capability: required,
            });
        }
        let control = Arc::new(BudgetControl {
            budget: self.budget.clone(),
            supervisor: control,
            refused: AtomicBool::new(false),
        });
        control.checkpoint()?;
        let _admission = self
            .budget
            .admit(request)
            .map_err(HostIoBudgetError::host_error)?;
        // Close a revocation race after debit; never refund the reservation.
        control.checkpoint()?;
        // Never drop live control by falling back to inner.perform. The trait's
        // default refuses uncontrolled network implementations for this reason.
        let outcome = self
            .inner
            .perform_controlled(request, granted, control.clone());
        control.checkpoint()?;
        outcome
    }
}

impl SandboxedHostIo {
    /// Preserve this configured sandbox's limits, root descriptor, TLS roots,
    /// entropy quota and destination-policy obligations while adding a shared
    /// workload admission membrane. No new ambient capability is granted.
    pub fn with_work_budget(self, budget: HostIoWorkBudget) -> BudgetedHostIo {
        BudgetedHostIo::new(Arc::new(self), budget)
    }
}

#[cfg(test)]
#[path = "host_io_budget_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "host_io_budget_hierarchy_tests.rs"]
mod hierarchy_tests;
