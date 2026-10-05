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
use std::sync::{Arc, Mutex};

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
    revoked: AtomicBool,
}

/// Clones share one balance, one concurrency limit and one irreversible revoke
/// signal. Creating a new budget is a trusted host operation, not a guest API.
#[derive(Debug, Clone)]
pub struct HostIoWorkBudget {
    shared: Arc<SharedBudget>,
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
                revoked: AtomicBool::new(false),
            }),
        }
    }

    pub fn limits(&self) -> HostIoBudgetLimits {
        self.shared.limits
    }

    /// Stop future admission and cooperatively cancel admitted network work at
    /// the native provider's existing checkpoints. This does not undo effects,
    /// interrupt a synchronous filesystem syscall, or certify quiescent close.
    pub fn revoke(&self) {
        self.shared.revoked.store(true, Ordering::Release);
    }

    pub fn is_revoked(&self) -> bool {
        self.shared.revoked.load(Ordering::Acquire)
    }

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
        } else if self.shared.balance.is_poisoned() {
            Err(HostIoBudgetError::Poisoned)
        } else {
            // Exhausting admission does NOT revoke an already-admitted call.
            Ok(())
        }
    }

    fn admit(&self, request: &HostIoRequest) -> Result<Admission, HostIoBudgetError> {
        self.check_active()?;
        let bytes = request_bytes(request)?;
        let mut balance = self
            .shared
            .balance
            .lock()
            .map_err(|_| HostIoBudgetError::Poisoned)?;
        self.check_active()?;
        if balance.in_flight >= self.shared.limits.max_in_flight {
            return Err(HostIoBudgetError::TooManyInFlight);
        }
        if balance.requests == 0 {
            return Err(HostIoBudgetError::RequestsExhausted);
        }
        if bytes > balance.request_bytes {
            return Err(HostIoBudgetError::RequestBytesExhausted);
        }
        // All dimensions are validated under one lock. A refused request never
        // partially consumes a different dimension, and clones cannot overspend.
        balance.requests -= 1;
        balance.request_bytes -= bytes;
        balance.in_flight += 1;
        Ok(Admission {
            budget: self.clone(),
        })
    }
}

struct Admission {
    budget: HostIoWorkBudget,
}

impl Drop for Admission {
    fn drop(&mut self) {
        // A caught provider panic must not allow reuse of potentially corrupted
        // provider state through another clone of this workload's membrane.
        if std::thread::panicking() {
            self.budget.revoke();
        }
        let mut balance = self
            .budget
            .shared
            .balance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Poison recovery here releases capacity only; new admission continues
        // to reject the poisoned balance. Committed work is never refunded.
        balance.in_flight = balance.in_flight.saturating_sub(1);
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
        self.budget.check_active().map_err(HostIoBudgetError::host_error)?;
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
            return Err(HostIoError::CapabilityMissing { capability: required });
        }
        let control = Arc::new(BudgetControl {
            budget: self.budget.clone(),
            supervisor: control,
            refused: AtomicBool::new(false),
        });
        control.checkpoint()?;
        let _admission = self.budget.admit(request).map_err(HostIoBudgetError::host_error)?;
        // Close a revocation race after debit; never refund the reservation.
        control.checkpoint()?;
        // Never drop live control by falling back to inner.perform. The trait's
        // default refuses uncontrolled network implementations for this reason.
        let outcome = self.inner.perform_controlled(request, granted, control.clone());
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
