//! Consumable work quotas shared by explicitly participating native instances.
//!
//! This is the same logical work measured by the VM, not CPU time or a wall
//! clock: opcodes, bulk work, activation setup, host dispatch, buffer copies and
//! replay hashing. Parsing, initial state allocation and unmetered trusted Rust
//! are outside that metric. Bind a pool to EVERY registry in the intended scope.
//! An unbound registry retains its existing per-invocation limits.
//!
//! Accepted charges never return, including after traps, cancellation, provider
//! panic, guest exit or destruction. Clones spend the same counter; no reset or
//! serialization operation can manufacture a fresh balance for a live scope.
//! Atomic admission bounds concurrent aggregate spending, but not which racing
//! caller wins. Deterministic schedules give deterministic charge ordering.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmWorkPoolExhausted {
    pub requested: u64,
    /// Balance observed at the failed charge, not a promise to a later caller.
    pub remaining: u64,
}

impl fmt::Display for WasmWorkPoolExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wasm shared work charge needs {} units, only {} remain", self.requested, self.remaining)
    }
}

impl std::error::Error for WasmWorkPoolExhausted {}

#[derive(Debug)]
struct Balance {
    limit: u64,
    remaining: AtomicU64,
}

/// An explicit, non-refillable execution allotment. Merely binding a pool or
/// preparing an invocation spends nothing. Only accepted VM work charges spend
/// units. This grants no provider or module capability and owns no guest state.
#[derive(Debug, Clone)]
pub struct WasmWorkPool {
    balance: Arc<Balance>,
}

impl WasmWorkPool {
    pub fn new(limit: u64) -> Self {
        Self { balance: Arc::new(Balance { limit, remaining: AtomicU64::new(limit) }) }
    }

    pub fn limit(&self) -> u64 { self.balance.limit }

    /// A concurrent observation, not a reservation. Execution must still use
    /// the meter's checked atomic charge before performing its effects.
    pub fn remaining(&self) -> u64 { self.balance.remaining.load(Ordering::Acquire) }

    pub(crate) fn charge(&self, units: u64) -> Result<(), WasmWorkPoolExhausted> {
        if units == 0 { return Ok(()); }
        self.balance.remaining.fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(units)
        }).map(|_| ()).map_err(|remaining| WasmWorkPoolExhausted { requested: units, remaining })
    }
}

impl WasmWorkPool {
    /// Transfer an allotment into an independent tenant or execution-cell pool.
    /// The complete allotment is debited atomically before the child is returned;
    /// siblings cannot spend it, even while that child is idle. Nested transfers
    /// obey the same rule and cannot increase the original aggregate budget.
    ///
    /// This transfer is deliberately IRREVOCABLE. Unlike a memory reservation,
    /// dropping the child does not refund unspent fuel to the parent. A new
    /// execution epoch needs a newly authorized pool, not a reset of an existing
    /// scope. There is no parent-handle escape, reparenting or refill operation.
    pub fn partition(&self, units: u64) -> Result<Self, WasmWorkPoolExhausted> {
        // Allocate the child before debiting: allocation failure must not lose
        // credits. This child remains private until the atomic transfer succeeds.
        let child = Self::new(units);
        self.charge(units)?;
        Ok(child)
    }
}
