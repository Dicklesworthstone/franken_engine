//! Private, non-refundable work reservations for compound host operations.
//!
//! All ordinary caller methods remain on the existing bounds, live-control and
//! recording paths. Only their work debit changes: consume already-paid credit
//! rather than compete for the shared balance between individual effects.

use super::{WasmHostCaller, WasmHostError, WasmNumericVmError};

struct Scope<'scope, 'call, 'vm> {
    caller: &'scope mut WasmHostCaller<'call, 'vm>,
    parent: Option<u64>,
    returned: bool,
}

impl Drop for Scope<'_, '_, '_> {
    fn drop(&mut self) {
        self.caller.prepaid_work = self.parent;
        // A provider may catch a nested operation's unwind. Restore accounting
        // but never let that turn the interrupted operation into a success.
        // An earlier latched fault retains precedence. No work is refunded.
        if !self.returned && self.caller.failure.is_none() {
            self.caller.failure = Some(WasmHostError::PrepaidWorkInterrupted.into());
        }
    }
}

impl WasmHostCaller<'_, '_> {
    /// Atomically prepay a bounded, synchronous compound host operation.
    ///
    /// Reserve `units` against both the invocation meter and its shared pool
    /// BEFORE invoking `operation`. Within it, `charge_work`, `read_memory` and
    /// `write_memory` consume this private credit without charging either meter
    /// again. Competing instances cannot take that credit. Scope exhaustion is
    /// a latched error, never an automatic spill into the surrounding allowance.
    /// Nested scopes deduct their complete reservation from the parent credit.
    ///
    /// The full reservation counts as spent work even when the operation uses
    /// less, returns an error, exits, is cancelled, or unwinds. Unused credit is
    /// discarded, not refunded or made available to later guest instructions.
    /// Consequently successful exact reservations preserve existing work counts;
    /// a provider that reserves conservatively also pays for its unused margin.
    /// Recording includes the complete debit, and replay pays it independently.
    ///
    /// This reserves WORK, not authority, memory destinations, or transcript
    /// capacity. Every access still checks bounds, cancellation and revocation.
    /// Those failures may leave previously completed effects visible. Validate
    /// complete output extents and provider limits before entering this scope.
    /// It is not a transaction, a native-code sandbox, or a scheduling boundary.
    /// Native callbacks remain responsible for bounded, cooperative execution.
    ///
    /// The closure borrows this caller exclusively; neither it nor unused work
    /// credit can escape. `E` lets providers retain ordinary errno distinctions
    /// while propagating VM faults through their existing error conversion.
    pub fn with_prepaid_work<T, E>(
        &mut self,
        units: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<WasmNumericVmError>,
    {
        self.charge_work(units).map_err(E::from)?;
        let parent = self.prepaid_work.replace(units);
        let mut scope = Scope { caller: self, parent, returned: false };
        let outcome = operation(&mut *scope.caller);
        scope.returned = true;
        // Ignoring a failed charge/access inside the closure cannot launder
        // it into Ok. Do not replace an operation error with a new live poll;
        // the enclosing host boundary retains its normal completion checkpoint.
        if let Some(error) = &scope.caller.failure {
            return Err(E::from(error.clone()));
        }
        outcome
    }
}
