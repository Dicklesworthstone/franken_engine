//! Process operations share the live host-effect pool, not a second allowance.
//!
//! Install this inside the engine's journal/attempt-authority boundary, around
//! the final policy-gated process provider. Replay still consumes recorded
//! outcomes without entering this wrapper. Preflight and canonical preparation
//! are delegated unchanged and do not debit live-operation credits.

use super::{ExecutionWorkPool, HostEffectBudgetError, HostEffectWorkPool, WorkScopeRevocation};
use frankenengine_extension_host::process_spawn::{
    ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnError, ProcessSpawnOutcome,
    ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
    UnrestrictedProcessSpawnControl,
};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

impl HostEffectWorkPool {
    /// Bind the final process provider to the same lifetime operation and
    /// concurrent-dispatch allowance as `bind_host_io`. Clones cannot multiply
    /// either allowance. Every ordinary process request (including wait, stdin
    /// and guest signals) needs a credit and its original capability.
    ///
    /// The concurrency limit counts dispatched operations, NOT retained live
    /// children; keep the native provider's signed child/stream/runtime limits.
    /// Engine-owned `cleanup_handle` is deliberately exempt from admission and
    /// revocation. A depleted guest must not prevent compensating containment.
    /// Its caller must still reserve and commit cleanup in the effect journal.
    pub fn bind_process_spawn(
        &self,
        provider: Arc<dyn ProcessSpawnProvider>,
        execution: &ExecutionWorkPool,
    ) -> BudgetedProcessSpawn {
        BudgetedProcessSpawn {
            provider,
            pool: self.clone(),
            scope: execution.revocation_signal(),
        }
    }
}

/// Live process provider with shared operation admission and execution-scope
/// cancellation. This owner does not expose its wrapped provider or issue new
/// capabilities. Native process preparation, identity pinning, policy and
/// compensating cleanup remain the wrapped provider's responsibility.
#[derive(Clone)]
pub struct BudgetedProcessSpawn {
    provider: Arc<dyn ProcessSpawnProvider>,
    pool: HostEffectWorkPool,
    scope: WorkScopeRevocation,
}

impl fmt::Debug for BudgetedProcessSpawn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A custom provider/control may retain launch arguments or secrets.
        f.debug_struct("BudgetedProcessSpawn")
            .field("limits", &self.pool.limits())
            .field(
                "revoked",
                &(self.pool.is_revoked() || self.scope.is_revoked()),
            )
            .finish_non_exhaustive()
    }
}

fn denied(code: &str) -> ProcessSpawnError {
    ProcessSpawnError::Denied {
        reason: code.to_string(),
    }
}

fn budget_error(error: HostEffectBudgetError) -> ProcessSpawnError {
    denied(error.code())
}

struct ProcessEffectControl {
    pool: HostEffectWorkPool,
    scope: WorkScopeRevocation,
    caller: Arc<dyn ProcessSpawnControl>,
    refused: AtomicBool,
}

impl fmt::Debug for ProcessEffectControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessEffectControl")
            .finish_non_exhaustive()
    }
}

impl ProcessSpawnControl for ProcessEffectControl {
    fn checkpoint(&self) -> Result<(), ProcessSpawnError> {
        if !self.refused.load(Ordering::Acquire)
            && (self.pool.is_revoked()
                || self.pool.has_poisoned_accounting()
                || self.scope.is_revoked()
                || self.caller.checkpoint().is_err())
        {
            self.refused.store(true, Ordering::Release);
        }
        if self.refused.load(Ordering::Acquire) {
            // Never export a supervisor's private text or turn its refusal into
            // an ordinary guest-catchable native I/O/partial-output failure.
            Err(budget_error(HostEffectBudgetError::Revoked))
        } else {
            // Exhausted admission is NOT cancellation of work already admitted.
            Ok(())
        }
    }
}

impl ProcessSpawnProvider for BudgetedProcessSpawn {
    fn name(&self) -> &str {
        self.provider.name()
    }

    fn preflight_request(&self, request: &ProcessSpawnRequest) -> Result<(), ProcessSpawnError> {
        // This also runs on replay. Do not consult or debit a live pool here.
        self.provider.preflight_request(request)
    }

    fn prepare_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        self.provider.prepare_request(request)
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        self.perform_controlled(request, granted, Arc::new(UnrestrictedProcessSpawnControl))
    }

    fn perform_controlled(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
        caller: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        // Cleanup has a separate trusted-host entry point. Do not provide an
        // unmetered guest effect merely because it has the same enum variant.
        if matches!(request, ProcessSpawnRequest::Cleanup { .. }) {
            return Err(denied("HOST_EFFECT_CLEANUP_REQUIRES_HOST_AUTHORITY"));
        }
        if !granted.contains(&request.required_capability()) {
            return Err(ProcessSpawnError::CapabilityMissing {
                capability: request.required_capability(),
            });
        }
        let control = Arc::new(ProcessEffectControl {
            pool: self.pool.clone(),
            scope: self.scope.clone(),
            caller,
            refused: AtomicBool::new(false),
        });
        control.checkpoint()?;
        self.provider.preflight_request(request)?;
        let _permit = self.pool.admit().map_err(budget_error)?;
        // Revocation racing with admission spends the credit but cannot refund
        // or bypass it. No accounting mutex is held across native work.
        control.checkpoint()?;
        let outcome = self
            .provider
            .perform_controlled(request, granted, control.clone());
        match &outcome {
            // A completed spawn has created a resource. Never hide that handle
            // behind a late denial, or call unjournaled cleanup here: the engine
            // must first register/journal it, then perform compensating teardown.
            // The native provider retains this live control for its watchdog;
            // subsequent guest operations still require fresh authorization.
            Ok(ProcessSpawnResponse::Spawned { .. }) => outcome,
            // Preserve typed native failures, including bounded captured output
            // and terminal/cleanup evidence, exactly as the producer returned.
            Err(_) => outcome,
            Ok(_) => {
                control.checkpoint()?;
                outcome
            }
        }
    }

    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
        // No work credit, concurrency permit or cancellation check may strand
        // an engine-owned child. Do not synthesize successful cleanup: preserve
        // the provider's real typed result for the journal and cell close.
        self.provider.cleanup_handle(handle)
    }
}

#[cfg(test)]
mod tests;
