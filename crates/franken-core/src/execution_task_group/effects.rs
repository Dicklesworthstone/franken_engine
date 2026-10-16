//! Join native workers and drain their configured provider-call scope.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    ExecutionAdmission, ExecutionGroupStartError, ExecutionTaskGroup, ExecutionTaskId,
    ExecutionTaskJoinError, ExecutionWorkPool, InterpreterConfig, InterpreterHook, Ir3Module,
    WorkBudgetError,
};
use crate::host_effect_budget::{
    BudgetedHostIo, BudgetedProcessSpawn, HostEffectDrainError, HostEffectSnapshot, HostEffectWorkPool,
};

use frankenengine_extension_host::host_io::HostIoProvider;
use frankenengine_extension_host::process_spawn::ProcessSpawnProvider;

/// Borrowed preparation context for this group's exact prepaid job and effect
/// frontier. Neither raw pool authority nor an owned admission can escape it.
/// Decorators may be retained, but their job-local scope closes when the admission
/// completes, is refused, is cancelled, or unwinds. Binding grants no capability.
pub struct ExecutionHostBindings<'a> {
    admission: &'a ExecutionAdmission,
    effects: &'a HostEffectWorkPool,
}

impl fmt::Debug for ExecutionHostBindings<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionHostBindings").finish_non_exhaustive()
    }
}

impl ExecutionHostBindings<'_> {
    /// Effective absolute job deadline, already attenuated by ancestor scopes.
    /// Native execution and both provider decorators observe this SAME deadline.
    pub fn deadline(&self) -> Option<Instant> {
        self.admission.deadline()
    }

    /// Preserve the configured provider's policy while sharing this group's
    /// operation credits, in-flight frontier and the job's cancellation lifetime.
    pub fn bind_host_io(&self, provider: Arc<dyn HostIoProvider>) -> BudgetedHostIo {
        self.effects.bind_host_io_for_admission(provider, self.admission)
    }

    /// Process dispatch shares the SAME credits and in-flight ceiling as I/O.
    /// Preserve spawned handles, native typed failures and trusted cleanup. Only
    /// admitted dispatch is drained; cleanup/reaping/journaling remain external.
    pub fn bind_process_spawn(&self, provider: Arc<dyn ProcessSpawnProvider>) -> BudgetedProcessSpawn {
        self.effects.bind_process_spawn_for_admission(provider, self.admission)
    }
}

/// A failed group drain never certifies provider or native-worker completion.
/// The group stays closed and retains every task/result for a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionGroupDrainError {
    /// No provider frontier was configured; a native join is not an effect drain.
    HostEffectsUnconfigured,
    InvalidTimeout,
    Tasks(ExecutionTaskJoinError),
    Effects(HostEffectDrainError),
}

impl fmt::Display for ExecutionGroupDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostEffectsUnconfigured => f.write_str("native group has no host-effect scope"),
            Self::InvalidTimeout => f.write_str("native group drain deadline is not representable"),
            Self::Tasks(error) => write!(f, "native group worker drain: {error}"),
            Self::Effects(error) => write!(f, "native group provider drain: {error}"),
        }
    }
}

impl std::error::Error for ExecutionGroupDrainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tasks(error) => Some(error),
            Self::Effects(error) => Some(error),
            _ => None,
        }
    }
}

impl ExecutionTaskGroup {
    /// Prepare provider decorators against the same effect scope that
    /// `close_and_drain` waits on and the exact admission consumed by the worker.
    /// Install them in the trusted host's current configuration or returned hook.
    /// The callback receives neither an owned admission nor a raw effect pool,
    /// preventing accidental binding to a different frontier through this API.
    /// Arbitrary providers already hidden in custom hooks are not auto-wrapped.
    ///
    /// All ordinary capacity, quota, capability and cancellation checks remain
    /// on `spawn_with_preparation`. Missing effect configuration refuses before
    /// debit or callback entry. Setup refusal closes the job without refund;
    /// setup unwind cancels BOTH group scopes and keeps existing task handles.
    /// Preparation is trusted synchronous host code, never a guest callback.
    pub fn spawn_with_effect_preparation(
        &mut self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        prepare: impl FnOnce(
            &ExecutionHostBindings<'_>,
            &mut InterpreterConfig,
        ) -> Result<Option<Arc<dyn InterpreterHook>>, WorkBudgetError>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        self.spawn_effect_prepared(module, current_config, trace_id, None, prepare)
    }

    /// Deadline-aware dispatch using the exact job and effect scope supervised
    /// by this group. The deadline includes trusted preparation and reaches all
    /// derived provider controls; no fresh timeout begins at worker creation.
    /// Neither expiry nor setup failure may hide an already-admitted provider
    /// call from the existing drain frontier. Sibling jobs remain independent.
    pub fn spawn_with_effect_preparation_until(
        &mut self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        deadline: Instant,
        prepare: impl FnOnce(
            &ExecutionHostBindings<'_>,
            &mut InterpreterConfig,
        ) -> Result<Option<Arc<dyn InterpreterHook>>, WorkBudgetError>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        self.spawn_effect_prepared(module, current_config, trace_id, Some(deadline), prepare)
    }

    fn spawn_effect_prepared(
        &mut self,
        module: Ir3Module,
        current_config: InterpreterConfig,
        trace_id: impl Into<String>,
        deadline: Option<Instant>,
        prepare: impl FnOnce(
            &ExecutionHostBindings<'_>,
            &mut InterpreterConfig,
        ) -> Result<Option<Arc<dyn InterpreterHook>>, WorkBudgetError>,
    ) -> Result<ExecutionTaskId, ExecutionGroupStartError> {
        if self.is_closed() {
            return Err(ExecutionGroupStartError::Closed);
        }
        let effects = self.effects.clone()
            .ok_or(ExecutionGroupStartError::HostEffectsUnconfigured)?;
        self.spawn_prepared(module, current_config, trace_id, deadline, |admission, config| {
            prepare(&ExecutionHostBindings { admission, effects: &effects }, config)
        })
    }

    /// Own an existing host-designated effect scope along with a new private
    /// instruction partition. No effect credits are created or delegated here.
    /// Existing aliases intentionally share revocation and the drain frontier.
    /// Supply a dedicated `HostEffectWorkPool::partition` for sibling isolation.
    /// Failure to partition instructions leaves the supplied effect scope alone.
    ///
    /// Hosts must route this group's providers through this effect scope; the
    /// constructor does not wrap arbitrary providers hidden in custom hooks.
    /// Closing the group revokes both scopes before waiting. Dropping it only
    /// requests cancellation; retain the owner and explicitly close and drain.
    pub fn new_with_host_effects(
        parent: &ExecutionWorkPool,
        instruction_limit: u64,
        capacity: usize,
        effects: HostEffectWorkPool,
    ) -> Result<Self, WorkBudgetError> {
        let mut group = Self::new(parent, instruction_limit, capacity)?;
        group.effects = Some(effects);
        Ok(group)
    }

    /// Revoke BOTH scopes, join every worker, then drain admitted provider calls
    /// using one monotonic deadline for the entire operation. No phase renews
    /// the timeout. Zero is an immediate revoking probe; every error leaves
    /// cancellation requested, handles/results retained, and credits unchanged.
    /// A retry must use the same owner. Successful drain does not discard outcomes
    /// or imply successful guest execution; collect each native result separately.
    ///
    /// Only calls accounted to the configured scope (including its descendants)
    /// are covered. This does NOT certify retained-child exit, detached provider
    /// work, unmetered compensating cleanup, or journal finalization. Those remain
    /// the execution-cell owner's responsibility. In particular, process spawn
    /// may return and release its dispatch permit while its child is still alive.
    ///
    /// Call from the supervising host, not a callback holding a permit being
    /// drained. Scheduling, mutex reacquisition and OS join are not hard real-time
    /// bounds. An unconfigured provider frontier fails closed instead of reporting
    /// an empty effect drain. `close_and_join` remains available for native-only
    /// groups and explicitly does not certify provider drain.
    pub fn close_and_drain(
        &mut self,
        timeout: Duration,
    ) -> Result<HostEffectSnapshot, ExecutionGroupDrainError> {
        let started = Instant::now();
        self.close();
        let deadline = started
            .checked_add(timeout)
            .ok_or(ExecutionGroupDrainError::InvalidTimeout)?;
        let effects = self
            .effects
            .clone()
            .ok_or(ExecutionGroupDrainError::HostEffectsUnconfigured)?;
        self.join_until(deadline)
            .map_err(ExecutionGroupDrainError::Tasks)?;
        effects
            .revoke_and_drain_until(deadline)
            .map_err(ExecutionGroupDrainError::Effects)
    }
}
