//! Join native workers and drain their configured provider-call scope.

use std::fmt;
use std::time::{Duration, Instant};

use super::{ExecutionTaskGroup, ExecutionTaskJoinError, ExecutionWorkPool, WorkBudgetError};
use crate::host_effect_budget::{
    HostEffectDrainError, HostEffectSnapshot, HostEffectWorkPool,
};

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
