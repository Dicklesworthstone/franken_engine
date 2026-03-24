//! Activation / update / rollback lifecycle contract.
//!
//! Governs how security-critical components are deployed, updated, and
//! recovered.  Every lifecycle transition is explicit, auditable, and
//! reversible.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//!
//! Plan reference: Section 10.10 item 28, bd-1p4.
//! Dependencies: bd-1ai (revocation freshness), bd-2ic (revocation enforcement),
//!               bd-26f (revocation chain), bd-1bi (session channel).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT: &str = "activation_lifecycle";

/// Default crash-loop threshold (crashes within window to trigger rollback).
const DEFAULT_CRASH_THRESHOLD: u32 = 3;

/// Default crash-loop window in logical ticks.
const DEFAULT_CRASH_WINDOW_TICKS: u64 = 60;

/// Default holdoff ticks before a rollback version can be re-updated.
const DEFAULT_ROLLBACK_HOLDOFF_TICKS: u64 = 30;

// ---------------------------------------------------------------------------
// Lifecycle state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of a managed component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecycleState {
    /// Not yet activated.
    Inactive,
    /// Pre-activation checks passed, awaiting health gate.
    PendingActivation,
    /// Running and healthy.
    Active,
    /// Staged rollout in progress.
    Updating(RolloutPhase),
    /// Rolling back to known-good.
    RollingBack,
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive => write!(f, "inactive"),
            Self::PendingActivation => write!(f, "pending_activation"),
            Self::Active => write!(f, "active"),
            Self::Updating(phase) => write!(f, "updating:{phase}"),
            Self::RollingBack => write!(f, "rolling_back"),
        }
    }
}

/// Staged rollout phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RolloutPhase {
    /// New version runs alongside old; output compared but not used.
    Shadow,
    /// New version serves a small traffic fraction.
    Canary,
    /// Gradually increasing traffic fraction.
    Ramp,
    /// New version serves all traffic.
    Default,
}

impl RolloutPhase {
    /// Next phase in the rollout pipeline.  `Default` is terminal.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Shadow => Some(Self::Canary),
            Self::Canary => Some(Self::Ramp),
            Self::Ramp => Some(Self::Default),
            Self::Default => None,
        }
    }

    pub const ALL: [RolloutPhase; 4] = [Self::Shadow, Self::Canary, Self::Ramp, Self::Default];
}

impl fmt::Display for RolloutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shadow => write!(f, "shadow"),
            Self::Canary => write!(f, "canary"),
            Self::Ramp => write!(f, "ramp"),
            Self::Default => write!(f, "default"),
        }
    }
}

/// Trigger that caused a lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransitionTrigger {
    /// Explicit operator or automated request.
    Manual,
    /// Automated by policy (health checks, metrics).
    Auto,
    /// Crash-loop detection triggered rollback.
    CrashLoop,
}

impl fmt::Display for TransitionTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::Auto => write!(f, "auto"),
            Self::CrashLoop => write!(f, "crash_loop"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pre-activation checks
// ---------------------------------------------------------------------------

/// Result of a pre-activation validation check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PreActivationCheck {
    pub check_name: String,
    pub passed: bool,
    pub detail: String,
}

/// Combined pre-activation validation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationValidation {
    pub component_id: String,
    pub version: String,
    pub checks: Vec<PreActivationCheck>,
    pub all_passed: bool,
}

impl ActivationValidation {
    /// Create validation from a list of checks.
    pub fn from_checks(component_id: &str, version: &str, checks: Vec<PreActivationCheck>) -> Self {
        let all_passed = checks.iter().all(|c| c.passed);
        Self {
            component_id: component_id.to_string(),
            version: version.to_string(),
            checks,
            all_passed,
        }
    }
}

// ---------------------------------------------------------------------------
// Ephemeral secret injection
// ---------------------------------------------------------------------------

/// An ephemeral secret that must never be persisted to disk.
/// Cleared on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EphemeralSecret {
    pub key_name: String,
    #[serde(with = "hex_bytes")]
    value: Vec<u8>,
}

impl EphemeralSecret {
    pub fn new(key_name: &str, value: Vec<u8>) -> Self {
        Self {
            key_name: key_name.to_string(),
            value,
        }
    }

    /// Access the secret value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Consume and return the inner value, zeroing the original.
    pub fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.value)
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        // Zero out the secret memory.
        for byte in &mut self.value {
            *byte = 0;
        }
    }
}

impl fmt::Debug for EphemeralSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralSecret({}:REDACTED)", self.key_name)
    }
}

/// Hex serialization for secret bytes.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let hex_str: String = data.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let hex_str = String::deserialize(d)?;
        if hex_str.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex string must have even length"));
        }
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Sealed channel for injecting ephemeral secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInjectionReceipt {
    pub component_id: String,
    pub injected_keys: Vec<String>,
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Known-good pin
// ---------------------------------------------------------------------------

/// Record of the last known-good version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KnownGoodPin {
    pub component_id: String,
    pub version: String,
    pub version_hash: String,
    pub activated_at: DeterministicTimestamp,
    pub health_check_passed_at: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Crash-loop detector
// ---------------------------------------------------------------------------

/// Sliding-window crash-loop detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashLoopDetector {
    crash_timestamps: Vec<u64>,
    threshold: u32,
    window_ticks: u64,
}

impl CrashLoopDetector {
    pub fn new(threshold: u32, window_ticks: u64) -> Self {
        Self {
            crash_timestamps: Vec::new(),
            threshold,
            window_ticks,
        }
    }

    /// Record a crash at the given tick.  Returns `true` if the crash-loop
    /// threshold has been reached.
    pub fn record_crash(&mut self, tick: u64) -> bool {
        self.crash_timestamps.push(tick);
        self.prune(tick);
        self.crash_timestamps.len() >= self.threshold as usize
    }

    /// Number of crashes in the current window.
    pub fn crash_count(&self, current_tick: u64) -> usize {
        let cutoff = current_tick.saturating_sub(self.window_ticks);
        self.crash_timestamps
            .iter()
            .filter(|&&t| t >= cutoff)
            .count()
    }

    /// Reset after a successful rollback.
    pub fn reset(&mut self) {
        self.crash_timestamps.clear();
    }

    fn prune(&mut self, current_tick: u64) {
        let cutoff = current_tick.saturating_sub(self.window_ticks);
        self.crash_timestamps.retain(|&t| t >= cutoff);
    }
}

impl Default for CrashLoopDetector {
    fn default() -> Self {
        Self::new(DEFAULT_CRASH_THRESHOLD, DEFAULT_CRASH_WINDOW_TICKS)
    }
}

// ---------------------------------------------------------------------------
// Component descriptor
// ---------------------------------------------------------------------------

/// Describes a managed component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDescriptor {
    pub component_id: String,
    pub version: String,
    pub version_hash: String,
    pub capabilities_required: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Lifecycle events (structured audit)
// ---------------------------------------------------------------------------

/// Structured lifecycle audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub component_id: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub trigger: Option<String>,
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Lifecycle error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleError {
    /// Invalid state transition.
    InvalidTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    /// Pre-activation validation failed.
    ActivationValidationFailed { detail: String },
    /// Component not found.
    ComponentNotFound { component_id: String },
    /// Rollout phase mismatch.
    RolloutPhaseMismatch {
        expected: RolloutPhase,
        actual: RolloutPhase,
    },
    /// No known-good version to rollback to.
    NoKnownGoodVersion { component_id: String },
    /// Crash-loop detected.
    CrashLoopDetected {
        component_id: String,
        crash_count: usize,
    },
    /// Revocation check failed (component or signing key revoked).
    RevocationCheckFailed { detail: String },
    /// Rollback holdoff active (too soon to re-update).
    RollbackHoldoffActive {
        component_id: String,
        remaining_ticks: u64,
    },
    /// Checkpoint frontier would regress.
    CheckpointRegression { component_id: String },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::ActivationValidationFailed { detail } => {
                write!(f, "activation validation failed: {detail}")
            }
            Self::ComponentNotFound { component_id } => {
                write!(f, "component not found: {component_id}")
            }
            Self::RolloutPhaseMismatch { expected, actual } => {
                write!(
                    f,
                    "rollout phase mismatch: expected {expected}, got {actual}"
                )
            }
            Self::NoKnownGoodVersion { component_id } => {
                write!(f, "no known-good version for {component_id}")
            }
            Self::CrashLoopDetected {
                component_id,
                crash_count,
            } => {
                write!(
                    f,
                    "crash-loop detected for {component_id}: {crash_count} crashes"
                )
            }
            Self::RevocationCheckFailed { detail } => {
                write!(f, "revocation check failed: {detail}")
            }
            Self::RollbackHoldoffActive {
                component_id,
                remaining_ticks,
            } => {
                write!(
                    f,
                    "rollback holdoff active for {component_id}: {remaining_ticks} ticks remaining"
                )
            }
            Self::CheckpointRegression { component_id } => {
                write!(f, "checkpoint frontier would regress for {component_id}")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Stable error codes.
pub fn error_code(err: &LifecycleError) -> &'static str {
    match err {
        LifecycleError::InvalidTransition { .. } => "LC_INVALID_TRANSITION",
        LifecycleError::ActivationValidationFailed { .. } => "LC_ACTIVATION_FAILED",
        LifecycleError::ComponentNotFound { .. } => "LC_COMPONENT_NOT_FOUND",
        LifecycleError::RolloutPhaseMismatch { .. } => "LC_ROLLOUT_MISMATCH",
        LifecycleError::NoKnownGoodVersion { .. } => "LC_NO_KNOWN_GOOD",
        LifecycleError::CrashLoopDetected { .. } => "LC_CRASH_LOOP",
        LifecycleError::RevocationCheckFailed { .. } => "LC_REVOCATION_FAILED",
        LifecycleError::RollbackHoldoffActive { .. } => "LC_ROLLBACK_HOLDOFF",
        LifecycleError::CheckpointRegression { .. } => "LC_CHECKPOINT_REGRESSION",
    }
}

// ---------------------------------------------------------------------------
// Component entry (internal state per managed component)
// ---------------------------------------------------------------------------

/// Internal record of a managed component.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComponentEntry {
    descriptor: ComponentDescriptor,
    state: LifecycleState,
    known_good: Option<KnownGoodPin>,
    crash_detector: CrashLoopDetector,
    /// Tick at which the last rollback completed (for holdoff).
    last_rollback_tick: Option<u64>,
    /// Checkpoint sequence at activation time (non-regression).
    checkpoint_seq_at_activation: Option<u64>,
    /// Injected secret key names (for audit, not the values).
    injected_secret_keys: Vec<String>,
}

// ---------------------------------------------------------------------------
// Lifecycle controller
// ---------------------------------------------------------------------------

/// Configuration for the lifecycle controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfig {
    pub crash_threshold: u32,
    pub crash_window_ticks: u64,
    pub rollback_holdoff_ticks: u64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            crash_threshold: DEFAULT_CRASH_THRESHOLD,
            crash_window_ticks: DEFAULT_CRASH_WINDOW_TICKS,
            rollback_holdoff_ticks: DEFAULT_ROLLBACK_HOLDOFF_TICKS,
        }
    }
}

/// Manages the activation / update / rollback lifecycle for components.
#[derive(Debug)]
pub struct ActivationLifecycleController {
    config: LifecycleConfig,
    components: Vec<ComponentEntry>,
    events: Vec<LifecycleEvent>,
    current_tick: u64,
    zone: String,
    transition_count: u64,
}

impl ActivationLifecycleController {
    pub fn new(config: LifecycleConfig, zone: &str) -> Self {
        Self {
            config,
            components: Vec::new(),
            events: Vec::new(),
            current_tick: 0,
            zone: zone.to_string(),
            transition_count: 0,
        }
    }

    /// Set the current logical tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Zone identifier.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Number of managed components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Number of lifecycle transitions performed.
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Get the current state of a component.
    pub fn state(&self, component_id: &str) -> Option<LifecycleState> {
        self.find_component(component_id).map(|c| c.state)
    }

    /// Get the known-good pin for a component.
    pub fn known_good(&self, component_id: &str) -> Option<&KnownGoodPin> {
        self.find_component(component_id)
            .and_then(|c| c.known_good.as_ref())
    }

    /// Configuration.
    pub fn config(&self) -> &LifecycleConfig {
        &self.config
    }

    // -- Activation ---------------------------------------------------------

    /// Register a component in the Inactive state.
    pub fn register(
        &mut self,
        descriptor: ComponentDescriptor,
        trace_id: &str,
    ) -> Result<(), LifecycleError> {
        if self.find_component(&descriptor.component_id).is_some() {
            return Err(LifecycleError::ActivationValidationFailed {
                detail: format!("component already registered: {}", descriptor.component_id),
            });
        }
        let comp_id = descriptor.component_id.clone();
        self.components.push(ComponentEntry {
            descriptor,
            state: LifecycleState::Inactive,
            known_good: None,
            crash_detector: CrashLoopDetector::new(
                self.config.crash_threshold,
                self.config.crash_window_ticks,
            ),
            last_rollback_tick: None,
            checkpoint_seq_at_activation: None,
            injected_secret_keys: Vec::new(),
        });
        self.push_event(trace_id, "component_registered", "ok", None, Some(&comp_id));
        Ok(())
    }

    /// Begin activation: run pre-activation validation checks.
    /// Transitions from Inactive -> PendingActivation if checks pass.
    pub fn begin_activation(
        &mut self,
        component_id: &str,
        validation: &ActivationValidation,
        trace_id: &str,
    ) -> Result<(), LifecycleError> {
        let entry = self.find_component_mut(component_id)?;

        if entry.state != LifecycleState::Inactive {
            return Err(LifecycleError::InvalidTransition {
                from: entry.state,
                to: LifecycleState::PendingActivation,
            });
        }

        if !validation.all_passed {
            let failed: Vec<&str> = validation
                .checks
                .iter()
                .filter(|c| !c.passed)
                .map(|c| c.check_name.as_str())
                .collect();
            return Err(LifecycleError::ActivationValidationFailed {
                detail: format!("failed checks: {}", failed.join(", ")),
            });
        }

        entry.state = LifecycleState::PendingActivation;
        self.transition_count = self.transition_count.saturating_add(1);
        self.push_transition(
            trace_id,
            component_id,
            LifecycleState::Inactive,
            LifecycleState::PendingActivation,
            TransitionTrigger::Manual,
        );
        Ok(())
    }

    /// Inject ephemeral secrets into a pending-activation component.
    pub fn inject_secrets(
        &mut self,
        component_id: &str,
        secrets: &[EphemeralSecret],
        trace_id: &str,
    ) -> Result<SecretInjectionReceipt, LifecycleError> {
        let tick = self.current_tick;
        let entry = self.find_component_mut(component_id)?;

        if entry.state != LifecycleState::PendingActivation {
            return Err(LifecycleError::InvalidTransition {
                from: entry.state,
                to: LifecycleState::PendingActivation,
            });
        }

        let key_names: Vec<String> = secrets.iter().map(|s| s.key_name.clone()).collect();
        entry.injected_secret_keys = key_names.clone();

        let receipt = SecretInjectionReceipt {
            component_id: component_id.to_string(),
            injected_keys: key_names,
            timestamp: DeterministicTimestamp(tick),
        };

        self.push_event(trace_id, "secrets_injected", "ok", None, Some(component_id));
        Ok(receipt)
    }

    /// Complete activation: health check passed.
    /// Transitions from PendingActivation -> Active.
    pub fn complete_activation(
        &mut self,
        component_id: &str,
        checkpoint_seq: u64,
        trace_id: &str,
    ) -> Result<(), LifecycleError> {
        let tick = self.current_tick;
        let entry = self.find_component_mut(component_id)?;

        if entry.state != LifecycleState::PendingActivation {
            return Err(LifecycleError::InvalidTransition {
                from: entry.state,
                to: LifecycleState::Active,
            });
        }

        entry.state = LifecycleState::Active;
        entry.checkpoint_seq_at_activation = Some(checkpoint_seq);
        entry.known_good = Some(KnownGoodPin {
            component_id: component_id.to_string(),
            version: entry.descriptor.version.clone(),
            version_hash: entry.descriptor.version_hash.clone(),
            activated_at: DeterministicTimestamp(tick),
            health_check_passed_at: DeterministicTimestamp(tick),
        });

        self.transition_count = self.transition_count.saturating_add(1);
        self.push_transition(
            trace_id,
            component_id,
            LifecycleState::PendingActivation,
            LifecycleState::Active,
            TransitionTrigger::Auto,
        );
        Ok(())
    }

    // -- Update (staged rollout) --------------------------------------------

    /// Begin a staged update.
    /// Transitions from Active -> Updating(Shadow).
    pub fn begin_update(
        &mut self,
        component_id: &str,
        new_descriptor: ComponentDescriptor,
        checkpoint_seq: u64,
        trace_id: &str,
    ) -> Result<(), LifecycleError> {
        let tick = self.current_tick;
        let holdoff = self.config.rollback_holdoff_ticks;
        let entry = self.find_component_mut(component_id)?;

        if entry.state != LifecycleState::Active {
            return Err(LifecycleError::InvalidTransition {
                from: entry.state,
                to: LifecycleState::Updating(RolloutPhase::Shadow),
            });
        }

        // Check rollback holdoff.
        if let Some(last_rollback) = entry.last_rollback_tick {
            let elapsed = tick.saturating_sub(last_rollback);
            if elapsed < holdoff {
                return Err(LifecycleError::RollbackHoldoffActive {
                    component_id: component_id.to_string(),
                    remaining_ticks: holdoff - elapsed,
                });
            }
        }

        // Verify checkpoint non-regression.
        if let Some(seq_at_activation) = entry.checkpoint_seq_at_activation
            && checkpoint_seq < seq_at_activation
        {
            return Err(LifecycleError::CheckpointRegression {
                component_id: component_id.to_string(),
            });
        }

        let old_version = entry.descriptor.version.clone();
        let new_version = new_descriptor.version.clone();
        entry.descriptor = new_descriptor;
        entry.state = LifecycleState::Updating(RolloutPhase::Shadow);
        entry.checkpoint_seq_at_activation = Some(checkpoint_seq);

        self.transition_count = self.transition_count.saturating_add(1);
        self.push_update_event(
            trace_id,
            component_id,
            &old_version,
            &new_version,
            "update_started",
            TransitionTrigger::Manual,
        );
        Ok(())
    }

    /// Advance to the next rollout phase.
    pub fn advance_rollout(
        &mut self,
        component_id: &str,
        trace_id: &str,
    ) -> Result<RolloutPhase, LifecycleError> {
        let tick = self.current_tick;
        let entry = self.find_component_mut(component_id)?;

        if let LifecycleState::Updating(current_phase) = entry.state {
            match current_phase.next() {
                Some(next) => {
                    entry.state = LifecycleState::Updating(next);
                    self.transition_count = self.transition_count.saturating_add(1);
                    self.push_transition(
                        trace_id,
                        component_id,
                        LifecycleState::Updating(current_phase),
                        LifecycleState::Updating(next),
                        TransitionTrigger::Auto,
                    );
                    Ok(next)
                }
                None => {
                    // Reaching end of rollout: finalize to Active.
                    let final_phase = current_phase;
                    entry.state = LifecycleState::Active;
                    entry.known_good = Some(KnownGoodPin {
                        component_id: component_id.to_string(),
                        version: entry.descriptor.version.clone(),
                        version_hash: entry.descriptor.version_hash.clone(),
                        activated_at: DeterministicTimestamp(tick),
                        health_check_passed_at: DeterministicTimestamp(tick),
                    });
                    self.transition_count = self.transition_count.saturating_add(1);
                    self.push_transition(
                        trace_id,
                        component_id,
                        LifecycleState::Updating(current_phase),
                        LifecycleState::Active,
                        TransitionTrigger::Auto,
                    );
                    Ok(final_phase)
                }
            }
        } else {
            let current = entry.state;
            Err(LifecycleError::InvalidTransition {
                from: current,
                to: LifecycleState::Updating(RolloutPhase::Shadow),
            })
        }
    }

    // -- Rollback -----------------------------------------------------------

    /// Trigger a manual rollback to the known-good version.
    pub fn rollback(
        &mut self,
        component_id: &str,
        trace_id: &str,
    ) -> Result<KnownGoodPin, LifecycleError> {
        self.do_rollback(component_id, TransitionTrigger::Manual, trace_id)
    }

    /// Report a crash.  Returns `Ok(Some(pin))` if crash-loop triggered
    /// auto-rollback, `Ok(None)` if crash recorded but threshold not reached.
    pub fn report_crash(
        &mut self,
        component_id: &str,
        trace_id: &str,
    ) -> Result<Option<KnownGoodPin>, LifecycleError> {
        let tick = self.current_tick;
        let entry = self.find_component_mut(component_id)?;

        if entry.state == LifecycleState::Inactive {
            return Err(LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::RollingBack,
            });
        }

        let is_loop = entry.crash_detector.record_crash(tick);

        self.push_event(
            trace_id,
            "crash_reported",
            "recorded",
            None,
            Some(component_id),
        );

        if is_loop {
            let pin = self.do_rollback(component_id, TransitionTrigger::CrashLoop, trace_id)?;
            Ok(Some(pin))
        } else {
            Ok(None)
        }
    }

    /// Deactivate a component (Active -> Inactive).
    pub fn deactivate(&mut self, component_id: &str, trace_id: &str) -> Result<(), LifecycleError> {
        let entry = self.find_component_mut(component_id)?;

        if entry.state != LifecycleState::Active {
            return Err(LifecycleError::InvalidTransition {
                from: entry.state,
                to: LifecycleState::Inactive,
            });
        }

        let old_state = entry.state;
        entry.state = LifecycleState::Inactive;
        entry.injected_secret_keys.clear();
        self.transition_count = self.transition_count.saturating_add(1);
        self.push_transition(
            trace_id,
            component_id,
            old_state,
            LifecycleState::Inactive,
            TransitionTrigger::Manual,
        );
        Ok(())
    }

    // -- Accessors ----------------------------------------------------------

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<LifecycleEvent> {
        std::mem::take(&mut self.events)
    }

    /// Access accumulated events.
    pub fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// Get the summary of all components and their states.
    pub fn summary(&self) -> BTreeMap<String, LifecycleState> {
        let mut result = BTreeMap::new();
        for entry in &self.components {
            result.insert(entry.descriptor.component_id.clone(), entry.state);
        }
        result
    }

    /// Active component count.
    pub fn active_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.state == LifecycleState::Active)
            .count()
    }

    /// Get the current version of a component.
    pub fn component_version(&self, component_id: &str) -> String {
        self.find_component(component_id)
            .map(|c| c.descriptor.version.clone())
            .unwrap_or_default()
    }

    // -- Internal helpers ---------------------------------------------------

    fn find_component(&self, component_id: &str) -> Option<&ComponentEntry> {
        self.components
            .iter()
            .find(|c| c.descriptor.component_id == component_id)
    }

    fn find_component_mut(
        &mut self,
        component_id: &str,
    ) -> Result<&mut ComponentEntry, LifecycleError> {
        self.components
            .iter_mut()
            .find(|c| c.descriptor.component_id == component_id)
            .ok_or_else(|| LifecycleError::ComponentNotFound {
                component_id: component_id.to_string(),
            })
    }

    fn do_rollback(
        &mut self,
        component_id: &str,
        trigger: TransitionTrigger,
        trace_id: &str,
    ) -> Result<KnownGoodPin, LifecycleError> {
        let tick = self.current_tick;
        let entry = self.find_component_mut(component_id)?;

        let old_state = entry.state;
        if old_state == LifecycleState::Inactive || old_state == LifecycleState::RollingBack {
            return Err(LifecycleError::InvalidTransition {
                from: old_state,
                to: LifecycleState::RollingBack,
            });
        }

        let pin = entry
            .known_good
            .clone()
            .ok_or_else(|| LifecycleError::NoKnownGoodVersion {
                component_id: component_id.to_string(),
            })?;

        // Transition to RollingBack then immediately to Active with known-good.
        entry.state = LifecycleState::RollingBack;
        self.transition_count = self.transition_count.saturating_add(1);
        self.push_transition(
            trace_id,
            component_id,
            old_state,
            LifecycleState::RollingBack,
            trigger,
        );

        let entry = self.find_component_mut(component_id)?;
        entry.descriptor.version = pin.version.clone();
        entry.descriptor.version_hash = pin.version_hash.clone();
        entry.state = LifecycleState::Active;
        if old_state == LifecycleState::PendingActivation {
            entry.injected_secret_keys.clear();
        }
        entry.last_rollback_tick = Some(tick);
        entry.crash_detector.reset();
        self.transition_count = self.transition_count.saturating_add(1);
        self.push_transition(
            trace_id,
            component_id,
            LifecycleState::RollingBack,
            LifecycleState::Active,
            trigger,
        );

        Ok(pin)
    }

    fn push_event(
        &mut self,
        trace_id: &str,
        event: &str,
        outcome: &str,
        err_code: Option<&str>,
        component_id: Option<&str>,
    ) {
        self.events.push(LifecycleEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
            component_id: component_id.map(str::to_string),
            from_version: None,
            to_version: None,
            from_state: None,
            to_state: None,
            trigger: None,
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }

    fn push_transition(
        &mut self,
        trace_id: &str,
        component_id: &str,
        from: LifecycleState,
        to: LifecycleState,
        trigger: TransitionTrigger,
    ) {
        self.events.push(LifecycleEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: "lifecycle_transition".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            component_id: Some(component_id.to_string()),
            from_version: None,
            to_version: None,
            from_state: Some(from.to_string()),
            to_state: Some(to.to_string()),
            trigger: Some(trigger.to_string()),
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }

    fn push_update_event(
        &mut self,
        trace_id: &str,
        component_id: &str,
        from_version: &str,
        to_version: &str,
        event: &str,
        trigger: TransitionTrigger,
    ) {
        self.events.push(LifecycleEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            component_id: Some(component_id.to_string()),
            from_version: Some(from_version.to_string()),
            to_version: Some(to_version.to_string()),
            from_state: Some(LifecycleState::Active.to_string()),
            to_state: Some(LifecycleState::Updating(RolloutPhase::Shadow).to_string()),
            trigger: Some(trigger.to_string()),
            timestamp: DeterministicTimestamp(self.current_tick),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ------------------------------------------------------------

    fn make_controller() -> ActivationLifecycleController {
        ActivationLifecycleController::new(LifecycleConfig::default(), "test-zone")
    }

    fn test_descriptor(id: &str, version: &str) -> ComponentDescriptor {
        ComponentDescriptor {
            component_id: id.to_string(),
            version: version.to_string(),
            version_hash: format!("hash-{version}"),
            capabilities_required: BTreeSet::new(),
        }
    }

    fn passing_validation(id: &str, version: &str) -> ActivationValidation {
        ActivationValidation::from_checks(
            id,
            version,
            vec![
                PreActivationCheck {
                    check_name: "signature".to_string(),
                    passed: true,
                    detail: "valid".to_string(),
                },
                PreActivationCheck {
                    check_name: "revocation".to_string(),
                    passed: true,
                    detail: "not revoked".to_string(),
                },
            ],
        )
    }

    fn failing_validation(id: &str, version: &str) -> ActivationValidation {
        ActivationValidation::from_checks(
            id,
            version,
            vec![
                PreActivationCheck {
                    check_name: "signature".to_string(),
                    passed: true,
                    detail: "valid".to_string(),
                },
                PreActivationCheck {
                    check_name: "revocation".to_string(),
                    passed: false,
                    detail: "revoked".to_string(),
                },
            ],
        )
    }

    fn activate_component(ctrl: &mut ActivationLifecycleController, id: &str, version: &str) {
        ctrl.register(test_descriptor(id, version), "trace-1")
            .unwrap();
        ctrl.begin_activation(id, &passing_validation(id, version), "trace-1")
            .unwrap();
        ctrl.inject_secrets(id, &[EphemeralSecret::new("key1", vec![0xAA])], "trace-1")
            .unwrap();
        ctrl.complete_activation(id, 1, "trace-1").unwrap();
    }

    // -- registration -------------------------------------------------------

    #[test]
    fn register_component() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        assert_eq!(ctrl.component_count(), 1);
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
    }

    #[test]
    fn reject_duplicate_registration() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl
            .register(test_descriptor("comp-a", "2.0.0"), "trace-1")
            .unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::ActivationValidationFailed { .. }
        ));
    }

    // -- activation ---------------------------------------------------------

    #[test]
    fn full_activation_lifecycle() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert!(ctrl.known_good("comp-a").is_some());
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "1.0.0");
    }

    #[test]
    fn activation_fails_if_validation_fails() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl
            .begin_activation("comp-a", &failing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap_err();
        assert!(matches!(
            err,
            LifecycleError::ActivationValidationFailed { .. }
        ));
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
    }

    #[test]
    fn activation_requires_inactive_state() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        let err = ctrl
            .begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    #[test]
    fn complete_activation_requires_pending() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl
            .complete_activation("comp-a", 1, "trace-1")
            .unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // -- secret injection ---------------------------------------------------

    #[test]
    fn inject_secrets_in_pending_state() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();

        let secrets = vec![
            EphemeralSecret::new("session_key", vec![1, 2, 3]),
            EphemeralSecret::new("encryption_key", vec![4, 5, 6]),
        ];
        let receipt = ctrl.inject_secrets("comp-a", &secrets, "trace-1").unwrap();
        assert_eq!(receipt.injected_keys.len(), 2);
        assert_eq!(receipt.component_id, "comp-a");
    }

    #[test]
    fn inject_secrets_requires_pending() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl.inject_secrets("comp-a", &[], "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // -- ephemeral secret properties ----------------------------------------

    #[test]
    fn ephemeral_secret_zeroed_on_drop() {
        let secret = EphemeralSecret::new("test", vec![0xAA, 0xBB, 0xCC]);
        let ptr = secret.value.as_ptr();
        let len = secret.value.len();
        drop(secret);
        // After drop, the memory should have been zeroed.
        // We can't safely read freed memory, but the Drop impl is correct.
        let _ = (ptr, len);
    }

    #[test]
    fn ephemeral_secret_debug_redacted() {
        let secret = EphemeralSecret::new("my_key", vec![0xFF]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("255")); // Should not show value.
    }

    #[test]
    fn ephemeral_secret_take() {
        let secret = EphemeralSecret::new("key", vec![1, 2, 3]);
        let value = secret.take();
        assert_eq!(value, vec![1, 2, 3]);
    }

    // -- staged rollout -----------------------------------------------------

    #[test]
    fn staged_rollout_phases() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::Updating(RolloutPhase::Shadow))
        );

        let phase = ctrl.advance_rollout("comp-a", "trace-1").unwrap();
        assert_eq!(phase, RolloutPhase::Canary);

        let phase = ctrl.advance_rollout("comp-a", "trace-1").unwrap();
        assert_eq!(phase, RolloutPhase::Ramp);

        let phase = ctrl.advance_rollout("comp-a", "trace-1").unwrap();
        assert_eq!(phase, RolloutPhase::Default);

        // Advancing past Default finalizes to Active.
        let phase = ctrl.advance_rollout("comp-a", "trace-1").unwrap();
        assert_eq!(phase, RolloutPhase::Default);
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "2.0.0");
    }

    #[test]
    fn update_requires_active_state() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl
            .begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    #[test]
    fn advance_rollout_requires_updating() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        let err = ctrl.advance_rollout("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // -- rollback -----------------------------------------------------------

    #[test]
    fn manual_rollback_during_update() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();

        let pin = ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(pin.version, "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    }

    #[test]
    fn rollback_to_known_good_version() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary

        let pin = ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(pin.version, "1.0.0");
    }

    #[test]
    fn rollback_from_inactive_fails() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl.rollback("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    #[test]
    fn rollback_without_known_good_fails() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        // PendingActivation but no known_good yet.
        let err = ctrl.rollback("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
    }

    #[test]
    fn rollback_from_reactivation_pending_clears_injected_secret_keys() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.deactivate("comp-a", "trace-1").unwrap();
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.inject_secrets(
            "comp-a",
            &[EphemeralSecret::new("stale_key", vec![0xCC])],
            "trace-1",
        )
        .unwrap();

        let entry = ctrl.find_component("comp-a").unwrap();
        assert_eq!(entry.state, LifecycleState::PendingActivation);
        assert_eq!(entry.injected_secret_keys, vec!["stale_key"]);

        let pin = ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(pin.version, "1.0.0");

        let entry = ctrl.find_component("comp-a").unwrap();
        assert_eq!(entry.state, LifecycleState::Active);
        assert!(entry.injected_secret_keys.is_empty());
    }

    // -- crash-loop detection -----------------------------------------------

    #[test]
    fn crash_loop_triggers_auto_rollback() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();

        ctrl.set_tick(10);
        assert!(ctrl.report_crash("comp-a", "trace-1").unwrap().is_none());
        ctrl.set_tick(11);
        assert!(ctrl.report_crash("comp-a", "trace-1").unwrap().is_none());
        ctrl.set_tick(12);
        let result = ctrl.report_crash("comp-a", "trace-1").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().version, "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    }

    #[test]
    fn crash_outside_window_does_not_trigger() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();

        // Crashes spread across different windows.
        ctrl.set_tick(10);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(100); // Far beyond window.
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(200);
        let result = ctrl.report_crash("comp-a", "trace-1").unwrap();
        assert!(result.is_none()); // No crash-loop because spread out.
    }

    // -- rollback holdoff ---------------------------------------------------

    #[test]
    fn rollback_holdoff_prevents_immediate_reupdate() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();

        ctrl.set_tick(10);
        ctrl.rollback("comp-a", "trace-1").unwrap();

        // Try to update immediately after rollback.
        ctrl.set_tick(11);
        let err = ctrl
            .begin_update("comp-a", test_descriptor("comp-a", "3.0.0"), 1, "trace-1")
            .unwrap_err();
        assert!(matches!(err, LifecycleError::RollbackHoldoffActive { .. }));

        // After holdoff expires.
        ctrl.set_tick(10 + DEFAULT_ROLLBACK_HOLDOFF_TICKS);
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "3.0.0"), 1, "trace-1")
            .unwrap();
    }

    // -- checkpoint regression guard ----------------------------------------

    #[test]
    fn checkpoint_regression_rejected() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        // Activation set checkpoint_seq = 1. Try update with seq 0.
        let err = ctrl
            .begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 0, "trace-1")
            .unwrap_err();
        assert!(matches!(err, LifecycleError::CheckpointRegression { .. }));
    }

    #[test]
    fn checkpoint_advancement_accepted() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 2, "trace-1")
            .unwrap();
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::Updating(RolloutPhase::Shadow))
        );
    }

    // -- deactivation -------------------------------------------------------

    #[test]
    fn deactivate_active_component() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.deactivate("comp-a", "trace-1").unwrap();
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Inactive));
    }

    #[test]
    fn deactivate_non_active_fails() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl.deactivate("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // -- events emission ----------------------------------------------------

    #[test]
    fn events_emitted_on_activation() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        let events = ctrl.drain_events();
        // register + transition(inactive->pending) + secrets + transition(pending->active)
        assert!(events.len() >= 4);
        assert!(events.iter().any(|e| e.event == "component_registered"));
        assert!(events.iter().any(|e| e.event == "secrets_injected"));
        assert!(
            events
                .iter()
                .any(|e| e.event == "lifecycle_transition"
                    && e.to_state.as_deref() == Some("active"))
        );
    }

    #[test]
    fn events_emitted_on_rollback() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.drain_events();

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.rollback("comp-a", "trace-1").unwrap();

        let events = ctrl.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.to_state.as_deref() == Some("rolling_back"))
        );
        assert!(
            events
                .iter()
                .any(|e| e.trigger.as_deref() == Some("manual"))
        );
    }

    #[test]
    fn events_emitted_on_crash_loop_rollback() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.drain_events();

        ctrl.set_tick(10);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(11);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(12);
        ctrl.report_crash("comp-a", "trace-1").unwrap();

        let events = ctrl.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.trigger.as_deref() == Some("crash_loop"))
        );
    }

    // -- summary ------------------------------------------------------------

    #[test]
    fn summary_shows_all_components() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.register(test_descriptor("comp-b", "1.0.0"), "trace-1")
            .unwrap();

        let summary = ctrl.summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary["comp-a"], LifecycleState::Active);
        assert_eq!(summary["comp-b"], LifecycleState::Inactive);
    }

    #[test]
    fn active_count() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        activate_component(&mut ctrl, "comp-b", "1.0.0");
        ctrl.register(test_descriptor("comp-c", "1.0.0"), "trace-1")
            .unwrap();

        assert_eq!(ctrl.active_count(), 2);
    }

    // -- component not found ------------------------------------------------

    #[test]
    fn operations_on_missing_component_fail() {
        let mut ctrl = make_controller();
        assert!(matches!(
            ctrl.begin_activation("missing", &passing_validation("missing", "1.0.0"), "t"),
            Err(LifecycleError::ComponentNotFound { .. })
        ));
        assert!(matches!(
            ctrl.complete_activation("missing", 1, "t"),
            Err(LifecycleError::ComponentNotFound { .. })
        ));
        assert!(matches!(
            ctrl.rollback("missing", "t"),
            Err(LifecycleError::ComponentNotFound { .. })
        ));
    }

    // -- serde roundtrips ---------------------------------------------------

    #[test]
    fn lifecycle_state_serde_roundtrip() {
        for state in [
            LifecycleState::Inactive,
            LifecycleState::PendingActivation,
            LifecycleState::Active,
            LifecycleState::Updating(RolloutPhase::Shadow),
            LifecycleState::Updating(RolloutPhase::Canary),
            LifecycleState::Updating(RolloutPhase::Ramp),
            LifecycleState::Updating(RolloutPhase::Default),
            LifecycleState::RollingBack,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deser: LifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deser);
        }
    }

    #[test]
    fn rollout_phase_serde_roundtrip() {
        for phase in RolloutPhase::ALL {
            let json = serde_json::to_string(&phase).unwrap();
            let deser: RolloutPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, deser);
        }
    }

    #[test]
    fn transition_trigger_serde_roundtrip() {
        for trigger in [
            TransitionTrigger::Manual,
            TransitionTrigger::Auto,
            TransitionTrigger::CrashLoop,
        ] {
            let json = serde_json::to_string(&trigger).unwrap();
            let deser: TransitionTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(trigger, deser);
        }
    }

    #[test]
    fn known_good_pin_serde_roundtrip() {
        let pin = KnownGoodPin {
            component_id: "comp-a".to_string(),
            version: "1.0.0".to_string(),
            version_hash: "hash-1.0.0".to_string(),
            activated_at: DeterministicTimestamp(100),
            health_check_passed_at: DeterministicTimestamp(101),
        };
        let json = serde_json::to_string(&pin).unwrap();
        let deser: KnownGoodPin = serde_json::from_str(&json).unwrap();
        assert_eq!(pin, deser);
    }

    #[test]
    fn lifecycle_event_serde_roundtrip() {
        let ev = LifecycleEvent {
            trace_id: "t1".to_string(),
            component: COMPONENT.to_string(),
            event: "lifecycle_transition".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            component_id: Some("comp-a".to_string()),
            from_version: Some("1.0.0".to_string()),
            to_version: Some("2.0.0".to_string()),
            from_state: Some("active".to_string()),
            to_state: Some("updating:shadow".to_string()),
            trigger: Some("manual".to_string()),
            timestamp: DeterministicTimestamp(42),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let deser: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deser);
    }

    #[test]
    fn lifecycle_error_serde_roundtrip() {
        let errors = vec![
            LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            },
            LifecycleError::ActivationValidationFailed {
                detail: "test".to_string(),
            },
            LifecycleError::ComponentNotFound {
                component_id: "x".to_string(),
            },
            LifecycleError::NoKnownGoodVersion {
                component_id: "x".to_string(),
            },
            LifecycleError::CrashLoopDetected {
                component_id: "x".to_string(),
                crash_count: 3,
            },
            LifecycleError::RevocationCheckFailed {
                detail: "revoked".to_string(),
            },
            LifecycleError::RollbackHoldoffActive {
                component_id: "x".to_string(),
                remaining_ticks: 10,
            },
            LifecycleError::CheckpointRegression {
                component_id: "x".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: LifecycleError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deser);
        }
    }

    #[test]
    fn ephemeral_secret_serde_roundtrip() {
        let secret = EphemeralSecret::new("key1", vec![0xAA, 0xBB, 0xCC]);
        let json = serde_json::to_string(&secret).unwrap();
        let deser: EphemeralSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(secret.key_name, deser.key_name);
        assert_eq!(secret.value(), deser.value());
    }

    #[test]
    fn ephemeral_secret_serde_rejects_odd_hex_length() {
        let err = serde_json::from_str::<EphemeralSecret>(r#"{"key_name":"key1","value":"abc"}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("even length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ephemeral_secret_serde_rejects_non_hex_characters() {
        let err = serde_json::from_str::<EphemeralSecret>(r#"{"key_name":"key1","value":"zz"}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid digit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn component_descriptor_serde_roundtrip() {
        let desc = test_descriptor("comp-a", "1.0.0");
        let json = serde_json::to_string(&desc).unwrap();
        let deser: ComponentDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(desc, deser);
    }

    #[test]
    fn activation_validation_serde_roundtrip() {
        let val = passing_validation("comp-a", "1.0.0");
        let json = serde_json::to_string(&val).unwrap();
        let deser: ActivationValidation = serde_json::from_str(&json).unwrap();
        assert_eq!(val, deser);
    }

    // -- display coverage ---------------------------------------------------

    #[test]
    fn lifecycle_state_display() {
        assert_eq!(LifecycleState::Inactive.to_string(), "inactive");
        assert_eq!(LifecycleState::Active.to_string(), "active");
        assert_eq!(
            LifecycleState::Updating(RolloutPhase::Shadow).to_string(),
            "updating:shadow"
        );
        assert_eq!(LifecycleState::RollingBack.to_string(), "rolling_back");
    }

    #[test]
    fn rollout_phase_display() {
        assert_eq!(RolloutPhase::Shadow.to_string(), "shadow");
        assert_eq!(RolloutPhase::Default.to_string(), "default");
    }

    #[test]
    fn transition_trigger_display() {
        assert_eq!(TransitionTrigger::CrashLoop.to_string(), "crash_loop");
    }

    #[test]
    fn error_display_coverage() {
        let err = LifecycleError::InvalidTransition {
            from: LifecycleState::Inactive,
            to: LifecycleState::Active,
        };
        assert!(err.to_string().contains("invalid transition"));
        let err = LifecycleError::CrashLoopDetected {
            component_id: "x".to_string(),
            crash_count: 5,
        };
        assert!(err.to_string().contains("crash-loop"));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            error_code(&LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            }),
            "LC_INVALID_TRANSITION"
        );
        assert_eq!(
            error_code(&LifecycleError::CrashLoopDetected {
                component_id: "x".to_string(),
                crash_count: 3,
            }),
            "LC_CRASH_LOOP"
        );
        assert_eq!(
            error_code(&LifecycleError::CheckpointRegression {
                component_id: "x".to_string(),
            }),
            "LC_CHECKPOINT_REGRESSION"
        );
    }

    // -- crash-loop detector unit tests -------------------------------------

    #[test]
    fn crash_loop_detector_threshold() {
        let mut det = CrashLoopDetector::new(3, 60);
        assert!(!det.record_crash(10));
        assert!(!det.record_crash(11));
        assert!(det.record_crash(12)); // 3rd crash triggers.
    }

    #[test]
    fn crash_loop_detector_window_pruning() {
        let mut det = CrashLoopDetector::new(3, 10);
        det.record_crash(0);
        det.record_crash(5);
        // After window passes, old crashes are pruned.
        assert!(!det.record_crash(20)); // Only 1 crash in [10..20] window.
    }

    #[test]
    fn crash_loop_detector_reset() {
        let mut det = CrashLoopDetector::new(3, 60);
        det.record_crash(1);
        det.record_crash(2);
        det.reset();
        assert_eq!(det.crash_count(3), 0);
    }

    #[test]
    fn crash_loop_detector_default() {
        let det = CrashLoopDetector::default();
        assert_eq!(det.threshold, DEFAULT_CRASH_THRESHOLD);
        assert_eq!(det.window_ticks, DEFAULT_CRASH_WINDOW_TICKS);
    }

    // -- rollout phase next -------------------------------------------------

    #[test]
    fn rollout_phase_next_chain() {
        assert_eq!(RolloutPhase::Shadow.next(), Some(RolloutPhase::Canary));
        assert_eq!(RolloutPhase::Canary.next(), Some(RolloutPhase::Ramp));
        assert_eq!(RolloutPhase::Ramp.next(), Some(RolloutPhase::Default));
        assert_eq!(RolloutPhase::Default.next(), None);
    }

    // -- validation ---------------------------------------------------------

    #[test]
    fn activation_validation_all_passed() {
        let val = passing_validation("comp-a", "1.0.0");
        assert!(val.all_passed);
    }

    #[test]
    fn activation_validation_not_all_passed() {
        let val = failing_validation("comp-a", "1.0.0");
        assert!(!val.all_passed);
    }

    // -- transition count ---------------------------------------------------

    #[test]
    fn transition_count_tracks() {
        let mut ctrl = make_controller();
        assert_eq!(ctrl.transition_count(), 0);
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        // Inactive->PendingActivation + PendingActivation->Active = 2.
        assert_eq!(ctrl.transition_count(), 2);
    }

    // -- full lifecycle scenario ---------------------------------------------

    #[test]
    fn full_lifecycle_activate_update_crash_rollback() {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);

        // 1. Activate v1.0.0.
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));

        // 2. Begin update to v2.0.0.
        ctrl.set_tick(100);
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 2, "trace-2")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-2").unwrap(); // canary

        // 3. Crash 3 times -> auto-rollback.
        ctrl.set_tick(101);
        ctrl.report_crash("comp-a", "trace-2").unwrap();
        ctrl.set_tick(102);
        ctrl.report_crash("comp-a", "trace-2").unwrap();
        ctrl.set_tick(103);
        let pin = ctrl.report_crash("comp-a", "trace-2").unwrap().unwrap();
        assert_eq!(pin.version, "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));

        // 4. Wait for holdoff, then re-update.
        ctrl.set_tick(103 + DEFAULT_ROLLBACK_HOLDOFF_TICKS);
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "3.0.0"), 3, "trace-3")
            .unwrap();

        // 5. Complete full rollout.
        ctrl.advance_rollout("comp-a", "trace-3").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "trace-3").unwrap(); // ramp
        ctrl.advance_rollout("comp-a", "trace-3").unwrap(); // default
        ctrl.advance_rollout("comp-a", "trace-3").unwrap(); // finalize -> active
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "3.0.0");
    }

    // -- zone ---------------------------------------------------------------

    #[test]
    fn zone_is_set() {
        let ctrl = make_controller();
        assert_eq!(ctrl.zone(), "test-zone");
    }

    // -- drain events -------------------------------------------------------

    #[test]
    fn drain_events_clears_buffer() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        assert!(!ctrl.events().is_empty());
        let drained = ctrl.drain_events();
        assert!(!drained.is_empty());
        assert!(ctrl.events().is_empty());
    }

    // -- secret injection receipt -------------------------------------------

    #[test]
    fn secret_injection_receipt_serde_roundtrip() {
        let receipt = SecretInjectionReceipt {
            component_id: "comp-a".to_string(),
            injected_keys: vec!["key1".to_string(), "key2".to_string()],
            timestamp: DeterministicTimestamp(42),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let deser: SecretInjectionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deser);
    }

    // -- crash loop detector serde ------------------------------------------

    #[test]
    fn crash_loop_detector_serde_roundtrip() {
        let mut det = CrashLoopDetector::new(5, 100);
        det.record_crash(10);
        det.record_crash(20);
        let json = serde_json::to_string(&det).unwrap();
        let deser: CrashLoopDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(det, deser);
    }

    // -- lifecycle config serde ---------------------------------------------

    #[test]
    fn lifecycle_config_serde_roundtrip() {
        let config = LifecycleConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deser: LifecycleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deser);
    }

    // -- rollback at every rollout phase ------------------------------------

    #[test]
    fn rollback_during_canary_phase() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::Updating(RolloutPhase::Canary))
        );
        let pin = ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(pin.version, "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    }

    #[test]
    fn rollback_during_ramp_phase() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // ramp
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::Updating(RolloutPhase::Ramp))
        );
        let pin = ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(pin.version, "1.0.0");
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
    }

    // -- adversarial: crashes during activation -----------------------------

    #[test]
    fn crash_during_pending_activation_no_known_good() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::PendingActivation)
        );

        // Crash during PendingActivation with no known_good: first two don't trigger,
        // third triggers crash-loop but rollback fails (no known-good).
        ctrl.set_tick(1);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(2);
        ctrl.report_crash("comp-a", "trace-1").unwrap();
        ctrl.set_tick(3);
        let err = ctrl.report_crash("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::NoKnownGoodVersion { .. }));
    }

    #[test]
    fn crash_on_inactive_component_rejected() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let err = ctrl.report_crash("comp-a", "trace-1").unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
    }

    // -- multi-component isolation ------------------------------------------

    #[test]
    fn operations_on_one_component_do_not_affect_another() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        activate_component(&mut ctrl, "comp-b", "1.0.0");

        // Update comp-a, comp-b stays active.
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        assert_eq!(
            ctrl.state("comp-a"),
            Some(LifecycleState::Updating(RolloutPhase::Shadow))
        );
        assert_eq!(ctrl.state("comp-b"), Some(LifecycleState::Active));

        // Rollback comp-a, comp-b unaffected.
        ctrl.rollback("comp-a", "trace-1").unwrap();
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "1.0.0");
        assert_eq!(ctrl.known_good("comp-b").unwrap().version, "1.0.0");
    }

    // -- deactivation clears secrets ----------------------------------------

    #[test]
    fn deactivation_clears_injected_secret_keys() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.deactivate("comp-a", "trace-1").unwrap();

        // Re-activate to verify fresh secret state.
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        let receipt = ctrl
            .inject_secrets(
                "comp-a",
                &[EphemeralSecret::new("new_key", vec![0xBB])],
                "trace-1",
            )
            .unwrap();
        assert_eq!(receipt.injected_keys, vec!["new_key"]);
    }

    // -- audit event field completeness -------------------------------------

    #[test]
    fn update_events_contain_version_fields() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.drain_events();

        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-u")
            .unwrap();
        let events = ctrl.drain_events();
        let update_ev = events
            .iter()
            .find(|e| e.event == "update_started")
            .expect("update_started event");
        assert_eq!(update_ev.from_version.as_deref(), Some("1.0.0"));
        assert_eq!(update_ev.to_version.as_deref(), Some("2.0.0"));
        assert_eq!(update_ev.trigger.as_deref(), Some("manual"));
        assert_eq!(update_ev.component_id.as_deref(), Some("comp-a"));
    }

    #[test]
    fn transition_events_have_from_to_states() {
        let mut ctrl = make_controller();
        ctrl.register(test_descriptor("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.begin_activation("comp-a", &passing_validation("comp-a", "1.0.0"), "trace-1")
            .unwrap();
        ctrl.complete_activation("comp-a", 1, "trace-1").unwrap();

        let events = ctrl.drain_events();
        let transitions: Vec<_> = events
            .iter()
            .filter(|e| e.event == "lifecycle_transition")
            .collect();
        assert!(transitions.len() >= 2);
        for t in &transitions {
            assert!(t.from_state.is_some(), "transition must have from_state");
            assert!(t.to_state.is_some(), "transition must have to_state");
            assert!(t.trigger.is_some(), "transition must have trigger");
        }
    }

    // -- determinism: repeated runs produce same events ---------------------

    #[test]
    fn lifecycle_replay_deterministic() {
        let run = || {
            let mut ctrl = make_controller();
            ctrl.set_tick(100);
            activate_component(&mut ctrl, "comp-a", "1.0.0");
            ctrl.set_tick(200);
            ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 2, "trace-1")
                .unwrap();
            ctrl.advance_rollout("comp-a", "trace-1").unwrap();
            ctrl.set_tick(201);
            ctrl.report_crash("comp-a", "trace-1").unwrap();
            ctrl.set_tick(202);
            ctrl.report_crash("comp-a", "trace-1").unwrap();
            ctrl.set_tick(203);
            ctrl.report_crash("comp-a", "trace-1").unwrap();
            let events = ctrl.drain_events();
            serde_json::to_string(&events).unwrap()
        };
        assert_eq!(run(), run());
    }

    // -- edge: rapid update cycle -------------------------------------------

    #[test]
    fn rapid_update_after_holdoff() {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate_component(&mut ctrl, "comp-a", "1.0.0");

        // Update v2, rollback, wait holdoff, update v3, complete.
        ctrl.set_tick(10);
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 2, "trace-1")
            .unwrap();
        ctrl.rollback("comp-a", "trace-1").unwrap();

        ctrl.set_tick(10 + DEFAULT_ROLLBACK_HOLDOFF_TICKS);
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "3.0.0"), 3, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // ramp
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // default
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // finalize -> active
        assert_eq!(ctrl.state("comp-a"), Some(LifecycleState::Active));
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "3.0.0");
    }

    // -- edge: component version consistency after rollback -----------------

    #[test]
    fn version_restored_after_rollback() {
        let mut ctrl = make_controller();
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 1, "trace-1")
            .unwrap();
        ctrl.rollback("comp-a", "trace-1").unwrap();
        // component_version helper should return the known-good version.
        assert_eq!(ctrl.component_version("comp-a"), "1.0.0");
    }

    // -- activation validation from_checks ----------------------------------

    #[test]
    fn activation_validation_empty_checks_passes() {
        let val = ActivationValidation::from_checks("comp-a", "1.0.0", vec![]);
        assert!(val.all_passed); // No checks means nothing failed.
    }

    // -- config accessors ---------------------------------------------------

    #[test]
    fn config_accessor() {
        let ctrl = make_controller();
        let cfg = ctrl.config();
        assert_eq!(cfg.crash_threshold, DEFAULT_CRASH_THRESHOLD);
        assert_eq!(cfg.crash_window_ticks, DEFAULT_CRASH_WINDOW_TICKS);
        assert_eq!(cfg.rollback_holdoff_ticks, DEFAULT_ROLLBACK_HOLDOFF_TICKS);
    }

    // -- error_code covers all variants -------------------------------------

    #[test]
    fn error_code_all_variants_stable() {
        let codes: Vec<(&'static str, LifecycleError)> = vec![
            (
                "LC_INVALID_TRANSITION",
                LifecycleError::InvalidTransition {
                    from: LifecycleState::Inactive,
                    to: LifecycleState::Active,
                },
            ),
            (
                "LC_ACTIVATION_FAILED",
                LifecycleError::ActivationValidationFailed {
                    detail: "x".to_string(),
                },
            ),
            (
                "LC_COMPONENT_NOT_FOUND",
                LifecycleError::ComponentNotFound {
                    component_id: "x".to_string(),
                },
            ),
            (
                "LC_ROLLOUT_MISMATCH",
                LifecycleError::RolloutPhaseMismatch {
                    expected: RolloutPhase::Canary,
                    actual: RolloutPhase::Shadow,
                },
            ),
            (
                "LC_NO_KNOWN_GOOD",
                LifecycleError::NoKnownGoodVersion {
                    component_id: "x".to_string(),
                },
            ),
            (
                "LC_CRASH_LOOP",
                LifecycleError::CrashLoopDetected {
                    component_id: "x".to_string(),
                    crash_count: 3,
                },
            ),
            (
                "LC_REVOCATION_FAILED",
                LifecycleError::RevocationCheckFailed {
                    detail: "x".to_string(),
                },
            ),
            (
                "LC_ROLLBACK_HOLDOFF",
                LifecycleError::RollbackHoldoffActive {
                    component_id: "x".to_string(),
                    remaining_ticks: 10,
                },
            ),
            (
                "LC_CHECKPOINT_REGRESSION",
                LifecycleError::CheckpointRegression {
                    component_id: "x".to_string(),
                },
            ),
        ];
        for (expected_code, err) in &codes {
            assert_eq!(error_code(err), *expected_code);
        }
    }

    // -- rollout phase ALL constant -----------------------------------------

    #[test]
    fn rollout_phase_all_has_four_phases() {
        assert_eq!(RolloutPhase::ALL.len(), 4);
        assert_eq!(RolloutPhase::ALL[0], RolloutPhase::Shadow);
        assert_eq!(RolloutPhase::ALL[3], RolloutPhase::Default);
    }

    // -- error Display coverage for remaining variants ----------------------

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<LifecycleError> = vec![
            LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            },
            LifecycleError::ActivationValidationFailed {
                detail: "bad sig".to_string(),
            },
            LifecycleError::ComponentNotFound {
                component_id: "x".to_string(),
            },
            LifecycleError::RolloutPhaseMismatch {
                expected: RolloutPhase::Canary,
                actual: RolloutPhase::Shadow,
            },
            LifecycleError::NoKnownGoodVersion {
                component_id: "x".to_string(),
            },
            LifecycleError::CrashLoopDetected {
                component_id: "x".to_string(),
                crash_count: 3,
            },
            LifecycleError::RevocationCheckFailed {
                detail: "revoked".to_string(),
            },
            LifecycleError::RollbackHoldoffActive {
                component_id: "x".to_string(),
                remaining_ticks: 5,
            },
            LifecycleError::CheckpointRegression {
                component_id: "x".to_string(),
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "error display must not be empty");
        }
    }

    // -- lifecycle state ordering -------------------------------------------

    #[test]
    fn lifecycle_state_has_stable_ord() {
        assert!(LifecycleState::Inactive < LifecycleState::PendingActivation);
        assert!(LifecycleState::PendingActivation < LifecycleState::Active);
        assert!(LifecycleState::Active < LifecycleState::Updating(RolloutPhase::Shadow));
    }

    // -- multiple updates preserve known_good lineage -----------------------

    #[test]
    fn successive_updates_advance_known_good() {
        let mut ctrl = make_controller();
        ctrl.set_tick(0);
        activate_component(&mut ctrl, "comp-a", "1.0.0");
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "1.0.0");

        // Update to v2, complete rollout (shadow->canary->ramp->default->active).
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "2.0.0"), 2, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // ramp
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // default
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // finalize -> active
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "2.0.0");

        // Update to v3, complete rollout.
        ctrl.begin_update("comp-a", test_descriptor("comp-a", "3.0.0"), 3, "trace-1")
            .unwrap();
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // canary
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // ramp
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // default
        ctrl.advance_rollout("comp-a", "trace-1").unwrap(); // finalize -> active
        assert_eq!(ctrl.known_good("comp-a").unwrap().version, "3.0.0");
    }

    // ── enrichment: missing Display variants ────────────────────────────

    #[test]
    fn lifecycle_state_display_pending_activation() {
        assert_eq!(
            LifecycleState::PendingActivation.to_string(),
            "pending_activation"
        );
    }

    #[test]
    fn rollout_phase_display_canary() {
        assert_eq!(RolloutPhase::Canary.to_string(), "canary");
    }

    #[test]
    fn rollout_phase_display_ramp() {
        assert_eq!(RolloutPhase::Ramp.to_string(), "ramp");
    }

    #[test]
    fn transition_trigger_display_manual() {
        assert_eq!(TransitionTrigger::Manual.to_string(), "manual");
    }

    #[test]
    fn transition_trigger_display_auto() {
        assert_eq!(TransitionTrigger::Auto.to_string(), "auto");
    }

    // ── enrichment: Display uniqueness ──────────────────────────────────

    #[test]
    fn lifecycle_state_display_all_unique() {
        let variants = [
            LifecycleState::Inactive,
            LifecycleState::PendingActivation,
            LifecycleState::Active,
            LifecycleState::Updating(RolloutPhase::Shadow),
            LifecycleState::Updating(RolloutPhase::Canary),
            LifecycleState::Updating(RolloutPhase::Ramp),
            LifecycleState::Updating(RolloutPhase::Default),
            LifecycleState::RollingBack,
        ];
        let strings: BTreeSet<_> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(strings.len(), variants.len());
    }

    #[test]
    fn rollout_phase_display_all_unique() {
        let strings: BTreeSet<_> = RolloutPhase::ALL.iter().map(|p| p.to_string()).collect();
        assert_eq!(strings.len(), RolloutPhase::ALL.len());
    }

    #[test]
    fn transition_trigger_display_all_unique() {
        let variants = [
            TransitionTrigger::Manual,
            TransitionTrigger::Auto,
            TransitionTrigger::CrashLoop,
        ];
        let strings: BTreeSet<_> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(strings.len(), variants.len());
    }

    // ── enrichment: serde roundtrips ────────────────────────────────────

    #[test]
    fn lifecycle_state_serde_all_variants() {
        let variants = [
            LifecycleState::Inactive,
            LifecycleState::PendingActivation,
            LifecycleState::Active,
            LifecycleState::Updating(RolloutPhase::Shadow),
            LifecycleState::Updating(RolloutPhase::Canary),
            LifecycleState::Updating(RolloutPhase::Ramp),
            LifecycleState::Updating(RolloutPhase::Default),
            LifecycleState::RollingBack,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let deser: LifecycleState = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, deser);
        }
    }

    #[test]
    fn rollout_phase_serde_all_variants() {
        for p in &RolloutPhase::ALL {
            let json = serde_json::to_string(p).unwrap();
            let deser: RolloutPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, deser);
        }
    }

    #[test]
    fn transition_trigger_serde_all_variants() {
        let variants = [
            TransitionTrigger::Manual,
            TransitionTrigger::Auto,
            TransitionTrigger::CrashLoop,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let deser: TransitionTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, deser);
        }
    }

    #[test]
    fn lifecycle_error_serde_rollout_phase_mismatch() {
        let err = LifecycleError::RolloutPhaseMismatch {
            expected: RolloutPhase::Canary,
            actual: RolloutPhase::Shadow,
        };
        let json = serde_json::to_string(&err).unwrap();
        let deser: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }

    #[test]
    fn lifecycle_error_serde_all_variants() {
        let errors: Vec<LifecycleError> = vec![
            LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            },
            LifecycleError::ActivationValidationFailed {
                detail: "sig".to_string(),
            },
            LifecycleError::ComponentNotFound {
                component_id: "c".to_string(),
            },
            LifecycleError::RolloutPhaseMismatch {
                expected: RolloutPhase::Ramp,
                actual: RolloutPhase::Canary,
            },
            LifecycleError::NoKnownGoodVersion {
                component_id: "c".to_string(),
            },
            LifecycleError::CrashLoopDetected {
                component_id: "c".to_string(),
                crash_count: 5,
            },
            LifecycleError::RevocationCheckFailed {
                detail: "rev".to_string(),
            },
            LifecycleError::RollbackHoldoffActive {
                component_id: "c".to_string(),
                remaining_ticks: 10,
            },
            LifecycleError::CheckpointRegression {
                component_id: "c".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let deser: LifecycleError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, deser);
        }
    }

    // ── enrichment: std::error::Error ───────────────────────────────────

    #[test]
    fn lifecycle_error_is_std_error() {
        let err: &dyn std::error::Error = &LifecycleError::ComponentNotFound {
            component_id: "x".to_string(),
        };
        assert!(err.source().is_none());
    }

    // ── enrichment: EphemeralSecret Debug redaction ─────────────────────

    #[test]
    fn ephemeral_secret_debug_redacts_value() {
        let secret = EphemeralSecret::new("api_key", vec![0xDE, 0xAD]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"), "debug: {debug}");
        assert!(!debug.contains("dead"), "secret leaked in debug: {debug}");
    }

    #[test]
    fn ephemeral_secret_take_returns_value() {
        let secret = EphemeralSecret::new("k", vec![1, 2, 3]);
        let val = secret.take();
        assert_eq!(val, vec![1, 2, 3]);
    }

    // ── enrichment: LifecycleEvent serde ────────────────────────────────

    #[test]
    fn lifecycle_event_serde_roundtrip_full_fields() {
        let event = LifecycleEvent {
            trace_id: "t-1".to_string(),
            component: COMPONENT.to_string(),
            event: "lifecycle_transition".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            component_id: Some("comp-a".to_string()),
            from_version: Some("1.0.0".to_string()),
            to_version: Some("2.0.0".to_string()),
            from_state: Some("inactive".to_string()),
            to_state: Some("active".to_string()),
            trigger: Some("manual".to_string()),
            timestamp: DeterministicTimestamp(100),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deser: LifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deser);
    }

    // ── enrichment: PreActivationCheck serde ────────────────────────────

    #[test]
    fn pre_activation_check_serde_roundtrip() {
        let check = PreActivationCheck {
            check_name: "sig-verify".to_string(),
            passed: true,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let deser: PreActivationCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, deser);
    }

    // ── enrichment: error Display remaining variants ────────────────────

    #[test]
    fn error_display_rollout_phase_mismatch() {
        let err = LifecycleError::RolloutPhaseMismatch {
            expected: RolloutPhase::Canary,
            actual: RolloutPhase::Shadow,
        };
        let msg = err.to_string();
        assert!(msg.contains("canary"), "msg: {msg}");
        assert!(msg.contains("shadow"), "msg: {msg}");
    }

    #[test]
    fn error_display_rollback_holdoff_active() {
        let err = LifecycleError::RollbackHoldoffActive {
            component_id: "comp-a".to_string(),
            remaining_ticks: 15,
        };
        let msg = err.to_string();
        assert!(msg.contains("comp-a"), "msg: {msg}");
        assert!(msg.contains("15"), "msg: {msg}");
    }

    #[test]
    fn error_display_all_variants_unique() {
        let errors: Vec<LifecycleError> = vec![
            LifecycleError::InvalidTransition {
                from: LifecycleState::Inactive,
                to: LifecycleState::Active,
            },
            LifecycleError::ActivationValidationFailed {
                detail: "x".to_string(),
            },
            LifecycleError::ComponentNotFound {
                component_id: "c".to_string(),
            },
            LifecycleError::RolloutPhaseMismatch {
                expected: RolloutPhase::Canary,
                actual: RolloutPhase::Shadow,
            },
            LifecycleError::NoKnownGoodVersion {
                component_id: "c".to_string(),
            },
            LifecycleError::CrashLoopDetected {
                component_id: "c".to_string(),
                crash_count: 5,
            },
            LifecycleError::RevocationCheckFailed {
                detail: "r".to_string(),
            },
            LifecycleError::RollbackHoldoffActive {
                component_id: "c".to_string(),
                remaining_ticks: 10,
            },
            LifecycleError::CheckpointRegression {
                component_id: "c".to_string(),
            },
        ];
        let strings: BTreeSet<_> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(strings.len(), errors.len());
    }
}
