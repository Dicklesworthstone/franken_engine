#![forbid(unsafe_code)]

//! Bounded feedback control and policy-as-data for tail-latency preservation.
//!
//! Bead: bd-1lsy.7.11.3 [RGC-611C]
//!
//! Implements a bounded feedback-control layer that keeps tail latency inside
//! declared budgets under shifting regimes while remaining deterministic,
//! inspectable, and easy to disable.
//!
//! Key design:
//! - Proportional-integral (PI) controllers with anti-windup for each stage
//! - Policy-as-data: all knobs are serializable, diffable, and auditable
//! - Explicit saturation bounds prevent unbounded actuator drift
//! - Deterministic fixed-point arithmetic (millionths) — no floats
//! - Content-addressed decision receipts for replay and forensics
//!
//! All latencies are in nanoseconds, gains and ratios in millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const FEEDBACK_SCHEMA_VERSION: &str = "franken-engine.bounded-feedback-controller.v1";
pub const FEEDBACK_BEAD_ID: &str = "bd-1lsy.7.11.3";

/// Fixed-point millionths unit.
const MILLIONTHS: i64 = 1_000_000;

/// Default proportional gain: 0.5 (500_000 millionths).
pub const DEFAULT_KP_MILLIONTHS: i64 = 500_000;

/// Default integral gain: 0.1 (100_000 millionths).
pub const DEFAULT_KI_MILLIONTHS: i64 = 100_000;

/// Default anti-windup clamp for integrator state (± ns).
pub const DEFAULT_INTEGRATOR_CLAMP_NS: i64 = 10_000_000;

/// Default output clamp (± millionths): max 50% adjustment.
pub const DEFAULT_OUTPUT_CLAMP_MILLIONTHS: i64 = 500_000;

/// Minimum controller epoch interval before output is trusted.
pub const MIN_WARMUP_EPOCHS: u64 = 3;

// ---------------------------------------------------------------------------
// Controller mode
// ---------------------------------------------------------------------------

/// Operating mode of a feedback controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerMode {
    /// Active: controller output drives actuators.
    Active,
    /// Observe: controller computes output but does not actuate.
    Observe,
    /// Disabled: controller is completely bypassed.
    Disabled,
    /// Fallback: controller uses a fixed safe output.
    Fallback,
}

impl fmt::Display for ControllerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Active => "active",
            Self::Observe => "observe",
            Self::Disabled => "disabled",
            Self::Fallback => "fallback",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Actuator kind
// ---------------------------------------------------------------------------

/// What the controller can adjust to meet latency targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActuatorKind {
    /// Adjust admission rate (tokens/epoch).
    AdmissionRate,
    /// Adjust worker concurrency level.
    WorkerConcurrency,
    /// Adjust compilation tier threshold.
    TierThreshold,
    /// Adjust GC budget allocation.
    GcBudget,
    /// Adjust batch size for hostcalls.
    BatchSize,
    /// Adjust cache eviction pressure.
    CacheEvictionPressure,
}

impl fmt::Display for ActuatorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::AdmissionRate => "admission_rate",
            Self::WorkerConcurrency => "worker_concurrency",
            Self::TierThreshold => "tier_threshold",
            Self::GcBudget => "gc_budget",
            Self::BatchSize => "batch_size",
            Self::CacheEvictionPressure => "cache_eviction_pressure",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Controller output action
// ---------------------------------------------------------------------------

/// What the controller decided for a single epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    /// Increase the actuator value by this fraction (millionths).
    Increase { delta_millionths: i64 },
    /// Decrease the actuator value by this fraction (millionths).
    Decrease { delta_millionths: i64 },
    /// Hold steady — error within deadband.
    Hold,
    /// Controller is in warmup, no action taken.
    Warmup { epochs_remaining: u64 },
    /// Controller is disabled or in fallback.
    Bypassed { mode: ControllerMode },
}

impl fmt::Display for ControlAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Increase { delta_millionths } => {
                write!(f, "increase({delta_millionths}/1M)")
            }
            Self::Decrease { delta_millionths } => {
                write!(f, "decrease({delta_millionths}/1M)")
            }
            Self::Hold => write!(f, "hold"),
            Self::Warmup { epochs_remaining } => {
                write!(f, "warmup({epochs_remaining})")
            }
            Self::Bypassed { mode } => write!(f, "bypassed({mode})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Latency target
// ---------------------------------------------------------------------------

/// Declared latency target for a stage+percentile pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyTarget {
    pub stage: ExecutionStage,
    pub percentile: LatencyPercentile,
    /// Target latency in nanoseconds.
    pub target_ns: u64,
    /// Deadband: don't actuate if |error| < deadband_ns.
    pub deadband_ns: u64,
    /// Maximum tolerable latency before emergency shedding.
    pub emergency_ns: u64,
}

impl LatencyTarget {
    pub fn new(
        stage: ExecutionStage,
        percentile: LatencyPercentile,
        target_ns: u64,
        deadband_ns: u64,
        emergency_ns: u64,
    ) -> Self {
        Self {
            stage,
            percentile,
            target_ns,
            deadband_ns,
            emergency_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Controller config (policy-as-data)
// ---------------------------------------------------------------------------

/// Serializable, diffable configuration for one PI controller instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// Schema version for forward-compat.
    pub schema_version: String,
    /// Which actuator this controller drives.
    pub actuator: ActuatorKind,
    /// Operating mode.
    pub mode: ControllerMode,
    /// Proportional gain (millionths).
    pub kp_millionths: i64,
    /// Integral gain (millionths).
    pub ki_millionths: i64,
    /// Integrator anti-windup clamp (± ns).
    pub integrator_clamp_ns: i64,
    /// Output saturation clamp (± millionths).
    pub output_clamp_millionths: i64,
    /// Deadband override: ignore errors smaller than this (ns).
    pub deadband_override_ns: Option<u64>,
    /// Warmup epochs before output is trusted.
    pub warmup_epochs: u64,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            actuator: ActuatorKind::AdmissionRate,
            mode: ControllerMode::Active,
            kp_millionths: DEFAULT_KP_MILLIONTHS,
            ki_millionths: DEFAULT_KI_MILLIONTHS,
            integrator_clamp_ns: DEFAULT_INTEGRATOR_CLAMP_NS,
            output_clamp_millionths: DEFAULT_OUTPUT_CLAMP_MILLIONTHS,
            deadband_override_ns: None,
            warmup_epochs: MIN_WARMUP_EPOCHS,
        }
    }
}

impl ControllerConfig {
    /// Compute a content hash of this config for change detection.
    pub fn content_hash(&self) -> String {
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}:{:?}:{}",
            self.schema_version,
            self.actuator,
            self.mode,
            self.kp_millionths,
            self.ki_millionths,
            self.integrator_clamp_ns,
            self.output_clamp_millionths,
            self.deadband_override_ns,
            self.warmup_epochs,
        );
        hex_encode(ContentHash::compute(canonical.as_bytes()).as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Controller state
// ---------------------------------------------------------------------------

/// Mutable state for one PI controller instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerState {
    /// Accumulated integrator value (in nanoseconds, clamped).
    pub integrator_ns: i64,
    /// Number of epochs this controller has run.
    pub epoch_count: u64,
    /// Last error signal (ns, signed: positive = over target).
    pub last_error_ns: i64,
    /// Last computed output (millionths).
    pub last_output_millionths: i64,
    /// Whether the controller is currently in emergency mode.
    pub emergency_active: bool,
    /// Total number of emergency activations.
    pub emergency_count: u64,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            integrator_ns: 0,
            epoch_count: 0,
            last_error_ns: 0,
            last_output_millionths: 0,
            emergency_active: false,
            emergency_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Latency observation
// ---------------------------------------------------------------------------

/// A single latency observation fed into the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyObservation {
    pub stage: ExecutionStage,
    pub percentile: LatencyPercentile,
    /// Observed latency in nanoseconds.
    pub observed_ns: u64,
    /// Number of samples backing this observation.
    pub sample_count: u64,
    /// Security epoch when observed.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Controller decision
// ---------------------------------------------------------------------------

/// Full decision record for one controller tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerDecision {
    /// Schema version.
    pub schema_version: String,
    /// Which actuator.
    pub actuator: ActuatorKind,
    /// The target that was evaluated.
    pub target_ns: u64,
    /// Observed latency.
    pub observed_ns: u64,
    /// Error signal (observed - target), signed.
    pub error_ns: i64,
    /// Proportional term (millionths).
    pub p_term_millionths: i64,
    /// Integral term (millionths).
    pub i_term_millionths: i64,
    /// Raw output before clamping (millionths).
    pub raw_output_millionths: i64,
    /// Clamped output (millionths).
    pub clamped_output_millionths: i64,
    /// Action taken.
    pub action: ControlAction,
    /// Whether emergency was triggered.
    pub emergency: bool,
    /// Epoch count at decision time.
    pub epoch_count: u64,
    /// Content hash for replay verification.
    pub decision_hash: String,
}

// ---------------------------------------------------------------------------
// PI controller
// ---------------------------------------------------------------------------

/// A bounded PI controller for one actuator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiController {
    pub config: ControllerConfig,
    pub state: ControllerState,
    pub target: LatencyTarget,
}

impl PiController {
    pub fn new(config: ControllerConfig, target: LatencyTarget) -> Self {
        Self {
            config,
            state: ControllerState::default(),
            target,
        }
    }

    /// Reset controller state without changing config.
    pub fn reset(&mut self) {
        self.state = ControllerState::default();
    }

    /// Tick the controller with a new observation. Returns the decision.
    pub fn tick(&mut self, observation: &LatencyObservation) -> ControllerDecision {
        self.state.epoch_count += 1;

        // Handle disabled/fallback modes.
        if matches!(
            self.config.mode,
            ControllerMode::Disabled | ControllerMode::Fallback
        ) {
            return self.bypassed_decision(observation);
        }

        // Handle warmup.
        if self.state.epoch_count <= self.config.warmup_epochs {
            return self.warmup_decision(observation);
        }

        // Compute error signal (positive = over target = need to reduce).
        let error_ns = observation.observed_ns as i64 - self.target.target_ns as i64;

        // Check deadband.
        let effective_deadband = self
            .config
            .deadband_override_ns
            .unwrap_or(self.target.deadband_ns);
        let in_deadband = error_ns.unsigned_abs() < effective_deadband;

        // Update integrator (with anti-windup clamping).
        if !in_deadband {
            self.state.integrator_ns = clamp(
                self.state.integrator_ns.saturating_add(error_ns),
                -self.config.integrator_clamp_ns,
                self.config.integrator_clamp_ns,
            );
        }

        // Compute PI output.
        let p_term = mul_millionths(error_ns, self.config.kp_millionths);
        let i_term = mul_millionths(self.state.integrator_ns, self.config.ki_millionths);
        let raw_output = p_term.saturating_add(i_term);
        let clamped_output = clamp(
            raw_output,
            -self.config.output_clamp_millionths,
            self.config.output_clamp_millionths,
        );

        // Check emergency.
        let emergency = observation.observed_ns > self.target.emergency_ns;
        if emergency && !self.state.emergency_active {
            self.state.emergency_count += 1;
        }
        self.state.emergency_active = emergency;

        // Determine action.
        let action = if in_deadband {
            ControlAction::Hold
        } else if self.config.mode == ControllerMode::Observe {
            ControlAction::Bypassed {
                mode: ControllerMode::Observe,
            }
        } else if clamped_output > 0 {
            ControlAction::Decrease {
                delta_millionths: clamped_output,
            }
        } else if clamped_output < 0 {
            ControlAction::Increase {
                delta_millionths: -clamped_output,
            }
        } else {
            ControlAction::Hold
        };

        self.state.last_error_ns = error_ns;
        self.state.last_output_millionths = clamped_output;

        let hash = compute_decision_hash(
            self.config.actuator,
            self.target.target_ns,
            observation.observed_ns,
            error_ns,
            clamped_output,
            self.state.epoch_count,
        );

        ControllerDecision {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            actuator: self.config.actuator,
            target_ns: self.target.target_ns,
            observed_ns: observation.observed_ns,
            error_ns,
            p_term_millionths: p_term,
            i_term_millionths: i_term,
            raw_output_millionths: raw_output,
            clamped_output_millionths: clamped_output,
            action,
            emergency,
            epoch_count: self.state.epoch_count,
            decision_hash: hash,
        }
    }

    fn bypassed_decision(&self, observation: &LatencyObservation) -> ControllerDecision {
        let hash = compute_decision_hash(
            self.config.actuator,
            self.target.target_ns,
            observation.observed_ns,
            0,
            0,
            self.state.epoch_count,
        );
        ControllerDecision {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            actuator: self.config.actuator,
            target_ns: self.target.target_ns,
            observed_ns: observation.observed_ns,
            error_ns: 0,
            p_term_millionths: 0,
            i_term_millionths: 0,
            raw_output_millionths: 0,
            clamped_output_millionths: 0,
            action: ControlAction::Bypassed {
                mode: self.config.mode,
            },
            emergency: false,
            epoch_count: self.state.epoch_count,
            decision_hash: hash,
        }
    }

    fn warmup_decision(&self, observation: &LatencyObservation) -> ControllerDecision {
        let remaining = self.config.warmup_epochs - self.state.epoch_count;
        let hash = compute_decision_hash(
            self.config.actuator,
            self.target.target_ns,
            observation.observed_ns,
            0,
            0,
            self.state.epoch_count,
        );
        ControllerDecision {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            actuator: self.config.actuator,
            target_ns: self.target.target_ns,
            observed_ns: observation.observed_ns,
            error_ns: 0,
            p_term_millionths: 0,
            i_term_millionths: 0,
            raw_output_millionths: 0,
            clamped_output_millionths: 0,
            action: ControlAction::Warmup {
                epochs_remaining: remaining,
            },
            emergency: false,
            epoch_count: self.state.epoch_count,
            decision_hash: hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Feedback policy (multi-controller policy-as-data)
// ---------------------------------------------------------------------------

/// A complete feedback policy describing all controllers for a runtime instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Policy identifier for change tracking.
    pub policy_id: String,
    /// Per-actuator controller configs.
    pub controllers: BTreeMap<String, ControllerConfig>,
    /// Per-stage latency targets.
    pub targets: Vec<LatencyTarget>,
    /// Whether the entire feedback system is enabled.
    pub enabled: bool,
    /// Global emergency threshold multiplier (millionths of target).
    pub emergency_multiplier_millionths: u64,
}

impl Default for FeedbackPolicy {
    fn default() -> Self {
        Self {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            policy_id: "default".into(),
            controllers: BTreeMap::new(),
            targets: Vec::new(),
            enabled: true,
            emergency_multiplier_millionths: 3_000_000, // 3x target
        }
    }
}

impl FeedbackPolicy {
    /// Content hash of the entire policy for diffing and audit.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.as_bytes());
        hasher.update(self.policy_id.as_bytes());
        hasher.update(&(self.controllers.len() as u64).to_le_bytes());
        for (key, config) in &self.controllers {
            hasher.update(key.as_bytes());
            hasher.update(config.content_hash().as_bytes());
        }
        hasher.update(&(self.targets.len() as u64).to_le_bytes());
        for target in &self.targets {
            hasher.update(&target.target_ns.to_le_bytes());
            hasher.update(&target.deadband_ns.to_le_bytes());
            hasher.update(&target.emergency_ns.to_le_bytes());
        }
        hasher.update(&[u8::from(self.enabled)]);
        hasher.update(&self.emergency_multiplier_millionths.to_le_bytes());
        hex_encode(&hasher.finalize())
    }

    /// Validate the policy for internal consistency.
    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if self.controllers.is_empty() && self.enabled {
            return Err(PolicyValidationError::NoControllers);
        }
        for target in &self.targets {
            if target.target_ns == 0 {
                return Err(PolicyValidationError::ZeroTarget {
                    stage: target.stage,
                });
            }
            if target.emergency_ns <= target.target_ns {
                return Err(PolicyValidationError::EmergencyBelowTarget {
                    stage: target.stage,
                    target_ns: target.target_ns,
                    emergency_ns: target.emergency_ns,
                });
            }
            if target.deadband_ns >= target.target_ns {
                return Err(PolicyValidationError::DeadbandExceedsTarget {
                    stage: target.stage,
                    deadband_ns: target.deadband_ns,
                    target_ns: target.target_ns,
                });
            }
        }
        for config in self.controllers.values() {
            if config.kp_millionths == 0 && config.ki_millionths == 0 {
                return Err(PolicyValidationError::ZeroGains {
                    actuator: config.actuator,
                });
            }
            if config.output_clamp_millionths <= 0 {
                return Err(PolicyValidationError::InvalidClamp {
                    actuator: config.actuator,
                });
            }
        }
        Ok(())
    }
}

/// Policy validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyValidationError {
    NoControllers,
    ZeroTarget {
        stage: ExecutionStage,
    },
    EmergencyBelowTarget {
        stage: ExecutionStage,
        target_ns: u64,
        emergency_ns: u64,
    },
    DeadbandExceedsTarget {
        stage: ExecutionStage,
        deadband_ns: u64,
        target_ns: u64,
    },
    ZeroGains {
        actuator: ActuatorKind,
    },
    InvalidClamp {
        actuator: ActuatorKind,
    },
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoControllers => write!(f, "no controllers configured"),
            Self::ZeroTarget { stage } => {
                write!(f, "zero target for stage {stage}")
            }
            Self::EmergencyBelowTarget {
                stage,
                target_ns,
                emergency_ns,
            } => write!(
                f,
                "emergency ({emergency_ns}ns) <= target ({target_ns}ns) for {stage}"
            ),
            Self::DeadbandExceedsTarget {
                stage,
                deadband_ns,
                target_ns,
            } => write!(
                f,
                "deadband ({deadband_ns}ns) >= target ({target_ns}ns) for {stage}"
            ),
            Self::ZeroGains { actuator } => {
                write!(f, "both Kp and Ki are zero for {actuator}")
            }
            Self::InvalidClamp { actuator } => {
                write!(f, "output clamp <= 0 for {actuator}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-controller coordinator
// ---------------------------------------------------------------------------

/// Coordinates multiple PI controllers according to a feedback policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackCoordinator {
    pub policy: FeedbackPolicy,
    pub controllers: BTreeMap<String, PiController>,
    /// History of recent decisions for audit (bounded ring).
    pub decision_log: Vec<ControllerDecision>,
    /// Maximum entries in the decision log.
    pub max_log_entries: usize,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
}

impl FeedbackCoordinator {
    pub fn new(policy: FeedbackPolicy, epoch: SecurityEpoch) -> Self {
        let mut controllers = BTreeMap::new();
        for (key, config) in &policy.controllers {
            // Find matching target for this controller's actuator.
            let target = policy
                .targets
                .iter()
                .find(|t| t.stage == ExecutionStage::ExecutionQuantum)
                .cloned()
                .unwrap_or(LatencyTarget {
                    stage: ExecutionStage::ExecutionQuantum,
                    percentile: LatencyPercentile::P99,
                    target_ns: 10_000_000,
                    deadband_ns: 500_000,
                    emergency_ns: 30_000_000,
                });
            controllers.insert(key.clone(), PiController::new(config.clone(), target));
        }
        Self {
            policy,
            controllers,
            decision_log: Vec::new(),
            max_log_entries: 1000,
            epoch,
        }
    }

    /// Tick all controllers with observations. Returns all decisions.
    pub fn tick_all(&mut self, observations: &[LatencyObservation]) -> Vec<ControllerDecision> {
        if !self.policy.enabled {
            return Vec::new();
        }
        let mut decisions = Vec::new();
        for (key, controller) in &mut self.controllers {
            // Find the best-matching observation for this controller.
            if let Some(obs) = observations
                .iter()
                .find(|o| o.stage == controller.target.stage)
            {
                let decision = controller.tick(obs);
                decisions.push(decision.clone());
                // Add to log with bounded size.
                if self.decision_log.len() >= self.max_log_entries {
                    self.decision_log.remove(0);
                }
                self.decision_log.push(decision);
            }
            let _ = key; // suppress unused warning in loop
        }
        decisions
    }

    /// Get the current health summary.
    pub fn health_summary(&self) -> CoordinatorHealthSummary {
        let total = self.controllers.len() as u64;
        let active = self
            .controllers
            .values()
            .filter(|c| c.config.mode == ControllerMode::Active)
            .count() as u64;
        let in_emergency = self
            .controllers
            .values()
            .filter(|c| c.state.emergency_active)
            .count() as u64;
        let total_emergencies = self
            .controllers
            .values()
            .map(|c| c.state.emergency_count)
            .sum();
        let warmup_remaining = self
            .controllers
            .values()
            .filter(|c| c.state.epoch_count <= c.config.warmup_epochs)
            .count() as u64;

        CoordinatorHealthSummary {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            total_controllers: total,
            active_controllers: active,
            controllers_in_emergency: in_emergency,
            total_emergency_activations: total_emergencies,
            controllers_in_warmup: warmup_remaining,
            policy_hash: self.policy.content_hash(),
            epoch: self.epoch,
        }
    }

    /// Disable all controllers (safe shutdown).
    pub fn disable_all(&mut self) {
        for controller in self.controllers.values_mut() {
            controller.config.mode = ControllerMode::Disabled;
        }
    }

    /// Switch all controllers to observe-only mode.
    pub fn observe_only(&mut self) {
        for controller in self.controllers.values_mut() {
            controller.config.mode = ControllerMode::Observe;
        }
    }

    /// Reset all controller states without changing configs.
    pub fn reset_all(&mut self) {
        for controller in self.controllers.values_mut() {
            controller.reset();
        }
        self.decision_log.clear();
    }

    /// Apply a new policy, preserving controller state where configs match.
    pub fn apply_policy(&mut self, new_policy: FeedbackPolicy) {
        let mut new_controllers = BTreeMap::new();
        for (key, config) in &new_policy.controllers {
            let target = new_policy
                .targets
                .iter()
                .find(|t| t.stage == ExecutionStage::ExecutionQuantum)
                .cloned()
                .unwrap_or(LatencyTarget {
                    stage: ExecutionStage::ExecutionQuantum,
                    percentile: LatencyPercentile::P99,
                    target_ns: 10_000_000,
                    deadband_ns: 500_000,
                    emergency_ns: 30_000_000,
                });
            let mut controller = PiController::new(config.clone(), target);
            // Preserve state if config hash matches.
            if let Some(existing) = self.controllers.get(key) {
                if existing.config.content_hash() == config.content_hash() {
                    controller.state = existing.state.clone();
                }
            }
            new_controllers.insert(key.clone(), controller);
        }
        self.controllers = new_controllers;
        self.policy = new_policy;
    }
}

/// Health summary for operator dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorHealthSummary {
    pub schema_version: String,
    pub total_controllers: u64,
    pub active_controllers: u64,
    pub controllers_in_emergency: u64,
    pub total_emergency_activations: u64,
    pub controllers_in_warmup: u64,
    pub policy_hash: String,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

/// Evidence manifest for the feedback controller subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackEvidenceManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub controller_count: u64,
    pub decision_count: u64,
    pub emergency_count: u64,
    pub policy_hash: String,
    pub manifest_hash: String,
}

impl FeedbackEvidenceManifest {
    pub fn from_coordinator(coordinator: &FeedbackCoordinator) -> Self {
        let emergency_count: u64 = coordinator
            .controllers
            .values()
            .map(|c| c.state.emergency_count)
            .sum();
        let policy_hash = coordinator.policy.content_hash();
        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            FEEDBACK_SCHEMA_VERSION,
            FEEDBACK_BEAD_ID,
            coordinator.controllers.len(),
            coordinator.decision_log.len(),
            emergency_count,
        );
        let manifest_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());
        Self {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            bead_id: FEEDBACK_BEAD_ID.into(),
            controller_count: coordinator.controllers.len() as u64,
            decision_count: coordinator.decision_log.len() as u64,
            emergency_count,
            policy_hash,
            manifest_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Multiply a value by a millionths gain, returning millionths.
fn mul_millionths(value_ns: i64, gain_millionths: i64) -> i64 {
    // (value * gain) / MILLIONTHS
    // Use i128 to prevent overflow.
    let product = (value_ns as i128) * (gain_millionths as i128);
    (product / MILLIONTHS as i128) as i64
}

/// Clamp a value between min and max.
fn clamp(value: i64, min: i64, max: i64) -> i64 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Compute a content-addressed decision hash.
fn compute_decision_hash(
    actuator: ActuatorKind,
    target_ns: u64,
    observed_ns: u64,
    error_ns: i64,
    output_millionths: i64,
    epoch_count: u64,
) -> String {
    let input = format!(
        "{}:{}:{}:{}:{}:{}",
        actuator, target_ns, observed_ns, error_ns, output_millionths, epoch_count,
    );
    hex_encode(ContentHash::compute(input.as_bytes()).as_bytes())
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_target() -> LatencyTarget {
        LatencyTarget::new(
            ExecutionStage::ExecutionQuantum,
            LatencyPercentile::P99,
            5_000_000,  // 5ms target
            200_000,    // 200us deadband
            15_000_000, // 15ms emergency
        )
    }

    fn test_observation(observed_ns: u64) -> LatencyObservation {
        LatencyObservation {
            stage: ExecutionStage::ExecutionQuantum,
            percentile: LatencyPercentile::P99,
            observed_ns,
            sample_count: 100,
            epoch: test_epoch(),
        }
    }

    #[test]
    fn controller_mode_display() {
        assert_eq!(ControllerMode::Active.to_string(), "active");
        assert_eq!(ControllerMode::Observe.to_string(), "observe");
        assert_eq!(ControllerMode::Disabled.to_string(), "disabled");
        assert_eq!(ControllerMode::Fallback.to_string(), "fallback");
    }

    #[test]
    fn actuator_kind_display() {
        assert_eq!(ActuatorKind::AdmissionRate.to_string(), "admission_rate");
        assert_eq!(
            ActuatorKind::WorkerConcurrency.to_string(),
            "worker_concurrency"
        );
        assert_eq!(ActuatorKind::GcBudget.to_string(), "gc_budget");
        assert_eq!(ActuatorKind::BatchSize.to_string(), "batch_size");
        assert_eq!(
            ActuatorKind::CacheEvictionPressure.to_string(),
            "cache_eviction_pressure"
        );
        assert_eq!(ActuatorKind::TierThreshold.to_string(), "tier_threshold");
    }

    #[test]
    fn control_action_display() {
        assert_eq!(
            ControlAction::Increase {
                delta_millionths: 100_000
            }
            .to_string(),
            "increase(100000/1M)"
        );
        assert_eq!(
            ControlAction::Decrease {
                delta_millionths: 200_000
            }
            .to_string(),
            "decrease(200000/1M)"
        );
        assert_eq!(ControlAction::Hold.to_string(), "hold");
        assert_eq!(
            ControlAction::Warmup {
                epochs_remaining: 2
            }
            .to_string(),
            "warmup(2)"
        );
        assert_eq!(
            ControlAction::Bypassed {
                mode: ControllerMode::Disabled
            }
            .to_string(),
            "bypassed(disabled)"
        );
    }

    #[test]
    fn warmup_during_initial_epochs() {
        let config = ControllerConfig {
            warmup_epochs: 3,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        for i in 0..3 {
            let d = ctrl.tick(&test_observation(10_000_000));
            assert!(
                matches!(d.action, ControlAction::Warmup { .. }),
                "epoch {i}"
            );
        }
        // Fourth tick should produce a real decision.
        let d = ctrl.tick(&test_observation(10_000_000));
        assert!(!matches!(d.action, ControlAction::Warmup { .. }));
    }

    #[test]
    fn hold_within_deadband() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let target = test_target(); // 5ms target, 200us deadband
        let mut ctrl = PiController::new(config, target);
        // Observe 5.1ms — within 200us deadband.
        let d = ctrl.tick(&test_observation(5_100_000));
        assert_eq!(d.action, ControlAction::Hold);
    }

    #[test]
    fn decrease_when_over_target() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Observe 8ms — well above 5ms target.
        let d = ctrl.tick(&test_observation(8_000_000));
        assert!(
            matches!(d.action, ControlAction::Decrease { .. }),
            "expected decrease, got {}",
            d.action
        );
        assert!(d.error_ns > 0);
    }

    #[test]
    fn increase_when_under_target() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Observe 2ms — well below 5ms target.
        let d = ctrl.tick(&test_observation(2_000_000));
        assert!(
            matches!(d.action, ControlAction::Increase { .. }),
            "expected increase, got {}",
            d.action
        );
        assert!(d.error_ns < 0);
    }

    #[test]
    fn emergency_triggered_above_threshold() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Observe 20ms — above 15ms emergency.
        let d = ctrl.tick(&test_observation(20_000_000));
        assert!(d.emergency);
        assert!(ctrl.state.emergency_active);
        assert_eq!(ctrl.state.emergency_count, 1);
    }

    #[test]
    fn emergency_cleared_when_below_threshold() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Trigger emergency.
        ctrl.tick(&test_observation(20_000_000));
        assert!(ctrl.state.emergency_active);
        // Recover.
        ctrl.tick(&test_observation(5_000_000));
        assert!(!ctrl.state.emergency_active);
        assert_eq!(ctrl.state.emergency_count, 1); // count doesn't decrease
    }

    #[test]
    fn integrator_anti_windup() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            integrator_clamp_ns: 1_000_000, // ±1ms
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Feed many over-target observations to saturate integrator.
        for _ in 0..100 {
            ctrl.tick(&test_observation(10_000_000));
        }
        // Integrator should be clamped.
        assert!(ctrl.state.integrator_ns <= 1_000_000);
        assert!(ctrl.state.integrator_ns >= -1_000_000);
    }

    #[test]
    fn output_saturation_clamp() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            kp_millionths: 2_000_000, // very high gain
            ki_millionths: 0,
            output_clamp_millionths: 300_000,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        let d = ctrl.tick(&test_observation(100_000_000)); // 100ms, huge error
        assert!(d.clamped_output_millionths <= 300_000);
    }

    #[test]
    fn disabled_mode_bypasses() {
        let config = ControllerConfig {
            mode: ControllerMode::Disabled,
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        let d = ctrl.tick(&test_observation(100_000_000));
        assert!(matches!(
            d.action,
            ControlAction::Bypassed {
                mode: ControllerMode::Disabled
            }
        ));
    }

    #[test]
    fn observe_mode_computes_but_does_not_actuate() {
        let config = ControllerConfig {
            mode: ControllerMode::Observe,
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        let d = ctrl.tick(&test_observation(8_000_000));
        // Observe mode returns Bypassed during tick for observe mode.
        // But error is still computed.
        assert!(matches!(
            d.action,
            ControlAction::Bypassed {
                mode: ControllerMode::Observe,
            }
        ));
    }

    #[test]
    fn decision_hash_deterministic() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl1 = PiController::new(config.clone(), test_target());
        let mut ctrl2 = PiController::new(config, test_target());
        let d1 = ctrl1.tick(&test_observation(8_000_000));
        let d2 = ctrl2.tick(&test_observation(8_000_000));
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn controller_reset_clears_state() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        ctrl.tick(&test_observation(8_000_000));
        ctrl.tick(&test_observation(8_000_000));
        assert!(ctrl.state.epoch_count > 0);
        ctrl.reset();
        assert_eq!(ctrl.state.epoch_count, 0);
        assert_eq!(ctrl.state.integrator_ns, 0);
    }

    #[test]
    fn policy_validation_rejects_no_controllers() {
        let policy = FeedbackPolicy {
            enabled: true,
            ..Default::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::NoControllers)
        ));
    }

    #[test]
    fn policy_validation_rejects_zero_target() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(LatencyTarget {
            stage: ExecutionStage::ExecutionQuantum,
            percentile: LatencyPercentile::P99,
            target_ns: 0,
            deadband_ns: 0,
            emergency_ns: 1,
        });
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::ZeroTarget { .. })
        ));
    }

    #[test]
    fn policy_validation_rejects_emergency_below_target() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(LatencyTarget {
            stage: ExecutionStage::ExecutionQuantum,
            percentile: LatencyPercentile::P99,
            target_ns: 5_000_000,
            deadband_ns: 100_000,
            emergency_ns: 4_000_000, // below target!
        });
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::EmergencyBelowTarget { .. })
        ));
    }

    #[test]
    fn policy_validation_rejects_deadband_exceeds_target() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(LatencyTarget {
            stage: ExecutionStage::ExecutionQuantum,
            percentile: LatencyPercentile::P99,
            target_ns: 5_000_000,
            deadband_ns: 5_000_000, // equals target
            emergency_ns: 10_000_000,
        });
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::DeadbandExceedsTarget { .. })
        ));
    }

    #[test]
    fn policy_validation_rejects_zero_gains() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                kp_millionths: 0,
                ki_millionths: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::ZeroGains { .. })
        ));
    }

    #[test]
    fn policy_content_hash_changes_with_config() {
        let mut p1 = FeedbackPolicy::default();
        p1.controllers
            .insert("test".into(), ControllerConfig::default());
        p1.targets.push(test_target());
        let h1 = p1.content_hash();

        let mut p2 = p1.clone();
        p2.controllers.get_mut("test").unwrap().kp_millionths = 900_000;
        let h2 = p2.content_hash();

        assert_ne!(h1, h2);
    }

    #[test]
    fn coordinator_health_summary() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("admission".into(), ControllerConfig::default());
        policy.controllers.insert(
            "gc".into(),
            ControllerConfig {
                actuator: ActuatorKind::GcBudget,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let coordinator = FeedbackCoordinator::new(policy, test_epoch());
        let summary = coordinator.health_summary();
        assert_eq!(summary.total_controllers, 2);
        assert_eq!(summary.active_controllers, 2);
        assert_eq!(summary.controllers_in_emergency, 0);
        assert_eq!(summary.controllers_in_warmup, 2); // both in warmup
    }

    #[test]
    fn coordinator_tick_all_produces_decisions() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "admission".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        let decisions = coordinator.tick_all(&[test_observation(8_000_000)]);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(
            decisions[0].action,
            ControlAction::Decrease { .. }
        ));
    }

    #[test]
    fn coordinator_disable_all() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        coordinator.disable_all();
        for controller in coordinator.controllers.values() {
            assert_eq!(controller.config.mode, ControllerMode::Disabled);
        }
    }

    #[test]
    fn coordinator_observe_only() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        coordinator.observe_only();
        for controller in coordinator.controllers.values() {
            assert_eq!(controller.config.mode, ControllerMode::Observe);
        }
    }

    #[test]
    fn coordinator_reset_all() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        coordinator.tick_all(&[test_observation(8_000_000)]);
        assert!(!coordinator.decision_log.is_empty());
        coordinator.reset_all();
        assert!(coordinator.decision_log.is_empty());
        for controller in coordinator.controllers.values() {
            assert_eq!(controller.state.epoch_count, 0);
        }
    }

    #[test]
    fn coordinator_apply_policy_preserves_matching_state() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy.clone(), test_epoch());
        coordinator.tick_all(&[test_observation(8_000_000)]);
        let old_epoch_count = coordinator.controllers["test"].state.epoch_count;

        // Apply same policy — state should be preserved.
        coordinator.apply_policy(policy);
        assert_eq!(
            coordinator.controllers["test"].state.epoch_count,
            old_epoch_count
        );
    }

    #[test]
    fn coordinator_apply_policy_resets_on_config_change() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy.clone(), test_epoch());
        coordinator.tick_all(&[test_observation(8_000_000)]);

        // Change config.
        let mut new_policy = policy;
        new_policy
            .controllers
            .get_mut("test")
            .unwrap()
            .kp_millionths = 900_000;
        coordinator.apply_policy(new_policy);
        assert_eq!(coordinator.controllers["test"].state.epoch_count, 0);
    }

    #[test]
    fn evidence_manifest_from_coordinator() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        coordinator.tick_all(&[test_observation(20_000_000)]); // trigger emergency
        let manifest = FeedbackEvidenceManifest::from_coordinator(&coordinator);
        assert_eq!(manifest.bead_id, FEEDBACK_BEAD_ID);
        assert_eq!(manifest.controller_count, 1);
        assert_eq!(manifest.decision_count, 1);
        assert_eq!(manifest.emergency_count, 1);
        assert!(!manifest.manifest_hash.is_empty());
    }

    #[test]
    fn mul_millionths_correctness() {
        // 1.0 * 1.0 = 1.0
        assert_eq!(mul_millionths(MILLIONTHS, MILLIONTHS), MILLIONTHS);
        // 2.0 * 0.5 = 1.0
        assert_eq!(mul_millionths(2 * MILLIONTHS, 500_000), MILLIONTHS);
        // -3.0 * 0.25 = -0.75
        assert_eq!(mul_millionths(-3 * MILLIONTHS, 250_000), -750_000);
        // 0 * anything = 0
        assert_eq!(mul_millionths(0, 999_999), 0);
    }

    #[test]
    fn clamp_correctness() {
        assert_eq!(clamp(5, 0, 10), 5);
        assert_eq!(clamp(-5, 0, 10), 0);
        assert_eq!(clamp(15, 0, 10), 10);
        assert_eq!(clamp(0, 0, 0), 0);
    }

    #[test]
    fn latency_target_construction() {
        let t = LatencyTarget::new(
            ExecutionStage::ExecutionQuantum,
            LatencyPercentile::P99,
            5_000_000,
            200_000,
            15_000_000,
        );
        assert_eq!(t.target_ns, 5_000_000);
        assert_eq!(t.deadband_ns, 200_000);
        assert_eq!(t.emergency_ns, 15_000_000);
    }

    #[test]
    fn config_content_hash_deterministic() {
        let c1 = ControllerConfig::default();
        let c2 = ControllerConfig::default();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn config_content_hash_changes() {
        let c1 = ControllerConfig::default();
        let c2 = ControllerConfig {
            kp_millionths: 900_000,
            ..Default::default()
        };
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn controller_config_serde_roundtrip() {
        let config = ControllerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ControllerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn controller_state_serde_roundtrip() {
        let state = ControllerState {
            integrator_ns: 42,
            epoch_count: 10,
            last_error_ns: -500,
            last_output_millionths: 100_000,
            emergency_active: false,
            emergency_count: 1,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: ControllerState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn controller_decision_serde_roundtrip() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        let d = ctrl.tick(&test_observation(8_000_000));
        let json = serde_json::to_string(&d).unwrap();
        let back: ControllerDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn feedback_policy_serde_roundtrip() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(test_target());
        let json = serde_json::to_string(&policy).unwrap();
        let back: FeedbackPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn policy_validation_passes_for_valid_policy() {
        let mut policy = FeedbackPolicy::default();
        policy
            .controllers
            .insert("test".into(), ControllerConfig::default());
        policy.targets.push(test_target());
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn disabled_policy_skips_tick() {
        let mut policy = FeedbackPolicy::default();
        policy.enabled = false;
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        let decisions = coordinator.tick_all(&[test_observation(8_000_000)]);
        assert!(decisions.is_empty());
    }

    #[test]
    fn coordinator_decision_log_bounded() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                warmup_epochs: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        let mut coordinator = FeedbackCoordinator::new(policy, test_epoch());
        coordinator.max_log_entries = 5;
        for _ in 0..10 {
            coordinator.tick_all(&[test_observation(8_000_000)]);
        }
        assert!(coordinator.decision_log.len() <= 5);
    }

    #[test]
    fn steady_state_convergence() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            kp_millionths: 300_000,
            ki_millionths: 50_000,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // Simulate 20 epochs at 6ms (1ms over target).
        let mut last_output = 0i64;
        for _ in 0..20 {
            let d = ctrl.tick(&test_observation(6_000_000));
            last_output = d.clamped_output_millionths;
        }
        // Output should be positive (requesting decrease) and growing due to integrator.
        assert!(
            last_output > 0,
            "expected positive output, got {last_output}"
        );
    }

    #[test]
    fn pi_controller_serde_roundtrip() {
        let config = ControllerConfig::default();
        let ctrl = PiController::new(config, test_target());
        let json = serde_json::to_string(&ctrl).unwrap();
        let back: PiController = serde_json::from_str(&json).unwrap();
        assert_eq!(ctrl, back);
    }

    #[test]
    fn policy_validation_error_display() {
        let err = PolicyValidationError::NoControllers;
        assert_eq!(err.to_string(), "no controllers configured");
        let err = PolicyValidationError::ZeroTarget {
            stage: ExecutionStage::ExecutionQuantum,
        };
        assert!(err.to_string().contains("zero target"));
    }

    #[test]
    fn coordinator_health_summary_serde_roundtrip() {
        let summary = CoordinatorHealthSummary {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            total_controllers: 2,
            active_controllers: 1,
            controllers_in_emergency: 0,
            total_emergency_activations: 3,
            controllers_in_warmup: 1,
            policy_hash: "abc".into(),
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: CoordinatorHealthSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn evidence_manifest_serde_roundtrip() {
        let manifest = FeedbackEvidenceManifest {
            schema_version: FEEDBACK_SCHEMA_VERSION.into(),
            bead_id: FEEDBACK_BEAD_ID.into(),
            controller_count: 3,
            decision_count: 100,
            emergency_count: 2,
            policy_hash: "hash123".into(),
            manifest_hash: "mhash456".into(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: FeedbackEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn fallback_mode_bypasses() {
        let config = ControllerConfig {
            mode: ControllerMode::Fallback,
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        let d = ctrl.tick(&test_observation(100_000_000));
        assert!(matches!(
            d.action,
            ControlAction::Bypassed {
                mode: ControllerMode::Fallback
            }
        ));
    }

    #[test]
    fn policy_validation_rejects_invalid_clamp() {
        let mut policy = FeedbackPolicy::default();
        policy.controllers.insert(
            "test".into(),
            ControllerConfig {
                output_clamp_millionths: 0,
                ..Default::default()
            },
        );
        policy.targets.push(test_target());
        assert!(matches!(
            policy.validate(),
            Err(PolicyValidationError::InvalidClamp { .. })
        ));
    }

    #[test]
    fn multiple_emergency_activations_counted() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            ..Default::default()
        };
        let mut ctrl = PiController::new(config, test_target());
        // First emergency.
        ctrl.tick(&test_observation(20_000_000));
        assert_eq!(ctrl.state.emergency_count, 1);
        // Recovery.
        ctrl.tick(&test_observation(5_000_000));
        // Second emergency.
        ctrl.tick(&test_observation(20_000_000));
        assert_eq!(ctrl.state.emergency_count, 2);
    }

    #[test]
    fn deadband_override_takes_precedence() {
        let config = ControllerConfig {
            warmup_epochs: 0,
            deadband_override_ns: Some(1_000_000), // 1ms override
            ..Default::default()
        };
        let target = LatencyTarget::new(
            ExecutionStage::ExecutionQuantum,
            LatencyPercentile::P99,
            5_000_000,
            100_000, // 100us original deadband
            15_000_000,
        );
        let mut ctrl = PiController::new(config, target);
        // 5.5ms — outside original 100us deadband but inside 1ms override.
        let d = ctrl.tick(&test_observation(5_500_000));
        assert_eq!(d.action, ControlAction::Hold);
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }
}
