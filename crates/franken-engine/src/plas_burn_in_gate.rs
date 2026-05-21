//! Deterministic burn-in promotion gate for PLAS synthesized policies.
//!
//! Enforces shadow success-rate, false-deny envelope, and rollback-proof
//! artifact checks before allowing auto-enforcement promotion.
//!
//! Plan reference: Section 10.15 item 13 (`bd-24ie`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_witness::RollbackToken;
use crate::hash_tiers::ContentHash;

const PLAS_BURN_IN_COMPONENT: &str = "plas_burn_in_gate";

/// Extension risk class used to select default threshold strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRiskClass {
    Low,
    Standard,
    High,
}

impl ExtensionRiskClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Standard => "standard",
            Self::High => "high",
        }
    }
}

impl fmt::Display for ExtensionRiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Burn-in thresholds that must be satisfied for promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInThresholds {
    /// Minimum shadow success rate (millionths).
    pub min_shadow_success_millionths: u64,
    /// Maximum false-deny rate (millionths).
    pub max_false_deny_millionths: u64,
    /// Minimum shadow burn-in duration in nanoseconds.
    pub min_shadow_duration_ns: u64,
    /// Minimum number of shadow observations before gate evaluation.
    pub min_shadow_observations: u64,
}

impl BurnInThresholds {
    /// Default strictness by extension risk class.
    pub fn for_risk_class(risk_class: ExtensionRiskClass) -> Self {
        match risk_class {
            ExtensionRiskClass::Low => Self {
                min_shadow_success_millionths: 992_000,
                max_false_deny_millionths: 8_000,
                min_shadow_duration_ns: 60_000_000_000,
                min_shadow_observations: 100,
            },
            ExtensionRiskClass::Standard => Self {
                min_shadow_success_millionths: 995_000,
                max_false_deny_millionths: 5_000,
                min_shadow_duration_ns: 180_000_000_000,
                min_shadow_observations: 250,
            },
            ExtensionRiskClass::High => Self {
                min_shadow_success_millionths: 998_000,
                max_false_deny_millionths: 2_000,
                min_shadow_duration_ns: 300_000_000_000,
                min_shadow_observations: 500,
            },
        }
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.min_shadow_success_millionths > 1_000_000 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_success_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.max_false_deny_millionths > 1_000_000 {
            return Err(BurnInError::InvalidConfig {
                detail: "max_false_deny_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.min_shadow_duration_ns == 0 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_duration_ns must be > 0".to_string(),
            });
        }
        if self.min_shadow_observations == 0 {
            return Err(BurnInError::InvalidConfig {
                detail: "min_shadow_observations must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

/// Shadow-mode lifecycle for a synthesized policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnInLifecycleState {
    ShadowStart,
    ShadowEvaluation,
    PromotionGate,
    AutoEnforcement,
    Rejection,
}

impl BurnInLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShadowStart => "shadow_start",
            Self::ShadowEvaluation => "shadow_evaluation",
            Self::PromotionGate => "promotion_gate",
            Self::AutoEnforcement => "auto_enforcement",
            Self::Rejection => "rejection",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::AutoEnforcement | Self::Rejection)
    }
}

impl fmt::Display for BurnInLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure taxonomy for burn-in decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnInFailureCode {
    EarlyTerminationFalseDeny,
    InsufficientShadowDuration,
    InsufficientShadowObservations,
    ShadowSuccessRateBelowThreshold,
    FalseDenyEnvelopeExceeded,
    RollbackProofArtifactsMissing,
}

impl BurnInFailureCode {
    pub fn error_code(self) -> &'static str {
        match self {
            Self::EarlyTerminationFalseDeny => "early_termination_false_deny",
            Self::InsufficientShadowDuration => "insufficient_shadow_duration",
            Self::InsufficientShadowObservations => "insufficient_shadow_observations",
            Self::ShadowSuccessRateBelowThreshold => "shadow_success_rate_below_threshold",
            Self::FalseDenyEnvelopeExceeded => "false_deny_envelope_exceeded",
            Self::RollbackProofArtifactsMissing => "rollback_proof_artifacts_missing",
        }
    }
}

impl fmt::Display for BurnInFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error_code())
    }
}

/// Rollback artifacts required for safe fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RollbackProofArtifacts {
    /// Whether the rollback command has been exercised successfully.
    pub rollback_command_tested: bool,
    /// Reference to a previous policy snapshot artifact.
    pub previous_policy_snapshot_ref: Option<String>,
    /// Whether the transition receipt is signed and verified.
    pub transition_receipt_signed: bool,
    /// Reference to transition receipt artifact.
    pub transition_receipt_ref: Option<String>,
    /// Deterministic rollback token linking to prior witness version.
    pub rollback_token: Option<RollbackToken>,
}

impl RollbackProofArtifacts {
    fn normalize(&mut self) {
        self.previous_policy_snapshot_ref = self
            .previous_policy_snapshot_ref
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.transition_receipt_ref = self
            .transition_receipt_ref
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    }

    pub fn is_complete(&self) -> bool {
        self.rollback_command_tested
            && self.transition_receipt_signed
            && self.previous_policy_snapshot_ref.is_some()
            && self.transition_receipt_ref.is_some()
            && self.rollback_token.is_some()
    }
}

/// One shadow observation used in burn-in evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowObservation {
    pub observation_id: String,
    pub timestamp_ns: u64,
    pub success: bool,
    pub false_deny: bool,
}

impl ShadowObservation {
    fn normalize(&mut self) {
        self.observation_id = self.observation_id.trim().to_string();
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.observation_id.is_empty() {
            return Err(BurnInError::InvalidObservation {
                detail: "observation_id must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Aggregated shadow metrics used by promotion decision logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInMetrics {
    pub started_at_ns: u64,
    pub latest_timestamp_ns: u64,
    pub total_observations: u64,
    pub successful_observations: u64,
    pub false_denies: u64,
}

impl BurnInMetrics {
    fn new(started_at_ns: u64) -> Self {
        Self {
            started_at_ns,
            latest_timestamp_ns: started_at_ns,
            total_observations: 0,
            successful_observations: 0,
            false_denies: 0,
        }
    }

    pub fn elapsed_ns(&self) -> u64 {
        self.latest_timestamp_ns.saturating_sub(self.started_at_ns)
    }

    pub fn shadow_success_rate_millionths(&self) -> u64 {
        if self.total_observations == 0 {
            return 0;
        }
        self.successful_observations
            .saturating_mul(1_000_000)
            .saturating_div(self.total_observations)
    }

    pub fn false_deny_rate_millionths(&self) -> u64 {
        if self.total_observations == 0 {
            return 0;
        }
        self.false_denies
            .saturating_mul(1_000_000)
            .saturating_div(self.total_observations)
    }
}

/// Configuration for a burn-in session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInSessionConfig {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub risk_class: ExtensionRiskClass,
    pub thresholds: BurnInThresholds,
    pub shadow_start_timestamp_ns: u64,
}

impl BurnInSessionConfig {
    fn normalize(&mut self) {
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.extension_id = self.extension_id.trim().to_string();
    }

    fn validate(&self) -> Result<(), BurnInError> {
        if self.trace_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.extension_id.is_empty() {
            return Err(BurnInError::InvalidConfig {
                detail: "extension_id must not be empty".to_string(),
            });
        }
        self.thresholds.validate()?;
        Ok(())
    }
}

/// Structured log event with stable keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub lifecycle_state: BurnInLifecycleState,
}

/// Deterministic decision artifact produced on promotion-gate or early termination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInDecisionArtifact {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_id: String,
    pub risk_class: ExtensionRiskClass,
    pub lifecycle_state: BurnInLifecycleState,
    pub outcome: String,
    pub failure_codes: Vec<BurnInFailureCode>,
    pub metrics: BurnInMetrics,
    pub thresholds: BurnInThresholds,
    pub rollback_artifacts_verified: bool,
    pub diagnostic_report: Option<String>,
    pub decision_hash: ContentHash,
}

/// Snapshot for PLAS benchmark/governance scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInScorecardMetrics {
    pub shadow_success_rate_millionths: u64,
    pub false_deny_rate_millionths: u64,
    pub rollback_artifacts_verified: bool,
    pub lifecycle_state: BurnInLifecycleState,
}

/// Burn-in gate errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BurnInError {
    InvalidConfig {
        detail: String,
    },
    InvalidObservation {
        detail: String,
    },
    InvalidTransition {
        from: BurnInLifecycleState,
        to: BurnInLifecycleState,
    },
    NonMonotonicTimestamp {
        previous_ns: u64,
        observed_ns: u64,
    },
}

impl fmt::Display for BurnInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { detail } => write!(f, "invalid burn-in config: {detail}"),
            Self::InvalidObservation { detail } => {
                write!(f, "invalid burn-in observation: {detail}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid burn-in lifecycle transition: {from} -> {to}")
            }
            Self::NonMonotonicTimestamp {
                previous_ns,
                observed_ns,
            } => {
                write!(
                    f,
                    "non-monotonic timestamp: previous={previous_ns}, observed={observed_ns}"
                )
            }
        }
    }
}

impl std::error::Error for BurnInError {}

/// Stateful deterministic burn-in evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnInSession {
    config: BurnInSessionConfig,
    rollback_artifacts: RollbackProofArtifacts,
    lifecycle_state: BurnInLifecycleState,
    metrics: BurnInMetrics,
    logs: Vec<BurnInLogEvent>,
    decision_artifact: Option<BurnInDecisionArtifact>,
}

impl BurnInSession {
    /// Create a new burn-in session at `shadow_start`.
    pub fn new(
        mut config: BurnInSessionConfig,
        mut rollback_artifacts: RollbackProofArtifacts,
    ) -> Result<Self, BurnInError> {
        config.normalize();
        config.validate()?;
        rollback_artifacts.normalize();

        let initial_state = BurnInLifecycleState::ShadowStart;
        let mut session = Self {
            metrics: BurnInMetrics::new(config.shadow_start_timestamp_ns),
            config,
            rollback_artifacts,
            lifecycle_state: initial_state,
            logs: Vec::new(),
            decision_artifact: None,
        };
        session.push_log("shadow_start", "pass", None, initial_state);
        Ok(session)
    }

    /// Transition from `shadow_start` to `shadow_evaluation`.
    pub fn begin_shadow_evaluation(&mut self) -> Result<(), BurnInError> {
        self.transition_to(BurnInLifecycleState::ShadowEvaluation)?;
        self.push_log(
            "shadow_evaluation",
            "pass",
            None,
            BurnInLifecycleState::ShadowEvaluation,
        );
        Ok(())
    }

    /// Record one shadow observation.
    ///
    /// Returns a decision artifact when early termination triggers.
    pub fn record_shadow_observation(
        &mut self,
        mut observation: ShadowObservation,
    ) -> Result<Option<BurnInDecisionArtifact>, BurnInError> {
        if self.lifecycle_state != BurnInLifecycleState::ShadowEvaluation {
            return Err(BurnInError::InvalidTransition {
                from: self.lifecycle_state,
                to: BurnInLifecycleState::ShadowEvaluation,
            });
        }

        observation.normalize();
        observation.validate()?;

        if observation.timestamp_ns < self.metrics.latest_timestamp_ns {
            return Err(BurnInError::NonMonotonicTimestamp {
                previous_ns: self.metrics.latest_timestamp_ns,
                observed_ns: observation.timestamp_ns,
            });
        }

        self.metrics.latest_timestamp_ns = observation.timestamp_ns;
        self.metrics.total_observations = self.metrics.total_observations.saturating_add(1);
        if observation.success {
            self.metrics.successful_observations =
                self.metrics.successful_observations.saturating_add(1);
        }
        if observation.false_deny {
            self.metrics.false_denies = self.metrics.false_denies.saturating_add(1);
        }

        self.push_log(
            "shadow_observation_recorded",
            "pass",
            None,
            BurnInLifecycleState::ShadowEvaluation,
        );

        if self.metrics.false_deny_rate_millionths()
            > self.config.thresholds.max_false_deny_millionths
        {
            self.transition_to(BurnInLifecycleState::Rejection)?;
            let failure_codes = vec![BurnInFailureCode::EarlyTerminationFalseDeny];
            let artifact = self.build_decision_artifact(
                BurnInLifecycleState::Rejection,
                &failure_codes,
                Some(
                    "false-deny envelope exceeded during shadow evaluation; early termination"
                        .to_string(),
                ),
            );
            self.decision_artifact = Some(artifact.clone());
            self.push_log(
                "shadow_evaluation",
                "fail",
                Some(BurnInFailureCode::EarlyTerminationFalseDeny),
                BurnInLifecycleState::Rejection,
            );
            return Ok(Some(artifact));
        }

        Ok(None)
    }

    /// Execute the promotion gate and transition to terminal state.
    pub fn evaluate_promotion_gate(
        &mut self,
        evaluation_timestamp_ns: u64,
    ) -> Result<BurnInDecisionArtifact, BurnInError> {
        if self.lifecycle_state != BurnInLifecycleState::ShadowEvaluation {
            return Err(BurnInError::InvalidTransition {
                from: self.lifecycle_state,
                to: BurnInLifecycleState::PromotionGate,
            });
        }
        if evaluation_timestamp_ns < self.metrics.latest_timestamp_ns {
            return Err(BurnInError::NonMonotonicTimestamp {
                previous_ns: self.metrics.latest_timestamp_ns,
                observed_ns: evaluation_timestamp_ns,
            });
        }

        self.metrics.latest_timestamp_ns = evaluation_timestamp_ns;
        self.transition_to(BurnInLifecycleState::PromotionGate)?;

        let mut failure_codes = Vec::new();
        if self.metrics.elapsed_ns() < self.config.thresholds.min_shadow_duration_ns {
            failure_codes.push(BurnInFailureCode::InsufficientShadowDuration);
        }
        if self.metrics.total_observations < self.config.thresholds.min_shadow_observations {
            failure_codes.push(BurnInFailureCode::InsufficientShadowObservations);
        }
        if self.metrics.shadow_success_rate_millionths()
            < self.config.thresholds.min_shadow_success_millionths
        {
            failure_codes.push(BurnInFailureCode::ShadowSuccessRateBelowThreshold);
        }
        if self.metrics.false_deny_rate_millionths()
            > self.config.thresholds.max_false_deny_millionths
        {
            failure_codes.push(BurnInFailureCode::FalseDenyEnvelopeExceeded);
        }
        if !self.rollback_artifacts.is_complete() {
            failure_codes.push(BurnInFailureCode::RollbackProofArtifactsMissing);
        }
        failure_codes.sort();
        failure_codes.dedup();

        let final_state = if failure_codes.is_empty() {
            BurnInLifecycleState::AutoEnforcement
        } else {
            BurnInLifecycleState::Rejection
        };
        self.transition_to(final_state)?;

        let artifact = self.build_decision_artifact(final_state, &failure_codes, None);
        self.decision_artifact = Some(artifact.clone());

        self.push_log(
            "promotion_gate",
            if failure_codes.is_empty() {
                "pass"
            } else {
                "fail"
            },
            failure_codes.first().copied(),
            final_state,
        );

        Ok(artifact)
    }

    pub fn lifecycle_state(&self) -> BurnInLifecycleState {
        self.lifecycle_state
    }

    pub fn metrics(&self) -> &BurnInMetrics {
        &self.metrics
    }

    pub fn logs(&self) -> &[BurnInLogEvent] {
        &self.logs
    }

    pub fn decision_artifact(&self) -> Option<&BurnInDecisionArtifact> {
        self.decision_artifact.as_ref()
    }

    pub fn scorecard_metrics(&self) -> BurnInScorecardMetrics {
        BurnInScorecardMetrics {
            shadow_success_rate_millionths: self.metrics.shadow_success_rate_millionths(),
            false_deny_rate_millionths: self.metrics.false_deny_rate_millionths(),
            rollback_artifacts_verified: self.rollback_artifacts.is_complete(),
            lifecycle_state: self.lifecycle_state,
        }
    }

    fn transition_to(&mut self, to: BurnInLifecycleState) -> Result<(), BurnInError> {
        let from = self.lifecycle_state;
        let valid = matches!(
            (from, to),
            (
                BurnInLifecycleState::ShadowStart,
                BurnInLifecycleState::ShadowEvaluation
            ) | (
                BurnInLifecycleState::ShadowEvaluation,
                BurnInLifecycleState::PromotionGate
            ) | (
                BurnInLifecycleState::ShadowEvaluation,
                BurnInLifecycleState::Rejection
            ) | (
                BurnInLifecycleState::PromotionGate,
                BurnInLifecycleState::AutoEnforcement
            ) | (
                BurnInLifecycleState::PromotionGate,
                BurnInLifecycleState::Rejection
            )
        );
        if !valid {
            return Err(BurnInError::InvalidTransition { from, to });
        }
        self.lifecycle_state = to;
        Ok(())
    }

    fn build_decision_artifact(
        &self,
        lifecycle_state: BurnInLifecycleState,
        failure_codes: &[BurnInFailureCode],
        diagnostic_report: Option<String>,
    ) -> BurnInDecisionArtifact {
        let outcome = if failure_codes.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        };

        let mut unsigned = Vec::new();
        unsigned.extend_from_slice(self.config.trace_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.decision_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.policy_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(self.config.extension_id.as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(lifecycle_state.as_str().as_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(outcome.as_bytes());
        unsigned.push(b'|');
        for code in failure_codes {
            unsigned.extend_from_slice(code.error_code().as_bytes());
            unsigned.push(b',');
        }
        unsigned.push(b'|');
        unsigned.extend_from_slice(&self.metrics.total_observations.to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.successful_observations.to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.false_denies.to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(&self.metrics.shadow_success_rate_millionths().to_be_bytes());
        unsigned.extend_from_slice(&self.metrics.false_deny_rate_millionths().to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(
            &self
                .config
                .thresholds
                .min_shadow_success_millionths
                .to_be_bytes(),
        );
        unsigned.extend_from_slice(
            &self
                .config
                .thresholds
                .max_false_deny_millionths
                .to_be_bytes(),
        );
        unsigned.extend_from_slice(&self.config.thresholds.min_shadow_duration_ns.to_be_bytes());
        unsigned.extend_from_slice(&self.config.thresholds.min_shadow_observations.to_be_bytes());
        unsigned.push(b'|');
        unsigned.extend_from_slice(if self.rollback_artifacts.is_complete() {
            b"rollback_complete"
        } else {
            b"rollback_incomplete"
        });
        if let Some(report) = &diagnostic_report {
            unsigned.push(b'|');
            unsigned.extend_from_slice(report.as_bytes());
        }

        BurnInDecisionArtifact {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            extension_id: self.config.extension_id.clone(),
            risk_class: self.config.risk_class,
            lifecycle_state,
            outcome,
            failure_codes: failure_codes.to_vec(),
            metrics: self.metrics.clone(),
            thresholds: self.config.thresholds.clone(),
            rollback_artifacts_verified: self.rollback_artifacts.is_complete(),
            diagnostic_report,
            decision_hash: ContentHash::compute(&unsigned),
        }
    }

    fn push_log(
        &mut self,
        event: &str,
        outcome: &str,
        error_code: Option<BurnInFailureCode>,
        lifecycle_state: BurnInLifecycleState,
    ) {
        self.logs.push(BurnInLogEvent {
            trace_id: self.config.trace_id.clone(),
            decision_id: self.config.decision_id.clone(),
            policy_id: self.config.policy_id.clone(),
            component: PLAS_BURN_IN_COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(|code| code.error_code().to_string()),
            lifecycle_state,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::SecurityEpoch;

    // ── helpers ──────────────────────────────────────────────────────

    fn make_config() -> BurnInSessionConfig {
        BurnInSessionConfig {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            extension_id: "e1".to_string(),
            risk_class: ExtensionRiskClass::Standard,
            thresholds: BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard),
            shadow_start_timestamp_ns: 1_000_000,
        }
    }

    fn complete_rollback_artifacts() -> RollbackProofArtifacts {
        RollbackProofArtifacts {
            rollback_command_tested: true,
            previous_policy_snapshot_ref: Some("snap-1".to_string()),
            transition_receipt_signed: true,
            transition_receipt_ref: Some("receipt-1".to_string()),
            rollback_token: Some(RollbackToken {
                previous_witness_hash: ContentHash::compute(b"prev"),
                previous_witness_id: Some(crate::engine_object_id::EngineObjectId([1u8; 32])),
                created_epoch: SecurityEpoch::from_raw(1),
                sequence: 0,
            }),
        }
    }

    fn success_observation(id: &str, ts: u64) -> ShadowObservation {
        ShadowObservation {
            observation_id: id.to_string(),
            timestamp_ns: ts,
            success: true,
            false_deny: false,
        }
    }

    fn false_deny_observation(id: &str, ts: u64) -> ShadowObservation {
        ShadowObservation {
            observation_id: id.to_string(),
            timestamp_ns: ts,
            success: false,
            false_deny: true,
        }
    }

    // Build a session ready for promotion with enough passing observations
    fn session_ready_for_promotion() -> BurnInSession {
        let mut config = make_config();
        // Use low-risk thresholds for simpler test setup
        config.risk_class = ExtensionRiskClass::Low;
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 100_000,
            min_shadow_duration_ns: 100,
            min_shadow_observations: 5,
        };
        config.shadow_start_timestamp_ns = 1_000;

        let mut session = BurnInSession::new(config, complete_rollback_artifacts())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");

        for i in 0..10 {
            let obs = success_observation(&format!("obs-{i}"), 2_000 + i * 100);
            session
                .record_shadow_observation(obs)
                .expect("serde deserialization should succeed");
        }
        session
    }

    // ── ExtensionRiskClass ──────────────────────────────────────────

    #[test]
    fn risk_class_as_str() {
        assert_eq!(ExtensionRiskClass::Low.as_str(), "low");
        assert_eq!(ExtensionRiskClass::Standard.as_str(), "standard");
        assert_eq!(ExtensionRiskClass::High.as_str(), "high");
    }

    #[test]
    fn risk_class_display() {
        assert_eq!(format!("{}", ExtensionRiskClass::High), "high");
    }

    #[test]
    fn risk_class_ordering() {
        assert!(ExtensionRiskClass::Low < ExtensionRiskClass::Standard);
        assert!(ExtensionRiskClass::Standard < ExtensionRiskClass::High);
    }

    #[test]
    fn risk_class_serde_roundtrip() {
        for variant in [
            ExtensionRiskClass::Low,
            ExtensionRiskClass::Standard,
            ExtensionRiskClass::High,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: ExtensionRiskClass =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    // ── BurnInThresholds ────────────────────────────────────────────

    #[test]
    fn thresholds_for_risk_class_low() {
        let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::Low);
        assert_eq!(t.min_shadow_success_millionths, 992_000);
        assert_eq!(t.max_false_deny_millionths, 8_000);
        assert_eq!(t.min_shadow_observations, 100);
    }

    #[test]
    fn thresholds_for_risk_class_standard() {
        let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard);
        assert_eq!(t.min_shadow_success_millionths, 995_000);
        assert_eq!(t.max_false_deny_millionths, 5_000);
        assert_eq!(t.min_shadow_observations, 250);
    }

    #[test]
    fn thresholds_for_risk_class_high() {
        let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);
        assert_eq!(t.min_shadow_success_millionths, 998_000);
        assert_eq!(t.max_false_deny_millionths, 2_000);
        assert_eq!(t.min_shadow_observations, 500);
    }

    #[test]
    fn thresholds_validate_success_too_high() {
        let t = BurnInThresholds {
            min_shadow_success_millionths: 1_000_001,
            max_false_deny_millionths: 5_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 1,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_false_deny_too_high() {
        let t = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 1_000_001,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 1,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_zero_duration() {
        let t = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 5_000,
            min_shadow_duration_ns: 0,
            min_shadow_observations: 1,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_zero_observations() {
        let t = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 5_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 0,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);
        let json = serde_json::to_string(&t).expect("serialize derived Serialize");
        let back: BurnInThresholds =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(t, back);
    }

    // ── BurnInLifecycleState ────────────────────────────────────────

    #[test]
    fn lifecycle_as_str() {
        assert_eq!(BurnInLifecycleState::ShadowStart.as_str(), "shadow_start");
        assert_eq!(
            BurnInLifecycleState::ShadowEvaluation.as_str(),
            "shadow_evaluation"
        );
        assert_eq!(
            BurnInLifecycleState::PromotionGate.as_str(),
            "promotion_gate"
        );
        assert_eq!(
            BurnInLifecycleState::AutoEnforcement.as_str(),
            "auto_enforcement"
        );
        assert_eq!(BurnInLifecycleState::Rejection.as_str(), "rejection");
    }

    #[test]
    fn lifecycle_is_terminal() {
        assert!(!BurnInLifecycleState::ShadowStart.is_terminal());
        assert!(!BurnInLifecycleState::ShadowEvaluation.is_terminal());
        assert!(!BurnInLifecycleState::PromotionGate.is_terminal());
        assert!(BurnInLifecycleState::AutoEnforcement.is_terminal());
        assert!(BurnInLifecycleState::Rejection.is_terminal());
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(
            format!("{}", BurnInLifecycleState::PromotionGate),
            "promotion_gate"
        );
    }

    #[test]
    fn lifecycle_serde_roundtrip() {
        for variant in [
            BurnInLifecycleState::ShadowStart,
            BurnInLifecycleState::ShadowEvaluation,
            BurnInLifecycleState::PromotionGate,
            BurnInLifecycleState::AutoEnforcement,
            BurnInLifecycleState::Rejection,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: BurnInLifecycleState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    // ── BurnInFailureCode ───────────────────────────────────────────

    #[test]
    fn failure_code_error_code() {
        assert_eq!(
            BurnInFailureCode::EarlyTerminationFalseDeny.error_code(),
            "early_termination_false_deny"
        );
        assert_eq!(
            BurnInFailureCode::InsufficientShadowDuration.error_code(),
            "insufficient_shadow_duration"
        );
        assert_eq!(
            BurnInFailureCode::RollbackProofArtifactsMissing.error_code(),
            "rollback_proof_artifacts_missing"
        );
    }

    #[test]
    fn failure_code_display() {
        for variant in [
            BurnInFailureCode::EarlyTerminationFalseDeny,
            BurnInFailureCode::InsufficientShadowDuration,
            BurnInFailureCode::InsufficientShadowObservations,
            BurnInFailureCode::ShadowSuccessRateBelowThreshold,
            BurnInFailureCode::FalseDenyEnvelopeExceeded,
            BurnInFailureCode::RollbackProofArtifactsMissing,
        ] {
            assert_eq!(format!("{variant}"), variant.error_code());
        }
    }

    #[test]
    fn failure_code_serde_roundtrip() {
        for variant in [
            BurnInFailureCode::EarlyTerminationFalseDeny,
            BurnInFailureCode::InsufficientShadowDuration,
            BurnInFailureCode::InsufficientShadowObservations,
            BurnInFailureCode::ShadowSuccessRateBelowThreshold,
            BurnInFailureCode::FalseDenyEnvelopeExceeded,
            BurnInFailureCode::RollbackProofArtifactsMissing,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            let back: BurnInFailureCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(variant, back);
        }
    }

    // ── RollbackProofArtifacts ──────────────────────────────────────

    #[test]
    fn rollback_artifacts_default_incomplete() {
        let a = RollbackProofArtifacts::default();
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_complete() {
        let a = complete_rollback_artifacts();
        assert!(a.is_complete());
    }

    #[test]
    fn rollback_artifacts_missing_command_tested() {
        let mut a = complete_rollback_artifacts();
        a.rollback_command_tested = false;
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_missing_snapshot_ref() {
        let mut a = complete_rollback_artifacts();
        a.previous_policy_snapshot_ref = None;
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_missing_receipt_signed() {
        let mut a = complete_rollback_artifacts();
        a.transition_receipt_signed = false;
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_missing_receipt_ref() {
        let mut a = complete_rollback_artifacts();
        a.transition_receipt_ref = None;
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_missing_token() {
        let mut a = complete_rollback_artifacts();
        a.rollback_token = None;
        assert!(!a.is_complete());
    }

    #[test]
    fn rollback_artifacts_normalize_trims() {
        let mut a = RollbackProofArtifacts {
            rollback_command_tested: true,
            previous_policy_snapshot_ref: Some("  snap  ".to_string()),
            transition_receipt_signed: true,
            transition_receipt_ref: Some("  ".to_string()),
            rollback_token: None,
        };
        a.normalize();
        assert_eq!(a.previous_policy_snapshot_ref.as_deref(), Some("snap"));
        assert!(a.transition_receipt_ref.is_none()); // empty after trim
    }

    #[test]
    fn rollback_artifacts_serde_roundtrip() {
        let a = complete_rollback_artifacts();
        let json = serde_json::to_string(&a).expect("serialize derived Serialize");
        let back: RollbackProofArtifacts =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(a, back);
    }

    // ── ShadowObservation ───────────────────────────────────────────

    #[test]
    fn shadow_observation_validate_empty_id() {
        let o = ShadowObservation {
            observation_id: "".to_string(),
            timestamp_ns: 100,
            success: true,
            false_deny: false,
        };
        assert!(o.validate().is_err());
    }

    #[test]
    fn shadow_observation_normalize_trims() {
        let mut o = ShadowObservation {
            observation_id: "  obs-1  ".to_string(),
            timestamp_ns: 100,
            success: true,
            false_deny: false,
        };
        o.normalize();
        assert_eq!(o.observation_id, "obs-1");
    }

    #[test]
    fn shadow_observation_serde_roundtrip() {
        let o = success_observation("obs-1", 100);
        let json = serde_json::to_string(&o).expect("serialize derived Serialize");
        let back: ShadowObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(o, back);
    }

    // ── BurnInMetrics ───────────────────────────────────────────────

    #[test]
    fn metrics_new_defaults() {
        let m = BurnInMetrics::new(1000);
        assert_eq!(m.started_at_ns, 1000);
        assert_eq!(m.latest_timestamp_ns, 1000);
        assert_eq!(m.total_observations, 0);
        assert_eq!(m.elapsed_ns(), 0);
    }

    #[test]
    fn metrics_elapsed() {
        let m = BurnInMetrics {
            started_at_ns: 100,
            latest_timestamp_ns: 500,
            total_observations: 0,
            successful_observations: 0,
            false_denies: 0,
        };
        assert_eq!(m.elapsed_ns(), 400);
    }

    #[test]
    fn metrics_shadow_success_rate_zero_obs() {
        let m = BurnInMetrics::new(0);
        assert_eq!(m.shadow_success_rate_millionths(), 0);
    }

    #[test]
    fn metrics_shadow_success_rate_all_success() {
        let m = BurnInMetrics {
            started_at_ns: 0,
            latest_timestamp_ns: 0,
            total_observations: 100,
            successful_observations: 100,
            false_denies: 0,
        };
        assert_eq!(m.shadow_success_rate_millionths(), 1_000_000);
    }

    #[test]
    fn metrics_shadow_success_rate_half() {
        let m = BurnInMetrics {
            started_at_ns: 0,
            latest_timestamp_ns: 0,
            total_observations: 100,
            successful_observations: 50,
            false_denies: 0,
        };
        assert_eq!(m.shadow_success_rate_millionths(), 500_000);
    }

    #[test]
    fn metrics_false_deny_rate_zero_obs() {
        let m = BurnInMetrics::new(0);
        assert_eq!(m.false_deny_rate_millionths(), 0);
    }

    #[test]
    fn metrics_false_deny_rate_some() {
        let m = BurnInMetrics {
            started_at_ns: 0,
            latest_timestamp_ns: 0,
            total_observations: 1000,
            successful_observations: 990,
            false_denies: 10,
        };
        assert_eq!(m.false_deny_rate_millionths(), 10_000);
    }

    #[test]
    fn metrics_serde_roundtrip() {
        let m = BurnInMetrics {
            started_at_ns: 100,
            latest_timestamp_ns: 500,
            total_observations: 10,
            successful_observations: 9,
            false_denies: 1,
        };
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let back: BurnInMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, back);
    }

    // ── BurnInError ─────────────────────────────────────────────────

    #[test]
    fn error_display_invalid_config() {
        let err = BurnInError::InvalidConfig {
            detail: "bad".to_string(),
        };
        assert_eq!(format!("{err}"), "invalid burn-in config: bad");
    }

    #[test]
    fn error_display_invalid_observation() {
        let err = BurnInError::InvalidObservation {
            detail: "missing id".to_string(),
        };
        assert!(format!("{err}").contains("missing id"));
    }

    #[test]
    fn error_display_invalid_transition() {
        let err = BurnInError::InvalidTransition {
            from: BurnInLifecycleState::ShadowStart,
            to: BurnInLifecycleState::AutoEnforcement,
        };
        let msg = format!("{err}");
        assert!(msg.contains("shadow_start"));
        assert!(msg.contains("auto_enforcement"));
    }

    #[test]
    fn error_display_non_monotonic() {
        let err = BurnInError::NonMonotonicTimestamp {
            previous_ns: 100,
            observed_ns: 50,
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = BurnInError::InvalidTransition {
            from: BurnInLifecycleState::ShadowStart,
            to: BurnInLifecycleState::Rejection,
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: BurnInError = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    // ── BurnInSessionConfig ─────────────────────────────────────────

    #[test]
    fn config_validate_empty_trace_id() {
        let mut c = make_config();
        c.trace_id = "".to_string();
        let err = BurnInSession::new(c, RollbackProofArtifacts::default()).unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn config_validate_empty_decision_id() {
        let mut c = make_config();
        c.decision_id = "".to_string();
        let err = BurnInSession::new(c, RollbackProofArtifacts::default()).unwrap_err();
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn config_validate_empty_policy_id() {
        let mut c = make_config();
        c.policy_id = "".to_string();
        let err = BurnInSession::new(c, RollbackProofArtifacts::default()).unwrap_err();
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn config_validate_empty_extension_id() {
        let mut c = make_config();
        c.extension_id = "".to_string();
        let err = BurnInSession::new(c, RollbackProofArtifacts::default()).unwrap_err();
        assert!(err.to_string().contains("extension_id"));
    }

    #[test]
    fn config_normalize_trims_ids() {
        let mut c = make_config();
        c.trace_id = "  t1  ".to_string();
        c.decision_id = "  d1  ".to_string();
        c.policy_id = "  p1  ".to_string();
        c.extension_id = "  e1  ".to_string();
        let session = BurnInSession::new(c, RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        let log = &session.logs()[0];
        assert_eq!(log.trace_id, "t1");
        assert_eq!(log.decision_id, "d1");
        assert_eq!(log.policy_id, "p1");
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = make_config();
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let back: BurnInSessionConfig =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, back);
    }

    // ── BurnInSession: new ──────────────────────────────────────────

    #[test]
    fn session_new_starts_at_shadow_start() {
        let session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        assert_eq!(session.lifecycle_state(), BurnInLifecycleState::ShadowStart);
        assert_eq!(session.logs().len(), 1);
        assert_eq!(session.logs()[0].event, "shadow_start");
    }

    #[test]
    fn session_new_metrics_initialized() {
        let config = make_config();
        let session = BurnInSession::new(config.clone(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        let m = session.metrics();
        assert_eq!(m.started_at_ns, config.shadow_start_timestamp_ns);
        assert_eq!(m.total_observations, 0);
    }

    // ── BurnInSession: begin_shadow_evaluation ──────────────────────

    #[test]
    fn session_begin_shadow_evaluation() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        assert_eq!(
            session.lifecycle_state(),
            BurnInLifecycleState::ShadowEvaluation
        );
        assert_eq!(session.logs().len(), 2);
    }

    #[test]
    fn session_double_begin_shadow_evaluation_fails() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        let err = session.begin_shadow_evaluation().unwrap_err();
        assert!(matches!(err, BurnInError::InvalidTransition { .. }));
    }

    // ── BurnInSession: record_shadow_observation ────────────────────

    #[test]
    fn session_record_observation_success() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        let result = session
            .record_shadow_observation(success_observation("obs-1", 2_000_000))
            .expect("serde deserialization should succeed");
        assert!(result.is_none()); // no early termination
        assert_eq!(session.metrics().total_observations, 1);
        assert_eq!(session.metrics().successful_observations, 1);
        assert_eq!(session.metrics().false_denies, 0);
    }

    #[test]
    fn session_record_observation_false_deny() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        let result = session
            .record_shadow_observation(false_deny_observation("obs-1", 2_000_000))
            .expect("serde deserialization should succeed");
        // With 1 observation and 1 false_deny, rate = 1_000_000 > 5_000 threshold → early termination
        assert!(result.is_some());
        let artifact = result.expect("serde deserialization should succeed");
        assert_eq!(artifact.lifecycle_state, BurnInLifecycleState::Rejection);
        assert!(
            artifact
                .failure_codes
                .contains(&BurnInFailureCode::EarlyTerminationFalseDeny)
        );
    }

    #[test]
    fn session_record_observation_wrong_state() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        // Still in ShadowStart, not ShadowEvaluation
        let err = session
            .record_shadow_observation(success_observation("obs-1", 2_000_000))
            .unwrap_err();
        assert!(matches!(err, BurnInError::InvalidTransition { .. }));
    }

    #[test]
    fn session_record_observation_non_monotonic_timestamp() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(success_observation("obs-1", 2_000_000))
            .expect("serde deserialization should succeed");
        let err = session
            .record_shadow_observation(success_observation("obs-2", 1_000_000))
            .unwrap_err();
        assert!(matches!(err, BurnInError::NonMonotonicTimestamp { .. }));
    }

    #[test]
    fn session_record_observation_empty_id() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        let obs = ShadowObservation {
            observation_id: "".to_string(),
            timestamp_ns: 2_000_000,
            success: true,
            false_deny: false,
        };
        let err = session.record_shadow_observation(obs).unwrap_err();
        assert!(matches!(err, BurnInError::InvalidObservation { .. }));
    }

    // ── BurnInSession: evaluate_promotion_gate ──────────────────────

    #[test]
    fn session_promotion_gate_pass() {
        let mut session = session_ready_for_promotion();
        let artifact = session
            .evaluate_promotion_gate(100_000)
            .expect("serde deserialization should succeed");
        assert_eq!(artifact.outcome, "pass");
        assert!(artifact.failure_codes.is_empty());
        assert_eq!(
            artifact.lifecycle_state,
            BurnInLifecycleState::AutoEnforcement
        );
        assert!(artifact.rollback_artifacts_verified);
        assert_eq!(
            session.lifecycle_state(),
            BurnInLifecycleState::AutoEnforcement
        );
    }

    #[test]
    fn session_promotion_gate_insufficient_duration() {
        let mut config = make_config();
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 0,
            max_false_deny_millionths: 1_000_000,
            min_shadow_duration_ns: 1_000_000_000, // 1 second
            min_shadow_observations: 1,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, complete_rollback_artifacts())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(success_observation("obs-1", 2_000))
            .expect("serde deserialization should succeed");
        let artifact = session
            .evaluate_promotion_gate(3_000)
            .expect("serde deserialization should succeed");
        assert_eq!(artifact.outcome, "fail");
        assert!(
            artifact
                .failure_codes
                .contains(&BurnInFailureCode::InsufficientShadowDuration)
        );
    }

    #[test]
    fn session_promotion_gate_insufficient_observations() {
        let mut config = make_config();
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 0,
            max_false_deny_millionths: 1_000_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 100,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, complete_rollback_artifacts())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(success_observation("obs-1", 2_000))
            .expect("serde deserialization should succeed");
        let artifact = session
            .evaluate_promotion_gate(3_000)
            .expect("serde deserialization should succeed");
        assert!(
            artifact
                .failure_codes
                .contains(&BurnInFailureCode::InsufficientShadowObservations)
        );
    }

    #[test]
    fn session_promotion_gate_low_success_rate() {
        let mut config = make_config();
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 1_000_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 1,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, complete_rollback_artifacts())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        // Record 1 failure out of 2 = 500_000 millionths success rate
        session
            .record_shadow_observation(success_observation("obs-1", 2_000))
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(ShadowObservation {
                observation_id: "obs-2".to_string(),
                timestamp_ns: 3_000,
                success: false,
                false_deny: false,
            })
            .expect("serde deserialization should succeed");
        let artifact = session
            .evaluate_promotion_gate(4_000)
            .expect("serde deserialization should succeed");
        assert!(
            artifact
                .failure_codes
                .contains(&BurnInFailureCode::ShadowSuccessRateBelowThreshold)
        );
    }

    #[test]
    fn session_promotion_gate_rollback_artifacts_missing() {
        let mut config = make_config();
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 0,
            max_false_deny_millionths: 1_000_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 1,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(success_observation("obs-1", 2_000))
            .expect("serde deserialization should succeed");
        let artifact = session
            .evaluate_promotion_gate(3_000)
            .expect("serde deserialization should succeed");
        assert!(
            artifact
                .failure_codes
                .contains(&BurnInFailureCode::RollbackProofArtifactsMissing)
        );
        assert!(!artifact.rollback_artifacts_verified);
    }

    #[test]
    fn session_promotion_gate_wrong_state() {
        let session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        let mut session = session;
        let err = session.evaluate_promotion_gate(5_000_000).unwrap_err();
        assert!(matches!(err, BurnInError::InvalidTransition { .. }));
    }

    #[test]
    fn session_promotion_gate_non_monotonic() {
        let mut session = session_ready_for_promotion();
        // latest_timestamp_ns is at least 2_000 + 9*100 = 2_900, so 1 is non-monotonic
        let err = session.evaluate_promotion_gate(1).unwrap_err();
        assert!(matches!(err, BurnInError::NonMonotonicTimestamp { .. }));
    }

    // ── BurnInSession: decision_hash determinism ────────────────────

    #[test]
    fn decision_hash_deterministic() {
        let a1 = {
            let mut s = session_ready_for_promotion();
            s.evaluate_promotion_gate(100_000)
                .expect("serde deserialization should succeed")
        };
        let a2 = {
            let mut s = session_ready_for_promotion();
            s.evaluate_promotion_gate(100_000)
                .expect("serde deserialization should succeed")
        };
        assert_eq!(a1.decision_hash, a2.decision_hash);
    }

    #[test]
    fn decision_hash_differs_on_different_outcome() {
        let pass_hash = {
            let mut s = session_ready_for_promotion();
            s.evaluate_promotion_gate(100_000)
                .expect("serde deserialization should succeed")
                .decision_hash
        };
        // Create a rejection by using incomplete rollback artifacts
        let mut config = make_config();
        config.risk_class = ExtensionRiskClass::Low;
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 100_000,
            min_shadow_duration_ns: 100,
            min_shadow_observations: 5,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        for i in 0..10 {
            session
                .record_shadow_observation(success_observation(
                    &format!("obs-{i}"),
                    2_000 + i * 100,
                ))
                .expect("serde deserialization should succeed");
        }
        let reject_hash = session
            .evaluate_promotion_gate(100_000)
            .expect("serde deserialization should succeed")
            .decision_hash;
        assert_ne!(pass_hash, reject_hash);
    }

    // ── BurnInSession: scorecard_metrics ────────────────────────────

    #[test]
    fn scorecard_metrics_initial() {
        let session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        let sc = session.scorecard_metrics();
        assert_eq!(sc.shadow_success_rate_millionths, 0);
        assert_eq!(sc.false_deny_rate_millionths, 0);
        assert!(!sc.rollback_artifacts_verified);
        assert_eq!(sc.lifecycle_state, BurnInLifecycleState::ShadowStart);
    }

    #[test]
    fn scorecard_metrics_after_promotion() {
        let mut session = session_ready_for_promotion();
        session
            .evaluate_promotion_gate(100_000)
            .expect("serde deserialization should succeed");
        let sc = session.scorecard_metrics();
        assert_eq!(sc.shadow_success_rate_millionths, 1_000_000);
        assert_eq!(sc.false_deny_rate_millionths, 0);
        assert!(sc.rollback_artifacts_verified);
        assert_eq!(sc.lifecycle_state, BurnInLifecycleState::AutoEnforcement);
    }

    // ── BurnInSession: decision_artifact accessor ───────────────────

    #[test]
    fn decision_artifact_none_before_gate() {
        let session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        assert!(session.decision_artifact().is_none());
    }

    #[test]
    fn decision_artifact_some_after_gate() {
        let mut session = session_ready_for_promotion();
        session
            .evaluate_promotion_gate(100_000)
            .expect("serde deserialization should succeed");
        assert!(session.decision_artifact().is_some());
    }

    // ── BurnInSession serde roundtrip ───────────────────────────────

    #[test]
    fn session_serde_roundtrip() {
        let session = session_ready_for_promotion();
        let json = serde_json::to_string(&session).expect("serialize derived Serialize");
        let back: BurnInSession =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(session, back);
    }

    // ── BurnInLogEvent serde ────────────────────────────────────────

    #[test]
    fn log_event_serde_roundtrip() {
        let le = BurnInLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            lifecycle_state: BurnInLifecycleState::ShadowStart,
        };
        let json = serde_json::to_string(&le).expect("serialize derived Serialize");
        let back: BurnInLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(le, back);
    }

    // ── BurnInDecisionArtifact serde ────────────────────────────────

    #[test]
    fn decision_artifact_serde_roundtrip() {
        let mut session = session_ready_for_promotion();
        let artifact = session
            .evaluate_promotion_gate(100_000)
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&artifact).expect("serialize derived Serialize");
        let back: BurnInDecisionArtifact =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(artifact, back);
    }

    // ── BurnInScorecardMetrics serde ────────────────────────────────

    #[test]
    fn scorecard_metrics_serde_roundtrip() {
        let sc = BurnInScorecardMetrics {
            shadow_success_rate_millionths: 990_000,
            false_deny_rate_millionths: 3_000,
            rollback_artifacts_verified: true,
            lifecycle_state: BurnInLifecycleState::AutoEnforcement,
        };
        let json = serde_json::to_string(&sc).expect("serialize derived Serialize");
        let back: BurnInScorecardMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sc, back);
    }

    // ── Early termination stores artifact ───────────────────────────

    #[test]
    fn early_termination_stores_decision_artifact() {
        let mut session = BurnInSession::new(make_config(), RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        let artifact = session
            .record_shadow_observation(false_deny_observation("obs-1", 2_000_000))
            .expect("serde deserialization should succeed");
        assert!(artifact.is_some());
        assert!(session.decision_artifact().is_some());
        assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    }

    // ── Multiple failure codes in single gate evaluation ────────────

    #[test]
    fn promotion_gate_multiple_failures() {
        let mut config = make_config();
        config.thresholds = BurnInThresholds {
            min_shadow_success_millionths: 999_000,
            max_false_deny_millionths: 0,
            min_shadow_duration_ns: 1_000_000_000_000,
            min_shadow_observations: 10_000,
        };
        config.shadow_start_timestamp_ns = 1_000;
        let mut session = BurnInSession::new(config, RollbackProofArtifacts::default())
            .expect("serde deserialization should succeed");
        session
            .begin_shadow_evaluation()
            .expect("serde deserialization should succeed");
        session
            .record_shadow_observation(success_observation("obs-1", 2_000))
            .expect("serde deserialization should succeed");
        let artifact = session
            .evaluate_promotion_gate(3_000)
            .expect("serde deserialization should succeed");
        // Should have at least: insufficient duration, insufficient observations, rollback missing
        assert!(artifact.failure_codes.len() >= 3);
        assert_eq!(artifact.lifecycle_state, BurnInLifecycleState::Rejection);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn risk_class_as_str_distinct() {
        let all = [
            ExtensionRiskClass::Low,
            ExtensionRiskClass::Standard,
            ExtensionRiskClass::High,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn lifecycle_as_str_distinct() {
        let all = [
            BurnInLifecycleState::ShadowStart,
            BurnInLifecycleState::ShadowEvaluation,
            BurnInLifecycleState::PromotionGate,
            BurnInLifecycleState::AutoEnforcement,
            BurnInLifecycleState::Rejection,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn failure_code_error_code_distinct() {
        let all = [
            BurnInFailureCode::EarlyTerminationFalseDeny,
            BurnInFailureCode::InsufficientShadowDuration,
            BurnInFailureCode::InsufficientShadowObservations,
            BurnInFailureCode::ShadowSuccessRateBelowThreshold,
            BurnInFailureCode::FalseDenyEnvelopeExceeded,
            BurnInFailureCode::RollbackProofArtifactsMissing,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|c| c.error_code()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn burn_in_error_serde_all_variants() {
        let variants: Vec<BurnInError> = vec![
            BurnInError::InvalidConfig {
                detail: "bad".into(),
            },
            BurnInError::InvalidObservation {
                detail: "obs".into(),
            },
            BurnInError::InvalidTransition {
                from: BurnInLifecycleState::ShadowStart,
                to: BurnInLifecycleState::AutoEnforcement,
            },
            BurnInError::NonMonotonicTimestamp {
                previous_ns: 100,
                observed_ns: 50,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: BurnInError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, back);
        }
    }
}
