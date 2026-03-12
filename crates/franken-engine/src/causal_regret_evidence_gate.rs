//! [FRX-15.4] Causal / Regret Evidence Integration into Milestone Gate Automation
//!
//! Wires off-policy counterfactual evaluation results and regret certificates
//! from the adaptive lane router into milestone-stage promotion gates.
//!
//! Milestone stages follow [`MoonshotStage`] progression:
//! `Research → Shadow → Canary → Production`, each stage requiring
//! progressively stricter causal-confidence and regret-bound evidence.
//!
//! Promotions are blocked when:
//! - Counterfactual safety status is [`EnvelopeStatus::Unsafe`]
//! - Regret certificate is not within theoretical bounds
//! - Causal confidence is below the configured stage threshold
//! - Recent demotion history exceeds the allowed count
//!
//! All arithmetic uses fixed-point millionths (1 000 000 = 1.0) for
//! determinism.  No floating point.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::counterfactual_evaluator::{EnvelopeStatus, EstimatorKind, EvaluationResult, PolicyId};
use crate::demotion_rollback::{DemotionReason, DemotionSeverity};
use crate::hash_tiers::ContentHash;
use crate::moonshot_contract::MoonshotStage;
use crate::regret_bounded_router::{RegimeKind, RegretCertificate};
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{GateVerdict, RiskLevel};

// ── Constants ─────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for serialised gate artefacts.
pub const CAUSAL_REGRET_GATE_SCHEMA_VERSION: &str = "franken-engine.causal-regret-evidence-gate.v1";

/// Component label used in telemetry and evidence ledger entries.
pub const CAUSAL_REGRET_GATE_COMPONENT: &str = "causal_regret_evidence_gate";

/// Maximum number of demotion history items considered.
const MAX_DEMOTION_HISTORY: usize = 1_000;

/// Maximum number of evaluation results in a single gate input.
const MAX_EVALUATIONS: usize = 100;

// ── Milestone thresholds ──────────────────────────────────────────────

/// Per-stage configuration for causal/regret evidence thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageThresholds {
    /// Target milestone stage.
    pub stage: MoonshotStage,
    /// Minimum causal-confidence lower-bound (millionths) required.
    /// The lower bound of the improvement envelope must exceed this.
    pub min_confidence_lower_millionths: i64,
    /// Minimum effective samples required from the counterfactual evaluator.
    pub min_effective_samples: u64,
    /// Maximum realised regret (millionths) tolerated.
    pub max_regret_millionths: i64,
    /// Whether the regret certificate must prove within-bound (exact).
    pub require_regret_within_bound: bool,
    /// Maximum number of recent Critical-severity demotions tolerated.
    pub max_recent_critical_demotions: u64,
    /// Maximum number of recent demotions (any severity) tolerated.
    pub max_recent_demotions: u64,
    /// Whether to require `EnvelopeStatus::Safe` (vs allowing `Inconclusive`).
    pub require_safe_envelope: bool,
    /// Allowed estimator kinds (empty = any).
    pub allowed_estimators: Vec<EstimatorKind>,
}

impl StageThresholds {
    /// Default thresholds for Research stage — minimal requirements.
    pub fn research() -> Self {
        Self {
            stage: MoonshotStage::Research,
            min_confidence_lower_millionths: 0,
            min_effective_samples: 0,
            max_regret_millionths: MILLION,
            require_regret_within_bound: false,
            max_recent_critical_demotions: 10,
            max_recent_demotions: 50,
            require_safe_envelope: false,
            allowed_estimators: Vec::new(),
        }
    }

    /// Default thresholds for Shadow stage — moderate requirements.
    pub fn shadow() -> Self {
        Self {
            stage: MoonshotStage::Shadow,
            min_confidence_lower_millionths: 50_000, // 5%
            min_effective_samples: 100,
            max_regret_millionths: 500_000, // 0.5
            require_regret_within_bound: false,
            max_recent_critical_demotions: 3,
            max_recent_demotions: 10,
            require_safe_envelope: false,
            allowed_estimators: Vec::new(),
        }
    }

    /// Default thresholds for Canary stage — strict requirements.
    pub fn canary() -> Self {
        Self {
            stage: MoonshotStage::Canary,
            min_confidence_lower_millionths: 100_000, // 10%
            min_effective_samples: 500,
            max_regret_millionths: 200_000, // 0.2
            require_regret_within_bound: true,
            max_recent_critical_demotions: 0,
            max_recent_demotions: 3,
            require_safe_envelope: true,
            allowed_estimators: vec![EstimatorKind::DoublyRobust],
        }
    }

    /// Default thresholds for Production stage — most stringent.
    pub fn production() -> Self {
        Self {
            stage: MoonshotStage::Production,
            min_confidence_lower_millionths: 200_000, // 20%
            min_effective_samples: 1_000,
            max_regret_millionths: 100_000, // 0.1
            require_regret_within_bound: true,
            max_recent_critical_demotions: 0,
            max_recent_demotions: 0,
            require_safe_envelope: true,
            allowed_estimators: vec![EstimatorKind::DoublyRobust],
        }
    }

    /// Default thresholds for a given stage.
    pub fn for_stage(stage: MoonshotStage) -> Self {
        match stage {
            MoonshotStage::Research => Self::research(),
            MoonshotStage::Shadow => Self::shadow(),
            MoonshotStage::Canary => Self::canary(),
            MoonshotStage::Production => Self::production(),
        }
    }
}

// ── Gate configuration ────────────────────────────────────────────────

/// Full configuration for the causal/regret evidence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalRegretGateConfig {
    /// Per-stage threshold overrides.  Missing stages use defaults.
    pub stage_thresholds: BTreeMap<String, StageThresholds>,
    /// How many recent epochs to consider for demotion history.
    pub demotion_lookback_epochs: u64,
    /// Whether to block on inconclusive evaluations.
    pub block_on_inconclusive: bool,
    /// Maximum allowed per-round regret (millionths) across all stages.
    pub max_per_round_regret_millionths: i64,
    /// Require at least one evaluation result.
    pub require_evaluation: bool,
    /// Require regret certificate.
    pub require_regret_certificate: bool,
}

impl Default for CausalRegretGateConfig {
    fn default() -> Self {
        Self {
            stage_thresholds: BTreeMap::new(),
            demotion_lookback_epochs: 5,
            block_on_inconclusive: false,
            max_per_round_regret_millionths: 50_000, // 0.05
            require_evaluation: true,
            require_regret_certificate: true,
        }
    }
}

impl CausalRegretGateConfig {
    /// Retrieve thresholds for a stage, falling back to defaults.
    pub fn thresholds_for(&self, stage: MoonshotStage) -> StageThresholds {
        self.stage_thresholds
            .get(&format!("{stage}"))
            .cloned()
            .unwrap_or_else(|| StageThresholds::for_stage(stage))
    }
}

// ── Demotion history item ─────────────────────────────────────────────

/// Summary of a past demotion event for gate input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionHistoryItem {
    /// Epoch when the demotion occurred.
    pub epoch: SecurityEpoch,
    /// Reason for the demotion.
    pub reason: DemotionReason,
    /// Severity of the demotion.
    pub severity: DemotionSeverity,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

// ── Gate input ────────────────────────────────────────────────────────

/// Input to the causal/regret evidence gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateInput {
    /// Current milestone stage from which promotion is attempted.
    pub current_stage: MoonshotStage,
    /// Target milestone stage being promoted into.
    pub target_stage: MoonshotStage,
    /// Off-policy evaluation results (one per estimator/policy pair).
    pub evaluations: Vec<EvaluationResult>,
    /// Regret certificate from the adaptive router.
    pub regret_certificate: Option<RegretCertificate>,
    /// Recent demotion history.
    pub demotion_history: Vec<DemotionHistoryItem>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Evaluation timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Current routing regime.
    pub regime: RegimeKind,
    /// Optional moonshot contract identifier.
    pub moonshot_id: Option<String>,
}

// ── Blocking reason ───────────────────────────────────────────────────

/// Reason why the gate blocked a promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingReason {
    /// Counterfactual safety envelope is Unsafe.
    UnsafeEnvelope {
        policy_id: String,
        estimator: EstimatorKind,
    },
    /// Counterfactual envelope is Inconclusive and gate is configured to block.
    InconclusiveEnvelope {
        policy_id: String,
        estimator: EstimatorKind,
    },
    /// Causal confidence lower bound is below threshold.
    InsufficientConfidence {
        observed_millionths: i64,
        required_millionths: i64,
    },
    /// Effective sample count is too low.
    InsufficientSamples { observed: u64, required: u64 },
    /// Estimator kind is not in the allowed set for the target stage.
    DisallowedEstimator { estimator: EstimatorKind },
    /// Regret certificate absent when required.
    MissingRegretCertificate,
    /// Realised regret exceeds maximum.
    ExcessiveRegret {
        realized_millionths: i64,
        max_millionths: i64,
    },
    /// Per-round regret exceeds global limit.
    ExcessivePerRoundRegret {
        per_round_millionths: i64,
        max_millionths: i64,
    },
    /// Regret certificate is not within theoretical bound.
    RegretNotWithinBound,
    /// Too many recent critical demotions.
    TooManyCriticalDemotions { count: u64, max: u64 },
    /// Too many recent demotions (any severity).
    TooManyDemotions { count: u64, max: u64 },
    /// No evaluation results provided when required.
    MissingEvaluation,
    /// Target stage is not a valid progression from current stage.
    InvalidStageProgression {
        current: MoonshotStage,
        target: MoonshotStage,
    },
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeEnvelope {
                policy_id,
                estimator,
            } => write!(
                f,
                "unsafe envelope: policy={policy_id} estimator={estimator}"
            ),
            Self::InconclusiveEnvelope {
                policy_id,
                estimator,
            } => write!(
                f,
                "inconclusive envelope: policy={policy_id} estimator={estimator}"
            ),
            Self::InsufficientConfidence {
                observed_millionths,
                required_millionths,
            } => write!(
                f,
                "insufficient confidence: observed={observed_millionths} required={required_millionths}"
            ),
            Self::InsufficientSamples { observed, required } => {
                write!(
                    f,
                    "insufficient samples: observed={observed} required={required}"
                )
            }
            Self::DisallowedEstimator { estimator } => {
                write!(f, "disallowed estimator: {estimator}")
            }
            Self::MissingRegretCertificate => write!(f, "missing regret certificate"),
            Self::ExcessiveRegret {
                realized_millionths,
                max_millionths,
            } => write!(
                f,
                "excessive regret: realized={realized_millionths} max={max_millionths}"
            ),
            Self::ExcessivePerRoundRegret {
                per_round_millionths,
                max_millionths,
            } => write!(
                f,
                "excessive per-round regret: per_round={per_round_millionths} max={max_millionths}"
            ),
            Self::RegretNotWithinBound => write!(f, "regret not within theoretical bound"),
            Self::TooManyCriticalDemotions { count, max } => {
                write!(f, "too many critical demotions: {count} > {max}")
            }
            Self::TooManyDemotions { count, max } => {
                write!(f, "too many demotions: {count} > {max}")
            }
            Self::MissingEvaluation => write!(f, "no evaluation results provided"),
            Self::InvalidStageProgression { current, target } => {
                write!(f, "invalid progression: {current} -> {target}")
            }
        }
    }
}

// ── Evidence summary ──────────────────────────────────────────────────

/// Summary of a single counterfactual evaluation's contribution to the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationSummary {
    /// Policy evaluated.
    pub policy_id: PolicyId,
    /// Estimator used.
    pub estimator: EstimatorKind,
    /// Safety status from the evaluator.
    pub safety_status: EnvelopeStatus,
    /// Improvement envelope lower bound (millionths).
    pub improvement_lower_millionths: i64,
    /// Effective sample count.
    pub effective_samples: u64,
    /// Artifact hash from the evaluator.
    pub artifact_hash: ContentHash,
}

/// Summary of regret evidence contribution to the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegretSummary {
    /// Total rounds evaluated.
    pub rounds: u64,
    /// Realised regret (millionths).
    pub realized_regret_millionths: i64,
    /// Theoretical bound (millionths).
    pub theoretical_bound_millionths: i64,
    /// Whether regret is within theoretical bound.
    pub within_bound: bool,
    /// Per-round regret (millionths).
    pub per_round_regret_millionths: i64,
}

// ── Gate output ───────────────────────────────────────────────────────

/// Gate verdict for milestone promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateOutput {
    /// Schema version.
    pub schema_version: String,
    /// Component label.
    pub component: String,
    /// Gate verdict.
    pub verdict: GateVerdict,
    /// Assessed risk level.
    pub risk_level: RiskLevel,
    /// Target stage being evaluated.
    pub target_stage: MoonshotStage,
    /// Current stage.
    pub current_stage: MoonshotStage,
    /// Blocking reasons (empty if approved).
    pub blocking_reasons: Vec<BlockingReason>,
    /// Evaluation summaries.
    pub evaluation_summaries: Vec<EvaluationSummary>,
    /// Regret summary (if certificate provided).
    pub regret_summary: Option<RegretSummary>,
    /// Number of recent demotions considered.
    pub demotions_considered: u64,
    /// Number of recent critical demotions.
    pub critical_demotions_count: u64,
    /// Routing regime at evaluation time.
    pub regime: RegimeKind,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Moonshot contract identifier (if provided).
    pub moonshot_id: Option<String>,
    /// Deterministic artifact hash.
    pub artifact_hash: ContentHash,
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors from the causal/regret evidence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CausalRegretGateError {
    /// Too many evaluation results.
    TooManyEvaluations { count: usize, max: usize },
    /// Too many demotion history items.
    TooManyDemotionItems { count: usize, max: usize },
    /// Configuration validation failure.
    InvalidConfig { reason: String },
}

impl fmt::Display for CausalRegretGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEvaluations { count, max } => {
                write!(f, "too many evaluations: {count} > {max}")
            }
            Self::TooManyDemotionItems { count, max } => {
                write!(f, "too many demotion items: {count} > {max}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
        }
    }
}

// ── Gate engine ───────────────────────────────────────────────────────

/// Causal/regret evidence gate for milestone promotions.
///
/// Evaluates off-policy counterfactual evidence and regret certificates
/// against configurable per-stage thresholds to produce promotion verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalRegretEvidenceGate {
    config: CausalRegretGateConfig,
    /// Number of evaluations run.
    evaluations_run: u64,
    /// Number of promotions approved.
    promotions_approved: u64,
    /// Number of promotions denied.
    promotions_denied: u64,
}

impl CausalRegretEvidenceGate {
    /// Create a new gate with default configuration.
    pub fn new() -> Self {
        Self {
            config: CausalRegretGateConfig::default(),
            evaluations_run: 0,
            promotions_approved: 0,
            promotions_denied: 0,
        }
    }

    /// Create a new gate with custom configuration.
    pub fn with_config(config: CausalRegretGateConfig) -> Result<Self, CausalRegretGateError> {
        if config.max_per_round_regret_millionths < 0 {
            return Err(CausalRegretGateError::InvalidConfig {
                reason: "max_per_round_regret_millionths must be non-negative".into(),
            });
        }
        Ok(Self {
            config,
            evaluations_run: 0,
            promotions_approved: 0,
            promotions_denied: 0,
        })
    }

    /// Access the gate configuration.
    pub fn config(&self) -> &CausalRegretGateConfig {
        &self.config
    }

    /// Number of evaluations run.
    pub fn evaluations_run(&self) -> u64 {
        self.evaluations_run
    }

    /// Number of promotions approved.
    pub fn promotions_approved(&self) -> u64 {
        self.promotions_approved
    }

    /// Number of promotions denied.
    pub fn promotions_denied(&self) -> u64 {
        self.promotions_denied
    }

    /// Evaluate a promotion gate.
    pub fn evaluate(&mut self, input: &GateInput) -> Result<GateOutput, CausalRegretGateError> {
        // Validate input sizes.
        if input.evaluations.len() > MAX_EVALUATIONS {
            return Err(CausalRegretGateError::TooManyEvaluations {
                count: input.evaluations.len(),
                max: MAX_EVALUATIONS,
            });
        }
        if input.demotion_history.len() > MAX_DEMOTION_HISTORY {
            return Err(CausalRegretGateError::TooManyDemotionItems {
                count: input.demotion_history.len(),
                max: MAX_DEMOTION_HISTORY,
            });
        }

        let thresholds = self.config.thresholds_for(input.target_stage);
        let mut blocking_reasons = Vec::new();

        // 1. Validate stage progression.
        if !is_valid_progression(input.current_stage, input.target_stage) {
            blocking_reasons.push(BlockingReason::InvalidStageProgression {
                current: input.current_stage,
                target: input.target_stage,
            });
        }

        // 2. Check evaluation results.
        let mut evaluation_summaries = Vec::new();
        if input.evaluations.is_empty() && self.config.require_evaluation {
            blocking_reasons.push(BlockingReason::MissingEvaluation);
        }
        for eval in &input.evaluations {
            let summary = EvaluationSummary {
                policy_id: eval.candidate_policy_id.clone(),
                estimator: eval.estimator,
                safety_status: eval.safety_status,
                improvement_lower_millionths: eval.improvement_envelope.lower_millionths,
                effective_samples: eval.improvement_envelope.effective_samples,
                artifact_hash: eval.artifact_hash,
            };

            // Check safety status.
            match eval.safety_status {
                EnvelopeStatus::Unsafe => {
                    blocking_reasons.push(BlockingReason::UnsafeEnvelope {
                        policy_id: eval.candidate_policy_id.0.clone(),
                        estimator: eval.estimator,
                    });
                }
                EnvelopeStatus::Inconclusive => {
                    if thresholds.require_safe_envelope || self.config.block_on_inconclusive {
                        blocking_reasons.push(BlockingReason::InconclusiveEnvelope {
                            policy_id: eval.candidate_policy_id.0.clone(),
                            estimator: eval.estimator,
                        });
                    }
                }
                EnvelopeStatus::Safe => {}
            }

            // Check confidence lower bound.
            if eval.improvement_envelope.lower_millionths
                < thresholds.min_confidence_lower_millionths
            {
                blocking_reasons.push(BlockingReason::InsufficientConfidence {
                    observed_millionths: eval.improvement_envelope.lower_millionths,
                    required_millionths: thresholds.min_confidence_lower_millionths,
                });
            }

            // Check effective samples.
            if eval.improvement_envelope.effective_samples < thresholds.min_effective_samples {
                blocking_reasons.push(BlockingReason::InsufficientSamples {
                    observed: eval.improvement_envelope.effective_samples,
                    required: thresholds.min_effective_samples,
                });
            }

            // Check estimator allowlist.
            if !thresholds.allowed_estimators.is_empty()
                && !thresholds.allowed_estimators.contains(&eval.estimator)
            {
                blocking_reasons.push(BlockingReason::DisallowedEstimator {
                    estimator: eval.estimator,
                });
            }

            evaluation_summaries.push(summary);
        }

        // 3. Check regret certificate.
        let regret_summary = if let Some(cert) = &input.regret_certificate {
            // Realised regret.
            if cert.realized_regret_millionths > thresholds.max_regret_millionths {
                blocking_reasons.push(BlockingReason::ExcessiveRegret {
                    realized_millionths: cert.realized_regret_millionths,
                    max_millionths: thresholds.max_regret_millionths,
                });
            }

            // Within-bound requirement.
            if thresholds.require_regret_within_bound && !cert.within_bound {
                blocking_reasons.push(BlockingReason::RegretNotWithinBound);
            }

            // Per-round regret.
            if cert.per_round_regret_millionths > self.config.max_per_round_regret_millionths {
                blocking_reasons.push(BlockingReason::ExcessivePerRoundRegret {
                    per_round_millionths: cert.per_round_regret_millionths,
                    max_millionths: self.config.max_per_round_regret_millionths,
                });
            }

            Some(RegretSummary {
                rounds: cert.rounds,
                realized_regret_millionths: cert.realized_regret_millionths,
                theoretical_bound_millionths: cert.theoretical_bound_millionths,
                within_bound: cert.within_bound,
                per_round_regret_millionths: cert.per_round_regret_millionths,
            })
        } else {
            if self.config.require_regret_certificate {
                blocking_reasons.push(BlockingReason::MissingRegretCertificate);
            }
            None
        };

        // 4. Check demotion history.
        let lookback_epoch_min = input
            .epoch
            .as_u64()
            .saturating_sub(self.config.demotion_lookback_epochs);
        let recent_demotions: Vec<_> = input
            .demotion_history
            .iter()
            .filter(|d| d.epoch.as_u64() >= lookback_epoch_min)
            .collect();
        let total_recent = recent_demotions.len() as u64;
        let critical_count = recent_demotions
            .iter()
            .filter(|d| d.severity == DemotionSeverity::Critical)
            .count() as u64;

        if critical_count > thresholds.max_recent_critical_demotions {
            blocking_reasons.push(BlockingReason::TooManyCriticalDemotions {
                count: critical_count,
                max: thresholds.max_recent_critical_demotions,
            });
        }
        if total_recent > thresholds.max_recent_demotions {
            blocking_reasons.push(BlockingReason::TooManyDemotions {
                count: total_recent,
                max: thresholds.max_recent_demotions,
            });
        }

        // 5. Compute verdict and risk level.
        let verdict = if blocking_reasons.is_empty() {
            GateVerdict::Approved
        } else {
            GateVerdict::Denied
        };

        let risk_level = compute_risk_level(
            &blocking_reasons,
            critical_count,
            &evaluation_summaries,
            input.target_stage,
        );

        // 6. Compute artifact hash.
        let artifact_hash = compute_artifact_hash(
            &verdict,
            input.target_stage,
            &blocking_reasons,
            &evaluation_summaries,
            &regret_summary,
            input.epoch,
            input.timestamp_ns,
        );

        self.evaluations_run += 1;
        match verdict {
            GateVerdict::Approved => self.promotions_approved += 1,
            GateVerdict::Denied | GateVerdict::Inconclusive => self.promotions_denied += 1,
        }

        Ok(GateOutput {
            schema_version: CAUSAL_REGRET_GATE_SCHEMA_VERSION.to_string(),
            component: CAUSAL_REGRET_GATE_COMPONENT.to_string(),
            verdict,
            risk_level,
            target_stage: input.target_stage,
            current_stage: input.current_stage,
            blocking_reasons,
            evaluation_summaries,
            regret_summary,
            demotions_considered: total_recent,
            critical_demotions_count: critical_count,
            regime: input.regime,
            epoch: input.epoch,
            timestamp_ns: input.timestamp_ns,
            moonshot_id: input.moonshot_id.clone(),
            artifact_hash,
        })
    }

    /// Reset counters.
    pub fn reset_counters(&mut self) {
        self.evaluations_run = 0;
        self.promotions_approved = 0;
        self.promotions_denied = 0;
    }
}

impl Default for CausalRegretEvidenceGate {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Check whether the target stage is a valid progression from the current stage.
fn is_valid_progression(current: MoonshotStage, target: MoonshotStage) -> bool {
    matches!(
        (current, target),
        (MoonshotStage::Research, MoonshotStage::Shadow)
            | (MoonshotStage::Shadow, MoonshotStage::Canary)
            | (MoonshotStage::Canary, MoonshotStage::Production)
    )
}

/// Compute risk level from blocking reasons and context.
fn compute_risk_level(
    blocking_reasons: &[BlockingReason],
    critical_demotions: u64,
    evaluation_summaries: &[EvaluationSummary],
    target: MoonshotStage,
) -> RiskLevel {
    // Any unsafe envelope or critical demotion history → Critical
    let has_unsafe = blocking_reasons.iter().any(|r| {
        matches!(
            r,
            BlockingReason::UnsafeEnvelope { .. } | BlockingReason::InvalidStageProgression { .. }
        )
    });
    if has_unsafe || critical_demotions > 0 {
        return RiskLevel::Critical;
    }

    // Production target with any blocking → High
    if target == MoonshotStage::Production && !blocking_reasons.is_empty() {
        return RiskLevel::High;
    }

    // Excessive regret or insufficient confidence → High
    let has_severe = blocking_reasons.iter().any(|r| {
        matches!(
            r,
            BlockingReason::ExcessiveRegret { .. }
                | BlockingReason::RegretNotWithinBound
                | BlockingReason::ExcessivePerRoundRegret { .. }
        )
    });
    if has_severe {
        return RiskLevel::High;
    }

    // Any blocking reason → Medium
    if !blocking_reasons.is_empty() {
        return RiskLevel::Medium;
    }

    // No blocking but low effective samples → Medium
    let low_samples = evaluation_summaries
        .iter()
        .any(|s| s.effective_samples < 100);
    if low_samples {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

/// Compute a deterministic artifact hash over the gate output.
fn compute_artifact_hash(
    verdict: &GateVerdict,
    target: MoonshotStage,
    blocking_reasons: &[BlockingReason],
    evaluation_summaries: &[EvaluationSummary],
    regret_summary: &Option<RegretSummary>,
    epoch: SecurityEpoch,
    timestamp_ns: u64,
) -> ContentHash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CAUSAL_REGRET_GATE_SCHEMA_VERSION.as_bytes());
    bytes.extend_from_slice(format!("{verdict:?}").as_bytes());
    bytes.extend_from_slice(format!("{target}").as_bytes());
    bytes.extend_from_slice(&(blocking_reasons.len() as u64).to_le_bytes());
    for reason in blocking_reasons {
        bytes.extend_from_slice(format!("{reason}").as_bytes());
    }
    bytes.extend_from_slice(&(evaluation_summaries.len() as u64).to_le_bytes());
    for summary in evaluation_summaries {
        bytes.extend_from_slice(summary.policy_id.0.as_bytes());
        bytes.extend_from_slice(format!("{:?}", summary.estimator).as_bytes());
        bytes.extend_from_slice(&summary.improvement_lower_millionths.to_le_bytes());
        bytes.extend_from_slice(&summary.effective_samples.to_le_bytes());
    }
    if let Some(rs) = regret_summary {
        bytes.push(1);
        bytes.extend_from_slice(&rs.rounds.to_le_bytes());
        bytes.extend_from_slice(&rs.realized_regret_millionths.to_le_bytes());
        bytes.extend_from_slice(&rs.theoretical_bound_millionths.to_le_bytes());
        bytes.push(u8::from(rs.within_bound));
        bytes.extend_from_slice(&rs.per_round_regret_millionths.to_le_bytes());
    } else {
        bytes.push(0);
    }
    bytes.extend_from_slice(&epoch.as_u64().to_le_bytes());
    bytes.extend_from_slice(&timestamp_ns.to_le_bytes());
    ContentHash::compute(&bytes)
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counterfactual_evaluator::ConfidenceEnvelope;
    use crate::hash_tiers::ContentHash;

    // ── Helpers ───────────────────────────────────────────────────────

    fn make_envelope(lower: i64, upper: i64, samples: u64) -> ConfidenceEnvelope {
        ConfidenceEnvelope {
            estimate_millionths: (lower + upper) / 2,
            lower_millionths: lower,
            upper_millionths: upper,
            confidence_millionths: 950_000,
            effective_samples: samples,
        }
    }

    fn make_eval(
        policy: &str,
        estimator: EstimatorKind,
        status: EnvelopeStatus,
        lower: i64,
        samples: u64,
    ) -> EvaluationResult {
        let envelope = make_envelope(lower, lower + 100_000, samples);
        EvaluationResult {
            schema_version: "test".into(),
            estimator,
            candidate_policy_id: PolicyId(policy.into()),
            baseline_policy_id: PolicyId("baseline".into()),
            candidate_envelope: envelope.clone(),
            baseline_envelope: make_envelope(0, 50_000, samples),
            improvement_envelope: envelope,
            safety_status: status,
            regime_breakdown: BTreeMap::new(),
            artifact_hash: ContentHash::compute(policy.as_bytes()),
        }
    }

    fn make_regret_cert(
        realized: i64,
        bound: i64,
        within: bool,
        per_round: i64,
    ) -> RegretCertificate {
        RegretCertificate {
            schema: "test".into(),
            rounds: 1000,
            realized_regret_millionths: realized,
            theoretical_bound_millionths: bound,
            within_bound: within,
            exact_regret_available: within,
            per_round_regret_millionths: per_round,
            growth_rate_class: "sublinear".into(),
        }
    }

    fn make_demotion(epoch: u64, severity: DemotionSeverity) -> DemotionHistoryItem {
        DemotionHistoryItem {
            epoch: SecurityEpoch::from_raw(epoch),
            reason: DemotionReason::PerformanceBreach {
                metric_name: "latency".into(),
                observed_millionths: 500_000,
                threshold_millionths: 200_000,
                sustained_duration_ns: 1_000_000,
            },
            severity,
            timestamp_ns: epoch * 1_000_000_000,
        }
    }

    fn basic_input(target: MoonshotStage) -> GateInput {
        let current = match target {
            MoonshotStage::Shadow => MoonshotStage::Research,
            MoonshotStage::Canary => MoonshotStage::Shadow,
            MoonshotStage::Production => MoonshotStage::Canary,
            MoonshotStage::Research => MoonshotStage::Research,
        };
        GateInput {
            current_stage: current,
            target_stage: target,
            evaluations: vec![make_eval(
                "policy-1",
                EstimatorKind::DoublyRobust,
                EnvelopeStatus::Safe,
                250_000,
                2_000,
            )],
            regret_certificate: Some(make_regret_cert(50_000, 100_000, true, 50)),
            demotion_history: Vec::new(),
            epoch: SecurityEpoch::from_raw(10),
            timestamp_ns: 1_000_000_000,
            regime: RegimeKind::Stochastic,
            moonshot_id: Some("moonshot-1".into()),
        }
    }

    // ── Construction / serde ──────────────────────────────────────────

    #[test]
    fn new_gate_default_config() {
        let gate = CausalRegretEvidenceGate::new();
        assert_eq!(gate.evaluations_run(), 0);
        assert_eq!(gate.promotions_approved(), 0);
        assert_eq!(gate.promotions_denied(), 0);
        assert!(gate.config().require_evaluation);
        assert!(gate.config().require_regret_certificate);
    }

    #[test]
    fn default_impl_matches_new() {
        let a = CausalRegretEvidenceGate::new();
        let b = CausalRegretEvidenceGate::default();
        assert_eq!(a, b);
    }

    #[test]
    fn config_invalid_negative_per_round() {
        let config = CausalRegretGateConfig {
            max_per_round_regret_millionths: -1,
            ..Default::default()
        };
        let err = CausalRegretEvidenceGate::with_config(config).unwrap_err();
        assert!(matches!(err, CausalRegretGateError::InvalidConfig { .. }));
    }

    #[test]
    fn gate_serde_roundtrip() {
        let gate = CausalRegretEvidenceGate::new();
        let json = serde_json::to_string(&gate).unwrap();
        let restored: CausalRegretEvidenceGate = serde_json::from_str(&json).unwrap();
        assert_eq!(gate, restored);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = CausalRegretGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: CausalRegretGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn gate_output_serde_roundtrip() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let restored: GateOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, restored);
    }

    // ── Stage thresholds ─────────────────────────────────────────────

    #[test]
    fn stage_thresholds_research_lenient() {
        let t = StageThresholds::research();
        assert_eq!(t.stage, MoonshotStage::Research);
        assert_eq!(t.min_confidence_lower_millionths, 0);
        assert_eq!(t.min_effective_samples, 0);
        assert!(!t.require_regret_within_bound);
        assert!(!t.require_safe_envelope);
    }

    #[test]
    fn stage_thresholds_production_strict() {
        let t = StageThresholds::production();
        assert_eq!(t.stage, MoonshotStage::Production);
        assert_eq!(t.min_confidence_lower_millionths, 200_000);
        assert_eq!(t.min_effective_samples, 1_000);
        assert!(t.require_regret_within_bound);
        assert!(t.require_safe_envelope);
        assert_eq!(t.max_recent_critical_demotions, 0);
        assert_eq!(t.max_recent_demotions, 0);
    }

    #[test]
    fn stage_thresholds_for_stage_all() {
        for stage in MoonshotStage::all() {
            let t = StageThresholds::for_stage(*stage);
            assert_eq!(t.stage, *stage);
        }
    }

    #[test]
    fn stage_thresholds_progressively_stricter() {
        let research = StageThresholds::research();
        let shadow = StageThresholds::shadow();
        let canary = StageThresholds::canary();
        let production = StageThresholds::production();

        assert!(research.min_confidence_lower_millionths <= shadow.min_confidence_lower_millionths);
        assert!(shadow.min_confidence_lower_millionths <= canary.min_confidence_lower_millionths);
        assert!(
            canary.min_confidence_lower_millionths <= production.min_confidence_lower_millionths
        );

        assert!(research.max_regret_millionths >= shadow.max_regret_millionths);
        assert!(shadow.max_regret_millionths >= canary.max_regret_millionths);
        assert!(canary.max_regret_millionths >= production.max_regret_millionths);
    }

    #[test]
    fn config_thresholds_for_uses_override() {
        let mut config = CausalRegretGateConfig::default();
        let mut custom = StageThresholds::shadow();
        custom.min_effective_samples = 42;
        config
            .stage_thresholds
            .insert("shadow".into(), custom.clone());

        let t = config.thresholds_for(MoonshotStage::Shadow);
        assert_eq!(t.min_effective_samples, 42);

        // Non-overridden stage uses default.
        let t2 = config.thresholds_for(MoonshotStage::Canary);
        assert_eq!(t2, StageThresholds::canary());
    }

    // ── Valid progression ─────────────────────────────────────────────

    #[test]
    fn valid_progressions() {
        assert!(is_valid_progression(
            MoonshotStage::Research,
            MoonshotStage::Shadow
        ));
        assert!(is_valid_progression(
            MoonshotStage::Shadow,
            MoonshotStage::Canary
        ));
        assert!(is_valid_progression(
            MoonshotStage::Canary,
            MoonshotStage::Production
        ));
    }

    #[test]
    fn invalid_progressions() {
        // Same stage.
        assert!(!is_valid_progression(
            MoonshotStage::Research,
            MoonshotStage::Research
        ));
        // Backward.
        assert!(!is_valid_progression(
            MoonshotStage::Shadow,
            MoonshotStage::Research
        ));
        // Skip.
        assert!(!is_valid_progression(
            MoonshotStage::Research,
            MoonshotStage::Canary
        ));
        // Skip Production.
        assert!(!is_valid_progression(
            MoonshotStage::Research,
            MoonshotStage::Production
        ));
    }

    // ── Approved promotions ──────────────────────────────────────────

    #[test]
    fn shadow_promotion_approved() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert!(output.blocking_reasons.is_empty());
        assert_eq!(output.target_stage, MoonshotStage::Shadow);
        assert_eq!(output.current_stage, MoonshotStage::Research);
        assert_eq!(gate.evaluations_run(), 1);
        assert_eq!(gate.promotions_approved(), 1);
    }

    #[test]
    fn canary_promotion_approved() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Canary);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert!(output.blocking_reasons.is_empty());
    }

    #[test]
    fn production_promotion_approved() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Production);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert!(output.blocking_reasons.is_empty());
    }

    #[test]
    fn approved_output_has_summaries() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.evaluation_summaries.len(), 1);
        assert_eq!(
            output.evaluation_summaries[0].policy_id,
            PolicyId("policy-1".into())
        );
        assert!(output.regret_summary.is_some());
    }

    // ── Blocking: unsafe envelope ────────────────────────────────────

    #[test]
    fn unsafe_envelope_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Unsafe,
            -50_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::UnsafeEnvelope { .. }))
        );
        assert_eq!(output.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn inconclusive_envelope_allowed_for_research() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Inconclusive,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        // Shadow doesn't require safe envelope by default.
        assert_eq!(output.verdict, GateVerdict::Approved);
    }

    #[test]
    fn inconclusive_envelope_blocks_for_canary() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Inconclusive,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InconclusiveEnvelope { .. }))
        );
    }

    #[test]
    fn block_on_inconclusive_config() {
        let config = CausalRegretGateConfig {
            block_on_inconclusive: true,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Inconclusive,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
    }

    // ── Blocking: insufficient confidence ────────────────────────────

    #[test]
    fn insufficient_confidence_blocks_canary() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        // Canary requires min_confidence_lower = 100_000. Give 50_000.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            50_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InsufficientConfidence { .. }))
        );
    }

    #[test]
    fn exactly_at_confidence_threshold_passes() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        // Canary requires 100_000, give exactly 100_000.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            100_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InsufficientConfidence { .. }))
        );
    }

    // ── Blocking: insufficient samples ───────────────────────────────

    #[test]
    fn insufficient_samples_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        // Production requires 1000 samples. Give 500.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            250_000,
            500,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InsufficientSamples { .. }))
        );
    }

    // ── Blocking: disallowed estimator ───────────────────────────────

    #[test]
    fn disallowed_estimator_blocks_production() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        // Production requires DoublyRobust. Use Ips.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::Ips,
            EnvelopeStatus::Safe,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::DisallowedEstimator { .. }))
        );
    }

    #[test]
    fn any_estimator_allowed_for_shadow() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::Ips,
            EnvelopeStatus::Safe,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::DisallowedEstimator { .. }))
        );
    }

    // ── Blocking: regret ─────────────────────────────────────────────

    #[test]
    fn excessive_regret_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Shadow allows up to 500_000 regret.
        input.regret_certificate = Some(make_regret_cert(600_000, 700_000, true, 600));
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
        );
    }

    #[test]
    fn regret_not_within_bound_blocks_canary() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        input.regret_certificate = Some(make_regret_cert(100_000, 200_000, false, 100));
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::RegretNotWithinBound))
        );
    }

    #[test]
    fn regret_not_within_bound_ok_for_shadow() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regret_certificate = Some(make_regret_cert(100_000, 200_000, false, 100));
        let output = gate.evaluate(&input).unwrap();
        // Shadow doesn't require within_bound.
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::RegretNotWithinBound))
        );
    }

    #[test]
    fn excessive_per_round_regret_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Config default: max per-round = 50_000.
        input.regret_certificate = Some(make_regret_cert(100_000, 200_000, true, 60_000));
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ExcessivePerRoundRegret { .. }))
        );
    }

    #[test]
    fn missing_regret_certificate_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regret_certificate = None;
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::MissingRegretCertificate))
        );
    }

    #[test]
    fn missing_regret_certificate_ok_when_not_required() {
        let config = CausalRegretGateConfig {
            require_regret_certificate: false,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regret_certificate = None;
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::MissingRegretCertificate))
        );
    }

    // ── Blocking: missing evaluation ─────────────────────────────────

    #[test]
    fn missing_evaluation_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations.clear();
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::MissingEvaluation))
        );
    }

    #[test]
    fn missing_evaluation_ok_when_not_required() {
        let config = CausalRegretGateConfig {
            require_evaluation: false,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations.clear();
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::MissingEvaluation))
        );
    }

    // ── Blocking: demotion history ───────────────────────────────────

    #[test]
    fn critical_demotions_block_canary() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        // Canary allows 0 critical demotions.
        input.demotion_history = vec![make_demotion(8, DemotionSeverity::Critical)];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::TooManyCriticalDemotions { .. }))
        );
        assert_eq!(output.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn advisory_demotions_tolerated_for_shadow() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Shadow allows 10 recent demotions.
        input.demotion_history = vec![
            make_demotion(8, DemotionSeverity::Advisory),
            make_demotion(9, DemotionSeverity::Advisory),
        ];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert_eq!(output.demotions_considered, 2);
    }

    #[test]
    fn too_many_demotions_blocks_production() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        // Production allows 0 recent demotions.
        input.demotion_history = vec![make_demotion(8, DemotionSeverity::Advisory)];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::TooManyDemotions { .. }))
        );
    }

    #[test]
    fn old_demotions_outside_lookback_ignored() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        // Epoch=10, lookback=5, so epoch < 5 is outside lookback.
        input.demotion_history = vec![make_demotion(3, DemotionSeverity::Critical)];
        let output = gate.evaluate(&input).unwrap();
        // Old demotion is outside lookback so not counted.
        assert_eq!(output.demotions_considered, 0);
        assert_eq!(output.critical_demotions_count, 0);
    }

    // ── Blocking: invalid stage progression ──────────────────────────

    #[test]
    fn invalid_progression_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.current_stage = MoonshotStage::Production; // backwards
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
        );
    }

    #[test]
    fn skip_stage_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Canary);
        input.current_stage = MoonshotStage::Research; // skipping Shadow
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::InvalidStageProgression { .. }))
        );
    }

    // ── Risk level classification ────────────────────────────────────

    #[test]
    fn risk_level_low_when_approved() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.risk_level, RiskLevel::Low);
    }

    #[test]
    fn risk_level_critical_for_unsafe() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Unsafe,
            -50_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn risk_level_high_for_production_blocking() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        // Production requires DoublyRobust. Use IPS.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::Ips,
            EnvelopeStatus::Safe,
            250_000,
            2_000,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.risk_level, RiskLevel::High);
    }

    #[test]
    fn risk_level_high_for_excessive_regret() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regret_certificate = Some(make_regret_cert(600_000, 700_000, true, 600));
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.risk_level, RiskLevel::High);
    }

    #[test]
    fn risk_level_medium_for_low_samples_when_approved() {
        let config = CausalRegretGateConfig {
            require_evaluation: true,
            require_regret_certificate: true,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Shadow requires 100 samples. Give 50 — but envelope still safe.
        // This will block on insufficient samples.
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::DoublyRobust,
            EnvelopeStatus::Safe,
            250_000,
            50,
        )];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.risk_level, RiskLevel::Medium);
    }

    // ── Multiple evaluations ─────────────────────────────────────────

    #[test]
    fn multiple_evaluations_all_safe() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![
            make_eval(
                "policy-a",
                EstimatorKind::DoublyRobust,
                EnvelopeStatus::Safe,
                200_000,
                500,
            ),
            make_eval(
                "policy-b",
                EstimatorKind::Ips,
                EnvelopeStatus::Safe,
                300_000,
                1_000,
            ),
        ];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Approved);
        assert_eq!(output.evaluation_summaries.len(), 2);
    }

    #[test]
    fn multiple_evaluations_one_unsafe() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = vec![
            make_eval(
                "policy-a",
                EstimatorKind::DoublyRobust,
                EnvelopeStatus::Safe,
                200_000,
                500,
            ),
            make_eval(
                "policy-b",
                EstimatorKind::Ips,
                EnvelopeStatus::Unsafe,
                -10_000,
                1_000,
            ),
        ];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
    }

    // ── Counter tracking ─────────────────────────────────────────────

    #[test]
    fn counters_track_correctly() {
        let mut gate = CausalRegretEvidenceGate::new();

        // Approved
        let input = basic_input(MoonshotStage::Shadow);
        gate.evaluate(&input).unwrap();
        assert_eq!(gate.evaluations_run(), 1);
        assert_eq!(gate.promotions_approved(), 1);

        // Denied
        let mut input2 = basic_input(MoonshotStage::Shadow);
        input2.evaluations.clear();
        gate.evaluate(&input2).unwrap();
        assert_eq!(gate.evaluations_run(), 2);
        assert_eq!(gate.promotions_denied(), 1);
    }

    #[test]
    fn reset_counters() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        gate.evaluate(&input).unwrap();
        gate.reset_counters();
        assert_eq!(gate.evaluations_run(), 0);
        assert_eq!(gate.promotions_approved(), 0);
        assert_eq!(gate.promotions_denied(), 0);
    }

    // ── Artifact hash determinism ────────────────────────────────────

    #[test]
    fn artifact_hash_deterministic() {
        let mut gate1 = CausalRegretEvidenceGate::new();
        let mut gate2 = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let o1 = gate1.evaluate(&input).unwrap();
        let o2 = gate2.evaluate(&input).unwrap();
        assert_eq!(o1.artifact_hash, o2.artifact_hash);
    }

    #[test]
    fn artifact_hash_changes_with_verdict() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input_ok = basic_input(MoonshotStage::Shadow);
        let o1 = gate.evaluate(&input_ok).unwrap();

        let mut input_bad = basic_input(MoonshotStage::Shadow);
        input_bad.evaluations.clear();
        let o2 = gate.evaluate(&input_bad).unwrap();

        assert_ne!(o1.artifact_hash, o2.artifact_hash);
    }

    #[test]
    fn artifact_hash_changes_with_timestamp() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input1 = basic_input(MoonshotStage::Shadow);
        input1.timestamp_ns = 1_000;
        let o1 = gate.evaluate(&input1).unwrap();

        let mut input2 = basic_input(MoonshotStage::Shadow);
        input2.timestamp_ns = 2_000;
        let o2 = gate.evaluate(&input2).unwrap();

        assert_ne!(o1.artifact_hash, o2.artifact_hash);
    }

    // ── Error cases ──────────────────────────────────────────────────

    #[test]
    fn too_many_evaluations_error() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = (0..101)
            .map(|i| {
                make_eval(
                    &format!("policy-{i}"),
                    EstimatorKind::DoublyRobust,
                    EnvelopeStatus::Safe,
                    250_000,
                    2_000,
                )
            })
            .collect();
        let err = gate.evaluate(&input).unwrap_err();
        assert!(matches!(
            err,
            CausalRegretGateError::TooManyEvaluations { .. }
        ));
    }

    #[test]
    fn too_many_demotion_items_error() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.demotion_history = (0..1001)
            .map(|i| make_demotion(i, DemotionSeverity::Advisory))
            .collect();
        let err = gate.evaluate(&input).unwrap_err();
        assert!(matches!(
            err,
            CausalRegretGateError::TooManyDemotionItems { .. }
        ));
    }

    // ── Display impls ────────────────────────────────────────────────

    #[test]
    fn blocking_reason_display_all() {
        let reasons = vec![
            BlockingReason::UnsafeEnvelope {
                policy_id: "p".into(),
                estimator: EstimatorKind::Ips,
            },
            BlockingReason::InconclusiveEnvelope {
                policy_id: "p".into(),
                estimator: EstimatorKind::DoublyRobust,
            },
            BlockingReason::InsufficientConfidence {
                observed_millionths: 10,
                required_millionths: 100,
            },
            BlockingReason::InsufficientSamples {
                observed: 5,
                required: 100,
            },
            BlockingReason::DisallowedEstimator {
                estimator: EstimatorKind::DirectMethod,
            },
            BlockingReason::MissingRegretCertificate,
            BlockingReason::ExcessiveRegret {
                realized_millionths: 500,
                max_millionths: 100,
            },
            BlockingReason::ExcessivePerRoundRegret {
                per_round_millionths: 500,
                max_millionths: 100,
            },
            BlockingReason::RegretNotWithinBound,
            BlockingReason::TooManyCriticalDemotions { count: 3, max: 0 },
            BlockingReason::TooManyDemotions { count: 5, max: 2 },
            BlockingReason::MissingEvaluation,
            BlockingReason::InvalidStageProgression {
                current: MoonshotStage::Production,
                target: MoonshotStage::Research,
            },
        ];
        for r in &reasons {
            let s = format!("{r}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn error_display_all() {
        let errors = vec![
            CausalRegretGateError::TooManyEvaluations {
                count: 200,
                max: 100,
            },
            CausalRegretGateError::TooManyDemotionItems {
                count: 2000,
                max: 1000,
            },
            CausalRegretGateError::InvalidConfig {
                reason: "bad".into(),
            },
        ];
        for e in &errors {
            let s = format!("{e}");
            assert!(!s.is_empty());
        }
    }

    // ── Schema and component ─────────────────────────────────────────

    #[test]
    fn output_has_correct_schema() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.schema_version, CAUSAL_REGRET_GATE_SCHEMA_VERSION);
        assert_eq!(output.component, CAUSAL_REGRET_GATE_COMPONENT);
    }

    #[test]
    fn output_carries_moonshot_id() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.moonshot_id, Some("moonshot-1".into()));
    }

    #[test]
    fn output_carries_regime() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Shadow);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.regime, RegimeKind::Stochastic);
    }

    // ── Multiple blocking reasons accumulate ─────────────────────────

    #[test]
    fn multiple_blocking_reasons_accumulate() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Production);
        input.current_stage = MoonshotStage::Research; // skip stages
        input.evaluations = vec![make_eval(
            "policy-1",
            EstimatorKind::Ips, // disallowed for production
            EnvelopeStatus::Unsafe,
            -50_000, // insufficient confidence
            100,     // insufficient samples
        )];
        input.regret_certificate = None; // missing
        input.demotion_history = vec![make_demotion(9, DemotionSeverity::Critical)];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.verdict, GateVerdict::Denied);
        // Should have many blocking reasons.
        assert!(output.blocking_reasons.len() >= 5);
    }

    // ── Edge: zero-epoch demotion lookback ────────────────────────────

    #[test]
    fn zero_epoch_demotion_lookback() {
        let config = CausalRegretGateConfig {
            demotion_lookback_epochs: 0,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Production);
        // Only epoch==10 (same as current) should be in lookback.
        input.demotion_history = vec![
            make_demotion(10, DemotionSeverity::Advisory),
            make_demotion(9, DemotionSeverity::Advisory),
        ];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.demotions_considered, 1);
    }

    // ── Edge: large demotion lookback ────────────────────────────────

    #[test]
    fn large_lookback_includes_all() {
        let config = CausalRegretGateConfig {
            demotion_lookback_epochs: 100,
            ..Default::default()
        };
        let mut gate = CausalRegretEvidenceGate::with_config(config).unwrap();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.demotion_history = vec![
            make_demotion(1, DemotionSeverity::Advisory),
            make_demotion(5, DemotionSeverity::Advisory),
            make_demotion(10, DemotionSeverity::Advisory),
        ];
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.demotions_considered, 3);
    }

    // ── StageThresholds serde roundtrip ──────────────────────────────

    #[test]
    fn stage_thresholds_serde_roundtrip() {
        for stage in MoonshotStage::all() {
            let t = StageThresholds::for_stage(*stage);
            let json = serde_json::to_string(&t).unwrap();
            let restored: StageThresholds = serde_json::from_str(&json).unwrap();
            assert_eq!(t, restored);
        }
    }

    // ── EvaluationSummary serde ──────────────────────────────────────

    #[test]
    fn evaluation_summary_serde_roundtrip() {
        let summary = EvaluationSummary {
            policy_id: PolicyId("test".into()),
            estimator: EstimatorKind::DoublyRobust,
            safety_status: EnvelopeStatus::Safe,
            improvement_lower_millionths: 100_000,
            effective_samples: 500,
            artifact_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: EvaluationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    // ── RegretSummary serde ──────────────────────────────────────────

    #[test]
    fn regret_summary_serde_roundtrip() {
        let summary = RegretSummary {
            rounds: 1000,
            realized_regret_millionths: 50_000,
            theoretical_bound_millionths: 100_000,
            within_bound: true,
            per_round_regret_millionths: 50,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: RegretSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    // ── DemotionHistoryItem serde ────────────────────────────────────

    #[test]
    fn demotion_history_item_serde_roundtrip() {
        let item = make_demotion(5, DemotionSeverity::Warning);
        let json = serde_json::to_string(&item).unwrap();
        let restored: DemotionHistoryItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, restored);
    }

    // ── BlockingReason ordering ──────────────────────────────────────

    #[test]
    fn blocking_reason_eq() {
        let a = BlockingReason::MissingEvaluation;
        let b = BlockingReason::MissingRegretCertificate;
        assert_ne!(a, b);
        assert_eq!(a, BlockingReason::MissingEvaluation);
    }

    // ── GateInput serde ──────────────────────────────────────────────

    #[test]
    fn gate_input_serde_roundtrip() {
        let input = basic_input(MoonshotStage::Shadow);
        let json = serde_json::to_string(&input).unwrap();
        let restored: GateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    // ── Adversarial regime integration ───────────────────────────────

    #[test]
    fn adversarial_regime_propagated() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regime = RegimeKind::Adversarial;
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.regime, RegimeKind::Adversarial);
    }

    // ── Empty demotion history ───────────────────────────────────────

    #[test]
    fn empty_demotion_history_ok() {
        let mut gate = CausalRegretEvidenceGate::new();
        let input = basic_input(MoonshotStage::Production);
        let output = gate.evaluate(&input).unwrap();
        assert_eq!(output.demotions_considered, 0);
        assert_eq!(output.critical_demotions_count, 0);
    }

    // ── Boundary: regret exactly at threshold ────────────────────────

    #[test]
    fn regret_exactly_at_threshold_passes() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Shadow max = 500_000. Exactly 500_000 should pass.
        input.regret_certificate = Some(make_regret_cert(500_000, 600_000, true, 50));
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
        );
    }

    #[test]
    fn regret_one_above_threshold_blocks() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        input.regret_certificate = Some(make_regret_cert(500_001, 600_000, true, 50));
        let output = gate.evaluate(&input).unwrap();
        assert!(
            output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ExcessiveRegret { .. }))
        );
    }

    // ── Boundary: per-round regret at threshold ──────────────────────

    #[test]
    fn per_round_regret_exactly_at_threshold_passes() {
        let mut gate = CausalRegretEvidenceGate::new();
        let mut input = basic_input(MoonshotStage::Shadow);
        // Config default per-round max = 50_000.
        input.regret_certificate = Some(make_regret_cert(100_000, 200_000, true, 50_000));
        let output = gate.evaluate(&input).unwrap();
        assert!(
            !output
                .blocking_reasons
                .iter()
                .any(|r| matches!(r, BlockingReason::ExcessivePerRoundRegret { .. }))
        );
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn demotion_history_item_enrichment_serde_roundtrip() {
        let item = make_demotion(5, DemotionSeverity::Critical);
        let json = serde_json::to_string(&item).unwrap();
        let back: DemotionHistoryItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn blocking_reason_serde_roundtrip_all_variants() {
        let variants: Vec<BlockingReason> = vec![
            BlockingReason::UnsafeEnvelope {
                policy_id: "p".into(),
                estimator: EstimatorKind::DoublyRobust,
            },
            BlockingReason::InconclusiveEnvelope {
                policy_id: "p".into(),
                estimator: EstimatorKind::Ips,
            },
            BlockingReason::InsufficientConfidence {
                observed_millionths: 100,
                required_millionths: 200,
            },
            BlockingReason::InsufficientSamples {
                observed: 10,
                required: 100,
            },
            BlockingReason::DisallowedEstimator {
                estimator: EstimatorKind::DirectMethod,
            },
            BlockingReason::MissingRegretCertificate,
            BlockingReason::ExcessiveRegret {
                realized_millionths: 500,
                max_millionths: 200,
            },
            BlockingReason::ExcessivePerRoundRegret {
                per_round_millionths: 100,
                max_millionths: 50,
            },
            BlockingReason::RegretNotWithinBound,
            BlockingReason::TooManyCriticalDemotions { count: 3, max: 2 },
            BlockingReason::TooManyDemotions { count: 5, max: 3 },
            BlockingReason::MissingEvaluation,
            BlockingReason::InvalidStageProgression {
                current: MoonshotStage::Production,
                target: MoonshotStage::Research,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: BlockingReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn causal_regret_gate_error_serde_roundtrip_all_variants() {
        let variants: Vec<CausalRegretGateError> = vec![
            CausalRegretGateError::TooManyEvaluations {
                count: 200,
                max: 100,
            },
            CausalRegretGateError::TooManyDemotionItems {
                count: 2000,
                max: 1000,
            },
            CausalRegretGateError::InvalidConfig {
                reason: "bad".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CausalRegretGateError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn gate_input_serde_roundtrip_empty_evaluations() {
        let mut input = basic_input(MoonshotStage::Shadow);
        input.evaluations = Vec::new();
        let json = serde_json::to_string(&input).unwrap();
        let back: GateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }
}
