//! Moonshot contract schema for portfolio governance.
//!
//! Every moonshot initiative carries a machine-readable contract
//! specifying hypothesis, target metrics, expected-value model, risk
//! budget, artifact obligations, kill criteria, and rollback plan.
//! This makes governance machine-enforceable rather than aspirational.
//!
//! Contracts are versioned and canonically encoded for content-addressable
//! identity.  Creation and amendments require signed governance approval.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.15, subsection 9I.3 (Moonshot Portfolio
//! Governor), item 1 of 3.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// MoonshotStage — initiative lifecycle stages
// ---------------------------------------------------------------------------

/// Stage in the moonshot lifecycle.
///
/// Stages progress linearly: research → shadow → canary → production.
/// Each stage has per-stage artifact requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MoonshotStage {
    /// Exploratory research and proof-of-concept.
    Research = 0,
    /// Shadow-mode deployment for observation without live impact.
    Shadow = 1,
    /// Canary deployment to a limited subset of fleet.
    Canary = 2,
    /// Full production deployment.
    Production = 3,
}

impl MoonshotStage {
    /// All stages in progression order.
    pub fn all() -> &'static [MoonshotStage] {
        &[Self::Research, Self::Shadow, Self::Canary, Self::Production]
    }
}

impl fmt::Display for MoonshotStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Research => write!(f, "research"),
            Self::Shadow => write!(f, "shadow"),
            Self::Canary => write!(f, "canary"),
            Self::Production => write!(f, "production"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hypothesis — structured moonshot thesis
// ---------------------------------------------------------------------------

/// Structured hypothesis for a moonshot initiative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Problem statement: what gap or failure mode is being addressed.
    pub problem: String,
    /// Proposed mechanism: how the initiative addresses the problem.
    pub mechanism: String,
    /// Expected outcome: measurable result if the hypothesis holds.
    pub expected_outcome: String,
    /// Falsification criteria: what evidence would disprove the hypothesis.
    pub falsification_criteria: Vec<String>,
}

impl Hypothesis {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.problem.is_empty() {
            return Err(ContractError::InvalidHypothesis {
                reason: "problem statement is empty".into(),
            });
        }
        if self.mechanism.is_empty() {
            return Err(ContractError::InvalidHypothesis {
                reason: "mechanism is empty".into(),
            });
        }
        if self.expected_outcome.is_empty() {
            return Err(ContractError::InvalidHypothesis {
                reason: "expected outcome is empty".into(),
            });
        }
        if self.falsification_criteria.is_empty() {
            return Err(ContractError::InvalidHypothesis {
                reason: "falsification criteria must not be empty".into(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TargetMetric — success metrics
// ---------------------------------------------------------------------------

/// Method for measuring a target metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MeasurementMethod {
    /// Automated benchmark suite.
    Benchmark,
    /// Evidence ledger query.
    EvidenceQuery,
    /// Fleet telemetry aggregation.
    FleetTelemetry,
    /// Manual operator review.
    OperatorReview,
}

impl fmt::Display for MeasurementMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Benchmark => write!(f, "benchmark"),
            Self::EvidenceQuery => write!(f, "evidence_query"),
            Self::FleetTelemetry => write!(f, "fleet_telemetry"),
            Self::OperatorReview => write!(f, "operator_review"),
        }
    }
}

/// Direction of success for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricDirection {
    /// Higher values are better (e.g., detection rate).
    HigherIsBetter,
    /// Lower values are better (e.g., false positive rate).
    LowerIsBetter,
}

/// A typed success metric with threshold and evaluation cadence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetMetric {
    /// Unique metric identifier.
    pub metric_id: String,
    /// Human-readable description.
    pub description: String,
    /// Success threshold in millionths.
    pub threshold_millionths: i64,
    /// Direction of improvement.
    pub direction: MetricDirection,
    /// How the metric is measured.
    pub measurement_method: MeasurementMethod,
    /// Evaluation interval in nanoseconds.
    pub evaluation_cadence_ns: u64,
}

// ---------------------------------------------------------------------------
// EvModel — expected-value model
// ---------------------------------------------------------------------------

/// Distribution type for outcome modeling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DistributionType {
    /// Point estimate (single value).
    PointEstimate,
    /// Uniform distribution over a range.
    Uniform,
    /// Beta distribution (for probabilities).
    Beta,
    /// Log-normal distribution (for positive quantities).
    LogNormal,
}

impl fmt::Display for DistributionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PointEstimate => write!(f, "point_estimate"),
            Self::Uniform => write!(f, "uniform"),
            Self::Beta => write!(f, "beta"),
            Self::LogNormal => write!(f, "log_normal"),
        }
    }
}

/// Expected-value model for a moonshot initiative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvModel {
    /// Distribution type for success probability.
    pub success_distribution: DistributionType,
    /// Distribution parameters in millionths (semantics depend on type).
    /// For PointEstimate: single "value" key.
    /// For Beta: "alpha" and "beta" keys.
    /// For Uniform: "low" and "high" keys.
    /// For LogNormal: "mu" and "sigma" keys.
    pub distribution_params: BTreeMap<String, i64>,
    /// Cost of the initiative in millionths (budget units).
    pub cost_millionths: i64,
    /// Expected benefit on success in millionths (benefit units).
    pub benefit_on_success_millionths: i64,
    /// Expected harm on failure in millionths.
    pub harm_on_failure_millionths: i64,
}

impl EvModel {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.cost_millionths <= 0 {
            return Err(ContractError::InvalidEvModel {
                reason: "cost must be positive".into(),
            });
        }
        // Validate distribution parameters.
        match self.success_distribution {
            DistributionType::PointEstimate => {
                if !self.distribution_params.contains_key("value") {
                    return Err(ContractError::InvalidEvModel {
                        reason: "PointEstimate requires 'value' parameter".into(),
                    });
                }
            }
            DistributionType::Beta => {
                if !self.distribution_params.contains_key("alpha")
                    || !self.distribution_params.contains_key("beta")
                {
                    return Err(ContractError::InvalidEvModel {
                        reason: "Beta requires 'alpha' and 'beta' parameters".into(),
                    });
                }
            }
            DistributionType::Uniform => {
                if !self.distribution_params.contains_key("low")
                    || !self.distribution_params.contains_key("high")
                {
                    return Err(ContractError::InvalidEvModel {
                        reason: "Uniform requires 'low' and 'high' parameters".into(),
                    });
                }
            }
            DistributionType::LogNormal => {
                if !self.distribution_params.contains_key("mu")
                    || !self.distribution_params.contains_key("sigma")
                {
                    return Err(ContractError::InvalidEvModel {
                        reason: "LogNormal requires 'mu' and 'sigma' parameters".into(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Compute a simple net-EV estimate for PointEstimate distribution.
    ///
    /// net_EV = P(success) * benefit - (1 - P(success)) * |harm| - cost
    ///
    /// Uses i128 intermediates to prevent overflow.
    pub fn net_ev_point_estimate(&self) -> Result<i64, ContractError> {
        if self.success_distribution != DistributionType::PointEstimate {
            return Err(ContractError::InvalidEvModel {
                reason: "net_ev_point_estimate only works with PointEstimate".into(),
            });
        }
        let p = *self.distribution_params.get("value").ok_or_else(|| {
            ContractError::InvalidEvModel {
                reason: "missing 'value' parameter".into(),
            }
        })?;
        let benefit = self.benefit_on_success_millionths as i128;
        let harm = self.harm_on_failure_millionths.unsigned_abs() as i128;
        let cost = self.cost_millionths as i128;
        let p128 = p as i128;
        let one_million = 1_000_000i128;

        // net_EV = p * benefit / 1M - (1M - p) * harm / 1M - cost
        let ev_success = p128 * benefit / one_million;
        let ev_failure = (one_million - p128) * harm / one_million;
        let net = ev_success - ev_failure - cost;

        Ok(net.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
    }
}

// ---------------------------------------------------------------------------
// RiskBudget — maximum tolerable risk
// ---------------------------------------------------------------------------

/// Risk dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskDimension {
    /// Risk of security regression.
    SecurityRegression,
    /// Risk of performance regression.
    PerformanceRegression,
    /// Operational burden increase.
    OperationalBurden,
    /// Interference with other initiatives.
    CrossInitiativeInterference,
}

impl fmt::Display for RiskDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityRegression => write!(f, "security_regression"),
            Self::PerformanceRegression => write!(f, "performance_regression"),
            Self::OperationalBurden => write!(f, "operational_burden"),
            Self::CrossInitiativeInterference => write!(f, "cross_initiative_interference"),
        }
    }
}

/// Maximum tolerable risk budget across dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBudget {
    /// Per-dimension risk caps in millionths.
    pub dimension_caps: BTreeMap<RiskDimension, u64>,
}

impl RiskBudget {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.dimension_caps.is_empty() {
            return Err(ContractError::InvalidRiskBudget {
                reason: "risk budget must have at least one dimension".into(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArtifactObligation — mandatory deliverables per stage
// ---------------------------------------------------------------------------

/// Type of artifact required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactType {
    /// Proof artifact (formal or semi-formal).
    Proof,
    /// Benchmark result bundle.
    BenchmarkResult,
    /// Conformance evidence.
    ConformanceEvidence,
    /// Operator documentation.
    OperatorDocumentation,
    /// Risk assessment report.
    RiskAssessment,
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof => write!(f, "proof"),
            Self::BenchmarkResult => write!(f, "benchmark_result"),
            Self::ConformanceEvidence => write!(f, "conformance_evidence"),
            Self::OperatorDocumentation => write!(f, "operator_documentation"),
            Self::RiskAssessment => write!(f, "risk_assessment"),
        }
    }
}

/// A mandatory deliverable at a specific stage gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactObligation {
    /// Unique obligation identifier.
    pub obligation_id: String,
    /// Stage at which this artifact is required.
    pub required_at_stage: MoonshotStage,
    /// Type of artifact.
    pub artifact_type: ArtifactType,
    /// Human-readable description.
    pub description: String,
    /// Whether this obligation is blocking for stage promotion.
    pub blocking: bool,
}

// ---------------------------------------------------------------------------
// KillCriterion — automatic termination conditions
// ---------------------------------------------------------------------------

/// Type of kill trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KillTrigger {
    /// Budget exhausted without meaningful signal.
    BudgetExhaustedNoSignal,
    /// Metric regression beyond threshold.
    MetricRegression,
    /// Reproducibility failure.
    ReproducibilityFailure,
    /// Risk constraint violation.
    RiskConstraintViolation,
    /// Time-bound expiry without promotion.
    TimeExpiry,
}

impl fmt::Display for KillTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhaustedNoSignal => write!(f, "budget_exhausted_no_signal"),
            Self::MetricRegression => write!(f, "metric_regression"),
            Self::ReproducibilityFailure => write!(f, "reproducibility_failure"),
            Self::RiskConstraintViolation => write!(f, "risk_constraint_violation"),
            Self::TimeExpiry => write!(f, "time_expiry"),
        }
    }
}

/// An automatic termination condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillCriterion {
    /// Unique criterion identifier.
    pub criterion_id: String,
    /// Type of trigger.
    pub trigger: KillTrigger,
    /// Human-readable description of the condition.
    pub condition: String,
    /// Threshold in millionths (semantics depend on trigger type).
    pub threshold_millionths: Option<i64>,
    /// Maximum duration before kill (nanoseconds; for TimeExpiry).
    pub max_duration_ns: Option<u64>,
}

// ---------------------------------------------------------------------------
// RollbackPlan — deterministic rollback procedure
// ---------------------------------------------------------------------------

/// A step in the rollback procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackStep {
    /// Step sequence number (1-indexed).
    pub step_number: u32,
    /// Human-readable description.
    pub description: String,
    /// Verification command or artifact reference.
    pub verification: String,
}

/// Deterministic rollback procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    /// Ordered rollback steps.
    pub steps: Vec<RollbackStep>,
    /// Artifact references for rollback state.
    pub artifact_references: Vec<String>,
    /// Description of expected state after rollback.
    pub expected_state_after_rollback: String,
}

impl RollbackPlan {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.steps.is_empty() {
            return Err(ContractError::InvalidRollback {
                reason: "rollback plan must have at least one step".into(),
            });
        }
        if self.expected_state_after_rollback.is_empty() {
            return Err(ContractError::InvalidRollback {
                reason: "expected state after rollback is empty".into(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ContractVersion — versioned contract identity
// ---------------------------------------------------------------------------

/// Versioned contract identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// MoonshotContract — top-level contract
// ---------------------------------------------------------------------------

/// Complete moonshot contract.
///
/// Every moonshot initiative must carry this contract with all fields
/// populated.  The contract is content-addressable via canonical
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotContract {
    /// Unique contract identifier.
    pub contract_id: String,
    /// Contract version.
    pub version: ContractVersion,
    /// Structured hypothesis.
    pub hypothesis: Hypothesis,
    /// Target success metrics.
    pub target_metrics: Vec<TargetMetric>,
    /// Expected-value model.
    pub ev_model: EvModel,
    /// Risk budget.
    pub risk_budget: RiskBudget,
    /// Artifact obligations per stage gate.
    pub artifact_obligations: Vec<ArtifactObligation>,
    /// Kill criteria (automatic termination conditions).
    pub kill_criteria: Vec<KillCriterion>,
    /// Rollback plan.
    pub rollback_plan: RollbackPlan,
    /// Current stage.
    pub current_stage: MoonshotStage,
    /// Security epoch when contract was created.
    pub epoch: SecurityEpoch,
    /// Governance approval signature.
    pub governance_signature: Option<String>,
    /// Additional metadata (deterministic ordering).
    pub metadata: BTreeMap<String, String>,
}

impl MoonshotContract {
    /// Validate the entire contract.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_id.is_empty() {
            return Err(ContractError::EmptyContractId);
        }
        self.hypothesis.validate()?;
        if self.target_metrics.is_empty() {
            return Err(ContractError::EmptyTargetMetrics);
        }
        self.ev_model.validate()?;
        self.risk_budget.validate()?;
        if self.kill_criteria.is_empty() {
            return Err(ContractError::EmptyKillCriteria);
        }
        self.rollback_plan.validate()?;
        Ok(())
    }

    /// Check whether all artifact obligations for a given stage are met.
    ///
    /// `completed_artifacts` is the set of completed obligation IDs.
    pub fn stage_obligations_met(
        &self,
        stage: MoonshotStage,
        completed_artifacts: &[String],
    ) -> bool {
        self.artifact_obligations
            .iter()
            .filter(|o| o.required_at_stage == stage && o.blocking)
            .all(|o| completed_artifacts.contains(&o.obligation_id))
    }

    /// Check if any kill criterion is triggered.
    ///
    /// `current_metrics` maps metric_id to current value in millionths.
    /// `elapsed_ns` is time since initiative start.
    /// `budget_spent_fraction_millionths` is fraction of budget consumed.
    pub fn check_kill_criteria(
        &self,
        current_metrics: &BTreeMap<String, i64>,
        elapsed_ns: u64,
        budget_spent_fraction_millionths: u64,
    ) -> Vec<&KillCriterion> {
        let mut triggered = Vec::new();
        for criterion in &self.kill_criteria {
            match criterion.trigger {
                KillTrigger::BudgetExhaustedNoSignal => {
                    // Budget >= 90% spent with no metrics improving.
                    if budget_spent_fraction_millionths >= 900_000
                        && !self.any_metric_improving(current_metrics)
                    {
                        triggered.push(criterion);
                    }
                }
                KillTrigger::MetricRegression => {
                    if let Some(threshold) = criterion.threshold_millionths {
                        for metric in &self.target_metrics {
                            if let Some(&current) = current_metrics.get(&metric.metric_id) {
                                let regressed = match metric.direction {
                                    MetricDirection::HigherIsBetter => current < threshold,
                                    MetricDirection::LowerIsBetter => current > threshold,
                                };
                                if regressed {
                                    triggered.push(criterion);
                                    break;
                                }
                            }
                        }
                    }
                }
                KillTrigger::TimeExpiry => {
                    if let Some(max_ns) = criterion.max_duration_ns
                        && elapsed_ns > max_ns
                    {
                        triggered.push(criterion);
                    }
                }
                KillTrigger::RiskConstraintViolation | KillTrigger::ReproducibilityFailure => {
                    // These are triggered externally; not auto-evaluated here.
                }
            }
        }
        triggered
    }

    /// Check if any target metric is improving (above threshold for
    /// higher-is-better, below threshold for lower-is-better).
    fn any_metric_improving(&self, current_metrics: &BTreeMap<String, i64>) -> bool {
        for metric in &self.target_metrics {
            if let Some(&current) = current_metrics.get(&metric.metric_id) {
                let improving = match metric.direction {
                    MetricDirection::HigherIsBetter => current > metric.threshold_millionths,
                    MetricDirection::LowerIsBetter => current < metric.threshold_millionths,
                };
                if improving {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// ContractError — validation errors
// ---------------------------------------------------------------------------

/// Errors arising from moonshot contract operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractError {
    EmptyContractId,
    InvalidHypothesis { reason: String },
    EmptyTargetMetrics,
    InvalidEvModel { reason: String },
    InvalidRiskBudget { reason: String },
    EmptyKillCriteria,
    InvalidRollback { reason: String },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyContractId => write!(f, "contract ID is empty"),
            Self::InvalidHypothesis { reason } => {
                write!(f, "invalid hypothesis: {reason}")
            }
            Self::EmptyTargetMetrics => write!(f, "target metrics must not be empty"),
            Self::InvalidEvModel { reason } => {
                write!(f, "invalid EV model: {reason}")
            }
            Self::InvalidRiskBudget { reason } => {
                write!(f, "invalid risk budget: {reason}")
            }
            Self::EmptyKillCriteria => write!(f, "kill criteria must not be empty"),
            Self::InvalidRollback { reason } => {
                write!(f, "invalid rollback plan: {reason}")
            }
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn test_hypothesis() -> Hypothesis {
        Hypothesis {
            problem: "Detection latency too high for supply-chain attacks".into(),
            mechanism: "Fleet-wide evidence sharing reduces time-to-detection".into(),
            expected_outcome: "50% reduction in median detection latency".into(),
            falsification_criteria: vec![
                "No latency improvement after 90 days of deployment".into(),
                "Detection accuracy degrades below 95%".into(),
            ],
        }
    }

    fn test_metrics() -> Vec<TargetMetric> {
        vec![
            TargetMetric {
                metric_id: "detection_latency_p50".into(),
                description: "Median detection latency in milliseconds".into(),
                threshold_millionths: 250_000_000, // 250ms
                direction: MetricDirection::LowerIsBetter,
                measurement_method: MeasurementMethod::FleetTelemetry,
                evaluation_cadence_ns: 86_400_000_000_000, // daily
            },
            TargetMetric {
                metric_id: "false_positive_rate".into(),
                description: "False positive rate".into(),
                threshold_millionths: 10_000, // 0.01 = 1%
                direction: MetricDirection::LowerIsBetter,
                measurement_method: MeasurementMethod::EvidenceQuery,
                evaluation_cadence_ns: 86_400_000_000_000,
            },
        ]
    }

    fn test_ev_model() -> EvModel {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 600_000i64); // 0.6 probability
        EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 500_000,                 // 0.5 budget units
            benefit_on_success_millionths: 5_000_000, // 5.0 benefit
            harm_on_failure_millionths: -200_000,     // -0.2 harm
        }
    }

    fn test_risk_budget() -> RiskBudget {
        let mut caps = BTreeMap::new();
        caps.insert(RiskDimension::SecurityRegression, 50_000u64);
        caps.insert(RiskDimension::PerformanceRegression, 100_000u64);
        RiskBudget {
            dimension_caps: caps,
        }
    }

    fn test_obligations() -> Vec<ArtifactObligation> {
        vec![
            ArtifactObligation {
                obligation_id: "proof-research".into(),
                required_at_stage: MoonshotStage::Research,
                artifact_type: ArtifactType::Proof,
                description: "Proof of concept results".into(),
                blocking: true,
            },
            ArtifactObligation {
                obligation_id: "bench-shadow".into(),
                required_at_stage: MoonshotStage::Shadow,
                artifact_type: ArtifactType::BenchmarkResult,
                description: "Shadow-mode benchmark results".into(),
                blocking: true,
            },
        ]
    }

    fn test_kill_criteria() -> Vec<KillCriterion> {
        vec![
            KillCriterion {
                criterion_id: "budget-kill".into(),
                trigger: KillTrigger::BudgetExhaustedNoSignal,
                condition: "90% budget spent with no metric improvement".into(),
                threshold_millionths: None,
                max_duration_ns: None,
            },
            KillCriterion {
                criterion_id: "time-kill".into(),
                trigger: KillTrigger::TimeExpiry,
                condition: "180 days without stage promotion".into(),
                threshold_millionths: None,
                max_duration_ns: Some(15_552_000_000_000_000), // 180 days
            },
            KillCriterion {
                criterion_id: "regression-kill".into(),
                trigger: KillTrigger::MetricRegression,
                condition: "Detection latency exceeds 500ms".into(),
                threshold_millionths: Some(500_000_000), // 500ms
                max_duration_ns: None,
            },
        ]
    }

    fn test_rollback() -> RollbackPlan {
        RollbackPlan {
            steps: vec![
                RollbackStep {
                    step_number: 1,
                    description: "Disable fleet evidence sharing".into(),
                    verification: "frankenctl feature disable fleet-evidence".into(),
                },
                RollbackStep {
                    step_number: 2,
                    description: "Restore previous detection policy".into(),
                    verification: "frankenctl policy revert --to checkpoint-X".into(),
                },
            ],
            artifact_references: vec!["checkpoint-X".into()],
            expected_state_after_rollback: "Pre-moonshot detection pipeline restored".into(),
        }
    }

    fn test_contract() -> MoonshotContract {
        MoonshotContract {
            contract_id: "mc-fleet-evidence-001".into(),
            version: ContractVersion { major: 1, minor: 0 },
            hypothesis: test_hypothesis(),
            target_metrics: test_metrics(),
            ev_model: test_ev_model(),
            risk_budget: test_risk_budget(),
            artifact_obligations: test_obligations(),
            kill_criteria: test_kill_criteria(),
            rollback_plan: test_rollback(),
            current_stage: MoonshotStage::Research,
            epoch: SecurityEpoch::from_raw(1),
            governance_signature: Some("sig:gov-approval".into()),
            metadata: BTreeMap::new(),
        }
    }

    // -- Validation tests --

    #[test]
    fn contract_validates_ok() {
        test_contract().validate().unwrap();
    }

    #[test]
    fn contract_rejects_empty_id() {
        let mut c = test_contract();
        c.contract_id = String::new();
        assert!(matches!(c.validate(), Err(ContractError::EmptyContractId)));
    }

    #[test]
    fn contract_rejects_empty_hypothesis_problem() {
        let mut c = test_contract();
        c.hypothesis.problem = String::new();
        assert!(matches!(
            c.validate(),
            Err(ContractError::InvalidHypothesis { .. })
        ));
    }

    #[test]
    fn contract_rejects_empty_falsification() {
        let mut c = test_contract();
        c.hypothesis.falsification_criteria = vec![];
        assert!(matches!(
            c.validate(),
            Err(ContractError::InvalidHypothesis { .. })
        ));
    }

    #[test]
    fn contract_rejects_empty_metrics() {
        let mut c = test_contract();
        c.target_metrics = vec![];
        assert!(matches!(
            c.validate(),
            Err(ContractError::EmptyTargetMetrics)
        ));
    }

    #[test]
    fn contract_rejects_empty_kill_criteria() {
        let mut c = test_contract();
        c.kill_criteria = vec![];
        assert!(matches!(
            c.validate(),
            Err(ContractError::EmptyKillCriteria)
        ));
    }

    #[test]
    fn contract_rejects_empty_rollback() {
        let mut c = test_contract();
        c.rollback_plan.steps = vec![];
        assert!(matches!(
            c.validate(),
            Err(ContractError::InvalidRollback { .. })
        ));
    }

    // -- EV model tests --

    #[test]
    fn ev_model_validates_ok() {
        test_ev_model().validate().unwrap();
    }

    #[test]
    fn ev_model_rejects_zero_cost() {
        let mut ev = test_ev_model();
        ev.cost_millionths = 0;
        assert!(matches!(
            ev.validate(),
            Err(ContractError::InvalidEvModel { .. })
        ));
    }

    #[test]
    fn ev_model_rejects_missing_params() {
        let ev = EvModel {
            success_distribution: DistributionType::Beta,
            distribution_params: BTreeMap::new(),
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        assert!(matches!(
            ev.validate(),
            Err(ContractError::InvalidEvModel { .. })
        ));
    }

    #[test]
    fn ev_model_net_ev_point_estimate() {
        let ev = test_ev_model();
        // P=0.6, benefit=5.0, harm=0.2, cost=0.5
        // EV = 0.6*5.0 - 0.4*0.2 - 0.5 = 3.0 - 0.08 - 0.5 = 2.42
        // In millionths: 2_420_000
        let net = ev.net_ev_point_estimate().unwrap();
        assert_eq!(net, 2_420_000);
    }

    #[test]
    fn ev_model_net_ev_rejects_non_point() {
        let mut ev = test_ev_model();
        ev.success_distribution = DistributionType::Beta;
        ev.distribution_params.insert("alpha".into(), 2_000_000);
        ev.distribution_params.insert("beta".into(), 3_000_000);
        assert!(ev.net_ev_point_estimate().is_err());
    }

    // -- Risk budget tests --

    #[test]
    fn risk_budget_validates_ok() {
        test_risk_budget().validate().unwrap();
    }

    #[test]
    fn risk_budget_rejects_empty() {
        let rb = RiskBudget {
            dimension_caps: BTreeMap::new(),
        };
        assert!(matches!(
            rb.validate(),
            Err(ContractError::InvalidRiskBudget { .. })
        ));
    }

    // -- Stage obligation tests --

    #[test]
    fn stage_obligations_met_when_completed() {
        let c = test_contract();
        assert!(c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
    }

    #[test]
    fn stage_obligations_not_met_when_missing() {
        let c = test_contract();
        assert!(!c.stage_obligations_met(MoonshotStage::Research, &[]));
    }

    #[test]
    fn stage_obligations_met_no_obligations() {
        let c = test_contract();
        // Canary has no obligations in test data.
        assert!(c.stage_obligations_met(MoonshotStage::Canary, &[]));
    }

    // -- Kill criteria tests --

    #[test]
    fn kill_criteria_time_expiry() {
        let c = test_contract();
        let metrics = BTreeMap::new();
        // 200 days > 180 days limit.
        let triggered = c.check_kill_criteria(
            &metrics,
            17_280_000_000_000_000, // 200 days
            0,
        );
        assert!(
            triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::TimeExpiry)
        );
    }

    #[test]
    fn kill_criteria_no_trigger_when_under_limit() {
        let c = test_contract();
        let mut metrics = BTreeMap::new();
        metrics.insert("detection_latency_p50".into(), 200_000_000i64); // 200ms < 250ms
        let triggered = c.check_kill_criteria(
            &metrics,
            1_000_000_000_000, // 1 day
            100_000,           // 10% budget
        );
        assert!(triggered.is_empty());
    }

    #[test]
    fn kill_criteria_budget_exhausted_no_signal() {
        let c = test_contract();
        let mut metrics = BTreeMap::new();
        // Metrics above threshold (worse than target for lower-is-better).
        metrics.insert("detection_latency_p50".into(), 300_000_000i64); // 300ms > 250ms threshold
        metrics.insert("false_positive_rate".into(), 20_000i64); // 2% > 1% threshold
        let triggered = c.check_kill_criteria(
            &metrics,
            1_000_000_000_000,
            950_000, // 95% budget spent
        );
        assert!(
            triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
        );
    }

    #[test]
    fn kill_criteria_metric_regression() {
        let c = test_contract();
        let mut metrics = BTreeMap::new();
        // detection_latency_p50 at 600ms > regression threshold 500ms.
        metrics.insert("detection_latency_p50".into(), 600_000_000i64);
        let triggered = c.check_kill_criteria(&metrics, 0, 0);
        assert!(
            triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::MetricRegression)
        );
    }

    // -- Stage tests --

    #[test]
    fn moonshot_stage_ordering() {
        assert!(MoonshotStage::Research < MoonshotStage::Shadow);
        assert!(MoonshotStage::Shadow < MoonshotStage::Canary);
        assert!(MoonshotStage::Canary < MoonshotStage::Production);
    }

    #[test]
    fn moonshot_stage_display() {
        assert_eq!(MoonshotStage::Research.to_string(), "research");
        assert_eq!(MoonshotStage::Production.to_string(), "production");
    }

    #[test]
    fn moonshot_stage_all() {
        assert_eq!(MoonshotStage::all().len(), 4);
    }

    // -- Serialization tests --

    #[test]
    fn contract_serde_round_trip() {
        let c = test_contract();
        let json = serde_json::to_string(&c).unwrap();
        let decoded: MoonshotContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn deterministic_serialization() {
        let c1 = test_contract();
        let c2 = test_contract();
        assert_eq!(
            serde_json::to_string(&c1).unwrap(),
            serde_json::to_string(&c2).unwrap()
        );
    }

    #[test]
    fn error_serde_round_trip() {
        let err = ContractError::InvalidEvModel {
            reason: "test".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: ContractError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    // -- Display tests --

    #[test]
    fn error_display() {
        assert_eq!(
            ContractError::EmptyContractId.to_string(),
            "contract ID is empty"
        );
        assert_eq!(
            ContractError::EmptyKillCriteria.to_string(),
            "kill criteria must not be empty"
        );
    }

    #[test]
    fn distribution_type_display() {
        assert_eq!(DistributionType::Beta.to_string(), "beta");
        assert_eq!(DistributionType::LogNormal.to_string(), "log_normal");
    }

    #[test]
    fn risk_dimension_display() {
        assert_eq!(
            RiskDimension::SecurityRegression.to_string(),
            "security_regression"
        );
    }

    #[test]
    fn artifact_type_display() {
        assert_eq!(ArtifactType::Proof.to_string(), "proof");
        assert_eq!(
            ArtifactType::BenchmarkResult.to_string(),
            "benchmark_result"
        );
    }

    #[test]
    fn kill_trigger_display() {
        assert_eq!(
            KillTrigger::BudgetExhaustedNoSignal.to_string(),
            "budget_exhausted_no_signal"
        );
    }

    #[test]
    fn contract_version_display() {
        assert_eq!(ContractVersion { major: 2, minor: 3 }.to_string(), "2.3");
    }

    #[test]
    fn measurement_method_display() {
        assert_eq!(MeasurementMethod::Benchmark.to_string(), "benchmark");
        assert_eq!(
            MeasurementMethod::FleetTelemetry.to_string(),
            "fleet_telemetry"
        );
    }

    // -- Enrichment: std::error --

    #[test]
    fn contract_error_implements_std_error() {
        let variants: [Box<dyn std::error::Error>; 7] = [
            Box::new(ContractError::EmptyContractId),
            Box::new(ContractError::InvalidHypothesis {
                reason: "empty".into(),
            }),
            Box::new(ContractError::EmptyTargetMetrics),
            Box::new(ContractError::InvalidEvModel {
                reason: "bad prior".into(),
            }),
            Box::new(ContractError::InvalidRiskBudget {
                reason: "negative".into(),
            }),
            Box::new(ContractError::EmptyKillCriteria),
            Box::new(ContractError::InvalidRollback {
                reason: "stale".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            7,
            "all 7 variants produce distinct messages"
        );
    }

    // -- Enrichment: additional coverage --

    #[test]
    fn moonshot_stage_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> =
            MoonshotStage::all().iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), 4, "all 4 stages must have unique Display");
    }

    #[test]
    fn distribution_type_display_uniqueness() {
        let types = [
            DistributionType::PointEstimate,
            DistributionType::Uniform,
            DistributionType::Beta,
            DistributionType::LogNormal,
        ];
        let displays: std::collections::BTreeSet<String> =
            types.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn risk_dimension_display_uniqueness() {
        let dims = [
            RiskDimension::SecurityRegression,
            RiskDimension::PerformanceRegression,
            RiskDimension::OperationalBurden,
            RiskDimension::CrossInitiativeInterference,
        ];
        let displays: std::collections::BTreeSet<String> =
            dims.iter().map(|d| d.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn artifact_type_display_uniqueness() {
        let types = [
            ArtifactType::Proof,
            ArtifactType::BenchmarkResult,
            ArtifactType::ConformanceEvidence,
            ArtifactType::OperatorDocumentation,
            ArtifactType::RiskAssessment,
        ];
        let displays: std::collections::BTreeSet<String> =
            types.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn kill_trigger_display_uniqueness() {
        let triggers = [
            KillTrigger::BudgetExhaustedNoSignal,
            KillTrigger::MetricRegression,
            KillTrigger::ReproducibilityFailure,
            KillTrigger::RiskConstraintViolation,
            KillTrigger::TimeExpiry,
        ];
        let displays: std::collections::BTreeSet<String> =
            triggers.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn hypothesis_validate_empty_mechanism() {
        let mut h = test_hypothesis();
        h.mechanism = String::new();
        assert!(matches!(
            h.validate(),
            Err(ContractError::InvalidHypothesis { .. })
        ));
    }

    #[test]
    fn hypothesis_validate_empty_expected_outcome() {
        let mut h = test_hypothesis();
        h.expected_outcome = String::new();
        assert!(matches!(
            h.validate(),
            Err(ContractError::InvalidHypothesis { .. })
        ));
    }

    #[test]
    fn ev_model_validate_uniform_requires_low_high() {
        let ev = EvModel {
            success_distribution: DistributionType::Uniform,
            distribution_params: BTreeMap::new(),
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        assert!(matches!(
            ev.validate(),
            Err(ContractError::InvalidEvModel { .. })
        ));
    }

    #[test]
    fn ev_model_validate_lognormal_requires_mu_sigma() {
        let ev = EvModel {
            success_distribution: DistributionType::LogNormal,
            distribution_params: BTreeMap::new(),
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        assert!(matches!(
            ev.validate(),
            Err(ContractError::InvalidEvModel { .. })
        ));
    }

    #[test]
    fn rollback_plan_rejects_empty_expected_state() {
        let rp = RollbackPlan {
            steps: vec![RollbackStep {
                step_number: 1,
                description: "step".into(),
                verification: "verify".into(),
            }],
            artifact_references: vec![],
            expected_state_after_rollback: String::new(),
        };
        assert!(matches!(
            rp.validate(),
            Err(ContractError::InvalidRollback { .. })
        ));
    }

    #[test]
    fn contract_error_all_variants_serde_roundtrip() {
        let errors = [
            ContractError::EmptyContractId,
            ContractError::InvalidHypothesis {
                reason: "test reason".into(),
            },
            ContractError::EmptyTargetMetrics,
            ContractError::InvalidEvModel {
                reason: "bad model".into(),
            },
            ContractError::InvalidRiskBudget {
                reason: "empty".into(),
            },
            ContractError::EmptyKillCriteria,
            ContractError::InvalidRollback {
                reason: "no steps".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: ContractError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn contract_with_metadata_serde_deterministic() {
        let mut c1 = test_contract();
        c1.metadata.insert("owner".into(), "team-alpha".into());
        c1.metadata.insert("priority".into(), "high".into());
        let mut c2 = test_contract();
        c2.metadata.insert("priority".into(), "high".into());
        c2.metadata.insert("owner".into(), "team-alpha".into());
        // BTreeMap guarantees deterministic ordering regardless of insert order
        assert_eq!(
            serde_json::to_string(&c1).unwrap(),
            serde_json::to_string(&c2).unwrap()
        );
    }

    #[test]
    fn stage_obligations_met_non_blocking_ignored() {
        let mut c = test_contract();
        c.artifact_obligations.push(ArtifactObligation {
            obligation_id: "optional-doc".into(),
            required_at_stage: MoonshotStage::Research,
            artifact_type: ArtifactType::OperatorDocumentation,
            description: "Optional documentation".into(),
            blocking: false,
        });
        // Non-blocking obligation should not prevent stage promotion
        assert!(c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
    }

    #[test]
    fn hypothesis_clone_equality() {
        let h = Hypothesis {
            problem: "slow detection".into(),
            mechanism: "shared evidence".into(),
            expected_outcome: "faster response".into(),
            falsification_criteria: vec!["no measurable improvement".into()],
        };
        let cloned = h.clone();
        assert_eq!(h, cloned);
    }

    #[test]
    fn target_metric_clone_equality() {
        let m = TargetMetric {
            metric_id: "m-1".into(),
            description: "latency".into(),
            threshold_millionths: 500_000,
            direction: MetricDirection::LowerIsBetter,
            measurement_method: MeasurementMethod::Benchmark,
            evaluation_cadence_ns: 1_000_000_000,
        };
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn ev_model_clone_equality() {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 300_000);
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 1_000_000,
            benefit_on_success_millionths: 10_000_000,
            harm_on_failure_millionths: -500_000,
        };
        let cloned = ev.clone();
        assert_eq!(ev, cloned);
    }

    #[test]
    fn risk_budget_clone_equality() {
        let mut caps = BTreeMap::new();
        caps.insert(RiskDimension::SecurityRegression, 50_000);
        let rb = RiskBudget {
            dimension_caps: caps,
        };
        let cloned = rb.clone();
        assert_eq!(rb, cloned);
    }

    #[test]
    fn moonshot_contract_clone_equality() {
        let c = test_contract();
        let cloned = c.clone();
        assert_eq!(c, cloned);
    }

    #[test]
    fn hypothesis_json_field_presence() {
        let h = Hypothesis {
            problem: "desc".into(),
            mechanism: "mechanism".into(),
            expected_outcome: "outcome".into(),
            falsification_criteria: vec!["criterion".into()],
        };
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"problem\""));
        assert!(json.contains("\"mechanism\""));
        assert!(json.contains("\"expected_outcome\""));
        assert!(json.contains("\"falsification_criteria\""));
    }

    #[test]
    fn target_metric_json_field_presence() {
        let m = TargetMetric {
            metric_id: "m-1".into(),
            description: "d".into(),
            threshold_millionths: 500_000,
            direction: MetricDirection::LowerIsBetter,
            measurement_method: MeasurementMethod::FleetTelemetry,
            evaluation_cadence_ns: 1_000_000_000,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"metric_id\""));
        assert!(json.contains("\"direction\""));
        assert!(json.contains("\"threshold_millionths\""));
        assert!(json.contains("\"measurement_method\""));
        assert!(json.contains("\"evaluation_cadence_ns\""));
    }

    #[test]
    fn ev_model_json_field_presence() {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 300_000);
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 1_000_000,
            benefit_on_success_millionths: 10_000_000,
            harm_on_failure_millionths: -500_000,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"success_distribution\""));
        assert!(json.contains("\"distribution_params\""));
        assert!(json.contains("\"benefit_on_success_millionths\""));
        assert!(json.contains("\"cost_millionths\""));
        assert!(json.contains("\"harm_on_failure_millionths\""));
    }

    #[test]
    fn contract_error_source_is_none() {
        let err = ContractError::InvalidHypothesis {
            reason: "bad".into(),
        };
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn measurement_method_display_uniqueness() {
        let variants = [
            MeasurementMethod::Benchmark,
            MeasurementMethod::EvidenceQuery,
            MeasurementMethod::FleetTelemetry,
            MeasurementMethod::OperatorReview,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v}")).collect();
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn metric_direction_serde_roundtrip() {
        for d in [
            MetricDirection::HigherIsBetter,
            MetricDirection::LowerIsBetter,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: MetricDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn contract_version_clone_equality() {
        let v = ContractVersion { major: 2, minor: 5 };
        let cloned = v;
        assert_eq!(v, cloned);
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 5);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrich_moonshot_stage_serde_roundtrip_all_variants() {
        for stage in MoonshotStage::all() {
            let json = serde_json::to_string(stage).unwrap();
            let back: MoonshotStage = serde_json::from_str(&json).unwrap();
            assert_eq!(*stage, back);
        }
    }

    #[test]
    fn enrich_moonshot_stage_btreeset_insertion_order() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(MoonshotStage::Production);
        set.insert(MoonshotStage::Research);
        set.insert(MoonshotStage::Canary);
        set.insert(MoonshotStage::Shadow);
        let ordered: Vec<_> = set.into_iter().collect();
        assert_eq!(
            ordered,
            vec![
                MoonshotStage::Research,
                MoonshotStage::Shadow,
                MoonshotStage::Canary,
                MoonshotStage::Production,
            ]
        );
    }

    #[test]
    fn enrich_moonshot_stage_copy_semantics() {
        let a = MoonshotStage::Canary;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrich_measurement_method_serde_roundtrip_all() {
        for m in [
            MeasurementMethod::Benchmark,
            MeasurementMethod::EvidenceQuery,
            MeasurementMethod::FleetTelemetry,
            MeasurementMethod::OperatorReview,
        ] {
            let json = serde_json::to_string(&m).unwrap();
            let back: MeasurementMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(m, back);
        }
    }

    #[test]
    fn enrich_measurement_method_btreeset_deterministic() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(MeasurementMethod::OperatorReview);
        set.insert(MeasurementMethod::Benchmark);
        set.insert(MeasurementMethod::FleetTelemetry);
        set.insert(MeasurementMethod::EvidenceQuery);
        assert_eq!(set.len(), 4);
        let first = *set.iter().next().unwrap();
        let last = *set.iter().next_back().unwrap();
        assert!(first < last);
    }

    #[test]
    fn enrich_distribution_type_serde_roundtrip_all() {
        for d in [
            DistributionType::PointEstimate,
            DistributionType::Uniform,
            DistributionType::Beta,
            DistributionType::LogNormal,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: DistributionType = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn enrich_distribution_type_btreeset_deterministic() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(DistributionType::LogNormal);
        set.insert(DistributionType::PointEstimate);
        set.insert(DistributionType::Beta);
        set.insert(DistributionType::Uniform);
        assert_eq!(set.len(), 4);
        let vec: Vec<_> = set.into_iter().collect();
        assert_eq!(vec[0], DistributionType::PointEstimate);
        assert_eq!(vec[3], DistributionType::LogNormal);
    }

    #[test]
    fn enrich_risk_dimension_serde_roundtrip_all() {
        for d in [
            RiskDimension::SecurityRegression,
            RiskDimension::PerformanceRegression,
            RiskDimension::OperationalBurden,
            RiskDimension::CrossInitiativeInterference,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: RiskDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn enrich_artifact_type_serde_roundtrip_all() {
        for a in [
            ArtifactType::Proof,
            ArtifactType::BenchmarkResult,
            ArtifactType::ConformanceEvidence,
            ArtifactType::OperatorDocumentation,
            ArtifactType::RiskAssessment,
        ] {
            let json = serde_json::to_string(&a).unwrap();
            let back: ArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(a, back);
        }
    }

    #[test]
    fn enrich_artifact_type_btreeset_deterministic() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(ArtifactType::RiskAssessment);
        set.insert(ArtifactType::Proof);
        set.insert(ArtifactType::ConformanceEvidence);
        set.insert(ArtifactType::BenchmarkResult);
        set.insert(ArtifactType::OperatorDocumentation);
        assert_eq!(set.len(), 5);
        let first = *set.iter().next().unwrap();
        assert_eq!(first, ArtifactType::Proof);
    }

    #[test]
    fn enrich_kill_trigger_serde_roundtrip_all() {
        for k in [
            KillTrigger::BudgetExhaustedNoSignal,
            KillTrigger::MetricRegression,
            KillTrigger::ReproducibilityFailure,
            KillTrigger::RiskConstraintViolation,
            KillTrigger::TimeExpiry,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            let back: KillTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn enrich_kill_trigger_btreeset_deterministic() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(KillTrigger::TimeExpiry);
        set.insert(KillTrigger::BudgetExhaustedNoSignal);
        set.insert(KillTrigger::MetricRegression);
        set.insert(KillTrigger::ReproducibilityFailure);
        set.insert(KillTrigger::RiskConstraintViolation);
        assert_eq!(set.len(), 5);
        let first = *set.iter().next().unwrap();
        assert_eq!(first, KillTrigger::BudgetExhaustedNoSignal);
    }

    #[test]
    fn enrich_hypothesis_serde_roundtrip() {
        let h = test_hypothesis();
        let json = serde_json::to_string(&h).unwrap();
        let back: Hypothesis = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn enrich_target_metric_serde_roundtrip() {
        for m in test_metrics() {
            let json = serde_json::to_string(&m).unwrap();
            let back: TargetMetric = serde_json::from_str(&json).unwrap();
            assert_eq!(m, back);
        }
    }

    #[test]
    fn enrich_risk_budget_serde_roundtrip() {
        let rb = test_risk_budget();
        let json = serde_json::to_string(&rb).unwrap();
        let back: RiskBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(rb, back);
    }

    #[test]
    fn enrich_artifact_obligation_serde_roundtrip() {
        for o in test_obligations() {
            let json = serde_json::to_string(&o).unwrap();
            let back: ArtifactObligation = serde_json::from_str(&json).unwrap();
            assert_eq!(o, back);
        }
    }

    #[test]
    fn enrich_kill_criterion_serde_roundtrip() {
        for k in test_kill_criteria() {
            let json = serde_json::to_string(&k).unwrap();
            let back: KillCriterion = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn enrich_rollback_plan_serde_roundtrip() {
        let rp = test_rollback();
        let json = serde_json::to_string(&rp).unwrap();
        let back: RollbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(rp, back);
    }

    #[test]
    fn enrich_rollback_step_serde_roundtrip() {
        let s = RollbackStep {
            step_number: 42,
            description: "revert schema".into(),
            verification: "SELECT version FROM migrations".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RollbackStep = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enrich_contract_version_serde_roundtrip() {
        let v = ContractVersion { major: 3, minor: 7 };
        let json = serde_json::to_string(&v).unwrap();
        let back: ContractVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn enrich_contract_version_ordering() {
        let v1 = ContractVersion { major: 1, minor: 0 };
        let v2 = ContractVersion { major: 1, minor: 1 };
        let v3 = ContractVersion { major: 2, minor: 0 };
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn enrich_contract_version_btreeset() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(ContractVersion { major: 2, minor: 0 });
        set.insert(ContractVersion { major: 1, minor: 3 });
        set.insert(ContractVersion { major: 1, minor: 0 });
        let ordered: Vec<_> = set.into_iter().collect();
        assert_eq!(ordered[0], ContractVersion { major: 1, minor: 0 });
        assert_eq!(ordered[1], ContractVersion { major: 1, minor: 3 });
        assert_eq!(ordered[2], ContractVersion { major: 2, minor: 0 });
    }

    #[test]
    fn enrich_hypothesis_clone_independence() {
        let mut h = test_hypothesis();
        let cloned = h.clone();
        h.problem = "mutated".into();
        assert_ne!(h.problem, cloned.problem);
    }

    #[test]
    fn enrich_ev_model_clone_independence() {
        let mut ev = test_ev_model();
        let cloned = ev.clone();
        ev.cost_millionths = 999_999;
        assert_ne!(ev.cost_millionths, cloned.cost_millionths);
    }

    #[test]
    fn enrich_risk_budget_clone_independence() {
        let mut rb = test_risk_budget();
        let cloned = rb.clone();
        rb.dimension_caps
            .insert(RiskDimension::OperationalBurden, 999_999);
        assert!(
            !cloned
                .dimension_caps
                .contains_key(&RiskDimension::OperationalBurden)
        );
    }

    #[test]
    fn enrich_contract_clone_independence() {
        let mut c = test_contract();
        let cloned = c.clone();
        c.contract_id = "mutated-id".into();
        c.metadata.insert("extra".into(), "val".into());
        assert_ne!(c.contract_id, cloned.contract_id);
        assert!(cloned.metadata.is_empty());
    }

    #[test]
    fn enrich_ev_model_validate_negative_cost() {
        let mut ev = test_ev_model();
        ev.cost_millionths = -100;
        let err = ev.validate().unwrap_err();
        assert!(matches!(err, ContractError::InvalidEvModel { .. }));
        assert!(err.to_string().contains("cost must be positive"));
    }

    #[test]
    fn enrich_ev_model_net_ev_zero_probability() {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 0i64);
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 500_000,
            benefit_on_success_millionths: 5_000_000,
            harm_on_failure_millionths: -200_000,
        };
        let net = ev.net_ev_point_estimate().unwrap();
        assert_eq!(net, -700_000);
    }

    #[test]
    fn enrich_ev_model_net_ev_certainty() {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 1_000_000i64);
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: 500_000,
            benefit_on_success_millionths: 5_000_000,
            harm_on_failure_millionths: -200_000,
        };
        let net = ev.net_ev_point_estimate().unwrap();
        assert_eq!(net, 4_500_000);
    }

    #[test]
    fn enrich_ev_model_net_ev_missing_value_param() {
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: BTreeMap::new(),
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        let err = ev.net_ev_point_estimate().unwrap_err();
        assert!(err.to_string().contains("missing 'value' parameter"));
    }

    #[test]
    fn enrich_ev_model_validate_point_estimate_requires_value() {
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: BTreeMap::new(),
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        let err = ev.validate().unwrap_err();
        assert!(err.to_string().contains("PointEstimate requires 'value'"));
    }

    #[test]
    fn enrich_ev_model_validate_beta_ok() {
        let mut params = BTreeMap::new();
        params.insert("alpha".into(), 2_000_000i64);
        params.insert("beta".into(), 3_000_000i64);
        let ev = EvModel {
            success_distribution: DistributionType::Beta,
            distribution_params: params,
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        ev.validate().unwrap();
    }

    #[test]
    fn enrich_ev_model_validate_uniform_ok() {
        let mut params = BTreeMap::new();
        params.insert("low".into(), 100_000i64);
        params.insert("high".into(), 900_000i64);
        let ev = EvModel {
            success_distribution: DistributionType::Uniform,
            distribution_params: params,
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        ev.validate().unwrap();
    }

    #[test]
    fn enrich_ev_model_validate_lognormal_ok() {
        let mut params = BTreeMap::new();
        params.insert("mu".into(), 0i64);
        params.insert("sigma".into(), 500_000i64);
        let ev = EvModel {
            success_distribution: DistributionType::LogNormal,
            distribution_params: params,
            cost_millionths: 100_000,
            benefit_on_success_millionths: 1_000_000,
            harm_on_failure_millionths: -50_000,
        };
        ev.validate().unwrap();
    }

    #[test]
    fn enrich_kill_criteria_time_not_triggered_at_boundary() {
        let c = test_contract();
        let metrics = BTreeMap::new();
        let triggered = c.check_kill_criteria(&metrics, 15_552_000_000_000_000, 0);
        assert!(
            !triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::TimeExpiry)
        );
    }

    #[test]
    fn enrich_kill_criteria_budget_below_threshold() {
        let c = test_contract();
        let metrics = BTreeMap::new();
        let triggered = c.check_kill_criteria(&metrics, 0, 899_000);
        assert!(
            !triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
        );
    }

    #[test]
    fn enrich_kill_criteria_budget_not_triggered_improving() {
        let c = test_contract();
        let mut metrics = BTreeMap::new();
        metrics.insert("detection_latency_p50".into(), 100_000_000i64);
        let triggered = c.check_kill_criteria(&metrics, 0, 950_000);
        assert!(
            !triggered
                .iter()
                .any(|k| k.trigger == KillTrigger::BudgetExhaustedNoSignal)
        );
    }

    #[test]
    fn enrich_kill_criteria_regression_higher_is_better() {
        let mut c = test_contract();
        c.target_metrics = vec![TargetMetric {
            metric_id: "detection_rate".into(),
            description: "detection accuracy".into(),
            threshold_millionths: 950_000,
            direction: MetricDirection::HigherIsBetter,
            measurement_method: MeasurementMethod::Benchmark,
            evaluation_cadence_ns: 86_400_000_000_000,
        }];
        c.kill_criteria = vec![KillCriterion {
            criterion_id: "regression".into(),
            trigger: KillTrigger::MetricRegression,
            condition: "accuracy regression".into(),
            threshold_millionths: Some(900_000),
            max_duration_ns: None,
        }];
        let mut metrics = BTreeMap::new();
        metrics.insert("detection_rate".into(), 800_000i64);
        let triggered = c.check_kill_criteria(&metrics, 0, 0);
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0].trigger, KillTrigger::MetricRegression);
    }

    #[test]
    fn enrich_kill_criteria_regression_not_triggered() {
        let mut c = test_contract();
        c.target_metrics = vec![TargetMetric {
            metric_id: "detection_rate".into(),
            description: "detection accuracy".into(),
            threshold_millionths: 950_000,
            direction: MetricDirection::HigherIsBetter,
            measurement_method: MeasurementMethod::Benchmark,
            evaluation_cadence_ns: 86_400_000_000_000,
        }];
        c.kill_criteria = vec![KillCriterion {
            criterion_id: "regression".into(),
            trigger: KillTrigger::MetricRegression,
            condition: "accuracy regression".into(),
            threshold_millionths: Some(900_000),
            max_duration_ns: None,
        }];
        let mut metrics = BTreeMap::new();
        metrics.insert("detection_rate".into(), 950_000i64);
        let triggered = c.check_kill_criteria(&metrics, 0, 0);
        assert!(triggered.is_empty());
    }

    #[test]
    fn enrich_kill_criteria_regression_no_threshold() {
        let mut c = test_contract();
        c.kill_criteria = vec![KillCriterion {
            criterion_id: "regression-no-thresh".into(),
            trigger: KillTrigger::MetricRegression,
            condition: "no threshold set".into(),
            threshold_millionths: None,
            max_duration_ns: None,
        }];
        let mut metrics = BTreeMap::new();
        metrics.insert("detection_latency_p50".into(), 999_999_999i64);
        let triggered = c.check_kill_criteria(&metrics, 0, 0);
        assert!(triggered.is_empty());
    }

    #[test]
    fn enrich_stage_obligations_multiple_blocking() {
        let mut c = test_contract();
        c.artifact_obligations.push(ArtifactObligation {
            obligation_id: "extra-research".into(),
            required_at_stage: MoonshotStage::Research,
            artifact_type: ArtifactType::RiskAssessment,
            description: "Risk assessment for research phase".into(),
            blocking: true,
        });
        assert!(!c.stage_obligations_met(MoonshotStage::Research, &["proof-research".into()]));
        assert!(c.stage_obligations_met(
            MoonshotStage::Research,
            &["proof-research".into(), "extra-research".into()]
        ));
    }

    #[test]
    fn enrich_contract_no_governance_signature() {
        let mut c = test_contract();
        c.governance_signature = None;
        c.validate().unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: MoonshotContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert!(back.governance_signature.is_none());
    }

    #[test]
    fn enrich_contract_metadata_stress() {
        let mut c = test_contract();
        for i in 0..20 {
            c.metadata.insert(format!("key-{i:03}"), format!("val-{i}"));
        }
        let json1 = serde_json::to_string(&c).unwrap();
        let json2 = serde_json::to_string(&c).unwrap();
        assert_eq!(json1, json2);
        let back: MoonshotContract = serde_json::from_str(&json1).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enrich_contract_error_display_all_distinct() {
        let errors = [
            ContractError::EmptyContractId,
            ContractError::InvalidHypothesis {
                reason: "r1".into(),
            },
            ContractError::EmptyTargetMetrics,
            ContractError::InvalidEvModel {
                reason: "r2".into(),
            },
            ContractError::InvalidRiskBudget {
                reason: "r3".into(),
            },
            ContractError::EmptyKillCriteria,
            ContractError::InvalidRollback {
                reason: "r4".into(),
            },
        ];
        use std::collections::BTreeSet;
        let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    #[test]
    fn enrich_contract_error_debug_not_empty() {
        let err = ContractError::EmptyContractId;
        let dbg = format!("{err:?}");
        assert!(!dbg.is_empty());
    }

    #[test]
    fn enrich_error_hypothesis_display_contains_reason() {
        let err = ContractError::InvalidHypothesis {
            reason: "missing data".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("missing data"));
        assert!(msg.contains("hypothesis"));
    }

    #[test]
    fn enrich_error_ev_model_display_contains_reason() {
        let err = ContractError::InvalidEvModel {
            reason: "bad distribution".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad distribution"));
        assert!(msg.contains("EV model"));
    }

    #[test]
    fn enrich_error_risk_budget_display_contains_reason() {
        let err = ContractError::InvalidRiskBudget {
            reason: "empty dimensions".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("empty dimensions"));
        assert!(msg.contains("risk budget"));
    }

    #[test]
    fn enrich_error_rollback_display_contains_reason() {
        let err = ContractError::InvalidRollback {
            reason: "no steps defined".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("no steps defined"));
        assert!(msg.contains("rollback"));
    }

    #[test]
    fn enrich_ev_model_net_ev_large_values_no_overflow() {
        let mut params = BTreeMap::new();
        params.insert("value".into(), 999_999i64);
        let ev = EvModel {
            success_distribution: DistributionType::PointEstimate,
            distribution_params: params,
            cost_millionths: i64::MAX / 2,
            benefit_on_success_millionths: i64::MAX / 2,
            harm_on_failure_millionths: i64::MIN / 2,
        };
        let _net = ev.net_ev_point_estimate().unwrap();
    }

    #[test]
    fn enrich_contract_serde_all_fields_populated() {
        let mut c = test_contract();
        c.metadata.insert("team".into(), "alpha".into());
        c.metadata.insert("region".into(), "us-east".into());
        c.governance_signature = Some("sig:abc123".into());
        c.current_stage = MoonshotStage::Canary;
        c.artifact_obligations.push(ArtifactObligation {
            obligation_id: "conf-canary".into(),
            required_at_stage: MoonshotStage::Canary,
            artifact_type: ArtifactType::ConformanceEvidence,
            description: "Canary conformance evidence".into(),
            blocking: true,
        });
        let json = serde_json::to_string_pretty(&c).unwrap();
        let back: MoonshotContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enrich_contract_deterministic_replay_validate() {
        let c = test_contract();
        let r1 = c.validate();
        let r2 = c.validate();
        assert_eq!(r1, r2);
    }

    #[test]
    fn enrich_contract_deterministic_replay_kill() {
        let c = test_contract();
        let metrics = BTreeMap::new();
        let t1 = c.check_kill_criteria(&metrics, 20_000_000_000_000_000, 950_000);
        let t2 = c.check_kill_criteria(&metrics, 20_000_000_000_000_000, 950_000);
        assert_eq!(t1.len(), t2.len());
        for (a, b) in t1.iter().zip(t2.iter()) {
            assert_eq!(a.criterion_id, b.criterion_id);
        }
    }

    #[test]
    fn enrich_contract_empty_metadata_serde() {
        let c = test_contract();
        assert!(c.metadata.is_empty());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"metadata\":{}"));
        let back: MoonshotContract = serde_json::from_str(&json).unwrap();
        assert!(back.metadata.is_empty());
    }

    #[test]
    fn enrich_rollback_step_clone_independence() {
        let mut s = RollbackStep {
            step_number: 1,
            description: "original".into(),
            verification: "check".into(),
        };
        let cloned = s.clone();
        s.description = "modified".into();
        assert_ne!(s.description, cloned.description);
    }

    #[test]
    fn enrich_kill_criterion_clone_independence() {
        let mut k = KillCriterion {
            criterion_id: "k1".into(),
            trigger: KillTrigger::TimeExpiry,
            condition: "original".into(),
            threshold_millionths: Some(100_000),
            max_duration_ns: Some(86_400_000_000_000),
        };
        let cloned = k.clone();
        k.condition = "mutated".into();
        k.threshold_millionths = None;
        assert_ne!(k.condition, cloned.condition);
        assert!(cloned.threshold_millionths.is_some());
    }

    #[test]
    fn enrich_artifact_obligation_clone_independence() {
        let mut o = ArtifactObligation {
            obligation_id: "o1".into(),
            required_at_stage: MoonshotStage::Research,
            artifact_type: ArtifactType::Proof,
            description: "original".into(),
            blocking: true,
        };
        let cloned = o.clone();
        o.blocking = false;
        o.description = "mutated".into();
        assert!(cloned.blocking);
        assert_ne!(o.description, cloned.description);
    }

    #[test]
    fn enrich_contract_stress_many_obligations() {
        let mut c = test_contract();
        for i in 0..100 {
            c.artifact_obligations.push(ArtifactObligation {
                obligation_id: format!("stress-{i}"),
                required_at_stage: MoonshotStage::all()[i % 4],
                artifact_type: ArtifactType::Proof,
                description: format!("stress obligation {i}"),
                blocking: i.is_multiple_of(2),
            });
        }
        c.validate().unwrap();
        let blocking_research: Vec<_> = c
            .artifact_obligations
            .iter()
            .filter(|o| o.required_at_stage == MoonshotStage::Research && o.blocking)
            .map(|o| o.obligation_id.clone())
            .collect();
        assert!(c.stage_obligations_met(MoonshotStage::Research, &blocking_research));
    }

    #[test]
    fn enrich_risk_budget_all_dimensions() {
        let mut caps = BTreeMap::new();
        caps.insert(RiskDimension::SecurityRegression, 50_000u64);
        caps.insert(RiskDimension::PerformanceRegression, 100_000u64);
        caps.insert(RiskDimension::OperationalBurden, 75_000u64);
        caps.insert(RiskDimension::CrossInitiativeInterference, 25_000u64);
        let rb = RiskBudget {
            dimension_caps: caps,
        };
        rb.validate().unwrap();
        assert_eq!(rb.dimension_caps.len(), 4);
        let json = serde_json::to_string(&rb).unwrap();
        let back: RiskBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(rb, back);
    }

    #[test]
    fn enrich_stage_all_covers_every_variant() {
        let all = MoonshotStage::all();
        assert!(all.contains(&MoonshotStage::Research));
        assert!(all.contains(&MoonshotStage::Shadow));
        assert!(all.contains(&MoonshotStage::Canary));
        assert!(all.contains(&MoonshotStage::Production));
    }

    #[test]
    fn enrich_stage_display_shadow_canary() {
        assert_eq!(MoonshotStage::Shadow.to_string(), "shadow");
        assert_eq!(MoonshotStage::Canary.to_string(), "canary");
    }

    #[test]
    fn enrich_measurement_display_evidence_operator() {
        assert_eq!(
            MeasurementMethod::EvidenceQuery.to_string(),
            "evidence_query"
        );
        assert_eq!(
            MeasurementMethod::OperatorReview.to_string(),
            "operator_review"
        );
    }

    #[test]
    fn enrich_artifact_type_display_remaining() {
        assert_eq!(
            ArtifactType::ConformanceEvidence.to_string(),
            "conformance_evidence"
        );
        assert_eq!(
            ArtifactType::OperatorDocumentation.to_string(),
            "operator_documentation"
        );
        assert_eq!(ArtifactType::RiskAssessment.to_string(), "risk_assessment");
    }

    #[test]
    fn enrich_kill_trigger_display_remaining() {
        assert_eq!(
            KillTrigger::MetricRegression.to_string(),
            "metric_regression"
        );
        assert_eq!(
            KillTrigger::ReproducibilityFailure.to_string(),
            "reproducibility_failure"
        );
        assert_eq!(
            KillTrigger::RiskConstraintViolation.to_string(),
            "risk_constraint_violation"
        );
        assert_eq!(KillTrigger::TimeExpiry.to_string(), "time_expiry");
    }

    #[test]
    fn enrich_risk_dimension_display_remaining() {
        assert_eq!(
            RiskDimension::PerformanceRegression.to_string(),
            "performance_regression"
        );
        assert_eq!(
            RiskDimension::OperationalBurden.to_string(),
            "operational_burden"
        );
        assert_eq!(
            RiskDimension::CrossInitiativeInterference.to_string(),
            "cross_initiative_interference"
        );
    }

    #[test]
    fn enrich_distribution_type_display_remaining() {
        assert_eq!(
            DistributionType::PointEstimate.to_string(),
            "point_estimate"
        );
        assert_eq!(DistributionType::Uniform.to_string(), "uniform");
    }
}
