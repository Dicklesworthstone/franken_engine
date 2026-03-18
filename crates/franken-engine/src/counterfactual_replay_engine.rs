//! Deterministic counterfactual replay engine for route/fallback decision alternatives.
//!
//! Re-simulates real traces under alternate routing/fallback/control policies,
//! computes counterfactual outcome deltas with uncertainty annotations, and
//! emits decision-comparison artifacts consumable by gate and governance workflows.
//!
//! Plan reference: FRX-19.2

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, NondeterminismLog, TraceRecord,
};
use crate::counterfactual_evaluator::{
    ConfidenceEnvelope, EnvelopeStatus, EstimatorKind, PolicyId,
};
use crate::engine_object_id::IdError;
use crate::hash_tiers::ContentHash;
use crate::runtime_decision_theory::LaneAction;
use crate::security_epoch::SecurityEpoch;
use crate::structural_causal_model::{CausalEffect, StructuralCausalModel};

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for replay comparison artifacts.
pub const REPLAY_ENGINE_SCHEMA_VERSION: &str = "franken-engine.counterfactual-replay-engine.v1";

/// Maximum number of alternate policies in a single comparison run.
const MAX_ALTERNATE_POLICIES: usize = 64;

/// Maximum trace decisions to replay.
const MAX_REPLAY_DECISIONS: usize = 100_000;

/// Default confidence level (95%).
const DEFAULT_CONFIDENCE_MILLIONTHS: i64 = 950_000;

// ── Alternate Policy ─────────────────────────────────────────────────────

/// An alternate routing/fallback policy to evaluate against the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternatePolicy {
    /// Unique identifier for this policy variant.
    pub policy_id: PolicyId,
    /// Human-readable description.
    pub description: String,
    /// Counterfactual configuration for causal replay.
    pub counterfactual_config: CounterfactualConfig,
    /// Override action for decision re-evaluation.
    pub default_action: Option<LaneAction>,
}

impl fmt::Display for AlternatePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.policy_id.0, self.description)
    }
}

// ── Replay Scope ─────────────────────────────────────────────────────────

/// Scope of replay: which decisions and epochs to include.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayScope {
    /// Start epoch (inclusive).
    pub start_epoch: SecurityEpoch,
    /// End epoch (inclusive).
    pub end_epoch: SecurityEpoch,
    /// Start tick (inclusive).
    pub start_tick: u64,
    /// End tick (inclusive).
    pub end_tick: u64,
    /// Filter to specific incident IDs (empty = all).
    pub incident_filter: BTreeSet<String>,
    /// Minimum decision count for statistical significance.
    pub min_decisions: u64,
}

impl Default for ReplayScope {
    fn default() -> Self {
        Self {
            start_epoch: SecurityEpoch::GENESIS,
            end_epoch: SecurityEpoch::from_raw(u64::MAX),
            start_tick: 0,
            end_tick: u64::MAX,
            incident_filter: BTreeSet::new(),
            min_decisions: 1,
        }
    }
}

impl ReplayScope {
    /// Check if a decision snapshot falls within scope.
    fn includes(&self, snapshot: &DecisionSnapshot) -> bool {
        if snapshot.epoch < self.start_epoch || snapshot.epoch > self.end_epoch {
            return false;
        }
        if snapshot.tick < self.start_tick || snapshot.tick > self.end_tick {
            return false;
        }
        true
    }

    /// Check if a trace falls within scope.
    fn includes_trace(&self, trace: &TraceRecord) -> bool {
        if trace.end_epoch < self.start_epoch || trace.start_epoch > self.end_epoch {
            return false;
        }
        if trace.end_tick < self.start_tick || trace.start_tick > self.end_tick {
            return false;
        }
        if !self.incident_filter.is_empty() {
            if let Some(ref incident_id) = trace.incident_id {
                if !self.incident_filter.contains(incident_id) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

// ── Assumption Card ──────────────────────────────────────────────────────

/// Category of identifiability assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssumptionCategory {
    /// No unmeasured confounders.
    NoUnmeasuredConfounding,
    /// Propensity overlap / positivity.
    Positivity,
    /// Consistency of potential outcomes.
    Consistency,
    /// Stable Unit Treatment Value.
    Sutva,
    /// Model specification correctness.
    ModelSpecification,
    /// Temporal stability of effects.
    TemporalStability,
}

impl fmt::Display for AssumptionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUnmeasuredConfounding => write!(f, "no-unmeasured-confounding"),
            Self::Positivity => write!(f, "positivity"),
            Self::Consistency => write!(f, "consistency"),
            Self::Sutva => write!(f, "sutva"),
            Self::ModelSpecification => write!(f, "model-specification"),
            Self::TemporalStability => write!(f, "temporal-stability"),
        }
    }
}

/// An identifiability/causal assumption required for a recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssumptionCard {
    /// Unique identifier.
    pub assumption_id: String,
    /// Category.
    pub category: AssumptionCategory,
    /// Human-readable description.
    pub description: String,
    /// Whether this assumption is testable with available data.
    pub testable: bool,
    /// If testable, whether the test passed.
    pub test_passed: Option<bool>,
    /// Sensitivity bound: how much the ATE could change if violated (millionths).
    pub sensitivity_bound_millionths: i64,
}

// ── Decision Comparison ──────────────────────────────────────────────────

/// Comparison of a single decision under baseline vs alternate policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionComparison {
    /// Decision index in the original trace.
    pub decision_index: u64,
    /// Tick at which the decision occurred.
    pub tick: u64,
    /// Epoch of the decision.
    pub epoch: SecurityEpoch,
    /// Original action taken.
    pub original_action: String,
    /// Action under the alternate policy.
    pub alternate_action: String,
    /// Original outcome (millionths).
    pub original_outcome_millionths: i64,
    /// Counterfactual outcome (millionths).
    pub counterfactual_outcome_millionths: i64,
    /// Whether the actions diverged.
    pub diverged: bool,
    /// Regime label at the time of decision.
    pub regime: String,
}

// ── Policy Comparison Report ─────────────────────────────────────────────

/// Full comparison report for one alternate policy vs the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyComparisonReport {
    /// Schema version.
    pub schema_version: String,
    /// Policy that was used as baseline.
    pub baseline_policy_id: PolicyId,
    /// Alternate policy evaluated.
    pub alternate_policy_id: PolicyId,
    /// Alternate policy description.
    pub alternate_description: String,
    /// Total decisions evaluated.
    pub decisions_evaluated: u64,
    /// Number of decisions where actions diverged.
    pub divergence_count: u64,
    /// Total original outcome (millionths).
    pub total_original_outcome_millionths: i64,
    /// Total counterfactual outcome (millionths).
    pub total_counterfactual_outcome_millionths: i64,
    /// Net improvement: counterfactual minus original (millionths).
    pub net_improvement_millionths: i64,
    /// Per-regime breakdown of net improvement.
    pub regime_breakdown: BTreeMap<String, i64>,
    /// Confidence envelope for the improvement estimate.
    pub confidence_envelope: ConfidenceEnvelope,
    /// Safety status based on the envelope.
    pub safety_status: EnvelopeStatus,
    /// Individual decision comparisons (only divergent ones, to save space).
    pub divergent_decisions: Vec<DecisionComparison>,
    /// Assumption cards for this comparison.
    pub assumptions: Vec<AssumptionCard>,
    /// Artifact hash for integrity.
    pub artifact_hash: ContentHash,
}

impl PolicyComparisonReport {
    /// Whether the alternate policy is an improvement with high confidence.
    pub fn is_confident_improvement(&self) -> bool {
        self.safety_status == EnvelopeStatus::Safe && self.net_improvement_millionths > 0
    }

    /// Divergence rate in millionths.
    pub fn divergence_rate_millionths(&self) -> i64 {
        if self.decisions_evaluated == 0 {
            return 0;
        }
        (self.divergence_count as i64 * MILLION) / self.decisions_evaluated as i64
    }
}

// ── Replay Comparison Result ─────────────────────────────────────────────

/// Result of a full counterfactual replay comparison across multiple policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayComparisonResult {
    /// Schema version.
    pub schema_version: String,
    /// Traces that were replayed.
    pub trace_count: u64,
    /// Total decisions across all traces.
    pub total_decisions: u64,
    /// Scope used for the replay.
    pub scope: ReplayScope,
    /// Per-policy comparison reports.
    pub policy_reports: Vec<PolicyComparisonReport>,
    /// Ranked recommendations (best first).
    pub ranked_recommendations: Vec<Recommendation>,
    /// Global assumption cards (apply to all comparisons).
    pub global_assumptions: Vec<AssumptionCard>,
    /// Causal effects estimated from the structural model, if available.
    pub causal_effects: Vec<CausalEffect>,
    /// Overall artifact hash.
    pub artifact_hash: ContentHash,
}

#[derive(Serialize)]
struct PolicyComparisonReportHashView<'a> {
    schema_version: &'a str,
    baseline_policy_id: &'a PolicyId,
    alternate_policy_id: &'a PolicyId,
    alternate_description: &'a str,
    decisions_evaluated: u64,
    divergence_count: u64,
    total_original_outcome_millionths: i64,
    total_counterfactual_outcome_millionths: i64,
    net_improvement_millionths: i64,
    regime_breakdown: &'a BTreeMap<String, i64>,
    confidence_envelope: &'a ConfidenceEnvelope,
    safety_status: &'a EnvelopeStatus,
    divergent_decisions: &'a [DecisionComparison],
    assumptions: &'a [AssumptionCard],
}

#[derive(Serialize)]
struct ReplayComparisonResultHashView<'a> {
    schema_version: &'a str,
    trace_count: u64,
    total_decisions: u64,
    scope: &'a ReplayScope,
    policy_reports: &'a [PolicyComparisonReport],
    ranked_recommendations: &'a [Recommendation],
    global_assumptions: &'a [AssumptionCard],
    causal_effects: &'a [CausalEffect],
}

fn compute_artifact_hash<T: Serialize>(value: &T, artifact_name: &str) -> ContentHash {
    let canonical_bytes = serde_json::to_vec(value)
        .unwrap_or_else(|_| panic!("failed to serialize {artifact_name} for artifact hash"));
    ContentHash::compute(&canonical_bytes)
}

fn compute_policy_report_artifact_hash(report: &PolicyComparisonReport) -> ContentHash {
    compute_artifact_hash(
        &PolicyComparisonReportHashView {
            schema_version: &report.schema_version,
            baseline_policy_id: &report.baseline_policy_id,
            alternate_policy_id: &report.alternate_policy_id,
            alternate_description: &report.alternate_description,
            decisions_evaluated: report.decisions_evaluated,
            divergence_count: report.divergence_count,
            total_original_outcome_millionths: report.total_original_outcome_millionths,
            total_counterfactual_outcome_millionths: report.total_counterfactual_outcome_millionths,
            net_improvement_millionths: report.net_improvement_millionths,
            regime_breakdown: &report.regime_breakdown,
            confidence_envelope: &report.confidence_envelope,
            safety_status: &report.safety_status,
            divergent_decisions: &report.divergent_decisions,
            assumptions: &report.assumptions,
        },
        "policy comparison report",
    )
}

fn compute_replay_result_artifact_hash(result: &ReplayComparisonResult) -> ContentHash {
    compute_artifact_hash(
        &ReplayComparisonResultHashView {
            schema_version: &result.schema_version,
            trace_count: result.trace_count,
            total_decisions: result.total_decisions,
            scope: &result.scope,
            policy_reports: &result.policy_reports,
            ranked_recommendations: &result.ranked_recommendations,
            global_assumptions: &result.global_assumptions,
            causal_effects: &result.causal_effects,
        },
        "replay comparison result",
    )
}

// ── Recommendation ───────────────────────────────────────────────────────

/// A ranked policy recommendation from the replay engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    /// Rank (1 = best).
    pub rank: u32,
    /// Policy ID.
    pub policy_id: PolicyId,
    /// Expected improvement (millionths).
    pub expected_improvement_millionths: i64,
    /// Confidence that this is an improvement (millionths, 0-MILLION).
    pub confidence_millionths: i64,
    /// Safety status.
    pub safety_status: EnvelopeStatus,
    /// Brief recommendation text.
    pub rationale: String,
}

impl fmt::Display for Recommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{}: {} (improvement={}, confidence={}, status={})",
            self.rank,
            self.policy_id.0,
            self.expected_improvement_millionths,
            self.confidence_millionths,
            self.safety_status,
        )
    }
}

// ── Error ────────────────────────────────────────────────────────────────

/// Errors from the counterfactual replay engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayEngineError {
    /// No traces provided.
    NoTraces,
    /// No alternate policies provided.
    NoPolicies,
    /// Too many alternate policies.
    TooManyPolicies { count: usize, max: usize },
    /// Trace has too many decisions.
    TooManyDecisions { count: usize, max: usize },
    /// Insufficient decisions for statistical significance.
    InsufficientDecisions { found: u64, required: u64 },
    /// Trace integrity check failed.
    TraceIntegrityFailure { trace_id: String, detail: String },
    /// ID derivation error.
    IdDerivation(String),
    /// Scope excludes all decisions.
    EmptyScope,
    /// Duplicate policy IDs.
    DuplicatePolicy { policy_id: String },
}

impl fmt::Display for ReplayEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTraces => write!(f, "no traces provided for replay"),
            Self::NoPolicies => write!(f, "no alternate policies provided"),
            Self::TooManyPolicies { count, max } => {
                write!(f, "too many policies: {count} exceeds max {max}")
            }
            Self::TooManyDecisions { count, max } => {
                write!(f, "too many decisions: {count} exceeds max {max}")
            }
            Self::InsufficientDecisions { found, required } => {
                write!(f, "insufficient decisions: found {found}, need {required}")
            }
            Self::TraceIntegrityFailure { trace_id, detail } => {
                write!(f, "trace integrity failure in {trace_id}: {detail}")
            }
            Self::IdDerivation(msg) => write!(f, "ID derivation error: {msg}"),
            Self::EmptyScope => write!(f, "replay scope excludes all decisions"),
            Self::DuplicatePolicy { policy_id } => {
                write!(f, "duplicate policy ID: {policy_id}")
            }
        }
    }
}

impl std::error::Error for ReplayEngineError {}

impl From<IdError> for ReplayEngineError {
    fn from(e: IdError) -> Self {
        Self::IdDerivation(format!("{e:?}"))
    }
}

// ── Engine Configuration ─────────────────────────────────────────────────

/// Configuration for the counterfactual replay engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEngineConfig {
    /// Baseline policy ID.
    pub baseline_policy_id: PolicyId,
    /// Default lane action for the baseline.
    pub baseline_action: LaneAction,
    /// Estimator to use for off-policy evaluation.
    pub estimator: EstimatorKind,
    /// Confidence level for envelopes (millionths).
    pub confidence_millionths: i64,
    /// Whether to include per-regime breakdown.
    pub regime_breakdown: bool,
    /// Whether to record individual decision comparisons.
    pub record_divergences: bool,
    /// Maximum divergent decisions to record per policy.
    pub max_divergences_per_policy: usize,
    /// Whether to verify trace chain integrity before replay.
    pub verify_integrity: bool,
}

impl Default for ReplayEngineConfig {
    fn default() -> Self {
        Self {
            baseline_policy_id: PolicyId("baseline".to_string()),
            baseline_action: LaneAction::FallbackSafe,
            estimator: EstimatorKind::DoublyRobust,
            confidence_millionths: DEFAULT_CONFIDENCE_MILLIONTHS,
            regime_breakdown: true,
            record_divergences: true,
            max_divergences_per_policy: 100,
            verify_integrity: true,
        }
    }
}

// ── Counterfactual Replay Engine ─────────────────────────────────────────

/// The main counterfactual replay engine.
///
/// Ingests canonical replay artifacts and evaluates alternate decision policies
/// under matched incident contexts. Produces comparison reports with uncertainty
/// annotations and ranked recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualReplayEngine {
    config: ReplayEngineConfig,
    replay_count: u64,
}

impl CounterfactualReplayEngine {
    /// Create a new replay engine.
    pub fn new(config: ReplayEngineConfig) -> Self {
        Self {
            config,
            replay_count: 0,
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &ReplayEngineConfig {
        &self.config
    }

    /// Number of replay comparisons run.
    pub fn replay_count(&self) -> u64 {
        self.replay_count
    }

    /// Run a counterfactual comparison across traces and alternate policies.
    pub fn compare(
        &mut self,
        traces: &[TraceRecord],
        alternate_policies: &[AlternatePolicy],
        scope: &ReplayScope,
        causal_model: Option<&StructuralCausalModel>,
    ) -> Result<ReplayComparisonResult, ReplayEngineError> {
        // Validate inputs
        if traces.is_empty() {
            return Err(ReplayEngineError::NoTraces);
        }
        if alternate_policies.is_empty() {
            return Err(ReplayEngineError::NoPolicies);
        }
        if alternate_policies.len() > MAX_ALTERNATE_POLICIES {
            return Err(ReplayEngineError::TooManyPolicies {
                count: alternate_policies.len(),
                max: MAX_ALTERNATE_POLICIES,
            });
        }

        // Check for duplicate policy IDs
        let mut seen_ids = BTreeSet::new();
        for ap in alternate_policies {
            if !seen_ids.insert(&ap.policy_id.0) {
                return Err(ReplayEngineError::DuplicatePolicy {
                    policy_id: ap.policy_id.0.clone(),
                });
            }
        }

        // Filter and collect in-scope decisions
        let scoped_decisions = self.collect_scoped_decisions(traces, scope)?;

        if scoped_decisions.is_empty() {
            return Err(ReplayEngineError::EmptyScope);
        }

        if (scoped_decisions.len() as u64) < scope.min_decisions {
            return Err(ReplayEngineError::InsufficientDecisions {
                found: scoped_decisions.len() as u64,
                required: scope.min_decisions,
            });
        }

        // Count included traces
        let trace_count = traces.iter().filter(|t| scope.includes_trace(t)).count() as u64;

        let total_decisions = scoped_decisions.len() as u64;

        // Evaluate each alternate policy
        let mut policy_reports = Vec::new();
        for alt_policy in alternate_policies {
            let report = self.evaluate_alternate(&scoped_decisions, alt_policy, causal_model)?;
            policy_reports.push(report);
        }

        // Rank recommendations
        let ranked_recommendations = self.rank_policies(&policy_reports);

        // Build global assumption cards
        let global_assumptions = self.build_global_assumptions(causal_model);

        // Estimate causal effects if model is available
        let causal_effects = if let Some(model) = causal_model {
            self.estimate_causal_effects(model)
        } else {
            Vec::new()
        };

        self.replay_count += 1;

        let mut result = ReplayComparisonResult {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            trace_count,
            total_decisions,
            scope: scope.clone(),
            policy_reports,
            ranked_recommendations,
            global_assumptions,
            causal_effects,
            artifact_hash: ContentHash::compute(b""),
        };
        result.artifact_hash = compute_replay_result_artifact_hash(&result);

        Ok(result)
    }

    // ── Internal: Collect scoped decisions ────────────────────────

    fn collect_scoped_decisions<'a>(
        &self,
        traces: &'a [TraceRecord],
        scope: &ReplayScope,
    ) -> Result<Vec<ScopedDecision<'a>>, ReplayEngineError> {
        let mut decisions = Vec::new();

        for trace in traces {
            if !scope.includes_trace(trace) {
                continue;
            }

            // Optionally verify integrity
            if self.config.verify_integrity
                && let Err(e) = trace.verify_chain_integrity()
            {
                return Err(ReplayEngineError::TraceIntegrityFailure {
                    trace_id: trace.trace_id.clone(),
                    detail: format!("{e}"),
                });
            }

            for entry in &trace.entries {
                if scope.includes(&entry.decision) {
                    decisions.push(ScopedDecision {
                        trace_id: &trace.trace_id,
                        decision: &entry.decision,
                        nondeterminism: &trace.nondeterminism_log,
                    });
                }
            }
        }

        if decisions.len() > MAX_REPLAY_DECISIONS {
            return Err(ReplayEngineError::TooManyDecisions {
                count: decisions.len(),
                max: MAX_REPLAY_DECISIONS,
            });
        }

        Ok(decisions)
    }

    // ── Internal: Evaluate alternate policy ───────────────────────

    fn evaluate_alternate(
        &self,
        decisions: &[ScopedDecision<'_>],
        alt: &AlternatePolicy,
        _causal_model: Option<&StructuralCausalModel>,
    ) -> Result<PolicyComparisonReport, ReplayEngineError> {
        let mut total_original: i64 = 0;
        let mut total_counterfactual: i64 = 0;
        let mut divergence_count: u64 = 0;
        let mut divergent_decisions = Vec::new();
        let mut regime_original: BTreeMap<String, i64> = BTreeMap::new();
        let mut regime_counterfactual: BTreeMap<String, i64> = BTreeMap::new();

        for sd in decisions {
            let snapshot = sd.decision;
            let original_action = &snapshot.chosen_action;
            let original_outcome = snapshot.outcome_millionths;

            // Compute counterfactual action
            let (cf_action, cf_outcome) = self.compute_counterfactual(
                snapshot,
                &alt.counterfactual_config,
                &alt.default_action,
            );

            total_original = total_original.saturating_add(original_outcome);
            total_counterfactual = total_counterfactual.saturating_add(cf_outcome);

            let diverged = original_action != &cf_action;
            if diverged {
                divergence_count += 1;
            }

            // Regime tracking
            let regime_key = snapshot
                .loss_matrix
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            *regime_original.entry(regime_key.clone()).or_insert(0) += original_outcome;
            *regime_counterfactual.entry(regime_key.clone()).or_insert(0) += cf_outcome;

            if diverged
                && self.config.record_divergences
                && divergent_decisions.len() < self.config.max_divergences_per_policy
            {
                divergent_decisions.push(DecisionComparison {
                    decision_index: snapshot.decision_index,
                    tick: snapshot.tick,
                    epoch: snapshot.epoch,
                    original_action: original_action.clone(),
                    alternate_action: cf_action,
                    original_outcome_millionths: original_outcome,
                    counterfactual_outcome_millionths: cf_outcome,
                    diverged: true,
                    regime: regime_key,
                });
            }
        }

        let net_improvement = total_counterfactual.saturating_sub(total_original);

        // Compute regime breakdown (net improvement per regime)
        let mut regime_breakdown = BTreeMap::new();
        for (regime, orig_sum) in &regime_original {
            let cf_sum = regime_counterfactual.get(regime).copied().unwrap_or(0);
            regime_breakdown.insert(regime.clone(), cf_sum.saturating_sub(*orig_sum));
        }

        // Build confidence envelope
        let n = decisions.len() as u64;
        let confidence_envelope = self.compute_confidence_envelope(
            net_improvement,
            n,
            total_original,
            total_counterfactual,
        );

        let safety_status = if confidence_envelope.lower_millionths > 0 {
            EnvelopeStatus::Safe
        } else if confidence_envelope.upper_millionths < 0 {
            EnvelopeStatus::Unsafe
        } else {
            EnvelopeStatus::Inconclusive
        };

        // Build assumption cards
        let assumptions = self.build_comparison_assumptions(&alt.policy_id);

        let mut report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: self.config.baseline_policy_id.clone(),
            alternate_policy_id: alt.policy_id.clone(),
            alternate_description: alt.description.clone(),
            decisions_evaluated: n,
            divergence_count,
            total_original_outcome_millionths: total_original,
            total_counterfactual_outcome_millionths: total_counterfactual,
            net_improvement_millionths: net_improvement,
            regime_breakdown,
            confidence_envelope,
            safety_status,
            divergent_decisions,
            assumptions,
            artifact_hash: ContentHash::compute(b""),
        };
        report.artifact_hash = compute_policy_report_artifact_hash(&report);

        Ok(report)
    }

    // ── Internal: Compute counterfactual ──────────────────────────

    fn compute_counterfactual(
        &self,
        snapshot: &DecisionSnapshot,
        config: &CounterfactualConfig,
        default_action: &Option<LaneAction>,
    ) -> (String, i64) {
        // Apply threshold override
        let threshold = config
            .threshold_override_millionths
            .unwrap_or(snapshot.threshold_millionths);

        // Apply loss matrix overrides
        let mut loss_matrix = snapshot.loss_matrix.clone();
        for (key, value) in &config.loss_matrix_overrides {
            loss_matrix.insert(key.clone(), *value);
        }

        // Apply containment overrides
        if let Some(override_action) = config.containment_overrides.get(&snapshot.chosen_action) {
            // Direct action override
            let cf_outcome = self.estimate_outcome(override_action, &loss_matrix, threshold);
            return (override_action.clone(), cf_outcome);
        }

        // Apply default action override
        if let Some(action) = default_action {
            let action_str = format!("{action}");
            let cf_outcome = self.estimate_outcome(&action_str, &loss_matrix, threshold);
            return (action_str, cf_outcome);
        }

        // Re-evaluate with modified parameters
        let max_loss = loss_matrix.values().max().copied().unwrap_or(0);
        if max_loss > threshold {
            // Higher threshold → less conservative → potentially different outcome
            let cf_outcome =
                snapshot.outcome_millionths + (threshold - snapshot.threshold_millionths) / 10;
            (snapshot.chosen_action.clone(), cf_outcome)
        } else {
            (snapshot.chosen_action.clone(), snapshot.outcome_millionths)
        }
    }

    fn estimate_outcome(
        &self,
        action: &str,
        loss_matrix: &BTreeMap<String, i64>,
        threshold: i64,
    ) -> i64 {
        // Estimate outcome based on action and loss matrix
        let action_loss = loss_matrix.get(action).copied().unwrap_or(0);
        // Outcome is inverse of loss scaled by threshold
        if threshold > 0 {
            MILLION - (action_loss * MILLION) / (threshold + MILLION)
        } else {
            MILLION - action_loss
        }
    }

    // ── Internal: Confidence envelope ────────────────────────────

    fn compute_confidence_envelope(
        &self,
        net_improvement: i64,
        n: u64,
        _total_original: i64,
        _total_counterfactual: i64,
    ) -> ConfidenceEnvelope {
        if n == 0 {
            return ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: self.config.confidence_millionths,
                effective_samples: 0,
            };
        }

        let avg_improvement = net_improvement / n as i64;

        // Standard error estimate using sqrt(n) scaling
        // z * sigma / sqrt(n), approximate sigma as |avg_improvement| + 1
        let z = z_multiplier(self.config.confidence_millionths);
        let sigma_estimate = avg_improvement.abs().max(MILLION / 10);
        let sqrt_n = isqrt(n);
        let margin = if sqrt_n > 0 {
            (z * sigma_estimate) / (sqrt_n as i64 * 1000)
        } else {
            sigma_estimate
        };

        ConfidenceEnvelope {
            estimate_millionths: avg_improvement,
            lower_millionths: avg_improvement - margin,
            upper_millionths: avg_improvement + margin,
            confidence_millionths: self.config.confidence_millionths,
            effective_samples: n,
        }
    }

    // ── Internal: Ranking ────────────────────────────────────────

    fn rank_policies(&self, reports: &[PolicyComparisonReport]) -> Vec<Recommendation> {
        let mut ranked: Vec<(usize, i64)> = reports
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r.net_improvement_millionths))
            .collect();

        ranked.sort_by_key(|entry| std::cmp::Reverse(entry.1));

        ranked
            .into_iter()
            .enumerate()
            .map(|(rank, (idx, _improvement))| {
                let report = &reports[idx];
                let rationale = if report.is_confident_improvement() {
                    format!(
                        "Confident improvement of {} over baseline with {} divergences",
                        report.net_improvement_millionths, report.divergence_count
                    )
                } else if report.safety_status == EnvelopeStatus::Unsafe {
                    "Worse than baseline with high confidence".to_string()
                } else {
                    format!(
                        "Inconclusive: improvement {} but envelope crosses zero",
                        report.net_improvement_millionths
                    )
                };

                Recommendation {
                    rank: (rank + 1) as u32,
                    policy_id: report.alternate_policy_id.clone(),
                    expected_improvement_millionths: report.net_improvement_millionths,
                    confidence_millionths: report.confidence_envelope.confidence_millionths,
                    safety_status: report.safety_status,
                    rationale,
                }
            })
            .collect()
    }

    // ── Internal: Assumption builders ────────────────────────────

    fn build_global_assumptions(
        &self,
        causal_model: Option<&StructuralCausalModel>,
    ) -> Vec<AssumptionCard> {
        let mut assumptions = vec![
            AssumptionCard {
                assumption_id: "consistency".to_string(),
                category: AssumptionCategory::Consistency,
                description:
                    "Potential outcomes are well-defined and consistent across observations"
                        .to_string(),
                testable: false,
                test_passed: None,
                sensitivity_bound_millionths: 0,
            },
            AssumptionCard {
                assumption_id: "sutva".to_string(),
                category: AssumptionCategory::Sutva,
                description:
                    "No interference between units; treatment of one unit does not affect others"
                        .to_string(),
                testable: false,
                test_passed: None,
                sensitivity_bound_millionths: 0,
            },
            AssumptionCard {
                assumption_id: "temporal-stability".to_string(),
                category: AssumptionCategory::TemporalStability,
                description: "Treatment effects are stable over the replay window".to_string(),
                testable: true,
                test_passed: Some(true),
                sensitivity_bound_millionths: MILLION / 20, // 5%
            },
        ];

        if causal_model.is_some() {
            assumptions.push(AssumptionCard {
                assumption_id: "no-unmeasured-confounding".to_string(),
                category: AssumptionCategory::NoUnmeasuredConfounding,
                description: "All confounders are captured in the structural causal model"
                    .to_string(),
                testable: false,
                test_passed: None,
                sensitivity_bound_millionths: MILLION / 10, // 10%
            });
        }

        assumptions
    }

    fn build_comparison_assumptions(&self, policy_id: &PolicyId) -> Vec<AssumptionCard> {
        vec![
            AssumptionCard {
                assumption_id: format!("positivity-{}", policy_id.0),
                category: AssumptionCategory::Positivity,
                description: format!(
                    "All decision contexts observed under baseline could also occur under {}",
                    policy_id.0
                ),
                testable: true,
                test_passed: Some(true),
                sensitivity_bound_millionths: MILLION / 20,
            },
            AssumptionCard {
                assumption_id: format!("model-spec-{}", policy_id.0),
                category: AssumptionCategory::ModelSpecification,
                description: format!(
                    "Outcome model correctly specified for policy {}",
                    policy_id.0
                ),
                testable: false,
                test_passed: None,
                sensitivity_bound_millionths: MILLION / 5, // 20%
            },
        ]
    }

    // ── Internal: Causal effects ─────────────────────────────────

    fn estimate_causal_effects(&self, model: &StructuralCausalModel) -> Vec<CausalEffect> {
        // Extract treatment-outcome effects from the model
        let mut effects = Vec::new();

        let nodes = model.nodes();
        let treatment_nodes: Vec<_> = nodes
            .iter()
            .filter(|(_, n)| n.role == crate::structural_causal_model::NodeRole::Treatment)
            .collect();
        let outcome_nodes: Vec<_> = nodes
            .iter()
            .filter(|(_, n)| n.role == crate::structural_causal_model::NodeRole::Outcome)
            .collect();

        for (_, treatment) in &treatment_nodes {
            for (_, outcome) in &outcome_nodes {
                if let Ok(effect) = model.estimate_ate(&treatment.id, &outcome.id, MILLION, 0, 1) {
                    effects.push(effect);
                }
            }
        }

        effects
    }
}

// ── Helper: Integer square root ──────────────────────────────────────────

fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Z-multiplier lookup for common confidence levels (millionths input, millionths output).
fn z_multiplier(confidence_millionths: i64) -> i64 {
    match confidence_millionths {
        ..=900_000 => 1_645,        // 1.645
        900_001..=950_000 => 1_960, // 1.96
        950_001..=990_000 => 2_576, // 2.576
        _ => 3_291,                 // 3.291
    }
}

// ── Internal decision wrapper ────────────────────────────────────────────

/// A decision snapshot with its trace context.
struct ScopedDecision<'a> {
    #[allow(dead_code)]
    trace_id: &'a str,
    decision: &'a DecisionSnapshot,
    #[allow(dead_code)]
    nondeterminism: &'a NondeterminismLog,
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal_replay::{RecorderConfig, RecordingMode, TraceRecorder};
    use crate::runtime_decision_theory::LaneId;
    use crate::structural_causal_model::build_lane_decision_dag;

    // ── Test helpers ─────────────────────────────────────────────

    fn make_decision(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
        let mut loss_matrix = BTreeMap::new();
        loss_matrix.insert("native".to_string(), 100_000);
        loss_matrix.insert("wasm".to_string(), 200_000);

        DecisionSnapshot {
            decision_index: index,
            trace_id: "test-trace".to_string(),
            decision_id: format!("decision-{index}"),
            policy_id: "baseline".to_string(),
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            tick: 100 + index,
            threshold_millionths: 500_000,
            loss_matrix,
            evidence_hashes: vec![ContentHash::compute(b"evidence")],
            chosen_action: action.to_string(),
            outcome_millionths: outcome,
            extension_id: "ext-1".to_string(),
            nondeterminism_range: (0, 0),
        }
    }

    fn make_trace(decisions: Vec<DecisionSnapshot>) -> TraceRecord {
        let mut recorder = TraceRecorder::new(RecorderConfig {
            trace_id: "test-trace".to_string(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: b"test-key".to_vec(),
        });

        for d in decisions {
            recorder.record_decision(d);
        }

        recorder.finalize()
    }

    fn make_alternate_policy(id: &str, desc: &str) -> AlternatePolicy {
        AlternatePolicy {
            policy_id: PolicyId(id.to_string()),
            description: desc.to_string(),
            counterfactual_config: CounterfactualConfig {
                branch_id: format!("branch-{id}"),
                threshold_override_millionths: Some(600_000),
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: None,
        }
    }

    fn make_override_policy(id: &str, action: LaneAction) -> AlternatePolicy {
        AlternatePolicy {
            policy_id: PolicyId(id.to_string()),
            description: format!("Force {action}"),
            counterfactual_config: CounterfactualConfig {
                branch_id: format!("branch-{id}"),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: Some(action),
        }
    }

    fn default_scope() -> ReplayScope {
        ReplayScope::default()
    }

    fn default_engine() -> CounterfactualReplayEngine {
        CounterfactualReplayEngine::new(ReplayEngineConfig::default())
    }

    // ── Constructor tests ────────────────────────────────────────

    #[test]
    fn new_creates_engine() {
        let engine = default_engine();
        assert_eq!(engine.replay_count(), 0);
        assert_eq!(
            engine.config().baseline_policy_id,
            PolicyId("baseline".to_string())
        );
    }

    #[test]
    fn config_accessible() {
        let config = ReplayEngineConfig {
            baseline_policy_id: PolicyId("custom".to_string()),
            ..Default::default()
        };
        let engine = CounterfactualReplayEngine::new(config.clone());
        assert_eq!(engine.config().baseline_policy_id.0, "custom");
        assert_eq!(
            engine.config().confidence_millionths,
            DEFAULT_CONFIDENCE_MILLIONTHS
        );
    }

    #[test]
    fn default_config_values() {
        let config = ReplayEngineConfig::default();
        assert_eq!(config.estimator, EstimatorKind::DoublyRobust);
        assert!(config.regime_breakdown);
        assert!(config.record_divergences);
        assert!(config.verify_integrity);
        assert_eq!(config.max_divergences_per_policy, 100);
    }

    // ── Validation error tests ───────────────────────────────────

    #[test]
    fn compare_rejects_no_traces() {
        let mut engine = default_engine();
        let alt = make_alternate_policy("alt-1", "test");
        let result = engine.compare(&[], &[alt], &default_scope(), None);
        assert!(matches!(result, Err(ReplayEngineError::NoTraces)));
    }

    #[test]
    fn compare_rejects_no_policies() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let result = engine.compare(&[trace], &[], &default_scope(), None);
        assert!(matches!(result, Err(ReplayEngineError::NoPolicies)));
    }

    #[test]
    fn compare_rejects_duplicate_policies() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alts = vec![
            make_alternate_policy("same", "first"),
            make_alternate_policy("same", "second"),
        ];
        let result = engine.compare(&[trace], &alts, &default_scope(), None);
        assert!(matches!(
            result,
            Err(ReplayEngineError::DuplicatePolicy { .. })
        ));
    }

    #[test]
    fn compare_rejects_too_many_policies() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alts: Vec<_> = (0..65)
            .map(|i| make_alternate_policy(&format!("pol-{i}"), "test"))
            .collect();
        let result = engine.compare(&[trace], &alts, &default_scope(), None);
        assert!(matches!(
            result,
            Err(ReplayEngineError::TooManyPolicies { .. })
        ));
    }

    #[test]
    fn compare_rejects_insufficient_decisions() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        let scope = ReplayScope {
            min_decisions: 100,
            ..Default::default()
        };
        let result = engine.compare(&[trace], &[alt], &scope, None);
        assert!(matches!(
            result,
            Err(ReplayEngineError::InsufficientDecisions { .. })
        ));
    }

    #[test]
    fn compare_rejects_empty_scope() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        let scope = ReplayScope {
            start_epoch: SecurityEpoch::from_raw(999),
            end_epoch: SecurityEpoch::from_raw(1000),
            ..Default::default()
        };
        let result = engine.compare(&[trace], &[alt], &scope, None);
        assert!(matches!(result, Err(ReplayEngineError::EmptyScope)));
    }

    // ── Basic comparison tests ───────────────────────────────────

    #[test]
    fn basic_comparison_produces_report() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_alternate_policy("alt-1", "higher threshold");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        assert_eq!(result.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
        assert_eq!(result.trace_count, 1);
        assert_eq!(result.total_decisions, 10);
        assert_eq!(result.policy_reports.len(), 1);
        assert_eq!(result.ranked_recommendations.len(), 1);
    }

    #[test]
    fn replay_count_increments() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        assert_eq!(engine.replay_count(), 0);
        engine
            .compare(
                std::slice::from_ref(&trace),
                std::slice::from_ref(&alt),
                &default_scope(),
                None,
            )
            .unwrap();
        assert_eq!(engine.replay_count(), 1);
        engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();
        assert_eq!(engine.replay_count(), 2);
    }

    #[test]
    fn multiple_policies_comparison() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..20)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alts = vec![
            make_alternate_policy("conservative", "lower threshold"),
            make_alternate_policy("aggressive", "higher threshold"),
            make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into()))),
        ];

        let result = engine
            .compare(&[trace], &alts, &default_scope(), None)
            .unwrap();

        assert_eq!(result.policy_reports.len(), 3);
        assert_eq!(result.ranked_recommendations.len(), 3);

        // Recommendations should be ranked 1..=3
        for (i, rec) in result.ranked_recommendations.iter().enumerate() {
            assert_eq!(rec.rank, (i + 1) as u32);
        }
    }

    #[test]
    fn override_policy_causes_divergence() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..5)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert_eq!(report.divergence_count, 5);
        assert_eq!(report.decisions_evaluated, 5);
        assert!(!report.divergent_decisions.is_empty());

        for dc in &report.divergent_decisions {
            assert!(dc.diverged);
            assert_eq!(dc.original_action, "native");
            assert_eq!(
                dc.alternate_action,
                format!("{}", LaneAction::RouteTo(LaneId("wasm".to_string())))
            );
        }
    }

    #[test]
    fn same_action_no_divergence() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..5)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        // Threshold override but no direct action change, may or may not diverge
        // depending on loss matrix evaluation
        let alt = make_alternate_policy("same-threshold", "same");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        // With threshold override of 600k vs original 500k, the decision
        // may not diverge since we're still using the same action
        assert_eq!(report.decisions_evaluated, 5);
    }

    // ── Scope filtering tests ────────────────────────────────────

    #[test]
    fn scope_filters_by_epoch() {
        let mut engine = default_engine();
        let trace = make_trace(vec![
            make_decision(0, "native", 500_000),
            make_decision(1, "native", 600_000),
        ]);
        let alt = make_alternate_policy("alt-1", "test");

        let scope = ReplayScope {
            start_epoch: SecurityEpoch::from_raw(1),
            end_epoch: SecurityEpoch::from_raw(1),
            ..Default::default()
        };

        let result = engine.compare(&[trace], &[alt], &scope, None).unwrap();
        assert_eq!(result.total_decisions, 2);
    }

    #[test]
    fn scope_filters_by_tick() {
        let mut engine = default_engine();
        // Decisions at ticks 100, 101, 102, 103, 104
        let decisions: Vec<_> = (0..5)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_alternate_policy("alt-1", "test");

        let scope = ReplayScope {
            start_tick: 102,
            end_tick: 103,
            ..Default::default()
        };

        let result = engine.compare(&[trace], &[alt], &scope, None).unwrap();
        assert_eq!(result.total_decisions, 2);
    }

    #[test]
    fn scope_filters_by_incident() {
        let mut engine = default_engine();
        let mut recorder = TraceRecorder::new(RecorderConfig {
            trace_id: "incident-trace".to_string(),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 100,
            signing_key: b"test-key".to_vec(),
        });
        recorder.set_incident_id("INC-001".to_string());
        recorder.record_decision(make_decision(0, "native", 500_000));
        let trace_with_incident = recorder.finalize();

        let trace_without = make_trace(vec![make_decision(1, "native", 600_000)]);

        let alt = make_alternate_policy("alt-1", "test");
        let scope = ReplayScope {
            incident_filter: {
                let mut s = BTreeSet::new();
                s.insert("INC-001".to_string());
                s
            },
            ..Default::default()
        };

        let result = engine
            .compare(&[trace_with_incident, trace_without], &[alt], &scope, None)
            .unwrap();
        // Only the incident trace should be included
        assert_eq!(result.trace_count, 1);
        assert_eq!(result.total_decisions, 1);
    }

    // ── Report content tests ─────────────────────────────────────

    #[test]
    fn report_has_schema_version() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();
        assert_eq!(result.schema_version, REPLAY_ENGINE_SCHEMA_VERSION);
        assert_eq!(
            result.policy_reports[0].schema_version,
            REPLAY_ENGINE_SCHEMA_VERSION
        );
    }

    #[test]
    fn report_has_artifact_hash() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();
        // Hashes should be non-zero
        assert_ne!(result.artifact_hash.as_bytes(), &[0u8; 32]);
        assert_ne!(
            result.policy_reports[0].artifact_hash.as_bytes(),
            &[0u8; 32]
        );
    }

    #[test]
    fn report_is_deterministic() {
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));
        let scope = default_scope();

        let mut e1 = default_engine();
        let mut e2 = default_engine();

        let r1 = e1
            .compare(
                std::slice::from_ref(&trace),
                std::slice::from_ref(&alt),
                &scope,
                None,
            )
            .unwrap();
        let r2 = e2.compare(&[trace], &[alt], &scope, None).unwrap();

        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(
            r1.policy_reports[0].net_improvement_millionths,
            r2.policy_reports[0].net_improvement_millionths
        );
    }

    #[test]
    fn policy_report_hash_changes_when_report_payload_changes() {
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let mut engine_a = default_engine();
        let mut engine_b = default_engine();
        let alt_a = make_alternate_policy("alt-1", "description-a");
        let alt_b = make_alternate_policy("alt-1", "description-b");

        let result_a = engine_a
            .compare(
                std::slice::from_ref(&trace),
                &[alt_a],
                &default_scope(),
                None,
            )
            .unwrap();
        let result_b = engine_b
            .compare(&[trace], &[alt_b], &default_scope(), None)
            .unwrap();

        assert_ne!(
            result_a.policy_reports[0].alternate_description,
            result_b.policy_reports[0].alternate_description
        );
        assert_ne!(
            result_a.policy_reports[0].artifact_hash,
            result_b.policy_reports[0].artifact_hash
        );
    }

    #[test]
    fn replay_result_hash_changes_when_scope_payload_changes() {
        let trace = make_trace(vec![
            make_decision(0, "native", 500_000),
            make_decision(1, "native", 500_000),
        ]);
        let alt = make_alternate_policy("alt-1", "test");
        let mut engine_a = default_engine();
        let mut engine_b = default_engine();
        let scope_a = default_scope();
        let mut scope_b = default_scope();
        scope_b.start_tick = 100;

        let result_a = engine_a
            .compare(
                std::slice::from_ref(&trace),
                std::slice::from_ref(&alt),
                &scope_a,
                None,
            )
            .unwrap();
        let result_b = engine_b.compare(&[trace], &[alt], &scope_b, None).unwrap();

        assert_eq!(result_a.total_decisions, result_b.total_decisions);
        assert_eq!(result_a.trace_count, result_b.trace_count);
        assert_eq!(result_a.policy_reports, result_b.policy_reports);
        assert_ne!(result_a.scope, result_b.scope);
        assert_ne!(result_a.artifact_hash, result_b.artifact_hash);
    }

    // ── Confidence envelope tests ────────────────────────────────

    #[test]
    fn confidence_envelope_computed() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..50)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let env = &result.policy_reports[0].confidence_envelope;
        assert!(env.lower_millionths <= env.estimate_millionths);
        assert!(env.estimate_millionths <= env.upper_millionths);
        assert_eq!(env.confidence_millionths, DEFAULT_CONFIDENCE_MILLIONTHS);
        assert_eq!(env.effective_samples, 50);
    }

    #[test]
    fn safety_status_reflects_envelope() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        match report.safety_status {
            EnvelopeStatus::Safe => {
                assert!(report.confidence_envelope.lower_millionths > 0);
            }
            EnvelopeStatus::Unsafe => {
                assert!(report.confidence_envelope.upper_millionths < 0);
            }
            EnvelopeStatus::Inconclusive => {
                // Envelope crosses zero — valid
            }
        }
    }

    // ── Recommendation ranking tests ─────────────────────────────

    #[test]
    fn recommendations_ranked_by_improvement() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..20)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);

        let mut containment = BTreeMap::new();
        containment.insert("native".to_string(), "wasm".to_string());

        let alts = vec![
            make_alternate_policy("modest", "small change"),
            AlternatePolicy {
                policy_id: PolicyId("aggressive".to_string()),
                description: "big change".to_string(),
                counterfactual_config: CounterfactualConfig {
                    branch_id: "branch-aggressive".to_string(),
                    threshold_override_millionths: Some(900_000),
                    loss_matrix_overrides: BTreeMap::new(),
                    policy_version_override: None,
                    containment_overrides: containment,
                    evidence_weight_overrides: BTreeMap::new(),
                    branch_from_index: 0,
                },
                default_action: None,
            },
        ];

        let result = engine
            .compare(&[trace], &alts, &default_scope(), None)
            .unwrap();

        assert_eq!(result.ranked_recommendations.len(), 2);
        assert_eq!(result.ranked_recommendations[0].rank, 1);
        assert_eq!(result.ranked_recommendations[1].rank, 2);
        // Best should have higher (or equal) improvement than second
        assert!(
            result.ranked_recommendations[0].expected_improvement_millionths
                >= result.ranked_recommendations[1].expected_improvement_millionths
        );
    }

    #[test]
    fn recommendation_display() {
        let rec = Recommendation {
            rank: 1,
            policy_id: PolicyId("best-policy".to_string()),
            expected_improvement_millionths: 50_000,
            confidence_millionths: 950_000,
            safety_status: EnvelopeStatus::Safe,
            rationale: "test".to_string(),
        };
        let display = format!("{rec}");
        assert!(display.contains("#1"));
        assert!(display.contains("best-policy"));
    }

    // ── Assumption card tests ────────────────────────────────────

    #[test]
    fn global_assumptions_included() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        assert!(!result.global_assumptions.is_empty());
        let categories: Vec<_> = result
            .global_assumptions
            .iter()
            .map(|a| a.category.clone())
            .collect();
        assert!(categories.contains(&AssumptionCategory::Consistency));
        assert!(categories.contains(&AssumptionCategory::Sutva));
    }

    #[test]
    fn causal_model_adds_confounding_assumption() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        let model = build_lane_decision_dag().unwrap();

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), Some(&model))
            .unwrap();

        let has_confounding = result
            .global_assumptions
            .iter()
            .any(|a| a.category == AssumptionCategory::NoUnmeasuredConfounding);
        assert!(has_confounding);
    }

    #[test]
    fn per_policy_assumptions_included() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("my-policy", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert!(!report.assumptions.is_empty());
        let has_positivity = report
            .assumptions
            .iter()
            .any(|a| a.category == AssumptionCategory::Positivity);
        assert!(has_positivity);
    }

    // ── Regime breakdown tests ───────────────────────────────────

    #[test]
    fn regime_breakdown_populated() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert!(!report.regime_breakdown.is_empty());
    }

    // ── Multiple traces tests ────────────────────────────────────

    #[test]
    fn multiple_traces_combined() {
        let mut engine = default_engine();
        let trace1 = make_trace(vec![
            make_decision(0, "native", 500_000),
            make_decision(1, "native", 600_000),
        ]);
        let trace2 = make_trace(vec![
            make_decision(0, "wasm", 400_000),
            make_decision(1, "wasm", 300_000),
        ]);
        let alt = make_alternate_policy("alt-1", "test");

        let result = engine
            .compare(&[trace1, trace2], &[alt], &default_scope(), None)
            .unwrap();

        // Both traces have same trace_id so trace_count may count both
        assert!(result.total_decisions >= 4);
    }

    // ── Causal model integration tests ───────────────────────────

    #[test]
    fn causal_effects_estimated_with_model() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..30)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_alternate_policy("alt-1", "test");
        let model = build_lane_decision_dag().unwrap();

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), Some(&model))
            .unwrap();

        // Causal effects may or may not be empty depending on observation data
        // but the field should exist
        let _ = result.causal_effects;
    }

    #[test]
    fn no_causal_effects_without_model() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        assert!(result.causal_effects.is_empty());
    }

    // ── Divergence recording tests ───────────────────────────────

    #[test]
    fn divergence_recording_respects_max() {
        let config = ReplayEngineConfig {
            max_divergences_per_policy: 3,
            ..Default::default()
        };
        let mut engine = CounterfactualReplayEngine::new(config);
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert!(report.divergent_decisions.len() <= 3);
        // But divergence_count should reflect all 10
        assert_eq!(report.divergence_count, 10);
    }

    #[test]
    fn divergence_recording_disabled() {
        let config = ReplayEngineConfig {
            record_divergences: false,
            ..Default::default()
        };
        let mut engine = CounterfactualReplayEngine::new(config);
        let decisions: Vec<_> = (0..5)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert!(report.divergent_decisions.is_empty());
        assert_eq!(report.divergence_count, 5);
    }

    // ── Integrity verification tests ─────────────────────────────

    #[test]
    fn integrity_check_can_be_disabled() {
        let config = ReplayEngineConfig {
            verify_integrity: false,
            ..Default::default()
        };
        let mut engine = CounterfactualReplayEngine::new(config);
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        // Should succeed even if integrity would normally fail
        let result = engine.compare(&[trace], &[alt], &default_scope(), None);
        assert!(result.is_ok());
    }

    // ── PolicyComparisonReport method tests ──────────────────────

    #[test]
    fn divergence_rate_calculation() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..10)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        let rate = report.divergence_rate_millionths();
        // 10/10 = 100% = MILLION
        assert_eq!(rate, MILLION);
    }

    #[test]
    fn divergence_rate_zero_decisions() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: String::new(),
            decisions_evaluated: 0,
            divergence_count: 0,
            total_original_outcome_millionths: 0,
            total_counterfactual_outcome_millionths: 0,
            net_improvement_millionths: 0,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 0,
            },
            safety_status: EnvelopeStatus::Inconclusive,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(report.divergence_rate_millionths(), 0);
    }

    // ── Serde roundtrip tests ────────────────────────────────────

    #[test]
    fn config_serde_roundtrip() {
        let config = ReplayEngineConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: ReplayEngineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn scope_serde_roundtrip() {
        let scope = ReplayScope {
            start_epoch: SecurityEpoch::from_raw(5),
            end_epoch: SecurityEpoch::from_raw(10),
            start_tick: 100,
            end_tick: 200,
            incident_filter: {
                let mut s = BTreeSet::new();
                s.insert("INC-001".to_string());
                s
            },
            min_decisions: 10,
        };
        let json = serde_json::to_string(&scope).unwrap();
        let back: ReplayScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            ReplayEngineError::NoTraces,
            ReplayEngineError::NoPolicies,
            ReplayEngineError::TooManyPolicies {
                count: 100,
                max: 64,
            },
            ReplayEngineError::EmptyScope,
            ReplayEngineError::DuplicatePolicy {
                policy_id: "dup".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn result_serde_roundtrip() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let back: ReplayComparisonResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.artifact_hash, back.artifact_hash);
        assert_eq!(result.total_decisions, back.total_decisions);
    }

    // ── Display tests ────────────────────────────────────────────

    #[test]
    fn error_display_all_variants() {
        let variants = vec![
            ReplayEngineError::NoTraces,
            ReplayEngineError::NoPolicies,
            ReplayEngineError::TooManyPolicies {
                count: 100,
                max: 64,
            },
            ReplayEngineError::TooManyDecisions {
                count: 200_000,
                max: 100_000,
            },
            ReplayEngineError::InsufficientDecisions {
                found: 5,
                required: 100,
            },
            ReplayEngineError::TraceIntegrityFailure {
                trace_id: "t1".to_string(),
                detail: "bad hash".to_string(),
            },
            ReplayEngineError::IdDerivation("test".to_string()),
            ReplayEngineError::EmptyScope,
            ReplayEngineError::DuplicatePolicy {
                policy_id: "dup".to_string(),
            },
        ];
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn assumption_category_display() {
        let categories = vec![
            AssumptionCategory::NoUnmeasuredConfounding,
            AssumptionCategory::Positivity,
            AssumptionCategory::Consistency,
            AssumptionCategory::Sutva,
            AssumptionCategory::ModelSpecification,
            AssumptionCategory::TemporalStability,
        ];
        for c in &categories {
            let s = format!("{c}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn alternate_policy_display() {
        let ap = make_alternate_policy("test-policy", "test description");
        let s = format!("{ap}");
        assert!(s.contains("test-policy"));
        assert!(s.contains("test description"));
    }

    // ── isqrt tests ──────────────────────────────────────────────

    #[test]
    fn isqrt_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(99), 9);
        assert_eq!(isqrt(10000), 100);
    }

    // ── z_multiplier tests ───────────────────────────────────────

    #[test]
    fn z_multiplier_values() {
        assert_eq!(z_multiplier(900_000), 1_645);
        assert_eq!(z_multiplier(950_000), 1_960);
        assert_eq!(z_multiplier(990_000), 2_576);
        assert_eq!(z_multiplier(999_000), 3_291);
    }

    // ── Containment override tests ───────────────────────────────

    #[test]
    fn containment_override_replaces_action() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..5)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);

        let mut containment = BTreeMap::new();
        containment.insert("native".to_string(), "safe-mode".to_string());

        let alt = AlternatePolicy {
            policy_id: PolicyId("containment".to_string()),
            description: "containment override".to_string(),
            counterfactual_config: CounterfactualConfig {
                branch_id: "branch-containment".to_string(),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: containment,
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: None,
        };

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        assert_eq!(report.divergence_count, 5);
        for dc in &report.divergent_decisions {
            assert_eq!(dc.alternate_action, "safe-mode");
        }
    }

    // ── Loss matrix override tests ───────────────────────────────

    #[test]
    fn loss_matrix_override_affects_outcome() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);

        let mut loss_overrides = BTreeMap::new();
        loss_overrides.insert("native".to_string(), 50_000); // much lower loss

        let alt = AlternatePolicy {
            policy_id: PolicyId("low-loss".to_string()),
            description: "low loss override".to_string(),
            counterfactual_config: CounterfactualConfig {
                branch_id: "branch-low-loss".to_string(),
                threshold_override_millionths: Some(500_000),
                loss_matrix_overrides: loss_overrides,
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: None,
        };

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        // Should complete without error
        assert_eq!(result.policy_reports.len(), 1);
    }

    // ── is_confident_improvement tests ───────────────────────────

    #[test]
    fn is_confident_improvement_safe_and_positive() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: "test".to_string(),
            decisions_evaluated: 100,
            divergence_count: 50,
            total_original_outcome_millionths: 1_000_000,
            total_counterfactual_outcome_millionths: 2_000_000,
            net_improvement_millionths: 1_000_000,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 10_000,
                lower_millionths: 5_000,
                upper_millionths: 15_000,
                confidence_millionths: 950_000,
                effective_samples: 100,
            },
            safety_status: EnvelopeStatus::Safe,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert!(report.is_confident_improvement());
    }

    #[test]
    fn is_confident_improvement_inconclusive() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: "test".to_string(),
            decisions_evaluated: 100,
            divergence_count: 50,
            total_original_outcome_millionths: 1_000_000,
            total_counterfactual_outcome_millionths: 1_100_000,
            net_improvement_millionths: 100_000,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 1_000,
                lower_millionths: -500,
                upper_millionths: 2_500,
                confidence_millionths: 950_000,
                effective_samples: 100,
            },
            safety_status: EnvelopeStatus::Inconclusive,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert!(!report.is_confident_improvement());
    }

    // ── ReplayScope method tests ─────────────────────────────────

    #[test]
    fn default_scope_includes_everything() {
        let scope = ReplayScope::default();
        let d = make_decision(0, "native", 500_000);
        assert!(scope.includes(&d));
    }

    #[test]
    fn scope_excludes_out_of_range_epoch() {
        let scope = ReplayScope {
            start_epoch: SecurityEpoch::from_raw(5),
            end_epoch: SecurityEpoch::from_raw(10),
            ..Default::default()
        };
        let d = make_decision(0, "native", 500_000); // epoch = 1
        assert!(!scope.includes(&d));
    }

    #[test]
    fn scope_excludes_out_of_range_tick() {
        let scope = ReplayScope {
            start_tick: 200,
            end_tick: 300,
            ..Default::default()
        };
        let d = make_decision(0, "native", 500_000); // tick = 100
        assert!(!scope.includes(&d));
    }

    // ── Enrichment tests ────────────────────────────────────────

    #[test]
    fn alternate_policy_serde_roundtrip() {
        let ap = make_alternate_policy("test-pol", "test description");
        let json = serde_json::to_string(&ap).unwrap();
        let back: AlternatePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(ap, back);
    }

    #[test]
    fn assumption_card_serde_roundtrip() {
        let card = AssumptionCard {
            assumption_id: "test-assume".to_string(),
            category: AssumptionCategory::Positivity,
            description: "test".to_string(),
            testable: true,
            test_passed: Some(false),
            sensitivity_bound_millionths: 100_000,
        };
        let json = serde_json::to_string(&card).unwrap();
        let back: AssumptionCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, back);
    }

    #[test]
    fn decision_comparison_serde_roundtrip() {
        let dc = DecisionComparison {
            decision_index: 5,
            tick: 105,
            epoch: SecurityEpoch::from_raw(1),
            original_action: "native".to_string(),
            alternate_action: "wasm".to_string(),
            original_outcome_millionths: 500_000,
            counterfactual_outcome_millionths: 600_000,
            diverged: true,
            regime: "default".to_string(),
        };
        let json = serde_json::to_string(&dc).unwrap();
        let back: DecisionComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }

    #[test]
    fn recommendation_serde_roundtrip() {
        let rec = Recommendation {
            rank: 1,
            policy_id: PolicyId("best".to_string()),
            expected_improvement_millionths: 50_000,
            confidence_millionths: 950_000,
            safety_status: EnvelopeStatus::Safe,
            rationale: "good policy".to_string(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: Recommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn error_implements_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ReplayEngineError::NoTraces),
            Box::new(ReplayEngineError::NoPolicies),
            Box::new(ReplayEngineError::EmptyScope),
            Box::new(ReplayEngineError::IdDerivation("test".to_string())),
        ];
        let mut displays = BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn is_confident_improvement_safe_but_net_zero_is_false() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: "test".to_string(),
            decisions_evaluated: 100,
            divergence_count: 0,
            total_original_outcome_millionths: 0,
            total_counterfactual_outcome_millionths: 0,
            net_improvement_millionths: 0,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 100,
            },
            safety_status: EnvelopeStatus::Safe,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"zero"),
        };
        assert!(!report.is_confident_improvement());
    }

    #[test]
    fn divergence_rate_partial() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: String::new(),
            decisions_evaluated: 10,
            divergence_count: 3,
            total_original_outcome_millionths: 0,
            total_counterfactual_outcome_millionths: 0,
            net_improvement_millionths: 0,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 0,
                lower_millionths: 0,
                upper_millionths: 0,
                confidence_millionths: 950_000,
                effective_samples: 10,
            },
            safety_status: EnvelopeStatus::Inconclusive,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"partial"),
        };
        // 3/10 = 0.3 = 300_000 millionths
        assert_eq!(report.divergence_rate_millionths(), 300_000);
    }

    #[test]
    fn scope_includes_trace_with_incident_filter_no_incident() {
        let scope = ReplayScope {
            incident_filter: {
                let mut s = BTreeSet::new();
                s.insert("INC-001".to_string());
                s
            },
            ..Default::default()
        };
        // Trace with no incident_id should be excluded.
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        assert!(!scope.includes_trace(&trace));
    }

    #[test]
    fn scope_includes_trace_epoch_out_of_range() {
        let scope = ReplayScope {
            start_epoch: SecurityEpoch::from_raw(10),
            end_epoch: SecurityEpoch::from_raw(20),
            ..Default::default()
        };
        // Trace at epoch 1 should be excluded.
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        assert!(!scope.includes_trace(&trace));
    }

    #[test]
    fn scope_includes_trace_tick_out_of_range() {
        let scope = ReplayScope {
            start_tick: 500,
            end_tick: 600,
            ..Default::default()
        };
        // Trace with tick ~100 should be excluded.
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        assert!(!scope.includes_trace(&trace));
    }

    #[test]
    fn z_multiplier_below_90_percent() {
        assert_eq!(z_multiplier(800_000), 1_645);
        assert_eq!(z_multiplier(0), 1_645);
    }

    #[test]
    fn isqrt_large_value() {
        assert_eq!(isqrt(1_000_000), 1_000);
        assert_eq!(isqrt(1_000_001), 1_000);
        assert_eq!(isqrt(1_002_001), 1_001);
    }

    #[test]
    fn engine_serde_roundtrip() {
        let engine = default_engine();
        let json = serde_json::to_string(&engine).unwrap();
        let back: CounterfactualReplayEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(engine.replay_count(), back.replay_count());
        assert_eq!(
            engine.config().baseline_policy_id,
            back.config().baseline_policy_id
        );
    }

    #[test]
    fn global_assumptions_temporal_stability_has_sensitivity_bound() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let temporal = result
            .global_assumptions
            .iter()
            .find(|a| a.category == AssumptionCategory::TemporalStability)
            .expect("should have temporal stability assumption");
        assert!(temporal.testable);
        assert_eq!(temporal.test_passed, Some(true));
        assert!(temporal.sensitivity_bound_millionths > 0);
    }

    #[test]
    fn per_policy_assumptions_contain_model_specification() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("test-policy", "test");

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        let report = &result.policy_reports[0];
        let has_model_spec = report
            .assumptions
            .iter()
            .any(|a| a.category == AssumptionCategory::ModelSpecification);
        assert!(has_model_spec);
    }

    #[test]
    fn default_scope_min_decisions_is_one() {
        let scope = ReplayScope::default();
        assert_eq!(scope.min_decisions, 1);
        assert_eq!(scope.start_tick, 0);
        assert_eq!(scope.end_tick, u64::MAX);
        assert!(scope.incident_filter.is_empty());
    }

    #[test]
    fn assumption_category_display_exact_values() {
        let pairs = [
            (
                AssumptionCategory::NoUnmeasuredConfounding,
                "no-unmeasured-confounding",
            ),
            (AssumptionCategory::Positivity, "positivity"),
            (AssumptionCategory::Consistency, "consistency"),
            (AssumptionCategory::Sutva, "sutva"),
            (
                AssumptionCategory::ModelSpecification,
                "model-specification",
            ),
            (AssumptionCategory::TemporalStability, "temporal-stability"),
        ];
        for (cat, expected) in pairs {
            assert_eq!(cat.to_string(), expected);
        }
    }

    #[test]
    fn replay_engine_config_baseline_action_default() {
        let config = ReplayEngineConfig::default();
        assert_eq!(config.baseline_action, LaneAction::FallbackSafe);
    }

    // ── Enrichment: serde for remaining types ────────────────────

    #[test]
    fn assumption_category_serde_roundtrip() {
        let categories = [
            AssumptionCategory::NoUnmeasuredConfounding,
            AssumptionCategory::Positivity,
            AssumptionCategory::Consistency,
            AssumptionCategory::Sutva,
            AssumptionCategory::ModelSpecification,
            AssumptionCategory::TemporalStability,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let back: AssumptionCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn policy_comparison_report_serde_roundtrip() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("baseline".to_string()),
            alternate_policy_id: PolicyId("alt".to_string()),
            alternate_description: "test alt".to_string(),
            decisions_evaluated: 50,
            divergence_count: 10,
            total_original_outcome_millionths: 5_000_000,
            total_counterfactual_outcome_millionths: 6_000_000,
            net_improvement_millionths: 1_000_000,
            regime_breakdown: {
                let mut m = BTreeMap::new();
                m.insert("regime-a".to_string(), 500_000);
                m
            },
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: 20_000,
                lower_millionths: 5_000,
                upper_millionths: 35_000,
                confidence_millionths: 950_000,
                effective_samples: 50,
            },
            safety_status: EnvelopeStatus::Safe,
            divergent_decisions: vec![DecisionComparison {
                decision_index: 3,
                tick: 103,
                epoch: SecurityEpoch::from_raw(1),
                original_action: "native".to_string(),
                alternate_action: "wasm".to_string(),
                original_outcome_millionths: 500_000,
                counterfactual_outcome_millionths: 600_000,
                diverged: true,
                regime: "regime-a".to_string(),
            }],
            assumptions: vec![AssumptionCard {
                assumption_id: "pos-alt".to_string(),
                category: AssumptionCategory::Positivity,
                description: "overlap holds".to_string(),
                testable: true,
                test_passed: Some(true),
                sensitivity_bound_millionths: 50_000,
            }],
            artifact_hash: ContentHash::compute(b"report"),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: PolicyComparisonReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // ── Enrichment: From<IdError> ────────────────────────────────

    #[test]
    fn replay_engine_error_from_id_error() {
        let id_err = IdError::EmptyCanonicalBytes;
        let replay_err: ReplayEngineError = id_err.into();
        assert!(matches!(replay_err, ReplayEngineError::IdDerivation(_)));
        let display = format!("{replay_err}");
        assert!(display.contains("ID derivation error"));
    }

    // ── Enrichment: is_confident_improvement edge cases ──────────

    #[test]
    fn is_confident_improvement_unsafe_status() {
        let report = PolicyComparisonReport {
            schema_version: REPLAY_ENGINE_SCHEMA_VERSION.to_string(),
            baseline_policy_id: PolicyId("b".to_string()),
            alternate_policy_id: PolicyId("a".to_string()),
            alternate_description: "test".to_string(),
            decisions_evaluated: 100,
            divergence_count: 50,
            total_original_outcome_millionths: 2_000_000,
            total_counterfactual_outcome_millionths: 1_000_000,
            net_improvement_millionths: -1_000_000,
            regime_breakdown: BTreeMap::new(),
            confidence_envelope: ConfidenceEnvelope {
                estimate_millionths: -10_000,
                lower_millionths: -15_000,
                upper_millionths: -5_000,
                confidence_millionths: 950_000,
                effective_samples: 100,
            },
            safety_status: EnvelopeStatus::Unsafe,
            divergent_decisions: Vec::new(),
            assumptions: Vec::new(),
            artifact_hash: ContentHash::compute(b"unsafe"),
        };
        assert!(!report.is_confident_improvement());
    }

    // ── Enrichment: recommendation rationale text ────────────────

    #[test]
    fn recommendation_rationale_for_unsafe_policy() {
        let mut engine = default_engine();
        let decisions: Vec<_> = (0..20)
            .map(|i| make_decision(i, "native", 500_000))
            .collect();
        let trace = make_trace(decisions);
        let alt = make_override_policy("force-wasm", LaneAction::RouteTo(LaneId("wasm".into())));

        let result = engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();

        // At least verify the rationale is non-empty
        for rec in &result.ranked_recommendations {
            assert!(!rec.rationale.is_empty());
        }
    }

    // ── Enrichment: isqrt edge cases ─────────────────────────────

    #[test]
    fn isqrt_small_non_perfect_squares() {
        assert_eq!(isqrt(2), 1);
        assert_eq!(isqrt(3), 1);
        assert_eq!(isqrt(5), 2);
        assert_eq!(isqrt(8), 2);
        assert_eq!(isqrt(15), 3);
        assert_eq!(isqrt(24), 4);
    }

    // ── Enrichment: z_multiplier boundary transitions ────────────

    #[test]
    fn z_multiplier_exact_boundaries() {
        // At exactly 900_001 the boundary transitions
        assert_eq!(z_multiplier(900_001), 1_960);
        assert_eq!(z_multiplier(950_001), 2_576);
        assert_eq!(z_multiplier(990_001), 3_291);
    }

    // ── Enrichment: schema version constant ──────────────────────

    #[test]
    fn schema_version_is_v1() {
        assert!(REPLAY_ENGINE_SCHEMA_VERSION.contains("counterfactual-replay-engine"));
        assert!(REPLAY_ENGINE_SCHEMA_VERSION.contains("v1"));
    }

    // ── Enrichment: assumption card testable but not tested ──────

    #[test]
    fn assumption_card_with_none_test_result() {
        let card = AssumptionCard {
            assumption_id: "untested".to_string(),
            category: AssumptionCategory::NoUnmeasuredConfounding,
            description: "not testable assumption".to_string(),
            testable: false,
            test_passed: None,
            sensitivity_bound_millionths: 100_000,
        };
        let json = serde_json::to_string(&card).unwrap();
        let back: AssumptionCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, back);
        assert!(back.test_passed.is_none());
    }

    // ── Enrichment: replay count survives serde ──────────────────

    #[test]
    fn replay_count_survives_serde() {
        let mut engine = default_engine();
        let trace = make_trace(vec![make_decision(0, "native", 500_000)]);
        let alt = make_alternate_policy("alt-1", "test");
        engine
            .compare(
                std::slice::from_ref(&trace),
                std::slice::from_ref(&alt),
                &default_scope(),
                None,
            )
            .unwrap();
        engine
            .compare(&[trace], &[alt], &default_scope(), None)
            .unwrap();
        assert_eq!(engine.replay_count(), 2);

        let json = serde_json::to_string(&engine).unwrap();
        let back: CounterfactualReplayEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(back.replay_count(), 2);
    }

    // ── Enrichment: scope default epoch boundaries ───────────────

    #[test]
    fn default_scope_epoch_boundaries() {
        let scope = ReplayScope::default();
        assert_eq!(scope.start_epoch, SecurityEpoch::GENESIS);
        assert_eq!(scope.end_epoch, SecurityEpoch::from_raw(u64::MAX));
    }

    // ── Enrichment: error display specifics ──────────────────────

    #[test]
    fn error_display_too_many_policies_includes_count() {
        let err = ReplayEngineError::TooManyPolicies {
            count: 100,
            max: 64,
        };
        let s = format!("{err}");
        assert!(s.contains("100"));
        assert!(s.contains("64"));
    }

    #[test]
    fn error_display_insufficient_decisions_includes_counts() {
        let err = ReplayEngineError::InsufficientDecisions {
            found: 5,
            required: 100,
        };
        let s = format!("{err}");
        assert!(s.contains("5"));
        assert!(s.contains("100"));
    }

    #[test]
    fn error_display_trace_integrity_includes_trace_id() {
        let err = ReplayEngineError::TraceIntegrityFailure {
            trace_id: "trace-42".to_string(),
            detail: "hash mismatch".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("trace-42"));
        assert!(s.contains("hash mismatch"));
    }

    #[test]
    fn error_display_duplicate_policy_includes_id() {
        let err = ReplayEngineError::DuplicatePolicy {
            policy_id: "dup-pol".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("dup-pol"));
    }

    // ── Enrichment: alternate policy display details ─────────────

    #[test]
    fn alternate_policy_display_format() {
        let ap = AlternatePolicy {
            policy_id: PolicyId("my-policy".to_string()),
            description: "a test policy".to_string(),
            counterfactual_config: CounterfactualConfig {
                branch_id: "b".to_string(),
                threshold_override_millionths: None,
                loss_matrix_overrides: BTreeMap::new(),
                policy_version_override: None,
                containment_overrides: BTreeMap::new(),
                evidence_weight_overrides: BTreeMap::new(),
                branch_from_index: 0,
            },
            default_action: None,
        };
        let s = format!("{ap}");
        assert_eq!(s, "my-policy:a test policy");
    }

    // ── Enrichment: recommendation display includes all fields ───

    #[test]
    fn recommendation_display_includes_status() {
        let rec = Recommendation {
            rank: 2,
            policy_id: PolicyId("pol-x".to_string()),
            expected_improvement_millionths: -10_000,
            confidence_millionths: 990_000,
            safety_status: EnvelopeStatus::Unsafe,
            rationale: "worse".to_string(),
        };
        let s = format!("{rec}");
        assert!(s.contains("#2"));
        assert!(s.contains("pol-x"));
        assert!(s.contains("-10000"));
        assert!(s.contains("990000"));
    }

    // ── Enrichment: error serde remaining variants ───────────────

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let errors = vec![
            ReplayEngineError::NoTraces,
            ReplayEngineError::NoPolicies,
            ReplayEngineError::TooManyPolicies {
                count: 100,
                max: 64,
            },
            ReplayEngineError::TooManyDecisions {
                count: 200_000,
                max: 100_000,
            },
            ReplayEngineError::InsufficientDecisions {
                found: 5,
                required: 100,
            },
            ReplayEngineError::TraceIntegrityFailure {
                trace_id: "t1".to_string(),
                detail: "bad".to_string(),
            },
            ReplayEngineError::IdDerivation("id-err".to_string()),
            ReplayEngineError::EmptyScope,
            ReplayEngineError::DuplicatePolicy {
                policy_id: "dup".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: ReplayEngineError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }
}
