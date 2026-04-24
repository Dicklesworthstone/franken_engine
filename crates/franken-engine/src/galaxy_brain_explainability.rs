//! Galaxy-Brain Explainability for Lane/Fallback/Optimization Decisions.
//!
//! Provides structured explainability surfaces ("galaxy-brain mode") for
//! operator and developer debugging of major engine decisions.
//!
//! For each decision the module captures:
//! - the governing equation/model,
//! - substituted parameter values,
//! - plain-language rationale,
//! - the chosen action and all rejected alternatives with reasons.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-08.2 (Galaxy-Brain Explainability).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime_decision_theory::{DemotionReason, LaneAction, LaneId, RegimeLabel};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for explainability artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.galaxy-brain-explainability.v1";

// ---------------------------------------------------------------------------
// VerbosityLevel — controls explanation depth
// ---------------------------------------------------------------------------

/// Controls how much detail the explainability engine emits.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum VerbosityLevel {
    /// Minimal: chosen action + one-line rationale.
    Minimal,
    /// Standard: chosen action, rejected alternatives, key metrics.
    #[default]
    Standard,
    /// Full galaxy-brain: complete posterior, counterfactuals, constraint
    /// interaction analysis, and risk breakdowns.
    GalaxyBrain,
}

impl fmt::Display for VerbosityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Minimal => f.write_str("minimal"),
            Self::Standard => f.write_str("standard"),
            Self::GalaxyBrain => f.write_str("galaxy_brain"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionDomain — categorizes the decision space
// ---------------------------------------------------------------------------

/// Domain of the decision being explained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionDomain {
    /// Lane routing: which execution lane to use.
    LaneRouting,
    /// Fallback: demotion/safe-mode trigger.
    Fallback,
    /// Optimization: compiler pass selection, e-graph rewriting.
    Optimization,
    /// Security: capability grant/revoke, quarantine.
    Security,
    /// Governance: policy update, epoch transition.
    Governance,
}

impl fmt::Display for DecisionDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaneRouting => f.write_str("lane_routing"),
            Self::Fallback => f.write_str("fallback"),
            Self::Optimization => f.write_str("optimization"),
            Self::Security => f.write_str("security"),
            Self::Governance => f.write_str("governance"),
        }
    }
}

// ---------------------------------------------------------------------------
// GoverningEquation — the model/rule that drove the decision
// ---------------------------------------------------------------------------

/// Describes the equation or model that governed the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoverningEquation {
    /// Human-readable name of the equation/model.
    pub name: String,
    /// LaTeX or plain-text formula.
    pub formula: String,
    /// Substituted parameter values (name → millionths).
    pub parameters: BTreeMap<String, i64>,
    /// Computed result (millionths).
    pub result_millionths: i64,
    /// Threshold the result was compared against (millionths), if any.
    pub threshold_millionths: Option<i64>,
    /// Whether the threshold was exceeded.
    pub threshold_exceeded: bool,
}

impl GoverningEquation {
    /// Render a plain-language summary of the equation evaluation.
    pub fn plain_language(&self) -> String {
        let result_frac = self.result_millionths as f64 / MILLION as f64;
        match self.threshold_millionths {
            Some(thresh) => {
                let thresh_frac = thresh as f64 / MILLION as f64;
                if self.threshold_exceeded {
                    format!(
                        "{}: computed {:.6} exceeded threshold {:.6}",
                        self.name, result_frac, thresh_frac,
                    )
                } else {
                    format!(
                        "{}: computed {:.6} within threshold {:.6}",
                        self.name, result_frac, thresh_frac,
                    )
                }
            }
            None => {
                format!("{}: computed {:.6}", self.name, result_frac)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExplainedAlternative — a rejected action with reasoning
// ---------------------------------------------------------------------------

/// An action that was considered but not selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainedAlternative {
    /// The action that was considered.
    pub action: LaneAction,
    /// Expected loss of this alternative (millionths).
    pub expected_loss_millionths: i64,
    /// Why this alternative was rejected.
    pub rejection_reason: RejectionReason,
    /// Free-text detail on the rejection.
    pub detail: String,
}

/// Reason an alternative action was not selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Higher expected loss than the chosen action.
    HigherLoss,
    /// Guardrail constraint would be violated.
    GuardrailViolation,
    /// Budget insufficient for this action.
    BudgetInsufficient,
    /// Calibration score too low for this action.
    CalibrationInsufficient,
    /// Action not available in current regime.
    RegimeRestriction,
    /// Operator policy explicitly forbids this action.
    PolicyForbidden,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HigherLoss => f.write_str("higher_loss"),
            Self::GuardrailViolation => f.write_str("guardrail_violation"),
            Self::BudgetInsufficient => f.write_str("budget_insufficient"),
            Self::CalibrationInsufficient => f.write_str("calibration_insufficient"),
            Self::RegimeRestriction => f.write_str("regime_restriction"),
            Self::PolicyForbidden => f.write_str("policy_forbidden"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConstraintInteraction — which constraints were active
// ---------------------------------------------------------------------------

/// A constraint that was evaluated during the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintInteraction {
    /// Unique constraint identifier.
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the constraint was binding (actively limited the choice).
    pub binding: bool,
    /// Slack: how far the decision was from violating this constraint
    /// (millionths). Zero if binding.
    pub slack_millionths: i64,
}

// ---------------------------------------------------------------------------
// RiskBreakdown — per-factor risk decomposition
// ---------------------------------------------------------------------------

/// Per-risk-factor contribution to the overall risk assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBreakdown {
    /// Risk factor name.
    pub factor: String,
    /// Weight assigned to this factor (millionths).
    pub weight_millionths: i64,
    /// Current belief/estimate for this factor (millionths).
    pub belief_millionths: i64,
    /// Contribution to overall risk (weight * belief, millionths).
    pub contribution_millionths: i64,
}

// ---------------------------------------------------------------------------
// CounterfactualOutcome — what-if analysis
// ---------------------------------------------------------------------------

/// Counterfactual analysis: what would have happened with a different action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualOutcome {
    /// The hypothetical action.
    pub action: LaneAction,
    /// Predicted expected loss under this action (millionths).
    pub predicted_loss_millionths: i64,
    /// Delta from chosen action's loss (positive = worse, negative = better).
    pub loss_delta_millionths: i64,
    /// Whether this action would have triggered a guardrail.
    pub would_trigger_guardrail: bool,
    /// Narrative explanation.
    pub narrative: String,
}

// ---------------------------------------------------------------------------
// DecisionExplanation — the full explanation record
// ---------------------------------------------------------------------------

/// Complete explanation of a single engine decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionExplanation {
    /// Content-addressed explanation identifier.
    pub explanation_id: String,
    /// Decision identifier this explains.
    pub decision_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Decision domain.
    pub domain: DecisionDomain,
    /// Verbosity level this explanation was generated at.
    pub verbosity: VerbosityLevel,
    /// The current regime at decision time.
    pub regime: RegimeLabel,

    // -- Core explainability fields --
    /// Governing equation(s) that drove the decision.
    pub equations: Vec<GoverningEquation>,
    /// The chosen action.
    pub chosen_action: LaneAction,
    /// Expected loss of the chosen action (millionths).
    pub chosen_loss_millionths: i64,
    /// Plain-language rationale for the decision.
    pub rationale: String,
    /// Rejected alternatives with reasons.
    pub alternatives: Vec<ExplainedAlternative>,

    // -- Extended fields (populated in Standard/GalaxyBrain) --
    /// Active constraints and their binding status.
    pub constraints: Vec<ConstraintInteraction>,
    /// Per-factor risk decomposition.
    pub risk_breakdown: Vec<RiskBreakdown>,

    // -- Galaxy-Brain only fields --
    /// Counterfactual outcomes for alternative actions.
    pub counterfactuals: Vec<CounterfactualOutcome>,
    /// Posterior distribution over risk factors (factor → millionths).
    pub posterior_millionths: BTreeMap<String, i64>,
    /// Confidence in the decision (millionths, 0 = none, 1M = certain).
    pub confidence_millionths: i64,
}

impl DecisionExplanation {
    /// Compute content-addressed ID from core fields.
    pub fn compute_id(decision_id: &str, epoch: &SecurityEpoch, domain: &DecisionDomain) -> String {
        let mut hasher = Sha256::new();
        hasher.update(decision_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(domain.to_string().as_bytes());
        let hash = hasher.finalize();
        format!("expl-{}", hex::encode(&hash[..16]))
    }

    /// Generate a one-line summary suitable for log output.
    pub fn one_line_summary(&self) -> String {
        format!(
            "[{}] {} → {} (loss={}, regime={}): {}",
            self.domain,
            self.decision_id,
            self.chosen_action,
            self.chosen_loss_millionths,
            self.regime,
            self.rationale,
        )
    }

    /// Return the total number of alternatives considered (including chosen).
    pub fn candidates_considered(&self) -> usize {
        1 + self.alternatives.len()
    }

    /// Check if any constraint was binding.
    pub fn has_binding_constraint(&self) -> bool {
        self.constraints.iter().any(|c| c.binding)
    }

    /// Total risk from the breakdown (sum of contributions).
    pub fn total_risk_millionths(&self) -> i64 {
        self.risk_breakdown
            .iter()
            .map(|r| r.contribution_millionths)
            .sum()
    }
}

// ---------------------------------------------------------------------------
// ExplanationBuilder — fluent builder for DecisionExplanation
// ---------------------------------------------------------------------------

/// Builder for constructing `DecisionExplanation` incrementally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationBuilder {
    decision_id: String,
    epoch: SecurityEpoch,
    domain: DecisionDomain,
    verbosity: VerbosityLevel,
    regime: RegimeLabel,
    equations: Vec<GoverningEquation>,
    chosen_action: Option<LaneAction>,
    chosen_loss_millionths: i64,
    rationale: String,
    alternatives: Vec<ExplainedAlternative>,
    constraints: Vec<ConstraintInteraction>,
    risk_breakdown: Vec<RiskBreakdown>,
    counterfactuals: Vec<CounterfactualOutcome>,
    posterior_millionths: BTreeMap<String, i64>,
    confidence_millionths: i64,
}

impl ExplanationBuilder {
    /// Create a new builder with required fields.
    pub fn new(decision_id: String, epoch: SecurityEpoch, domain: DecisionDomain) -> Self {
        Self {
            decision_id,
            epoch,
            domain,
            verbosity: VerbosityLevel::Standard,
            regime: RegimeLabel::Normal,
            equations: Vec::new(),
            chosen_action: None,
            chosen_loss_millionths: 0,
            rationale: String::new(),
            alternatives: Vec::new(),
            constraints: Vec::new(),
            risk_breakdown: Vec::new(),
            counterfactuals: Vec::new(),
            posterior_millionths: BTreeMap::new(),
            confidence_millionths: 0,
        }
    }

    /// Set the verbosity level.
    pub fn verbosity(mut self, v: VerbosityLevel) -> Self {
        self.verbosity = v;
        self
    }

    /// Set the regime.
    pub fn regime(mut self, r: RegimeLabel) -> Self {
        self.regime = r;
        self
    }

    /// Add a governing equation.
    pub fn equation(mut self, eq: GoverningEquation) -> Self {
        self.equations.push(eq);
        self
    }

    /// Set the chosen action and its expected loss.
    pub fn chosen(mut self, action: LaneAction, loss_millionths: i64) -> Self {
        self.chosen_action = Some(action);
        self.chosen_loss_millionths = loss_millionths;
        self
    }

    /// Set the rationale string.
    pub fn rationale(mut self, r: String) -> Self {
        self.rationale = r;
        self
    }

    /// Add a rejected alternative.
    pub fn alternative(mut self, alt: ExplainedAlternative) -> Self {
        self.alternatives.push(alt);
        self
    }

    /// Add a constraint interaction.
    pub fn constraint(mut self, c: ConstraintInteraction) -> Self {
        self.constraints.push(c);
        self
    }

    /// Add a risk breakdown entry.
    pub fn risk(mut self, r: RiskBreakdown) -> Self {
        self.risk_breakdown.push(r);
        self
    }

    /// Add a counterfactual outcome.
    pub fn counterfactual(mut self, cf: CounterfactualOutcome) -> Self {
        self.counterfactuals.push(cf);
        self
    }

    /// Set posterior belief over a named factor.
    pub fn posterior(mut self, factor: String, value_millionths: i64) -> Self {
        self.posterior_millionths.insert(factor, value_millionths);
        self
    }

    /// Set confidence in the decision.
    pub fn confidence(mut self, millionths: i64) -> Self {
        self.confidence_millionths = millionths;
        self
    }

    /// Build the explanation. Returns `None` if chosen action was not set.
    pub fn build(self) -> Option<DecisionExplanation> {
        let chosen_action = self.chosen_action?;
        let explanation_id =
            DecisionExplanation::compute_id(&self.decision_id, &self.epoch, &self.domain);
        Some(DecisionExplanation {
            explanation_id,
            decision_id: self.decision_id,
            epoch: self.epoch,
            domain: self.domain,
            verbosity: self.verbosity,
            regime: self.regime,
            equations: self.equations,
            chosen_action,
            chosen_loss_millionths: self.chosen_loss_millionths,
            rationale: self.rationale,
            alternatives: self.alternatives,
            constraints: self.constraints,
            risk_breakdown: self.risk_breakdown,
            counterfactuals: self.counterfactuals,
            posterior_millionths: self.posterior_millionths,
            confidence_millionths: self.confidence_millionths,
        })
    }
}

// ---------------------------------------------------------------------------
// ExplanationIndex — lookup and query structure
// ---------------------------------------------------------------------------

/// Index of explanations with query capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplanationIndex {
    /// All explanations keyed by explanation_id.
    entries: BTreeMap<String, DecisionExplanation>,
    /// Decision-id → explanation-id mapping for fast lookup.
    by_decision: BTreeMap<String, String>,
    /// Domain → list of explanation-ids.
    by_domain: BTreeMap<String, Vec<String>>,
    /// Epoch → list of explanation-ids.
    by_epoch: BTreeMap<u64, Vec<String>>,
}

impl ExplanationIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an explanation into the index.
    pub fn insert(&mut self, expl: DecisionExplanation) {
        let id = expl.explanation_id.clone();
        self.by_decision
            .insert(expl.decision_id.clone(), id.clone());
        self.by_domain
            .entry(expl.domain.to_string())
            .or_default()
            .push(id.clone());
        self.by_epoch
            .entry(expl.epoch.as_u64())
            .or_default()
            .push(id.clone());
        self.entries.insert(id, expl);
    }

    /// Look up by explanation ID.
    pub fn get(&self, explanation_id: &str) -> Option<&DecisionExplanation> {
        self.entries.get(explanation_id)
    }

    /// Look up by decision ID.
    pub fn get_by_decision(&self, decision_id: &str) -> Option<&DecisionExplanation> {
        self.by_decision
            .get(decision_id)
            .and_then(|eid| self.entries.get(eid))
    }

    /// Get all explanations for a given domain.
    pub fn by_domain(&self, domain: DecisionDomain) -> Vec<&DecisionExplanation> {
        let key = domain.to_string();
        self.by_domain
            .get(&key)
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all explanations for a given epoch.
    pub fn by_epoch(&self, epoch: &SecurityEpoch) -> Vec<&DecisionExplanation> {
        self.by_epoch
            .get(&epoch.as_u64())
            .map(|ids| ids.iter().filter_map(|id| self.entries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Total number of explanations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All explanations where a constraint was binding.
    pub fn with_binding_constraints(&self) -> Vec<&DecisionExplanation> {
        self.entries
            .values()
            .filter(|e| e.has_binding_constraint())
            .collect()
    }

    /// All explanations in a specific regime.
    pub fn in_regime(&self, regime: RegimeLabel) -> Vec<&DecisionExplanation> {
        self.entries
            .values()
            .filter(|e| e.regime == regime)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ExplainabilityReport — CI-readable aggregate report
// ---------------------------------------------------------------------------

/// CI-readable report summarizing explainability coverage and quality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainabilityReport {
    /// Schema version.
    pub schema_version: String,
    /// Epoch this report covers.
    pub epoch: SecurityEpoch,
    /// Total decisions explained.
    pub total_explained: usize,
    /// Per-domain breakdown.
    pub domain_counts: BTreeMap<String, usize>,
    /// Per-verbosity breakdown.
    pub verbosity_counts: BTreeMap<String, usize>,
    /// Decisions with at least one binding constraint.
    pub binding_constraint_count: usize,
    /// Decisions made under non-normal regime.
    pub non_normal_regime_count: usize,
    /// Average confidence across all decisions (millionths).
    pub average_confidence_millionths: i64,
    /// Average number of alternatives per decision (millionths for precision).
    pub average_alternatives_millionths: i64,
    /// Content hash for integrity verification.
    pub content_hash: String,
}

/// Generate an `ExplainabilityReport` from an `ExplanationIndex`.
pub fn generate_report(index: &ExplanationIndex, epoch: &SecurityEpoch) -> ExplainabilityReport {
    let epoch_entries = index.by_epoch(epoch);
    let total = epoch_entries.len();

    let mut domain_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut verbosity_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut binding_count = 0usize;
    let mut non_normal_count = 0usize;
    let mut confidence_sum: i64 = 0;
    let mut alternatives_sum: i64 = 0;

    for e in &epoch_entries {
        *domain_counts.entry(e.domain.to_string()).or_default() += 1;
        *verbosity_counts.entry(e.verbosity.to_string()).or_default() += 1;
        if e.has_binding_constraint() {
            binding_count += 1;
        }
        if e.regime != RegimeLabel::Normal {
            non_normal_count += 1;
        }
        confidence_sum = confidence_sum.saturating_add(e.confidence_millionths);
        alternatives_sum = alternatives_sum.saturating_add(e.alternatives.len() as i64 * MILLION);
    }

    let avg_confidence = if total > 0 {
        confidence_sum / total as i64
    } else {
        0
    };
    let avg_alternatives = if total > 0 {
        alternatives_sum / total as i64
    } else {
        0
    };

    // Content hash for integrity.
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update((total as u64).to_le_bytes());
    hasher.update(avg_confidence.to_le_bytes());
    for (k, v) in &domain_counts {
        hasher.update(k.as_bytes());
        hasher.update((*v as u64).to_le_bytes());
    }
    let hash = hasher.finalize();
    let content_hash = hex::encode(&hash[..16]);

    ExplainabilityReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch: *epoch,
        total_explained: total,
        domain_counts,
        verbosity_counts,
        binding_constraint_count: binding_count,
        non_normal_regime_count: non_normal_count,
        average_confidence_millionths: avg_confidence,
        average_alternatives_millionths: avg_alternatives,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Explain helpers — convenience functions to build common explanations
// ---------------------------------------------------------------------------

/// Build a lane-routing explanation.
#[derive(Debug, Clone)]
pub struct LaneRoutingExplanationInput {
    pub decision_id: String,
    pub epoch: SecurityEpoch,
    pub regime: RegimeLabel,
    pub chosen_lane: LaneId,
    pub chosen_loss_millionths: i64,
    pub alternatives: Vec<ExplainedAlternative>,
    pub equations: Vec<GoverningEquation>,
    pub verbosity: VerbosityLevel,
}

/// Build a lane-routing explanation.
pub fn explain_lane_routing(input: LaneRoutingExplanationInput) -> Option<DecisionExplanation> {
    let LaneRoutingExplanationInput {
        decision_id,
        epoch,
        regime,
        chosen_lane,
        chosen_loss_millionths,
        alternatives,
        equations,
        verbosity,
    } = input;
    let rationale = format!(
        "Routed to lane {} under {} regime; expected loss {}",
        chosen_lane, regime, chosen_loss_millionths,
    );
    ExplanationBuilder::new(decision_id, epoch, DecisionDomain::LaneRouting)
        .verbosity(verbosity)
        .regime(regime)
        .chosen(LaneAction::RouteTo(chosen_lane), chosen_loss_millionths)
        .rationale(rationale)
        .alternatives(alternatives)
        .equations(equations)
        .build()
}

/// Build a fallback/demotion explanation.
#[derive(Debug, Clone)]
pub struct FallbackExplanationInput {
    pub decision_id: String,
    pub epoch: SecurityEpoch,
    pub regime: RegimeLabel,
    pub from_lane: LaneId,
    pub reason: DemotionReason,
    pub equations: Vec<GoverningEquation>,
    pub constraints: Vec<ConstraintInteraction>,
    pub verbosity: VerbosityLevel,
}

/// Build a fallback/demotion explanation.
pub fn explain_fallback(input: FallbackExplanationInput) -> Option<DecisionExplanation> {
    let FallbackExplanationInput {
        decision_id,
        epoch,
        regime,
        from_lane,
        reason,
        equations,
        constraints,
        verbosity,
    } = input;
    let rationale = format!(
        "Demoted from lane {} due to {reason:?}; switching to safe mode",
        from_lane,
    );
    let action = LaneAction::Demote {
        from_lane,
        reason: reason.clone(),
    };
    ExplanationBuilder::new(decision_id, epoch, DecisionDomain::Fallback)
        .verbosity(verbosity)
        .regime(regime)
        .chosen(action, 0)
        .rationale(rationale)
        .equations(equations)
        .constraints(constraints)
        .build()
}

// ---------------------------------------------------------------------------
// Builder batch helpers (private, used by explain_* convenience fns)
// ---------------------------------------------------------------------------

impl ExplanationBuilder {
    fn alternatives(mut self, alts: Vec<ExplainedAlternative>) -> Self {
        self.alternatives = alts;
        self
    }

    fn equations(mut self, eqs: Vec<GoverningEquation>) -> Self {
        self.equations = eqs;
        self
    }

    fn constraints(mut self, cs: Vec<ConstraintInteraction>) -> Self {
        self.constraints = cs;
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn test_lane(name: &str) -> LaneId {
        LaneId(name.to_string())
    }

    // -- VerbosityLevel tests --

    #[test]
    fn verbosity_default_is_standard() {
        assert_eq!(VerbosityLevel::default(), VerbosityLevel::Standard);
    }

    #[test]
    fn verbosity_display() {
        assert_eq!(VerbosityLevel::Minimal.to_string(), "minimal");
        assert_eq!(VerbosityLevel::Standard.to_string(), "standard");
        assert_eq!(VerbosityLevel::GalaxyBrain.to_string(), "galaxy_brain");
    }

    #[test]
    fn verbosity_ordering() {
        assert!(VerbosityLevel::Minimal < VerbosityLevel::Standard);
        assert!(VerbosityLevel::Standard < VerbosityLevel::GalaxyBrain);
    }

    #[test]
    fn verbosity_serde_roundtrip() {
        for v in [
            VerbosityLevel::Minimal,
            VerbosityLevel::Standard,
            VerbosityLevel::GalaxyBrain,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: VerbosityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // -- DecisionDomain tests --

    #[test]
    fn domain_display_all_five() {
        let domains = [
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
            DecisionDomain::Optimization,
            DecisionDomain::Security,
            DecisionDomain::Governance,
        ];
        let names: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
        assert_eq!(names.len(), 5);
        // All unique.
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn domain_serde_roundtrip() {
        for d in [
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
            DecisionDomain::Optimization,
            DecisionDomain::Security,
            DecisionDomain::Governance,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: DecisionDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    // -- GoverningEquation tests --

    #[test]
    fn equation_plain_language_with_threshold_exceeded() {
        let eq = GoverningEquation {
            name: "CVaR check".to_string(),
            formula: "CVaR(alpha) = E[L | L > VaR(alpha)]".to_string(),
            parameters: BTreeMap::from([("alpha".to_string(), 50_000)]),
            result_millionths: 800_000,
            threshold_millionths: Some(500_000),
            threshold_exceeded: true,
        };
        let text = eq.plain_language();
        assert!(text.contains("exceeded"));
        assert!(text.contains("CVaR check"));
    }

    #[test]
    fn equation_plain_language_within_threshold() {
        let eq = GoverningEquation {
            name: "budget".to_string(),
            formula: "remaining >= min".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 300_000,
            threshold_millionths: Some(500_000),
            threshold_exceeded: false,
        };
        let text = eq.plain_language();
        assert!(text.contains("within"));
    }

    #[test]
    fn equation_plain_language_no_threshold() {
        let eq = GoverningEquation {
            name: "loss".to_string(),
            formula: "E[L]".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 123_456,
            threshold_millionths: None,
            threshold_exceeded: false,
        };
        let text = eq.plain_language();
        assert!(text.contains("loss"));
        assert!(text.contains("computed"));
    }

    #[test]
    fn equation_serde_roundtrip() {
        let eq = GoverningEquation {
            name: "test".to_string(),
            formula: "x + y".to_string(),
            parameters: BTreeMap::from([("x".to_string(), 100), ("y".to_string(), 200)]),
            result_millionths: 300,
            threshold_millionths: Some(500),
            threshold_exceeded: false,
        };
        let json = serde_json::to_string(&eq).unwrap();
        let back: GoverningEquation = serde_json::from_str(&json).unwrap();
        assert_eq!(eq, back);
    }

    // -- RejectionReason tests --

    #[test]
    fn rejection_reason_display() {
        assert_eq!(RejectionReason::HigherLoss.to_string(), "higher_loss");
        assert_eq!(
            RejectionReason::GuardrailViolation.to_string(),
            "guardrail_violation",
        );
        assert_eq!(
            RejectionReason::BudgetInsufficient.to_string(),
            "budget_insufficient",
        );
    }

    #[test]
    fn rejection_reason_serde_roundtrip() {
        for r in [
            RejectionReason::HigherLoss,
            RejectionReason::GuardrailViolation,
            RejectionReason::BudgetInsufficient,
            RejectionReason::CalibrationInsufficient,
            RejectionReason::RegimeRestriction,
            RejectionReason::PolicyForbidden,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: RejectionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    // -- ExplanationBuilder tests --

    #[test]
    fn builder_returns_none_without_chosen_action() {
        let builder =
            ExplanationBuilder::new("d-1".to_string(), test_epoch(), DecisionDomain::LaneRouting);
        assert!(builder.build().is_none());
    }

    #[test]
    fn builder_minimal_explanation() {
        let expl =
            ExplanationBuilder::new("d-2".to_string(), test_epoch(), DecisionDomain::LaneRouting)
                .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
                .rationale("lowest loss".to_string())
                .build()
                .unwrap();

        assert_eq!(expl.decision_id, "d-2");
        assert_eq!(expl.domain, DecisionDomain::LaneRouting);
        assert_eq!(expl.chosen_loss_millionths, 100_000);
        assert_eq!(expl.rationale, "lowest loss");
        assert!(!expl.explanation_id.is_empty());
    }

    #[test]
    fn builder_with_alternatives() {
        let alt = ExplainedAlternative {
            action: LaneAction::RouteTo(test_lane("wasm")),
            expected_loss_millionths: 500_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "wasm lane has 5x loss".to_string(),
        };
        let expl =
            ExplanationBuilder::new("d-3".to_string(), test_epoch(), DecisionDomain::LaneRouting)
                .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
                .alternative(alt)
                .rationale("lowest loss".to_string())
                .build()
                .unwrap();

        assert_eq!(expl.alternatives.len(), 1);
        assert_eq!(expl.candidates_considered(), 2);
    }

    #[test]
    fn builder_with_constraints() {
        let constraint = ConstraintInteraction {
            constraint_id: "budget-floor".to_string(),
            description: "minimum budget threshold".to_string(),
            binding: true,
            slack_millionths: 0,
        };
        let expl =
            ExplanationBuilder::new("d-4".to_string(), test_epoch(), DecisionDomain::Fallback)
                .chosen(LaneAction::FallbackSafe, 0)
                .constraint(constraint)
                .rationale("budget exhausted".to_string())
                .build()
                .unwrap();

        assert!(expl.has_binding_constraint());
    }

    #[test]
    fn builder_with_risk_breakdown() {
        let risk = RiskBreakdown {
            factor: "latency".to_string(),
            weight_millionths: 300_000,
            belief_millionths: 700_000,
            contribution_millionths: 210_000,
        };
        let expl = ExplanationBuilder::new(
            "d-5".to_string(),
            test_epoch(),
            DecisionDomain::Optimization,
        )
        .chosen(LaneAction::RouteTo(test_lane("fast")), 50_000)
        .risk(risk)
        .rationale("optimizing for latency".to_string())
        .build()
        .unwrap();

        assert_eq!(expl.total_risk_millionths(), 210_000);
    }

    #[test]
    fn builder_galaxy_brain_with_counterfactuals() {
        let cf = CounterfactualOutcome {
            action: LaneAction::FallbackSafe,
            predicted_loss_millionths: 0,
            loss_delta_millionths: -100_000,
            would_trigger_guardrail: false,
            narrative: "safe mode would have zero loss but no optimization".to_string(),
        };
        let expl =
            ExplanationBuilder::new("d-6".to_string(), test_epoch(), DecisionDomain::LaneRouting)
                .verbosity(VerbosityLevel::GalaxyBrain)
                .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
                .counterfactual(cf)
                .posterior("latency".to_string(), 600_000)
                .confidence(850_000)
                .rationale("accepted risk for optimization gains".to_string())
                .build()
                .unwrap();

        assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
        assert_eq!(expl.counterfactuals.len(), 1);
        assert_eq!(expl.posterior_millionths.len(), 1);
        assert_eq!(expl.confidence_millionths, 850_000);
    }

    #[test]
    fn builder_with_regime() {
        let expl =
            ExplanationBuilder::new("d-7".to_string(), test_epoch(), DecisionDomain::Security)
                .regime(RegimeLabel::Attack)
                .chosen(LaneAction::SuspendAdaptive, 0)
                .rationale("attack regime detected".to_string())
                .build()
                .unwrap();

        assert_eq!(expl.regime, RegimeLabel::Attack);
    }

    // -- DecisionExplanation tests --

    #[test]
    fn explanation_id_deterministic() {
        let id1 = DecisionExplanation::compute_id("d-1", &test_epoch(), &DecisionDomain::Fallback);
        let id2 = DecisionExplanation::compute_id("d-1", &test_epoch(), &DecisionDomain::Fallback);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("expl-"));
    }

    #[test]
    fn explanation_id_differs_by_domain() {
        let id1 =
            DecisionExplanation::compute_id("d-1", &test_epoch(), &DecisionDomain::LaneRouting);
        let id2 = DecisionExplanation::compute_id("d-1", &test_epoch(), &DecisionDomain::Fallback);
        assert_ne!(id1, id2);
    }

    #[test]
    fn one_line_summary_contains_key_fields() {
        let expl = ExplanationBuilder::new(
            "d-10".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("lowest loss lane".to_string())
        .build()
        .unwrap();

        let summary = expl.one_line_summary();
        assert!(summary.contains("d-10"));
        assert!(summary.contains("lane_routing"));
        assert!(summary.contains("lowest loss lane"));
    }

    #[test]
    fn explanation_serde_roundtrip() {
        let expl = ExplanationBuilder::new(
            "d-11".to_string(),
            test_epoch(),
            DecisionDomain::Optimization,
        )
        .chosen(LaneAction::RouteTo(test_lane("wasm")), 200_000)
        .rationale("wasm optimized path".to_string())
        .build()
        .unwrap();

        let json = serde_json::to_string(&expl).unwrap();
        let back: DecisionExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(expl, back);
    }

    #[test]
    fn no_binding_constraints_when_empty() {
        let expl = ExplanationBuilder::new(
            "d-12".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("ok".to_string())
        .build()
        .unwrap();

        assert!(!expl.has_binding_constraint());
    }

    #[test]
    fn total_risk_sums_contributions() {
        let expl =
            ExplanationBuilder::new("d-13".to_string(), test_epoch(), DecisionDomain::Security)
                .chosen(LaneAction::FallbackSafe, 0)
                .risk(RiskBreakdown {
                    factor: "a".to_string(),
                    weight_millionths: 500_000,
                    belief_millionths: 400_000,
                    contribution_millionths: 200_000,
                })
                .risk(RiskBreakdown {
                    factor: "b".to_string(),
                    weight_millionths: 500_000,
                    belief_millionths: 600_000,
                    contribution_millionths: 300_000,
                })
                .rationale("security assessment".to_string())
                .build()
                .unwrap();

        assert_eq!(expl.total_risk_millionths(), 500_000);
    }

    // -- ExplanationIndex tests --

    #[test]
    fn index_starts_empty() {
        let idx = ExplanationIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn index_insert_and_get() {
        let mut idx = ExplanationIndex::new();
        let expl = ExplanationBuilder::new(
            "d-20".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("test".to_string())
        .build()
        .unwrap();

        let eid = expl.explanation_id.clone();
        idx.insert(expl);

        assert_eq!(idx.len(), 1);
        assert!(idx.get(&eid).is_some());
    }

    #[test]
    fn index_get_by_decision() {
        let mut idx = ExplanationIndex::new();
        let expl =
            ExplanationBuilder::new("d-21".to_string(), test_epoch(), DecisionDomain::Fallback)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test".to_string())
                .build()
                .unwrap();

        idx.insert(expl);
        assert!(idx.get_by_decision("d-21").is_some());
        assert!(idx.get_by_decision("d-nonexistent").is_none());
    }

    #[test]
    fn index_by_domain() {
        let mut idx = ExplanationIndex::new();
        for (i, domain) in [
            DecisionDomain::LaneRouting,
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
        ]
        .iter()
        .enumerate()
        {
            let expl = ExplanationBuilder::new(format!("d-{}", 30 + i), test_epoch(), *domain)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test".to_string())
                .build()
                .unwrap();
            idx.insert(expl);
        }

        assert_eq!(idx.by_domain(DecisionDomain::LaneRouting).len(), 2);
        assert_eq!(idx.by_domain(DecisionDomain::Fallback).len(), 1);
        assert_eq!(idx.by_domain(DecisionDomain::Security).len(), 0);
    }

    #[test]
    fn index_by_epoch() {
        let mut idx = ExplanationIndex::new();
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);

        for (i, ep) in [&epoch1, &epoch1, &epoch2].iter().enumerate() {
            let expl = ExplanationBuilder::new(
                format!("d-{}", 40 + i),
                **ep,
                DecisionDomain::Optimization,
            )
            .chosen(LaneAction::FallbackSafe, 0)
            .rationale("test".to_string())
            .build()
            .unwrap();
            idx.insert(expl);
        }

        assert_eq!(idx.by_epoch(&epoch1).len(), 2);
        assert_eq!(idx.by_epoch(&epoch2).len(), 1);
    }

    #[test]
    fn index_with_binding_constraints() {
        let mut idx = ExplanationIndex::new();

        // One with binding constraint.
        let expl1 =
            ExplanationBuilder::new("d-50".to_string(), test_epoch(), DecisionDomain::Fallback)
                .chosen(LaneAction::FallbackSafe, 0)
                .constraint(ConstraintInteraction {
                    constraint_id: "c1".to_string(),
                    description: "binding".to_string(),
                    binding: true,
                    slack_millionths: 0,
                })
                .rationale("bound".to_string())
                .build()
                .unwrap();

        // One without.
        let expl2 = ExplanationBuilder::new(
            "d-51".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("free".to_string())
        .build()
        .unwrap();

        idx.insert(expl1);
        idx.insert(expl2);

        assert_eq!(idx.with_binding_constraints().len(), 1);
    }

    #[test]
    fn index_in_regime() {
        let mut idx = ExplanationIndex::new();

        let expl1 =
            ExplanationBuilder::new("d-60".to_string(), test_epoch(), DecisionDomain::Security)
                .regime(RegimeLabel::Attack)
                .chosen(LaneAction::SuspendAdaptive, 0)
                .rationale("attack".to_string())
                .build()
                .unwrap();

        let expl2 = ExplanationBuilder::new(
            "d-61".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .regime(RegimeLabel::Normal)
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("normal".to_string())
        .build()
        .unwrap();

        idx.insert(expl1);
        idx.insert(expl2);

        assert_eq!(idx.in_regime(RegimeLabel::Attack).len(), 1);
        assert_eq!(idx.in_regime(RegimeLabel::Normal).len(), 1);
        assert_eq!(idx.in_regime(RegimeLabel::Degraded).len(), 0);
    }

    // -- ExplainabilityReport tests --

    #[test]
    fn report_empty_index() {
        let idx = ExplanationIndex::new();
        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.total_explained, 0);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert!(!report.content_hash.is_empty());
    }

    #[test]
    fn report_counts_domains() {
        let mut idx = ExplanationIndex::new();
        for (i, domain) in [
            DecisionDomain::LaneRouting,
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
        ]
        .iter()
        .enumerate()
        {
            let expl = ExplanationBuilder::new(format!("d-{}", 70 + i), test_epoch(), *domain)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test".to_string())
                .build()
                .unwrap();
            idx.insert(expl);
        }

        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.total_explained, 3);
        assert_eq!(report.domain_counts.get("lane_routing"), Some(&2),);
        assert_eq!(report.domain_counts.get("fallback"), Some(&1));
    }

    #[test]
    fn report_content_hash_deterministic() {
        let mut idx = ExplanationIndex::new();
        let expl =
            ExplanationBuilder::new("d-80".to_string(), test_epoch(), DecisionDomain::Governance)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test".to_string())
                .build()
                .unwrap();
        idx.insert(expl);

        let r1 = generate_report(&idx, &test_epoch());
        let r2 = generate_report(&idx, &test_epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut idx = ExplanationIndex::new();
        let expl = ExplanationBuilder::new(
            "d-81".to_string(),
            test_epoch(),
            DecisionDomain::Optimization,
        )
        .chosen(LaneAction::RouteTo(test_lane("fast")), 50_000)
        .confidence(900_000)
        .rationale("optimized".to_string())
        .build()
        .unwrap();
        idx.insert(expl);

        let report = generate_report(&idx, &test_epoch());
        let json = serde_json::to_string(&report).unwrap();
        let back: ExplainabilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn report_average_confidence() {
        let mut idx = ExplanationIndex::new();
        for (i, conf) in [800_000i64, 600_000].iter().enumerate() {
            let expl = ExplanationBuilder::new(
                format!("d-{}", 90 + i),
                test_epoch(),
                DecisionDomain::LaneRouting,
            )
            .chosen(LaneAction::FallbackSafe, 0)
            .confidence(*conf)
            .rationale("test".to_string())
            .build()
            .unwrap();
            idx.insert(expl);
        }

        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.average_confidence_millionths, 700_000);
    }

    #[test]
    fn report_non_normal_regime_count() {
        let mut idx = ExplanationIndex::new();

        let expl1 =
            ExplanationBuilder::new("d-100".to_string(), test_epoch(), DecisionDomain::Fallback)
                .regime(RegimeLabel::Attack)
                .chosen(LaneAction::SuspendAdaptive, 0)
                .rationale("attack".to_string())
                .build()
                .unwrap();

        let expl2 = ExplanationBuilder::new(
            "d-101".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .regime(RegimeLabel::Normal)
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("normal".to_string())
        .build()
        .unwrap();

        idx.insert(expl1);
        idx.insert(expl2);

        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.non_normal_regime_count, 1);
    }

    // -- Convenience function tests --

    #[test]
    fn explain_lane_routing_builds() {
        let expl = explain_lane_routing(LaneRoutingExplanationInput {
            decision_id: "d-200".to_string(),
            epoch: test_epoch(),
            regime: RegimeLabel::Normal,
            chosen_lane: test_lane("js"),
            chosen_loss_millionths: 100_000,
            alternatives: vec![ExplainedAlternative {
                action: LaneAction::RouteTo(test_lane("wasm")),
                expected_loss_millionths: 500_000,
                rejection_reason: RejectionReason::HigherLoss,
                detail: "5x more expensive".to_string(),
            }],
            equations: vec![],
            verbosity: VerbosityLevel::Standard,
        })
        .unwrap();

        assert_eq!(expl.domain, DecisionDomain::LaneRouting);
        assert!(expl.rationale.contains("js"));
        assert_eq!(expl.alternatives.len(), 1);
    }

    #[test]
    fn explain_fallback_builds() {
        let expl = explain_fallback(FallbackExplanationInput {
            decision_id: "d-201".to_string(),
            epoch: test_epoch(),
            regime: RegimeLabel::Degraded,
            from_lane: test_lane("wasm"),
            reason: DemotionReason::CvarExceeded,
            equations: vec![GoverningEquation {
                name: "CVaR".to_string(),
                formula: "CVaR > threshold".to_string(),
                parameters: BTreeMap::from([("cvar".to_string(), 800_000)]),
                result_millionths: 800_000,
                threshold_millionths: Some(500_000),
                threshold_exceeded: true,
            }],
            constraints: vec![ConstraintInteraction {
                constraint_id: "cvar-limit".to_string(),
                description: "CVaR must not exceed 0.5".to_string(),
                binding: true,
                slack_millionths: 0,
            }],
            verbosity: VerbosityLevel::GalaxyBrain,
        })
        .unwrap();

        assert_eq!(expl.domain, DecisionDomain::Fallback);
        assert!(expl.rationale.contains("Demoted"));
        assert!(expl.rationale.contains("CvarExceeded"));
        assert!(expl.has_binding_constraint());
        assert_eq!(expl.equations.len(), 1);
    }

    // -- ConstraintInteraction tests --

    #[test]
    fn constraint_serde_roundtrip() {
        let c = ConstraintInteraction {
            constraint_id: "budget-floor".to_string(),
            description: "minimum budget".to_string(),
            binding: true,
            slack_millionths: 0,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: ConstraintInteraction = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -- RiskBreakdown tests --

    #[test]
    fn risk_breakdown_serde_roundtrip() {
        let r = RiskBreakdown {
            factor: "latency".to_string(),
            weight_millionths: 300_000,
            belief_millionths: 700_000,
            contribution_millionths: 210_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RiskBreakdown = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- CounterfactualOutcome tests --

    #[test]
    fn counterfactual_serde_roundtrip() {
        let cf = CounterfactualOutcome {
            action: LaneAction::FallbackSafe,
            predicted_loss_millionths: 0,
            loss_delta_millionths: -100_000,
            would_trigger_guardrail: false,
            narrative: "safe mode would avoid all risk".to_string(),
        };
        let json = serde_json::to_string(&cf).unwrap();
        let back: CounterfactualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(cf, back);
    }

    // -- ExplainedAlternative tests --

    #[test]
    fn explained_alternative_serde_roundtrip() {
        let alt = ExplainedAlternative {
            action: LaneAction::RouteTo(test_lane("wasm")),
            expected_loss_millionths: 500_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "wasm lane has higher loss".to_string(),
        };
        let json = serde_json::to_string(&alt).unwrap();
        let back: ExplainedAlternative = serde_json::from_str(&json).unwrap();
        assert_eq!(alt, back);
    }

    // -- Edge cases --

    #[test]
    fn builder_verbosity_and_confidence_set() {
        let expl = ExplanationBuilder::new(
            "d-300".to_string(),
            test_epoch(),
            DecisionDomain::Governance,
        )
        .verbosity(VerbosityLevel::Minimal)
        .confidence(MILLION)
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("minimal explanation".to_string())
        .build()
        .unwrap();

        assert_eq!(expl.verbosity, VerbosityLevel::Minimal);
        assert_eq!(expl.confidence_millionths, MILLION);
    }

    #[test]
    fn candidates_considered_with_multiple_alternatives() {
        let mut builder = ExplanationBuilder::new(
            "d-301".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("best".to_string());

        for i in 0..5 {
            builder = builder.alternative(ExplainedAlternative {
                action: LaneAction::RouteTo(test_lane(&format!("alt-{i}"))),
                expected_loss_millionths: (i as i64 + 2) * 100_000,
                rejection_reason: RejectionReason::HigherLoss,
                detail: format!("alt-{i} rejected"),
            });
        }

        let expl = builder.build().unwrap();
        assert_eq!(expl.candidates_considered(), 6);
    }

    #[test]
    fn report_average_alternatives() {
        let mut idx = ExplanationIndex::new();

        // 2 alternatives.
        let expl1 = ExplanationBuilder::new(
            "d-400".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(test_lane("wasm")),
            expected_loss_millionths: 200_000,
            rejection_reason: RejectionReason::HigherLoss,
            detail: "higher".to_string(),
        })
        .alternative(ExplainedAlternative {
            action: LaneAction::FallbackSafe,
            expected_loss_millionths: 0,
            rejection_reason: RejectionReason::PolicyForbidden,
            detail: "forbidden".to_string(),
        })
        .rationale("test".to_string())
        .build()
        .unwrap();

        // 0 alternatives.
        let expl2 =
            ExplanationBuilder::new("d-401".to_string(), test_epoch(), DecisionDomain::Fallback)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test".to_string())
                .build()
                .unwrap();

        idx.insert(expl1);
        idx.insert(expl2);

        let report = generate_report(&idx, &test_epoch());
        // (2 + 0) / 2 = 1.0 = 1_000_000 millionths
        assert_eq!(report.average_alternatives_millionths, MILLION);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_rejection_reason_display_uniqueness() {
        let reasons = [
            RejectionReason::HigherLoss,
            RejectionReason::GuardrailViolation,
            RejectionReason::BudgetInsufficient,
            RejectionReason::CalibrationInsufficient,
            RejectionReason::RegimeRestriction,
            RejectionReason::PolicyForbidden,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for r in &reasons {
            let s = format!("{r}");
            assert!(!s.is_empty());
            displays.insert(s);
        }
        assert_eq!(
            displays.len(),
            6,
            "all 6 RejectionReason variants produce distinct Display strings"
        );
    }

    #[test]
    fn enrichment_explanation_index_insert_and_query() {
        let mut idx = ExplanationIndex::new();
        let expl =
            ExplanationBuilder::new("d-500".to_string(), test_epoch(), DecisionDomain::Security)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("test rationale".to_string())
                .build()
                .unwrap();
        let eid = expl.explanation_id.clone();
        idx.insert(expl);
        assert_eq!(idx.len(), 1);
        assert!(idx.get(&eid).is_some());
    }

    #[test]
    fn enrichment_governing_equation_serde_roundtrip() {
        let mut params = BTreeMap::new();
        params.insert("alpha".to_string(), 500_000i64);
        let eq = GoverningEquation {
            name: "test-equation".to_string(),
            formula: "alpha * x".to_string(),
            parameters: params,
            result_millionths: 250_000,
            threshold_millionths: Some(300_000),
            threshold_exceeded: false,
        };
        let json = serde_json::to_string(&eq).unwrap();
        let back: GoverningEquation = serde_json::from_str(&json).unwrap();
        assert_eq!(eq, back);
    }

    #[test]
    fn enrichment_decision_domain_display_uniqueness() {
        let domains = [
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
            DecisionDomain::Optimization,
            DecisionDomain::Security,
            DecisionDomain::Governance,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for d in &domains {
            displays.insert(d.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all 5 DecisionDomain variants produce distinct Display strings"
        );
    }

    #[test]
    fn enrichment_empty_index_by_domain_returns_empty() {
        let idx = ExplanationIndex::new();
        let by_domain = idx.by_domain(DecisionDomain::LaneRouting);
        assert!(by_domain.is_empty());
    }

    #[test]
    fn enrichment_report_on_empty_index() {
        let idx = ExplanationIndex::new();
        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.total_explained, 0);
        assert_eq!(report.average_alternatives_millionths, 0);
    }

    #[test]
    fn enrichment_governing_equation_plain_language_contains_name() {
        let eq = GoverningEquation {
            name: "my-equation".to_string(),
            formula: "a + b".to_string(),
            parameters: BTreeMap::new(),
            result_millionths: 100_000,
            threshold_millionths: None,
            threshold_exceeded: false,
        };
        let summary = eq.plain_language();
        assert!(
            summary.contains("my-equation"),
            "plain_language should mention the equation name"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-28
    // -----------------------------------------------------------------------

    #[test]
    fn compute_id_differs_by_epoch() {
        let id1 = DecisionExplanation::compute_id(
            "d-x",
            &SecurityEpoch::from_raw(1),
            &DecisionDomain::LaneRouting,
        );
        let id2 = DecisionExplanation::compute_id(
            "d-x",
            &SecurityEpoch::from_raw(2),
            &DecisionDomain::LaneRouting,
        );
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_id_differs_by_decision_id() {
        let id1 =
            DecisionExplanation::compute_id("d-a", &test_epoch(), &DecisionDomain::LaneRouting);
        let id2 =
            DecisionExplanation::compute_id("d-b", &test_epoch(), &DecisionDomain::LaneRouting);
        assert_ne!(id1, id2);
    }

    #[test]
    fn builder_serde_roundtrip() {
        let builder = ExplanationBuilder::new(
            "d-ser".to_string(),
            test_epoch(),
            DecisionDomain::Optimization,
        )
        .verbosity(VerbosityLevel::GalaxyBrain)
        .regime(RegimeLabel::Degraded)
        .confidence(750_000)
        .posterior("factor_a".to_string(), 400_000);
        let json = serde_json::to_string(&builder).unwrap();
        let back: ExplanationBuilder = serde_json::from_str(&json).unwrap();
        // Build both and compare: chosen_action not set so both return None.
        assert!(back.build().is_none());
    }

    #[test]
    fn index_serde_roundtrip() {
        let mut idx = ExplanationIndex::new();
        let expl = ExplanationBuilder::new(
            "d-idx-ser".to_string(),
            test_epoch(),
            DecisionDomain::Governance,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("serde test".to_string())
        .build()
        .unwrap();
        idx.insert(expl);

        let json = serde_json::to_string(&idx).unwrap();
        let back: ExplanationIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back.get_by_decision("d-idx-ser").is_some());
    }

    #[test]
    fn report_verbosity_counts() {
        let mut idx = ExplanationIndex::new();
        for (i, v) in [
            VerbosityLevel::Minimal,
            VerbosityLevel::Standard,
            VerbosityLevel::Standard,
            VerbosityLevel::GalaxyBrain,
        ]
        .iter()
        .enumerate()
        {
            let expl = ExplanationBuilder::new(
                format!("d-vc-{i}"),
                test_epoch(),
                DecisionDomain::LaneRouting,
            )
            .verbosity(*v)
            .chosen(LaneAction::FallbackSafe, 0)
            .rationale("test".to_string())
            .build()
            .unwrap();
            idx.insert(expl);
        }
        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.verbosity_counts.get("minimal"), Some(&1));
        assert_eq!(report.verbosity_counts.get("standard"), Some(&2));
        assert_eq!(report.verbosity_counts.get("galaxy_brain"), Some(&1));
    }

    #[test]
    fn counterfactual_with_guardrail_trigger() {
        let cf = CounterfactualOutcome {
            action: LaneAction::RouteTo(test_lane("risky")),
            predicted_loss_millionths: 900_000,
            loss_delta_millionths: 800_000,
            would_trigger_guardrail: true,
            narrative: "risky lane would violate guardrail".to_string(),
        };
        assert!(cf.would_trigger_guardrail);
        let json = serde_json::to_string(&cf).unwrap();
        let back: CounterfactualOutcome = serde_json::from_str(&json).unwrap();
        assert!(back.would_trigger_guardrail);
    }

    #[test]
    fn constraint_non_binding_with_positive_slack() {
        let c = ConstraintInteraction {
            constraint_id: "latency-cap".to_string(),
            description: "latency must stay below 100ms".to_string(),
            binding: false,
            slack_millionths: 250_000,
        };
        assert!(!c.binding);
        assert_eq!(c.slack_millionths, 250_000);
        let json = serde_json::to_string(&c).unwrap();
        let back: ConstraintInteraction = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn explain_lane_routing_with_equations() {
        let eq = GoverningEquation {
            name: "expected_loss".to_string(),
            formula: "sum(w_i * l_i)".to_string(),
            parameters: BTreeMap::from([
                ("w_latency".to_string(), 300_000),
                ("l_latency".to_string(), 200_000),
            ]),
            result_millionths: 60_000,
            threshold_millionths: Some(500_000),
            threshold_exceeded: false,
        };
        let expl = explain_lane_routing(LaneRoutingExplanationInput {
            decision_id: "d-eq-test".to_string(),
            epoch: test_epoch(),
            regime: RegimeLabel::Normal,
            chosen_lane: test_lane("native"),
            chosen_loss_millionths: 60_000,
            alternatives: vec![],
            equations: vec![eq],
            verbosity: VerbosityLevel::GalaxyBrain,
        })
        .unwrap();
        assert_eq!(expl.equations.len(), 1);
        assert_eq!(expl.equations[0].name, "expected_loss");
        assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
    }

    #[test]
    fn explain_fallback_empty_constraints() {
        let expl = explain_fallback(FallbackExplanationInput {
            decision_id: "d-fb-empty".to_string(),
            epoch: test_epoch(),
            regime: RegimeLabel::Normal,
            from_lane: test_lane("js"),
            reason: DemotionReason::CvarExceeded,
            equations: vec![],
            constraints: vec![],
            verbosity: VerbosityLevel::Minimal,
        })
        .unwrap();
        assert!(!expl.has_binding_constraint());
        assert!(expl.constraints.is_empty());
    }

    #[test]
    fn index_overwrite_same_decision_id() {
        let mut idx = ExplanationIndex::new();
        let expl1 = ExplanationBuilder::new(
            "d-ow".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("first".to_string())
        .build()
        .unwrap();
        let expl2 = ExplanationBuilder::new(
            "d-ow".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("wasm")), 200_000)
        .rationale("second".to_string())
        .build()
        .unwrap();
        idx.insert(expl1);
        idx.insert(expl2);
        // Same decision_id + epoch + domain → same explanation_id → overwrite.
        assert_eq!(idx.len(), 1);
        let retrieved = idx.get_by_decision("d-ow").unwrap();
        assert_eq!(retrieved.rationale, "second");
    }

    #[test]
    fn report_for_different_epoch_returns_zeros() {
        let mut idx = ExplanationIndex::new();
        let expl = ExplanationBuilder::new(
            "d-diff-ep".to_string(),
            SecurityEpoch::from_raw(10),
            DecisionDomain::Security,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("epoch 10".to_string())
        .build()
        .unwrap();
        idx.insert(expl);

        let report = generate_report(&idx, &SecurityEpoch::from_raw(99));
        assert_eq!(report.total_explained, 0);
        assert_eq!(report.average_confidence_millionths, 0);
    }

    #[test]
    fn builder_all_fields_galaxy_brain() {
        let eq = GoverningEquation {
            name: "risk_model".to_string(),
            formula: "R = sum(w * b)".to_string(),
            parameters: BTreeMap::from([("w".to_string(), 500_000), ("b".to_string(), 600_000)]),
            result_millionths: 300_000,
            threshold_millionths: Some(400_000),
            threshold_exceeded: false,
        };
        let alt = ExplainedAlternative {
            action: LaneAction::RouteTo(test_lane("wasm")),
            expected_loss_millionths: 500_000,
            rejection_reason: RejectionReason::GuardrailViolation,
            detail: "guardrail would be violated".to_string(),
        };
        let constraint = ConstraintInteraction {
            constraint_id: "budget-cap".to_string(),
            description: "budget limit".to_string(),
            binding: true,
            slack_millionths: 0,
        };
        let risk = RiskBreakdown {
            factor: "throughput".to_string(),
            weight_millionths: 400_000,
            belief_millionths: 500_000,
            contribution_millionths: 200_000,
        };
        let cf = CounterfactualOutcome {
            action: LaneAction::SuspendAdaptive,
            predicted_loss_millionths: 0,
            loss_delta_millionths: -300_000,
            would_trigger_guardrail: false,
            narrative: "suspend would avoid all risk".to_string(),
        };

        let expl = ExplanationBuilder::new(
            "d-full".to_string(),
            test_epoch(),
            DecisionDomain::Optimization,
        )
        .verbosity(VerbosityLevel::GalaxyBrain)
        .regime(RegimeLabel::Degraded)
        .equation(eq)
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("full galaxy-brain analysis".to_string())
        .alternative(alt)
        .constraint(constraint)
        .risk(risk)
        .counterfactual(cf)
        .posterior("throughput".to_string(), 500_000)
        .posterior("latency".to_string(), 300_000)
        .confidence(850_000)
        .build()
        .unwrap();

        assert_eq!(expl.verbosity, VerbosityLevel::GalaxyBrain);
        assert_eq!(expl.regime, RegimeLabel::Degraded);
        assert_eq!(expl.equations.len(), 1);
        assert_eq!(expl.alternatives.len(), 1);
        assert!(expl.has_binding_constraint());
        assert_eq!(expl.total_risk_millionths(), 200_000);
        assert_eq!(expl.counterfactuals.len(), 1);
        assert_eq!(expl.posterior_millionths.len(), 2);
        assert_eq!(expl.confidence_millionths, 850_000);
        assert_eq!(expl.candidates_considered(), 2);
    }

    #[test]
    fn multiple_counterfactuals_and_posteriors() {
        let expl = ExplanationBuilder::new(
            "d-multi-cf".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::RouteTo(test_lane("js")), 100_000)
        .rationale("multi test".to_string())
        .counterfactual(CounterfactualOutcome {
            action: LaneAction::FallbackSafe,
            predicted_loss_millionths: 0,
            loss_delta_millionths: -100_000,
            would_trigger_guardrail: false,
            narrative: "safe".to_string(),
        })
        .counterfactual(CounterfactualOutcome {
            action: LaneAction::RouteTo(test_lane("wasm")),
            predicted_loss_millionths: 200_000,
            loss_delta_millionths: 100_000,
            would_trigger_guardrail: true,
            narrative: "wasm risky".to_string(),
        })
        .counterfactual(CounterfactualOutcome {
            action: LaneAction::SuspendAdaptive,
            predicted_loss_millionths: 50_000,
            loss_delta_millionths: -50_000,
            would_trigger_guardrail: false,
            narrative: "suspend".to_string(),
        })
        .posterior("factor_a".to_string(), 600_000)
        .posterior("factor_b".to_string(), 400_000)
        .posterior("factor_c".to_string(), 200_000)
        .build()
        .unwrap();

        assert_eq!(expl.counterfactuals.len(), 3);
        assert_eq!(expl.posterior_millionths.len(), 3);
    }

    #[test]
    fn multiple_risk_factors_sum() {
        let expl = ExplanationBuilder::new(
            "d-risk-sum".to_string(),
            test_epoch(),
            DecisionDomain::Security,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("multi risk".to_string())
        .risk(RiskBreakdown {
            factor: "a".to_string(),
            weight_millionths: 300_000,
            belief_millionths: 500_000,
            contribution_millionths: 150_000,
        })
        .risk(RiskBreakdown {
            factor: "b".to_string(),
            weight_millionths: 300_000,
            belief_millionths: 300_000,
            contribution_millionths: 90_000,
        })
        .risk(RiskBreakdown {
            factor: "c".to_string(),
            weight_millionths: 400_000,
            belief_millionths: 200_000,
            contribution_millionths: 80_000,
        })
        .build()
        .unwrap();

        assert_eq!(expl.total_risk_millionths(), 320_000);
        assert_eq!(expl.risk_breakdown.len(), 3);
    }

    #[test]
    fn zero_risk_when_no_breakdown() {
        let expl = ExplanationBuilder::new(
            "d-no-risk".to_string(),
            test_epoch(),
            DecisionDomain::Governance,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("no risk".to_string())
        .build()
        .unwrap();
        assert_eq!(expl.total_risk_millionths(), 0);
    }

    #[test]
    fn report_multiple_binding_constraints() {
        let mut idx = ExplanationIndex::new();
        let expl =
            ExplanationBuilder::new("d-mc".to_string(), test_epoch(), DecisionDomain::Security)
                .chosen(LaneAction::FallbackSafe, 0)
                .constraint(ConstraintInteraction {
                    constraint_id: "c1".to_string(),
                    description: "first".to_string(),
                    binding: true,
                    slack_millionths: 0,
                })
                .constraint(ConstraintInteraction {
                    constraint_id: "c2".to_string(),
                    description: "second".to_string(),
                    binding: true,
                    slack_millionths: 0,
                })
                .constraint(ConstraintInteraction {
                    constraint_id: "c3".to_string(),
                    description: "third non-binding".to_string(),
                    binding: false,
                    slack_millionths: 100_000,
                })
                .rationale("multiple constraints".to_string())
                .build()
                .unwrap();
        idx.insert(expl);

        let report = generate_report(&idx, &test_epoch());
        assert_eq!(report.binding_constraint_count, 1);
    }

    #[test]
    fn all_rejection_reasons_serde_and_ordering() {
        let reasons = [
            RejectionReason::HigherLoss,
            RejectionReason::GuardrailViolation,
            RejectionReason::BudgetInsufficient,
            RejectionReason::CalibrationInsufficient,
            RejectionReason::RegimeRestriction,
            RejectionReason::PolicyForbidden,
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let back: RejectionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
        // Ordering: HigherLoss < GuardrailViolation < ... < PolicyForbidden
        for window in reasons.windows(2) {
            assert!(window[0] < window[1]);
        }
    }

    #[test]
    fn explained_alternative_all_rejection_reasons() {
        let reasons = [
            RejectionReason::HigherLoss,
            RejectionReason::GuardrailViolation,
            RejectionReason::BudgetInsufficient,
            RejectionReason::CalibrationInsufficient,
            RejectionReason::RegimeRestriction,
            RejectionReason::PolicyForbidden,
        ];
        for (i, reason) in reasons.iter().enumerate() {
            let alt = ExplainedAlternative {
                action: LaneAction::RouteTo(test_lane(&format!("lane-{i}"))),
                expected_loss_millionths: (i as i64 + 1) * 100_000,
                rejection_reason: *reason,
                detail: format!("rejected for {reason}"),
            };
            let json = serde_json::to_string(&alt).unwrap();
            let back: ExplainedAlternative = serde_json::from_str(&json).unwrap();
            assert_eq!(alt, back);
        }
    }

    #[test]
    fn domain_ordering() {
        assert!(DecisionDomain::LaneRouting < DecisionDomain::Fallback);
        assert!(DecisionDomain::Fallback < DecisionDomain::Optimization);
        assert!(DecisionDomain::Optimization < DecisionDomain::Security);
        assert!(DecisionDomain::Security < DecisionDomain::Governance);
    }

    #[test]
    fn index_by_epoch_empty_epoch() {
        let mut idx = ExplanationIndex::new();
        let expl = ExplanationBuilder::new(
            "d-ep".to_string(),
            SecurityEpoch::from_raw(5),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("test".to_string())
        .build()
        .unwrap();
        idx.insert(expl);

        assert!(idx.by_epoch(&SecurityEpoch::from_raw(999)).is_empty());
    }

    #[test]
    fn one_line_summary_contains_loss() {
        let expl =
            ExplanationBuilder::new("d-summ".to_string(), test_epoch(), DecisionDomain::Fallback)
                .chosen(LaneAction::FallbackSafe, 42_000)
                .rationale("for testing".to_string())
                .build()
                .unwrap();
        let summary = expl.one_line_summary();
        assert!(summary.contains("42000"));
        assert!(summary.contains("fallback"));
    }

    #[test]
    fn explanation_full_serde_with_all_fields() {
        let expl = ExplanationBuilder::new(
            "d-full-serde".to_string(),
            test_epoch(),
            DecisionDomain::Security,
        )
        .verbosity(VerbosityLevel::GalaxyBrain)
        .regime(RegimeLabel::Attack)
        .equation(GoverningEquation {
            name: "threat".to_string(),
            formula: "T > threshold".to_string(),
            parameters: BTreeMap::from([("T".to_string(), 900_000)]),
            result_millionths: 900_000,
            threshold_millionths: Some(500_000),
            threshold_exceeded: true,
        })
        .chosen(LaneAction::SuspendAdaptive, 0)
        .rationale("full serde test".to_string())
        .alternative(ExplainedAlternative {
            action: LaneAction::RouteTo(test_lane("js")),
            expected_loss_millionths: 800_000,
            rejection_reason: RejectionReason::GuardrailViolation,
            detail: "guardrail".to_string(),
        })
        .constraint(ConstraintInteraction {
            constraint_id: "sec-1".to_string(),
            description: "security constraint".to_string(),
            binding: true,
            slack_millionths: 0,
        })
        .risk(RiskBreakdown {
            factor: "threat_level".to_string(),
            weight_millionths: 600_000,
            belief_millionths: 900_000,
            contribution_millionths: 540_000,
        })
        .counterfactual(CounterfactualOutcome {
            action: LaneAction::RouteTo(test_lane("js")),
            predicted_loss_millionths: 800_000,
            loss_delta_millionths: 800_000,
            would_trigger_guardrail: true,
            narrative: "would trigger guardrail".to_string(),
        })
        .posterior("threat_level".to_string(), 900_000)
        .confidence(950_000)
        .build()
        .unwrap();

        let json = serde_json::to_string_pretty(&expl).unwrap();
        let back: DecisionExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(expl, back);
    }

    #[test]
    fn governing_equation_many_parameters() {
        let mut params = BTreeMap::new();
        for i in 0..10 {
            params.insert(format!("param_{i}"), i * 100_000);
        }
        let eq = GoverningEquation {
            name: "multi-param".to_string(),
            formula: "sum(params)".to_string(),
            parameters: params.clone(),
            result_millionths: 4_500_000,
            threshold_millionths: None,
            threshold_exceeded: false,
        };
        assert_eq!(eq.parameters.len(), 10);
        let json = serde_json::to_string(&eq).unwrap();
        let back: GoverningEquation = serde_json::from_str(&json).unwrap();
        assert_eq!(eq, back);
    }

    #[test]
    fn schema_version_correct() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.galaxy-brain-explainability.v1"
        );
    }

    #[test]
    fn report_content_hash_differs_by_data() {
        let mut idx1 = ExplanationIndex::new();
        let expl1 = ExplanationBuilder::new(
            "d-h1".to_string(),
            test_epoch(),
            DecisionDomain::LaneRouting,
        )
        .chosen(LaneAction::FallbackSafe, 0)
        .rationale("one".to_string())
        .build()
        .unwrap();
        idx1.insert(expl1);

        let mut idx2 = ExplanationIndex::new();
        let expl2 =
            ExplanationBuilder::new("d-h2".to_string(), test_epoch(), DecisionDomain::Security)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("two".to_string())
                .build()
                .unwrap();
        idx2.insert(expl2);

        let r1 = generate_report(&idx1, &test_epoch());
        let r2 = generate_report(&idx2, &test_epoch());
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn index_multiple_decisions_across_domains_and_epochs() {
        let mut idx = ExplanationIndex::new();
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let domains = [
            DecisionDomain::LaneRouting,
            DecisionDomain::Fallback,
            DecisionDomain::Security,
        ];

        for (i, (ep, dom)) in [
            (epoch1, domains[0]),
            (epoch1, domains[1]),
            (epoch2, domains[2]),
        ]
        .iter()
        .enumerate()
        {
            let expl = ExplanationBuilder::new(format!("d-cross-{i}"), *ep, *dom)
                .chosen(LaneAction::FallbackSafe, 0)
                .rationale("cross test".to_string())
                .build()
                .unwrap();
            idx.insert(expl);
        }

        assert_eq!(idx.len(), 3);
        assert_eq!(idx.by_epoch(&epoch1).len(), 2);
        assert_eq!(idx.by_epoch(&epoch2).len(), 1);
        assert_eq!(idx.by_domain(DecisionDomain::LaneRouting).len(), 1);
        assert_eq!(idx.by_domain(DecisionDomain::Fallback).len(), 1);
        assert_eq!(idx.by_domain(DecisionDomain::Security).len(), 1);
    }
}
