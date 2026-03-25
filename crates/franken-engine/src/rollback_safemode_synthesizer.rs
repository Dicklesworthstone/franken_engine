//! Automated rollback and safe-mode policy synthesizer from twin counterfactual evidence.
//!
//! Compiles counterfactual replay results and bifurcation boundary scan outputs
//! into deterministic rollback and safe-mode policy bundles with replay verification
//! hooks. Enforces non-regression constraints against constitutional compatibility
//! invariants before emitting signed bundles.
//!
//! Plan reference: FRX-19.4

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bifurcation_boundary_scanner::ScanResult;
use crate::counterfactual_evaluator::EnvelopeStatus;
use crate::counterfactual_replay_engine::ReplayComparisonResult;
use crate::hash_tiers::ContentHash;
use crate::runtime_decision_theory::{LaneAction, LaneId};
use crate::security_epoch::SecurityEpoch;

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for synthesizer artifacts.
pub const SYNTHESIZER_SCHEMA_VERSION: &str = "franken-engine.rollback-safemode-synthesizer.v1";

/// Maximum number of synthesis rules.
const MAX_SYNTHESIS_RULES: usize = 256;

/// Maximum number of policy deltas per bundle.
const MAX_DELTAS_PER_BUNDLE: usize = 128;

/// Maximum number of non-regression constraints.
const MAX_CONSTRAINTS: usize = 128;

/// Default minimum confidence for adopting a recommendation (millionths).
const DEFAULT_MIN_CONFIDENCE_MILLIONTHS: i64 = 900_000;

/// Default maximum allowed regression (millionths). Bundles exceeding this are rejected.
const DEFAULT_MAX_REGRESSION_MILLIONTHS: i64 = 50_000;

/// Default minimum improvement to trigger rollback synthesis (millionths).
const DEFAULT_IMPROVEMENT_THRESHOLD_MILLIONTHS: i64 = 100_000;

// ── Synthesis Rule ──────────────────────────────────────────────────────

/// A rule that maps evidence patterns to policy deltas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisRule {
    /// Unique rule identifier.
    pub rule_id: String,
    /// Human-readable description.
    pub description: String,
    /// Evidence trigger category.
    pub trigger: EvidenceTrigger,
    /// Minimum confidence required to fire (millionths).
    pub min_confidence_millionths: i64,
    /// Priority for rule ordering (lower = higher priority).
    pub priority: u32,
    /// Whether the rule produces rollback or safe-mode output.
    pub output_kind: BundleKind,
    /// Whether the rule is enabled.
    pub enabled: bool,
}

impl fmt::Display for SynthesisRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule({}, {:?}, pri={})",
            self.rule_id, self.output_kind, self.priority
        )
    }
}

/// Category of evidence that can trigger a synthesis rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTrigger {
    /// Counterfactual replay showed improvement with alternate policy.
    CounterfactualImprovement {
        /// Minimum improvement millionths to trigger.
        min_improvement_millionths: i64,
    },
    /// Bifurcation boundary scan detected instability.
    BifurcationInstability {
        /// Minimum risk value millionths to trigger.
        min_risk_millionths: i64,
    },
    /// Early warning indicators are active.
    EarlyWarningActive {
        /// Minimum number of active warnings.
        min_active_count: usize,
    },
    /// Preemptive actions were recommended by scanner.
    PreemptiveActionRecommended,
    /// Combined evidence from replay + bifurcation.
    CombinedEvidence {
        /// Minimum replay improvement millionths.
        min_replay_improvement_millionths: i64,
        /// Minimum bifurcation risk millionths.
        min_bifurcation_risk_millionths: i64,
    },
}

impl fmt::Display for EvidenceTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterfactualImprovement {
                min_improvement_millionths,
            } => {
                write!(f, "cf-improvement(min={})", min_improvement_millionths)
            }
            Self::BifurcationInstability {
                min_risk_millionths,
            } => {
                write!(f, "bifurcation-instability(min={})", min_risk_millionths)
            }
            Self::EarlyWarningActive { min_active_count } => {
                write!(f, "early-warning(min={})", min_active_count)
            }
            Self::PreemptiveActionRecommended => write!(f, "preemptive-action"),
            Self::CombinedEvidence {
                min_replay_improvement_millionths,
                min_bifurcation_risk_millionths,
            } => {
                write!(
                    f,
                    "combined(replay={}, bifurcation={})",
                    min_replay_improvement_millionths, min_bifurcation_risk_millionths
                )
            }
        }
    }
}

/// The kind of bundle a synthesis rule produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleKind {
    /// Rollback to previous known-good configuration.
    Rollback,
    /// Switch to safe-mode routing.
    SafeMode,
    /// Adaptive — choose based on evidence severity.
    Adaptive,
}

impl fmt::Display for BundleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rollback => write!(f, "rollback"),
            Self::SafeMode => write!(f, "safe-mode"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

// ── Policy Delta ────────────────────────────────────────────────────────

/// A concrete policy change within a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDelta {
    /// Delta identifier.
    pub delta_id: String,
    /// Which rule produced this delta.
    pub source_rule_id: String,
    /// The lane action to apply.
    pub action: LaneAction,
    /// Epoch at which this delta takes effect.
    pub effective_epoch: SecurityEpoch,
    /// Expected improvement from applying this delta (millionths).
    pub expected_improvement_millionths: i64,
    /// Confidence in the expected improvement (millionths).
    pub confidence_millionths: i64,
    /// Rationale for the delta.
    pub rationale: String,
}

impl fmt::Display for PolicyDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "delta({}, action={}, improvement={})",
            self.delta_id, self.action, self.expected_improvement_millionths
        )
    }
}

// ── Non-Regression Constraint ───────────────────────────────────────────

/// A constitutional compatibility invariant that bundles must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonRegressionConstraint {
    /// Constraint identifier.
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Category of the constraint.
    pub category: ConstraintCategory,
    /// Maximum allowed regression (millionths). 0 = no regression allowed.
    pub max_regression_millionths: i64,
    /// Whether this constraint is hard (blocks bundle) or soft (advisory).
    pub hard: bool,
}

impl fmt::Display for NonRegressionConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.hard { "hard" } else { "soft" };
        write!(
            f,
            "constraint({}, {}, {})",
            self.constraint_id, self.category, kind
        )
    }
}

/// Category of non-regression constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintCategory {
    /// Safety invariant — never make the system less safe.
    Safety,
    /// Performance invariant — don't regress throughput/latency.
    Performance,
    /// Correctness invariant — don't break functional behavior.
    Correctness,
    /// Stability invariant — don't increase variance.
    Stability,
    /// Compatibility invariant — don't break API/protocol compatibility.
    Compatibility,
}

impl fmt::Display for ConstraintCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safety => write!(f, "safety"),
            Self::Performance => write!(f, "performance"),
            Self::Correctness => write!(f, "correctness"),
            Self::Stability => write!(f, "stability"),
            Self::Compatibility => write!(f, "compatibility"),
        }
    }
}

/// Result of checking a constraint against a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintCheckResult {
    /// Constraint that was checked.
    pub constraint_id: String,
    /// Whether the constraint passed.
    pub passed: bool,
    /// Measured regression value (millionths). Negative = improvement.
    pub regression_millionths: i64,
    /// Detail message.
    pub detail: String,
}

// ── Synthesized Bundle ──────────────────────────────────────────────────

/// A complete synthesized rollback or safe-mode bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedBundle {
    /// Bundle identifier.
    pub bundle_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Kind of bundle.
    pub kind: BundleKind,
    /// Epoch at which the bundle was synthesized.
    pub synthesis_epoch: SecurityEpoch,
    /// Policy deltas in this bundle, ordered by priority.
    pub deltas: Vec<PolicyDelta>,
    /// Non-regression check results.
    pub constraint_checks: Vec<ConstraintCheckResult>,
    /// Whether all hard constraints passed.
    pub all_hard_constraints_passed: bool,
    /// Whether any soft constraints were violated.
    pub soft_violations: u64,
    /// Total expected improvement from all deltas (millionths).
    pub total_improvement_millionths: i64,
    /// Minimum confidence across all deltas (millionths).
    pub min_confidence_millionths: i64,
    /// Replay verification hooks.
    pub verification_hooks: Vec<ReplayVerificationHook>,
    /// Evidence references that produced this bundle.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Artifact hash for integrity.
    pub artifact_hash: ContentHash,
}

impl SynthesizedBundle {
    /// Whether the bundle is approved for application.
    pub fn is_approved(&self) -> bool {
        self.all_hard_constraints_passed && !self.deltas.is_empty()
    }

    /// Number of deltas in the bundle.
    pub fn delta_count(&self) -> usize {
        self.deltas.len()
    }

    /// Number of constraint violations (hard + soft).
    pub fn violation_count(&self) -> u64 {
        self.constraint_checks.iter().filter(|c| !c.passed).count() as u64
    }
}

impl fmt::Display for SynthesizedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_approved() {
            "approved"
        } else {
            "rejected"
        };
        write!(
            f,
            "bundle({}, {}, deltas={}, {})",
            self.bundle_id,
            self.kind,
            self.deltas.len(),
            status
        )
    }
}

/// A replay verification hook attached to a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayVerificationHook {
    /// Hook identifier.
    pub hook_id: String,
    /// Description of what the hook verifies.
    pub description: String,
    /// The verification kind.
    pub verification_kind: VerificationKind,
    /// Expected outcome after applying the bundle's deltas.
    pub expected_outcome_millionths: i64,
    /// Tolerance for the expected outcome (millionths).
    pub tolerance_millionths: i64,
}

/// Kind of replay verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationKind {
    /// Verify improvement by replaying with new policy.
    ImprovementReplay,
    /// Verify no regression against baseline.
    NonRegressionReplay,
    /// Verify stability under boundary conditions.
    StabilityReplay,
    /// Verify safe-mode behavior is correct.
    SafeModeReplay,
}

impl fmt::Display for VerificationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImprovementReplay => write!(f, "improvement-replay"),
            Self::NonRegressionReplay => write!(f, "non-regression-replay"),
            Self::StabilityReplay => write!(f, "stability-replay"),
            Self::SafeModeReplay => write!(f, "safe-mode-replay"),
        }
    }
}

/// Reference to evidence that contributed to a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Source kind.
    pub source: EvidenceSource,
    /// Artifact hash of the source evidence.
    pub artifact_hash: ContentHash,
    /// Summary of what the evidence showed.
    pub summary: String,
}

/// Source of evidence for synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// From counterfactual replay engine.
    CounterfactualReplay,
    /// From bifurcation boundary scanner.
    BifurcationScan,
    /// From both sources combined.
    Combined,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterfactualReplay => write!(f, "counterfactual-replay"),
            Self::BifurcationScan => write!(f, "bifurcation-scan"),
            Self::Combined => write!(f, "combined"),
        }
    }
}

// ── Synthesis Result ────────────────────────────────────────────────────

/// Complete output of the synthesis process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisResult {
    /// Schema version.
    pub schema_version: String,
    /// Epoch of synthesis.
    pub epoch: SecurityEpoch,
    /// Rules that fired during synthesis.
    pub rules_fired: Vec<String>,
    /// Rules that were evaluated but did not fire.
    pub rules_skipped: Vec<String>,
    /// Synthesized bundles, ordered by total improvement.
    pub bundles: Vec<SynthesizedBundle>,
    /// Number of approved bundles.
    pub approved_count: u64,
    /// Number of rejected bundles (hard constraint violations).
    pub rejected_count: u64,
    /// Artifact hash.
    pub artifact_hash: ContentHash,
}

impl SynthesisResult {
    /// Whether any bundles were produced.
    pub fn has_bundles(&self) -> bool {
        !self.bundles.is_empty()
    }

    /// Best approved bundle (highest improvement).
    pub fn best_approved(&self) -> Option<&SynthesizedBundle> {
        self.bundles.iter().find(|b| b.is_approved())
    }

    /// All approved bundles.
    pub fn approved_bundles(&self) -> Vec<&SynthesizedBundle> {
        self.bundles.iter().filter(|b| b.is_approved()).collect()
    }
}

impl fmt::Display for SynthesisResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "synthesis(epoch={}, bundles={}, approved={}, rejected={})",
            self.epoch,
            self.bundles.len(),
            self.approved_count,
            self.rejected_count
        )
    }
}

// ── Error ───────────────────────────────────────────────────────────────

/// Errors from the synthesis process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesizerError {
    /// No synthesis rules configured.
    NoRules,
    /// Too many synthesis rules.
    TooManyRules { count: usize, max: usize },
    /// No evidence provided.
    NoEvidence,
    /// Too many deltas in a bundle.
    TooManyDeltas { count: usize, max: usize },
    /// Too many constraints.
    TooManyConstraints { count: usize, max: usize },
    /// Duplicate rule ID.
    DuplicateRule { rule_id: String },
    /// Duplicate constraint ID.
    DuplicateConstraint { constraint_id: String },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl fmt::Display for SynthesizerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRules => write!(f, "no synthesis rules configured"),
            Self::TooManyRules { count, max } => {
                write!(f, "too many rules: {} exceeds max {}", count, max)
            }
            Self::NoEvidence => write!(f, "no evidence provided for synthesis"),
            Self::TooManyDeltas { count, max } => {
                write!(f, "too many deltas: {} exceeds max {}", count, max)
            }
            Self::TooManyConstraints { count, max } => {
                write!(f, "too many constraints: {} exceeds max {}", count, max)
            }
            Self::DuplicateRule { rule_id } => {
                write!(f, "duplicate rule ID: {}", rule_id)
            }
            Self::DuplicateConstraint { constraint_id } => {
                write!(f, "duplicate constraint ID: {}", constraint_id)
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid config: {}", detail)
            }
        }
    }
}

impl std::error::Error for SynthesizerError {}

// ── Synthesis Input ─────────────────────────────────────────────────────

/// Evidence input for the synthesis process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisInput {
    /// Counterfactual replay result (optional).
    pub replay_result: Option<ReplayComparisonResult>,
    /// Bifurcation scan result (optional).
    pub scan_result: Option<ScanResult>,
}

impl SynthesisInput {
    /// Whether any evidence is present.
    pub fn has_evidence(&self) -> bool {
        self.replay_result.is_some() || self.scan_result.is_some()
    }
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the synthesizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizerConfig {
    /// Epoch for synthesis.
    pub epoch: SecurityEpoch,
    /// Minimum confidence to accept a recommendation (millionths).
    pub min_confidence_millionths: i64,
    /// Maximum allowed regression for bundle approval (millionths).
    pub max_regression_millionths: i64,
    /// Minimum improvement threshold to trigger rollback synthesis (millionths).
    pub improvement_threshold_millionths: i64,
    /// Whether to generate replay verification hooks.
    pub generate_verification_hooks: bool,
    /// Default lane for safe-mode routing.
    pub safe_mode_lane: LaneId,
    /// Default lane for rollback routing.
    pub rollback_lane: LaneId,
}

impl Default for SynthesizerConfig {
    fn default() -> Self {
        Self {
            epoch: SecurityEpoch::from_raw(1),
            min_confidence_millionths: DEFAULT_MIN_CONFIDENCE_MILLIONTHS,
            max_regression_millionths: DEFAULT_MAX_REGRESSION_MILLIONTHS,
            improvement_threshold_millionths: DEFAULT_IMPROVEMENT_THRESHOLD_MILLIONTHS,
            generate_verification_hooks: true,
            safe_mode_lane: LaneId("safe".to_string()),
            rollback_lane: LaneId("baseline".to_string()),
        }
    }
}

// ── Main Synthesizer ────────────────────────────────────────────────────

/// Synthesizes rollback and safe-mode policy bundles from twin evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSafemodeSynthesizer {
    config: SynthesizerConfig,
    rules: Vec<SynthesisRule>,
    constraints: Vec<NonRegressionConstraint>,
    synthesis_count: u64,
}

impl RollbackSafemodeSynthesizer {
    /// Create a new synthesizer.
    pub fn new(
        config: SynthesizerConfig,
        rules: Vec<SynthesisRule>,
        constraints: Vec<NonRegressionConstraint>,
    ) -> Result<Self, SynthesizerError> {
        if rules.is_empty() {
            return Err(SynthesizerError::NoRules);
        }
        if rules.len() > MAX_SYNTHESIS_RULES {
            return Err(SynthesizerError::TooManyRules {
                count: rules.len(),
                max: MAX_SYNTHESIS_RULES,
            });
        }
        if constraints.len() > MAX_CONSTRAINTS {
            return Err(SynthesizerError::TooManyConstraints {
                count: constraints.len(),
                max: MAX_CONSTRAINTS,
            });
        }

        // Check duplicate rule IDs.
        let mut seen_rules = BTreeSet::new();
        for rule in &rules {
            if !seen_rules.insert(&rule.rule_id) {
                return Err(SynthesizerError::DuplicateRule {
                    rule_id: rule.rule_id.clone(),
                });
            }
        }

        // Check duplicate constraint IDs.
        let mut seen_constraints = BTreeSet::new();
        for constraint in &constraints {
            if !seen_constraints.insert(&constraint.constraint_id) {
                return Err(SynthesizerError::DuplicateConstraint {
                    constraint_id: constraint.constraint_id.clone(),
                });
            }
        }

        if config.min_confidence_millionths < 0 || config.min_confidence_millionths > MILLION {
            return Err(SynthesizerError::InvalidConfig {
                detail: format!(
                    "min_confidence_millionths {} out of range [0, {}]",
                    config.min_confidence_millionths, MILLION
                ),
            });
        }

        Ok(Self {
            config,
            rules,
            constraints,
            synthesis_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &SynthesizerConfig {
        &self.config
    }

    /// Number of synthesis operations performed.
    pub fn synthesis_count(&self) -> u64 {
        self.synthesis_count
    }

    /// Number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Number of constraints.
    pub fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Run synthesis against the provided evidence.
    pub fn synthesize(
        &mut self,
        input: &SynthesisInput,
    ) -> Result<SynthesisResult, SynthesizerError> {
        if !input.has_evidence() {
            return Err(SynthesizerError::NoEvidence);
        }

        self.synthesis_count += 1;

        let mut rules_fired = Vec::new();
        let mut rules_skipped = Vec::new();
        let mut bundles = Vec::new();

        // Sort rules by priority (lower = higher priority).
        let mut sorted_rules = self.rules.clone();
        sorted_rules.sort_by_key(|r| r.priority);

        for rule in &sorted_rules {
            if !rule.enabled {
                rules_skipped.push(rule.rule_id.clone());
                continue;
            }

            if let Some(deltas) = self.evaluate_rule(rule, input) {
                if deltas.is_empty() {
                    rules_skipped.push(rule.rule_id.clone());
                    continue;
                }

                rules_fired.push(rule.rule_id.clone());

                // Determine bundle kind.
                let kind = self.resolve_bundle_kind(rule, input);

                // Build bundle.
                let bundle = self.build_bundle(&rule.rule_id, kind, deltas, input)?;

                bundles.push(bundle);
            } else {
                rules_skipped.push(rule.rule_id.clone());
            }
        }

        // Sort bundles by total improvement (highest first).
        bundles.sort_by(|a, b| {
            b.total_improvement_millionths
                .cmp(&a.total_improvement_millionths)
        });

        let approved_count = bundles.iter().filter(|b| b.is_approved()).count() as u64;
        let rejected_count = bundles.iter().filter(|b| !b.is_approved()).count() as u64;

        // Compute artifact hash covering all fields.
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(SYNTHESIZER_SCHEMA_VERSION.as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        // Sort and include rules_fired/skipped for determinism.
        let mut sorted_fired = rules_fired.clone();
        sorted_fired.sort();
        for r in &sorted_fired {
            hash_buf.extend_from_slice(r.as_bytes());
        }
        let mut sorted_skipped = rules_skipped.clone();
        sorted_skipped.sort();
        for r in &sorted_skipped {
            hash_buf.extend_from_slice(r.as_bytes());
        }
        hash_buf.extend_from_slice(&(bundles.len() as u64).to_le_bytes());
        for bundle in &bundles {
            hash_buf.extend_from_slice(bundle.artifact_hash.as_bytes());
        }
        hash_buf.extend_from_slice(&approved_count.to_le_bytes());
        hash_buf.extend_from_slice(&rejected_count.to_le_bytes());

        Ok(SynthesisResult {
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            epoch: self.config.epoch,
            rules_fired,
            rules_skipped,
            bundles,
            approved_count,
            rejected_count,
            artifact_hash: ContentHash::compute(&hash_buf),
        })
    }

    // ── Rule Evaluation ─────────────────────────────────────────────

    fn evaluate_rule(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
    ) -> Option<Vec<PolicyDelta>> {
        match &rule.trigger {
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths,
            } => self.evaluate_counterfactual_trigger(rule, input, *min_improvement_millionths),
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths,
            } => self.evaluate_bifurcation_trigger(rule, input, *min_risk_millionths),
            EvidenceTrigger::EarlyWarningActive { min_active_count } => {
                self.evaluate_early_warning_trigger(rule, input, *min_active_count)
            }
            EvidenceTrigger::PreemptiveActionRecommended => {
                self.evaluate_preemptive_trigger(rule, input)
            }
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths,
                min_bifurcation_risk_millionths,
            } => self.evaluate_combined_trigger(
                rule,
                input,
                *min_replay_improvement_millionths,
                *min_bifurcation_risk_millionths,
            ),
        }
    }

    fn evaluate_counterfactual_trigger(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
        min_improvement: i64,
    ) -> Option<Vec<PolicyDelta>> {
        let replay = input.replay_result.as_ref()?;

        let mut deltas = Vec::new();
        for rec in &replay.ranked_recommendations {
            if rec.expected_improvement_millionths >= min_improvement
                && rec.confidence_millionths >= rule.min_confidence_millionths
                && rec.safety_status != EnvelopeStatus::Unsafe
            {
                let action = self.action_for_kind(rule.output_kind);
                deltas.push(PolicyDelta {
                    delta_id: format!("d-{}-{}", rule.rule_id, rec.policy_id),
                    source_rule_id: rule.rule_id.clone(),
                    action,
                    effective_epoch: self.config.epoch,
                    expected_improvement_millionths: rec.expected_improvement_millionths,
                    confidence_millionths: rec.confidence_millionths,
                    rationale: format!(
                        "Counterfactual replay recommends {} with improvement {}",
                        rec.policy_id, rec.expected_improvement_millionths
                    ),
                });
            }
        }

        if deltas.is_empty() {
            None
        } else {
            Some(deltas)
        }
    }

    fn evaluate_bifurcation_trigger(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
        min_risk: i64,
    ) -> Option<Vec<PolicyDelta>> {
        let scan = input.scan_result.as_ref()?;

        let mut deltas = Vec::new();

        // Check if stability is below risk threshold.
        let risk = MILLION - scan.stability_score_millionths;
        if risk >= min_risk {
            for action in &scan.preemptive_actions {
                deltas.push(PolicyDelta {
                    delta_id: format!("d-{}-{}", rule.rule_id, action.action_id),
                    source_rule_id: rule.rule_id.clone(),
                    action: action.lane_action.clone(),
                    effective_epoch: self.config.epoch,
                    expected_improvement_millionths: action.trigger_risk_millionths,
                    confidence_millionths: scan.stability_score_millionths,
                    rationale: format!(
                        "Bifurcation instability detected: risk={}, action={}",
                        risk, action.rationale
                    ),
                });
            }

            // If no preemptive actions but risk is high, add a default safe-mode delta.
            if deltas.is_empty() {
                deltas.push(PolicyDelta {
                    delta_id: format!("d-{}-default", rule.rule_id),
                    source_rule_id: rule.rule_id.clone(),
                    action: self.action_for_kind(rule.output_kind),
                    effective_epoch: self.config.epoch,
                    expected_improvement_millionths: risk,
                    confidence_millionths: MILLION - risk,
                    rationale: format!("Bifurcation risk {} exceeds threshold {}", risk, min_risk),
                });
            }
        }

        if deltas.is_empty() {
            None
        } else {
            Some(deltas)
        }
    }

    fn evaluate_early_warning_trigger(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
        min_active_count: usize,
    ) -> Option<Vec<PolicyDelta>> {
        let scan = input.scan_result.as_ref()?;

        let active_warnings: Vec<_> = scan.warnings.iter().filter(|w| w.active).collect();
        if active_warnings.len() < min_active_count {
            return None;
        }

        let mut deltas = Vec::new();
        let max_risk = active_warnings
            .iter()
            .map(|w| w.risk_value_millionths)
            .max()
            .unwrap_or(0);

        deltas.push(PolicyDelta {
            delta_id: format!("d-{}-ew", rule.rule_id),
            source_rule_id: rule.rule_id.clone(),
            action: self.action_for_kind(rule.output_kind),
            effective_epoch: self.config.epoch,
            expected_improvement_millionths: max_risk,
            confidence_millionths: scan.stability_score_millionths,
            rationale: format!(
                "{} active early warnings, max risk={}",
                active_warnings.len(),
                max_risk
            ),
        });

        Some(deltas)
    }

    fn evaluate_preemptive_trigger(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
    ) -> Option<Vec<PolicyDelta>> {
        let scan = input.scan_result.as_ref()?;

        if scan.preemptive_actions.is_empty() {
            return None;
        }

        let mut deltas = Vec::new();
        for action in &scan.preemptive_actions {
            deltas.push(PolicyDelta {
                delta_id: format!("d-{}-{}", rule.rule_id, action.action_id),
                source_rule_id: rule.rule_id.clone(),
                action: action.lane_action.clone(),
                effective_epoch: self.config.epoch,
                expected_improvement_millionths: action.trigger_risk_millionths,
                confidence_millionths: MILLION,
                rationale: format!("Preemptive action: {}", action.rationale),
            });
        }

        Some(deltas)
    }

    fn evaluate_combined_trigger(
        &self,
        rule: &SynthesisRule,
        input: &SynthesisInput,
        min_replay_improvement: i64,
        min_bifurcation_risk: i64,
    ) -> Option<Vec<PolicyDelta>> {
        let replay = input.replay_result.as_ref()?;
        let scan = input.scan_result.as_ref()?;

        // Need both sources to confirm.
        let best_improvement = replay
            .ranked_recommendations
            .first()
            .map(|r| r.expected_improvement_millionths)
            .unwrap_or(0);

        let risk = MILLION - scan.stability_score_millionths;

        if best_improvement < min_replay_improvement || risk < min_bifurcation_risk {
            return None;
        }

        let mut deltas = Vec::new();

        // Use the best counterfactual recommendation.
        if let Some(rec) = replay.ranked_recommendations.first()
            && rec.confidence_millionths >= rule.min_confidence_millionths
            && rec.safety_status != EnvelopeStatus::Unsafe
        {
            deltas.push(PolicyDelta {
                delta_id: format!("d-{}-combined", rule.rule_id),
                source_rule_id: rule.rule_id.clone(),
                action: self.action_for_kind(rule.output_kind),
                effective_epoch: self.config.epoch,
                expected_improvement_millionths: best_improvement,
                confidence_millionths: rec.confidence_millionths,
                rationale: format!(
                    "Combined evidence: replay improvement={}, bifurcation risk={}",
                    best_improvement, risk
                ),
            });
        }

        if deltas.is_empty() {
            None
        } else {
            Some(deltas)
        }
    }

    // ── Bundle Building ─────────────────────────────────────────────

    fn resolve_bundle_kind(&self, rule: &SynthesisRule, input: &SynthesisInput) -> BundleKind {
        match rule.output_kind {
            BundleKind::Adaptive => {
                // If bifurcation shows catastrophic risk, use safe-mode.
                if let Some(scan) = &input.scan_result {
                    let critical = scan.warnings.iter().filter(|w| w.is_critical()).count();
                    if critical > 0 || !scan.preemptive_actions.is_empty() {
                        return BundleKind::SafeMode;
                    }
                }
                BundleKind::Rollback
            }
            other => other,
        }
    }

    fn action_for_kind(&self, kind: BundleKind) -> LaneAction {
        match kind {
            BundleKind::SafeMode | BundleKind::Adaptive => LaneAction::FallbackSafe,
            BundleKind::Rollback => LaneAction::RouteTo(self.config.rollback_lane.clone()),
        }
    }

    fn build_bundle(
        &self,
        rule_id: &str,
        kind: BundleKind,
        mut deltas: Vec<PolicyDelta>,
        input: &SynthesisInput,
    ) -> Result<SynthesizedBundle, SynthesizerError> {
        // Enforce max deltas.
        if deltas.len() > MAX_DELTAS_PER_BUNDLE {
            return Err(SynthesizerError::TooManyDeltas {
                count: deltas.len(),
                max: MAX_DELTAS_PER_BUNDLE,
            });
        }

        // Sort deltas by expected improvement (highest first).
        deltas.sort_by(|a, b| {
            b.expected_improvement_millionths
                .cmp(&a.expected_improvement_millionths)
        });

        // Compute totals.
        let total_improvement: i64 = deltas
            .iter()
            .map(|d| d.expected_improvement_millionths)
            .sum();
        let min_confidence = deltas
            .iter()
            .map(|d| d.confidence_millionths)
            .min()
            .unwrap_or(0);

        // Run non-regression checks.
        let constraint_checks = self.check_constraints(&deltas, total_improvement);
        let all_hard_passed = self.constraints.iter().all(|c| {
            !c.hard
                || constraint_checks
                    .iter()
                    .find(|r| r.constraint_id == c.constraint_id)
                    .map(|r| r.passed)
                    .unwrap_or(true)
        });
        let soft_violations = constraint_checks.iter().filter(|c| !c.passed).count() as u64;

        // Generate verification hooks.
        let verification_hooks = if self.config.generate_verification_hooks {
            self.generate_hooks(kind, &deltas, total_improvement)
        } else {
            Vec::new()
        };

        // Collect evidence references.
        let evidence_refs = self.collect_evidence_refs(input);

        // Compute bundle artifact hash covering all fields.
        let bundle_id = format!("bundle-{}-{}-{}", rule_id, kind, self.synthesis_count);
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(bundle_id.as_bytes());
        hash_buf.extend_from_slice(format!("{kind:?}").as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        hash_buf.extend_from_slice(&(deltas.len() as u64).to_le_bytes());
        for delta in &deltas {
            hash_buf.extend_from_slice(delta.delta_id.as_bytes());
            hash_buf.extend_from_slice(&delta.expected_improvement_millionths.to_le_bytes());
        }
        hash_buf.extend_from_slice(&(constraint_checks.len() as u64).to_le_bytes());
        for cc in &constraint_checks {
            hash_buf.push(if cc.passed { 1 } else { 0 });
        }
        hash_buf.push(if all_hard_passed { 1 } else { 0 });
        hash_buf.extend_from_slice(&soft_violations.to_le_bytes());
        hash_buf.extend_from_slice(&total_improvement.to_le_bytes());
        hash_buf.extend_from_slice(&min_confidence.to_le_bytes());
        hash_buf.extend_from_slice(&(verification_hooks.len() as u64).to_le_bytes());
        hash_buf.extend_from_slice(&(evidence_refs.len() as u64).to_le_bytes());

        Ok(SynthesizedBundle {
            bundle_id,
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            kind,
            synthesis_epoch: self.config.epoch,
            deltas,
            constraint_checks,
            all_hard_constraints_passed: all_hard_passed,
            soft_violations,
            total_improvement_millionths: total_improvement,
            min_confidence_millionths: min_confidence,
            verification_hooks,
            evidence_refs,
            artifact_hash: ContentHash::compute(&hash_buf),
        })
    }

    // ── Constraint Checking ─────────────────────────────────────────

    fn check_constraints(
        &self,
        deltas: &[PolicyDelta],
        total_improvement: i64,
    ) -> Vec<ConstraintCheckResult> {
        self.constraints
            .iter()
            .map(|constraint| {
                let regression = self.estimate_regression(constraint, deltas, total_improvement);
                let passed = regression <= constraint.max_regression_millionths;
                ConstraintCheckResult {
                    constraint_id: constraint.constraint_id.clone(),
                    passed,
                    regression_millionths: regression,
                    detail: if passed {
                        format!(
                            "regression {} within limit {}",
                            regression, constraint.max_regression_millionths
                        )
                    } else {
                        format!(
                            "regression {} exceeds limit {}",
                            regression, constraint.max_regression_millionths
                        )
                    },
                }
            })
            .collect()
    }

    fn estimate_regression(
        &self,
        constraint: &NonRegressionConstraint,
        deltas: &[PolicyDelta],
        total_improvement: i64,
    ) -> i64 {
        // Conservative regression estimate based on constraint category.
        // If total improvement is positive and confidence is high, regression is low.
        // Safety constraints are evaluated more conservatively.
        let min_confidence = deltas
            .iter()
            .map(|d| d.confidence_millionths)
            .min()
            .unwrap_or(0);

        let category_factor = match constraint.category {
            ConstraintCategory::Safety => 3,
            ConstraintCategory::Correctness => 2,
            ConstraintCategory::Stability => 2,
            ConstraintCategory::Performance => 1,
            ConstraintCategory::Compatibility => 1,
        };

        // Regression estimate = uncertainty * category factor.
        // Uncertainty = (1 - min_confidence) * |total_improvement|.
        let uncertainty = MILLION - min_confidence;
        let base_regression = (uncertainty * total_improvement.abs()) / (MILLION * category_factor);
        base_regression.max(0)
    }

    // ── Verification Hook Generation ────────────────────────────────

    fn generate_hooks(
        &self,
        kind: BundleKind,
        deltas: &[PolicyDelta],
        total_improvement: i64,
    ) -> Vec<ReplayVerificationHook> {
        let mut hooks = Vec::new();

        // Improvement verification hook.
        hooks.push(ReplayVerificationHook {
            hook_id: format!("hook-improvement-{}", self.synthesis_count),
            description: "Verify improvement by replaying with new policy".to_string(),
            verification_kind: VerificationKind::ImprovementReplay,
            expected_outcome_millionths: total_improvement,
            tolerance_millionths: total_improvement.abs() / 10, // 10% tolerance
        });

        // Non-regression hook.
        hooks.push(ReplayVerificationHook {
            hook_id: format!("hook-nonregression-{}", self.synthesis_count),
            description: "Verify no regression against baseline".to_string(),
            verification_kind: VerificationKind::NonRegressionReplay,
            expected_outcome_millionths: 0,
            tolerance_millionths: self.config.max_regression_millionths,
        });

        // Safe-mode verification hook (only for safe-mode bundles).
        if kind == BundleKind::SafeMode {
            hooks.push(ReplayVerificationHook {
                hook_id: format!("hook-safemode-{}", self.synthesis_count),
                description: "Verify safe-mode behavior is correct".to_string(),
                verification_kind: VerificationKind::SafeModeReplay,
                expected_outcome_millionths: 0,
                tolerance_millionths: MILLION / 100, // 1% tolerance
            });
        }

        // Stability hook if there are many deltas.
        if deltas.len() > 1 {
            hooks.push(ReplayVerificationHook {
                hook_id: format!("hook-stability-{}", self.synthesis_count),
                description: "Verify stability under boundary conditions".to_string(),
                verification_kind: VerificationKind::StabilityReplay,
                expected_outcome_millionths: 0,
                tolerance_millionths: MILLION / 20, // 5% tolerance
            });
        }

        hooks
    }

    // ── Evidence Collection ─────────────────────────────────────────

    fn collect_evidence_refs(&self, input: &SynthesisInput) -> Vec<EvidenceRef> {
        let mut refs = Vec::new();

        if let Some(replay) = &input.replay_result {
            refs.push(EvidenceRef {
                source: EvidenceSource::CounterfactualReplay,
                artifact_hash: replay.artifact_hash,
                summary: format!(
                    "{} traces, {} decisions, {} recommendations",
                    replay.trace_count,
                    replay.total_decisions,
                    replay.ranked_recommendations.len()
                ),
            });
        }

        if let Some(scan) = &input.scan_result {
            refs.push(EvidenceRef {
                source: EvidenceSource::BifurcationScan,
                artifact_hash: scan.artifact_hash,
                summary: format!(
                    "{} params, {} bifurcations, {} warnings, stability={}",
                    scan.parameters_scanned,
                    scan.bifurcation_points.len(),
                    scan.warnings.len(),
                    scan.stability_score_millionths
                ),
            });
        }

        refs
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::bifurcation_boundary_scanner::{EarlyWarningIndicator, PreemptiveAction};
    use crate::counterfactual_evaluator::PolicyId;
    use crate::counterfactual_replay_engine::Recommendation;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_rule(id: &str, trigger: EvidenceTrigger, kind: BundleKind) -> SynthesisRule {
        SynthesisRule {
            rule_id: id.to_string(),
            description: format!("Rule {}", id),
            trigger,
            min_confidence_millionths: 500_000,
            priority: 1,
            output_kind: kind,
            enabled: true,
        }
    }

    fn make_constraint(
        id: &str,
        category: ConstraintCategory,
        hard: bool,
    ) -> NonRegressionConstraint {
        NonRegressionConstraint {
            constraint_id: id.to_string(),
            description: format!("Constraint {}", id),
            category,
            max_regression_millionths: DEFAULT_MAX_REGRESSION_MILLIONTHS,
            hard,
        }
    }

    fn make_recommendation(policy_id: &str, improvement: i64, confidence: i64) -> Recommendation {
        Recommendation {
            rank: 1,
            policy_id: PolicyId(policy_id.to_string()),
            expected_improvement_millionths: improvement,
            confidence_millionths: confidence,
            safety_status: EnvelopeStatus::Safe,
            rationale: format!("Recommend {}", policy_id),
        }
    }

    fn make_replay_result(recommendations: Vec<Recommendation>) -> ReplayComparisonResult {
        use crate::counterfactual_replay_engine::ReplayScope;

        ReplayComparisonResult {
            schema_version: "test".to_string(),
            trace_count: 10,
            total_decisions: 100,
            scope: ReplayScope::default(),
            policy_reports: Vec::new(),
            ranked_recommendations: recommendations,
            global_assumptions: Vec::new(),
            causal_effects: Vec::new(),
            artifact_hash: ContentHash::compute(b"test-replay"),
        }
    }

    fn make_scan_result(
        stability: i64,
        warnings: Vec<EarlyWarningIndicator>,
        preemptive: Vec<PreemptiveAction>,
    ) -> ScanResult {
        ScanResult {
            schema_version: "test".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            parameters_scanned: 5,
            bifurcation_points: Vec::new(),
            warnings,
            preemptive_actions: preemptive,
            stability_score_millionths: stability,
            regime_summary: BTreeMap::new(),
            artifact_hash: ContentHash::compute(b"test-scan"),
        }
    }

    fn make_warning(id: &str, risk: i64, active: bool) -> EarlyWarningIndicator {
        EarlyWarningIndicator {
            indicator_id: id.to_string(),
            parameter_id: format!("param-{}", id),
            risk_value_millionths: risk,
            threshold_millionths: 750_000,
            active,
            trend_millionths: 0,
            observation_count: 10,
        }
    }

    fn make_preemptive_action(id: &str, risk: i64) -> PreemptiveAction {
        PreemptiveAction {
            action_id: id.to_string(),
            trigger_indicator_id: format!("ew-{}", id),
            parameter_id: format!("param-{}", id),
            lane_action: LaneAction::FallbackSafe,
            epoch: SecurityEpoch::from_raw(1),
            trigger_risk_millionths: risk,
            rationale: format!("Preemptive action {}", id),
        }
    }

    fn default_synthesizer() -> RollbackSafemodeSynthesizer {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let constraints = vec![make_constraint("c1", ConstraintCategory::Safety, true)];
        RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints).unwrap()
    }

    // ── Constructor Tests ───────────────────────────────────────────

    #[test]
    fn new_creates_synthesizer() {
        let synth = default_synthesizer();
        assert_eq!(synth.rule_count(), 1);
        assert_eq!(synth.constraint_count(), 1);
        assert_eq!(synth.synthesis_count(), 0);
    }

    #[test]
    fn new_rejects_no_rules() {
        let result =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), Vec::new(), Vec::new());
        assert!(matches!(result, Err(SynthesizerError::NoRules)));
    }

    #[test]
    fn new_rejects_too_many_rules() {
        let rules: Vec<_> = (0..257)
            .map(|i| {
                make_rule(
                    &format!("r{}", i),
                    EvidenceTrigger::PreemptiveActionRecommended,
                    BundleKind::SafeMode,
                )
            })
            .collect();
        let result =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new());
        assert!(matches!(
            result,
            Err(SynthesizerError::TooManyRules {
                count: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn new_rejects_too_many_constraints() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let constraints: Vec<_> = (0..129)
            .map(|i| make_constraint(&format!("c{}", i), ConstraintCategory::Safety, true))
            .collect();
        let result =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints);
        assert!(matches!(
            result,
            Err(SynthesizerError::TooManyConstraints {
                count: 129,
                max: 128
            })
        ));
    }

    #[test]
    fn new_rejects_duplicate_rules() {
        let rules = vec![
            make_rule(
                "dup",
                EvidenceTrigger::PreemptiveActionRecommended,
                BundleKind::SafeMode,
            ),
            make_rule(
                "dup",
                EvidenceTrigger::PreemptiveActionRecommended,
                BundleKind::Rollback,
            ),
        ];
        let result =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new());
        assert!(matches!(
            result,
            Err(SynthesizerError::DuplicateRule { .. })
        ));
    }

    #[test]
    fn new_rejects_duplicate_constraints() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let constraints = vec![
            make_constraint("dup", ConstraintCategory::Safety, true),
            make_constraint("dup", ConstraintCategory::Performance, false),
        ];
        let result =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints);
        assert!(matches!(
            result,
            Err(SynthesizerError::DuplicateConstraint { .. })
        ));
    }

    #[test]
    fn new_rejects_invalid_confidence() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let config = SynthesizerConfig {
            min_confidence_millionths: MILLION + 1,
            ..Default::default()
        };
        let result = RollbackSafemodeSynthesizer::new(config, rules, Vec::new());
        assert!(matches!(
            result,
            Err(SynthesizerError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn new_rejects_negative_confidence() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let config = SynthesizerConfig {
            min_confidence_millionths: -1,
            ..Default::default()
        };
        let result = RollbackSafemodeSynthesizer::new(config, rules, Vec::new());
        assert!(matches!(
            result,
            Err(SynthesizerError::InvalidConfig { .. })
        ));
    }

    // ── Synthesis Tests ─────────────────────────────────────────────

    #[test]
    fn synthesize_rejects_no_evidence() {
        let mut synth = default_synthesizer();
        let input = SynthesisInput {
            replay_result: None,
            scan_result: None,
        };
        assert!(matches!(
            synth.synthesize(&input),
            Err(SynthesizerError::NoEvidence)
        ));
    }

    #[test]
    fn synthesize_increments_count() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let _ = synth.synthesize(&input);
        assert_eq!(synth.synthesis_count(), 1);
        let _ = synth.synthesize(&input);
        assert_eq!(synth.synthesis_count(), 2);
    }

    #[test]
    fn synthesize_from_counterfactual_improvement() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        assert_eq!(result.approved_count, 1);
        assert_eq!(result.bundles[0].kind, BundleKind::Rollback);
        assert!(!result.bundles[0].deltas.is_empty());
        assert_eq!(result.rules_fired, vec!["r1"]);
    }

    #[test]
    fn synthesize_skips_low_improvement() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 50_000, 950_000); // Below 100_000 threshold
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
        assert!(result.rules_fired.is_empty());
    }

    #[test]
    fn synthesize_skips_low_confidence() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 400_000); // Below 500_000 rule threshold
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn synthesize_skips_violated_safety() {
        let mut synth = default_synthesizer();
        let rec = Recommendation {
            rank: 1,
            policy_id: PolicyId("alt1".to_string()),
            expected_improvement_millionths: 200_000,
            confidence_millionths: 950_000,
            safety_status: EnvelopeStatus::Unsafe,
            rationale: "test".to_string(),
        };
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn synthesize_from_bifurcation_instability() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths: 200_000,
            },
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let scan = make_scan_result(600_000, Vec::new(), Vec::new()); // risk = 400_000
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        assert_eq!(result.bundles[0].kind, BundleKind::SafeMode);
    }

    #[test]
    fn synthesize_from_bifurcation_with_preemptive_actions() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths: 200_000,
            },
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let actions = vec![make_preemptive_action("pa1", 400_000)];
        let scan = make_scan_result(500_000, Vec::new(), actions); // risk = 500_000
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        assert_eq!(result.bundles[0].deltas.len(), 1);
        assert_eq!(result.bundles[0].deltas[0].delta_id, "d-r1-pa1");
    }

    #[test]
    fn synthesize_bifurcation_stable_skips() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths: 200_000,
            },
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let scan = make_scan_result(900_000, Vec::new(), Vec::new()); // risk = 100_000, below 200_000
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn synthesize_from_early_warnings() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::EarlyWarningActive {
                min_active_count: 2,
            },
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let warnings = vec![
            make_warning("w1", 800_000, true),
            make_warning("w2", 700_000, true),
            make_warning("w3", 300_000, false),
        ];
        let scan = make_scan_result(700_000, warnings, Vec::new());
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        assert_eq!(
            result.bundles[0].deltas[0].expected_improvement_millionths,
            800_000
        );
    }

    #[test]
    fn synthesize_early_warnings_insufficient() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::EarlyWarningActive {
                min_active_count: 3,
            },
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let warnings = vec![
            make_warning("w1", 800_000, true),
            make_warning("w2", 700_000, true), // Only 2 active
        ];
        let scan = make_scan_result(700_000, warnings, Vec::new());
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn synthesize_from_preemptive_actions() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let actions = vec![
            make_preemptive_action("pa1", 300_000),
            make_preemptive_action("pa2", 500_000),
        ];
        let scan = make_scan_result(700_000, Vec::new(), actions);
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        assert_eq!(result.bundles[0].deltas.len(), 2);
    }

    #[test]
    fn synthesize_preemptive_none_skips() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let scan = make_scan_result(900_000, Vec::new(), Vec::new());
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn synthesize_from_combined_evidence() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
            BundleKind::Adaptive,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let scan = make_scan_result(600_000, Vec::new(), Vec::new()); // risk = 400_000
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
    }

    #[test]
    fn combined_needs_both_thresholds() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
            BundleKind::Adaptive,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        // Replay good but bifurcation stable
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let scan = make_scan_result(900_000, Vec::new(), Vec::new()); // risk = 100_000, below 200_000
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    // ── Bundle Properties ───────────────────────────────────────────

    #[test]
    fn bundle_approved_with_hard_constraint_passing() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let constraints = vec![make_constraint("c1", ConstraintCategory::Performance, true)];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 980_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.bundles[0].is_approved());
        assert!(result.bundles[0].all_hard_constraints_passed);
    }

    #[test]
    fn bundle_rejected_when_hard_constraint_fails() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let mut constraint = make_constraint("c1", ConstraintCategory::Safety, true);
        constraint.max_regression_millionths = 0; // No regression at all
        let constraints = vec![constraint];

        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        // Use low confidence to trigger regression estimate.
        let rec = make_recommendation("alt1", 500_000, 500_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.bundles[0].is_approved());
        assert_eq!(result.rejected_count, 1);
    }

    #[test]
    fn bundle_has_verification_hooks() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.bundles[0].verification_hooks.is_empty());
        assert!(
            result.bundles[0]
                .verification_hooks
                .iter()
                .any(|h| h.verification_kind == VerificationKind::ImprovementReplay)
        );
        assert!(
            result.bundles[0]
                .verification_hooks
                .iter()
                .any(|h| h.verification_kind == VerificationKind::NonRegressionReplay)
        );
    }

    #[test]
    fn safemode_bundle_has_safemode_hook() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let actions = vec![make_preemptive_action("pa1", 300_000)];
        let scan = make_scan_result(700_000, Vec::new(), actions);
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(
            result.bundles[0]
                .verification_hooks
                .iter()
                .any(|h| h.verification_kind == VerificationKind::SafeModeReplay)
        );
    }

    #[test]
    fn no_hooks_when_disabled() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let config = SynthesizerConfig {
            generate_verification_hooks: false,
            ..Default::default()
        };
        let mut synth = RollbackSafemodeSynthesizer::new(config, rules, Vec::new()).unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.bundles[0].verification_hooks.is_empty());
    }

    #[test]
    fn bundle_has_evidence_refs() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].evidence_refs.len(), 1);
        assert_eq!(
            result.bundles[0].evidence_refs[0].source,
            EvidenceSource::CounterfactualReplay
        );
    }

    #[test]
    fn bundle_both_evidence_sources() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
            BundleKind::Adaptive,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let scan = make_scan_result(600_000, Vec::new(), Vec::new());
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].evidence_refs.len(), 2);
    }

    // ── Adaptive Bundle Kind Resolution ─────────────────────────────

    #[test]
    fn adaptive_resolves_to_safemode_with_critical_warnings() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
            BundleKind::Adaptive,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let warnings = vec![make_warning("w1", 900_000, true)]; // critical (risk > threshold)
        let scan = make_scan_result(600_000, warnings, Vec::new());
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].kind, BundleKind::SafeMode);
    }

    #[test]
    fn adaptive_resolves_to_rollback_without_critical() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
            BundleKind::Adaptive,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        // No warnings, no preemptive actions, but risk still above threshold
        let scan = make_scan_result(600_000, Vec::new(), Vec::new());
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].kind, BundleKind::Rollback);
    }

    // ── Multiple Rules ──────────────────────────────────────────────

    #[test]
    fn multiple_rules_produce_multiple_bundles() {
        let rules = vec![
            make_rule(
                "r1",
                EvidenceTrigger::CounterfactualImprovement {
                    min_improvement_millionths: 100_000,
                },
                BundleKind::Rollback,
            ),
            make_rule(
                "r2",
                EvidenceTrigger::PreemptiveActionRecommended,
                BundleKind::SafeMode,
            ),
        ];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let actions = vec![make_preemptive_action("pa1", 300_000)];
        let scan = make_scan_result(700_000, Vec::new(), actions);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles.len(), 2);
        assert_eq!(result.rules_fired.len(), 2);
    }

    #[test]
    fn disabled_rules_skipped() {
        let mut rule = make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        );
        rule.enabled = false;
        let rules = vec![rule];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
        assert_eq!(result.rules_skipped, vec!["r1"]);
    }

    #[test]
    fn rules_fire_by_priority_order() {
        let mut r1 = make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        );
        r1.priority = 5;
        let mut r2 = make_rule(
            "r2",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::SafeMode,
        );
        r2.priority = 1;
        let rules = vec![r1, r2]; // r1 first in vec but r2 has higher priority
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        // r2 fires first (priority 1 < 5)
        assert_eq!(result.rules_fired, vec!["r2", "r1"]);
    }

    // ── Deltas Sorting ──────────────────────────────────────────────

    #[test]
    fn deltas_sorted_by_improvement() {
        let mut synth = default_synthesizer();
        let recs = vec![
            make_recommendation("alt1", 150_000, 950_000),
            make_recommendation("alt2", 300_000, 950_000),
            make_recommendation("alt3", 200_000, 950_000),
        ];
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(recs)),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let improvements: Vec<i64> = result.bundles[0]
            .deltas
            .iter()
            .map(|d| d.expected_improvement_millionths)
            .collect();
        assert_eq!(improvements, vec![300_000, 200_000, 150_000]);
    }

    // ── Bundles Sorted by Improvement ───────────────────────────────

    #[test]
    fn bundles_sorted_by_total_improvement() {
        let rules = vec![
            make_rule(
                "r1",
                EvidenceTrigger::CounterfactualImprovement {
                    min_improvement_millionths: 100_000,
                },
                BundleKind::Rollback,
            ),
            make_rule(
                "r2",
                EvidenceTrigger::PreemptiveActionRecommended,
                BundleKind::SafeMode,
            ),
        ];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let actions = vec![make_preemptive_action("pa1", 600_000)]; // Higher improvement
        let scan = make_scan_result(700_000, Vec::new(), actions);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(
            result.bundles[0].total_improvement_millionths
                >= result.bundles[1].total_improvement_millionths
        );
    }

    // ── SynthesisResult Methods ─────────────────────────────────────

    #[test]
    fn best_approved_returns_first_approved() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let best = result.best_approved().unwrap();
        assert!(best.is_approved());
    }

    #[test]
    fn approved_bundles_filters_correctly() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let approved = result.approved_bundles();
        assert_eq!(approved.len(), result.approved_count as usize);
    }

    // ── Display / Serde ─────────────────────────────────────────────

    #[test]
    fn display_implementations() {
        let rule = make_rule(
            "test-rule",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        );
        let display = format!("{}", rule);
        assert!(display.contains("test-rule"));

        let kind = BundleKind::SafeMode;
        assert_eq!(format!("{}", kind), "safe-mode");

        let category = ConstraintCategory::Safety;
        assert_eq!(format!("{}", category), "safety");

        let source = EvidenceSource::CounterfactualReplay;
        assert_eq!(format!("{}", source), "counterfactual-replay");

        let vk = VerificationKind::ImprovementReplay;
        assert_eq!(format!("{}", vk), "improvement-replay");
    }

    #[test]
    fn evidence_trigger_display() {
        assert!(
            format!(
                "{}",
                EvidenceTrigger::CounterfactualImprovement {
                    min_improvement_millionths: 100_000,
                }
            )
            .contains("cf-improvement")
        );
        assert!(
            format!(
                "{}",
                EvidenceTrigger::BifurcationInstability {
                    min_risk_millionths: 200_000,
                }
            )
            .contains("bifurcation-instability")
        );
        assert!(
            format!(
                "{}",
                EvidenceTrigger::EarlyWarningActive {
                    min_active_count: 3,
                }
            )
            .contains("early-warning")
        );
        assert_eq!(
            format!("{}", EvidenceTrigger::PreemptiveActionRecommended),
            "preemptive-action"
        );
        assert!(
            format!(
                "{}",
                EvidenceTrigger::CombinedEvidence {
                    min_replay_improvement_millionths: 100_000,
                    min_bifurcation_risk_millionths: 200_000,
                }
            )
            .contains("combined")
        );
    }

    #[test]
    fn constraint_category_display_all() {
        assert_eq!(format!("{}", ConstraintCategory::Safety), "safety");
        assert_eq!(
            format!("{}", ConstraintCategory::Performance),
            "performance"
        );
        assert_eq!(
            format!("{}", ConstraintCategory::Correctness),
            "correctness"
        );
        assert_eq!(format!("{}", ConstraintCategory::Stability), "stability");
        assert_eq!(
            format!("{}", ConstraintCategory::Compatibility),
            "compatibility"
        );
    }

    #[test]
    fn bundle_kind_display_all() {
        assert_eq!(format!("{}", BundleKind::Rollback), "rollback");
        assert_eq!(format!("{}", BundleKind::SafeMode), "safe-mode");
        assert_eq!(format!("{}", BundleKind::Adaptive), "adaptive");
    }

    #[test]
    fn verification_kind_display_all() {
        assert_eq!(
            format!("{}", VerificationKind::ImprovementReplay),
            "improvement-replay"
        );
        assert_eq!(
            format!("{}", VerificationKind::NonRegressionReplay),
            "non-regression-replay"
        );
        assert_eq!(
            format!("{}", VerificationKind::StabilityReplay),
            "stability-replay"
        );
        assert_eq!(
            format!("{}", VerificationKind::SafeModeReplay),
            "safe-mode-replay"
        );
    }

    #[test]
    fn evidence_source_display_all() {
        assert_eq!(
            format!("{}", EvidenceSource::CounterfactualReplay),
            "counterfactual-replay"
        );
        assert_eq!(
            format!("{}", EvidenceSource::BifurcationScan),
            "bifurcation-scan"
        );
        assert_eq!(format!("{}", EvidenceSource::Combined), "combined");
    }

    #[test]
    fn synthesizer_error_display() {
        assert_eq!(
            format!("{}", SynthesizerError::NoRules),
            "no synthesis rules configured"
        );
        assert!(
            format!(
                "{}",
                SynthesizerError::TooManyRules {
                    count: 300,
                    max: 256
                }
            )
            .contains("300")
        );
        assert!(
            format!(
                "{}",
                SynthesizerError::DuplicateRule {
                    rule_id: "x".to_string()
                }
            )
            .contains("x")
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err = SynthesizerError::NoRules;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn serde_roundtrip_synthesis_rule() {
        let rule = make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        );
        let json = serde_json::to_string(&rule).unwrap();
        let back: SynthesisRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn serde_roundtrip_constraint() {
        let c = make_constraint("c1", ConstraintCategory::Safety, true);
        let json = serde_json::to_string(&c).unwrap();
        let back: NonRegressionConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn serde_roundtrip_policy_delta() {
        let delta = PolicyDelta {
            delta_id: "d1".to_string(),
            source_rule_id: "r1".to_string(),
            action: LaneAction::FallbackSafe,
            effective_epoch: SecurityEpoch::from_raw(1),
            expected_improvement_millionths: 200_000,
            confidence_millionths: 950_000,
            rationale: "test".to_string(),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: PolicyDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, back);
    }

    #[test]
    fn serde_roundtrip_synthesized_bundle() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let bundle = &result.bundles[0];
        let json = serde_json::to_string(bundle).unwrap();
        let back: SynthesizedBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(*bundle, back);
    }

    #[test]
    fn serde_roundtrip_synthesis_result() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: SynthesisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // ── Artifact Hash Determinism ───────────────────────────────────

    #[test]
    fn artifact_hash_deterministic() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };

        let mut s1 = RollbackSafemodeSynthesizer::new(
            SynthesizerConfig::default(),
            rules.clone(),
            Vec::new(),
        )
        .unwrap();
        let r1 = s1.synthesize(&input).unwrap();

        let mut s2 =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();
        let r2 = s2.synthesize(&input).unwrap();

        assert_eq!(r1.artifact_hash, r2.artifact_hash);
        assert_eq!(r1.bundles[0].artifact_hash, r2.bundles[0].artifact_hash);
    }

    // ── SynthesisInput Tests ────────────────────────────────────────

    #[test]
    fn synthesis_input_has_evidence() {
        let input = SynthesisInput {
            replay_result: None,
            scan_result: None,
        };
        assert!(!input.has_evidence());

        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input2 = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        assert!(input2.has_evidence());
    }

    // ── SynthesizedBundle Methods ───────────────────────────────────

    #[test]
    fn bundle_delta_count() {
        let mut synth = default_synthesizer();
        let recs = vec![
            make_recommendation("alt1", 200_000, 950_000),
            make_recommendation("alt2", 300_000, 950_000),
        ];
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(recs)),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].delta_count(), 2);
    }

    #[test]
    fn bundle_violation_count() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let mut constraint = make_constraint("c1", ConstraintCategory::Safety, true);
        constraint.max_regression_millionths = 0;
        let constraints = vec![constraint];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        let rec = make_recommendation("alt1", 500_000, 500_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.bundles[0].violation_count() > 0);
    }

    // ── Constraint Regression Estimation ────────────────────────────

    #[test]
    fn safety_constraint_more_conservative() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let constraints = vec![
            make_constraint("safety", ConstraintCategory::Safety, true),
            make_constraint("perf", ConstraintCategory::Performance, true),
        ];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        let rec = make_recommendation("alt1", 200_000, 800_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let bundle = &result.bundles[0];
        let safety_check = bundle
            .constraint_checks
            .iter()
            .find(|c| c.constraint_id == "safety")
            .unwrap();
        let perf_check = bundle
            .constraint_checks
            .iter()
            .find(|c| c.constraint_id == "perf")
            .unwrap();
        // Safety regression should be <= performance regression due to higher category factor
        assert!(safety_check.regression_millionths <= perf_check.regression_millionths);
    }

    // ── Display for SynthesisResult ─────────────────────────────────

    #[test]
    fn synthesis_result_display() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let display = format!("{}", result);
        assert!(display.contains("synthesis"));
        assert!(display.contains("approved=1"));
    }

    #[test]
    fn synthesized_bundle_display() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let display = format!("{}", result.bundles[0]);
        assert!(display.contains("bundle"));
        assert!(display.contains("approved"));
    }

    #[test]
    fn policy_delta_display() {
        let delta = PolicyDelta {
            delta_id: "d1".to_string(),
            source_rule_id: "r1".to_string(),
            action: LaneAction::FallbackSafe,
            effective_epoch: SecurityEpoch::from_raw(1),
            expected_improvement_millionths: 200_000,
            confidence_millionths: 950_000,
            rationale: "test".to_string(),
        };
        let display = format!("{}", delta);
        assert!(display.contains("d1"));
        assert!(display.contains("200000"));
    }

    #[test]
    fn constraint_display() {
        let c = make_constraint("c1", ConstraintCategory::Safety, true);
        let display = format!("{}", c);
        assert!(display.contains("c1"));
        assert!(display.contains("safety"));
        assert!(display.contains("hard"));
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn zero_confidence_recommendation_skipped() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 0);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(!result.has_bundles());
    }

    #[test]
    fn multiple_recommendations_filtered() {
        let mut synth = default_synthesizer();
        let recs = vec![
            make_recommendation("alt1", 50_000, 950_000), // Too low improvement
            make_recommendation("alt2", 200_000, 100_000), // Too low confidence
            make_recommendation("alt3", 200_000, 950_000), // Good
        ];
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(recs)),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.bundles[0].deltas.len(), 1);
        assert!(result.bundles[0].deltas[0].delta_id.contains("alt3"));
    }

    #[test]
    fn stability_hook_added_for_multi_delta() {
        let mut synth = default_synthesizer();
        let recs = vec![
            make_recommendation("alt1", 200_000, 950_000),
            make_recommendation("alt2", 300_000, 950_000),
        ];
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(recs)),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(
            result.bundles[0]
                .verification_hooks
                .iter()
                .any(|h| h.verification_kind == VerificationKind::StabilityReplay)
        );
    }

    #[test]
    fn no_stability_hook_for_single_delta() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(
            !result.bundles[0]
                .verification_hooks
                .iter()
                .any(|h| h.verification_kind == VerificationKind::StabilityReplay)
        );
    }

    #[test]
    fn config_accessor() {
        let synth = default_synthesizer();
        assert_eq!(synth.config().epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn synthesizer_config_default() {
        let config = SynthesizerConfig::default();
        assert_eq!(
            config.min_confidence_millionths,
            DEFAULT_MIN_CONFIDENCE_MILLIONTHS
        );
        assert_eq!(
            config.max_regression_millionths,
            DEFAULT_MAX_REGRESSION_MILLIONTHS
        );
        assert_eq!(
            config.improvement_threshold_millionths,
            DEFAULT_IMPROVEMENT_THRESHOLD_MILLIONTHS
        );
        assert!(config.generate_verification_hooks);
    }

    #[test]
    fn scan_only_evidence_works() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        )];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, Vec::new())
                .unwrap();

        let actions = vec![make_preemptive_action("pa1", 300_000)];
        let scan = make_scan_result(700_000, Vec::new(), actions);
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.has_bundles());
        // Evidence refs should only have bifurcation scan
        assert_eq!(result.bundles[0].evidence_refs.len(), 1);
        assert_eq!(
            result.bundles[0].evidence_refs[0].source,
            EvidenceSource::BifurcationScan
        );
    }

    // ── Enrichment batch ──────────────────────────────────────────────

    #[test]
    fn synthesizer_config_serde_roundtrip() {
        let config = SynthesizerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: SynthesizerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn synthesis_input_has_evidence_scan_only() {
        let scan = make_scan_result(900_000, Vec::new(), Vec::new());
        let input = SynthesisInput {
            replay_result: None,
            scan_result: Some(scan),
        };
        assert!(input.has_evidence());
    }

    #[test]
    fn synthesis_input_serde_roundtrip() {
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: SynthesisInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn synthesizer_error_serde_roundtrip_all_variants() {
        let errors = vec![
            SynthesizerError::NoRules,
            SynthesizerError::TooManyRules {
                count: 300,
                max: 256,
            },
            SynthesizerError::NoEvidence,
            SynthesizerError::TooManyDeltas {
                count: 200,
                max: 128,
            },
            SynthesizerError::TooManyConstraints {
                count: 200,
                max: 128,
            },
            SynthesizerError::DuplicateRule {
                rule_id: "x".to_string(),
            },
            SynthesizerError::DuplicateConstraint {
                constraint_id: "y".to_string(),
            },
            SynthesizerError::InvalidConfig {
                detail: "bad".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: SynthesizerError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn synthesizer_error_display_all_variants() {
        assert!(format!("{}", SynthesizerError::NoEvidence).contains("no evidence"));
        assert!(
            format!(
                "{}",
                SynthesizerError::TooManyDeltas {
                    count: 200,
                    max: 128
                }
            )
            .contains("200")
        );
        assert!(
            format!(
                "{}",
                SynthesizerError::TooManyConstraints {
                    count: 200,
                    max: 128
                }
            )
            .contains("200")
        );
        assert!(
            format!(
                "{}",
                SynthesizerError::DuplicateConstraint {
                    constraint_id: "y".to_string()
                }
            )
            .contains("y")
        );
        assert!(
            format!(
                "{}",
                SynthesizerError::InvalidConfig {
                    detail: "oops".to_string()
                }
            )
            .contains("oops")
        );
    }

    #[test]
    fn evidence_ref_serde_roundtrip() {
        let eref = EvidenceRef {
            source: EvidenceSource::CounterfactualReplay,
            artifact_hash: ContentHash::compute(b"test"),
            summary: "10 traces".to_string(),
        };
        let json = serde_json::to_string(&eref).unwrap();
        let back: EvidenceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(eref, back);
    }

    #[test]
    fn replay_verification_hook_serde_roundtrip() {
        let hook = ReplayVerificationHook {
            hook_id: "h1".to_string(),
            description: "verify improvement".to_string(),
            verification_kind: VerificationKind::ImprovementReplay,
            expected_outcome_millionths: 200_000,
            tolerance_millionths: 20_000,
        };
        let json = serde_json::to_string(&hook).unwrap();
        let back: ReplayVerificationHook = serde_json::from_str(&json).unwrap();
        assert_eq!(hook, back);
    }

    #[test]
    fn constraint_check_result_serde_roundtrip() {
        let check = ConstraintCheckResult {
            constraint_id: "c1".to_string(),
            passed: true,
            regression_millionths: 10_000,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: ConstraintCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    #[test]
    fn bundle_kind_serde_roundtrip() {
        for kind in [
            BundleKind::Rollback,
            BundleKind::SafeMode,
            BundleKind::Adaptive,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: BundleKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn constraint_category_serde_roundtrip() {
        for cat in [
            ConstraintCategory::Safety,
            ConstraintCategory::Performance,
            ConstraintCategory::Correctness,
            ConstraintCategory::Stability,
            ConstraintCategory::Compatibility,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: ConstraintCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn evidence_source_serde_roundtrip() {
        for src in [
            EvidenceSource::CounterfactualReplay,
            EvidenceSource::BifurcationScan,
            EvidenceSource::Combined,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: EvidenceSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, back);
        }
    }

    #[test]
    fn verification_kind_serde_roundtrip() {
        for vk in [
            VerificationKind::ImprovementReplay,
            VerificationKind::NonRegressionReplay,
            VerificationKind::StabilityReplay,
            VerificationKind::SafeModeReplay,
        ] {
            let json = serde_json::to_string(&vk).unwrap();
            let back: VerificationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(vk, back);
        }
    }

    #[test]
    fn soft_constraint_violation_does_not_block_bundle() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let mut constraint = make_constraint("c1", ConstraintCategory::Performance, false);
        constraint.max_regression_millionths = 0; // Will fail
        let constraints = vec![constraint];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        let rec = make_recommendation("alt1", 500_000, 500_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        // Soft constraint fails but bundle is still approved
        assert!(result.bundles[0].is_approved());
        assert!(result.bundles[0].soft_violations > 0);
    }

    #[test]
    fn synthesizer_serde_roundtrip() {
        let synth = default_synthesizer();
        let json = serde_json::to_string(&synth).unwrap();
        let back: RollbackSafemodeSynthesizer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_count(), synth.rule_count());
        assert_eq!(back.constraint_count(), synth.constraint_count());
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(
            SYNTHESIZER_SCHEMA_VERSION,
            "franken-engine.rollback-safemode-synthesizer.v1"
        );
    }

    #[test]
    fn best_approved_none_when_all_rejected() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let mut constraint = make_constraint("c1", ConstraintCategory::Safety, true);
        constraint.max_regression_millionths = 0;
        let constraints = vec![constraint];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        let rec = make_recommendation("alt1", 500_000, 500_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.best_approved().is_none());
    }

    #[test]
    fn best_approved_none_when_no_bundles() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 50_000, 950_000); // Below improvement threshold
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert!(result.best_approved().is_none());
    }

    #[test]
    fn bundle_schema_version_matches_constant() {
        let mut synth = default_synthesizer();
        let rec = make_recommendation("alt1", 200_000, 950_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        assert_eq!(result.schema_version, SYNTHESIZER_SCHEMA_VERSION);
        assert_eq!(result.bundles[0].schema_version, SYNTHESIZER_SCHEMA_VERSION);
    }

    #[test]
    fn high_confidence_yields_zero_regression() {
        let rules = vec![make_rule(
            "r1",
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            BundleKind::Rollback,
        )];
        let constraints = vec![make_constraint("c1", ConstraintCategory::Performance, true)];
        let mut synth =
            RollbackSafemodeSynthesizer::new(SynthesizerConfig::default(), rules, constraints)
                .unwrap();

        // Perfect confidence → uncertainty=0 → regression=0
        let rec = make_recommendation("alt1", 200_000, 1_000_000);
        let input = SynthesisInput {
            replay_result: Some(make_replay_result(vec![rec])),
            scan_result: None,
        };
        let result = synth.synthesize(&input).unwrap();
        let check = &result.bundles[0].constraint_checks[0];
        assert_eq!(check.regression_millionths, 0);
        assert!(check.passed);
    }

    // ── Enrichment: Display tests ────────────────────────────────────

    #[test]
    fn evidence_trigger_display_all_variants() {
        let variants = [
            (
                EvidenceTrigger::CounterfactualImprovement {
                    min_improvement_millionths: 100_000,
                },
                "cf-improvement(min=100000)",
            ),
            (
                EvidenceTrigger::BifurcationInstability {
                    min_risk_millionths: 200_000,
                },
                "bifurcation-instability(min=200000)",
            ),
            (
                EvidenceTrigger::EarlyWarningActive {
                    min_active_count: 3,
                },
                "early-warning(min=3)",
            ),
            (
                EvidenceTrigger::PreemptiveActionRecommended,
                "preemptive-action",
            ),
            (
                EvidenceTrigger::CombinedEvidence {
                    min_replay_improvement_millionths: 100_000,
                    min_bifurcation_risk_millionths: 200_000,
                },
                "combined(replay=100000, bifurcation=200000)",
            ),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (trigger, expected) in &variants {
            let s = trigger.to_string();
            assert_eq!(&s, expected, "Display mismatch for {:?}", trigger);
            assert!(seen.insert(s), "Duplicate Display for {:?}", trigger);
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn bundle_kind_display_all_variants() {
        assert_eq!(BundleKind::Rollback.to_string(), "rollback");
        assert_eq!(BundleKind::SafeMode.to_string(), "safe-mode");
        assert_eq!(BundleKind::Adaptive.to_string(), "adaptive");
        let mut seen = std::collections::BTreeSet::new();
        for kind in [
            BundleKind::Rollback,
            BundleKind::SafeMode,
            BundleKind::Adaptive,
        ] {
            assert!(seen.insert(kind.to_string()));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn constraint_category_display_all_variants() {
        let all = [
            (ConstraintCategory::Safety, "safety"),
            (ConstraintCategory::Performance, "performance"),
            (ConstraintCategory::Correctness, "correctness"),
            (ConstraintCategory::Stability, "stability"),
            (ConstraintCategory::Compatibility, "compatibility"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (cat, expected) in &all {
            assert_eq!(&cat.to_string(), expected);
            assert!(seen.insert(cat.to_string()));
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn verification_kind_display_all_variants() {
        let all = [
            (VerificationKind::ImprovementReplay, "improvement-replay"),
            (
                VerificationKind::NonRegressionReplay,
                "non-regression-replay",
            ),
            (VerificationKind::StabilityReplay, "stability-replay"),
            (VerificationKind::SafeModeReplay, "safe-mode-replay"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (kind, expected) in &all {
            assert_eq!(&kind.to_string(), expected);
            assert!(seen.insert(kind.to_string()));
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn evidence_source_display_all_variants() {
        let all = [
            (
                EvidenceSource::CounterfactualReplay,
                "counterfactual-replay",
            ),
            (EvidenceSource::BifurcationScan, "bifurcation-scan"),
            (EvidenceSource::Combined, "combined"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (src, expected) in &all {
            assert_eq!(&src.to_string(), expected);
            assert!(seen.insert(src.to_string()));
        }
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn synthesizer_error_display_exact_messages() {
        let all = [
            (SynthesizerError::NoRules, "no synthesis rules configured"),
            (
                SynthesizerError::TooManyRules {
                    count: 300,
                    max: 256,
                },
                "too many rules: 300 exceeds max 256",
            ),
            (
                SynthesizerError::NoEvidence,
                "no evidence provided for synthesis",
            ),
            (
                SynthesizerError::TooManyDeltas {
                    count: 200,
                    max: 128,
                },
                "too many deltas: 200 exceeds max 128",
            ),
            (
                SynthesizerError::TooManyConstraints {
                    count: 150,
                    max: 128,
                },
                "too many constraints: 150 exceeds max 128",
            ),
            (
                SynthesizerError::DuplicateRule {
                    rule_id: "r1".to_string(),
                },
                "duplicate rule ID: r1",
            ),
            (
                SynthesizerError::DuplicateConstraint {
                    constraint_id: "c1".to_string(),
                },
                "duplicate constraint ID: c1",
            ),
            (
                SynthesizerError::InvalidConfig {
                    detail: "bad value".to_string(),
                },
                "invalid config: bad value",
            ),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (err, expected) in &all {
            let s = err.to_string();
            assert_eq!(&s, expected);
            assert!(seen.insert(s));
        }
        assert_eq!(seen.len(), 8);
    }

    #[test]
    fn synthesis_rule_display() {
        let rule = make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        );
        let s = rule.to_string();
        assert!(s.contains("r1"));
        assert!(s.contains("SafeMode"));
        assert!(s.contains("pri=1"));
    }

    #[test]
    fn policy_delta_display_content() {
        let delta = PolicyDelta {
            delta_id: "d1".to_string(),
            source_rule_id: "r1".to_string(),
            action: LaneAction::RouteTo(LaneId("baseline".to_string())),
            effective_epoch: SecurityEpoch::from_raw(1),
            expected_improvement_millionths: 150_000,
            confidence_millionths: 900_000,
            rationale: "test".to_string(),
        };
        let s = delta.to_string();
        assert!(s.contains("d1"));
        assert!(s.contains("150000"));
    }

    #[test]
    fn non_regression_constraint_display_hard_vs_soft() {
        let hard = NonRegressionConstraint {
            constraint_id: "c1".to_string(),
            description: "test".to_string(),
            category: ConstraintCategory::Safety,
            max_regression_millionths: 50_000,
            hard: true,
        };
        let soft = NonRegressionConstraint {
            constraint_id: "c2".to_string(),
            description: "test".to_string(),
            category: ConstraintCategory::Performance,
            max_regression_millionths: 50_000,
            hard: false,
        };
        assert!(hard.to_string().contains("hard"));
        assert!(soft.to_string().contains("soft"));
        assert!(hard.to_string().contains("safety"));
        assert!(soft.to_string().contains("performance"));
    }

    #[test]
    fn synthesized_bundle_display_approved_and_rejected() {
        let bundle = SynthesizedBundle {
            bundle_id: "b1".to_string(),
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            kind: BundleKind::Rollback,
            synthesis_epoch: SecurityEpoch::from_raw(1),
            deltas: vec![PolicyDelta {
                delta_id: "d1".to_string(),
                source_rule_id: "r1".to_string(),
                action: LaneAction::RouteTo(LaneId("baseline".to_string())),
                effective_epoch: SecurityEpoch::from_raw(1),
                expected_improvement_millionths: 150_000,
                confidence_millionths: 900_000,
                rationale: "test".to_string(),
            }],
            constraint_checks: vec![],
            all_hard_constraints_passed: true,
            soft_violations: 0,
            total_improvement_millionths: 150_000,
            min_confidence_millionths: 900_000,
            verification_hooks: vec![],
            evidence_refs: vec![],
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert!(bundle.to_string().contains("approved"));
        assert!(bundle.to_string().contains("b1"));
        assert!(bundle.to_string().contains("rollback"));

        let rejected = SynthesizedBundle {
            all_hard_constraints_passed: false,
            ..bundle.clone()
        };
        assert!(rejected.to_string().contains("rejected"));
    }

    #[test]
    fn synthesis_result_display_content() {
        let result = SynthesisResult {
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            epoch: SecurityEpoch::from_raw(5),
            rules_fired: vec!["r1".to_string()],
            rules_skipped: vec![],
            bundles: vec![],
            approved_count: 1,
            rejected_count: 0,
            artifact_hash: ContentHash::compute(b"res"),
        };
        let s = result.to_string();
        assert!(s.contains("epoch="));
        assert!(s.contains("approved=1"));
        assert!(s.contains("rejected=0"));
    }

    // ── Enrichment: Serde roundtrip tests ────────────────────────────

    #[test]
    fn evidence_trigger_serde_roundtrip_all_variants() {
        let variants = [
            EvidenceTrigger::CounterfactualImprovement {
                min_improvement_millionths: 100_000,
            },
            EvidenceTrigger::BifurcationInstability {
                min_risk_millionths: 200_000,
            },
            EvidenceTrigger::EarlyWarningActive {
                min_active_count: 3,
            },
            EvidenceTrigger::PreemptiveActionRecommended,
            EvidenceTrigger::CombinedEvidence {
                min_replay_improvement_millionths: 100_000,
                min_bifurcation_risk_millionths: 200_000,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EvidenceTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn bundle_kind_serde_roundtrip_all_variants() {
        for kind in [
            BundleKind::Rollback,
            BundleKind::SafeMode,
            BundleKind::Adaptive,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: BundleKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn constraint_category_serde_roundtrip_all_variants() {
        let all = [
            ConstraintCategory::Safety,
            ConstraintCategory::Performance,
            ConstraintCategory::Correctness,
            ConstraintCategory::Stability,
            ConstraintCategory::Compatibility,
        ];
        for cat in &all {
            let json = serde_json::to_string(cat).unwrap();
            let back: ConstraintCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, cat);
        }
    }

    #[test]
    fn verification_kind_serde_roundtrip_all_variants() {
        let all = [
            VerificationKind::ImprovementReplay,
            VerificationKind::NonRegressionReplay,
            VerificationKind::StabilityReplay,
            VerificationKind::SafeModeReplay,
        ];
        for kind in &all {
            let json = serde_json::to_string(kind).unwrap();
            let back: VerificationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, kind);
        }
    }

    #[test]
    fn evidence_source_serde_roundtrip_all_variants() {
        for src in [
            EvidenceSource::CounterfactualReplay,
            EvidenceSource::BifurcationScan,
            EvidenceSource::Combined,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: EvidenceSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn synthesizer_error_serde_roundtrip_complete() {
        let all = [
            SynthesizerError::NoRules,
            SynthesizerError::TooManyRules {
                count: 300,
                max: 256,
            },
            SynthesizerError::NoEvidence,
            SynthesizerError::TooManyDeltas {
                count: 200,
                max: 128,
            },
            SynthesizerError::TooManyConstraints {
                count: 150,
                max: 128,
            },
            SynthesizerError::DuplicateRule {
                rule_id: "r1".to_string(),
            },
            SynthesizerError::DuplicateConstraint {
                constraint_id: "c1".to_string(),
            },
            SynthesizerError::InvalidConfig {
                detail: "bad".to_string(),
            },
        ];
        for err in &all {
            let json = serde_json::to_string(err).unwrap();
            let back: SynthesizerError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, err);
        }
    }

    #[test]
    fn synthesis_rule_serde_roundtrip() {
        let rule = make_rule(
            "r1",
            EvidenceTrigger::PreemptiveActionRecommended,
            BundleKind::SafeMode,
        );
        let json = serde_json::to_string(&rule).unwrap();
        let back: SynthesisRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn policy_delta_serde_roundtrip() {
        let delta = PolicyDelta {
            delta_id: "d1".to_string(),
            source_rule_id: "r1".to_string(),
            action: LaneAction::RouteTo(LaneId("baseline".to_string())),
            effective_epoch: SecurityEpoch::from_raw(1),
            expected_improvement_millionths: 150_000,
            confidence_millionths: 900_000,
            rationale: "test delta".to_string(),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: PolicyDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(back, delta);
    }

    #[test]
    fn non_regression_constraint_serde_roundtrip() {
        let c = NonRegressionConstraint {
            constraint_id: "c1".to_string(),
            description: "no perf regression".to_string(),
            category: ConstraintCategory::Performance,
            max_regression_millionths: 50_000,
            hard: true,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: NonRegressionConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn constraint_check_result_serde_improved() {
        let r = ConstraintCheckResult {
            constraint_id: "c1".to_string(),
            passed: true,
            regression_millionths: -5_000,
            detail: "improved".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ConstraintCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn replay_verification_hook_serde_with_tolerance() {
        let hook = ReplayVerificationHook {
            hook_id: "h1".to_string(),
            description: "verify improvement".to_string(),
            verification_kind: VerificationKind::ImprovementReplay,
            expected_outcome_millionths: 150_000,
            tolerance_millionths: 10_000,
        };
        let json = serde_json::to_string(&hook).unwrap();
        let back: ReplayVerificationHook = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hook);
    }

    #[test]
    fn evidence_ref_serde_with_summary() {
        let r = EvidenceRef {
            source: EvidenceSource::CounterfactualReplay,
            artifact_hash: ContentHash::compute(b"evidence"),
            summary: "replay showed improvement".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: EvidenceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn synthesizer_config_serde_default_roundtrip() {
        let cfg = SynthesizerConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: SynthesizerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn synthesis_input_serde_roundtrip_both_none() {
        let input = SynthesisInput {
            replay_result: None,
            scan_result: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: SynthesisInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back, input);
        assert!(!back.has_evidence());
    }

    // ── Enrichment: Edge case tests ─────────────────────────────────

    #[test]
    fn synthesized_bundle_is_approved_empty_deltas() {
        let bundle = SynthesizedBundle {
            bundle_id: "b1".to_string(),
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            kind: BundleKind::Rollback,
            synthesis_epoch: SecurityEpoch::from_raw(1),
            deltas: vec![],
            constraint_checks: vec![],
            all_hard_constraints_passed: true,
            soft_violations: 0,
            total_improvement_millionths: 0,
            min_confidence_millionths: 0,
            verification_hooks: vec![],
            evidence_refs: vec![],
            artifact_hash: ContentHash::compute(b"empty"),
        };
        assert!(!bundle.is_approved(), "empty deltas means not approved");
        assert_eq!(bundle.delta_count(), 0);
        assert_eq!(bundle.violation_count(), 0);
    }

    #[test]
    fn synthesis_result_no_bundles() {
        let result = SynthesisResult {
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            epoch: SecurityEpoch::from_raw(1),
            rules_fired: vec![],
            rules_skipped: vec!["r1".to_string()],
            bundles: vec![],
            approved_count: 0,
            rejected_count: 0,
            artifact_hash: ContentHash::compute(b"empty"),
        };
        assert!(!result.has_bundles());
        assert!(result.best_approved().is_none());
        assert!(result.approved_bundles().is_empty());
    }

    #[test]
    fn synthesized_bundle_violation_count_mixed() {
        let bundle = SynthesizedBundle {
            bundle_id: "b1".to_string(),
            schema_version: SYNTHESIZER_SCHEMA_VERSION.to_string(),
            kind: BundleKind::SafeMode,
            synthesis_epoch: SecurityEpoch::from_raw(1),
            deltas: vec![PolicyDelta {
                delta_id: "d1".to_string(),
                source_rule_id: "r1".to_string(),
                action: LaneAction::RouteTo(LaneId("safe".to_string())),
                effective_epoch: SecurityEpoch::from_raw(1),
                expected_improvement_millionths: 100_000,
                confidence_millionths: 950_000,
                rationale: "test".to_string(),
            }],
            constraint_checks: vec![
                ConstraintCheckResult {
                    constraint_id: "c1".to_string(),
                    passed: true,
                    regression_millionths: 0,
                    detail: "ok".to_string(),
                },
                ConstraintCheckResult {
                    constraint_id: "c2".to_string(),
                    passed: false,
                    regression_millionths: 60_000,
                    detail: "exceeded".to_string(),
                },
                ConstraintCheckResult {
                    constraint_id: "c3".to_string(),
                    passed: false,
                    regression_millionths: 30_000,
                    detail: "borderline".to_string(),
                },
            ],
            all_hard_constraints_passed: false,
            soft_violations: 2,
            total_improvement_millionths: 100_000,
            min_confidence_millionths: 950_000,
            verification_hooks: vec![],
            evidence_refs: vec![],
            artifact_hash: ContentHash::compute(b"mixed"),
        };
        assert_eq!(bundle.violation_count(), 2);
        assert!(!bundle.is_approved());
    }
}
