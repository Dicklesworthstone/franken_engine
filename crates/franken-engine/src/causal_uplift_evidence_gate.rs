//! Causal uplift evidence gate for regression, transfer, and supremacy claims.
//!
//! Implements [RGC-615C]: wires causal uplift certificates into the evidence
//! pipeline so public claims (regressions, transfer wins, supremacy verdicts)
//! only pass when causal evidence actually supports them.
//!
//! # Design
//!
//! - `UpliftClaim` declares a performance win with an associated causal effect.
//! - `CausalBacking` encapsulates the causal evidence supporting a claim.
//! - `GateVerdict` is the pass/fail result of evidence evaluation.
//! - `EvidenceGate` evaluates claims against configurable thresholds.
//!
//! A claim is only admitted if:
//! 1. Causal identification succeeded (not abstained).
//! 2. The estimated causal effect is positive and above the minimum threshold.
//! 3. The confidence interval does not span zero.
//! 4. The adjustment set is non-empty or an instrumental variable was used.
//! 5. The claim category matches the evidence surface.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-615C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.causal-uplift-evidence-gate.v1";

/// Component name.
pub const COMPONENT: &str = "causal_uplift_evidence_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.15.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-615C";

/// Minimum causal effect size to admit a claim (millionths).
/// An effect must be at least 1% to be non-trivial.
pub const MIN_EFFECT_THRESHOLD: u64 = 10_000;

/// Minimum identification confidence to trust a causal result (millionths).
/// 80% = 800_000.
pub const MIN_IDENTIFICATION_CONFIDENCE: u64 = 800_000;

/// Maximum allowed interval width relative to effect size (millionths).
/// If the CI width exceeds 2x the effect, the result is too uncertain.
pub const MAX_RELATIVE_CI_WIDTH: u64 = 2_000_000;

/// Default maximum claims per gate evaluation batch.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// ClaimCategory
// ---------------------------------------------------------------------------

/// Category of a performance or correctness claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCategory {
    /// Regression detection: a change caused performance degradation.
    Regression,
    /// Transfer claim: a win on one surface applies to another.
    Transfer,
    /// Supremacy claim: this engine dominates a competitor on a surface.
    Supremacy,
    /// Rollout claim: a change is safe to ship.
    Rollout,
    /// Optimization claim: a specific optimization pass produced a win.
    Optimization,
}

impl ClaimCategory {
    pub const ALL: &[Self] = &[
        Self::Regression,
        Self::Transfer,
        Self::Supremacy,
        Self::Rollout,
        Self::Optimization,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regression => "regression",
            Self::Transfer => "transfer",
            Self::Supremacy => "supremacy",
            Self::Rollout => "rollout",
            Self::Optimization => "optimization",
        }
    }
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// IdentificationMethod
// ---------------------------------------------------------------------------

/// How a causal effect was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationMethod {
    /// Backdoor criterion adjustment.
    Backdoor,
    /// Front-door criterion identification.
    FrontDoor,
    /// Instrumental variable approach.
    InstrumentalVariable,
    /// Randomized experiment (A/B test).
    Randomized,
    /// Difference-in-differences.
    DifferenceInDifferences,
    /// Expert assertion (weakest evidence).
    ExpertAssertion,
}

impl IdentificationMethod {
    pub const ALL: &[Self] = &[
        Self::Backdoor,
        Self::FrontDoor,
        Self::InstrumentalVariable,
        Self::Randomized,
        Self::DifferenceInDifferences,
        Self::ExpertAssertion,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Backdoor => "backdoor",
            Self::FrontDoor => "front_door",
            Self::InstrumentalVariable => "instrumental_variable",
            Self::Randomized => "randomized",
            Self::DifferenceInDifferences => "difference_in_differences",
            Self::ExpertAssertion => "expert_assertion",
        }
    }

    /// Evidence strength ranking (higher = stronger).
    pub const fn strength_rank(self) -> u32 {
        match self {
            Self::Randomized => 5,
            Self::InstrumentalVariable => 4,
            Self::FrontDoor => 3,
            Self::Backdoor => 3,
            Self::DifferenceInDifferences => 2,
            Self::ExpertAssertion => 1,
        }
    }
}

impl fmt::Display for IdentificationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

/// Why a claim was rejected by the evidence gate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Causal identification abstained (no valid method found).
    IdentificationAbstained,
    /// Estimated effect is below minimum threshold.
    EffectBelowThreshold {
        effect_millionths: u64,
        threshold_millionths: u64,
    },
    /// Confidence interval spans zero (effect direction uncertain).
    IntervalSpansZero {
        lower_millionths: i64,
        upper_millionths: i64,
    },
    /// Confidence interval too wide relative to effect.
    IntervalTooWide {
        width_millionths: u64,
        effect_millionths: u64,
    },
    /// Identification confidence below minimum.
    LowConfidence {
        confidence_millionths: u64,
        threshold_millionths: u64,
    },
    /// Claim category does not match evidence surface.
    CategoryMismatch {
        claim: ClaimCategory,
        evidence: ClaimCategory,
    },
    /// No adjustment set and no instrumental variable identified.
    NoAdjustmentPath,
    /// Evidence strength too weak for claim category.
    WeakEvidence {
        method: IdentificationMethod,
        min_strength: u32,
    },
}

impl RejectionReason {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::IdentificationAbstained => "identification_abstained",
            Self::EffectBelowThreshold { .. } => "effect_below_threshold",
            Self::IntervalSpansZero { .. } => "interval_spans_zero",
            Self::IntervalTooWide { .. } => "interval_too_wide",
            Self::LowConfidence { .. } => "low_confidence",
            Self::CategoryMismatch { .. } => "category_mismatch",
            Self::NoAdjustmentPath => "no_adjustment_path",
            Self::WeakEvidence { .. } => "weak_evidence",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentificationAbstained => write!(f, "causal identification abstained"),
            Self::EffectBelowThreshold {
                effect_millionths,
                threshold_millionths,
            } => write!(
                f,
                "effect {effect_millionths} below threshold {threshold_millionths}"
            ),
            Self::IntervalSpansZero {
                lower_millionths,
                upper_millionths,
            } => write!(
                f,
                "CI [{lower_millionths}, {upper_millionths}] spans zero"
            ),
            Self::IntervalTooWide {
                width_millionths,
                effect_millionths,
            } => write!(
                f,
                "CI width {width_millionths} too wide for effect {effect_millionths}"
            ),
            Self::LowConfidence {
                confidence_millionths,
                threshold_millionths,
            } => write!(
                f,
                "confidence {confidence_millionths} below threshold {threshold_millionths}"
            ),
            Self::CategoryMismatch { claim, evidence } => {
                write!(f, "category mismatch: claim={claim}, evidence={evidence}")
            }
            Self::NoAdjustmentPath => write!(f, "no adjustment set or instrument identified"),
            Self::WeakEvidence {
                method,
                min_strength,
            } => write!(
                f,
                "evidence method {method} too weak (need strength >= {min_strength})"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// CausalBacking
// ---------------------------------------------------------------------------

/// Causal evidence backing a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalBacking {
    /// Identification method used.
    pub method: IdentificationMethod,
    /// Estimated causal effect (millionths). Positive = beneficial.
    pub effect_millionths: i64,
    /// Lower bound of confidence interval (millionths).
    pub ci_lower_millionths: i64,
    /// Upper bound of confidence interval (millionths).
    pub ci_upper_millionths: i64,
    /// Identification confidence (millionths, 0–1_000_000).
    pub confidence_millionths: u64,
    /// Variables in the adjustment set.
    pub adjustment_variables: BTreeSet<String>,
    /// Evidence category this backing applies to.
    pub evidence_category: ClaimCategory,
    /// Whether identification succeeded (vs abstained).
    pub identified: bool,
    /// Content hash of the underlying causal certificate.
    pub certificate_hash: ContentHash,
}

impl CausalBacking {
    /// Confidence interval width.
    pub fn ci_width(&self) -> u64 {
        (self.ci_upper_millionths - self.ci_lower_millionths) as u64
    }

    /// Whether the CI spans zero.
    pub fn ci_spans_zero(&self) -> bool {
        self.ci_lower_millionths <= 0 && self.ci_upper_millionths >= 0
    }

    /// Whether the effect is positive.
    pub fn effect_is_positive(&self) -> bool {
        self.effect_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// UpliftClaim
// ---------------------------------------------------------------------------

/// A performance or correctness claim requiring causal evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpliftClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Claim category.
    pub category: ClaimCategory,
    /// Description of the claimed effect.
    pub description: String,
    /// Claimed improvement magnitude (millionths). E.g., 50_000 = 5%.
    pub claimed_effect_millionths: u64,
    /// Surface or scope of the claim (e.g., "latency-p99", "throughput").
    pub surface: String,
    /// Minimum evidence strength required for this claim.
    pub min_evidence_strength: u32,
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Result of evaluating a claim against causal evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Claim is admitted: causal evidence supports it.
    Admitted {
        claim_id: String,
        method: IdentificationMethod,
        effect_millionths: i64,
        confidence_millionths: u64,
    },
    /// Claim is rejected: insufficient or contradictory evidence.
    Rejected {
        claim_id: String,
        reasons: Vec<RejectionReason>,
    },
    /// Claim has no backing evidence at all.
    NoBacking { claim_id: String },
}

impl GateVerdict {
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub fn claim_id(&self) -> &str {
        match self {
            Self::Admitted { claim_id, .. }
            | Self::Rejected { claim_id, .. }
            | Self::NoBacking { claim_id } => claim_id,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Admitted { .. } => "admitted",
            Self::Rejected { .. } => "rejected",
            Self::NoBacking { .. } => "no_backing",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admitted {
                claim_id,
                method,
                effect_millionths,
                ..
            } => write!(
                f,
                "ADMITTED {claim_id}: effect={effect_millionths} via {method}"
            ),
            Self::Rejected {
                claim_id, reasons, ..
            } => write!(
                f,
                "REJECTED {claim_id}: {} reason(s)",
                reasons.len()
            ),
            Self::NoBacking { claim_id } => write!(f, "NO_BACKING {claim_id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the evidence gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum effect threshold (millionths).
    pub min_effect_threshold: u64,
    /// Minimum identification confidence (millionths).
    pub min_confidence: u64,
    /// Maximum relative CI width (millionths).
    pub max_relative_ci_width: u64,
    /// Require strict category matching.
    pub strict_category_match: bool,
    /// Minimum evidence strength per category.
    pub category_min_strength: BTreeMap<ClaimCategory, u32>,
}

impl GateConfig {
    /// Default configuration using module constants.
    pub fn default_config() -> Self {
        let mut category_min_strength = BTreeMap::new();
        category_min_strength.insert(ClaimCategory::Supremacy, 3);
        category_min_strength.insert(ClaimCategory::Regression, 2);
        category_min_strength.insert(ClaimCategory::Transfer, 3);
        category_min_strength.insert(ClaimCategory::Rollout, 2);
        category_min_strength.insert(ClaimCategory::Optimization, 1);

        Self {
            min_effect_threshold: MIN_EFFECT_THRESHOLD,
            min_confidence: MIN_IDENTIFICATION_CONFIDENCE,
            max_relative_ci_width: MAX_RELATIVE_CI_WIDTH,
            strict_category_match: true,
            category_min_strength,
        }
    }

    /// Permissive config for testing.
    pub fn permissive() -> Self {
        Self {
            min_effect_threshold: 0,
            min_confidence: 0,
            max_relative_ci_width: u64::MAX,
            strict_category_match: false,
            category_min_strength: BTreeMap::new(),
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// EvidenceGate
// ---------------------------------------------------------------------------

/// Evaluates uplift claims against causal evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGate {
    /// Configuration.
    pub config: GateConfig,
    /// Schema version.
    pub schema_version: String,
}

impl EvidenceGate {
    /// Create a gate with default config.
    pub fn with_defaults() -> Self {
        Self {
            config: GateConfig::default(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Create a gate with custom config.
    pub fn with_config(config: GateConfig) -> Self {
        Self {
            config,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Evaluate a single claim against its causal backing.
    pub fn evaluate(&self, claim: &UpliftClaim, backing: Option<&CausalBacking>) -> GateVerdict {
        let Some(backing) = backing else {
            return GateVerdict::NoBacking {
                claim_id: claim.claim_id.clone(),
            };
        };

        let mut reasons = Vec::new();

        // 1. Identification must have succeeded.
        if !backing.identified {
            reasons.push(RejectionReason::IdentificationAbstained);
        }

        // 2. Effect must be positive and above threshold.
        if backing.effect_millionths <= 0 || (backing.effect_millionths as u64) < self.config.min_effect_threshold {
            reasons.push(RejectionReason::EffectBelowThreshold {
                effect_millionths: backing.effect_millionths.unsigned_abs(),
                threshold_millionths: self.config.min_effect_threshold,
            });
        }

        // 3. CI must not span zero.
        if backing.ci_spans_zero() {
            reasons.push(RejectionReason::IntervalSpansZero {
                lower_millionths: backing.ci_lower_millionths,
                upper_millionths: backing.ci_upper_millionths,
            });
        }

        // 4. CI width must be reasonable relative to effect.
        if backing.effect_millionths > 0 {
            let width = backing.ci_width();
            let effect_abs = backing.effect_millionths as u64;
            let relative_width = width
                .saturating_mul(1_000_000)
                .checked_div(effect_abs)
                .unwrap_or(u64::MAX);
            if relative_width > self.config.max_relative_ci_width {
                reasons.push(RejectionReason::IntervalTooWide {
                    width_millionths: width,
                    effect_millionths: effect_abs,
                });
            }
        }

        // 5. Confidence must be above threshold.
        if backing.confidence_millionths < self.config.min_confidence {
            reasons.push(RejectionReason::LowConfidence {
                confidence_millionths: backing.confidence_millionths,
                threshold_millionths: self.config.min_confidence,
            });
        }

        // 6. Category match (if strict mode).
        if self.config.strict_category_match && backing.evidence_category != claim.category {
            reasons.push(RejectionReason::CategoryMismatch {
                claim: claim.category,
                evidence: backing.evidence_category,
            });
        }

        // 7. Adjustment set or instrument.
        if backing.adjustment_variables.is_empty()
            && backing.method != IdentificationMethod::InstrumentalVariable
            && backing.method != IdentificationMethod::Randomized
        {
            reasons.push(RejectionReason::NoAdjustmentPath);
        }

        // 8. Evidence strength.
        let min_strength = self
            .config
            .category_min_strength
            .get(&claim.category)
            .copied()
            .unwrap_or(claim.min_evidence_strength);
        if backing.method.strength_rank() < min_strength {
            reasons.push(RejectionReason::WeakEvidence {
                method: backing.method,
                min_strength,
            });
        }

        if reasons.is_empty() {
            GateVerdict::Admitted {
                claim_id: claim.claim_id.clone(),
                method: backing.method,
                effect_millionths: backing.effect_millionths,
                confidence_millionths: backing.confidence_millionths,
            }
        } else {
            GateVerdict::Rejected {
                claim_id: claim.claim_id.clone(),
                reasons,
            }
        }
    }

    /// Evaluate a batch of claims. Returns verdicts in claim order.
    pub fn evaluate_batch(
        &self,
        claims: &[UpliftClaim],
        backings: &BTreeMap<String, CausalBacking>,
    ) -> Vec<GateVerdict> {
        claims
            .iter()
            .map(|c| self.evaluate(c, backings.get(&c.claim_id)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

/// Report from a gate evaluation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// All verdicts.
    pub verdicts: Vec<GateVerdict>,
    /// Admitted count.
    pub admitted_count: usize,
    /// Rejected count.
    pub rejected_count: usize,
    /// No-backing count.
    pub no_backing_count: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GateReport {
    /// Create a report from verdicts.
    pub fn new(epoch: SecurityEpoch, verdicts: Vec<GateVerdict>) -> Self {
        let admitted_count = verdicts.iter().filter(|v| v.is_admitted()).count();
        let rejected_count = verdicts.iter().filter(|v| v.is_rejected()).count();
        let no_backing_count = verdicts
            .iter()
            .filter(|v| matches!(v, GateVerdict::NoBacking { .. }))
            .count();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update((verdicts.len() as u64).to_le_bytes());
        h.update((admitted_count as u64).to_le_bytes());
        h.update((rejected_count as u64).to_le_bytes());
        for v in &verdicts {
            h.update(v.claim_id().as_bytes());
            h.update(v.tag().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            verdicts,
            admitted_count,
            rejected_count,
            no_backing_count,
            content_hash,
        }
    }

    /// Total claims evaluated.
    pub fn total_count(&self) -> usize {
        self.verdicts.len()
    }

    /// Admission rate (millionths).
    pub fn admission_rate(&self) -> u64 {
        (self.admitted_count as u64)
            .saturating_mul(1_000_000)
            .checked_div(self.verdicts.len() as u64)
            .unwrap_or(0)
    }

    /// Whether all claims were admitted.
    pub fn all_admitted(&self) -> bool {
        !self.verdicts.is_empty() && self.admitted_count == self.verdicts.len()
    }

    /// Whether any claim was rejected.
    pub fn has_rejections(&self) -> bool {
        self.rejected_count > 0
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(800)
    }

    fn good_backing(category: ClaimCategory) -> CausalBacking {
        CausalBacking {
            method: IdentificationMethod::Backdoor,
            effect_millionths: 50_000,
            ci_lower_millionths: 20_000,
            ci_upper_millionths: 80_000,
            confidence_millionths: 900_000,
            adjustment_variables: BTreeSet::from(["workload_type".to_string()]),
            evidence_category: category,
            identified: true,
            certificate_hash: ContentHash::compute(b"test-cert"),
        }
    }

    fn strong_backing(category: ClaimCategory) -> CausalBacking {
        CausalBacking {
            method: IdentificationMethod::Randomized,
            effect_millionths: 100_000,
            ci_lower_millionths: 60_000,
            ci_upper_millionths: 140_000,
            confidence_millionths: 950_000,
            adjustment_variables: BTreeSet::new(),
            evidence_category: category,
            identified: true,
            certificate_hash: ContentHash::compute(b"strong-cert"),
        }
    }

    fn regression_claim() -> UpliftClaim {
        UpliftClaim {
            claim_id: "reg-1".into(),
            category: ClaimCategory::Regression,
            description: "10% latency regression".into(),
            claimed_effect_millionths: 100_000,
            surface: "latency-p99".into(),
            min_evidence_strength: 2,
        }
    }

    fn supremacy_claim() -> UpliftClaim {
        UpliftClaim {
            claim_id: "sup-1".into(),
            category: ClaimCategory::Supremacy,
            description: "Dominates competitor on throughput".into(),
            claimed_effect_millionths: 200_000,
            surface: "throughput".into(),
            min_evidence_strength: 3,
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "causal_uplift_evidence_gate");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn threshold_invariants() {
        assert!(MIN_EFFECT_THRESHOLD > 0);
        assert!(MIN_IDENTIFICATION_CONFIDENCE > 0);
        assert!(MAX_RELATIVE_CI_WIDTH > 0);
        assert!(DEFAULT_MAX_BATCH_SIZE > 0);
    }

    // --- ClaimCategory ---

    #[test]
    fn category_all_length() {
        assert_eq!(ClaimCategory::ALL.len(), 5);
    }

    #[test]
    fn category_names_unique() {
        let names: BTreeSet<&str> = ClaimCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ClaimCategory::ALL.len());
    }

    #[test]
    fn category_display_matches_as_str() {
        for c in ClaimCategory::ALL {
            assert_eq!(c.to_string(), c.as_str());
        }
    }

    #[test]
    fn category_serde_all() {
        for c in ClaimCategory::ALL {
            let json = serde_json::to_string(c).unwrap();
            let back: ClaimCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- IdentificationMethod ---

    #[test]
    fn method_all_length() {
        assert_eq!(IdentificationMethod::ALL.len(), 6);
    }

    #[test]
    fn method_names_unique() {
        let names: BTreeSet<&str> = IdentificationMethod::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(names.len(), IdentificationMethod::ALL.len());
    }

    #[test]
    fn method_display_matches_as_str() {
        for m in IdentificationMethod::ALL {
            assert_eq!(m.to_string(), m.as_str());
        }
    }

    #[test]
    fn method_serde_all() {
        for m in IdentificationMethod::ALL {
            let json = serde_json::to_string(m).unwrap();
            let back: IdentificationMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, back);
        }
    }

    #[test]
    fn method_strength_ordering() {
        assert!(IdentificationMethod::Randomized.strength_rank()
            > IdentificationMethod::ExpertAssertion.strength_rank());
        assert!(IdentificationMethod::InstrumentalVariable.strength_rank()
            > IdentificationMethod::DifferenceInDifferences.strength_rank());
    }

    // --- RejectionReason ---

    #[test]
    fn rejection_reason_tags_unique() {
        let reasons = vec![
            RejectionReason::IdentificationAbstained,
            RejectionReason::EffectBelowThreshold {
                effect_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::IntervalSpansZero {
                lower_millionths: 0,
                upper_millionths: 0,
            },
            RejectionReason::IntervalTooWide {
                width_millionths: 0,
                effect_millionths: 0,
            },
            RejectionReason::LowConfidence {
                confidence_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::CategoryMismatch {
                claim: ClaimCategory::Regression,
                evidence: ClaimCategory::Transfer,
            },
            RejectionReason::NoAdjustmentPath,
            RejectionReason::WeakEvidence {
                method: IdentificationMethod::ExpertAssertion,
                min_strength: 3,
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 8);
    }

    #[test]
    fn rejection_reason_display_content() {
        let r = RejectionReason::EffectBelowThreshold {
            effect_millionths: 5000,
            threshold_millionths: 10000,
        };
        let s = r.to_string();
        assert!(s.contains("5000"));
        assert!(s.contains("10000"));
    }

    #[test]
    fn rejection_reason_serde() {
        let r = RejectionReason::IntervalSpansZero {
            lower_millionths: -10_000,
            upper_millionths: 5_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- CausalBacking ---

    #[test]
    fn backing_ci_width() {
        let b = good_backing(ClaimCategory::Regression);
        assert_eq!(b.ci_width(), 60_000); // 80k - 20k
    }

    #[test]
    fn backing_ci_spans_zero_positive() {
        let mut b = good_backing(ClaimCategory::Regression);
        b.ci_lower_millionths = 10_000;
        assert!(!b.ci_spans_zero());
    }

    #[test]
    fn backing_ci_spans_zero_negative() {
        let mut b = good_backing(ClaimCategory::Regression);
        b.ci_lower_millionths = -10_000;
        assert!(b.ci_spans_zero());
    }

    #[test]
    fn backing_effect_positive() {
        let b = good_backing(ClaimCategory::Regression);
        assert!(b.effect_is_positive());
    }

    #[test]
    fn backing_serde() {
        let b = good_backing(ClaimCategory::Regression);
        let json = serde_json::to_string(&b).unwrap();
        let back: CausalBacking = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    // --- GateVerdict ---

    #[test]
    fn verdict_admitted_semantics() {
        let v = GateVerdict::Admitted {
            claim_id: "x".into(),
            method: IdentificationMethod::Backdoor,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        };
        assert!(v.is_admitted());
        assert!(!v.is_rejected());
        assert_eq!(v.claim_id(), "x");
        assert_eq!(v.tag(), "admitted");
    }

    #[test]
    fn verdict_rejected_semantics() {
        let v = GateVerdict::Rejected {
            claim_id: "y".into(),
            reasons: vec![RejectionReason::IdentificationAbstained],
        };
        assert!(v.is_rejected());
        assert!(!v.is_admitted());
        assert_eq!(v.tag(), "rejected");
    }

    #[test]
    fn verdict_no_backing() {
        let v = GateVerdict::NoBacking {
            claim_id: "z".into(),
        };
        assert!(!v.is_admitted());
        assert!(!v.is_rejected());
        assert_eq!(v.tag(), "no_backing");
    }

    #[test]
    fn verdict_display() {
        let v = GateVerdict::Admitted {
            claim_id: "test".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 100_000,
            confidence_millionths: 950_000,
        };
        let s = v.to_string();
        assert!(s.contains("ADMITTED"));
        assert!(s.contains("test"));
    }

    #[test]
    fn verdict_serde() {
        let v = GateVerdict::Rejected {
            claim_id: "c1".into(),
            reasons: vec![
                RejectionReason::IdentificationAbstained,
                RejectionReason::NoAdjustmentPath,
            ],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- GateConfig ---

    #[test]
    fn config_default() {
        let c = GateConfig::default_config();
        assert_eq!(c.min_effect_threshold, MIN_EFFECT_THRESHOLD);
        assert_eq!(c.min_confidence, MIN_IDENTIFICATION_CONFIDENCE);
        assert!(c.strict_category_match);
        assert!(!c.category_min_strength.is_empty());
    }

    #[test]
    fn config_permissive() {
        let c = GateConfig::permissive();
        assert_eq!(c.min_effect_threshold, 0);
        assert!(!c.strict_category_match);
    }

    #[test]
    fn config_default_trait() {
        let c = GateConfig::default();
        assert_eq!(c, GateConfig::default_config());
    }

    #[test]
    fn config_serde() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- EvidenceGate evaluation ---

    #[test]
    fn gate_admits_good_evidence() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let backing = good_backing(ClaimCategory::Regression);
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_admitted());
    }

    #[test]
    fn gate_rejects_no_backing() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let v = gate.evaluate(&claim, None);
        assert!(matches!(v, GateVerdict::NoBacking { .. }));
    }

    #[test]
    fn gate_rejects_unidentified() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let mut backing = good_backing(ClaimCategory::Regression);
        backing.identified = false;
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_negative_effect() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let mut backing = good_backing(ClaimCategory::Regression);
        backing.effect_millionths = -10_000;
        backing.ci_lower_millionths = -30_000;
        backing.ci_upper_millionths = -5_000;
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_ci_spans_zero() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let mut backing = good_backing(ClaimCategory::Regression);
        backing.ci_lower_millionths = -5_000;
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_low_confidence() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let mut backing = good_backing(ClaimCategory::Regression);
        backing.confidence_millionths = 500_000; // 50% < 80% threshold
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_category_mismatch() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim(); // category = Regression
        let backing = good_backing(ClaimCategory::Transfer); // evidence = Transfer
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_rejects_no_adjustment_path() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let mut backing = good_backing(ClaimCategory::Regression);
        backing.adjustment_variables.clear();
        backing.method = IdentificationMethod::ExpertAssertion;
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_admits_randomized_no_adjustment() {
        let gate = EvidenceGate::with_defaults();
        let claim = regression_claim();
        let backing = strong_backing(ClaimCategory::Regression);
        // Randomized method doesn't need adjustment set
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_admitted());
    }

    #[test]
    fn gate_rejects_weak_evidence_for_supremacy() {
        let gate = EvidenceGate::with_defaults();
        let claim = supremacy_claim(); // needs strength >= 3
        let mut backing = good_backing(ClaimCategory::Supremacy);
        backing.method = IdentificationMethod::DifferenceInDifferences; // strength = 2
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_rejected());
    }

    #[test]
    fn gate_admits_strong_evidence_for_supremacy() {
        let gate = EvidenceGate::with_defaults();
        let claim = supremacy_claim();
        let backing = strong_backing(ClaimCategory::Supremacy);
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_admitted());
    }

    // --- Batch evaluation ---

    #[test]
    fn gate_batch_empty() {
        let gate = EvidenceGate::with_defaults();
        let results = gate.evaluate_batch(&[], &BTreeMap::new());
        assert!(results.is_empty());
    }

    #[test]
    fn gate_batch_mixed() {
        let gate = EvidenceGate::with_defaults();
        let claims = vec![regression_claim(), supremacy_claim()];
        let mut backings = BTreeMap::new();
        backings.insert("reg-1".to_string(), good_backing(ClaimCategory::Regression));
        // sup-1 has no backing
        let results = gate.evaluate_batch(&claims, &backings);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_admitted());
        assert!(matches!(results[1], GateVerdict::NoBacking { .. }));
    }

    // --- GateReport ---

    #[test]
    fn report_empty() {
        let r = GateReport::new(epoch(), Vec::new());
        assert_eq!(r.total_count(), 0);
        assert_eq!(r.admission_rate(), 0);
        assert!(!r.all_admitted());
        assert!(!r.has_rejections());
    }

    #[test]
    fn report_all_admitted() {
        let verdicts = vec![
            GateVerdict::Admitted {
                claim_id: "a".into(),
                method: IdentificationMethod::Randomized,
                effect_millionths: 50_000,
                confidence_millionths: 900_000,
            },
            GateVerdict::Admitted {
                claim_id: "b".into(),
                method: IdentificationMethod::Backdoor,
                effect_millionths: 30_000,
                confidence_millionths: 850_000,
            },
        ];
        let r = GateReport::new(epoch(), verdicts);
        assert!(r.all_admitted());
        assert!(!r.has_rejections());
        assert_eq!(r.admission_rate(), 1_000_000);
    }

    #[test]
    fn report_mixed() {
        let verdicts = vec![
            GateVerdict::Admitted {
                claim_id: "a".into(),
                method: IdentificationMethod::Randomized,
                effect_millionths: 50_000,
                confidence_millionths: 900_000,
            },
            GateVerdict::Rejected {
                claim_id: "b".into(),
                reasons: vec![RejectionReason::IdentificationAbstained],
            },
            GateVerdict::NoBacking {
                claim_id: "c".into(),
            },
        ];
        let r = GateReport::new(epoch(), verdicts);
        assert_eq!(r.total_count(), 3);
        assert_eq!(r.admitted_count, 1);
        assert_eq!(r.rejected_count, 1);
        assert_eq!(r.no_backing_count, 1);
        assert!(!r.all_admitted());
        assert!(r.has_rejections());
    }

    #[test]
    fn report_hash_deterministic() {
        let verdicts = vec![GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        }];
        let r1 = GateReport::new(epoch(), verdicts.clone());
        let r2 = GateReport::new(epoch(), verdicts);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde() {
        let verdicts = vec![
            GateVerdict::Admitted {
                claim_id: "a".into(),
                method: IdentificationMethod::Randomized,
                effect_millionths: 50_000,
                confidence_millionths: 900_000,
            },
            GateVerdict::Rejected {
                claim_id: "b".into(),
                reasons: vec![RejectionReason::IdentificationAbstained],
            },
        ];
        let r = GateReport::new(epoch(), verdicts);
        let json = serde_json::to_string(&r).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- Permissive config ---

    #[test]
    fn permissive_config_admits_weak_evidence() {
        let gate = EvidenceGate::with_config(GateConfig::permissive());
        // Use optimization claim (min_evidence_strength=1), so ExpertAssertion (rank 1) passes
        let claim = UpliftClaim {
            claim_id: "perm-1".into(),
            category: ClaimCategory::Optimization,
            description: "test".into(),
            claimed_effect_millionths: 1,
            surface: "test".into(),
            min_evidence_strength: 1,
        };
        let backing = CausalBacking {
            method: IdentificationMethod::ExpertAssertion,
            effect_millionths: 1,
            ci_lower_millionths: 1,
            ci_upper_millionths: 2,
            confidence_millionths: 100_000,
            adjustment_variables: BTreeSet::from(["x".to_string()]),
            evidence_category: ClaimCategory::Regression, // mismatch, but permissive
            identified: true,
            certificate_hash: ContentHash::compute(b"weak"),
        };
        let v = gate.evaluate(&claim, Some(&backing));
        assert!(v.is_admitted());
    }
}
