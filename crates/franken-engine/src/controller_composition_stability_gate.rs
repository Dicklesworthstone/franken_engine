#![forbid(unsafe_code)]

//! Controller-composition stability gate for adaptive behavior and supremacy
//! evidence.
//!
//! Bead: bd-1lsy.7.14.3 \[RGC-614C\]
//!
//! Ensures that adaptive performance wins are only shipped when the composed
//! control plane is demonstrably stable.  Takes timescale-separation
//! certificates, bifurcation detector results, and per-claim evidence and
//! produces gating verdicts that block publication of unstable compositions.
//!
//! # Gate logic
//!
//! A composition claim is **admitted** only when:
//! 1. All controller pairs have sufficient timescale separation.
//! 2. No critical bifurcation signals are active.
//! 3. Overall stability assessment is at most "monitoring recommended".
//! 4. Composition confidence meets the minimum threshold.
//! 5. The claim category matches (if strict mode is active).
//!
//! Otherwise the claim is **rejected** with explicit reasons.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::timescale_separation_certificate::{
    CertificateBundle, SeparationVerdict, StabilityAssessment,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.controller-composition-stability-gate.v1";

/// Component identifier.
pub const COMPONENT: &str = "controller_composition_stability_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.14.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-614C";

const MILLION: u64 = 1_000_000;

/// Default minimum composition confidence (85%).
pub const DEFAULT_MIN_CONFIDENCE_MILLIONTHS: u64 = 850_000;

/// Default maximum allowed critical signals before rejection.
pub const DEFAULT_MAX_CRITICAL_SIGNALS: usize = 0;

/// Default maximum allowed warning signals.
pub const DEFAULT_MAX_WARNING_SIGNALS: usize = 3;

/// Default maximum allowed marginal pairs.
pub const DEFAULT_MAX_MARGINAL_PAIRS: usize = 1;

/// Default maximum allowed insufficient pairs.
pub const DEFAULT_MAX_INSUFFICIENT_PAIRS: usize = 0;

/// Default minimum timescale separation ratio (5x).
pub const DEFAULT_MIN_SEPARATION_RATIO_MILLIONTHS: u64 = 5_000_000;

// ---------------------------------------------------------------------------
// Claim categories
// ---------------------------------------------------------------------------

/// Category of claim subject to gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCategory {
    /// An adaptive performance win.
    AdaptivePerformance,
    /// A supremacy claim (explicit comparison against baseline).
    Supremacy,
    /// A rollout decision (shipping new adaptive behavior).
    Rollout,
    /// A regression analysis claim.
    Regression,
    /// A documentation or external-facing assertion.
    Documentation,
}

impl ClaimCategory {
    /// All claim category variants.
    pub const ALL: &'static [ClaimCategory] = &[
        ClaimCategory::AdaptivePerformance,
        ClaimCategory::Supremacy,
        ClaimCategory::Rollout,
        ClaimCategory::Regression,
        ClaimCategory::Documentation,
    ];

    /// Returns a string tag for this category.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::AdaptivePerformance => "adaptive_performance",
            Self::Supremacy => "supremacy",
            Self::Rollout => "rollout",
            Self::Regression => "regression",
            Self::Documentation => "documentation",
        }
    }
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

// ---------------------------------------------------------------------------
// Instability signals (gate input)
// ---------------------------------------------------------------------------

/// Kind of instability signal detected in the composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSeverity {
    /// Informational — not blocking.
    Info,
    /// Warning — counts against warning budget.
    Warning,
    /// Critical — blocks claims outright.
    Critical,
}

impl fmt::Display for SignalSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        };
        f.write_str(label)
    }
}

/// An instability signal from the bifurcation detector or telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstabilitySignal {
    /// Signal identifier.
    pub signal_id: String,
    /// Which controllers are involved.
    pub controller_ids: Vec<String>,
    /// Severity.
    pub severity: SignalSeverity,
    /// Human-readable description.
    pub description: String,
    /// Measured risk score (millionths, 0 = no risk, 1_000_000 = max).
    pub risk_score_millionths: u64,
}

impl fmt::Display for InstabilitySignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.signal_id, self.description)
    }
}

// ---------------------------------------------------------------------------
// Composition evidence
// ---------------------------------------------------------------------------

/// Evidence about a composition's stability, aggregated from upstream modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionEvidence {
    /// Composition identifier.
    pub composition_id: String,
    /// Number of controllers in the composition.
    pub controller_count: usize,
    /// Timescale separation certificate bundle (if available).
    pub separation_bundle: Option<CertificateBundle>,
    /// Stability assessment from the bifurcation detector.
    pub stability_assessment: Option<StabilityAssessment>,
    /// Active instability signals.
    pub signals: Vec<InstabilitySignal>,
    /// Composition confidence (millionths, 0..1_000_000).
    pub confidence_millionths: u64,
    /// Epoch at which the evidence was collected.
    pub evidence_epoch: u64,
}

impl CompositionEvidence {
    /// Count signals at each severity.
    pub fn signal_counts(&self) -> (usize, usize, usize) {
        let mut info = 0usize;
        let mut warning = 0usize;
        let mut critical = 0usize;
        for s in &self.signals {
            match s.severity {
                SignalSeverity::Info => info += 1,
                SignalSeverity::Warning => warning += 1,
                SignalSeverity::Critical => critical += 1,
            }
        }
        (info, warning, critical)
    }

    /// Count separation verdicts from the bundle.
    pub fn separation_counts(&self) -> (usize, usize, usize) {
        match &self.separation_bundle {
            None => (0, 0, 0),
            Some(bundle) => {
                let mut sufficient = 0usize;
                let mut marginal = 0usize;
                let mut insufficient = 0usize;
                for cert in &bundle.certificates {
                    match cert.verdict {
                        SeparationVerdict::Sufficient => sufficient += 1,
                        SeparationVerdict::Marginal => marginal += 1,
                        SeparationVerdict::Insufficient => insufficient += 1,
                    }
                }
                (sufficient, marginal, insufficient)
            }
        }
    }

    /// Compute content hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.composition_id.as_bytes());
        hasher.update(self.controller_count.to_le_bytes());
        hasher.update(self.confidence_millionths.to_le_bytes());
        hasher.update(self.evidence_epoch.to_le_bytes());
        hasher.update(self.signals.len().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Claims subject to gating
// ---------------------------------------------------------------------------

/// A claim to be gated by composition stability evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityClaim {
    /// Claim identifier.
    pub claim_id: String,
    /// Category.
    pub category: ClaimCategory,
    /// Which composition this claim is about.
    pub composition_id: String,
    /// Brief description of the claim.
    pub description: String,
}

impl fmt::Display for StabilityClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.category, self.claim_id, self.description)
    }
}

// ---------------------------------------------------------------------------
// Rejection reasons
// ---------------------------------------------------------------------------

/// Reason a claim was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// No composition evidence was provided.
    NoEvidence,
    /// Composition has insufficient timescale separation.
    InsufficientSeparation {
        insufficient_pairs: usize,
        max_allowed: usize,
    },
    /// Too many marginal timescale-separation pairs.
    TooManyMarginalPairs {
        marginal_pairs: usize,
        max_allowed: usize,
    },
    /// Critical instability signals are active.
    CriticalSignalsActive {
        count: usize,
        max_allowed: usize,
    },
    /// Too many warning signals.
    TooManyWarnings {
        count: usize,
        max_allowed: usize,
    },
    /// Stability assessment too severe.
    AssessmentTooSevere {
        assessment: StabilityAssessment,
    },
    /// Composition confidence too low.
    InsufficientConfidence {
        confidence_millionths: u64,
        minimum_millionths: u64,
    },
    /// Claim category is not allowed in strict mode.
    CategoryNotAllowed {
        category: ClaimCategory,
    },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEvidence => write!(f, "no composition evidence provided"),
            Self::InsufficientSeparation {
                insufficient_pairs,
                max_allowed,
            } => write!(
                f,
                "{insufficient_pairs} insufficient separation pairs (max {max_allowed})"
            ),
            Self::TooManyMarginalPairs {
                marginal_pairs,
                max_allowed,
            } => write!(f, "{marginal_pairs} marginal pairs (max {max_allowed})"),
            Self::CriticalSignalsActive { count, max_allowed } => {
                write!(f, "{count} critical signals active (max {max_allowed})")
            }
            Self::TooManyWarnings { count, max_allowed } => {
                write!(f, "{count} warning signals (max {max_allowed})")
            }
            Self::AssessmentTooSevere { assessment } => {
                write!(f, "stability assessment too severe: {assessment}")
            }
            Self::InsufficientConfidence {
                confidence_millionths,
                minimum_millionths,
            } => write!(
                f,
                "confidence {confidence_millionths} below minimum {minimum_millionths}"
            ),
            Self::CategoryNotAllowed { category } => {
                write!(f, "category {category} not allowed in strict mode")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Gate verdict
// ---------------------------------------------------------------------------

/// Verdict from the composition stability gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Claim is admitted — composition is sufficiently stable.
    Admitted {
        claim_id: String,
        composition_id: String,
        confidence_millionths: u64,
    },
    /// Claim is rejected — composition stability insufficient.
    Rejected {
        claim_id: String,
        composition_id: String,
        reasons: Vec<RejectionReason>,
    },
    /// No evidence available — gate is indeterminate.
    NoEvidence {
        claim_id: String,
        composition_id: String,
    },
}

impl GateVerdict {
    /// String tag for the verdict.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Admitted { .. } => "admitted",
            Self::Rejected { .. } => "rejected",
            Self::NoEvidence { .. } => "no_evidence",
        }
    }

    /// Whether the claim was admitted.
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// Whether the claim was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// The claim ID.
    pub fn claim_id(&self) -> &str {
        match self {
            Self::Admitted { claim_id, .. }
            | Self::Rejected { claim_id, .. }
            | Self::NoEvidence { claim_id, .. } => claim_id,
        }
    }

    /// The composition ID.
    pub fn composition_id(&self) -> &str {
        match self {
            Self::Admitted { composition_id, .. }
            | Self::Rejected { composition_id, .. }
            | Self::NoEvidence { composition_id, .. } => composition_id,
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admitted {
                claim_id,
                confidence_millionths,
                ..
            } => write!(
                f,
                "ADMITTED claim={claim_id} confidence={confidence_millionths}"
            ),
            Self::Rejected {
                claim_id, reasons, ..
            } => {
                write!(f, "REJECTED claim={claim_id} reasons={}", reasons.len())
            }
            Self::NoEvidence { claim_id, .. } => {
                write!(f, "NO_EVIDENCE claim={claim_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the composition stability gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum composition confidence (millionths).
    pub min_confidence_millionths: u64,
    /// Maximum number of critical signals allowed (0 = fail on any).
    pub max_critical_signals: usize,
    /// Maximum number of warning signals.
    pub max_warning_signals: usize,
    /// Maximum number of marginal timescale-separation pairs.
    pub max_marginal_pairs: usize,
    /// Maximum number of insufficient timescale-separation pairs.
    pub max_insufficient_pairs: usize,
    /// Minimum timescale separation ratio (millionths).
    pub min_separation_ratio_millionths: u64,
    /// Maximum stability assessment severity that passes.
    pub max_assessment_severity: StabilityAssessment,
    /// Whether to reject claims whose category is not in allowed set.
    pub strict_category_mode: bool,
    /// Allowed categories when strict mode is on.
    pub allowed_categories: Vec<ClaimCategory>,
    /// Whether missing evidence should be treated as rejection.
    pub fail_closed_on_missing: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_confidence_millionths: DEFAULT_MIN_CONFIDENCE_MILLIONTHS,
            max_critical_signals: DEFAULT_MAX_CRITICAL_SIGNALS,
            max_warning_signals: DEFAULT_MAX_WARNING_SIGNALS,
            max_marginal_pairs: DEFAULT_MAX_MARGINAL_PAIRS,
            max_insufficient_pairs: DEFAULT_MAX_INSUFFICIENT_PAIRS,
            min_separation_ratio_millionths: DEFAULT_MIN_SEPARATION_RATIO_MILLIONTHS,
            max_assessment_severity: StabilityAssessment::MonitoringRecommended,
            strict_category_mode: false,
            allowed_categories: Vec::new(),
            fail_closed_on_missing: true,
        }
    }
}

impl GateConfig {
    /// Default (strict) configuration.
    pub fn default_config() -> Self {
        Self::default()
    }

    /// Permissive configuration for testing.
    pub fn permissive() -> Self {
        Self {
            min_confidence_millionths: 0,
            max_critical_signals: 100,
            max_warning_signals: 100,
            max_marginal_pairs: 100,
            max_insufficient_pairs: 100,
            min_separation_ratio_millionths: 0,
            max_assessment_severity: StabilityAssessment::ImmediateActionRequired,
            strict_category_mode: false,
            allowed_categories: Vec::new(),
            fail_closed_on_missing: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate implementation
// ---------------------------------------------------------------------------

/// The composition stability gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionStabilityGate {
    /// Configuration.
    pub config: GateConfig,
    /// Schema version.
    pub schema_version: String,
}

impl CompositionStabilityGate {
    /// Create a gate with default configuration.
    pub fn with_defaults() -> Self {
        Self {
            config: GateConfig::default(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Create a gate with custom configuration.
    pub fn with_config(config: GateConfig) -> Self {
        Self {
            config,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Evaluate a single claim against composition evidence.
    pub fn evaluate(
        &self,
        claim: &StabilityClaim,
        evidence: Option<&CompositionEvidence>,
    ) -> GateVerdict {
        let evidence = match evidence {
            Some(e) => e,
            None => {
                if self.config.fail_closed_on_missing {
                    return GateVerdict::Rejected {
                        claim_id: claim.claim_id.clone(),
                        composition_id: claim.composition_id.clone(),
                        reasons: vec![RejectionReason::NoEvidence],
                    };
                }
                return GateVerdict::NoEvidence {
                    claim_id: claim.claim_id.clone(),
                    composition_id: claim.composition_id.clone(),
                };
            }
        };

        let mut reasons = Vec::new();

        // Check strict category mode.
        if self.config.strict_category_mode
            && !self.config.allowed_categories.contains(&claim.category)
        {
            reasons.push(RejectionReason::CategoryNotAllowed {
                category: claim.category,
            });
        }

        // Check confidence.
        if evidence.confidence_millionths < self.config.min_confidence_millionths {
            reasons.push(RejectionReason::InsufficientConfidence {
                confidence_millionths: evidence.confidence_millionths,
                minimum_millionths: self.config.min_confidence_millionths,
            });
        }

        // Check stability assessment.
        if let Some(assessment) = &evidence.stability_assessment {
            if assessment_severity(assessment) > assessment_severity(&self.config.max_assessment_severity)
            {
                reasons.push(RejectionReason::AssessmentTooSevere {
                    assessment: assessment.clone(),
                });
            }
        }

        // Check instability signals.
        let (_, warning_count, critical_count) = evidence.signal_counts();
        if critical_count > self.config.max_critical_signals {
            reasons.push(RejectionReason::CriticalSignalsActive {
                count: critical_count,
                max_allowed: self.config.max_critical_signals,
            });
        }
        if warning_count > self.config.max_warning_signals {
            reasons.push(RejectionReason::TooManyWarnings {
                count: warning_count,
                max_allowed: self.config.max_warning_signals,
            });
        }

        // Check timescale separation.
        let (_, marginal, insufficient) = evidence.separation_counts();
        if insufficient > self.config.max_insufficient_pairs {
            reasons.push(RejectionReason::InsufficientSeparation {
                insufficient_pairs: insufficient,
                max_allowed: self.config.max_insufficient_pairs,
            });
        }
        if marginal > self.config.max_marginal_pairs {
            reasons.push(RejectionReason::TooManyMarginalPairs {
                marginal_pairs: marginal,
                max_allowed: self.config.max_marginal_pairs,
            });
        }

        if reasons.is_empty() {
            GateVerdict::Admitted {
                claim_id: claim.claim_id.clone(),
                composition_id: claim.composition_id.clone(),
                confidence_millionths: evidence.confidence_millionths,
            }
        } else {
            GateVerdict::Rejected {
                claim_id: claim.claim_id.clone(),
                composition_id: claim.composition_id.clone(),
                reasons,
            }
        }
    }

    /// Evaluate a batch of claims against a map of composition evidence.
    pub fn evaluate_batch(
        &self,
        claims: &[StabilityClaim],
        evidence_map: &BTreeMap<String, CompositionEvidence>,
    ) -> Vec<GateVerdict> {
        claims
            .iter()
            .map(|claim| {
                let evidence = evidence_map.get(&claim.composition_id);
                self.evaluate(claim, evidence)
            })
            .collect()
    }
}

/// Numeric severity for assessment comparison.
fn assessment_severity(a: &StabilityAssessment) -> u8 {
    match a {
        StabilityAssessment::Stable => 0,
        StabilityAssessment::MonitoringRecommended => 1,
        StabilityAssessment::InterventionRecommended => 2,
        StabilityAssessment::ImmediateActionRequired => 3,
    }
}

// ---------------------------------------------------------------------------
// Gate report
// ---------------------------------------------------------------------------

/// Aggregated report from a gate evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Individual verdicts.
    pub verdicts: Vec<GateVerdict>,
    /// Number admitted.
    pub admitted_count: usize,
    /// Number rejected.
    pub rejected_count: usize,
    /// Number with no evidence.
    pub no_evidence_count: usize,
    /// Content hash of the report.
    pub content_hash: ContentHash,
}

impl GateReport {
    /// Build a report from verdicts.
    pub fn new(epoch: SecurityEpoch, verdicts: Vec<GateVerdict>) -> Self {
        let admitted_count = verdicts.iter().filter(|v| v.is_admitted()).count();
        let rejected_count = verdicts.iter().filter(|v| v.is_rejected()).count();
        let no_evidence_count = verdicts.len() - admitted_count - rejected_count;

        let content_hash = {
            let mut hasher = Sha256::new();
            hasher.update(SCHEMA_VERSION.as_bytes());
            hasher.update(epoch.as_u64().to_le_bytes());
            hasher.update(verdicts.len().to_le_bytes());
            hasher.update(admitted_count.to_le_bytes());
            hasher.update(rejected_count.to_le_bytes());
            for v in &verdicts {
                hasher.update(v.claim_id().as_bytes());
                hasher.update(v.tag().as_bytes());
            }
            ContentHash::compute(&hasher.finalize())
        };

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            epoch,
            verdicts,
            admitted_count,
            rejected_count,
            no_evidence_count,
            content_hash,
        }
    }

    /// Total number of verdicts.
    pub fn total_count(&self) -> usize {
        self.verdicts.len()
    }

    /// Whether all claims were admitted.
    pub fn all_admitted(&self) -> bool {
        self.rejected_count == 0 && self.no_evidence_count == 0
    }

    /// Admission rate in millionths.
    pub fn admission_rate_millionths(&self) -> u64 {
        if self.verdicts.is_empty() {
            return MILLION;
        }
        (self.admitted_count as u64)
            .saturating_mul(MILLION)
            .checked_div(self.verdicts.len() as u64)
            .unwrap_or(0)
    }
}

impl fmt::Display for GateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateReport[{}: admitted={} rejected={} no_evidence={}]",
            self.epoch, self.admitted_count, self.rejected_count, self.no_evidence_count
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timescale_separation_certificate::{
        ControllerPairId, ControllerTimescaleProfile, RatioBasis, TimescaleRatio,
        TimescaleSeparationCertificate,
    };

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_claim(id: &str, category: ClaimCategory, comp: &str) -> StabilityClaim {
        StabilityClaim {
            claim_id: id.to_string(),
            category,
            composition_id: comp.to_string(),
            description: format!("test claim {id}"),
        }
    }

    fn make_evidence(comp_id: &str) -> CompositionEvidence {
        CompositionEvidence {
            composition_id: comp_id.to_string(),
            controller_count: 2,
            separation_bundle: None,
            stability_assessment: Some(StabilityAssessment::Stable),
            signals: Vec::new(),
            confidence_millionths: 900_000,
            evidence_epoch: 42,
        }
    }

    fn make_signal(id: &str, severity: SignalSeverity) -> InstabilitySignal {
        InstabilitySignal {
            signal_id: id.to_string(),
            controller_ids: vec!["ctrl-1".to_string()],
            severity,
            description: format!("signal {id}"),
            risk_score_millionths: 500_000,
        }
    }

    fn make_profile(id: &str) -> ControllerTimescaleProfile {
        ControllerTimescaleProfile {
            controller_id: id.to_string(),
            observation_interval_millionths: 1_000_000,
            write_interval_millionths: 2_000_000,
            sample_count: 100,
            measured_epoch: 42,
        }
    }

    fn make_cert(
        fast: &str,
        slow: &str,
        verdict: SeparationVerdict,
    ) -> TimescaleSeparationCertificate {
        TimescaleSeparationCertificate {
            schema_version: "test".to_string(),
            bead_id: "test".to_string(),
            certificate_id: format!("{fast}-{slow}"),
            pair: ControllerPairId {
                fast_controller: fast.to_string(),
                slow_controller: slow.to_string(),
            },
            ratio: TimescaleRatio {
                pair: ControllerPairId {
                    fast_controller: fast.to_string(),
                    slow_controller: slow.to_string(),
                },
                ratio_millionths: 10_000_000,
                ratio_basis: RatioBasis::MinimumOf,
            },
            verdict,
            sufficient_threshold_millionths: 10_000_000,
            marginal_threshold_millionths: 3_000_000,
            fast_profile: make_profile(fast),
            slow_profile: make_profile(slow),
            issued_epoch: 42,
            evidence_ids: Vec::new(),
        }
    }

    fn make_bundle(certs: Vec<TimescaleSeparationCertificate>) -> CertificateBundle {
        let sufficient_count = certs
            .iter()
            .filter(|c| c.verdict == SeparationVerdict::Sufficient)
            .count();
        let marginal_count = certs
            .iter()
            .filter(|c| c.verdict == SeparationVerdict::Marginal)
            .count();
        let insufficient_count = certs
            .iter()
            .filter(|c| c.verdict == SeparationVerdict::Insufficient)
            .count();
        let overall_verdict = if insufficient_count > 0 {
            SeparationVerdict::Insufficient
        } else if marginal_count > 0 {
            SeparationVerdict::Marginal
        } else {
            SeparationVerdict::Sufficient
        };
        CertificateBundle {
            schema_version: "test".to_string(),
            bead_id: "test".to_string(),
            certificates: certs,
            overall_verdict,
            bundle_epoch: 42,
            pair_count: sufficient_count + marginal_count + insufficient_count,
            sufficient_count,
            marginal_count,
            insufficient_count,
        }
    }

    // --- Constants ---

    #[test]
    fn constants_valid() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(DEFAULT_MIN_CONFIDENCE_MILLIONTHS <= MILLION);
    }

    // --- ClaimCategory ---

    #[test]
    fn claim_category_all_variants() {
        assert_eq!(ClaimCategory::ALL.len(), 5);
    }

    #[test]
    fn claim_category_tags_unique() {
        let tags: Vec<&str> = ClaimCategory::ALL.iter().map(|c| c.tag()).collect();
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn claim_category_display() {
        assert_eq!(
            format!("{}", ClaimCategory::AdaptivePerformance),
            "adaptive_performance"
        );
        assert_eq!(format!("{}", ClaimCategory::Supremacy), "supremacy");
    }

    #[test]
    fn claim_category_serde_roundtrip() {
        for cat in ClaimCategory::ALL {
            let json = serde_json::to_string(cat).unwrap();
            let back: ClaimCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    // --- SignalSeverity ---

    #[test]
    fn signal_severity_display() {
        assert_eq!(format!("{}", SignalSeverity::Info), "info");
        assert_eq!(format!("{}", SignalSeverity::Warning), "warning");
        assert_eq!(format!("{}", SignalSeverity::Critical), "critical");
    }

    #[test]
    fn signal_severity_serde_roundtrip() {
        for sev in [
            SignalSeverity::Info,
            SignalSeverity::Warning,
            SignalSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: SignalSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    // --- InstabilitySignal ---

    #[test]
    fn instability_signal_display() {
        let s = make_signal("s1", SignalSeverity::Warning);
        let d = format!("{s}");
        assert!(d.contains("warning"));
        assert!(d.contains("s1"));
    }

    // --- CompositionEvidence ---

    #[test]
    fn evidence_signal_counts_empty() {
        let e = make_evidence("c1");
        assert_eq!(e.signal_counts(), (0, 0, 0));
    }

    #[test]
    fn evidence_signal_counts_mixed() {
        let mut e = make_evidence("c1");
        e.signals = vec![
            make_signal("s1", SignalSeverity::Info),
            make_signal("s2", SignalSeverity::Warning),
            make_signal("s3", SignalSeverity::Critical),
            make_signal("s4", SignalSeverity::Warning),
        ];
        assert_eq!(e.signal_counts(), (1, 2, 1));
    }

    #[test]
    fn evidence_separation_counts_none() {
        let e = make_evidence("c1");
        assert_eq!(e.separation_counts(), (0, 0, 0));
    }

    #[test]
    fn evidence_separation_counts_mixed() {
        let mut e = make_evidence("c1");
        e.separation_bundle = Some(make_bundle(vec![
            make_cert("a", "b", SeparationVerdict::Sufficient),
            make_cert("a", "c", SeparationVerdict::Marginal),
            make_cert("b", "c", SeparationVerdict::Insufficient),
        ]));
        assert_eq!(e.separation_counts(), (1, 1, 1));
    }

    #[test]
    fn evidence_content_hash_deterministic() {
        let a = make_evidence("c1");
        let b = make_evidence("c1");
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn evidence_content_hash_differs() {
        let a = make_evidence("c1");
        let b = make_evidence("c2");
        assert_ne!(a.content_hash(), b.content_hash());
    }

    // --- StabilityClaim ---

    #[test]
    fn stability_claim_display() {
        let c = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
        let d = format!("{c}");
        assert!(d.contains("supremacy"));
        assert!(d.contains("cl-1"));
    }

    // --- RejectionReason ---

    #[test]
    fn rejection_reason_display() {
        let r = RejectionReason::NoEvidence;
        assert_eq!(format!("{r}"), "no composition evidence provided");
    }

    #[test]
    fn rejection_reason_insufficient_separation() {
        let r = RejectionReason::InsufficientSeparation {
            insufficient_pairs: 2,
            max_allowed: 0,
        };
        let d = format!("{r}");
        assert!(d.contains("2"));
        assert!(d.contains("max 0"));
    }

    #[test]
    fn rejection_reasons_serde_roundtrip() {
        let reasons = vec![
            RejectionReason::NoEvidence,
            RejectionReason::CriticalSignalsActive {
                count: 3,
                max_allowed: 0,
            },
            RejectionReason::InsufficientConfidence {
                confidence_millionths: 500_000,
                minimum_millionths: 850_000,
            },
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let back: RejectionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // --- GateVerdict ---

    #[test]
    fn verdict_admitted_properties() {
        let v = GateVerdict::Admitted {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
            confidence_millionths: 900_000,
        };
        assert!(v.is_admitted());
        assert!(!v.is_rejected());
        assert_eq!(v.tag(), "admitted");
        assert_eq!(v.claim_id(), "c1");
        assert_eq!(v.composition_id(), "comp1");
    }

    #[test]
    fn verdict_rejected_properties() {
        let v = GateVerdict::Rejected {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        };
        assert!(!v.is_admitted());
        assert!(v.is_rejected());
        assert_eq!(v.tag(), "rejected");
    }

    #[test]
    fn verdict_no_evidence_properties() {
        let v = GateVerdict::NoEvidence {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
        };
        assert!(!v.is_admitted());
        assert!(!v.is_rejected());
        assert_eq!(v.tag(), "no_evidence");
    }

    #[test]
    fn verdict_display() {
        let v = GateVerdict::Admitted {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
            confidence_millionths: 900_000,
        };
        let d = format!("{v}");
        assert!(d.contains("ADMITTED"));
        assert!(d.contains("c1"));
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = GateVerdict::Rejected {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- GateConfig ---

    #[test]
    fn default_config_sane() {
        let c = GateConfig::default();
        assert!(c.min_confidence_millionths > 0);
        assert_eq!(c.max_critical_signals, 0);
        assert!(c.fail_closed_on_missing);
    }

    #[test]
    fn permissive_config_allows_everything() {
        let c = GateConfig::permissive();
        assert_eq!(c.min_confidence_millionths, 0);
        assert!(!c.fail_closed_on_missing);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- Gate evaluation ---

    #[test]
    fn gate_admits_stable_composition() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let evidence = make_evidence("comp1");
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn gate_rejects_no_evidence_fail_closed() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let verdict = gate.evaluate(&claim, None);
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_no_evidence_returns_no_evidence_when_open() {
        let gate = CompositionStabilityGate::with_config(GateConfig {
            fail_closed_on_missing: false,
            ..GateConfig::default()
        });
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let verdict = gate.evaluate(&claim, None);
        assert_eq!(verdict.tag(), "no_evidence");
    }

    #[test]
    fn gate_rejects_low_confidence() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.confidence_millionths = 100_000;
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_rejects_critical_signals() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.signals = vec![make_signal("s1", SignalSeverity::Critical)];
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_rejects_too_many_warnings() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.signals = vec![
            make_signal("w1", SignalSeverity::Warning),
            make_signal("w2", SignalSeverity::Warning),
            make_signal("w3", SignalSeverity::Warning),
            make_signal("w4", SignalSeverity::Warning),
        ];
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_admits_within_warning_budget() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.signals = vec![
            make_signal("w1", SignalSeverity::Warning),
            make_signal("w2", SignalSeverity::Warning),
        ];
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn gate_rejects_severe_assessment() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_admits_monitoring_assessment() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.stability_assessment = Some(StabilityAssessment::MonitoringRecommended);
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn gate_rejects_insufficient_separation() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.separation_bundle = Some(make_bundle(vec![
            make_cert("a", "b", SeparationVerdict::Insufficient),
        ]));
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_admits_sufficient_separation() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.separation_bundle = Some(make_bundle(vec![
            make_cert("a", "b", SeparationVerdict::Sufficient),
        ]));
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn gate_rejects_too_many_marginal() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.separation_bundle = Some(make_bundle(vec![
            make_cert("a", "b", SeparationVerdict::Marginal),
            make_cert("a", "c", SeparationVerdict::Marginal),
        ]));
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_strict_category_rejects_unlisted() {
        let gate = CompositionStabilityGate::with_config(GateConfig {
            strict_category_mode: true,
            allowed_categories: vec![ClaimCategory::Supremacy],
            ..GateConfig::default()
        });
        let claim = make_claim("c1", ClaimCategory::Documentation, "comp1");
        let evidence = make_evidence("comp1");
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_rejected());
    }

    #[test]
    fn gate_strict_category_admits_listed() {
        let gate = CompositionStabilityGate::with_config(GateConfig {
            strict_category_mode: true,
            allowed_categories: vec![ClaimCategory::Supremacy],
            ..GateConfig::default()
        });
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let evidence = make_evidence("comp1");
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn gate_permissive_admits_everything() {
        let gate = CompositionStabilityGate::with_config(GateConfig::permissive());
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.confidence_millionths = 0;
        evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);
        evidence.signals = vec![make_signal("s1", SignalSeverity::Critical)];
        evidence.separation_bundle = Some(make_bundle(vec![
            make_cert("a", "b", SeparationVerdict::Insufficient),
        ]));
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    // --- Batch evaluation ---

    #[test]
    fn batch_evaluation_maps_claims() {
        let gate = CompositionStabilityGate::with_defaults();
        let claims = vec![
            make_claim("c1", ClaimCategory::Supremacy, "comp1"),
            make_claim("c2", ClaimCategory::Rollout, "comp2"),
        ];
        let mut evidence_map = BTreeMap::new();
        evidence_map.insert("comp1".to_string(), make_evidence("comp1"));
        // comp2 has no evidence

        let verdicts = gate.evaluate_batch(&claims, &evidence_map);
        assert_eq!(verdicts.len(), 2);
        assert!(verdicts[0].is_admitted());
        assert!(verdicts[1].is_rejected()); // fail_closed_on_missing
    }

    // --- GateReport ---

    #[test]
    fn report_new_empty() {
        let report = GateReport::new(test_epoch(), vec![]);
        assert_eq!(report.total_count(), 0);
        assert!(report.all_admitted());
        assert_eq!(report.admission_rate_millionths(), MILLION);
    }

    #[test]
    fn report_counts() {
        let verdicts = vec![
            GateVerdict::Admitted {
                claim_id: "c1".to_string(),
                composition_id: "comp1".to_string(),
                confidence_millionths: 900_000,
            },
            GateVerdict::Rejected {
                claim_id: "c2".to_string(),
                composition_id: "comp2".to_string(),
                reasons: vec![RejectionReason::NoEvidence],
            },
        ];
        let report = GateReport::new(test_epoch(), verdicts);
        assert_eq!(report.admitted_count, 1);
        assert_eq!(report.rejected_count, 1);
        assert_eq!(report.no_evidence_count, 0);
        assert!(!report.all_admitted());
        assert_eq!(report.admission_rate_millionths(), 500_000);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let verdicts = vec![GateVerdict::Admitted {
            claim_id: "c1".to_string(),
            composition_id: "comp1".to_string(),
            confidence_millionths: 900_000,
        }];
        let a = GateReport::new(test_epoch(), verdicts.clone());
        let b = GateReport::new(test_epoch(), verdicts);
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn report_display() {
        let report = GateReport::new(test_epoch(), vec![]);
        let d = format!("{report}");
        assert!(d.contains("GateReport"));
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = GateReport::new(test_epoch(), vec![]);
        let json = serde_json::to_string(&report).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- Edge cases ---

    #[test]
    fn multiple_rejection_reasons() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.confidence_millionths = 100_000;
        evidence.signals = vec![make_signal("s1", SignalSeverity::Critical)];
        evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);

        let verdict = gate.evaluate(&claim, Some(&evidence));
        if let GateVerdict::Rejected { reasons, .. } = &verdict {
            assert!(reasons.len() >= 3);
        } else {
            panic!("expected rejection");
        }
    }

    #[test]
    fn info_signals_dont_block() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.signals = vec![
            make_signal("i1", SignalSeverity::Info),
            make_signal("i2", SignalSeverity::Info),
            make_signal("i3", SignalSeverity::Info),
        ];
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }

    #[test]
    fn assessment_none_is_not_severe() {
        let gate = CompositionStabilityGate::with_defaults();
        let claim = make_claim("c1", ClaimCategory::Supremacy, "comp1");
        let mut evidence = make_evidence("comp1");
        evidence.stability_assessment = None;
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(verdict.is_admitted());
    }
}
