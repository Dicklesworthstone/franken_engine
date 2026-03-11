//! Benchmark-board coverage saturation and distributional representativeness gate.
//!
//! Bead: bd-1lsy.8.5.5 [RGC-705E]
//!
//! Proves that the declared benchmark board is not a narrow cherry-picked slice
//! by gating on corpus-coverage and distributional representativeness across
//! workload families: branch-heavy, vectorizable, proof-specialized,
//! native-addon, hostcall-boundary, startup-image, metadata-locality,
//! observability-sensitive, resource-spiky.
//!
//! # Design
//!
//! - `FamilyCoverage` reports per-family weight and coverage fraction.
//! - `DistributionProfile` aggregates coverage into Gini coefficient, entropy,
//!   and share bounds.
//! - `evaluate_saturation` decides whether coverage is saturated, sparse, or
//!   cherry-picked.
//! - `evaluate_representativeness` classifies distributional balance.
//! - `evaluate` combines both into a final `GateResult` with receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705E]

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.benchmark-coverage-saturation-gate.v1";

/// Component name.
pub const COMPONENT: &str = "benchmark_coverage_saturation_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.5.5";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705E";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Total number of recognised workload families.
pub const TOTAL_WORKLOAD_FAMILIES: usize = 9;

/// Default minimum families that must be covered.
pub const DEFAULT_MIN_FAMILIES_COVERED: usize = 7;

/// Default minimum per-family coverage fraction (millionths). 10% = 100_000.
pub const DEFAULT_MIN_FAMILY_COVERAGE: u64 = 100_000;

/// Default maximum Gini coefficient (millionths). 0.35 = 350_000.
pub const DEFAULT_MAX_GINI: u64 = 350_000;

/// Default minimum entropy (millionths). 0.80 = 800_000.
pub const DEFAULT_MIN_ENTROPY: u64 = 800_000;

/// Default maximum share any single family may hold (millionths). 0.30 = 300_000.
pub const DEFAULT_MAX_SINGLE_FAMILY_SHARE: u64 = 300_000;

/// Default minimum workloads per family.
pub const DEFAULT_MIN_WORKLOADS_PER_FAMILY: u64 = 3;

// ---------------------------------------------------------------------------
// WorkloadFamily
// ---------------------------------------------------------------------------

/// A recognised workload family in the benchmark board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFamily {
    /// Branch-heavy control-flow programs.
    BranchHeavy,
    /// Vectorizable numeric/data-parallel programs.
    Vectorizable,
    /// Proof-specialised cryptographic/verification workloads.
    ProofSpecialized,
    /// Native-addon / FFI boundary workloads.
    NativeAddon,
    /// Hostcall-boundary workloads.
    HostcallBoundary,
    /// Startup-image cold-start workloads.
    StartupImage,
    /// Metadata-locality workloads.
    MetadataLocality,
    /// Observability-sensitive telemetry workloads.
    ObservabilitySensitive,
    /// Resource-spiky allocation/GC-pressure workloads.
    ResourceSpiky,
}

impl WorkloadFamily {
    /// All recognised families in canonical order.
    pub const ALL: &[Self] = &[
        Self::BranchHeavy,
        Self::Vectorizable,
        Self::ProofSpecialized,
        Self::NativeAddon,
        Self::HostcallBoundary,
        Self::StartupImage,
        Self::MetadataLocality,
        Self::ObservabilitySensitive,
        Self::ResourceSpiky,
    ];

    /// Stable snake_case tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BranchHeavy => "branch_heavy",
            Self::Vectorizable => "vectorizable",
            Self::ProofSpecialized => "proof_specialized",
            Self::NativeAddon => "native_addon",
            Self::HostcallBoundary => "hostcall_boundary",
            Self::StartupImage => "startup_image",
            Self::MetadataLocality => "metadata_locality",
            Self::ObservabilitySensitive => "observability_sensitive",
            Self::ResourceSpiky => "resource_spiky",
        }
    }
}

impl fmt::Display for WorkloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SaturationVerdict
// ---------------------------------------------------------------------------

/// Verdict on coverage saturation of the benchmark board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaturationVerdict {
    /// Board covers all families with sufficient depth.
    Saturated,
    /// Board covers most families but has minor gaps.
    NearSaturated,
    /// Board coverage is thin across many families.
    Sparse,
    /// Board appears to be a narrow cherry-picked slice.
    CherryPicked,
    /// Not enough data to determine saturation.
    InsufficientData,
}

impl SaturationVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Saturated => "saturated",
            Self::NearSaturated => "near_saturated",
            Self::Sparse => "sparse",
            Self::CherryPicked => "cherry_picked",
            Self::InsufficientData => "insufficient_data",
        }
    }

    /// Whether this verdict is acceptable for gating.
    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::Saturated | Self::NearSaturated)
    }
}

impl fmt::Display for SaturationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RepresentativenessLevel
// ---------------------------------------------------------------------------

/// How representative the benchmark distribution is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentativenessLevel {
    /// Distribution closely mirrors expected workload mix.
    Representative,
    /// Distribution is acceptable but slightly skewed.
    MarginallyRepresentative,
    /// Distribution is noticeably skewed toward some families.
    Skewed,
    /// Distribution is dominated by one or few families.
    Unrepresentative,
}

impl RepresentativenessLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Representative => "representative",
            Self::MarginallyRepresentative => "marginally_representative",
            Self::Skewed => "skewed",
            Self::Unrepresentative => "unrepresentative",
        }
    }

    /// Whether this level is acceptable for gating.
    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::Representative | Self::MarginallyRepresentative)
    }
}

impl fmt::Display for RepresentativenessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// Final gate decision combining saturation and representativeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// Board passes all checks.
    Pass,
    /// Board passes with conditions (some minor gaps).
    ConditionalPass,
    /// Board fails — coverage or representativeness is inadequate.
    Fail,
    /// Not enough evidence to make a decision.
    InsufficientEvidence,
}

impl GateDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ConditionalPass => "conditional_pass",
            Self::Fail => "fail",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }

    /// Whether this decision allows the board to proceed.
    pub fn allows_proceed(self) -> bool {
        matches!(self, Self::Pass | Self::ConditionalPass)
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FamilyCoverage
// ---------------------------------------------------------------------------

/// Coverage information for a single workload family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCoverage {
    /// Which family this coverage is for.
    pub family: WorkloadFamily,
    /// Number of workloads in this family.
    pub workload_count: u64,
    /// Total weight assigned to this family (millionths).
    pub total_weight: u64,
    /// Fraction of the family's space covered (millionths).
    pub coverage_fraction: u64,
    /// Largest gap in coverage within this family (millionths).
    pub max_gap_fraction: u64,
}

impl FamilyCoverage {
    /// Create a new coverage record.
    pub fn new(
        family: WorkloadFamily,
        workload_count: u64,
        total_weight: u64,
        coverage_fraction: u64,
        max_gap_fraction: u64,
    ) -> Self {
        Self {
            family,
            workload_count,
            total_weight,
            coverage_fraction,
            max_gap_fraction,
        }
    }

    /// Whether this family has any workloads at all.
    pub fn is_present(&self) -> bool {
        self.workload_count > 0
    }

    /// Whether coverage meets a threshold.
    pub fn meets_coverage(&self, threshold: u64) -> bool {
        self.coverage_fraction >= threshold
    }
}

// ---------------------------------------------------------------------------
// DistributionProfile
// ---------------------------------------------------------------------------

/// Aggregate distribution profile across all covered families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionProfile {
    /// Per-family coverage records.
    pub family_coverages: Vec<FamilyCoverage>,
    /// Gini coefficient of weight distribution (millionths, 0 = perfect equality).
    pub gini_coefficient: u64,
    /// Normalised entropy of weight distribution (millionths, 1_000_000 = max entropy).
    pub entropy: u64,
    /// Maximum share held by any single family (millionths).
    pub max_family_share: u64,
    /// Minimum share held by any family (millionths, 0 if a family is absent).
    pub min_family_share: u64,
}

// ---------------------------------------------------------------------------
// SaturationEvidence
// ---------------------------------------------------------------------------

/// Evidence record from a saturation evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationEvidence {
    /// The saturation verdict.
    pub verdict: SaturationVerdict,
    /// The distribution profile used.
    pub profile: DistributionProfile,
    /// Total number of workloads in the board.
    pub total_workloads: u64,
    /// Number of families with at least one workload.
    pub covered_families: usize,
    /// Epoch of this evidence.
    pub epoch: SecurityEpoch,
    /// Content hash of this evidence.
    pub receipt_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the coverage saturation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum number of families that must be covered.
    pub min_families_covered: usize,
    /// Minimum per-family coverage fraction (millionths).
    pub min_family_coverage_fraction: u64,
    /// Maximum Gini coefficient (millionths).
    pub max_gini_coefficient: u64,
    /// Minimum normalised entropy (millionths).
    pub min_entropy: u64,
    /// Maximum share any single family may hold (millionths).
    pub max_single_family_share: u64,
    /// Minimum workloads per family to count as covered.
    pub min_workloads_per_family: u64,
}

impl GateConfig {
    /// Strict configuration for production gating.
    pub fn strict() -> Self {
        Self {
            min_families_covered: TOTAL_WORKLOAD_FAMILIES,
            min_family_coverage_fraction: 200_000,
            max_gini_coefficient: 200_000,
            min_entropy: 900_000,
            max_single_family_share: 200_000,
            min_workloads_per_family: 5,
        }
    }

    /// Permissive configuration for development.
    pub fn permissive() -> Self {
        Self {
            min_families_covered: 1,
            min_family_coverage_fraction: 0,
            max_gini_coefficient: FIXED_ONE,
            min_entropy: 0,
            max_single_family_share: FIXED_ONE,
            min_workloads_per_family: 1,
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_families_covered: DEFAULT_MIN_FAMILIES_COVERED,
            min_family_coverage_fraction: DEFAULT_MIN_FAMILY_COVERAGE,
            max_gini_coefficient: DEFAULT_MAX_GINI,
            min_entropy: DEFAULT_MIN_ENTROPY,
            max_single_family_share: DEFAULT_MAX_SINGLE_FAMILY_SHARE,
            min_workloads_per_family: DEFAULT_MIN_WORKLOADS_PER_FAMILY,
        }
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Result of a full gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Final decision.
    pub decision: GateDecision,
    /// Saturation verdict.
    pub verdict: SaturationVerdict,
    /// Representativeness level.
    pub representativeness: RepresentativenessLevel,
    /// Reasons blocking a pass, if any.
    pub blocking_reasons: Vec<String>,
    /// Recommendations for improvement.
    pub recommendations: Vec<String>,
    /// Content hash of the result.
    pub receipt_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Tamper-evident receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
    /// Component that produced the receipt.
    pub component: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// The decision.
    pub decision: GateDecision,
    /// Hash of the underlying evidence.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Build a receipt from a gate result and epoch.
    pub fn from_result(result: &GateResult, epoch: SecurityEpoch) -> Self {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(COMPONENT.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(result.decision.as_str().as_bytes());
        h.update(result.receipt_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());

        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch,
            decision: result.decision,
            evidence_hash: result.receipt_hash.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// BatchResult
// ---------------------------------------------------------------------------

/// Results from evaluating multiple boards in a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResult {
    /// Individual results.
    pub results: Vec<GateResult>,
    /// Summary line.
    pub summary: String,
}

impl BatchResult {
    /// Build a batch result with an auto-generated summary.
    pub fn new(results: Vec<GateResult>) -> Self {
        let pass_count = results
            .iter()
            .filter(|r| r.decision == GateDecision::Pass)
            .count();
        let conditional_count = results
            .iter()
            .filter(|r| r.decision == GateDecision::ConditionalPass)
            .count();
        let fail_count = results
            .iter()
            .filter(|r| r.decision == GateDecision::Fail)
            .count();
        let insuf_count = results
            .iter()
            .filter(|r| r.decision == GateDecision::InsufficientEvidence)
            .count();
        let summary = format!(
            "{} evaluated: {} pass, {} conditional, {} fail, {} insufficient",
            results.len(),
            pass_count,
            conditional_count,
            fail_count,
            insuf_count,
        );
        Self { results, summary }
    }

    /// Number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Whether all results pass or conditionally pass.
    pub fn all_acceptable(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.decision.allows_proceed())
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute a distribution profile from per-family coverage records.
///
/// Computes Gini coefficient, normalised entropy, and share bounds.
/// All values in fixed-point millionths.
pub fn compute_coverage(families: &[FamilyCoverage]) -> DistributionProfile {
    if families.is_empty() {
        return DistributionProfile {
            family_coverages: Vec::new(),
            gini_coefficient: 0,
            entropy: 0,
            max_family_share: 0,
            min_family_share: 0,
        };
    }

    let total_weight: u64 = families.iter().map(|fc| fc.total_weight).sum();

    // Compute shares (millionths).
    let shares: Vec<u64> = families
        .iter()
        .map(|fc| {
            if total_weight == 0 {
                0
            } else {
                fc.total_weight
                    .saturating_mul(FIXED_ONE)
                    .checked_div(total_weight)
                    .unwrap_or(0)
            }
        })
        .collect();

    let max_family_share = shares.iter().copied().max().unwrap_or(0);
    let min_family_share = shares.iter().copied().min().unwrap_or(0);

    // Gini coefficient.
    let gini_coefficient = compute_gini(&shares);

    // Normalised entropy.
    let entropy = compute_normalised_entropy(&shares);

    DistributionProfile {
        family_coverages: families.to_vec(),
        gini_coefficient,
        entropy,
        max_family_share,
        min_family_share,
    }
}

/// Compute the Gini coefficient from a set of shares (each in millionths).
/// Returns value in millionths where 0 = perfect equality, 1_000_000 = max inequality.
fn compute_gini(shares: &[u64]) -> u64 {
    let n = shares.len() as u64;
    if n <= 1 {
        return 0;
    }

    let mean = shares
        .iter()
        .copied()
        .sum::<u64>()
        .checked_div(n)
        .unwrap_or(0);
    if mean == 0 {
        return 0;
    }

    // Sum of absolute differences.
    let mut abs_diff_sum: u128 = 0;
    for &a in shares {
        for &b in shares {
            abs_diff_sum += a.abs_diff(b) as u128;
        }
    }

    // Gini = sum_abs_diff / (2 * n * n * mean)
    // Scale to millionths.
    let denominator = 2u128 * (n as u128) * (n as u128) * (mean as u128);
    if denominator == 0 {
        return 0;
    }
    let gini_raw = abs_diff_sum
        .saturating_mul(FIXED_ONE as u128)
        .checked_div(denominator)
        .unwrap_or(0);
    // Clamp to FIXED_ONE.
    gini_raw.min(FIXED_ONE as u128) as u64
}

/// Compute normalised entropy from shares (each in millionths).
/// Returns value in millionths where 1_000_000 = maximum entropy (uniform).
fn compute_normalised_entropy(shares: &[u64]) -> u64 {
    let n = shares.len();
    if n <= 1 {
        return FIXED_ONE; // Single element is maximally entropic by convention.
    }

    // Maximum entropy = ln(n). We compute entropy as:
    // H = -sum(p * ln(p)) for each p > 0.
    // Normalised = H / ln(n).
    //
    // Since we work in fixed-point millionths, convert shares to f64 for
    // log computation, then convert back. This is deterministic because
    // the inputs are fixed-point and we only use the result as a millionths value.
    let total: u64 = shares.iter().sum();
    if total == 0 {
        return 0;
    }

    let max_entropy = (n as f64).ln();
    if max_entropy == 0.0 {
        return FIXED_ONE;
    }

    let mut entropy = 0.0_f64;
    for &s in shares {
        if s > 0 {
            let p = s as f64 / total as f64;
            entropy -= p * p.ln();
        }
    }

    let normalised = entropy / max_entropy;
    // Convert to millionths, clamped.
    let result = (normalised * FIXED_ONE as f64).round() as i64;
    result.clamp(0, FIXED_ONE as i64) as u64
}

/// Evaluate saturation of the benchmark board.
pub fn evaluate_saturation(
    profile: &DistributionProfile,
    config: &GateConfig,
) -> SaturationVerdict {
    if profile.family_coverages.is_empty() {
        return SaturationVerdict::InsufficientData;
    }

    let covered_families = profile
        .family_coverages
        .iter()
        .filter(|fc| fc.workload_count >= config.min_workloads_per_family)
        .count();

    let total_workloads: u64 = profile
        .family_coverages
        .iter()
        .map(|fc| fc.workload_count)
        .sum();

    if total_workloads == 0 {
        return SaturationVerdict::InsufficientData;
    }

    // Check if it's cherry-picked: very few families covered, high concentration.
    if covered_families <= 2 && profile.max_family_share > 500_000 {
        return SaturationVerdict::CherryPicked;
    }

    // All families meet coverage?
    let all_families_covered = profile
        .family_coverages
        .iter()
        .filter(|fc| fc.workload_count >= config.min_workloads_per_family)
        .all(|fc| fc.coverage_fraction >= config.min_family_coverage_fraction);

    if covered_families >= config.min_families_covered && all_families_covered {
        return SaturationVerdict::Saturated;
    }

    // Near-saturated: most families covered.
    let near_threshold = config.min_families_covered.saturating_sub(1).max(1);
    if covered_families >= near_threshold {
        return SaturationVerdict::NearSaturated;
    }

    SaturationVerdict::Sparse
}

/// Evaluate distributional representativeness.
pub fn evaluate_representativeness(
    profile: &DistributionProfile,
    config: &GateConfig,
) -> RepresentativenessLevel {
    if profile.family_coverages.is_empty() {
        return RepresentativenessLevel::Unrepresentative;
    }

    let gini_ok = profile.gini_coefficient <= config.max_gini_coefficient;
    let entropy_ok = profile.entropy >= config.min_entropy;
    let share_ok = profile.max_family_share <= config.max_single_family_share;

    if gini_ok && entropy_ok && share_ok {
        return RepresentativenessLevel::Representative;
    }

    // Count how many checks pass.
    let pass_count = [gini_ok, entropy_ok, share_ok]
        .iter()
        .filter(|&&x| x)
        .count();

    if pass_count >= 2 {
        return RepresentativenessLevel::MarginallyRepresentative;
    }

    if pass_count >= 1 {
        return RepresentativenessLevel::Skewed;
    }

    RepresentativenessLevel::Unrepresentative
}

/// Full evaluation: compute profile, saturation, representativeness, and produce
/// a `GateResult` with receipt hash.
pub fn evaluate(families: &[FamilyCoverage], config: &GateConfig) -> GateResult {
    let profile = compute_coverage(families);
    let verdict = evaluate_saturation(&profile, config);
    let representativeness = evaluate_representativeness(&profile, config);

    let mut blocking_reasons = Vec::new();
    let mut recommendations = Vec::new();

    // Collect blocking reasons.
    if !verdict.is_acceptable() {
        blocking_reasons.push(format!("saturation verdict: {verdict}"));
    }
    if !representativeness.is_acceptable() {
        blocking_reasons.push(format!("representativeness: {representativeness}"));
    }

    // Check per-family issues.
    let covered_count = profile
        .family_coverages
        .iter()
        .filter(|fc| fc.workload_count >= config.min_workloads_per_family)
        .count();
    if covered_count < config.min_families_covered {
        blocking_reasons.push(format!(
            "only {covered_count}/{} families covered",
            config.min_families_covered,
        ));
    }

    if profile.gini_coefficient > config.max_gini_coefficient {
        recommendations.push(format!(
            "reduce Gini from {} to below {}",
            profile.gini_coefficient, config.max_gini_coefficient,
        ));
    }
    if profile.entropy < config.min_entropy {
        recommendations.push(format!(
            "increase entropy from {} to above {}",
            profile.entropy, config.min_entropy,
        ));
    }
    if profile.max_family_share > config.max_single_family_share {
        recommendations.push(format!(
            "reduce max family share from {} to below {}",
            profile.max_family_share, config.max_single_family_share,
        ));
    }

    // Sparse families.
    for fc in &profile.family_coverages {
        if fc.workload_count > 0 && fc.workload_count < config.min_workloads_per_family {
            recommendations.push(format!(
                "add workloads to {}: {} < {}",
                fc.family, fc.workload_count, config.min_workloads_per_family,
            ));
        }
    }

    // Determine decision.
    let decision = if blocking_reasons.is_empty() {
        if recommendations.is_empty() {
            GateDecision::Pass
        } else {
            GateDecision::ConditionalPass
        }
    } else if verdict == SaturationVerdict::InsufficientData {
        GateDecision::InsufficientEvidence
    } else {
        GateDecision::Fail
    };

    // Compute receipt hash.
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(decision.as_str().as_bytes());
    h.update(verdict.as_str().as_bytes());
    h.update(representativeness.as_str().as_bytes());
    h.update((blocking_reasons.len() as u64).to_le_bytes());
    for reason in &blocking_reasons {
        h.update(reason.as_bytes());
    }
    let receipt_hash = ContentHash::compute(&h.finalize());

    GateResult {
        decision,
        verdict,
        representativeness,
        blocking_reasons,
        recommendations,
        receipt_hash,
    }
}

/// Build saturation evidence from a profile and verdict.
pub fn build_evidence(
    profile: &DistributionProfile,
    verdict: SaturationVerdict,
    epoch: SecurityEpoch,
) -> SaturationEvidence {
    let total_workloads: u64 = profile
        .family_coverages
        .iter()
        .map(|fc| fc.workload_count)
        .sum();
    let covered_families = profile
        .family_coverages
        .iter()
        .filter(|fc| fc.workload_count > 0)
        .count();

    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(verdict.as_str().as_bytes());
    h.update(epoch.as_u64().to_le_bytes());
    h.update(total_workloads.to_le_bytes());
    h.update((covered_families as u64).to_le_bytes());
    let receipt_hash = ContentHash::compute(&h.finalize());

    SaturationEvidence {
        verdict,
        profile: profile.clone(),
        total_workloads,
        covered_families,
        epoch,
        receipt_hash,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(500)
    }

    /// Build an equal-weight family coverage for testing.
    fn equal_families() -> Vec<FamilyCoverage> {
        WorkloadFamily::ALL
            .iter()
            .map(|&f| FamilyCoverage::new(f, 10, 111_111, 900_000, 50_000))
            .collect()
    }

    /// Build families where one family dominates.
    fn dominant_family() -> Vec<FamilyCoverage> {
        let mut fams: Vec<FamilyCoverage> = WorkloadFamily::ALL
            .iter()
            .map(|&f| FamilyCoverage::new(f, 5, 10_000, 500_000, 100_000))
            .collect();
        fams[0].total_weight = 900_000;
        fams[0].workload_count = 50;
        fams
    }

    /// Build a cherry-picked board: two families, rest absent.
    fn cherry_picked_families() -> Vec<FamilyCoverage> {
        vec![
            FamilyCoverage::new(WorkloadFamily::BranchHeavy, 20, 700_000, 950_000, 20_000),
            FamilyCoverage::new(WorkloadFamily::Vectorizable, 15, 300_000, 800_000, 50_000),
        ]
    }

    // -- Constants --

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("benchmark-coverage-saturation-gate"));
    }

    #[test]
    fn test_component_name() {
        assert_eq!(COMPONENT, "benchmark_coverage_saturation_gate");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-705E");
    }

    #[test]
    fn test_fixed_one() {
        assert_eq!(FIXED_ONE, 1_000_000);
    }

    #[test]
    fn test_total_workload_families() {
        assert_eq!(TOTAL_WORKLOAD_FAMILIES, WorkloadFamily::ALL.len());
    }

    // -- WorkloadFamily --

    #[test]
    fn test_workload_family_all_count() {
        assert_eq!(WorkloadFamily::ALL.len(), 9);
    }

    #[test]
    fn test_workload_family_display() {
        assert_eq!(WorkloadFamily::BranchHeavy.to_string(), "branch_heavy");
        assert_eq!(WorkloadFamily::Vectorizable.to_string(), "vectorizable");
        assert_eq!(
            WorkloadFamily::ProofSpecialized.to_string(),
            "proof_specialized"
        );
        assert_eq!(WorkloadFamily::NativeAddon.to_string(), "native_addon");
        assert_eq!(
            WorkloadFamily::HostcallBoundary.to_string(),
            "hostcall_boundary"
        );
        assert_eq!(WorkloadFamily::StartupImage.to_string(), "startup_image");
        assert_eq!(
            WorkloadFamily::MetadataLocality.to_string(),
            "metadata_locality"
        );
        assert_eq!(
            WorkloadFamily::ObservabilitySensitive.to_string(),
            "observability_sensitive"
        );
        assert_eq!(WorkloadFamily::ResourceSpiky.to_string(), "resource_spiky");
    }

    #[test]
    fn test_workload_family_serde_roundtrip() {
        for &f in WorkloadFamily::ALL {
            let json = serde_json::to_string(&f).unwrap();
            let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(f, back);
        }
    }

    #[test]
    fn test_workload_family_ordering() {
        // Canonical order check — BranchHeavy < Vectorizable etc.
        assert!(WorkloadFamily::BranchHeavy < WorkloadFamily::Vectorizable);
        assert!(WorkloadFamily::Vectorizable < WorkloadFamily::ProofSpecialized);
    }

    // -- SaturationVerdict --

    #[test]
    fn test_saturation_verdict_display() {
        assert_eq!(SaturationVerdict::Saturated.to_string(), "saturated");
        assert_eq!(
            SaturationVerdict::NearSaturated.to_string(),
            "near_saturated"
        );
        assert_eq!(SaturationVerdict::Sparse.to_string(), "sparse");
        assert_eq!(SaturationVerdict::CherryPicked.to_string(), "cherry_picked");
        assert_eq!(
            SaturationVerdict::InsufficientData.to_string(),
            "insufficient_data"
        );
    }

    #[test]
    fn test_saturation_verdict_acceptable() {
        assert!(SaturationVerdict::Saturated.is_acceptable());
        assert!(SaturationVerdict::NearSaturated.is_acceptable());
        assert!(!SaturationVerdict::Sparse.is_acceptable());
        assert!(!SaturationVerdict::CherryPicked.is_acceptable());
        assert!(!SaturationVerdict::InsufficientData.is_acceptable());
    }

    #[test]
    fn test_saturation_verdict_serde_roundtrip() {
        let v = SaturationVerdict::CherryPicked;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"cherry_picked\"");
        let back: SaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- RepresentativenessLevel --

    #[test]
    fn test_representativeness_display() {
        assert_eq!(
            RepresentativenessLevel::Representative.to_string(),
            "representative"
        );
        assert_eq!(
            RepresentativenessLevel::MarginallyRepresentative.to_string(),
            "marginally_representative"
        );
        assert_eq!(RepresentativenessLevel::Skewed.to_string(), "skewed");
        assert_eq!(
            RepresentativenessLevel::Unrepresentative.to_string(),
            "unrepresentative"
        );
    }

    #[test]
    fn test_representativeness_acceptable() {
        assert!(RepresentativenessLevel::Representative.is_acceptable());
        assert!(RepresentativenessLevel::MarginallyRepresentative.is_acceptable());
        assert!(!RepresentativenessLevel::Skewed.is_acceptable());
        assert!(!RepresentativenessLevel::Unrepresentative.is_acceptable());
    }

    #[test]
    fn test_representativeness_serde_roundtrip() {
        let v = RepresentativenessLevel::Skewed;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"skewed\"");
        let back: RepresentativenessLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- GateDecision --

    #[test]
    fn test_gate_decision_display() {
        assert_eq!(GateDecision::Pass.to_string(), "pass");
        assert_eq!(
            GateDecision::ConditionalPass.to_string(),
            "conditional_pass"
        );
        assert_eq!(GateDecision::Fail.to_string(), "fail");
        assert_eq!(
            GateDecision::InsufficientEvidence.to_string(),
            "insufficient_evidence"
        );
    }

    #[test]
    fn test_gate_decision_allows_proceed() {
        assert!(GateDecision::Pass.allows_proceed());
        assert!(GateDecision::ConditionalPass.allows_proceed());
        assert!(!GateDecision::Fail.allows_proceed());
        assert!(!GateDecision::InsufficientEvidence.allows_proceed());
    }

    #[test]
    fn test_gate_decision_serde_roundtrip() {
        for d in &[
            GateDecision::Pass,
            GateDecision::ConditionalPass,
            GateDecision::Fail,
            GateDecision::InsufficientEvidence,
        ] {
            let json = serde_json::to_string(d).unwrap();
            let back: GateDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // -- FamilyCoverage --

    #[test]
    fn test_family_coverage_construction() {
        let fc = FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 200_000, 800_000, 50_000);
        assert_eq!(fc.family, WorkloadFamily::BranchHeavy);
        assert_eq!(fc.workload_count, 10);
        assert_eq!(fc.total_weight, 200_000);
        assert_eq!(fc.coverage_fraction, 800_000);
        assert_eq!(fc.max_gap_fraction, 50_000);
    }

    #[test]
    fn test_family_coverage_is_present() {
        let present = FamilyCoverage::new(WorkloadFamily::Vectorizable, 5, 100_000, 500_000, 0);
        let absent = FamilyCoverage::new(WorkloadFamily::Vectorizable, 0, 0, 0, 0);
        assert!(present.is_present());
        assert!(!absent.is_present());
    }

    #[test]
    fn test_family_coverage_meets_coverage() {
        let fc = FamilyCoverage::new(WorkloadFamily::StartupImage, 3, 100_000, 500_000, 0);
        assert!(fc.meets_coverage(500_000));
        assert!(fc.meets_coverage(400_000));
        assert!(!fc.meets_coverage(600_000));
    }

    // -- DistributionProfile / compute_coverage --

    #[test]
    fn test_compute_coverage_empty() {
        let profile = compute_coverage(&[]);
        assert!(profile.family_coverages.is_empty());
        assert_eq!(profile.gini_coefficient, 0);
        assert_eq!(profile.entropy, 0);
        assert_eq!(profile.max_family_share, 0);
        assert_eq!(profile.min_family_share, 0);
    }

    #[test]
    fn test_compute_coverage_single_family() {
        let families = vec![FamilyCoverage::new(
            WorkloadFamily::BranchHeavy,
            10,
            FIXED_ONE,
            900_000,
            50_000,
        )];
        let profile = compute_coverage(&families);
        assert_eq!(profile.max_family_share, FIXED_ONE);
        assert_eq!(profile.min_family_share, FIXED_ONE);
        // Single family: Gini = 0, entropy = FIXED_ONE.
        assert_eq!(profile.gini_coefficient, 0);
        assert_eq!(profile.entropy, FIXED_ONE);
    }

    #[test]
    fn test_compute_coverage_equal_weights() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        // 9 families, all same weight.
        // Gini should be 0 (perfect equality).
        assert_eq!(profile.gini_coefficient, 0);
        // Entropy should be ~FIXED_ONE (maximum).
        assert!(
            profile.entropy >= 990_000,
            "entropy should be near max: {}",
            profile.entropy
        );
    }

    #[test]
    fn test_compute_coverage_dominant_family() {
        let families = dominant_family();
        let profile = compute_coverage(&families);
        // One family has 900k weight out of ~980k total → high share.
        assert!(
            profile.max_family_share > 500_000,
            "max share: {}",
            profile.max_family_share
        );
        // Gini should be high.
        assert!(
            profile.gini_coefficient > 200_000,
            "gini: {}",
            profile.gini_coefficient
        );
    }

    #[test]
    fn test_compute_coverage_preserves_families() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        assert_eq!(profile.family_coverages.len(), 9);
    }

    // -- Gini edge cases --

    #[test]
    fn test_gini_all_zero() {
        let shares = vec![0, 0, 0];
        assert_eq!(compute_gini(&shares), 0);
    }

    #[test]
    fn test_gini_perfect_equality() {
        let shares = vec![100_000; 5];
        assert_eq!(compute_gini(&shares), 0);
    }

    #[test]
    fn test_gini_maximum_inequality() {
        // One element has everything, rest have nothing.
        let shares = vec![FIXED_ONE, 0, 0, 0, 0];
        let gini = compute_gini(&shares);
        // Should be ~0.8 (= (n-1)/n = 4/5).
        assert!(gini > 700_000, "gini should be high: {gini}");
    }

    // -- Entropy edge cases --

    #[test]
    fn test_entropy_all_zero() {
        let shares = vec![0, 0, 0];
        assert_eq!(compute_normalised_entropy(&shares), 0);
    }

    #[test]
    fn test_entropy_uniform() {
        let shares = vec![100_000; 9];
        let e = compute_normalised_entropy(&shares);
        assert!(e >= 990_000, "entropy should be ~1M: {e}");
    }

    #[test]
    fn test_entropy_single_element() {
        let shares = vec![FIXED_ONE];
        let e = compute_normalised_entropy(&shares);
        assert_eq!(e, FIXED_ONE);
    }

    #[test]
    fn test_entropy_one_dominant() {
        // 99% in one, 1% in another.
        let shares = vec![990_000, 10_000];
        let e = compute_normalised_entropy(&shares);
        // Should be low.
        assert!(e < 200_000, "entropy should be low: {e}");
    }

    // -- evaluate_saturation --

    #[test]
    fn test_saturation_empty_is_insufficient() {
        let profile = compute_coverage(&[]);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_saturation(&profile, &config),
            SaturationVerdict::InsufficientData
        );
    }

    #[test]
    fn test_saturation_all_families_saturated() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_saturation(&profile, &config),
            SaturationVerdict::Saturated
        );
    }

    #[test]
    fn test_saturation_near_saturated() {
        // 6 families covered (just under default min of 7).
        let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
            .iter()
            .take(6)
            .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
            .collect();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_saturation(&profile, &config),
            SaturationVerdict::NearSaturated
        );
    }

    #[test]
    fn test_saturation_sparse() {
        // Only 3 families.
        let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
            .iter()
            .take(3)
            .map(|&f| FamilyCoverage::new(f, 5, 100_000, 500_000, 50_000))
            .collect();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_saturation(&profile, &config),
            SaturationVerdict::Sparse
        );
    }

    #[test]
    fn test_saturation_cherry_picked() {
        let families = cherry_picked_families();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_saturation(&profile, &config),
            SaturationVerdict::CherryPicked
        );
    }

    // -- evaluate_representativeness --

    #[test]
    fn test_representativeness_equal_families() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_representativeness(&profile, &config),
            RepresentativenessLevel::Representative
        );
    }

    #[test]
    fn test_representativeness_dominant_unrepresentative() {
        let families = dominant_family();
        let profile = compute_coverage(&families);
        let config = GateConfig::default();
        // One dominant family → high gini, low entropy, high share.
        let level = evaluate_representativeness(&profile, &config);
        assert!(
            !level.is_acceptable(),
            "expected skewed/unrepresentative, got {level}"
        );
    }

    #[test]
    fn test_representativeness_empty() {
        let profile = compute_coverage(&[]);
        let config = GateConfig::default();
        assert_eq!(
            evaluate_representativeness(&profile, &config),
            RepresentativenessLevel::Unrepresentative
        );
    }

    // -- Full evaluate --

    #[test]
    fn test_evaluate_pass() {
        let families = equal_families();
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        assert_eq!(result.decision, GateDecision::Pass);
        assert_eq!(result.verdict, SaturationVerdict::Saturated);
        assert_eq!(
            result.representativeness,
            RepresentativenessLevel::Representative
        );
        assert!(result.blocking_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_fail_cherry_picked() {
        let families = cherry_picked_families();
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        assert_eq!(result.decision, GateDecision::Fail);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_insufficient_evidence() {
        let families: Vec<FamilyCoverage> = Vec::new();
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        assert_eq!(result.decision, GateDecision::InsufficientEvidence);
    }

    #[test]
    fn test_evaluate_conditional_pass() {
        // All families present with good distribution but some have < min_workloads.
        let mut families = equal_families();
        // One family has only 2 workloads (below default min 3).
        families[4].workload_count = 2;
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        // Should still pass (8 out of 7 min) but with a recommendation.
        assert!(
            result.decision == GateDecision::Pass
                || result.decision == GateDecision::ConditionalPass,
            "decision: {:?}",
            result.decision
        );
    }

    #[test]
    fn test_evaluate_receipt_hash_deterministic() {
        let families = equal_families();
        let config = GateConfig::default();
        let r1 = evaluate(&families, &config);
        let r2 = evaluate(&families, &config);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    // -- GateConfig --

    #[test]
    fn test_gate_config_default() {
        let config = GateConfig::default();
        assert_eq!(config.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
        assert_eq!(
            config.min_family_coverage_fraction,
            DEFAULT_MIN_FAMILY_COVERAGE
        );
        assert_eq!(config.max_gini_coefficient, DEFAULT_MAX_GINI);
        assert_eq!(config.min_entropy, DEFAULT_MIN_ENTROPY);
        assert_eq!(
            config.max_single_family_share,
            DEFAULT_MAX_SINGLE_FAMILY_SHARE
        );
        assert_eq!(
            config.min_workloads_per_family,
            DEFAULT_MIN_WORKLOADS_PER_FAMILY
        );
    }

    #[test]
    fn test_gate_config_strict() {
        let strict = GateConfig::strict();
        assert_eq!(strict.min_families_covered, TOTAL_WORKLOAD_FAMILIES);
        assert!(strict.min_family_coverage_fraction > DEFAULT_MIN_FAMILY_COVERAGE);
    }

    #[test]
    fn test_gate_config_permissive() {
        let p = GateConfig::permissive();
        assert_eq!(p.min_families_covered, 1);
        assert_eq!(p.max_gini_coefficient, FIXED_ONE);
    }

    // -- DecisionReceipt --

    #[test]
    fn test_decision_receipt_from_result() {
        let families = equal_families();
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        let receipt = DecisionReceipt::from_result(&result, epoch());
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.epoch, epoch());
        assert_eq!(receipt.decision, result.decision);
        assert_eq!(receipt.evidence_hash, result.receipt_hash);
    }

    #[test]
    fn test_decision_receipt_deterministic() {
        let families = equal_families();
        let config = GateConfig::default();
        let result = evaluate(&families, &config);
        let r1 = DecisionReceipt::from_result(&result, epoch());
        let r2 = DecisionReceipt::from_result(&result, epoch());
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    // -- BatchResult --

    #[test]
    fn test_batch_result_empty() {
        let batch = BatchResult::new(Vec::new());
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
        assert!(!batch.all_acceptable());
    }

    #[test]
    fn test_batch_result_all_pass() {
        let families = equal_families();
        let config = GateConfig::default();
        let r1 = evaluate(&families, &config);
        let r2 = evaluate(&families, &config);
        let batch = BatchResult::new(vec![r1, r2]);
        assert_eq!(batch.len(), 2);
        assert!(batch.all_acceptable());
        assert!(batch.summary.contains("2 evaluated"));
        assert!(batch.summary.contains("2 pass"));
    }

    #[test]
    fn test_batch_result_mixed() {
        let good = evaluate(&equal_families(), &GateConfig::default());
        let bad = evaluate(&cherry_picked_families(), &GateConfig::default());
        let batch = BatchResult::new(vec![good, bad]);
        assert!(!batch.all_acceptable());
        assert!(batch.summary.contains("1 fail"));
    }

    // -- SaturationEvidence --

    #[test]
    fn test_build_evidence() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        let evidence = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
        assert_eq!(evidence.verdict, SaturationVerdict::Saturated);
        assert_eq!(evidence.total_workloads, 90); // 9 families * 10
        assert_eq!(evidence.covered_families, 9);
        assert_eq!(evidence.epoch, epoch());
    }

    #[test]
    fn test_build_evidence_hash_deterministic() {
        let families = equal_families();
        let profile = compute_coverage(&families);
        let e1 = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
        let e2 = build_evidence(&profile, SaturationVerdict::Saturated, epoch());
        assert_eq!(e1.receipt_hash, e2.receipt_hash);
    }

    // -- Edge cases --

    #[test]
    fn test_all_zero_weight_families() {
        let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
            .iter()
            .map(|&f| FamilyCoverage::new(f, 5, 0, 0, 0))
            .collect();
        let profile = compute_coverage(&families);
        // All zero weight → shares are all zero.
        assert_eq!(profile.gini_coefficient, 0);
        assert_eq!(profile.max_family_share, 0);
    }

    #[test]
    fn test_two_equal_families() {
        let families = vec![
            FamilyCoverage::new(WorkloadFamily::BranchHeavy, 10, 500_000, 800_000, 30_000),
            FamilyCoverage::new(WorkloadFamily::Vectorizable, 10, 500_000, 800_000, 30_000),
        ];
        let profile = compute_coverage(&families);
        assert_eq!(profile.gini_coefficient, 0);
        assert!(profile.entropy >= 990_000);
        assert_eq!(profile.max_family_share, profile.min_family_share);
    }

    #[test]
    fn test_evaluate_with_permissive_config() {
        // Even a cherry-picked board passes with permissive config.
        let families = cherry_picked_families();
        let config = GateConfig::permissive();
        let result = evaluate(&families, &config);
        assert!(
            result.decision.allows_proceed(),
            "permissive should pass: {:?}",
            result.decision
        );
    }

    #[test]
    fn test_evaluate_with_strict_config() {
        // Equal families might still fail strict if coverage fraction is low.
        let families: Vec<FamilyCoverage> = WorkloadFamily::ALL
            .iter()
            .map(|&f| FamilyCoverage::new(f, 10, 111_111, 150_000, 50_000))
            .collect();
        let config = GateConfig::strict();
        let result = evaluate(&families, &config);
        // 150_000 < strict min 200_000 → not all families meet coverage.
        assert_eq!(result.verdict, SaturationVerdict::NearSaturated);
    }
}
