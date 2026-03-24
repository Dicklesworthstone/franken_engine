#![forbid(unsafe_code)]

//! Adversarial workload synthesis and counterexample mining for supremacy claims.
//!
//! Bead: bd-1lsy.8.5.4 [RGC-705D]
//!
//! Red-teams supremacy claims with adversarial workload synthesis and
//! falsification search so the benchmark suite cannot be quietly overfit
//! to easy wins.  Every claim must survive a structured adversarial search
//! before it is allowed to stand.
//!
//! # Design
//!
//! - `SyntheticWorkload` models a single adversarial workload, content-addressed
//!   by its metadata so that identical workloads are deduplicated.
//! - `Counterexample` records a specific workload that contradicts a claim,
//!   together with the observed vs. expected performance gap.
//! - `FalsificationResult` aggregates counterexamples per claim and renders a
//!   verdict: falsified, weakened, survived, or insufficient search.
//! - `MiningConfig` controls generation budget, mutation rate, and coverage
//!   thresholds.
//! - `SynthesisReport` summarizes a full adversarial campaign across claims.
//! - `DecisionReceipt` captures an auditable hash trail for each verdict.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705D]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the adversarial supremacy synthesis module.
pub const SCHEMA_VERSION: &str = "franken-engine.adversarial-supremacy-synthesis.v1";

/// Component name.
pub const COMPONENT: &str = "adversarial_supremacy_synthesis";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.8.5.4";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705D";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum generations per mining run.
pub const DEFAULT_MAX_GENERATIONS: u64 = 100;

/// Default workloads per generation.
pub const DEFAULT_WORKLOADS_PER_GENERATION: u64 = 64;

/// Default mutation rate (millionths).  10% = 100_000.
pub const DEFAULT_MUTATION_RATE: u64 = 100_000;

/// Default minimum coverage fraction (millionths).  80% = 800_000.
pub const DEFAULT_MIN_COVERAGE: u64 = 800_000;

/// Default severity threshold — anything at or above `Minor` is reported.
pub const DEFAULT_SEVERITY_THRESHOLD: CounterexampleSeverity = CounterexampleSeverity::Minor;

/// Default maximum search budget (millionths).  100% = 1_000_000.
pub const DEFAULT_MAX_SEARCH_BUDGET: u64 = 1_000_000;

/// Gap fraction threshold for Critical severity (millionths).  50% = 500_000.
pub const CRITICAL_GAP_THRESHOLD: u64 = 500_000;

/// Gap fraction threshold for Major severity (millionths).  20% = 200_000.
pub const MAJOR_GAP_THRESHOLD: u64 = 200_000;

/// Gap fraction threshold for Minor severity (millionths).  5% = 50_000.
pub const MINOR_GAP_THRESHOLD: u64 = 50_000;

/// Number of strategy variants.
pub const STRATEGY_COUNT: usize = 6;

/// Number of archetype variants.
pub const ARCHETYPE_COUNT: usize = 8;

// ---------------------------------------------------------------------------
// SynthesisStrategy
// ---------------------------------------------------------------------------

/// Strategy used to synthesize adversarial workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisStrategy {
    /// Gradient-guided search towards claim boundaries.
    GradientGuided,
    /// Random mutation of existing workloads.
    RandomMutation,
    /// Coverage-directed search targeting unexplored regions.
    CoverageDirected,
    /// Recombination of patterns from multiple workloads.
    PatternRecombination,
    /// Probe claim boundaries with extreme parameter values.
    BoundaryProbe,
    /// Invert workload archetypes to create adversarial mismatch.
    ArchetypeInversion,
}

impl SynthesisStrategy {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::GradientGuided,
        Self::RandomMutation,
        Self::CoverageDirected,
        Self::PatternRecombination,
        Self::BoundaryProbe,
        Self::ArchetypeInversion,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GradientGuided => "gradient_guided",
            Self::RandomMutation => "random_mutation",
            Self::CoverageDirected => "coverage_directed",
            Self::PatternRecombination => "pattern_recombination",
            Self::BoundaryProbe => "boundary_probe",
            Self::ArchetypeInversion => "archetype_inversion",
        }
    }

    /// Base effectiveness multiplier for this strategy (millionths).
    ///
    /// Coverage-directed and gradient-guided tend to find counterexamples
    /// faster because they explore the claim surface intentionally.
    pub const fn effectiveness_multiplier(self) -> u64 {
        match self {
            Self::GradientGuided => 850_000,
            Self::RandomMutation => 400_000,
            Self::CoverageDirected => 900_000,
            Self::PatternRecombination => 600_000,
            Self::BoundaryProbe => 750_000,
            Self::ArchetypeInversion => 700_000,
        }
    }
}

impl fmt::Display for SynthesisStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CounterexampleSeverity
// ---------------------------------------------------------------------------

/// Severity of a discovered counterexample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleSeverity {
    /// Informational — gap below minor threshold.
    Informational,
    /// Minor deviation from claimed performance.
    Minor,
    /// Major deviation that weakens the claim significantly.
    Major,
    /// Critical — claim is likely false.
    Critical,
}

impl CounterexampleSeverity {
    /// All variants in canonical order (ascending severity).
    pub const ALL: &[Self] = &[
        Self::Informational,
        Self::Minor,
        Self::Major,
        Self::Critical,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Minor => "minor",
            Self::Major => "major",
            Self::Critical => "critical",
        }
    }

    /// Whether this severity meets or exceeds the given threshold.
    pub fn meets_threshold(self, threshold: Self) -> bool {
        self >= threshold
    }
}

impl fmt::Display for CounterexampleSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FalsificationVerdict
// ---------------------------------------------------------------------------

/// Verdict from a falsification search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FalsificationVerdict {
    /// The claim survived the search — no counterexamples found.
    Survived,
    /// The search was insufficient to draw conclusions.
    InsufficientSearch,
    /// The claim was weakened — counterexamples exist but below critical.
    Weakened,
    /// The claim was falsified — critical counterexample(s) found.
    Falsified,
}

impl FalsificationVerdict {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Survived,
        Self::InsufficientSearch,
        Self::Weakened,
        Self::Falsified,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Survived => "survived",
            Self::InsufficientSearch => "insufficient_search",
            Self::Weakened => "weakened",
            Self::Falsified => "falsified",
        }
    }

    /// Whether the verdict indicates the claim is still valid.
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Survived)
    }

    /// Whether the verdict indicates the claim is compromised.
    pub fn is_compromised(self) -> bool {
        matches!(self, Self::Falsified | Self::Weakened)
    }
}

impl fmt::Display for FalsificationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadArchetype
// ---------------------------------------------------------------------------

/// Classification of a synthetic workload's computational profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadArchetype {
    /// CPU-intensive computation.
    CpuBound,
    /// Memory-bandwidth-intensive workload.
    MemoryBound,
    /// I/O-intensive workload.
    IoBound,
    /// Latency-sensitive interactive workload.
    LatencySensitive,
    /// Branch-heavy control flow.
    BranchHeavy,
    /// Allocation-heavy workload.
    AllocationHeavy,
    /// Garbage-collection pressure workload.
    GcPressure,
    /// Mixed profile that combines multiple archetypes.
    MixedProfile,
}

impl WorkloadArchetype {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::CpuBound,
        Self::MemoryBound,
        Self::IoBound,
        Self::LatencySensitive,
        Self::BranchHeavy,
        Self::AllocationHeavy,
        Self::GcPressure,
        Self::MixedProfile,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CpuBound => "cpu_bound",
            Self::MemoryBound => "memory_bound",
            Self::IoBound => "io_bound",
            Self::LatencySensitive => "latency_sensitive",
            Self::BranchHeavy => "branch_heavy",
            Self::AllocationHeavy => "allocation_heavy",
            Self::GcPressure => "gc_pressure",
            Self::MixedProfile => "mixed_profile",
        }
    }

    /// Base complexity factor for this archetype (millionths).
    pub const fn base_complexity(self) -> u64 {
        match self {
            Self::CpuBound => 600_000,
            Self::MemoryBound => 500_000,
            Self::IoBound => 400_000,
            Self::LatencySensitive => 700_000,
            Self::BranchHeavy => 800_000,
            Self::AllocationHeavy => 550_000,
            Self::GcPressure => 650_000,
            Self::MixedProfile => 750_000,
        }
    }
}

impl fmt::Display for WorkloadArchetype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SyntheticWorkload
// ---------------------------------------------------------------------------

/// A single adversarial workload synthesized to probe a supremacy claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticWorkload {
    /// Unique identifier for this workload.
    pub workload_id: String,
    /// Computational archetype.
    pub archetype: WorkloadArchetype,
    /// Strategy used to create this workload.
    pub strategy: SynthesisStrategy,
    /// Content hash of the workload program.
    pub program_hash: ContentHash,
    /// Size of the workload program in bytes.
    pub size_bytes: u64,
    /// Complexity score (millionths).
    pub complexity_score: u64,
    /// Generation number in the evolutionary search.
    pub generation: u64,
    /// Security epoch under which this workload was created.
    pub epoch: SecurityEpoch,
}

impl SyntheticWorkload {
    /// Compute a deterministic content hash from workload metadata.
    fn compute_hash(
        workload_id: &str,
        archetype: WorkloadArchetype,
        strategy: SynthesisStrategy,
        seed: &[u8],
        generation: u64,
    ) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"adversarial-workload-v1:");
        h.update(workload_id.as_bytes());
        h.update(b":");
        h.update(archetype.as_str().as_bytes());
        h.update(b":");
        h.update(strategy.as_str().as_bytes());
        h.update(b":");
        h.update(seed);
        h.update(b":");
        h.update(generation.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for SyntheticWorkload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "workload[{}] arch={} strat={} gen={} complexity={}",
            self.workload_id, self.archetype, self.strategy, self.generation, self.complexity_score,
        )
    }
}

// ---------------------------------------------------------------------------
// Counterexample
// ---------------------------------------------------------------------------

/// A counterexample that contradicts a supremacy claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    /// The workload that produced this counterexample.
    pub workload: SyntheticWorkload,
    /// Severity of the discovered gap.
    pub severity: CounterexampleSeverity,
    /// The claim this counterexample targets.
    pub claim_id: String,
    /// Expected performance (millionths).
    pub expected_millionths: u64,
    /// Observed performance (millionths).
    pub observed_millionths: u64,
    /// Gap fraction between expected and observed (millionths).
    pub gap_fraction: u64,
    /// Human-readable explanation.
    pub explanation: String,
}

impl Counterexample {
    /// Whether this counterexample exceeds the given severity threshold.
    pub fn exceeds_threshold(&self, threshold: CounterexampleSeverity) -> bool {
        self.severity >= threshold
    }
}

impl fmt::Display for Counterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "counterexample[{}] claim={} severity={} gap={}",
            self.workload.workload_id, self.claim_id, self.severity, self.gap_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// FalsificationResult
// ---------------------------------------------------------------------------

/// Result of a falsification search for a single claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsificationResult {
    /// The claim being tested.
    pub claim_id: String,
    /// Verdict from the search.
    pub verdict: FalsificationVerdict,
    /// Counterexamples discovered during the search.
    pub counterexamples: Vec<Counterexample>,
    /// Total workloads tested.
    pub workloads_tested: u64,
    /// Fraction of the claim surface covered by the search (millionths).
    pub coverage_fraction: u64,
    /// Fraction of the search budget consumed (millionths).
    pub search_budget_used: u64,
    /// Security epoch for this result.
    pub epoch: SecurityEpoch,
}

impl FalsificationResult {
    /// Whether any critical counterexamples were found.
    pub fn has_critical(&self) -> bool {
        self.counterexamples
            .iter()
            .any(|c| c.severity == CounterexampleSeverity::Critical)
    }

    /// Whether any counterexamples at or above `Major` severity were found.
    pub fn has_major_or_worse(&self) -> bool {
        self.counterexamples
            .iter()
            .any(|c| c.severity >= CounterexampleSeverity::Major)
    }

    /// Count of counterexamples meeting the given severity threshold.
    pub fn count_at_severity(&self, threshold: CounterexampleSeverity) -> usize {
        self.counterexamples
            .iter()
            .filter(|c| c.severity >= threshold)
            .count()
    }

    /// The strongest (highest gap fraction) counterexample, if any.
    pub fn strongest_counterexample(&self) -> Option<&Counterexample> {
        self.counterexamples.iter().max_by_key(|c| c.gap_fraction)
    }
}

impl fmt::Display for FalsificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "falsification[{}] verdict={} counterexamples={} tested={} coverage={}",
            self.claim_id,
            self.verdict,
            self.counterexamples.len(),
            self.workloads_tested,
            self.coverage_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// MiningConfig
// ---------------------------------------------------------------------------

/// Configuration for the adversarial mining process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Maximum generations to run.
    pub max_generations: u64,
    /// Workloads synthesized per generation.
    pub workloads_per_generation: u64,
    /// Mutation rate (millionths).
    pub mutation_rate: u64,
    /// Minimum coverage fraction to achieve before stopping (millionths).
    pub min_coverage_fraction: u64,
    /// Minimum severity to include in counterexamples.
    pub severity_threshold: CounterexampleSeverity,
    /// Maximum search budget (millionths).
    pub max_search_budget: u64,
}

impl MiningConfig {
    /// Total maximum workloads across all generations.
    pub fn max_total_workloads(&self) -> u64 {
        self.max_generations
            .saturating_mul(self.workloads_per_generation)
    }

    /// Whether the given coverage fraction meets the minimum.
    pub fn coverage_sufficient(&self, coverage: u64) -> bool {
        coverage >= self.min_coverage_fraction
    }

    /// Whether the given budget usage exceeds the limit.
    pub fn budget_exhausted(&self, used: u64) -> bool {
        used >= self.max_search_budget
    }
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            max_generations: DEFAULT_MAX_GENERATIONS,
            workloads_per_generation: DEFAULT_WORKLOADS_PER_GENERATION,
            mutation_rate: DEFAULT_MUTATION_RATE,
            min_coverage_fraction: DEFAULT_MIN_COVERAGE,
            severity_threshold: DEFAULT_SEVERITY_THRESHOLD,
            max_search_budget: DEFAULT_MAX_SEARCH_BUDGET,
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesisReport
// ---------------------------------------------------------------------------

/// Summary report of an adversarial synthesis campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisReport {
    /// Total workloads synthesized across all claims.
    pub total_workloads: u64,
    /// Total counterexamples discovered.
    pub total_counterexamples: u64,
    /// Number of claims falsified.
    pub falsified_claims: u64,
    /// Number of claims weakened.
    pub weakened_claims: u64,
    /// Number of claims that survived.
    pub survived_claims: u64,
    /// The strongest counterexample across all claims.
    pub strongest_counterexample: Option<Counterexample>,
    /// Content hash over the entire report.
    pub receipt_hash: ContentHash,
}

impl SynthesisReport {
    /// Total claims evaluated.
    pub fn total_claims(&self) -> u64 {
        self.falsified_claims
            .saturating_add(self.weakened_claims)
            .saturating_add(self.survived_claims)
    }

    /// Falsification rate (millionths).
    pub fn falsification_rate(&self) -> u64 {
        let total = self.total_claims();
        self.falsified_claims
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Whether any claims were compromised (falsified or weakened).
    pub fn has_compromised_claims(&self) -> bool {
        self.falsified_claims > 0 || self.weakened_claims > 0
    }

    /// Whether all claims survived.
    pub fn all_survived(&self) -> bool {
        self.falsified_claims == 0 && self.weakened_claims == 0 && self.survived_claims > 0
    }
}

impl fmt::Display for SynthesisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "report: workloads={} counterexamples={} falsified={} weakened={} survived={}",
            self.total_workloads,
            self.total_counterexamples,
            self.falsified_claims,
            self.weakened_claims,
            self.survived_claims,
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for an adversarial synthesis decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Hash of the receipt itself.
    pub receipt_hash: ContentHash,
    /// Component that produced this receipt.
    pub component: String,
    /// Epoch under which this decision was made.
    pub epoch: SecurityEpoch,
    /// The verdict rendered.
    pub verdict: FalsificationVerdict,
    /// Hash of the evidence used to reach the verdict.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a receipt from a falsification result.
    pub fn from_result(result: &FalsificationResult) -> Self {
        let evidence_hash = Self::compute_evidence_hash(result);
        let receipt_hash = Self::compute_receipt_hash(&evidence_hash, result);
        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch: result.epoch,
            verdict: result.verdict,
            evidence_hash,
        }
    }

    fn compute_evidence_hash(result: &FalsificationResult) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"adversarial-evidence-v1:");
        h.update(result.claim_id.as_bytes());
        h.update(b":");
        h.update(result.verdict.as_str().as_bytes());
        h.update(b":");
        h.update(result.workloads_tested.to_le_bytes());
        h.update(b":");
        h.update(result.coverage_fraction.to_le_bytes());
        for ce in &result.counterexamples {
            h.update(ce.workload.workload_id.as_bytes());
            h.update(ce.gap_fraction.to_le_bytes());
        }
        ContentHash::compute(&h.finalize())
    }

    fn compute_receipt_hash(
        evidence_hash: &ContentHash,
        result: &FalsificationResult,
    ) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"adversarial-receipt-v1:");
        h.update(COMPONENT.as_bytes());
        h.update(b":");
        h.update(result.epoch.as_u64().to_le_bytes());
        h.update(b":");
        h.update(evidence_hash.as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}] verdict={} epoch={}",
            self.component,
            self.verdict,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Generate a single adversarial workload.
///
/// The workload is content-addressed from the archetype, strategy, generation,
/// and seed.  Complexity is derived from the archetype's base complexity
/// combined with the strategy's effectiveness multiplier.
pub fn generate_workload(
    archetype: WorkloadArchetype,
    strategy: SynthesisStrategy,
    generation: u64,
    seed: &[u8],
    epoch: SecurityEpoch,
) -> SyntheticWorkload {
    // Derive a unique ID from the inputs.
    let mut id_hasher = Sha256::new();
    id_hasher.update(b"workload-id:");
    id_hasher.update(archetype.as_str().as_bytes());
    id_hasher.update(b":");
    id_hasher.update(strategy.as_str().as_bytes());
    id_hasher.update(b":");
    id_hasher.update(generation.to_le_bytes());
    id_hasher.update(b":");
    id_hasher.update(seed);
    let id_hash = ContentHash::compute(&id_hasher.finalize());
    let workload_id = format!("wl-{}", &id_hash.to_hex()[..16]);

    // Compute complexity from archetype base and strategy multiplier.
    let base = archetype.base_complexity();
    let mult = strategy.effectiveness_multiplier();
    let complexity_score = base
        .saturating_mul(mult)
        .checked_div(MILLIONTHS)
        .unwrap_or(base);

    // Size is a deterministic function of generation and seed length.
    let size_bytes = 256_u64
        .saturating_add(generation.saturating_mul(16))
        .saturating_add(seed.len() as u64);

    let program_hash =
        SyntheticWorkload::compute_hash(&workload_id, archetype, strategy, seed, generation);

    SyntheticWorkload {
        workload_id,
        archetype,
        strategy,
        program_hash,
        size_bytes,
        complexity_score,
        generation,
        epoch,
    }
}

/// Classify the severity of a counterexample based on its gap fraction.
///
/// Gap fraction is in millionths.
pub fn classify_severity(gap_fraction: u64) -> CounterexampleSeverity {
    if gap_fraction >= CRITICAL_GAP_THRESHOLD {
        CounterexampleSeverity::Critical
    } else if gap_fraction >= MAJOR_GAP_THRESHOLD {
        CounterexampleSeverity::Major
    } else if gap_fraction >= MINOR_GAP_THRESHOLD {
        CounterexampleSeverity::Minor
    } else {
        CounterexampleSeverity::Informational
    }
}

/// Evaluate whether a workload constitutes a counterexample for a claim.
///
/// Returns `Some(Counterexample)` if observed < expected (i.e., the claim
/// overstates performance), `None` otherwise.
pub fn evaluate_counterexample(
    workload: &SyntheticWorkload,
    claim_id: &str,
    expected: u64,
    observed: u64,
) -> Option<Counterexample> {
    if observed >= expected {
        return None;
    }

    let gap = expected.saturating_sub(observed);
    let gap_fraction = gap
        .saturating_mul(MILLIONTHS)
        .checked_div(expected)
        .unwrap_or(0);

    let severity = classify_severity(gap_fraction);

    let explanation = format!(
        "{} workload (gen {}) showed {} vs expected {} (gap {:.1}%)",
        workload.archetype,
        workload.generation,
        observed,
        expected,
        gap_fraction as f64 / 10_000.0,
    );

    Some(Counterexample {
        workload: workload.clone(),
        severity,
        claim_id: claim_id.to_string(),
        expected_millionths: expected,
        observed_millionths: observed,
        gap_fraction,
        explanation,
    })
}

/// Synthesize a batch of adversarial workloads and test a claim.
///
/// Iterates through generations, producing workloads from the cross product
/// of archetypes and strategies.  For each workload, a deterministic
/// "observed" performance is derived from the workload's complexity and
/// generation, simulating the falsification process.
pub fn synthesize_batch(
    archetypes: &[WorkloadArchetype],
    strategies: &[SynthesisStrategy],
    claim_id: &str,
    config: &MiningConfig,
    epoch: SecurityEpoch,
) -> FalsificationResult {
    let mut counterexamples = Vec::new();
    let mut workloads_tested: u64 = 0;
    let max_total = config.max_total_workloads();

    for generation in 0..config.max_generations {
        for archetype in archetypes {
            for strategy in strategies {
                if workloads_tested >= max_total {
                    break;
                }

                // Derive a deterministic seed for this combination.
                let seed_data = format!(
                    "{claim_id}:{generation}:{}:{}",
                    archetype.as_str(),
                    strategy.as_str()
                );
                let workload = generate_workload(
                    *archetype,
                    *strategy,
                    generation,
                    seed_data.as_bytes(),
                    epoch,
                );

                // Simulate observed performance: base expectation is MILLIONTHS,
                // reduced by workload complexity and generation pressure.
                let expected = MILLIONTHS;
                let pressure = workload
                    .complexity_score
                    .saturating_mul(generation.saturating_add(1))
                    .checked_div(config.max_generations.max(1))
                    .unwrap_or(0);
                let observed = expected.saturating_sub(pressure);

                if let Some(ce) = evaluate_counterexample(&workload, claim_id, expected, observed)
                    && ce.severity.meets_threshold(config.severity_threshold)
                {
                    counterexamples.push(ce);
                }

                workloads_tested = workloads_tested.saturating_add(1);
            }
        }
    }

    // Compute coverage fraction: how much of the archetype x strategy space
    // was explored relative to the actual reachable space.
    let actual_space = config
        .max_generations
        .saturating_mul(archetypes.len() as u64)
        .saturating_mul(strategies.len() as u64);
    let coverage_denominator = max_total.min(actual_space).max(1);
    let coverage_fraction = workloads_tested
        .saturating_mul(MILLIONTHS)
        .checked_div(coverage_denominator)
        .unwrap_or(0);

    let search_budget_used = workloads_tested
        .saturating_mul(MILLIONTHS)
        .checked_div(max_total.max(1))
        .unwrap_or(0);

    // Determine verdict.
    let verdict = determine_verdict(&counterexamples, coverage_fraction, config);

    FalsificationResult {
        claim_id: claim_id.to_string(),
        verdict,
        counterexamples,
        workloads_tested,
        coverage_fraction,
        search_budget_used,
        epoch,
    }
}

/// Determine the falsification verdict from counterexamples and coverage.
fn determine_verdict(
    counterexamples: &[Counterexample],
    coverage_fraction: u64,
    config: &MiningConfig,
) -> FalsificationVerdict {
    if counterexamples.is_empty() {
        if coverage_fraction < config.min_coverage_fraction {
            return FalsificationVerdict::InsufficientSearch;
        }
        return FalsificationVerdict::Survived;
    }

    let has_critical = counterexamples
        .iter()
        .any(|c| c.severity == CounterexampleSeverity::Critical);

    if has_critical {
        FalsificationVerdict::Falsified
    } else {
        FalsificationVerdict::Weakened
    }
}

/// Summarize multiple falsification results into a single report.
pub fn summarize(results: &[FalsificationResult]) -> SynthesisReport {
    let total_workloads: u64 = results.iter().map(|r| r.workloads_tested).sum();
    let total_counterexamples: u64 = results.iter().map(|r| r.counterexamples.len() as u64).sum();
    let falsified_claims = results
        .iter()
        .filter(|r| r.verdict == FalsificationVerdict::Falsified)
        .count() as u64;
    let weakened_claims = results
        .iter()
        .filter(|r| r.verdict == FalsificationVerdict::Weakened)
        .count() as u64;
    let survived_claims = results
        .iter()
        .filter(|r| r.verdict == FalsificationVerdict::Survived)
        .count() as u64;

    // Find the strongest counterexample across all results.
    let strongest_counterexample = results
        .iter()
        .flat_map(|r| r.counterexamples.iter())
        .max_by_key(|c| c.gap_fraction)
        .cloned();

    // Compute receipt hash.
    let mut h = Sha256::new();
    h.update(b"adversarial-report-v1:");
    h.update(total_workloads.to_le_bytes());
    h.update(total_counterexamples.to_le_bytes());
    h.update(falsified_claims.to_le_bytes());
    h.update(weakened_claims.to_le_bytes());
    h.update(survived_claims.to_le_bytes());
    if let Some(ref sc) = strongest_counterexample {
        h.update(sc.workload.program_hash.as_bytes());
        h.update(sc.workload.workload_id.as_bytes());
        h.update(sc.workload.size_bytes.to_le_bytes());
        h.update(sc.gap_fraction.to_le_bytes());
        h.update(sc.severity.to_string().as_bytes());
        h.update(sc.claim_id.as_bytes());
        h.update(sc.expected_millionths.to_le_bytes());
        h.update(sc.observed_millionths.to_le_bytes());
    }
    let receipt_hash = ContentHash::compute(&h.finalize());

    SynthesisReport {
        total_workloads,
        total_counterexamples,
        falsified_claims,
        weakened_claims,
        survived_claims,
        strongest_counterexample,
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

    fn default_workload() -> SyntheticWorkload {
        generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"test-seed",
            epoch(),
        )
    }

    fn small_config() -> MiningConfig {
        MiningConfig {
            max_generations: 3,
            workloads_per_generation: 4,
            mutation_rate: 100_000,
            min_coverage_fraction: 800_000,
            severity_threshold: CounterexampleSeverity::Minor,
            max_search_budget: 1_000_000,
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "adversarial_supremacy_synthesis");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
        assert_eq!(BEAD_ID, "bd-1lsy.8.5.4");
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
        assert_eq!(POLICY_ID, "RGC-705D");
    }

    #[test]
    fn constant_invariants() {
        const {
            assert!(DEFAULT_MAX_GENERATIONS > 0);
            assert!(DEFAULT_WORKLOADS_PER_GENERATION > 0);
            assert!(DEFAULT_MUTATION_RATE > 0);
            assert!(DEFAULT_MUTATION_RATE <= MILLIONTHS);
            assert!(DEFAULT_MIN_COVERAGE > 0);
            assert!(DEFAULT_MIN_COVERAGE <= MILLIONTHS);
            assert!(DEFAULT_MAX_SEARCH_BUDGET > 0);
            assert!(CRITICAL_GAP_THRESHOLD > MAJOR_GAP_THRESHOLD);
            assert!(MAJOR_GAP_THRESHOLD > MINOR_GAP_THRESHOLD);
            assert!(MINOR_GAP_THRESHOLD > 0);
        }
        assert_eq!(STRATEGY_COUNT, SynthesisStrategy::ALL.len());
        assert_eq!(ARCHETYPE_COUNT, WorkloadArchetype::ALL.len());
    }

    // --- SynthesisStrategy ---

    #[test]
    fn strategy_all_length() {
        assert_eq!(SynthesisStrategy::ALL.len(), 6);
    }

    #[test]
    fn strategy_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            SynthesisStrategy::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), SynthesisStrategy::ALL.len());
    }

    #[test]
    fn strategy_display_matches_as_str() {
        for s in SynthesisStrategy::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn strategy_serde_roundtrip() {
        for s in SynthesisStrategy::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: SynthesisStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn strategy_effectiveness_positive() {
        for s in SynthesisStrategy::ALL {
            assert!(s.effectiveness_multiplier() > 0);
            assert!(s.effectiveness_multiplier() <= MILLIONTHS);
        }
    }

    // --- CounterexampleSeverity ---

    #[test]
    fn severity_all_length() {
        assert_eq!(CounterexampleSeverity::ALL.len(), 4);
    }

    #[test]
    fn severity_ordering() {
        assert!(CounterexampleSeverity::Informational < CounterexampleSeverity::Minor);
        assert!(CounterexampleSeverity::Minor < CounterexampleSeverity::Major);
        assert!(CounterexampleSeverity::Major < CounterexampleSeverity::Critical);
    }

    #[test]
    fn severity_meets_threshold() {
        assert!(CounterexampleSeverity::Critical.meets_threshold(CounterexampleSeverity::Minor));
        assert!(CounterexampleSeverity::Minor.meets_threshold(CounterexampleSeverity::Minor));
        assert!(
            !CounterexampleSeverity::Informational.meets_threshold(CounterexampleSeverity::Minor)
        );
    }

    #[test]
    fn severity_serde_roundtrip() {
        for s in CounterexampleSeverity::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CounterexampleSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn severity_display() {
        for s in CounterexampleSeverity::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    // --- FalsificationVerdict ---

    #[test]
    fn verdict_all_length() {
        assert_eq!(FalsificationVerdict::ALL.len(), 4);
    }

    #[test]
    fn verdict_is_valid() {
        assert!(FalsificationVerdict::Survived.is_valid());
        assert!(!FalsificationVerdict::Falsified.is_valid());
        assert!(!FalsificationVerdict::Weakened.is_valid());
        assert!(!FalsificationVerdict::InsufficientSearch.is_valid());
    }

    #[test]
    fn verdict_is_compromised() {
        assert!(FalsificationVerdict::Falsified.is_compromised());
        assert!(FalsificationVerdict::Weakened.is_compromised());
        assert!(!FalsificationVerdict::Survived.is_compromised());
        assert!(!FalsificationVerdict::InsufficientSearch.is_compromised());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in FalsificationVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: FalsificationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn verdict_display() {
        for v in FalsificationVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    // --- WorkloadArchetype ---

    #[test]
    fn archetype_all_length() {
        assert_eq!(WorkloadArchetype::ALL.len(), 8);
    }

    #[test]
    fn archetype_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            WorkloadArchetype::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names.len(), WorkloadArchetype::ALL.len());
    }

    #[test]
    fn archetype_base_complexity_positive() {
        for a in WorkloadArchetype::ALL {
            assert!(a.base_complexity() > 0);
            assert!(a.base_complexity() <= MILLIONTHS);
        }
    }

    #[test]
    fn archetype_serde_roundtrip() {
        for a in WorkloadArchetype::ALL {
            let json = serde_json::to_string(a).unwrap();
            let back: WorkloadArchetype = serde_json::from_str(&json).unwrap();
            assert_eq!(*a, back);
        }
    }

    #[test]
    fn archetype_display() {
        for a in WorkloadArchetype::ALL {
            assert_eq!(a.to_string(), a.as_str());
        }
    }

    // --- SyntheticWorkload ---

    #[test]
    fn generate_workload_deterministic() {
        let w1 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            5,
            b"seed-a",
            epoch(),
        );
        let w2 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            5,
            b"seed-a",
            epoch(),
        );
        assert_eq!(w1.workload_id, w2.workload_id);
        assert_eq!(w1.program_hash, w2.program_hash);
        assert_eq!(w1.complexity_score, w2.complexity_score);
    }

    #[test]
    fn generate_workload_different_seeds() {
        let w1 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"seed-a",
            epoch(),
        );
        let w2 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"seed-b",
            epoch(),
        );
        assert_ne!(w1.workload_id, w2.workload_id);
        assert_ne!(w1.program_hash, w2.program_hash);
    }

    #[test]
    fn generate_workload_different_archetypes() {
        let w1 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"seed",
            epoch(),
        );
        let w2 = generate_workload(
            WorkloadArchetype::MemoryBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"seed",
            epoch(),
        );
        assert_ne!(w1.workload_id, w2.workload_id);
        assert_ne!(w1.complexity_score, w2.complexity_score);
    }

    #[test]
    fn generate_workload_complexity_varies_by_strategy() {
        let w1 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::RandomMutation,
            0,
            b"seed",
            epoch(),
        );
        let w2 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::CoverageDirected,
            0,
            b"seed",
            epoch(),
        );
        // CoverageDirected has higher effectiveness than RandomMutation.
        assert!(w2.complexity_score > w1.complexity_score);
    }

    #[test]
    fn workload_id_has_prefix() {
        let w = default_workload();
        assert!(w.workload_id.starts_with("wl-"));
    }

    #[test]
    fn workload_display() {
        let w = default_workload();
        let s = w.to_string();
        assert!(s.contains("workload["));
        assert!(s.contains("arch="));
        assert!(s.contains("strat="));
    }

    #[test]
    fn workload_size_increases_with_generation() {
        let w0 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            0,
            b"seed",
            epoch(),
        );
        let w10 = generate_workload(
            WorkloadArchetype::CpuBound,
            SynthesisStrategy::GradientGuided,
            10,
            b"seed",
            epoch(),
        );
        assert!(w10.size_bytes > w0.size_bytes);
    }

    // --- classify_severity ---

    #[test]
    fn classify_critical() {
        assert_eq!(classify_severity(500_000), CounterexampleSeverity::Critical);
        assert_eq!(classify_severity(999_999), CounterexampleSeverity::Critical);
    }

    #[test]
    fn classify_major() {
        assert_eq!(classify_severity(200_000), CounterexampleSeverity::Major);
        assert_eq!(classify_severity(499_999), CounterexampleSeverity::Major);
    }

    #[test]
    fn classify_minor() {
        assert_eq!(classify_severity(50_000), CounterexampleSeverity::Minor);
        assert_eq!(classify_severity(199_999), CounterexampleSeverity::Minor);
    }

    #[test]
    fn classify_informational() {
        assert_eq!(classify_severity(0), CounterexampleSeverity::Informational);
        assert_eq!(
            classify_severity(49_999),
            CounterexampleSeverity::Informational
        );
    }

    // --- evaluate_counterexample ---

    #[test]
    fn evaluate_no_counterexample_when_observed_meets_expected() {
        let w = default_workload();
        assert!(evaluate_counterexample(&w, "claim-1", 1_000_000, 1_000_000).is_none());
    }

    #[test]
    fn evaluate_no_counterexample_when_observed_exceeds_expected() {
        let w = default_workload();
        assert!(evaluate_counterexample(&w, "claim-1", 500_000, 600_000).is_none());
    }

    #[test]
    fn evaluate_counterexample_minor_gap() {
        let w = default_workload();
        // 10% gap => 100_000 millionths gap fraction => Minor.
        let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 900_000).unwrap();
        assert_eq!(ce.severity, CounterexampleSeverity::Minor);
        assert_eq!(ce.claim_id, "claim-1");
        assert_eq!(ce.expected_millionths, 1_000_000);
        assert_eq!(ce.observed_millionths, 900_000);
        assert_eq!(ce.gap_fraction, 100_000);
    }

    #[test]
    fn evaluate_counterexample_critical_gap() {
        let w = default_workload();
        // 60% gap => 600_000 millionths gap fraction => Critical.
        let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 400_000).unwrap();
        assert_eq!(ce.severity, CounterexampleSeverity::Critical);
        assert_eq!(ce.gap_fraction, 600_000);
    }

    #[test]
    fn evaluate_counterexample_expected_zero() {
        let w = default_workload();
        // expected=0, observed=0 => observed >= expected, no counterexample.
        assert!(evaluate_counterexample(&w, "claim-1", 0, 0).is_none());
    }

    #[test]
    fn counterexample_exceeds_threshold() {
        let w = default_workload();
        let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 700_000).unwrap();
        assert!(ce.exceeds_threshold(CounterexampleSeverity::Minor));
        assert!(ce.exceeds_threshold(CounterexampleSeverity::Major));
        assert!(!ce.exceeds_threshold(CounterexampleSeverity::Critical));
    }

    #[test]
    fn counterexample_display() {
        let w = default_workload();
        let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 700_000).unwrap();
        let s = ce.to_string();
        assert!(s.contains("counterexample["));
        assert!(s.contains("claim="));
        assert!(s.contains("severity="));
    }

    // --- MiningConfig ---

    #[test]
    fn mining_config_default() {
        let c = MiningConfig::default();
        assert_eq!(c.max_generations, DEFAULT_MAX_GENERATIONS);
        assert_eq!(c.workloads_per_generation, DEFAULT_WORKLOADS_PER_GENERATION);
        assert_eq!(c.mutation_rate, DEFAULT_MUTATION_RATE);
        assert_eq!(c.min_coverage_fraction, DEFAULT_MIN_COVERAGE);
        assert_eq!(c.severity_threshold, DEFAULT_SEVERITY_THRESHOLD);
        assert_eq!(c.max_search_budget, DEFAULT_MAX_SEARCH_BUDGET);
    }

    #[test]
    fn mining_config_max_total_workloads() {
        let c = small_config();
        assert_eq!(c.max_total_workloads(), 12);
    }

    #[test]
    fn mining_config_coverage_sufficient() {
        let c = small_config();
        assert!(c.coverage_sufficient(800_000));
        assert!(c.coverage_sufficient(1_000_000));
        assert!(!c.coverage_sufficient(799_999));
    }

    #[test]
    fn mining_config_budget_exhausted() {
        let c = small_config();
        assert!(c.budget_exhausted(1_000_000));
        assert!(!c.budget_exhausted(999_999));
    }

    // --- synthesize_batch ---

    #[test]
    fn synthesize_batch_single_archetype_strategy() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-1",
            &config,
            epoch(),
        );
        assert_eq!(result.claim_id, "claim-1");
        assert!(result.workloads_tested > 0);
        assert!(result.coverage_fraction > 0);
    }

    #[test]
    fn synthesize_batch_multiple_archetypes() {
        let config = MiningConfig {
            max_generations: 2,
            workloads_per_generation: 20,
            ..small_config()
        };
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound, WorkloadArchetype::MemoryBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-2",
            &config,
            epoch(),
        );
        assert!(result.workloads_tested > 0);
    }

    #[test]
    fn synthesize_batch_empty_archetypes() {
        let config = small_config();
        let result = synthesize_batch(
            &[],
            &[SynthesisStrategy::GradientGuided],
            "claim-3",
            &config,
            epoch(),
        );
        assert_eq!(result.workloads_tested, 0);
        // No workloads => insufficient coverage => InsufficientSearch.
        assert_eq!(result.verdict, FalsificationVerdict::InsufficientSearch);
    }

    #[test]
    fn synthesize_batch_verdict_deterministic() {
        let config = small_config();
        let r1 = synthesize_batch(
            &[WorkloadArchetype::BranchHeavy],
            &[SynthesisStrategy::CoverageDirected],
            "claim-det",
            &config,
            epoch(),
        );
        let r2 = synthesize_batch(
            &[WorkloadArchetype::BranchHeavy],
            &[SynthesisStrategy::CoverageDirected],
            "claim-det",
            &config,
            epoch(),
        );
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.workloads_tested, r2.workloads_tested);
        assert_eq!(r1.counterexamples.len(), r2.counterexamples.len());
    }

    // --- FalsificationResult ---

    #[test]
    fn falsification_result_has_critical() {
        let config = MiningConfig {
            max_generations: 10,
            workloads_per_generation: 20,
            severity_threshold: CounterexampleSeverity::Informational,
            ..small_config()
        };
        let result = synthesize_batch(
            &[WorkloadArchetype::BranchHeavy],
            &[SynthesisStrategy::CoverageDirected],
            "claim-crit",
            &config,
            epoch(),
        );
        // BranchHeavy (800k) x CoverageDirected (900k) = 720k complexity.
        // At high generations, gap will be critical.
        if result.has_critical() {
            assert_eq!(result.verdict, FalsificationVerdict::Falsified);
        }
    }

    #[test]
    fn falsification_result_count_at_severity() {
        let config = MiningConfig {
            max_generations: 5,
            workloads_per_generation: 10,
            severity_threshold: CounterexampleSeverity::Informational,
            ..small_config()
        };
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::RandomMutation],
            "claim-cnt",
            &config,
            epoch(),
        );
        let total_ce = result.counterexamples.len();
        let major_plus = result.count_at_severity(CounterexampleSeverity::Major);
        let critical_only = result.count_at_severity(CounterexampleSeverity::Critical);
        assert!(major_plus <= total_ce);
        assert!(critical_only <= major_plus);
    }

    #[test]
    fn falsification_result_strongest() {
        let config = MiningConfig {
            max_generations: 5,
            workloads_per_generation: 10,
            severity_threshold: CounterexampleSeverity::Informational,
            ..small_config()
        };
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-str",
            &config,
            epoch(),
        );
        if let Some(strongest) = result.strongest_counterexample() {
            for ce in &result.counterexamples {
                assert!(strongest.gap_fraction >= ce.gap_fraction);
            }
        }
    }

    #[test]
    fn falsification_result_display() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-disp",
            &config,
            epoch(),
        );
        let s = result.to_string();
        assert!(s.contains("falsification["));
        assert!(s.contains("verdict="));
    }

    // --- summarize ---

    #[test]
    fn summarize_empty() {
        let report = summarize(&[]);
        assert_eq!(report.total_workloads, 0);
        assert_eq!(report.total_counterexamples, 0);
        assert_eq!(report.falsified_claims, 0);
        assert_eq!(report.weakened_claims, 0);
        assert_eq!(report.survived_claims, 0);
        assert!(report.strongest_counterexample.is_none());
    }

    #[test]
    fn summarize_single_result() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-s1",
            &config,
            epoch(),
        );
        let report = summarize(std::slice::from_ref(&result));
        assert_eq!(report.total_workloads, result.workloads_tested);
        assert_eq!(
            report.total_counterexamples,
            result.counterexamples.len() as u64
        );
        assert_eq!(report.total_claims(), 1);
    }

    #[test]
    fn summarize_multiple_results() {
        let config = small_config();
        let r1 = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-m1",
            &config,
            epoch(),
        );
        let r2 = synthesize_batch(
            &[WorkloadArchetype::MemoryBound],
            &[SynthesisStrategy::BoundaryProbe],
            "claim-m2",
            &config,
            epoch(),
        );
        let report = summarize(&[r1.clone(), r2.clone()]);
        assert_eq!(
            report.total_workloads,
            r1.workloads_tested + r2.workloads_tested,
        );
        assert_eq!(report.total_claims(), 2);
    }

    #[test]
    fn summarize_falsification_rate() {
        let report = SynthesisReport {
            total_workloads: 100,
            total_counterexamples: 10,
            falsified_claims: 1,
            weakened_claims: 1,
            survived_claims: 2,
            strongest_counterexample: None,
            receipt_hash: ContentHash::compute(b"test"),
        };
        // 1 falsified out of 4 total => 250_000 millionths.
        assert_eq!(report.falsification_rate(), 250_000);
    }

    #[test]
    fn summarize_all_survived() {
        let report = SynthesisReport {
            total_workloads: 100,
            total_counterexamples: 0,
            falsified_claims: 0,
            weakened_claims: 0,
            survived_claims: 3,
            strongest_counterexample: None,
            receipt_hash: ContentHash::compute(b"test"),
        };
        assert!(report.all_survived());
        assert!(!report.has_compromised_claims());
    }

    #[test]
    fn summarize_has_compromised() {
        let report = SynthesisReport {
            total_workloads: 100,
            total_counterexamples: 5,
            falsified_claims: 1,
            weakened_claims: 0,
            survived_claims: 2,
            strongest_counterexample: None,
            receipt_hash: ContentHash::compute(b"test"),
        };
        assert!(report.has_compromised_claims());
        assert!(!report.all_survived());
    }

    #[test]
    fn report_display() {
        let report = summarize(&[]);
        let s = report.to_string();
        assert!(s.contains("report:"));
        assert!(s.contains("workloads="));
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_from_result() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-rcpt",
            &config,
            epoch(),
        );
        let receipt = DecisionReceipt::from_result(&result);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.epoch, epoch());
        assert_eq!(receipt.verdict, result.verdict);
    }

    #[test]
    fn receipt_deterministic() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-det-r",
            &config,
            epoch(),
        );
        let r1 = DecisionReceipt::from_result(&result);
        let r2 = DecisionReceipt::from_result(&result);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
        assert_eq!(r1.evidence_hash, r2.evidence_hash);
    }

    #[test]
    fn receipt_display() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-d",
            &config,
            epoch(),
        );
        let receipt = DecisionReceipt::from_result(&result);
        let s = receipt.to_string();
        assert!(s.contains("receipt["));
        assert!(s.contains("verdict="));
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-ser",
            &config,
            epoch(),
        );
        let receipt = DecisionReceipt::from_result(&result);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- Workload serde ---

    #[test]
    fn workload_serde_roundtrip() {
        let w = default_workload();
        let json = serde_json::to_string(&w).unwrap();
        let back: SyntheticWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    // --- Counterexample serde ---

    #[test]
    fn counterexample_serde_roundtrip() {
        let w = default_workload();
        let ce = evaluate_counterexample(&w, "claim-1", 1_000_000, 700_000).unwrap();
        let json = serde_json::to_string(&ce).unwrap();
        let back: Counterexample = serde_json::from_str(&json).unwrap();
        assert_eq!(ce, back);
    }

    // --- FalsificationResult serde ---

    #[test]
    fn falsification_result_serde_roundtrip() {
        let config = small_config();
        let result = synthesize_batch(
            &[WorkloadArchetype::CpuBound],
            &[SynthesisStrategy::GradientGuided],
            "claim-fser",
            &config,
            epoch(),
        );
        let json = serde_json::to_string(&result).unwrap();
        let back: FalsificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }
}
