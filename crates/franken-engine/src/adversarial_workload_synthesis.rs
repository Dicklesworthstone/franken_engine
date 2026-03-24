//! Adversarial workload synthesis and counterexample mining for supremacy claims.
//!
//! Bead: bd-1lsy.8.5.4 [RGC-705D]
//!
//! Red-teams the supremacy claim with adversarial workload synthesis and
//! falsification search so the benchmark suite cannot be quietly overfit to
//! easy wins.  Every domain that the supremacy claim covers must be probed
//! with synthesised adversarial workloads; discovered counterexamples carry
//! regression magnitudes and provenance hashes for audit.
//!
//! # Design
//!
//! - `WorkloadDomain`: twelve workload surfaces the claim must defend.
//! - `FalsificationStrategy`: six counterexample-mining strategies.
//! - `SynthesisInput`: a seed workload with domain, IR hash, and complexity.
//! - `Counterexample`: an adversarial workload that falsifies a supremacy claim.
//! - `SynthesisConfig`: iteration budget, regression threshold, domain/strategy sets.
//! - `SynthesisCampaign`: tracks one full synthesis campaign with coverage.
//! - `SynthesisVerdict`: four-valued outcome (Fortified, Falsified, Incomplete,
//!   InfrastructureFailure).
//! - `SynthesisReport`: aggregated multi-campaign report with worst-case tracking.
//! - `SynthesisEngine`: orchestrates campaigns, refuses Fortified unless all
//!   configured domains are covered and iteration thresholds are met.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705D]

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
pub const SCHEMA_VERSION: &str = "franken-engine.adversarial-workload-synthesis.v1";

/// Component name.
pub const COMPONENT: &str = "adversarial_workload_synthesis";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.5.4";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705D";

/// One in fixed-point millionths.
const MILLIONTHS: u64 = 1_000_000;

/// Default minimum iterations per domain before a Fortified verdict is allowed.
pub const DEFAULT_MIN_ITERATIONS_PER_DOMAIN: u64 = 100;

/// Default minimum regression threshold in millionths (5% = 50_000).
pub const DEFAULT_MIN_REGRESSION_THRESHOLD: u64 = 50_000;

/// Default budget in nanoseconds (10 seconds).
pub const DEFAULT_BUDGET_NS: u64 = 10_000_000_000;

/// Maximum counterexamples retained per campaign.
pub const MAX_COUNTEREXAMPLES_PER_CAMPAIGN: usize = 1024;

/// Maximum campaigns per engine.
pub const MAX_CAMPAIGNS_PER_ENGINE: usize = 64;

/// Maximum inputs per engine.
pub const MAX_INPUTS_PER_ENGINE: usize = 4096;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Append a u64 in little-endian to a SHA-256 hasher.
fn append_u64(h: &mut Sha256, v: u64) {
    h.update(v.to_le_bytes());
}

/// Append a string to a SHA-256 hasher.
fn append_str(h: &mut Sha256, s: &str) {
    append_u64(h, s.len() as u64);
    h.update(s.as_bytes());
}

/// Compute a content hash from a SHA-256 hasher.
fn compute_digest(h: Sha256) -> ContentHash {
    ContentHash::compute(&h.finalize())
}

// ---------------------------------------------------------------------------
// WorkloadDomain
// ---------------------------------------------------------------------------

/// Workload surface that a supremacy claim must defend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadDomain {
    /// Branch-heavy control flow.
    BranchHeavy,
    /// Vectorizable numeric loops.
    Vectorizable,
    /// Proof-specialised JIT paths.
    ProofSpecialized,
    /// Native addon FFI boundary.
    NativeAddon,
    /// Hostcall-intensive boundary crossing.
    HostcallBoundary,
    /// Cold-start / image loading.
    StartupImage,
    /// Metadata-locality-sensitive workloads.
    MetadataLocality,
    /// Observability-overhead-sensitive workloads.
    ObservabilitySensitive,
    /// Resource-bounded / memory-constrained.
    ResourceBounded,
    /// String/regexp processing.
    StringRegexp,
    /// React lifecycle-heavy rendering.
    ReactLifecycle,
    /// Async-iterator-heavy streaming.
    AsyncIterator,
}

impl WorkloadDomain {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::BranchHeavy,
        Self::Vectorizable,
        Self::ProofSpecialized,
        Self::NativeAddon,
        Self::HostcallBoundary,
        Self::StartupImage,
        Self::MetadataLocality,
        Self::ObservabilitySensitive,
        Self::ResourceBounded,
        Self::StringRegexp,
        Self::ReactLifecycle,
        Self::AsyncIterator,
    ];

    /// Stable string representation.
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
            Self::ResourceBounded => "resource_bounded",
            Self::StringRegexp => "string_regexp",
            Self::ReactLifecycle => "react_lifecycle",
            Self::AsyncIterator => "async_iterator",
        }
    }

    /// Total number of domains.
    pub const fn count() -> usize {
        Self::ALL.len()
    }
}

impl fmt::Display for WorkloadDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FalsificationStrategy
// ---------------------------------------------------------------------------

/// Strategy for mining counterexamples from adversarial workloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FalsificationStrategy {
    /// Random mutation of seed workloads.
    RandomMutation,
    /// Gradient-guided perturbation towards regression.
    GuidedGradient,
    /// Coverage-directed exploration of untested paths.
    CoverageDirected,
    /// Symbolic execution of workload constraints.
    SymbolicExecution,
    /// Property-based fuzzing of workload invariants.
    PropertyFuzzing,
    /// Domain-specific expert heuristics.
    DomainSpecific,
}

impl FalsificationStrategy {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::RandomMutation,
        Self::GuidedGradient,
        Self::CoverageDirected,
        Self::SymbolicExecution,
        Self::PropertyFuzzing,
        Self::DomainSpecific,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RandomMutation => "random_mutation",
            Self::GuidedGradient => "guided_gradient",
            Self::CoverageDirected => "coverage_directed",
            Self::SymbolicExecution => "symbolic_execution",
            Self::PropertyFuzzing => "property_fuzzing",
            Self::DomainSpecific => "domain_specific",
        }
    }

    /// Total number of strategies.
    pub const fn count() -> usize {
        Self::ALL.len()
    }
}

impl fmt::Display for FalsificationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SynthesisInput
// ---------------------------------------------------------------------------

/// A seed workload for adversarial synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisInput {
    /// Human-readable identifier for the seed.
    pub seed_id: String,
    /// Domain this seed belongs to.
    pub domain: WorkloadDomain,
    /// Hash of the bytecodes / IR representation.
    pub ir_hash: ContentHash,
    /// Complexity score (higher = more complex).
    pub complexity_score: u64,
    /// Content hash of this input record.
    pub input_hash: ContentHash,
}

impl SynthesisInput {
    /// Create a new synthesis input and compute its content hash.
    pub fn new(
        seed_id: impl Into<String>,
        domain: WorkloadDomain,
        ir_hash: ContentHash,
        complexity_score: u64,
    ) -> Self {
        let seed_id = seed_id.into();
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_str(&mut h, &seed_id);
        append_str(&mut h, domain.as_str());
        h.update(ir_hash.as_bytes());
        append_u64(&mut h, complexity_score);
        let input_hash = compute_digest(h);

        Self {
            seed_id,
            domain,
            ir_hash,
            complexity_score,
            input_hash,
        }
    }
}

impl fmt::Display for SynthesisInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seed[{}] domain={} complexity={}",
            self.seed_id, self.domain, self.complexity_score,
        )
    }
}

// ---------------------------------------------------------------------------
// Counterexample
// ---------------------------------------------------------------------------

/// A discovered adversarial workload that falsifies a supremacy claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    /// Regression magnitude in millionths (e.g. 50_000 = 5% regression).
    pub regression_magnitude_millionths: u64,
    /// Domain of the adversarial workload.
    pub domain: WorkloadDomain,
    /// Strategy that discovered this counterexample.
    pub discovery_strategy: FalsificationStrategy,
    /// Hash of the seed input that was mutated.
    pub seed_input_hash: ContentHash,
    /// Timestamp in nanoseconds when the counterexample was found.
    pub timestamp_ns: u64,
    /// Content hash of this counterexample record.
    pub counterexample_hash: ContentHash,
}

impl Counterexample {
    /// Create a new counterexample and compute its content hash.
    pub fn new(
        regression_magnitude_millionths: u64,
        domain: WorkloadDomain,
        discovery_strategy: FalsificationStrategy,
        seed_input_hash: ContentHash,
        timestamp_ns: u64,
    ) -> Self {
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_u64(&mut h, regression_magnitude_millionths);
        append_str(&mut h, domain.as_str());
        append_str(&mut h, discovery_strategy.as_str());
        h.update(seed_input_hash.as_bytes());
        append_u64(&mut h, timestamp_ns);
        let counterexample_hash = compute_digest(h);

        Self {
            regression_magnitude_millionths,
            domain,
            discovery_strategy,
            seed_input_hash,
            timestamp_ns,
            counterexample_hash,
        }
    }

    /// Whether this counterexample exceeds the given threshold.
    pub fn exceeds_threshold(&self, threshold_millionths: u64) -> bool {
        self.regression_magnitude_millionths >= threshold_millionths
    }
}

impl fmt::Display for Counterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "counterexample domain={} strategy={} regression={} millionths",
            self.domain, self.discovery_strategy, self.regression_magnitude_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisConfig
// ---------------------------------------------------------------------------

/// Configuration for a synthesis campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisConfig {
    /// Maximum iterations to run across all domains.
    pub max_iterations: u64,
    /// Minimum regression threshold in millionths to count as a counterexample.
    pub min_regression_threshold_millionths: u64,
    /// Time budget in nanoseconds.
    pub budget_ns: u64,
    /// Domains to probe.
    pub domains: BTreeSet<WorkloadDomain>,
    /// Strategies to employ.
    pub strategies: BTreeSet<FalsificationStrategy>,
    /// Minimum iterations per domain before Fortified is allowed.
    pub min_iterations_per_domain: u64,
    /// Epoch at which this config was created.
    pub epoch: SecurityEpoch,
}

impl SynthesisConfig {
    /// Default configuration covering all domains and strategies.
    pub fn default_config(epoch: SecurityEpoch) -> Self {
        Self {
            max_iterations: 10_000,
            min_regression_threshold_millionths: DEFAULT_MIN_REGRESSION_THRESHOLD,
            budget_ns: DEFAULT_BUDGET_NS,
            domains: WorkloadDomain::ALL.iter().copied().collect(),
            strategies: FalsificationStrategy::ALL.iter().copied().collect(),
            min_iterations_per_domain: DEFAULT_MIN_ITERATIONS_PER_DOMAIN,
            epoch,
        }
    }

    /// Minimal configuration for quick testing.
    pub fn minimal(epoch: SecurityEpoch) -> Self {
        let mut domains = BTreeSet::new();
        domains.insert(WorkloadDomain::BranchHeavy);
        let mut strategies = BTreeSet::new();
        strategies.insert(FalsificationStrategy::RandomMutation);
        Self {
            max_iterations: 100,
            min_regression_threshold_millionths: DEFAULT_MIN_REGRESSION_THRESHOLD,
            budget_ns: 1_000_000_000,
            domains,
            strategies,
            min_iterations_per_domain: 10,
            epoch,
        }
    }

    /// Whether the config covers all twelve domains.
    pub fn covers_all_domains(&self) -> bool {
        self.domains.len() == WorkloadDomain::count()
    }

    /// Number of configured domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Number of configured strategies.
    pub fn strategy_count(&self) -> usize {
        self.strategies.len()
    }

    /// Compute a content hash for this config.
    pub fn compute_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_u64(&mut h, self.max_iterations);
        append_u64(&mut h, self.min_regression_threshold_millionths);
        append_u64(&mut h, self.budget_ns);
        append_u64(&mut h, self.domains.len() as u64);
        for d in &self.domains {
            append_str(&mut h, d.as_str());
        }
        append_u64(&mut h, self.strategies.len() as u64);
        for s in &self.strategies {
            append_str(&mut h, s.as_str());
        }
        append_u64(&mut h, self.min_iterations_per_domain);
        append_u64(&mut h, self.epoch.as_u64());
        compute_digest(h)
    }
}

impl fmt::Display for SynthesisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "config[domains={}, strategies={}, max_iter={}, budget_ns={}]",
            self.domains.len(),
            self.strategies.len(),
            self.max_iterations,
            self.budget_ns,
        )
    }
}

// ---------------------------------------------------------------------------
// DomainCoverage
// ---------------------------------------------------------------------------

/// Coverage statistics for a single domain within a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainCoverage {
    /// Domain being tracked.
    pub domain: WorkloadDomain,
    /// Number of iterations completed for this domain.
    pub iterations: u64,
    /// Number of counterexamples discovered in this domain.
    pub counterexamples_found: u64,
    /// Worst regression magnitude seen in this domain (millionths).
    pub worst_regression_millionths: u64,
    /// Number of unique seed inputs used.
    pub seeds_used: u64,
}

impl DomainCoverage {
    /// Create a new zero-state coverage record.
    pub fn new(domain: WorkloadDomain) -> Self {
        Self {
            domain,
            iterations: 0,
            counterexamples_found: 0,
            worst_regression_millionths: 0,
            seeds_used: 0,
        }
    }

    /// Whether the minimum iteration threshold has been met.
    pub fn meets_threshold(&self, min_iterations: u64) -> bool {
        self.iterations >= min_iterations
    }

    /// Record an iteration (optionally with a discovered counterexample).
    pub fn record_iteration(&mut self, counterexample: Option<&Counterexample>) {
        self.iterations += 1;
        if let Some(cx) = counterexample {
            self.counterexamples_found += 1;
            if cx.regression_magnitude_millionths > self.worst_regression_millionths {
                self.worst_regression_millionths = cx.regression_magnitude_millionths;
            }
        }
    }

    /// Coverage fraction in millionths (iterations / threshold * MILLIONTHS).
    pub fn coverage_fraction_millionths(&self, min_iterations: u64) -> u64 {
        if min_iterations == 0 {
            return MILLIONTHS;
        }
        self.iterations
            .saturating_mul(MILLIONTHS)
            .checked_div(min_iterations)
            .unwrap_or(0)
            .min(MILLIONTHS)
    }
}

impl fmt::Display for DomainCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[iter={}, cx={}, worst={}]",
            self.domain,
            self.iterations,
            self.counterexamples_found,
            self.worst_regression_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisCampaign
// ---------------------------------------------------------------------------

/// A full adversarial synthesis campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisCampaign {
    /// Campaign identifier.
    pub campaign_id: String,
    /// Configuration for this campaign.
    pub config: SynthesisConfig,
    /// All discovered counterexamples.
    pub counterexamples: Vec<Counterexample>,
    /// Per-domain coverage tracking.
    pub coverage_by_domain: BTreeMap<String, DomainCoverage>,
    /// Total iterations completed across all domains.
    pub iterations_completed: u64,
    /// Time budget consumed in nanoseconds.
    pub budget_spent_ns: u64,
    /// Whether an infrastructure failure occurred.
    pub infra_failure: bool,
    /// Optional infrastructure failure detail.
    pub infra_failure_detail: Option<String>,
}

impl SynthesisCampaign {
    /// Create a new campaign from config.
    pub fn new(campaign_id: impl Into<String>, config: SynthesisConfig) -> Self {
        let mut coverage_by_domain = BTreeMap::new();
        for d in &config.domains {
            coverage_by_domain.insert(d.as_str().to_string(), DomainCoverage::new(*d));
        }
        Self {
            campaign_id: campaign_id.into(),
            config,
            counterexamples: Vec::new(),
            coverage_by_domain,
            iterations_completed: 0,
            budget_spent_ns: 0,
            infra_failure: false,
            infra_failure_detail: None,
        }
    }

    /// Record a synthesis iteration for the given domain.
    pub fn record_iteration(
        &mut self,
        domain: WorkloadDomain,
        counterexample: Option<Counterexample>,
        elapsed_ns: u64,
    ) {
        self.iterations_completed += 1;
        self.budget_spent_ns = self.budget_spent_ns.saturating_add(elapsed_ns);

        let domain_key = domain.as_str().to_string();
        if let Some(cov) = self.coverage_by_domain.get_mut(&domain_key) {
            cov.record_iteration(counterexample.as_ref());
        }

        if let Some(cx) = counterexample
            && self.counterexamples.len() < MAX_COUNTEREXAMPLES_PER_CAMPAIGN
        {
            self.counterexamples.push(cx);
        }
    }

    /// Record an infrastructure failure.
    pub fn record_infra_failure(&mut self, detail: impl Into<String>) {
        self.infra_failure = true;
        self.infra_failure_detail = Some(detail.into());
    }

    /// Whether the budget has been exhausted.
    pub fn budget_exhausted(&self) -> bool {
        self.budget_spent_ns >= self.config.budget_ns
    }

    /// Whether max iterations have been reached.
    pub fn iterations_exhausted(&self) -> bool {
        self.iterations_completed >= self.config.max_iterations
    }

    /// Whether all configured domains meet the minimum iteration threshold.
    pub fn all_domains_covered(&self) -> bool {
        self.coverage_by_domain
            .values()
            .all(|cov| cov.meets_threshold(self.config.min_iterations_per_domain))
    }

    /// Domains that have NOT met the iteration threshold.
    pub fn uncovered_domains(&self) -> Vec<WorkloadDomain> {
        self.coverage_by_domain
            .values()
            .filter(|cov| !cov.meets_threshold(self.config.min_iterations_per_domain))
            .map(|cov| cov.domain)
            .collect()
    }

    /// Number of counterexamples discovered.
    pub fn counterexample_count(&self) -> usize {
        self.counterexamples.len()
    }

    /// Worst regression magnitude across all counterexamples (millionths).
    pub fn worst_regression_millionths(&self) -> u64 {
        self.counterexamples
            .iter()
            .map(|cx| cx.regression_magnitude_millionths)
            .max()
            .unwrap_or(0)
    }

    /// Determine the verdict for this campaign.
    pub fn verdict(&self) -> SynthesisVerdict {
        if self.infra_failure {
            return SynthesisVerdict::InfrastructureFailure;
        }
        if !self.counterexamples.is_empty() {
            return SynthesisVerdict::Falsified;
        }
        // Must have covered all domains to be Fortified.
        if !self.all_domains_covered() {
            return SynthesisVerdict::Incomplete;
        }
        // Must have completed at least min_iterations_per_domain * domain_count.
        let min_total = self
            .config
            .min_iterations_per_domain
            .saturating_mul(self.config.domains.len() as u64);
        if self.iterations_completed < min_total {
            return SynthesisVerdict::Incomplete;
        }
        SynthesisVerdict::Fortified
    }

    /// Compute content hash for the campaign.
    pub fn compute_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_str(&mut h, &self.campaign_id);
        h.update(self.config.compute_hash().as_bytes());
        append_u64(&mut h, self.iterations_completed);
        append_u64(&mut h, self.budget_spent_ns);
        append_u64(&mut h, self.counterexamples.len() as u64);
        for cx in &self.counterexamples {
            h.update(cx.counterexample_hash.as_bytes());
        }
        append_u64(&mut h, if self.infra_failure { 1 } else { 0 });
        if let Some(detail) = &self.infra_failure_detail {
            append_str(&mut h, detail);
        }
        compute_digest(h)
    }
}

impl fmt::Display for SynthesisCampaign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "campaign[{}] verdict={} iter={} cx={} budget_spent={}ns",
            self.campaign_id,
            self.verdict(),
            self.iterations_completed,
            self.counterexamples.len(),
            self.budget_spent_ns,
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisVerdict
// ---------------------------------------------------------------------------

/// Outcome of an adversarial synthesis campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisVerdict {
    /// No counterexamples found after thorough probing of all domains.
    Fortified,
    /// At least one counterexample was discovered.
    Falsified,
    /// Budget or iteration limit exhausted before full coverage.
    Incomplete,
    /// An infrastructure failure prevented completion.
    InfrastructureFailure,
}

impl SynthesisVerdict {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Fortified,
        Self::Falsified,
        Self::Incomplete,
        Self::InfrastructureFailure,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fortified => "fortified",
            Self::Falsified => "falsified",
            Self::Incomplete => "incomplete",
            Self::InfrastructureFailure => "infrastructure_failure",
        }
    }

    /// Whether this verdict allows the supremacy claim to stand.
    pub const fn claim_survives(self) -> bool {
        matches!(self, Self::Fortified)
    }

    /// Whether this verdict definitively blocks the claim.
    pub const fn claim_blocked(self) -> bool {
        matches!(self, Self::Falsified)
    }
}

impl fmt::Display for SynthesisVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SynthesisReport
// ---------------------------------------------------------------------------

/// Aggregated report across one or more synthesis campaigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisReport {
    /// Report identifier.
    pub report_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Aggregate verdict (worst across campaigns).
    pub verdict: SynthesisVerdict,
    /// Total counterexamples across all campaigns.
    pub total_counterexamples: usize,
    /// Worst regression magnitude across all campaigns (millionths).
    pub worst_regression_millionths: u64,
    /// Per-domain coverage aggregated across campaigns.
    pub domain_coverage: BTreeMap<String, DomainCoverage>,
    /// All campaigns in this report.
    pub all_campaigns: Vec<SynthesisCampaign>,
    /// Epoch of the report.
    pub epoch: SecurityEpoch,
    /// Content hash of the report.
    pub content_hash: ContentHash,
}

impl SynthesisReport {
    /// Compute content hash for the report (excluding the content_hash field).
    fn compute_report_hash(
        report_id: &str,
        verdict: SynthesisVerdict,
        total_counterexamples: usize,
        worst_regression_millionths: u64,
        campaigns: &[SynthesisCampaign],
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut h = Sha256::new();
        append_str(&mut h, SCHEMA_VERSION);
        append_str(&mut h, report_id);
        append_str(&mut h, verdict.as_str());
        append_u64(&mut h, total_counterexamples as u64);
        append_u64(&mut h, worst_regression_millionths);
        append_u64(&mut h, campaigns.len() as u64);
        for c in campaigns {
            h.update(c.compute_hash().as_bytes());
        }
        append_u64(&mut h, epoch.as_u64());
        compute_digest(h)
    }

    /// Compute content hash including domain coverage.
    pub fn full_content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.content_hash.as_bytes());
        // domain_coverage is BTreeMap so iteration is deterministic.
        for (domain, cov) in &self.domain_coverage {
            append_str(&mut h, domain);
            append_u64(&mut h, cov.iterations);
            append_u64(&mut h, cov.counterexamples_found);
            append_u64(&mut h, cov.worst_regression_millionths);
            append_u64(&mut h, cov.seeds_used);
        }
        compute_digest(h)
    }

    /// Whether the report indicates the claim survived adversarial probing.
    pub fn claim_survives(&self) -> bool {
        self.verdict.claim_survives()
    }

    /// Whether any campaign found counterexamples.
    pub fn has_counterexamples(&self) -> bool {
        self.total_counterexamples > 0
    }

    /// Total iterations across all campaigns.
    pub fn total_iterations(&self) -> u64 {
        self.all_campaigns
            .iter()
            .map(|c| c.iterations_completed)
            .sum()
    }

    /// Verify the report's content hash.
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_report_hash(
            &self.report_id,
            self.verdict,
            self.total_counterexamples,
            self.worst_regression_millionths,
            &self.all_campaigns,
            self.epoch,
        );
        expected == self.content_hash
    }
}

impl fmt::Display for SynthesisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "report[{}] verdict={} cx={} worst_regression={} campaigns={}",
            self.report_id,
            self.verdict,
            self.total_counterexamples,
            self.worst_regression_millionths,
            self.all_campaigns.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisError
// ---------------------------------------------------------------------------

/// Errors from the synthesis engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisError {
    /// No inputs have been registered.
    NoInputs,
    /// Too many inputs registered.
    TooManyInputs { count: usize, max: usize },
    /// Too many campaigns registered.
    TooManyCampaigns { count: usize, max: usize },
    /// Campaign with this ID already exists.
    DuplicateCampaignId { campaign_id: String },
    /// No campaigns have been run.
    NoCampaigns,
    /// Config has no domains.
    EmptyDomains,
    /// Config has no strategies.
    EmptyStrategies,
    /// No inputs exist for a required domain.
    MissingDomainInputs { domain: String },
}

impl SynthesisError {
    /// Stable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoInputs => "no_inputs",
            Self::TooManyInputs { .. } => "too_many_inputs",
            Self::TooManyCampaigns { .. } => "too_many_campaigns",
            Self::DuplicateCampaignId { .. } => "duplicate_campaign_id",
            Self::NoCampaigns => "no_campaigns",
            Self::EmptyDomains => "empty_domains",
            Self::EmptyStrategies => "empty_strategies",
            Self::MissingDomainInputs { .. } => "missing_domain_inputs",
        }
    }
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputs => write!(f, "no inputs registered"),
            Self::TooManyInputs { count, max } => {
                write!(f, "too many inputs: {count} > {max}")
            }
            Self::TooManyCampaigns { count, max } => {
                write!(f, "too many campaigns: {count} > {max}")
            }
            Self::DuplicateCampaignId { campaign_id } => {
                write!(f, "duplicate campaign ID: {campaign_id}")
            }
            Self::NoCampaigns => write!(f, "no campaigns have been run"),
            Self::EmptyDomains => write!(f, "config has no domains"),
            Self::EmptyStrategies => write!(f, "config has no strategies"),
            Self::MissingDomainInputs { domain } => {
                write!(f, "no inputs for required domain: {domain}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesisEngine
// ---------------------------------------------------------------------------

/// Orchestrates adversarial synthesis campaigns.
///
/// Maintains a registry of seed inputs, runs campaigns, and produces
/// aggregated reports.  The engine refuses to emit a Fortified verdict
/// unless all configured domains were covered and minimum iteration
/// thresholds were met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisEngine {
    /// Registered seed inputs indexed by domain.
    pub inputs_by_domain: BTreeMap<String, Vec<SynthesisInput>>,
    /// All registered inputs (flat).
    pub all_inputs: Vec<SynthesisInput>,
    /// Completed campaigns.
    pub campaigns: Vec<SynthesisCampaign>,
    /// Engine epoch.
    pub epoch: SecurityEpoch,
}

impl SynthesisEngine {
    /// Create a new engine.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            inputs_by_domain: BTreeMap::new(),
            all_inputs: Vec::new(),
            campaigns: Vec::new(),
            epoch,
        }
    }

    /// Register a seed input.
    pub fn add_input(&mut self, input: SynthesisInput) -> Result<(), SynthesisError> {
        if self.all_inputs.len() >= MAX_INPUTS_PER_ENGINE {
            return Err(SynthesisError::TooManyInputs {
                count: self.all_inputs.len() + 1,
                max: MAX_INPUTS_PER_ENGINE,
            });
        }
        let domain_key = input.domain.as_str().to_string();
        self.inputs_by_domain
            .entry(domain_key)
            .or_default()
            .push(input.clone());
        self.all_inputs.push(input);
        Ok(())
    }

    /// Number of registered inputs.
    pub fn input_count(&self) -> usize {
        self.all_inputs.len()
    }

    /// Number of completed campaigns.
    pub fn campaign_count(&self) -> usize {
        self.campaigns.len()
    }

    /// Domains that have at least one registered input.
    pub fn covered_input_domains(&self) -> BTreeSet<WorkloadDomain> {
        let mut result = BTreeSet::new();
        for input in &self.all_inputs {
            result.insert(input.domain);
        }
        result
    }

    /// Validate that a config can be run against current inputs.
    pub fn validate_config(&self, config: &SynthesisConfig) -> Result<(), SynthesisError> {
        if self.all_inputs.is_empty() {
            return Err(SynthesisError::NoInputs);
        }
        if config.domains.is_empty() {
            return Err(SynthesisError::EmptyDomains);
        }
        if config.strategies.is_empty() {
            return Err(SynthesisError::EmptyStrategies);
        }
        let covered = self.covered_input_domains();
        for domain in &config.domains {
            if !covered.contains(domain) {
                return Err(SynthesisError::MissingDomainInputs {
                    domain: domain.as_str().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Run a campaign. This simulates the synthesis loop:
    ///
    /// For each configured domain, iterate over seeds and strategies,
    /// recording any discovered counterexamples.  The caller provides
    /// a `probe_fn` that receives a seed input, domain, and strategy
    /// and returns an optional counterexample regression magnitude.
    ///
    /// Returns the campaign (also stored internally).
    pub fn run_campaign<F>(
        &mut self,
        campaign_id: impl Into<String>,
        config: SynthesisConfig,
        mut probe_fn: F,
    ) -> Result<SynthesisCampaign, SynthesisError>
    where
        F: FnMut(&SynthesisInput, WorkloadDomain, FalsificationStrategy) -> Option<u64>,
    {
        let campaign_id = campaign_id.into();

        // Check for duplicate campaign ID.
        if self.campaigns.iter().any(|c| c.campaign_id == campaign_id) {
            return Err(SynthesisError::DuplicateCampaignId {
                campaign_id: campaign_id.clone(),
            });
        }
        if self.campaigns.len() >= MAX_CAMPAIGNS_PER_ENGINE {
            return Err(SynthesisError::TooManyCampaigns {
                count: self.campaigns.len() + 1,
                max: MAX_CAMPAIGNS_PER_ENGINE,
            });
        }

        self.validate_config(&config)?;

        let mut campaign = SynthesisCampaign::new(&campaign_id, config.clone());
        let mut timestamp_ns: u64 = 1_000_000;

        for domain in &config.domains {
            let domain_key = domain.as_str().to_string();
            let seeds = self
                .inputs_by_domain
                .get(&domain_key)
                .cloned()
                .unwrap_or_default();

            for strategy in &config.strategies {
                for seed in &seeds {
                    if campaign.iterations_exhausted() || campaign.budget_exhausted() {
                        break;
                    }

                    let regression = probe_fn(seed, *domain, *strategy);
                    let cx = regression
                        .filter(|r| *r >= config.min_regression_threshold_millionths)
                        .map(|r| {
                            Counterexample::new(
                                r,
                                *domain,
                                *strategy,
                                seed.input_hash,
                                timestamp_ns,
                            )
                        });

                    // Simulate elapsed time.
                    let elapsed = 1_000;
                    campaign.record_iteration(*domain, cx, elapsed);
                    timestamp_ns += 1_000;

                    // Update seeds_used count in coverage.
                    if let Some(cov) = campaign.coverage_by_domain.get_mut(&domain_key) {
                        // Seeds used is tracked per unique seed across all iterations.
                        cov.seeds_used = seeds.len() as u64;
                    }
                }
            }
        }

        self.campaigns.push(campaign.clone());
        Ok(campaign)
    }

    /// Evaluate all campaigns and produce an aggregated report.
    pub fn evaluate(
        &self,
        report_id: impl Into<String>,
    ) -> Result<SynthesisReport, SynthesisError> {
        if self.campaigns.is_empty() {
            return Err(SynthesisError::NoCampaigns);
        }

        let report_id = report_id.into();

        // Aggregate verdict: worst across all campaigns.
        let mut aggregate_verdict = SynthesisVerdict::Fortified;
        let mut total_counterexamples: usize = 0;
        let mut worst_regression: u64 = 0;
        let mut domain_coverage: BTreeMap<String, DomainCoverage> = BTreeMap::new();

        for campaign in &self.campaigns {
            let v = campaign.verdict();
            // Worst verdict wins (Falsified > InfraFailure > Incomplete > Fortified).
            match v {
                SynthesisVerdict::Falsified => {
                    aggregate_verdict = SynthesisVerdict::Falsified;
                }
                SynthesisVerdict::InfrastructureFailure => {
                    if aggregate_verdict != SynthesisVerdict::Falsified {
                        aggregate_verdict = SynthesisVerdict::InfrastructureFailure;
                    }
                }
                SynthesisVerdict::Incomplete => {
                    if aggregate_verdict == SynthesisVerdict::Fortified {
                        aggregate_verdict = SynthesisVerdict::Incomplete;
                    }
                }
                SynthesisVerdict::Fortified => {}
            }

            total_counterexamples += campaign.counterexample_count();
            let campaign_worst = campaign.worst_regression_millionths();
            if campaign_worst > worst_regression {
                worst_regression = campaign_worst;
            }

            // Merge domain coverage.
            for (key, cov) in &campaign.coverage_by_domain {
                let entry = domain_coverage
                    .entry(key.clone())
                    .or_insert_with(|| DomainCoverage::new(cov.domain));
                entry.iterations += cov.iterations;
                entry.counterexamples_found += cov.counterexamples_found;
                if cov.worst_regression_millionths > entry.worst_regression_millionths {
                    entry.worst_regression_millionths = cov.worst_regression_millionths;
                }
                entry.seeds_used = entry.seeds_used.max(cov.seeds_used);
            }
        }

        let content_hash = SynthesisReport::compute_report_hash(
            &report_id,
            aggregate_verdict,
            total_counterexamples,
            worst_regression,
            &self.campaigns,
            self.epoch,
        );

        Ok(SynthesisReport {
            report_id,
            schema_version: SCHEMA_VERSION.to_string(),
            verdict: aggregate_verdict,
            total_counterexamples,
            worst_regression_millionths: worst_regression,
            domain_coverage,
            all_campaigns: self.campaigns.clone(),
            epoch: self.epoch,
            content_hash,
        })
    }
}

impl fmt::Display for SynthesisEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SynthesisEngine[inputs={}, campaigns={}, epoch={}]",
            self.all_inputs.len(),
            self.campaigns.len(),
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_input(seed_id: &str, domain: WorkloadDomain) -> SynthesisInput {
        SynthesisInput::new(
            seed_id,
            domain,
            ContentHash::compute(seed_id.as_bytes()),
            100,
        )
    }

    fn make_counterexample(domain: WorkloadDomain, regression: u64) -> Counterexample {
        Counterexample::new(
            regression,
            domain,
            FalsificationStrategy::RandomMutation,
            ContentHash::compute(b"seed"),
            1_000_000,
        )
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("adversarial-workload-synthesis"));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "adversarial_workload_synthesis");
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
    fn default_constants_valid() {
        assert_eq!(DEFAULT_MIN_ITERATIONS_PER_DOMAIN, 100);
        assert_eq!(DEFAULT_MIN_REGRESSION_THRESHOLD, 50_000);
        assert_eq!(DEFAULT_BUDGET_NS, 10_000_000_000);
        const {
            assert!(MAX_COUNTEREXAMPLES_PER_CAMPAIGN > 0);
            assert!(MAX_CAMPAIGNS_PER_ENGINE > 0);
            assert!(MAX_INPUTS_PER_ENGINE > 0);
        }
    }

    // --- WorkloadDomain ---

    #[test]
    fn workload_domain_all_count() {
        assert_eq!(WorkloadDomain::ALL.len(), 12);
        assert_eq!(WorkloadDomain::count(), 12);
    }

    #[test]
    fn workload_domain_ordering() {
        let mut domains: Vec<WorkloadDomain> = WorkloadDomain::ALL.to_vec();
        let original = domains.clone();
        domains.sort();
        assert_eq!(domains, original, "ALL must be in derived Ord order");
    }

    #[test]
    fn workload_domain_display() {
        assert_eq!(WorkloadDomain::BranchHeavy.to_string(), "branch_heavy");
        assert_eq!(WorkloadDomain::AsyncIterator.to_string(), "async_iterator");
        assert_eq!(
            WorkloadDomain::ReactLifecycle.to_string(),
            "react_lifecycle"
        );
    }

    #[test]
    fn workload_domain_as_str_unique() {
        let strs: BTreeSet<&str> = WorkloadDomain::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(strs.len(), WorkloadDomain::ALL.len());
    }

    #[test]
    fn workload_domain_roundtrip_serde() {
        for domain in WorkloadDomain::ALL {
            let json = serde_json::to_string(domain).unwrap();
            let back: WorkloadDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*domain, back);
        }
    }

    // --- FalsificationStrategy ---

    #[test]
    fn falsification_strategy_all_count() {
        assert_eq!(FalsificationStrategy::ALL.len(), 6);
        assert_eq!(FalsificationStrategy::count(), 6);
    }

    #[test]
    fn falsification_strategy_ordering() {
        let mut strategies: Vec<FalsificationStrategy> = FalsificationStrategy::ALL.to_vec();
        let original = strategies.clone();
        strategies.sort();
        assert_eq!(strategies, original, "ALL must be in derived Ord order");
    }

    #[test]
    fn falsification_strategy_display() {
        assert_eq!(
            FalsificationStrategy::RandomMutation.to_string(),
            "random_mutation"
        );
        assert_eq!(
            FalsificationStrategy::SymbolicExecution.to_string(),
            "symbolic_execution"
        );
    }

    #[test]
    fn falsification_strategy_as_str_unique() {
        let strs: BTreeSet<&str> = FalsificationStrategy::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(strs.len(), FalsificationStrategy::ALL.len());
    }

    // --- SynthesisInput ---

    #[test]
    fn synthesis_input_hash_determinism() {
        let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
        let b = make_input("seed_a", WorkloadDomain::BranchHeavy);
        assert_eq!(a.input_hash, b.input_hash);
    }

    #[test]
    fn synthesis_input_different_seeds_different_hashes() {
        let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
        let b = make_input("seed_b", WorkloadDomain::BranchHeavy);
        assert_ne!(a.input_hash, b.input_hash);
    }

    #[test]
    fn synthesis_input_different_domains_different_hashes() {
        let a = make_input("seed_a", WorkloadDomain::BranchHeavy);
        let b = make_input("seed_a", WorkloadDomain::Vectorizable);
        assert_ne!(a.input_hash, b.input_hash);
    }

    #[test]
    fn synthesis_input_display() {
        let input = make_input("test_seed", WorkloadDomain::StringRegexp);
        let display = input.to_string();
        assert!(display.contains("test_seed"));
        assert!(display.contains("string_regexp"));
    }

    // --- Counterexample ---

    #[test]
    fn counterexample_construction_and_hash() {
        let cx = make_counterexample(WorkloadDomain::BranchHeavy, 100_000);
        assert_eq!(cx.regression_magnitude_millionths, 100_000);
        assert_eq!(cx.domain, WorkloadDomain::BranchHeavy);
        assert_eq!(cx.discovery_strategy, FalsificationStrategy::RandomMutation);
        // Hash should not be all zeros.
        assert_ne!(cx.counterexample_hash, ContentHash::default());
    }

    #[test]
    fn counterexample_hash_determinism() {
        let a = Counterexample::new(
            75_000,
            WorkloadDomain::Vectorizable,
            FalsificationStrategy::GuidedGradient,
            ContentHash::compute(b"seed_x"),
            999,
        );
        let b = Counterexample::new(
            75_000,
            WorkloadDomain::Vectorizable,
            FalsificationStrategy::GuidedGradient,
            ContentHash::compute(b"seed_x"),
            999,
        );
        assert_eq!(a.counterexample_hash, b.counterexample_hash);
    }

    #[test]
    fn counterexample_exceeds_threshold() {
        let cx = make_counterexample(WorkloadDomain::BranchHeavy, 100_000);
        assert!(cx.exceeds_threshold(50_000));
        assert!(cx.exceeds_threshold(100_000));
        assert!(!cx.exceeds_threshold(100_001));
    }

    #[test]
    fn counterexample_display() {
        let cx = make_counterexample(WorkloadDomain::NativeAddon, 200_000);
        let display = cx.to_string();
        assert!(display.contains("native_addon"));
        assert!(display.contains("200000"));
    }

    // --- SynthesisConfig ---

    #[test]
    fn config_default_covers_all() {
        let config = SynthesisConfig::default_config(epoch());
        assert!(config.covers_all_domains());
        assert_eq!(config.domain_count(), 12);
        assert_eq!(config.strategy_count(), 6);
    }

    #[test]
    fn config_minimal_single_domain() {
        let config = SynthesisConfig::minimal(epoch());
        assert!(!config.covers_all_domains());
        assert_eq!(config.domain_count(), 1);
        assert_eq!(config.strategy_count(), 1);
        assert!(config.domains.contains(&WorkloadDomain::BranchHeavy));
    }

    #[test]
    fn config_hash_determinism() {
        let a = SynthesisConfig::default_config(epoch());
        let b = SynthesisConfig::default_config(epoch());
        assert_eq!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn config_hash_varies_with_epoch() {
        let a = SynthesisConfig::default_config(SecurityEpoch::from_raw(1));
        let b = SynthesisConfig::default_config(SecurityEpoch::from_raw(2));
        assert_ne!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn config_display() {
        let config = SynthesisConfig::default_config(epoch());
        let display = config.to_string();
        assert!(display.contains("domains=12"));
        assert!(display.contains("strategies=6"));
    }

    // --- DomainCoverage ---

    #[test]
    fn domain_coverage_new_is_zero() {
        let cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
        assert_eq!(cov.iterations, 0);
        assert_eq!(cov.counterexamples_found, 0);
        assert_eq!(cov.worst_regression_millionths, 0);
        assert_eq!(cov.seeds_used, 0);
    }

    #[test]
    fn domain_coverage_record_iteration() {
        let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
        cov.record_iteration(None);
        assert_eq!(cov.iterations, 1);
        assert_eq!(cov.counterexamples_found, 0);

        let cx = make_counterexample(WorkloadDomain::BranchHeavy, 80_000);
        cov.record_iteration(Some(&cx));
        assert_eq!(cov.iterations, 2);
        assert_eq!(cov.counterexamples_found, 1);
        assert_eq!(cov.worst_regression_millionths, 80_000);
    }

    #[test]
    fn domain_coverage_worst_regression_tracked() {
        let mut cov = DomainCoverage::new(WorkloadDomain::Vectorizable);
        let cx1 = make_counterexample(WorkloadDomain::Vectorizable, 50_000);
        let cx2 = make_counterexample(WorkloadDomain::Vectorizable, 120_000);
        let cx3 = make_counterexample(WorkloadDomain::Vectorizable, 90_000);
        cov.record_iteration(Some(&cx1));
        cov.record_iteration(Some(&cx2));
        cov.record_iteration(Some(&cx3));
        assert_eq!(cov.worst_regression_millionths, 120_000);
    }

    #[test]
    fn domain_coverage_meets_threshold() {
        let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
        assert!(!cov.meets_threshold(10));
        for _ in 0..10 {
            cov.record_iteration(None);
        }
        assert!(cov.meets_threshold(10));
        assert!(!cov.meets_threshold(11));
    }

    #[test]
    fn domain_coverage_fraction_millionths() {
        let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
        assert_eq!(cov.coverage_fraction_millionths(0), MILLIONTHS);
        assert_eq!(cov.coverage_fraction_millionths(100), 0);
        for _ in 0..50 {
            cov.record_iteration(None);
        }
        assert_eq!(cov.coverage_fraction_millionths(100), 500_000);
        for _ in 0..50 {
            cov.record_iteration(None);
        }
        assert_eq!(cov.coverage_fraction_millionths(100), MILLIONTHS);
    }

    #[test]
    fn domain_coverage_fraction_caps_at_millionths() {
        let mut cov = DomainCoverage::new(WorkloadDomain::BranchHeavy);
        for _ in 0..200 {
            cov.record_iteration(None);
        }
        assert_eq!(cov.coverage_fraction_millionths(100), MILLIONTHS);
    }

    // --- SynthesisCampaign ---

    #[test]
    fn campaign_new_starts_empty() {
        let config = SynthesisConfig::minimal(epoch());
        let campaign = SynthesisCampaign::new("camp_1", config);
        assert_eq!(campaign.campaign_id, "camp_1");
        assert_eq!(campaign.iterations_completed, 0);
        assert_eq!(campaign.counterexample_count(), 0);
        assert_eq!(campaign.budget_spent_ns, 0);
        assert!(!campaign.infra_failure);
    }

    #[test]
    fn campaign_record_iteration_tracks_state() {
        let config = SynthesisConfig::minimal(epoch());
        let mut campaign = SynthesisCampaign::new("camp_2", config);
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 500);
        assert_eq!(campaign.iterations_completed, 1);
        assert_eq!(campaign.budget_spent_ns, 500);
        assert_eq!(campaign.counterexample_count(), 0);
    }

    #[test]
    fn campaign_record_counterexample() {
        let config = SynthesisConfig::minimal(epoch());
        let mut campaign = SynthesisCampaign::new("camp_3", config);
        let cx = make_counterexample(WorkloadDomain::BranchHeavy, 60_000);
        campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 1_000);
        assert_eq!(campaign.counterexample_count(), 1);
        assert_eq!(campaign.worst_regression_millionths(), 60_000);
    }

    #[test]
    fn campaign_verdict_fortified_when_covered() {
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 2;
        let mut campaign = SynthesisCampaign::new("camp_4", config);
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 100);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
    }

    #[test]
    fn campaign_verdict_falsified_with_counterexamples() {
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        let mut campaign = SynthesisCampaign::new("camp_5", config);
        let cx = make_counterexample(WorkloadDomain::BranchHeavy, 100_000);
        campaign.record_iteration(WorkloadDomain::BranchHeavy, Some(cx), 100);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
    }

    #[test]
    fn campaign_verdict_incomplete_not_enough_iterations() {
        let config = SynthesisConfig::minimal(epoch());
        let campaign = SynthesisCampaign::new("camp_6", config);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
    }

    #[test]
    fn campaign_verdict_infra_failure() {
        let config = SynthesisConfig::minimal(epoch());
        let mut campaign = SynthesisCampaign::new("camp_7", config);
        campaign.record_infra_failure("disk full");
        assert_eq!(campaign.verdict(), SynthesisVerdict::InfrastructureFailure);
    }

    #[test]
    fn campaign_uncovered_domains() {
        let config = SynthesisConfig::default_config(epoch());
        let campaign = SynthesisCampaign::new("camp_8", config);
        let uncovered = campaign.uncovered_domains();
        assert_eq!(uncovered.len(), 12);
    }

    #[test]
    fn campaign_hash_determinism() {
        let config = SynthesisConfig::minimal(epoch());
        let a = SynthesisCampaign::new("camp_det", config.clone());
        let b = SynthesisCampaign::new("camp_det", config);
        assert_eq!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn campaign_display() {
        let config = SynthesisConfig::minimal(epoch());
        let campaign = SynthesisCampaign::new("camp_disp", config);
        let display = campaign.to_string();
        assert!(display.contains("camp_disp"));
        assert!(display.contains("incomplete"));
    }

    // --- SynthesisVerdict ---

    #[test]
    fn verdict_all_variants() {
        assert_eq!(SynthesisVerdict::ALL.len(), 4);
    }

    #[test]
    fn verdict_claim_survives() {
        assert!(SynthesisVerdict::Fortified.claim_survives());
        assert!(!SynthesisVerdict::Falsified.claim_survives());
        assert!(!SynthesisVerdict::Incomplete.claim_survives());
        assert!(!SynthesisVerdict::InfrastructureFailure.claim_survives());
    }

    #[test]
    fn verdict_claim_blocked() {
        assert!(!SynthesisVerdict::Fortified.claim_blocked());
        assert!(SynthesisVerdict::Falsified.claim_blocked());
        assert!(!SynthesisVerdict::Incomplete.claim_blocked());
        assert!(!SynthesisVerdict::InfrastructureFailure.claim_blocked());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(SynthesisVerdict::Fortified.to_string(), "fortified");
        assert_eq!(SynthesisVerdict::Falsified.to_string(), "falsified");
        assert_eq!(SynthesisVerdict::Incomplete.to_string(), "incomplete");
        assert_eq!(
            SynthesisVerdict::InfrastructureFailure.to_string(),
            "infrastructure_failure"
        );
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in SynthesisVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: SynthesisVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- SynthesisEngine ---

    #[test]
    fn engine_new_empty() {
        let engine = SynthesisEngine::new(epoch());
        assert_eq!(engine.input_count(), 0);
        assert_eq!(engine.campaign_count(), 0);
    }

    #[test]
    fn engine_add_input() {
        let mut engine = SynthesisEngine::new(epoch());
        let input = make_input("s1", WorkloadDomain::BranchHeavy);
        engine.add_input(input).unwrap();
        assert_eq!(engine.input_count(), 1);
        assert!(
            engine
                .covered_input_domains()
                .contains(&WorkloadDomain::BranchHeavy)
        );
    }

    #[test]
    fn engine_validate_config_no_inputs() {
        let engine = SynthesisEngine::new(epoch());
        let config = SynthesisConfig::minimal(epoch());
        let err = engine.validate_config(&config).unwrap_err();
        assert_eq!(err.tag(), "no_inputs");
    }

    #[test]
    fn engine_validate_config_empty_domains() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.domains.clear();
        let err = engine.validate_config(&config).unwrap_err();
        assert_eq!(err.tag(), "empty_domains");
    }

    #[test]
    fn engine_validate_config_empty_strategies() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.strategies.clear();
        let err = engine.validate_config(&config).unwrap_err();
        assert_eq!(err.tag(), "empty_strategies");
    }

    #[test]
    fn engine_validate_config_missing_domain_inputs() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let config = SynthesisConfig::default_config(epoch());
        let err = engine.validate_config(&config).unwrap_err();
        assert_eq!(err.tag(), "missing_domain_inputs");
    }

    #[test]
    fn engine_run_campaign_no_counterexamples() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        let campaign = engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        assert_eq!(campaign.counterexample_count(), 0);
        // With 1 seed, 1 strategy, 1 domain: 1 iteration.
        assert_eq!(campaign.iterations_completed, 1);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Fortified);
    }

    #[test]
    fn engine_run_campaign_with_counterexamples() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        let campaign = engine
            .run_campaign("c1", config, |_, _, _| Some(80_000))
            .unwrap();
        assert_eq!(campaign.counterexample_count(), 1);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Falsified);
        assert_eq!(campaign.worst_regression_millionths(), 80_000);
    }

    #[test]
    fn engine_run_campaign_below_threshold_no_counterexample() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        config.min_regression_threshold_millionths = 100_000;
        // Return regression below threshold.
        let campaign = engine
            .run_campaign("c1", config, |_, _, _| Some(50_000))
            .unwrap();
        assert_eq!(campaign.counterexample_count(), 0);
    }

    #[test]
    fn engine_run_campaign_duplicate_id() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let config = SynthesisConfig::minimal(epoch());
        engine
            .run_campaign("dup", config.clone(), |_, _, _| None)
            .unwrap();
        let err = engine
            .run_campaign("dup", config, |_, _, _| None)
            .unwrap_err();
        assert_eq!(err.tag(), "duplicate_campaign_id");
    }

    #[test]
    fn engine_evaluate_no_campaigns() {
        let engine = SynthesisEngine::new(epoch());
        let err = engine.evaluate("r1").unwrap_err();
        assert_eq!(err.tag(), "no_campaigns");
    }

    #[test]
    fn engine_evaluate_fortified_report() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.verdict, SynthesisVerdict::Fortified);
        assert_eq!(report.total_counterexamples, 0);
        assert_eq!(report.worst_regression_millionths, 0);
        assert!(report.claim_survives());
        assert!(!report.has_counterexamples());
    }

    #[test]
    fn engine_evaluate_falsified_report() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        engine
            .run_campaign("c1", config, |_, _, _| Some(150_000))
            .unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.verdict, SynthesisVerdict::Falsified);
        assert_eq!(report.total_counterexamples, 1);
        assert_eq!(report.worst_regression_millionths, 150_000);
        assert!(!report.claim_survives());
        assert!(report.has_counterexamples());
    }

    #[test]
    fn engine_evaluate_report_integrity() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert!(report.verify_integrity());
    }

    #[test]
    fn engine_evaluate_multiple_campaigns() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        // First campaign: no counterexamples.
        engine
            .run_campaign("c1", config.clone(), |_, _, _| None)
            .unwrap();
        // Second campaign: counterexample found.
        engine
            .run_campaign("c2", config, |_, _, _| Some(200_000))
            .unwrap();

        let report = engine.evaluate("r1").unwrap();
        // Worst verdict wins: Falsified.
        assert_eq!(report.verdict, SynthesisVerdict::Falsified);
        assert_eq!(report.total_counterexamples, 1);
        assert_eq!(report.worst_regression_millionths, 200_000);
        assert_eq!(report.all_campaigns.len(), 2);
    }

    #[test]
    fn engine_evaluate_worst_regression_tracking() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        engine
            .add_input(make_input("s2", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        let mut call_count = 0u64;
        engine
            .run_campaign("c1", config, |_, _, _| {
                call_count += 1;
                // First seed: small regression, second: large.
                if call_count == 1 {
                    Some(60_000)
                } else {
                    Some(300_000)
                }
            })
            .unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.worst_regression_millionths, 300_000);
    }

    #[test]
    fn engine_gate_refuses_fortified_missing_domains() {
        let mut engine = SynthesisEngine::new(epoch());
        // Only add input for one domain.
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        // Config asks for two domains.
        let mut config = SynthesisConfig::minimal(epoch());
        config.domains.insert(WorkloadDomain::Vectorizable);
        let err = engine
            .run_campaign("c1", config, |_, _, _| None)
            .unwrap_err();
        assert_eq!(err.tag(), "missing_domain_inputs");
    }

    #[test]
    fn engine_gate_refuses_fortified_below_iteration_threshold() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        // Require 100 iterations per domain but only 1 seed x 1 strategy = 1 iteration.
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 100;
        config.max_iterations = 10_000;
        let campaign = engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.verdict, SynthesisVerdict::Incomplete);
        assert!(!report.claim_survives());
    }

    #[test]
    fn engine_empty_campaign_handling() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.max_iterations = 0;
        let campaign = engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        assert_eq!(campaign.iterations_completed, 0);
        assert_eq!(campaign.verdict(), SynthesisVerdict::Incomplete);
    }

    #[test]
    fn engine_report_total_iterations() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        engine
            .run_campaign("c1", config.clone(), |_, _, _| None)
            .unwrap();
        engine.run_campaign("c2", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.total_iterations(), 2);
    }

    #[test]
    fn engine_domain_coverage_aggregated() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        engine
            .run_campaign("c1", config.clone(), |_, _, _| None)
            .unwrap();
        engine.run_campaign("c2", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        let cov = report.domain_coverage.get("branch_heavy").unwrap();
        assert_eq!(cov.iterations, 2);
    }

    #[test]
    fn engine_display() {
        let engine = SynthesisEngine::new(epoch());
        let display = engine.to_string();
        assert!(display.contains("SynthesisEngine"));
        assert!(display.contains("inputs=0"));
    }

    #[test]
    fn synthesis_error_display() {
        let err = SynthesisError::NoInputs;
        assert_eq!(err.to_string(), "no inputs registered");
        let err = SynthesisError::TooManyInputs {
            count: 5000,
            max: 4096,
        };
        assert!(err.to_string().contains("5000"));
    }

    #[test]
    fn synthesis_error_tags_unique() {
        let errors: Vec<SynthesisError> = vec![
            SynthesisError::NoInputs,
            SynthesisError::TooManyInputs { count: 1, max: 1 },
            SynthesisError::TooManyCampaigns { count: 1, max: 1 },
            SynthesisError::DuplicateCampaignId {
                campaign_id: "x".into(),
            },
            SynthesisError::NoCampaigns,
            SynthesisError::EmptyDomains,
            SynthesisError::EmptyStrategies,
            SynthesisError::MissingDomainInputs { domain: "x".into() },
        ];
        let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
        assert_eq!(tags.len(), errors.len());
    }

    #[test]
    fn report_schema_version_set() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_display() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;
        engine.run_campaign("c1", config, |_, _, _| None).unwrap();
        let report = engine.evaluate("r1").unwrap();
        let display = report.to_string();
        assert!(display.contains("r1"));
        assert!(display.contains("fortified"));
    }

    #[test]
    fn infra_failure_overrides_incomplete() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        // First campaign: Fortified.
        engine
            .run_campaign("c1", config.clone(), |_, _, _| None)
            .unwrap();

        // Manually add an infra-failed campaign.
        let mut failed_campaign = SynthesisCampaign::new("c_fail", config);
        failed_campaign.record_infra_failure("network timeout");
        engine.campaigns.push(failed_campaign);

        let report = engine.evaluate("r1").unwrap();
        assert_eq!(report.verdict, SynthesisVerdict::InfrastructureFailure);
    }

    #[test]
    fn falsified_overrides_infra_failure() {
        let mut engine = SynthesisEngine::new(epoch());
        engine
            .add_input(make_input("s1", WorkloadDomain::BranchHeavy))
            .unwrap();
        let mut config = SynthesisConfig::minimal(epoch());
        config.min_iterations_per_domain = 1;
        config.max_iterations = 100;

        // First campaign: counterexample found.
        engine
            .run_campaign("c1", config.clone(), |_, _, _| Some(100_000))
            .unwrap();

        // Manually add an infra-failed campaign.
        let mut failed_campaign = SynthesisCampaign::new("c_fail", config);
        failed_campaign.record_infra_failure("disk full");
        engine.campaigns.push(failed_campaign);

        let report = engine.evaluate("r1").unwrap();
        // Falsified is the worst — it wins.
        assert_eq!(report.verdict, SynthesisVerdict::Falsified);
    }

    #[test]
    fn campaign_budget_exhaustion() {
        let mut config = SynthesisConfig::minimal(epoch());
        config.budget_ns = 500;
        let mut campaign = SynthesisCampaign::new("camp_budget", config);
        assert!(!campaign.budget_exhausted());
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 300);
        assert!(!campaign.budget_exhausted());
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 300);
        assert!(campaign.budget_exhausted());
    }

    #[test]
    fn campaign_iterations_exhaustion() {
        let mut config = SynthesisConfig::minimal(epoch());
        config.max_iterations = 2;
        let mut campaign = SynthesisCampaign::new("camp_iter", config);
        assert!(!campaign.iterations_exhausted());
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
        assert!(!campaign.iterations_exhausted());
        campaign.record_iteration(WorkloadDomain::BranchHeavy, None, 1);
        assert!(campaign.iterations_exhausted());
    }
}
