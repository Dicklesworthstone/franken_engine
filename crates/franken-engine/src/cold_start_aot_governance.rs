//! Cold-start AOT governance gate.
//!
//! Bead: bd-1lsy.7.10.3 [RGC-610C]
//!
//! Governs cold-start benchmark, parity, and rollback for cache/AOT paths so
//! startup win claims are published only when cached or AOT paths are truly
//! faster, semantically honest, and still defensible under observability modes.
//!
//! # Design
//!
//! - `StartupPathKind` classifies the startup path under evaluation.
//! - `BenchmarkVerdict` summarises a benchmark comparison (Faster/Slower/etc.).
//! - `ParityCheckKind` + `ParityResult` verify semantic, behavioral, and
//!   performance parity between the candidate and baseline path.
//! - `RollbackTrigger` enumerates conditions that force a rollback.
//! - `GovernanceConfig` configures thresholds, sample counts, staleness.
//! - `GovernanceVerdict` is the top-level gate output.
//! - `ColdStartEvidence` captures per-sample benchmark data.
//! - `DecisionReceipt` is a content-hashed governance receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-610C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.cold-start-aot-governance.v1";

/// Component name.
pub const COMPONENT: &str = "cold_start_aot_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.10.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-610C";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default minimum benchmark samples required.
pub const DEFAULT_MIN_BENCHMARK_SAMPLES: u64 = 30;

/// Default maximum regression threshold (millionths). 50_000 = 5%.
pub const DEFAULT_MAX_REGRESSION_MILLIONTHS: u64 = 50_000;

/// Default maximum staleness epochs before evidence expires.
pub const DEFAULT_MAX_STALENESS_EPOCHS: u64 = 10;

/// Default minimum speedup to qualify as "Faster" (millionths). 10_000 = 1%.
pub const DEFAULT_MIN_SPEEDUP_THRESHOLD: u64 = 10_000;

/// Default divergence tolerance for parity checks (millionths). 5_000 = 0.5%.
pub const DEFAULT_MAX_DIVERGENCE: u64 = 5_000;

// ---------------------------------------------------------------------------
// StartupPathKind
// ---------------------------------------------------------------------------

/// Classification of the startup path under governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPathKind {
    /// Cold start — no prior state, full initialisation.
    ColdStart,
    /// Warm cache — previous run artefacts in memory/disk.
    WarmCache,
    /// AOT-restored — ahead-of-time compiled image loaded.
    AotRestored,
    /// Zygote fork — fork from a pre-initialised parent process.
    ZygoteFork,
    /// Pre-warmed pool — reused from an idle pool.
    PrewarmedPool,
}

impl StartupPathKind {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::ColdStart,
        Self::WarmCache,
        Self::AotRestored,
        Self::ZygoteFork,
        Self::PrewarmedPool,
    ];

    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ColdStart => "cold_start",
            Self::WarmCache => "warm_cache",
            Self::AotRestored => "aot_restored",
            Self::ZygoteFork => "zygote_fork",
            Self::PrewarmedPool => "prewarmed_pool",
        }
    }

    /// Whether this path kind represents an optimised (non-cold) path.
    #[must_use]
    pub const fn is_optimised(self) -> bool {
        !matches!(self, Self::ColdStart)
    }
}

impl fmt::Display for StartupPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkVerdict
// ---------------------------------------------------------------------------

/// Outcome of comparing a candidate startup path against the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkVerdict {
    /// Candidate is faster by at least the minimum speedup threshold.
    Faster,
    /// Candidate is slower than the baseline.
    Slower,
    /// Candidate and baseline are within tolerance.
    Equivalent,
    /// Not enough data to decide.
    Inconclusive,
}

impl BenchmarkVerdict {
    /// All variants.
    pub const ALL: &[Self] = &[
        Self::Faster,
        Self::Slower,
        Self::Equivalent,
        Self::Inconclusive,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Faster => "faster",
            Self::Slower => "slower",
            Self::Equivalent => "equivalent",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether this verdict supports publishing a startup-win claim.
    #[must_use]
    pub const fn supports_win_claim(self) -> bool {
        matches!(self, Self::Faster)
    }
}

impl fmt::Display for BenchmarkVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityCheckKind
// ---------------------------------------------------------------------------

/// Kind of parity check between candidate and baseline paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityCheckKind {
    /// Outputs are byte-identical.
    SemanticParity,
    /// Same observable side effects (I/O, state mutations).
    BehavioralParity,
    /// Performance within tolerance of baseline.
    PerformanceParity,
}

impl ParityCheckKind {
    pub const ALL: &[Self] = &[
        Self::SemanticParity,
        Self::BehavioralParity,
        Self::PerformanceParity,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticParity => "semantic_parity",
            Self::BehavioralParity => "behavioral_parity",
            Self::PerformanceParity => "performance_parity",
        }
    }
}

impl fmt::Display for ParityCheckKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityResult
// ---------------------------------------------------------------------------

/// Result of a single parity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// Which check was performed.
    pub check_kind: ParityCheckKind,
    /// Whether the check passed.
    pub passed: bool,
    /// Measured divergence in millionths (0 = perfect parity).
    pub divergence_millionths: u64,
    /// Content hash of the evidence backing this result.
    pub evidence_hash: ContentHash,
}

impl ParityResult {
    /// Create a new parity result with computed evidence hash.
    #[must_use]
    pub fn new(
        check_kind: ParityCheckKind,
        passed: bool,
        divergence_millionths: u64,
        evidence: &[u8],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(check_kind.as_str().as_bytes());
        h.update(if passed { b"pass" } else { b"fail" });
        h.update(divergence_millionths.to_le_bytes());
        h.update(evidence);
        let evidence_hash = ContentHash::compute(&h.finalize());
        Self {
            check_kind,
            passed,
            divergence_millionths,
            evidence_hash,
        }
    }
}

impl fmt::Display for ParityResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParityResult({} passed={} divergence={})",
            self.check_kind, self.passed, self.divergence_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

/// Condition that forces a rollback of a startup-path optimisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTrigger {
    /// Output differs between baseline and candidate.
    SemanticDrift,
    /// Candidate is slower than baseline beyond tolerance.
    PerformanceRegression,
    /// Integrity of the cached/AOT artefact is compromised.
    IntegrityFailure,
    /// A policy rule was violated.
    PolicyViolation,
    /// Observability probes yield different traces.
    ObservabilityMismatch,
}

impl RollbackTrigger {
    pub const ALL: &[Self] = &[
        Self::SemanticDrift,
        Self::PerformanceRegression,
        Self::IntegrityFailure,
        Self::PolicyViolation,
        Self::ObservabilityMismatch,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticDrift => "semantic_drift",
            Self::PerformanceRegression => "performance_regression",
            Self::IntegrityFailure => "integrity_failure",
            Self::PolicyViolation => "policy_violation",
            Self::ObservabilityMismatch => "observability_mismatch",
        }
    }

    /// Whether this trigger is critical (requires immediate rollback).
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::SemanticDrift | Self::IntegrityFailure | Self::PolicyViolation
        )
    }
}

impl fmt::Display for RollbackTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configuration for the cold-start AOT governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum number of benchmark samples required before a verdict.
    pub min_benchmark_samples: u64,
    /// Maximum regression (millionths) before the candidate is rejected.
    pub max_regression_millionths: u64,
    /// Whether semantic parity is required for approval.
    pub require_semantic_parity: bool,
    /// Whether observability proof is required for approval.
    pub require_observability_proof: bool,
    /// Maximum staleness in epochs before evidence expires.
    pub max_staleness_epochs: u64,
    /// Minimum speedup (millionths) to qualify as Faster.
    pub min_speedup_threshold: u64,
    /// Maximum divergence (millionths) for parity checks.
    pub max_divergence: u64,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            min_benchmark_samples: DEFAULT_MIN_BENCHMARK_SAMPLES,
            max_regression_millionths: DEFAULT_MAX_REGRESSION_MILLIONTHS,
            require_semantic_parity: true,
            require_observability_proof: false,
            max_staleness_epochs: DEFAULT_MAX_STALENESS_EPOCHS,
            min_speedup_threshold: DEFAULT_MIN_SPEEDUP_THRESHOLD,
            max_divergence: DEFAULT_MAX_DIVERGENCE,
        }
    }
}

impl fmt::Display for GovernanceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceConfig(min_samples={} max_reg={} sem_parity={} obs_proof={} staleness={} speedup={} div={})",
            self.min_benchmark_samples,
            self.max_regression_millionths,
            self.require_semantic_parity,
            self.require_observability_proof,
            self.max_staleness_epochs,
            self.min_speedup_threshold,
            self.max_divergence
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Top-level verdict from the cold-start AOT governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks passed — startup-win claim may be published.
    Approved,
    /// One or more checks failed — claim must not be published.
    Blocked { reasons: Vec<String> },
    /// Active rollback is required.
    Rollback { triggers: Vec<RollbackTrigger> },
}

impl GovernanceVerdict {
    /// Whether the verdict allows publishing a startup-win claim.
    #[must_use]
    pub fn allows_publication(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Whether the verdict requires a rollback.
    #[must_use]
    pub fn requires_rollback(&self) -> bool {
        matches!(self, Self::Rollback { .. })
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => f.write_str("approved"),
            Self::Blocked { reasons } => {
                write!(f, "blocked(reasons={})", reasons.len())
            }
            Self::Rollback { triggers } => {
                write!(f, "rollback(triggers={})", triggers.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceError
// ---------------------------------------------------------------------------

/// Errors from governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceError {
    /// No evidence was provided.
    EmptyEvidence,
    /// Configuration is invalid.
    InvalidConfig { reason: String },
    /// Evidence is stale (epoch too old).
    StaleEvidence { age_epochs: u64 },
    /// Insufficient samples across all evidence.
    InsufficientSamples { have: u64, need: u64 },
}

impl GovernanceError {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyEvidence => "empty_evidence",
            Self::InvalidConfig { .. } => "invalid_config",
            Self::StaleEvidence { .. } => "stale_evidence",
            Self::InsufficientSamples { .. } => "insufficient_samples",
        }
    }
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEvidence => f.write_str("no evidence provided"),
            Self::InvalidConfig { reason } => write!(f, "invalid config: {reason}"),
            Self::StaleEvidence { age_epochs } => {
                write!(f, "stale evidence: age={age_epochs} epochs")
            }
            Self::InsufficientSamples { have, need } => {
                write!(f, "insufficient samples: have={have} need={need}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ColdStartEvidence
// ---------------------------------------------------------------------------

/// Evidence from a cold-start benchmark comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartEvidence {
    /// Kind of startup path being evaluated.
    pub path_kind: StartupPathKind,
    /// Baseline (cold-start) latency in nanoseconds.
    pub baseline_nanos: u64,
    /// Candidate path latency in nanoseconds.
    pub candidate_nanos: u64,
    /// Computed speedup in millionths (positive = faster, negative = slower).
    pub speedup_millionths: i64,
    /// Number of benchmark samples taken.
    pub sample_count: u64,
    /// Epoch when the evidence was collected.
    pub epoch: SecurityEpoch,
    /// Content hash of the evidence.
    pub evidence_hash: ContentHash,
}

impl ColdStartEvidence {
    /// Create new evidence with computed speedup and content hash.
    #[must_use]
    pub fn new(
        path_kind: StartupPathKind,
        baseline_nanos: u64,
        candidate_nanos: u64,
        sample_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let speedup_millionths = compute_speedup(baseline_nanos, candidate_nanos);
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(path_kind.as_str().as_bytes());
        h.update(baseline_nanos.to_le_bytes());
        h.update(candidate_nanos.to_le_bytes());
        h.update(speedup_millionths.to_le_bytes());
        h.update(sample_count.to_le_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        let evidence_hash = ContentHash::compute(&h.finalize());
        Self {
            path_kind,
            baseline_nanos,
            candidate_nanos,
            speedup_millionths,
            sample_count,
            epoch,
            evidence_hash,
        }
    }

    /// Determine the benchmark verdict relative to a given config.
    #[must_use]
    pub fn verdict(&self, config: &GovernanceConfig) -> BenchmarkVerdict {
        if self.sample_count < config.min_benchmark_samples {
            return BenchmarkVerdict::Inconclusive;
        }
        let threshold = config.min_speedup_threshold as i64;
        if self.speedup_millionths >= threshold {
            BenchmarkVerdict::Faster
        } else if self.speedup_millionths <= -threshold {
            BenchmarkVerdict::Slower
        } else {
            BenchmarkVerdict::Equivalent
        }
    }
}

impl fmt::Display for ColdStartEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ColdStartEvidence({} baseline={}ns candidate={}ns speedup={} n={})",
            self.path_kind,
            self.baseline_nanos,
            self.candidate_nanos,
            self.speedup_millionths,
            self.sample_count
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Content-hashed receipt for a governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Hash of the receipt (computed from all fields).
    pub receipt_hash: ContentHash,
    /// Component that produced this receipt.
    pub component: String,
    /// Epoch of the decision.
    pub epoch: SecurityEpoch,
    /// The verdict.
    pub verdict: GovernanceVerdict,
    /// Hashes of evidence inputs.
    pub evidence_hashes: Vec<ContentHash>,
    /// Hashes of parity results.
    pub parity_hashes: Vec<ContentHash>,
}

impl DecisionReceipt {
    /// Create a receipt with chained content hash.
    #[must_use]
    pub fn new(
        epoch: SecurityEpoch,
        verdict: GovernanceVerdict,
        evidence_hashes: Vec<ContentHash>,
        parity_hashes: Vec<ContentHash>,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(verdict.to_string().as_bytes());
        for eh in &evidence_hashes {
            h.update(eh.as_bytes());
        }
        for ph in &parity_hashes {
            h.update(ph.as_bytes());
        }
        let receipt_hash = ContentHash::compute(&h.finalize());
        Self {
            receipt_hash,
            component: COMPONENT.into(),
            epoch,
            verdict,
            evidence_hashes,
            parity_hashes,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecisionReceipt({} verdict={} evidence={} parity={} epoch={})",
            self.component,
            self.verdict,
            self.evidence_hashes.len(),
            self.parity_hashes.len(),
            self.epoch.as_u64()
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute speedup in millionths.
///
/// Returns positive if the candidate is faster (lower nanos), negative if
/// slower. If `baseline_nanos` is zero, returns 0 to avoid division by zero.
#[must_use]
pub fn compute_speedup(baseline_nanos: u64, candidate_nanos: u64) -> i64 {
    if baseline_nanos == 0 {
        return 0;
    }
    // speedup = (baseline - candidate) / baseline  (in millionths)
    let diff = baseline_nanos as i128 - candidate_nanos as i128;
    let result = diff.saturating_mul(FIXED_ONE as i128) / baseline_nanos as i128;
    result as i64
}

/// Validate a governance configuration.
///
/// Returns `Ok(())` if valid, or `Err(GovernanceError::InvalidConfig)` with a
/// description of the problem.
pub fn validate_config(config: &GovernanceConfig) -> Result<(), GovernanceError> {
    if config.min_benchmark_samples == 0 {
        return Err(GovernanceError::InvalidConfig {
            reason: "min_benchmark_samples must be > 0".into(),
        });
    }
    if config.max_regression_millionths > FIXED_ONE {
        return Err(GovernanceError::InvalidConfig {
            reason: "max_regression_millionths must be <= 1_000_000".into(),
        });
    }
    if config.max_staleness_epochs == 0 {
        return Err(GovernanceError::InvalidConfig {
            reason: "max_staleness_epochs must be > 0".into(),
        });
    }
    if config.min_speedup_threshold > FIXED_ONE {
        return Err(GovernanceError::InvalidConfig {
            reason: "min_speedup_threshold must be <= 1_000_000".into(),
        });
    }
    if config.max_divergence > FIXED_ONE {
        return Err(GovernanceError::InvalidConfig {
            reason: "max_divergence must be <= 1_000_000".into(),
        });
    }
    Ok(())
}

/// Check whether rollback is needed based on evidence and config.
///
/// Returns a list of rollback triggers; an empty list means no rollback needed.
#[must_use]
pub fn check_rollback_needed(
    evidence: &[ColdStartEvidence],
    config: &GovernanceConfig,
) -> Vec<RollbackTrigger> {
    let mut triggers = Vec::new();

    // Check for performance regression across samples.
    let regression_count = evidence
        .iter()
        .filter(|e| {
            e.speedup_millionths < 0
                && e.speedup_millionths.unsigned_abs() > config.max_regression_millionths
        })
        .count();
    if regression_count > 0 {
        triggers.push(RollbackTrigger::PerformanceRegression);
    }

    // Check for observability mismatch: if observability proof is required but
    // any evidence is from a non-cold path with zero speedup data, flag it.
    if config.require_observability_proof {
        let missing_observability = evidence
            .iter()
            .any(|e| e.path_kind.is_optimised() && e.sample_count == 0);
        if missing_observability {
            triggers.push(RollbackTrigger::ObservabilityMismatch);
        }
    }

    triggers
}

/// Evaluate cold-start governance from evidence, parity results, and config.
///
/// # Errors
///
/// Returns `GovernanceError` if evidence is empty or config is invalid.
pub fn evaluate_cold_start(
    evidence: &[ColdStartEvidence],
    parity: &[ParityResult],
    config: &GovernanceConfig,
) -> Result<GovernanceVerdict, GovernanceError> {
    validate_config(config)?;

    if evidence.is_empty() {
        return Err(GovernanceError::EmptyEvidence);
    }

    // Aggregate sample count.
    let total_samples: u64 = evidence.iter().map(|e| e.sample_count).sum();
    if total_samples < config.min_benchmark_samples {
        return Err(GovernanceError::InsufficientSamples {
            have: total_samples,
            need: config.min_benchmark_samples,
        });
    }

    // Check rollback triggers first — they take priority.
    let rollback_triggers = check_rollback_needed(evidence, config);
    if !rollback_triggers.is_empty() {
        return Ok(GovernanceVerdict::Rollback {
            triggers: rollback_triggers,
        });
    }

    let mut reasons = Vec::new();

    // Evaluate benchmark verdicts.
    let mut has_faster = false;
    let mut has_slower = false;
    for ev in evidence {
        let v = ev.verdict(config);
        if v == BenchmarkVerdict::Faster {
            has_faster = true;
        }
        if v == BenchmarkVerdict::Slower {
            has_slower = true;
        }
    }

    if has_slower {
        reasons.push("candidate path is slower than baseline in some samples".into());
    }
    if !has_faster {
        reasons.push("no evidence of speedup in any sample".into());
    }

    // Evaluate parity checks.
    if config.require_semantic_parity {
        let semantic_ok = parity
            .iter()
            .filter(|p| p.check_kind == ParityCheckKind::SemanticParity)
            .all(|p| p.passed);
        let has_semantic = parity
            .iter()
            .any(|p| p.check_kind == ParityCheckKind::SemanticParity);
        if !has_semantic {
            reasons.push("semantic parity evidence missing".into());
        } else if !semantic_ok {
            reasons.push("semantic parity check failed".into());
        }
    }

    // Check divergence across all parity results.
    for p in parity {
        if p.divergence_millionths > config.max_divergence && p.passed {
            reasons.push(format!(
                "{} divergence {} exceeds max {}",
                p.check_kind, p.divergence_millionths, config.max_divergence
            ));
        }
    }

    // Check observability proof requirement.
    if config.require_observability_proof {
        let has_behavioral = parity
            .iter()
            .any(|p| p.check_kind == ParityCheckKind::BehavioralParity && p.passed);
        if !has_behavioral {
            reasons.push("observability proof (behavioral parity) missing or failed".into());
        }
    }

    if reasons.is_empty() {
        Ok(GovernanceVerdict::Approved)
    } else {
        Ok(GovernanceVerdict::Blocked { reasons })
    }
}

/// Produce a decision receipt for a governance evaluation.
#[must_use]
pub fn produce_receipt(
    epoch: SecurityEpoch,
    evidence: &[ColdStartEvidence],
    parity: &[ParityResult],
    verdict: &GovernanceVerdict,
) -> DecisionReceipt {
    let evidence_hashes: Vec<ContentHash> = evidence.iter().map(|e| e.evidence_hash).collect();
    let parity_hashes: Vec<ContentHash> = parity.iter().map(|p| p.evidence_hash).collect();
    DecisionReceipt::new(epoch, verdict.clone(), evidence_hashes, parity_hashes)
}

/// Compute the aggregate speedup across multiple evidence records (weighted by
/// sample count).
#[must_use]
pub fn aggregate_speedup(evidence: &[ColdStartEvidence]) -> i64 {
    if evidence.is_empty() {
        return 0;
    }
    let total_samples: u64 = evidence.iter().map(|e| e.sample_count).sum();
    if total_samples == 0 {
        return 0;
    }
    let weighted_sum: i128 = evidence
        .iter()
        .map(|e| e.speedup_millionths as i128 * e.sample_count as i128)
        .sum();
    (weighted_sum / total_samples as i128) as i64
}

/// Determine the overall benchmark verdict from aggregated evidence.
#[must_use]
pub fn aggregate_verdict(
    evidence: &[ColdStartEvidence],
    config: &GovernanceConfig,
) -> BenchmarkVerdict {
    let total_samples: u64 = evidence.iter().map(|e| e.sample_count).sum();
    if total_samples < config.min_benchmark_samples {
        return BenchmarkVerdict::Inconclusive;
    }
    let speedup = aggregate_speedup(evidence);
    let threshold = config.min_speedup_threshold as i64;
    if speedup >= threshold {
        BenchmarkVerdict::Faster
    } else if speedup <= -threshold {
        BenchmarkVerdict::Slower
    } else {
        BenchmarkVerdict::Equivalent
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_evidence(
        path: StartupPathKind,
        baseline: u64,
        candidate: u64,
        samples: u64,
    ) -> ColdStartEvidence {
        ColdStartEvidence::new(path, baseline, candidate, samples, ep(10))
    }

    fn make_parity(kind: ParityCheckKind, passed: bool, divergence: u64) -> ParityResult {
        ParityResult::new(kind, passed, divergence, b"test-evidence")
    }

    fn default_config() -> GovernanceConfig {
        GovernanceConfig::default()
    }

    // -- Constants --

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("cold-start-aot-governance"));
        assert!(SCHEMA_VERSION.contains("v1"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "cold_start_aot_governance");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.10.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-610C");
    }

    #[test]
    fn test_fixed_one() {
        assert_eq!(FIXED_ONE, 1_000_000);
    }

    // -- StartupPathKind --

    #[test]
    fn test_startup_path_all_count() {
        assert_eq!(StartupPathKind::ALL.len(), 5);
    }

    #[test]
    fn test_startup_path_display() {
        assert_eq!(StartupPathKind::ColdStart.to_string(), "cold_start");
        assert_eq!(StartupPathKind::WarmCache.to_string(), "warm_cache");
        assert_eq!(StartupPathKind::AotRestored.to_string(), "aot_restored");
        assert_eq!(StartupPathKind::ZygoteFork.to_string(), "zygote_fork");
        assert_eq!(StartupPathKind::PrewarmedPool.to_string(), "prewarmed_pool");
    }

    #[test]
    fn test_startup_path_is_optimised() {
        assert!(!StartupPathKind::ColdStart.is_optimised());
        assert!(StartupPathKind::WarmCache.is_optimised());
        assert!(StartupPathKind::AotRestored.is_optimised());
        assert!(StartupPathKind::ZygoteFork.is_optimised());
        assert!(StartupPathKind::PrewarmedPool.is_optimised());
    }

    #[test]
    fn test_startup_path_serde_roundtrip() {
        for kind in StartupPathKind::ALL {
            let j = serde_json::to_string(kind).unwrap();
            let back: StartupPathKind = serde_json::from_str(&j).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // -- BenchmarkVerdict --

    #[test]
    fn test_benchmark_verdict_all_count() {
        assert_eq!(BenchmarkVerdict::ALL.len(), 4);
    }

    #[test]
    fn test_benchmark_verdict_display() {
        assert_eq!(BenchmarkVerdict::Faster.to_string(), "faster");
        assert_eq!(BenchmarkVerdict::Slower.to_string(), "slower");
        assert_eq!(BenchmarkVerdict::Equivalent.to_string(), "equivalent");
        assert_eq!(BenchmarkVerdict::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn test_benchmark_verdict_supports_win_claim() {
        assert!(BenchmarkVerdict::Faster.supports_win_claim());
        assert!(!BenchmarkVerdict::Slower.supports_win_claim());
        assert!(!BenchmarkVerdict::Equivalent.supports_win_claim());
        assert!(!BenchmarkVerdict::Inconclusive.supports_win_claim());
    }

    #[test]
    fn test_benchmark_verdict_serde_roundtrip() {
        for v in BenchmarkVerdict::ALL {
            let j = serde_json::to_string(v).unwrap();
            let back: BenchmarkVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- ParityCheckKind --

    #[test]
    fn test_parity_check_kind_all_count() {
        assert_eq!(ParityCheckKind::ALL.len(), 3);
    }

    #[test]
    fn test_parity_check_kind_display() {
        assert_eq!(
            ParityCheckKind::SemanticParity.to_string(),
            "semantic_parity"
        );
        assert_eq!(
            ParityCheckKind::BehavioralParity.to_string(),
            "behavioral_parity"
        );
        assert_eq!(
            ParityCheckKind::PerformanceParity.to_string(),
            "performance_parity"
        );
    }

    #[test]
    fn test_parity_check_kind_serde_roundtrip() {
        for k in ParityCheckKind::ALL {
            let j = serde_json::to_string(k).unwrap();
            let back: ParityCheckKind = serde_json::from_str(&j).unwrap();
            assert_eq!(*k, back);
        }
    }

    // -- RollbackTrigger --

    #[test]
    fn test_rollback_trigger_all_count() {
        assert_eq!(RollbackTrigger::ALL.len(), 5);
    }

    #[test]
    fn test_rollback_trigger_display() {
        assert_eq!(RollbackTrigger::SemanticDrift.to_string(), "semantic_drift");
        assert_eq!(
            RollbackTrigger::PerformanceRegression.to_string(),
            "performance_regression"
        );
        assert_eq!(
            RollbackTrigger::IntegrityFailure.to_string(),
            "integrity_failure"
        );
        assert_eq!(
            RollbackTrigger::PolicyViolation.to_string(),
            "policy_violation"
        );
        assert_eq!(
            RollbackTrigger::ObservabilityMismatch.to_string(),
            "observability_mismatch"
        );
    }

    #[test]
    fn test_rollback_trigger_is_critical() {
        assert!(RollbackTrigger::SemanticDrift.is_critical());
        assert!(!RollbackTrigger::PerformanceRegression.is_critical());
        assert!(RollbackTrigger::IntegrityFailure.is_critical());
        assert!(RollbackTrigger::PolicyViolation.is_critical());
        assert!(!RollbackTrigger::ObservabilityMismatch.is_critical());
    }

    #[test]
    fn test_rollback_trigger_serde_roundtrip() {
        for t in RollbackTrigger::ALL {
            let j = serde_json::to_string(t).unwrap();
            let back: RollbackTrigger = serde_json::from_str(&j).unwrap();
            assert_eq!(*t, back);
        }
    }

    // -- GovernanceConfig --

    #[test]
    fn test_config_default() {
        let cfg = GovernanceConfig::default();
        assert_eq!(cfg.min_benchmark_samples, 30);
        assert_eq!(cfg.max_regression_millionths, 50_000);
        assert!(cfg.require_semantic_parity);
        assert!(!cfg.require_observability_proof);
        assert_eq!(cfg.max_staleness_epochs, 10);
        assert_eq!(cfg.min_speedup_threshold, 10_000);
        assert_eq!(cfg.max_divergence, 5_000);
    }

    #[test]
    fn test_config_display() {
        let cfg = GovernanceConfig::default();
        let s = cfg.to_string();
        assert!(s.contains("GovernanceConfig"));
        assert!(s.contains("min_samples=30"));
    }

    #[test]
    fn test_validate_config_ok() {
        assert!(validate_config(&default_config()).is_ok());
    }

    #[test]
    fn test_validate_config_zero_samples() {
        let mut cfg = default_config();
        cfg.min_benchmark_samples = 0;
        let err = validate_config(&cfg).unwrap_err();
        assert_eq!(err.as_str(), "invalid_config");
    }

    #[test]
    fn test_validate_config_regression_too_large() {
        let mut cfg = default_config();
        cfg.max_regression_millionths = FIXED_ONE + 1;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_validate_config_zero_staleness() {
        let mut cfg = default_config();
        cfg.max_staleness_epochs = 0;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_validate_config_speedup_too_large() {
        let mut cfg = default_config();
        cfg.min_speedup_threshold = FIXED_ONE + 1;
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn test_validate_config_divergence_too_large() {
        let mut cfg = default_config();
        cfg.max_divergence = FIXED_ONE + 1;
        assert!(validate_config(&cfg).is_err());
    }

    // -- compute_speedup --

    #[test]
    fn test_compute_speedup_faster() {
        // Candidate takes 80ns vs baseline 100ns => 20% speedup => 200_000 millionths
        let s = compute_speedup(100, 80);
        assert_eq!(s, 200_000);
    }

    #[test]
    fn test_compute_speedup_slower() {
        // Candidate takes 120ns vs baseline 100ns => -20% => -200_000 millionths
        let s = compute_speedup(100, 120);
        assert_eq!(s, -200_000);
    }

    #[test]
    fn test_compute_speedup_equal() {
        assert_eq!(compute_speedup(100, 100), 0);
    }

    #[test]
    fn test_compute_speedup_zero_baseline() {
        assert_eq!(compute_speedup(0, 100), 0);
    }

    #[test]
    fn test_compute_speedup_zero_candidate() {
        // 100% speedup
        assert_eq!(compute_speedup(100, 0), 1_000_000);
    }

    // -- ColdStartEvidence --

    #[test]
    fn test_evidence_creation() {
        let ev = make_evidence(StartupPathKind::AotRestored, 100, 80, 50);
        assert_eq!(ev.path_kind, StartupPathKind::AotRestored);
        assert_eq!(ev.baseline_nanos, 100);
        assert_eq!(ev.candidate_nanos, 80);
        assert_eq!(ev.speedup_millionths, 200_000);
        assert_eq!(ev.sample_count, 50);
    }

    #[test]
    fn test_evidence_verdict_faster() {
        let cfg = default_config();
        let ev = make_evidence(StartupPathKind::WarmCache, 1000, 800, 50);
        assert_eq!(ev.verdict(&cfg), BenchmarkVerdict::Faster);
    }

    #[test]
    fn test_evidence_verdict_slower() {
        let cfg = default_config();
        let ev = make_evidence(StartupPathKind::WarmCache, 1000, 1200, 50);
        assert_eq!(ev.verdict(&cfg), BenchmarkVerdict::Slower);
    }

    #[test]
    fn test_evidence_verdict_equivalent() {
        let cfg = default_config();
        // 0.5% speedup — below threshold
        let ev = make_evidence(StartupPathKind::WarmCache, 1000, 995, 50);
        assert_eq!(ev.verdict(&cfg), BenchmarkVerdict::Equivalent);
    }

    #[test]
    fn test_evidence_verdict_inconclusive() {
        let cfg = default_config();
        let ev = make_evidence(StartupPathKind::WarmCache, 1000, 800, 5); // too few samples
        assert_eq!(ev.verdict(&cfg), BenchmarkVerdict::Inconclusive);
    }

    #[test]
    fn test_evidence_display() {
        let ev = make_evidence(StartupPathKind::AotRestored, 100, 80, 50);
        let s = ev.to_string();
        assert!(s.contains("ColdStartEvidence"));
        assert!(s.contains("aot_restored"));
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let ev1 = make_evidence(StartupPathKind::AotRestored, 100, 80, 50);
        let ev2 = make_evidence(StartupPathKind::AotRestored, 100, 80, 50);
        assert_eq!(ev1.evidence_hash, ev2.evidence_hash);
    }

    #[test]
    fn test_evidence_hash_varies_with_path() {
        let ev1 = make_evidence(StartupPathKind::AotRestored, 100, 80, 50);
        let ev2 = make_evidence(StartupPathKind::WarmCache, 100, 80, 50);
        assert_ne!(ev1.evidence_hash, ev2.evidence_hash);
    }

    // -- ParityResult --

    #[test]
    fn test_parity_result_creation() {
        let p = make_parity(ParityCheckKind::SemanticParity, true, 0);
        assert!(p.passed);
        assert_eq!(p.divergence_millionths, 0);
    }

    #[test]
    fn test_parity_result_display() {
        let p = make_parity(ParityCheckKind::BehavioralParity, false, 100_000);
        let s = p.to_string();
        assert!(s.contains("ParityResult"));
        assert!(s.contains("behavioral_parity"));
        assert!(s.contains("false"));
    }

    // -- GovernanceVerdict --

    #[test]
    fn test_verdict_approved() {
        let v = GovernanceVerdict::Approved;
        assert!(v.allows_publication());
        assert!(!v.requires_rollback());
        assert_eq!(v.to_string(), "approved");
    }

    #[test]
    fn test_verdict_blocked() {
        let v = GovernanceVerdict::Blocked {
            reasons: vec!["test".into()],
        };
        assert!(!v.allows_publication());
        assert!(!v.requires_rollback());
        assert!(v.to_string().contains("blocked"));
    }

    #[test]
    fn test_verdict_rollback() {
        let v = GovernanceVerdict::Rollback {
            triggers: vec![RollbackTrigger::SemanticDrift],
        };
        assert!(!v.allows_publication());
        assert!(v.requires_rollback());
        assert!(v.to_string().contains("rollback"));
    }

    // -- GovernanceError --

    #[test]
    fn test_error_display() {
        assert_eq!(
            GovernanceError::EmptyEvidence.to_string(),
            "no evidence provided"
        );
        let e = GovernanceError::InvalidConfig {
            reason: "bad".into(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn test_error_as_str() {
        assert_eq!(GovernanceError::EmptyEvidence.as_str(), "empty_evidence");
        assert_eq!(
            GovernanceError::InsufficientSamples { have: 1, need: 30 }.as_str(),
            "insufficient_samples"
        );
    }

    // -- check_rollback_needed --

    #[test]
    fn test_no_rollback_when_no_regression() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let triggers = check_rollback_needed(&evidence, &cfg);
        assert!(triggers.is_empty());
    }

    #[test]
    fn test_rollback_on_regression() {
        let cfg = default_config();
        // 60% regression, exceeds 5% threshold
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 100, 160, 50)];
        let triggers = check_rollback_needed(&evidence, &cfg);
        assert!(triggers.contains(&RollbackTrigger::PerformanceRegression));
    }

    #[test]
    fn test_rollback_observability_mismatch() {
        let mut cfg = default_config();
        cfg.require_observability_proof = true;
        // Optimised path with 0 samples => missing observability
        let evidence = vec![ColdStartEvidence::new(
            StartupPathKind::AotRestored,
            100,
            80,
            0,
            ep(10),
        )];
        let triggers = check_rollback_needed(&evidence, &cfg);
        assert!(triggers.contains(&RollbackTrigger::ObservabilityMismatch));
    }

    // -- evaluate_cold_start --

    #[test]
    fn test_evaluate_approved() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        assert_eq!(verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluate_blocked_no_speedup() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 1000, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("no evidence of speedup")));
            }
            other => panic!("expected Blocked, got {other}"),
        }
    }

    #[test]
    fn test_evaluate_blocked_semantic_parity_failed() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, false, 100_000)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("semantic parity")));
            }
            other => panic!("expected Blocked, got {other}"),
        }
    }

    #[test]
    fn test_evaluate_empty_evidence_error() {
        let cfg = default_config();
        let err = evaluate_cold_start(&[], &[], &cfg).unwrap_err();
        assert_eq!(err, GovernanceError::EmptyEvidence);
    }

    #[test]
    fn test_evaluate_insufficient_samples_error() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 5)];
        let err = evaluate_cold_start(&evidence, &[], &cfg).unwrap_err();
        match err {
            GovernanceError::InsufficientSamples { have, need } => {
                assert_eq!(have, 5);
                assert_eq!(need, 30);
            }
            other => panic!("expected InsufficientSamples, got {other}"),
        }
    }

    #[test]
    fn test_evaluate_rollback_takes_priority() {
        let cfg = default_config();
        // 80% regression => triggers rollback
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 100, 180, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        assert!(verdict.requires_rollback());
    }

    // -- aggregate_speedup --

    #[test]
    fn test_aggregate_speedup_single() {
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let s = aggregate_speedup(&evidence);
        assert_eq!(s, 200_000);
    }

    #[test]
    fn test_aggregate_speedup_weighted() {
        let ev1 = make_evidence(StartupPathKind::WarmCache, 1000, 800, 100); // 200_000
        let ev2 = make_evidence(StartupPathKind::AotRestored, 1000, 900, 100); // 100_000
        let s = aggregate_speedup(&[ev1, ev2]);
        assert_eq!(s, 150_000); // weighted average
    }

    #[test]
    fn test_aggregate_speedup_empty() {
        assert_eq!(aggregate_speedup(&[]), 0);
    }

    // -- aggregate_verdict --

    #[test]
    fn test_aggregate_verdict_faster() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        assert_eq!(aggregate_verdict(&evidence, &cfg), BenchmarkVerdict::Faster);
    }

    #[test]
    fn test_aggregate_verdict_slower() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 1200, 50)];
        assert_eq!(aggregate_verdict(&evidence, &cfg), BenchmarkVerdict::Slower);
    }

    #[test]
    fn test_aggregate_verdict_inconclusive_few_samples() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 5)];
        assert_eq!(
            aggregate_verdict(&evidence, &cfg),
            BenchmarkVerdict::Inconclusive
        );
    }

    // -- DecisionReceipt --

    #[test]
    fn test_receipt_creation() {
        let r = DecisionReceipt::new(
            ep(10),
            GovernanceVerdict::Approved,
            vec![ContentHash::compute(b"e1")],
            vec![ContentHash::compute(b"p1")],
        );
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.epoch, ep(10));
        assert!(r.verdict.allows_publication());
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let r1 = DecisionReceipt::new(
            ep(10),
            GovernanceVerdict::Approved,
            vec![ContentHash::compute(b"e1")],
            vec![],
        );
        let r2 = DecisionReceipt::new(
            ep(10),
            GovernanceVerdict::Approved,
            vec![ContentHash::compute(b"e1")],
            vec![],
        );
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_receipt_hash_varies_with_verdict() {
        let r1 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
        let r2 = DecisionReceipt::new(
            ep(10),
            GovernanceVerdict::Blocked {
                reasons: vec!["x".into()],
            },
            vec![],
            vec![],
        );
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_receipt_display() {
        let r = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
        let s = r.to_string();
        assert!(s.contains("DecisionReceipt"));
        assert!(s.contains("approved"));
    }

    // -- produce_receipt --

    #[test]
    fn test_produce_receipt() {
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = GovernanceVerdict::Approved;
        let receipt = produce_receipt(ep(10), &evidence, &parity, &verdict);
        assert_eq!(receipt.evidence_hashes.len(), 1);
        assert_eq!(receipt.parity_hashes.len(), 1);
        assert!(receipt.verdict.allows_publication());
    }

    // -- Observability proof requirement --

    #[test]
    fn test_evaluate_requires_observability_proof() {
        let mut cfg = default_config();
        cfg.require_observability_proof = true;
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("observability")));
            }
            other => panic!("expected Blocked, got {other}"),
        }
    }

    #[test]
    fn test_evaluate_observability_proof_satisfied() {
        let mut cfg = default_config();
        cfg.require_observability_proof = true;
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let parity = vec![
            make_parity(ParityCheckKind::SemanticParity, true, 0),
            make_parity(ParityCheckKind::BehavioralParity, true, 0),
        ];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        assert_eq!(verdict, GovernanceVerdict::Approved);
    }

    // -- Edge cases --

    #[test]
    fn test_evaluate_invalid_config_propagates() {
        let mut cfg = default_config();
        cfg.min_benchmark_samples = 0;
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        let err = evaluate_cold_start(&evidence, &[], &cfg).unwrap_err();
        assert_eq!(err.as_str(), "invalid_config");
    }

    #[test]
    fn test_evaluate_semantic_parity_not_required() {
        let mut cfg = default_config();
        cfg.require_semantic_parity = false;
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        // No parity results at all — should still approve.
        let verdict = evaluate_cold_start(&evidence, &[], &cfg).unwrap();
        assert_eq!(verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_divergence_exceeding_max() {
        let cfg = default_config();
        let evidence = vec![make_evidence(StartupPathKind::WarmCache, 1000, 800, 50)];
        // Semantic parity passes but divergence exceeds max.
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 100_000)];
        let verdict = evaluate_cold_start(&evidence, &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("divergence")));
            }
            other => panic!("expected Blocked, got {other}"),
        }
    }

    #[test]
    fn test_multiple_evidence_mixed_verdicts() {
        let cfg = default_config();
        let ev_fast = make_evidence(StartupPathKind::WarmCache, 1000, 800, 50);
        // Regression exceeds max_regression_millionths (50_000), so rollback
        // takes priority over a simple "Blocked" verdict.
        let ev_slow = make_evidence(StartupPathKind::AotRestored, 1000, 1200, 50);
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&[ev_fast, ev_slow], &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Rollback { triggers } => {
                assert!(!triggers.is_empty());
            }
            other => panic!("expected Rollback, got {other}"),
        }
    }

    #[test]
    fn test_multiple_evidence_mild_regression_blocked() {
        let mut cfg = default_config();
        cfg.max_regression_millionths = 300_000; // raise threshold so rollback doesn't trigger
        let ev_fast = make_evidence(StartupPathKind::WarmCache, 1000, 800, 50);
        // -200_000 speedup: below rollback threshold (300k) but still slower
        let ev_slow = make_evidence(StartupPathKind::AotRestored, 1000, 1200, 50);
        let parity = vec![make_parity(ParityCheckKind::SemanticParity, true, 0)];
        let verdict = evaluate_cold_start(&[ev_fast, ev_slow], &parity, &cfg).unwrap();
        match verdict {
            GovernanceVerdict::Blocked { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("slower")));
            }
            other => panic!("expected Blocked, got {other}"),
        }
    }

    #[test]
    fn test_governance_error_serde_roundtrip() {
        let errors = vec![
            GovernanceError::EmptyEvidence,
            GovernanceError::InvalidConfig {
                reason: "test".into(),
            },
            GovernanceError::StaleEvidence { age_epochs: 5 },
            GovernanceError::InsufficientSamples { have: 1, need: 30 },
        ];
        for e in &errors {
            let j = serde_json::to_string(e).unwrap();
            let back: GovernanceError = serde_json::from_str(&j).unwrap();
            assert_eq!(*e, back);
        }
    }

    #[test]
    fn test_governance_verdict_serde_roundtrip() {
        let verdicts = vec![
            GovernanceVerdict::Approved,
            GovernanceVerdict::Blocked {
                reasons: vec!["x".into()],
            },
            GovernanceVerdict::Rollback {
                triggers: vec![RollbackTrigger::SemanticDrift],
            },
        ];
        for v in &verdicts {
            let j = serde_json::to_string(v).unwrap();
            let back: GovernanceVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(*v, back);
        }
    }
}
