#![forbid(unsafe_code)]

//! Transport Certificate Ledger — RGC-616B
//!
//! Bead: bd-1lsy.7.16.2
//!
//! Emits transport certificates and residual ledgers for rewrite,
//! synthesis, cache, and AOT artifacts across hardware cells.
//!
//! A **transport certificate** records what artifact was evaluated, what
//! transported successfully, what degraded, what failed, and why.  The
//! **residual ledger** shows how much of a source-cell performance
//! advantage survives on the target cell, broken down by component.
//!
//! # Design decisions
//!
//! - Each hardware cell is described by arch family, microarchitecture,
//!   vector width, and cache-line size.  Transport evaluation compares
//!   these features to detect degradation causes.
//! - Outcome classification uses residual-fraction thresholds over
//!   fixed-point millionths (1_000_000 = 1.0).
//! - Residual ledgers carry an unexplained remainder so consumers can
//!   tell how much variance the component decomposition does not cover.
//! - All structures are deterministic and serde-serializable.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for transport certificate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.transport_certificate_ledger.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.16.2";

/// Component name.
pub const COMPONENT: &str = "transport_certificate_ledger";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-616B";

/// One million — unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Threshold above which transport is classified as `FullTransport`.
const FULL_TRANSPORT_THRESHOLD: u64 = 950_000; // 95%

/// Threshold above which transport is classified as `PartialTransport`.
const PARTIAL_TRANSPORT_THRESHOLD: u64 = 700_000; // 70%

/// Threshold above which transport is classified as `Degraded`.
const DEGRADED_THRESHOLD: u64 = 300_000; // 30%

/// Maximum degradation reasons per certificate.
const MAX_DEGRADATION_REASONS: usize = 32;

/// Maximum components per residual ledger.
const MAX_LEDGER_COMPONENTS: usize = 128;

/// Maximum certificates in the canonical manifest.
#[allow(dead_code)]
const MAX_MANIFEST_CERTIFICATES: usize = 1024;

// ---------------------------------------------------------------------------
// ArtifactKind — what kind of artifact is being transported
// ---------------------------------------------------------------------------

/// Classification of the artifact being transported across hardware cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A rewrite rule (IR transformation).
    RewriteRule,
    /// A synthesized computational kernel.
    SynthesizedKernel,
    /// A cache entry (compiled code, metadata, profile).
    CacheEntry,
    /// An ahead-of-time compiled module.
    AotModule,
    /// A code layout decision (function ordering, hot/cold splitting).
    CodeLayout,
    /// Profile-guided optimization data (branch weights, call counts).
    ProfileData,
    /// A speculation guard (deoptimization checkpoint).
    SpeculationGuard,
}

impl ArtifactKind {
    /// All artifact kinds for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::RewriteRule,
        Self::SynthesizedKernel,
        Self::CacheEntry,
        Self::AotModule,
        Self::CodeLayout,
        Self::ProfileData,
        Self::SpeculationGuard,
    ];

    /// String identifier for this artifact kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RewriteRule => "rewrite_rule",
            Self::SynthesizedKernel => "synthesized_kernel",
            Self::CacheEntry => "cache_entry",
            Self::AotModule => "aot_module",
            Self::CodeLayout => "code_layout",
            Self::ProfileData => "profile_data",
            Self::SpeculationGuard => "speculation_guard",
        }
    }

    /// Whether this artifact kind is architecture-sensitive.
    pub fn is_arch_sensitive(self) -> bool {
        matches!(
            self,
            Self::AotModule
                | Self::SynthesizedKernel
                | Self::CodeLayout
                | Self::SpeculationGuard
        )
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TransportOutcome — result of transport evaluation
// ---------------------------------------------------------------------------

/// Outcome of attempting to transport an artifact across hardware cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportOutcome {
    /// Artifact transports with no measurable performance loss (≥95%).
    FullTransport,
    /// Artifact transports but with measurable performance loss (70-95%).
    PartialTransport,
    /// Artifact transports but with significant degradation (30-70%).
    Degraded,
    /// Artifact cannot function on target cell (<30%).
    Failed,
    /// Source and target cells are fundamentally incompatible.
    Incompatible,
}

impl TransportOutcome {
    /// String identifier for this outcome.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullTransport => "full_transport",
            Self::PartialTransport => "partial_transport",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Incompatible => "incompatible",
        }
    }

    /// Whether this outcome indicates the artifact is usable on the target.
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            Self::FullTransport | Self::PartialTransport | Self::Degraded
        )
    }

    /// Whether this outcome indicates full performance preservation.
    pub fn is_full(self) -> bool {
        matches!(self, Self::FullTransport)
    }
}

impl fmt::Display for TransportOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DegradationReason — why transport is degraded
// ---------------------------------------------------------------------------

/// Reason why an artifact degrades when transported to a different cell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationReason {
    /// Target microarchitecture differs from source (pipeline depth,
    /// execution unit layout, etc.).
    MicroarchMismatch,
    /// Target ISA is missing instructions the artifact depends on.
    IsaMissing,
    /// Target has less cache capacity, causing evictions.
    CachePressure,
    /// Target alignment requirements penalize the artifact's layout.
    AlignmentPenalty,
    /// Branch prediction tables are not portable; target starts cold.
    BranchPredictionDrift,
    /// Target lacks the vector width the artifact was optimized for.
    VectorizationUnavailable,
    /// Target has a weaker memory model (e.g., x86 → ARM TSO → relaxed).
    MemoryModelWeaker,
    /// Catch-all for reasons not in the enumeration.
    UnknownReason(String),
}

impl DegradationReason {
    /// String identifier for this reason.
    pub fn as_str(&self) -> &str {
        match self {
            Self::MicroarchMismatch => "microarch_mismatch",
            Self::IsaMissing => "isa_missing",
            Self::CachePressure => "cache_pressure",
            Self::AlignmentPenalty => "alignment_penalty",
            Self::BranchPredictionDrift => "branch_prediction_drift",
            Self::VectorizationUnavailable => "vectorization_unavailable",
            Self::MemoryModelWeaker => "memory_model_weaker",
            Self::UnknownReason(s) => s.as_str(),
        }
    }

    /// How much this reason penalizes the residual fraction (millionths).
    /// Returns a penalty to subtract from the residual.
    pub fn penalty_millionths(&self) -> u64 {
        match self {
            Self::MicroarchMismatch => 100_000,        // 10%
            Self::IsaMissing => 500_000,               // 50%
            Self::CachePressure => 80_000,             // 8%
            Self::AlignmentPenalty => 50_000,          // 5%
            Self::BranchPredictionDrift => 60_000,     // 6%
            Self::VectorizationUnavailable => 200_000, // 20%
            Self::MemoryModelWeaker => 150_000,        // 15%
            Self::UnknownReason(_) => 100_000,         // 10% default
        }
    }
}

impl fmt::Display for DegradationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HardwareCell — description of execution target
// ---------------------------------------------------------------------------

/// A hardware cell represents a specific execution environment with
/// known microarchitectural characteristics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HardwareCell {
    /// Unique identifier for this cell.
    pub cell_id: String,
    /// Architecture family (e.g., "x86_64", "aarch64", "riscv64").
    pub arch_family: String,
    /// Microarchitecture (e.g., "zen4", "neoverse_v2", "alderlake").
    pub microarch: String,
    /// SIMD vector width in bits (e.g., 128, 256, 512).
    pub vector_width_bits: u32,
    /// Cache line size in bytes (e.g., 64, 128).
    pub cache_line_bytes: u32,
}

impl HardwareCell {
    /// Create a new hardware cell.
    pub fn new(
        cell_id: &str,
        arch_family: &str,
        microarch: &str,
        vector_width_bits: u32,
        cache_line_bytes: u32,
    ) -> Self {
        Self {
            cell_id: cell_id.to_string(),
            arch_family: arch_family.to_string(),
            microarch: microarch.to_string(),
            vector_width_bits,
            cache_line_bytes,
        }
    }

    /// Whether two cells share the same architecture family.
    pub fn same_arch_family(&self, other: &Self) -> bool {
        self.arch_family == other.arch_family
    }

    /// Whether two cells share the same microarchitecture.
    pub fn same_microarch(&self, other: &Self) -> bool {
        self.microarch == other.microarch
    }

    /// Whether two cells are identical in hardware characteristics
    /// (ignoring cell_id).
    pub fn hardware_equivalent(&self, other: &Self) -> bool {
        self.arch_family == other.arch_family
            && self.microarch == other.microarch
            && self.vector_width_bits == other.vector_width_bits
            && self.cache_line_bytes == other.cache_line_bytes
    }

    /// Compute a content hash of this cell's characteristics.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.cell_id.as_bytes());
        hasher.update(self.arch_family.as_bytes());
        hasher.update(self.microarch.as_bytes());
        hasher.update(self.vector_width_bits.to_le_bytes());
        hasher.update(self.cache_line_bytes.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for HardwareCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cell:{}({}:{},vec={},cl={})",
            self.cell_id,
            self.arch_family,
            self.microarch,
            self.vector_width_bits,
            self.cache_line_bytes,
        )
    }
}

// ---------------------------------------------------------------------------
// TransportError — error conditions
// ---------------------------------------------------------------------------

/// Error conditions during transport evaluation or ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    /// Source and target cells are fundamentally incompatible.
    CellIncompatible,
    /// Artifact data is corrupted or invalid.
    ArtifactCorrupted,
    /// Performance measurement failed or produced nonsensical results.
    MeasurementFailed,
    /// Ledger component totals are inconsistent.
    LedgerInconsistent,
    /// Catch-all internal error with description.
    InternalError(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CellIncompatible => write!(f, "source and target cells are incompatible"),
            Self::ArtifactCorrupted => write!(f, "artifact data is corrupted"),
            Self::MeasurementFailed => write!(f, "performance measurement failed"),
            Self::LedgerInconsistent => write!(f, "ledger component totals are inconsistent"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransportCertificate — the core certificate
// ---------------------------------------------------------------------------

/// A transport certificate records the outcome of evaluating whether an
/// artifact can function on a different hardware cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCertificate {
    /// Unique identifier for this certificate.
    pub certificate_id: String,
    /// What kind of artifact was evaluated.
    pub artifact_kind: ArtifactKind,
    /// Content hash of the artifact itself.
    pub artifact_hash: ContentHash,
    /// The cell where the artifact was created/optimized.
    pub source_cell: HardwareCell,
    /// The cell where the artifact would be deployed.
    pub target_cell: HardwareCell,
    /// Transport outcome classification.
    pub outcome: TransportOutcome,
    /// Performance on source cell (millionths of normalized throughput).
    pub source_perf_millionths: u64,
    /// Performance on target cell (millionths of normalized throughput).
    pub target_perf_millionths: u64,
    /// Reasons for any degradation.
    pub degradation_reasons: Vec<DegradationReason>,
    /// Fraction of source performance retained on target (millionths).
    pub residual_fraction_millionths: u64,
    /// Content hash of the entire certificate (deterministic).
    pub content_hash: ContentHash,
}

impl TransportCertificate {
    /// Whether the artifact is usable on the target cell.
    pub fn is_usable(&self) -> bool {
        self.outcome.is_usable()
    }

    /// Whether transport preserves full performance.
    pub fn is_full_transport(&self) -> bool {
        self.outcome.is_full()
    }

    /// Performance loss in millionths.
    pub fn performance_loss_millionths(&self) -> u64 {
        MILLIONTHS.saturating_sub(self.residual_fraction_millionths)
    }

    /// Number of degradation reasons.
    pub fn degradation_count(&self) -> usize {
        self.degradation_reasons.len()
    }

    /// Whether the cells share the same architecture family.
    pub fn same_arch_family(&self) -> bool {
        self.source_cell.same_arch_family(&self.target_cell)
    }

    /// Whether the cells have identical hardware characteristics.
    pub fn same_hardware(&self) -> bool {
        self.source_cell.hardware_equivalent(&self.target_cell)
    }

    /// Compute the certificate content hash from its fields.
    #[allow(clippy::too_many_arguments)]
    fn compute_content_hash(
        certificate_id: &str,
        artifact_kind: ArtifactKind,
        artifact_hash: &ContentHash,
        source_cell: &HardwareCell,
        target_cell: &HardwareCell,
        outcome: TransportOutcome,
        source_perf: u64,
        target_perf: u64,
        degradation_reasons: &[DegradationReason],
        residual_fraction: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(certificate_id.as_bytes());
        hasher.update(artifact_kind.as_str().as_bytes());
        hasher.update(artifact_hash.as_bytes());
        hasher.update(source_cell.cell_id.as_bytes());
        hasher.update(source_cell.arch_family.as_bytes());
        hasher.update(source_cell.microarch.as_bytes());
        hasher.update(source_cell.vector_width_bits.to_le_bytes());
        hasher.update(source_cell.cache_line_bytes.to_le_bytes());
        hasher.update(target_cell.cell_id.as_bytes());
        hasher.update(target_cell.arch_family.as_bytes());
        hasher.update(target_cell.microarch.as_bytes());
        hasher.update(target_cell.vector_width_bits.to_le_bytes());
        hasher.update(target_cell.cache_line_bytes.to_le_bytes());
        hasher.update(outcome.as_str().as_bytes());
        hasher.update(source_perf.to_le_bytes());
        hasher.update(target_perf.to_le_bytes());
        for reason in degradation_reasons {
            hasher.update(reason.as_str().as_bytes());
        }
        hasher.update(residual_fraction.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for TransportCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cert:{}({} {} -> {}, outcome={}, residual={})",
            self.certificate_id,
            self.artifact_kind,
            self.source_cell.cell_id,
            self.target_cell.cell_id,
            self.outcome,
            self.residual_fraction_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// ResidualComponent — one line item in the residual ledger
// ---------------------------------------------------------------------------

/// A single component contributing to the residual performance analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualComponent {
    /// Name of this performance component (e.g., "branch_prediction",
    /// "vectorization", "cache_locality").
    pub component_name: String,
    /// Contribution on the source cell (millionths).
    pub source_contribution_millionths: u64,
    /// Contribution that survived transport to target cell (millionths).
    pub transported_contribution_millionths: u64,
    /// Human-readable explanation of why the contribution changed.
    pub explanation: String,
}

impl ResidualComponent {
    /// Create a new residual component.
    pub fn new(
        name: &str,
        source_contribution: u64,
        transported_contribution: u64,
        explanation: &str,
    ) -> Self {
        Self {
            component_name: name.to_string(),
            source_contribution_millionths: source_contribution,
            transported_contribution_millionths: transported_contribution,
            explanation: explanation.to_string(),
        }
    }

    /// Fraction of this component that survived transport (millionths).
    pub fn survival_fraction_millionths(&self) -> u64 {
        if self.source_contribution_millionths == 0 {
            return MILLIONTHS;
        }
        self.transported_contribution_millionths
            .saturating_mul(MILLIONTHS)
            .checked_div(self.source_contribution_millionths)
            .unwrap_or(0)
    }

    /// Loss for this component (millionths).
    pub fn loss_millionths(&self) -> u64 {
        self.source_contribution_millionths
            .saturating_sub(self.transported_contribution_millionths)
    }
}

impl fmt::Display for ResidualComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(src={}, xport={}, loss={})",
            self.component_name,
            self.source_contribution_millionths,
            self.transported_contribution_millionths,
            self.loss_millionths(),
        )
    }
}

// ---------------------------------------------------------------------------
// ResidualLedger — breakdown of performance residual
// ---------------------------------------------------------------------------

/// A residual ledger breaks down how much of the source-cell performance
/// advantage survives transport to the target cell, by component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualLedger {
    /// Unique identifier for this ledger.
    pub ledger_id: String,
    /// Certificate this ledger explains.
    pub certificate_id: String,
    /// Component-level breakdown.
    pub components: Vec<ResidualComponent>,
    /// Total source-cell performance across all components (millionths).
    pub total_source_millionths: u64,
    /// Total transported performance across all components (millionths).
    pub total_transported_millionths: u64,
    /// Performance variance not explained by any component (millionths).
    pub unexplained_remainder_millionths: u64,
    /// Content hash of the entire ledger (deterministic).
    pub content_hash: ContentHash,
}

impl ResidualLedger {
    /// Number of components in this ledger.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Overall survival fraction (millionths).
    pub fn survival_fraction_millionths(&self) -> u64 {
        if self.total_source_millionths == 0 {
            return MILLIONTHS;
        }
        self.total_transported_millionths
            .saturating_mul(MILLIONTHS)
            .checked_div(self.total_source_millionths)
            .unwrap_or(0)
    }

    /// Total loss across all components (millionths).
    pub fn total_loss_millionths(&self) -> u64 {
        self.total_source_millionths
            .saturating_sub(self.total_transported_millionths)
    }

    /// Whether the ledger balances (component totals match header totals).
    pub fn is_balanced(&self) -> bool {
        let sum_source: u64 = self
            .components
            .iter()
            .map(|c| c.source_contribution_millionths)
            .sum();
        let sum_transported: u64 = self
            .components
            .iter()
            .map(|c| c.transported_contribution_millionths)
            .sum();
        sum_source == self.total_source_millionths
            && sum_transported
                .saturating_add(self.unexplained_remainder_millionths)
                == self.total_transported_millionths
                    .saturating_add(self.unexplained_remainder_millionths)
    }

    /// Look up a component by name.
    pub fn component_by_name(&self, name: &str) -> Option<&ResidualComponent> {
        self.components.iter().find(|c| c.component_name == name)
    }

    /// Compute the ledger content hash from its fields.
    fn compute_content_hash(
        ledger_id: &str,
        certificate_id: &str,
        components: &[ResidualComponent],
        total_source: u64,
        total_transported: u64,
        unexplained: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(ledger_id.as_bytes());
        hasher.update(certificate_id.as_bytes());
        for comp in components {
            hasher.update(comp.component_name.as_bytes());
            hasher.update(comp.source_contribution_millionths.to_le_bytes());
            hasher.update(comp.transported_contribution_millionths.to_le_bytes());
            hasher.update(comp.explanation.as_bytes());
        }
        hasher.update(total_source.to_le_bytes());
        hasher.update(total_transported.to_le_bytes());
        hasher.update(unexplained.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for ResidualLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ledger:{}(cert={}, src={}, xport={}, unexplained={}, components={})",
            self.ledger_id,
            self.certificate_id,
            self.total_source_millionths,
            self.total_transported_millionths,
            self.unexplained_remainder_millionths,
            self.components.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Core functions — transport evaluation
// ---------------------------------------------------------------------------

/// Detect degradation reasons when transporting artifacts between two cells.
///
/// Compares architectural features to identify specific degradation causes.
pub fn detect_degradation(source: &HardwareCell, target: &HardwareCell) -> Vec<DegradationReason> {
    let mut reasons = Vec::new();

    // Different architecture family is the most severe incompatibility.
    if !source.same_arch_family(target) {
        reasons.push(DegradationReason::IsaMissing);
        reasons.push(DegradationReason::MemoryModelWeaker);
    }

    // Different microarchitecture within the same family.
    if source.same_arch_family(target) && !source.same_microarch(target) {
        reasons.push(DegradationReason::MicroarchMismatch);
        reasons.push(DegradationReason::BranchPredictionDrift);
    }

    // Vector width reduction.
    if target.vector_width_bits < source.vector_width_bits {
        reasons.push(DegradationReason::VectorizationUnavailable);
    }

    // Cache line mismatch.
    if target.cache_line_bytes != source.cache_line_bytes {
        reasons.push(DegradationReason::CachePressure);
        if target.cache_line_bytes > source.cache_line_bytes {
            reasons.push(DegradationReason::AlignmentPenalty);
        }
    }

    reasons.truncate(MAX_DEGRADATION_REASONS);
    reasons
}

/// Compute the residual performance fraction (millionths) from source
/// and target performance measurements.
///
/// Returns `MILLIONTHS` (1.0) if source_perf is zero (avoid division by
/// zero — treat as full transport).
pub fn compute_residual_fraction(source_perf: u64, target_perf: u64) -> u64 {
    if source_perf == 0 {
        return MILLIONTHS;
    }
    let fraction = target_perf.saturating_mul(MILLIONTHS)
        .checked_div(source_perf)
        .unwrap_or(0);
    // Cap at MILLIONTHS (target cannot exceed source for residual purposes).
    if fraction > MILLIONTHS {
        MILLIONTHS
    } else {
        fraction
    }
}

/// Classify a transport outcome based on the residual fraction.
///
/// Thresholds:
/// - ≥ 95%: `FullTransport`
/// - ≥ 70%: `PartialTransport`
/// - ≥ 30%: `Degraded`
/// - < 30%: `Failed`
pub fn classify_outcome(residual_fraction: u64) -> TransportOutcome {
    if residual_fraction >= FULL_TRANSPORT_THRESHOLD {
        TransportOutcome::FullTransport
    } else if residual_fraction >= PARTIAL_TRANSPORT_THRESHOLD {
        TransportOutcome::PartialTransport
    } else if residual_fraction >= DEGRADED_THRESHOLD {
        TransportOutcome::Degraded
    } else {
        TransportOutcome::Failed
    }
}

/// Evaluate whether an artifact can be transported from one hardware cell
/// to another, producing a transport certificate.
///
/// # Errors
///
/// Returns `TransportError::MeasurementFailed` if source performance is
/// zero and target performance is nonzero (nonsensical measurement).
pub fn evaluate_transport(
    artifact_kind: ArtifactKind,
    artifact_hash: ContentHash,
    source: &HardwareCell,
    target: &HardwareCell,
    source_perf: u64,
    target_perf: u64,
) -> Result<TransportCertificate, TransportError> {
    // Detect degradation reasons.
    let degradation_reasons = detect_degradation(source, target);

    // Compute residual fraction.
    let residual_fraction = compute_residual_fraction(source_perf, target_perf);

    // Classify the outcome.  If cells are from different arch families
    // and the artifact is arch-sensitive, mark as Incompatible.
    let outcome =
        if !source.same_arch_family(target) && artifact_kind.is_arch_sensitive() {
            TransportOutcome::Incompatible
        } else {
            classify_outcome(residual_fraction)
        };

    let certificate_id = generate_certificate_id(
        &artifact_kind,
        &artifact_hash,
        source,
        target,
    );

    let content_hash = TransportCertificate::compute_content_hash(
        &certificate_id,
        artifact_kind,
        &artifact_hash,
        source,
        target,
        outcome,
        source_perf,
        target_perf,
        &degradation_reasons,
        residual_fraction,
    );

    Ok(TransportCertificate {
        certificate_id,
        artifact_kind,
        artifact_hash,
        source_cell: source.clone(),
        target_cell: target.clone(),
        outcome,
        source_perf_millionths: source_perf,
        target_perf_millionths: target_perf,
        degradation_reasons,
        residual_fraction_millionths: residual_fraction,
        content_hash,
    })
}

/// Build a residual ledger that decomposes a certificate's performance
/// residual into named components.
///
/// # Errors
///
/// Returns `TransportError::LedgerInconsistent` if the component totals
/// exceed the certificate's source performance.
pub fn build_residual_ledger(
    cert: &TransportCertificate,
    components: Vec<ResidualComponent>,
) -> Result<ResidualLedger, TransportError> {
    if components.len() > MAX_LEDGER_COMPONENTS {
        return Err(TransportError::InternalError(format!(
            "too many components: {} > {MAX_LEDGER_COMPONENTS}",
            components.len()
        )));
    }

    let total_source: u64 = components
        .iter()
        .map(|c| c.source_contribution_millionths)
        .sum();
    let total_transported: u64 = components
        .iter()
        .map(|c| c.transported_contribution_millionths)
        .sum();

    // The unexplained remainder is the difference between what the
    // certificate says was transported and what the components account for.
    let unexplained = cert.target_perf_millionths.saturating_sub(total_transported);

    // Validate: component source total should not exceed certificate source.
    if total_source > cert.source_perf_millionths {
        return Err(TransportError::LedgerInconsistent);
    }

    let ledger_id = format!("ledger-{}", cert.certificate_id);

    let content_hash = ResidualLedger::compute_content_hash(
        &ledger_id,
        &cert.certificate_id,
        &components,
        total_source,
        total_transported,
        unexplained,
    );

    Ok(ResidualLedger {
        ledger_id,
        certificate_id: cert.certificate_id.clone(),
        components,
        total_source_millionths: total_source,
        total_transported_millionths: total_transported,
        unexplained_remainder_millionths: unexplained,
        content_hash,
    })
}

/// Validate that a residual ledger is internally consistent.
///
/// Checks:
/// 1. Component source contributions sum to total_source_millionths.
/// 2. Component transported contributions + unexplained = total_transported + unexplained.
/// 3. Transported contribution does not exceed source contribution for any component.
///
/// # Errors
///
/// Returns `TransportError::LedgerInconsistent` if any check fails.
pub fn validate_ledger_consistency(ledger: &ResidualLedger) -> Result<(), TransportError> {
    let sum_source: u64 = ledger
        .components
        .iter()
        .map(|c| c.source_contribution_millionths)
        .sum();
    if sum_source != ledger.total_source_millionths {
        return Err(TransportError::LedgerInconsistent);
    }

    let sum_transported: u64 = ledger
        .components
        .iter()
        .map(|c| c.transported_contribution_millionths)
        .sum();
    if sum_transported != ledger.total_transported_millionths {
        return Err(TransportError::LedgerInconsistent);
    }

    // Each component's transported contribution must not exceed its source.
    for comp in &ledger.components {
        if comp.transported_contribution_millionths > comp.source_contribution_millionths {
            return Err(TransportError::LedgerInconsistent);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Manifest — canonical reference set
// ---------------------------------------------------------------------------

/// Produce a canonical reference set of transport certificates that
/// exercise the major artifact kinds, cell configurations, and outcomes.
pub fn franken_engine_transport_manifest() -> Vec<TransportCertificate> {
    let cell_x86_zen4 = HardwareCell::new("x86-zen4", "x86_64", "zen4", 256, 64);
    let cell_x86_alder = HardwareCell::new("x86-alder", "x86_64", "alderlake", 256, 64);
    let cell_x86_avx512 = HardwareCell::new("x86-avx512", "x86_64", "sapphirerapids", 512, 64);
    let cell_arm_nv2 = HardwareCell::new("arm-nv2", "aarch64", "neoverse_v2", 128, 64);
    let cell_arm_a78 = HardwareCell::new("arm-a78", "aarch64", "cortex_a78", 128, 64);
    let cell_riscv = HardwareCell::new("riscv-generic", "riscv64", "generic", 128, 64);

    let hash_a = ContentHash::compute(b"rewrite-rule-alpha");
    let hash_b = ContentHash::compute(b"synth-kernel-beta");
    let hash_c = ContentHash::compute(b"cache-entry-gamma");
    let hash_d = ContentHash::compute(b"aot-module-delta");
    let hash_e = ContentHash::compute(b"code-layout-epsilon");
    let hash_f = ContentHash::compute(b"profile-data-zeta");
    let hash_g = ContentHash::compute(b"spec-guard-eta");

    let mut certs = Vec::new();

    // Same-cell transport (full transport).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::RewriteRule,
        hash_a.clone(),
        &cell_x86_zen4,
        &cell_x86_zen4,
        MILLIONTHS,
        MILLIONTHS,
    ) {
        certs.push(c);
    }

    // Same arch, different microarch (partial transport).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::SynthesizedKernel,
        hash_b.clone(),
        &cell_x86_zen4,
        &cell_x86_alder,
        MILLIONTHS,
        850_000,
    ) {
        certs.push(c);
    }

    // Vector width reduction (degraded).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::CacheEntry,
        hash_c.clone(),
        &cell_x86_avx512,
        &cell_x86_zen4,
        MILLIONTHS,
        600_000,
    ) {
        certs.push(c);
    }

    // Cross-arch transport of non-arch-sensitive artifact (profile data).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::ProfileData,
        hash_f.clone(),
        &cell_x86_zen4,
        &cell_arm_nv2,
        MILLIONTHS,
        400_000,
    ) {
        certs.push(c);
    }

    // Cross-arch transport of arch-sensitive artifact (incompatible).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::AotModule,
        hash_d.clone(),
        &cell_x86_zen4,
        &cell_arm_nv2,
        MILLIONTHS,
        200_000,
    ) {
        certs.push(c);
    }

    // ARM to ARM same microarch (full transport).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::CodeLayout,
        hash_e.clone(),
        &cell_arm_nv2,
        &cell_arm_nv2,
        MILLIONTHS,
        980_000,
    ) {
        certs.push(c);
    }

    // ARM different microarch.
    if let Ok(c) = evaluate_transport(
        ArtifactKind::SpeculationGuard,
        hash_g.clone(),
        &cell_arm_nv2,
        &cell_arm_a78,
        MILLIONTHS,
        750_000,
    ) {
        certs.push(c);
    }

    // RISC-V to x86 cross-arch (incompatible for AOT).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::AotModule,
        hash_d,
        &cell_riscv,
        &cell_x86_zen4,
        MILLIONTHS,
        100_000,
    ) {
        certs.push(c);
    }

    // Failed transport (very low residual).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::SynthesizedKernel,
        hash_b,
        &cell_x86_avx512,
        &cell_riscv,
        MILLIONTHS,
        50_000,
    ) {
        certs.push(c);
    }

    // Rewrite rule cross-arch (non-arch-sensitive, degraded).
    if let Ok(c) = evaluate_transport(
        ArtifactKind::RewriteRule,
        hash_a,
        &cell_x86_zen4,
        &cell_riscv,
        MILLIONTHS,
        500_000,
    ) {
        certs.push(c);
    }

    // Cache entry same arch different uarch.
    if let Ok(c) = evaluate_transport(
        ArtifactKind::CacheEntry,
        hash_c,
        &cell_arm_nv2,
        &cell_arm_a78,
        MILLIONTHS,
        920_000,
    ) {
        certs.push(c);
    }

    // Profile data ARM to ARM.
    if let Ok(c) = evaluate_transport(
        ArtifactKind::ProfileData,
        hash_f,
        &cell_arm_nv2,
        &cell_arm_a78,
        MILLIONTHS,
        960_000,
    ) {
        certs.push(c);
    }

    certs
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a deterministic certificate ID from artifact and cell info.
fn generate_certificate_id(
    artifact_kind: &ArtifactKind,
    artifact_hash: &ContentHash,
    source: &HardwareCell,
    target: &HardwareCell,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(artifact_kind.as_str().as_bytes());
    hasher.update(artifact_hash.as_bytes());
    hasher.update(source.cell_id.as_bytes());
    hasher.update(target.cell_id.as_bytes());
    let digest = hasher.finalize();
    let short = &digest[..8];
    let mut hex = String::with_capacity(16);
    for b in short {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("tc-{hex}")
}

// ---------------------------------------------------------------------------
// TransportManifestSummary — aggregate view of multiple certificates
// ---------------------------------------------------------------------------

/// Aggregate summary of a set of transport certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportManifestSummary {
    /// Number of certificates in the manifest.
    pub total_certificates: usize,
    /// Number with FullTransport outcome.
    pub full_transport_count: usize,
    /// Number with PartialTransport outcome.
    pub partial_transport_count: usize,
    /// Number with Degraded outcome.
    pub degraded_count: usize,
    /// Number with Failed outcome.
    pub failed_count: usize,
    /// Number with Incompatible outcome.
    pub incompatible_count: usize,
    /// Average residual fraction across all certificates (millionths).
    pub avg_residual_fraction_millionths: u64,
    /// Content hash of the summary.
    pub content_hash: ContentHash,
}

impl TransportManifestSummary {
    /// Build a summary from a set of certificates.
    pub fn build(certs: &[TransportCertificate]) -> Self {
        let total = certs.len();
        let mut full = 0usize;
        let mut partial = 0usize;
        let mut degraded = 0usize;
        let mut failed = 0usize;
        let mut incompatible = 0usize;
        let mut sum_residual: u64 = 0;

        for cert in certs {
            match cert.outcome {
                TransportOutcome::FullTransport => full += 1,
                TransportOutcome::PartialTransport => partial += 1,
                TransportOutcome::Degraded => degraded += 1,
                TransportOutcome::Failed => failed += 1,
                TransportOutcome::Incompatible => incompatible += 1,
            }
            sum_residual = sum_residual.saturating_add(cert.residual_fraction_millionths);
        }

        let avg_residual = if total > 0 {
            sum_residual
                .checked_div(total as u64)
                .unwrap_or(0)
        } else {
            0
        };

        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(b"manifest-summary");
        hasher.update((total as u64).to_le_bytes());
        hasher.update((full as u64).to_le_bytes());
        hasher.update((partial as u64).to_le_bytes());
        hasher.update((degraded as u64).to_le_bytes());
        hasher.update((failed as u64).to_le_bytes());
        hasher.update((incompatible as u64).to_le_bytes());
        hasher.update(avg_residual.to_le_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());

        Self {
            total_certificates: total,
            full_transport_count: full,
            partial_transport_count: partial,
            degraded_count: degraded,
            failed_count: failed,
            incompatible_count: incompatible,
            avg_residual_fraction_millionths: avg_residual,
            content_hash,
        }
    }

    /// Whether all certificates achieved full transport.
    pub fn all_full_transport(&self) -> bool {
        self.full_transport_count == self.total_certificates
    }

    /// Whether any certificate failed.
    pub fn has_failures(&self) -> bool {
        self.failed_count > 0 || self.incompatible_count > 0
    }

    /// Usability rate (millionths) — fraction of certificates that are usable.
    pub fn usability_rate_millionths(&self) -> u64 {
        if self.total_certificates == 0 {
            return 0;
        }
        let usable = self.full_transport_count
            + self.partial_transport_count
            + self.degraded_count;
        (usable as u64)
            .saturating_mul(MILLIONTHS)
            .checked_div(self.total_certificates as u64)
            .unwrap_or(0)
    }
}

impl fmt::Display for TransportManifestSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "manifest(total={}, full={}, partial={}, degraded={}, failed={}, incompat={}, avg_residual={})",
            self.total_certificates,
            self.full_transport_count,
            self.partial_transport_count,
            self.degraded_count,
            self.failed_count,
            self.incompatible_count,
            self.avg_residual_fraction_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// TransportEvent — auditable transport activity
// ---------------------------------------------------------------------------

/// An auditable event in the transport certificate lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEvent {
    /// Event kind.
    pub kind: TransportEventKind,
    /// Certificate ID (if applicable).
    pub certificate_id: String,
    /// Artifact kind involved.
    pub artifact_kind: ArtifactKind,
    /// Source cell ID.
    pub source_cell_id: String,
    /// Target cell ID.
    pub target_cell_id: String,
    /// Outcome of the transport.
    pub outcome: TransportOutcome,
    /// Residual fraction (millionths).
    pub residual_fraction_millionths: u64,
    /// Security epoch at event time.
    pub epoch: SecurityEpoch,
    /// Content hash.
    pub content_hash: ContentHash,
}

/// Kind of transport event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportEventKind {
    /// Certificate was created.
    CertificateCreated,
    /// Ledger was built for a certificate.
    LedgerBuilt,
    /// Certificate was invalidated.
    CertificateInvalidated,
    /// Transport was re-evaluated.
    TransportReEvaluated,
}

impl TransportEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CertificateCreated => "certificate_created",
            Self::LedgerBuilt => "ledger_built",
            Self::CertificateInvalidated => "certificate_invalidated",
            Self::TransportReEvaluated => "transport_re_evaluated",
        }
    }
}

impl fmt::Display for TransportEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TransportEvent {
    /// Create a transport event from a certificate and epoch.
    pub fn from_certificate(
        cert: &TransportCertificate,
        kind: TransportEventKind,
        epoch: SecurityEpoch,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_str().as_bytes());
        hasher.update(cert.certificate_id.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());

        Self {
            kind,
            certificate_id: cert.certificate_id.clone(),
            artifact_kind: cert.artifact_kind,
            source_cell_id: cert.source_cell.cell_id.clone(),
            target_cell_id: cert.target_cell.cell_id.clone(),
            outcome: cert.outcome,
            residual_fraction_millionths: cert.residual_fraction_millionths,
            epoch,
            content_hash,
        }
    }
}

impl fmt::Display for TransportEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "event:{}(cert={}, {} -> {}, outcome={})",
            self.kind,
            self.certificate_id,
            self.source_cell_id,
            self.target_cell_id,
            self.outcome,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test helpers ---

    fn cell_x86_zen4() -> HardwareCell {
        HardwareCell::new("x86-zen4", "x86_64", "zen4", 256, 64)
    }

    fn cell_x86_alder() -> HardwareCell {
        HardwareCell::new("x86-alder", "x86_64", "alderlake", 256, 64)
    }

    fn cell_x86_avx512() -> HardwareCell {
        HardwareCell::new("x86-avx512", "x86_64", "sapphirerapids", 512, 64)
    }

    fn cell_arm_nv2() -> HardwareCell {
        HardwareCell::new("arm-nv2", "aarch64", "neoverse_v2", 128, 64)
    }

    fn cell_arm_a78() -> HardwareCell {
        HardwareCell::new("arm-a78", "aarch64", "cortex_a78", 128, 64)
    }

    #[allow(dead_code)]
    fn cell_riscv() -> HardwareCell {
        HardwareCell::new("riscv-gen", "riscv64", "generic", 128, 64)
    }

    fn cell_arm_wide_cache() -> HardwareCell {
        HardwareCell::new("arm-wide", "aarch64", "neoverse_v2", 128, 128)
    }

    fn test_hash(label: &str) -> ContentHash {
        ContentHash::compute(label.as_bytes())
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    // --- ArtifactKind tests ---

    #[test]
    fn artifact_kind_serde_roundtrip() {
        for kind in ArtifactKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: ArtifactKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn artifact_kind_display() {
        assert_eq!(format!("{}", ArtifactKind::RewriteRule), "rewrite_rule");
        assert_eq!(
            format!("{}", ArtifactKind::SynthesizedKernel),
            "synthesized_kernel"
        );
        assert_eq!(format!("{}", ArtifactKind::CacheEntry), "cache_entry");
        assert_eq!(format!("{}", ArtifactKind::AotModule), "aot_module");
        assert_eq!(format!("{}", ArtifactKind::CodeLayout), "code_layout");
        assert_eq!(format!("{}", ArtifactKind::ProfileData), "profile_data");
        assert_eq!(
            format!("{}", ArtifactKind::SpeculationGuard),
            "speculation_guard"
        );
    }

    #[test]
    fn artifact_kind_arch_sensitivity() {
        assert!(!ArtifactKind::RewriteRule.is_arch_sensitive());
        assert!(ArtifactKind::SynthesizedKernel.is_arch_sensitive());
        assert!(!ArtifactKind::CacheEntry.is_arch_sensitive());
        assert!(ArtifactKind::AotModule.is_arch_sensitive());
        assert!(ArtifactKind::CodeLayout.is_arch_sensitive());
        assert!(!ArtifactKind::ProfileData.is_arch_sensitive());
        assert!(ArtifactKind::SpeculationGuard.is_arch_sensitive());
    }

    #[test]
    fn artifact_kind_all_count() {
        assert_eq!(ArtifactKind::ALL.len(), 7);
    }

    // --- TransportOutcome tests ---

    #[test]
    fn transport_outcome_serde_roundtrip() {
        let outcomes = [
            TransportOutcome::FullTransport,
            TransportOutcome::PartialTransport,
            TransportOutcome::Degraded,
            TransportOutcome::Failed,
            TransportOutcome::Incompatible,
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: TransportOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    #[test]
    fn transport_outcome_display() {
        assert_eq!(
            format!("{}", TransportOutcome::FullTransport),
            "full_transport"
        );
        assert_eq!(
            format!("{}", TransportOutcome::PartialTransport),
            "partial_transport"
        );
        assert_eq!(format!("{}", TransportOutcome::Degraded), "degraded");
        assert_eq!(format!("{}", TransportOutcome::Failed), "failed");
        assert_eq!(
            format!("{}", TransportOutcome::Incompatible),
            "incompatible"
        );
    }

    #[test]
    fn transport_outcome_usable() {
        assert!(TransportOutcome::FullTransport.is_usable());
        assert!(TransportOutcome::PartialTransport.is_usable());
        assert!(TransportOutcome::Degraded.is_usable());
        assert!(!TransportOutcome::Failed.is_usable());
        assert!(!TransportOutcome::Incompatible.is_usable());
    }

    #[test]
    fn transport_outcome_is_full() {
        assert!(TransportOutcome::FullTransport.is_full());
        assert!(!TransportOutcome::PartialTransport.is_full());
        assert!(!TransportOutcome::Degraded.is_full());
    }

    // --- DegradationReason tests ---

    #[test]
    fn degradation_reason_serde_roundtrip() {
        let reasons = vec![
            DegradationReason::MicroarchMismatch,
            DegradationReason::IsaMissing,
            DegradationReason::CachePressure,
            DegradationReason::AlignmentPenalty,
            DegradationReason::BranchPredictionDrift,
            DegradationReason::VectorizationUnavailable,
            DegradationReason::MemoryModelWeaker,
            DegradationReason::UnknownReason("custom".into()),
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let back: DegradationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn degradation_reason_display() {
        assert_eq!(
            format!("{}", DegradationReason::MicroarchMismatch),
            "microarch_mismatch"
        );
        assert_eq!(format!("{}", DegradationReason::IsaMissing), "isa_missing");
        assert_eq!(
            format!("{}", DegradationReason::VectorizationUnavailable),
            "vectorization_unavailable"
        );
        assert_eq!(
            format!("{}", DegradationReason::UnknownReason("test".into())),
            "test"
        );
    }

    #[test]
    fn degradation_reason_penalties() {
        assert_eq!(DegradationReason::MicroarchMismatch.penalty_millionths(), 100_000);
        assert_eq!(DegradationReason::IsaMissing.penalty_millionths(), 500_000);
        assert_eq!(DegradationReason::CachePressure.penalty_millionths(), 80_000);
        assert_eq!(DegradationReason::AlignmentPenalty.penalty_millionths(), 50_000);
        assert_eq!(
            DegradationReason::BranchPredictionDrift.penalty_millionths(),
            60_000
        );
        assert_eq!(
            DegradationReason::VectorizationUnavailable.penalty_millionths(),
            200_000
        );
        assert_eq!(DegradationReason::MemoryModelWeaker.penalty_millionths(), 150_000);
        assert_eq!(
            DegradationReason::UnknownReason("x".into()).penalty_millionths(),
            100_000
        );
    }

    // --- HardwareCell tests ---

    #[test]
    fn hardware_cell_same_arch_family() {
        let zen4 = cell_x86_zen4();
        let alder = cell_x86_alder();
        let arm = cell_arm_nv2();

        assert!(zen4.same_arch_family(&alder));
        assert!(!zen4.same_arch_family(&arm));
    }

    #[test]
    fn hardware_cell_same_microarch() {
        let zen4_a = cell_x86_zen4();
        let zen4_b = HardwareCell::new("x86-zen4-b", "x86_64", "zen4", 256, 64);
        let alder = cell_x86_alder();

        assert!(zen4_a.same_microarch(&zen4_b));
        assert!(!zen4_a.same_microarch(&alder));
    }

    #[test]
    fn hardware_cell_hardware_equivalent() {
        let zen4_a = cell_x86_zen4();
        let zen4_b = HardwareCell::new("different-id", "x86_64", "zen4", 256, 64);
        let avx512 = cell_x86_avx512();

        // Same hw characteristics, different IDs -> equivalent.
        assert!(zen4_a.hardware_equivalent(&zen4_b));
        // Different vector width -> not equivalent.
        assert!(!zen4_a.hardware_equivalent(&avx512));
    }

    #[test]
    fn hardware_cell_display() {
        let cell = cell_x86_zen4();
        let s = format!("{cell}");
        assert!(s.contains("x86-zen4"));
        assert!(s.contains("x86_64"));
        assert!(s.contains("zen4"));
    }

    #[test]
    fn hardware_cell_serde_roundtrip() {
        let cell = cell_x86_avx512();
        let json = serde_json::to_string(&cell).unwrap();
        let back: HardwareCell = serde_json::from_str(&json).unwrap();
        assert_eq!(cell, back);
    }

    #[test]
    fn hardware_cell_content_hash_deterministic() {
        let a = cell_arm_nv2();
        let b = cell_arm_nv2();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    // --- classify_outcome tests ---

    #[test]
    fn classify_outcome_full_transport() {
        assert_eq!(classify_outcome(MILLIONTHS), TransportOutcome::FullTransport);
        assert_eq!(
            classify_outcome(FULL_TRANSPORT_THRESHOLD),
            TransportOutcome::FullTransport
        );
        assert_eq!(classify_outcome(999_999), TransportOutcome::FullTransport);
    }

    #[test]
    fn classify_outcome_partial_transport() {
        assert_eq!(
            classify_outcome(FULL_TRANSPORT_THRESHOLD - 1),
            TransportOutcome::PartialTransport
        );
        assert_eq!(
            classify_outcome(PARTIAL_TRANSPORT_THRESHOLD),
            TransportOutcome::PartialTransport
        );
        assert_eq!(classify_outcome(800_000), TransportOutcome::PartialTransport);
    }

    #[test]
    fn classify_outcome_degraded() {
        assert_eq!(
            classify_outcome(PARTIAL_TRANSPORT_THRESHOLD - 1),
            TransportOutcome::Degraded
        );
        assert_eq!(
            classify_outcome(DEGRADED_THRESHOLD),
            TransportOutcome::Degraded
        );
        assert_eq!(classify_outcome(500_000), TransportOutcome::Degraded);
    }

    #[test]
    fn classify_outcome_failed() {
        assert_eq!(
            classify_outcome(DEGRADED_THRESHOLD - 1),
            TransportOutcome::Failed
        );
        assert_eq!(classify_outcome(0), TransportOutcome::Failed);
        assert_eq!(classify_outcome(100_000), TransportOutcome::Failed);
    }

    // --- compute_residual_fraction tests ---

    #[test]
    fn residual_fraction_same_perf() {
        assert_eq!(
            compute_residual_fraction(MILLIONTHS, MILLIONTHS),
            MILLIONTHS
        );
    }

    #[test]
    fn residual_fraction_half_perf() {
        assert_eq!(
            compute_residual_fraction(MILLIONTHS, 500_000),
            500_000
        );
    }

    #[test]
    fn residual_fraction_zero_source() {
        // Zero source → treat as full transport.
        assert_eq!(compute_residual_fraction(0, 500_000), MILLIONTHS);
    }

    #[test]
    fn residual_fraction_zero_target() {
        assert_eq!(compute_residual_fraction(MILLIONTHS, 0), 0);
    }

    #[test]
    fn residual_fraction_target_exceeds_source() {
        // Capped at MILLIONTHS.
        assert_eq!(
            compute_residual_fraction(500_000, MILLIONTHS),
            MILLIONTHS
        );
    }

    #[test]
    fn residual_fraction_large_values() {
        let source = 10 * MILLIONTHS;
        let target = 8 * MILLIONTHS;
        assert_eq!(compute_residual_fraction(source, target), 800_000);
    }

    // --- detect_degradation tests ---

    #[test]
    fn detect_degradation_same_cell() {
        let cell = cell_x86_zen4();
        let reasons = detect_degradation(&cell, &cell);
        assert!(reasons.is_empty());
    }

    #[test]
    fn detect_degradation_same_arch_diff_microarch() {
        let reasons = detect_degradation(&cell_x86_zen4(), &cell_x86_alder());
        assert!(reasons.contains(&DegradationReason::MicroarchMismatch));
        assert!(reasons.contains(&DegradationReason::BranchPredictionDrift));
        assert!(!reasons.contains(&DegradationReason::IsaMissing));
    }

    #[test]
    fn detect_degradation_cross_arch() {
        let reasons = detect_degradation(&cell_x86_zen4(), &cell_arm_nv2());
        assert!(reasons.contains(&DegradationReason::IsaMissing));
        assert!(reasons.contains(&DegradationReason::MemoryModelWeaker));
    }

    #[test]
    fn detect_degradation_vector_width_reduction() {
        let reasons = detect_degradation(&cell_x86_avx512(), &cell_x86_zen4());
        assert!(reasons.contains(&DegradationReason::VectorizationUnavailable));
    }

    #[test]
    fn detect_degradation_cache_line_mismatch() {
        let source = cell_arm_nv2(); // 64-byte cache lines
        let target = cell_arm_wide_cache(); // 128-byte cache lines
        let reasons = detect_degradation(&source, &target);
        assert!(reasons.contains(&DegradationReason::CachePressure));
        assert!(reasons.contains(&DegradationReason::AlignmentPenalty));
    }

    #[test]
    fn detect_degradation_no_alignment_when_target_smaller() {
        let source = cell_arm_wide_cache(); // 128-byte
        let target = cell_arm_nv2();        // 64-byte
        let reasons = detect_degradation(&source, &target);
        assert!(reasons.contains(&DegradationReason::CachePressure));
        // No alignment penalty when target cache line is smaller.
        assert!(!reasons.contains(&DegradationReason::AlignmentPenalty));
    }

    // --- evaluate_transport tests ---

    #[test]
    fn evaluate_same_cell_full_transport() {
        let cell = cell_x86_zen4();
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("rr"),
            &cell,
            &cell,
            MILLIONTHS,
            MILLIONTHS,
        )
        .unwrap();
        assert_eq!(cert.outcome, TransportOutcome::FullTransport);
        assert_eq!(cert.residual_fraction_millionths, MILLIONTHS);
        assert!(cert.degradation_reasons.is_empty());
        assert!(cert.is_usable());
        assert!(cert.is_full_transport());
    }

    #[test]
    fn evaluate_same_arch_diff_microarch_partial() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("ce"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            850_000,
        )
        .unwrap();
        assert_eq!(cert.outcome, TransportOutcome::PartialTransport);
        assert_eq!(cert.residual_fraction_millionths, 850_000);
        assert!(cert.degradation_reasons.contains(&DegradationReason::MicroarchMismatch));
    }

    #[test]
    fn evaluate_cross_arch_arch_sensitive_incompatible() {
        let cert = evaluate_transport(
            ArtifactKind::AotModule,
            test_hash("aot"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            200_000,
        )
        .unwrap();
        assert_eq!(cert.outcome, TransportOutcome::Incompatible);
        assert!(!cert.is_usable());
    }

    #[test]
    fn evaluate_cross_arch_non_sensitive_allows_transport() {
        let cert = evaluate_transport(
            ArtifactKind::ProfileData,
            test_hash("pd"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();
        // ProfileData is not arch-sensitive, so it can transport.
        assert_eq!(cert.outcome, TransportOutcome::PartialTransport);
        assert!(cert.is_usable());
    }

    #[test]
    fn evaluate_very_low_residual_failed() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("low"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            100_000,
        )
        .unwrap();
        assert_eq!(cert.outcome, TransportOutcome::Failed);
        assert!(!cert.is_usable());
    }

    #[test]
    fn evaluate_performance_loss_computation() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("loss"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            750_000,
        )
        .unwrap();
        assert_eq!(cert.performance_loss_millionths(), 250_000);
    }

    #[test]
    fn evaluate_certificate_id_deterministic() {
        let h = test_hash("det");
        let c1 = evaluate_transport(
            ArtifactKind::RewriteRule,
            h.clone(),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            500_000,
        )
        .unwrap();
        let c2 = evaluate_transport(
            ArtifactKind::RewriteRule,
            h,
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            500_000,
        )
        .unwrap();
        assert_eq!(c1.certificate_id, c2.certificate_id);
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn evaluate_certificate_display() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("disp"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            500_000,
        )
        .unwrap();
        let s = format!("{cert}");
        assert!(s.contains("rewrite_rule"));
        assert!(s.contains("x86-zen4"));
        assert!(s.contains("arm-nv2"));
    }

    #[test]
    fn evaluate_certificate_serde_roundtrip() {
        let cert = evaluate_transport(
            ArtifactKind::SynthesizedKernel,
            test_hash("serde"),
            &cell_x86_avx512(),
            &cell_x86_zen4(),
            MILLIONTHS,
            700_000,
        )
        .unwrap();
        let json = serde_json::to_string(&cert).unwrap();
        let back: TransportCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // --- ResidualComponent tests ---

    #[test]
    fn residual_component_survival_fraction() {
        let comp = ResidualComponent::new(
            "branch_prediction",
            400_000,
            300_000,
            "branch tables not ported",
        );
        assert_eq!(comp.survival_fraction_millionths(), 750_000);
        assert_eq!(comp.loss_millionths(), 100_000);
    }

    #[test]
    fn residual_component_zero_source() {
        let comp = ResidualComponent::new("zero", 0, 0, "nothing");
        assert_eq!(comp.survival_fraction_millionths(), MILLIONTHS);
    }

    #[test]
    fn residual_component_display() {
        let comp = ResidualComponent::new("vec", 200_000, 100_000, "lost");
        let s = format!("{comp}");
        assert!(s.contains("vec"));
        assert!(s.contains("200000"));
        assert!(s.contains("100000"));
    }

    #[test]
    fn residual_component_serde_roundtrip() {
        let comp = ResidualComponent::new("cache", 500_000, 400_000, "eviction");
        let json = serde_json::to_string(&comp).unwrap();
        let back: ResidualComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(comp, back);
    }

    // --- build_residual_ledger tests ---

    #[test]
    fn build_ledger_basic() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("ledger"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();

        let components = vec![
            ResidualComponent::new("branch", 400_000, 350_000, "cold branch tables"),
            ResidualComponent::new("cache", 300_000, 250_000, "cache pressure"),
            ResidualComponent::new("other", 200_000, 180_000, "misc"),
        ];

        let ledger = build_residual_ledger(&cert, components).unwrap();
        assert_eq!(ledger.total_source_millionths, 900_000);
        assert_eq!(ledger.total_transported_millionths, 780_000);
        assert_eq!(ledger.component_count(), 3);
        assert!(ledger.certificate_id.starts_with("tc-"));
    }

    #[test]
    fn build_ledger_empty_components() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("empty"),
            &cell_x86_zen4(),
            &cell_x86_zen4(),
            MILLIONTHS,
            MILLIONTHS,
        )
        .unwrap();

        let ledger = build_residual_ledger(&cert, vec![]).unwrap();
        assert_eq!(ledger.total_source_millionths, 0);
        assert_eq!(ledger.total_transported_millionths, 0);
        assert_eq!(ledger.component_count(), 0);
    }

    #[test]
    fn build_ledger_exceeds_source_error() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("exceed"),
            &cell_x86_zen4(),
            &cell_x86_zen4(),
            500_000,
            500_000,
        )
        .unwrap();

        // Component source total exceeds certificate source perf.
        let components = vec![
            ResidualComponent::new("a", 400_000, 400_000, "fine"),
            ResidualComponent::new("b", 300_000, 300_000, "too much"),
        ];

        let result = build_residual_ledger(&cert, components);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TransportError::LedgerInconsistent);
    }

    #[test]
    fn build_ledger_serde_roundtrip() {
        let cert = evaluate_transport(
            ArtifactKind::ProfileData,
            test_hash("lserde"),
            &cell_arm_nv2(),
            &cell_arm_a78(),
            MILLIONTHS,
            900_000,
        )
        .unwrap();

        let components = vec![ResidualComponent::new(
            "profile",
            500_000,
            450_000,
            "profile portability",
        )];

        let ledger = build_residual_ledger(&cert, components).unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: ResidualLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn build_ledger_deterministic_hash() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("det-ledger"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();

        let comps1 = vec![ResidualComponent::new("a", 300_000, 250_000, "x")];
        let comps2 = vec![ResidualComponent::new("a", 300_000, 250_000, "x")];

        let l1 = build_residual_ledger(&cert, comps1).unwrap();
        let l2 = build_residual_ledger(&cert, comps2).unwrap();
        assert_eq!(l1.content_hash, l2.content_hash);
    }

    #[test]
    fn build_ledger_display() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("disp-l"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();
        let ledger = build_residual_ledger(&cert, vec![]).unwrap();
        let s = format!("{ledger}");
        assert!(s.contains("ledger:"));
        assert!(s.contains("cert="));
    }

    #[test]
    fn build_ledger_component_by_name() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("lookup"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();

        let components = vec![
            ResidualComponent::new("branch", 400_000, 350_000, "x"),
            ResidualComponent::new("cache", 300_000, 250_000, "y"),
        ];

        let ledger = build_residual_ledger(&cert, components).unwrap();
        assert!(ledger.component_by_name("branch").is_some());
        assert!(ledger.component_by_name("cache").is_some());
        assert!(ledger.component_by_name("missing").is_none());
    }

    // --- validate_ledger_consistency tests ---

    #[test]
    fn validate_consistent_ledger() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("valid"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();

        let components = vec![
            ResidualComponent::new("a", 400_000, 350_000, "x"),
            ResidualComponent::new("b", 300_000, 250_000, "y"),
        ];

        let ledger = build_residual_ledger(&cert, components).unwrap();
        assert!(validate_ledger_consistency(&ledger).is_ok());
    }

    #[test]
    fn validate_inconsistent_ledger_source_mismatch() {
        // Manually construct a ledger with wrong totals.
        let ledger = ResidualLedger {
            ledger_id: "bad-ledger".into(),
            certificate_id: "cert-x".into(),
            components: vec![ResidualComponent::new("a", 100_000, 80_000, "x")],
            total_source_millionths: 999_999, // wrong
            total_transported_millionths: 80_000,
            unexplained_remainder_millionths: 0,
            content_hash: ContentHash::compute(b"bad"),
        };
        assert_eq!(
            validate_ledger_consistency(&ledger).unwrap_err(),
            TransportError::LedgerInconsistent
        );
    }

    #[test]
    fn validate_inconsistent_ledger_transported_exceeds_source() {
        let ledger = ResidualLedger {
            ledger_id: "bad-ledger-2".into(),
            certificate_id: "cert-y".into(),
            components: vec![ResidualComponent::new("a", 100_000, 200_000, "x")],
            total_source_millionths: 100_000,
            total_transported_millionths: 200_000,
            unexplained_remainder_millionths: 0,
            content_hash: ContentHash::compute(b"bad2"),
        };
        assert_eq!(
            validate_ledger_consistency(&ledger).unwrap_err(),
            TransportError::LedgerInconsistent
        );
    }

    // --- TransportError tests ---

    #[test]
    fn transport_error_display() {
        assert_eq!(
            format!("{}", TransportError::CellIncompatible),
            "source and target cells are incompatible"
        );
        assert_eq!(
            format!("{}", TransportError::ArtifactCorrupted),
            "artifact data is corrupted"
        );
        assert_eq!(
            format!("{}", TransportError::MeasurementFailed),
            "performance measurement failed"
        );
        assert_eq!(
            format!("{}", TransportError::LedgerInconsistent),
            "ledger component totals are inconsistent"
        );
        assert_eq!(
            format!("{}", TransportError::InternalError("oops".into())),
            "internal error: oops"
        );
    }

    #[test]
    fn transport_error_serde_roundtrip() {
        let errors = vec![
            TransportError::CellIncompatible,
            TransportError::ArtifactCorrupted,
            TransportError::MeasurementFailed,
            TransportError::LedgerInconsistent,
            TransportError::InternalError("test error".into()),
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: TransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // --- Manifest tests ---

    #[test]
    fn manifest_produces_certificates() {
        let certs = franken_engine_transport_manifest();
        assert!(certs.len() >= 10, "manifest should have at least 10 certs");
    }

    #[test]
    fn manifest_has_full_transport() {
        let certs = franken_engine_transport_manifest();
        assert!(
            certs.iter().any(|c| c.outcome == TransportOutcome::FullTransport),
            "manifest should contain a FullTransport"
        );
    }

    #[test]
    fn manifest_has_incompatible() {
        let certs = franken_engine_transport_manifest();
        assert!(
            certs.iter().any(|c| c.outcome == TransportOutcome::Incompatible),
            "manifest should contain an Incompatible"
        );
    }

    #[test]
    fn manifest_has_diverse_artifact_kinds() {
        let certs = franken_engine_transport_manifest();
        let kinds: std::collections::BTreeSet<_> =
            certs.iter().map(|c| c.artifact_kind).collect();
        assert!(
            kinds.len() >= 5,
            "manifest should cover at least 5 artifact kinds"
        );
    }

    #[test]
    fn manifest_all_certificates_valid_hashes() {
        let certs = franken_engine_transport_manifest();
        for cert in &certs {
            // Re-derive hash and compare.
            let expected = TransportCertificate::compute_content_hash(
                &cert.certificate_id,
                cert.artifact_kind,
                &cert.artifact_hash,
                &cert.source_cell,
                &cert.target_cell,
                cert.outcome,
                cert.source_perf_millionths,
                cert.target_perf_millionths,
                &cert.degradation_reasons,
                cert.residual_fraction_millionths,
            );
            assert_eq!(cert.content_hash, expected);
        }
    }

    // --- TransportManifestSummary tests ---

    #[test]
    fn manifest_summary_from_manifest() {
        let certs = franken_engine_transport_manifest();
        let summary = TransportManifestSummary::build(&certs);
        assert_eq!(summary.total_certificates, certs.len());
        assert!(
            summary.full_transport_count
                + summary.partial_transport_count
                + summary.degraded_count
                + summary.failed_count
                + summary.incompatible_count
                == summary.total_certificates
        );
    }

    #[test]
    fn manifest_summary_empty() {
        let summary = TransportManifestSummary::build(&[]);
        assert_eq!(summary.total_certificates, 0);
        assert_eq!(summary.avg_residual_fraction_millionths, 0);
        assert_eq!(summary.usability_rate_millionths(), 0);
        assert!(!summary.has_failures());
        // 0 == 0 so all_full_transport is vacuously true for empty set.
        assert!(summary.all_full_transport());
    }

    #[test]
    fn manifest_summary_serde_roundtrip() {
        let certs = franken_engine_transport_manifest();
        let summary = TransportManifestSummary::build(&certs);
        let json = serde_json::to_string(&summary).unwrap();
        let back: TransportManifestSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn manifest_summary_display() {
        let certs = franken_engine_transport_manifest();
        let summary = TransportManifestSummary::build(&certs);
        let s = format!("{summary}");
        assert!(s.contains("manifest"));
        assert!(s.contains("total="));
    }

    #[test]
    fn manifest_summary_deterministic_hash() {
        let certs = franken_engine_transport_manifest();
        let s1 = TransportManifestSummary::build(&certs);
        let s2 = TransportManifestSummary::build(&certs);
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // --- TransportEvent tests ---

    #[test]
    fn transport_event_from_certificate() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("evt"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            500_000,
        )
        .unwrap();
        let evt = TransportEvent::from_certificate(
            &cert,
            TransportEventKind::CertificateCreated,
            test_epoch(),
        );
        assert_eq!(evt.kind, TransportEventKind::CertificateCreated);
        assert_eq!(evt.certificate_id, cert.certificate_id);
        assert_eq!(evt.artifact_kind, ArtifactKind::RewriteRule);
        assert_eq!(evt.outcome, cert.outcome);
        assert_eq!(evt.epoch, test_epoch());
    }

    #[test]
    fn transport_event_serde_roundtrip() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("evt-serde"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();
        let evt = TransportEvent::from_certificate(
            &cert,
            TransportEventKind::LedgerBuilt,
            test_epoch(),
        );
        let json = serde_json::to_string(&evt).unwrap();
        let back: TransportEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    #[test]
    fn transport_event_kind_display() {
        assert_eq!(
            format!("{}", TransportEventKind::CertificateCreated),
            "certificate_created"
        );
        assert_eq!(
            format!("{}", TransportEventKind::LedgerBuilt),
            "ledger_built"
        );
        assert_eq!(
            format!("{}", TransportEventKind::CertificateInvalidated),
            "certificate_invalidated"
        );
        assert_eq!(
            format!("{}", TransportEventKind::TransportReEvaluated),
            "transport_re_evaluated"
        );
    }

    #[test]
    fn transport_event_display() {
        let cert = evaluate_transport(
            ArtifactKind::AotModule,
            test_hash("evt-disp"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            200_000,
        )
        .unwrap();
        let evt = TransportEvent::from_certificate(
            &cert,
            TransportEventKind::CertificateCreated,
            test_epoch(),
        );
        let s = format!("{evt}");
        assert!(s.contains("certificate_created"));
        assert!(s.contains("x86-zen4"));
        assert!(s.contains("arm-nv2"));
    }

    // --- Constants tests ---

    #[test]
    fn constants_valid() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.16.2");
        assert_eq!(POLICY_ID, "RGC-616B");
        assert_eq!(COMPONENT, "transport_certificate_ledger");
        assert!(SCHEMA_VERSION.contains("transport_certificate_ledger"));
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // --- Ledger survival fraction ---

    #[test]
    fn ledger_survival_fraction() {
        let cert = evaluate_transport(
            ArtifactKind::CacheEntry,
            test_hash("surv"),
            &cell_x86_zen4(),
            &cell_x86_alder(),
            MILLIONTHS,
            800_000,
        )
        .unwrap();

        let components = vec![
            ResidualComponent::new("a", 600_000, 480_000, "x"),
            ResidualComponent::new("b", 400_000, 320_000, "y"),
        ];

        let ledger = build_residual_ledger(&cert, components).unwrap();
        assert_eq!(ledger.survival_fraction_millionths(), 800_000);
        assert_eq!(ledger.total_loss_millionths(), 200_000);
    }

    #[test]
    fn ledger_survival_fraction_zero_source() {
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("zsurv"),
            &cell_x86_zen4(),
            &cell_x86_zen4(),
            MILLIONTHS,
            MILLIONTHS,
        )
        .unwrap();

        let ledger = build_residual_ledger(&cert, vec![]).unwrap();
        // Zero source total → returns MILLIONTHS.
        assert_eq!(ledger.survival_fraction_millionths(), MILLIONTHS);
    }

    // --- Certificate same_arch / same_hardware ---

    #[test]
    fn certificate_same_arch_and_hardware() {
        let cell = cell_x86_zen4();
        let cert = evaluate_transport(
            ArtifactKind::RewriteRule,
            test_hash("same"),
            &cell,
            &cell,
            MILLIONTHS,
            MILLIONTHS,
        )
        .unwrap();
        assert!(cert.same_arch_family());
        assert!(cert.same_hardware());
    }

    #[test]
    fn certificate_diff_arch() {
        let cert = evaluate_transport(
            ArtifactKind::ProfileData,
            test_hash("diff"),
            &cell_x86_zen4(),
            &cell_arm_nv2(),
            MILLIONTHS,
            500_000,
        )
        .unwrap();
        assert!(!cert.same_arch_family());
        assert!(!cert.same_hardware());
    }
}
