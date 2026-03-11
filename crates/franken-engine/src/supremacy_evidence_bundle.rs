//! Supremacy evidence bundle — publication-grade packaging of supremacy verdicts.
//!
//! Bead: bd-1lsy.8.5.3 [RGC-705C]
//!
//! Packages supremacy verdicts into a fail-closed publication bundle that
//! can block docs, rollout, and GA if even one declared cell is missing,
//! red, unsupported, or mode-ambiguous.
//!
//! # Design
//!
//! - `CellStatus`: six-valued cell outcome (Green, Red, Yellow, Missing,
//!   Unsupported, ModeAmbiguous).
//! - `CellEvidence`: per-cell evidence record with status, verdict hash,
//!   observation count, effect size, and observability mode.
//! - `CoverageStats`: aggregate counts and coverage fraction.
//! - `BlockReason`: typed reasons a bundle blocks publication.
//! - `PublicationGateVerdict`: Approved or Blocked with reasons.
//! - `EvidenceBundle`: the assembled bundle with cells, verdict, hash chain.
//! - `BundleConfig`: required cell IDs, staleness, coverage, mode strictness.
//! - `DecisionReceipt`: hash-chained publication receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.supremacy-evidence-bundle.v1";

/// Component name.
pub const COMPONENT: &str = "supremacy_evidence_bundle";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.5.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705C";

/// One in fixed-point millionths.
const MILLIONTHS: u64 = 1_000_000;

/// Default minimum coverage fraction (millionths). 100% = 1_000_000.
pub const DEFAULT_MIN_COVERAGE_FRACTION: u64 = 1_000_000;

/// Default maximum staleness in epochs.
pub const DEFAULT_MAX_STALENESS_EPOCHS: u64 = 10;

/// Maximum cells per bundle.
pub const MAX_CELLS_PER_BUNDLE: usize = 512;

/// Maximum block reasons per verdict.
pub const MAX_BLOCK_REASONS: usize = 64;

// ---------------------------------------------------------------------------
// CellStatus
// ---------------------------------------------------------------------------

/// Six-valued status for a supremacy cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    /// Confirmed supremacy — cell passed all statistical checks.
    Green,
    /// Rejected — cell failed statistical or side-constraint checks.
    Red,
    /// Inconclusive — insufficient data to decide.
    Yellow,
    /// No data at all for this cell.
    Missing,
    /// Cell is not applicable to the current configuration.
    Unsupported,
    /// Observability mode is unclear or conflicting.
    ModeAmbiguous,
}

impl CellStatus {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Green,
        Self::Red,
        Self::Yellow,
        Self::Missing,
        Self::Unsupported,
        Self::ModeAmbiguous,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Red => "red",
            Self::Yellow => "yellow",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
            Self::ModeAmbiguous => "mode_ambiguous",
        }
    }

    /// Whether this status allows publication to proceed.
    pub const fn is_publication_safe(self) -> bool {
        matches!(self, Self::Green | Self::Yellow)
    }

    /// Whether this status blocks publication in strict mode.
    pub const fn blocks_strict(self) -> bool {
        matches!(
            self,
            Self::Red | Self::Missing | Self::Unsupported | Self::ModeAmbiguous
        )
    }
}

impl fmt::Display for CellStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ObservabilityMode
// ---------------------------------------------------------------------------

/// Telemetry/capture regime under which evidence was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityMode {
    /// Production-budgeted probabilistic telemetry.
    BudgetedCapture,
    /// Full exact counting — not production-safe but used for validation.
    ExactShadow,
    /// Degraded-mode capture with sampling.
    DegradedCapture,
    /// Incident / full-capture mode — temporarily unbounded.
    IncidentCapture,
}

impl ObservabilityMode {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::BudgetedCapture,
        Self::ExactShadow,
        Self::DegradedCapture,
        Self::IncidentCapture,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetedCapture => "budgeted_capture",
            Self::ExactShadow => "exact_shadow",
            Self::DegradedCapture => "degraded_capture",
            Self::IncidentCapture => "incident_capture",
        }
    }

    /// Whether this mode provides statistically rigorous measurements.
    pub const fn is_rigorous(self) -> bool {
        matches!(self, Self::BudgetedCapture | Self::ExactShadow)
    }
}

impl fmt::Display for ObservabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BlockReason
// ---------------------------------------------------------------------------

/// Typed reason why a publication gate blocks the bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// A required cell has no evidence at all.
    MissingCell { cell_id: String },
    /// A required cell has status Red.
    RedCell { cell_id: String },
    /// A cell is not applicable but was declared as required.
    UnsupportedCell { cell_id: String },
    /// A cell has ambiguous observability mode.
    ModeAmbiguousCell { cell_id: String },
    /// Aggregate green coverage is below the minimum fraction.
    InsufficientCoverage {
        coverage_fraction_millionths: u64,
        required_millionths: u64,
    },
    /// Evidence is stale — epoch gap exceeds the maximum.
    StaleEvidence {
        cell_id: String,
        evidence_epoch: u64,
        current_epoch: u64,
        max_staleness: u64,
    },
    /// Bundle hash verification failed.
    IntegrityFailure { details: String },
}

impl BlockReason {
    /// Stable tag for programmatic classification.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::MissingCell { .. } => "missing_cell",
            Self::RedCell { .. } => "red_cell",
            Self::UnsupportedCell { .. } => "unsupported_cell",
            Self::ModeAmbiguousCell { .. } => "mode_ambiguous_cell",
            Self::InsufficientCoverage { .. } => "insufficient_coverage",
            Self::StaleEvidence { .. } => "stale_evidence",
            Self::IntegrityFailure { .. } => "integrity_failure",
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCell { cell_id } => write!(f, "missing cell: {cell_id}"),
            Self::RedCell { cell_id } => write!(f, "red cell: {cell_id}"),
            Self::UnsupportedCell { cell_id } => write!(f, "unsupported cell: {cell_id}"),
            Self::ModeAmbiguousCell { cell_id } => {
                write!(f, "mode-ambiguous cell: {cell_id}")
            }
            Self::InsufficientCoverage {
                coverage_fraction_millionths,
                required_millionths,
            } => write!(
                f,
                "coverage {coverage_fraction_millionths} < required {required_millionths}"
            ),
            Self::StaleEvidence {
                cell_id,
                evidence_epoch,
                current_epoch,
                max_staleness,
            } => write!(
                f,
                "stale evidence for {cell_id}: epoch {evidence_epoch} vs current {current_epoch} (max staleness {max_staleness})"
            ),
            Self::IntegrityFailure { details } => {
                write!(f, "integrity failure: {details}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PublicationGateVerdict
// ---------------------------------------------------------------------------

/// Publication gate outcome: either approved or blocked with reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationGateVerdict {
    /// Bundle approved for publication.
    Approved,
    /// Bundle blocked — at least one reason prevents publication.
    Blocked { reasons: Vec<BlockReason> },
}

impl PublicationGateVerdict {
    /// Whether the verdict allows publication.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Whether the verdict blocks publication.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// Number of block reasons (0 if approved).
    pub fn block_count(&self) -> usize {
        match self {
            Self::Approved => 0,
            Self::Blocked { reasons } => reasons.len(),
        }
    }

    /// Stable tag for programmatic use.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Blocked { .. } => "blocked",
        }
    }
}

impl fmt::Display for PublicationGateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => write!(f, "APPROVED"),
            Self::Blocked { reasons } => {
                write!(f, "BLOCKED ({} reason(s))", reasons.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CellEvidence
// ---------------------------------------------------------------------------

/// Evidence record for a single supremacy cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellEvidence {
    /// Unique cell identifier.
    pub cell_id: String,
    /// Status of this cell.
    pub status: CellStatus,
    /// Hash of the underlying verdict that produced this status.
    pub verdict_hash: ContentHash,
    /// Number of observations that informed this cell.
    pub observation_count: u64,
    /// Effect size in millionths (Cohen's d scaled to millionths).
    pub effect_size_millionths: u64,
    /// Observability mode under which evidence was collected.
    pub observability_mode: ObservabilityMode,
    /// Epoch at which the evidence was generated.
    pub evidence_epoch: SecurityEpoch,
}

impl CellEvidence {
    /// Compute a content hash over this cell evidence.
    pub fn compute_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.cell_id.as_bytes());
        h.update(self.status.as_str().as_bytes());
        h.update(self.verdict_hash.as_bytes());
        h.update(self.observation_count.to_le_bytes());
        h.update(self.effect_size_millionths.to_le_bytes());
        h.update(self.observability_mode.as_str().as_bytes());
        h.update(self.evidence_epoch.as_u64().to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// CoverageStats
// ---------------------------------------------------------------------------

/// Aggregate coverage statistics for a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Total cells in the bundle.
    pub total_cells: usize,
    /// Cells with status Green.
    pub green_count: usize,
    /// Cells with status Red.
    pub red_count: usize,
    /// Cells with status Yellow.
    pub yellow_count: usize,
    /// Cells with status Missing.
    pub missing_count: usize,
    /// Cells with status Unsupported.
    pub unsupported_count: usize,
    /// Cells with status ModeAmbiguous.
    pub mode_ambiguous_count: usize,
    /// Green fraction in millionths (green_count / total_cells * 1_000_000).
    pub coverage_fraction_millionths: u64,
}

impl CoverageStats {
    /// Whether all cells are green.
    pub fn all_green(&self) -> bool {
        self.total_cells > 0 && self.green_count == self.total_cells
    }

    /// Whether any blocking status exists (red, missing, unsupported, mode-ambiguous).
    pub fn has_blocking_cells(&self) -> bool {
        self.red_count > 0
            || self.missing_count > 0
            || self.unsupported_count > 0
            || self.mode_ambiguous_count > 0
    }
}

impl fmt::Display for CoverageStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "coverage: {}/{} green ({} millionths), {} red, {} yellow, {} missing, {} unsupported, {} ambiguous",
            self.green_count,
            self.total_cells,
            self.coverage_fraction_millionths,
            self.red_count,
            self.yellow_count,
            self.missing_count,
            self.unsupported_count,
            self.mode_ambiguous_count,
        )
    }
}

// ---------------------------------------------------------------------------
// BundleConfig
// ---------------------------------------------------------------------------

/// Configuration for evidence bundle assembly and gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleConfig {
    /// Set of cell IDs that must be present in the bundle.
    pub required_cell_ids: BTreeSet<String>,
    /// Maximum epoch staleness allowed before evidence is considered stale.
    pub max_staleness_epochs: u64,
    /// Minimum green coverage fraction in millionths.
    pub min_coverage_fraction_millionths: u64,
    /// Whether *all* cells must be green for approval (strict mode).
    pub require_all_green: bool,
}

impl BundleConfig {
    /// Default configuration: strict, requires all green, no staleness.
    pub fn default_config() -> Self {
        Self {
            required_cell_ids: BTreeSet::new(),
            max_staleness_epochs: DEFAULT_MAX_STALENESS_EPOCHS,
            min_coverage_fraction_millionths: DEFAULT_MIN_COVERAGE_FRACTION,
            require_all_green: true,
        }
    }

    /// Permissive configuration for testing.
    pub fn permissive() -> Self {
        Self {
            required_cell_ids: BTreeSet::new(),
            max_staleness_epochs: u64::MAX,
            min_coverage_fraction_millionths: 0,
            require_all_green: false,
        }
    }
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// BundleError
// ---------------------------------------------------------------------------

/// Errors from bundle assembly or validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleError {
    /// No cells provided.
    EmptyCells,
    /// Too many cells (exceeds MAX_CELLS_PER_BUNDLE).
    TooManyCells { count: usize, max: usize },
    /// Duplicate cell IDs found.
    DuplicateCellIds { duplicates: Vec<String> },
    /// Required cell IDs are missing from the cell list.
    MissingRequiredCells { missing: Vec<String> },
    /// Bundle hash does not match recomputed hash.
    IntegrityMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
}

impl BundleError {
    /// Stable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::EmptyCells => "empty_cells",
            Self::TooManyCells { .. } => "too_many_cells",
            Self::DuplicateCellIds { .. } => "duplicate_cell_ids",
            Self::MissingRequiredCells { .. } => "missing_required_cells",
            Self::IntegrityMismatch { .. } => "integrity_mismatch",
        }
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCells => write!(f, "no cells provided"),
            Self::TooManyCells { count, max } => {
                write!(f, "too many cells: {count} > {max}")
            }
            Self::DuplicateCellIds { duplicates } => {
                write!(f, "duplicate cell IDs: {}", duplicates.join(", "))
            }
            Self::MissingRequiredCells { missing } => {
                write!(f, "missing required cells: {}", missing.join(", "))
            }
            Self::IntegrityMismatch { expected, actual } => {
                write!(f, "integrity mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceBundle
// ---------------------------------------------------------------------------

/// A publication-grade evidence bundle packaging supremacy verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Unique bundle identifier.
    pub bundle_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Per-cell evidence records.
    pub cells: Vec<CellEvidence>,
    /// Publication gate verdict.
    pub verdict: PublicationGateVerdict,
    /// Coverage statistics.
    pub coverage_stats: CoverageStats,
    /// Epoch at which the bundle was created.
    pub creation_epoch: SecurityEpoch,
    /// Content hash of the entire bundle (excluding this field).
    pub bundle_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Hash-chained publication receipt for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Bundle this receipt covers.
    pub bundle_id: String,
    /// The publication verdict at time of receipt.
    pub verdict_tag: String,
    /// Epoch of the receipt.
    pub epoch: SecurityEpoch,
    /// Hash of the bundle.
    pub bundle_hash: ContentHash,
    /// Hash of the previous receipt in the chain (zeroed for the first).
    pub previous_receipt_hash: ContentHash,
    /// This receipt's own hash.
    pub receipt_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new decision receipt with computed hash chain.
    pub fn new(
        receipt_id: impl Into<String>,
        bundle: &EvidenceBundle,
        previous_receipt_hash: ContentHash,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let bundle_id = bundle.bundle_id.clone();
        let verdict_tag = bundle.verdict.tag().to_string();
        let epoch = bundle.creation_epoch;
        let bundle_hash = bundle.bundle_hash.clone();

        let mut h = Sha256::new();
        h.update(receipt_id.as_bytes());
        h.update(bundle_id.as_bytes());
        h.update(verdict_tag.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(bundle_hash.as_bytes());
        h.update(previous_receipt_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());

        Self {
            receipt_id,
            bundle_id,
            verdict_tag,
            epoch,
            bundle_hash,
            previous_receipt_hash,
            receipt_hash,
        }
    }

    /// Verify the receipt hash is correct.
    pub fn verify(&self) -> bool {
        let mut h = Sha256::new();
        h.update(self.receipt_id.as_bytes());
        h.update(self.bundle_id.as_bytes());
        h.update(self.verdict_tag.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.bundle_hash.as_bytes());
        h.update(self.previous_receipt_hash.as_bytes());
        let expected = ContentHash::compute(&h.finalize());
        self.receipt_hash == expected
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute aggregate coverage statistics from a set of cell evidence records.
pub fn compute_coverage_stats(cells: &[CellEvidence]) -> CoverageStats {
    let total_cells = cells.len();
    let green_count = cells
        .iter()
        .filter(|c| c.status == CellStatus::Green)
        .count();
    let red_count = cells.iter().filter(|c| c.status == CellStatus::Red).count();
    let yellow_count = cells
        .iter()
        .filter(|c| c.status == CellStatus::Yellow)
        .count();
    let missing_count = cells
        .iter()
        .filter(|c| c.status == CellStatus::Missing)
        .count();
    let unsupported_count = cells
        .iter()
        .filter(|c| c.status == CellStatus::Unsupported)
        .count();
    let mode_ambiguous_count = cells
        .iter()
        .filter(|c| c.status == CellStatus::ModeAmbiguous)
        .count();

    let coverage_fraction_millionths = if total_cells == 0 {
        0
    } else {
        (green_count as u64)
            .saturating_mul(MILLIONTHS)
            .checked_div(total_cells as u64)
            .unwrap_or(0)
    };

    CoverageStats {
        total_cells,
        green_count,
        red_count,
        yellow_count,
        missing_count,
        unsupported_count,
        mode_ambiguous_count,
        coverage_fraction_millionths,
    }
}

/// Evaluate the publication gate against a bundle and config.
///
/// Fail-closed: any issue produces a Blocked verdict.
pub fn evaluate_publication_gate(
    bundle: &EvidenceBundle,
    config: &BundleConfig,
) -> PublicationGateVerdict {
    let mut reasons = Vec::new();

    // 1. Check required cells are present.
    let present_ids: BTreeSet<&str> = bundle.cells.iter().map(|c| c.cell_id.as_str()).collect();
    for req in &config.required_cell_ids {
        if !present_ids.contains(req.as_str()) {
            reasons.push(BlockReason::MissingCell {
                cell_id: req.clone(),
            });
        }
    }

    // 2. Check individual cell statuses.
    for cell in &bundle.cells {
        match cell.status {
            CellStatus::Red => {
                reasons.push(BlockReason::RedCell {
                    cell_id: cell.cell_id.clone(),
                });
            }
            CellStatus::Missing => {
                reasons.push(BlockReason::MissingCell {
                    cell_id: cell.cell_id.clone(),
                });
            }
            CellStatus::Unsupported => {
                reasons.push(BlockReason::UnsupportedCell {
                    cell_id: cell.cell_id.clone(),
                });
            }
            CellStatus::ModeAmbiguous => {
                reasons.push(BlockReason::ModeAmbiguousCell {
                    cell_id: cell.cell_id.clone(),
                });
            }
            CellStatus::Green | CellStatus::Yellow => {}
        }
    }

    // 3. Check yellow cells if require_all_green.
    if config.require_all_green {
        let yellow_exists = bundle.cells.iter().any(|c| c.status == CellStatus::Yellow);
        if yellow_exists {
            // In strict mode, yellow cells contribute to insufficient coverage.
            let green_fraction = bundle.coverage_stats.coverage_fraction_millionths;
            if green_fraction < config.min_coverage_fraction_millionths {
                reasons.push(BlockReason::InsufficientCoverage {
                    coverage_fraction_millionths: green_fraction,
                    required_millionths: config.min_coverage_fraction_millionths,
                });
            }
        }
    }

    // 4. Check overall coverage fraction.
    if bundle.coverage_stats.coverage_fraction_millionths < config.min_coverage_fraction_millionths
    {
        // Avoid duplicate if already pushed from yellow check.
        let already_pushed = reasons
            .iter()
            .any(|r| matches!(r, BlockReason::InsufficientCoverage { .. }));
        if !already_pushed {
            reasons.push(BlockReason::InsufficientCoverage {
                coverage_fraction_millionths: bundle.coverage_stats.coverage_fraction_millionths,
                required_millionths: config.min_coverage_fraction_millionths,
            });
        }
    }

    // 5. Check staleness.
    let current_epoch = bundle.creation_epoch.as_u64();
    for cell in &bundle.cells {
        let cell_epoch = cell.evidence_epoch.as_u64();
        if current_epoch > cell_epoch {
            let gap = current_epoch - cell_epoch;
            if gap > config.max_staleness_epochs {
                reasons.push(BlockReason::StaleEvidence {
                    cell_id: cell.cell_id.clone(),
                    evidence_epoch: cell_epoch,
                    current_epoch,
                    max_staleness: config.max_staleness_epochs,
                });
            }
        }
    }

    if reasons.is_empty() {
        PublicationGateVerdict::Approved
    } else {
        PublicationGateVerdict::Blocked { reasons }
    }
}

/// Compute the content hash for a bundle given its cells, epoch, and verdict.
fn compute_bundle_hash(
    bundle_id: &str,
    cells: &[CellEvidence],
    verdict: &PublicationGateVerdict,
    creation_epoch: SecurityEpoch,
    coverage_stats: &CoverageStats,
) -> ContentHash {
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(bundle_id.as_bytes());
    h.update(creation_epoch.as_u64().to_le_bytes());
    h.update((cells.len() as u64).to_le_bytes());
    for cell in cells {
        h.update(cell.cell_id.as_bytes());
        h.update(cell.status.as_str().as_bytes());
        h.update(cell.verdict_hash.as_bytes());
    }
    h.update(verdict.tag().as_bytes());
    h.update(coverage_stats.coverage_fraction_millionths.to_le_bytes());
    ContentHash::compute(&h.finalize())
}

/// Assemble an evidence bundle from cells and config.
///
/// Validates inputs, computes coverage stats, evaluates the publication gate,
/// and produces a hash-sealed bundle.
pub fn assemble_bundle(
    bundle_id: impl Into<String>,
    cells: &[CellEvidence],
    config: &BundleConfig,
    creation_epoch: SecurityEpoch,
) -> Result<EvidenceBundle, BundleError> {
    // Validate: non-empty.
    if cells.is_empty() {
        return Err(BundleError::EmptyCells);
    }

    // Validate: not too many.
    if cells.len() > MAX_CELLS_PER_BUNDLE {
        return Err(BundleError::TooManyCells {
            count: cells.len(),
            max: MAX_CELLS_PER_BUNDLE,
        });
    }

    // Validate: no duplicate cell IDs.
    let mut seen = BTreeSet::new();
    let mut duplicates = Vec::new();
    for cell in cells {
        if !seen.insert(&cell.cell_id) {
            duplicates.push(cell.cell_id.clone());
        }
    }
    if !duplicates.is_empty() {
        duplicates.sort();
        duplicates.dedup();
        return Err(BundleError::DuplicateCellIds { duplicates });
    }

    // Validate: required cells present.
    let present: BTreeSet<&str> = cells.iter().map(|c| c.cell_id.as_str()).collect();
    let missing: Vec<String> = config
        .required_cell_ids
        .iter()
        .filter(|r| !present.contains(r.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(BundleError::MissingRequiredCells { missing });
    }

    let bundle_id = bundle_id.into();
    let coverage_stats = compute_coverage_stats(cells);

    // Build a temporary bundle to evaluate the gate.
    let temp_verdict = PublicationGateVerdict::Approved; // placeholder
    let temp_hash = ContentHash::compute(b"temp");
    let temp_bundle = EvidenceBundle {
        bundle_id: bundle_id.clone(),
        schema_version: SCHEMA_VERSION.to_string(),
        cells: cells.to_vec(),
        verdict: temp_verdict,
        coverage_stats: coverage_stats.clone(),
        creation_epoch,
        bundle_hash: temp_hash,
    };

    let verdict = evaluate_publication_gate(&temp_bundle, config);

    let bundle_hash =
        compute_bundle_hash(&bundle_id, cells, &verdict, creation_epoch, &coverage_stats);

    Ok(EvidenceBundle {
        bundle_id,
        schema_version: SCHEMA_VERSION.to_string(),
        cells: cells.to_vec(),
        verdict,
        coverage_stats,
        creation_epoch,
        bundle_hash,
    })
}

/// Validate the integrity of an existing bundle by recomputing its hash.
pub fn validate_bundle_integrity(bundle: &EvidenceBundle) -> Result<(), BundleError> {
    let expected = compute_bundle_hash(
        &bundle.bundle_id,
        &bundle.cells,
        &bundle.verdict,
        bundle.creation_epoch,
        &bundle.coverage_stats,
    );
    if expected == bundle.bundle_hash {
        Ok(())
    } else {
        Err(BundleError::IntegrityMismatch {
            expected,
            actual: bundle.bundle_hash.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn green_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Green,
            verdict_hash: ContentHash::compute(id.as_bytes()),
            observation_count: 100,
            effect_size_millionths: 300_000,
            observability_mode: ObservabilityMode::BudgetedCapture,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn red_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Red,
            verdict_hash: ContentHash::compute(id.as_bytes()),
            observation_count: 50,
            effect_size_millionths: 100_000,
            observability_mode: ObservabilityMode::BudgetedCapture,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn yellow_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Yellow,
            verdict_hash: ContentHash::compute(id.as_bytes()),
            observation_count: 10,
            effect_size_millionths: 50_000,
            observability_mode: ObservabilityMode::ExactShadow,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn missing_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Missing,
            verdict_hash: ContentHash::compute(b"empty"),
            observation_count: 0,
            effect_size_millionths: 0,
            observability_mode: ObservabilityMode::BudgetedCapture,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn unsupported_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Unsupported,
            verdict_hash: ContentHash::compute(b"na"),
            observation_count: 0,
            effect_size_millionths: 0,
            observability_mode: ObservabilityMode::DegradedCapture,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn ambiguous_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::ModeAmbiguous,
            verdict_hash: ContentHash::compute(b"ambig"),
            observation_count: 30,
            effect_size_millionths: 200_000,
            observability_mode: ObservabilityMode::IncidentCapture,
            evidence_epoch: SecurityEpoch::from_raw(100),
        }
    }

    fn stale_cell(id: &str) -> CellEvidence {
        CellEvidence {
            cell_id: id.to_string(),
            status: CellStatus::Green,
            verdict_hash: ContentHash::compute(id.as_bytes()),
            observation_count: 100,
            effect_size_millionths: 300_000,
            observability_mode: ObservabilityMode::BudgetedCapture,
            evidence_epoch: SecurityEpoch::from_raw(50), // old epoch
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("supremacy-evidence-bundle"));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "supremacy_evidence_bundle");
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
    fn default_constants_valid() {
        assert_eq!(DEFAULT_MIN_COVERAGE_FRACTION, 1_000_000);
        const { assert!(DEFAULT_MIN_COVERAGE_FRACTION <= MILLIONTHS) };
        assert_eq!(DEFAULT_MAX_STALENESS_EPOCHS, 10);
        assert_eq!(MAX_CELLS_PER_BUNDLE, 512);
        assert_eq!(MAX_BLOCK_REASONS, 64);
    }

    // --- CellStatus ---

    #[test]
    fn cell_status_all_length() {
        assert_eq!(CellStatus::ALL.len(), 6);
    }

    #[test]
    fn cell_status_names_unique() {
        let names: BTreeSet<&str> = CellStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), CellStatus::ALL.len());
    }

    #[test]
    fn cell_status_display() {
        for s in CellStatus::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn cell_status_serde_roundtrip() {
        for s in CellStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CellStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn cell_status_publication_safe() {
        assert!(CellStatus::Green.is_publication_safe());
        assert!(CellStatus::Yellow.is_publication_safe());
        assert!(!CellStatus::Red.is_publication_safe());
        assert!(!CellStatus::Missing.is_publication_safe());
        assert!(!CellStatus::Unsupported.is_publication_safe());
        assert!(!CellStatus::ModeAmbiguous.is_publication_safe());
    }

    #[test]
    fn cell_status_blocks_strict() {
        assert!(!CellStatus::Green.blocks_strict());
        assert!(!CellStatus::Yellow.blocks_strict());
        assert!(CellStatus::Red.blocks_strict());
        assert!(CellStatus::Missing.blocks_strict());
        assert!(CellStatus::Unsupported.blocks_strict());
        assert!(CellStatus::ModeAmbiguous.blocks_strict());
    }

    // --- ObservabilityMode ---

    #[test]
    fn obs_mode_all_length() {
        assert_eq!(ObservabilityMode::ALL.len(), 4);
    }

    #[test]
    fn obs_mode_names_unique() {
        let names: BTreeSet<&str> = ObservabilityMode::ALL.iter().map(|m| m.as_str()).collect();
        assert_eq!(names.len(), ObservabilityMode::ALL.len());
    }

    #[test]
    fn obs_mode_display() {
        for m in ObservabilityMode::ALL {
            assert_eq!(m.to_string(), m.as_str());
        }
    }

    #[test]
    fn obs_mode_serde() {
        for m in ObservabilityMode::ALL {
            let json = serde_json::to_string(m).unwrap();
            let back: ObservabilityMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, back);
        }
    }

    #[test]
    fn obs_mode_rigor() {
        assert!(ObservabilityMode::BudgetedCapture.is_rigorous());
        assert!(ObservabilityMode::ExactShadow.is_rigorous());
        assert!(!ObservabilityMode::DegradedCapture.is_rigorous());
        assert!(!ObservabilityMode::IncidentCapture.is_rigorous());
    }

    // --- BlockReason ---

    #[test]
    fn block_reason_tags_unique() {
        let reasons = [
            BlockReason::MissingCell {
                cell_id: "a".into(),
            },
            BlockReason::RedCell {
                cell_id: "b".into(),
            },
            BlockReason::UnsupportedCell {
                cell_id: "c".into(),
            },
            BlockReason::ModeAmbiguousCell {
                cell_id: "d".into(),
            },
            BlockReason::InsufficientCoverage {
                coverage_fraction_millionths: 0,
                required_millionths: 0,
            },
            BlockReason::StaleEvidence {
                cell_id: "e".into(),
                evidence_epoch: 0,
                current_epoch: 100,
                max_staleness: 10,
            },
            BlockReason::IntegrityFailure {
                details: "bad".into(),
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 7);
    }

    #[test]
    fn block_reason_display_missing() {
        let r = BlockReason::MissingCell {
            cell_id: "cell-x".into(),
        };
        assert!(r.to_string().contains("cell-x"));
    }

    #[test]
    fn block_reason_display_red() {
        let r = BlockReason::RedCell {
            cell_id: "cell-y".into(),
        };
        assert!(r.to_string().contains("red"));
    }

    #[test]
    fn block_reason_display_stale() {
        let r = BlockReason::StaleEvidence {
            cell_id: "cell-z".into(),
            evidence_epoch: 10,
            current_epoch: 100,
            max_staleness: 5,
        };
        let s = r.to_string();
        assert!(s.contains("stale"));
        assert!(s.contains("cell-z"));
    }

    #[test]
    fn block_reason_serde_roundtrip() {
        let r = BlockReason::InsufficientCoverage {
            coverage_fraction_millionths: 500_000,
            required_millionths: 1_000_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: BlockReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- PublicationGateVerdict ---

    #[test]
    fn verdict_approved() {
        let v = PublicationGateVerdict::Approved;
        assert!(v.is_approved());
        assert!(!v.is_blocked());
        assert_eq!(v.block_count(), 0);
        assert_eq!(v.tag(), "approved");
    }

    #[test]
    fn verdict_blocked() {
        let v = PublicationGateVerdict::Blocked {
            reasons: vec![BlockReason::MissingCell {
                cell_id: "x".into(),
            }],
        };
        assert!(!v.is_approved());
        assert!(v.is_blocked());
        assert_eq!(v.block_count(), 1);
        assert_eq!(v.tag(), "blocked");
    }

    #[test]
    fn verdict_display() {
        let v = PublicationGateVerdict::Approved;
        assert_eq!(v.to_string(), "APPROVED");
        let v2 = PublicationGateVerdict::Blocked {
            reasons: vec![
                BlockReason::RedCell {
                    cell_id: "a".into(),
                },
                BlockReason::RedCell {
                    cell_id: "b".into(),
                },
            ],
        };
        assert!(v2.to_string().contains("2 reason(s)"));
    }

    #[test]
    fn verdict_serde() {
        let v = PublicationGateVerdict::Blocked {
            reasons: vec![BlockReason::IntegrityFailure {
                details: "hash mismatch".into(),
            }],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PublicationGateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- CellEvidence ---

    #[test]
    fn cell_evidence_hash_deterministic() {
        let c1 = green_cell("cell-a");
        let c2 = green_cell("cell-a");
        assert_eq!(c1.compute_hash(), c2.compute_hash());
    }

    #[test]
    fn cell_evidence_different_id_different_hash() {
        let c1 = green_cell("cell-a");
        let c2 = green_cell("cell-b");
        assert_ne!(c1.compute_hash(), c2.compute_hash());
    }

    #[test]
    fn cell_evidence_serde() {
        let c = green_cell("cell-serde");
        let json = serde_json::to_string(&c).unwrap();
        let back: CellEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- CoverageStats ---

    #[test]
    fn coverage_all_green() {
        let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
        let stats = compute_coverage_stats(&cells);
        assert_eq!(stats.total_cells, 3);
        assert_eq!(stats.green_count, 3);
        assert_eq!(stats.red_count, 0);
        assert!(stats.all_green());
        assert!(!stats.has_blocking_cells());
        assert_eq!(stats.coverage_fraction_millionths, MILLIONTHS);
    }

    #[test]
    fn coverage_mixed() {
        let cells = vec![green_cell("a"), red_cell("b"), yellow_cell("c")];
        let stats = compute_coverage_stats(&cells);
        assert_eq!(stats.total_cells, 3);
        assert_eq!(stats.green_count, 1);
        assert_eq!(stats.red_count, 1);
        assert_eq!(stats.yellow_count, 1);
        assert!(!stats.all_green());
        assert!(stats.has_blocking_cells());
        // 1/3 * 1_000_000 = 333_333
        assert_eq!(stats.coverage_fraction_millionths, 333_333);
    }

    #[test]
    fn coverage_empty() {
        let stats = compute_coverage_stats(&[]);
        assert_eq!(stats.total_cells, 0);
        assert!(!stats.all_green());
        assert_eq!(stats.coverage_fraction_millionths, 0);
    }

    #[test]
    fn coverage_stats_display() {
        let cells = vec![green_cell("a"), red_cell("b")];
        let stats = compute_coverage_stats(&cells);
        let s = stats.to_string();
        assert!(s.contains("coverage"));
        assert!(s.contains("green"));
    }

    #[test]
    fn coverage_all_missing() {
        let cells = vec![missing_cell("a"), missing_cell("b")];
        let stats = compute_coverage_stats(&cells);
        assert_eq!(stats.missing_count, 2);
        assert_eq!(stats.green_count, 0);
        assert!(stats.has_blocking_cells());
    }

    #[test]
    fn coverage_unsupported_and_ambiguous() {
        let cells = vec![unsupported_cell("a"), ambiguous_cell("b")];
        let stats = compute_coverage_stats(&cells);
        assert_eq!(stats.unsupported_count, 1);
        assert_eq!(stats.mode_ambiguous_count, 1);
        assert!(stats.has_blocking_cells());
    }

    // --- BundleConfig ---

    #[test]
    fn config_default() {
        let c = BundleConfig::default();
        assert!(c.required_cell_ids.is_empty());
        assert_eq!(c.max_staleness_epochs, DEFAULT_MAX_STALENESS_EPOCHS);
        assert_eq!(
            c.min_coverage_fraction_millionths,
            DEFAULT_MIN_COVERAGE_FRACTION
        );
        assert!(c.require_all_green);
    }

    #[test]
    fn config_permissive() {
        let c = BundleConfig::permissive();
        assert!(!c.require_all_green);
        assert_eq!(c.min_coverage_fraction_millionths, 0);
    }

    #[test]
    fn config_serde() {
        let c = BundleConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: BundleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- BundleError ---

    #[test]
    fn error_tags_unique() {
        let errors: Vec<BundleError> = vec![
            BundleError::EmptyCells,
            BundleError::TooManyCells {
                count: 600,
                max: 512,
            },
            BundleError::DuplicateCellIds {
                duplicates: vec!["a".into()],
            },
            BundleError::MissingRequiredCells {
                missing: vec!["b".into()],
            },
            BundleError::IntegrityMismatch {
                expected: ContentHash::compute(b"a"),
                actual: ContentHash::compute(b"b"),
            },
        ];
        let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
        assert_eq!(tags.len(), 5);
    }

    #[test]
    fn error_display() {
        assert!(BundleError::EmptyCells.to_string().contains("no cells"));
        let e = BundleError::TooManyCells {
            count: 600,
            max: 512,
        };
        assert!(e.to_string().contains("600"));
    }

    #[test]
    fn error_serde() {
        let e = BundleError::DuplicateCellIds {
            duplicates: vec!["cell-1".into(), "cell-2".into()],
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: BundleError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- assemble_bundle ---

    #[test]
    fn assemble_all_green_approved() {
        let cells = vec![green_cell("a"), green_cell("b"), green_cell("c")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("bundle-1", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_approved());
        assert_eq!(bundle.cells.len(), 3);
        assert_eq!(bundle.coverage_stats.green_count, 3);
    }

    #[test]
    fn assemble_with_red_blocked() {
        let cells = vec![green_cell("a"), red_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("bundle-red", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
    }

    #[test]
    fn assemble_empty_error() {
        let config = BundleConfig::default();
        let err = assemble_bundle("empty", &[], &config, epoch()).unwrap_err();
        assert_eq!(err.tag(), "empty_cells");
    }

    #[test]
    fn assemble_duplicate_ids_error() {
        let cells = vec![green_cell("dup"), green_cell("dup")];
        let config = BundleConfig::permissive();
        let err = assemble_bundle("dup-bundle", &cells, &config, epoch()).unwrap_err();
        assert_eq!(err.tag(), "duplicate_cell_ids");
    }

    #[test]
    fn assemble_missing_required_error() {
        let cells = vec![green_cell("a")];
        let mut config = BundleConfig::permissive();
        config.required_cell_ids.insert("b".to_string());
        let err = assemble_bundle("miss", &cells, &config, epoch()).unwrap_err();
        assert_eq!(err.tag(), "missing_required_cells");
    }

    #[test]
    fn assemble_stale_evidence_blocked() {
        let cells = vec![stale_cell("stale-a")];
        let mut config = BundleConfig::permissive();
        config.max_staleness_epochs = 5;
        let bundle = assemble_bundle("stale-bundle", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
        if let PublicationGateVerdict::Blocked { reasons } = &bundle.verdict {
            assert!(reasons.iter().any(|r| r.tag() == "stale_evidence"));
        }
    }

    // --- validate_bundle_integrity ---

    #[test]
    fn integrity_valid() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("valid", &cells, &config, epoch()).unwrap();
        assert!(validate_bundle_integrity(&bundle).is_ok());
    }

    #[test]
    fn integrity_tampered() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let mut bundle = assemble_bundle("tamper", &cells, &config, epoch()).unwrap();
        bundle.bundle_id = "tampered-id".to_string();
        assert!(validate_bundle_integrity(&bundle).is_err());
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_creation() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("rcpt", &cells, &config, epoch()).unwrap();
        let genesis_hash = ContentHash::compute(b"genesis");
        let receipt = DecisionReceipt::new("rcpt-001", &bundle, genesis_hash);
        assert_eq!(receipt.bundle_id, "rcpt");
        assert!(receipt.verify());
    }

    #[test]
    fn receipt_chain() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let bundle1 = assemble_bundle("b1", &cells, &config, epoch()).unwrap();
        let bundle2 = assemble_bundle("b2", &cells, &config, epoch()).unwrap();

        let genesis = ContentHash::compute(b"genesis");
        let r1 = DecisionReceipt::new("r1", &bundle1, genesis);
        assert!(r1.verify());

        let r2 = DecisionReceipt::new("r2", &bundle2, r1.receipt_hash.clone());
        assert!(r2.verify());
        assert_eq!(r2.previous_receipt_hash, r1.receipt_hash);
    }

    #[test]
    fn receipt_tampered_fails_verify() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("rtamp", &cells, &config, epoch()).unwrap();
        let genesis = ContentHash::compute(b"genesis");
        let mut receipt = DecisionReceipt::new("rtamp-001", &bundle, genesis);
        receipt.verdict_tag = "tampered".to_string();
        assert!(!receipt.verify());
    }

    #[test]
    fn receipt_serde() {
        let cells = vec![green_cell("a")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("rserde", &cells, &config, epoch()).unwrap();
        let genesis = ContentHash::compute(b"genesis");
        let receipt = DecisionReceipt::new("rs-001", &bundle, genesis);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- evaluate_publication_gate ---

    #[test]
    fn gate_blocks_unsupported() {
        let cells = vec![green_cell("a"), unsupported_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("unsup", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
    }

    #[test]
    fn gate_blocks_mode_ambiguous() {
        let cells = vec![green_cell("a"), ambiguous_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("ambig", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
    }

    #[test]
    fn gate_blocks_missing_status() {
        let cells = vec![green_cell("a"), missing_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("miss-status", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
    }

    #[test]
    fn gate_coverage_threshold() {
        // 1 green, 1 yellow => 50% green. With min 100%, should block.
        let cells = vec![green_cell("a"), yellow_cell("b")];
        let mut config = BundleConfig::permissive();
        config.min_coverage_fraction_millionths = MILLIONTHS;
        config.require_all_green = true;
        let bundle = assemble_bundle("cov-low", &cells, &config, epoch()).unwrap();
        assert!(bundle.verdict.is_blocked());
    }

    #[test]
    fn gate_yellow_approved_permissive() {
        let cells = vec![green_cell("a"), yellow_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("yellow-ok", &cells, &config, epoch()).unwrap();
        // Permissive: yellow is not blocking by itself (no strict check).
        assert!(bundle.verdict.is_approved());
    }

    // --- EvidenceBundle serde ---

    #[test]
    fn bundle_serde_roundtrip() {
        let cells = vec![green_cell("a"), green_cell("b")];
        let config = BundleConfig::permissive();
        let bundle = assemble_bundle("serde-test", &cells, &config, epoch()).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn bundle_hash_deterministic() {
        let cells = vec![green_cell("a"), green_cell("b")];
        let config = BundleConfig::permissive();
        let b1 = assemble_bundle("det", &cells, &config, epoch()).unwrap();
        let b2 = assemble_bundle("det", &cells, &config, epoch()).unwrap();
        assert_eq!(b1.bundle_hash, b2.bundle_hash);
    }
}
