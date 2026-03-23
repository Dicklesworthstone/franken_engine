//! JS/TS shipped-path matrix with artifact-rich mismatch classification.
//!
//! Implements [RGC-806B]: extends parity verification across JS and TS workload
//! classes with standardized artifact capture and deterministic mismatch
//! classification. This verifies that the library API and shipped CLI
//! (frankenctl) produce equivalent results.
//!
//! # Design
//!
//! - `WorkloadClass` partitions the JS/TS workload space into six categories.
//! - `Surface` identifies the execution surface (library or CLI).
//! - `CapturedArtifact` records a content-hashed artifact from one surface.
//! - `ClassifiedMismatch` labels each artifact discrepancy with class, severity,
//!   and provenance metadata.
//! - `MatrixCell` gathers per-workload-class artifacts from both surfaces and
//!   the resulting mismatches.
//! - `evaluate_matrix` produces a `MatrixReport` with an overall verdict and
//!   a cryptographic `DecisionReceipt`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-806B]

#![forbid(unsafe_code)]

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
pub const SCHEMA_VERSION: &str = "franken-engine.shipped-path-matrix.v1";

/// Component name.
pub const COMPONENT: &str = "shipped_path_matrix";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.6.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-806B";

/// Default maximum size divergence threshold (millionths).
/// 10% = 100_000.
pub const DEFAULT_MAX_SIZE_DIVERGENCE: u64 = 100_000;

/// Default severity threshold: mismatches at or above this severity fail.
pub const DEFAULT_SEVERITY_THRESHOLD: MismatchSeverity = MismatchSeverity::Major;

// ---------------------------------------------------------------------------
// WorkloadClass
// ---------------------------------------------------------------------------

/// JS/TS workload class partitioning the input space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadClass {
    /// Pure JavaScript workload.
    PureJs,
    /// Pure TypeScript workload.
    PureTs,
    /// Mixed JS and TS workload.
    MixedJsTs,
    /// ECMAScript module workload.
    Esm,
    /// CommonJS module workload.
    Cjs,
    /// Mixed ESM and CJS workload.
    MixedEsmCjs,
}

impl WorkloadClass {
    pub const ALL: &[Self] = &[
        Self::PureJs,
        Self::PureTs,
        Self::MixedJsTs,
        Self::Esm,
        Self::Cjs,
        Self::MixedEsmCjs,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PureJs => "pure_js",
            Self::PureTs => "pure_ts",
            Self::MixedJsTs => "mixed_js_ts",
            Self::Esm => "esm",
            Self::Cjs => "cjs",
            Self::MixedEsmCjs => "mixed_esm_cjs",
        }
    }
}

impl fmt::Display for WorkloadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// Execution surface: library API or CLI binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Library API surface.
    Library,
    /// CLI (frankenctl) surface.
    Cli,
}

impl Surface {
    pub const ALL: &[Self] = &[Self::Library, Self::Cli];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Cli => "cli",
        }
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

/// Kind of captured artifact from an execution surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Compiled output code.
    CompiledOutput,
    /// Source map.
    SourceMap,
    /// Type annotation metadata.
    TypeAnnotation,
    /// Diagnostic message.
    Diagnostic,
    /// Module dependency graph.
    ModuleGraph,
    /// Binding trace for live-binding verification.
    BindingTrace,
}

impl ArtifactKind {
    pub const ALL: &[Self] = &[
        Self::CompiledOutput,
        Self::SourceMap,
        Self::TypeAnnotation,
        Self::Diagnostic,
        Self::ModuleGraph,
        Self::BindingTrace,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompiledOutput => "compiled_output",
            Self::SourceMap => "source_map",
            Self::TypeAnnotation => "type_annotation",
            Self::Diagnostic => "diagnostic",
            Self::ModuleGraph => "module_graph",
            Self::BindingTrace => "binding_trace",
        }
    }

    /// Semantic weight of this artifact kind for severity classification.
    /// Higher weight = mismatches here are more severe.
    pub const fn semantic_weight(self) -> u32 {
        match self {
            Self::CompiledOutput => 10,
            Self::ModuleGraph => 8,
            Self::BindingTrace => 7,
            Self::TypeAnnotation => 6,
            Self::SourceMap => 4,
            Self::Diagnostic => 3,
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CapturedArtifact
// ---------------------------------------------------------------------------

/// An artifact captured from one execution surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedArtifact {
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// Surface that produced this artifact.
    pub surface: Surface,
    /// Content hash of the artifact payload.
    pub content_hash: ContentHash,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Workload class this artifact belongs to.
    pub workload_class: WorkloadClass,
}

impl CapturedArtifact {
    /// Create a new captured artifact.
    pub fn new(
        kind: ArtifactKind,
        surface: Surface,
        payload: &[u8],
        workload_class: WorkloadClass,
    ) -> Self {
        Self {
            kind,
            surface,
            content_hash: ContentHash::compute(payload),
            size_bytes: payload.len() as u64,
            workload_class,
        }
    }
}

// ---------------------------------------------------------------------------
// MismatchClass
// ---------------------------------------------------------------------------

/// Classification of a mismatch between surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchClass {
    /// Artifact present on one surface but missing on the other.
    Missing,
    /// Extra artifact on one surface not expected.
    Extra,
    /// Content of the artifact differs.
    ContentDivergence,
    /// Size differs beyond threshold.
    SizeDivergence,
    /// Order of artifacts differs.
    OrderDivergence,
    /// Semantically equivalent but structurally different.
    SemanticDivergence,
}

impl MismatchClass {
    pub const ALL: &[Self] = &[
        Self::Missing,
        Self::Extra,
        Self::ContentDivergence,
        Self::SizeDivergence,
        Self::OrderDivergence,
        Self::SemanticDivergence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Extra => "extra",
            Self::ContentDivergence => "content_divergence",
            Self::SizeDivergence => "size_divergence",
            Self::OrderDivergence => "order_divergence",
            Self::SemanticDivergence => "semantic_divergence",
        }
    }
}

impl fmt::Display for MismatchClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MismatchSeverity
// ---------------------------------------------------------------------------

/// Severity of a classified mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    /// Informational only, no action needed.
    Informational,
    /// Minor mismatch, may be acceptable.
    Minor,
    /// Major mismatch, usually actionable.
    Major,
    /// Critical mismatch, blocks shipping.
    Critical,
}

impl MismatchSeverity {
    pub const ALL: &[Self] = &[
        Self::Informational,
        Self::Minor,
        Self::Major,
        Self::Critical,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Minor => "minor",
            Self::Major => "major",
            Self::Critical => "critical",
        }
    }

    /// Numeric rank for comparisons (higher = more severe).
    pub const fn rank(self) -> u32 {
        match self {
            Self::Informational => 0,
            Self::Minor => 1,
            Self::Major => 2,
            Self::Critical => 3,
        }
    }
}

impl fmt::Display for MismatchSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ClassifiedMismatch
// ---------------------------------------------------------------------------

/// A mismatch between two surfaces, fully classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedMismatch {
    /// Classification of the mismatch.
    pub class: MismatchClass,
    /// Severity.
    pub severity: MismatchSeverity,
    /// Which surface diverged (the "extra" or "different" side).
    pub surface: Surface,
    /// Kind of artifact involved.
    pub artifact_kind: ArtifactKind,
    /// Workload class.
    pub workload_class: WorkloadClass,
    /// Human-readable detail.
    pub detail: String,
    /// Content hash from surface A (Library), if present.
    pub content_hash_a: Option<ContentHash>,
    /// Content hash from surface B (CLI), if present.
    pub content_hash_b: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// CellVerdict
// ---------------------------------------------------------------------------

/// Verdict for a single matrix cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellVerdict {
    /// All artifacts match.
    Pass,
    /// Artifacts do not match.
    Fail,
    /// Cannot determine (missing data).
    Inconclusive,
}

impl CellVerdict {
    pub const ALL: &[Self] = &[Self::Pass, Self::Fail, Self::Inconclusive];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for CellVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MatrixCell
// ---------------------------------------------------------------------------

/// A single cell in the shipped-path matrix, one per workload class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCell {
    /// Workload class for this cell.
    pub workload_class: WorkloadClass,
    /// Artifacts from surface A (Library).
    pub artifacts_a: Vec<CapturedArtifact>,
    /// Artifacts from surface B (CLI).
    pub artifacts_b: Vec<CapturedArtifact>,
    /// Classified mismatches.
    pub mismatches: Vec<ClassifiedMismatch>,
    /// Verdict for this cell.
    pub verdict: CellVerdict,
}

impl MatrixCell {
    /// Create a new cell with pre-computed mismatches and verdict.
    pub fn new(
        workload_class: WorkloadClass,
        artifacts_a: Vec<CapturedArtifact>,
        artifacts_b: Vec<CapturedArtifact>,
        mismatches: Vec<ClassifiedMismatch>,
        verdict: CellVerdict,
    ) -> Self {
        Self {
            workload_class,
            artifacts_a,
            artifacts_b,
            mismatches,
            verdict,
        }
    }

    /// Number of critical mismatches.
    pub fn critical_count(&self) -> usize {
        self.mismatches
            .iter()
            .filter(|m| m.severity == MismatchSeverity::Critical)
            .count()
    }

    /// Number of major mismatches.
    pub fn major_count(&self) -> usize {
        self.mismatches
            .iter()
            .filter(|m| m.severity == MismatchSeverity::Major)
            .count()
    }
}

// ---------------------------------------------------------------------------
// MatrixConfig
// ---------------------------------------------------------------------------

/// Configuration for matrix evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixConfig {
    /// Required workload classes — cells for these must exist and pass.
    pub required_workload_classes: BTreeSet<WorkloadClass>,
    /// Maximum tolerated size divergence (millionths).
    pub max_size_divergence_millionths: u64,
    /// Whether source maps are required for every compiled output.
    pub require_source_maps: bool,
    /// Whether binding traces are required.
    pub require_binding_traces: bool,
    /// Severity threshold: mismatches at or above this severity cause failure.
    pub severity_threshold: MismatchSeverity,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            required_workload_classes: WorkloadClass::ALL.iter().copied().collect(),
            max_size_divergence_millionths: DEFAULT_MAX_SIZE_DIVERGENCE,
            require_source_maps: true,
            require_binding_traces: false,
            severity_threshold: DEFAULT_SEVERITY_THRESHOLD,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Cryptographic receipt binding a matrix evaluation to its inputs and verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead reference.
    pub bead_id: String,
    /// Policy reference.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Hash of the evaluation inputs.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
}

impl DecisionReceipt {
    /// Compute a new receipt.
    pub fn compute(
        epoch: &SecurityEpoch,
        input_hash: ContentHash,
        verdict: CellVerdict,
        timestamp_micros: u64,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(COMPONENT.as_bytes());
        h.update(verdict.as_str().as_bytes());
        h.update(input_hash.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(timestamp_micros.to_le_bytes());
        let verdict_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            epoch: *epoch,
            input_hash,
            verdict_hash,
            timestamp_micros,
        }
    }
}

// ---------------------------------------------------------------------------
// MatrixReport
// ---------------------------------------------------------------------------

/// Report from a shipped-path matrix evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixReport {
    /// Per-workload-class cells.
    pub cells: Vec<MatrixCell>,
    /// Overall verdict.
    pub overall_verdict: CellVerdict,
    /// Total mismatch count across all cells.
    pub total_mismatches: usize,
    /// Critical mismatch count.
    pub critical_count: usize,
    /// Major mismatch count.
    pub major_count: usize,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// MatrixError
// ---------------------------------------------------------------------------

/// Errors produced by matrix evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum MatrixError {
    /// No cells provided.
    #[error("no cells provided for matrix evaluation")]
    NoCells,
    /// Required workload class missing from cells.
    #[error("required workload class missing: {class}")]
    MissingWorkloadClass { class: WorkloadClass },
    /// Duplicate workload class in cells.
    #[error("duplicate workload class: {class}")]
    DuplicateWorkloadClass { class: WorkloadClass },
    /// Invalid configuration.
    #[error("invalid configuration: {detail}")]
    InvalidConfig { detail: String },
}

// ---------------------------------------------------------------------------
// classify_mismatch
// ---------------------------------------------------------------------------

/// Classify the severity of a mismatch based on artifact kind and surface.
///
/// Higher-weight artifact kinds produce more severe classifications.
/// Missing compiled output or module graphs are always critical.
pub fn classify_mismatch(kind: &ArtifactKind, _surface: Surface, detail: &str) -> MismatchSeverity {
    let weight = kind.semantic_weight();
    if detail.contains("missing") || detail.contains("absent") {
        // Missing artifacts are critical for high-weight kinds.
        if weight >= 8 {
            return MismatchSeverity::Critical;
        }
        return MismatchSeverity::Major;
    }
    if weight >= 8 {
        MismatchSeverity::Critical
    } else if weight >= 6 {
        MismatchSeverity::Major
    } else if weight >= 4 {
        MismatchSeverity::Minor
    } else {
        MismatchSeverity::Informational
    }
}

// ---------------------------------------------------------------------------
// compare_artifacts
// ---------------------------------------------------------------------------

/// Compare artifact lists from two surfaces and produce classified mismatches.
///
/// Artifacts are matched by (kind, workload_class). Unmatched artifacts produce
/// Missing/Extra classifications. Matched artifacts are compared for content
/// and size divergence.
pub fn compare_artifacts(
    a: &[CapturedArtifact],
    b: &[CapturedArtifact],
    config: &MatrixConfig,
) -> Vec<ClassifiedMismatch> {
    let mut mismatches = Vec::new();

    // Index artifacts by kind for matching.
    let a_by_kind: Vec<(ArtifactKind, &CapturedArtifact)> =
        a.iter().map(|art| (art.kind, art)).collect();
    let b_by_kind: Vec<(ArtifactKind, &CapturedArtifact)> =
        b.iter().map(|art| (art.kind, art)).collect();

    let a_kinds: BTreeSet<ArtifactKind> = a_by_kind.iter().map(|(k, _)| *k).collect();
    let b_kinds: BTreeSet<ArtifactKind> = b_by_kind.iter().map(|(k, _)| *k).collect();

    // Check for required artifacts.
    if config.require_source_maps {
        let wc = a
            .first()
            .map(|art| art.workload_class)
            .or_else(|| b.first().map(|art| art.workload_class));

        if let Some(wc) = wc {
            // If compiled output exists on a surface but source map does not, flag it.
            if a_kinds.contains(&ArtifactKind::CompiledOutput)
                && !a_kinds.contains(&ArtifactKind::SourceMap)
            {
                mismatches.push(ClassifiedMismatch {
                    class: MismatchClass::Missing,
                    severity: MismatchSeverity::Major,
                    surface: Surface::Library,
                    artifact_kind: ArtifactKind::SourceMap,
                    workload_class: wc,
                    detail: "source map missing from library surface".to_string(),
                    content_hash_a: None,
                    content_hash_b: None,
                });
            }
            if b_kinds.contains(&ArtifactKind::CompiledOutput)
                && !b_kinds.contains(&ArtifactKind::SourceMap)
            {
                mismatches.push(ClassifiedMismatch {
                    class: MismatchClass::Missing,
                    severity: MismatchSeverity::Major,
                    surface: Surface::Cli,
                    artifact_kind: ArtifactKind::SourceMap,
                    workload_class: wc,
                    detail: "source map missing from CLI surface".to_string(),
                    content_hash_a: None,
                    content_hash_b: None,
                });
            }
        }
    }

    if config.require_binding_traces {
        let wc = a
            .first()
            .map(|art| art.workload_class)
            .or_else(|| b.first().map(|art| art.workload_class));

        if let Some(wc) = wc {
            if !a_kinds.contains(&ArtifactKind::BindingTrace) {
                mismatches.push(ClassifiedMismatch {
                    class: MismatchClass::Missing,
                    severity: MismatchSeverity::Major,
                    surface: Surface::Library,
                    artifact_kind: ArtifactKind::BindingTrace,
                    workload_class: wc,
                    detail: "binding trace missing from library surface".to_string(),
                    content_hash_a: None,
                    content_hash_b: None,
                });
            }
            if !b_kinds.contains(&ArtifactKind::BindingTrace) {
                mismatches.push(ClassifiedMismatch {
                    class: MismatchClass::Missing,
                    severity: MismatchSeverity::Major,
                    surface: Surface::Cli,
                    artifact_kind: ArtifactKind::BindingTrace,
                    workload_class: wc,
                    detail: "binding trace missing from CLI surface".to_string(),
                    content_hash_a: None,
                    content_hash_b: None,
                });
            }
        }
    }

    // Missing from B (present in A only).
    for kind in a_kinds.difference(&b_kinds) {
        for (_, art) in a_by_kind.iter().filter(|(k, _)| k == kind) {
            let severity = classify_mismatch(kind, Surface::Cli, "missing from CLI");
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::Missing,
                severity,
                surface: Surface::Cli,
                artifact_kind: *kind,
                workload_class: art.workload_class,
                detail: format!("{kind} missing from CLI surface"),
                content_hash_a: Some(art.content_hash),
                content_hash_b: None,
            });
        }
    }

    // Extra on B (present in B only).
    for kind in b_kinds.difference(&a_kinds) {
        for (_, art) in b_by_kind.iter().filter(|(k, _)| k == kind) {
            let severity = classify_mismatch(kind, Surface::Cli, "extra on CLI");
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::Extra,
                severity,
                surface: Surface::Cli,
                artifact_kind: *kind,
                workload_class: art.workload_class,
                detail: format!("{kind} extra on CLI surface"),
                content_hash_a: None,
                content_hash_b: Some(art.content_hash),
            });
        }
    }

    // Compare matched kinds.
    for kind in a_kinds.intersection(&b_kinds) {
        let arts_a: Vec<&CapturedArtifact> = a_by_kind
            .iter()
            .filter(|(k, _)| k == kind)
            .map(|(_, a)| *a)
            .collect();
        let arts_b: Vec<&CapturedArtifact> = b_by_kind
            .iter()
            .filter(|(k, _)| k == kind)
            .map(|(_, a)| *a)
            .collect();

        // Compare pairwise (first-to-first for simplicity; real systems would
        // align more carefully).
        let pairs = arts_a.len().min(arts_b.len());
        for i in 0..pairs {
            let aa = arts_a[i];
            let bb = arts_b[i];

            // Content divergence check.
            if aa.content_hash != bb.content_hash {
                let severity = classify_mismatch(kind, Surface::Cli, "content divergence");
                mismatches.push(ClassifiedMismatch {
                    class: MismatchClass::ContentDivergence,
                    severity,
                    surface: Surface::Cli,
                    artifact_kind: *kind,
                    workload_class: aa.workload_class,
                    detail: format!("{kind} content divergence between surfaces"),
                    content_hash_a: Some(aa.content_hash),
                    content_hash_b: Some(bb.content_hash),
                });
            }

            // Size divergence check.
            let max_size = aa.size_bytes.max(bb.size_bytes);
            if max_size > 0 {
                let diff = aa.size_bytes.abs_diff(bb.size_bytes);
                let divergence_millionths = diff
                    .saturating_mul(1_000_000)
                    .checked_div(max_size)
                    .unwrap_or(0);
                if divergence_millionths > config.max_size_divergence_millionths {
                    mismatches.push(ClassifiedMismatch {
                        class: MismatchClass::SizeDivergence,
                        severity: if divergence_millionths > 500_000 {
                            MismatchSeverity::Major
                        } else {
                            MismatchSeverity::Minor
                        },
                        surface: if aa.size_bytes > bb.size_bytes {
                            Surface::Library
                        } else {
                            Surface::Cli
                        },
                        artifact_kind: *kind,
                        workload_class: aa.workload_class,
                        detail: format!(
                            "{kind} size divergence: {} vs {} bytes ({divergence_millionths} millionths)",
                            aa.size_bytes, bb.size_bytes
                        ),
                        content_hash_a: Some(aa.content_hash),
                        content_hash_b: Some(bb.content_hash),
                    });
                }
            }
        }

        // Order divergence: if counts differ for same kind.
        if arts_a.len() != arts_b.len() {
            let wc = arts_a
                .first()
                .map(|a| a.workload_class)
                .unwrap_or(WorkloadClass::PureJs);
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::OrderDivergence,
                severity: MismatchSeverity::Minor,
                surface: if arts_a.len() > arts_b.len() {
                    Surface::Library
                } else {
                    Surface::Cli
                },
                artifact_kind: *kind,
                workload_class: wc,
                detail: format!(
                    "{kind} count mismatch: {} vs {}",
                    arts_a.len(),
                    arts_b.len()
                ),
                content_hash_a: None,
                content_hash_b: None,
            });
        }
    }

    mismatches
}

// ---------------------------------------------------------------------------
// compute_cell_verdict
// ---------------------------------------------------------------------------

/// Compute the verdict for a cell based on its mismatches and config threshold.
///
/// A cell fails if any mismatch has severity at or above the configured
/// threshold. A cell with no mismatches passes. A cell with no artifacts on
/// either side is inconclusive.
pub fn compute_cell_verdict(
    mismatches: &[ClassifiedMismatch],
    config: &MatrixConfig,
) -> CellVerdict {
    for m in mismatches {
        if m.severity.rank() >= config.severity_threshold.rank() {
            return CellVerdict::Fail;
        }
    }
    if mismatches.is_empty() {
        CellVerdict::Pass
    } else {
        // Has mismatches but all below threshold.
        CellVerdict::Pass
    }
}

// ---------------------------------------------------------------------------
// evaluate_matrix
// ---------------------------------------------------------------------------

/// Evaluate a shipped-path matrix and produce a report with a decision receipt.
///
/// # Errors
///
/// Returns `MatrixError` if:
/// - No cells are provided.
/// - A required workload class is missing.
/// - Duplicate workload classes are found.
pub fn evaluate_matrix(
    cells: &[MatrixCell],
    config: &MatrixConfig,
    epoch: &SecurityEpoch,
    ts: u64,
) -> Result<MatrixReport, MatrixError> {
    if cells.is_empty() {
        return Err(MatrixError::NoCells);
    }

    // Check for duplicates.
    let mut seen = BTreeSet::new();
    for cell in cells {
        if !seen.insert(cell.workload_class) {
            return Err(MatrixError::DuplicateWorkloadClass {
                class: cell.workload_class,
            });
        }
    }

    // Check required classes.
    for required in &config.required_workload_classes {
        if !seen.contains(required) {
            return Err(MatrixError::MissingWorkloadClass { class: *required });
        }
    }

    // Aggregate.
    let mut total_mismatches = 0usize;
    let mut critical_count = 0usize;
    let mut major_count = 0usize;
    let mut any_fail = false;
    let mut any_inconclusive = false;

    for cell in cells {
        total_mismatches += cell.mismatches.len();
        critical_count += cell.critical_count();
        major_count += cell.major_count();
        match cell.verdict {
            CellVerdict::Fail => any_fail = true,
            CellVerdict::Inconclusive => any_inconclusive = true,
            CellVerdict::Pass => {}
        }
    }

    let overall_verdict = if any_fail {
        CellVerdict::Fail
    } else if any_inconclusive {
        CellVerdict::Inconclusive
    } else {
        CellVerdict::Pass
    };

    // Compute input hash including mismatch details for content addressability.
    let mut ih = Sha256::new();
    for cell in cells {
        ih.update(cell.workload_class.as_str().as_bytes());
        ih.update((cell.artifacts_a.len() as u64).to_le_bytes());
        ih.update((cell.artifacts_b.len() as u64).to_le_bytes());
        ih.update((cell.mismatches.len() as u64).to_le_bytes());
        for m in &cell.mismatches {
            ih.update(m.class.as_str().as_bytes());
            ih.update(m.severity.as_str().as_bytes());
            ih.update(m.surface.to_string().as_bytes());
        }
        ih.update(cell.verdict.as_str().as_bytes());
    }
    let input_hash = ContentHash::compute(&ih.finalize());

    let receipt = DecisionReceipt::compute(epoch, input_hash, overall_verdict, ts);

    Ok(MatrixReport {
        cells: cells.to_vec(),
        overall_verdict,
        total_mismatches,
        critical_count,
        major_count,
        receipt,
    })
}

// ---------------------------------------------------------------------------
// build_cell — convenience builder
// ---------------------------------------------------------------------------

/// Build a matrix cell by comparing artifacts from two surfaces.
///
/// This is a convenience function that runs `compare_artifacts` and
/// `compute_cell_verdict` for a single workload class.
pub fn build_cell(
    workload_class: WorkloadClass,
    artifacts_a: Vec<CapturedArtifact>,
    artifacts_b: Vec<CapturedArtifact>,
    config: &MatrixConfig,
) -> MatrixCell {
    let mismatches = compare_artifacts(&artifacts_a, &artifacts_b, config);
    let verdict = compute_cell_verdict(&mismatches, config);
    MatrixCell {
        workload_class,
        artifacts_a,
        artifacts_b,
        mismatches,
        verdict,
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn art(
        kind: ArtifactKind,
        surface: Surface,
        payload: &[u8],
        wc: WorkloadClass,
    ) -> CapturedArtifact {
        CapturedArtifact::new(kind, surface, payload, wc)
    }

    fn default_config() -> MatrixConfig {
        MatrixConfig::default()
    }

    fn relaxed_config() -> MatrixConfig {
        MatrixConfig {
            required_workload_classes: BTreeSet::new(),
            max_size_divergence_millionths: 1_000_000,
            require_source_maps: false,
            require_binding_traces: false,
            severity_threshold: MismatchSeverity::Critical,
        }
    }

    fn passing_cell(wc: WorkloadClass) -> MatrixCell {
        MatrixCell::new(wc, vec![], vec![], vec![], CellVerdict::Pass)
    }

    fn failing_cell(wc: WorkloadClass) -> MatrixCell {
        let mm = vec![ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Critical,
            surface: Surface::Cli,
            artifact_kind: ArtifactKind::CompiledOutput,
            workload_class: wc,
            detail: "test failure".to_string(),
            content_hash_a: Some(ContentHash::compute(b"a")),
            content_hash_b: Some(ContentHash::compute(b"b")),
        }];
        MatrixCell::new(wc, vec![], vec![], mm, CellVerdict::Fail)
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.shipped-path-matrix.v1");
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "shipped_path_matrix");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.9.6.2");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-806B");
    }

    #[test]
    fn test_default_max_size_divergence() {
        assert_eq!(DEFAULT_MAX_SIZE_DIVERGENCE, 100_000);
    }

    // -----------------------------------------------------------------------
    // WorkloadClass
    // -----------------------------------------------------------------------

    #[test]
    fn test_workload_class_all_count() {
        assert_eq!(WorkloadClass::ALL.len(), 6);
    }

    #[test]
    fn test_workload_class_as_str_roundtrip() {
        for wc in WorkloadClass::ALL {
            let s = wc.as_str();
            assert!(!s.is_empty());
            assert_eq!(format!("{wc}"), s);
        }
    }

    #[test]
    fn test_workload_class_ordering() {
        assert!(WorkloadClass::PureJs < WorkloadClass::PureTs);
        assert!(WorkloadClass::PureTs < WorkloadClass::MixedJsTs);
    }

    #[test]
    fn test_workload_class_serde_roundtrip() {
        for wc in WorkloadClass::ALL {
            let json = serde_json::to_string(wc).unwrap();
            let back: WorkloadClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*wc, back);
        }
    }

    // -----------------------------------------------------------------------
    // Surface
    // -----------------------------------------------------------------------

    #[test]
    fn test_surface_all_count() {
        assert_eq!(Surface::ALL.len(), 2);
    }

    #[test]
    fn test_surface_as_str() {
        assert_eq!(Surface::Library.as_str(), "library");
        assert_eq!(Surface::Cli.as_str(), "cli");
    }

    #[test]
    fn test_surface_display() {
        assert_eq!(format!("{}", Surface::Library), "library");
        assert_eq!(format!("{}", Surface::Cli), "cli");
    }

    #[test]
    fn test_surface_serde() {
        let json = serde_json::to_string(&Surface::Cli).unwrap();
        assert_eq!(json, "\"cli\"");
        let back: Surface = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Surface::Cli);
    }

    // -----------------------------------------------------------------------
    // ArtifactKind
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_kind_all_count() {
        assert_eq!(ArtifactKind::ALL.len(), 6);
    }

    #[test]
    fn test_artifact_kind_as_str() {
        assert_eq!(ArtifactKind::CompiledOutput.as_str(), "compiled_output");
        assert_eq!(ArtifactKind::SourceMap.as_str(), "source_map");
        assert_eq!(ArtifactKind::BindingTrace.as_str(), "binding_trace");
    }

    #[test]
    fn test_artifact_kind_semantic_weight() {
        assert!(
            ArtifactKind::CompiledOutput.semantic_weight()
                > ArtifactKind::Diagnostic.semantic_weight()
        );
        assert!(
            ArtifactKind::ModuleGraph.semantic_weight() > ArtifactKind::SourceMap.semantic_weight()
        );
    }

    #[test]
    fn test_artifact_kind_serde_roundtrip() {
        for k in ArtifactKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ArtifactKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn test_artifact_kind_display() {
        for k in ArtifactKind::ALL {
            assert_eq!(format!("{k}"), k.as_str());
        }
    }

    // -----------------------------------------------------------------------
    // CapturedArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn test_captured_artifact_new() {
        let a = CapturedArtifact::new(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"hello world",
            WorkloadClass::PureJs,
        );
        assert_eq!(a.kind, ArtifactKind::CompiledOutput);
        assert_eq!(a.surface, Surface::Library);
        assert_eq!(a.size_bytes, 11);
        assert_eq!(a.workload_class, WorkloadClass::PureJs);
    }

    #[test]
    fn test_captured_artifact_hash_determinism() {
        let a = CapturedArtifact::new(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"data",
            WorkloadClass::Esm,
        );
        let b = CapturedArtifact::new(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"data",
            WorkloadClass::Esm,
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn test_captured_artifact_different_payload() {
        let a = CapturedArtifact::new(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"alpha",
            WorkloadClass::Esm,
        );
        let b = CapturedArtifact::new(
            ArtifactKind::SourceMap,
            Surface::Cli,
            b"beta",
            WorkloadClass::Esm,
        );
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn test_captured_artifact_serde() {
        let a = CapturedArtifact::new(
            ArtifactKind::Diagnostic,
            Surface::Library,
            b"msg",
            WorkloadClass::Cjs,
        );
        let json = serde_json::to_string(&a).unwrap();
        let back: CapturedArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // -----------------------------------------------------------------------
    // MismatchClass
    // -----------------------------------------------------------------------

    #[test]
    fn test_mismatch_class_all_count() {
        assert_eq!(MismatchClass::ALL.len(), 6);
    }

    #[test]
    fn test_mismatch_class_as_str() {
        assert_eq!(MismatchClass::Missing.as_str(), "missing");
        assert_eq!(
            MismatchClass::ContentDivergence.as_str(),
            "content_divergence"
        );
    }

    #[test]
    fn test_mismatch_class_serde_roundtrip() {
        for mc in MismatchClass::ALL {
            let json = serde_json::to_string(mc).unwrap();
            let back: MismatchClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*mc, back);
        }
    }

    #[test]
    fn test_mismatch_class_display() {
        for mc in MismatchClass::ALL {
            assert_eq!(format!("{mc}"), mc.as_str());
        }
    }

    // -----------------------------------------------------------------------
    // MismatchSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_all_count() {
        assert_eq!(MismatchSeverity::ALL.len(), 4);
    }

    #[test]
    fn test_severity_rank_ordering() {
        assert!(MismatchSeverity::Informational.rank() < MismatchSeverity::Minor.rank());
        assert!(MismatchSeverity::Minor.rank() < MismatchSeverity::Major.rank());
        assert!(MismatchSeverity::Major.rank() < MismatchSeverity::Critical.rank());
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        for s in MismatchSeverity::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: MismatchSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", MismatchSeverity::Critical), "critical");
    }

    // -----------------------------------------------------------------------
    // CellVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_cell_verdict_all_count() {
        assert_eq!(CellVerdict::ALL.len(), 3);
    }

    #[test]
    fn test_cell_verdict_as_str() {
        assert_eq!(CellVerdict::Pass.as_str(), "pass");
        assert_eq!(CellVerdict::Fail.as_str(), "fail");
        assert_eq!(CellVerdict::Inconclusive.as_str(), "inconclusive");
    }

    #[test]
    fn test_cell_verdict_display() {
        for v in CellVerdict::ALL {
            assert_eq!(format!("{v}"), v.as_str());
        }
    }

    #[test]
    fn test_cell_verdict_serde() {
        let json = serde_json::to_string(&CellVerdict::Fail).unwrap();
        let back: CellVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CellVerdict::Fail);
    }

    // -----------------------------------------------------------------------
    // classify_mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_compiled_output_critical() {
        let sev = classify_mismatch(
            &ArtifactKind::CompiledOutput,
            Surface::Library,
            "divergence",
        );
        assert_eq!(sev, MismatchSeverity::Critical);
    }

    #[test]
    fn test_classify_module_graph_critical() {
        let sev = classify_mismatch(&ArtifactKind::ModuleGraph, Surface::Cli, "divergence");
        assert_eq!(sev, MismatchSeverity::Critical);
    }

    #[test]
    fn test_classify_source_map_minor() {
        let sev = classify_mismatch(&ArtifactKind::SourceMap, Surface::Library, "divergence");
        assert_eq!(sev, MismatchSeverity::Minor);
    }

    #[test]
    fn test_classify_diagnostic_informational() {
        let sev = classify_mismatch(&ArtifactKind::Diagnostic, Surface::Cli, "divergence");
        assert_eq!(sev, MismatchSeverity::Informational);
    }

    #[test]
    fn test_classify_missing_high_weight_critical() {
        let sev = classify_mismatch(&ArtifactKind::ModuleGraph, Surface::Cli, "missing from CLI");
        assert_eq!(sev, MismatchSeverity::Critical);
    }

    #[test]
    fn test_classify_missing_low_weight_major() {
        let sev = classify_mismatch(&ArtifactKind::SourceMap, Surface::Library, "missing");
        assert_eq!(sev, MismatchSeverity::Major);
    }

    #[test]
    fn test_classify_type_annotation_major() {
        let sev = classify_mismatch(
            &ArtifactKind::TypeAnnotation,
            Surface::Library,
            "divergence",
        );
        assert_eq!(sev, MismatchSeverity::Major);
    }

    #[test]
    fn test_classify_binding_trace_major() {
        let sev = classify_mismatch(&ArtifactKind::BindingTrace, Surface::Cli, "content");
        assert_eq!(sev, MismatchSeverity::Major);
    }

    // -----------------------------------------------------------------------
    // compare_artifacts
    // -----------------------------------------------------------------------

    #[test]
    fn test_compare_identical_artifacts_no_mismatches() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::PureJs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::PureJs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(mm.is_empty(), "expected no mismatches, got {mm:?}");
    }

    #[test]
    fn test_compare_content_divergence() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code_a",
            WorkloadClass::PureJs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code_b",
            WorkloadClass::PureJs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(
            mm.iter()
                .any(|m| m.class == MismatchClass::ContentDivergence)
        );
    }

    #[test]
    fn test_compare_missing_artifact() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::ModuleGraph,
            Surface::Library,
            b"graph",
            WorkloadClass::Esm,
        )];
        let b = vec![];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(mm.iter().any(|m| m.class == MismatchClass::Missing));
    }

    #[test]
    fn test_compare_extra_artifact() {
        let cfg = relaxed_config();
        let a = vec![];
        let b = vec![art(
            ArtifactKind::Diagnostic,
            Surface::Cli,
            b"diag",
            WorkloadClass::Cjs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(mm.iter().any(|m| m.class == MismatchClass::Extra));
    }

    #[test]
    fn test_compare_size_divergence() {
        let cfg = MatrixConfig {
            max_size_divergence_millionths: 50_000, // 5%
            require_source_maps: false,
            require_binding_traces: false,
            ..default_config()
        };
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            &[0u8; 100],
            WorkloadClass::PureTs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            &[0u8; 200],
            WorkloadClass::PureTs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(mm.iter().any(|m| m.class == MismatchClass::SizeDivergence));
    }

    #[test]
    fn test_compare_required_source_maps_flagged() {
        let cfg = MatrixConfig {
            require_source_maps: true,
            require_binding_traces: false,
            ..relaxed_config()
        };
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::PureJs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::PureJs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        // Both surfaces missing source maps.
        let sm_missing: Vec<_> = mm
            .iter()
            .filter(|m| m.artifact_kind == ArtifactKind::SourceMap)
            .collect();
        assert_eq!(sm_missing.len(), 2);
    }

    // -----------------------------------------------------------------------
    // compute_cell_verdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_verdict_pass_no_mismatches() {
        let cfg = default_config();
        let v = compute_cell_verdict(&[], &cfg);
        assert_eq!(v, CellVerdict::Pass);
    }

    #[test]
    fn test_verdict_fail_critical() {
        let cfg = default_config();
        let mm = vec![ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Critical,
            surface: Surface::Cli,
            artifact_kind: ArtifactKind::CompiledOutput,
            workload_class: WorkloadClass::PureJs,
            detail: "test".to_string(),
            content_hash_a: None,
            content_hash_b: None,
        }];
        let v = compute_cell_verdict(&mm, &cfg);
        assert_eq!(v, CellVerdict::Fail);
    }

    #[test]
    fn test_verdict_pass_below_threshold() {
        let cfg = MatrixConfig {
            severity_threshold: MismatchSeverity::Critical,
            ..default_config()
        };
        let mm = vec![ClassifiedMismatch {
            class: MismatchClass::SemanticDivergence,
            severity: MismatchSeverity::Minor,
            surface: Surface::Library,
            artifact_kind: ArtifactKind::Diagnostic,
            workload_class: WorkloadClass::MixedJsTs,
            detail: "minor".to_string(),
            content_hash_a: None,
            content_hash_b: None,
        }];
        let v = compute_cell_verdict(&mm, &cfg);
        assert_eq!(v, CellVerdict::Pass);
    }

    #[test]
    fn test_verdict_fail_major_at_major_threshold() {
        let cfg = MatrixConfig {
            severity_threshold: MismatchSeverity::Major,
            ..default_config()
        };
        let mm = vec![ClassifiedMismatch {
            class: MismatchClass::Missing,
            severity: MismatchSeverity::Major,
            surface: Surface::Cli,
            artifact_kind: ArtifactKind::SourceMap,
            workload_class: WorkloadClass::Esm,
            detail: "missing".to_string(),
            content_hash_a: None,
            content_hash_b: None,
        }];
        let v = compute_cell_verdict(&mm, &cfg);
        assert_eq!(v, CellVerdict::Fail);
    }

    // -----------------------------------------------------------------------
    // MatrixCell
    // -----------------------------------------------------------------------

    #[test]
    fn test_matrix_cell_critical_count() {
        let cell = failing_cell(WorkloadClass::PureJs);
        assert_eq!(cell.critical_count(), 1);
        assert_eq!(cell.major_count(), 0);
    }

    #[test]
    fn test_matrix_cell_passing() {
        let cell = passing_cell(WorkloadClass::PureTs);
        assert_eq!(cell.verdict, CellVerdict::Pass);
        assert_eq!(cell.mismatches.len(), 0);
    }

    // -----------------------------------------------------------------------
    // MatrixConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let cfg = MatrixConfig::default();
        assert_eq!(cfg.required_workload_classes.len(), 6);
        assert!(cfg.require_source_maps);
        assert!(!cfg.require_binding_traces);
        assert_eq!(cfg.severity_threshold, MismatchSeverity::Major);
        assert_eq!(
            cfg.max_size_divergence_millionths,
            DEFAULT_MAX_SIZE_DIVERGENCE
        );
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = MatrixConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: MatrixConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -----------------------------------------------------------------------
    // DecisionReceipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_determinism() {
        let e = epoch();
        let ih = ContentHash::compute(b"input");
        let r1 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1_000_000);
        let r2 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1_000_000);
        assert_eq!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn test_receipt_different_verdict_different_hash() {
        let e = epoch();
        let ih = ContentHash::compute(b"input");
        let r1 = DecisionReceipt::compute(&e, ih, CellVerdict::Pass, 1_000_000);
        let r2 = DecisionReceipt::compute(&e, ih, CellVerdict::Fail, 1_000_000);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn test_receipt_different_epoch_different_hash() {
        let ih = ContentHash::compute(b"input");
        let r1 = DecisionReceipt::compute(&SecurityEpoch::from_raw(1), ih, CellVerdict::Pass, 100);
        let r2 = DecisionReceipt::compute(&SecurityEpoch::from_raw(2), ih, CellVerdict::Pass, 100);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn test_receipt_fields() {
        let r =
            DecisionReceipt::compute(&epoch(), ContentHash::compute(b"x"), CellVerdict::Pass, 42);
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.bead_id, BEAD_ID);
        assert_eq!(r.policy_id, POLICY_ID);
        assert_eq!(r.timestamp_micros, 42);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let r =
            DecisionReceipt::compute(&epoch(), ContentHash::compute(b"x"), CellVerdict::Fail, 999);
        let json = serde_json::to_string(&r).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -----------------------------------------------------------------------
    // evaluate_matrix
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_no_cells_error() {
        let cfg = relaxed_config();
        let err = evaluate_matrix(&[], &cfg, &epoch(), 0).unwrap_err();
        assert!(matches!(err, MatrixError::NoCells));
    }

    #[test]
    fn test_evaluate_duplicate_class_error() {
        let cfg = relaxed_config();
        let cells = vec![
            passing_cell(WorkloadClass::PureJs),
            passing_cell(WorkloadClass::PureJs),
        ];
        let err = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap_err();
        assert!(matches!(err, MatrixError::DuplicateWorkloadClass { .. }));
    }

    #[test]
    fn test_evaluate_missing_required_class_error() {
        let cfg = default_config(); // requires all 6
        let cells = vec![passing_cell(WorkloadClass::PureJs)];
        let err = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap_err();
        assert!(matches!(err, MatrixError::MissingWorkloadClass { .. }));
    }

    #[test]
    fn test_evaluate_all_pass() {
        let cfg = relaxed_config();
        let cells: Vec<MatrixCell> = WorkloadClass::ALL
            .iter()
            .map(|wc| passing_cell(*wc))
            .collect();
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 1000).unwrap();
        assert_eq!(report.overall_verdict, CellVerdict::Pass);
        assert_eq!(report.total_mismatches, 0);
        assert_eq!(report.critical_count, 0);
        assert_eq!(report.major_count, 0);
    }

    #[test]
    fn test_evaluate_one_fail_overall_fail() {
        let cfg = relaxed_config();
        let cells = vec![
            passing_cell(WorkloadClass::PureJs),
            failing_cell(WorkloadClass::PureTs),
        ];
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, CellVerdict::Fail);
        assert_eq!(report.critical_count, 1);
    }

    #[test]
    fn test_evaluate_inconclusive_propagates() {
        let cfg = relaxed_config();
        let cells = vec![
            passing_cell(WorkloadClass::PureJs),
            MatrixCell::new(
                WorkloadClass::Esm,
                vec![],
                vec![],
                vec![],
                CellVerdict::Inconclusive,
            ),
        ];
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, CellVerdict::Inconclusive);
    }

    #[test]
    fn test_evaluate_fail_beats_inconclusive() {
        let cfg = relaxed_config();
        let cells = vec![
            failing_cell(WorkloadClass::PureJs),
            MatrixCell::new(
                WorkloadClass::Esm,
                vec![],
                vec![],
                vec![],
                CellVerdict::Inconclusive,
            ),
        ];
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, CellVerdict::Fail);
    }

    #[test]
    fn test_evaluate_report_receipt_present() {
        let cfg = relaxed_config();
        let cells = vec![passing_cell(WorkloadClass::PureJs)];
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 42_000).unwrap();
        assert_eq!(report.receipt.timestamp_micros, 42_000);
        assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
    }

    // -----------------------------------------------------------------------
    // MatrixError
    // -----------------------------------------------------------------------

    #[test]
    fn test_matrix_error_display_no_cells() {
        let e = MatrixError::NoCells;
        assert_eq!(format!("{e}"), "no cells provided for matrix evaluation");
    }

    #[test]
    fn test_matrix_error_display_missing() {
        let e = MatrixError::MissingWorkloadClass {
            class: WorkloadClass::Esm,
        };
        let s = format!("{e}");
        assert!(s.contains("esm"));
    }

    #[test]
    fn test_matrix_error_display_duplicate() {
        let e = MatrixError::DuplicateWorkloadClass {
            class: WorkloadClass::Cjs,
        };
        let s = format!("{e}");
        assert!(s.contains("cjs"));
    }

    #[test]
    fn test_matrix_error_serde_roundtrip() {
        let e = MatrixError::NoCells;
        let json = serde_json::to_string(&e).unwrap();
        let back: MatrixError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -----------------------------------------------------------------------
    // build_cell
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cell_pass_identical() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"x",
            WorkloadClass::PureJs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"x",
            WorkloadClass::PureJs,
        )];
        let cell = build_cell(WorkloadClass::PureJs, a, b, &cfg);
        assert_eq!(cell.verdict, CellVerdict::Pass);
        assert!(cell.mismatches.is_empty());
    }

    #[test]
    fn test_build_cell_divergence_detected() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"alpha",
            WorkloadClass::PureTs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"beta",
            WorkloadClass::PureTs,
        )];
        let cell = build_cell(WorkloadClass::PureTs, a, b, &cfg);
        assert!(!cell.mismatches.is_empty());
    }

    // -----------------------------------------------------------------------
    // MatrixReport serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_report_serde_roundtrip() {
        let cfg = relaxed_config();
        let cells = vec![passing_cell(WorkloadClass::PureJs)];
        let report = evaluate_matrix(&cells, &cfg, &epoch(), 1).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: MatrixReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_artifact_lists_no_mismatches() {
        let cfg = relaxed_config();
        let mm = compare_artifacts(&[], &[], &cfg);
        assert!(mm.is_empty());
    }

    #[test]
    fn test_zero_size_artifacts() {
        let cfg = relaxed_config();
        let a = vec![art(
            ArtifactKind::Diagnostic,
            Surface::Library,
            b"",
            WorkloadClass::Cjs,
        )];
        let b = vec![art(
            ArtifactKind::Diagnostic,
            Surface::Cli,
            b"",
            WorkloadClass::Cjs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        assert!(mm.is_empty());
    }

    #[test]
    fn test_binding_trace_required_flagged() {
        let cfg = MatrixConfig {
            require_binding_traces: true,
            require_source_maps: false,
            ..relaxed_config()
        };
        let a = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            b"code",
            WorkloadClass::MixedEsmCjs,
        )];
        let b = vec![art(
            ArtifactKind::CompiledOutput,
            Surface::Cli,
            b"code",
            WorkloadClass::MixedEsmCjs,
        )];
        let mm = compare_artifacts(&a, &b, &cfg);
        let bt_missing: Vec<_> = mm
            .iter()
            .filter(|m| m.artifact_kind == ArtifactKind::BindingTrace)
            .collect();
        assert_eq!(bt_missing.len(), 2);
    }
}
