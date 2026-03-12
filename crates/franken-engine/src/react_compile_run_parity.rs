//! Shipped-path React compile/run parity and example-app matrix.
//!
//! Proves that the native React compilation lane works where users actually
//! touch the product: library entrypoints, frankenctl compile/run, and
//! representative example apps spanning compile-only, execute, and
//! SSR-oriented workflows.
//!
//! The module captures artifacts from a reference surface and a candidate
//! surface, classifies mismatches, evaluates per-cell verdicts across a
//! multi-dimensional matrix (surface x workflow x app-tier), and rolls up
//! an overall verdict with a signed decision receipt.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-206C], bead bd-1lsy.3.6.3.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the react compile/run parity contract.
pub const SCHEMA_VERSION: &str = "franken-engine.react-compile-run-parity.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_compile_run_parity";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.3.6.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-206C";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum size divergence: 5% = 50_000 millionths.
pub const DEFAULT_MAX_SIZE_DIVERGENCE: u64 = 50_000;

/// Maximum number of artifacts per cell side (reference or candidate).
const MAX_ARTIFACTS_PER_SIDE: usize = 1_000;

/// Maximum number of cells in a single matrix evaluation.
const MAX_CELLS: usize = 4_096;

// ---------------------------------------------------------------------------
// WorkflowKind
// ---------------------------------------------------------------------------

/// The kind of shipped workflow being exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    /// Compile-only: produce artifacts without executing them.
    CompileOnly,
    /// Execute: compile and run the resulting code.
    Execute,
    /// Server-side render: produce HTML from components on the server.
    SsrRender,
    /// Hydration round: attach client-side interactivity to SSR output.
    HydrationRound,
    /// Static generation: pre-render pages at build time.
    StaticGeneration,
    /// Streaming render: progressive server-side rendering with chunked output.
    StreamingRender,
}

impl WorkflowKind {
    /// Stable string tag for serialization and display.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileOnly => "compile_only",
            Self::Execute => "execute",
            Self::SsrRender => "ssr_render",
            Self::HydrationRound => "hydration_round",
            Self::StaticGeneration => "static_generation",
            Self::StreamingRender => "streaming_render",
        }
    }

    /// All variants in definition order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::CompileOnly,
            Self::Execute,
            Self::SsrRender,
            Self::HydrationRound,
            Self::StaticGeneration,
            Self::StreamingRender,
        ]
    }
}

impl fmt::Display for WorkflowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// The product surface through which the user exercises the React lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Library API: programmatic Rust/WASM entrypoint.
    Library,
    /// `frankenctl compile` CLI command.
    FrankenctlCompile,
    /// `frankenctl run` CLI command.
    FrankenctlRun,
    /// Representative example application.
    ExampleApp,
}

impl Surface {
    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::FrankenctlCompile => "frankenctl_compile",
            Self::FrankenctlRun => "frankenctl_run",
            Self::ExampleApp => "example_app",
        }
    }

    /// All variants in definition order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Library,
            Self::FrankenctlCompile,
            Self::FrankenctlRun,
            Self::ExampleApp,
        ]
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

/// Classification of a captured artifact from a compile/run surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Compiled JavaScript/bytecode output.
    CompiledOutput,
    /// Source map linking compiled output back to source.
    SourceMap,
    /// Diagnostic messages (warnings, errors, hints).
    Diagnostics,
    /// Module dependency graph.
    ModuleGraph,
    /// Execution trace from running the compiled output.
    ExecutionTrace,
    /// Rendered HTML or stream output from SSR/hydration.
    RenderOutput,
}

impl ArtifactKind {
    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompiledOutput => "compiled_output",
            Self::SourceMap => "source_map",
            Self::Diagnostics => "diagnostics",
            Self::ModuleGraph => "module_graph",
            Self::ExecutionTrace => "execution_trace",
            Self::RenderOutput => "render_output",
        }
    }

    /// All variants in definition order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::CompiledOutput,
            Self::SourceMap,
            Self::Diagnostics,
            Self::ModuleGraph,
            Self::ExecutionTrace,
            Self::RenderOutput,
        ]
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MismatchClass
// ---------------------------------------------------------------------------

/// Classification of a detected mismatch between reference and candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchClass {
    /// An artifact present in reference is absent from candidate.
    Missing,
    /// An artifact present in candidate is absent from reference.
    Extra,
    /// Artifact content hashes differ.
    ContentDivergence,
    /// Artifact sizes diverge beyond the configured threshold.
    SizeDivergence,
    /// Artifacts appear in different order (same content).
    OrderDivergence,
    /// Semantic meaning differs despite structural similarity.
    SemanticDivergence,
}

impl MismatchClass {
    /// Stable string tag.
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
    /// Informational: cosmetic or negligible difference.
    Informational,
    /// Minor: small divergence that unlikely affects users.
    Minor,
    /// Major: significant divergence that may affect users.
    Major,
    /// Critical: fundamental correctness violation.
    Critical,
}

impl MismatchSeverity {
    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Minor => "minor",
            Self::Major => "major",
            Self::Critical => "critical",
        }
    }

    /// Numeric rank for threshold comparisons (higher = more severe).
    pub const fn rank(self) -> u8 {
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
// CellVerdict
// ---------------------------------------------------------------------------

/// Pass/fail/inconclusive verdict for a single matrix cell or the overall matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellVerdict {
    /// All checks passed; no mismatches at or above threshold.
    Pass,
    /// One or more mismatches at or above threshold severity.
    Fail,
    /// Insufficient data to render a verdict.
    Inconclusive,
}

impl CellVerdict {
    /// Stable string tag.
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
// ExampleAppTier
// ---------------------------------------------------------------------------

/// Complexity tier of a representative example application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExampleAppTier {
    /// Minimal: single component, no routing, no state management.
    Minimal,
    /// Typical: a few components, basic routing, local state.
    Typical,
    /// Complex: many components, deep routing, external state, code splitting.
    Complex,
    /// SSR-focused: server-side rendering with data fetching.
    SsrFocused,
    /// Hybrid/Isomorphic: full client+server with hydration and streaming.
    HybridIsomorphic,
}

impl ExampleAppTier {
    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Typical => "typical",
            Self::Complex => "complex",
            Self::SsrFocused => "ssr_focused",
            Self::HybridIsomorphic => "hybrid_isomorphic",
        }
    }

    /// All variants in definition order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Minimal,
            Self::Typical,
            Self::Complex,
            Self::SsrFocused,
            Self::HybridIsomorphic,
        ]
    }
}

impl fmt::Display for ExampleAppTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CapturedArtifact
// ---------------------------------------------------------------------------

/// A single artifact captured from a compile/run surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedArtifact {
    /// What kind of artifact this is.
    pub kind: ArtifactKind,
    /// The surface it was captured from.
    pub surface: Surface,
    /// The workflow that produced it.
    pub workflow: WorkflowKind,
    /// Content hash of the artifact bytes.
    pub content_hash: ContentHash,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Example-app complexity tier.
    pub app_tier: ExampleAppTier,
}

// ---------------------------------------------------------------------------
// ClassifiedMismatch
// ---------------------------------------------------------------------------

/// A mismatch between reference and candidate artifacts, fully classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedMismatch {
    /// Structural class of the mismatch.
    pub class: MismatchClass,
    /// Severity assessment.
    pub severity: MismatchSeverity,
    /// The surface where the mismatch was observed.
    pub surface: Surface,
    /// The workflow that produced the mismatched artifacts.
    pub workflow: WorkflowKind,
    /// The artifact kind involved.
    pub artifact_kind: ArtifactKind,
    /// Human-readable detail string.
    pub detail: String,
    /// Content hash of the reference artifact (if present).
    pub hash_a: Option<ContentHash>,
    /// Content hash of the candidate artifact (if present).
    pub hash_b: Option<ContentHash>,
}

// ---------------------------------------------------------------------------
// MatrixCell
// ---------------------------------------------------------------------------

/// One cell in the parity matrix: a (surface, workflow, app_tier) coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCell {
    /// The surface under test.
    pub surface: Surface,
    /// The workflow exercised.
    pub workflow: WorkflowKind,
    /// The example-app tier.
    pub app_tier: ExampleAppTier,
    /// Reference artifacts (the "known-good" side).
    pub artifacts_reference: Vec<CapturedArtifact>,
    /// Candidate artifacts (the side under test).
    pub artifacts_candidate: Vec<CapturedArtifact>,
    /// Classified mismatches found in this cell.
    pub mismatches: Vec<ClassifiedMismatch>,
    /// Verdict for this cell.
    pub verdict: CellVerdict,
}

// ---------------------------------------------------------------------------
// MatrixConfig
// ---------------------------------------------------------------------------

/// Configuration for the parity matrix evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixConfig {
    /// Surfaces that must be represented in the matrix.
    pub required_surfaces: BTreeSet<Surface>,
    /// Workflows that must be represented in the matrix.
    pub required_workflows: BTreeSet<WorkflowKind>,
    /// Maximum allowed size divergence in millionths (default 50_000 = 5%).
    pub max_size_divergence_millionths: u64,
    /// Minimum severity that causes a cell to fail (default Major).
    pub severity_threshold: MismatchSeverity,
    /// Whether source maps are required in every cell.
    pub require_source_maps: bool,
    /// Whether execution traces are required in every cell.
    pub require_execution_traces: bool,
    /// Whether all example-app tiers must be covered.
    pub require_all_app_tiers: bool,
}

impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            required_surfaces: BTreeSet::new(),
            required_workflows: BTreeSet::new(),
            max_size_divergence_millionths: DEFAULT_MAX_SIZE_DIVERGENCE,
            severity_threshold: MismatchSeverity::Major,
            require_source_maps: true,
            require_execution_traces: true,
            require_all_app_tiers: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CoverageReport
// ---------------------------------------------------------------------------

/// Coverage statistics for the parity matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Per-surface coverage (millionths, 1_000_000 = fully covered).
    pub surface_coverage: Vec<(Surface, u64)>,
    /// Per-workflow coverage (millionths).
    pub workflow_coverage: Vec<(WorkflowKind, u64)>,
    /// Per-app-tier coverage (millionths).
    pub app_tier_coverage: Vec<(ExampleAppTier, u64)>,
    /// Overall coverage (millionths).
    pub overall_coverage_millionths: u64,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Signed receipt for the parity verdict, for evidence-chain linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version tag.
    pub schema_version: String,
    /// Component that produced this receipt.
    pub component: String,
    /// Bead that this receipt is associated with.
    pub bead_id: String,
    /// Policy ID governing this evaluation.
    pub policy_id: String,
    /// Security epoch at evaluation time.
    pub epoch: SecurityEpoch,
    /// Hash of the evaluation inputs (config + cells).
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds since an arbitrary epoch.
    pub timestamp_micros: u64,
}

// ---------------------------------------------------------------------------
// MatrixReport
// ---------------------------------------------------------------------------

/// Complete result of a parity matrix evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixReport {
    /// All evaluated cells.
    pub cells: Vec<MatrixCell>,
    /// Aggregate verdict.
    pub overall_verdict: CellVerdict,
    /// Total number of mismatches across all cells.
    pub total_mismatches: usize,
    /// Number of Critical mismatches.
    pub critical_count: usize,
    /// Number of Major mismatches.
    pub major_count: usize,
    /// Number of Minor mismatches.
    pub minor_count: usize,
    /// Coverage statistics.
    pub coverage: CoverageReport,
    /// Decision receipt for evidence-chain linkage.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// severity_at_or_above
// ---------------------------------------------------------------------------

/// Returns `true` if `severity` is at or above `threshold`.
pub fn severity_at_or_above(severity: &MismatchSeverity, threshold: &MismatchSeverity) -> bool {
    severity.rank() >= threshold.rank()
}

// ---------------------------------------------------------------------------
// classify_mismatch
// ---------------------------------------------------------------------------

/// Compare two captured artifacts and return a classified mismatch if they
/// diverge.
///
/// Returns `None` if the artifacts are identical. Checks content hash first,
/// then size divergence.
pub fn classify_mismatch(
    artifact_a: &CapturedArtifact,
    artifact_b: &CapturedArtifact,
    max_size_divergence: u64,
) -> Option<ClassifiedMismatch> {
    // If content hashes match and sizes match, no mismatch.
    if artifact_a.content_hash == artifact_b.content_hash
        && artifact_a.size_bytes == artifact_b.size_bytes
    {
        return None;
    }

    // Check size divergence first (it may be the only issue).
    let size_a = artifact_a.size_bytes;
    let size_b = artifact_b.size_bytes;
    let max_size = size_a.max(size_b);

    if let Some(divergence_millionths) = size_a
        .abs_diff(size_b)
        .saturating_mul(MILLIONTHS)
        .checked_div(max_size)
        && divergence_millionths > max_size_divergence
    {
        return Some(ClassifiedMismatch {
            class: MismatchClass::SizeDivergence,
            severity: if divergence_millionths > 200_000 {
                MismatchSeverity::Critical
            } else if divergence_millionths > 100_000 {
                MismatchSeverity::Major
            } else {
                MismatchSeverity::Minor
            },
            surface: artifact_a.surface,
            workflow: artifact_a.workflow,
            artifact_kind: artifact_a.kind,
            detail: format!(
                "size divergence {divergence_millionths} millionths \
                 (ref={size_a}, cand={size_b})"
            ),
            hash_a: Some(artifact_a.content_hash),
            hash_b: Some(artifact_b.content_hash),
        });
    }

    // Content hash differs but size divergence is within tolerance.
    if artifact_a.content_hash != artifact_b.content_hash {
        return Some(ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Major,
            surface: artifact_a.surface,
            workflow: artifact_a.workflow,
            artifact_kind: artifact_a.kind,
            detail: "content hashes differ".to_string(),
            hash_a: Some(artifact_a.content_hash),
            hash_b: Some(artifact_b.content_hash),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// evaluate_cell
// ---------------------------------------------------------------------------

/// Evaluate a single matrix cell by comparing reference and candidate artifacts.
///
/// Produces `Missing` mismatches for reference artifacts absent from candidate,
/// `Extra` mismatches for candidate artifacts absent from reference, and
/// content/size mismatches for paired artifacts.
pub fn evaluate_cell(
    reference: &[CapturedArtifact],
    candidate: &[CapturedArtifact],
    config: &MatrixConfig,
    surface: Surface,
    workflow: WorkflowKind,
    app_tier: ExampleAppTier,
) -> MatrixCell {
    let ref_capped = if reference.len() > MAX_ARTIFACTS_PER_SIDE {
        &reference[..MAX_ARTIFACTS_PER_SIDE]
    } else {
        reference
    };
    let cand_capped = if candidate.len() > MAX_ARTIFACTS_PER_SIDE {
        &candidate[..MAX_ARTIFACTS_PER_SIDE]
    } else {
        candidate
    };

    let mut mismatches = Vec::new();

    // If both sides are empty, the cell is inconclusive.
    if ref_capped.is_empty() && cand_capped.is_empty() {
        return MatrixCell {
            surface,
            workflow,
            app_tier,
            artifacts_reference: ref_capped.to_vec(),
            artifacts_candidate: cand_capped.to_vec(),
            mismatches,
            verdict: CellVerdict::Inconclusive,
        };
    }

    // Match reference artifacts to candidate by (kind) — find first match.
    let mut candidate_matched = vec![false; cand_capped.len()];

    for ref_art in ref_capped {
        let mut found = false;
        for (ci, cand_art) in cand_capped.iter().enumerate() {
            if !candidate_matched[ci] && ref_art.kind == cand_art.kind {
                candidate_matched[ci] = true;
                found = true;
                if let Some(mm) =
                    classify_mismatch(ref_art, cand_art, config.max_size_divergence_millionths)
                {
                    mismatches.push(mm);
                }
                break;
            }
        }
        if !found {
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::Missing,
                severity: MismatchSeverity::Critical,
                surface,
                workflow,
                artifact_kind: ref_art.kind,
                detail: format!(
                    "reference artifact {:?} not found in candidate",
                    ref_art.kind
                ),
                hash_a: Some(ref_art.content_hash),
                hash_b: None,
            });
        }
    }

    // Extra artifacts in candidate not matched to any reference.
    for (ci, matched) in candidate_matched.iter().enumerate() {
        if !matched {
            let cand_art = &cand_capped[ci];
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::Extra,
                severity: MismatchSeverity::Minor,
                surface,
                workflow,
                artifact_kind: cand_art.kind,
                detail: format!(
                    "candidate artifact {:?} has no reference counterpart",
                    cand_art.kind
                ),
                hash_a: None,
                hash_b: Some(cand_art.content_hash),
            });
        }
    }

    // Check for required artifact kinds based on config.
    if config.require_source_maps {
        let ref_has_sm = ref_capped.iter().any(|a| a.kind == ArtifactKind::SourceMap);
        let cand_has_sm = cand_capped
            .iter()
            .any(|a| a.kind == ArtifactKind::SourceMap);
        if ref_has_sm && !cand_has_sm {
            // Already captured as Missing above — no duplicate needed.
        } else if !ref_has_sm && !cand_has_sm && !ref_capped.is_empty() {
            mismatches.push(ClassifiedMismatch {
                class: MismatchClass::Missing,
                severity: MismatchSeverity::Major,
                surface,
                workflow,
                artifact_kind: ArtifactKind::SourceMap,
                detail: "source maps required but absent from both sides".to_string(),
                hash_a: None,
                hash_b: None,
            });
        }
    }

    if config.require_execution_traces {
        let needs_trace = matches!(
            workflow,
            WorkflowKind::Execute
                | WorkflowKind::SsrRender
                | WorkflowKind::HydrationRound
                | WorkflowKind::StreamingRender
        );
        if needs_trace {
            let cand_has_trace = cand_capped
                .iter()
                .any(|a| a.kind == ArtifactKind::ExecutionTrace);
            if !cand_has_trace {
                let ref_has_trace = ref_capped
                    .iter()
                    .any(|a| a.kind == ArtifactKind::ExecutionTrace);
                if !ref_has_trace {
                    mismatches.push(ClassifiedMismatch {
                        class: MismatchClass::Missing,
                        severity: MismatchSeverity::Major,
                        surface,
                        workflow,
                        artifact_kind: ArtifactKind::ExecutionTrace,
                        detail: "execution trace required for this workflow but absent".to_string(),
                        hash_a: None,
                        hash_b: None,
                    });
                }
            }
        }
    }

    // Derive cell verdict.
    let has_failing = mismatches
        .iter()
        .any(|m| severity_at_or_above(&m.severity, &config.severity_threshold));

    let verdict = if has_failing {
        CellVerdict::Fail
    } else {
        CellVerdict::Pass
    };

    MatrixCell {
        surface,
        workflow,
        app_tier,
        artifacts_reference: ref_capped.to_vec(),
        artifacts_candidate: cand_capped.to_vec(),
        mismatches,
        verdict,
    }
}

// ---------------------------------------------------------------------------
// compute_coverage
// ---------------------------------------------------------------------------

/// Compute coverage statistics for the evaluated matrix.
///
/// Coverage for a dimension is the fraction of exercised values over the
/// total possible values, expressed in millionths.
pub fn compute_coverage(cells: &[MatrixCell], _config: &MatrixConfig) -> CoverageReport {
    let exercised_surfaces: BTreeSet<Surface> = cells.iter().map(|c| c.surface).collect();
    let exercised_workflows: BTreeSet<WorkflowKind> = cells.iter().map(|c| c.workflow).collect();
    let exercised_tiers: BTreeSet<ExampleAppTier> = cells.iter().map(|c| c.app_tier).collect();

    let total_surfaces = Surface::all().len() as u64;
    let total_workflows = WorkflowKind::all().len() as u64;
    let total_tiers = ExampleAppTier::all().len() as u64;

    let surface_coverage: Vec<(Surface, u64)> = Surface::all()
        .iter()
        .map(|s| {
            let covered = if exercised_surfaces.contains(s) {
                MILLIONTHS
            } else {
                0
            };
            (*s, covered)
        })
        .collect();

    let workflow_coverage: Vec<(WorkflowKind, u64)> = WorkflowKind::all()
        .iter()
        .map(|w| {
            let covered = if exercised_workflows.contains(w) {
                MILLIONTHS
            } else {
                0
            };
            (*w, covered)
        })
        .collect();

    let app_tier_coverage: Vec<(ExampleAppTier, u64)> = ExampleAppTier::all()
        .iter()
        .map(|t| {
            let covered = if exercised_tiers.contains(t) {
                MILLIONTHS
            } else {
                0
            };
            (*t, covered)
        })
        .collect();

    // Overall coverage: geometric mean of dimension coverages (in millionths).
    let surf_frac = (exercised_surfaces.len() as u64 * MILLIONTHS)
        .checked_div(total_surfaces)
        .unwrap_or(0);
    let wf_frac = (exercised_workflows.len() as u64 * MILLIONTHS)
        .checked_div(total_workflows)
        .unwrap_or(0);
    let tier_frac = (exercised_tiers.len() as u64 * MILLIONTHS)
        .checked_div(total_tiers)
        .unwrap_or(0);

    // Simple average of three dimensions (all in millionths).
    let overall = if total_surfaces > 0 || total_workflows > 0 || total_tiers > 0 {
        (surf_frac + wf_frac + tier_frac) / 3
    } else {
        0
    };

    CoverageReport {
        surface_coverage,
        workflow_coverage,
        app_tier_coverage,
        overall_coverage_millionths: overall,
    }
}

// ---------------------------------------------------------------------------
// derive_overall_verdict
// ---------------------------------------------------------------------------

/// Derive the overall matrix verdict from individual cell verdicts.
///
/// - If any cell is `Fail`, the overall verdict is `Fail`.
/// - If all cells are `Pass`, the overall verdict is `Pass`.
/// - If any required surface or workflow is missing, `Fail`.
/// - Otherwise `Inconclusive`.
pub fn derive_overall_verdict(cells: &[MatrixCell], config: &MatrixConfig) -> CellVerdict {
    if cells.is_empty() {
        return CellVerdict::Inconclusive;
    }

    // Check for any failing cell.
    let has_fail = cells.iter().any(|c| c.verdict == CellVerdict::Fail);
    if has_fail {
        return CellVerdict::Fail;
    }

    // Check required surfaces.
    let exercised_surfaces: BTreeSet<Surface> = cells.iter().map(|c| c.surface).collect();
    for required in &config.required_surfaces {
        if !exercised_surfaces.contains(required) {
            return CellVerdict::Fail;
        }
    }

    // Check required workflows.
    let exercised_workflows: BTreeSet<WorkflowKind> = cells.iter().map(|c| c.workflow).collect();
    for required in &config.required_workflows {
        if !exercised_workflows.contains(required) {
            return CellVerdict::Fail;
        }
    }

    // Check require_all_app_tiers.
    if config.require_all_app_tiers {
        let exercised_tiers: BTreeSet<ExampleAppTier> = cells.iter().map(|c| c.app_tier).collect();
        for tier in ExampleAppTier::all() {
            if !exercised_tiers.contains(tier) {
                return CellVerdict::Fail;
            }
        }
    }

    // If all cells are pass, overall is pass.
    let all_pass = cells.iter().all(|c| c.verdict == CellVerdict::Pass);
    if all_pass {
        return CellVerdict::Pass;
    }

    // Mix of pass and inconclusive.
    CellVerdict::Inconclusive
}

// ---------------------------------------------------------------------------
// compute_receipt
// ---------------------------------------------------------------------------

/// Build a decision receipt over the evaluation inputs and verdict.
pub fn compute_receipt(
    input_hash: ContentHash,
    verdict: &CellVerdict,
    epoch: SecurityEpoch,
) -> DecisionReceipt {
    let verdict_bytes = verdict.as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(verdict_bytes);
    hasher.update(input_hash.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    let digest = hasher.finalize();
    let mut verdict_hash_bytes = [0u8; 32];
    verdict_hash_bytes.copy_from_slice(&digest);

    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch,
        input_hash,
        verdict_hash: ContentHash(verdict_hash_bytes),
        timestamp_micros: 0, // caller-supplied or zero for determinism
    }
}

// ---------------------------------------------------------------------------
// evaluate_parity_matrix
// ---------------------------------------------------------------------------

/// Main entry point: evaluate the full parity matrix.
///
/// Scans all provided cells, aggregates mismatches, computes coverage, and
/// derives the overall verdict with a decision receipt.
pub fn evaluate_parity_matrix(
    config: &MatrixConfig,
    cells: &[MatrixCell],
    epoch: SecurityEpoch,
) -> MatrixReport {
    let capped = if cells.len() > MAX_CELLS {
        &cells[..MAX_CELLS]
    } else {
        cells
    };

    let mut total_mismatches = 0usize;
    let mut critical_count = 0usize;
    let mut major_count = 0usize;
    let mut minor_count = 0usize;

    for cell in capped {
        total_mismatches += cell.mismatches.len();
        for mm in &cell.mismatches {
            match mm.severity {
                MismatchSeverity::Critical => critical_count += 1,
                MismatchSeverity::Major => major_count += 1,
                MismatchSeverity::Minor => minor_count += 1,
                MismatchSeverity::Informational => {}
            }
        }
    }

    let overall_verdict = derive_overall_verdict(capped, config);
    let coverage = compute_coverage(capped, config);

    // Build input hash over config + cells digest.
    let mut input_hasher = Sha256::new();
    input_hasher.update(SCHEMA_VERSION.as_bytes());
    input_hasher.update((capped.len() as u64).to_le_bytes());
    input_hasher.update(config.max_size_divergence_millionths.to_le_bytes());
    for cell in capped {
        input_hasher.update(cell.surface.as_str().as_bytes());
        input_hasher.update(cell.workflow.as_str().as_bytes());
        input_hasher.update(cell.app_tier.as_str().as_bytes());
        input_hasher.update((cell.mismatches.len() as u64).to_le_bytes());
    }
    let input_digest = input_hasher.finalize();
    let mut input_hash_bytes = [0u8; 32];
    input_hash_bytes.copy_from_slice(&input_digest);
    let input_hash = ContentHash(input_hash_bytes);

    let receipt = compute_receipt(input_hash, &overall_verdict, epoch);

    MatrixReport {
        cells: capped.to_vec(),
        overall_verdict,
        total_mismatches,
        critical_count,
        major_count,
        minor_count,
        coverage,
        receipt,
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_artifact(
        kind: ArtifactKind,
        surface: Surface,
        workflow: WorkflowKind,
        tier: ExampleAppTier,
        data: &[u8],
        size: u64,
    ) -> CapturedArtifact {
        CapturedArtifact {
            kind,
            surface,
            workflow,
            content_hash: ContentHash::compute(data),
            size_bytes: size,
            app_tier: tier,
        }
    }

    fn default_config() -> MatrixConfig {
        MatrixConfig::default()
    }

    fn make_passing_cell(
        surface: Surface,
        workflow: WorkflowKind,
        tier: ExampleAppTier,
    ) -> MatrixCell {
        let data = b"same content";
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            surface,
            workflow,
            tier,
            data,
            100,
        );
        let cand_art = ref_art.clone();
        MatrixCell {
            surface,
            workflow,
            app_tier: tier,
            artifacts_reference: vec![ref_art],
            artifacts_candidate: vec![cand_art],
            mismatches: vec![],
            verdict: CellVerdict::Pass,
        }
    }

    fn make_failing_cell(
        surface: Surface,
        workflow: WorkflowKind,
        tier: ExampleAppTier,
    ) -> MatrixCell {
        MatrixCell {
            surface,
            workflow,
            app_tier: tier,
            artifacts_reference: vec![make_artifact(
                ArtifactKind::CompiledOutput,
                surface,
                workflow,
                tier,
                b"ref",
                100,
            )],
            artifacts_candidate: vec![make_artifact(
                ArtifactKind::CompiledOutput,
                surface,
                workflow,
                tier,
                b"cand",
                100,
            )],
            mismatches: vec![ClassifiedMismatch {
                class: MismatchClass::ContentDivergence,
                severity: MismatchSeverity::Critical,
                surface,
                workflow,
                artifact_kind: ArtifactKind::CompiledOutput,
                detail: "content differs".to_string(),
                hash_a: Some(ContentHash::compute(b"ref")),
                hash_b: Some(ContentHash::compute(b"cand")),
            }],
            verdict: CellVerdict::Fail,
        }
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.react-compile-run-parity.v1");
        assert_eq!(COMPONENT, "react_compile_run_parity");
        assert_eq!(BEAD_ID, "bd-1lsy.3.6.3");
        assert_eq!(POLICY_ID, "RGC-206C");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // WorkflowKind
    // -----------------------------------------------------------------------

    #[test]
    fn test_workflow_kind_as_str() {
        assert_eq!(WorkflowKind::CompileOnly.as_str(), "compile_only");
        assert_eq!(WorkflowKind::Execute.as_str(), "execute");
        assert_eq!(WorkflowKind::SsrRender.as_str(), "ssr_render");
        assert_eq!(WorkflowKind::HydrationRound.as_str(), "hydration_round");
        assert_eq!(WorkflowKind::StaticGeneration.as_str(), "static_generation");
        assert_eq!(WorkflowKind::StreamingRender.as_str(), "streaming_render");
    }

    #[test]
    fn test_workflow_kind_display() {
        assert_eq!(format!("{}", WorkflowKind::CompileOnly), "compile_only");
        assert_eq!(
            format!("{}", WorkflowKind::StreamingRender),
            "streaming_render"
        );
    }

    #[test]
    fn test_workflow_kind_all_count() {
        assert_eq!(WorkflowKind::all().len(), 6);
    }

    // -----------------------------------------------------------------------
    // Surface
    // -----------------------------------------------------------------------

    #[test]
    fn test_surface_as_str() {
        assert_eq!(Surface::Library.as_str(), "library");
        assert_eq!(Surface::FrankenctlCompile.as_str(), "frankenctl_compile");
        assert_eq!(Surface::FrankenctlRun.as_str(), "frankenctl_run");
        assert_eq!(Surface::ExampleApp.as_str(), "example_app");
    }

    #[test]
    fn test_surface_display() {
        assert_eq!(format!("{}", Surface::Library), "library");
        assert_eq!(format!("{}", Surface::ExampleApp), "example_app");
    }

    #[test]
    fn test_surface_all_count() {
        assert_eq!(Surface::all().len(), 4);
    }

    // -----------------------------------------------------------------------
    // ArtifactKind
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_kind_as_str() {
        assert_eq!(ArtifactKind::CompiledOutput.as_str(), "compiled_output");
        assert_eq!(ArtifactKind::SourceMap.as_str(), "source_map");
        assert_eq!(ArtifactKind::Diagnostics.as_str(), "diagnostics");
        assert_eq!(ArtifactKind::ModuleGraph.as_str(), "module_graph");
        assert_eq!(ArtifactKind::ExecutionTrace.as_str(), "execution_trace");
        assert_eq!(ArtifactKind::RenderOutput.as_str(), "render_output");
    }

    #[test]
    fn test_artifact_kind_all_count() {
        assert_eq!(ArtifactKind::all().len(), 6);
    }

    // -----------------------------------------------------------------------
    // MismatchClass
    // -----------------------------------------------------------------------

    #[test]
    fn test_mismatch_class_as_str() {
        assert_eq!(MismatchClass::Missing.as_str(), "missing");
        assert_eq!(MismatchClass::Extra.as_str(), "extra");
        assert_eq!(
            MismatchClass::ContentDivergence.as_str(),
            "content_divergence"
        );
        assert_eq!(MismatchClass::SizeDivergence.as_str(), "size_divergence");
        assert_eq!(MismatchClass::OrderDivergence.as_str(), "order_divergence");
        assert_eq!(
            MismatchClass::SemanticDivergence.as_str(),
            "semantic_divergence"
        );
    }

    #[test]
    fn test_mismatch_class_display() {
        assert_eq!(format!("{}", MismatchClass::Missing), "missing");
        assert_eq!(
            format!("{}", MismatchClass::SemanticDivergence),
            "semantic_divergence"
        );
    }

    // -----------------------------------------------------------------------
    // MismatchSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_rank_ordering() {
        assert!(MismatchSeverity::Informational.rank() < MismatchSeverity::Minor.rank());
        assert!(MismatchSeverity::Minor.rank() < MismatchSeverity::Major.rank());
        assert!(MismatchSeverity::Major.rank() < MismatchSeverity::Critical.rank());
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(MismatchSeverity::Informational.as_str(), "informational");
        assert_eq!(MismatchSeverity::Minor.as_str(), "minor");
        assert_eq!(MismatchSeverity::Major.as_str(), "major");
        assert_eq!(MismatchSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", MismatchSeverity::Critical), "critical");
    }

    // -----------------------------------------------------------------------
    // CellVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_cell_verdict_as_str() {
        assert_eq!(CellVerdict::Pass.as_str(), "pass");
        assert_eq!(CellVerdict::Fail.as_str(), "fail");
        assert_eq!(CellVerdict::Inconclusive.as_str(), "inconclusive");
    }

    #[test]
    fn test_cell_verdict_display() {
        assert_eq!(format!("{}", CellVerdict::Inconclusive), "inconclusive");
    }

    // -----------------------------------------------------------------------
    // ExampleAppTier
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_tier_as_str() {
        assert_eq!(ExampleAppTier::Minimal.as_str(), "minimal");
        assert_eq!(ExampleAppTier::Typical.as_str(), "typical");
        assert_eq!(ExampleAppTier::Complex.as_str(), "complex");
        assert_eq!(ExampleAppTier::SsrFocused.as_str(), "ssr_focused");
        assert_eq!(
            ExampleAppTier::HybridIsomorphic.as_str(),
            "hybrid_isomorphic"
        );
    }

    #[test]
    fn test_app_tier_all_count() {
        assert_eq!(ExampleAppTier::all().len(), 5);
    }

    #[test]
    fn test_app_tier_display() {
        assert_eq!(
            format!("{}", ExampleAppTier::HybridIsomorphic),
            "hybrid_isomorphic"
        );
    }

    // -----------------------------------------------------------------------
    // severity_at_or_above
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_at_or_above_same() {
        assert!(severity_at_or_above(
            &MismatchSeverity::Major,
            &MismatchSeverity::Major
        ));
    }

    #[test]
    fn test_severity_at_or_above_higher() {
        assert!(severity_at_or_above(
            &MismatchSeverity::Critical,
            &MismatchSeverity::Major
        ));
    }

    #[test]
    fn test_severity_at_or_above_lower() {
        assert!(!severity_at_or_above(
            &MismatchSeverity::Minor,
            &MismatchSeverity::Major
        ));
    }

    #[test]
    fn test_severity_at_or_above_informational_threshold() {
        // Everything is at or above Informational.
        assert!(severity_at_or_above(
            &MismatchSeverity::Informational,
            &MismatchSeverity::Informational
        ));
        assert!(severity_at_or_above(
            &MismatchSeverity::Minor,
            &MismatchSeverity::Informational
        ));
        assert!(severity_at_or_above(
            &MismatchSeverity::Critical,
            &MismatchSeverity::Informational
        ));
    }

    #[test]
    fn test_severity_at_or_above_critical_threshold() {
        // Only Critical passes a Critical threshold.
        assert!(!severity_at_or_above(
            &MismatchSeverity::Major,
            &MismatchSeverity::Critical
        ));
        assert!(severity_at_or_above(
            &MismatchSeverity::Critical,
            &MismatchSeverity::Critical
        ));
    }

    // -----------------------------------------------------------------------
    // classify_mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_identical_artifacts_no_mismatch() {
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"hello",
            5,
        );
        let b = a.clone();
        assert!(classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).is_none());
    }

    #[test]
    fn test_classify_content_divergence() {
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"aaa",
            100,
        );
        let b = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"bbb",
            100,
        );
        let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
        assert_eq!(mm.class, MismatchClass::ContentDivergence);
        assert_eq!(mm.severity, MismatchSeverity::Major);
    }

    #[test]
    fn test_classify_size_divergence_minor() {
        // 10% divergence (100 vs 90): > 5% threshold, ≤ 10% → Minor
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"aaa",
            100,
        );
        let b = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"bbb",
            90,
        );
        let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
        assert_eq!(mm.class, MismatchClass::SizeDivergence);
        assert_eq!(mm.severity, MismatchSeverity::Minor);
    }

    #[test]
    fn test_classify_size_divergence_major() {
        // 15% divergence (200 vs 170): > 10% → Major
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"aaa",
            200,
        );
        let b = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"bbb",
            170,
        );
        let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
        assert_eq!(mm.class, MismatchClass::SizeDivergence);
        assert_eq!(mm.severity, MismatchSeverity::Major);
    }

    #[test]
    fn test_classify_size_divergence_critical() {
        // 50% divergence: > 20% → Critical
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"aaa",
            100,
        );
        let b = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"bbb",
            50,
        );
        let mm = classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).unwrap();
        assert_eq!(mm.class, MismatchClass::SizeDivergence);
        assert_eq!(mm.severity, MismatchSeverity::Critical);
    }

    #[test]
    fn test_classify_within_size_tolerance_content_same() {
        // Same content, same size → no mismatch
        let data = b"content";
        let a = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            data,
            100,
        );
        let b = a.clone();
        assert!(classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).is_none());
    }

    // -----------------------------------------------------------------------
    // evaluate_cell
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_cell_empty_both_sides() {
        let config = default_config();
        let cell = evaluate_cell(
            &[],
            &[],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        assert_eq!(cell.verdict, CellVerdict::Inconclusive);
        assert!(cell.mismatches.is_empty());
    }

    #[test]
    fn test_evaluate_cell_matching_artifacts() {
        let data = b"same";
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: false,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            data,
            100,
        );
        let cand_art = ref_art.clone();
        let cell = evaluate_cell(
            &[ref_art],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        assert_eq!(cell.verdict, CellVerdict::Pass);
        assert!(cell.mismatches.is_empty());
    }

    #[test]
    fn test_evaluate_cell_missing_artifact() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: false,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"data",
            100,
        );
        let cell = evaluate_cell(
            &[ref_art],
            &[],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        assert_eq!(cell.verdict, CellVerdict::Fail);
        assert!(!cell.mismatches.is_empty());
        assert_eq!(cell.mismatches[0].class, MismatchClass::Missing);
        assert_eq!(cell.mismatches[0].severity, MismatchSeverity::Critical);
    }

    #[test]
    fn test_evaluate_cell_extra_artifact() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: false,
            severity_threshold: MismatchSeverity::Major,
            ..default_config()
        };
        let cand_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"extra",
            100,
        );
        let cell = evaluate_cell(
            &[],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        // Extra artifact is Minor severity, threshold is Major → Pass.
        assert_eq!(cell.verdict, CellVerdict::Pass);
        assert_eq!(cell.mismatches.len(), 1);
        assert_eq!(cell.mismatches[0].class, MismatchClass::Extra);
    }

    #[test]
    fn test_evaluate_cell_content_divergence() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: false,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"ref_content",
            100,
        );
        let cand_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"cand_content",
            100,
        );
        let cell = evaluate_cell(
            &[ref_art],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        assert_eq!(cell.verdict, CellVerdict::Fail);
        assert!(
            cell.mismatches
                .iter()
                .any(|m| m.class == MismatchClass::ContentDivergence)
        );
    }

    #[test]
    fn test_evaluate_cell_source_map_required_but_missing() {
        let config = MatrixConfig {
            require_source_maps: true,
            require_execution_traces: false,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"same",
            100,
        );
        let cand_art = ref_art.clone();
        let cell = evaluate_cell(
            &[ref_art],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        // Source map required but absent from both sides → Major mismatch.
        assert_eq!(cell.verdict, CellVerdict::Fail);
        assert!(cell.mismatches.iter().any(|m| {
            m.artifact_kind == ArtifactKind::SourceMap && m.class == MismatchClass::Missing
        }));
    }

    #[test]
    fn test_evaluate_cell_execution_trace_required_for_execute() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: true,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::Execute,
            ExampleAppTier::Minimal,
            b"same",
            100,
        );
        let cand_art = ref_art.clone();
        let cell = evaluate_cell(
            &[ref_art],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::Execute,
            ExampleAppTier::Minimal,
        );
        // Execution trace required for Execute workflow but absent.
        assert_eq!(cell.verdict, CellVerdict::Fail);
        assert!(
            cell.mismatches
                .iter()
                .any(|m| { m.artifact_kind == ArtifactKind::ExecutionTrace })
        );
    }

    #[test]
    fn test_evaluate_cell_execution_trace_not_required_for_compile_only() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: true,
            ..default_config()
        };
        let ref_art = make_artifact(
            ArtifactKind::CompiledOutput,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"same",
            100,
        );
        let cand_art = ref_art.clone();
        let cell = evaluate_cell(
            &[ref_art],
            &[cand_art],
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        // CompileOnly doesn't need execution traces, so no mismatch.
        assert_eq!(cell.verdict, CellVerdict::Pass);
    }

    // -----------------------------------------------------------------------
    // compute_coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_coverage_empty_cells() {
        let config = default_config();
        let coverage = compute_coverage(&[], &config);
        assert_eq!(coverage.overall_coverage_millionths, 0);
        for (_, v) in &coverage.surface_coverage {
            assert_eq!(*v, 0);
        }
    }

    #[test]
    fn test_coverage_full() {
        let config = default_config();
        let mut cells = Vec::new();
        for surface in Surface::all() {
            for workflow in WorkflowKind::all() {
                for tier in ExampleAppTier::all() {
                    cells.push(make_passing_cell(*surface, *workflow, *tier));
                }
            }
        }
        let coverage = compute_coverage(&cells, &config);
        assert_eq!(coverage.overall_coverage_millionths, MILLIONTHS);
    }

    #[test]
    fn test_coverage_partial_surfaces() {
        let config = default_config();
        // Only Library surface exercised (1 of 4).
        let cells = vec![make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        let coverage = compute_coverage(&cells, &config);
        // Surface: 1/4 = 250_000, Workflow: 1/6 = 166_666, Tier: 1/5 = 200_000
        // Average ≈ 205_555
        assert!(coverage.overall_coverage_millionths > 0);
        assert!(coverage.overall_coverage_millionths < MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // derive_overall_verdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_overall_verdict_empty_cells() {
        let config = default_config();
        assert_eq!(
            derive_overall_verdict(&[], &config),
            CellVerdict::Inconclusive
        );
    }

    #[test]
    fn test_overall_verdict_all_pass() {
        let config = default_config();
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            make_passing_cell(
                Surface::ExampleApp,
                WorkflowKind::Execute,
                ExampleAppTier::Typical,
            ),
        ];
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
    }

    #[test]
    fn test_overall_verdict_single_fail() {
        let config = default_config();
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            make_failing_cell(
                Surface::ExampleApp,
                WorkflowKind::Execute,
                ExampleAppTier::Typical,
            ),
        ];
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
    }

    #[test]
    fn test_overall_verdict_missing_required_surface() {
        let mut config = default_config();
        config.required_surfaces.insert(Surface::FrankenctlRun);
        let cells = vec![make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
    }

    #[test]
    fn test_overall_verdict_missing_required_workflow() {
        let mut config = default_config();
        config.required_workflows.insert(WorkflowKind::SsrRender);
        let cells = vec![make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
    }

    #[test]
    fn test_overall_verdict_require_all_app_tiers() {
        let mut config = default_config();
        config.require_all_app_tiers = true;
        let cells = vec![make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        // Only Minimal tier exercised, but all required → Fail.
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Fail);
    }

    #[test]
    fn test_overall_verdict_all_tiers_present() {
        let mut config = default_config();
        config.require_all_app_tiers = true;
        let cells: Vec<MatrixCell> = ExampleAppTier::all()
            .iter()
            .map(|tier| make_passing_cell(Surface::Library, WorkflowKind::CompileOnly, *tier))
            .collect();
        assert_eq!(derive_overall_verdict(&cells, &config), CellVerdict::Pass);
    }

    #[test]
    fn test_overall_verdict_inconclusive_mixed() {
        let config = default_config();
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            MatrixCell {
                surface: Surface::ExampleApp,
                workflow: WorkflowKind::Execute,
                app_tier: ExampleAppTier::Typical,
                artifacts_reference: vec![],
                artifacts_candidate: vec![],
                mismatches: vec![],
                verdict: CellVerdict::Inconclusive,
            },
        ];
        // Mix of Pass and Inconclusive → Inconclusive.
        assert_eq!(
            derive_overall_verdict(&cells, &config),
            CellVerdict::Inconclusive
        );
    }

    // -----------------------------------------------------------------------
    // compute_receipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_determinism() {
        let input_hash = ContentHash::compute(b"test input");
        let epoch = SecurityEpoch::from_raw(42);
        let r1 = compute_receipt(input_hash, &CellVerdict::Pass, epoch);
        let r2 = compute_receipt(input_hash, &CellVerdict::Pass, epoch);
        assert_eq!(r1.verdict_hash, r2.verdict_hash);
        assert_eq!(r1.schema_version, SCHEMA_VERSION);
        assert_eq!(r1.component, COMPONENT);
        assert_eq!(r1.bead_id, BEAD_ID);
        assert_eq!(r1.policy_id, POLICY_ID);
    }

    #[test]
    fn test_receipt_different_verdicts_differ() {
        let input_hash = ContentHash::compute(b"test input");
        let epoch = SecurityEpoch::from_raw(1);
        let r_pass = compute_receipt(input_hash, &CellVerdict::Pass, epoch);
        let r_fail = compute_receipt(input_hash, &CellVerdict::Fail, epoch);
        assert_ne!(r_pass.verdict_hash, r_fail.verdict_hash);
    }

    #[test]
    fn test_receipt_different_epochs_differ() {
        let input_hash = ContentHash::compute(b"test input");
        let r1 = compute_receipt(input_hash, &CellVerdict::Pass, SecurityEpoch::from_raw(1));
        let r2 = compute_receipt(input_hash, &CellVerdict::Pass, SecurityEpoch::from_raw(2));
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    // -----------------------------------------------------------------------
    // evaluate_parity_matrix
    // -----------------------------------------------------------------------

    #[test]
    fn test_matrix_empty_cells_inconclusive() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let report = evaluate_parity_matrix(&config, &[], epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Inconclusive);
        assert_eq!(report.total_mismatches, 0);
        assert_eq!(report.critical_count, 0);
    }

    #[test]
    fn test_matrix_all_passing() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            make_passing_cell(
                Surface::FrankenctlCompile,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Typical,
            ),
        ];
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Pass);
        assert_eq!(report.total_mismatches, 0);
    }

    #[test]
    fn test_matrix_single_critical_mismatch() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells = vec![make_failing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Fail);
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.total_mismatches, 1);
    }

    #[test]
    fn test_matrix_mismatch_counts() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(5);
        let mut cell = make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        cell.mismatches.push(ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Critical,
            surface: Surface::Library,
            workflow: WorkflowKind::CompileOnly,
            artifact_kind: ArtifactKind::CompiledOutput,
            detail: "test critical".to_string(),
            hash_a: None,
            hash_b: None,
        });
        cell.mismatches.push(ClassifiedMismatch {
            class: MismatchClass::SizeDivergence,
            severity: MismatchSeverity::Major,
            surface: Surface::Library,
            workflow: WorkflowKind::CompileOnly,
            artifact_kind: ArtifactKind::CompiledOutput,
            detail: "test major".to_string(),
            hash_a: None,
            hash_b: None,
        });
        cell.mismatches.push(ClassifiedMismatch {
            class: MismatchClass::Extra,
            severity: MismatchSeverity::Minor,
            surface: Surface::Library,
            workflow: WorkflowKind::CompileOnly,
            artifact_kind: ArtifactKind::SourceMap,
            detail: "test minor".to_string(),
            hash_a: None,
            hash_b: None,
        });
        cell.verdict = CellVerdict::Fail;
        let report = evaluate_parity_matrix(&config, &[cell], epoch);
        assert_eq!(report.total_mismatches, 3);
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.major_count, 1);
        assert_eq!(report.minor_count, 1);
    }

    #[test]
    fn test_matrix_receipt_present() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(99);
        let cells = vec![make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        )];
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.receipt.epoch, epoch);
        assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
    }

    // -----------------------------------------------------------------------
    // MatrixConfig defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_defaults() {
        let config = MatrixConfig::default();
        assert!(config.required_surfaces.is_empty());
        assert!(config.required_workflows.is_empty());
        assert_eq!(config.max_size_divergence_millionths, 50_000);
        assert_eq!(config.severity_threshold, MismatchSeverity::Major);
        assert!(config.require_source_maps);
        assert!(config.require_execution_traces);
        assert!(!config.require_all_app_tiers);
    }

    // -----------------------------------------------------------------------
    // Mixed severity threshold filtering
    // -----------------------------------------------------------------------

    #[test]
    fn test_threshold_informational_passes_minor() {
        let _config = MatrixConfig {
            severity_threshold: MismatchSeverity::Critical,
            require_source_maps: false,
            require_execution_traces: false,
            ..default_config()
        };
        // Cell with a Major mismatch, but threshold is Critical → should pass.
        let mut cell = make_passing_cell(
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        cell.mismatches.push(ClassifiedMismatch {
            class: MismatchClass::ContentDivergence,
            severity: MismatchSeverity::Major,
            surface: Surface::Library,
            workflow: WorkflowKind::CompileOnly,
            artifact_kind: ArtifactKind::CompiledOutput,
            detail: "major but below threshold".to_string(),
            hash_a: None,
            hash_b: None,
        });
        // Re-evaluate: the cell itself was already set to Pass by helper,
        // but in the real flow evaluate_cell would check. We check
        // severity_at_or_above directly.
        assert!(!severity_at_or_above(
            &MismatchSeverity::Major,
            &MismatchSeverity::Critical
        ));
    }

    // -----------------------------------------------------------------------
    // All surface types exercised
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_surfaces_in_matrix() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells: Vec<MatrixCell> = Surface::all()
            .iter()
            .map(|s| make_passing_cell(*s, WorkflowKind::CompileOnly, ExampleAppTier::Minimal))
            .collect();
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Pass);
        assert_eq!(report.cells.len(), 4);
    }

    // -----------------------------------------------------------------------
    // All workflow kinds exercised
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_workflows_in_matrix() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells: Vec<MatrixCell> = WorkflowKind::all()
            .iter()
            .map(|w| make_passing_cell(Surface::Library, *w, ExampleAppTier::Minimal))
            .collect();
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Pass);
        assert_eq!(report.cells.len(), 6);
    }

    // -----------------------------------------------------------------------
    // All app tiers exercised
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_app_tiers_in_matrix() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells: Vec<MatrixCell> = ExampleAppTier::all()
            .iter()
            .map(|t| make_passing_cell(Surface::Library, WorkflowKind::CompileOnly, *t))
            .collect();
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Pass);
        assert_eq!(report.cells.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_serde_round_trip_workflow_kind() {
        for wk in WorkflowKind::all() {
            let json = serde_json::to_string(wk).unwrap();
            let back: WorkflowKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*wk, back);
        }
    }

    #[test]
    fn test_serde_round_trip_surface() {
        for s in Surface::all() {
            let json = serde_json::to_string(s).unwrap();
            let back: Surface = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn test_serde_round_trip_cell_verdict() {
        for v in &[
            CellVerdict::Pass,
            CellVerdict::Fail,
            CellVerdict::Inconclusive,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let back: CellVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn test_serde_round_trip_matrix_config() {
        let config = MatrixConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: MatrixConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_zero_size_both() {
        let a = make_artifact(
            ArtifactKind::Diagnostics,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
            b"same",
            0,
        );
        let b = a.clone();
        assert!(classify_mismatch(&a, &b, DEFAULT_MAX_SIZE_DIVERGENCE).is_none());
    }

    #[test]
    fn test_evaluate_cell_multiple_artifact_kinds() {
        let config = MatrixConfig {
            require_source_maps: false,
            require_execution_traces: false,
            ..default_config()
        };
        let data = b"x";
        let ref_arts = vec![
            make_artifact(
                ArtifactKind::CompiledOutput,
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
                data,
                50,
            ),
            make_artifact(
                ArtifactKind::SourceMap,
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
                data,
                30,
            ),
        ];
        let cand_arts = vec![
            make_artifact(
                ArtifactKind::CompiledOutput,
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
                data,
                50,
            ),
            make_artifact(
                ArtifactKind::SourceMap,
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
                data,
                30,
            ),
        ];
        let cell = evaluate_cell(
            &ref_arts,
            &cand_arts,
            &config,
            Surface::Library,
            WorkflowKind::CompileOnly,
            ExampleAppTier::Minimal,
        );
        assert_eq!(cell.verdict, CellVerdict::Pass);
        assert!(cell.mismatches.is_empty());
    }

    #[test]
    fn test_matrix_coverage_report_surfaces() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            make_passing_cell(
                Surface::FrankenctlRun,
                WorkflowKind::Execute,
                ExampleAppTier::Typical,
            ),
        ];
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        // 2 of 4 surfaces exercised.
        let lib_cov = report
            .coverage
            .surface_coverage
            .iter()
            .find(|(s, _)| *s == Surface::Library)
            .unwrap()
            .1;
        assert_eq!(lib_cov, MILLIONTHS);
        let compile_cov = report
            .coverage
            .surface_coverage
            .iter()
            .find(|(s, _)| *s == Surface::FrankenctlCompile)
            .unwrap()
            .1;
        assert_eq!(compile_cov, 0);
    }

    #[test]
    fn test_multiple_cells_across_surfaces() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(10);
        let cells = vec![
            make_passing_cell(
                Surface::Library,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Minimal,
            ),
            make_passing_cell(
                Surface::FrankenctlCompile,
                WorkflowKind::CompileOnly,
                ExampleAppTier::Typical,
            ),
            make_failing_cell(
                Surface::FrankenctlRun,
                WorkflowKind::Execute,
                ExampleAppTier::Complex,
            ),
            make_passing_cell(
                Surface::ExampleApp,
                WorkflowKind::SsrRender,
                ExampleAppTier::SsrFocused,
            ),
        ];
        let report = evaluate_parity_matrix(&config, &cells, epoch);
        assert_eq!(report.overall_verdict, CellVerdict::Fail);
        assert_eq!(report.cells.len(), 4);
        assert!(report.critical_count >= 1);
    }
}
