#![forbid(unsafe_code)]

//! Differentially verify native React compile outputs, diagnostics, and
//! artifact shapes across library and shipped CLI surfaces.
//!
//! Compares compilation results from two surfaces (typically `Library` and
//! `CliShipped`) to detect content divergence, missing/extra artifacts,
//! diagnostic mismatches, source-map gaps, and size divergence. A
//! configurable policy governs which divergences are tolerated and which
//! cause the verification gate to fail.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-807A], bead bd-1lsy.9.7.1.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the react compile verification module.
pub const SCHEMA_VERSION: &str = "franken-engine.react-compile-verification.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_compile_verification";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.7.1";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-807A";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Default max size divergence: 5% = 50_000 millionths.
pub const DEFAULT_MAX_SIZE_DIVERGENCE: u64 = 50_000;

/// Default max diagnostic divergence: 0 (exact parity).
pub const DEFAULT_MAX_DIAGNOSTIC_DIVERGENCE: usize = 0;

/// Maximum number of artifacts per compile result.
const MAX_ARTIFACTS_PER_RESULT: usize = 1_000;

/// Maximum number of diagnostics per compile result.
const MAX_DIAGNOSTICS_PER_RESULT: usize = 10_000;

// ---------------------------------------------------------------------------
// CompileMode
// ---------------------------------------------------------------------------

/// JSX runtime compilation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileMode {
    /// Classic: `React.createElement(type, props, ...children)`.
    Classic,
    /// Automatic: `jsx(type, { ...props, children })`.
    Automatic,
}

impl CompileMode {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[Self::Classic, Self::Automatic];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Automatic => "automatic",
        }
    }
}

impl fmt::Display for CompileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ArtifactKind
// ---------------------------------------------------------------------------

/// Kind of artifact produced by compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Compiled JavaScript/TypeScript output.
    CompiledOutput,
    /// Source map file.
    SourceMap,
    /// Diagnostic report (structured).
    Diagnostics,
    /// TypeScript type declaration (.d.ts).
    TypeDeclaration,
    /// Bundle manifest (chunk graph, entry points).
    BundleManifest,
}

impl ArtifactKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::CompiledOutput,
        Self::SourceMap,
        Self::Diagnostics,
        Self::TypeDeclaration,
        Self::BundleManifest,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompiledOutput => "compiled_output",
            Self::SourceMap => "source_map",
            Self::Diagnostics => "diagnostics",
            Self::TypeDeclaration => "type_declaration",
            Self::BundleManifest => "bundle_manifest",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

/// Severity of a compile diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Hint: suggestion for improvement.
    Hint,
    /// Info: informational message, no action required.
    Info,
    /// Warning: potential issue.
    Warning,
    /// Error: compilation failure.
    Error,
}

impl DiagnosticSeverity {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[Self::Hint, Self::Info, Self::Warning, Self::Error];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hint => "hint",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Numeric weight for severity-based scoring (millionths).
    pub const fn weight(self) -> u64 {
        match self {
            Self::Hint => 50_000,     // 0.05
            Self::Info => 100_000,    // 0.1
            Self::Warning => 400_000, // 0.4
            Self::Error => 1_000_000, // 1.0
        }
    }
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CompileDiagnostic
// ---------------------------------------------------------------------------

/// A single diagnostic emitted during compilation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompileDiagnostic {
    /// Human-readable diagnostic message.
    pub message: String,
    /// Severity of this diagnostic.
    pub severity: DiagnosticSeverity,
    /// Source line (1-based).
    pub line: u32,
    /// Source column (1-based).
    pub column: u32,
    /// Byte range in the source [start, end).
    pub source_range: (u32, u32),
}

impl CompileDiagnostic {
    /// Compute a content hash for this diagnostic.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.message.as_bytes());
        h.update(self.severity.as_str().as_bytes());
        h.update(self.line.to_le_bytes());
        h.update(self.column.to_le_bytes());
        h.update(self.source_range.0.to_le_bytes());
        h.update(self.source_range.1.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for CompileDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}:{}: {}",
            self.severity, self.line, self.column, self.message
        )
    }
}

// ---------------------------------------------------------------------------
// CompileArtifact
// ---------------------------------------------------------------------------

/// A single artifact produced by compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileArtifact {
    /// Kind of artifact.
    pub kind: ArtifactKind,
    /// Content hash of the artifact bytes.
    pub content_hash: ContentHash,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Provenance string (e.g. file path, pipeline stage).
    pub provenance: String,
}

impl CompileArtifact {
    /// Create a new artifact with the given content bytes.
    pub fn from_content(kind: ArtifactKind, content: &[u8], provenance: impl Into<String>) -> Self {
        Self {
            kind,
            content_hash: ContentHash::compute(content),
            size_bytes: content.len() as u64,
            provenance: provenance.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// CompileSurface
// ---------------------------------------------------------------------------

/// The compilation surface being compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileSurface {
    /// Library API surface (programmatic usage).
    Library,
    /// Shipped CLI surface (command-line tool).
    CliShipped,
}

impl CompileSurface {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[Self::Library, Self::CliShipped];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::CliShipped => "cli_shipped",
        }
    }
}

impl fmt::Display for CompileSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CompileResult
// ---------------------------------------------------------------------------

/// Result of a compilation run on a specific surface/mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileResult {
    /// Surface that produced this result.
    pub surface: CompileSurface,
    /// Compile mode used.
    pub mode: CompileMode,
    /// Artifacts produced.
    pub artifacts: Vec<CompileArtifact>,
    /// Diagnostics emitted.
    pub diagnostics: Vec<CompileDiagnostic>,
    /// Whether compilation succeeded.
    pub success: bool,
    /// Wall-clock duration in microseconds.
    pub duration_micros: u64,
}

impl CompileResult {
    /// Find artifacts by kind.
    pub fn artifacts_by_kind(&self, kind: ArtifactKind) -> Vec<&CompileArtifact> {
        self.artifacts.iter().filter(|a| a.kind == kind).collect()
    }

    /// Whether a source map artifact is present.
    pub fn has_source_map(&self) -> bool {
        self.artifacts
            .iter()
            .any(|a| a.kind == ArtifactKind::SourceMap)
    }

    /// Count of diagnostics at a given severity.
    pub fn diagnostic_count(&self, severity: DiagnosticSeverity) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == severity)
            .count()
    }

    /// Total artifact size in bytes.
    pub fn total_artifact_size(&self) -> u64 {
        self.artifacts.iter().map(|a| a.size_bytes).sum()
    }

    /// Compute content hash over all artifacts and diagnostics.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(self.surface.as_str().as_bytes());
        h.update(self.mode.as_str().as_bytes());
        h.update((self.artifacts.len() as u64).to_le_bytes());
        for a in &self.artifacts {
            h.update(a.kind.as_str().as_bytes());
            h.update(a.content_hash.as_bytes());
            h.update(a.size_bytes.to_le_bytes());
        }
        h.update((self.diagnostics.len() as u64).to_le_bytes());
        for d in &self.diagnostics {
            h.update(d.content_hash().as_bytes());
        }
        h.update(if self.success { &[1u8] } else { &[0u8] });
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// MismatchKind
// ---------------------------------------------------------------------------

/// Kind of mismatch detected between two compile results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    /// An artifact present in one result is missing in the other.
    ArtifactMissing,
    /// An artifact present in one result has no counterpart in the other.
    ArtifactExtra,
    /// Matching artifacts have different content hashes.
    ContentDivergence,
    /// Diagnostics differ between the two results.
    DiagnosticDivergence,
    /// Artifact sizes diverge beyond the configured threshold.
    SizeDivergence,
    /// Source map content or presence diverges.
    SourceMapDivergence,
}

impl MismatchKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::ArtifactMissing,
        Self::ArtifactExtra,
        Self::ContentDivergence,
        Self::DiagnosticDivergence,
        Self::SizeDivergence,
        Self::SourceMapDivergence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactMissing => "artifact_missing",
            Self::ArtifactExtra => "artifact_extra",
            Self::ContentDivergence => "content_divergence",
            Self::DiagnosticDivergence => "diagnostic_divergence",
            Self::SizeDivergence => "size_divergence",
            Self::SourceMapDivergence => "source_map_divergence",
        }
    }
}

impl fmt::Display for MismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Mismatch
// ---------------------------------------------------------------------------

/// A single mismatch between two compile results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mismatch {
    /// Kind of mismatch.
    pub kind: MismatchKind,
    /// Which surface diverged (the "different" side).
    pub surface: CompileSurface,
    /// Artifact kind involved (if applicable).
    pub artifact_kind: Option<ArtifactKind>,
    /// Human-readable detail of the mismatch.
    pub detail: String,
    /// Severity classification.
    pub severity: DiagnosticSeverity,
}

impl Mismatch {
    /// Compute a content hash for this mismatch.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.kind.as_str().as_bytes());
        h.update(self.surface.as_str().as_bytes());
        if let Some(ak) = self.artifact_kind {
            h.update(ak.as_str().as_bytes());
        }
        h.update(self.detail.as_bytes());
        h.update(self.severity.as_str().as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} on {}: {}",
            self.severity, self.kind, self.surface, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// VerificationConfig
// ---------------------------------------------------------------------------

/// Configuration for parity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Maximum allowed size divergence ratio (millionths).
    /// E.g. 50_000 = 5%.
    pub max_size_divergence_millionths: u64,
    /// Whether source maps are required on both surfaces.
    pub require_source_maps: bool,
    /// Whether diagnostics must be identical across surfaces.
    pub require_diagnostics_parity: bool,
    /// Maximum number of diagnostic differences before failure.
    pub max_diagnostic_divergence: usize,
}

impl VerificationConfig {
    /// Strict configuration: zero tolerance.
    pub fn strict() -> Self {
        Self {
            max_size_divergence_millionths: 0,
            require_source_maps: true,
            require_diagnostics_parity: true,
            max_diagnostic_divergence: 0,
        }
    }

    /// Permissive configuration for exploratory runs.
    pub fn permissive() -> Self {
        Self {
            max_size_divergence_millionths: 200_000, // 20%
            require_source_maps: false,
            require_diagnostics_parity: false,
            max_diagnostic_divergence: usize::MAX,
        }
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            max_size_divergence_millionths: DEFAULT_MAX_SIZE_DIVERGENCE,
            require_source_maps: true,
            require_diagnostics_parity: true,
            max_diagnostic_divergence: DEFAULT_MAX_DIAGNOSTIC_DIVERGENCE,
        }
    }
}

// ---------------------------------------------------------------------------
// VerificationVerdict
// ---------------------------------------------------------------------------

/// Verdict of a verification run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    /// All checks passed: surfaces are parity-equivalent.
    Pass,
    /// One or more checks failed.
    Fail,
    /// Verification could not complete (e.g. one side failed to compile).
    Inconclusive,
}

impl VerificationVerdict {
    pub const ALL: &[Self] = &[Self::Pass, Self::Fail, Self::Inconclusive];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl fmt::Display for VerificationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Tamper-evident receipt of a verification decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead ID.
    pub bead_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Hash of the verification inputs.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
}

impl DecisionReceipt {
    /// Compute a content hash for the receipt itself.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.schema_version.as_bytes());
        h.update(self.component.as_bytes());
        h.update(self.bead_id.as_bytes());
        h.update(self.policy_id.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.input_hash.as_bytes());
        h.update(self.verdict_hash.as_bytes());
        h.update(self.timestamp_micros.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// VerificationReport
// ---------------------------------------------------------------------------

/// Report from a parity verification run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Result from surface A.
    pub result_a: CompileResult,
    /// Result from surface B.
    pub result_b: CompileResult,
    /// Detected mismatches.
    pub mismatches: Vec<Mismatch>,
    /// Overall verdict.
    pub verdict: VerificationVerdict,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

impl VerificationReport {
    /// Count of mismatches by kind.
    pub fn mismatch_count_by_kind(&self, kind: MismatchKind) -> usize {
        self.mismatches.iter().filter(|m| m.kind == kind).count()
    }

    /// Count of mismatches by severity.
    pub fn mismatch_count_by_severity(&self, severity: DiagnosticSeverity) -> usize {
        self.mismatches
            .iter()
            .filter(|m| m.severity == severity)
            .count()
    }

    /// Whether this report has any error-severity mismatches.
    pub fn has_errors(&self) -> bool {
        self.mismatches
            .iter()
            .any(|m| m.severity == DiagnosticSeverity::Error)
    }

    /// Total weighted mismatch score (millionths).
    pub fn weighted_score(&self) -> u64 {
        self.mismatches.iter().map(|m| m.severity.weight()).sum()
    }

    /// Content hash of the entire report.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(self.result_a.content_hash().as_bytes());
        h.update(self.result_b.content_hash().as_bytes());
        h.update((self.mismatches.len() as u64).to_le_bytes());
        for m in &self.mismatches {
            h.update(m.content_hash().as_bytes());
        }
        h.update(self.verdict.as_str().as_bytes());
        h.update(self.receipt.input_hash.as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// VerificationError
// ---------------------------------------------------------------------------

/// Errors from verification operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum VerificationError {
    /// Both results used the same surface.
    #[error("same surface: both results are from {surface}")]
    SameSurface { surface: CompileSurface },

    /// Mode mismatch: results compiled with different modes.
    #[error("mode mismatch: {mode_a} vs {mode_b}")]
    ModeMismatch {
        mode_a: CompileMode,
        mode_b: CompileMode,
    },

    /// Too many artifacts in a result.
    #[error("too many artifacts: {count} > {max}")]
    TooManyArtifacts { count: usize, max: usize },

    /// Too many diagnostics in a result.
    #[error("too many diagnostics: {count} > {max}")]
    TooManyDiagnostics { count: usize, max: usize },

    /// Invalid configuration.
    #[error("invalid config: {reason}")]
    InvalidConfig { reason: String },
}

// ---------------------------------------------------------------------------
// classify_mismatch_severity
// ---------------------------------------------------------------------------

/// Classify the severity of a mismatch based on its kind.
pub fn classify_mismatch_severity(kind: MismatchKind) -> DiagnosticSeverity {
    match kind {
        MismatchKind::ArtifactMissing => DiagnosticSeverity::Error,
        MismatchKind::ArtifactExtra => DiagnosticSeverity::Warning,
        MismatchKind::ContentDivergence => DiagnosticSeverity::Error,
        MismatchKind::DiagnosticDivergence => DiagnosticSeverity::Warning,
        MismatchKind::SizeDivergence => DiagnosticSeverity::Info,
        MismatchKind::SourceMapDivergence => DiagnosticSeverity::Warning,
    }
}

// ---------------------------------------------------------------------------
// compute_receipt
// ---------------------------------------------------------------------------

/// Compute a decision receipt for a verification report.
pub fn compute_receipt(
    input_hash: ContentHash,
    verdict: &VerificationVerdict,
    epoch: &SecurityEpoch,
    timestamp_micros: u64,
) -> DecisionReceipt {
    let verdict_hash = ContentHash::compute(verdict.as_str().as_bytes());
    DecisionReceipt {
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

// ---------------------------------------------------------------------------
// verify_compile_parity
// ---------------------------------------------------------------------------

/// Compare two compile results and produce a verification report.
///
/// # Errors
///
/// Returns `VerificationError` if the inputs are structurally invalid
/// (e.g. same surface, different modes, capacity limits exceeded).
pub fn verify_compile_parity(
    a: &CompileResult,
    b: &CompileResult,
    config: &VerificationConfig,
    epoch: &SecurityEpoch,
    timestamp_micros: u64,
) -> Result<VerificationReport, VerificationError> {
    // Validate inputs.
    if a.surface == b.surface {
        return Err(VerificationError::SameSurface { surface: a.surface });
    }
    if a.mode != b.mode {
        return Err(VerificationError::ModeMismatch {
            mode_a: a.mode,
            mode_b: b.mode,
        });
    }
    if a.artifacts.len() > MAX_ARTIFACTS_PER_RESULT {
        return Err(VerificationError::TooManyArtifacts {
            count: a.artifacts.len(),
            max: MAX_ARTIFACTS_PER_RESULT,
        });
    }
    if b.artifacts.len() > MAX_ARTIFACTS_PER_RESULT {
        return Err(VerificationError::TooManyArtifacts {
            count: b.artifacts.len(),
            max: MAX_ARTIFACTS_PER_RESULT,
        });
    }
    if a.diagnostics.len() > MAX_DIAGNOSTICS_PER_RESULT {
        return Err(VerificationError::TooManyDiagnostics {
            count: a.diagnostics.len(),
            max: MAX_DIAGNOSTICS_PER_RESULT,
        });
    }
    if b.diagnostics.len() > MAX_DIAGNOSTICS_PER_RESULT {
        return Err(VerificationError::TooManyDiagnostics {
            count: b.diagnostics.len(),
            max: MAX_DIAGNOSTICS_PER_RESULT,
        });
    }

    // If either side failed to compile, verdict is inconclusive.
    if !a.success || !b.success {
        let input_hash = compute_input_hash(a, b);
        let verdict = VerificationVerdict::Inconclusive;
        let receipt = compute_receipt(input_hash, &verdict, epoch, timestamp_micros);
        return Ok(VerificationReport {
            result_a: a.clone(),
            result_b: b.clone(),
            mismatches: Vec::new(),
            verdict,
            receipt,
        });
    }

    let mut mismatches = Vec::new();

    // 1. Artifact parity by kind.
    compare_artifacts(a, b, config, &mut mismatches);

    // 2. Diagnostic parity.
    compare_diagnostics(a, b, config, &mut mismatches);

    // 3. Source map checks.
    check_source_maps(a, b, config, &mut mismatches);

    // Determine verdict.
    let has_error = mismatches
        .iter()
        .any(|m| m.severity == DiagnosticSeverity::Error);
    let verdict = if has_error {
        VerificationVerdict::Fail
    } else {
        VerificationVerdict::Pass
    };

    let input_hash = compute_input_hash(a, b);
    let receipt = compute_receipt(input_hash, &verdict, epoch, timestamp_micros);

    Ok(VerificationReport {
        result_a: a.clone(),
        result_b: b.clone(),
        mismatches,
        verdict,
        receipt,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn compute_input_hash(a: &CompileResult, b: &CompileResult) -> ContentHash {
    let mut h = Sha256::new();
    h.update(a.content_hash().as_bytes());
    h.update(b.content_hash().as_bytes());
    ContentHash::compute(&h.finalize())
}

/// Build a BTreeMap from ArtifactKind -> Vec<&CompileArtifact> for one result.
fn artifact_index(result: &CompileResult) -> BTreeMap<ArtifactKind, Vec<&CompileArtifact>> {
    let mut map: BTreeMap<ArtifactKind, Vec<&CompileArtifact>> = BTreeMap::new();
    for a in &result.artifacts {
        map.entry(a.kind).or_default().push(a);
    }
    map
}

fn compare_artifacts(
    a: &CompileResult,
    b: &CompileResult,
    config: &VerificationConfig,
    mismatches: &mut Vec<Mismatch>,
) {
    let idx_a = artifact_index(a);
    let idx_b = artifact_index(b);

    // Check for missing/extra artifacts.
    for kind in ArtifactKind::ALL {
        let in_a = idx_a.get(kind).map(|v| v.len()).unwrap_or(0);
        let in_b = idx_b.get(kind).map(|v| v.len()).unwrap_or(0);

        if in_a > 0 && in_b == 0 {
            mismatches.push(Mismatch {
                kind: MismatchKind::ArtifactMissing,
                surface: b.surface,
                artifact_kind: Some(*kind),
                detail: format!(
                    "{} present in {} but missing in {}",
                    kind, a.surface, b.surface
                ),
                severity: classify_mismatch_severity(MismatchKind::ArtifactMissing),
            });
        } else if in_a == 0 && in_b > 0 {
            mismatches.push(Mismatch {
                kind: MismatchKind::ArtifactExtra,
                surface: b.surface,
                artifact_kind: Some(*kind),
                detail: format!("{} present in {} but not in {}", kind, b.surface, a.surface),
                severity: classify_mismatch_severity(MismatchKind::ArtifactExtra),
            });
        }
    }

    // Content divergence: compare matching kinds.
    for kind in ArtifactKind::ALL {
        let arts_a = match idx_a.get(kind) {
            Some(v) => v,
            None => continue,
        };
        let arts_b = match idx_b.get(kind) {
            Some(v) => v,
            None => continue,
        };

        // Compare pairwise up to the min count.
        let pairs = arts_a.len().min(arts_b.len());
        for i in 0..pairs {
            let aa = arts_a[i];
            let ab = arts_b[i];

            // Content hash divergence.
            if aa.content_hash != ab.content_hash {
                mismatches.push(Mismatch {
                    kind: MismatchKind::ContentDivergence,
                    surface: b.surface,
                    artifact_kind: Some(*kind),
                    detail: format!(
                        "{} content diverges between {} and {}",
                        kind, a.surface, b.surface
                    ),
                    severity: classify_mismatch_severity(MismatchKind::ContentDivergence),
                });
            }

            // Size divergence.
            let max_size = aa.size_bytes.max(ab.size_bytes);
            if max_size > 0 {
                let diff = aa.size_bytes.abs_diff(ab.size_bytes);
                let divergence_millionths = diff
                    .saturating_mul(MILLIONTHS)
                    .checked_div(max_size)
                    .unwrap_or(0);
                if divergence_millionths > config.max_size_divergence_millionths {
                    mismatches.push(Mismatch {
                        kind: MismatchKind::SizeDivergence,
                        surface: b.surface,
                        artifact_kind: Some(*kind),
                        detail: format!(
                            "{} size divergence: {} vs {} bytes ({} millionths)",
                            kind, aa.size_bytes, ab.size_bytes, divergence_millionths
                        ),
                        severity: classify_mismatch_severity(MismatchKind::SizeDivergence),
                    });
                }
            }
        }
    }
}

fn compare_diagnostics(
    a: &CompileResult,
    b: &CompileResult,
    config: &VerificationConfig,
    mismatches: &mut Vec<Mismatch>,
) {
    if !config.require_diagnostics_parity {
        return;
    }

    // Compare diagnostic hashes.
    let hashes_a: Vec<ContentHash> = a.diagnostics.iter().map(|d| d.content_hash()).collect();
    let hashes_b: Vec<ContentHash> = b.diagnostics.iter().map(|d| d.content_hash()).collect();

    // Count divergences.
    let mut divergence_count = 0usize;

    // Diagnostics in A but not in B.
    for h in &hashes_a {
        if !hashes_b.contains(h) {
            divergence_count += 1;
        }
    }
    // Diagnostics in B but not in A.
    for h in &hashes_b {
        if !hashes_a.contains(h) {
            divergence_count += 1;
        }
    }

    if divergence_count > config.max_diagnostic_divergence {
        mismatches.push(Mismatch {
            kind: MismatchKind::DiagnosticDivergence,
            surface: b.surface,
            artifact_kind: None,
            detail: format!(
                "{} diagnostic difference(s) between {} and {} (max: {})",
                divergence_count, a.surface, b.surface, config.max_diagnostic_divergence
            ),
            severity: classify_mismatch_severity(MismatchKind::DiagnosticDivergence),
        });
    }
}

fn check_source_maps(
    a: &CompileResult,
    b: &CompileResult,
    config: &VerificationConfig,
    mismatches: &mut Vec<Mismatch>,
) {
    if !config.require_source_maps {
        return;
    }

    let a_has = a.has_source_map();
    let b_has = b.has_source_map();

    if a_has != b_has {
        let missing_surface = if a_has { b.surface } else { a.surface };
        mismatches.push(Mismatch {
            kind: MismatchKind::SourceMapDivergence,
            surface: missing_surface,
            artifact_kind: Some(ArtifactKind::SourceMap),
            detail: format!(
                "source map present on {} but missing on {}",
                if a_has { a.surface } else { b.surface },
                missing_surface
            ),
            severity: classify_mismatch_severity(MismatchKind::SourceMapDivergence),
        });
    } else if a_has && b_has {
        // Both have source maps — check content parity of first source map.
        let sm_a = a.artifacts_by_kind(ArtifactKind::SourceMap);
        let sm_b = b.artifacts_by_kind(ArtifactKind::SourceMap);
        if let (Some(sa), Some(sb)) = (sm_a.first(), sm_b.first())
            && sa.content_hash != sb.content_hash
        {
            mismatches.push(Mismatch {
                kind: MismatchKind::SourceMapDivergence,
                surface: b.surface,
                artifact_kind: Some(ArtifactKind::SourceMap),
                detail: format!(
                    "source map content diverges between {} and {}",
                    a.surface, b.surface
                ),
                severity: classify_mismatch_severity(MismatchKind::SourceMapDivergence),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/// A named verification scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationScenario {
    /// Scenario name.
    pub name: String,
    /// Result from surface A.
    pub result_a: CompileResult,
    /// Result from surface B.
    pub result_b: CompileResult,
}

/// Batch verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerificationReport {
    /// Schema version.
    pub schema_version: String,
    /// Individual reports keyed by scenario name.
    pub reports: Vec<(String, VerificationReport)>,
    /// Overall verdict.
    pub overall_verdict: VerificationVerdict,
    /// Total mismatch count.
    pub total_mismatches: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl BatchVerificationReport {
    /// Count of passing scenarios.
    pub fn pass_count(&self) -> usize {
        self.reports
            .iter()
            .filter(|(_, r)| r.verdict.is_pass())
            .count()
    }

    /// Count of failing scenarios.
    pub fn fail_count(&self) -> usize {
        self.reports
            .iter()
            .filter(|(_, r)| r.verdict.is_fail())
            .count()
    }

    /// Pass rate in millionths.
    pub fn pass_rate(&self) -> u64 {
        let total = self.reports.len() as u64;
        if total == 0 {
            return 0;
        }
        (self.pass_count() as u64)
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    }
}

/// Run parity verification across a batch of scenarios.
pub fn verify_batch(
    scenarios: &[VerificationScenario],
    config: &VerificationConfig,
    epoch: &SecurityEpoch,
    base_timestamp: u64,
) -> Result<BatchVerificationReport, VerificationError> {
    let mut reports = Vec::new();
    let mut total_mismatches = 0usize;
    let mut any_fail = false;
    let mut any_inconclusive = false;

    for (i, scenario) in scenarios.iter().enumerate() {
        let ts = base_timestamp.saturating_add(i as u64);
        let report =
            verify_compile_parity(&scenario.result_a, &scenario.result_b, config, epoch, ts)?;
        total_mismatches += report.mismatches.len();
        if report.verdict.is_fail() {
            any_fail = true;
        }
        if report.verdict == VerificationVerdict::Inconclusive {
            any_inconclusive = true;
        }
        reports.push((scenario.name.clone(), report));
    }

    let overall_verdict = if any_fail {
        VerificationVerdict::Fail
    } else if any_inconclusive {
        VerificationVerdict::Inconclusive
    } else {
        VerificationVerdict::Pass
    };

    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update((reports.len() as u64).to_le_bytes());
    for (name, r) in &reports {
        h.update(name.as_bytes());
        h.update(r.verdict.as_str().as_bytes());
    }
    let content_hash = ContentHash::compute(&h.finalize());

    Ok(BatchVerificationReport {
        schema_version: SCHEMA_VERSION.to_string(),
        reports,
        overall_verdict,
        total_mismatches,
        content_hash,
    })
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

    fn make_artifact(kind: ArtifactKind, content: &[u8]) -> CompileArtifact {
        CompileArtifact::from_content(kind, content, "test-provenance")
    }

    fn make_diagnostic(msg: &str, severity: DiagnosticSeverity) -> CompileDiagnostic {
        CompileDiagnostic {
            message: msg.to_string(),
            severity,
            line: 1,
            column: 1,
            source_range: (0, 10),
        }
    }

    fn library_result(
        artifacts: Vec<CompileArtifact>,
        diagnostics: Vec<CompileDiagnostic>,
    ) -> CompileResult {
        CompileResult {
            surface: CompileSurface::Library,
            mode: CompileMode::Automatic,
            artifacts,
            diagnostics,
            success: true,
            duration_micros: 1000,
        }
    }

    fn cli_result(
        artifacts: Vec<CompileArtifact>,
        diagnostics: Vec<CompileDiagnostic>,
    ) -> CompileResult {
        CompileResult {
            surface: CompileSurface::CliShipped,
            mode: CompileMode::Automatic,
            artifacts,
            diagnostics,
            success: true,
            duration_micros: 1200,
        }
    }

    fn default_config() -> VerificationConfig {
        VerificationConfig::default()
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "react_compile_verification");
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
    fn default_size_divergence_valid() {
        const { assert!(DEFAULT_MAX_SIZE_DIVERGENCE <= MILLIONTHS) };
    }

    // --- CompileMode ---

    #[test]
    fn compile_mode_all_count() {
        assert_eq!(CompileMode::ALL.len(), 2);
    }

    #[test]
    fn compile_mode_as_str_unique() {
        let strs: Vec<_> = CompileMode::ALL.iter().map(|m| m.as_str()).collect();
        assert_ne!(strs[0], strs[1]);
    }

    #[test]
    fn compile_mode_display() {
        for m in CompileMode::ALL {
            assert_eq!(m.to_string(), m.as_str());
        }
    }

    #[test]
    fn compile_mode_serde_roundtrip() {
        for m in CompileMode::ALL {
            let json = serde_json::to_string(m).unwrap();
            let back: CompileMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, back);
        }
    }

    // --- ArtifactKind ---

    #[test]
    fn artifact_kind_all_count() {
        assert_eq!(ArtifactKind::ALL.len(), 5);
    }

    #[test]
    fn artifact_kind_as_str_unique() {
        let mut strs: Vec<_> = ArtifactKind::ALL.iter().map(|k| k.as_str()).collect();
        strs.sort();
        strs.dedup();
        assert_eq!(strs.len(), ArtifactKind::ALL.len());
    }

    #[test]
    fn artifact_kind_display() {
        for k in ArtifactKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn artifact_kind_serde() {
        for k in ArtifactKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ArtifactKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- DiagnosticSeverity ---

    #[test]
    fn diagnostic_severity_all_count() {
        assert_eq!(DiagnosticSeverity::ALL.len(), 4);
    }

    #[test]
    fn diagnostic_severity_display() {
        for s in DiagnosticSeverity::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn diagnostic_severity_serde() {
        for s in DiagnosticSeverity::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn diagnostic_severity_weights_ascending() {
        let weights: Vec<u64> = DiagnosticSeverity::ALL.iter().map(|s| s.weight()).collect();
        for w in weights.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn diagnostic_severity_weight_bounds() {
        for s in DiagnosticSeverity::ALL {
            assert!(s.weight() > 0);
            assert!(s.weight() <= MILLIONTHS);
        }
    }

    // --- CompileSurface ---

    #[test]
    fn compile_surface_all_count() {
        assert_eq!(CompileSurface::ALL.len(), 2);
    }

    #[test]
    fn compile_surface_display() {
        for s in CompileSurface::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn compile_surface_serde() {
        for s in CompileSurface::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CompileSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- MismatchKind ---

    #[test]
    fn mismatch_kind_all_count() {
        assert_eq!(MismatchKind::ALL.len(), 6);
    }

    #[test]
    fn mismatch_kind_as_str_unique() {
        let mut strs: Vec<_> = MismatchKind::ALL.iter().map(|k| k.as_str()).collect();
        strs.sort();
        strs.dedup();
        assert_eq!(strs.len(), MismatchKind::ALL.len());
    }

    #[test]
    fn mismatch_kind_display() {
        for k in MismatchKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn mismatch_kind_serde() {
        for k in MismatchKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: MismatchKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- VerificationVerdict ---

    #[test]
    fn verdict_all_count() {
        assert_eq!(VerificationVerdict::ALL.len(), 3);
    }

    #[test]
    fn verdict_display() {
        for v in VerificationVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn verdict_serde() {
        for v in VerificationVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: VerificationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn verdict_pass_is_pass() {
        assert!(VerificationVerdict::Pass.is_pass());
        assert!(!VerificationVerdict::Fail.is_pass());
        assert!(!VerificationVerdict::Inconclusive.is_pass());
    }

    #[test]
    fn verdict_fail_is_fail() {
        assert!(VerificationVerdict::Fail.is_fail());
        assert!(!VerificationVerdict::Pass.is_fail());
    }

    // --- CompileDiagnostic ---

    #[test]
    fn diagnostic_hash_deterministic() {
        let d1 = make_diagnostic("test", DiagnosticSeverity::Warning);
        let d2 = make_diagnostic("test", DiagnosticSeverity::Warning);
        assert_eq!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn diagnostic_hash_varies_with_message() {
        let d1 = make_diagnostic("alpha", DiagnosticSeverity::Warning);
        let d2 = make_diagnostic("beta", DiagnosticSeverity::Warning);
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn diagnostic_display_includes_severity() {
        let d = make_diagnostic("bad thing", DiagnosticSeverity::Error);
        let s = d.to_string();
        assert!(s.contains("error"));
        assert!(s.contains("bad thing"));
    }

    #[test]
    fn diagnostic_serde_roundtrip() {
        let d = make_diagnostic("hello", DiagnosticSeverity::Info);
        let json = serde_json::to_string(&d).unwrap();
        let back: CompileDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- CompileArtifact ---

    #[test]
    fn artifact_from_content_size() {
        let data = b"hello world";
        let a = CompileArtifact::from_content(ArtifactKind::CompiledOutput, data, "test");
        assert_eq!(a.size_bytes, data.len() as u64);
    }

    #[test]
    fn artifact_from_content_hash_deterministic() {
        let a1 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map", "test");
        let a2 = CompileArtifact::from_content(ArtifactKind::SourceMap, b"map", "test");
        assert_eq!(a1.content_hash, a2.content_hash);
    }

    #[test]
    fn artifact_serde_roundtrip() {
        let a = make_artifact(ArtifactKind::BundleManifest, b"manifest");
        let json = serde_json::to_string(&a).unwrap();
        let back: CompileArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- CompileResult ---

    #[test]
    fn result_artifacts_by_kind() {
        let r = library_result(
            vec![
                make_artifact(ArtifactKind::CompiledOutput, b"js"),
                make_artifact(ArtifactKind::SourceMap, b"map"),
                make_artifact(ArtifactKind::CompiledOutput, b"js2"),
            ],
            vec![],
        );
        assert_eq!(r.artifacts_by_kind(ArtifactKind::CompiledOutput).len(), 2);
        assert_eq!(r.artifacts_by_kind(ArtifactKind::SourceMap).len(), 1);
        assert_eq!(r.artifacts_by_kind(ArtifactKind::BundleManifest).len(), 0);
    }

    #[test]
    fn result_has_source_map() {
        let r = library_result(vec![make_artifact(ArtifactKind::SourceMap, b"map")], vec![]);
        assert!(r.has_source_map());
    }

    #[test]
    fn result_no_source_map() {
        let r = library_result(vec![], vec![]);
        assert!(!r.has_source_map());
    }

    #[test]
    fn result_diagnostic_count() {
        let r = library_result(
            vec![],
            vec![
                make_diagnostic("a", DiagnosticSeverity::Warning),
                make_diagnostic("b", DiagnosticSeverity::Error),
                make_diagnostic("c", DiagnosticSeverity::Warning),
            ],
        );
        assert_eq!(r.diagnostic_count(DiagnosticSeverity::Warning), 2);
        assert_eq!(r.diagnostic_count(DiagnosticSeverity::Error), 1);
        assert_eq!(r.diagnostic_count(DiagnosticSeverity::Info), 0);
    }

    #[test]
    fn result_total_artifact_size() {
        let r = library_result(
            vec![
                make_artifact(ArtifactKind::CompiledOutput, b"abc"),
                make_artifact(ArtifactKind::SourceMap, b"de"),
            ],
            vec![],
        );
        assert_eq!(r.total_artifact_size(), 5);
    }

    #[test]
    fn result_content_hash_deterministic() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
        let diags = vec![make_diagnostic("w", DiagnosticSeverity::Warning)];
        let r1 = library_result(arts.clone(), diags.clone());
        let r2 = library_result(arts, diags);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn result_serde_roundtrip() {
        let r = library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"code")],
            vec![make_diagnostic("w", DiagnosticSeverity::Warning)],
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: CompileResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- VerificationConfig ---

    #[test]
    fn config_default() {
        let c = VerificationConfig::default();
        assert_eq!(
            c.max_size_divergence_millionths,
            DEFAULT_MAX_SIZE_DIVERGENCE
        );
        assert!(c.require_source_maps);
        assert!(c.require_diagnostics_parity);
        assert_eq!(
            c.max_diagnostic_divergence,
            DEFAULT_MAX_DIAGNOSTIC_DIVERGENCE
        );
    }

    #[test]
    fn config_strict() {
        let c = VerificationConfig::strict();
        assert_eq!(c.max_size_divergence_millionths, 0);
    }

    #[test]
    fn config_permissive() {
        let c = VerificationConfig::permissive();
        assert!(c.max_size_divergence_millionths > DEFAULT_MAX_SIZE_DIVERGENCE);
        assert!(!c.require_source_maps);
        assert!(!c.require_diagnostics_parity);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = default_config();
        let json = serde_json::to_string(&c).unwrap();
        let back: VerificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- classify_mismatch_severity ---

    #[test]
    fn classify_artifact_missing_error() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::ArtifactMissing),
            DiagnosticSeverity::Error
        );
    }

    #[test]
    fn classify_artifact_extra_warning() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::ArtifactExtra),
            DiagnosticSeverity::Warning
        );
    }

    #[test]
    fn classify_content_divergence_error() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::ContentDivergence),
            DiagnosticSeverity::Error
        );
    }

    #[test]
    fn classify_diagnostic_divergence_warning() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::DiagnosticDivergence),
            DiagnosticSeverity::Warning
        );
    }

    #[test]
    fn classify_size_divergence_info() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::SizeDivergence),
            DiagnosticSeverity::Info
        );
    }

    #[test]
    fn classify_source_map_divergence_warning() {
        assert_eq!(
            classify_mismatch_severity(MismatchKind::SourceMapDivergence),
            DiagnosticSeverity::Warning
        );
    }

    // --- verify_compile_parity ---

    #[test]
    fn parity_identical_pass() {
        let arts = vec![
            make_artifact(ArtifactKind::CompiledOutput, b"code"),
            make_artifact(ArtifactKind::SourceMap, b"map"),
        ];
        let a = library_result(arts.clone(), vec![]);
        let b = cli_result(arts, vec![]);
        let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 100).unwrap();
        assert_eq!(report.verdict, VerificationVerdict::Pass);
        assert!(report.mismatches.is_empty());
    }

    #[test]
    fn parity_same_surface_error() {
        let a = library_result(vec![], vec![]);
        let b = library_result(vec![], vec![]);
        let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
        assert!(matches!(err, VerificationError::SameSurface { .. }));
    }

    #[test]
    fn parity_mode_mismatch_error() {
        let a = library_result(vec![], vec![]);
        let mut b = cli_result(vec![], vec![]);
        b.mode = CompileMode::Classic;
        let err = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap_err();
        assert!(matches!(err, VerificationError::ModeMismatch { .. }));
    }

    #[test]
    fn parity_compile_failure_inconclusive() {
        let a = library_result(vec![], vec![]);
        let mut b = cli_result(vec![], vec![]);
        b.success = false;
        let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
        assert_eq!(report.verdict, VerificationVerdict::Inconclusive);
    }

    #[test]
    fn parity_artifact_missing_fail() {
        let a = library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"code")],
            vec![],
        );
        let b = cli_result(vec![], vec![]);
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.verdict, VerificationVerdict::Fail);
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::ArtifactMissing)
        );
    }

    #[test]
    fn parity_artifact_extra_pass() {
        // Extra artifact is warning-level, should still pass.
        let a = library_result(vec![], vec![]);
        let b = cli_result(
            vec![make_artifact(ArtifactKind::BundleManifest, b"m")],
            vec![],
        );
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.verdict, VerificationVerdict::Pass);
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::ArtifactExtra)
        );
    }

    #[test]
    fn parity_content_divergence_fail() {
        let a = library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"code_a")],
            vec![],
        );
        let b = cli_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"code_b")],
            vec![],
        );
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.verdict, VerificationVerdict::Fail);
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::ContentDivergence)
        );
    }

    #[test]
    fn parity_size_divergence_pass_with_info() {
        // 100 vs 200 bytes = 50% divergence, but default threshold is 5%
        let a = library_result(
            vec![CompileArtifact {
                kind: ArtifactKind::CompiledOutput,
                content_hash: ContentHash::compute(b"a"),
                size_bytes: 100,
                provenance: "test".into(),
            }],
            vec![],
        );
        let b = cli_result(
            vec![CompileArtifact {
                kind: ArtifactKind::CompiledOutput,
                content_hash: ContentHash::compute(b"a"),
                size_bytes: 200,
                provenance: "test".into(),
            }],
            vec![],
        );
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        // Size divergence is info-level, doesn't cause fail.
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::SizeDivergence)
        );
        assert_eq!(report.verdict, VerificationVerdict::Pass);
    }

    #[test]
    fn parity_diagnostic_divergence() {
        let a = library_result(
            vec![],
            vec![make_diagnostic("warning A", DiagnosticSeverity::Warning)],
        );
        let b = cli_result(
            vec![],
            vec![make_diagnostic("warning B", DiagnosticSeverity::Warning)],
        );
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::DiagnosticDivergence)
        );
    }

    #[test]
    fn parity_source_map_missing_one_side() {
        let a = library_result(vec![make_artifact(ArtifactKind::SourceMap, b"map")], vec![]);
        let b = cli_result(vec![], vec![]);
        let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::SourceMapDivergence)
        );
    }

    #[test]
    fn parity_source_map_content_divergence() {
        let a = library_result(
            vec![make_artifact(ArtifactKind::SourceMap, b"map_a")],
            vec![],
        );
        let b = cli_result(
            vec![make_artifact(ArtifactKind::SourceMap, b"map_b")],
            vec![],
        );
        let report = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
        assert!(
            report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::SourceMapDivergence)
        );
    }

    #[test]
    fn parity_source_maps_not_required_no_divergence() {
        let a = library_result(vec![], vec![]);
        let b = cli_result(vec![], vec![]);
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert!(
            !report
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::SourceMapDivergence)
        );
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_hash_deterministic() {
        let r1 = compute_receipt(
            ContentHash::compute(b"input"),
            &VerificationVerdict::Pass,
            &epoch(),
            100,
        );
        let r2 = compute_receipt(
            ContentHash::compute(b"input"),
            &VerificationVerdict::Pass,
            &epoch(),
            100,
        );
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn receipt_has_correct_fields() {
        let r = compute_receipt(
            ContentHash::compute(b"in"),
            &VerificationVerdict::Fail,
            &epoch(),
            999,
        );
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.bead_id, BEAD_ID);
        assert_eq!(r.policy_id, POLICY_ID);
        assert_eq!(r.epoch.as_u64(), 42);
        assert_eq!(r.timestamp_micros, 999);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let r = compute_receipt(
            ContentHash::compute(b"test"),
            &VerificationVerdict::Pass,
            &epoch(),
            0,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- VerificationReport ---

    #[test]
    fn report_mismatch_count_by_kind() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
        let a = library_result(arts.clone(), vec![]);
        let b = cli_result(vec![], vec![]);
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert!(report.mismatch_count_by_kind(MismatchKind::ArtifactMissing) > 0);
    }

    #[test]
    fn report_weighted_score() {
        let a = library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
            vec![],
        );
        let b = cli_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"b")],
            vec![],
        );
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert!(report.weighted_score() > 0);
    }

    #[test]
    fn report_has_errors_when_fail() {
        let a = library_result(
            vec![make_artifact(ArtifactKind::CompiledOutput, b"a")],
            vec![],
        );
        let b = cli_result(vec![], vec![]);
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_compile_parity(&a, &b, &cfg, &epoch(), 0).unwrap();
        assert!(report.has_errors());
    }

    #[test]
    fn report_content_hash_deterministic() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
        let a = library_result(arts.clone(), vec![]);
        let b = cli_result(arts, vec![]);
        let r1 = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
        let r2 = verify_compile_parity(&a, &b, &default_config(), &epoch(), 0).unwrap();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    // --- Mismatch ---

    #[test]
    fn mismatch_content_hash_deterministic() {
        let m1 = Mismatch {
            kind: MismatchKind::ContentDivergence,
            surface: CompileSurface::Library,
            artifact_kind: Some(ArtifactKind::CompiledOutput),
            detail: "test".into(),
            severity: DiagnosticSeverity::Error,
        };
        let m2 = m1.clone();
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn mismatch_display() {
        let m = Mismatch {
            kind: MismatchKind::ArtifactMissing,
            surface: CompileSurface::CliShipped,
            artifact_kind: Some(ArtifactKind::SourceMap),
            detail: "missing source map".into(),
            severity: DiagnosticSeverity::Error,
        };
        let s = m.to_string();
        assert!(s.contains("error"));
        assert!(s.contains("artifact_missing"));
    }

    #[test]
    fn mismatch_serde_roundtrip() {
        let m = Mismatch {
            kind: MismatchKind::SizeDivergence,
            surface: CompileSurface::Library,
            artifact_kind: None,
            detail: "size off".into(),
            severity: DiagnosticSeverity::Info,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Mismatch = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // --- Batch verification ---

    #[test]
    fn batch_empty_pass() {
        let report = verify_batch(&[], &default_config(), &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, VerificationVerdict::Pass);
        assert_eq!(report.total_mismatches, 0);
    }

    #[test]
    fn batch_single_pass() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"code")];
        let scenario = VerificationScenario {
            name: "s1".into(),
            result_a: library_result(arts.clone(), vec![]),
            result_b: cli_result(arts, vec![]),
        };
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_batch(&[scenario], &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, VerificationVerdict::Pass);
        assert_eq!(report.pass_count(), 1);
        assert_eq!(report.fail_count(), 0);
    }

    #[test]
    fn batch_mixed_verdicts() {
        let s_pass = VerificationScenario {
            name: "pass".into(),
            result_a: library_result(vec![], vec![]),
            result_b: cli_result(vec![], vec![]),
        };
        let s_fail = VerificationScenario {
            name: "fail".into(),
            result_a: library_result(
                vec![make_artifact(ArtifactKind::CompiledOutput, b"x")],
                vec![],
            ),
            result_b: cli_result(vec![], vec![]),
        };
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_batch(&[s_pass, s_fail], &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.overall_verdict, VerificationVerdict::Fail);
        assert_eq!(report.pass_count(), 1);
        assert_eq!(report.fail_count(), 1);
    }

    #[test]
    fn batch_pass_rate() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"c")];
        let scenarios: Vec<_> = (0..4)
            .map(|i| VerificationScenario {
                name: format!("s{i}"),
                result_a: library_result(arts.clone(), vec![]),
                result_b: cli_result(arts.clone(), vec![]),
            })
            .collect();
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let report = verify_batch(&scenarios, &cfg, &epoch(), 0).unwrap();
        assert_eq!(report.pass_rate(), 1_000_000);
    }

    #[test]
    fn batch_content_hash_deterministic() {
        let arts = vec![make_artifact(ArtifactKind::CompiledOutput, b"c")];
        let scenarios = vec![VerificationScenario {
            name: "s1".into(),
            result_a: library_result(arts.clone(), vec![]),
            result_b: cli_result(arts, vec![]),
        }];
        let cfg = VerificationConfig {
            require_source_maps: false,
            ..default_config()
        };
        let r1 = verify_batch(&scenarios, &cfg, &epoch(), 0).unwrap();
        let r2 = verify_batch(&scenarios, &cfg, &epoch(), 0).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // --- VerificationError ---

    #[test]
    fn error_same_surface_display() {
        let e = VerificationError::SameSurface {
            surface: CompileSurface::Library,
        };
        let s = e.to_string();
        assert!(s.contains("same surface"));
        assert!(s.contains("library"));
    }

    #[test]
    fn error_mode_mismatch_display() {
        let e = VerificationError::ModeMismatch {
            mode_a: CompileMode::Classic,
            mode_b: CompileMode::Automatic,
        };
        let s = e.to_string();
        assert!(s.contains("mode mismatch"));
    }

    #[test]
    fn error_too_many_artifacts_display() {
        let e = VerificationError::TooManyArtifacts {
            count: 2000,
            max: 1000,
        };
        let s = e.to_string();
        assert!(s.contains("too many artifacts"));
    }

    #[test]
    fn error_too_many_diagnostics_display() {
        let e = VerificationError::TooManyDiagnostics {
            count: 20000,
            max: 10000,
        };
        let s = e.to_string();
        assert!(s.contains("too many diagnostics"));
    }

    #[test]
    fn error_invalid_config_display() {
        let e = VerificationError::InvalidConfig {
            reason: "bad".into(),
        };
        let s = e.to_string();
        assert!(s.contains("invalid config"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            VerificationError::SameSurface {
                surface: CompileSurface::CliShipped,
            },
            VerificationError::ModeMismatch {
                mode_a: CompileMode::Classic,
                mode_b: CompileMode::Automatic,
            },
            VerificationError::TooManyArtifacts { count: 5, max: 3 },
            VerificationError::TooManyDiagnostics { count: 5, max: 3 },
            VerificationError::InvalidConfig {
                reason: "test".into(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: VerificationError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }
}
