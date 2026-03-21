//! Shipped-path parity verifier for internal eval APIs and frankenctl.
//!
//! Compares internal library entrypoints with frankenctl CLI command surfaces
//! for the same workloads, producing detailed divergence classification and
//! evidence artifacts. The goal is to ensure the API and CLI surfaces agree
//! on semantics for every supported input.
//!
//! ## Design
//!
//! - **Command families**: core frankenctl verbs (compile, run, verify,
//!   benchmark, replay) each with library and CLI entrypoints.
//! - **Input matrix**: JS and TS inputs exercised across every command family
//!   with detailed per-cell parity status.
//! - **Divergence taxonomy**: classify mismatches by type, severity, and
//!   whether they affect user-visible behavior.
//! - **Evidence artifacts**: structured reports with deterministic hashes
//!   for evidence-ledger integration.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.9, bd-1lsy.9.6 (RGC-806).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "shipped_path_parity_verifier";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.shipped-path-parity-verifier.v1";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.6";

/// Maximum test cases per command family.
pub const MAX_CASES_PER_FAMILY: usize = 500;

/// Maximum total parity matrix entries.
pub const MAX_MATRIX_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Command family taxonomy
// ---------------------------------------------------------------------------

/// Core frankenctl command families with paired library entrypoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandFamily {
    /// compile: parse and lower source to artifact.
    Compile,
    /// run: execute source through orchestrator.
    Run,
    /// verify: validate artifact integrity.
    Verify,
    /// benchmark: run benchmark families.
    Benchmark,
    /// replay: replay captured traces.
    Replay,
    /// doctor: runtime diagnostics.
    Doctor,
}

impl CommandFamily {
    /// All command families in deterministic order.
    pub const ALL: &'static [Self] = &[
        Self::Compile,
        Self::Run,
        Self::Verify,
        Self::Benchmark,
        Self::Replay,
        Self::Doctor,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Run => "run",
            Self::Verify => "verify",
            Self::Benchmark => "benchmark",
            Self::Replay => "replay",
            Self::Doctor => "doctor",
        }
    }

    /// Description of what this command family exercises.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Compile => "Parse and lower source into a versioned compile artifact",
            Self::Run => "Execute source through the orchestrator and emit execution report",
            Self::Verify => "Validate artifact integrity and schema invariants",
            Self::Benchmark => "Run benchmark families and emit evidence artifacts",
            Self::Replay => "Replay captured nondeterminism traces",
            Self::Doctor => "Summarize runtime diagnostics and emit operator artifacts",
        }
    }
}

impl fmt::Display for CommandFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Entrypoint surface
// ---------------------------------------------------------------------------

/// Surface through which the command was invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointSurface {
    /// Internal library API (Rust function call).
    LibraryApi,
    /// frankenctl CLI binary.
    FrankenctlCli,
}

impl EntrypointSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LibraryApi => "library_api",
            Self::FrankenctlCli => "frankenctl_cli",
        }
    }
}

impl fmt::Display for EntrypointSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Input language
// ---------------------------------------------------------------------------

/// Input language type for parity testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityInputLanguage {
    JavaScript,
    TypeScript,
    Jsx,
    Tsx,
}

impl ParityInputLanguage {
    pub const ALL: &'static [Self] = &[Self::JavaScript, Self::TypeScript, Self::Jsx, Self::Tsx];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
        }
    }
}

impl fmt::Display for ParityInputLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Execution outcome
// ---------------------------------------------------------------------------

/// Outcome of running a workload through an entrypoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Completed successfully with output.
    Success {
        output_hash: ContentHash,
        artifact_hash: Option<ContentHash>,
    },
    /// Failed with an error.
    Error {
        error_code: String,
        error_message: String,
    },
    /// Timed out.
    Timeout { elapsed_millis: u64 },
    /// Crashed or was killed.
    Crash { signal: Option<i32> },
    /// Unsupported (command not available on this surface).
    Unsupported { reason: String },
}

impl ExecutionOutcome {
    /// Whether this outcome represents successful execution.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Whether this outcome represents an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

// ---------------------------------------------------------------------------
// Parity result
// ---------------------------------------------------------------------------

/// Classification of a parity divergence between surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityStatus {
    /// Both surfaces produce identical output.
    Identical,
    /// Both surfaces produce semantically equivalent output (formatting differs).
    SemanticEquivalent,
    /// CLI adds extra metadata not present in library output.
    CliExtraMetadata,
    /// Library produces different artifact schema than CLI.
    ArtifactSchemaDrift,
    /// One surface succeeds while the other fails.
    SuccessFailureSplit,
    /// Both fail but with different error codes.
    ErrorCodeDivergence,
    /// Both fail but with different error messages.
    ErrorMessageDivergence,
    /// One surface times out while the other completes.
    TimeoutDivergence,
    /// One surface crashes while the other completes.
    CrashDivergence,
    /// Surface does not support this command family.
    UnsupportedOnSurface,
}

impl ParityStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::SemanticEquivalent => "semantic_equivalent",
            Self::CliExtraMetadata => "cli_extra_metadata",
            Self::ArtifactSchemaDrift => "artifact_schema_drift",
            Self::SuccessFailureSplit => "success_failure_split",
            Self::ErrorCodeDivergence => "error_code_divergence",
            Self::ErrorMessageDivergence => "error_message_divergence",
            Self::TimeoutDivergence => "timeout_divergence",
            Self::CrashDivergence => "crash_divergence",
            Self::UnsupportedOnSurface => "unsupported_on_surface",
        }
    }

    /// Whether this status represents acceptable parity.
    pub const fn is_acceptable(self) -> bool {
        matches!(
            self,
            Self::Identical | Self::SemanticEquivalent | Self::CliExtraMetadata
        )
    }

    /// Severity weight for aggregate scoring (millionths).
    pub const fn severity_millionths(self) -> u64 {
        match self {
            Self::Identical => 0,
            Self::SemanticEquivalent => 5_000,
            Self::CliExtraMetadata => 10_000,
            Self::ArtifactSchemaDrift => 200_000,
            Self::SuccessFailureSplit => 1_000_000,
            Self::ErrorCodeDivergence => 300_000,
            Self::ErrorMessageDivergence => 50_000,
            Self::TimeoutDivergence => 700_000,
            Self::CrashDivergence => 900_000,
            Self::UnsupportedOnSurface => 0,
        }
    }
}

impl fmt::Display for ParityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Parity test case
// ---------------------------------------------------------------------------

/// A single parity test comparing library and CLI output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParityTestCase {
    /// Unique case identifier.
    pub id: String,
    /// Command family being tested.
    pub command_family: CommandFamily,
    /// Input language.
    pub language: ParityInputLanguage,
    /// Input description (what the workload does).
    pub input_description: String,
    /// Content hash of the input source.
    pub input_hash: ContentHash,
    /// Library API outcome.
    pub library_outcome: ExecutionOutcome,
    /// frankenctl CLI outcome.
    pub cli_outcome: ExecutionOutcome,
    /// Parity classification.
    pub parity_status: ParityStatus,
    /// Divergence details (if any).
    pub divergence_details: String,
    /// Evidence artifact path.
    pub evidence_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Parity matrix
// ---------------------------------------------------------------------------

/// Cell key for the parity matrix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MatrixCellKey {
    pub command_family: CommandFamily,
    pub language: ParityInputLanguage,
}

/// Summary of parity for a single matrix cell (command x language).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCellSummary {
    /// Cell key.
    pub key: MatrixCellKey,
    /// Total test cases for this cell.
    pub total_cases: usize,
    /// Cases with acceptable parity.
    pub acceptable_count: usize,
    /// Cases with unacceptable divergence.
    pub unacceptable_count: usize,
    /// Parity rate (millionths).
    pub parity_rate_millionths: u64,
    /// Status distribution (Vec instead of BTreeMap because ParityStatus
    /// is not a string and JSON serde requires string keys).
    pub status_distribution: Vec<(ParityStatus, usize)>,
}

/// The shipped-path parity matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityMatrix {
    /// Schema version.
    pub version: String,
    /// All test cases.
    pub test_cases: Vec<ParityTestCase>,
    /// Per-cell summaries (Vec instead of BTreeMap because MatrixCellKey
    /// is not a string and JSON serde requires string keys).
    pub cell_summaries: Vec<MatrixCellSummary>,
}

impl ParityMatrix {
    /// Create a new empty parity matrix.
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            test_cases: Vec::new(),
            cell_summaries: Vec::new(),
        }
    }

    /// Add a test case.
    pub fn add_case(&mut self, case: ParityTestCase) -> Result<(), VerifierError> {
        if self.test_cases.len() >= MAX_MATRIX_SIZE {
            return Err(VerifierError::MatrixOverflow {
                max: MAX_MATRIX_SIZE,
                attempted: self.test_cases.len() + 1,
            });
        }
        // Check for duplicate IDs
        if self.test_cases.iter().any(|c| c.id == case.id) {
            return Err(VerifierError::DuplicateCase {
                id: case.id.clone(),
            });
        }
        self.test_cases.push(case);
        self.recompute_summaries();
        Ok(())
    }

    /// Number of test cases.
    pub fn case_count(&self) -> usize {
        self.test_cases.len()
    }

    /// Number of cells with at least one test case.
    pub fn covered_cell_count(&self) -> usize {
        self.cell_summaries.len()
    }

    /// Total possible cells (command families x languages).
    pub fn total_possible_cells() -> usize {
        CommandFamily::ALL.len() * ParityInputLanguage::ALL.len()
    }

    /// Cells with no test coverage.
    pub fn uncovered_cells(&self) -> Vec<MatrixCellKey> {
        let mut uncovered = Vec::new();
        for family in CommandFamily::ALL {
            for lang in ParityInputLanguage::ALL {
                let key = MatrixCellKey {
                    command_family: *family,
                    language: *lang,
                };
                if !self.cell_summaries.iter().any(|s| s.key == key) {
                    uncovered.push(key);
                }
            }
        }
        uncovered
    }

    /// Cases with unacceptable parity.
    pub fn unacceptable_cases(&self) -> Vec<&ParityTestCase> {
        self.test_cases
            .iter()
            .filter(|c| !c.parity_status.is_acceptable())
            .collect()
    }

    /// Compute a deterministic content hash over the matrix.
    pub fn content_hash(&self) -> ContentHash {
        let mut entries = Vec::new();
        for case in &self.test_cases {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                ("id".to_string(), CanonicalValue::String(case.id.clone())),
                (
                    "command".to_string(),
                    CanonicalValue::String(case.command_family.as_str().to_string()),
                ),
                (
                    "language".to_string(),
                    CanonicalValue::String(case.language.as_str().to_string()),
                ),
                (
                    "parity".to_string(),
                    CanonicalValue::String(case.parity_status.as_str().to_string()),
                ),
            ])));
        }
        let canonical = CanonicalValue::Array(entries);
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }

    /// Recompute cell summaries from test cases.
    fn recompute_summaries(&mut self) {
        // Use a temporary BTreeMap for accumulation, then flatten to Vec
        let mut map: BTreeMap<MatrixCellKey, MatrixCellSummary> = BTreeMap::new();
        for case in &self.test_cases {
            let key = MatrixCellKey {
                command_family: case.command_family,
                language: case.language,
            };
            let summary = map.entry(key.clone()).or_insert_with(|| MatrixCellSummary {
                key,
                total_cases: 0,
                acceptable_count: 0,
                unacceptable_count: 0,
                parity_rate_millionths: 0,
                status_distribution: Vec::new(),
            });
            summary.total_cases += 1;
            if case.parity_status.is_acceptable() {
                summary.acceptable_count += 1;
            } else {
                summary.unacceptable_count += 1;
            }
            if let Some(entry) = summary
                .status_distribution
                .iter_mut()
                .find(|(s, _)| *s == case.parity_status)
            {
                entry.1 += 1;
            } else {
                summary.status_distribution.push((case.parity_status, 1));
            }
            // Recompute rate
            summary.parity_rate_millionths = (summary.acceptable_count as u64)
                .saturating_mul(1_000_000)
                .checked_div(summary.total_cases as u64)
                .unwrap_or(0);
        }
        self.cell_summaries = map.into_values().collect();
    }
}

impl Default for ParityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Verifier configuration
// ---------------------------------------------------------------------------

/// Configuration for the parity verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Minimum cell coverage ratio (millionths) to pass the gate.
    pub min_coverage_ratio_millionths: u64,
    /// Minimum parity rate per cell (millionths).
    pub min_parity_rate_millionths: u64,
    /// Maximum acceptable divergence severity (millionths, average).
    pub max_avg_severity_millionths: u64,
    /// Required command families.
    pub required_families: BTreeSet<CommandFamily>,
    /// Required languages.
    pub required_languages: BTreeSet<ParityInputLanguage>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            min_coverage_ratio_millionths: 800_000, // 80%
            min_parity_rate_millionths: 950_000,    // 95%
            max_avg_severity_millionths: 100_000,   // 10%
            required_families: CommandFamily::ALL.iter().copied().collect(),
            required_languages: {
                let mut langs = BTreeSet::new();
                langs.insert(ParityInputLanguage::JavaScript);
                langs.insert(ParityInputLanguage::TypeScript);
                langs
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Verification verdict
// ---------------------------------------------------------------------------

/// Reason the verifier rejected the matrix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Matrix is empty.
    EmptyMatrix,
    /// Insufficient cell coverage.
    InsufficientCoverage {
        required_ratio_millionths: u64,
        actual_ratio_millionths: u64,
    },
    /// A required family has no test cases.
    MissingFamily { family: CommandFamily },
    /// A required language has no test cases.
    MissingLanguage { language: ParityInputLanguage },
    /// Cell parity rate below threshold.
    CellParityBelowThreshold {
        key: MatrixCellKey,
        rate_millionths: u64,
        threshold: u64,
    },
    /// Average divergence severity too high.
    ExcessiveSeverity {
        avg_severity_millionths: u64,
        threshold: u64,
    },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMatrix => write!(f, "parity matrix is empty"),
            Self::InsufficientCoverage {
                required_ratio_millionths,
                actual_ratio_millionths,
            } => {
                write!(
                    f,
                    "insufficient coverage: {actual_ratio_millionths}/1M < {required_ratio_millionths}/1M"
                )
            }
            Self::MissingFamily { family } => {
                write!(f, "missing required command family: {family}")
            }
            Self::MissingLanguage { language } => {
                write!(f, "missing required language: {language}")
            }
            Self::CellParityBelowThreshold {
                key,
                rate_millionths,
                threshold,
            } => {
                write!(
                    f,
                    "cell {}/{} parity {rate_millionths}/1M < {threshold}/1M",
                    key.command_family, key.language
                )
            }
            Self::ExcessiveSeverity {
                avg_severity_millionths,
                threshold,
            } => {
                write!(
                    f,
                    "excessive severity: {avg_severity_millionths}/1M > {threshold}/1M"
                )
            }
        }
    }
}

/// Verification verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierVerdict {
    /// Parity verified — surfaces agree.
    Pass,
    /// Parity failed — surfaces diverge unacceptably.
    Fail { reasons: Vec<RejectionReason> },
    /// Insufficient data to render a verdict.
    InsufficientData { reason: String },
}

impl VerifierVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for VerifierVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reasons } => write!(f, "FAIL ({} reasons)", reasons.len()),
            Self::InsufficientData { reason } => write!(f, "INSUFFICIENT_DATA: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification report
// ---------------------------------------------------------------------------

/// Full verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead reference.
    pub bead_id: String,
    /// Component.
    pub component: String,
    /// Verdict.
    pub verdict: VerifierVerdict,
    /// Matrix content hash.
    pub matrix_hash: ContentHash,
    /// Total test cases.
    pub total_cases: usize,
    /// Covered cells.
    pub covered_cells: usize,
    /// Total possible cells.
    pub total_possible_cells: usize,
    /// Coverage ratio (millionths).
    pub coverage_ratio_millionths: u64,
    /// Aggregate parity rate (millionths).
    pub aggregate_parity_rate_millionths: u64,
    /// Aggregate divergence severity (millionths).
    pub aggregate_severity_millionths: u64,
    /// Uncovered cells.
    pub uncovered_cells: Vec<MatrixCellKey>,
    /// Per-cell summaries.
    pub cell_summaries: Vec<MatrixCellSummary>,
    /// Unacceptable case count.
    pub unacceptable_case_count: usize,
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// The shipped-path parity verifier.
#[derive(Debug, Clone)]
pub struct ShippedPathParityVerifier {
    config: VerifierConfig,
}

impl ShippedPathParityVerifier {
    /// Create a verifier with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Create a verifier with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(VerifierConfig::default())
    }

    /// Verify the parity matrix and produce a report.
    pub fn verify(&self, matrix: &ParityMatrix) -> VerificationReport {
        let mut reasons = Vec::new();

        // Empty check
        if matrix.test_cases.is_empty() {
            return VerificationReport {
                schema_version: SCHEMA_VERSION.to_string(),
                bead_id: BEAD_ID.to_string(),
                component: COMPONENT.to_string(),
                verdict: VerifierVerdict::Fail {
                    reasons: vec![RejectionReason::EmptyMatrix],
                },
                matrix_hash: matrix.content_hash(),
                total_cases: 0,
                covered_cells: 0,
                total_possible_cells: ParityMatrix::total_possible_cells(),
                coverage_ratio_millionths: 0,
                aggregate_parity_rate_millionths: 0,
                aggregate_severity_millionths: 0,
                uncovered_cells: matrix.uncovered_cells(),
                cell_summaries: Vec::new(),
                unacceptable_case_count: 0,
            };
        }

        // Coverage check
        let covered = matrix.covered_cell_count();
        let total_possible = ParityMatrix::total_possible_cells();
        let coverage_ratio = (covered as u64)
            .saturating_mul(1_000_000)
            .checked_div(total_possible as u64)
            .unwrap_or(0);

        if coverage_ratio < self.config.min_coverage_ratio_millionths {
            reasons.push(RejectionReason::InsufficientCoverage {
                required_ratio_millionths: self.config.min_coverage_ratio_millionths,
                actual_ratio_millionths: coverage_ratio,
            });
        }

        // Required families check
        let covered_families: BTreeSet<CommandFamily> = matrix
            .cell_summaries
            .iter()
            .map(|s| s.key.command_family)
            .collect();
        for family in &self.config.required_families {
            if !covered_families.contains(family) {
                reasons.push(RejectionReason::MissingFamily { family: *family });
            }
        }

        // Required languages check
        let covered_languages: BTreeSet<ParityInputLanguage> = matrix
            .cell_summaries
            .iter()
            .map(|s| s.key.language)
            .collect();
        for lang in &self.config.required_languages {
            if !covered_languages.contains(lang) {
                reasons.push(RejectionReason::MissingLanguage { language: *lang });
            }
        }

        // Per-cell parity check
        for summary in &matrix.cell_summaries {
            if summary.parity_rate_millionths < self.config.min_parity_rate_millionths {
                reasons.push(RejectionReason::CellParityBelowThreshold {
                    key: summary.key.clone(),
                    rate_millionths: summary.parity_rate_millionths,
                    threshold: self.config.min_parity_rate_millionths,
                });
            }
        }

        // Aggregate severity check
        let total_severity: u64 = matrix
            .test_cases
            .iter()
            .map(|c| c.parity_status.severity_millionths())
            .sum();
        let avg_severity = total_severity
            .checked_div(matrix.test_cases.len() as u64)
            .unwrap_or(0);

        if avg_severity > self.config.max_avg_severity_millionths {
            reasons.push(RejectionReason::ExcessiveSeverity {
                avg_severity_millionths: avg_severity,
                threshold: self.config.max_avg_severity_millionths,
            });
        }

        // Aggregate parity rate
        let acceptable_count = matrix
            .test_cases
            .iter()
            .filter(|c| c.parity_status.is_acceptable())
            .count();
        let parity_rate = (acceptable_count as u64)
            .saturating_mul(1_000_000)
            .checked_div(matrix.test_cases.len() as u64)
            .unwrap_or(0);

        let unacceptable_count = matrix.unacceptable_cases().len();
        let cell_summaries: Vec<MatrixCellSummary> = matrix.cell_summaries.clone();

        let verdict = if reasons.is_empty() {
            VerifierVerdict::Pass
        } else {
            VerifierVerdict::Fail { reasons }
        };

        VerificationReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            verdict,
            matrix_hash: matrix.content_hash(),
            total_cases: matrix.case_count(),
            covered_cells: covered,
            total_possible_cells: total_possible,
            coverage_ratio_millionths: coverage_ratio,
            aggregate_parity_rate_millionths: parity_rate,
            aggregate_severity_millionths: avg_severity,
            uncovered_cells: matrix.uncovered_cells(),
            cell_summaries,
            unacceptable_case_count: unacceptable_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Parity classifier
// ---------------------------------------------------------------------------

/// Classify the parity between two execution outcomes.
pub fn classify_parity(library: &ExecutionOutcome, cli: &ExecutionOutcome) -> ParityStatus {
    match (library, cli) {
        (
            ExecutionOutcome::Success {
                output_hash: lib_hash,
                ..
            },
            ExecutionOutcome::Success {
                output_hash: cli_hash,
                ..
            },
        ) => {
            if lib_hash == cli_hash {
                ParityStatus::Identical
            } else {
                ParityStatus::ArtifactSchemaDrift
            }
        }
        (ExecutionOutcome::Success { .. }, ExecutionOutcome::Error { .. })
        | (ExecutionOutcome::Error { .. }, ExecutionOutcome::Success { .. }) => {
            ParityStatus::SuccessFailureSplit
        }
        (
            ExecutionOutcome::Error {
                error_code: lib_code,
                error_message: lib_msg,
            },
            ExecutionOutcome::Error {
                error_code: cli_code,
                error_message: cli_msg,
            },
        ) => {
            if lib_code == cli_code && lib_msg == cli_msg {
                ParityStatus::Identical
            } else if lib_code == cli_code {
                ParityStatus::ErrorMessageDivergence
            } else {
                ParityStatus::ErrorCodeDivergence
            }
        }
        (ExecutionOutcome::Timeout { .. }, ExecutionOutcome::Success { .. })
        | (ExecutionOutcome::Success { .. }, ExecutionOutcome::Timeout { .. }) => {
            ParityStatus::TimeoutDivergence
        }
        (ExecutionOutcome::Crash { .. }, _) | (_, ExecutionOutcome::Crash { .. }) => {
            ParityStatus::CrashDivergence
        }
        (ExecutionOutcome::Timeout { .. }, ExecutionOutcome::Timeout { .. }) => {
            ParityStatus::Identical
        }
        (ExecutionOutcome::Unsupported { .. }, _) | (_, ExecutionOutcome::Unsupported { .. }) => {
            ParityStatus::UnsupportedOnSurface
        }
        (ExecutionOutcome::Timeout { .. }, ExecutionOutcome::Error { .. })
        | (ExecutionOutcome::Error { .. }, ExecutionOutcome::Timeout { .. }) => {
            ParityStatus::TimeoutDivergence
        }
    }
}

// ---------------------------------------------------------------------------
// Seed matrix builder
// ---------------------------------------------------------------------------

/// Build a seed parity matrix with representative test cases.
pub fn build_seed_matrix() -> ParityMatrix {
    let mut matrix = ParityMatrix::new();
    let success_hash = ContentHash::compute(b"success_output");

    let cases = [
        (
            "compile_js",
            CommandFamily::Compile,
            ParityInputLanguage::JavaScript,
        ),
        (
            "compile_ts",
            CommandFamily::Compile,
            ParityInputLanguage::TypeScript,
        ),
        (
            "run_js",
            CommandFamily::Run,
            ParityInputLanguage::JavaScript,
        ),
        (
            "run_ts",
            CommandFamily::Run,
            ParityInputLanguage::TypeScript,
        ),
        (
            "verify_js",
            CommandFamily::Verify,
            ParityInputLanguage::JavaScript,
        ),
        (
            "verify_ts",
            CommandFamily::Verify,
            ParityInputLanguage::TypeScript,
        ),
        (
            "benchmark_js",
            CommandFamily::Benchmark,
            ParityInputLanguage::JavaScript,
        ),
        (
            "benchmark_ts",
            CommandFamily::Benchmark,
            ParityInputLanguage::TypeScript,
        ),
        (
            "replay_js",
            CommandFamily::Replay,
            ParityInputLanguage::JavaScript,
        ),
        (
            "replay_ts",
            CommandFamily::Replay,
            ParityInputLanguage::TypeScript,
        ),
        (
            "doctor_js",
            CommandFamily::Doctor,
            ParityInputLanguage::JavaScript,
        ),
        (
            "doctor_ts",
            CommandFamily::Doctor,
            ParityInputLanguage::TypeScript,
        ),
    ];

    for (id, family, lang) in &cases {
        let case = ParityTestCase {
            id: id.to_string(),
            command_family: *family,
            language: *lang,
            input_description: format!("Seed {} {} workload", family.as_str(), lang.as_str()),
            input_hash: ContentHash::compute(id.as_bytes()),
            library_outcome: ExecutionOutcome::Success {
                output_hash: success_hash,
                artifact_hash: Some(ContentHash::compute(b"artifact")),
            },
            cli_outcome: ExecutionOutcome::Success {
                output_hash: success_hash,
                artifact_hash: Some(ContentHash::compute(b"artifact")),
            },
            parity_status: ParityStatus::Identical,
            divergence_details: String::new(),
            evidence_path: None,
        };
        let _ = matrix.add_case(case);
    }
    matrix
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from the parity verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifierError {
    /// Matrix size limit exceeded.
    MatrixOverflow { max: usize, attempted: usize },
    /// Duplicate case ID.
    DuplicateCase { id: String },
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MatrixOverflow { max, attempted } => {
                write!(f, "matrix overflow: {attempted} > {max}")
            }
            Self::DuplicateCase { id } => write!(f, "duplicate case: {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_case(
        id: &str,
        family: CommandFamily,
        lang: ParityInputLanguage,
        status: ParityStatus,
    ) -> ParityTestCase {
        let hash = ContentHash::compute(b"output");
        ParityTestCase {
            id: id.to_string(),
            command_family: family,
            language: lang,
            input_description: format!("test {id}"),
            input_hash: ContentHash::compute(id.as_bytes()),
            library_outcome: ExecutionOutcome::Success {
                output_hash: hash,
                artifact_hash: None,
            },
            cli_outcome: ExecutionOutcome::Success {
                output_hash: hash,
                artifact_hash: None,
            },
            parity_status: status,
            divergence_details: String::new(),
            evidence_path: None,
        }
    }

    // --- CommandFamily tests ---

    #[test]
    fn command_family_all_has_six() {
        assert_eq!(CommandFamily::ALL.len(), 6);
    }

    #[test]
    fn command_family_as_str_roundtrip() {
        for fam in CommandFamily::ALL {
            let s = fam.as_str();
            assert!(!s.is_empty());
            assert_eq!(fam.to_string(), s);
        }
    }

    #[test]
    fn command_family_description_nonempty() {
        for fam in CommandFamily::ALL {
            assert!(!fam.description().is_empty());
        }
    }

    #[test]
    fn command_family_serde_roundtrip() {
        for fam in CommandFamily::ALL {
            let json = serde_json::to_string(fam).unwrap();
            let back: CommandFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*fam, back);
        }
    }

    // --- ParityStatus tests ---

    #[test]
    fn parity_status_acceptable() {
        assert!(ParityStatus::Identical.is_acceptable());
        assert!(ParityStatus::SemanticEquivalent.is_acceptable());
        assert!(ParityStatus::CliExtraMetadata.is_acceptable());
        assert!(!ParityStatus::SuccessFailureSplit.is_acceptable());
        assert!(!ParityStatus::CrashDivergence.is_acceptable());
    }

    #[test]
    fn parity_status_severity_ordering() {
        assert_eq!(ParityStatus::Identical.severity_millionths(), 0);
        assert!(
            ParityStatus::ErrorMessageDivergence.severity_millionths()
                < ParityStatus::SuccessFailureSplit.severity_millionths()
        );
    }

    #[test]
    fn parity_status_serde_roundtrip() {
        let status = ParityStatus::ArtifactSchemaDrift;
        let json = serde_json::to_string(&status).unwrap();
        let back: ParityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    // --- ExecutionOutcome tests ---

    #[test]
    fn outcome_success() {
        let o = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"test"),
            artifact_hash: None,
        };
        assert!(o.is_success());
        assert!(!o.is_error());
    }

    #[test]
    fn outcome_error() {
        let o = ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "test error".to_string(),
        };
        assert!(o.is_error());
        assert!(!o.is_success());
    }

    #[test]
    fn outcome_serde_roundtrip() {
        let o = ExecutionOutcome::Timeout {
            elapsed_millis: 5000,
        };
        let json = serde_json::to_string(&o).unwrap();
        let back: ExecutionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // --- ParityMatrix tests ---

    #[test]
    fn empty_matrix() {
        let matrix = ParityMatrix::new();
        assert_eq!(matrix.case_count(), 0);
        assert_eq!(matrix.covered_cell_count(), 0);
        assert_eq!(ParityMatrix::total_possible_cells(), 24); // 6 families * 4 languages
    }

    #[test]
    fn add_and_count_cases() {
        let mut matrix = ParityMatrix::new();
        matrix
            .add_case(make_case(
                "c1",
                CommandFamily::Compile,
                ParityInputLanguage::JavaScript,
                ParityStatus::Identical,
            ))
            .unwrap();
        assert_eq!(matrix.case_count(), 1);
        assert_eq!(matrix.covered_cell_count(), 1);
    }

    #[test]
    fn duplicate_case_rejected() {
        let mut matrix = ParityMatrix::new();
        matrix
            .add_case(make_case(
                "c1",
                CommandFamily::Compile,
                ParityInputLanguage::JavaScript,
                ParityStatus::Identical,
            ))
            .unwrap();
        let err = matrix
            .add_case(make_case(
                "c1",
                CommandFamily::Run,
                ParityInputLanguage::TypeScript,
                ParityStatus::Identical,
            ))
            .unwrap_err();
        assert!(matches!(err, VerifierError::DuplicateCase { .. }));
    }

    #[test]
    fn uncovered_cells() {
        let matrix = ParityMatrix::new();
        assert_eq!(matrix.uncovered_cells().len(), 24);
    }

    #[test]
    fn content_hash_deterministic() {
        let m1 = build_seed_matrix();
        let m2 = build_seed_matrix();
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn content_hash_changes_with_cases() {
        let m1 = build_seed_matrix();
        let mut m2 = build_seed_matrix();
        m2.add_case(make_case(
            "extra",
            CommandFamily::Compile,
            ParityInputLanguage::Jsx,
            ParityStatus::Identical,
        ))
        .unwrap();
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn matrix_serde_roundtrip() {
        let matrix = build_seed_matrix();
        let json = serde_json::to_string(&matrix).unwrap();
        let back: ParityMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(matrix.case_count(), back.case_count());
        assert_eq!(matrix.content_hash(), back.content_hash());
    }

    #[test]
    fn default_matrix_is_empty() {
        let matrix = ParityMatrix::default();
        assert_eq!(matrix.case_count(), 0);
    }

    // --- Seed matrix tests ---

    #[test]
    fn seed_matrix_covers_all_families() {
        let matrix = build_seed_matrix();
        let families: BTreeSet<CommandFamily> = matrix
            .cell_summaries
            .iter()
            .map(|s| s.key.command_family)
            .collect();
        assert_eq!(families.len(), 6);
    }

    #[test]
    fn seed_matrix_all_identical() {
        let matrix = build_seed_matrix();
        assert!(matrix.unacceptable_cases().is_empty());
    }

    // --- Verifier tests ---

    #[test]
    fn empty_matrix_fails() {
        let verifier = ShippedPathParityVerifier::with_defaults();
        let matrix = ParityMatrix::new();
        let report = verifier.verify(&matrix);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn seed_matrix_passes_relaxed() {
        let matrix = build_seed_matrix();
        let config = VerifierConfig {
            min_coverage_ratio_millionths: 400_000, // 40% (seed covers 50%)
            ..VerifierConfig::default()
        };
        let verifier = ShippedPathParityVerifier::new(config);
        let report = verifier.verify(&matrix);
        assert!(report.verdict.is_pass());
    }

    #[test]
    fn missing_family_fails() {
        let mut matrix = ParityMatrix::new();
        // Only add Compile cases
        matrix
            .add_case(make_case(
                "c1",
                CommandFamily::Compile,
                ParityInputLanguage::JavaScript,
                ParityStatus::Identical,
            ))
            .unwrap();
        let verifier = ShippedPathParityVerifier::with_defaults();
        let report = verifier.verify(&matrix);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn divergence_fails_gate() {
        let mut matrix = ParityMatrix::new();
        matrix
            .add_case(make_case(
                "bad",
                CommandFamily::Compile,
                ParityInputLanguage::JavaScript,
                ParityStatus::SuccessFailureSplit,
            ))
            .unwrap();
        let config = VerifierConfig {
            min_coverage_ratio_millionths: 0,
            required_families: BTreeSet::new(),
            required_languages: BTreeSet::new(),
            ..VerifierConfig::default()
        };
        let verifier = ShippedPathParityVerifier::new(config);
        let report = verifier.verify(&matrix);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn report_serde_roundtrip() {
        let verifier = ShippedPathParityVerifier::with_defaults();
        let matrix = build_seed_matrix();
        let report = verifier.verify(&matrix);
        let json = serde_json::to_string(&report).unwrap();
        let back: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_cases, back.total_cases);
    }

    // --- classify_parity tests ---

    #[test]
    fn classify_identical_success() {
        let hash = ContentHash::compute(b"same");
        let lib = ExecutionOutcome::Success {
            output_hash: hash,
            artifact_hash: None,
        };
        let cli = ExecutionOutcome::Success {
            output_hash: hash,
            artifact_hash: None,
        };
        assert_eq!(classify_parity(&lib, &cli), ParityStatus::Identical);
    }

    #[test]
    fn classify_success_failure_split() {
        let lib = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"ok"),
            artifact_hash: None,
        };
        let cli = ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "failed".to_string(),
        };
        assert_eq!(
            classify_parity(&lib, &cli),
            ParityStatus::SuccessFailureSplit
        );
    }

    #[test]
    fn classify_error_code_divergence() {
        let lib = ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "msg".to_string(),
        };
        let cli = ExecutionOutcome::Error {
            error_code: "E002".to_string(),
            error_message: "msg".to_string(),
        };
        assert_eq!(
            classify_parity(&lib, &cli),
            ParityStatus::ErrorCodeDivergence
        );
    }

    #[test]
    fn classify_error_message_divergence() {
        let lib = ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "library msg".to_string(),
        };
        let cli = ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "cli msg".to_string(),
        };
        assert_eq!(
            classify_parity(&lib, &cli),
            ParityStatus::ErrorMessageDivergence
        );
    }

    #[test]
    fn classify_timeout_divergence() {
        let lib = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"ok"),
            artifact_hash: None,
        };
        let cli = ExecutionOutcome::Timeout {
            elapsed_millis: 5000,
        };
        assert_eq!(classify_parity(&lib, &cli), ParityStatus::TimeoutDivergence);
    }

    #[test]
    fn classify_crash_divergence() {
        let lib = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"ok"),
            artifact_hash: None,
        };
        let cli = ExecutionOutcome::Crash { signal: Some(11) };
        assert_eq!(classify_parity(&lib, &cli), ParityStatus::CrashDivergence);
    }

    #[test]
    fn classify_unsupported() {
        let lib = ExecutionOutcome::Unsupported {
            reason: "not available".to_string(),
        };
        let cli = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"ok"),
            artifact_hash: None,
        };
        assert_eq!(
            classify_parity(&lib, &cli),
            ParityStatus::UnsupportedOnSurface
        );
    }

    #[test]
    fn classify_both_timeout_identical() {
        let lib = ExecutionOutcome::Timeout {
            elapsed_millis: 5000,
        };
        let cli = ExecutionOutcome::Timeout {
            elapsed_millis: 6000,
        };
        assert_eq!(classify_parity(&lib, &cli), ParityStatus::Identical);
    }

    #[test]
    fn classify_different_output_hashes() {
        let lib = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"lib"),
            artifact_hash: None,
        };
        let cli = ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"cli"),
            artifact_hash: None,
        };
        assert_eq!(
            classify_parity(&lib, &cli),
            ParityStatus::ArtifactSchemaDrift
        );
    }

    // --- VerifierConfig tests ---

    #[test]
    fn default_config() {
        let config = VerifierConfig::default();
        assert_eq!(config.required_families.len(), 6);
        assert_eq!(config.required_languages.len(), 2);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = VerifierConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: VerifierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Error tests ---

    #[test]
    fn error_display() {
        let e = VerifierError::MatrixOverflow {
            max: 100,
            attempted: 101,
        };
        assert!(format!("{e}").contains("101"));
    }

    // --- Constants ---

    #[test]
    fn schema_version() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.shipped-path-parity-verifier.v1"
        );
    }

    #[test]
    fn bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.9.6");
    }

    #[test]
    fn component() {
        assert_eq!(COMPONENT, "shipped_path_parity_verifier");
    }

    // --- Verdict tests ---

    #[test]
    fn verdict_pass_is_pass() {
        assert!(VerifierVerdict::Pass.is_pass());
    }

    #[test]
    fn verdict_fail_is_not_pass() {
        let v = VerifierVerdict::Fail {
            reasons: vec![RejectionReason::EmptyMatrix],
        };
        assert!(!v.is_pass());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", VerifierVerdict::Pass), "PASS");
    }

    // --- EntrypointSurface tests ---

    #[test]
    fn entrypoint_as_str() {
        assert_eq!(EntrypointSurface::LibraryApi.as_str(), "library_api");
        assert_eq!(EntrypointSurface::FrankenctlCli.as_str(), "frankenctl_cli");
    }

    // --- ParityInputLanguage tests ---

    #[test]
    fn input_language_all_has_four() {
        assert_eq!(ParityInputLanguage::ALL.len(), 4);
    }

    #[test]
    fn input_language_serde_roundtrip() {
        for lang in ParityInputLanguage::ALL {
            let json = serde_json::to_string(lang).unwrap();
            let back: ParityInputLanguage = serde_json::from_str(&json).unwrap();
            assert_eq!(*lang, back);
        }
    }
}
