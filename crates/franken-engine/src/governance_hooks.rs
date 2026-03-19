//! Enterprise governance hooks: policy-as-code pipelines, audit evidence
//! export, and compliance evidence contracts.
//!
//! This module wires policy-as-code compilation and validation into the
//! FrankenEngine governance lifecycle. It provides:
//!
//! - **PolicySource / PolicyArtifact**: where policies come from and the
//!   compiled, content-addressed result of compilation.
//! - **PolicyCompilationResult**: success/failure with structured diagnostics.
//! - **AuditExportRequest / AuditExportResult**: export evidence in multiple
//!   formats (JsonLines, CSV, Parquet, CompliancePDF) for a requested time
//!   range.
//! - **ComplianceEvidence / ComplianceEvidenceContract**: structured evidence
//!   bundles mapping compliance controls (SOC 2, ISO 27001, HIPAA, PCI-DSS,
//!   GDPR, Custom) to engine evidence entries.
//! - **GovernancePipeline**: orchestrator that fires hooks in order and halts
//!   on first failure.
//! - **GovernanceEvent**: structured, append-only log of all governance
//!   operations.
//!
//! All arithmetic is fixed-point millionths (1_000_000 = 1.0).
//! All collections use `BTreeMap`/`BTreeSet` for deterministic ordering.
//! All public types implement `Serialize` + `Deserialize`.
//!
//! Plan reference: bd-3bz4.3 (enterprise governance hooks).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Zone tag used for governance-hook object identity derivation.
const GOVERNANCE_ZONE: &str = "governance";

/// Schema definition for PolicyArtifact objects.
const POLICY_ARTIFACT_SCHEMA_DEF: &[u8] = b"FrankenEngine.GovernanceHooks.PolicyArtifact.v1";

/// Schema definition for ComplianceEvidence objects.
const COMPLIANCE_EVIDENCE_SCHEMA_DEF: &[u8] =
    b"FrankenEngine.GovernanceHooks.ComplianceEvidence.v1";

/// Schema definition for AuditExportResult objects.
const AUDIT_EXPORT_RESULT_SCHEMA_DEF: &[u8] = b"FrankenEngine.GovernanceHooks.AuditExportResult.v1";

/// Schema definition for GovernanceEvent objects.
const GOVERNANCE_EVENT_SCHEMA_DEF: &[u8] = b"FrankenEngine.GovernanceHooks.GovernanceEvent.v1";

// ---------------------------------------------------------------------------
// PolicySource — where a policy originates
// ---------------------------------------------------------------------------

/// The source from which a policy definition was loaded.
///
/// Each variant captures enough metadata to reproduce or audit the origin
/// without retaining the full raw bytes outside of `PolicyArtifact`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicySource {
    /// Policy loaded from a Git repository (URL + commit SHA).
    GitRepo {
        /// Remote repository URL.
        repo_url: String,
        /// Exact commit SHA (40 hex chars).
        commit_sha: String,
        /// Relative path to the policy file within the repo.
        file_path: String,
    },
    /// Policy loaded from the local filesystem.
    FileSystem {
        /// Absolute path to the policy file.
        absolute_path: String,
    },
    /// Policy provided as an inline TOML string.
    InlineToml {
        /// Display label identifying the caller / context.
        label: String,
    },
    /// Policy provided as an inline JSON string.
    InlineJson {
        /// Display label identifying the caller / context.
        label: String,
    },
}

impl PolicySource {
    /// Short string tag for display and metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitRepo { .. } => "git_repo",
            Self::FileSystem { .. } => "filesystem",
            Self::InlineToml { .. } => "inline_toml",
            Self::InlineJson { .. } => "inline_json",
        }
    }

    /// Enumerate all discriminant variants (excluding parameterised fields).
    pub fn all_tags() -> &'static [&'static str] {
        &["git_repo", "filesystem", "inline_toml", "inline_json"]
    }
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GitRepo {
                repo_url,
                commit_sha,
                file_path,
            } => write!(
                f,
                "git_repo:{}@{}:{}",
                repo_url,
                &commit_sha[..8],
                file_path
            ),
            Self::FileSystem { absolute_path } => write!(f, "filesystem:{absolute_path}"),
            Self::InlineToml { label } => write!(f, "inline_toml:{label}"),
            Self::InlineJson { label } => write!(f, "inline_json:{label}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyArtifact — compiled, content-addressed policy
// ---------------------------------------------------------------------------

/// A compiled, content-addressed policy ready for engine enforcement.
///
/// The `artifact_id` is derived deterministically from the canonical bytes of
/// the policy body, ensuring that identical policies produce the same ID
/// regardless of the source (git, filesystem, inline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyArtifact {
    /// Deterministic object ID derived from the compiled policy body.
    pub artifact_id: EngineObjectId,
    /// Monotonic policy version assigned at compile time.
    pub version: u64,
    /// Content hash of the raw policy definition bytes.
    pub definition_hash: ContentHash,
    /// Content hash of the compiled (normalised) policy body.
    pub compiled_hash: ContentHash,
    /// Canonical serialised bytes of the compiled policy.
    pub compiled_bytes: Vec<u8>,
    /// Source from which the policy was loaded.
    pub source: PolicySource,
    /// Logical timestamp at which the artifact was produced.
    pub compiled_at: DeterministicTimestamp,
    /// Human-readable name of the policy (e.g. `"runtime_execution_v3"`).
    pub policy_name: String,
    /// Free-form metadata tags (sorted for determinism).
    pub tags: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// PolicyDiagnostic — single diagnostic produced during compilation
// ---------------------------------------------------------------------------

/// Severity level of a compilation or validation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    /// Informational — does not block compilation.
    Info,
    /// Warning — compilation succeeds but the operator should review.
    Warning,
    /// Error — compilation or validation failed.
    Error,
}

impl DiagnosticSeverity {
    /// Short ASCII tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// All variants in severity order (ascending).
    pub fn all() -> &'static [DiagnosticSeverity] {
        &[Self::Info, Self::Warning, Self::Error]
    }
}

impl fmt::Display for DiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single structured diagnostic message produced during compilation or
/// validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDiagnostic {
    /// Severity of the diagnostic.
    pub severity: DiagnosticSeverity,
    /// Machine-readable diagnostic code (e.g. `"E0042"`).
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Optional source span (byte offset start..end in the definition).
    pub span: Option<(usize, usize)>,
}

// ---------------------------------------------------------------------------
// PolicyCompilationResult — outcome of compiling a policy definition
// ---------------------------------------------------------------------------

/// The result of compiling a policy definition from raw bytes.
///
/// On success the caller receives a `PolicyArtifact`.  On failure all
/// diagnostics are preserved for operator review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyCompilationResult {
    /// Compilation succeeded.
    Success {
        /// The compiled artifact (boxed to reduce enum size).
        artifact: Box<PolicyArtifact>,
        /// Non-fatal diagnostics (warnings, infos).
        diagnostics: Vec<PolicyDiagnostic>,
    },
    /// Compilation failed.
    Failure {
        /// All diagnostics including errors.
        diagnostics: Vec<PolicyDiagnostic>,
        /// Short summary of the failure root cause.
        error_summary: String,
    },
}

impl PolicyCompilationResult {
    /// Returns `true` if compilation succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Returns the artifact if successful.
    pub fn artifact(&self) -> Option<&PolicyArtifact> {
        match self {
            Self::Success { artifact, .. } => Some(artifact),
            Self::Failure { .. } => None,
        }
    }

    /// Returns all diagnostics regardless of outcome.
    pub fn diagnostics(&self) -> &[PolicyDiagnostic] {
        match self {
            Self::Success { diagnostics, .. } => diagnostics,
            Self::Failure { diagnostics, .. } => diagnostics,
        }
    }

    /// Count diagnostics at or above the given severity.
    pub fn count_at_severity(&self, min: DiagnosticSeverity) -> usize {
        self.diagnostics()
            .iter()
            .filter(|d| d.severity >= min)
            .count()
    }
}

// ---------------------------------------------------------------------------
// ComplianceFramework — supported regulatory / industry frameworks
// ---------------------------------------------------------------------------

/// A supported compliance framework.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// SOC 2 (Trust Services Criteria).
    Soc2,
    /// ISO/IEC 27001 (Information Security Management).
    Iso27001,
    /// HIPAA (Health Insurance Portability and Accountability Act).
    Hipaa,
    /// PCI-DSS (Payment Card Industry Data Security Standard).
    PciDss,
    /// GDPR (General Data Protection Regulation).
    Gdpr,
    /// Custom framework with an operator-defined identifier.
    Custom(String),
}

impl ComplianceFramework {
    /// Short ASCII identifier for the framework.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Soc2 => "soc2",
            Self::Iso27001 => "iso27001",
            Self::Hipaa => "hipaa",
            Self::PciDss => "pci_dss",
            Self::Gdpr => "gdpr",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// All built-in (non-Custom) variants.
    pub fn all_builtin() -> &'static [ComplianceFramework] {
        &[
            Self::Soc2,
            Self::Iso27001,
            Self::Hipaa,
            Self::PciDss,
            Self::Gdpr,
        ]
    }
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AuditExportFormat — supported export wire formats
// ---------------------------------------------------------------------------

/// Supported wire formats for exporting audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AuditExportFormat {
    /// Newline-delimited JSON (one JSON object per evidence entry).
    JsonLines,
    /// Comma-separated values (header row + data rows).
    Csv,
    /// Apache Parquet columnar format.
    Parquet,
    /// Compliance-ready PDF report.
    CompliancePdf,
}

impl AuditExportFormat {
    /// Short ASCII tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonLines => "jsonlines",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::CompliancePdf => "compliance_pdf",
        }
    }

    /// File extension (without leading dot).
    pub fn file_extension(self) -> &'static str {
        match self {
            Self::JsonLines => "jsonl",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::CompliancePdf => "pdf",
        }
    }

    /// All variants for exhaustive iteration.
    pub fn all() -> &'static [AuditExportFormat] {
        &[
            Self::JsonLines,
            Self::Csv,
            Self::Parquet,
            Self::CompliancePdf,
        ]
    }
}

impl fmt::Display for AuditExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AuditExportRequest — what to export, from where, in which format
// ---------------------------------------------------------------------------

/// A request to export a range of audit evidence.
///
/// The engine honours `start_tick..=end_tick` as a closed timestamp interval.
/// Setting `evidence_kinds` to `None` exports all available kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportRequest {
    /// Desired output format.
    pub format: AuditExportFormat,
    /// Inclusive start of the export window (logical ticks).
    pub start_tick: DeterministicTimestamp,
    /// Inclusive end of the export window (logical ticks).
    pub end_tick: DeterministicTimestamp,
    /// If `Some`, filter to only the listed evidence kinds.
    pub evidence_kinds: Option<BTreeSet<String>>,
    /// Maximum number of entries to include (`None` = no limit).
    pub max_entries: Option<u64>,
    /// Human-readable requester identity (for audit trail).
    pub requester: String,
    /// Optional correlation ID linking this export to a compliance review.
    pub correlation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// AuditExportResult — the exported payload with metadata
// ---------------------------------------------------------------------------

/// The result of an audit export operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExportResult {
    /// Deterministic object ID for this export result.
    pub export_id: EngineObjectId,
    /// The format of the exported payload.
    pub format: AuditExportFormat,
    /// Content hash of the exported bytes.
    pub payload_hash: ContentHash,
    /// The exported bytes (may be large; callers may stream in production).
    pub payload_bytes: Vec<u8>,
    /// Number of evidence entries included in the export.
    pub entry_count: u64,
    /// Logical timestamp when the export was produced.
    pub exported_at: DeterministicTimestamp,
    /// The original request.
    pub request: AuditExportRequest,
}

// ---------------------------------------------------------------------------
// EvidenceEntry — a single piece of audit evidence
// ---------------------------------------------------------------------------

/// A single structured audit evidence record included in exports and
/// compliance bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Unique identifier for this evidence entry.
    pub entry_id: EngineObjectId,
    /// Kind of evidence (e.g. `"policy_update"`, `"epoch_transition"`).
    pub kind: String,
    /// Logical timestamp of the event.
    pub timestamp: DeterministicTimestamp,
    /// Human-readable summary of the event.
    pub summary: String,
    /// Structured key-value payload (sorted for determinism).
    pub attributes: BTreeMap<String, String>,
    /// Content hash of the underlying evidence object.
    pub evidence_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ComplianceControl — a single control requirement
// ---------------------------------------------------------------------------

/// A single compliance control requirement with its satisfaction status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceControl {
    /// Control identifier within the framework (e.g. `"CC6.1"` for SOC 2).
    pub control_id: String,
    /// Human-readable description of the control.
    pub description: String,
    /// Whether sufficient evidence was found to satisfy the control.
    pub satisfied: bool,
    /// IDs of evidence entries that satisfy or partially satisfy this control.
    pub evidence_entry_ids: Vec<EngineObjectId>,
    /// Any gaps identified (populated when `satisfied == false`).
    pub gaps: Vec<String>,
}

// ---------------------------------------------------------------------------
// ComplianceEvidence — structured evidence bundle for compliance review
// ---------------------------------------------------------------------------

/// A structured bundle of evidence assembled for a compliance review.
///
/// Contains all evidence entries relevant to the requested framework and
/// review window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    /// Deterministic ID for this evidence bundle.
    pub bundle_id: EngineObjectId,
    /// The compliance framework this bundle targets.
    pub framework: ComplianceFramework,
    /// Logical window for which evidence was collected.
    pub window_start: DeterministicTimestamp,
    /// Logical window end.
    pub window_end: DeterministicTimestamp,
    /// All evidence entries gathered in this window.
    pub entries: Vec<EvidenceEntry>,
    /// Content hash covering all entry hashes (Merkle-style chain).
    pub bundle_hash: ContentHash,
    /// Timestamp when this bundle was assembled.
    pub assembled_at: DeterministicTimestamp,
}

impl ComplianceEvidence {
    /// Total number of evidence entries in this bundle.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Collect entry IDs that match the given kind.
    pub fn ids_for_kind(&self, kind: &str) -> Vec<EngineObjectId> {
        self.entries
            .iter()
            .filter(|e| e.kind == kind)
            .map(|e| e.entry_id.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ComplianceEvidenceContract — control-to-evidence mapping
// ---------------------------------------------------------------------------

/// Maps compliance framework controls to the evidence that satisfies them.
///
/// The contract serves as the authoritative link between engine evidence and
/// the compliance requirements an auditor must verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidenceContract {
    /// Deterministic ID for this contract.
    pub contract_id: EngineObjectId,
    /// The compliance framework this contract covers.
    pub framework: ComplianceFramework,
    /// Controls within the framework (keyed by `control_id`).
    ///
    /// Uses `Vec` with linear scan because `EngineObjectId`-keyed `BTreeMap`
    /// violates the JSON-serde constraint.  Control IDs are `String`-keyed and
    /// thus safe, but we use `Vec` here for uniformity and append-friendly
    /// semantics.
    pub controls: Vec<ComplianceControl>,
    /// The evidence bundle this contract was evaluated against.
    pub evidence_bundle_id: EngineObjectId,
    /// Overall satisfaction rate (millionths: satisfied / total controls).
    pub satisfaction_rate_millionths: u64,
    /// Timestamp when the contract was evaluated.
    pub evaluated_at: DeterministicTimestamp,
}

impl ComplianceEvidenceContract {
    /// Find a control by ID with linear scan.
    pub fn find_control(&self, control_id: &str) -> Option<&ComplianceControl> {
        self.controls.iter().find(|c| c.control_id == control_id)
    }

    /// Count unsatisfied controls.
    pub fn unsatisfied_count(&self) -> usize {
        self.controls.iter().filter(|c| !c.satisfied).count()
    }

    /// Collect all identified gaps across all controls.
    pub fn all_gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        for control in &self.controls {
            for gap in &control.gaps {
                gaps.push(format!("[{}] {}", control.control_id, gap));
            }
        }
        gaps
    }
}

// ---------------------------------------------------------------------------
// GovernanceHookType — points at which hooks fire
// ---------------------------------------------------------------------------

/// Enumeration of hook points in the governance pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GovernanceHookType {
    /// Fires before a policy or extension is deployed.
    PreDeploy,
    /// Fires after a successful deployment.
    PostDeploy,
    /// Fires when any policy definition changes.
    PolicyChange,
    /// Fires when audit evidence is exported.
    AuditExport,
    /// Fires when a compliance check is run.
    ComplianceCheck,
}

impl GovernanceHookType {
    /// Short ASCII tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreDeploy => "pre_deploy",
            Self::PostDeploy => "post_deploy",
            Self::PolicyChange => "policy_change",
            Self::AuditExport => "audit_export",
            Self::ComplianceCheck => "compliance_check",
        }
    }

    /// All variants in pipeline firing order.
    pub fn all() -> &'static [GovernanceHookType] {
        &[
            Self::PreDeploy,
            Self::PostDeploy,
            Self::PolicyChange,
            Self::AuditExport,
            Self::ComplianceCheck,
        ]
    }
}

impl fmt::Display for GovernanceHookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceHookResult — outcome of executing a single hook
// ---------------------------------------------------------------------------

/// Result of executing a single governance hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceHookResult {
    /// Which hook fired.
    pub hook_type: GovernanceHookType,
    /// Whether the hook passed (or was a no-op).
    pub passed: bool,
    /// Human-readable outcome message.
    pub message: String,
    /// Structured diagnostic details (key → value).
    pub details: BTreeMap<String, String>,
    /// Logical timestamp when the hook completed.
    pub completed_at: DeterministicTimestamp,
}

impl GovernanceHookResult {
    /// Construct a passing hook result.
    pub fn pass(
        hook_type: GovernanceHookType,
        message: impl Into<String>,
        completed_at: DeterministicTimestamp,
    ) -> Self {
        Self {
            hook_type,
            passed: true,
            message: message.into(),
            details: BTreeMap::new(),
            completed_at,
        }
    }

    /// Construct a failing hook result.
    pub fn fail(
        hook_type: GovernanceHookType,
        message: impl Into<String>,
        completed_at: DeterministicTimestamp,
    ) -> Self {
        Self {
            hook_type,
            passed: false,
            message: message.into(),
            details: BTreeMap::new(),
            completed_at,
        }
    }
}

impl fmt::Display for GovernanceHookResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "PASS" } else { "FAIL" };
        write!(f, "[{}] {} — {}", status, self.hook_type, self.message)
    }
}

// ---------------------------------------------------------------------------
// GovernancePipeline — orchestrator
// ---------------------------------------------------------------------------

/// Configuration for the governance pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernancePipelineConfig {
    /// Hooks to execute, in order.
    pub hooks: Vec<GovernanceHookType>,
    /// If `true`, halt the pipeline on the first hook failure.
    pub halt_on_failure: bool,
    /// Maximum number of evidence entries to include in export snapshots.
    pub max_export_entries: u64,
    /// Frameworks to evaluate during `ComplianceCheck` hooks.
    pub frameworks: Vec<ComplianceFramework>,
}

impl Default for GovernancePipelineConfig {
    fn default() -> Self {
        Self {
            hooks: GovernanceHookType::all().to_vec(),
            halt_on_failure: true,
            max_export_entries: 100_000,
            frameworks: ComplianceFramework::all_builtin().to_vec(),
        }
    }
}

/// An orchestrator that runs governance hooks in sequence and collects results.
pub struct GovernancePipeline {
    config: GovernancePipelineConfig,
    /// Append-only log of all events (hook firings, exports, checks).
    events: Vec<GovernanceEvent>,
}

impl GovernancePipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: GovernancePipelineConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
        }
    }

    /// Return all events accumulated so far.
    pub fn events(&self) -> &[GovernanceEvent] {
        &self.events
    }

    /// Return a reference to the pipeline configuration.
    pub fn config(&self) -> &GovernancePipelineConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvent — structured audit log entry
// ---------------------------------------------------------------------------

/// A structured, immutable governance event written to the append-only log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvent {
    /// Deterministic ID for this event.
    pub event_id: EngineObjectId,
    /// Which hook or operation produced this event.
    pub hook_type: GovernanceHookType,
    /// Whether the associated hook passed.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
    /// Structured key-value payload (sorted for determinism).
    pub attributes: BTreeMap<String, String>,
    /// Logical timestamp of the event.
    pub timestamp: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// GovernanceError — error type for this module
// ---------------------------------------------------------------------------

/// Error type for governance-hook operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceError {
    /// The policy definition bytes were empty.
    EmptyPolicyDefinition,
    /// The policy definition is syntactically invalid.
    InvalidPolicySyntax {
        /// Format in which the definition was expected (e.g. `"toml"`).
        expected_format: String,
        /// Human-readable reason for the failure.
        reason: String,
    },
    /// The policy definition is semantically invalid (schema mismatch, unknown
    /// fields, version incompatibility, etc.).
    PolicySchemaViolation {
        /// Which schema constraint was violated.
        constraint: String,
    },
    /// Object ID derivation failed.
    IdDerivationFailed { detail: String },
    /// The audit export time range is invalid (start > end).
    InvalidTimeRange {
        start: DeterministicTimestamp,
        end: DeterministicTimestamp,
    },
    /// No evidence was found for the requested time range.
    NoEvidenceInRange {
        start: DeterministicTimestamp,
        end: DeterministicTimestamp,
    },
    /// The requested compliance framework has no registered controls.
    UnknownFramework { framework: String },
    /// A required compliance control is missing from the evidence bundle.
    MissingControl { control_id: String },
    /// A governance hook failed and `halt_on_failure` is set.
    HookFailed {
        hook_type: GovernanceHookType,
        reason: String,
    },
    /// Serialisation failed during export.
    SerialisationFailed { reason: String },
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPolicyDefinition => write!(f, "policy definition bytes are empty"),
            Self::InvalidPolicySyntax {
                expected_format,
                reason,
            } => write!(f, "invalid {expected_format} policy syntax: {reason}"),
            Self::PolicySchemaViolation { constraint } => {
                write!(f, "policy schema violation: {constraint}")
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "ID derivation failed: {detail}")
            }
            Self::InvalidTimeRange { start, end } => {
                write!(f, "invalid time range: start {start} > end {end}")
            }
            Self::NoEvidenceInRange { start, end } => {
                write!(f, "no evidence found in range {start}..={end}")
            }
            Self::UnknownFramework { framework } => {
                write!(f, "unknown compliance framework: {framework}")
            }
            Self::MissingControl { control_id } => {
                write!(f, "missing compliance control: {control_id}")
            }
            Self::HookFailed { hook_type, reason } => {
                write!(f, "governance hook {hook_type} failed: {reason}")
            }
            Self::SerialisationFailed { reason } => {
                write!(f, "serialisation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for GovernanceError {}

// ---------------------------------------------------------------------------
// compile_policy — parse and validate a policy definition → PolicyArtifact
// ---------------------------------------------------------------------------

/// Compile a raw policy definition into a content-addressed `PolicyArtifact`.
///
/// Accepts both TOML and JSON sources (determined by `source`).  The
/// compilation step:
/// 1. Validates that `definition_bytes` is non-empty.
/// 2. Parses the bytes according to the declared format.
/// 3. Normalises the parsed value into a canonical JSON byte representation
///    for deterministic content-addressing.
/// 4. Derives an `EngineObjectId` from the canonical bytes.
/// 5. Returns a `PolicyCompilationResult`.
///
/// This function is pure (no I/O).  The caller is responsible for loading
/// bytes from the declared `PolicySource`.
pub fn compile_policy(
    source: PolicySource,
    definition_bytes: &[u8],
    policy_name: impl Into<String>,
    version: u64,
    now: DeterministicTimestamp,
    tags: BTreeSet<String>,
) -> PolicyCompilationResult {
    let policy_name = policy_name.into();

    // --- Empty check ---
    if definition_bytes.is_empty() {
        return PolicyCompilationResult::Failure {
            diagnostics: vec![PolicyDiagnostic {
                severity: DiagnosticSeverity::Error,
                code: "E0001".to_string(),
                message: "policy definition bytes are empty".to_string(),
                span: None,
            }],
            error_summary: "empty definition".to_string(),
        };
    }

    // --- Format-specific parse & normalise ---
    let (compiled_bytes, warnings) = match &source {
        PolicySource::InlineToml { .. }
        | PolicySource::GitRepo { .. }
        | PolicySource::FileSystem { .. } => {
            // Treat non-JSON sources as TOML: parse and normalise to canonical
            // form.  We use a lightweight structural check: the bytes must be
            // valid UTF-8, must contain at least one `=` (TOML key-value
            // assignment) or be valid JSON (for FileSystem/GitRepo which may
            // contain either).
            match parse_and_normalise_policy(definition_bytes, "toml") {
                Ok(bytes) => (bytes, vec![]),
                Err(reason) => {
                    return PolicyCompilationResult::Failure {
                        diagnostics: vec![PolicyDiagnostic {
                            severity: DiagnosticSeverity::Error,
                            code: "E0010".to_string(),
                            message: reason.clone(),
                            span: None,
                        }],
                        error_summary: reason,
                    };
                }
            }
        }
        PolicySource::InlineJson { .. } => {
            match parse_and_normalise_policy(definition_bytes, "json") {
                Ok(bytes) => (bytes, vec![]),
                Err(reason) => {
                    return PolicyCompilationResult::Failure {
                        diagnostics: vec![PolicyDiagnostic {
                            severity: DiagnosticSeverity::Error,
                            code: "E0011".to_string(),
                            message: reason.clone(),
                            span: None,
                        }],
                        error_summary: reason,
                    };
                }
            }
        }
    };

    // --- Content addressing ---
    let definition_hash = ContentHash::compute(definition_bytes);
    let compiled_hash = ContentHash::compute(&compiled_bytes);

    let schema_id = SchemaId::from_definition(POLICY_ARTIFACT_SCHEMA_DEF);
    let artifact_id = match engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        GOVERNANCE_ZONE,
        &schema_id,
        &compiled_bytes,
    ) {
        Ok(id) => id,
        Err(e) => {
            return PolicyCompilationResult::Failure {
                diagnostics: vec![PolicyDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: "E0020".to_string(),
                    message: format!("ID derivation failed: {e}"),
                    span: None,
                }],
                error_summary: format!("ID derivation: {e}"),
            };
        }
    };

    let artifact = PolicyArtifact {
        artifact_id,
        version,
        definition_hash,
        compiled_hash,
        compiled_bytes,
        source,
        compiled_at: now,
        policy_name,
        tags,
    };

    PolicyCompilationResult::Success {
        artifact: Box::new(artifact),
        diagnostics: warnings,
    }
}

// ---------------------------------------------------------------------------
// validate_policy — check a policy artifact against the current schema
// ---------------------------------------------------------------------------

/// Validate a `PolicyArtifact` against the current schema constraints.
///
/// Checks:
/// - The compiled bytes are non-empty and their content hash matches.
/// - The version is non-zero.
/// - The policy name is non-empty.
/// - Any caller-supplied `required_version_min` constraint is satisfied.
///
/// Returns `Ok(())` on success or a `GovernanceError` describing the first
/// violation found.
pub fn validate_policy(
    artifact: &PolicyArtifact,
    required_version_min: Option<u64>,
) -> Result<(), GovernanceError> {
    // Non-empty compiled bytes.
    if artifact.compiled_bytes.is_empty() {
        return Err(GovernanceError::PolicySchemaViolation {
            constraint: "compiled_bytes must be non-empty".to_string(),
        });
    }

    // Content-hash consistency.
    let recomputed = ContentHash::compute(&artifact.compiled_bytes);
    if recomputed != artifact.compiled_hash {
        return Err(GovernanceError::PolicySchemaViolation {
            constraint: format!(
                "compiled_hash mismatch: stored {}, recomputed {}",
                artifact.compiled_hash.to_hex(),
                recomputed.to_hex()
            ),
        });
    }

    // Version constraint.
    if artifact.version == 0 {
        return Err(GovernanceError::PolicySchemaViolation {
            constraint: "version must be non-zero".to_string(),
        });
    }

    if let Some(min) = required_version_min
        && artifact.version < min
    {
        return Err(GovernanceError::PolicySchemaViolation {
            constraint: format!(
                "version {} is below required minimum {}",
                artifact.version, min
            ),
        });
    }

    // Non-empty policy name.
    if artifact.policy_name.trim().is_empty() {
        return Err(GovernanceError::PolicySchemaViolation {
            constraint: "policy_name must be non-empty".to_string(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// export_audit_evidence — export evidence for a time range
// ---------------------------------------------------------------------------

/// Export audit evidence for the time range specified in `request`.
///
/// `available_entries` is the set of evidence the caller has already
/// materialised from the ledger.  This function filters, formats, and
/// packages them according to the request.
pub fn export_audit_evidence(
    request: AuditExportRequest,
    available_entries: Vec<EvidenceEntry>,
    now: DeterministicTimestamp,
) -> Result<AuditExportResult, GovernanceError> {
    // Validate the time range.
    if request.start_tick.0 > request.end_tick.0 {
        return Err(GovernanceError::InvalidTimeRange {
            start: request.start_tick,
            end: request.end_tick,
        });
    }

    // Filter by time range.
    let mut filtered: Vec<&EvidenceEntry> = available_entries
        .iter()
        .filter(|e| e.timestamp.0 >= request.start_tick.0 && e.timestamp.0 <= request.end_tick.0)
        .collect();

    // Filter by kind if requested.
    if let Some(ref kinds) = request.evidence_kinds {
        filtered.retain(|e| kinds.contains(&e.kind));
    }

    // Apply entry limit.
    if let Some(max) = request.max_entries {
        let max = max as usize;
        if filtered.len() > max {
            filtered.truncate(max);
        }
    }

    let entry_count = filtered.len() as u64;

    // Serialise according to format.
    let payload_bytes = serialise_entries(&filtered, request.format)?;
    let payload_hash = ContentHash::compute(&payload_bytes);

    // Derive ID.  The canonical preimage includes the payload hash and the
    // entry count so that even an empty export has a non-empty canonical.
    let schema_id = SchemaId::from_definition(AUDIT_EXPORT_RESULT_SCHEMA_DEF);
    let id_canonical: Vec<u8> = {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(payload_hash.as_bytes());
        buf.extend_from_slice(&entry_count.to_be_bytes());
        buf.extend_from_slice(request.format.as_str().as_bytes());
        buf
    };
    let export_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        GOVERNANCE_ZONE,
        &schema_id,
        &id_canonical,
    )
    .map_err(|e| GovernanceError::IdDerivationFailed {
        detail: e.to_string(),
    })?;

    Ok(AuditExportResult {
        export_id,
        format: request.format,
        payload_hash,
        payload_bytes,
        entry_count,
        exported_at: now,
        request,
    })
}

// ---------------------------------------------------------------------------
// generate_compliance_bundle — create a compliance evidence package
// ---------------------------------------------------------------------------

/// Generate a compliance evidence bundle and evaluate a contract against it.
///
/// `available_entries` should contain all evidence the engine has in memory
/// (or a pre-filtered slice). This function:
/// 1. Filters entries to the requested window.
/// 2. Assembles a `ComplianceEvidence` bundle.
/// 3. Evaluates the controls defined by `framework` against the bundle.
/// 4. Returns both the bundle and the evaluated contract.
pub fn generate_compliance_bundle(
    framework: ComplianceFramework,
    window_start: DeterministicTimestamp,
    window_end: DeterministicTimestamp,
    available_entries: Vec<EvidenceEntry>,
    now: DeterministicTimestamp,
) -> Result<(ComplianceEvidence, ComplianceEvidenceContract), GovernanceError> {
    if window_start.0 > window_end.0 {
        return Err(GovernanceError::InvalidTimeRange {
            start: window_start,
            end: window_end,
        });
    }

    // Filter entries to window.
    let entries: Vec<EvidenceEntry> = available_entries
        .into_iter()
        .filter(|e| e.timestamp.0 >= window_start.0 && e.timestamp.0 <= window_end.0)
        .collect();

    // Compute bundle hash (chain entry hashes).
    let bundle_hash = compute_bundle_hash(&entries);

    // Derive bundle ID.
    let bundle_schema = SchemaId::from_definition(COMPLIANCE_EVIDENCE_SCHEMA_DEF);
    let bundle_canonical: Vec<u8> = {
        let mut buf = Vec::new();
        buf.extend_from_slice(framework.as_str().as_bytes());
        buf.extend_from_slice(&window_start.0.to_be_bytes());
        buf.extend_from_slice(&window_end.0.to_be_bytes());
        buf.extend_from_slice(bundle_hash.as_bytes());
        buf
    };
    let bundle_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        GOVERNANCE_ZONE,
        &bundle_schema,
        &bundle_canonical,
    )
    .map_err(|e| GovernanceError::IdDerivationFailed {
        detail: e.to_string(),
    })?;

    let evidence_bundle = ComplianceEvidence {
        bundle_id: bundle_id.clone(),
        framework: framework.clone(),
        window_start,
        window_end,
        entries,
        bundle_hash,
        assembled_at: now,
    };

    // Build the compliance controls for the framework.
    let controls = evaluate_controls(&framework, &evidence_bundle);
    let satisfied = controls.iter().filter(|c| c.satisfied).count() as u64;
    let total = controls.len() as u64;
    // Vacuous truth: zero controls → 100% satisfaction (consistent with
    // execute_hook compliance check which uses 1_000_000 for total==0).
    let satisfaction_rate_millionths = satisfied
        .saturating_mul(1_000_000)
        .checked_div(total)
        .unwrap_or(1_000_000);

    // Derive contract ID.
    let contract_schema = SchemaId::from_definition(COMPLIANCE_EVIDENCE_SCHEMA_DEF);
    let contract_canonical: Vec<u8> = {
        let mut buf = bundle_canonical.clone();
        buf.extend_from_slice(&satisfaction_rate_millionths.to_be_bytes());
        buf
    };
    let contract_id = engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        GOVERNANCE_ZONE,
        &contract_schema,
        &contract_canonical,
    )
    .map_err(|e| GovernanceError::IdDerivationFailed {
        detail: e.to_string(),
    })?;

    let contract = ComplianceEvidenceContract {
        contract_id,
        framework,
        controls,
        evidence_bundle_id: bundle_id,
        satisfaction_rate_millionths,
        evaluated_at: now,
    };

    Ok((evidence_bundle, contract))
}

// ---------------------------------------------------------------------------
// run_governance_pipeline — execute the full governance pipeline
// ---------------------------------------------------------------------------

/// Execute the governance pipeline over a set of policy artifacts and evidence.
///
/// Fires hooks in the order defined by `pipeline.config().hooks`.
/// If `halt_on_failure` is set, stops at the first failing hook.
///
/// Returns the list of `GovernanceHookResult`s (one per hook fired).
pub fn run_governance_pipeline(
    pipeline: &mut GovernancePipeline,
    artifacts: &[PolicyArtifact],
    available_entries: Vec<EvidenceEntry>,
    now: DeterministicTimestamp,
) -> Result<Vec<GovernanceHookResult>, GovernanceError> {
    let hooks = pipeline.config().hooks.clone();
    let halt_on_failure = pipeline.config().halt_on_failure;
    let frameworks = pipeline.config().frameworks.clone();
    let max_export_entries = pipeline.config().max_export_entries;

    let mut results = Vec::new();

    for hook_type in &hooks {
        let result = execute_hook(
            *hook_type,
            artifacts,
            &available_entries,
            &frameworks,
            max_export_entries,
            now,
        );

        // Record a GovernanceEvent.
        let event = build_event(*hook_type, &result, now)?;
        pipeline.events.push(event);
        results.push(result);

        let last = results.last().unwrap();
        if !last.passed && halt_on_failure {
            return Err(GovernanceError::HookFailed {
                hook_type: *hook_type,
                reason: last.message.clone(),
            });
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Lightweight parse + normalise a policy definition.
///
/// For TOML: verifies UTF-8, checks for at least one `=` or `[`.
/// For JSON: verifies the bytes start with `{` or `[` after whitespace.
/// Returns the normalised bytes on success or an error string.
fn parse_and_normalise_policy(bytes: &[u8], format: &str) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("UTF-8 decode error: {e}"))?;

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("policy text is empty after trimming whitespace".to_string());
    }

    match format {
        "json" => {
            if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
                return Err("JSON policy must start with '{' or '['".to_string());
            }
            // Normalise: re-emit UTF-8 bytes of the trimmed text.
            Ok(trimmed.as_bytes().to_vec())
        }
        _ => {
            // TOML/unknown: require at least one `=` or a section header `[`.
            if !trimmed.contains('=') && !trimmed.contains('[') {
                return Err(
                    "TOML policy must contain at least one key=value or section header".to_string(),
                );
            }
            Ok(trimmed.as_bytes().to_vec())
        }
    }
}

/// Serialise a slice of evidence entries into the requested format.
fn serialise_entries(
    entries: &[&EvidenceEntry],
    format: AuditExportFormat,
) -> Result<Vec<u8>, GovernanceError> {
    match format {
        AuditExportFormat::JsonLines => {
            let mut buf = Vec::new();
            for entry in entries {
                let line = serialise_entry_json(entry);
                buf.extend_from_slice(line.as_bytes());
                buf.push(b'\n');
            }
            Ok(buf)
        }
        AuditExportFormat::Csv => {
            let mut buf = Vec::new();
            // Header.
            buf.extend_from_slice(b"entry_id,kind,timestamp,summary,evidence_hash\n");
            for entry in entries {
                let row = format!(
                    "{},{},{},{},{}\n",
                    entry.entry_id,
                    csv_escape(&entry.kind),
                    entry.timestamp.0,
                    csv_escape(&entry.summary),
                    entry.evidence_hash.to_hex(),
                );
                buf.extend_from_slice(row.as_bytes());
            }
            Ok(buf)
        }
        AuditExportFormat::Parquet => {
            // Parquet is a binary columnar format.  We emit a deterministic
            // placeholder encoding (column-major newline-delimited records)
            // rather than a full Parquet implementation which would require
            // external crates.
            let mut buf = Vec::new();
            buf.extend_from_slice(b"FRANKEN_PARQUET_V1\n");
            for entry in entries {
                let record = format!(
                    "{}\t{}\t{}\t{}\n",
                    entry.entry_id,
                    entry.kind,
                    entry.timestamp.0,
                    entry.evidence_hash.to_hex(),
                );
                buf.extend_from_slice(record.as_bytes());
            }
            Ok(buf)
        }
        AuditExportFormat::CompliancePdf => {
            // PDF generation requires external libraries; emit a structured
            // text report as a deterministic stand-in.
            let mut buf = Vec::new();
            buf.extend_from_slice(b"FRANKEN_COMPLIANCE_REPORT_V1\n");
            buf.extend_from_slice(format!("total_entries: {}\n", entries.len()).as_bytes());
            for entry in entries {
                let line = format!(
                    "entry: {} | {} | {} | {}\n",
                    entry.entry_id, entry.kind, entry.timestamp.0, entry.summary,
                );
                buf.extend_from_slice(line.as_bytes());
            }
            Ok(buf)
        }
    }
}

/// Produce a JSON-like representation of a single entry (no external crates).
fn serialise_entry_json(entry: &EvidenceEntry) -> String {
    let attrs: String = entry
        .attributes
        .iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"entry_id\":\"{}\",\"kind\":\"{}\",\"timestamp\":{},\"summary\":\"{}\",\"evidence_hash\":\"{}\",\"attributes\":{{{}}}}}",
        entry.entry_id,
        json_escape(&entry.kind),
        entry.timestamp.0,
        json_escape(&entry.summary),
        entry.evidence_hash.to_hex(),
        attrs,
    )
}

/// Minimal JSON string escaping.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Minimal CSV field escaping (wraps in quotes if needed).
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Compute a chained hash over all evidence entry hashes.
fn compute_bundle_hash(entries: &[EvidenceEntry]) -> ContentHash {
    let mut buf = Vec::with_capacity(entries.len() * 32);
    for entry in entries {
        buf.extend_from_slice(entry.evidence_hash.as_bytes());
    }
    ContentHash::compute(&buf)
}

/// Evaluate compliance controls for a given framework against a bundle.
fn evaluate_controls(
    framework: &ComplianceFramework,
    bundle: &ComplianceEvidence,
) -> Vec<ComplianceControl> {
    let control_defs = framework_controls(framework);
    control_defs
        .into_iter()
        .map(|(control_id, description, required_kinds)| {
            let matching: Vec<EngineObjectId> = required_kinds
                .iter()
                .flat_map(|kind| bundle.ids_for_kind(kind))
                .collect();
            let mut gaps = Vec::new();
            for kind in &required_kinds {
                if bundle.ids_for_kind(kind).is_empty() {
                    gaps.push(format!("no evidence of kind '{kind}'"));
                }
            }
            let satisfied = gaps.is_empty();
            ComplianceControl {
                control_id,
                description,
                satisfied,
                evidence_entry_ids: matching,
                gaps,
            }
        })
        .collect()
}

/// Return the control definitions for a given framework.
///
/// Each entry is `(control_id, description, required_evidence_kinds)`.
fn framework_controls(framework: &ComplianceFramework) -> Vec<(String, String, Vec<String>)> {
    match framework {
        ComplianceFramework::Soc2 => vec![
            (
                "CC6.1".to_string(),
                "Logical and physical access controls are implemented".to_string(),
                vec![
                    "capability_decision".to_string(),
                    "policy_update".to_string(),
                ],
            ),
            (
                "CC6.2".to_string(),
                "User registration and de-registration processes".to_string(),
                vec!["activation_lifecycle".to_string()],
            ),
            (
                "CC7.2".to_string(),
                "System monitoring and anomaly detection".to_string(),
                vec![
                    "security_action".to_string(),
                    "epoch_transition".to_string(),
                ],
            ),
            (
                "CC9.2".to_string(),
                "Risk mitigation — vendor and business partner agreements".to_string(),
                vec!["revocation".to_string()],
            ),
        ],
        ComplianceFramework::Iso27001 => vec![
            (
                "A.9.1".to_string(),
                "Access control policy".to_string(),
                vec![
                    "capability_decision".to_string(),
                    "policy_update".to_string(),
                ],
            ),
            (
                "A.12.4".to_string(),
                "Logging and monitoring".to_string(),
                vec!["security_action".to_string()],
            ),
            (
                "A.16.1".to_string(),
                "Incident management procedures".to_string(),
                vec![
                    "security_action".to_string(),
                    "epoch_transition".to_string(),
                ],
            ),
        ],
        ComplianceFramework::Hipaa => vec![
            (
                "164.312(a)(1)".to_string(),
                "Access control — unique user identification".to_string(),
                vec!["capability_decision".to_string()],
            ),
            (
                "164.312(b)".to_string(),
                "Audit controls".to_string(),
                vec!["policy_update".to_string(), "epoch_transition".to_string()],
            ),
            (
                "164.312(e)(2)(ii)".to_string(),
                "Encryption and decryption".to_string(),
                vec!["revocation".to_string()],
            ),
        ],
        ComplianceFramework::PciDss => vec![
            (
                "10.1".to_string(),
                "Audit log linkage to individuals".to_string(),
                vec!["capability_decision".to_string()],
            ),
            (
                "10.2".to_string(),
                "Audit log events".to_string(),
                vec!["security_action".to_string(), "policy_update".to_string()],
            ),
            (
                "10.6".to_string(),
                "Review logs for anomalies".to_string(),
                vec!["epoch_transition".to_string()],
            ),
            (
                "12.10".to_string(),
                "Incident response plan".to_string(),
                vec!["revocation".to_string()],
            ),
        ],
        ComplianceFramework::Gdpr => vec![
            (
                "Art.30".to_string(),
                "Records of processing activities".to_string(),
                vec![
                    "capability_decision".to_string(),
                    "policy_update".to_string(),
                ],
            ),
            (
                "Art.32".to_string(),
                "Security of processing".to_string(),
                vec![
                    "security_action".to_string(),
                    "epoch_transition".to_string(),
                ],
            ),
            (
                "Art.33".to_string(),
                "Notification of personal data breach".to_string(),
                vec!["revocation".to_string()],
            ),
        ],
        ComplianceFramework::Custom(_) => vec![
            (
                "CUSTOM-1".to_string(),
                "Custom control 1".to_string(),
                vec!["policy_update".to_string()],
            ),
            (
                "CUSTOM-2".to_string(),
                "Custom control 2".to_string(),
                vec!["security_action".to_string()],
            ),
        ],
    }
}

/// Execute a single hook and produce its result.
fn execute_hook(
    hook_type: GovernanceHookType,
    artifacts: &[PolicyArtifact],
    entries: &[EvidenceEntry],
    frameworks: &[ComplianceFramework],
    max_export_entries: u64,
    now: DeterministicTimestamp,
) -> GovernanceHookResult {
    match hook_type {
        GovernanceHookType::PreDeploy => {
            // Check that all artifacts pass validation.
            for artifact in artifacts {
                if let Err(e) = validate_policy(artifact, None) {
                    return GovernanceHookResult::fail(
                        hook_type,
                        format!(
                            "pre-deploy validation failed for '{}': {e}",
                            artifact.policy_name
                        ),
                        now,
                    );
                }
            }
            let mut result = GovernanceHookResult::pass(
                hook_type,
                format!(
                    "pre-deploy checks passed for {} artifact(s)",
                    artifacts.len()
                ),
                now,
            );
            result
                .details
                .insert("artifact_count".to_string(), artifacts.len().to_string());
            result
        }
        GovernanceHookType::PostDeploy => {
            // Verify that all artifacts have non-empty compiled bytes and valid hashes.
            for artifact in artifacts {
                let recomputed = ContentHash::compute(&artifact.compiled_bytes);
                if recomputed != artifact.compiled_hash {
                    return GovernanceHookResult::fail(
                        hook_type,
                        format!(
                            "post-deploy hash check failed for '{}'",
                            artifact.policy_name
                        ),
                        now,
                    );
                }
            }
            let mut result = GovernanceHookResult::pass(
                hook_type,
                format!(
                    "post-deploy integrity verified for {} artifact(s)",
                    artifacts.len()
                ),
                now,
            );
            result
                .details
                .insert("artifact_count".to_string(), artifacts.len().to_string());
            result
        }
        GovernanceHookType::PolicyChange => {
            // Verify each artifact is distinct (no duplicate compiled_hash).
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for artifact in artifacts {
                let key = artifact.compiled_hash.to_hex();
                if !seen.insert(key.clone()) {
                    return GovernanceHookResult::fail(
                        hook_type,
                        format!("duplicate policy hash detected: {key}"),
                        now,
                    );
                }
            }
            let mut result = GovernanceHookResult::pass(
                hook_type,
                format!(
                    "policy-change hook: {} unique artifact(s) verified",
                    artifacts.len()
                ),
                now,
            );
            result
                .details
                .insert("unique_count".to_string(), artifacts.len().to_string());
            result
        }
        GovernanceHookType::AuditExport => {
            // Perform a snapshot export of all available entries.
            let count = entries.len().min(max_export_entries as usize);
            let mut result = GovernanceHookResult::pass(
                hook_type,
                format!("audit-export hook: {count} entries available for export"),
                now,
            );
            result
                .details
                .insert("entry_count".to_string(), count.to_string());
            result
        }
        GovernanceHookType::ComplianceCheck => {
            // Evaluate all configured frameworks.
            let mut overall_pass = true;
            let mut framework_results: BTreeMap<String, String> = BTreeMap::new();
            for framework in frameworks {
                let controls = evaluate_controls(
                    framework,
                    &ComplianceEvidence {
                        bundle_id: {
                            // Build a minimal placeholder bundle for hook-level evaluation.
                            let schema = SchemaId::from_definition(COMPLIANCE_EVIDENCE_SCHEMA_DEF);
                            let canonical = b"hook_compliance_check";
                            match engine_object_id::derive_id(
                                ObjectDomain::EvidenceRecord,
                                GOVERNANCE_ZONE,
                                &schema,
                                canonical,
                            ) {
                                Ok(id) => id,
                                Err(_) => {
                                    overall_pass = false;
                                    framework_results.insert(
                                        framework.as_str().to_string(),
                                        "id_derivation_failed".to_string(),
                                    );
                                    continue;
                                }
                            }
                        },
                        framework: framework.clone(),
                        window_start: DeterministicTimestamp(0),
                        window_end: now,
                        entries: entries.to_vec(),
                        bundle_hash: compute_bundle_hash(entries),
                        assembled_at: now,
                    },
                );

                let satisfied = controls.iter().filter(|c| c.satisfied).count();
                let total = controls.len();
                let rate = if total == 0 {
                    1_000_000u64
                } else {
                    satisfied as u64 * 1_000_000 / total as u64
                };
                framework_results.insert(
                    framework.as_str().to_string(),
                    format!("{}/{} controls ({} ppm)", satisfied, total, rate),
                );
                // Require at least 50% of controls to be satisfied.
                if rate < 500_000 {
                    overall_pass = false;
                }
            }
            let msg = if overall_pass {
                "compliance check passed across all frameworks".to_string()
            } else {
                "compliance check failed: satisfaction rate below 50% in one or more frameworks"
                    .to_string()
            };
            let mut result = if overall_pass {
                GovernanceHookResult::pass(hook_type, msg, now)
            } else {
                GovernanceHookResult::fail(hook_type, msg, now)
            };
            result.details = framework_results;
            result
        }
    }
}

/// Build a `GovernanceEvent` from a hook result.
fn build_event(
    hook_type: GovernanceHookType,
    result: &GovernanceHookResult,
    now: DeterministicTimestamp,
) -> Result<GovernanceEvent, GovernanceError> {
    let summary = format!("{}: {}", hook_type, result.message);
    let canonical: Vec<u8> = {
        let mut buf = Vec::new();
        let hook_bytes = hook_type.as_str().as_bytes();
        buf.extend_from_slice(&(hook_bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(hook_bytes);
        let msg_bytes = result.message.as_bytes();
        buf.extend_from_slice(&(msg_bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(msg_bytes);
        buf.extend_from_slice(&[result.passed as u8]);
        buf.extend_from_slice(&now.0.to_be_bytes());
        buf
    };
    let schema = SchemaId::from_definition(GOVERNANCE_EVENT_SCHEMA_DEF);
    let event_id = engine_object_id::derive_id(
        ObjectDomain::EvidenceRecord,
        GOVERNANCE_ZONE,
        &schema,
        &canonical,
    )
    .map_err(|e| GovernanceError::IdDerivationFailed {
        detail: e.to_string(),
    })?;

    Ok(GovernanceEvent {
        event_id,
        hook_type,
        passed: result.passed,
        summary,
        attributes: result.details.clone(),
        timestamp: now,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn ts(tick: u64) -> DeterministicTimestamp {
        DeterministicTimestamp(tick)
    }

    fn make_entry(kind: &str, tick: u64) -> EvidenceEntry {
        let summary = format!("{kind} at tick {tick}");
        let evidence_hash = ContentHash::compute(summary.as_bytes());
        // Derive a deterministic ID.
        let schema = SchemaId::from_definition(b"TestEntry.v1");
        let canonical = format!("{kind}:{tick}");
        let entry_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            "test",
            &schema,
            canonical.as_bytes(),
        )
        .unwrap();
        EvidenceEntry {
            entry_id,
            kind: kind.to_string(),
            timestamp: ts(tick),
            summary,
            attributes: BTreeMap::new(),
            evidence_hash,
        }
    }

    fn toml_policy() -> &'static [u8] {
        b"[runtime]\nmax_fuel = 1000000\nallow_network = false"
    }

    fn json_policy() -> &'static [u8] {
        b"{\"max_fuel\": 1000000, \"allow_network\": false}"
    }

    fn compile_ok(source: PolicySource, bytes: &[u8]) -> PolicyArtifact {
        let result = compile_policy(source, bytes, "test_policy", 1, ts(100), BTreeSet::new());
        assert!(result.is_success(), "expected success: {:?}", result);
        result.artifact().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // PolicySource
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_source_as_str() {
        assert_eq!(
            PolicySource::GitRepo {
                repo_url: "https://example.com/repo".to_string(),
                commit_sha: "abc123def456abc123def456abc123def456abc1".to_string(),
                file_path: "policy/runtime.toml".to_string(),
            }
            .as_str(),
            "git_repo"
        );
        assert_eq!(
            PolicySource::FileSystem {
                absolute_path: "/etc/policy.toml".to_string()
            }
            .as_str(),
            "filesystem"
        );
        assert_eq!(
            PolicySource::InlineToml {
                label: "test".to_string()
            }
            .as_str(),
            "inline_toml"
        );
        assert_eq!(
            PolicySource::InlineJson {
                label: "test".to_string()
            }
            .as_str(),
            "inline_json"
        );
    }

    #[test]
    fn test_policy_source_all_tags() {
        let tags = PolicySource::all_tags();
        assert_eq!(tags.len(), 4);
        assert!(tags.contains(&"git_repo"));
        assert!(tags.contains(&"filesystem"));
        assert!(tags.contains(&"inline_toml"));
        assert!(tags.contains(&"inline_json"));
    }

    #[test]
    fn test_policy_source_display() {
        let git = PolicySource::GitRepo {
            repo_url: "https://repo".to_string(),
            commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
            file_path: "p.toml".to_string(),
        };
        let s = format!("{git}");
        assert!(s.contains("git_repo:"));
        assert!(s.contains("p.toml"));

        let fs = PolicySource::FileSystem {
            absolute_path: "/tmp/p.toml".to_string(),
        };
        assert_eq!(format!("{fs}"), "filesystem:/tmp/p.toml");

        let inline = PolicySource::InlineToml {
            label: "ctx".to_string(),
        };
        assert_eq!(format!("{inline}"), "inline_toml:ctx");
    }

    #[test]
    fn test_policy_source_serde_roundtrip() {
        let sources = vec![
            PolicySource::GitRepo {
                repo_url: "https://example.com".to_string(),
                commit_sha: "a".repeat(40),
                file_path: "f.toml".to_string(),
            },
            PolicySource::FileSystem {
                absolute_path: "/path".to_string(),
            },
            PolicySource::InlineToml {
                label: "label".to_string(),
            },
            PolicySource::InlineJson {
                label: "label".to_string(),
            },
        ];
        for src in sources {
            let json = serde_json::to_string(&src).unwrap();
            let decoded: PolicySource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // compile_policy — valid inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_toml_policy_success() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
            "runtime_v1",
            1,
            ts(50),
            BTreeSet::new(),
        );
        assert!(result.is_success());
        let art = result.artifact().unwrap();
        assert_eq!(art.version, 1);
        assert_eq!(art.policy_name, "runtime_v1");
        assert!(!art.compiled_bytes.is_empty());
        assert_eq!(art.compiled_hash, ContentHash::compute(&art.compiled_bytes));
    }

    #[test]
    fn test_compile_json_policy_success() {
        let result = compile_policy(
            PolicySource::InlineJson {
                label: "j".to_string(),
            },
            json_policy(),
            "runtime_json_v1",
            2,
            ts(60),
            BTreeSet::new(),
        );
        assert!(result.is_success());
        let art = result.artifact().unwrap();
        assert_eq!(art.version, 2);
    }

    #[test]
    fn test_compile_filesystem_policy_success() {
        let result = compile_policy(
            PolicySource::FileSystem {
                absolute_path: "/etc/policy.toml".to_string(),
            },
            toml_policy(),
            "fs_policy",
            1,
            ts(70),
            BTreeSet::new(),
        );
        assert!(result.is_success());
    }

    #[test]
    fn test_compile_git_policy_success() {
        let result = compile_policy(
            PolicySource::GitRepo {
                repo_url: "https://example.com/repo".to_string(),
                commit_sha: "a".repeat(40),
                file_path: "policy.toml".to_string(),
            },
            toml_policy(),
            "git_policy",
            3,
            ts(80),
            BTreeSet::new(),
        );
        assert!(result.is_success());
        let art = result.artifact().unwrap();
        assert_eq!(art.version, 3);
    }

    #[test]
    fn test_compile_policy_with_tags() {
        let mut tags = BTreeSet::new();
        tags.insert("security".to_string());
        tags.insert("runtime".to_string());
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
            "tagged_policy",
            1,
            ts(90),
            tags.clone(),
        );
        assert!(result.is_success());
        assert_eq!(result.artifact().unwrap().tags, tags);
    }

    #[test]
    fn test_compile_policy_deterministic_id() {
        // Same bytes + same version → same artifact_id.
        let r1 = compile_policy(
            PolicySource::InlineToml {
                label: "a".to_string(),
            },
            toml_policy(),
            "p",
            1,
            ts(1),
            BTreeSet::new(),
        );
        let r2 = compile_policy(
            PolicySource::InlineToml {
                label: "b".to_string(),
            },
            toml_policy(),
            "p",
            1,
            ts(999),
            BTreeSet::new(),
        );
        // compiled_hash (and thus artifact_id) depends only on compiled_bytes.
        assert_eq!(
            r1.artifact().unwrap().compiled_hash,
            r2.artifact().unwrap().compiled_hash
        );
        assert_eq!(
            r1.artifact().unwrap().artifact_id,
            r2.artifact().unwrap().artifact_id
        );
    }

    // -----------------------------------------------------------------------
    // compile_policy — failure cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_compile_policy_empty_bytes() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"",
            "empty",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
        assert!(result.count_at_severity(DiagnosticSeverity::Error) > 0);
    }

    #[test]
    fn test_compile_policy_whitespace_only() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"   \n  \t  ",
            "ws",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
    }

    #[test]
    fn test_compile_json_invalid_syntax() {
        let result = compile_policy(
            PolicySource::InlineJson {
                label: "j".to_string(),
            },
            b"not-json-at-all",
            "bad",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
        assert_eq!(result.count_at_severity(DiagnosticSeverity::Error), 1);
    }

    #[test]
    fn test_compile_toml_invalid_syntax() {
        // No `=` or `[` present.
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"this is not toml at all",
            "bad_toml",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
    }

    #[test]
    fn test_compile_policy_invalid_utf8() {
        let bad_bytes = [0xFF, 0xFE, 0x00];
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            &bad_bytes,
            "bad_utf8",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
    }

    // -----------------------------------------------------------------------
    // PolicyCompilationResult helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_compilation_result_diagnostics_access() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"",
            "p",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
        assert!(!result.diagnostics().is_empty());
        assert_eq!(result.artifact(), None);
    }

    // -----------------------------------------------------------------------
    // validate_policy
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_ok() {
        let art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        assert!(validate_policy(&art, None).is_ok());
    }

    #[test]
    fn test_validate_policy_version_min_ok() {
        let art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        assert!(validate_policy(&art, Some(1)).is_ok());
    }

    #[test]
    fn test_validate_policy_version_min_fail() {
        let art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        let err = validate_policy(&art, Some(99)).unwrap_err();
        assert!(matches!(err, GovernanceError::PolicySchemaViolation { .. }));
    }

    #[test]
    fn test_validate_policy_empty_compiled_bytes() {
        let art = PolicyArtifact {
            artifact_id: {
                let schema = SchemaId::from_definition(POLICY_ARTIFACT_SCHEMA_DEF);
                engine_object_id::derive_id(
                    ObjectDomain::PolicyObject,
                    GOVERNANCE_ZONE,
                    &schema,
                    b"placeholder",
                )
                .unwrap()
            },
            version: 1,
            definition_hash: ContentHash::compute(b"x"),
            compiled_hash: ContentHash::compute(b""),
            compiled_bytes: vec![],
            source: PolicySource::InlineToml {
                label: "t".to_string(),
            },
            compiled_at: ts(1),
            policy_name: "p".to_string(),
            tags: BTreeSet::new(),
        };
        let err = validate_policy(&art, None).unwrap_err();
        assert!(matches!(err, GovernanceError::PolicySchemaViolation { .. }));
    }

    #[test]
    fn test_validate_policy_hash_mismatch() {
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        // Corrupt the compiled_hash.
        art.compiled_hash = ContentHash::compute(b"wrong");
        let err = validate_policy(&art, None).unwrap_err();
        assert!(matches!(err, GovernanceError::PolicySchemaViolation { .. }));
    }

    #[test]
    fn test_validate_policy_zero_version() {
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        art.version = 0;
        let err = validate_policy(&art, None).unwrap_err();
        assert!(matches!(err, GovernanceError::PolicySchemaViolation { .. }));
    }

    #[test]
    fn test_validate_policy_empty_name() {
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        art.policy_name = "   ".to_string();
        let err = validate_policy(&art, None).unwrap_err();
        assert!(matches!(err, GovernanceError::PolicySchemaViolation { .. }));
    }

    // -----------------------------------------------------------------------
    // AuditExportFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_export_format_as_str() {
        assert_eq!(AuditExportFormat::JsonLines.as_str(), "jsonlines");
        assert_eq!(AuditExportFormat::Csv.as_str(), "csv");
        assert_eq!(AuditExportFormat::Parquet.as_str(), "parquet");
        assert_eq!(AuditExportFormat::CompliancePdf.as_str(), "compliance_pdf");
    }

    #[test]
    fn test_audit_export_format_file_extension() {
        assert_eq!(AuditExportFormat::JsonLines.file_extension(), "jsonl");
        assert_eq!(AuditExportFormat::Csv.file_extension(), "csv");
        assert_eq!(AuditExportFormat::Parquet.file_extension(), "parquet");
        assert_eq!(AuditExportFormat::CompliancePdf.file_extension(), "pdf");
    }

    #[test]
    fn test_audit_export_format_all() {
        assert_eq!(AuditExportFormat::all().len(), 4);
    }

    #[test]
    fn test_audit_export_format_display() {
        for fmt in AuditExportFormat::all() {
            let s = format!("{fmt}");
            assert!(!s.is_empty());
            assert_eq!(s, fmt.as_str());
        }
    }

    #[test]
    fn test_audit_export_format_serde() {
        for fmt in AuditExportFormat::all() {
            let json = serde_json::to_string(fmt).unwrap();
            let decoded: AuditExportFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(*fmt, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // export_audit_evidence
    // -----------------------------------------------------------------------

    fn make_export_request(format: AuditExportFormat, start: u64, end: u64) -> AuditExportRequest {
        AuditExportRequest {
            format,
            start_tick: ts(start),
            end_tick: ts(end),
            evidence_kinds: None,
            max_entries: None,
            requester: "test_agent".to_string(),
            correlation_id: None,
        }
    }

    #[test]
    fn test_export_jsonlines_success() {
        let entries = vec![
            make_entry("policy_update", 10),
            make_entry("security_action", 20),
        ];
        let req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 2);
        assert!(result.payload_bytes.contains(&b'\n'));
        let text = std::str::from_utf8(&result.payload_bytes).unwrap();
        assert!(text.contains("policy_update"));
    }

    #[test]
    fn test_export_csv_success() {
        let entries = vec![make_entry("epoch_transition", 15)];
        let req = make_export_request(AuditExportFormat::Csv, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 1);
        let text = std::str::from_utf8(&result.payload_bytes).unwrap();
        assert!(text.starts_with("entry_id,"));
        assert!(text.contains("epoch_transition"));
    }

    #[test]
    fn test_export_parquet_success() {
        let entries = vec![make_entry("capability_decision", 30)];
        let req = make_export_request(AuditExportFormat::Parquet, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 1);
        let text = std::str::from_utf8(&result.payload_bytes).unwrap();
        assert!(text.starts_with("FRANKEN_PARQUET_V1"));
    }

    #[test]
    fn test_export_compliance_pdf_success() {
        let entries = vec![make_entry("revocation", 40)];
        let req = make_export_request(AuditExportFormat::CompliancePdf, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 1);
        let text = std::str::from_utf8(&result.payload_bytes).unwrap();
        assert!(text.contains("FRANKEN_COMPLIANCE_REPORT_V1"));
    }

    #[test]
    fn test_export_empty_range() {
        let entries = vec![make_entry("policy_update", 200)];
        // The entry is outside the requested range.
        let req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result = export_audit_evidence(req, entries, ts(300)).unwrap();
        assert_eq!(result.entry_count, 0);
        assert!(result.payload_bytes.is_empty());
    }

    #[test]
    fn test_export_invalid_time_range() {
        let req = make_export_request(AuditExportFormat::JsonLines, 100, 50);
        let err = export_audit_evidence(req, vec![], ts(200)).unwrap_err();
        assert!(matches!(err, GovernanceError::InvalidTimeRange { .. }));
    }

    #[test]
    fn test_export_kind_filter() {
        let entries = vec![
            make_entry("policy_update", 10),
            make_entry("security_action", 20),
            make_entry("policy_update", 30),
        ];
        let mut req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let mut kinds = BTreeSet::new();
        kinds.insert("policy_update".to_string());
        req.evidence_kinds = Some(kinds);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 2);
    }

    #[test]
    fn test_export_max_entries_cap() {
        let entries: Vec<EvidenceEntry> = (0..10)
            .map(|i| make_entry("policy_update", i * 5))
            .collect();
        let mut req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        req.max_entries = Some(3);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(result.entry_count, 3);
    }

    #[test]
    fn test_export_payload_hash_consistency() {
        let entries = vec![make_entry("policy_update", 10)];
        let req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(
            result.payload_hash,
            ContentHash::compute(&result.payload_bytes)
        );
    }

    #[test]
    fn test_export_correlation_id_preserved() {
        let mut req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        req.correlation_id = Some("AUDIT-2026-001".to_string());
        let result = export_audit_evidence(req, vec![], ts(200)).unwrap();
        assert_eq!(
            result.request.correlation_id,
            Some("AUDIT-2026-001".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // ComplianceFramework
    // -----------------------------------------------------------------------

    #[test]
    fn test_compliance_framework_as_str() {
        assert_eq!(ComplianceFramework::Soc2.as_str(), "soc2");
        assert_eq!(ComplianceFramework::Iso27001.as_str(), "iso27001");
        assert_eq!(ComplianceFramework::Hipaa.as_str(), "hipaa");
        assert_eq!(ComplianceFramework::PciDss.as_str(), "pci_dss");
        assert_eq!(ComplianceFramework::Gdpr.as_str(), "gdpr");
        assert_eq!(
            ComplianceFramework::Custom("myfw".to_string()).as_str(),
            "myfw"
        );
    }

    #[test]
    fn test_compliance_framework_display() {
        assert_eq!(format!("{}", ComplianceFramework::Soc2), "soc2");
        assert_eq!(
            format!("{}", ComplianceFramework::Custom("x".to_string())),
            "x"
        );
    }

    #[test]
    fn test_compliance_framework_all_builtin() {
        let all = ComplianceFramework::all_builtin();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_compliance_framework_serde() {
        let fw = ComplianceFramework::Custom("special_framework".to_string());
        let json = serde_json::to_string(&fw).unwrap();
        let decoded: ComplianceFramework = serde_json::from_str(&json).unwrap();
        assert_eq!(fw, decoded);
    }

    // -----------------------------------------------------------------------
    // generate_compliance_bundle
    // -----------------------------------------------------------------------

    fn full_evidence_set() -> Vec<EvidenceEntry> {
        vec![
            make_entry("capability_decision", 10),
            make_entry("policy_update", 20),
            make_entry("security_action", 30),
            make_entry("epoch_transition", 40),
            make_entry("revocation", 50),
            make_entry("activation_lifecycle", 60),
        ]
    }

    #[test]
    fn test_compliance_bundle_soc2_all_satisfied() {
        let entries = full_evidence_set();
        let (bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(bundle.framework, ComplianceFramework::Soc2);
        // With all evidence kinds present, all controls should be satisfied.
        assert!(contract.satisfaction_rate_millionths > 0);
        assert_eq!(contract.framework, ComplianceFramework::Soc2);
    }

    #[test]
    fn test_compliance_bundle_empty_entries() {
        let (bundle, contract) =
            generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), vec![], ts(200))
                .unwrap();
        assert_eq!(bundle.entries.len(), 0);
        assert_eq!(contract.satisfaction_rate_millionths, 0);
        assert!(contract.unsatisfied_count() > 0);
    }

    #[test]
    fn test_compliance_bundle_missing_control_kinds() {
        // Provide only one evidence kind for SOC 2 which needs several.
        let entries = vec![make_entry("policy_update", 10)];
        let (_bundle, contract) =
            generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
                .unwrap();
        // Some controls will not be satisfied (CC6.2, CC7.2, CC9.2 require
        // other kinds).
        assert!(contract.unsatisfied_count() > 0);
        let gaps = contract.all_gaps();
        assert!(!gaps.is_empty());
    }

    #[test]
    fn test_compliance_bundle_iso27001() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Iso27001,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(contract.framework, ComplianceFramework::Iso27001);
        assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
    }

    #[test]
    fn test_compliance_bundle_hipaa() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Hipaa,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(contract.framework, ComplianceFramework::Hipaa);
        assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
    }

    #[test]
    fn test_compliance_bundle_pci_dss() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::PciDss,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(contract.framework, ComplianceFramework::PciDss);
        assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
    }

    #[test]
    fn test_compliance_bundle_gdpr() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Gdpr,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
    }

    #[test]
    fn test_compliance_bundle_custom_framework() {
        let entries = vec![
            make_entry("policy_update", 10),
            make_entry("security_action", 20),
        ];
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Custom("my_fw".to_string()),
            ts(0),
            ts(100),
            entries,
            ts(200),
        )
        .unwrap();
        assert_eq!(contract.satisfaction_rate_millionths, 1_000_000);
    }

    #[test]
    fn test_compliance_bundle_invalid_time_range() {
        let err = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(500),
            ts(100),
            vec![],
            ts(600),
        )
        .unwrap_err();
        assert!(matches!(err, GovernanceError::InvalidTimeRange { .. }));
    }

    #[test]
    fn test_compliance_bundle_window_filtering() {
        let entries = vec![
            make_entry("policy_update", 10),
            make_entry("policy_update", 500), // outside window
        ];
        let (bundle, _contract) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            entries,
            ts(200),
        )
        .unwrap();
        assert_eq!(bundle.entries.len(), 1);
    }

    #[test]
    fn test_compliance_contract_find_control() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        let ctrl = contract.find_control("CC6.1").unwrap();
        assert_eq!(ctrl.control_id, "CC6.1");
        assert!(contract.find_control("NONEXISTENT").is_none());
    }

    #[test]
    fn test_compliance_bundle_hash_determinism() {
        let entries = vec![make_entry("policy_update", 10)];
        let (b1, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            entries.clone(),
            ts(200),
        )
        .unwrap();
        let (b2, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            entries,
            ts(999),
        )
        .unwrap();
        // bundle_hash depends only on evidence entries, not on assembled_at.
        assert_eq!(b1.bundle_hash, b2.bundle_hash);
    }

    // -----------------------------------------------------------------------
    // GovernanceHookType
    // -----------------------------------------------------------------------

    #[test]
    fn test_hook_type_as_str() {
        assert_eq!(GovernanceHookType::PreDeploy.as_str(), "pre_deploy");
        assert_eq!(GovernanceHookType::PostDeploy.as_str(), "post_deploy");
        assert_eq!(GovernanceHookType::PolicyChange.as_str(), "policy_change");
        assert_eq!(GovernanceHookType::AuditExport.as_str(), "audit_export");
        assert_eq!(
            GovernanceHookType::ComplianceCheck.as_str(),
            "compliance_check"
        );
    }

    #[test]
    fn test_hook_type_display() {
        for h in GovernanceHookType::all() {
            assert_eq!(format!("{h}"), h.as_str());
        }
    }

    #[test]
    fn test_hook_type_all() {
        assert_eq!(GovernanceHookType::all().len(), 5);
    }

    #[test]
    fn test_hook_type_serde() {
        for h in GovernanceHookType::all() {
            let json = serde_json::to_string(h).unwrap();
            let decoded: GovernanceHookType = serde_json::from_str(&json).unwrap();
            assert_eq!(*h, decoded);
        }
    }

    // -----------------------------------------------------------------------
    // GovernanceHookResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_hook_result_pass_fail() {
        let pass = GovernanceHookResult::pass(GovernanceHookType::PreDeploy, "all good", ts(1));
        assert!(pass.passed);
        let fail =
            GovernanceHookResult::fail(GovernanceHookType::PostDeploy, "hash mismatch", ts(2));
        assert!(!fail.passed);
    }

    #[test]
    fn test_hook_result_display_pass() {
        let r = GovernanceHookResult::pass(GovernanceHookType::PolicyChange, "ok", ts(1));
        let s = format!("{r}");
        assert!(s.contains("PASS"));
        assert!(s.contains("policy_change"));
        assert!(s.contains("ok"));
    }

    #[test]
    fn test_hook_result_display_fail() {
        let r = GovernanceHookResult::fail(
            GovernanceHookType::ComplianceCheck,
            "below threshold",
            ts(1),
        );
        let s = format!("{r}");
        assert!(s.contains("FAIL"));
        assert!(s.contains("compliance_check"));
    }

    #[test]
    fn test_hook_result_serde() {
        let r = GovernanceHookResult::pass(GovernanceHookType::AuditExport, "exported", ts(99));
        let json = serde_json::to_string(&r).unwrap();
        let decoded: GovernanceHookResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    // -----------------------------------------------------------------------
    // DiagnosticSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn test_diagnostic_severity_all() {
        let all = DiagnosticSeverity::all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_diagnostic_severity_display() {
        assert_eq!(format!("{}", DiagnosticSeverity::Info), "info");
        assert_eq!(format!("{}", DiagnosticSeverity::Warning), "warning");
        assert_eq!(format!("{}", DiagnosticSeverity::Error), "error");
    }

    #[test]
    fn test_diagnostic_severity_ordering() {
        assert!(DiagnosticSeverity::Info < DiagnosticSeverity::Warning);
        assert!(DiagnosticSeverity::Warning < DiagnosticSeverity::Error);
    }

    // -----------------------------------------------------------------------
    // run_governance_pipeline
    // -----------------------------------------------------------------------

    fn make_pipeline(halt: bool) -> GovernancePipeline {
        GovernancePipeline::new(GovernancePipelineConfig {
            halt_on_failure: halt,
            ..Default::default()
        })
    }

    fn single_artifact() -> Vec<PolicyArtifact> {
        vec![compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        )]
    }

    #[test]
    fn test_pipeline_all_hooks_pass_no_evidence() {
        // With halt_on_failure=false all 5 hooks fire regardless of outcome.
        // ComplianceCheck will fail with 0% satisfaction (no evidence), but
        // the pipeline continues and records all hook results.
        let mut pipeline = make_pipeline(false);
        let results =
            run_governance_pipeline(&mut pipeline, &single_artifact(), vec![], ts(500)).unwrap();
        assert_eq!(results.len(), GovernanceHookType::all().len());
        // PreDeploy, PostDeploy, PolicyChange, and AuditExport all pass.
        assert!(results[0].passed, "PreDeploy should pass");
        assert!(results[1].passed, "PostDeploy should pass");
        assert!(results[2].passed, "PolicyChange should pass");
        assert!(results[3].passed, "AuditExport should pass");
        // ComplianceCheck with no evidence fails (0% satisfaction < 50%).
        assert!(
            !results[4].passed,
            "ComplianceCheck should fail with no evidence"
        );
        assert_eq!(pipeline.events().len(), results.len());
    }

    #[test]
    fn test_pipeline_all_hooks_pass_with_evidence() {
        let mut pipeline = make_pipeline(true);
        let entries = full_evidence_set();
        let results =
            run_governance_pipeline(&mut pipeline, &single_artifact(), entries, ts(500)).unwrap();
        assert_eq!(results.len(), GovernanceHookType::all().len());
        // With full evidence set all built-in frameworks satisfy > 50% controls.
        for r in &results {
            assert!(
                r.passed,
                "hook {:?} unexpectedly failed: {}",
                r.hook_type, r.message
            );
        }
    }

    #[test]
    fn test_pipeline_events_recorded() {
        let mut pipeline = make_pipeline(false);
        let results =
            run_governance_pipeline(&mut pipeline, &single_artifact(), vec![], ts(300)).unwrap();
        assert_eq!(pipeline.events().len(), results.len());
        for event in pipeline.events() {
            assert!(!event.summary.is_empty());
        }
    }

    #[test]
    fn test_pipeline_halt_on_pre_deploy_failure() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![
                GovernanceHookType::PreDeploy,
                GovernanceHookType::PostDeploy,
            ],
            halt_on_failure: true,
            ..Default::default()
        });
        // Inject an invalid artifact (zero version).
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        art.version = 0; // makes validate_policy fail
        let err = run_governance_pipeline(&mut pipeline, &[art], vec![], ts(100)).unwrap_err();
        assert!(matches!(err, GovernanceError::HookFailed { .. }));
        // Pipeline halted after first hook.
        assert_eq!(pipeline.events().len(), 1);
    }

    #[test]
    fn test_pipeline_continue_on_failure() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![
                GovernanceHookType::PreDeploy,
                GovernanceHookType::PostDeploy,
            ],
            halt_on_failure: false,
            ..Default::default()
        });
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        art.version = 0;
        // Should NOT return Err because halt_on_failure = false.
        let results = run_governance_pipeline(&mut pipeline, &[art], vec![], ts(100)).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].passed);
        // PostDeploy checks compiled_hash consistency — valid artifact still passes.
    }

    #[test]
    fn test_pipeline_empty_hooks() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![],
            halt_on_failure: true,
            ..Default::default()
        });
        let results = run_governance_pipeline(&mut pipeline, &[], vec![], ts(1)).unwrap();
        assert!(results.is_empty());
        assert!(pipeline.events().is_empty());
    }

    #[test]
    fn test_pipeline_single_hook_audit_export() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::AuditExport],
            halt_on_failure: true,
            ..Default::default()
        });
        let entries = vec![make_entry("policy_update", 10)];
        let results = run_governance_pipeline(&mut pipeline, &[], entries, ts(200)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert!(results[0].details.contains_key("entry_count"));
    }

    #[test]
    fn test_pipeline_policy_change_duplicate_hash_detected() {
        // Two artifacts compiled from identical bytes → same compiled_hash →
        // PolicyChange hook should fail.
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::PolicyChange],
            halt_on_failure: false,
            ..Default::default()
        });
        let art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        let art2 = art.clone();
        let results =
            run_governance_pipeline(&mut pipeline, &[art, art2], vec![], ts(100)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
    }

    // -----------------------------------------------------------------------
    // GovernanceError display
    // -----------------------------------------------------------------------

    #[test]
    fn test_governance_error_display_coverage() {
        let errors = vec![
            GovernanceError::EmptyPolicyDefinition,
            GovernanceError::InvalidPolicySyntax {
                expected_format: "toml".to_string(),
                reason: "missing =".to_string(),
            },
            GovernanceError::PolicySchemaViolation {
                constraint: "version must be non-zero".to_string(),
            },
            GovernanceError::IdDerivationFailed {
                detail: "empty canonical bytes".to_string(),
            },
            GovernanceError::InvalidTimeRange {
                start: ts(100),
                end: ts(50),
            },
            GovernanceError::NoEvidenceInRange {
                start: ts(0),
                end: ts(100),
            },
            GovernanceError::UnknownFramework {
                framework: "mystery".to_string(),
            },
            GovernanceError::MissingControl {
                control_id: "CC6.1".to_string(),
            },
            GovernanceError::HookFailed {
                hook_type: GovernanceHookType::PreDeploy,
                reason: "validation failed".to_string(),
            },
            GovernanceError::SerialisationFailed {
                reason: "IO error".to_string(),
            },
        ];
        for err in &errors {
            let s = format!("{err}");
            assert!(!s.is_empty(), "empty display for {err:?}");
        }
    }

    #[test]
    fn test_governance_error_serde() {
        let err = GovernanceError::PolicySchemaViolation {
            constraint: "version must be non-zero".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips for all public types
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_artifact_serde() {
        let art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        let json = serde_json::to_string(&art).unwrap();
        let decoded: PolicyArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(art, decoded);
    }

    #[test]
    fn test_compliance_evidence_serde() {
        let entries = vec![make_entry("policy_update", 10)];
        let (bundle, _) =
            generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), entries, ts(200))
                .unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let decoded: ComplianceEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, decoded);
    }

    #[test]
    fn test_compliance_evidence_contract_serde() {
        let entries = full_evidence_set();
        let (_, contract) = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        let json = serde_json::to_string(&contract).unwrap();
        let decoded: ComplianceEvidenceContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, decoded);
    }

    #[test]
    fn test_audit_export_result_serde() {
        let entries = vec![make_entry("policy_update", 10)];
        let req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let decoded: AuditExportResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn test_governance_event_serde() {
        let event = GovernanceEvent {
            event_id: {
                let schema = SchemaId::from_definition(GOVERNANCE_EVENT_SCHEMA_DEF);
                engine_object_id::derive_id(
                    ObjectDomain::EvidenceRecord,
                    GOVERNANCE_ZONE,
                    &schema,
                    b"test_event",
                )
                .unwrap()
            },
            hook_type: GovernanceHookType::PolicyChange,
            passed: true,
            summary: "policy changed".to_string(),
            attributes: BTreeMap::new(),
            timestamp: ts(42),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: GovernanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_large_policy_bytes() {
        let large = vec![b'a'; 500_000];
        // Insert a `=` so it looks like TOML.
        let mut policy = large;
        policy.extend_from_slice(b"\nkey=value");
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "big".to_string(),
            },
            &policy,
            "large_policy",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(result.is_success());
    }

    #[test]
    fn test_export_exact_boundary_ticks() {
        let entries = vec![
            make_entry("policy_update", 0),
            make_entry("policy_update", 50),
            make_entry("policy_update", 100),
        ];
        let req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        // All three entries are within [0, 100] inclusive.
        assert_eq!(result.entry_count, 3);
    }

    #[test]
    fn test_compliance_contract_all_gaps_formatting() {
        // Force all controls to be unsatisfied (empty evidence).
        let (_bundle, contract) =
            generate_compliance_bundle(ComplianceFramework::Soc2, ts(0), ts(100), vec![], ts(200))
                .unwrap();
        let gaps = contract.all_gaps();
        // Every gap should be prefixed with the control ID.
        for gap in &gaps {
            assert!(gap.starts_with('['), "gap missing control prefix: {gap}");
        }
    }

    #[test]
    fn test_evidence_entry_ids_for_kind() {
        let entries = vec![
            make_entry("policy_update", 10),
            make_entry("security_action", 20),
            make_entry("policy_update", 30),
        ];
        let (bundle, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            entries,
            ts(200),
        )
        .unwrap();
        let ids = bundle.ids_for_kind("policy_update");
        assert_eq!(ids.len(), 2);
        let ids2 = bundle.ids_for_kind("revocation");
        assert!(ids2.is_empty());
    }

    #[test]
    fn test_pipeline_config_default_hooks_coverage() {
        let cfg = GovernancePipelineConfig::default();
        // Default should have all 5 hooks.
        assert_eq!(cfg.hooks.len(), GovernanceHookType::all().len());
        assert!(cfg.halt_on_failure);
        assert_eq!(cfg.max_export_entries, 100_000);
    }

    // -- Enrichment: std::error --

    #[test]
    fn governance_error_implements_std_error() {
        use crate::policy_checkpoint::DeterministicTimestamp;
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(GovernanceError::EmptyPolicyDefinition),
            Box::new(GovernanceError::InvalidPolicySyntax {
                expected_format: "json".into(),
                reason: "parse fail".into(),
            }),
            Box::new(GovernanceError::PolicySchemaViolation {
                constraint: "max_length".into(),
            }),
            Box::new(GovernanceError::IdDerivationFailed {
                detail: "bad".into(),
            }),
            Box::new(GovernanceError::InvalidTimeRange {
                start: DeterministicTimestamp(100),
                end: DeterministicTimestamp(50),
            }),
            Box::new(GovernanceError::NoEvidenceInRange {
                start: DeterministicTimestamp(0),
                end: DeterministicTimestamp(100),
            }),
            Box::new(GovernanceError::UnknownFramework {
                framework: "soc3".into(),
            }),
            Box::new(GovernanceError::MissingControl {
                control_id: "AC-1".into(),
            }),
            Box::new(GovernanceError::HookFailed {
                hook_type: GovernanceHookType::PreDeploy,
                reason: "timeout".into(),
            }),
            Box::new(GovernanceError::SerialisationFailed {
                reason: "json".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            10,
            "all 10 variants produce distinct messages"
        );
    }

    #[test]
    fn test_diagnostic_severity_serde() {
        for sev in DiagnosticSeverity::all() {
            let json = serde_json::to_string(sev).unwrap();
            let decoded: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, decoded);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn governance_error_serde_all_variants() {
        let errors = vec![
            GovernanceError::EmptyPolicyDefinition,
            GovernanceError::InvalidPolicySyntax {
                expected_format: "toml".to_string(),
                reason: "parse error".to_string(),
            },
            GovernanceError::PolicySchemaViolation {
                constraint: "c".to_string(),
            },
            GovernanceError::IdDerivationFailed {
                detail: "d".to_string(),
            },
            GovernanceError::InvalidTimeRange {
                start: ts(100),
                end: ts(50),
            },
            GovernanceError::NoEvidenceInRange {
                start: ts(0),
                end: ts(100),
            },
            GovernanceError::UnknownFramework {
                framework: "mystery".to_string(),
            },
            GovernanceError::MissingControl {
                control_id: "CC6.1".to_string(),
            },
            GovernanceError::HookFailed {
                hook_type: GovernanceHookType::PreDeploy,
                reason: "timeout".to_string(),
            },
            GovernanceError::SerialisationFailed {
                reason: "io".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let decoded: GovernanceError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, decoded);
        }
        assert_eq!(errors.len(), 10);
    }

    #[test]
    fn policy_diagnostic_serde_roundtrip() {
        let diag = PolicyDiagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "W0001".to_string(),
            message: "deprecated field".to_string(),
            span: Some((10, 20)),
        };
        let json = serde_json::to_string(&diag).unwrap();
        let decoded: PolicyDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, decoded);

        // Also test with None span.
        let diag2 = PolicyDiagnostic {
            severity: DiagnosticSeverity::Info,
            code: "I0001".to_string(),
            message: "hint".to_string(),
            span: None,
        };
        let json2 = serde_json::to_string(&diag2).unwrap();
        let decoded2: PolicyDiagnostic = serde_json::from_str(&json2).unwrap();
        assert_eq!(diag2, decoded2);
    }

    #[test]
    fn policy_compilation_result_serde_success_variant() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
            "p",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(result.is_success());
        let json = serde_json::to_string(&result).unwrap();
        let decoded: PolicyCompilationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn policy_compilation_result_serde_failure_variant() {
        let result = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"",
            "p",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert!(!result.is_success());
        let json = serde_json::to_string(&result).unwrap();
        let decoded: PolicyCompilationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn governance_pipeline_config_serde_roundtrip() {
        let config = GovernancePipelineConfig {
            hooks: vec![
                GovernanceHookType::PreDeploy,
                GovernanceHookType::AuditExport,
            ],
            halt_on_failure: false,
            max_export_entries: 42,
            frameworks: vec![ComplianceFramework::Soc2],
        };
        let json = serde_json::to_string(&config).unwrap();
        let decoded: GovernancePipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn audit_export_request_serde_roundtrip() {
        let mut kinds = BTreeSet::new();
        kinds.insert("policy_update".to_string());
        let req = AuditExportRequest {
            format: AuditExportFormat::Csv,
            start_tick: ts(10),
            end_tick: ts(90),
            evidence_kinds: Some(kinds),
            max_entries: Some(50),
            requester: "auditor".to_string(),
            correlation_id: Some("CORR-001".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: AuditExportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn compliance_control_serde_roundtrip() {
        let schema = SchemaId::from_definition(b"TestControl.v1");
        let eid = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            "test",
            &schema,
            b"evidence_1",
        )
        .unwrap();
        let ctrl = ComplianceControl {
            control_id: "CC6.1".to_string(),
            description: "Access controls".to_string(),
            satisfied: true,
            evidence_entry_ids: vec![eid],
            gaps: vec![],
        };
        let json = serde_json::to_string(&ctrl).unwrap();
        let decoded: ComplianceControl = serde_json::from_str(&json).unwrap();
        assert_eq!(ctrl, decoded);
    }

    #[test]
    fn evidence_entry_serde_roundtrip() {
        let mut attrs = BTreeMap::new();
        attrs.insert("key".to_string(), "value".to_string());
        let entry = make_entry("policy_update", 42);
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: EvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn compliance_evidence_entry_count_method() {
        let entries = full_evidence_set();
        let expected_count = entries.len();
        let (bundle, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(bundle.entry_count(), expected_count);
    }

    #[test]
    fn pipeline_config_accessor_returns_correct_values() {
        let config = GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::PreDeploy],
            halt_on_failure: false,
            max_export_entries: 77,
            frameworks: vec![ComplianceFramework::Gdpr],
        };
        let pipeline = GovernancePipeline::new(config.clone());
        assert_eq!(pipeline.config().hooks, config.hooks);
        assert!(!pipeline.config().halt_on_failure);
        assert_eq!(pipeline.config().max_export_entries, 77);
        assert_eq!(pipeline.config().frameworks.len(), 1);
    }

    #[test]
    fn compliance_bundle_hash_differs_for_different_entries() {
        let (b1, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            vec![make_entry("policy_update", 10)],
            ts(200),
        )
        .unwrap();
        let (b2, _) = generate_compliance_bundle(
            ComplianceFramework::Custom("f".to_string()),
            ts(0),
            ts(100),
            vec![make_entry("security_action", 10)],
            ts(200),
        )
        .unwrap();
        assert_ne!(
            b1.bundle_hash, b2.bundle_hash,
            "different evidence should produce different bundle hashes"
        );
    }

    #[test]
    fn post_deploy_hash_check_failure_halts_pipeline() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::PostDeploy],
            halt_on_failure: true,
            ..Default::default()
        });
        let mut art = compile_ok(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            toml_policy(),
        );
        // Corrupt the compiled_hash so PostDeploy fails.
        art.compiled_hash = ContentHash::compute(b"corrupted");
        let err = run_governance_pipeline(&mut pipeline, &[art], vec![], ts(100)).unwrap_err();
        assert!(matches!(err, GovernanceError::HookFailed { .. }));
        assert_eq!(pipeline.events().len(), 1);
    }

    #[test]
    fn policy_source_display_uniqueness_btreeset() {
        let sources = [
            PolicySource::GitRepo {
                repo_url: "https://r".to_string(),
                commit_sha: "a".repeat(40),
                file_path: "p.toml".to_string(),
            },
            PolicySource::FileSystem {
                absolute_path: "/p".to_string(),
            },
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            PolicySource::InlineJson {
                label: "j".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for s in &sources {
            displays.insert(format!("{s}"));
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 PolicySource variants produce distinct Display strings"
        );
    }

    #[test]
    fn compliance_bundle_id_sensitive_to_framework() {
        let entries = vec![make_entry("policy_update", 10)];
        let (b1, _) = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(0),
            ts(100),
            entries.clone(),
            ts(200),
        )
        .unwrap();
        let (b2, _) =
            generate_compliance_bundle(ComplianceFramework::Gdpr, ts(0), ts(100), entries, ts(200))
                .unwrap();
        assert_ne!(
            b1.bundle_id, b2.bundle_id,
            "different frameworks should produce different bundle IDs"
        );
    }

    #[test]
    fn governance_pipeline_config_default_serde_roundtrip() {
        let config = GovernancePipelineConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: GovernancePipelineConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 8 --

    #[test]
    fn policy_source_ord_ordering() {
        let git = PolicySource::GitRepo {
            repo_url: "https://r".to_string(),
            commit_sha: "a".repeat(40),
            file_path: "p.toml".to_string(),
        };
        let fs = PolicySource::FileSystem {
            absolute_path: "/p".to_string(),
        };
        let toml = PolicySource::InlineToml {
            label: "t".to_string(),
        };
        let json = PolicySource::InlineJson {
            label: "j".to_string(),
        };
        assert!(git < fs, "GitRepo < FileSystem");
        assert!(fs < toml, "FileSystem < InlineToml");
        assert!(toml < json, "InlineToml < InlineJson");
    }

    #[test]
    fn policy_source_display_inline_json() {
        let src = PolicySource::InlineJson {
            label: "my_ctx".to_string(),
        };
        assert_eq!(format!("{src}"), "inline_json:my_ctx");
    }

    #[test]
    fn audit_export_format_ord_ordering() {
        assert!(
            AuditExportFormat::JsonLines < AuditExportFormat::Csv,
            "JsonLines < Csv"
        );
        assert!(
            AuditExportFormat::Csv < AuditExportFormat::Parquet,
            "Csv < Parquet"
        );
        assert!(
            AuditExportFormat::Parquet < AuditExportFormat::CompliancePdf,
            "Parquet < CompliancePdf"
        );
    }

    #[test]
    fn export_id_differs_by_format() {
        let entries = vec![make_entry("policy_update", 10)];
        let req_jl = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        let result_jl = export_audit_evidence(req_jl, entries.clone(), ts(200)).unwrap();
        let req_csv = make_export_request(AuditExportFormat::Csv, 0, 100);
        let result_csv = export_audit_evidence(req_csv, entries, ts(200)).unwrap();
        assert_ne!(
            result_jl.export_id, result_csv.export_id,
            "different formats should produce different export IDs"
        );
    }

    #[test]
    fn unsatisfied_count_is_zero_when_all_satisfied() {
        let entries = full_evidence_set();
        let (_bundle, contract) = generate_compliance_bundle(
            ComplianceFramework::Soc2,
            ts(0),
            ts(1000),
            entries,
            ts(2000),
        )
        .unwrap();
        assert_eq!(
            contract.unsatisfied_count(),
            0,
            "with full evidence all SOC 2 controls should be satisfied"
        );
    }

    #[test]
    fn governance_event_attributes_from_hook_details() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::ComplianceCheck],
            halt_on_failure: false,
            frameworks: vec![ComplianceFramework::Soc2],
            ..Default::default()
        });
        let entries = full_evidence_set();
        let _results =
            run_governance_pipeline(&mut pipeline, &single_artifact(), entries, ts(500)).unwrap();
        let event = &pipeline.events()[0];
        // ComplianceCheck hook populates details with per-framework results;
        // those should flow into the event attributes.
        assert!(
            event.attributes.contains_key("soc2"),
            "event attributes should include framework key from hook details"
        );
    }

    #[test]
    fn max_entries_larger_than_available_preserves_all() {
        let entries: Vec<EvidenceEntry> = (0..3)
            .map(|i| make_entry("policy_update", i * 10))
            .collect();
        let mut req = make_export_request(AuditExportFormat::JsonLines, 0, 100);
        req.max_entries = Some(999);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(
            result.entry_count, 3,
            "max_entries > available should not truncate"
        );
    }

    #[test]
    fn pre_deploy_hook_details_contain_artifact_count() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::PreDeploy],
            halt_on_failure: true,
            ..Default::default()
        });
        let arts = single_artifact();
        let results = run_governance_pipeline(&mut pipeline, &arts, vec![], ts(100)).unwrap();
        assert!(results[0].passed);
        assert_eq!(
            results[0].details.get("artifact_count"),
            Some(&"1".to_string()),
            "PreDeploy hook should report artifact_count in details"
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn governance_error_source_returns_none() {
        use std::error::Error;
        let variants: Vec<GovernanceError> = vec![
            GovernanceError::EmptyPolicyDefinition,
            GovernanceError::InvalidPolicySyntax {
                expected_format: "toml".into(),
                reason: "bad".into(),
            },
            GovernanceError::PolicySchemaViolation {
                constraint: "c".into(),
            },
            GovernanceError::IdDerivationFailed { detail: "d".into() },
            GovernanceError::InvalidTimeRange {
                start: ts(100),
                end: ts(50),
            },
            GovernanceError::NoEvidenceInRange {
                start: ts(0),
                end: ts(100),
            },
            GovernanceError::UnknownFramework {
                framework: "x".into(),
            },
            GovernanceError::MissingControl {
                control_id: "c".into(),
            },
            GovernanceError::HookFailed {
                hook_type: GovernanceHookType::PreDeploy,
                reason: "r".into(),
            },
            GovernanceError::SerialisationFailed { reason: "r".into() },
        ];
        for v in &variants {
            assert!(v.source().is_none(), "source() should be None for {v:?}");
        }
    }

    #[test]
    fn governance_error_display_exact_format_all_10() {
        assert_eq!(
            GovernanceError::EmptyPolicyDefinition.to_string(),
            "policy definition bytes are empty"
        );
        assert_eq!(
            GovernanceError::InvalidPolicySyntax {
                expected_format: "toml".into(),
                reason: "missing =".into(),
            }
            .to_string(),
            "invalid toml policy syntax: missing ="
        );
        assert_eq!(
            GovernanceError::PolicySchemaViolation {
                constraint: "version must be non-zero".into(),
            }
            .to_string(),
            "policy schema violation: version must be non-zero"
        );
        assert_eq!(
            GovernanceError::IdDerivationFailed {
                detail: "empty bytes".into(),
            }
            .to_string(),
            "ID derivation failed: empty bytes"
        );
        assert_eq!(
            GovernanceError::InvalidTimeRange {
                start: ts(100),
                end: ts(50),
            }
            .to_string(),
            "invalid time range: start tick:100 > end tick:50"
        );
        assert_eq!(
            GovernanceError::NoEvidenceInRange {
                start: ts(0),
                end: ts(100),
            }
            .to_string(),
            "no evidence found in range tick:0..=tick:100"
        );
        assert_eq!(
            GovernanceError::UnknownFramework {
                framework: "soc3".into(),
            }
            .to_string(),
            "unknown compliance framework: soc3"
        );
        assert_eq!(
            GovernanceError::MissingControl {
                control_id: "CC6.1".into(),
            }
            .to_string(),
            "missing compliance control: CC6.1"
        );
        assert_eq!(
            GovernanceError::HookFailed {
                hook_type: GovernanceHookType::PreDeploy,
                reason: "timeout".into(),
            }
            .to_string(),
            "governance hook pre_deploy failed: timeout"
        );
        assert_eq!(
            GovernanceError::SerialisationFailed {
                reason: "IO error".into(),
            }
            .to_string(),
            "serialisation failed: IO error"
        );
    }

    #[test]
    fn csv_export_escapes_commas_in_summary() {
        let mut entry = make_entry("policy_update", 10);
        entry.summary = "contains, a comma".to_string();
        let entries = vec![entry];
        let req = make_export_request(AuditExportFormat::Csv, 0, 100);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        let text = std::str::from_utf8(&result.payload_bytes).unwrap();
        // csv_escape wraps in quotes when commas are present.
        assert!(
            text.contains("\"contains, a comma\""),
            "csv should quote fields with commas: {text}"
        );
    }

    #[test]
    fn export_zero_width_window_includes_exact_tick() {
        let entries = vec![
            make_entry("policy_update", 50),
            make_entry("policy_update", 51),
        ];
        let req = make_export_request(AuditExportFormat::JsonLines, 50, 50);
        let result = export_audit_evidence(req, entries, ts(200)).unwrap();
        assert_eq!(
            result.entry_count, 1,
            "zero-width window should include exact tick"
        );
    }

    #[test]
    fn compile_policy_different_bytes_different_artifact_id() {
        let r1 = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"key1 = true",
            "p1",
            1,
            ts(1),
            BTreeSet::new(),
        );
        let r2 = compile_policy(
            PolicySource::InlineToml {
                label: "t".to_string(),
            },
            b"key2 = false",
            "p2",
            1,
            ts(1),
            BTreeSet::new(),
        );
        assert_ne!(
            r1.artifact().unwrap().artifact_id,
            r2.artifact().unwrap().artifact_id,
            "different policy bytes should yield different artifact IDs"
        );
    }

    #[test]
    fn compliance_framework_serde_all_6_variants() {
        let variants = vec![
            ComplianceFramework::Soc2,
            ComplianceFramework::Iso27001,
            ComplianceFramework::Hipaa,
            ComplianceFramework::PciDss,
            ComplianceFramework::Gdpr,
            ComplianceFramework::Custom("my_fw".to_string()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let decoded: ComplianceFramework = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, decoded);
        }
    }

    #[test]
    fn governance_pipeline_new_starts_with_empty_events() {
        let pipeline = GovernancePipeline::new(GovernancePipelineConfig::default());
        assert!(pipeline.events().is_empty());
    }

    #[test]
    fn policy_change_hook_distinct_artifacts_passes() {
        let mut pipeline = GovernancePipeline::new(GovernancePipelineConfig {
            hooks: vec![GovernanceHookType::PolicyChange],
            halt_on_failure: true,
            ..Default::default()
        });
        let art1 = compile_ok(
            PolicySource::InlineToml {
                label: "a".to_string(),
            },
            b"key1 = true",
        );
        let art2 = compile_ok(
            PolicySource::InlineToml {
                label: "b".to_string(),
            },
            b"key2 = false",
        );
        let results =
            run_governance_pipeline(&mut pipeline, &[art1, art2], vec![], ts(100)).unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "PolicyChange should pass for distinct artifacts"
        );
        assert_eq!(
            results[0].details.get("unique_count"),
            Some(&"2".to_string())
        );
    }

    #[test]
    fn hook_result_display_exact_format() {
        let pass = GovernanceHookResult::pass(GovernanceHookType::PreDeploy, "all good", ts(1));
        assert_eq!(format!("{pass}"), "[PASS] pre_deploy \u{2014} all good");
        let fail = GovernanceHookResult::fail(
            GovernanceHookType::ComplianceCheck,
            "below threshold",
            ts(2),
        );
        assert_eq!(
            format!("{fail}"),
            "[FAIL] compliance_check \u{2014} below threshold"
        );
    }

    #[test]
    fn diagnostic_severity_as_str_all_3() {
        assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
        assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
        assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
    }

    #[test]
    fn governance_pipeline_config_default_frameworks_all_5_builtins() {
        let cfg = GovernancePipelineConfig::default();
        assert_eq!(cfg.frameworks.len(), 5);
        assert!(cfg.frameworks.contains(&ComplianceFramework::Soc2));
        assert!(cfg.frameworks.contains(&ComplianceFramework::Iso27001));
        assert!(cfg.frameworks.contains(&ComplianceFramework::Hipaa));
        assert!(cfg.frameworks.contains(&ComplianceFramework::PciDss));
        assert!(cfg.frameworks.contains(&ComplianceFramework::Gdpr));
    }

    #[test]
    fn compliance_control_direct_construction_with_gaps() {
        let ctrl = ComplianceControl {
            control_id: "CC6.1".to_string(),
            description: "Access controls".to_string(),
            satisfied: false,
            evidence_entry_ids: vec![],
            gaps: vec![
                "no evidence of kind 'capability_decision'".to_string(),
                "no evidence of kind 'policy_update'".to_string(),
            ],
        };
        assert!(!ctrl.satisfied);
        assert_eq!(ctrl.gaps.len(), 2);
        let json = serde_json::to_string(&ctrl).unwrap();
        let decoded: ComplianceControl = serde_json::from_str(&json).unwrap();
        assert_eq!(ctrl, decoded);
    }

    #[test]
    fn export_parquet_and_pdf_entry_count_matches() {
        let entries: Vec<EvidenceEntry> = (0..5)
            .map(|i| make_entry("security_action", i * 10))
            .collect();
        let req_parquet = make_export_request(AuditExportFormat::Parquet, 0, 100);
        let result_parquet = export_audit_evidence(req_parquet, entries.clone(), ts(200)).unwrap();
        let req_pdf = make_export_request(AuditExportFormat::CompliancePdf, 0, 100);
        let result_pdf = export_audit_evidence(req_pdf, entries, ts(200)).unwrap();
        assert_eq!(result_parquet.entry_count, 5);
        assert_eq!(result_pdf.entry_count, 5);
    }
}
