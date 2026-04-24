//! Advanced conformance-lab contract catalog for cross-repo boundary testing.
//!
//! Extends the baseline boundary contracts in `cross_repo_contract` with:
//! - Complete boundary surface enumeration (all sibling repos)
//! - Semantic version compatibility classes (patch / minor / major)
//! - Failure taxonomy with severity, required response, evidence requirements
//! - Replay obligations for conformance test reproducibility
//! - Machine-readable catalog with version-controlled change workflow
//!
//! Plan reference: Section 10.15 item 1 (`bd-1n78`).
//! Cross-refs: 9I.4 (FrankenSuite Cross-Repo Conformance Lab),
//! Section 10.14 (baseline boundary tests), Section 13 (release gate).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cross_repo_contract::RegressionClass;

// ---------------------------------------------------------------------------
// Boundary surface enumeration
// ---------------------------------------------------------------------------

/// Canonical sibling repo identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SiblingRepo {
    Asupersync,
    Frankentui,
    Frankensqlite,
    FrankenNode,
    SqlmodelRust,
    FastapiRust,
}

impl SiblingRepo {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asupersync => "asupersync",
            Self::Frankentui => "frankentui",
            Self::Frankensqlite => "frankensqlite",
            Self::FrankenNode => "franken_node",
            Self::SqlmodelRust => "sqlmodel_rust",
            Self::FastapiRust => "fastapi_rust",
        }
    }

    pub fn all() -> &'static [SiblingRepo] {
        &[
            Self::Asupersync,
            Self::Frankentui,
            Self::Frankensqlite,
            Self::FrankenNode,
            Self::SqlmodelRust,
            Self::FastapiRust,
        ]
    }

    /// Whether this boundary is a primary integration (always tested)
    /// or optional (tested when present).
    pub fn is_primary(self) -> bool {
        matches!(
            self,
            Self::Asupersync | Self::Frankentui | Self::Frankensqlite | Self::FrankenNode
        )
    }
}

impl fmt::Display for SiblingRepo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single boundary surface between FrankenEngine and a sibling repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundarySurface {
    pub sibling: SiblingRepo,
    pub surface_id: String,
    pub surface_kind: SurfaceKind,
    pub description: String,
    pub covered_fields: BTreeSet<String>,
    pub version_class: VersionClass,
}

/// Classification of a boundary surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SurfaceKind {
    IdentifierSchema,
    DecisionPayload,
    EvidencePayload,
    ApiMessage,
    PersistenceSemantics,
    ReplayFormat,
    ExportFormat,
    TuiEventContract,
    TuiStateContract,
    TelemetrySchema,
}

impl SurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentifierSchema => "identifier_schema",
            Self::DecisionPayload => "decision_payload",
            Self::EvidencePayload => "evidence_payload",
            Self::ApiMessage => "api_message",
            Self::PersistenceSemantics => "persistence_semantics",
            Self::ReplayFormat => "replay_format",
            Self::ExportFormat => "export_format",
            Self::TuiEventContract => "tui_event_contract",
            Self::TuiStateContract => "tui_state_contract",
            Self::TelemetrySchema => "telemetry_schema",
        }
    }
}

impl fmt::Display for SurfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Semantic version classes
// ---------------------------------------------------------------------------

/// Semantic version compatibility level for a contract field or surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VersionClass {
    /// No behavioral change: identical wire format, identical semantics.
    Patch,
    /// Additive only: new optional fields permitted, existing fields unchanged.
    Minor,
    /// Breaking changes permitted with documented migration path.
    Major,
}

impl VersionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    /// Whether adding a new optional field is permitted at this level.
    pub fn allows_additive_fields(self) -> bool {
        matches!(self, Self::Minor | Self::Major)
    }

    /// Whether removing or renaming fields is permitted at this level.
    pub fn allows_breaking_changes(self) -> bool {
        matches!(self, Self::Major)
    }
}

impl fmt::Display for VersionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-field version coverage: which compatibility level protects this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldVersionCoverage {
    pub field_name: String,
    pub protected_at: VersionClass,
    pub required: bool,
}

/// Version negotiation outcome between two repos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionNegotiationResult {
    pub boundary: SiblingRepo,
    pub local_version: SemanticVersion,
    pub remote_version: SemanticVersion,
    pub compatibility: VersionCompatibility,
    pub migration_required: bool,
    pub migration_path: Option<String>,
}

/// Semantic version triplet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Compatibility assessment between two semantic versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VersionCompatibility {
    /// Identical versions.
    Exact,
    /// Patch-level difference only.
    PatchCompatible,
    /// Minor-level difference (additive changes).
    MinorCompatible,
    /// Major-level difference (breaking).
    MajorIncompatible,
}

impl VersionCompatibility {
    pub fn is_compatible(self) -> bool {
        matches!(
            self,
            Self::Exact | Self::PatchCompatible | Self::MinorCompatible
        )
    }
}

impl fmt::Display for VersionCompatibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact => f.write_str("exact"),
            Self::PatchCompatible => f.write_str("patch_compatible"),
            Self::MinorCompatible => f.write_str("minor_compatible"),
            Self::MajorIncompatible => f.write_str("major_incompatible"),
        }
    }
}

/// Negotiate version compatibility between local and remote versions.
pub fn negotiate_version(local: SemanticVersion, remote: SemanticVersion) -> VersionCompatibility {
    if local == remote {
        return VersionCompatibility::Exact;
    }
    if local.major != remote.major {
        return VersionCompatibility::MajorIncompatible;
    }
    if local.minor != remote.minor {
        return VersionCompatibility::MinorCompatible;
    }
    VersionCompatibility::PatchCompatible
}

// ---------------------------------------------------------------------------
// Failure taxonomy
// ---------------------------------------------------------------------------

/// Severity level for a conformance failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FailureSeverity {
    /// Informational only — no action required.
    Info,
    /// Warning — should be investigated before release.
    Warning,
    /// Error — must be resolved before release.
    Error,
    /// Critical — immediate release-blocking failure.
    Critical,
}

impl FailureSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for FailureSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Required response when a conformance failure is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequiredResponse {
    /// Log the failure for observability.
    Log,
    /// Emit a warning visible to operators.
    Warn,
    /// Block the release pipeline.
    Block,
}

impl RequiredResponse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for RequiredResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Taxonomy entry: maps a regression class to severity, response, and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureTaxonomyEntry {
    pub regression_class: RegressionClass,
    pub severity: FailureSeverity,
    pub required_response: RequiredResponse,
    pub evidence_requirements: Vec<String>,
    pub description: String,
}

/// Build the canonical failure taxonomy.
pub fn failure_taxonomy() -> Vec<FailureTaxonomyEntry> {
    vec![
        FailureTaxonomyEntry {
            regression_class: RegressionClass::Breaking,
            severity: FailureSeverity::Critical,
            required_response: RequiredResponse::Block,
            evidence_requirements: vec![
                "serialized_before_bytes".to_string(),
                "serialized_after_bytes".to_string(),
                "schema_diff".to_string(),
                "affected_boundary".to_string(),
                "reproduction_seed".to_string(),
            ],
            description: "Wire-format contract violation: serialized shape changed in an \
                          incompatible way. Blocks release pipeline."
                .to_string(),
        },
        FailureTaxonomyEntry {
            regression_class: RegressionClass::Behavioral,
            severity: FailureSeverity::Error,
            required_response: RequiredResponse::Warn,
            evidence_requirements: vec![
                "expected_behavior".to_string(),
                "actual_behavior".to_string(),
                "affected_boundary".to_string(),
                "test_trace_id".to_string(),
            ],
            description: "Semantic deviation within contract bounds: ordering, defaults, or \
                          error messages changed. Requires investigation before release."
                .to_string(),
        },
        FailureTaxonomyEntry {
            regression_class: RegressionClass::Observability,
            severity: FailureSeverity::Warning,
            required_response: RequiredResponse::Warn,
            evidence_requirements: vec![
                "missing_fields".to_string(),
                "expected_log_schema".to_string(),
                "actual_log_event".to_string(),
            ],
            description: "Structured log or telemetry field regression: monitoring/alerting \
                          may be affected."
                .to_string(),
        },
        FailureTaxonomyEntry {
            regression_class: RegressionClass::Performance,
            severity: FailureSeverity::Warning,
            required_response: RequiredResponse::Log,
            evidence_requirements: vec![
                "metric_name".to_string(),
                "baseline_value".to_string(),
                "current_value".to_string(),
                "threshold".to_string(),
                "benchmark_run_id".to_string(),
            ],
            description: "Performance SLO regression: latency, throughput, or memory \
                          degradation beyond threshold."
                .to_string(),
        },
    ]
}

/// Classify a regression class to its taxonomy entry.
pub fn classify_failure(
    taxonomy: &[FailureTaxonomyEntry],
    regression_class: RegressionClass,
) -> Option<&FailureTaxonomyEntry> {
    taxonomy
        .iter()
        .find(|entry| entry.regression_class == regression_class)
}

// ---------------------------------------------------------------------------
// Replay obligations
// ---------------------------------------------------------------------------

/// Replay artifact produced by a conformance test run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayArtifact {
    pub test_id: String,
    pub boundary: SiblingRepo,
    pub deterministic_seed: u64,
    pub pinned_versions: BTreeMap<String, SemanticVersion>,
    pub input_snapshot: Vec<u8>,
    pub expected_output_hash: String,
    pub reproduction_command: String,
}

/// Replay obligation: requirements for a conformance test to be reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayObligation {
    pub test_id: String,
    pub boundary: SiblingRepo,
    pub must_pin_versions: bool,
    pub must_provide_seed: bool,
    pub must_capture_input: bool,
    pub must_hash_output: bool,
}

impl ReplayObligation {
    /// Standard obligation for all conformance tests.
    pub fn standard(test_id: impl Into<String>, boundary: SiblingRepo) -> Self {
        Self {
            test_id: test_id.into(),
            boundary,
            must_pin_versions: true,
            must_provide_seed: true,
            must_capture_input: true,
            must_hash_output: true,
        }
    }

    /// Verify that a replay artifact satisfies this obligation.
    pub fn verify(&self, artifact: &ReplayArtifact) -> Vec<String> {
        let mut errors = Vec::new();
        if self.must_pin_versions && artifact.pinned_versions.is_empty() {
            errors.push("pinned_versions must not be empty".to_string());
        }
        if self.must_provide_seed && artifact.deterministic_seed == 0 {
            errors.push("deterministic_seed must be non-zero".to_string());
        }
        if self.must_capture_input && artifact.input_snapshot.is_empty() {
            errors.push("input_snapshot must not be empty".to_string());
        }
        if self.must_hash_output && artifact.expected_output_hash.is_empty() {
            errors.push("expected_output_hash must not be empty".to_string());
        }
        if artifact.test_id != self.test_id {
            errors.push(format!(
                "test_id mismatch: expected `{}`, got `{}`",
                self.test_id, artifact.test_id
            ));
        }
        if artifact.boundary != self.boundary {
            errors.push(format!(
                "boundary mismatch: expected `{}`, got `{}`",
                self.boundary, artifact.boundary
            ));
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// Contract catalog
// ---------------------------------------------------------------------------

/// A single entry in the conformance catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub entry_id: String,
    pub boundary: BoundarySurface,
    pub positive_vectors: Vec<ConformanceVector>,
    pub negative_vectors: Vec<ConformanceVector>,
    pub replay_obligation: ReplayObligation,
    pub failure_class: RegressionClass,
    pub approved: bool,
    pub approval_epoch: Option<u64>,
}

impl CatalogEntry {
    /// Meta-test: every entry must have at least one positive and one negative vector.
    pub fn has_required_vectors(&self) -> bool {
        !self.positive_vectors.is_empty() && !self.negative_vectors.is_empty()
    }
}

/// A conformance test vector (positive = should pass, negative = should fail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    pub vector_id: String,
    pub description: String,
    pub input_json: String,
    pub expected_pass: bool,
    pub expected_regression_class: Option<RegressionClass>,
}

/// The full conformance-lab contract catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCatalog {
    pub catalog_version: SemanticVersion,
    pub entries: Vec<CatalogEntry>,
    pub taxonomy: Vec<FailureTaxonomyEntry>,
    pub change_log: Vec<CatalogChangeRecord>,
}

/// A change record for catalog version control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogChangeRecord {
    pub version: SemanticVersion,
    pub description: String,
    pub affected_entries: Vec<String>,
    pub change_kind: ChangeKind,
}

/// Kind of catalog change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ChangeKind {
    EntryAdded,
    EntryModified,
    EntryRemoved,
    TaxonomyUpdated,
    VectorAdded,
    VectorRemoved,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryAdded => f.write_str("entry_added"),
            Self::EntryModified => f.write_str("entry_modified"),
            Self::EntryRemoved => f.write_str("entry_removed"),
            Self::TaxonomyUpdated => f.write_str("taxonomy_updated"),
            Self::VectorAdded => f.write_str("vector_added"),
            Self::VectorRemoved => f.write_str("vector_removed"),
        }
    }
}

impl ConformanceCatalog {
    /// Create a new empty catalog at the given version.
    pub fn new(version: SemanticVersion) -> Self {
        Self {
            catalog_version: version,
            entries: Vec::new(),
            taxonomy: failure_taxonomy(),
            change_log: Vec::new(),
        }
    }

    /// Add an entry and record the change.
    pub fn add_entry(&mut self, entry: CatalogEntry) {
        let entry_id = entry.entry_id.clone();
        self.entries.push(entry);
        self.change_log.push(CatalogChangeRecord {
            version: self.catalog_version,
            description: format!("added entry {entry_id}"),
            affected_entries: vec![entry_id],
            change_kind: ChangeKind::EntryAdded,
        });
    }

    /// Look up an entry by ID.
    pub fn get_entry(&self, entry_id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.entry_id == entry_id)
    }

    /// All entries for a given sibling repo boundary.
    pub fn entries_for_boundary(&self, sibling: SiblingRepo) -> Vec<&CatalogEntry> {
        self.entries
            .iter()
            .filter(|e| e.boundary.sibling == sibling)
            .collect()
    }

    /// Meta-test: every entry must have positive and negative vectors.
    pub fn validate_vector_coverage(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for entry in &self.entries {
            if !entry.has_required_vectors() {
                errors.push(format!(
                    "entry `{}` missing required vectors (positive={}, negative={})",
                    entry.entry_id,
                    entry.positive_vectors.len(),
                    entry.negative_vectors.len()
                ));
            }
        }
        errors
    }

    /// All unique boundaries covered by catalog entries.
    pub fn covered_boundaries(&self) -> BTreeSet<SiblingRepo> {
        self.entries.iter().map(|e| e.boundary.sibling).collect()
    }

    /// Count entries by regression class.
    pub fn entries_by_class(&self) -> BTreeMap<RegressionClass, usize> {
        let mut counts = BTreeMap::new();
        for entry in &self.entries {
            *counts.entry(entry.failure_class).or_insert(0) += 1;
        }
        counts
    }
}

// ---------------------------------------------------------------------------
// Catalog builder: canonical boundary surfaces
// ---------------------------------------------------------------------------

/// Build the canonical set of boundary surfaces for all sibling repos.
pub fn canonical_boundary_surfaces() -> Vec<BoundarySurface> {
    vec![
        // asupersync boundaries
        BoundarySurface {
            sibling: SiblingRepo::Asupersync,
            surface_id: "asupersync/control_plane_types".to_string(),
            surface_kind: SurfaceKind::IdentifierSchema,
            description: "Canonical control-plane type imports (Cx, TraceId, DecisionId, \
                      PolicyId, SchemaVersion, Budget)"
                .to_string(),
            covered_fields: [
                "Cx",
                "TraceId",
                "DecisionId",
                "PolicyId",
                "SchemaVersion",
                "Budget",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Major,
        },
        BoundarySurface {
            sibling: SiblingRepo::Asupersync,
            surface_id: "asupersync/decision_payload".to_string(),
            surface_kind: SurfaceKind::DecisionPayload,
            description: "Decision record schema for cross-repo evidence chain".to_string(),
            covered_fields: [
                "decision_id",
                "policy_id",
                "trace_id",
                "outcome",
                "timestamp",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Minor,
        },
        BoundarySurface {
            sibling: SiblingRepo::Asupersync,
            surface_id: "asupersync/evidence_payload".to_string(),
            surface_kind: SurfaceKind::EvidencePayload,
            description: "Evidence entry schema for audit chain linkage".to_string(),
            covered_fields: [
                "trace_id",
                "decision_id",
                "component",
                "event",
                "outcome",
                "artifact_ref",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Minor,
        },
        // frankentui boundaries
        BoundarySurface {
            sibling: SiblingRepo::Frankentui,
            surface_id: "frankentui/adapter_envelope".to_string(),
            surface_kind: SurfaceKind::TuiEventContract,
            description: "AdapterEnvelope: schema-versioned transport for TUI payloads".to_string(),
            covered_fields: [
                "schema_version",
                "trace_id",
                "generated_at_unix_ms",
                "stream",
                "update_kind",
                "payload",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Minor,
        },
        BoundarySurface {
            sibling: SiblingRepo::Frankentui,
            surface_id: "frankentui/view_payloads".to_string(),
            surface_kind: SurfaceKind::TuiStateContract,
            description: "IncidentReplay, PolicyExplanation, ControlDashboard view schemas"
                .to_string(),
            covered_fields: ["incident_replay", "policy_explanation", "control_dashboard"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        },
        // frankensqlite boundaries
        BoundarySurface {
            sibling: SiblingRepo::Frankensqlite,
            surface_id: "frankensqlite/store_record".to_string(),
            surface_kind: SurfaceKind::PersistenceSemantics,
            description: "StoreRecord schema for deterministic key-value persistence".to_string(),
            covered_fields: ["store", "key", "value", "metadata", "revision"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Major,
        },
        BoundarySurface {
            sibling: SiblingRepo::Frankensqlite,
            surface_id: "frankensqlite/migration_receipt".to_string(),
            surface_kind: SurfaceKind::PersistenceSemantics,
            description: "MigrationReceipt for schema migration audit trail".to_string(),
            covered_fields: [
                "backend",
                "from_version",
                "to_version",
                "stores_touched",
                "records_touched",
                "state_hash_before",
                "state_hash_after",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Minor,
        },
        BoundarySurface {
            sibling: SiblingRepo::Frankensqlite,
            surface_id: "frankensqlite/telemetry".to_string(),
            surface_kind: SurfaceKind::TelemetrySchema,
            description: "StorageEvent structured log schema".to_string(),
            covered_fields: [
                "trace_id",
                "decision_id",
                "policy_id",
                "component",
                "event",
                "outcome",
                "error_code",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Patch,
        },
        // franken_node boundaries
        BoundarySurface {
            sibling: SiblingRepo::FrankenNode,
            surface_id: "franken_node/api_surface".to_string(),
            surface_kind: SurfaceKind::ApiMessage,
            description: "Node/Bun-compatible API surface superset".to_string(),
            covered_fields: [
                "endpoint_response",
                "error_envelope",
                "health_status",
                "control_action",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            version_class: VersionClass::Major,
        },
        // fastapi_rust boundaries
        BoundarySurface {
            sibling: SiblingRepo::FastapiRust,
            surface_id: "fastapi_rust/endpoint_response".to_string(),
            surface_kind: SurfaceKind::ApiMessage,
            description: "EndpointResponse envelope for service transport adapters".to_string(),
            covered_fields: ["status", "endpoint", "trace_id", "request_id", "log"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        },
        BoundarySurface {
            sibling: SiblingRepo::FastapiRust,
            surface_id: "fastapi_rust/replay_export".to_string(),
            surface_kind: SurfaceKind::ReplayFormat,
            description: "Replay control request/response for incident replay export".to_string(),
            covered_fields: ["session_id", "state", "trace_id", "command"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        },
        // sqlmodel_rust boundaries
        BoundarySurface {
            sibling: SiblingRepo::SqlmodelRust,
            surface_id: "sqlmodel_rust/query_contract".to_string(),
            surface_kind: SurfaceKind::PersistenceSemantics,
            description: "Query result schema for ORM-level persistence integration".to_string(),
            covered_fields: ["store_query", "batch_put_entry", "store_kind"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        },
    ]
}

/// Build a pre-populated catalog with canonical entries and vectors.
pub fn build_canonical_catalog() -> ConformanceCatalog {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let surfaces = canonical_boundary_surfaces();

    for surface in surfaces {
        let entry_id = surface.surface_id.clone();
        let sibling = surface.sibling;
        let failure_class = match surface.version_class {
            VersionClass::Major => RegressionClass::Breaking,
            VersionClass::Minor => RegressionClass::Behavioral,
            VersionClass::Patch => RegressionClass::Observability,
        };

        let positive = ConformanceVector {
            vector_id: format!("{entry_id}/positive/baseline"),
            description: format!("Baseline positive conformance for {entry_id}"),
            input_json: "{{}}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        };
        let negative = ConformanceVector {
            vector_id: format!("{entry_id}/negative/missing_field"),
            description: format!("Missing required field for {entry_id}"),
            input_json: "{{\"__invalid\": true}}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(failure_class),
        };

        let obligation = ReplayObligation::standard(&entry_id, sibling);

        let entry = CatalogEntry {
            entry_id: entry_id.clone(),
            boundary: surface,
            positive_vectors: vec![positive],
            negative_vectors: vec![negative],
            replay_obligation: obligation,
            failure_class,
            approved: true,
            approval_epoch: Some(1),
        };

        catalog.add_entry(entry);
    }

    catalog
}

// ---------------------------------------------------------------------------
// Catalog validation
// ---------------------------------------------------------------------------

/// Errors from catalog-level validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogValidationError {
    pub entry_id: Option<String>,
    pub field: String,
    pub detail: String,
}

impl fmt::Display for CatalogValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.entry_id {
            Some(id) => write!(f, "[{}] {}: {}", id, self.field, self.detail),
            None => write!(f, "[catalog] {}: {}", self.field, self.detail),
        }
    }
}

/// Validate the full catalog for structural integrity.
pub fn validate_catalog(catalog: &ConformanceCatalog) -> Vec<CatalogValidationError> {
    let mut errors = Vec::new();

    // Every entry must have vectors.
    for missing in catalog.validate_vector_coverage() {
        errors.push(CatalogValidationError {
            entry_id: None,
            field: "vector_coverage".to_string(),
            detail: missing,
        });
    }

    // Entry IDs must be unique.
    let mut seen_ids = BTreeSet::new();
    for entry in &catalog.entries {
        if !seen_ids.insert(&entry.entry_id) {
            errors.push(CatalogValidationError {
                entry_id: Some(entry.entry_id.clone()),
                field: "entry_id".to_string(),
                detail: "duplicate entry ID".to_string(),
            });
        }

        // Vector IDs must be unique within entry.
        let mut vector_ids = BTreeSet::new();
        for v in entry
            .positive_vectors
            .iter()
            .chain(entry.negative_vectors.iter())
        {
            if !vector_ids.insert(&v.vector_id) {
                errors.push(CatalogValidationError {
                    entry_id: Some(entry.entry_id.clone()),
                    field: "vector_id".to_string(),
                    detail: format!("duplicate vector ID: {}", v.vector_id),
                });
            }
        }

        // Surface covered fields must be non-empty.
        if entry.boundary.covered_fields.is_empty() {
            errors.push(CatalogValidationError {
                entry_id: Some(entry.entry_id.clone()),
                field: "covered_fields".to_string(),
                detail: "boundary surface must cover at least one field".to_string(),
            });
        }
    }

    // Taxonomy must cover all regression classes.
    let taxonomy_classes: BTreeSet<RegressionClass> = catalog
        .taxonomy
        .iter()
        .map(|t| t.regression_class)
        .collect();
    for class in [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ] {
        if !taxonomy_classes.contains(&class) {
            errors.push(CatalogValidationError {
                entry_id: None,
                field: "taxonomy".to_string(),
                detail: format!("missing taxonomy entry for {class}"),
            });
        }
    }

    errors
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── sibling repo enumeration ───────────────────────────────────────

    #[test]
    fn sibling_repo_all_returns_all_variants() {
        let all = SiblingRepo::all();
        assert_eq!(all.len(), 6);
        let names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        assert!(names.contains(&"asupersync"));
        assert!(names.contains(&"frankentui"));
        assert!(names.contains(&"frankensqlite"));
        assert!(names.contains(&"franken_node"));
        assert!(names.contains(&"sqlmodel_rust"));
        assert!(names.contains(&"fastapi_rust"));
    }

    #[test]
    fn sibling_repo_primary_classification() {
        assert!(SiblingRepo::Asupersync.is_primary());
        assert!(SiblingRepo::Frankentui.is_primary());
        assert!(SiblingRepo::Frankensqlite.is_primary());
        assert!(SiblingRepo::FrankenNode.is_primary());
        assert!(!SiblingRepo::SqlmodelRust.is_primary());
        assert!(!SiblingRepo::FastapiRust.is_primary());
    }

    #[test]
    fn sibling_repo_display() {
        assert_eq!(SiblingRepo::Asupersync.to_string(), "asupersync");
        assert_eq!(SiblingRepo::FrankenNode.to_string(), "franken_node");
    }

    #[test]
    fn sibling_repo_serde_round_trip() {
        for repo in SiblingRepo::all() {
            let json = serde_json::to_string(repo).expect("serde deserialization should succeed");
            let decoded: SiblingRepo = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*repo, decoded);
        }
    }

    // ── surface kind ───────────────────────────────────────────────────

    #[test]
    fn surface_kind_as_str_unique() {
        let kinds = [
            SurfaceKind::IdentifierSchema,
            SurfaceKind::DecisionPayload,
            SurfaceKind::EvidencePayload,
            SurfaceKind::ApiMessage,
            SurfaceKind::PersistenceSemantics,
            SurfaceKind::ReplayFormat,
            SurfaceKind::ExportFormat,
            SurfaceKind::TuiEventContract,
            SurfaceKind::TuiStateContract,
            SurfaceKind::TelemetrySchema,
        ];
        let mut seen = BTreeSet::new();
        for kind in &kinds {
            assert!(seen.insert(kind.as_str()), "duplicate: {}", kind.as_str());
        }
    }

    // ── version classes ────────────────────────────────────────────────

    #[test]
    fn version_class_permissions() {
        assert!(!VersionClass::Patch.allows_additive_fields());
        assert!(!VersionClass::Patch.allows_breaking_changes());
        assert!(VersionClass::Minor.allows_additive_fields());
        assert!(!VersionClass::Minor.allows_breaking_changes());
        assert!(VersionClass::Major.allows_additive_fields());
        assert!(VersionClass::Major.allows_breaking_changes());
    }

    #[test]
    fn version_class_ordering() {
        assert!(VersionClass::Patch < VersionClass::Minor);
        assert!(VersionClass::Minor < VersionClass::Major);
    }

    #[test]
    fn semantic_version_display() {
        let v = SemanticVersion::new(2, 3, 7);
        assert_eq!(v.to_string(), "2.3.7");
    }

    #[test]
    fn semantic_version_ordering() {
        let v1 = SemanticVersion::new(1, 0, 0);
        let v2 = SemanticVersion::new(1, 1, 0);
        let v3 = SemanticVersion::new(2, 0, 0);
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn semantic_version_serde_round_trip() {
        let v = SemanticVersion::new(1, 2, 3);
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let decoded: SemanticVersion = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, decoded);
    }

    // ── version negotiation ────────────────────────────────────────────

    #[test]
    fn negotiate_exact_match() {
        let v = SemanticVersion::new(1, 2, 3);
        assert_eq!(negotiate_version(v, v), VersionCompatibility::Exact);
    }

    #[test]
    fn negotiate_patch_compatible() {
        let local = SemanticVersion::new(1, 2, 3);
        let remote = SemanticVersion::new(1, 2, 5);
        assert_eq!(
            negotiate_version(local, remote),
            VersionCompatibility::PatchCompatible
        );
    }

    #[test]
    fn negotiate_minor_compatible() {
        let local = SemanticVersion::new(1, 2, 0);
        let remote = SemanticVersion::new(1, 3, 0);
        assert_eq!(
            negotiate_version(local, remote),
            VersionCompatibility::MinorCompatible
        );
    }

    #[test]
    fn negotiate_major_incompatible() {
        let local = SemanticVersion::new(1, 0, 0);
        let remote = SemanticVersion::new(2, 0, 0);
        let result = negotiate_version(local, remote);
        assert_eq!(result, VersionCompatibility::MajorIncompatible);
        assert!(!result.is_compatible());
    }

    #[test]
    fn version_compatibility_is_compatible() {
        assert!(VersionCompatibility::Exact.is_compatible());
        assert!(VersionCompatibility::PatchCompatible.is_compatible());
        assert!(VersionCompatibility::MinorCompatible.is_compatible());
        assert!(!VersionCompatibility::MajorIncompatible.is_compatible());
    }

    #[test]
    fn version_negotiation_result_serde_round_trip() {
        let result = VersionNegotiationResult {
            boundary: SiblingRepo::Frankentui,
            local_version: SemanticVersion::new(1, 0, 0),
            remote_version: SemanticVersion::new(1, 1, 0),
            compatibility: VersionCompatibility::MinorCompatible,
            migration_required: false,
            migration_path: None,
        };
        let json = serde_json::to_vec(&result).expect("serde deserialization should succeed");
        let decoded: VersionNegotiationResult = serde_json::from_slice(&json).expect("serde deserialization should succeed");
        assert_eq!(result, decoded);
    }

    // ── failure taxonomy ───────────────────────────────────────────────

    #[test]
    fn failure_taxonomy_covers_all_classes() {
        let taxonomy = failure_taxonomy();
        let classes: BTreeSet<RegressionClass> =
            taxonomy.iter().map(|t| t.regression_class).collect();
        assert!(classes.contains(&RegressionClass::Breaking));
        assert!(classes.contains(&RegressionClass::Behavioral));
        assert!(classes.contains(&RegressionClass::Observability));
        assert!(classes.contains(&RegressionClass::Performance));
    }

    #[test]
    fn failure_taxonomy_severity_ordering() {
        let taxonomy = failure_taxonomy();
        let breaking = taxonomy
            .iter()
            .find(|t| t.regression_class == RegressionClass::Breaking)
            .expect("breaking");
        let behavioral = taxonomy
            .iter()
            .find(|t| t.regression_class == RegressionClass::Behavioral)
            .expect("behavioral");
        assert!(breaking.severity > behavioral.severity);
    }

    #[test]
    fn failure_taxonomy_breaking_requires_block_response() {
        let taxonomy = failure_taxonomy();
        let breaking = taxonomy
            .iter()
            .find(|t| t.regression_class == RegressionClass::Breaking)
            .expect("breaking");
        assert_eq!(breaking.required_response, RequiredResponse::Block);
        assert_eq!(breaking.severity, FailureSeverity::Critical);
    }

    #[test]
    fn failure_taxonomy_evidence_requirements_non_empty() {
        let taxonomy = failure_taxonomy();
        for entry in &taxonomy {
            assert!(
                !entry.evidence_requirements.is_empty(),
                "taxonomy entry for {} must have evidence requirements",
                entry.regression_class
            );
        }
    }

    #[test]
    fn classify_failure_finds_matching_entry() {
        let taxonomy = failure_taxonomy();
        let entry = classify_failure(&taxonomy, RegressionClass::Breaking);
        assert!(entry.is_some());
        assert_eq!(entry.expect("serde deserialization should succeed").severity, FailureSeverity::Critical);
    }

    #[test]
    fn failure_severity_ordering() {
        assert!(FailureSeverity::Info < FailureSeverity::Warning);
        assert!(FailureSeverity::Warning < FailureSeverity::Error);
        assert!(FailureSeverity::Error < FailureSeverity::Critical);
    }

    #[test]
    fn failure_taxonomy_serde_round_trip() {
        let taxonomy = failure_taxonomy();
        let json = serde_json::to_vec(&taxonomy).expect("serde deserialization should succeed");
        let decoded: Vec<FailureTaxonomyEntry> = serde_json::from_slice(&json).expect("serde deserialization should succeed");
        assert_eq!(taxonomy, decoded);
    }

    // ── replay obligations ─────────────────────────────────────────────

    #[test]
    fn replay_obligation_standard_requires_all() {
        let obligation = ReplayObligation::standard("test-1", SiblingRepo::Frankensqlite);
        assert!(obligation.must_pin_versions);
        assert!(obligation.must_provide_seed);
        assert!(obligation.must_capture_input);
        assert!(obligation.must_hash_output);
    }

    #[test]
    fn replay_obligation_verify_valid_artifact() {
        let obligation = ReplayObligation::standard("test-1", SiblingRepo::Frankensqlite);
        let mut versions = BTreeMap::new();
        versions.insert("frankensqlite".to_string(), SemanticVersion::new(1, 0, 0));
        let artifact = ReplayArtifact {
            test_id: "test-1".to_string(),
            boundary: SiblingRepo::Frankensqlite,
            deterministic_seed: 42,
            pinned_versions: versions,
            input_snapshot: vec![1, 2, 3],
            expected_output_hash: "abc123".to_string(),
            reproduction_command: "cargo test --lib test_1".to_string(),
        };
        let errors = obligation.verify(&artifact);
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    #[test]
    fn replay_obligation_verify_detects_missing_versions() {
        let obligation = ReplayObligation::standard("test-1", SiblingRepo::Frankentui);
        let artifact = ReplayArtifact {
            test_id: "test-1".to_string(),
            boundary: SiblingRepo::Frankentui,
            deterministic_seed: 42,
            pinned_versions: BTreeMap::new(),
            input_snapshot: vec![1],
            expected_output_hash: "abc".to_string(),
            reproduction_command: "cargo test".to_string(),
        };
        let errors = obligation.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("pinned_versions"));
    }

    #[test]
    fn replay_obligation_verify_detects_zero_seed() {
        let obligation = ReplayObligation::standard("test-1", SiblingRepo::Frankentui);
        let mut versions = BTreeMap::new();
        versions.insert("frankentui".to_string(), SemanticVersion::new(1, 0, 0));
        let artifact = ReplayArtifact {
            test_id: "test-1".to_string(),
            boundary: SiblingRepo::Frankentui,
            deterministic_seed: 0,
            pinned_versions: versions,
            input_snapshot: vec![1],
            expected_output_hash: "abc".to_string(),
            reproduction_command: "cargo test".to_string(),
        };
        let errors = obligation.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("deterministic_seed"));
    }

    #[test]
    fn replay_obligation_verify_detects_boundary_mismatch() {
        let obligation = ReplayObligation::standard("test-1", SiblingRepo::Frankentui);
        let mut versions = BTreeMap::new();
        versions.insert("frankentui".to_string(), SemanticVersion::new(1, 0, 0));
        let artifact = ReplayArtifact {
            test_id: "test-1".to_string(),
            boundary: SiblingRepo::Frankensqlite,
            deterministic_seed: 42,
            pinned_versions: versions,
            input_snapshot: vec![1],
            expected_output_hash: "abc".to_string(),
            reproduction_command: "cargo test".to_string(),
        };
        let errors = obligation.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("boundary mismatch"));
    }

    #[test]
    fn replay_artifact_serde_round_trip() {
        let mut versions = BTreeMap::new();
        versions.insert("frankentui".to_string(), SemanticVersion::new(1, 2, 3));
        let artifact = ReplayArtifact {
            test_id: "test-round-trip".to_string(),
            boundary: SiblingRepo::Frankentui,
            deterministic_seed: 99,
            pinned_versions: versions,
            input_snapshot: vec![10, 20, 30],
            expected_output_hash: "deadbeef".to_string(),
            reproduction_command: "cargo test --lib".to_string(),
        };
        let json = serde_json::to_vec(&artifact).expect("serde deserialization should succeed");
        let decoded: ReplayArtifact = serde_json::from_slice(&json).expect("serde deserialization should succeed");
        assert_eq!(artifact, decoded);
    }

    // ── conformance catalog ────────────────────────────────────────────

    #[test]
    fn canonical_catalog_has_entries_for_all_primary_boundaries() {
        let catalog = build_canonical_catalog();
        let covered = catalog.covered_boundaries();
        for repo in SiblingRepo::all() {
            if repo.is_primary() {
                assert!(
                    covered.contains(repo),
                    "primary boundary {} not in catalog",
                    repo
                );
            }
        }
    }

    #[test]
    fn canonical_catalog_entries_have_required_vectors() {
        let catalog = build_canonical_catalog();
        let errors = catalog.validate_vector_coverage();
        assert!(errors.is_empty(), "vector coverage errors: {errors:?}");
    }

    #[test]
    fn canonical_catalog_validates_clean() {
        let catalog = build_canonical_catalog();
        let errors = validate_catalog(&catalog);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn canonical_catalog_has_taxonomy() {
        let catalog = build_canonical_catalog();
        assert_eq!(catalog.taxonomy.len(), 4);
    }

    #[test]
    fn canonical_catalog_has_change_log() {
        let catalog = build_canonical_catalog();
        assert!(
            !catalog.change_log.is_empty(),
            "catalog must have change log entries"
        );
        for entry in &catalog.change_log {
            assert_eq!(entry.change_kind, ChangeKind::EntryAdded);
        }
    }

    #[test]
    fn catalog_entry_lookup_by_id() {
        let catalog = build_canonical_catalog();
        let entry = catalog.get_entry("frankentui/adapter_envelope");
        assert!(entry.is_some());
        assert_eq!(entry.expect("serde deserialization should succeed").boundary.sibling, SiblingRepo::Frankentui);
    }

    #[test]
    fn catalog_entry_lookup_missing_returns_none() {
        let catalog = build_canonical_catalog();
        assert!(catalog.get_entry("nonexistent").is_none());
    }

    #[test]
    fn catalog_entries_for_boundary() {
        let catalog = build_canonical_catalog();
        let sqlite_entries = catalog.entries_for_boundary(SiblingRepo::Frankensqlite);
        assert!(
            sqlite_entries.len() >= 2,
            "expected at least 2 sqlite entries"
        );
    }

    #[test]
    fn catalog_entries_by_class_counts() {
        let catalog = build_canonical_catalog();
        let counts = catalog.entries_by_class();
        assert!(!counts.is_empty());
        let total: usize = counts.values().sum();
        assert_eq!(total, catalog.entries.len());
    }

    #[test]
    fn catalog_serde_round_trip() {
        let catalog = build_canonical_catalog();
        let json = serde_json::to_vec(&catalog).expect("serde deserialization should succeed");
        let decoded: ConformanceCatalog = serde_json::from_slice(&json).expect("serde deserialization should succeed");
        assert_eq!(catalog, decoded);
    }

    // ── catalog validation ─────────────────────────────────────────────

    #[test]
    fn validate_catalog_detects_missing_vectors() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
        catalog.add_entry(CatalogEntry {
            entry_id: "test/no_vectors".to_string(),
            boundary: BoundarySurface {
                sibling: SiblingRepo::Frankentui,
                surface_id: "test/no_vectors".to_string(),
                surface_kind: SurfaceKind::ApiMessage,
                description: "test".to_string(),
                covered_fields: ["field1"].iter().map(|s| s.to_string()).collect(),
                version_class: VersionClass::Minor,
            },
            positive_vectors: vec![],
            negative_vectors: vec![],
            replay_obligation: ReplayObligation::standard(
                "test/no_vectors",
                SiblingRepo::Frankentui,
            ),
            failure_class: RegressionClass::Behavioral,
            approved: false,
            approval_epoch: None,
        });

        let errors = validate_catalog(&catalog);
        assert!(!errors.is_empty());
        assert!(
            errors
                .iter()
                .any(|e| e.detail.contains("missing required vectors"))
        );
    }

    #[test]
    fn validate_catalog_detects_duplicate_entry_ids() {
        let mut catalog = build_canonical_catalog();
        let dup = catalog.entries[0].clone();
        catalog.entries.push(dup);

        let errors = validate_catalog(&catalog);
        assert!(
            errors
                .iter()
                .any(|e| e.detail.contains("duplicate entry ID"))
        );
    }

    #[test]
    fn validate_catalog_detects_empty_covered_fields() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
        catalog.add_entry(CatalogEntry {
            entry_id: "test/empty_fields".to_string(),
            boundary: BoundarySurface {
                sibling: SiblingRepo::Asupersync,
                surface_id: "test/empty_fields".to_string(),
                surface_kind: SurfaceKind::IdentifierSchema,
                description: "test".to_string(),
                covered_fields: BTreeSet::new(),
                version_class: VersionClass::Major,
            },
            positive_vectors: vec![ConformanceVector {
                vector_id: "p1".to_string(),
                description: "pos".to_string(),
                input_json: "{}".to_string(),
                expected_pass: true,
                expected_regression_class: None,
            }],
            negative_vectors: vec![ConformanceVector {
                vector_id: "n1".to_string(),
                description: "neg".to_string(),
                input_json: "{}".to_string(),
                expected_pass: false,
                expected_regression_class: Some(RegressionClass::Breaking),
            }],
            replay_obligation: ReplayObligation::standard(
                "test/empty_fields",
                SiblingRepo::Asupersync,
            ),
            failure_class: RegressionClass::Breaking,
            approved: false,
            approval_epoch: None,
        });

        let errors = validate_catalog(&catalog);
        assert!(
            errors
                .iter()
                .any(|e| e.detail.contains("covered_fields") || e.field == "covered_fields")
        );
    }

    // ── canonical boundary surfaces ────────────────────────────────────

    #[test]
    fn canonical_surfaces_cover_all_sibling_repos() {
        let surfaces = canonical_boundary_surfaces();
        let siblings: BTreeSet<SiblingRepo> = surfaces.iter().map(|s| s.sibling).collect();
        for repo in SiblingRepo::all() {
            assert!(
                siblings.contains(repo),
                "sibling {} not covered by canonical surfaces",
                repo
            );
        }
    }

    #[test]
    fn canonical_surfaces_have_unique_ids() {
        let surfaces = canonical_boundary_surfaces();
        let mut seen = BTreeSet::new();
        for surface in &surfaces {
            assert!(
                seen.insert(&surface.surface_id),
                "duplicate surface_id: {}",
                surface.surface_id
            );
        }
    }

    #[test]
    fn canonical_surfaces_have_non_empty_fields() {
        let surfaces = canonical_boundary_surfaces();
        for surface in &surfaces {
            assert!(
                !surface.covered_fields.is_empty(),
                "surface {} must have covered fields",
                surface.surface_id
            );
        }
    }

    // ── change kind ────────────────────────────────────────────────────

    #[test]
    fn change_kind_display() {
        assert_eq!(ChangeKind::EntryAdded.to_string(), "entry_added");
        assert_eq!(ChangeKind::EntryModified.to_string(), "entry_modified");
        assert_eq!(ChangeKind::VectorAdded.to_string(), "vector_added");
    }

    #[test]
    fn change_kind_serde_round_trip() {
        for kind in [
            ChangeKind::EntryAdded,
            ChangeKind::EntryModified,
            ChangeKind::EntryRemoved,
            ChangeKind::TaxonomyUpdated,
            ChangeKind::VectorAdded,
            ChangeKind::VectorRemoved,
        ] {
            let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
            let decoded: ChangeKind = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(kind, decoded);
        }
    }

    // ── catalog validation error display ───────────────────────────────

    #[test]
    fn catalog_validation_error_display_with_entry() {
        let err = CatalogValidationError {
            entry_id: Some("test/entry".to_string()),
            field: "vector_id".to_string(),
            detail: "duplicate".to_string(),
        };
        assert_eq!(err.to_string(), "[test/entry] vector_id: duplicate");
    }

    #[test]
    fn catalog_validation_error_display_without_entry() {
        let err = CatalogValidationError {
            entry_id: None,
            field: "taxonomy".to_string(),
            detail: "missing class".to_string(),
        };
        assert_eq!(err.to_string(), "[catalog] taxonomy: missing class");
    }

    // ── integration: version negotiation across boundaries ─────────────

    #[test]
    fn version_negotiation_full_workflow() {
        let local = SemanticVersion::new(1, 2, 0);
        let remote_patch = SemanticVersion::new(1, 2, 1);
        let remote_minor = SemanticVersion::new(1, 3, 0);
        let remote_major = SemanticVersion::new(2, 0, 0);

        let result_patch = VersionNegotiationResult {
            boundary: SiblingRepo::Frankensqlite,
            local_version: local,
            remote_version: remote_patch,
            compatibility: negotiate_version(local, remote_patch),
            migration_required: false,
            migration_path: None,
        };
        assert!(result_patch.compatibility.is_compatible());

        let result_minor = VersionNegotiationResult {
            boundary: SiblingRepo::Frankensqlite,
            local_version: local,
            remote_version: remote_minor,
            compatibility: negotiate_version(local, remote_minor),
            migration_required: false,
            migration_path: None,
        };
        assert!(result_minor.compatibility.is_compatible());

        let compat_major = negotiate_version(local, remote_major);
        let result_major = VersionNegotiationResult {
            boundary: SiblingRepo::Frankensqlite,
            local_version: local,
            remote_version: remote_major,
            compatibility: compat_major,
            migration_required: true,
            migration_path: Some("migrate_v1_to_v2".to_string()),
        };
        assert!(!result_major.compatibility.is_compatible());
        assert!(result_major.migration_required);
    }

    // ── integration: full catalog lifecycle ─────────────────────────────

    #[test]
    fn catalog_lifecycle_create_add_validate() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(0, 1, 0));
        assert!(catalog.entries.is_empty());

        let surface = BoundarySurface {
            sibling: SiblingRepo::Frankentui,
            surface_id: "lifecycle/test".to_string(),
            surface_kind: SurfaceKind::TuiEventContract,
            description: "lifecycle test".to_string(),
            covered_fields: ["field_a"].iter().map(|s| s.to_string()).collect(),
            version_class: VersionClass::Minor,
        };
        let entry = CatalogEntry {
            entry_id: "lifecycle/test".to_string(),
            boundary: surface,
            positive_vectors: vec![ConformanceVector {
                vector_id: "lifecycle/test/pos".to_string(),
                description: "positive".to_string(),
                input_json: "{}".to_string(),
                expected_pass: true,
                expected_regression_class: None,
            }],
            negative_vectors: vec![ConformanceVector {
                vector_id: "lifecycle/test/neg".to_string(),
                description: "negative".to_string(),
                input_json: "{}".to_string(),
                expected_pass: false,
                expected_regression_class: Some(RegressionClass::Behavioral),
            }],
            replay_obligation: ReplayObligation::standard(
                "lifecycle/test",
                SiblingRepo::Frankentui,
            ),
            failure_class: RegressionClass::Behavioral,
            approved: true,
            approval_epoch: Some(1),
        };

        catalog.add_entry(entry);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.change_log.len(), 1);

        let errors = validate_catalog(&catalog);
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    // -- Enrichment: Display uniqueness, serde, edge cases --

    #[test]
    fn sibling_repo_display_uniqueness() {
        let displays: BTreeSet<String> = SiblingRepo::all().iter().map(|r| r.to_string()).collect();
        assert_eq!(
            displays.len(),
            6,
            "all 6 sibling repos produce distinct display strings"
        );
    }

    #[test]
    fn version_class_display_uniqueness() {
        let variants = [
            VersionClass::Patch,
            VersionClass::Minor,
            VersionClass::Major,
        ];
        let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 version classes produce distinct display strings"
        );
    }

    #[test]
    fn version_compatibility_display_uniqueness() {
        let variants = [
            VersionCompatibility::Exact,
            VersionCompatibility::PatchCompatible,
            VersionCompatibility::MinorCompatible,
            VersionCompatibility::MajorIncompatible,
        ];
        let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 compatibility levels produce distinct display strings"
        );
    }

    #[test]
    fn regression_class_display_uniqueness() {
        let variants = [
            RegressionClass::Breaking,
            RegressionClass::Behavioral,
            RegressionClass::Observability,
            RegressionClass::Performance,
        ];
        let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 regression classes produce distinct display strings"
        );
    }

    #[test]
    fn surface_kind_display_uniqueness() {
        let kinds = [
            SurfaceKind::IdentifierSchema,
            SurfaceKind::DecisionPayload,
            SurfaceKind::EvidencePayload,
            SurfaceKind::ApiMessage,
            SurfaceKind::PersistenceSemantics,
            SurfaceKind::ReplayFormat,
            SurfaceKind::ExportFormat,
            SurfaceKind::TuiEventContract,
            SurfaceKind::TuiStateContract,
            SurfaceKind::TelemetrySchema,
        ];
        let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(
            displays.len(),
            10,
            "all 10 surface kinds produce distinct display strings"
        );
    }

    #[test]
    fn negotiate_version_symmetric_for_patch() {
        let a = SemanticVersion::new(1, 2, 3);
        let b = SemanticVersion::new(1, 2, 5);
        assert_eq!(negotiate_version(a, b), negotiate_version(b, a));
    }

    #[test]
    fn semantic_version_zero_zero_zero_display() {
        let v = SemanticVersion::new(0, 0, 0);
        assert_eq!(v.to_string(), "0.0.0");
    }

    #[test]
    fn catalog_validation_error_serde_roundtrip() {
        let err = CatalogValidationError {
            entry_id: Some("test/serde".to_string()),
            field: "vectors".to_string(),
            detail: "empty".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let decoded: CatalogValidationError = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, decoded);
    }

    // ── Copy/Clone semantics ───────────────────────────────────────────

    #[test]
    fn sibling_repo_copy_semantics() {
        let original = SiblingRepo::Frankentui;
        let copy = original;
        assert_eq!(original, copy);
        // both are independently usable after copy
        assert_eq!(original.as_str(), "frankentui");
        assert_eq!(copy.as_str(), "frankentui");
    }

    #[test]
    fn surface_kind_copy_semantics() {
        let original = SurfaceKind::TelemetrySchema;
        let copy = original;
        assert_eq!(original, copy);
        assert_eq!(original.as_str(), copy.as_str());
    }

    #[test]
    fn version_class_copy_semantics() {
        let original = VersionClass::Major;
        let copy = original;
        assert_eq!(original, copy);
        assert!(copy.allows_breaking_changes());
    }

    #[test]
    fn version_compatibility_copy_semantics() {
        let original = VersionCompatibility::PatchCompatible;
        let copy = original;
        assert_eq!(original, copy);
        assert!(copy.is_compatible());
    }

    #[test]
    fn failure_severity_copy_semantics() {
        let original = FailureSeverity::Critical;
        let copy = original;
        assert_eq!(original, copy);
        assert_eq!(original.as_str(), "critical");
    }

    #[test]
    fn required_response_copy_semantics() {
        let original = RequiredResponse::Block;
        let copy = original;
        assert_eq!(original, copy);
        assert_eq!(copy.as_str(), "block");
    }

    #[test]
    fn semantic_version_copy_semantics() {
        let original = SemanticVersion::new(3, 1, 4);
        let copy = original;
        assert_eq!(original, copy);
        assert_eq!(copy.to_string(), "3.1.4");
    }

    #[test]
    fn change_kind_copy_semantics() {
        let original = ChangeKind::TaxonomyUpdated;
        let copy = original;
        assert_eq!(original, copy);
    }

    // ── Clone independence ─────────────────────────────────────────────

    #[test]
    fn boundary_surface_clone_independence() {
        let surface = BoundarySurface {
            sibling: SiblingRepo::Asupersync,
            surface_id: "test/clone".to_string(),
            surface_kind: SurfaceKind::ApiMessage,
            description: "original".to_string(),
            covered_fields: ["f1"].iter().map(|s| s.to_string()).collect(),
            version_class: VersionClass::Patch,
        };
        let mut cloned = surface.clone();
        cloned.description = "mutated".to_string();
        assert_eq!(surface.description, "original");
        assert_eq!(cloned.description, "mutated");
    }

    #[test]
    fn replay_obligation_clone_independence() {
        let ob = ReplayObligation::standard("t1", SiblingRepo::FrankenNode);
        let mut cloned = ob.clone();
        cloned.must_capture_input = false;
        assert!(ob.must_capture_input);
        assert!(!cloned.must_capture_input);
    }

    #[test]
    fn conformance_catalog_clone_independence() {
        let catalog = build_canonical_catalog();
        let mut cloned = catalog.clone();
        cloned.entries.clear();
        assert!(!catalog.entries.is_empty());
        assert!(cloned.entries.is_empty());
    }

    #[test]
    fn failure_taxonomy_entry_clone_independence() {
        let entry = FailureTaxonomyEntry {
            regression_class: RegressionClass::Performance,
            severity: FailureSeverity::Warning,
            required_response: RequiredResponse::Log,
            evidence_requirements: vec!["metric".to_string()],
            description: "original".to_string(),
        };
        let mut cloned = entry.clone();
        cloned.description = "mutated".to_string();
        assert_eq!(entry.description, "original");
    }

    // ── Debug output non-empty and distinct ───────────────────────────

    #[test]
    fn sibling_repo_debug_distinct() {
        let debugs: BTreeSet<String> = SiblingRepo::all()
            .iter()
            .map(|r| format!("{r:?}"))
            .collect();
        assert_eq!(debugs.len(), 6);
        for d in &debugs {
            assert!(!d.is_empty());
        }
    }

    #[test]
    fn surface_kind_debug_distinct() {
        let kinds = [
            SurfaceKind::IdentifierSchema,
            SurfaceKind::DecisionPayload,
            SurfaceKind::EvidencePayload,
            SurfaceKind::ApiMessage,
            SurfaceKind::PersistenceSemantics,
            SurfaceKind::ReplayFormat,
            SurfaceKind::ExportFormat,
            SurfaceKind::TuiEventContract,
            SurfaceKind::TuiStateContract,
            SurfaceKind::TelemetrySchema,
        ];
        let debugs: BTreeSet<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(debugs.len(), 10);
    }

    #[test]
    fn failure_severity_debug_distinct() {
        let variants = [
            FailureSeverity::Info,
            FailureSeverity::Warning,
            FailureSeverity::Error,
            FailureSeverity::Critical,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(debugs.len(), 4);
    }

    #[test]
    fn required_response_debug_distinct() {
        let variants = [
            RequiredResponse::Log,
            RequiredResponse::Warn,
            RequiredResponse::Block,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(debugs.len(), 3);
    }

    #[test]
    fn change_kind_debug_distinct() {
        let kinds = [
            ChangeKind::EntryAdded,
            ChangeKind::EntryModified,
            ChangeKind::EntryRemoved,
            ChangeKind::TaxonomyUpdated,
            ChangeKind::VectorAdded,
            ChangeKind::VectorRemoved,
        ];
        let debugs: BTreeSet<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(debugs.len(), 6);
    }

    // ── Serde variant distinctness ─────────────────────────────────────

    #[test]
    fn sibling_repo_serde_variants_distinct() {
        let jsons: BTreeSet<String> = SiblingRepo::all()
            .iter()
            .map(|r| serde_json::to_string(r).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(
            jsons.len(),
            6,
            "all 6 sibling repo variants serialize distinctly"
        );
    }

    #[test]
    fn surface_kind_serde_variants_distinct() {
        let kinds = [
            SurfaceKind::IdentifierSchema,
            SurfaceKind::DecisionPayload,
            SurfaceKind::EvidencePayload,
            SurfaceKind::ApiMessage,
            SurfaceKind::PersistenceSemantics,
            SurfaceKind::ReplayFormat,
            SurfaceKind::ExportFormat,
            SurfaceKind::TuiEventContract,
            SurfaceKind::TuiStateContract,
            SurfaceKind::TelemetrySchema,
        ];
        let jsons: BTreeSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 10);
    }

    #[test]
    fn version_class_serde_variants_distinct() {
        let variants = [
            VersionClass::Patch,
            VersionClass::Minor,
            VersionClass::Major,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn version_compatibility_serde_variants_distinct() {
        let variants = [
            VersionCompatibility::Exact,
            VersionCompatibility::PatchCompatible,
            VersionCompatibility::MinorCompatible,
            VersionCompatibility::MajorIncompatible,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn failure_severity_serde_variants_distinct() {
        let variants = [
            FailureSeverity::Info,
            FailureSeverity::Warning,
            FailureSeverity::Error,
            FailureSeverity::Critical,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 4);
    }

    #[test]
    fn required_response_serde_variants_distinct() {
        let variants = [
            RequiredResponse::Log,
            RequiredResponse::Warn,
            RequiredResponse::Block,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn change_kind_serde_variants_distinct() {
        let kinds = [
            ChangeKind::EntryAdded,
            ChangeKind::EntryModified,
            ChangeKind::EntryRemoved,
            ChangeKind::TaxonomyUpdated,
            ChangeKind::VectorAdded,
            ChangeKind::VectorRemoved,
        ];
        let jsons: BTreeSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(jsons.len(), 6);
    }

    // ── JSON field-name stability ──────────────────────────────────────

    #[test]
    fn semantic_version_json_field_names() {
        let v = SemanticVersion::new(1, 2, 3);
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        assert!(json.contains("\"major\""), "expected 'major' field");
        assert!(json.contains("\"minor\""), "expected 'minor' field");
        assert!(json.contains("\"patch\""), "expected 'patch' field");
        assert!(json.contains("1"));
        assert!(json.contains("2"));
        assert!(json.contains("3"));
    }

    #[test]
    fn replay_artifact_json_field_names() {
        let mut versions = BTreeMap::new();
        versions.insert("repo".to_string(), SemanticVersion::new(1, 0, 0));
        let artifact = ReplayArtifact {
            test_id: "t1".to_string(),
            boundary: SiblingRepo::Frankentui,
            deterministic_seed: 7,
            pinned_versions: versions,
            input_snapshot: vec![1],
            expected_output_hash: "hash".to_string(),
            reproduction_command: "cmd".to_string(),
        };
        let json = serde_json::to_string(&artifact).expect("serde deserialization should succeed");
        assert!(json.contains("\"test_id\""));
        assert!(json.contains("\"boundary\""));
        assert!(json.contains("\"deterministic_seed\""));
        assert!(json.contains("\"pinned_versions\""));
        assert!(json.contains("\"input_snapshot\""));
        assert!(json.contains("\"expected_output_hash\""));
        assert!(json.contains("\"reproduction_command\""));
    }

    #[test]
    fn replay_obligation_json_field_names() {
        let ob = ReplayObligation::standard("tid", SiblingRepo::Asupersync);
        let json = serde_json::to_string(&ob).expect("serde deserialization should succeed");
        assert!(json.contains("\"test_id\""));
        assert!(json.contains("\"boundary\""));
        assert!(json.contains("\"must_pin_versions\""));
        assert!(json.contains("\"must_provide_seed\""));
        assert!(json.contains("\"must_capture_input\""));
        assert!(json.contains("\"must_hash_output\""));
    }

    #[test]
    fn catalog_validation_error_json_field_names() {
        let err = CatalogValidationError {
            entry_id: Some("e1".to_string()),
            field: "f1".to_string(),
            detail: "d1".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        assert!(json.contains("\"entry_id\""));
        assert!(json.contains("\"field\""));
        assert!(json.contains("\"detail\""));
    }

    #[test]
    fn catalog_change_record_json_field_names() {
        let record = CatalogChangeRecord {
            version: SemanticVersion::new(1, 0, 0),
            description: "added".to_string(),
            affected_entries: vec!["e1".to_string()],
            change_kind: ChangeKind::EntryAdded,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"affected_entries\""));
        assert!(json.contains("\"change_kind\""));
    }

    // ── Display format checks ──────────────────────────────────────────

    #[test]
    fn failure_severity_display_all() {
        assert_eq!(FailureSeverity::Info.to_string(), "info");
        assert_eq!(FailureSeverity::Warning.to_string(), "warning");
        assert_eq!(FailureSeverity::Error.to_string(), "error");
        assert_eq!(FailureSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn required_response_display_all() {
        assert_eq!(RequiredResponse::Log.to_string(), "log");
        assert_eq!(RequiredResponse::Warn.to_string(), "warn");
        assert_eq!(RequiredResponse::Block.to_string(), "block");
    }

    #[test]
    fn change_kind_display_all() {
        assert_eq!(ChangeKind::EntryAdded.to_string(), "entry_added");
        assert_eq!(ChangeKind::EntryModified.to_string(), "entry_modified");
        assert_eq!(ChangeKind::EntryRemoved.to_string(), "entry_removed");
        assert_eq!(ChangeKind::TaxonomyUpdated.to_string(), "taxonomy_updated");
        assert_eq!(ChangeKind::VectorAdded.to_string(), "vector_added");
        assert_eq!(ChangeKind::VectorRemoved.to_string(), "vector_removed");
    }

    #[test]
    fn surface_kind_display_matches_as_str() {
        let kinds = [
            SurfaceKind::IdentifierSchema,
            SurfaceKind::DecisionPayload,
            SurfaceKind::EvidencePayload,
            SurfaceKind::ApiMessage,
            SurfaceKind::PersistenceSemantics,
            SurfaceKind::ReplayFormat,
            SurfaceKind::ExportFormat,
            SurfaceKind::TuiEventContract,
            SurfaceKind::TuiStateContract,
            SurfaceKind::TelemetrySchema,
        ];
        for kind in &kinds {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    #[test]
    fn version_class_display_matches_as_str() {
        let variants = [
            VersionClass::Patch,
            VersionClass::Minor,
            VersionClass::Major,
        ];
        for v in &variants {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn failure_severity_display_matches_as_str() {
        let variants = [
            FailureSeverity::Info,
            FailureSeverity::Warning,
            FailureSeverity::Error,
            FailureSeverity::Critical,
        ];
        for v in &variants {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn required_response_display_matches_as_str() {
        let variants = [
            RequiredResponse::Log,
            RequiredResponse::Warn,
            RequiredResponse::Block,
        ];
        for v in &variants {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    // ── Hash consistency ───────────────────────────────────────────────

    #[test]
    fn sibling_repo_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let repo = SiblingRepo::Frankensqlite;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        repo.hash(&mut h1);
        repo.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn sibling_repo_hash_distinct_across_variants() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let hashes: BTreeSet<u64> = SiblingRepo::all()
            .iter()
            .map(|r| {
                let mut h = DefaultHasher::new();
                r.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 6, "all sibling repo variants hash distinctly");
    }

    #[test]
    fn semantic_version_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let v = SemanticVersion::new(1, 2, 3);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v.hash(&mut h1);
        v.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn semantic_version_hash_distinct_across_values() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let versions = [
            SemanticVersion::new(1, 0, 0),
            SemanticVersion::new(2, 0, 0),
            SemanticVersion::new(1, 1, 0),
            SemanticVersion::new(1, 0, 1),
        ];
        let hashes: BTreeSet<u64> = versions
            .iter()
            .map(|v| {
                let mut h = DefaultHasher::new();
                v.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), 4, "distinct versions should hash distinctly");
    }

    // ── Boundary/edge cases ────────────────────────────────────────────

    #[test]
    fn semantic_version_max_fields() {
        let v = SemanticVersion::new(u32::MAX, u32::MAX, u32::MAX);
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let decoded: SemanticVersion = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, decoded);
        assert_eq!(v.major, u32::MAX);
        assert_eq!(v.minor, u32::MAX);
        assert_eq!(v.patch, u32::MAX);
    }

    #[test]
    fn replay_artifact_empty_input_snapshot_detected() {
        let ob = ReplayObligation {
            test_id: "t1".to_string(),
            boundary: SiblingRepo::FrankenNode,
            must_pin_versions: false,
            must_provide_seed: false,
            must_capture_input: true,
            must_hash_output: false,
        };
        let artifact = ReplayArtifact {
            test_id: "t1".to_string(),
            boundary: SiblingRepo::FrankenNode,
            deterministic_seed: 1,
            pinned_versions: BTreeMap::new(),
            input_snapshot: vec![],
            expected_output_hash: "hash".to_string(),
            reproduction_command: "cmd".to_string(),
        };
        let errors = ob.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("input_snapshot"));
    }

    #[test]
    fn replay_obligation_verify_empty_hash_detected() {
        let ob = ReplayObligation {
            test_id: "t1".to_string(),
            boundary: SiblingRepo::FastapiRust,
            must_pin_versions: false,
            must_provide_seed: false,
            must_capture_input: false,
            must_hash_output: true,
        };
        let artifact = ReplayArtifact {
            test_id: "t1".to_string(),
            boundary: SiblingRepo::FastapiRust,
            deterministic_seed: 1,
            pinned_versions: BTreeMap::new(),
            input_snapshot: vec![],
            expected_output_hash: "".to_string(),
            reproduction_command: "cmd".to_string(),
        };
        let errors = ob.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("expected_output_hash"));
    }

    #[test]
    fn replay_obligation_verify_test_id_mismatch_detected() {
        let ob = ReplayObligation {
            test_id: "expected-id".to_string(),
            boundary: SiblingRepo::SqlmodelRust,
            must_pin_versions: false,
            must_provide_seed: false,
            must_capture_input: false,
            must_hash_output: false,
        };
        let artifact = ReplayArtifact {
            test_id: "wrong-id".to_string(),
            boundary: SiblingRepo::SqlmodelRust,
            deterministic_seed: 1,
            pinned_versions: BTreeMap::new(),
            input_snapshot: vec![],
            expected_output_hash: "hash".to_string(),
            reproduction_command: "cmd".to_string(),
        };
        let errors = ob.verify(&artifact);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("test_id mismatch"));
        assert!(errors[0].contains("expected-id"));
        assert!(errors[0].contains("wrong-id"));
    }

    #[test]
    fn conformance_vector_serde_roundtrip_with_regression_class() {
        let v = ConformanceVector {
            vector_id: "v1".to_string(),
            description: "desc".to_string(),
            input_json: "{\"x\": 1}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Breaking),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let decoded: ConformanceVector = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, decoded);
    }

    #[test]
    fn conformance_vector_serde_roundtrip_no_regression_class() {
        let v = ConformanceVector {
            vector_id: "v2".to_string(),
            description: "passes".to_string(),
            input_json: "{}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let decoded: ConformanceVector = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, decoded);
        assert!(decoded.expected_regression_class.is_none());
    }

    #[test]
    fn catalog_entry_has_required_vectors_true_when_both_present() {
        let make_entry =
            |id: &str, pos: Vec<ConformanceVector>, neg: Vec<ConformanceVector>| CatalogEntry {
                entry_id: id.to_string(),
                boundary: BoundarySurface {
                    sibling: SiblingRepo::Frankentui,
                    surface_id: id.to_string(),
                    surface_kind: SurfaceKind::ApiMessage,
                    description: "test".to_string(),
                    covered_fields: ["f"].iter().map(|s| s.to_string()).collect(),
                    version_class: VersionClass::Minor,
                },
                positive_vectors: pos,
                negative_vectors: neg,
                replay_obligation: ReplayObligation::standard(id, SiblingRepo::Frankentui),
                failure_class: RegressionClass::Behavioral,
                approved: false,
                approval_epoch: None,
            };
        let pos_vec = ConformanceVector {
            vector_id: "p".to_string(),
            description: "positive".to_string(),
            input_json: "{}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        };
        let neg_vec = ConformanceVector {
            vector_id: "n".to_string(),
            description: "negative".to_string(),
            input_json: "{}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Behavioral),
        };
        let e_both = make_entry("e1", vec![pos_vec.clone()], vec![neg_vec.clone()]);
        assert!(e_both.has_required_vectors());
        let e_no_neg = make_entry("e2", vec![pos_vec.clone()], vec![]);
        assert!(!e_no_neg.has_required_vectors());
        let e_no_pos = make_entry("e3", vec![], vec![neg_vec.clone()]);
        assert!(!e_no_pos.has_required_vectors());
        let e_none = make_entry("e4", vec![], vec![]);
        assert!(!e_none.has_required_vectors());
    }

    #[test]
    fn catalog_entry_serde_roundtrip() {
        let entry = CatalogEntry {
            entry_id: "serde/test_entry".to_string(),
            boundary: BoundarySurface {
                sibling: SiblingRepo::Frankensqlite,
                surface_id: "serde/test_entry".to_string(),
                surface_kind: SurfaceKind::PersistenceSemantics,
                description: "serde test".to_string(),
                covered_fields: ["key", "value"].iter().map(|s| s.to_string()).collect(),
                version_class: VersionClass::Major,
            },
            positive_vectors: vec![ConformanceVector {
                vector_id: "serde/pos".to_string(),
                description: "positive".to_string(),
                input_json: "{\"key\": \"k\"}".to_string(),
                expected_pass: true,
                expected_regression_class: None,
            }],
            negative_vectors: vec![ConformanceVector {
                vector_id: "serde/neg".to_string(),
                description: "negative".to_string(),
                input_json: "{}".to_string(),
                expected_pass: false,
                expected_regression_class: Some(RegressionClass::Breaking),
            }],
            replay_obligation: ReplayObligation::standard(
                "serde/test_entry",
                SiblingRepo::Frankensqlite,
            ),
            failure_class: RegressionClass::Breaking,
            approved: true,
            approval_epoch: Some(42),
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let decoded: CatalogEntry = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn boundary_surface_serde_roundtrip() {
        let surface = BoundarySurface {
            sibling: SiblingRepo::SqlmodelRust,
            surface_id: "sqlmodel/test".to_string(),
            surface_kind: SurfaceKind::PersistenceSemantics,
            description: "roundtrip test".to_string(),
            covered_fields: ["store_query", "batch_put_entry"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            version_class: VersionClass::Minor,
        };
        let json = serde_json::to_string(&surface).expect("serde deserialization should succeed");
        let decoded: BoundarySurface = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(surface, decoded);
    }

    #[test]
    fn field_version_coverage_serde_roundtrip() {
        let fvc = FieldVersionCoverage {
            field_name: "decision_id".to_string(),
            protected_at: VersionClass::Minor,
            required: true,
        };
        let json = serde_json::to_string(&fvc).expect("serde deserialization should succeed");
        let decoded: FieldVersionCoverage = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(fvc, decoded);
        assert_eq!(decoded.protected_at, VersionClass::Minor);
        assert!(decoded.required);
    }

    #[test]
    fn field_version_coverage_clone_independence() {
        let fvc = FieldVersionCoverage {
            field_name: "trace_id".to_string(),
            protected_at: VersionClass::Patch,
            required: false,
        };
        let mut cloned = fvc.clone();
        cloned.required = true;
        assert!(!fvc.required);
        assert!(cloned.required);
    }

    // ── Additional integration: classify_failure edge cases ────────────

    #[test]
    fn classify_failure_returns_none_for_empty_taxonomy() {
        let empty: Vec<FailureTaxonomyEntry> = vec![];
        assert!(classify_failure(&empty, RegressionClass::Breaking).is_none());
    }

    #[test]
    fn classify_failure_returns_correct_entry_for_each_class() {
        let taxonomy = failure_taxonomy();
        for class in [
            RegressionClass::Breaking,
            RegressionClass::Behavioral,
            RegressionClass::Observability,
            RegressionClass::Performance,
        ] {
            let entry = classify_failure(&taxonomy, class);
            assert!(entry.is_some(), "should find entry for {class:?}");
            assert_eq!(entry.expect("serde deserialization should succeed").regression_class, class);
        }
    }

    #[test]
    fn catalog_entries_by_class_sums_to_total_entries() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
        // Add entries across different classes
        for (id, class) in [
            ("e1", RegressionClass::Breaking),
            ("e2", RegressionClass::Behavioral),
            ("e3", RegressionClass::Observability),
            ("e4", RegressionClass::Performance),
            ("e5", RegressionClass::Breaking),
        ] {
            catalog.add_entry(CatalogEntry {
                entry_id: id.to_string(),
                boundary: BoundarySurface {
                    sibling: SiblingRepo::Asupersync,
                    surface_id: id.to_string(),
                    surface_kind: SurfaceKind::EvidencePayload,
                    description: "test".to_string(),
                    covered_fields: ["f"].iter().map(|s| s.to_string()).collect(),
                    version_class: VersionClass::Patch,
                },
                positive_vectors: vec![ConformanceVector {
                    vector_id: format!("{id}/p"),
                    description: "pos".to_string(),
                    input_json: "{}".to_string(),
                    expected_pass: true,
                    expected_regression_class: None,
                }],
                negative_vectors: vec![ConformanceVector {
                    vector_id: format!("{id}/n"),
                    description: "neg".to_string(),
                    input_json: "{}".to_string(),
                    expected_pass: false,
                    expected_regression_class: Some(class),
                }],
                replay_obligation: ReplayObligation::standard(id, SiblingRepo::Asupersync),
                failure_class: class,
                approved: true,
                approval_epoch: None,
            });
        }
        let counts = catalog.entries_by_class();
        let total: usize = counts.values().sum();
        assert_eq!(total, catalog.entries.len());
        assert_eq!(*counts.get(&RegressionClass::Breaking).expect("serde deserialization should succeed"), 2);
        assert_eq!(*counts.get(&RegressionClass::Behavioral).expect("serde deserialization should succeed"), 1);
    }

    #[test]
    fn covered_boundaries_returns_correct_set() {
        let catalog = build_canonical_catalog();
        let covered = catalog.covered_boundaries();
        // All 6 sibling repos should be covered by canonical catalog
        assert_eq!(covered.len(), 6);
        for repo in SiblingRepo::all() {
            assert!(
                covered.contains(repo),
                "expected {repo} in covered boundaries"
            );
        }
    }

    #[test]
    fn catalog_get_entry_returns_correct_entry() {
        let catalog = build_canonical_catalog();
        let entry = catalog.get_entry("frankensqlite/store_record");
        assert!(entry.is_some());
        let e = entry.expect("serde deserialization should succeed");
        assert_eq!(e.entry_id, "frankensqlite/store_record");
        assert_eq!(e.boundary.sibling, SiblingRepo::Frankensqlite);
        assert_eq!(e.boundary.surface_kind, SurfaceKind::PersistenceSemantics);
    }

    #[test]
    fn version_negotiation_result_with_migration_path_serde_roundtrip() {
        let result = VersionNegotiationResult {
            boundary: SiblingRepo::FrankenNode,
            local_version: SemanticVersion::new(1, 0, 0),
            remote_version: SemanticVersion::new(2, 0, 0),
            compatibility: VersionCompatibility::MajorIncompatible,
            migration_required: true,
            migration_path: Some("migrate_v1_to_v2.sh".to_string()),
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let decoded: VersionNegotiationResult = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, decoded);
        assert!(decoded.migration_required);
        assert_eq!(
            decoded.migration_path,
            Some("migrate_v1_to_v2.sh".to_string())
        );
    }

    #[test]
    fn catalog_change_record_serde_roundtrip() {
        let record = CatalogChangeRecord {
            version: SemanticVersion::new(2, 1, 0),
            description: "modified entry for frankentui".to_string(),
            affected_entries: vec!["frankentui/adapter_envelope".to_string()],
            change_kind: ChangeKind::EntryModified,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        let decoded: CatalogChangeRecord = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(record, decoded);
        assert_eq!(decoded.change_kind, ChangeKind::EntryModified);
    }

    #[test]
    fn validate_catalog_detects_duplicate_vector_ids() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
        let dup_vector = ConformanceVector {
            vector_id: "same-id".to_string(),
            description: "dup".to_string(),
            input_json: "{}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        };
        catalog.add_entry(CatalogEntry {
            entry_id: "test/dup_vectors".to_string(),
            boundary: BoundarySurface {
                sibling: SiblingRepo::SqlmodelRust,
                surface_id: "test/dup_vectors".to_string(),
                surface_kind: SurfaceKind::ExportFormat,
                description: "test".to_string(),
                covered_fields: ["f1"].iter().map(|s| s.to_string()).collect(),
                version_class: VersionClass::Minor,
            },
            positive_vectors: vec![dup_vector.clone()],
            negative_vectors: vec![ConformanceVector {
                vector_id: "same-id".to_string(), // duplicate!
                description: "negative with dup id".to_string(),
                input_json: "{}".to_string(),
                expected_pass: false,
                expected_regression_class: Some(RegressionClass::Behavioral),
            }],
            replay_obligation: ReplayObligation::standard(
                "test/dup_vectors",
                SiblingRepo::SqlmodelRust,
            ),
            failure_class: RegressionClass::Behavioral,
            approved: false,
            approval_epoch: None,
        });
        let errors = validate_catalog(&catalog);
        assert!(
            errors
                .iter()
                .any(|e| e.detail.contains("duplicate vector ID")),
            "expected duplicate vector ID error, got: {errors:?}"
        );
    }

    #[test]
    fn version_class_as_str_patch() {
        assert_eq!(VersionClass::Patch.as_str(), "patch");
    }

    #[test]
    fn negotiate_version_same_major_different_minor_and_patch_is_minor_compatible() {
        // When minor differs, even if patch also differs, result is MinorCompatible
        let local = SemanticVersion::new(1, 2, 0);
        let remote = SemanticVersion::new(1, 3, 5);
        assert_eq!(
            negotiate_version(local, remote),
            VersionCompatibility::MinorCompatible
        );
    }

    #[test]
    fn sibling_repo_ordering_is_deterministic() {
        // BTreeSet should consistently sort sibling repos
        let mut set = BTreeSet::new();
        for repo in SiblingRepo::all() {
            set.insert(*repo);
        }
        assert_eq!(set.len(), 6);
        let first = *set.iter().next().expect("serde deserialization should succeed");
        // Asupersync should be first alphabetically
        assert_eq!(first, SiblingRepo::Asupersync);
    }
}
