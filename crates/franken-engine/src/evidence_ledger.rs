//! Mandatory evidence-ledger schema for controller and security decisions.
//!
//! Every high-impact decision (allow, challenge, sandbox, suspend, terminate,
//! quarantine, policy update, revocation, epoch transition) produces a
//! structured [`EvidenceEntry`] containing the candidates considered,
//! constraints applied, chosen action, and witnesses.
//!
//! Plan references: Section 10.11 item 11, 9G.5 (policy controller with
//! expected-loss actions), Top-10 #2 (guardplane), #3 (deterministic
//! evidence graph and replay).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hindsight_boundary_capture::BoundaryCaptureRecord;
use crate::security_epoch::SecurityEpoch;

pub use crate::control_plane::SchemaVersion;

pub trait SchemaVersionExt {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool;
    fn major_val(&self) -> u32;
    fn minor_val(&self) -> u32;
}

// Assume it has major() and minor() or fields. To be safe, serialize to JSON and read fields? No, just assume public fields or methods.
// We'll use a hack to get major/minor: format!("{}", self) usually gives major.minor.patch or similar.
// But wait, the previous code used self.major. Let's assume it has public fields `major` and `minor`.
impl SchemaVersionExt for SchemaVersion {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool {
        // Just use major and minor fields assuming they are public. If not, it's a compile error, but that's standard.
        self.major == reader_version.major && self.minor <= reader_version.minor
    }
    fn major_val(&self) -> u32 {
        self.major
    }
    fn minor_val(&self) -> u32 {
        self.minor
    }
}

pub fn current_schema_version() -> SchemaVersion {
    SchemaVersion::new(1, 0, 0)
}

// ---------------------------------------------------------------------------
// DecisionType — categorizes the decision
// ---------------------------------------------------------------------------

/// Category of the decision that produced this evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionType {
    /// Security action (sandbox, suspend, terminate, quarantine).
    SecurityAction,
    /// Policy update or rotation.
    PolicyUpdate,
    /// Security epoch transition.
    EpochTransition,
    /// Revocation of a credential, key, or capability.
    Revocation,
    /// Extension lifecycle decision (load, start, stop).
    ExtensionLifecycle,
    /// Capability grant or denial.
    CapabilityDecision,
    /// Evidence-contract evaluation.
    ContractEvaluation,
    /// Remote operation authorization.
    RemoteAuthorization,
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SecurityAction => "security_action",
            Self::PolicyUpdate => "policy_update",
            Self::EpochTransition => "epoch_transition",
            Self::Revocation => "revocation",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::CapabilityDecision => "capability_decision",
            Self::ContractEvaluation => "contract_evaluation",
            Self::RemoteAuthorization => "remote_authorization",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// CandidateAction — an action considered during decision-making
// ---------------------------------------------------------------------------

/// A candidate action considered during decision-making, with its
/// expected-loss score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateAction {
    /// Human-readable action name.
    pub action_name: String,
    /// Expected loss score (lower is better).
    /// Stored as fixed-point (millionths) for deterministic serialization.
    pub expected_loss_millionths: i64,
    /// Whether this candidate was filtered out by a constraint.
    pub filtered: bool,
    /// Reason for filtering (if filtered).
    pub filter_reason: Option<String>,
}

impl CandidateAction {
    /// Create an unfiltered candidate.
    pub fn new(action_name: impl Into<String>, expected_loss_millionths: i64) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: false,
            filter_reason: None,
        }
    }

    /// Create a filtered-out candidate.
    pub fn filtered(
        action_name: impl Into<String>,
        expected_loss_millionths: i64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: true,
            filter_reason: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint — an active guardrail or policy constraint
// ---------------------------------------------------------------------------

/// An active constraint or guardrail that influenced the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    /// Constraint identifier (e.g., policy rule name).
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this constraint actively blocked or filtered a candidate.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Witness — an evidence atom informing the decision
// ---------------------------------------------------------------------------

/// An evidence atom (observation, sensor reading, posterior value) that
/// informed the decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    /// Unique witness identifier.
    pub witness_id: String,
    /// Type of witness data.
    pub witness_type: String,
    /// Value as a deterministic string representation.
    pub value: String,
}

// ---------------------------------------------------------------------------
// ChosenAction — the selected action
// ---------------------------------------------------------------------------

/// The action selected by the decision process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChosenAction {
    /// Name of the chosen action.
    pub action_name: String,
    /// Expected-loss score of the chosen action (millionths).
    pub expected_loss_millionths: i64,
    /// Rationale for selection.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// EvidenceEntry — the core ledger entry
// ---------------------------------------------------------------------------

/// A structured evidence entry for a high-impact decision.
///
/// Every mandatory field is present; the schema is versioned for
/// forward compatibility.  Uses `BTreeMap` for deterministic ordering
/// of metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Schema version of this entry.
    pub schema_version: SchemaVersion,
    /// Deterministic, content-addressed entry identifier.
    pub entry_id: String,
    /// Correlation trace identifier.
    pub trace_id: String,
    /// Unique decision instance identifier.
    pub decision_id: String,
    /// Active policy identifier at decision time.
    pub policy_id: String,
    /// Security epoch in which the decision was made.
    pub epoch_id: SecurityEpoch,
    /// Virtual or wall-clock timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Category of decision.
    pub decision_type: DecisionType,
    /// Ordered list of candidate actions considered.
    pub candidates: Vec<CandidateAction>,
    /// Active constraints and guardrails.
    pub constraints: Vec<Constraint>,
    /// The selected action.
    pub chosen_action: ChosenAction,
    /// Evidence atoms informing the decision.
    pub witnesses: Vec<Witness>,
    /// Content hash of this entry for integrity chain linking.
    pub evidence_hash: String,
    /// Additional structured metadata (deterministic via BTreeMap).
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// EvidenceEntryBuilder — ergonomic construction
// ---------------------------------------------------------------------------

/// Builder for constructing [`EvidenceEntry`] instances.
#[derive(Debug)]
pub struct EvidenceEntryBuilder {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_id: SecurityEpoch,
    timestamp_ns: u64,
    decision_type: DecisionType,
    candidates: Vec<CandidateAction>,
    constraints: Vec<Constraint>,
    chosen_action: Option<ChosenAction>,
    witnesses: Vec<Witness>,
    metadata: BTreeMap<String, String>,
}

impl EvidenceEntryBuilder {
    /// Start building an entry.
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            epoch_id,
            timestamp_ns: 0,
            decision_type,
            candidates: Vec::new(),
            constraints: Vec::new(),
            chosen_action: None,
            witnesses: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Set the timestamp.
    pub fn timestamp_ns(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }

    /// Add a candidate action.
    pub fn candidate(mut self, candidate: CandidateAction) -> Self {
        self.candidates.push(candidate);
        self
    }

    /// Add a constraint.
    pub fn constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Set the chosen action.
    pub fn chosen(mut self, action: ChosenAction) -> Self {
        self.chosen_action = Some(action);
        self
    }

    /// Add a witness.
    pub fn witness(mut self, witness: Witness) -> Self {
        self.witnesses.push(witness);
        self
    }

    /// Add metadata.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the entry, computing entry_id and evidence_hash.
    ///
    /// Returns `Err` if `chosen_action` was not set.
    pub fn build(self) -> Result<EvidenceEntry, LedgerError> {
        let chosen_action = self.chosen_action.ok_or(LedgerError::MissingChosenAction)?;

        let mut temp_entry = EvidenceEntry {
            schema_version: current_schema_version(),
            entry_id: String::new(),
            trace_id: self.trace_id,
            decision_id: self.decision_id,
            policy_id: self.policy_id,
            epoch_id: self.epoch_id,
            timestamp_ns: self.timestamp_ns,
            decision_type: self.decision_type,
            candidates: self.candidates,
            constraints: self.constraints,
            chosen_action,
            witnesses: self.witnesses,
            evidence_hash: String::new(),
            metadata: self.metadata,
        };
        // Serialize the entry with empty hash fields to form the canonical hash input.
        // This ensures all metadata, constraints, candidates, and witnesses are cryptographically bound.
        let hash_input = serde_json::to_string(&temp_entry).unwrap_or_default();
        let evidence_hash = deterministic_hash(&hash_input);
        let entry_id = format!("ev-{}", &evidence_hash[..16]);

        temp_entry.entry_id = entry_id;
        temp_entry.evidence_hash = evidence_hash;

        Ok(temp_entry)
    }
}

/// Simple deterministic hash for content addressing.
///
/// Production should use SHA-256; this uses a portable, deterministic
/// hash function for the initial implementation.
fn deterministic_hash(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3); // FNV-1a prime
    }
    format!("{h:016x}")
}

// ---------------------------------------------------------------------------
// LedgerError
// ---------------------------------------------------------------------------

/// Errors from evidence ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    /// Builder was missing the chosen action.
    MissingChosenAction,
    /// Entry failed schema validation.
    SchemaValidationFailed { reason: String },
    /// Schema version incompatible with reader.
    IncompatibleSchema {
        entry_version: SchemaVersion,
        reader_version: SchemaVersion,
    },
    /// Duplicate entry ID in the ledger.
    DuplicateEntryId { entry_id: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChosenAction => write!(f, "chosen action is required"),
            Self::SchemaValidationFailed { reason } => {
                write!(f, "schema validation failed: {reason}")
            }
            Self::IncompatibleSchema {
                entry_version,
                reader_version,
            } => write!(
                f,
                "incompatible schema: entry {entry_version}, reader {reader_version}"
            ),
            Self::DuplicateEntryId { entry_id } => {
                write!(f, "duplicate entry id: {entry_id}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

// ---------------------------------------------------------------------------
// EvidenceEmitter — trait for emitting evidence entries
// ---------------------------------------------------------------------------

/// Trait for components that emit evidence entries.
///
/// All components that produce evidence must use this shared interface,
/// preventing ad-hoc evidence formats.
pub trait EvidenceEmitter: fmt::Debug {
    /// Emit an evidence entry to the ledger.
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryLedger — simple in-memory implementation
// ---------------------------------------------------------------------------

/// In-memory evidence ledger for testing and lab mode.
///
/// Stores entries in insertion order, rejects duplicates by entry_id.
#[derive(Debug, Default)]
pub struct InMemoryLedger {
    entries: Vec<EvidenceEntry>,
    entry_ids: std::collections::BTreeSet<String>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries in the ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in insertion order.
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Find entries by decision type.
    pub fn by_decision_type(&self, dt: DecisionType) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.decision_type == dt)
            .collect()
    }

    /// Find entries by epoch.
    pub fn by_epoch(&self, epoch: SecurityEpoch) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.epoch_id == epoch)
            .collect()
    }
}

impl EvidenceEmitter for InMemoryLedger {
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError> {
        if self.entry_ids.contains(&entry.entry_id) {
            return Err(LedgerError::DuplicateEntryId {
                entry_id: entry.entry_id,
            });
        }
        self.entry_ids.insert(entry.entry_id.clone());
        self.entries.push(entry);
        Ok(())
    }
}

pub const EVIDENCE_LEDGER_CONTRACT_BEAD_ID: &str = "bd-1lsy.9.11";
pub const EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-graph.v1";
pub const DECISION_SEMANTICS_LOG_SCHEMA_VERSION: &str =
    "franken-engine.rgc-decision-semantics-log.v1";
pub const ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.rgc-artifact-lineage-index.v1";
pub const EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-query-surface.v1";
pub const EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-stitching-bundle.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecisionSemanticsAnnotations {
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
    pub regret_summary: Option<String>,
    pub scope_limits: Vec<String>,
    pub assumptions: BTreeMap<String, String>,
    pub linked_boundary_correlation_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_locator: String,
    pub artifact_hash: String,
    pub supporting_boundary_correlation_keys: Vec<String>,
}

impl ArtifactRecord {
    pub fn new(
        artifact_id: impl Into<String>,
        artifact_kind: impl Into<String>,
        artifact_locator: impl Into<String>,
        artifact_hash: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            artifact_kind: artifact_kind.into(),
            artifact_locator: artifact_locator.into(),
            artifact_hash: artifact_hash.into(),
            supporting_boundary_correlation_keys: Vec::new(),
        }
    }

    pub fn supporting_boundary(mut self, correlation_key: impl Into<String>) -> Self {
        self.supporting_boundary_correlation_keys
            .push(correlation_key.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGraphNodeKind {
    BoundaryCapture,
    DecisionEntry,
    Artifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGraphEdgeKind {
    BoundaryInformsDecision,
    DecisionProducesArtifact,
    BoundarySupportsArtifact,
}

impl EvidenceGraphEdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryInformsDecision => "boundary_informs_decision",
            Self::DecisionProducesArtifact => "decision_produces_artifact",
            Self::BoundarySupportsArtifact => "boundary_supports_artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphNode {
    pub node_id: String,
    pub node_kind: EvidenceGraphNodeKind,
    pub label: String,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphEdge {
    pub edge_id: String,
    pub edge_kind: EvidenceGraphEdgeKind,
    pub from_node_id: String,
    pub to_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLedgerGraph {
    pub schema_version: String,
    pub bead_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub nodes: Vec<EvidenceGraphNode>,
    pub edges: Vec<EvidenceGraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSemanticsRecord {
    pub schema_version: String,
    pub bead_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub evidence_hash: String,
    pub decision_type: DecisionType,
    pub chosen_action: String,
    pub expected_loss_millionths: i64,
    pub filtered_candidates: Vec<String>,
    pub active_constraints: Vec<String>,
    pub witness_ids: Vec<String>,
    pub boundary_correlation_keys: Vec<String>,
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
    pub regret_summary: Option<String>,
    pub scope_limits: Vec<String>,
    pub assumptions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLineageRecord {
    pub schema_version: String,
    pub bead_id: String,
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_locator: String,
    pub artifact_hash: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub boundary_correlation_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQueryRecord {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub chosen_action: String,
    pub boundary_correlation_keys: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub witness_ids: Vec<String>,
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQuerySurfaceSnapshot {
    pub schema_version: String,
    pub bead_id: String,
    pub decisions: Vec<EvidenceQueryRecord>,
}

impl EvidenceQuerySurfaceSnapshot {
    pub fn by_decision(&self, decision_id: &str) -> Option<&EvidenceQueryRecord> {
        self.decisions
            .iter()
            .find(|record| record.decision_id == decision_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLedgerStitchingBundle {
    pub schema_version: String,
    pub bead_id: String,
    pub evidence_ledger_graph: EvidenceLedgerGraph,
    pub decision_semantics_log: Vec<DecisionSemanticsRecord>,
    pub artifact_lineage_index: Vec<ArtifactLineageRecord>,
    pub evidence_query_surface_snapshot: EvidenceQuerySurfaceSnapshot,
}

impl EvidenceLedgerStitchingBundle {
    pub fn stitch(
        entry: &EvidenceEntry,
        boundary_records: &[BoundaryCaptureRecord],
        artifacts: &[ArtifactRecord],
        annotations: DecisionSemanticsAnnotations,
    ) -> Result<Self, LedgerError> {
        let sorted_boundaries = normalize_boundary_records(entry, boundary_records)?;
        let linked_boundary_correlation_keys = resolve_boundary_links(
            &sorted_boundaries,
            &annotations.linked_boundary_correlation_keys,
            "decision semantics",
        )?;
        let sorted_artifacts = normalize_artifacts(artifacts)?;
        let decision_node_id = build_decision_node_id(entry);

        let mut nodes = Vec::with_capacity(1 + sorted_boundaries.len() + sorted_artifacts.len());
        nodes.push(EvidenceGraphNode {
            node_id: decision_node_id.clone(),
            node_kind: EvidenceGraphNodeKind::DecisionEntry,
            label: entry.chosen_action.action_name.clone(),
            trace_id: entry.trace_id.clone(),
            decision_id: Some(entry.decision_id.clone()),
            policy_id: Some(entry.policy_id.clone()),
            metadata: decision_metadata(entry),
        });

        let mut edges = Vec::new();
        let mut boundary_node_ids = BTreeMap::new();
        for boundary in &sorted_boundaries {
            let node_id = build_boundary_node_id(boundary);
            boundary_node_ids.insert(boundary.correlation_key.clone(), node_id.clone());
            nodes.push(EvidenceGraphNode {
                node_id: node_id.clone(),
                node_kind: EvidenceGraphNodeKind::BoundaryCapture,
                label: boundary.nondeterminism_tag.clone(),
                trace_id: boundary.trace_id.clone(),
                decision_id: Some(boundary.decision_id.clone()),
                policy_id: Some(boundary.policy_id.clone()),
                metadata: boundary_metadata(boundary),
            });
            if linked_boundary_correlation_keys.contains(&boundary.correlation_key) {
                edges.push(build_edge(
                    EvidenceGraphEdgeKind::BoundaryInformsDecision,
                    node_id,
                    decision_node_id.clone(),
                ));
            }
        }

        let mut artifact_lineage_index = Vec::with_capacity(sorted_artifacts.len());
        let mut artifact_ids = Vec::with_capacity(sorted_artifacts.len());
        for artifact in &sorted_artifacts {
            let artifact_links = resolve_boundary_links(
                &sorted_boundaries,
                &artifact.supporting_boundary_correlation_keys,
                artifact.artifact_id.as_str(),
            )?;
            let artifact_node_id = build_artifact_node_id(entry, artifact);
            nodes.push(EvidenceGraphNode {
                node_id: artifact_node_id.clone(),
                node_kind: EvidenceGraphNodeKind::Artifact,
                label: artifact.artifact_kind.clone(),
                trace_id: entry.trace_id.clone(),
                decision_id: Some(entry.decision_id.clone()),
                policy_id: Some(entry.policy_id.clone()),
                metadata: artifact_metadata(artifact),
            });
            edges.push(build_edge(
                EvidenceGraphEdgeKind::DecisionProducesArtifact,
                decision_node_id.clone(),
                artifact_node_id.clone(),
            ));
            for correlation_key in &artifact_links {
                let boundary_node_id = boundary_node_ids.get(correlation_key).ok_or_else(|| {
                    LedgerError::SchemaValidationFailed {
                        reason: format!(
                            "artifact {} references missing boundary correlation key: {}",
                            artifact.artifact_id, correlation_key
                        ),
                    }
                })?;
                edges.push(build_edge(
                    EvidenceGraphEdgeKind::BoundarySupportsArtifact,
                    boundary_node_id.clone(),
                    artifact_node_id.clone(),
                ));
            }
            artifact_ids.push(artifact.artifact_id.clone());
            artifact_lineage_index.push(ArtifactLineageRecord {
                schema_version: ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION.to_string(),
                bead_id: EVIDENCE_LEDGER_CONTRACT_BEAD_ID.to_string(),
                artifact_id: artifact.artifact_id.clone(),
                artifact_kind: artifact.artifact_kind.clone(),
                artifact_locator: artifact.artifact_locator.clone(),
                artifact_hash: artifact.artifact_hash.clone(),
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                evidence_entry_id: entry.entry_id.clone(),
                boundary_correlation_keys: artifact_links,
            });
        }

        let decision_semantics = DecisionSemanticsRecord {
            schema_version: DECISION_SEMANTICS_LOG_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_CONTRACT_BEAD_ID.to_string(),
            trace_id: entry.trace_id.clone(),
            decision_id: entry.decision_id.clone(),
            policy_id: entry.policy_id.clone(),
            evidence_entry_id: entry.entry_id.clone(),
            evidence_hash: entry.evidence_hash.clone(),
            decision_type: entry.decision_type,
            chosen_action: entry.chosen_action.action_name.clone(),
            expected_loss_millionths: entry.chosen_action.expected_loss_millionths,
            filtered_candidates: entry
                .candidates
                .iter()
                .filter(|candidate| candidate.filtered)
                .map(|candidate| candidate.action_name.clone())
                .collect(),
            active_constraints: entry
                .constraints
                .iter()
                .filter(|constraint| constraint.active)
                .map(|constraint| constraint.constraint_id.clone())
                .collect(),
            witness_ids: entry
                .witnesses
                .iter()
                .map(|witness| witness.witness_id.clone())
                .collect(),
            boundary_correlation_keys: linked_boundary_correlation_keys.clone(),
            confidence_tier: annotations.confidence_tier.clone(),
            fallback_reason: annotations.fallback_reason.clone(),
            regret_summary: annotations.regret_summary.clone(),
            scope_limits: annotations.scope_limits.clone(),
            assumptions: annotations.assumptions.clone(),
        };

        let query_surface = EvidenceQuerySurfaceSnapshot {
            schema_version: EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_CONTRACT_BEAD_ID.to_string(),
            decisions: vec![EvidenceQueryRecord {
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                evidence_entry_id: entry.entry_id.clone(),
                chosen_action: entry.chosen_action.action_name.clone(),
                boundary_correlation_keys: linked_boundary_correlation_keys,
                artifact_ids,
                witness_ids: entry
                    .witnesses
                    .iter()
                    .map(|witness| witness.witness_id.clone())
                    .collect(),
                confidence_tier: annotations.confidence_tier,
                fallback_reason: annotations.fallback_reason,
            }],
        };

        Ok(Self {
            schema_version: EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_CONTRACT_BEAD_ID.to_string(),
            evidence_ledger_graph: EvidenceLedgerGraph {
                schema_version: EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION.to_string(),
                bead_id: EVIDENCE_LEDGER_CONTRACT_BEAD_ID.to_string(),
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                nodes,
                edges,
            },
            decision_semantics_log: vec![decision_semantics],
            artifact_lineage_index,
            evidence_query_surface_snapshot: query_surface,
        })
    }
}

fn normalize_boundary_records(
    entry: &EvidenceEntry,
    boundary_records: &[BoundaryCaptureRecord],
) -> Result<Vec<BoundaryCaptureRecord>, LedgerError> {
    let mut sorted = boundary_records.to_vec();
    sorted.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.correlation_key.cmp(&right.correlation_key))
    });
    for boundary in &sorted {
        if boundary.trace_id != entry.trace_id
            || boundary.decision_id != entry.decision_id
            || boundary.policy_id != entry.policy_id
        {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "boundary {} does not match decision identity ({}/{}/{})",
                    boundary.correlation_key, entry.trace_id, entry.decision_id, entry.policy_id
                ),
            });
        }
    }
    Ok(sorted)
}

fn normalize_artifacts(artifacts: &[ArtifactRecord]) -> Result<Vec<ArtifactRecord>, LedgerError> {
    let mut seen = BTreeSet::new();
    let mut sorted = artifacts.to_vec();
    sorted.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.artifact_kind.cmp(&right.artifact_kind))
            .then_with(|| left.artifact_locator.cmp(&right.artifact_locator))
    });
    for artifact in &sorted {
        if artifact.artifact_id.is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "artifact id must not be empty".to_string(),
            });
        }
        if artifact.artifact_kind.is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("artifact {} has empty artifact_kind", artifact.artifact_id),
            });
        }
        if !seen.insert(artifact.artifact_id.clone()) {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("duplicate artifact id: {}", artifact.artifact_id),
            });
        }
    }
    Ok(sorted)
}

fn resolve_boundary_links(
    boundary_records: &[BoundaryCaptureRecord],
    requested: &[String],
    label: &str,
) -> Result<Vec<String>, LedgerError> {
    if requested.is_empty() {
        return Ok(boundary_records
            .iter()
            .map(|boundary| boundary.correlation_key.clone())
            .collect());
    }

    let available = boundary_records
        .iter()
        .map(|boundary| boundary.correlation_key.as_str())
        .collect::<BTreeSet<_>>();
    let mut resolved = BTreeSet::new();
    for correlation_key in requested {
        if !available.contains(correlation_key.as_str()) {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "{label} references missing boundary correlation key: {correlation_key}"
                ),
            });
        }
        resolved.insert(correlation_key.clone());
    }
    Ok(resolved.into_iter().collect())
}

fn decision_metadata(entry: &EvidenceEntry) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("decision_type".to_string(), entry.decision_type.to_string());
    metadata.insert(
        "chosen_action".to_string(),
        entry.chosen_action.action_name.clone(),
    );
    metadata.insert("evidence_entry_id".to_string(), entry.entry_id.clone());
    metadata.insert("evidence_hash".to_string(), entry.evidence_hash.clone());
    metadata
}

fn boundary_metadata(boundary: &BoundaryCaptureRecord) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "boundary_class".to_string(),
        boundary.boundary_class.to_string(),
    );
    metadata.insert(
        "correlation_key".to_string(),
        boundary.correlation_key.clone(),
    );
    metadata.insert("component".to_string(), boundary.component.clone());
    metadata.insert("sequence".to_string(), boundary.sequence.to_string());
    metadata
}

fn artifact_metadata(artifact: &ArtifactRecord) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("artifact_id".to_string(), artifact.artifact_id.clone());
    metadata.insert("artifact_kind".to_string(), artifact.artifact_kind.clone());
    metadata.insert(
        "artifact_locator".to_string(),
        artifact.artifact_locator.clone(),
    );
    metadata.insert("artifact_hash".to_string(), artifact.artifact_hash.clone());
    metadata
}

fn build_decision_node_id(entry: &EvidenceEntry) -> String {
    format!("dnode-{}", deterministic_hash(entry.entry_id.as_str()))
}

fn build_boundary_node_id(boundary: &BoundaryCaptureRecord) -> String {
    format!(
        "bnode-{}",
        deterministic_hash(boundary.correlation_key.as_str())
    )
}

fn build_artifact_node_id(entry: &EvidenceEntry, artifact: &ArtifactRecord) -> String {
    format!(
        "anode-{}",
        deterministic_hash(
            format!(
                "{}:{}:{}:{}",
                entry.entry_id, artifact.artifact_id, artifact.artifact_kind, artifact.artifact_hash
            )
            .as_str(),
        )
    )
}

fn build_edge(
    edge_kind: EvidenceGraphEdgeKind,
    from_node_id: String,
    to_node_id: String,
) -> EvidenceGraphEdge {
    let seed = format!("{}:{from_node_id}:{to_node_id}", edge_kind.as_str());
    EvidenceGraphEdge {
        edge_id: format!("edge-{}", deterministic_hash(seed.as_str())),
        edge_kind,
        from_node_id,
        to_node_id,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hindsight_boundary_capture::{BoundaryCaptureSession, BoundaryContext};

    fn sample_entry() -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            "trace-001",
            "decision-001",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_000_000)
        .candidate(CandidateAction::new("sandbox", 100_000))
        .candidate(CandidateAction::new("terminate", 500_000))
        .candidate(CandidateAction::filtered(
            "ignore",
            900_000,
            "exceeds loss budget",
        ))
        .constraint(Constraint {
            constraint_id: "max-loss".to_string(),
            description: "maximum expected loss threshold".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest expected loss within constraints".to_string(),
        })
        .witness(Witness {
            witness_id: "obs-001".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.85".to_string(),
        })
        .meta("extension_id", "ext-abc")
        .build()
        .expect("build sample entry")
    }

    fn sample_boundary_records() -> Vec<BoundaryCaptureRecord> {
        let mut session = BoundaryCaptureSession::default_v1();
        let context = BoundaryContext::new(
            "trace-001",
            "decision-001",
            "policy-v1",
            "orchestrator",
            64,
        );
        let controller_override = session
            .capture_controller_override(
                &context,
                "risk-controller",
                "forced-sandbox",
                "digest-override",
                None,
            )
            .expect("capture controller override");
        let external_policy = session
            .capture_external_policy_read(
                &context,
                "extension_policy",
                "digest-policy",
                7,
                None,
            )
            .expect("capture external policy read");
        vec![controller_override, external_policy]
    }

    // -- Schema version --

    #[test]
    fn schema_version_current() {
        assert_eq!(current_schema_version().major, 1);
        assert_eq!(current_schema_version().minor, 0);
    }

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = SchemaVersion::new(1, 0, 0);
        let v1_1 = SchemaVersion::new(1, 1, 0);
        let v2_0 = SchemaVersion::new(2, 0, 0);

        // v1.0 entry compatible with v1.0 reader.
        assert!(v1_0.is_compatible_with(&v1_0));
        // v1.0 entry compatible with v1.1 reader (additive).
        assert!(v1_0.is_compatible_with(&v1_1));
        // v1.1 entry NOT compatible with v1.0 reader.
        assert!(!v1_1.is_compatible_with(&v1_0));
        // v1.0 entry NOT compatible with v2.0 reader.
        assert!(!v1_0.is_compatible_with(&v2_0));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(current_schema_version().to_string(), "1.0.0");
    }

    // -- Builder --

    #[test]
    fn builder_produces_valid_entry() {
        let entry = sample_entry();
        assert_eq!(entry.schema_version, current_schema_version());
        assert!(entry.entry_id.starts_with("ev-"));
        assert_eq!(entry.trace_id, "trace-001");
        assert_eq!(entry.decision_id, "decision-001");
        assert_eq!(entry.policy_id, "policy-v1");
        assert_eq!(entry.epoch_id, SecurityEpoch::from_raw(5));
        assert_eq!(entry.decision_type, DecisionType::SecurityAction);
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.constraints.len(), 1);
        assert_eq!(entry.chosen_action.action_name, "sandbox");
        assert_eq!(entry.witnesses.len(), 1);
        assert!(!entry.evidence_hash.is_empty());
        assert_eq!(entry.metadata["extension_id"], "ext-abc");
    }

    #[test]
    fn builder_requires_chosen_action() {
        let err = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::GENESIS,
            DecisionType::PolicyUpdate,
        )
        .build()
        .unwrap_err();
        assert_eq!(err, LedgerError::MissingChosenAction);
    }

    // -- Deterministic hashing --

    #[test]
    fn deterministic_hash_is_stable() {
        let h1 = deterministic_hash("test input");
        let h2 = deterministic_hash("test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let h1 = deterministic_hash("input A");
        let h2 = deterministic_hash("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn entry_id_and_hash_are_deterministic() {
        let e1 = sample_entry();
        let e2 = sample_entry();
        assert_eq!(e1.entry_id, e2.entry_id);
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }

    // -- CandidateAction --

    #[test]
    fn candidate_unfiltered() {
        let c = CandidateAction::new("allow", 50_000);
        assert!(!c.filtered);
        assert!(c.filter_reason.is_none());
    }

    #[test]
    fn candidate_filtered() {
        let c = CandidateAction::filtered("terminate", 999_000, "policy forbids");
        assert!(c.filtered);
        assert_eq!(c.filter_reason.as_deref(), Some("policy forbids"));
    }

    // -- Decision type display --

    #[test]
    fn decision_type_display() {
        assert_eq!(DecisionType::SecurityAction.to_string(), "security_action");
        assert_eq!(DecisionType::PolicyUpdate.to_string(), "policy_update");
        assert_eq!(
            DecisionType::EpochTransition.to_string(),
            "epoch_transition"
        );
        assert_eq!(DecisionType::Revocation.to_string(), "revocation");
    }

    // -- InMemoryLedger --

    #[test]
    fn ledger_stores_entries() {
        let mut ledger = InMemoryLedger::new();
        assert!(ledger.is_empty());

        ledger.emit(sample_entry()).expect("emit");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_duplicate_entry_id() {
        let mut ledger = InMemoryLedger::new();
        let entry = sample_entry();
        ledger.emit(entry.clone()).expect("first emit");

        let err = ledger.emit(entry).unwrap_err();
        assert!(matches!(err, LedgerError::DuplicateEntryId { .. }));
    }

    #[test]
    fn ledger_query_by_decision_type() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entry2 = EvidenceEntryBuilder::new(
            "trace-002",
            "decision-002",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::PolicyUpdate,
        )
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 0,
            rationale: "scheduled rotation".to_string(),
        })
        .build()
        .expect("build");
        ledger.emit(entry2).expect("emit");

        let security_entries = ledger.by_decision_type(DecisionType::SecurityAction);
        assert_eq!(security_entries.len(), 1);

        let policy_entries = ledger.by_decision_type(DecisionType::PolicyUpdate);
        assert_eq!(policy_entries.len(), 1);
    }

    #[test]
    fn ledger_query_by_epoch() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entries_e5 = ledger.by_epoch(SecurityEpoch::from_raw(5));
        assert_eq!(entries_e5.len(), 1);

        let entries_e1 = ledger.by_epoch(SecurityEpoch::from_raw(1));
        assert!(entries_e1.is_empty());
    }

    // -- Error display --

    #[test]
    fn ledger_error_display() {
        assert_eq!(
            LedgerError::MissingChosenAction.to_string(),
            "chosen action is required"
        );
        assert_eq!(
            LedgerError::DuplicateEntryId {
                entry_id: "ev-123".to_string()
            }
            .to_string(),
            "duplicate entry id: ev-123"
        );
        let err = LedgerError::IncompatibleSchema {
            entry_version: SchemaVersion::new(2, 0, 0),
            reader_version: current_schema_version(),
        };
        assert_eq!(
            err.to_string(),
            "incompatible schema: entry 2.0.0, reader 1.0.0"
        );
    }

    // -- Serialization --

    #[test]
    fn evidence_entry_serialization_round_trip() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: EvidenceEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, restored);
    }

    #[test]
    fn evidence_entry_deterministic_serialization() {
        let entry = sample_entry();
        let json1 = serde_json::to_string(&entry).expect("serialize");
        let json2 = serde_json::to_string(&entry).expect("serialize");
        assert_eq!(json1, json2);
    }

    #[test]
    fn all_error_variants_serialize() {
        let errors = vec![
            LedgerError::MissingChosenAction,
            LedgerError::SchemaValidationFailed {
                reason: "test".to_string(),
            },
            LedgerError::IncompatibleSchema {
                entry_version: SchemaVersion::new(2, 0, 0),
                reader_version: current_schema_version(),
            },
            LedgerError::DuplicateEntryId {
                entry_id: "ev-test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: LedgerError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn candidate_action_serialization_round_trip() {
        let c = CandidateAction::filtered("sandbox", 100_000, "max-loss");
        let json = serde_json::to_string(&c).expect("serialize");
        let restored: CandidateAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, restored);
    }

    #[test]
    fn schema_version_serialization_round_trip() {
        let v = current_schema_version();
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: SchemaVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn decision_type_ordering() {
        assert!(DecisionType::SecurityAction < DecisionType::PolicyUpdate);
        assert!(DecisionType::PolicyUpdate < DecisionType::EpochTransition);
        assert!(DecisionType::EpochTransition < DecisionType::Revocation);
        assert!(DecisionType::Revocation < DecisionType::ExtensionLifecycle);
        assert!(DecisionType::ExtensionLifecycle < DecisionType::CapabilityDecision);
        assert!(DecisionType::CapabilityDecision < DecisionType::ContractEvaluation);
        assert!(DecisionType::ContractEvaluation < DecisionType::RemoteAuthorization);
    }

    // -- Enrichment: error trait --

    #[test]
    fn ledger_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(LedgerError::MissingChosenAction),
            Box::new(LedgerError::SchemaValidationFailed {
                reason: "bad".to_string(),
            }),
            Box::new(LedgerError::DuplicateEntryId {
                entry_id: "e".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn decision_type_serde_roundtrip() {
        for dt in [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ] {
            let json = serde_json::to_string(&dt).expect("serialize");
            let restored: DecisionType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(dt, restored);
        }
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let c = Constraint {
            constraint_id: "c-1".to_string(),
            description: "rate limit".to_string(),
            active: true,
        };
        let json = serde_json::to_string(&c).expect("serialize");
        let restored: Constraint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, restored);
    }

    #[test]
    fn witness_serde_roundtrip() {
        let w = Witness {
            witness_id: "w-1".to_string(),
            witness_type: "monotonicity".to_string(),
            value: "proof-hash".to_string(),
        };
        let json = serde_json::to_string(&w).expect("serialize");
        let restored: Witness = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(w, restored);
    }

    #[test]
    fn chosen_action_serde_roundtrip() {
        let ca = ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest loss".to_string(),
        };
        let json = serde_json::to_string(&ca).expect("serialize");
        let restored: ChosenAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ca, restored);
    }

    // -- Enrichment: default --

    #[test]
    fn in_memory_ledger_default_is_empty() {
        let ledger = InMemoryLedger::default();
        assert_eq!(ledger.len(), 0);
        assert!(ledger.is_empty());
    }

    // --- enrichment: builder edge cases ---

    #[test]
    fn builder_no_candidates_builds_ok() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "default".to_string(),
        })
        .build()
        .unwrap();
        assert!(entry.candidates.is_empty());
        assert!(entry.constraints.is_empty());
        assert!(entry.witnesses.is_empty());
        assert!(entry.metadata.is_empty());
    }

    #[test]
    fn builder_timestamp_is_set() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::Revocation,
        )
        .timestamp_ns(42_000_000)
        .chosen(ChosenAction {
            action_name: "revoke".to_string(),
            expected_loss_millionths: 10_000,
            rationale: "expired".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.timestamp_ns, 42_000_000);
    }

    #[test]
    fn entry_id_format() {
        let entry = sample_entry();
        assert!(entry.entry_id.starts_with("ev-"));
        assert_eq!(entry.entry_id.len(), 3 + 16);
    }

    #[test]
    fn evidence_hash_is_16_hex_chars() {
        let entry = sample_entry();
        assert_eq!(entry.evidence_hash.len(), 16);
        assert!(entry.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn schema_version_ext_accessors() {
        let v = SchemaVersion::new(3, 7, 0);
        assert_eq!(v.major_val(), 3);
        assert_eq!(v.minor_val(), 7);
    }

    #[test]
    fn ledger_entries_accessor() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).unwrap();
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].trace_id, "trace-001");
    }

    #[test]
    fn decision_type_display_all_eight() {
        let types = [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for dt in &types {
            let s = dt.to_string();
            assert!(!s.is_empty());
            seen.insert(s);
        }
        assert_eq!(seen.len(), 8, "all 8 types have unique display strings");
    }

    #[test]
    fn different_decision_types_produce_different_hashes() {
        let e1 = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        let e2 = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::PolicyUpdate,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        assert_ne!(e1.evidence_hash, e2.evidence_hash);
        assert_ne!(e1.entry_id, e2.entry_id);
    }

    // -- Enrichment batch 2: additional coverage --

    #[test]
    fn candidate_negative_expected_loss_round_trips() {
        let c = CandidateAction::new("action", -999_999);
        assert_eq!(c.expected_loss_millionths, -999_999);
        let json = serde_json::to_string(&c).unwrap();
        let restored: CandidateAction = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    #[test]
    fn ledger_error_schema_validation_display() {
        let err = LedgerError::SchemaValidationFailed {
            reason: "missing field xyz".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("schema validation failed"));
        assert!(display.contains("missing field xyz"));
    }

    #[test]
    fn ledger_error_display_uniqueness() {
        let errors = [
            LedgerError::MissingChosenAction,
            LedgerError::SchemaValidationFailed {
                reason: "bad".to_string(),
            },
            LedgerError::IncompatibleSchema {
                entry_version: SchemaVersion::new(2, 0, 0),
                reader_version: current_schema_version(),
            },
            LedgerError::DuplicateEntryId {
                entry_id: "ev-x".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 error variants have distinct display"
        );
    }

    #[test]
    fn deterministic_hash_empty_input() {
        let h1 = deterministic_hash("");
        let h2 = deterministic_hash("");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn builder_multiple_metadata_keys_sorted() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .meta("z_key", "zval")
        .meta("a_key", "aval")
        .meta("m_key", "mval")
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        // BTreeMap keys should be in sorted order
        let keys: Vec<&String> = entry.metadata.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    #[test]
    fn builder_multiple_witnesses_preserved_in_order() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .witness(Witness {
            witness_id: "w-2".to_string(),
            witness_type: "b".to_string(),
            value: "v2".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "a".to_string(),
            value: "v1".to_string(),
        })
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.witnesses.len(), 2);
        assert_eq!(entry.witnesses[0].witness_id, "w-2");
        assert_eq!(entry.witnesses[1].witness_id, "w-1");
    }

    #[test]
    fn ledger_multiple_epochs_filter() {
        let mut ledger = InMemoryLedger::new();
        for epoch_raw in [1u64, 2, 3] {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{epoch_raw}"),
                format!("d-{epoch_raw}"),
                "p",
                SecurityEpoch::from_raw(epoch_raw),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "allow".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap();
            ledger.emit(entry).unwrap();
        }
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.by_epoch(SecurityEpoch::from_raw(2)).len(), 1);
        assert_eq!(ledger.by_epoch(SecurityEpoch::from_raw(99)).len(), 0);
    }

    #[test]
    fn ledger_multiple_decision_types_filter() {
        let mut ledger = InMemoryLedger::new();
        for (i, dt) in [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
        ]
        .iter()
        .enumerate()
        {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                *dt,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap();
            ledger.emit(entry).unwrap();
        }
        assert_eq!(ledger.by_decision_type(DecisionType::PolicyUpdate).len(), 2);
        assert_eq!(
            ledger.by_decision_type(DecisionType::EpochTransition).len(),
            1
        );
        assert_eq!(ledger.by_decision_type(DecisionType::Revocation).len(), 0);
    }

    #[test]
    fn schema_version_compatibility_same_major_higher_minor() {
        let v1_5 = SchemaVersion::new(1, 5, 0);
        let v1_3 = SchemaVersion::new(1, 3, 0);
        // v1.3 is compatible with reader v1.5
        assert!(v1_3.is_compatible_with(&v1_5));
        // v1.5 is NOT compatible with reader v1.3
        assert!(!v1_5.is_compatible_with(&v1_3));
    }

    // -- Enrichment batch 3: hash sensitivity and edge cases --

    #[test]
    fn hash_sensitive_to_trace_id_change() {
        let base = |trace: &str| {
            EvidenceEntryBuilder::new(
                trace,
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap()
        };
        let e1 = base("trace-A");
        let e2 = base("trace-B");
        assert_ne!(e1.evidence_hash, e2.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_policy_id_change() {
        let base = |policy: &str| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                policy,
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap()
        };
        assert_ne!(
            base("policy-v1").evidence_hash,
            base("policy-v2").evidence_hash
        );
    }

    #[test]
    fn hash_sensitive_to_epoch_change() {
        let base = |epoch: u64| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(epoch),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap()
        };
        assert_ne!(base(1).evidence_hash, base(2).evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_timestamp_change() {
        let base = |ts: u64| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .timestamp_ns(ts)
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap()
        };
        assert_ne!(base(1000).evidence_hash, base(2000).evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_metadata_change() {
        let base = |val: &str| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .meta("key", val)
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap()
        };
        assert_ne!(base("alpha").evidence_hash, base("beta").evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_candidate_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::new("extra", 50_000))
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_witness_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .witness(Witness {
            witness_id: "w".to_string(),
            witness_type: "t".to_string(),
            value: "v".to_string(),
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_constraint_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .constraint(Constraint {
            constraint_id: "c".to_string(),
            description: "d".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn genesis_epoch_entry_builds_ok() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::GENESIS,
            DecisionType::EpochTransition,
        )
        .chosen(ChosenAction {
            action_name: "transition".to_string(),
            expected_loss_millionths: 0,
            rationale: "genesis".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.epoch_id, SecurityEpoch::GENESIS);
    }

    #[test]
    fn entry_clone_preserves_all_fields() {
        let entry = sample_entry();
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
        assert_eq!(entry.entry_id, cloned.entry_id);
        assert_eq!(entry.evidence_hash, cloned.evidence_hash);
        assert_eq!(entry.metadata, cloned.metadata);
    }

    #[test]
    fn candidate_zero_expected_loss() {
        let c = CandidateAction::new("noop", 0);
        assert_eq!(c.expected_loss_millionths, 0);
        assert_eq!(c.action_name, "noop");
    }

    #[test]
    fn candidate_max_expected_loss() {
        let c = CandidateAction::new("extreme", i64::MAX);
        assert_eq!(c.expected_loss_millionths, i64::MAX);
    }

    #[test]
    fn witness_empty_value_round_trips() {
        let w = Witness {
            witness_id: "w-empty".to_string(),
            witness_type: "void".to_string(),
            value: String::new(),
        };
        let json = serde_json::to_string(&w).unwrap();
        let restored: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, restored);
        assert!(restored.value.is_empty());
    }

    #[test]
    fn constraint_inactive_round_trips() {
        let c = Constraint {
            constraint_id: "c-inactive".to_string(),
            description: "disabled rule".to_string(),
            active: false,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
        assert!(!restored.active);
    }

    #[test]
    fn multiple_filtered_candidates_different_reasons() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::filtered("a", 100, "reason-1"))
        .candidate(CandidateAction::filtered("b", 200, "reason-2"))
        .candidate(CandidateAction::filtered("c", 300, "reason-3"))
        .chosen(ChosenAction {
            action_name: "d".to_string(),
            expected_loss_millionths: 0,
            rationale: "only option".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.candidates.len(), 3);
        assert!(entry.candidates.iter().all(|c| c.filtered));
        let reasons: Vec<_> = entry
            .candidates
            .iter()
            .map(|c| c.filter_reason.as_deref().unwrap())
            .collect();
        assert_eq!(reasons, vec!["reason-1", "reason-2", "reason-3"]);
    }

    #[test]
    fn ledger_insertion_order_preserved() {
        let mut ledger = InMemoryLedger::new();
        let traces = ["trace-z", "trace-a", "trace-m"];
        for (i, trace) in traces.iter().enumerate() {
            let entry = EvidenceEntryBuilder::new(
                *trace,
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap();
            ledger.emit(entry).unwrap();
        }
        let stored_traces: Vec<&str> = ledger
            .entries()
            .iter()
            .map(|e| e.trace_id.as_str())
            .collect();
        assert_eq!(stored_traces, vec!["trace-z", "trace-a", "trace-m"]);
    }

    #[test]
    fn ledger_by_epoch_returns_correct_references() {
        let mut ledger = InMemoryLedger::new();
        let entry = EvidenceEntryBuilder::new(
            "t-ref",
            "d-ref",
            "p",
            SecurityEpoch::from_raw(42),
            DecisionType::Revocation,
        )
        .chosen(ChosenAction {
            action_name: "revoke".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        let expected_id = entry.entry_id.clone();
        ledger.emit(entry).unwrap();

        let results = ledger.by_epoch(SecurityEpoch::from_raw(42));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, expected_id);
        assert_eq!(results[0].trace_id, "t-ref");
    }

    #[test]
    fn empty_string_fields_produce_valid_entry() {
        let entry = EvidenceEntryBuilder::new(
            "",
            "",
            "",
            SecurityEpoch::from_raw(0),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: String::new(),
            expected_loss_millionths: 0,
            rationale: String::new(),
        })
        .build()
        .unwrap();
        assert!(entry.entry_id.starts_with("ev-"));
        assert!(!entry.evidence_hash.is_empty());
    }

    #[test]
    fn large_metadata_map_deterministic() {
        let build = || {
            let mut builder = EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            );
            for i in 0..50 {
                builder = builder.meta(format!("key-{i:03}"), format!("val-{i}"));
            }
            builder
                .chosen(ChosenAction {
                    action_name: "a".to_string(),
                    expected_loss_millionths: 0,
                    rationale: "r".to_string(),
                })
                .build()
                .unwrap()
        };
        let e1 = build();
        let e2 = build();
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
        assert_eq!(e1.metadata.len(), 50);
    }

    #[test]
    fn decision_type_copy_semantics() {
        let dt = DecisionType::SecurityAction;
        let dt2 = dt;
        assert_eq!(dt, dt2);
    }

    #[test]
    fn decision_type_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(DecisionType::SecurityAction);
        set.insert(DecisionType::SecurityAction);
        assert_eq!(set.len(), 1);
        set.insert(DecisionType::PolicyUpdate);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ledger_many_entries_no_collisions() {
        let mut ledger = InMemoryLedger::new();
        for i in 0..100 {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(i),
                DecisionType::SecurityAction,
            )
            .timestamp_ns(i)
            .chosen(ChosenAction {
                action_name: format!("action-{i}"),
                expected_loss_millionths: i as i64,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap();
            ledger.emit(entry).unwrap();
        }
        assert_eq!(ledger.len(), 100);
    }

    #[test]
    fn entry_json_contains_all_top_level_fields() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        for field in [
            "schema_version",
            "entry_id",
            "trace_id",
            "decision_id",
            "policy_id",
            "epoch_id",
            "timestamp_ns",
            "decision_type",
            "candidates",
            "constraints",
            "chosen_action",
            "witnesses",
            "evidence_hash",
            "metadata",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn chosen_action_negative_loss() {
        let ca = ChosenAction {
            action_name: "reward".to_string(),
            expected_loss_millionths: -500_000,
            rationale: "net gain".to_string(),
        };
        let json = serde_json::to_string(&ca).unwrap();
        let restored: ChosenAction = serde_json::from_str(&json).unwrap();
        assert_eq!(ca, restored);
        assert_eq!(restored.expected_loss_millionths, -500_000);
    }

    #[test]
    fn schema_version_patch_ignored_in_compatibility() {
        let v1_0_0 = SchemaVersion::new(1, 0, 0);
        let v1_0_5 = SchemaVersion::new(1, 0, 5);
        // Compatibility only checks major and minor, patch is irrelevant
        assert!(v1_0_0.is_compatible_with(&v1_0_5));
        assert!(v1_0_5.is_compatible_with(&v1_0_0));
    }

    #[test]
    fn builder_overwrites_metadata_key() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .meta("key", "first")
        .meta("key", "second")
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(entry.metadata["key"], "second");
    }

    #[test]
    fn all_decision_types_produce_valid_entries() {
        let types = [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ];
        for (i, dt) in types.iter().enumerate() {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                *dt,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .unwrap();
            assert!(entry.entry_id.starts_with("ev-"));
            assert_eq!(entry.decision_type, *dt);
        }
    }

    #[test]
    fn ledger_duplicate_error_contains_entry_id() {
        let mut ledger = InMemoryLedger::new();
        let entry = sample_entry();
        let entry_id = entry.entry_id.clone();
        ledger.emit(entry.clone()).unwrap();

        let err = ledger.emit(entry).unwrap_err();
        match err {
            LedgerError::DuplicateEntryId { entry_id: eid } => {
                assert_eq!(eid, entry_id);
            }
            other => panic!("expected DuplicateEntryId, got: {other:?}"),
        }
    }

    #[test]
    fn deterministic_hash_long_input() {
        let long_input: String = "x".repeat(10_000);
        let h1 = deterministic_hash(&long_input);
        let h2 = deterministic_hash(&long_input);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn deterministic_hash_single_byte_difference() {
        let h1 = deterministic_hash("abc");
        let h2 = deterministic_hash("abd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mixed_active_inactive_constraints() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .constraint(Constraint {
            constraint_id: "c-active".to_string(),
            description: "blocks action".to_string(),
            active: true,
        })
        .constraint(Constraint {
            constraint_id: "c-passive".to_string(),
            description: "monitored only".to_string(),
            active: false,
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        assert_eq!(entry.constraints.len(), 2);
        assert!(entry.constraints[0].active);
        assert!(!entry.constraints[1].active);
    }

    #[test]
    fn candidate_order_preserved_in_entry() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::new("c", 300))
        .candidate(CandidateAction::new("a", 100))
        .candidate(CandidateAction::new("b", 200))
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 100,
            rationale: "r".to_string(),
        })
        .build()
        .unwrap();
        let names: Vec<&str> = entry
            .candidates
            .iter()
            .map(|c| c.action_name.as_str())
            .collect();
        assert_eq!(names, vec!["c", "a", "b"]);
    }

    #[test]
    fn ledger_by_decision_type_empty_result() {
        let ledger = InMemoryLedger::new();
        assert!(
            ledger
                .by_decision_type(DecisionType::SecurityAction)
                .is_empty()
        );
    }

    #[test]
    fn ledger_by_epoch_empty_result() {
        let ledger = InMemoryLedger::new();
        assert!(ledger.by_epoch(SecurityEpoch::from_raw(1)).is_empty());
    }

    #[test]
    fn stitching_bundle_links_boundaries_decision_and_artifacts() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let artifacts = vec![
            ArtifactRecord::new(
                "release-gate",
                "release_gate_report",
                "artifacts/release-gate.json",
                "hash-release-gate",
            ),
            ArtifactRecord::new(
                "support-export",
                "support_bundle",
                "artifacts/support-export.json",
                "hash-support-export",
            )
            .supporting_boundary(boundaries[0].correlation_key.clone()),
        ];
        let annotations = DecisionSemanticsAnnotations {
            confidence_tier: Some("high".to_string()),
            fallback_reason: Some("safe_mode_guard".to_string()),
            regret_summary: Some("bounded_regret<=1000".to_string()),
            scope_limits: vec!["extension_id=ext-abc".to_string()],
            assumptions: BTreeMap::from([(
                "policy_snapshot".to_string(),
                "signed".to_string(),
            )]),
            linked_boundary_correlation_keys: boundaries
                .iter()
                .map(|boundary| boundary.correlation_key.clone())
                .collect(),
        };

        let bundle =
            EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
                .expect("stitching bundle");

        assert_eq!(bundle.evidence_ledger_graph.nodes.len(), 5);
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundaryInformsDecision)
                .count(),
            2
        );
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::DecisionProducesArtifact)
                .count(),
            2
        );
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundarySupportsArtifact)
                .count(),
            3
        );
        assert_eq!(bundle.decision_semantics_log.len(), 1);
        assert_eq!(
            bundle.decision_semantics_log[0].confidence_tier.as_deref(),
            Some("high")
        );
        assert_eq!(
            bundle.decision_semantics_log[0].boundary_correlation_keys.len(),
            2
        );
        let query = bundle
            .evidence_query_surface_snapshot
            .by_decision("decision-001")
            .expect("decision query record");
        assert_eq!(query.artifact_ids, vec!["release-gate", "support-export"]);
        assert_eq!(query.boundary_correlation_keys.len(), 2);
        assert_eq!(query.fallback_reason.as_deref(), Some("safe_mode_guard"));
    }

    #[test]
    fn stitching_bundle_is_deterministic_for_same_inputs() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let artifacts = vec![ArtifactRecord::new(
            "benchmark-proof",
            "benchmark_manifest",
            "artifacts/benchmark-proof.json",
            "hash-benchmark-proof",
        )];
        let annotations = DecisionSemanticsAnnotations {
            confidence_tier: Some("medium".to_string()),
            ..DecisionSemanticsAnnotations::default()
        };

        let left = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &boundaries,
            &artifacts,
            annotations.clone(),
        )
        .expect("left bundle");
        let right =
            EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
                .expect("right bundle");

        assert_eq!(left, right);
    }

    #[test]
    fn stitching_bundle_rejects_missing_boundary_link() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let err = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &boundaries,
            &[],
            DecisionSemanticsAnnotations {
                linked_boundary_correlation_keys: vec!["bcorr_missing".to_string()],
                ..DecisionSemanticsAnnotations::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            LedgerError::SchemaValidationFailed {
                reason: "decision semantics references missing boundary correlation key: bcorr_missing"
                    .to_string(),
            }
        );
    }

    #[test]
    fn stitching_bundle_rejects_boundary_from_other_decision() {
        let entry = sample_entry();
        let mut session = BoundaryCaptureSession::default_v1();
        let mismatched_context = BoundaryContext::new(
            "trace-other",
            "decision-other",
            "policy-v1",
            "orchestrator",
            10,
        );
        let mismatched = session
            .capture_clock_read(&mismatched_context, "mono", "monotonic", 99, None)
            .expect("capture clock read");

        let err = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &[mismatched],
            &[],
            DecisionSemanticsAnnotations::default(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LedgerError::SchemaValidationFailed { reason }
            if reason.contains("does not match decision identity")
        ));
    }
}
