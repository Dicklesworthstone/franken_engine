//! Runtime explanation bundle index.
//!
//! This module deliberately indexes existing runtime artifacts by stable
//! reference and [`ContentHash`]. It does not own a second truth model for
//! parser events, IR modules, guardplane decisions, IFC decisions, evidence
//! entries, replay results, or counterfactual reports. Callers provide the
//! actual artifact catalog; validation resolves the bundle against that
//! catalog and reports missing or stale links fail-closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

/// Current runtime explanation bundle schema.
pub const RUNTIME_EXPLAIN_BUNDLE_SCHEMA_VERSION: RuntimeExplainBundleSchemaVersion =
    RuntimeExplainBundleSchemaVersion { major: 1, minor: 0 };

/// Semantic version for the explain bundle index format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeExplainBundleSchemaVersion {
    pub major: u32,
    pub minor: u32,
}

impl RuntimeExplainBundleSchemaVersion {
    /// Compatible if the major version matches and the reader is at least as
    /// new as the bundle minor version.
    pub fn is_compatible_with(self, bundle_version: Self) -> bool {
        self.major == bundle_version.major && self.minor >= bundle_version.minor
    }
}

impl fmt::Display for RuntimeExplainBundleSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Category of an artifact referenced by a runtime explanation bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactKind {
    ParseEventIrHash,
    Ir0Module,
    Ir1Module,
    Ir2Module,
    Ir3ExecIr,
    CapabilityRequest,
    CapabilityGrant,
    IfcDecision,
    GuardplanePosterior,
    EProcessState,
    ExpectedLoss,
    ChosenAction,
    ContainmentReceipt,
    EvidenceEntry,
    ReplayStatus,
    CounterfactualStatus,
    Other { schema_id: String },
}

impl RuntimeArtifactKind {
    /// Default schema identifier used when callers do not supply a more
    /// specific existing schema/version.
    pub fn default_schema_id(&self) -> String {
        match self {
            Self::ParseEventIrHash => "franken-engine.parser-event-ir-hash.v1",
            Self::Ir0Module => "franken-engine.ir0-module.v1",
            Self::Ir1Module => "franken-engine.ir1-module.v1",
            Self::Ir2Module => "franken-engine.ir2-module.v1",
            Self::Ir3ExecIr => "franken-engine.ir3-exec-ir.v1",
            Self::CapabilityRequest => "franken-engine.capability-request.v1",
            Self::CapabilityGrant => "franken-engine.capability-grant.v1",
            Self::IfcDecision => "franken-engine.ifc-decision.v1",
            Self::GuardplanePosterior => "franken-engine.guardplane-posterior.v1",
            Self::EProcessState => "franken-engine.eprocess-state.v1",
            Self::ExpectedLoss => "franken-engine.expected-loss.v1",
            Self::ChosenAction => "franken-engine.chosen-action.v1",
            Self::ContainmentReceipt => "franken-engine.containment-receipt.v1",
            Self::EvidenceEntry => "franken-engine.evidence-entry.v1",
            Self::ReplayStatus => "franken-engine.replay-status.v1",
            Self::CounterfactualStatus => "franken-engine.counterfactual-status.v1",
            Self::Other { schema_id } => schema_id.as_str(),
        }
        .to_string()
    }
}

impl fmt::Display for RuntimeArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseEventIrHash => f.write_str("parse_event_ir_hash"),
            Self::Ir0Module => f.write_str("ir0_module"),
            Self::Ir1Module => f.write_str("ir1_module"),
            Self::Ir2Module => f.write_str("ir2_module"),
            Self::Ir3ExecIr => f.write_str("ir3_exec_ir"),
            Self::CapabilityRequest => f.write_str("capability_request"),
            Self::CapabilityGrant => f.write_str("capability_grant"),
            Self::IfcDecision => f.write_str("ifc_decision"),
            Self::GuardplanePosterior => f.write_str("guardplane_posterior"),
            Self::EProcessState => f.write_str("eprocess_state"),
            Self::ExpectedLoss => f.write_str("expected_loss"),
            Self::ChosenAction => f.write_str("chosen_action"),
            Self::ContainmentReceipt => f.write_str("containment_receipt"),
            Self::EvidenceEntry => f.write_str("evidence_entry"),
            Self::ReplayStatus => f.write_str("replay_status"),
            Self::CounterfactualStatus => f.write_str("counterfactual_status"),
            Self::Other { schema_id } => write!(f, "other:{schema_id}"),
        }
    }
}

/// Role an artifact plays inside a runtime explanation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExplainRole {
    ParseEventIrHash,
    Ir0Hash,
    Ir1Hash,
    Ir2Hash,
    Ir3Hash,
    CapabilityRequest,
    CapabilityGrant,
    IfcDecision,
    GuardplanePosterior,
    EProcessState,
    ExpectedLoss,
    ChosenAction,
    ContainmentReceipt,
    EvidenceEntry,
    ReplayStatus,
    CounterfactualStatus,
}

impl fmt::Display for RuntimeExplainRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = match self {
            Self::ParseEventIrHash => "parse_event_ir_hash",
            Self::Ir0Hash => "ir0_hash",
            Self::Ir1Hash => "ir1_hash",
            Self::Ir2Hash => "ir2_hash",
            Self::Ir3Hash => "ir3_hash",
            Self::CapabilityRequest => "capability_request",
            Self::CapabilityGrant => "capability_grant",
            Self::IfcDecision => "ifc_decision",
            Self::GuardplanePosterior => "guardplane_posterior",
            Self::EProcessState => "eprocess_state",
            Self::ExpectedLoss => "expected_loss",
            Self::ChosenAction => "chosen_action",
            Self::ContainmentReceipt => "containment_receipt",
            Self::EvidenceEntry => "evidence_entry",
            Self::ReplayStatus => "replay_status",
            Self::CounterfactualStatus => "counterfactual_status",
        };
        f.write_str(role)
    }
}

/// Stable lookup key for an existing artifact in its owning store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StableArtifactRef {
    /// Store or subsystem namespace, for example `ir_contract`,
    /// `evidence_ledger`, or `counterfactual_replay_engine`.
    pub namespace: String,
    /// Stable key inside the namespace.
    pub key: String,
    /// Optional source revision, run id, or schema epoch for the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

impl StableArtifactRef {
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            revision: None,
        }
    }

    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = Some(revision.into());
        self
    }
}

impl fmt::Display for StableArtifactRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.revision {
            Some(revision) => write!(f, "{}:{}@{}", self.namespace, self.key, revision),
            None => write!(f, "{}:{}", self.namespace, self.key),
        }
    }
}

/// A content-addressed reference to an existing artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeArtifactRef {
    /// Bundle-local artifact id.
    pub artifact_id: String,
    /// Artifact category.
    pub kind: RuntimeArtifactKind,
    /// Existing schema id/version, not a replacement schema.
    pub schema_id: String,
    /// Existing stable reference in the artifact's owning store.
    pub stable_ref: StableArtifactRef,
    /// Content hash already owned by the source artifact.
    pub content_hash: ContentHash,
    /// Producer or subsystem that emitted the artifact.
    pub producer: String,
    /// Logical run/epoch/tick if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_epoch: Option<u64>,
    /// Explanation roles satisfied by this artifact.
    #[serde(default)]
    pub roles: BTreeSet<RuntimeExplainRole>,
    /// Deterministic, non-authoritative display metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl RuntimeArtifactRef {
    pub fn new(
        artifact_id: impl Into<String>,
        kind: RuntimeArtifactKind,
        content_hash: ContentHash,
        stable_ref: StableArtifactRef,
    ) -> Self {
        let schema_id = kind.default_schema_id();
        Self {
            artifact_id: artifact_id.into(),
            kind,
            schema_id,
            stable_ref,
            content_hash,
            producer: "unknown".to_string(),
            logical_epoch: None,
            roles: BTreeSet::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_schema_id(mut self, schema_id: impl Into<String>) -> Self {
        self.schema_id = schema_id.into();
        self
    }

    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = producer.into();
        self
    }

    pub fn with_logical_epoch(mut self, logical_epoch: u64) -> Self {
        self.logical_epoch = Some(logical_epoch);
        self
    }

    pub fn with_role(mut self, role: RuntimeExplainRole) -> Self {
        self.roles.insert(role);
        self
    }

    pub fn with_roles<I>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = RuntimeExplainRole>,
    {
        self.roles.extend(roles);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Directed relationship between two referenced artifacts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeExplainRelation {
    DerivedFrom,
    ObservedDuring,
    RequiresCapability,
    GrantsCapability,
    AppliesIfcDecision,
    UsesPosterior,
    UsesEProcessState,
    ScoresExpectedLoss,
    SelectsAction,
    ProducesContainment,
    EmitsEvidence,
    ReplayChecks,
    CounterfactualChecks,
    Custom(String),
}

impl fmt::Display for RuntimeExplainRelation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let relation = match self {
            Self::DerivedFrom => "derived_from",
            Self::ObservedDuring => "observed_during",
            Self::RequiresCapability => "requires_capability",
            Self::GrantsCapability => "grants_capability",
            Self::AppliesIfcDecision => "applies_ifc_decision",
            Self::UsesPosterior => "uses_posterior",
            Self::UsesEProcessState => "uses_eprocess_state",
            Self::ScoresExpectedLoss => "scores_expected_loss",
            Self::SelectsAction => "selects_action",
            Self::ProducesContainment => "produces_containment",
            Self::EmitsEvidence => "emits_evidence",
            Self::ReplayChecks => "replay_checks",
            Self::CounterfactualChecks => "counterfactual_checks",
            Self::Custom(relation) => return f.write_str(relation),
        };
        f.write_str(relation)
    }
}

/// A typed link between two artifacts in the explanation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExplainLink {
    pub link_id: String,
    pub from_artifact_id: String,
    pub to_artifact_id: String,
    pub relation: RuntimeExplainRelation,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl RuntimeExplainLink {
    pub fn new(
        link_id: impl Into<String>,
        from_artifact_id: impl Into<String>,
        to_artifact_id: impl Into<String>,
        relation: RuntimeExplainRelation,
    ) -> Self {
        Self {
            link_id: link_id.into(),
            from_artifact_id: from_artifact_id.into(),
            to_artifact_id: to_artifact_id.into(),
            relation,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Thin explanation bundle. The authoritative artifact payloads stay in their
/// original stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExplainBundle {
    pub schema_version: RuntimeExplainBundleSchemaVersion,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub required_roles: BTreeSet<RuntimeExplainRole>,
    pub artifacts: BTreeMap<String, RuntimeArtifactRef>,
    pub links: Vec<RuntimeExplainLink>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl RuntimeExplainBundle {
    /// Compute a deterministic content hash for the index itself.
    pub fn content_hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self)
            .expect("RuntimeExplainBundle derives Serialize over serializable fields");
        ContentHash::compute(&bytes)
    }

    /// Validate every role, artifact reference, and link against an existing
    /// catalog. Validation reports problems; it never creates synthetic
    /// artifacts to hide missing evidence.
    pub fn validate(&self, catalog: &RuntimeArtifactCatalog) -> RuntimeExplainValidationReport {
        let mut diagnostics = Vec::new();

        if self.artifacts.is_empty() {
            diagnostics.push(RuntimeExplainDiagnostic::EmptyBundle);
        }

        for role in &self.required_roles {
            if !self
                .artifacts
                .values()
                .any(|artifact| artifact.roles.contains(role))
            {
                diagnostics
                    .push(RuntimeExplainDiagnostic::MissingRequiredRole { role: role.clone() });
            }
        }

        for artifact in self.artifacts.values() {
            match catalog.get(&artifact.artifact_id) {
                Some(actual) => {
                    if actual.content_hash != artifact.content_hash {
                        diagnostics.push(RuntimeExplainDiagnostic::StaleArtifactHash {
                            artifact_id: artifact.artifact_id.clone(),
                            expected: artifact.content_hash,
                            actual: actual.content_hash,
                        });
                    }
                    if actual.stable_ref != artifact.stable_ref {
                        diagnostics.push(RuntimeExplainDiagnostic::StaleStableRef {
                            artifact_id: artifact.artifact_id.clone(),
                            expected: artifact.stable_ref.clone(),
                            actual: actual.stable_ref.clone(),
                        });
                    }
                    if actual.schema_id != artifact.schema_id {
                        diagnostics.push(RuntimeExplainDiagnostic::SchemaMismatch {
                            artifact_id: artifact.artifact_id.clone(),
                            expected: artifact.schema_id.clone(),
                            actual: actual.schema_id.clone(),
                        });
                    }
                }
                None => diagnostics.push(RuntimeExplainDiagnostic::MissingCatalogArtifact {
                    artifact_id: artifact.artifact_id.clone(),
                }),
            }
        }

        for link in &self.links {
            if !self.artifacts.contains_key(&link.from_artifact_id) {
                diagnostics.push(RuntimeExplainDiagnostic::MissingLinkEndpoint {
                    link_id: link.link_id.clone(),
                    endpoint: RuntimeExplainLinkEndpoint::From,
                    artifact_id: link.from_artifact_id.clone(),
                });
            }
            if !self.artifacts.contains_key(&link.to_artifact_id) {
                diagnostics.push(RuntimeExplainDiagnostic::MissingLinkEndpoint {
                    link_id: link.link_id.clone(),
                    endpoint: RuntimeExplainLinkEndpoint::To,
                    artifact_id: link.to_artifact_id.clone(),
                });
            }
        }

        RuntimeExplainValidationReport::new(self.artifacts.len(), diagnostics)
    }
}

/// Builder for assembling a runtime explanation index.
#[derive(Debug, Clone)]
pub struct RuntimeExplainBundleBuilder {
    run_id: String,
    source_revision: Option<String>,
    required_roles: BTreeSet<RuntimeExplainRole>,
    artifacts: BTreeMap<String, RuntimeArtifactRef>,
    links: Vec<RuntimeExplainLink>,
    metadata: BTreeMap<String, String>,
}

impl RuntimeExplainBundleBuilder {
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            source_revision: None,
            required_roles: BTreeSet::new(),
            artifacts: BTreeMap::new(),
            links: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_source_revision(mut self, source_revision: impl Into<String>) -> Self {
        self.source_revision = Some(source_revision.into());
        self
    }

    pub fn require_role(mut self, role: RuntimeExplainRole) -> Self {
        self.required_roles.insert(role);
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn add_artifact(
        mut self,
        artifact: RuntimeArtifactRef,
    ) -> Result<Self, RuntimeExplainBundleError> {
        let artifact_id = artifact.artifact_id.clone();
        if self
            .artifacts
            .insert(artifact_id.clone(), artifact)
            .is_some()
        {
            return Err(RuntimeExplainBundleError::DuplicateArtifactId { artifact_id });
        }
        Ok(self)
    }

    pub fn add_link(mut self, link: RuntimeExplainLink) -> Self {
        self.links.push(link);
        self
    }

    pub fn build(self) -> RuntimeExplainBundle {
        RuntimeExplainBundle {
            schema_version: RUNTIME_EXPLAIN_BUNDLE_SCHEMA_VERSION,
            run_id: self.run_id,
            source_revision: self.source_revision,
            required_roles: self.required_roles,
            artifacts: self.artifacts,
            links: self.links,
            metadata: self.metadata,
        }
    }
}

/// Existing artifact inventory used to validate a bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeArtifactCatalog {
    artifacts: BTreeMap<String, RuntimeArtifactRef>,
}

impl RuntimeArtifactCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_artifacts<I>(artifacts: I) -> Self
    where
        I: IntoIterator<Item = RuntimeArtifactRef>,
    {
        let mut catalog = Self::new();
        for artifact in artifacts {
            catalog.insert(artifact);
        }
        catalog
    }

    pub fn insert(&mut self, artifact: RuntimeArtifactRef) {
        self.artifacts
            .insert(artifact.artifact_id.clone(), artifact);
    }

    pub fn get(&self, artifact_id: &str) -> Option<&RuntimeArtifactRef> {
        self.artifacts.get(artifact_id)
    }

    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

/// Validation status for a runtime explanation bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeExplainValidationStatus {
    Valid,
    Invalid,
}

/// Endpoint side for link validation diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuntimeExplainLinkEndpoint {
    From,
    To,
}

/// Fail-closed validation diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeExplainDiagnostic {
    EmptyBundle,
    MissingRequiredRole {
        role: RuntimeExplainRole,
    },
    MissingCatalogArtifact {
        artifact_id: String,
    },
    StaleArtifactHash {
        artifact_id: String,
        expected: ContentHash,
        actual: ContentHash,
    },
    StaleStableRef {
        artifact_id: String,
        expected: StableArtifactRef,
        actual: StableArtifactRef,
    },
    SchemaMismatch {
        artifact_id: String,
        expected: String,
        actual: String,
    },
    MissingLinkEndpoint {
        link_id: String,
        endpoint: RuntimeExplainLinkEndpoint,
        artifact_id: String,
    },
}

/// Result of validating an explanation bundle against an artifact catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExplainValidationReport {
    pub status: RuntimeExplainValidationStatus,
    pub resolved_artifact_count: usize,
    pub diagnostics: Vec<RuntimeExplainDiagnostic>,
}

impl RuntimeExplainValidationReport {
    fn new(resolved_artifact_count: usize, diagnostics: Vec<RuntimeExplainDiagnostic>) -> Self {
        let status = if diagnostics.is_empty() {
            RuntimeExplainValidationStatus::Valid
        } else {
            RuntimeExplainValidationStatus::Invalid
        };
        Self {
            status,
            resolved_artifact_count,
            diagnostics,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.status == RuntimeExplainValidationStatus::Valid
    }
}

/// Builder-level errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeExplainBundleError {
    DuplicateArtifactId { artifact_id: String },
}

impl fmt::Display for RuntimeExplainBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateArtifactId { artifact_id } => {
                write!(f, "duplicate runtime explain artifact id: {artifact_id}")
            }
        }
    }
}

impl std::error::Error for RuntimeExplainBundleError {}
