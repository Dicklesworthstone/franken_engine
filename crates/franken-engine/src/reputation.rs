//! Secure extension reputation graph schema.
//!
//! Tracks provenance, behavioral evidence, revocation history, and trust
//! transitions for extensions in the ecosystem.  The graph enables
//! risk-informed decisions about extensions before they execute, reducing
//! first-time compromise windows.
//!
//! Trust levels follow monotonic degradation: automated processes can
//! only lower trust; upgrades require explicit operator action with
//! signed justification.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 17, 9H.8 (Secure Extension
//! Reputation Graph), success criterion 13.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// TrustLevel — extension trust classification
// ---------------------------------------------------------------------------

/// Trust level for an extension in the reputation graph.
///
/// Levels are ordered by trust: `Unknown` is lowest non-negative trust,
/// `Trusted` is highest.  `Suspicious`, `Compromised`, and `Revoked`
/// represent degraded states.
///
/// Monotonic degradation rule: trust can only decrease via automated
/// processes; upgrades require explicit operator action with signed
/// justification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// No trust history; extension is new to the graph.
    Unknown,
    /// Minimal trust; extension is under observation.
    Provisional,
    /// Sufficient positive evidence; normal operation allowed.
    Established,
    /// Strong positive track record; eligible for elevated privileges.
    Trusted,
    /// Anomalous behavior detected; under heightened monitoring.
    Suspicious,
    /// Integrity violation confirmed; restricted operation.
    Compromised,
    /// Revoked; execution forbidden.
    Revoked,
}

// Manual Ord: trust ordering must place degraded states BELOW positive
// states. Derived Ord would use discriminant order, placing Suspicious(4)
// above Trusted(3), which is semantically inverted for trust comparisons.
// Order: Revoked < Compromised < Suspicious < Unknown < Provisional < Established < Trusted
impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.trust_rank().cmp(&other.trust_rank())
    }
}

impl PartialOrd for TrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TrustLevel {
    /// All variants in definition order.
    pub const ALL: [Self; 7] = [
        Self::Unknown,
        Self::Provisional,
        Self::Established,
        Self::Trusted,
        Self::Suspicious,
        Self::Compromised,
        Self::Revoked,
    ];

    /// Numeric rank for Ord: higher = more trusted.
    /// Revoked(0) < Compromised(1) < Suspicious(2) < Unknown(3) <
    /// Provisional(4) < Established(5) < Trusted(6)
    fn trust_rank(self) -> u8 {
        match self {
            Self::Revoked => 0,
            Self::Compromised => 1,
            Self::Suspicious => 2,
            Self::Unknown => 3,
            Self::Provisional => 4,
            Self::Established => 5,
            Self::Trusted => 6,
        }
    }

    /// Whether this level represents a degraded (negative) state.
    pub fn is_degraded(self) -> bool {
        matches!(self, Self::Suspicious | Self::Compromised | Self::Revoked)
    }

    /// Whether automated transition to `target` is permitted.
    ///
    /// Automated processes may only degrade trust (move to a worse state).
    /// Upgrades from a degraded state require operator override.
    pub fn can_auto_transition_to(self, target: Self) -> bool {
        match (self, target) {
            // Same level is always fine.
            (a, b) if a == b => true,
            // From non-degraded to degraded is always auto-allowed.
            (_, t) if t.is_degraded() => true,
            // Upgrades within non-degraded tiers (unknown->provisional->established->trusted).
            (Self::Unknown, Self::Provisional | Self::Established | Self::Trusted) => true,
            (Self::Provisional, Self::Established | Self::Trusted) => true,
            (Self::Established, Self::Trusted) => true,
            // From degraded back to non-degraded requires operator override.
            _ => false,
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Unknown => "unknown",
            Self::Provisional => "provisional",
            Self::Established => "established",
            Self::Trusted => "trusted",
            Self::Suspicious => "suspicious",
            Self::Compromised => "compromised",
            Self::Revoked => "revoked",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

/// Extension node in the reputation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionNode {
    /// Unique extension identifier.
    pub extension_id: String,
    /// Package name (e.g., npm package name).
    pub package_name: String,
    /// Semantic version string.
    pub version: String,
    /// Publisher who created this extension.
    pub publisher_id: String,
    /// Hash of the extension manifest.
    pub manifest_hash: [u8; 32],
    /// Timestamp when first observed (monotonic nanoseconds).
    pub first_seen_ns: u64,
    /// Current trust level.
    pub current_trust_level: TrustLevel,
    /// Direct dependencies (extension IDs).
    pub dependencies: BTreeSet<String>,
}

/// Publisher node in the reputation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherNode {
    /// Unique publisher identifier.
    pub publisher_id: String,
    /// Identity attestation hash (e.g., key fingerprint).
    pub identity_attestation: [u8; 32],
    /// Number of extensions published.
    pub published_count: u64,
    /// Summary trust score (millionths, 0..=1_000_000).
    pub trust_score: i64,
    /// Timestamp of first publication.
    pub first_published_ns: u64,
}

/// Evidence node in the reputation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceNode {
    /// Unique evidence identifier.
    pub evidence_id: String,
    /// Type of evidence.
    pub evidence_type: EvidenceType,
    /// Source of the evidence.
    pub source: EvidenceSource,
    /// Timestamp (monotonic nanoseconds).
    pub timestamp_ns: u64,
    /// Content hash for dedup and verification.
    pub content_hash: [u8; 32],
    /// Linked decision IDs (for traceability).
    pub linked_decision_ids: Vec<String>,
    /// Security epoch under which evidence was collected.
    pub epoch: SecurityEpoch,
}

/// Type of evidence in the reputation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Behavioral observation from runtime monitoring.
    BehavioralObservation,
    /// Result from adversarial campaign testing.
    AdversarialCampaignResult,
    /// Fleet immune-system cross-node evidence.
    FleetEvidence,
    /// Incident record.
    IncidentRecord,
    /// External threat intelligence.
    ThreatIntelligence,
    /// Provenance attestation verification.
    ProvenanceAttestation,
    /// Operator manual assessment.
    OperatorAssessment,
}

/// Source of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Bayesian sentinel (10.5).
    BayesianSentinel,
    /// Adversarial campaign generator (bd-2onl).
    AdversarialCampaign,
    /// Fleet immune system (bd-du2).
    FleetImmuneSystem,
    /// Operator manual input.
    OperatorManual,
    /// External threat feed.
    ExternalThreatFeed,
    /// Build provenance system.
    BuildProvenance,
}

/// Incident node in the reputation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentNode {
    /// Unique incident identifier.
    pub incident_id: String,
    /// Severity level.
    pub severity: IncidentSeverity,
    /// Extensions affected by this incident.
    pub affected_extensions: BTreeSet<String>,
    /// Containment actions taken.
    pub containment_actions: Vec<String>,
    /// Resolution status.
    pub resolution_status: ResolutionStatus,
    /// Timestamp (monotonic nanoseconds).
    pub timestamp_ns: u64,
}

/// Incident severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IncidentSeverity {
    /// Low impact, advisory only.
    Low,
    /// Moderate impact, monitoring increased.
    Medium,
    /// Significant impact, containment required.
    High,
    /// Critical impact, immediate quarantine.
    Critical,
}

/// Incident resolution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResolutionStatus {
    /// Incident is active, investigation ongoing.
    Active,
    /// Incident contained, under monitoring.
    Contained,
    /// Incident resolved, root cause identified.
    Resolved,
    /// Incident dismissed as false positive.
    FalsePositive,
}

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

/// Edge types in the reputation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    /// Extension published by publisher.
    PublishedBy {
        extension_id: String,
        publisher_id: String,
    },
    /// Extension depends on another extension.
    DependsOn {
        dependent_id: String,
        dependency_id: String,
    },
    /// Version derived from a prior version.
    DerivedFrom {
        new_version_id: String,
        old_version_id: String,
    },
    /// Extension has behavioral observation evidence.
    ObservedBehavior {
        extension_id: String,
        evidence_id: String,
    },
    /// Extension revoked due to incident.
    RevokedBy {
        extension_id: String,
        incident_id: String,
    },
    /// Revocation propagated to dependent extension.
    RevocationPropagatedTo {
        source_extension_id: String,
        target_extension_id: String,
        incident_id: String,
    },
    /// Trust transition with evidence linkage.
    TrustTransitioned {
        extension_id: String,
        transition_id: String,
    },
}

// ---------------------------------------------------------------------------
// TrustTransition — audit record for trust-level changes
// ---------------------------------------------------------------------------

/// Audit record for a trust-level change.
///
/// Every trust transition is recorded immutably for forensic analysis
/// and counterfactual replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustTransition {
    /// Unique transition identifier.
    pub transition_id: String,
    /// Extension whose trust changed.
    pub extension_id: String,
    /// Previous trust level.
    pub old_level: TrustLevel,
    /// New trust level.
    pub new_level: TrustLevel,
    /// Evidence that triggered this transition.
    pub triggering_evidence_ids: Vec<String>,
    /// Policy version under which transition occurred.
    pub policy_version: u64,
    /// Whether this was an operator override (upgrade from degraded).
    pub operator_override: bool,
    /// Operator justification (required for upgrades from degraded).
    pub operator_justification: Option<String>,
    /// Timestamp (monotonic nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch at transition time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// ProvenanceRecord — supply-chain lineage
// ---------------------------------------------------------------------------

/// Supply-chain provenance record for an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Extension this provenance applies to.
    pub extension_id: String,
    /// Publisher identity attestation verified.
    pub publisher_verified: bool,
    /// Build provenance attested (e.g., Sigstore, npm provenance).
    pub build_attested: bool,
    /// Source of build attestation.
    pub attestation_source: Option<String>,
    /// Dependency tree depth.
    pub dependency_depth: u32,
    /// Whether any provenance gap exists.
    pub has_provenance_gap: bool,
    /// Description of provenance gaps (if any).
    pub gap_descriptions: Vec<String>,
}

// ---------------------------------------------------------------------------
// ReputationGraphError
// ---------------------------------------------------------------------------

/// Errors from reputation graph operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationGraphError {
    /// Extension not found in the graph.
    ExtensionNotFound { extension_id: String },
    /// Publisher not found in the graph.
    PublisherNotFound { publisher_id: String },
    /// Automated trust upgrade denied (requires operator override).
    AutoUpgradeDenied {
        extension_id: String,
        current: TrustLevel,
        attempted: TrustLevel,
    },
    /// Duplicate extension ID.
    DuplicateExtension { extension_id: String },
    /// Duplicate evidence ID.
    DuplicateEvidence { evidence_id: String },
    /// Circular dependency detected.
    CircularDependency {
        extension_id: String,
        dependency_chain: Vec<String>,
    },
}

impl fmt::Display for ReputationGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::PublisherNotFound { publisher_id } => {
                write!(f, "publisher not found: {publisher_id}")
            }
            Self::AutoUpgradeDenied {
                extension_id,
                current,
                attempted,
            } => write!(
                f,
                "automated trust upgrade denied for {extension_id}: {current} -> {attempted} requires operator override"
            ),
            Self::DuplicateExtension { extension_id } => {
                write!(f, "duplicate extension: {extension_id}")
            }
            Self::DuplicateEvidence { evidence_id } => {
                write!(f, "duplicate evidence: {evidence_id}")
            }
            Self::CircularDependency {
                extension_id,
                dependency_chain,
            } => write!(
                f,
                "circular dependency at {extension_id}: {}",
                dependency_chain.join(" -> ")
            ),
        }
    }
}

impl std::error::Error for ReputationGraphError {}

// ---------------------------------------------------------------------------
// TrustLookupResult — query result for trust queries
// ---------------------------------------------------------------------------

/// Result of a trust lookup query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustLookupResult {
    /// Extension ID queried.
    pub extension_id: String,
    /// Current trust level.
    pub current_trust_level: TrustLevel,
    /// Number of trust transitions in history.
    pub transition_count: usize,
    /// Most recent transition (if any).
    pub last_transition: Option<TrustTransition>,
    /// Number of evidence nodes linked.
    pub evidence_count: usize,
    /// Dependency risk score (millionths, 0..=1_000_000).
    /// Higher = riskier dependencies.
    pub dependency_risk_score: i64,
    /// Publisher trust score (millionths).
    pub publisher_trust_score: Option<i64>,
}

/// Revocation impact result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationImpact {
    /// Extensions directly affected.
    pub directly_affected: BTreeSet<String>,
    /// Extensions transitively affected via dependency chains.
    pub transitively_affected: BTreeSet<String>,
    /// Trust degradations applied.
    pub trust_degradations: Vec<TrustTransition>,
}

// ---------------------------------------------------------------------------
// ReputationGraph — the graph data structure
// ---------------------------------------------------------------------------

/// In-memory reputation graph for extension trust management.
///
/// Nodes and edges are stored in `BTreeMap` for deterministic iteration.
/// Trust transitions are recorded in an append-only log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationGraph {
    /// Extension nodes indexed by extension_id.
    extensions: BTreeMap<String, ExtensionNode>,
    /// Publisher nodes indexed by publisher_id.
    publishers: BTreeMap<String, PublisherNode>,
    /// Evidence nodes indexed by evidence_id.
    evidence: BTreeMap<String, EvidenceNode>,
    /// Incident nodes indexed by incident_id.
    incidents: BTreeMap<String, IncidentNode>,
    /// Provenance records indexed by extension_id.
    provenance: BTreeMap<String, ProvenanceRecord>,
    /// Edges linking nodes.
    edges: Vec<EdgeType>,
    /// Append-only trust transition log.
    trust_transitions: Vec<TrustTransition>,
    /// Extension → evidence mapping for queries.
    extension_evidence: BTreeMap<String, BTreeSet<String>>,
    /// Monotonic transition counter for ID generation.
    transition_counter: u64,
}

/// Input for operator-initiated trust-level overrides.
///
/// Bundles the parameters for `operator_trust_override` to stay within
/// the 7-argument clippy limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorOverrideInput {
    /// Extension whose trust is being overridden.
    pub extension_id: String,
    /// Target trust level.
    pub new_level: TrustLevel,
    /// Mandatory justification for the override.
    pub justification: String,
    /// Evidence IDs supporting the override.
    pub evidence_ids: Vec<String>,
    /// Policy version authorising the override.
    pub policy_version: u64,
    /// Security epoch of the override.
    pub epoch: SecurityEpoch,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

impl ReputationGraph {
    /// Create an empty reputation graph.
    pub fn new() -> Self {
        Self {
            extensions: BTreeMap::new(),
            publishers: BTreeMap::new(),
            evidence: BTreeMap::new(),
            incidents: BTreeMap::new(),
            provenance: BTreeMap::new(),
            edges: Vec::new(),
            trust_transitions: Vec::new(),
            extension_evidence: BTreeMap::new(),
            transition_counter: 0,
        }
    }

    // -- Node management --

    /// Register a new extension in the graph.
    pub fn register_extension(&mut self, node: ExtensionNode) -> Result<(), ReputationGraphError> {
        if self.extensions.contains_key(&node.extension_id) {
            return Err(ReputationGraphError::DuplicateExtension {
                extension_id: node.extension_id.clone(),
            });
        }
        let ext_id = node.extension_id.clone();
        let pub_id = node.publisher_id.clone();
        self.extensions.insert(ext_id.clone(), node);
        self.edges.push(EdgeType::PublishedBy {
            extension_id: ext_id,
            publisher_id: pub_id,
        });
        Ok(())
    }

    /// Register a new publisher in the graph.
    pub fn register_publisher(&mut self, node: PublisherNode) {
        self.publishers.insert(node.publisher_id.clone(), node);
    }

    /// Get an extension node by ID.
    pub fn get_extension(&self, extension_id: &str) -> Option<&ExtensionNode> {
        self.extensions.get(extension_id)
    }

    /// Get a publisher node by ID.
    pub fn get_publisher(&self, publisher_id: &str) -> Option<&PublisherNode> {
        self.publishers.get(publisher_id)
    }

    /// Number of extension nodes.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Number of evidence nodes.
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    // -- Evidence management --

    /// Add an evidence node and link it to an extension.
    pub fn add_evidence(
        &mut self,
        extension_id: &str,
        node: EvidenceNode,
    ) -> Result<(), ReputationGraphError> {
        if !self.extensions.contains_key(extension_id) {
            return Err(ReputationGraphError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            });
        }
        if self.evidence.contains_key(&node.evidence_id) {
            return Err(ReputationGraphError::DuplicateEvidence {
                evidence_id: node.evidence_id.clone(),
            });
        }

        let ev_id = node.evidence_id.clone();
        self.evidence.insert(ev_id.clone(), node);
        self.edges.push(EdgeType::ObservedBehavior {
            extension_id: extension_id.to_string(),
            evidence_id: ev_id.clone(),
        });
        self.extension_evidence
            .entry(extension_id.to_string())
            .or_default()
            .insert(ev_id);
        Ok(())
    }

    /// Add an incident node.
    pub fn add_incident(&mut self, node: IncidentNode) {
        let incident_id = node.incident_id.clone();
        for ext_id in &node.affected_extensions {
            self.edges.push(EdgeType::RevokedBy {
                extension_id: ext_id.clone(),
                incident_id: incident_id.clone(),
            });
        }
        self.incidents.insert(incident_id, node);
    }

    /// Set provenance record for an extension.
    pub fn set_provenance(&mut self, record: ProvenanceRecord) -> Result<(), ReputationGraphError> {
        if !self.extensions.contains_key(&record.extension_id) {
            return Err(ReputationGraphError::ExtensionNotFound {
                extension_id: record.extension_id.clone(),
            });
        }
        self.provenance.insert(record.extension_id.clone(), record);
        Ok(())
    }

    // -- Trust transitions --

    /// Transition an extension's trust level (automated).
    ///
    /// Enforces monotonic degradation: automated processes may only
    /// lower trust.  Returns error for disallowed upgrades.
    pub fn transition_trust(
        &mut self,
        extension_id: &str,
        new_level: TrustLevel,
        evidence_ids: Vec<String>,
        policy_version: u64,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> Result<TrustTransition, ReputationGraphError> {
        let ext = self.extensions.get(extension_id).ok_or_else(|| {
            ReputationGraphError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;

        let old_level = ext.current_trust_level;
        if !old_level.can_auto_transition_to(new_level) {
            return Err(ReputationGraphError::AutoUpgradeDenied {
                extension_id: extension_id.to_string(),
                current: old_level,
                attempted: new_level,
            });
        }

        self.transition_counter += 1;
        let transition = TrustTransition {
            transition_id: format!("tt-{:08}", self.transition_counter),
            extension_id: extension_id.to_string(),
            old_level,
            new_level,
            triggering_evidence_ids: evidence_ids,
            policy_version,
            operator_override: false,
            operator_justification: None,
            timestamp_ns,
            epoch,
        };

        // Update extension trust level.
        if let Some(ext) = self.extensions.get_mut(extension_id) {
            ext.current_trust_level = new_level;
        }

        self.edges.push(EdgeType::TrustTransitioned {
            extension_id: extension_id.to_string(),
            transition_id: transition.transition_id.clone(),
        });

        self.trust_transitions.push(transition.clone());
        Ok(transition)
    }

    /// Transition an extension's trust level with operator override.
    ///
    /// Allows upgrades from degraded states with mandatory justification.
    pub fn operator_trust_override(
        &mut self,
        input: OperatorOverrideInput,
    ) -> Result<TrustTransition, ReputationGraphError> {
        let old_level = self
            .extensions
            .get(&input.extension_id)
            .ok_or_else(|| ReputationGraphError::ExtensionNotFound {
                extension_id: input.extension_id.clone(),
            })?
            .current_trust_level;

        // Operator overrides require non-empty justification for audit trail.
        if input.justification.trim().is_empty() {
            return Err(ReputationGraphError::AutoUpgradeDenied {
                extension_id: input.extension_id.clone(),
                current: old_level,
                attempted: input.new_level,
            });
        }
        self.transition_counter = self.transition_counter.saturating_add(1);

        let transition = TrustTransition {
            transition_id: format!("tt-{:08}", self.transition_counter),
            extension_id: input.extension_id.clone(),
            old_level,
            new_level: input.new_level,
            triggering_evidence_ids: input.evidence_ids,
            policy_version: input.policy_version,
            operator_override: true,
            operator_justification: Some(input.justification),
            timestamp_ns: input.timestamp_ns,
            epoch: input.epoch,
        };

        if let Some(ext) = self.extensions.get_mut(&input.extension_id) {
            ext.current_trust_level = input.new_level;
        }

        self.edges.push(EdgeType::TrustTransitioned {
            extension_id: input.extension_id,
            transition_id: transition.transition_id.clone(),
        });

        self.trust_transitions.push(transition.clone());
        Ok(transition)
    }

    // -- Revocation propagation --

    /// Propagate revocation along dependency edges.
    ///
    /// When an extension is revoked, all extensions that depend on it
    /// have their trust degraded to at least `Suspicious`.  Returns
    /// the full impact assessment.
    pub fn propagate_revocation(
        &mut self,
        extension_id: &str,
        incident_id: &str,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> Result<RevocationImpact, ReputationGraphError> {
        if !self.extensions.contains_key(extension_id) {
            return Err(ReputationGraphError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            });
        }

        let mut directly_affected = BTreeSet::new();
        let mut transitively_affected = BTreeSet::new();
        let mut trust_degradations = Vec::new();

        // Find all extensions that directly depend on the revoked extension.
        let dependents: Vec<String> = self
            .extensions
            .iter()
            .filter(|(_, ext)| ext.dependencies.contains(extension_id))
            .map(|(id, _)| id.clone())
            .collect();

        for dep_id in &dependents {
            directly_affected.insert(dep_id.clone());
            self.edges.push(EdgeType::RevocationPropagatedTo {
                source_extension_id: extension_id.to_string(),
                target_extension_id: dep_id.clone(),
                incident_id: incident_id.to_string(),
            });

            // Degrade trust to at least Suspicious if currently better.
            if let Some(ext) = self.extensions.get(dep_id)
                && !ext.current_trust_level.is_degraded()
                && let Ok(tt) = self.transition_trust(
                    dep_id,
                    TrustLevel::Suspicious,
                    vec![format!("revocation-propagation:{incident_id}")],
                    0, // policy version 0 = system-generated
                    epoch,
                    timestamp_ns,
                )
            {
                trust_degradations.push(tt);
            }
        }

        // BFS for transitive dependents.
        let mut queue: Vec<String> = dependents;
        let mut visited = BTreeSet::new();
        visited.insert(extension_id.to_string());

        while let Some(current) = queue.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            let transitive_deps: Vec<String> = self
                .extensions
                .iter()
                .filter(|(_, ext)| ext.dependencies.contains(&current))
                .map(|(id, _)| id.clone())
                .collect();

            for td_id in transitive_deps {
                if !directly_affected.contains(&td_id) {
                    transitively_affected.insert(td_id.clone());

                    // Degrade trust for transitive dependents as well
                    if let Some(ext) = self.extensions.get(&td_id)
                        && !ext.current_trust_level.is_degraded()
                        && let Ok(tt) = self.transition_trust(
                            &td_id,
                            TrustLevel::Suspicious,
                            vec![format!("transitive-revocation-propagation:{incident_id}")],
                            0,
                            epoch,
                            timestamp_ns,
                        )
                    {
                        trust_degradations.push(tt);
                    }
                }
                queue.push(td_id);
            }
        }

        Ok(RevocationImpact {
            directly_affected,
            transitively_affected,
            trust_degradations,
        })
    }

    // -- Queries --

    /// Look up trust information for an extension.
    pub fn trust_lookup(
        &self,
        extension_id: &str,
    ) -> Result<TrustLookupResult, ReputationGraphError> {
        let ext = self.extensions.get(extension_id).ok_or_else(|| {
            ReputationGraphError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;

        let transitions: Vec<&TrustTransition> = self
            .trust_transitions
            .iter()
            .filter(|tt| tt.extension_id == extension_id)
            .collect();

        let evidence_count = self
            .extension_evidence
            .get(extension_id)
            .map_or(0, |s| s.len());

        let dep_risk = self.compute_dependency_risk(extension_id);

        let publisher_trust = self
            .publishers
            .get(&ext.publisher_id)
            .map(|p| p.trust_score);

        Ok(TrustLookupResult {
            extension_id: extension_id.to_string(),
            current_trust_level: ext.current_trust_level,
            transition_count: transitions.len(),
            last_transition: transitions.last().cloned().cloned(),
            evidence_count,
            dependency_risk_score: dep_risk,
            publisher_trust_score: publisher_trust,
        })
    }

    /// Compute dependency risk score for an extension (millionths).
    ///
    /// Risk increases with degraded dependencies.
    fn compute_dependency_risk(&self, extension_id: &str) -> i64 {
        let ext = match self.extensions.get(extension_id) {
            Some(e) => e,
            None => return 0,
        };

        if ext.dependencies.is_empty() {
            return 0;
        }

        let mut risk_sum: i64 = 0;
        let mut dep_count: i64 = 0;

        for dep_id in &ext.dependencies {
            dep_count += 1;
            if let Some(dep) = self.extensions.get(dep_id) {
                let dep_risk = match dep.current_trust_level {
                    TrustLevel::Revoked => 1_000_000,
                    TrustLevel::Compromised => 800_000,
                    TrustLevel::Suspicious => 500_000,
                    TrustLevel::Unknown => 300_000,
                    TrustLevel::Provisional => 150_000,
                    TrustLevel::Established => 50_000,
                    TrustLevel::Trusted => 0,
                };
                risk_sum = risk_sum.saturating_add(dep_risk);
            } else {
                // Unknown dependency = high risk.
                risk_sum = risk_sum.saturating_add(500_000);
            }
        }

        if dep_count == 0 {
            return 0;
        }
        risk_sum / dep_count
    }

    /// Get all trust transitions for an extension.
    pub fn trust_history(&self, extension_id: &str) -> Vec<&TrustTransition> {
        self.trust_transitions
            .iter()
            .filter(|tt| tt.extension_id == extension_id)
            .collect()
    }

    /// Get provenance record for an extension.
    pub fn get_provenance(&self, extension_id: &str) -> Option<&ProvenanceRecord> {
        self.provenance.get(extension_id)
    }

    /// Get total number of trust transitions recorded.
    pub fn total_transitions(&self) -> usize {
        self.trust_transitions.len()
    }

    /// Get total number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get all evidence nodes linked to an extension.
    pub fn get_evidence_for_extension(&self, extension_id: &str) -> Vec<&EvidenceNode> {
        let Some(ev_ids) = self.extension_evidence.get(extension_id) else {
            return Vec::new();
        };
        ev_ids
            .iter()
            .filter_map(|id| self.evidence.get(id))
            .collect()
    }

    /// Count incidents affecting an extension.
    pub fn incident_count_for_extension(&self, extension_id: &str) -> usize {
        self.incidents
            .values()
            .filter(|inc| inc.affected_extensions.contains(extension_id))
            .count()
    }
}

impl Default for ReputationGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn test_extension(id: &str, publisher: &str) -> ExtensionNode {
        ExtensionNode {
            extension_id: id.to_string(),
            package_name: format!("pkg-{id}"),
            version: "1.0.0".to_string(),
            publisher_id: publisher.to_string(),
            manifest_hash: [0u8; 32],
            first_seen_ns: 1_000_000_000,
            current_trust_level: TrustLevel::Unknown,
            dependencies: BTreeSet::new(),
        }
    }

    fn test_extension_with_deps(id: &str, publisher: &str, deps: &[&str]) -> ExtensionNode {
        let mut ext = test_extension(id, publisher);
        ext.dependencies = deps.iter().map(|d| d.to_string()).collect();
        ext
    }

    fn test_publisher(id: &str) -> PublisherNode {
        PublisherNode {
            publisher_id: id.to_string(),
            identity_attestation: [1u8; 32],
            published_count: 1,
            trust_score: 500_000,
            first_published_ns: 1_000_000_000,
        }
    }

    fn test_evidence(id: &str) -> EvidenceNode {
        EvidenceNode {
            evidence_id: id.to_string(),
            evidence_type: EvidenceType::BehavioralObservation,
            source: EvidenceSource::BayesianSentinel,
            timestamp_ns: 2_000_000_000,
            content_hash: [2u8; 32],
            linked_decision_ids: vec!["dec-1".to_string()],
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    // -- TrustLevel --

    #[test]
    fn trust_level_display() {
        assert_eq!(TrustLevel::Unknown.to_string(), "unknown");
        assert_eq!(TrustLevel::Trusted.to_string(), "trusted");
        assert_eq!(TrustLevel::Revoked.to_string(), "revoked");
    }

    #[test]
    fn trust_level_is_degraded() {
        assert!(!TrustLevel::Unknown.is_degraded());
        assert!(!TrustLevel::Provisional.is_degraded());
        assert!(!TrustLevel::Established.is_degraded());
        assert!(!TrustLevel::Trusted.is_degraded());
        assert!(TrustLevel::Suspicious.is_degraded());
        assert!(TrustLevel::Compromised.is_degraded());
        assert!(TrustLevel::Revoked.is_degraded());
    }

    #[test]
    fn trust_level_auto_transition_allowed_degradation() {
        // Any state can auto-transition to a degraded state.
        for &src in &TrustLevel::ALL {
            for &tgt in &[
                TrustLevel::Suspicious,
                TrustLevel::Compromised,
                TrustLevel::Revoked,
            ] {
                assert!(
                    src.can_auto_transition_to(tgt),
                    "{src} -> {tgt} should be auto-allowed"
                );
            }
        }
    }

    #[test]
    fn trust_level_auto_upgrade_within_non_degraded() {
        assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Provisional));
        assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Established));
        assert!(TrustLevel::Unknown.can_auto_transition_to(TrustLevel::Trusted));
        assert!(TrustLevel::Provisional.can_auto_transition_to(TrustLevel::Established));
        assert!(TrustLevel::Established.can_auto_transition_to(TrustLevel::Trusted));
    }

    #[test]
    fn trust_level_auto_upgrade_from_degraded_denied() {
        assert!(!TrustLevel::Suspicious.can_auto_transition_to(TrustLevel::Established));
        assert!(!TrustLevel::Compromised.can_auto_transition_to(TrustLevel::Provisional));
        assert!(!TrustLevel::Revoked.can_auto_transition_to(TrustLevel::Unknown));
    }

    #[test]
    fn trust_level_same_level_allowed() {
        for &level in &TrustLevel::ALL {
            assert!(
                level.can_auto_transition_to(level),
                "same-level transition should be allowed: {level}"
            );
        }
    }

    // -- ReputationGraph: node management --

    #[test]
    fn register_extension_success() {
        let mut graph = ReputationGraph::new();
        let ext = test_extension("ext-1", "pub-1");
        assert!(graph.register_extension(ext).is_ok());
        assert_eq!(graph.extension_count(), 1);
        assert!(graph.get_extension("ext-1").is_some());
    }

    #[test]
    fn register_duplicate_extension_fails() {
        let mut graph = ReputationGraph::new();
        let ext = test_extension("ext-1", "pub-1");
        graph.register_extension(ext).unwrap();
        let ext2 = test_extension("ext-1", "pub-1");
        assert!(matches!(
            graph.register_extension(ext2),
            Err(ReputationGraphError::DuplicateExtension { .. })
        ));
    }

    #[test]
    fn register_publisher() {
        let mut graph = ReputationGraph::new();
        let pub_node = test_publisher("pub-1");
        graph.register_publisher(pub_node);
        assert!(graph.get_publisher("pub-1").is_some());
    }

    // -- Evidence management --

    #[test]
    fn add_evidence_success() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        let ev = test_evidence("ev-1");
        assert!(graph.add_evidence("ext-1", ev).is_ok());
        assert_eq!(graph.evidence_count(), 1);
    }

    #[test]
    fn add_evidence_missing_extension_fails() {
        let mut graph = ReputationGraph::new();
        let ev = test_evidence("ev-1");
        assert!(matches!(
            graph.add_evidence("nonexistent", ev),
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    #[test]
    fn add_duplicate_evidence_fails() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
        assert!(matches!(
            graph.add_evidence("ext-1", test_evidence("ev-1")),
            Err(ReputationGraphError::DuplicateEvidence { .. })
        ));
    }

    // -- Trust transitions --

    #[test]
    fn auto_trust_degradation() {
        let mut graph = ReputationGraph::new();
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = TrustLevel::Established;
        graph.register_extension(ext).unwrap();

        let tt = graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                3_000_000_000,
            )
            .unwrap();

        assert_eq!(tt.old_level, TrustLevel::Established);
        assert_eq!(tt.new_level, TrustLevel::Suspicious);
        assert!(!tt.operator_override);
        assert_eq!(
            graph.get_extension("ext-1").unwrap().current_trust_level,
            TrustLevel::Suspicious
        );
    }

    #[test]
    fn auto_trust_upgrade_non_degraded() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();

        let tt = graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                3_000_000_000,
            )
            .unwrap();

        assert_eq!(tt.old_level, TrustLevel::Unknown);
        assert_eq!(tt.new_level, TrustLevel::Provisional);
    }

    #[test]
    fn auto_upgrade_from_degraded_denied() {
        let mut graph = ReputationGraph::new();
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = TrustLevel::Suspicious;
        graph.register_extension(ext).unwrap();

        assert!(matches!(
            graph.transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                3_000_000_000,
            ),
            Err(ReputationGraphError::AutoUpgradeDenied { .. })
        ));
    }

    #[test]
    fn operator_override_upgrade() {
        let mut graph = ReputationGraph::new();
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = TrustLevel::Compromised;
        graph.register_extension(ext).unwrap();

        let tt = graph
            .operator_trust_override(OperatorOverrideInput {
                extension_id: "ext-1".into(),
                new_level: TrustLevel::Provisional,
                justification: "Incident resolved, root cause fixed".into(),
                evidence_ids: vec!["ev-resolution".into()],
                policy_version: 2,
                epoch: SecurityEpoch::from_raw(2),
                timestamp_ns: 4_000_000_000,
            })
            .unwrap();

        assert!(tt.operator_override);
        assert_eq!(tt.old_level, TrustLevel::Compromised);
        assert_eq!(tt.new_level, TrustLevel::Provisional);
        assert!(tt.operator_justification.is_some());
        assert_eq!(
            graph.get_extension("ext-1").unwrap().current_trust_level,
            TrustLevel::Provisional
        );
    }

    #[test]
    fn operator_override_blank_justification_reports_actual_current_level() {
        let mut graph = ReputationGraph::new();
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = TrustLevel::Compromised;
        graph.register_extension(ext).unwrap();

        let err = graph
            .operator_trust_override(OperatorOverrideInput {
                extension_id: "ext-1".into(),
                new_level: TrustLevel::Provisional,
                justification: "   ".into(),
                evidence_ids: vec!["ev-resolution".into()],
                policy_version: 2,
                epoch: SecurityEpoch::from_raw(2),
                timestamp_ns: 4_000_000_000,
            })
            .expect_err("blank justification must be rejected");

        assert_eq!(
            err,
            ReputationGraphError::AutoUpgradeDenied {
                extension_id: "ext-1".into(),
                current: TrustLevel::Compromised,
                attempted: TrustLevel::Provisional,
            }
        );
        assert_eq!(
            graph.get_extension("ext-1").unwrap().current_trust_level,
            TrustLevel::Compromised
        );
    }

    // -- Revocation propagation --

    #[test]
    fn revocation_propagation_direct_dependents() {
        let mut graph = ReputationGraph::new();
        let ext_a = test_extension("ext-a", "pub-1");
        let ext_b = test_extension_with_deps("ext-b", "pub-1", &["ext-a"]);
        let ext_c = test_extension_with_deps("ext-c", "pub-1", &["ext-a"]);
        graph.register_extension(ext_a).unwrap();
        graph.register_extension(ext_b).unwrap();
        graph.register_extension(ext_c).unwrap();

        // Revoke ext-a.
        graph
            .transition_trust(
                "ext-a",
                TrustLevel::Revoked,
                vec!["incident-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let impact = graph
            .propagate_revocation(
                "ext-a",
                "incident-1",
                SecurityEpoch::from_raw(1),
                5_000_000_001,
            )
            .unwrap();

        assert!(impact.directly_affected.contains("ext-b"));
        assert!(impact.directly_affected.contains("ext-c"));
        assert_eq!(impact.directly_affected.len(), 2);
    }

    #[test]
    fn revocation_propagation_degrades_trust() {
        let mut graph = ReputationGraph::new();
        let ext_a = test_extension("ext-a", "pub-1");
        let mut ext_b = test_extension_with_deps("ext-b", "pub-1", &["ext-a"]);
        ext_b.current_trust_level = TrustLevel::Established;
        graph.register_extension(ext_a).unwrap();
        graph.register_extension(ext_b).unwrap();

        graph
            .propagate_revocation(
                "ext-a",
                "incident-1",
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        assert_eq!(
            graph.get_extension("ext-b").unwrap().current_trust_level,
            TrustLevel::Suspicious
        );
    }

    #[test]
    fn revocation_nonexistent_extension() {
        let mut graph = ReputationGraph::new();
        assert!(matches!(
            graph.propagate_revocation("nonexistent", "inc-1", SecurityEpoch::from_raw(1), 0,),
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    // -- Queries --

    #[test]
    fn trust_lookup_returns_correct_data() {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
        graph.add_evidence("ext-1", test_evidence("ev-2")).unwrap();

        let result = graph.trust_lookup("ext-1").unwrap();
        assert_eq!(result.current_trust_level, TrustLevel::Unknown);
        assert_eq!(result.evidence_count, 2);
        assert_eq!(result.transition_count, 0);
        assert_eq!(result.publisher_trust_score, Some(500_000));
    }

    #[test]
    fn trust_lookup_missing_extension() {
        let graph = ReputationGraph::new();
        assert!(matches!(
            graph.trust_lookup("nonexistent"),
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    #[test]
    fn trust_history_tracks_transitions() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();

        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                1_000,
            )
            .unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec!["ev-2".into()],
                1,
                SecurityEpoch::from_raw(1),
                2_000,
            )
            .unwrap();

        let history = graph.trust_history("ext-1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].old_level, TrustLevel::Unknown);
        assert_eq!(history[0].new_level, TrustLevel::Provisional);
        assert_eq!(history[1].old_level, TrustLevel::Provisional);
        assert_eq!(history[1].new_level, TrustLevel::Established);
    }

    #[test]
    fn dependency_risk_score_reflects_dep_trust() {
        let mut graph = ReputationGraph::new();
        let dep_a = test_extension("dep-a", "pub-1");
        let mut dep_b = test_extension("dep-b", "pub-1");
        dep_b.current_trust_level = TrustLevel::Suspicious;

        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-a", "dep-b"]);

        graph.register_extension(dep_a).unwrap();
        graph.register_extension(dep_b).unwrap();
        graph.register_extension(ext).unwrap();

        let result = graph.trust_lookup("ext-1").unwrap();
        // dep-a is Unknown (300_000), dep-b is Suspicious (500_000)
        // Average: (300_000 + 500_000) / 2 = 400_000
        assert_eq!(result.dependency_risk_score, 400_000);
    }

    #[test]
    fn dependency_risk_score_zero_for_no_deps() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        let result = graph.trust_lookup("ext-1").unwrap();
        assert_eq!(result.dependency_risk_score, 0);
    }

    // -- Provenance --

    #[test]
    fn set_and_get_provenance() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();

        let record = ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: true,
            attestation_source: Some("sigstore".into()),
            dependency_depth: 2,
            has_provenance_gap: false,
            gap_descriptions: vec![],
        };
        graph.set_provenance(record).unwrap();

        let prov = graph.get_provenance("ext-1").unwrap();
        assert!(prov.publisher_verified);
        assert!(prov.build_attested);
    }

    #[test]
    fn provenance_for_missing_extension_fails() {
        let mut graph = ReputationGraph::new();
        let record = ProvenanceRecord {
            extension_id: "nonexistent".into(),
            publisher_verified: false,
            build_attested: false,
            attestation_source: None,
            dependency_depth: 0,
            has_provenance_gap: true,
            gap_descriptions: vec!["unknown publisher".into()],
        };
        assert!(matches!(
            graph.set_provenance(record),
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    // -- Serialization --

    #[test]
    fn graph_serialization_round_trip() {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                1_000,
            )
            .unwrap();

        let json = serde_json::to_string(&graph).expect("serialize");
        let restored: ReputationGraph = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.extension_count(), 1);
        assert_eq!(restored.evidence_count(), 1);
        assert_eq!(restored.total_transitions(), 1);
    }

    #[test]
    fn trust_transition_serialization_round_trip() {
        let tt = TrustTransition {
            transition_id: "tt-00000001".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Established,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec!["ev-1".into(), "ev-2".into()],
            policy_version: 3,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(2),
        };
        let json = serde_json::to_string(&tt).expect("serialize");
        let restored: TrustTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tt, restored);
    }

    #[test]
    fn error_serialization_round_trip() {
        let errors = vec![
            ReputationGraphError::ExtensionNotFound {
                extension_id: "ext-1".into(),
            },
            ReputationGraphError::PublisherNotFound {
                publisher_id: "pub-1".into(),
            },
            ReputationGraphError::AutoUpgradeDenied {
                extension_id: "ext-1".into(),
                current: TrustLevel::Suspicious,
                attempted: TrustLevel::Established,
            },
            ReputationGraphError::DuplicateExtension {
                extension_id: "ext-1".into(),
            },
            ReputationGraphError::DuplicateEvidence {
                evidence_id: "ev-1".into(),
            },
            ReputationGraphError::CircularDependency {
                extension_id: "ext-a".into(),
                dependency_chain: vec!["ext-b".into(), "ext-a".into()],
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ReputationGraphError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            ReputationGraphError::ExtensionNotFound {
                extension_id: "ext-1".into()
            }
            .to_string(),
            "extension not found: ext-1"
        );
        assert!(
            ReputationGraphError::AutoUpgradeDenied {
                extension_id: "ext-1".into(),
                current: TrustLevel::Suspicious,
                attempted: TrustLevel::Established,
            }
            .to_string()
            .contains("operator override")
        );
    }

    // -- Determinism --

    #[test]
    fn deterministic_serialization() {
        let build_graph = || {
            let mut g = ReputationGraph::new();
            g.register_publisher(test_publisher("pub-1"));
            g.register_extension(test_extension("ext-1", "pub-1"))
                .unwrap();
            g.register_extension(test_extension("ext-2", "pub-1"))
                .unwrap();
            g.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
            g
        };
        let json1 = serde_json::to_string(&build_graph()).unwrap();
        let json2 = serde_json::to_string(&build_graph()).unwrap();
        assert_eq!(json1, json2, "identical graphs must produce identical JSON");
    }

    // -- Edge counting --

    #[test]
    fn edges_created_on_operations() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        // register_extension creates a PublishedBy edge.
        assert_eq!(graph.edge_count(), 1);

        graph.add_evidence("ext-1", test_evidence("ev-1")).unwrap();
        // add_evidence creates an ObservedBehavior edge.
        assert_eq!(graph.edge_count(), 2);

        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                1_000,
            )
            .unwrap();
        // trust transition creates a TrustTransitioned edge.
        assert_eq!(graph.edge_count(), 3);
    }

    // -- Incident management --

    #[test]
    fn add_incident_creates_revoked_by_edges() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph
            .register_extension(test_extension("ext-2", "pub-1"))
            .unwrap();
        let initial_edges = graph.edge_count();

        let incident = IncidentNode {
            incident_id: "inc-1".into(),
            severity: IncidentSeverity::Critical,
            affected_extensions: ["ext-1".into(), "ext-2".into()].into_iter().collect(),
            containment_actions: vec!["quarantine".into()],
            resolution_status: ResolutionStatus::Active,
            timestamp_ns: 6_000_000_000,
        };
        graph.add_incident(incident);

        // Two RevokedBy edges created.
        assert_eq!(graph.edge_count(), initial_edges + 2);
    }

    // -- serde roundtrips for enum types --------------------------------------

    #[test]
    fn trust_level_serde_roundtrip_all_variants() {
        for level in &TrustLevel::ALL {
            let json = serde_json::to_string(level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*level, back);
        }
    }

    #[test]
    fn evidence_type_serde_roundtrip() {
        let variants = [
            EvidenceType::BehavioralObservation,
            EvidenceType::AdversarialCampaignResult,
            EvidenceType::FleetEvidence,
            EvidenceType::IncidentRecord,
            EvidenceType::ThreatIntelligence,
            EvidenceType::ProvenanceAttestation,
            EvidenceType::OperatorAssessment,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EvidenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn evidence_source_serde_roundtrip() {
        let variants = [
            EvidenceSource::BayesianSentinel,
            EvidenceSource::AdversarialCampaign,
            EvidenceSource::FleetImmuneSystem,
            EvidenceSource::OperatorManual,
            EvidenceSource::ExternalThreatFeed,
            EvidenceSource::BuildProvenance,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EvidenceSource = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn incident_severity_serde_roundtrip() {
        for sev in &[
            IncidentSeverity::Low,
            IncidentSeverity::Medium,
            IncidentSeverity::High,
            IncidentSeverity::Critical,
        ] {
            let json = serde_json::to_string(sev).unwrap();
            let back: IncidentSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    #[test]
    fn resolution_status_serde_roundtrip() {
        for status in &[
            ResolutionStatus::Active,
            ResolutionStatus::Contained,
            ResolutionStatus::Resolved,
            ResolutionStatus::FalsePositive,
        ] {
            let json = serde_json::to_string(status).unwrap();
            let back: ResolutionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    // -- serde roundtrips for struct types ------------------------------------

    #[test]
    fn provenance_record_serde_roundtrip() {
        let record = ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: false,
            attestation_source: Some("sigstore".into()),
            dependency_depth: 3,
            has_provenance_gap: true,
            gap_descriptions: vec!["missing attestation".into()],
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ProvenanceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn trust_lookup_result_serde_roundtrip() {
        let result = TrustLookupResult {
            extension_id: "ext-1".into(),
            current_trust_level: TrustLevel::Established,
            transition_count: 2,
            last_transition: None,
            evidence_count: 5,
            dependency_risk_score: 300_000,
            publisher_trust_score: Some(750_000),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TrustLookupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn revocation_impact_serde_roundtrip() {
        let impact = RevocationImpact {
            directly_affected: ["ext-b".into()].into_iter().collect(),
            transitively_affected: BTreeSet::new(),
            trust_degradations: vec![],
        };
        let json = serde_json::to_string(&impact).unwrap();
        let back: RevocationImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, back);
    }

    #[test]
    fn operator_override_input_serde_roundtrip() {
        let input = OperatorOverrideInput {
            extension_id: "ext-1".into(),
            new_level: TrustLevel::Provisional,
            justification: "incident resolved".into(),
            evidence_ids: vec!["ev-1".into()],
            policy_version: 2,
            epoch: SecurityEpoch::from_raw(3),
            timestamp_ns: 1_000,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: OperatorOverrideInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extension_id, "ext-1");
        assert_eq!(back.new_level, TrustLevel::Provisional);
    }

    // -- ReputationGraphError Display: all 6 variants -------------------------

    #[test]
    fn error_display_publisher_not_found() {
        let err = ReputationGraphError::PublisherNotFound {
            publisher_id: "pub-99".into(),
        };
        assert!(err.to_string().contains("pub-99"));
    }

    #[test]
    fn error_display_duplicate_extension() {
        let err = ReputationGraphError::DuplicateExtension {
            extension_id: "ext-dup".into(),
        };
        assert!(err.to_string().contains("ext-dup"));
    }

    #[test]
    fn error_display_duplicate_evidence() {
        let err = ReputationGraphError::DuplicateEvidence {
            evidence_id: "ev-dup".into(),
        };
        assert!(err.to_string().contains("ev-dup"));
    }

    #[test]
    fn error_display_circular_dependency() {
        let err = ReputationGraphError::CircularDependency {
            extension_id: "ext-a".into(),
            dependency_chain: vec!["ext-b".into(), "ext-a".into()],
        };
        let s = err.to_string();
        assert!(s.contains("ext-a"));
        assert!(s.contains("ext-b -> ext-a"));
    }

    // -- empty graph state ----------------------------------------------------

    #[test]
    fn empty_graph_counts() {
        let graph = ReputationGraph::new();
        assert_eq!(graph.extension_count(), 0);
        assert_eq!(graph.evidence_count(), 0);
        assert_eq!(graph.total_transitions(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn empty_graph_get_extension_returns_none() {
        let graph = ReputationGraph::new();
        assert!(graph.get_extension("nonexistent").is_none());
    }

    #[test]
    fn empty_graph_get_publisher_returns_none() {
        let graph = ReputationGraph::new();
        assert!(graph.get_publisher("nonexistent").is_none());
    }

    #[test]
    fn empty_graph_trust_history_empty() {
        let graph = ReputationGraph::new();
        assert!(graph.trust_history("nonexistent").is_empty());
    }

    // -- can_auto_transition_to edge cases ------------------------------------

    #[test]
    fn auto_transition_same_level_always_allowed() {
        for level in &TrustLevel::ALL {
            assert!(level.can_auto_transition_to(*level));
        }
    }

    #[test]
    fn auto_transition_degraded_to_non_degraded_denied() {
        assert!(!TrustLevel::Suspicious.can_auto_transition_to(TrustLevel::Unknown));
        assert!(!TrustLevel::Compromised.can_auto_transition_to(TrustLevel::Established));
        assert!(!TrustLevel::Revoked.can_auto_transition_to(TrustLevel::Trusted));
    }

    #[test]
    fn auto_transition_non_degraded_to_degraded_allowed() {
        for src in &[
            TrustLevel::Unknown,
            TrustLevel::Provisional,
            TrustLevel::Established,
            TrustLevel::Trusted,
        ] {
            for dst in &[
                TrustLevel::Suspicious,
                TrustLevel::Compromised,
                TrustLevel::Revoked,
            ] {
                assert!(
                    src.can_auto_transition_to(*dst),
                    "{src} -> {dst} should be auto-allowed"
                );
            }
        }
    }

    // -- incident severity ordering -------------------------------------------

    #[test]
    fn incident_severity_ordering() {
        assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
        assert!(IncidentSeverity::Medium < IncidentSeverity::High);
        assert!(IncidentSeverity::High < IncidentSeverity::Critical);
    }

    #[test]
    fn resolution_status_ordering() {
        assert!(ResolutionStatus::Active < ResolutionStatus::Contained);
        assert!(ResolutionStatus::Contained < ResolutionStatus::Resolved);
        assert!(ResolutionStatus::Resolved < ResolutionStatus::FalsePositive);
    }

    // -- get_provenance miss --------------------------------------------------

    #[test]
    fn get_provenance_nonexistent_returns_none() {
        let graph = ReputationGraph::new();
        assert!(graph.get_provenance("nonexistent").is_none());
    }

    // -- edge type serde roundtrip --------------------------------------------

    #[test]
    fn edge_type_serde_roundtrip() {
        let edges = vec![
            EdgeType::PublishedBy {
                extension_id: "ext-1".into(),
                publisher_id: "pub-1".into(),
            },
            EdgeType::DependsOn {
                dependent_id: "ext-1".into(),
                dependency_id: "ext-2".into(),
            },
            EdgeType::DerivedFrom {
                new_version_id: "v2".into(),
                old_version_id: "v1".into(),
            },
            EdgeType::ObservedBehavior {
                extension_id: "ext-1".into(),
                evidence_id: "ev-1".into(),
            },
            EdgeType::RevokedBy {
                extension_id: "ext-1".into(),
                incident_id: "inc-1".into(),
            },
            EdgeType::RevocationPropagatedTo {
                source_extension_id: "ext-1".into(),
                target_extension_id: "ext-2".into(),
                incident_id: "inc-1".into(),
            },
            EdgeType::TrustTransitioned {
                extension_id: "ext-1".into(),
                transition_id: "tt-1".into(),
            },
        ];
        for edge in &edges {
            let json = serde_json::to_string(edge).unwrap();
            let back: EdgeType = serde_json::from_str(&json).unwrap();
            assert_eq!(*edge, back);
        }
    }

    // -- Enrichment: std::error --

    #[test]
    fn reputation_graph_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ReputationGraphError::ExtensionNotFound {
                extension_id: "ext-1".into(),
            }),
            Box::new(ReputationGraphError::PublisherNotFound {
                publisher_id: "pub-1".into(),
            }),
            Box::new(ReputationGraphError::AutoUpgradeDenied {
                extension_id: "ext-2".into(),
                current: TrustLevel::Provisional,
                attempted: TrustLevel::Trusted,
            }),
            Box::new(ReputationGraphError::DuplicateExtension {
                extension_id: "ext-3".into(),
            }),
            Box::new(ReputationGraphError::DuplicateEvidence {
                evidence_id: "ev-1".into(),
            }),
            Box::new(ReputationGraphError::CircularDependency {
                extension_id: "ext-4".into(),
                dependency_chain: vec!["ext-4".into(), "ext-5".into()],
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
            6,
            "all 6 variants produce distinct messages"
        );
    }

    // -------------------------------------------------------------------------
    // Category 1: Copy semantics — Copy types survive copy without move
    // -------------------------------------------------------------------------

    #[test]
    fn trust_level_copy_survives() {
        let a = TrustLevel::Established;
        let b = a; // copy, not move
        assert_eq!(a, b);
        // a is still usable after the copy
        assert_eq!(a, TrustLevel::Established);
    }

    #[test]
    fn evidence_type_copy_survives() {
        let a = EvidenceType::ThreatIntelligence;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, EvidenceType::ThreatIntelligence);
    }

    #[test]
    fn evidence_source_copy_survives() {
        let a = EvidenceSource::FleetImmuneSystem;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, EvidenceSource::FleetImmuneSystem);
    }

    #[test]
    fn incident_severity_copy_survives() {
        let a = IncidentSeverity::High;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, IncidentSeverity::High);
    }

    #[test]
    fn resolution_status_copy_survives() {
        let a = ResolutionStatus::Contained;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, ResolutionStatus::Contained);
    }

    // -------------------------------------------------------------------------
    // Category 2: Debug distinctness — all enum variants produce distinct Debug
    // -------------------------------------------------------------------------

    #[test]
    fn trust_level_debug_all_distinct() {
        let debugs: BTreeSet<String> = TrustLevel::ALL.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            7,
            "all 7 TrustLevel variants have distinct Debug"
        );
    }

    #[test]
    fn evidence_type_debug_all_distinct() {
        let variants = [
            EvidenceType::BehavioralObservation,
            EvidenceType::AdversarialCampaignResult,
            EvidenceType::FleetEvidence,
            EvidenceType::IncidentRecord,
            EvidenceType::ThreatIntelligence,
            EvidenceType::ProvenanceAttestation,
            EvidenceType::OperatorAssessment,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            7,
            "all 7 EvidenceType variants have distinct Debug"
        );
    }

    #[test]
    fn evidence_source_debug_all_distinct() {
        let variants = [
            EvidenceSource::BayesianSentinel,
            EvidenceSource::AdversarialCampaign,
            EvidenceSource::FleetImmuneSystem,
            EvidenceSource::OperatorManual,
            EvidenceSource::ExternalThreatFeed,
            EvidenceSource::BuildProvenance,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            6,
            "all 6 EvidenceSource variants have distinct Debug"
        );
    }

    #[test]
    fn incident_severity_debug_all_distinct() {
        let variants = [
            IncidentSeverity::Low,
            IncidentSeverity::Medium,
            IncidentSeverity::High,
            IncidentSeverity::Critical,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(debugs.len(), 4);
    }

    #[test]
    fn resolution_status_debug_all_distinct() {
        let variants = [
            ResolutionStatus::Active,
            ResolutionStatus::Contained,
            ResolutionStatus::Resolved,
            ResolutionStatus::FalsePositive,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(debugs.len(), 4);
    }

    // -------------------------------------------------------------------------
    // Category 3: Serde variant distinctness — distinct JSON per variant
    // -------------------------------------------------------------------------

    #[test]
    fn trust_level_serde_all_distinct() {
        let jsons: BTreeSet<String> = TrustLevel::ALL
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            7,
            "all 7 TrustLevel variants serialize to distinct JSON"
        );
    }

    #[test]
    fn evidence_type_serde_all_distinct() {
        let variants = [
            EvidenceType::BehavioralObservation,
            EvidenceType::AdversarialCampaignResult,
            EvidenceType::FleetEvidence,
            EvidenceType::IncidentRecord,
            EvidenceType::ThreatIntelligence,
            EvidenceType::ProvenanceAttestation,
            EvidenceType::OperatorAssessment,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 7);
    }

    #[test]
    fn evidence_source_serde_all_distinct() {
        let variants = [
            EvidenceSource::BayesianSentinel,
            EvidenceSource::AdversarialCampaign,
            EvidenceSource::FleetImmuneSystem,
            EvidenceSource::OperatorManual,
            EvidenceSource::ExternalThreatFeed,
            EvidenceSource::BuildProvenance,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 6);
    }

    #[test]
    fn resolution_status_serde_all_distinct() {
        let variants = [
            ResolutionStatus::Active,
            ResolutionStatus::Contained,
            ResolutionStatus::Resolved,
            ResolutionStatus::FalsePositive,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 4);
    }

    // -------------------------------------------------------------------------
    // Category 4: Clone independence — mutating clone doesn't affect original
    // -------------------------------------------------------------------------

    #[test]
    fn extension_node_clone_independence() {
        let original = test_extension("ext-clone", "pub-1");
        let mut clone = original.clone();
        clone.version = "9.9.9".to_string();
        assert_eq!(original.version, "1.0.0");
        assert_eq!(clone.version, "9.9.9");
    }

    #[test]
    fn publisher_node_clone_independence() {
        let original = test_publisher("pub-clone");
        let mut clone = original.clone();
        clone.trust_score = 0;
        assert_eq!(original.trust_score, 500_000);
        assert_eq!(clone.trust_score, 0);
    }

    #[test]
    fn evidence_node_clone_independence() {
        let original = test_evidence("ev-clone");
        let mut clone = original.clone();
        clone.evidence_id = "ev-modified".to_string();
        assert_eq!(original.evidence_id, "ev-clone");
        assert_eq!(clone.evidence_id, "ev-modified");
    }

    #[test]
    fn provenance_record_clone_independence() {
        let original = ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: true,
            attestation_source: Some("sigstore".into()),
            dependency_depth: 1,
            has_provenance_gap: false,
            gap_descriptions: vec![],
        };
        let mut clone = original.clone();
        clone.dependency_depth = 99;
        assert_eq!(original.dependency_depth, 1);
        assert_eq!(clone.dependency_depth, 99);
    }

    #[test]
    fn trust_transition_clone_independence() {
        let original = TrustTransition {
            transition_id: "tt-orig".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec!["ev-1".into()],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 1_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let mut clone = original.clone();
        clone.policy_version = 42;
        assert_eq!(original.policy_version, 1);
        assert_eq!(clone.policy_version, 42);
    }

    // -------------------------------------------------------------------------
    // Category 5: JSON field-name stability
    // -------------------------------------------------------------------------

    #[test]
    fn extension_node_field_names() {
        let ext = test_extension("ext-field", "pub-field");
        let json = serde_json::to_string(&ext).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"package_name\""));
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"publisher_id\""));
        assert!(json.contains("\"manifest_hash\""));
        assert!(json.contains("\"first_seen_ns\""));
        assert!(json.contains("\"current_trust_level\""));
        assert!(json.contains("\"dependencies\""));
    }

    #[test]
    fn publisher_node_field_names() {
        let pub_node = test_publisher("pub-fields");
        let json = serde_json::to_string(&pub_node).unwrap();
        assert!(json.contains("\"publisher_id\""));
        assert!(json.contains("\"identity_attestation\""));
        assert!(json.contains("\"published_count\""));
        assert!(json.contains("\"trust_score\""));
        assert!(json.contains("\"first_published_ns\""));
    }

    #[test]
    fn evidence_node_field_names() {
        let ev = test_evidence("ev-fields");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"evidence_id\""));
        assert!(json.contains("\"evidence_type\""));
        assert!(json.contains("\"source\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"content_hash\""));
        assert!(json.contains("\"linked_decision_ids\""));
        assert!(json.contains("\"epoch\""));
    }

    #[test]
    fn provenance_record_field_names() {
        let record = ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: false,
            attestation_source: None,
            dependency_depth: 0,
            has_provenance_gap: false,
            gap_descriptions: vec![],
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"publisher_verified\""));
        assert!(json.contains("\"build_attested\""));
        assert!(json.contains("\"attestation_source\""));
        assert!(json.contains("\"dependency_depth\""));
        assert!(json.contains("\"has_provenance_gap\""));
        assert!(json.contains("\"gap_descriptions\""));
    }

    #[test]
    fn trust_transition_field_names() {
        let tt = TrustTransition {
            transition_id: "tt-fn".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&tt).unwrap();
        assert!(json.contains("\"transition_id\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"old_level\""));
        assert!(json.contains("\"new_level\""));
        assert!(json.contains("\"triggering_evidence_ids\""));
        assert!(json.contains("\"policy_version\""));
        assert!(json.contains("\"operator_override\""));
        assert!(json.contains("\"operator_justification\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"epoch\""));
    }

    // -------------------------------------------------------------------------
    // Category 6: Display format checks — exact string assertions
    // -------------------------------------------------------------------------

    #[test]
    fn trust_level_display_all_variants() {
        assert_eq!(TrustLevel::Unknown.to_string(), "unknown");
        assert_eq!(TrustLevel::Provisional.to_string(), "provisional");
        assert_eq!(TrustLevel::Established.to_string(), "established");
        assert_eq!(TrustLevel::Trusted.to_string(), "trusted");
        assert_eq!(TrustLevel::Suspicious.to_string(), "suspicious");
        assert_eq!(TrustLevel::Compromised.to_string(), "compromised");
        assert_eq!(TrustLevel::Revoked.to_string(), "revoked");
    }

    #[test]
    fn error_display_extension_not_found_exact() {
        let err = ReputationGraphError::ExtensionNotFound {
            extension_id: "my-ext".into(),
        };
        assert_eq!(err.to_string(), "extension not found: my-ext");
    }

    #[test]
    fn error_display_publisher_not_found_exact() {
        let err = ReputationGraphError::PublisherNotFound {
            publisher_id: "my-pub".into(),
        };
        assert_eq!(err.to_string(), "publisher not found: my-pub");
    }

    #[test]
    fn error_display_duplicate_extension_exact() {
        let err = ReputationGraphError::DuplicateExtension {
            extension_id: "ext-dup2".into(),
        };
        assert_eq!(err.to_string(), "duplicate extension: ext-dup2");
    }

    #[test]
    fn error_display_duplicate_evidence_exact() {
        let err = ReputationGraphError::DuplicateEvidence {
            evidence_id: "ev-dup2".into(),
        };
        assert_eq!(err.to_string(), "duplicate evidence: ev-dup2");
    }

    #[test]
    fn error_display_auto_upgrade_denied_exact() {
        let err = ReputationGraphError::AutoUpgradeDenied {
            extension_id: "ext-x".into(),
            current: TrustLevel::Suspicious,
            attempted: TrustLevel::Trusted,
        };
        let s = err.to_string();
        assert!(s.contains("ext-x"), "must contain extension id");
        assert!(s.contains("suspicious"), "must contain current level");
        assert!(s.contains("trusted"), "must contain attempted level");
        assert!(
            s.contains("operator override"),
            "must mention operator override"
        );
    }

    #[test]
    fn error_display_circular_dependency_exact() {
        let err = ReputationGraphError::CircularDependency {
            extension_id: "ext-circ".into(),
            dependency_chain: vec!["ext-a".into(), "ext-b".into(), "ext-circ".into()],
        };
        let s = err.to_string();
        assert!(s.contains("ext-circ"));
        assert!(s.contains("ext-a -> ext-b -> ext-circ"));
    }

    // -------------------------------------------------------------------------
    // Category 7: Hash consistency — same value hashes identically
    // -------------------------------------------------------------------------

    #[test]
    fn trust_level_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let level = TrustLevel::Established;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        level.hash(&mut h1);
        level.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn evidence_type_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let et = EvidenceType::AdversarialCampaignResult;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        et.hash(&mut h1);
        et.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn evidence_source_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let es = EvidenceSource::BuildProvenance;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        es.hash(&mut h1);
        es.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn incident_severity_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let sev = IncidentSeverity::Critical;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        sev.hash(&mut h1);
        sev.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn resolution_status_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let rs = ResolutionStatus::Resolved;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        rs.hash(&mut h1);
        rs.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // -------------------------------------------------------------------------
    // Category 8: Boundary/edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn extension_node_empty_strings_and_zero_values() {
        let ext = ExtensionNode {
            extension_id: String::new(),
            package_name: String::new(),
            version: String::new(),
            publisher_id: String::new(),
            manifest_hash: [0u8; 32],
            first_seen_ns: 0,
            current_trust_level: TrustLevel::Unknown,
            dependencies: BTreeSet::new(),
        };
        let json = serde_json::to_string(&ext).unwrap();
        let back: ExtensionNode = serde_json::from_str(&json).unwrap();
        assert_eq!(ext, back);
    }

    #[test]
    fn publisher_node_zero_trust_score() {
        let pub_node = PublisherNode {
            publisher_id: "pub-zero".into(),
            identity_attestation: [0u8; 32],
            published_count: 0,
            trust_score: 0,
            first_published_ns: 0,
        };
        let json = serde_json::to_string(&pub_node).unwrap();
        let back: PublisherNode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trust_score, 0);
    }

    #[test]
    fn publisher_node_u64_max_timestamps() {
        let pub_node = PublisherNode {
            publisher_id: "pub-max".into(),
            identity_attestation: [0xFFu8; 32],
            published_count: u64::MAX,
            trust_score: 1_000_000,
            first_published_ns: u64::MAX,
        };
        let json = serde_json::to_string(&pub_node).unwrap();
        let back: PublisherNode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.published_count, u64::MAX);
        assert_eq!(back.first_published_ns, u64::MAX);
    }

    #[test]
    fn provenance_record_none_attestation_source() {
        let record = ProvenanceRecord {
            extension_id: "ext-none".into(),
            publisher_verified: false,
            build_attested: false,
            attestation_source: None,
            dependency_depth: 0,
            has_provenance_gap: true,
            gap_descriptions: vec!["no source".into()],
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ProvenanceRecord = serde_json::from_str(&json).unwrap();
        assert!(back.attestation_source.is_none());
        assert!(back.has_provenance_gap);
    }

    #[test]
    fn trust_lookup_result_no_last_transition() {
        let result = TrustLookupResult {
            extension_id: "ext-notrans".into(),
            current_trust_level: TrustLevel::Unknown,
            transition_count: 0,
            last_transition: None,
            evidence_count: 0,
            dependency_risk_score: 0,
            publisher_trust_score: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TrustLookupResult = serde_json::from_str(&json).unwrap();
        assert!(back.last_transition.is_none());
        assert!(back.publisher_trust_score.is_none());
    }

    #[test]
    fn incident_node_empty_affected_extensions() {
        let incident = IncidentNode {
            incident_id: "inc-empty".into(),
            severity: IncidentSeverity::Low,
            affected_extensions: BTreeSet::new(),
            containment_actions: vec![],
            resolution_status: ResolutionStatus::FalsePositive,
            timestamp_ns: 0,
        };
        let json = serde_json::to_string(&incident).unwrap();
        let back: IncidentNode = serde_json::from_str(&json).unwrap();
        assert!(back.affected_extensions.is_empty());
        assert!(back.containment_actions.is_empty());
    }

    #[test]
    fn dependency_risk_score_revoked_dep_is_max() {
        let mut graph = ReputationGraph::new();
        let mut dep = test_extension("dep-rev", "pub-1");
        dep.current_trust_level = TrustLevel::Revoked;
        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-rev"]);
        graph.register_extension(dep).unwrap();
        graph.register_extension(ext).unwrap();
        let result = graph.trust_lookup("ext-1").unwrap();
        assert_eq!(result.dependency_risk_score, 1_000_000);
    }

    #[test]
    fn dependency_risk_score_compromised_dep() {
        let mut graph = ReputationGraph::new();
        let mut dep = test_extension("dep-comp", "pub-1");
        dep.current_trust_level = TrustLevel::Compromised;
        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-comp"]);
        graph.register_extension(dep).unwrap();
        graph.register_extension(ext).unwrap();
        let result = graph.trust_lookup("ext-1").unwrap();
        assert_eq!(result.dependency_risk_score, 800_000);
    }

    #[test]
    fn dependency_risk_unknown_dep_not_in_graph() {
        let mut graph = ReputationGraph::new();
        // ext-1 depends on dep-ghost which is not registered
        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-ghost"]);
        graph.register_extension(ext).unwrap();
        let result = graph.trust_lookup("ext-1").unwrap();
        // Unknown dependency = high risk (500_000)
        assert_eq!(result.dependency_risk_score, 500_000);
    }

    #[test]
    fn dependency_risk_trusted_dep_is_zero() {
        let mut graph = ReputationGraph::new();
        let mut dep = test_extension("dep-trusted", "pub-1");
        dep.current_trust_level = TrustLevel::Trusted;
        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-trusted"]);
        graph.register_extension(dep).unwrap();
        graph.register_extension(ext).unwrap();
        let result = graph.trust_lookup("ext-1").unwrap();
        assert_eq!(result.dependency_risk_score, 0);
    }

    // -------------------------------------------------------------------------
    // Category 9: Serde roundtrips — complex populated structs
    // -------------------------------------------------------------------------

    #[test]
    fn incident_node_serde_roundtrip() {
        let incident = IncidentNode {
            incident_id: "inc-rt".into(),
            severity: IncidentSeverity::High,
            affected_extensions: ["ext-a".into(), "ext-b".into()].into_iter().collect(),
            containment_actions: vec!["isolate".into(), "alert".into()],
            resolution_status: ResolutionStatus::Contained,
            timestamp_ns: 9_000_000_000,
        };
        let json = serde_json::to_string(&incident).unwrap();
        let back: IncidentNode = serde_json::from_str(&json).unwrap();
        assert_eq!(incident, back);
    }

    #[test]
    fn evidence_node_serde_roundtrip_all_fields() {
        let ev = EvidenceNode {
            evidence_id: "ev-rt".into(),
            evidence_type: EvidenceType::IncidentRecord,
            source: EvidenceSource::ExternalThreatFeed,
            timestamp_ns: 7_000_000_000,
            content_hash: [0xABu8; 32],
            linked_decision_ids: vec!["dec-a".into(), "dec-b".into()],
            epoch: SecurityEpoch::from_raw(5),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: EvidenceNode = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn trust_transition_with_justification_serde_roundtrip() {
        let tt = TrustTransition {
            transition_id: "tt-op".into(),
            extension_id: "ext-op".into(),
            old_level: TrustLevel::Compromised,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec!["ev-1".into(), "ev-2".into()],
            policy_version: 99,
            operator_override: true,
            operator_justification: Some("Incident resolved per audit trail".into()),
            timestamp_ns: 10_000_000_000,
            epoch: SecurityEpoch::from_raw(10),
        };
        let json = serde_json::to_string(&tt).unwrap();
        let back: TrustTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(tt, back);
        assert!(back.operator_override);
        assert_eq!(
            back.operator_justification.as_deref(),
            Some("Incident resolved per audit trail")
        );
    }

    #[test]
    fn revocation_impact_with_all_sets_serde_roundtrip() {
        let impact = RevocationImpact {
            directly_affected: ["ext-b".into(), "ext-c".into()].into_iter().collect(),
            transitively_affected: ["ext-d".into(), "ext-e".into()].into_iter().collect(),
            trust_degradations: vec![TrustTransition {
                transition_id: "tt-deg".into(),
                extension_id: "ext-b".into(),
                old_level: TrustLevel::Established,
                new_level: TrustLevel::Suspicious,
                triggering_evidence_ids: vec!["revocation-propagation:inc-1".into()],
                policy_version: 0,
                operator_override: false,
                operator_justification: None,
                timestamp_ns: 6_000_000_000,
                epoch: SecurityEpoch::from_raw(3),
            }],
        };
        let json = serde_json::to_string(&impact).unwrap();
        let back: RevocationImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, back);
        assert_eq!(back.directly_affected.len(), 2);
        assert_eq!(back.transitively_affected.len(), 2);
        assert_eq!(back.trust_degradations.len(), 1);
    }

    #[test]
    fn operator_override_input_full_serde_roundtrip() {
        let input = OperatorOverrideInput {
            extension_id: "ext-full".into(),
            new_level: TrustLevel::Established,
            justification: "Full review completed, clean audit".into(),
            evidence_ids: vec!["ev-a".into(), "ev-b".into(), "ev-c".into()],
            policy_version: 42,
            epoch: SecurityEpoch::from_raw(7),
            timestamp_ns: 8_888_888_888,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: OperatorOverrideInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extension_id, "ext-full");
        assert_eq!(back.new_level, TrustLevel::Established);
        assert_eq!(back.evidence_ids.len(), 3);
        assert_eq!(back.policy_version, 42);
    }

    // -------------------------------------------------------------------------
    // Category 10: Debug nonempty — all types produce non-empty Debug output
    // -------------------------------------------------------------------------

    #[test]
    fn extension_node_debug_nonempty() {
        let ext = test_extension("ext-dbg", "pub-dbg");
        let s = format!("{ext:?}");
        assert!(!s.is_empty());
        assert!(s.contains("ext-dbg"));
    }

    #[test]
    fn publisher_node_debug_nonempty() {
        let pub_node = test_publisher("pub-dbg");
        let s = format!("{pub_node:?}");
        assert!(!s.is_empty());
        assert!(s.contains("pub-dbg"));
    }

    #[test]
    fn evidence_node_debug_nonempty() {
        let ev = test_evidence("ev-dbg");
        let s = format!("{ev:?}");
        assert!(!s.is_empty());
        assert!(s.contains("ev-dbg"));
    }

    #[test]
    fn incident_node_debug_nonempty() {
        let incident = IncidentNode {
            incident_id: "inc-dbg".into(),
            severity: IncidentSeverity::Medium,
            affected_extensions: BTreeSet::new(),
            containment_actions: vec![],
            resolution_status: ResolutionStatus::Active,
            timestamp_ns: 0,
        };
        let s = format!("{incident:?}");
        assert!(!s.is_empty());
        assert!(s.contains("inc-dbg"));
    }

    #[test]
    fn trust_transition_debug_nonempty() {
        let tt = TrustTransition {
            transition_id: "tt-dbg".into(),
            extension_id: "ext-dbg".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Trusted,
            triggering_evidence_ids: vec![],
            policy_version: 0,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 0,
            epoch: SecurityEpoch::from_raw(1),
        };
        let s = format!("{tt:?}");
        assert!(!s.is_empty());
        assert!(s.contains("tt-dbg"));
    }

    #[test]
    fn reputation_graph_error_debug_nonempty() {
        let err = ReputationGraphError::ExtensionNotFound {
            extension_id: "ext-err-dbg".into(),
        };
        let s = format!("{err:?}");
        assert!(!s.is_empty());
        assert!(s.contains("ext-err-dbg"));
    }

    #[test]
    fn reputation_graph_debug_nonempty() {
        let graph = ReputationGraph::new();
        let s = format!("{graph:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn operator_override_input_debug_nonempty() {
        let input = OperatorOverrideInput {
            extension_id: "ext-ood".into(),
            new_level: TrustLevel::Provisional,
            justification: "test".into(),
            evidence_ids: vec![],
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 0,
        };
        let s = format!("{input:?}");
        assert!(!s.is_empty());
        assert!(s.contains("ext-ood"));
    }

    // -------------------------------------------------------------------------
    // Bonus: Additional behavioral / integration tests
    // -------------------------------------------------------------------------

    #[test]
    fn transition_trust_missing_extension_returns_error() {
        let mut graph = ReputationGraph::new();
        let result = graph.transition_trust(
            "nonexistent",
            TrustLevel::Revoked,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            0,
        );
        assert!(matches!(
            result,
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    #[test]
    fn operator_override_missing_extension_returns_error() {
        let mut graph = ReputationGraph::new();
        let result = graph.operator_trust_override(OperatorOverrideInput {
            extension_id: "no-such-ext".into(),
            new_level: TrustLevel::Trusted,
            justification: "test".into(),
            evidence_ids: vec![],
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 0,
        });
        assert!(matches!(
            result,
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    #[test]
    fn operator_override_blank_justification_does_not_mask_missing_extension() {
        let mut graph = ReputationGraph::new();
        let result = graph.operator_trust_override(OperatorOverrideInput {
            extension_id: "no-such-ext".into(),
            new_level: TrustLevel::Trusted,
            justification: "   ".into(),
            evidence_ids: vec![],
            policy_version: 1,
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 0,
        });
        assert!(matches!(
            result,
            Err(ReputationGraphError::ExtensionNotFound { .. })
        ));
    }

    #[test]
    fn trust_lookup_with_last_transition_populated() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-lt", "pub-1"))
            .unwrap();
        graph
            .transition_trust(
                "ext-lt",
                TrustLevel::Provisional,
                vec!["ev-x".into()],
                1,
                SecurityEpoch::from_raw(1),
                1_000,
            )
            .unwrap();
        let result = graph.trust_lookup("ext-lt").unwrap();
        assert_eq!(result.transition_count, 1);
        assert!(result.last_transition.is_some());
        let last = result.last_transition.unwrap();
        assert_eq!(last.new_level, TrustLevel::Provisional);
    }

    #[test]
    fn get_evidence_for_extension_returns_correct_nodes() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-ev", "pub-1"))
            .unwrap();
        graph.add_evidence("ext-ev", test_evidence("ev-a")).unwrap();
        graph.add_evidence("ext-ev", test_evidence("ev-b")).unwrap();
        let evs = graph.get_evidence_for_extension("ext-ev");
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn get_evidence_for_missing_extension_returns_empty() {
        let graph = ReputationGraph::new();
        let evs = graph.get_evidence_for_extension("nonexistent");
        assert!(evs.is_empty());
    }

    #[test]
    fn incident_count_for_extension_correct() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-inc", "pub-1"))
            .unwrap();
        let incident = IncidentNode {
            incident_id: "inc-count".into(),
            severity: IncidentSeverity::High,
            affected_extensions: ["ext-inc".into()].into_iter().collect(),
            containment_actions: vec![],
            resolution_status: ResolutionStatus::Active,
            timestamp_ns: 0,
        };
        graph.add_incident(incident);
        assert_eq!(graph.incident_count_for_extension("ext-inc"), 1);
        assert_eq!(graph.incident_count_for_extension("other-ext"), 0);
    }

    #[test]
    fn default_graph_equals_new_graph() {
        let default_graph = ReputationGraph::default();
        assert_eq!(default_graph.extension_count(), 0);
        assert_eq!(default_graph.edge_count(), 0);
        assert_eq!(default_graph.total_transitions(), 0);
    }

    #[test]
    fn trust_transition_id_format() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-id", "pub-1"))
            .unwrap();
        let tt = graph
            .transition_trust(
                "ext-id",
                TrustLevel::Provisional,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                0,
            )
            .unwrap();
        assert!(
            tt.transition_id.starts_with("tt-"),
            "transition ID must start with tt-"
        );
        assert_eq!(tt.transition_id, "tt-00000001");
    }

    #[test]
    fn multiple_operators_sequential_transitions() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-seq", "pub-1"))
            .unwrap();
        // unknown -> provisional -> established -> trusted
        let levels = [
            TrustLevel::Provisional,
            TrustLevel::Established,
            TrustLevel::Trusted,
        ];
        for (i, level) in levels.iter().enumerate() {
            graph
                .transition_trust(
                    "ext-seq",
                    *level,
                    vec![],
                    1,
                    SecurityEpoch::from_raw(1),
                    i as u64 * 1_000,
                )
                .unwrap();
        }
        assert_eq!(graph.total_transitions(), 3);
        assert_eq!(
            graph.get_extension("ext-seq").unwrap().current_trust_level,
            TrustLevel::Trusted
        );
    }

    #[test]
    fn revocation_propagation_no_dependents_produces_empty_impact() {
        let mut graph = ReputationGraph::new();
        graph
            .register_extension(test_extension("ext-isolated", "pub-1"))
            .unwrap();
        let impact = graph
            .propagate_revocation("ext-isolated", "inc-noop", SecurityEpoch::from_raw(1), 0)
            .unwrap();
        assert!(impact.directly_affected.is_empty());
        assert!(impact.transitively_affected.is_empty());
        assert!(impact.trust_degradations.is_empty());
    }

    #[test]
    fn incident_node_serde_field_names() {
        let incident = IncidentNode {
            incident_id: "inc-fn".into(),
            severity: IncidentSeverity::Low,
            affected_extensions: BTreeSet::new(),
            containment_actions: vec![],
            resolution_status: ResolutionStatus::Resolved,
            timestamp_ns: 0,
        };
        let json = serde_json::to_string(&incident).unwrap();
        assert!(json.contains("\"incident_id\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"affected_extensions\""));
        assert!(json.contains("\"containment_actions\""));
        assert!(json.contains("\"resolution_status\""));
        assert!(json.contains("\"timestamp_ns\""));
    }
}
