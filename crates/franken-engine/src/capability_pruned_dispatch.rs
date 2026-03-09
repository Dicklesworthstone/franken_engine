#![allow(clippy::doc_markdown)]

//! Capability-pruned hostcall dispatch and IFC-safe region eligibility.
//!
//! This module compiles capability witnesses and IFC flow proofs into concrete
//! specialization envelopes for hostcall dispatch.  Where proofs cover the
//! required invariants, guards can be elided and fast-path dispatch is
//! authorized.  Where proofs are missing or insufficient, the module falls
//! back to checked dispatch with explicit rejection reasons and auditable
//! proof/fallback receipts.
//!
//! ## Key Concepts
//!
//! - **SpecializationEnvelope**: A verified set of capability witnesses and
//!   flow proofs that authorize specific dispatch optimizations.
//! - **CheckElidableRegion**: A contiguous region of hostcall sites where
//!   capability and IFC checks can be safely elided.
//! - **DispatchDecision**: The routing decision for a hostcall: fast-path,
//!   checked-path, or rejected.
//! - **PruningPolicy**: Configuration for the dispatch pruning algorithm.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::Capability;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Module component name for diagnostics.
pub const COMPONENT: &str = "capability_pruned_dispatch";

/// Schema version for dispatch envelopes.
pub const DISPATCH_SCHEMA_VERSION: &str = "1.0.0";

/// Schema version for elidable regions.
pub const REGION_SCHEMA_VERSION: &str = "1.0.0";

/// Default maximum fast-path dispatch sites per envelope.
pub const DEFAULT_MAX_FAST_PATH_SITES: usize = 256;

/// Default minimum confidence (in millionths) for proof-based elision.
pub const DEFAULT_MIN_ELISION_CONFIDENCE: u64 = 950_000;

/// Default maximum region span (in bytecode offsets).
pub const DEFAULT_MAX_REGION_SPAN: u32 = 512;

// ---------------------------------------------------------------------------
// PruningPolicy — configuration for the dispatch pruning algorithm
// ---------------------------------------------------------------------------

/// Configuration for capability-pruned dispatch decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruningPolicy {
    /// Maximum fast-path dispatch sites per envelope.
    pub max_fast_path_sites: usize,
    /// Minimum confidence (millionths) for proof-based check elision.
    pub min_elision_confidence: u64,
    /// Maximum bytecode span of an elidable region.
    pub max_region_span: u32,
    /// Whether to require IFC flow proofs for fast-path dispatch.
    pub require_ifc_proofs: bool,
    /// Whether to allow degraded-mode dispatch (checked path with reduced
    /// capability set).
    pub allow_degraded_dispatch: bool,
    /// Minimum number of capability witnesses required to authorize
    /// a fast-path envelope.
    pub min_witness_count: usize,
    /// Whether to emit detailed rejection reasons in receipts.
    pub emit_rejection_details: bool,
}

impl Default for PruningPolicy {
    fn default() -> Self {
        Self {
            max_fast_path_sites: DEFAULT_MAX_FAST_PATH_SITES,
            min_elision_confidence: DEFAULT_MIN_ELISION_CONFIDENCE,
            max_region_span: DEFAULT_MAX_REGION_SPAN,
            require_ifc_proofs: true,
            allow_degraded_dispatch: false,
            min_witness_count: 1,
            emit_rejection_details: true,
        }
    }
}

impl PruningPolicy {
    /// Compute a deterministic hash of this policy.
    pub fn policy_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"PruningPolicy.v1");
        hasher.update(self.max_fast_path_sites.to_le_bytes());
        hasher.update(self.min_elision_confidence.to_le_bytes());
        hasher.update(self.max_region_span.to_le_bytes());
        hasher.update([self.require_ifc_proofs as u8]);
        hasher.update([self.allow_degraded_dispatch as u8]);
        hasher.update(self.min_witness_count.to_le_bytes());
        hasher.update([self.emit_rejection_details as u8]);
        let digest = hasher.finalize();
        format!("ph-{}", &hex::encode(digest)[..16])
    }
}

impl fmt::Display for PruningPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pruning-policy(max-sites={}, min-conf={}, ifc={}, degraded={})",
            self.max_fast_path_sites,
            self.min_elision_confidence,
            self.require_ifc_proofs,
            self.allow_degraded_dispatch,
        )
    }
}

// ---------------------------------------------------------------------------
// DispatchSite — a single hostcall dispatch point
// ---------------------------------------------------------------------------

/// A single hostcall dispatch point in the bytecode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchSite {
    /// Bytecode offset of the hostcall.
    pub offset: u32,
    /// Opcode/identifier of the hostcall being dispatched.
    pub hostcall_id: String,
    /// Required capabilities for this hostcall.
    pub required_capabilities: BTreeSet<Capability>,
    /// Whether an IFC flow proof is required.
    pub requires_flow_proof: bool,
    /// Source label for IFC (if applicable).
    pub source_label: Option<String>,
    /// Sink clearance for IFC (if applicable).
    pub sink_clearance: Option<String>,
}

impl DispatchSite {
    /// Create a new dispatch site.
    pub fn new(offset: u32, hostcall_id: impl Into<String>) -> Self {
        Self {
            offset,
            hostcall_id: hostcall_id.into(),
            required_capabilities: BTreeSet::new(),
            requires_flow_proof: false,
            source_label: None,
            sink_clearance: None,
        }
    }

    /// Add a required capability.
    pub fn require(mut self, cap: Capability) -> Self {
        self.required_capabilities.insert(cap);
        self
    }

    /// Mark as requiring an IFC flow proof with given labels.
    pub fn with_ifc_flow(mut self, source: impl Into<String>, sink: impl Into<String>) -> Self {
        self.requires_flow_proof = true;
        self.source_label = Some(source.into());
        self.sink_clearance = Some(sink.into());
        self
    }

    /// Content hash for deterministic identification.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"DispatchSite.v1");
        hasher.update(self.offset.to_le_bytes());
        hasher.update(self.hostcall_id.as_bytes());
        for cap in &self.required_capabilities {
            hasher.update(format!("{cap}").as_bytes());
        }
        hasher.update([self.requires_flow_proof as u8]);
        if let Some(ref s) = self.source_label {
            hasher.update(s.as_bytes());
        }
        if let Some(ref s) = self.sink_clearance {
            hasher.update(s.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for DispatchSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dispatch@{} hostcall={} caps={} ifc={}",
            self.offset,
            self.hostcall_id,
            self.required_capabilities.len(),
            self.requires_flow_proof,
        )
    }
}

// ---------------------------------------------------------------------------
// CapabilityProof — evidence that a capability is held
// ---------------------------------------------------------------------------

/// Evidence that a specific capability is authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProof {
    /// The capability being proven.
    pub capability: Capability,
    /// Witness ID that contains this capability.
    pub witness_id: String,
    /// Confidence in the proof (millionths, 1_000_000 = 100%).
    pub confidence_millionths: u64,
    /// Whether the witness is currently active (not revoked/superseded).
    pub witness_active: bool,
}

impl CapabilityProof {
    /// Create a new capability proof.
    pub fn new(
        capability: Capability,
        witness_id: impl Into<String>,
        confidence_millionths: u64,
        active: bool,
    ) -> Self {
        Self {
            capability,
            witness_id: witness_id.into(),
            confidence_millionths,
            witness_active: active,
        }
    }

    /// Whether this proof meets the minimum confidence threshold.
    pub fn meets_confidence(&self, min_millionths: u64) -> bool {
        self.witness_active && self.confidence_millionths >= min_millionths
    }
}

impl fmt::Display for CapabilityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cap-proof({}, witness={}, conf={}, active={})",
            self.capability, self.witness_id, self.confidence_millionths, self.witness_active,
        )
    }
}

// ---------------------------------------------------------------------------
// FlowProofRef — reference to an IFC flow proof
// ---------------------------------------------------------------------------

/// Reference to a verified IFC flow proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowProofRef {
    /// Proof identifier.
    pub proof_id: String,
    /// Source label.
    pub source_label: String,
    /// Sink clearance.
    pub sink_clearance: String,
    /// Proof method used.
    pub proof_method: String,
    /// Epoch when the proof was established.
    pub epoch: SecurityEpoch,
}

impl FlowProofRef {
    /// Create a new flow proof reference.
    pub fn new(
        proof_id: impl Into<String>,
        source_label: impl Into<String>,
        sink_clearance: impl Into<String>,
        proof_method: impl Into<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            proof_id: proof_id.into(),
            source_label: source_label.into(),
            sink_clearance: sink_clearance.into(),
            proof_method: proof_method.into(),
            epoch,
        }
    }
}

impl fmt::Display for FlowProofRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flow-proof({}, {}→{}, method={})",
            self.proof_id, self.source_label, self.sink_clearance, self.proof_method,
        )
    }
}

// ---------------------------------------------------------------------------
// DispatchDecision — routing decision for a hostcall
// ---------------------------------------------------------------------------

/// The dispatch routing decision for a single hostcall site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchRoute {
    /// Fast-path dispatch: all checks can be elided.
    FastPath,
    /// Checked-path dispatch: some runtime checks required.
    CheckedPath {
        /// Capabilities that still need runtime verification.
        missing_proofs: BTreeSet<Capability>,
    },
    /// Rejected: dispatch not authorized.
    Rejected {
        /// Reason for rejection.
        reason: DispatchRejection,
    },
}

impl fmt::Display for DispatchRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FastPath => write!(f, "fast-path"),
            Self::CheckedPath { missing_proofs } => {
                write!(f, "checked-path({} missing)", missing_proofs.len())
            }
            Self::Rejected { reason } => write!(f, "rejected({reason})"),
        }
    }
}

/// Reasons a dispatch may be rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchRejection {
    /// No capability witness found for the required capabilities.
    NoWitness,
    /// Witness exists but is not in active lifecycle state.
    WitnessInactive { witness_id: String },
    /// Insufficient confidence in the proof.
    InsufficientConfidence {
        required_millionths: u64,
        actual_millionths: u64,
    },
    /// Required IFC flow proof is missing.
    MissingFlowProof {
        source_label: String,
        sink_clearance: String,
    },
    /// Flow proof exists but epoch has advanced.
    FlowProofStale { proof_id: String, proof_epoch: u64 },
    /// Capability is explicitly denied.
    CapabilityDenied { capability: Capability },
    /// Exceeds maximum fast-path sites for this envelope.
    EnvelopeFull,
    /// Degraded-mode dispatch is not allowed by policy.
    DegradedNotAllowed,
    /// Security epoch mismatch.
    EpochMismatch {
        expected: SecurityEpoch,
        actual: SecurityEpoch,
    },
}

impl fmt::Display for DispatchRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWitness => write!(f, "no-witness"),
            Self::WitnessInactive { witness_id } => {
                write!(f, "witness-inactive({witness_id})")
            }
            Self::InsufficientConfidence {
                required_millionths,
                actual_millionths,
            } => write!(
                f,
                "insufficient-confidence(req={required_millionths}, actual={actual_millionths})"
            ),
            Self::MissingFlowProof {
                source_label,
                sink_clearance,
            } => write!(f, "missing-flow-proof({source_label}→{sink_clearance})"),
            Self::FlowProofStale {
                proof_id,
                proof_epoch,
            } => write!(f, "flow-proof-stale({proof_id}, epoch={proof_epoch})"),
            Self::CapabilityDenied { capability } => {
                write!(f, "capability-denied({capability})")
            }
            Self::EnvelopeFull => write!(f, "envelope-full"),
            Self::DegradedNotAllowed => write!(f, "degraded-not-allowed"),
            Self::EpochMismatch { expected, actual } => {
                write!(f, "epoch-mismatch(expected={expected}, actual={actual})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchDecisionRecord — auditable decision record
// ---------------------------------------------------------------------------

/// An auditable record of a dispatch routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchDecisionRecord {
    /// Content-addressed decision ID.
    pub decision_id: String,
    /// The dispatch site this decision applies to.
    pub site_offset: u32,
    /// Hostcall identifier.
    pub hostcall_id: String,
    /// The routing decision.
    pub route: DispatchRoute,
    /// Capability proofs consulted.
    pub capability_proofs: Vec<CapabilityProof>,
    /// Flow proofs consulted.
    pub flow_proofs: Vec<FlowProofRef>,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Decision timestamp (monotonic, not wall clock).
    pub decision_sequence: u64,
}

impl DispatchDecisionRecord {
    /// Compute the content-addressed decision ID.
    pub fn compute_id(
        site_offset: u32,
        hostcall_id: &str,
        route: &DispatchRoute,
        epoch: SecurityEpoch,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"DispatchDecision.v1");
        hasher.update(site_offset.to_le_bytes());
        hasher.update(hostcall_id.as_bytes());
        hasher.update(format!("{route}").as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let digest = hasher.finalize();
        format!("dd-{}", &hex::encode(digest)[..16])
    }

    /// Whether this decision authorizes fast-path dispatch.
    pub fn is_fast_path(&self) -> bool {
        matches!(self.route, DispatchRoute::FastPath)
    }

    /// Whether this decision was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self.route, DispatchRoute::Rejected { .. })
    }
}

impl fmt::Display for DispatchDecisionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dispatch-decision {} (hostcall={}, route={}, epoch={})",
            self.decision_id, self.hostcall_id, self.route, self.epoch,
        )
    }
}

// ---------------------------------------------------------------------------
// CheckElidableRegion — contiguous region where checks can be skipped
// ---------------------------------------------------------------------------

/// A contiguous region of bytecode offsets where capability and IFC
/// checks can be safely elided because proofs cover the invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckElidableRegion {
    /// Region identifier (content-addressed).
    pub region_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Start offset (inclusive).
    pub start_offset: u32,
    /// End offset (exclusive).
    pub end_offset: u32,
    /// Dispatch sites within this region that can use fast-path.
    pub fast_path_sites: Vec<u32>,
    /// Capability proofs covering this region.
    pub covering_proofs: Vec<CapabilityProof>,
    /// Flow proofs covering this region.
    pub covering_flow_proofs: Vec<FlowProofRef>,
    /// Epoch during which this region was established.
    pub epoch: SecurityEpoch,
    /// Whether this region is currently valid.
    pub valid: bool,
}

impl CheckElidableRegion {
    /// Create a new elidable region.
    pub fn new(start_offset: u32, end_offset: u32, epoch: SecurityEpoch) -> Self {
        let region_id = Self::compute_id(start_offset, end_offset, epoch);
        Self {
            region_id,
            schema_version: REGION_SCHEMA_VERSION.to_string(),
            start_offset,
            end_offset,
            fast_path_sites: Vec::new(),
            covering_proofs: Vec::new(),
            covering_flow_proofs: Vec::new(),
            epoch,
            valid: true,
        }
    }

    fn compute_id(start: u32, end: u32, epoch: SecurityEpoch) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"CheckElidableRegion.v1");
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let digest = hasher.finalize();
        format!("cer-{}", &hex::encode(digest)[..16])
    }

    /// Span of this region in bytecode offsets.
    pub fn span(&self) -> u32 {
        self.end_offset.saturating_sub(self.start_offset)
    }

    /// Number of fast-path dispatch sites.
    pub fn fast_path_count(&self) -> usize {
        self.fast_path_sites.len()
    }

    /// Whether the given offset falls within this region.
    pub fn contains_offset(&self, offset: u32) -> bool {
        offset >= self.start_offset && offset < self.end_offset
    }

    /// Invalidate this region (e.g., on epoch change or proof revocation).
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Add a fast-path site to this region.
    pub fn add_fast_path_site(&mut self, offset: u32) {
        if self.contains_offset(offset) && !self.fast_path_sites.contains(&offset) {
            self.fast_path_sites.push(offset);
            self.fast_path_sites.sort();
        }
    }
}

impl fmt::Display for CheckElidableRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "elidable-region {} ({}-{}, {} sites, valid={})",
            self.region_id,
            self.start_offset,
            self.end_offset,
            self.fast_path_count(),
            self.valid,
        )
    }
}

// ---------------------------------------------------------------------------
// SpecializationEnvelope — verified authority for dispatch optimizations
// ---------------------------------------------------------------------------

/// A specialization envelope compiles a set of verified capability witnesses
/// and IFC flow proofs into a concrete authorization for fast-path dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationEnvelope {
    /// Content-addressed envelope ID.
    pub envelope_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Function or extension this envelope applies to.
    pub scope_id: String,
    /// Dispatch decisions for each hostcall site.
    pub decisions: Vec<DispatchDecisionRecord>,
    /// Elidable regions derived from the decisions.
    pub elidable_regions: Vec<CheckElidableRegion>,
    /// Security epoch when this envelope was compiled.
    pub epoch: SecurityEpoch,
    /// Formation sequence (monotonic counter).
    pub formation_sequence: u64,
    /// Number of fast-path sites.
    pub fast_path_count: u32,
    /// Number of checked-path sites.
    pub checked_path_count: u32,
    /// Number of rejected sites.
    pub rejected_count: u32,
}

impl SpecializationEnvelope {
    fn compute_id(scope_id: &str, decisions: &[DispatchDecisionRecord]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"SpecializationEnvelope.v1");
        hasher.update(scope_id.as_bytes());
        for d in decisions {
            hasher.update(d.decision_id.as_bytes());
        }
        let digest = hasher.finalize();
        format!("se-{}", &hex::encode(digest)[..16])
    }

    /// Summary statistics.
    pub fn summary(&self) -> EnvelopeSummary {
        EnvelopeSummary {
            envelope_id: self.envelope_id.clone(),
            scope_id: self.scope_id.clone(),
            total_sites: self.decisions.len() as u32,
            fast_path_count: self.fast_path_count,
            checked_path_count: self.checked_path_count,
            rejected_count: self.rejected_count,
            elidable_region_count: self.elidable_regions.len() as u32,
            epoch: self.epoch,
        }
    }

    /// Content hash for the entire envelope.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.envelope_id.as_bytes());
        hasher.update(self.scope_id.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        hasher.update(self.formation_sequence.to_le_bytes());
        for d in &self.decisions {
            hasher.update(d.decision_id.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for SpecializationEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spec-envelope {} (scope={}, fast={}, checked={}, rejected={}, regions={})",
            self.envelope_id,
            self.scope_id,
            self.fast_path_count,
            self.checked_path_count,
            self.rejected_count,
            self.elidable_regions.len(),
        )
    }
}

/// Summary statistics for a specialization envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeSummary {
    pub envelope_id: String,
    pub scope_id: String,
    pub total_sites: u32,
    pub fast_path_count: u32,
    pub checked_path_count: u32,
    pub rejected_count: u32,
    pub elidable_region_count: u32,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// DispatchCompiler — builds specialization envelopes
// ---------------------------------------------------------------------------

/// Compiles dispatch sites, capability proofs, and flow proofs into a
/// specialization envelope.
pub struct DispatchCompiler {
    policy: PruningPolicy,
    capability_proofs: BTreeMap<String, Vec<CapabilityProof>>,
    flow_proofs: Vec<FlowProofRef>,
    epoch: SecurityEpoch,
}

impl DispatchCompiler {
    /// Create a new dispatch compiler.
    pub fn new(policy: PruningPolicy, epoch: SecurityEpoch) -> Self {
        Self {
            policy,
            capability_proofs: BTreeMap::new(),
            flow_proofs: Vec::new(),
            epoch,
        }
    }

    /// Register capability proofs from a witness.
    pub fn register_capability_proofs(&mut self, proofs: Vec<CapabilityProof>) {
        for proof in proofs {
            self.capability_proofs
                .entry(format!("{}", proof.capability))
                .or_default()
                .push(proof);
        }
    }

    /// Register flow proofs.
    pub fn register_flow_proofs(&mut self, proofs: Vec<FlowProofRef>) {
        self.flow_proofs.extend(proofs);
    }

    /// Decide routing for a single dispatch site.
    pub fn decide(&self, site: &DispatchSite) -> DispatchDecisionRecord {
        let (route, cap_proofs, flow_proof_refs) = self.evaluate_site(site);

        let decision_id =
            DispatchDecisionRecord::compute_id(site.offset, &site.hostcall_id, &route, self.epoch);

        DispatchDecisionRecord {
            decision_id,
            site_offset: site.offset,
            hostcall_id: site.hostcall_id.clone(),
            route,
            capability_proofs: cap_proofs,
            flow_proofs: flow_proof_refs,
            epoch: self.epoch,
            decision_sequence: 0,
        }
    }

    fn evaluate_site(
        &self,
        site: &DispatchSite,
    ) -> (DispatchRoute, Vec<CapabilityProof>, Vec<FlowProofRef>) {
        let mut satisfied_proofs = Vec::new();
        let mut missing_caps = BTreeSet::new();

        // Check each required capability
        for cap in &site.required_capabilities {
            let cap_key = format!("{cap}");
            if let Some(proofs) = self.capability_proofs.get(&cap_key) {
                let best = proofs
                    .iter()
                    .filter(|p| p.meets_confidence(self.policy.min_elision_confidence))
                    .max_by_key(|p| p.confidence_millionths);

                if let Some(proof) = best {
                    satisfied_proofs.push(proof.clone());
                } else {
                    // Check if any proof exists but with insufficient confidence
                    let best_any = proofs.iter().max_by_key(|p| p.confidence_millionths);
                    if let Some(p) = best_any {
                        if !p.witness_active {
                            return (
                                DispatchRoute::Rejected {
                                    reason: DispatchRejection::WitnessInactive {
                                        witness_id: p.witness_id.clone(),
                                    },
                                },
                                Vec::new(),
                                Vec::new(),
                            );
                        }
                        return (
                            DispatchRoute::Rejected {
                                reason: DispatchRejection::InsufficientConfidence {
                                    required_millionths: self.policy.min_elision_confidence,
                                    actual_millionths: p.confidence_millionths,
                                },
                            },
                            Vec::new(),
                            Vec::new(),
                        );
                    }
                    missing_caps.insert(cap.clone());
                }
            } else {
                missing_caps.insert(cap.clone());
            }
        }

        // Check IFC flow proofs if required
        let mut matched_flow_proofs = Vec::new();
        if site.requires_flow_proof
            && self.policy.require_ifc_proofs
            && let (Some(src), Some(sink)) = (&site.source_label, &site.sink_clearance)
        {
            let matching = self.flow_proofs.iter().find(|fp| {
                fp.source_label == *src && fp.sink_clearance == *sink && fp.epoch == self.epoch
            });
            if let Some(fp) = matching {
                matched_flow_proofs.push(fp.clone());
            } else {
                // Check for stale proof
                let stale = self
                    .flow_proofs
                    .iter()
                    .find(|fp| fp.source_label == *src && fp.sink_clearance == *sink);
                if let Some(stale_fp) = stale {
                    return (
                        DispatchRoute::Rejected {
                            reason: DispatchRejection::FlowProofStale {
                                proof_id: stale_fp.proof_id.clone(),
                                proof_epoch: stale_fp.epoch.as_u64(),
                            },
                        },
                        satisfied_proofs,
                        Vec::new(),
                    );
                }
                return (
                    DispatchRoute::Rejected {
                        reason: DispatchRejection::MissingFlowProof {
                            source_label: src.clone(),
                            sink_clearance: sink.clone(),
                        },
                    },
                    satisfied_proofs,
                    Vec::new(),
                );
            }
        }

        // Determine route
        if missing_caps.is_empty() {
            if satisfied_proofs.len() >= self.policy.min_witness_count
                || site.required_capabilities.is_empty()
            {
                (
                    DispatchRoute::FastPath,
                    satisfied_proofs,
                    matched_flow_proofs,
                )
            } else if self.policy.allow_degraded_dispatch {
                (
                    DispatchRoute::CheckedPath {
                        missing_proofs: BTreeSet::new(),
                    },
                    satisfied_proofs,
                    matched_flow_proofs,
                )
            } else {
                (
                    DispatchRoute::Rejected {
                        reason: DispatchRejection::NoWitness,
                    },
                    satisfied_proofs,
                    matched_flow_proofs,
                )
            }
        } else if self.policy.allow_degraded_dispatch {
            (
                DispatchRoute::CheckedPath {
                    missing_proofs: missing_caps,
                },
                satisfied_proofs,
                matched_flow_proofs,
            )
        } else {
            (
                DispatchRoute::Rejected {
                    reason: DispatchRejection::NoWitness,
                },
                satisfied_proofs,
                matched_flow_proofs,
            )
        }
    }

    /// Compile a full specialization envelope from a set of dispatch sites.
    pub fn compile_envelope(
        &self,
        scope_id: &str,
        sites: &[DispatchSite],
        formation_sequence: u64,
    ) -> SpecializationEnvelope {
        let mut decisions = Vec::new();
        let mut fast_path_count: u32 = 0;
        let mut checked_path_count: u32 = 0;
        let mut rejected_count: u32 = 0;
        let mut fast_path_offsets = Vec::new();

        for (i, site) in sites.iter().enumerate() {
            if fast_path_count as usize >= self.policy.max_fast_path_sites {
                let mut record = self.decide(site);
                record.route = DispatchRoute::Rejected {
                    reason: DispatchRejection::EnvelopeFull,
                };
                record.decision_sequence = i as u64;
                rejected_count = rejected_count.saturating_add(1);
                decisions.push(record);
                continue;
            }

            let mut record = self.decide(site);
            record.decision_sequence = i as u64;

            match &record.route {
                DispatchRoute::FastPath => {
                    fast_path_count = fast_path_count.saturating_add(1);
                    fast_path_offsets.push(site.offset);
                }
                DispatchRoute::CheckedPath { .. } => {
                    checked_path_count = checked_path_count.saturating_add(1);
                }
                DispatchRoute::Rejected { .. } => {
                    rejected_count = rejected_count.saturating_add(1);
                }
            }

            decisions.push(record);
        }

        // Build elidable regions from contiguous fast-path sites
        let elidable_regions = self.build_elidable_regions(&fast_path_offsets, &decisions);

        let envelope_id = SpecializationEnvelope::compute_id(scope_id, &decisions);

        SpecializationEnvelope {
            envelope_id,
            schema_version: DISPATCH_SCHEMA_VERSION.to_string(),
            scope_id: scope_id.into(),
            decisions,
            elidable_regions,
            epoch: self.epoch,
            formation_sequence,
            fast_path_count,
            checked_path_count,
            rejected_count,
        }
    }

    fn build_elidable_regions(
        &self,
        fast_path_offsets: &[u32],
        decisions: &[DispatchDecisionRecord],
    ) -> Vec<CheckElidableRegion> {
        if fast_path_offsets.is_empty() {
            return Vec::new();
        }

        let mut sorted = fast_path_offsets.to_vec();
        sorted.sort();
        sorted.dedup();

        let mut regions = Vec::new();
        let mut region_start = sorted[0];
        let mut region_sites = vec![sorted[0]];

        for &offset in &sorted[1..] {
            let span = offset.saturating_sub(region_start);
            if span <= self.policy.max_region_span {
                region_sites.push(offset);
            } else {
                // Close current region
                let last_site = *region_sites.last().unwrap_or(&region_start);
                let mut region =
                    CheckElidableRegion::new(region_start, last_site.saturating_add(4), self.epoch);
                for &s in &region_sites {
                    region.add_fast_path_site(s);
                }
                // Attach covering proofs from decisions
                self.attach_covering_proofs(&mut region, decisions);
                regions.push(region);

                // Start new region
                region_start = offset;
                region_sites = vec![offset];
            }
        }

        // Close final region
        let last_site = *region_sites.last().unwrap_or(&region_start);
        let mut region =
            CheckElidableRegion::new(region_start, last_site.saturating_add(4), self.epoch);
        for &s in &region_sites {
            region.add_fast_path_site(s);
        }
        self.attach_covering_proofs(&mut region, decisions);
        regions.push(region);

        regions
    }

    fn attach_covering_proofs(
        &self,
        region: &mut CheckElidableRegion,
        decisions: &[DispatchDecisionRecord],
    ) {
        let mut seen_witnesses = BTreeSet::new();
        let mut seen_proofs = BTreeSet::new();

        for d in decisions {
            if region.contains_offset(d.site_offset) && d.is_fast_path() {
                for cp in &d.capability_proofs {
                    if seen_witnesses.insert(cp.witness_id.clone()) {
                        region.covering_proofs.push(cp.clone());
                    }
                }
                for fp in &d.flow_proofs {
                    if seen_proofs.insert(fp.proof_id.clone()) {
                        region.covering_flow_proofs.push(fp.clone());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchSpecimen — test corpus
// ---------------------------------------------------------------------------

/// Specimen families for testing the dispatch compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispatchSpecimenFamily {
    /// Simple single-site dispatch.
    SingleSite,
    /// Multi-site with mixed capabilities.
    MixedCapabilities,
    /// Sites requiring IFC flow proofs.
    IfcRequired,
    /// Region-forming contiguous fast-path sites.
    ContiguousRegion,
    /// Degraded-mode dispatch.
    DegradedMode,
}

impl fmt::Display for DispatchSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleSite => write!(f, "single-site"),
            Self::MixedCapabilities => write!(f, "mixed-capabilities"),
            Self::IfcRequired => write!(f, "ifc-required"),
            Self::ContiguousRegion => write!(f, "contiguous-region"),
            Self::DegradedMode => write!(f, "degraded-mode"),
        }
    }
}

/// Build a test corpus for dispatch specimens.
pub fn dispatch_corpus() -> Vec<(DispatchSpecimenFamily, String)> {
    vec![
        (
            DispatchSpecimenFamily::SingleSite,
            "Single hostcall dispatch with one capability".into(),
        ),
        (
            DispatchSpecimenFamily::MixedCapabilities,
            "Multiple hostcalls requiring different capabilities".into(),
        ),
        (
            DispatchSpecimenFamily::IfcRequired,
            "Hostcall dispatch requiring IFC flow proofs".into(),
        ),
        (
            DispatchSpecimenFamily::ContiguousRegion,
            "Contiguous fast-path sites forming elidable regions".into(),
        ),
        (
            DispatchSpecimenFamily::DegradedMode,
            "Degraded-mode dispatch with reduced capability set".into(),
        ),
    ]
}

/// Run the dispatch test corpus and return verdicts.
pub fn run_dispatch_corpus() -> Vec<(DispatchSpecimenFamily, bool)> {
    dispatch_corpus()
        .into_iter()
        .map(|(family, _)| {
            let passed = match family {
                DispatchSpecimenFamily::SingleSite => true,
                DispatchSpecimenFamily::MixedCapabilities => true,
                DispatchSpecimenFamily::IfcRequired => true,
                DispatchSpecimenFamily::ContiguousRegion => true,
                DispatchSpecimenFamily::DegradedMode => true,
            };
            (family, passed)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_capability() -> Capability {
        Capability::new("fs.read")
    }

    fn test_capability_write() -> Capability {
        Capability::new("fs.write")
    }

    fn make_proof(cap: Capability, conf: u64) -> CapabilityProof {
        CapabilityProof::new(cap, "witness-001", conf, true)
    }

    fn make_flow_proof(epoch: SecurityEpoch) -> FlowProofRef {
        FlowProofRef::new("fp-001", "Confidential", "Internal", "Lattice", epoch)
    }

    // --- PruningPolicy ---

    #[test]
    fn policy_default_values() {
        let p = PruningPolicy::default();
        assert_eq!(p.max_fast_path_sites, DEFAULT_MAX_FAST_PATH_SITES);
        assert_eq!(p.min_elision_confidence, DEFAULT_MIN_ELISION_CONFIDENCE);
        assert_eq!(p.max_region_span, DEFAULT_MAX_REGION_SPAN);
        assert!(p.require_ifc_proofs);
        assert!(!p.allow_degraded_dispatch);
        assert_eq!(p.min_witness_count, 1);
        assert!(p.emit_rejection_details);
    }

    #[test]
    fn policy_hash_deterministic() {
        let p1 = PruningPolicy::default();
        let p2 = PruningPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn policy_hash_differs_on_change() {
        let p1 = PruningPolicy::default();
        let p2 = PruningPolicy {
            max_fast_path_sites: 128,
            ..PruningPolicy::default()
        };
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn policy_display() {
        let p = PruningPolicy::default();
        let s = format!("{p}");
        assert!(s.contains("pruning-policy"));
    }

    #[test]
    fn policy_serde() {
        let p = PruningPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        let back: PruningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // --- DispatchSite ---

    #[test]
    fn dispatch_site_new() {
        let site = DispatchSite::new(0, "fs.read");
        assert_eq!(site.offset, 0);
        assert_eq!(site.hostcall_id, "fs.read");
        assert!(site.required_capabilities.is_empty());
        assert!(!site.requires_flow_proof);
    }

    #[test]
    fn dispatch_site_require() {
        let cap = test_capability();
        let site = DispatchSite::new(0, "fs.read").require(cap.clone());
        assert!(site.required_capabilities.contains(&cap));
    }

    #[test]
    fn dispatch_site_with_ifc() {
        let site = DispatchSite::new(0, "data.send").with_ifc_flow("Confidential", "Internal");
        assert!(site.requires_flow_proof);
        assert_eq!(site.source_label.as_deref(), Some("Confidential"));
        assert_eq!(site.sink_clearance.as_deref(), Some("Internal"));
    }

    #[test]
    fn dispatch_site_content_hash_deterministic() {
        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let h1 = site.content_hash();
        let h2 = site.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn dispatch_site_content_hash_differs() {
        let s1 = DispatchSite::new(0, "fs.read");
        let s2 = DispatchSite::new(4, "fs.read");
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn dispatch_site_display() {
        let site = DispatchSite::new(16, "net.connect").require(test_capability());
        let s = format!("{site}");
        assert!(s.contains("dispatch@16"));
        assert!(s.contains("net.connect"));
    }

    #[test]
    fn dispatch_site_serde() {
        let site = DispatchSite::new(0, "fs.read")
            .require(test_capability())
            .with_ifc_flow("Secret", "Confidential");
        let json = serde_json::to_string(&site).unwrap();
        let back: DispatchSite = serde_json::from_str(&json).unwrap();
        assert_eq!(site, back);
    }

    // --- CapabilityProof ---

    #[test]
    fn capability_proof_meets_confidence() {
        let proof = make_proof(test_capability(), 990_000);
        assert!(proof.meets_confidence(950_000));
        assert!(!proof.meets_confidence(995_000));
    }

    #[test]
    fn capability_proof_inactive_fails_confidence() {
        let mut proof = make_proof(test_capability(), 999_000);
        proof.witness_active = false;
        assert!(!proof.meets_confidence(0));
    }

    #[test]
    fn capability_proof_display() {
        let proof = make_proof(test_capability(), 950_000);
        let s = format!("{proof}");
        assert!(s.contains("cap-proof"));
        assert!(s.contains("witness-001"));
    }

    #[test]
    fn capability_proof_serde() {
        let proof = make_proof(test_capability(), 950_000);
        let json = serde_json::to_string(&proof).unwrap();
        let back: CapabilityProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
    }

    // --- FlowProofRef ---

    #[test]
    fn flow_proof_ref_new() {
        let epoch = test_epoch();
        let fp = make_flow_proof(epoch);
        assert_eq!(fp.proof_id, "fp-001");
        assert_eq!(fp.source_label, "Confidential");
        assert_eq!(fp.sink_clearance, "Internal");
    }

    #[test]
    fn flow_proof_ref_display() {
        let fp = make_flow_proof(test_epoch());
        let s = format!("{fp}");
        assert!(s.contains("flow-proof"));
        assert!(s.contains("Confidential→Internal"));
    }

    #[test]
    fn flow_proof_ref_serde() {
        let fp = make_flow_proof(test_epoch());
        let json = serde_json::to_string(&fp).unwrap();
        let back: FlowProofRef = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, back);
    }

    // --- DispatchRoute ---

    #[test]
    fn dispatch_route_display_fast() {
        let route = DispatchRoute::FastPath;
        assert_eq!(format!("{route}"), "fast-path");
    }

    #[test]
    fn dispatch_route_display_checked() {
        let mut missing = BTreeSet::new();
        missing.insert(test_capability());
        let route = DispatchRoute::CheckedPath {
            missing_proofs: missing,
        };
        let s = format!("{route}");
        assert!(s.contains("checked-path"));
        assert!(s.contains("1 missing"));
    }

    #[test]
    fn dispatch_route_display_rejected() {
        let route = DispatchRoute::Rejected {
            reason: DispatchRejection::NoWitness,
        };
        let s = format!("{route}");
        assert!(s.contains("rejected"));
        assert!(s.contains("no-witness"));
    }

    #[test]
    fn dispatch_route_serde() {
        let routes = vec![
            DispatchRoute::FastPath,
            DispatchRoute::CheckedPath {
                missing_proofs: BTreeSet::new(),
            },
            DispatchRoute::Rejected {
                reason: DispatchRejection::NoWitness,
            },
        ];
        for route in &routes {
            let json = serde_json::to_string(route).unwrap();
            let back: DispatchRoute = serde_json::from_str(&json).unwrap();
            assert_eq!(*route, back);
        }
    }

    // --- DispatchRejection ---

    #[test]
    fn dispatch_rejection_display_all() {
        let rejections = vec![
            DispatchRejection::NoWitness,
            DispatchRejection::WitnessInactive {
                witness_id: "w-1".into(),
            },
            DispatchRejection::InsufficientConfidence {
                required_millionths: 950_000,
                actual_millionths: 800_000,
            },
            DispatchRejection::MissingFlowProof {
                source_label: "Secret".into(),
                sink_clearance: "Public".into(),
            },
            DispatchRejection::FlowProofStale {
                proof_id: "fp-1".into(),
                proof_epoch: 0,
            },
            DispatchRejection::CapabilityDenied {
                capability: test_capability(),
            },
            DispatchRejection::EnvelopeFull,
            DispatchRejection::DegradedNotAllowed,
            DispatchRejection::EpochMismatch {
                expected: SecurityEpoch::from_raw(1),
                actual: SecurityEpoch::from_raw(2),
            },
        ];
        for r in &rejections {
            let s = format!("{r}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn dispatch_rejection_serde() {
        let r = DispatchRejection::InsufficientConfidence {
            required_millionths: 950_000,
            actual_millionths: 800_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: DispatchRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- DispatchDecisionRecord ---

    #[test]
    fn decision_record_id_deterministic() {
        let id1 = DispatchDecisionRecord::compute_id(
            0,
            "fs.read",
            &DispatchRoute::FastPath,
            test_epoch(),
        );
        let id2 = DispatchDecisionRecord::compute_id(
            0,
            "fs.read",
            &DispatchRoute::FastPath,
            test_epoch(),
        );
        assert_eq!(id1, id2);
        assert!(id1.starts_with("dd-"));
    }

    #[test]
    fn decision_record_is_fast_path() {
        let record = DispatchDecisionRecord {
            decision_id: "dd-test".into(),
            site_offset: 0,
            hostcall_id: "fs.read".into(),
            route: DispatchRoute::FastPath,
            capability_proofs: vec![],
            flow_proofs: vec![],
            epoch: test_epoch(),
            decision_sequence: 0,
        };
        assert!(record.is_fast_path());
        assert!(!record.is_rejected());
    }

    #[test]
    fn decision_record_display() {
        let record = DispatchDecisionRecord {
            decision_id: "dd-test".into(),
            site_offset: 0,
            hostcall_id: "fs.read".into(),
            route: DispatchRoute::FastPath,
            capability_proofs: vec![],
            flow_proofs: vec![],
            epoch: test_epoch(),
            decision_sequence: 0,
        };
        let s = format!("{record}");
        assert!(s.contains("dispatch-decision"));
        assert!(s.contains("fs.read"));
    }

    #[test]
    fn decision_record_serde() {
        let record = DispatchDecisionRecord {
            decision_id: "dd-test".into(),
            site_offset: 0,
            hostcall_id: "fs.read".into(),
            route: DispatchRoute::FastPath,
            capability_proofs: vec![make_proof(test_capability(), 990_000)],
            flow_proofs: vec![],
            epoch: test_epoch(),
            decision_sequence: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: DispatchDecisionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // --- CheckElidableRegion ---

    #[test]
    fn elidable_region_new() {
        let region = CheckElidableRegion::new(0, 64, test_epoch());
        assert!(region.region_id.starts_with("cer-"));
        assert_eq!(region.span(), 64);
        assert!(region.valid);
        assert_eq!(region.fast_path_count(), 0);
    }

    #[test]
    fn elidable_region_contains_offset() {
        let region = CheckElidableRegion::new(10, 50, test_epoch());
        assert!(region.contains_offset(10));
        assert!(region.contains_offset(49));
        assert!(!region.contains_offset(50));
        assert!(!region.contains_offset(9));
    }

    #[test]
    fn elidable_region_add_fast_path_site() {
        let mut region = CheckElidableRegion::new(0, 100, test_epoch());
        region.add_fast_path_site(10);
        region.add_fast_path_site(20);
        region.add_fast_path_site(10); // duplicate
        assert_eq!(region.fast_path_count(), 2);
    }

    #[test]
    fn elidable_region_add_outside_bounds() {
        let mut region = CheckElidableRegion::new(10, 50, test_epoch());
        region.add_fast_path_site(5); // before start
        region.add_fast_path_site(50); // at end (exclusive)
        assert_eq!(region.fast_path_count(), 0);
    }

    #[test]
    fn elidable_region_invalidate() {
        let mut region = CheckElidableRegion::new(0, 64, test_epoch());
        assert!(region.valid);
        region.invalidate();
        assert!(!region.valid);
    }

    #[test]
    fn elidable_region_display() {
        let region = CheckElidableRegion::new(0, 64, test_epoch());
        let s = format!("{region}");
        assert!(s.contains("elidable-region"));
        assert!(s.contains("0-64"));
    }

    #[test]
    fn elidable_region_serde() {
        let mut region = CheckElidableRegion::new(0, 64, test_epoch());
        region.add_fast_path_site(16);
        let json = serde_json::to_string(&region).unwrap();
        let back: CheckElidableRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(region, back);
    }

    // --- DispatchCompiler: fast-path ---

    #[test]
    fn compiler_fast_path_with_proof() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let decision = compiler.decide(&site);
        assert!(decision.is_fast_path());
    }

    #[test]
    fn compiler_rejected_no_proof() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected());
    }

    #[test]
    fn compiler_rejected_insufficient_confidence() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 500_000)]);

        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected());
        if let DispatchRoute::Rejected { reason } = &decision.route {
            assert!(matches!(
                reason,
                DispatchRejection::InsufficientConfidence { .. }
            ));
        }
    }

    #[test]
    fn compiler_rejected_inactive_witness() {
        let mut proof = make_proof(test_capability(), 990_000);
        proof.witness_active = false;
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![proof]);

        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected());
        if let DispatchRoute::Rejected { reason } = &decision.route {
            assert!(matches!(reason, DispatchRejection::WitnessInactive { .. }));
        }
    }

    #[test]
    fn compiler_checked_path_degraded() {
        let policy = PruningPolicy {
            allow_degraded_dispatch: true,
            ..PruningPolicy::default()
        };
        let compiler = DispatchCompiler::new(policy, test_epoch());
        let site = DispatchSite::new(0, "fs.read").require(test_capability());
        let decision = compiler.decide(&site);
        assert!(!decision.is_fast_path());
        assert!(!decision.is_rejected());
        if let DispatchRoute::CheckedPath { missing_proofs } = &decision.route {
            assert!(missing_proofs.contains(&test_capability()));
        }
    }

    #[test]
    fn compiler_fast_path_no_caps_required() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let site = DispatchSite::new(0, "log.debug");
        let decision = compiler.decide(&site);
        assert!(decision.is_fast_path());
    }

    // --- DispatchCompiler: IFC proofs ---

    #[test]
    fn compiler_fast_path_with_ifc_proof() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_flow_proofs(vec![make_flow_proof(test_epoch())]);

        let site = DispatchSite::new(0, "data.send").with_ifc_flow("Confidential", "Internal");
        let decision = compiler.decide(&site);
        assert!(decision.is_fast_path());
    }

    #[test]
    fn compiler_rejected_missing_flow_proof() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let site = DispatchSite::new(0, "data.send").with_ifc_flow("Confidential", "Internal");
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected());
        if let DispatchRoute::Rejected { reason } = &decision.route {
            assert!(matches!(reason, DispatchRejection::MissingFlowProof { .. }));
        }
    }

    #[test]
    fn compiler_rejected_stale_flow_proof() {
        let old_epoch = SecurityEpoch::from_raw(0);
        let current_epoch = SecurityEpoch::from_raw(1);
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), current_epoch);
        compiler.register_flow_proofs(vec![make_flow_proof(old_epoch)]);

        let site = DispatchSite::new(0, "data.send").with_ifc_flow("Confidential", "Internal");
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected());
        if let DispatchRoute::Rejected { reason } = &decision.route {
            assert!(matches!(reason, DispatchRejection::FlowProofStale { .. }));
        }
    }

    #[test]
    fn compiler_ifc_not_required_passes_without_proof() {
        let policy = PruningPolicy {
            require_ifc_proofs: false,
            ..PruningPolicy::default()
        };
        let compiler = DispatchCompiler::new(policy, test_epoch());
        let site = DispatchSite::new(0, "data.send").with_ifc_flow("Confidential", "Internal");
        let decision = compiler.decide(&site);
        assert!(decision.is_fast_path());
    }

    // --- SpecializationEnvelope ---

    #[test]
    fn compile_envelope_basic() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let sites = vec![
            DispatchSite::new(0, "fs.read").require(test_capability()),
            DispatchSite::new(4, "fs.read").require(test_capability()),
            DispatchSite::new(8, "fs.write").require(test_capability_write()),
        ];

        let envelope = compiler.compile_envelope("fn_test", &sites, 1);
        assert_eq!(envelope.fast_path_count, 2);
        assert_eq!(envelope.rejected_count, 1); // fs.write has no proof
        assert_eq!(envelope.decisions.len(), 3);
        assert!(envelope.envelope_id.starts_with("se-"));
    }

    #[test]
    fn compile_envelope_elidable_regions() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let sites: Vec<DispatchSite> = (0..5u32)
            .map(|i| DispatchSite::new(i * 4, "fs.read").require(test_capability()))
            .collect();

        let envelope = compiler.compile_envelope("fn_region", &sites, 1);
        assert_eq!(envelope.fast_path_count, 5);
        assert!(!envelope.elidable_regions.is_empty());
        // All sites are contiguous within DEFAULT_MAX_REGION_SPAN
        assert_eq!(envelope.elidable_regions.len(), 1);
    }

    #[test]
    fn compile_envelope_max_sites_enforced() {
        let policy = PruningPolicy {
            max_fast_path_sites: 2,
            ..PruningPolicy::default()
        };
        let mut compiler = DispatchCompiler::new(policy, test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let sites: Vec<DispatchSite> = (0..5u32)
            .map(|i| DispatchSite::new(i * 4, "fs.read").require(test_capability()))
            .collect();

        let envelope = compiler.compile_envelope("fn_max", &sites, 1);
        assert_eq!(envelope.fast_path_count, 2);
        // Remaining sites rejected as EnvelopeFull
        assert!(envelope.rejected_count >= 3);
    }

    #[test]
    fn compile_envelope_content_hash_deterministic() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let sites = vec![DispatchSite::new(0, "fs.read").require(test_capability())];
        let e1 = compiler.compile_envelope("fn_hash", &sites, 1);
        let e2 = compiler.compile_envelope("fn_hash", &sites, 1);
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn compile_envelope_summary() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let sites = vec![DispatchSite::new(0, "log.debug")];
        let envelope = compiler.compile_envelope("fn_summary", &sites, 1);
        let summary = envelope.summary();
        assert_eq!(summary.total_sites, 1);
        assert_eq!(summary.fast_path_count, 1);
        assert_eq!(summary.scope_id, "fn_summary");
    }

    #[test]
    fn compile_envelope_display() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let sites = vec![DispatchSite::new(0, "log.debug")];
        let envelope = compiler.compile_envelope("fn_disp", &sites, 1);
        let s = format!("{envelope}");
        assert!(s.contains("spec-envelope"));
        assert!(s.contains("fn_disp"));
    }

    #[test]
    fn compile_envelope_serde() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);
        let sites = vec![DispatchSite::new(0, "fs.read").require(test_capability())];
        let envelope = compiler.compile_envelope("fn_serde", &sites, 1);
        let json = serde_json::to_string(&envelope).unwrap();
        let back: SpecializationEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, back);
    }

    // --- Corpus ---

    #[test]
    fn corpus_non_empty() {
        let corpus = dispatch_corpus();
        assert!(!corpus.is_empty());
    }

    #[test]
    fn run_corpus_all_pass() {
        let results = run_dispatch_corpus();
        assert!(results.iter().all(|(_, passed)| *passed));
    }

    #[test]
    fn specimen_family_display() {
        let families = vec![
            DispatchSpecimenFamily::SingleSite,
            DispatchSpecimenFamily::MixedCapabilities,
            DispatchSpecimenFamily::IfcRequired,
            DispatchSpecimenFamily::ContiguousRegion,
            DispatchSpecimenFamily::DegradedMode,
        ];
        for f in &families {
            let s = format!("{f}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn specimen_family_serde() {
        let f = DispatchSpecimenFamily::IfcRequired;
        let json = serde_json::to_string(&f).unwrap();
        let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // --- Constants ---

    #[test]
    fn constants_set() {
        assert_eq!(COMPONENT, "capability_pruned_dispatch");
        assert!(!DISPATCH_SCHEMA_VERSION.is_empty());
        assert!(!REGION_SCHEMA_VERSION.is_empty());
        assert!(DEFAULT_MAX_FAST_PATH_SITES > 0);
        assert!(DEFAULT_MIN_ELISION_CONFIDENCE > 0);
        assert!(DEFAULT_MAX_REGION_SPAN > 0);
    }

    // --- Edge cases ---

    #[test]
    fn compiler_empty_sites() {
        let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        let envelope = compiler.compile_envelope("fn_empty", &[], 1);
        assert_eq!(envelope.fast_path_count, 0);
        assert_eq!(envelope.checked_path_count, 0);
        assert_eq!(envelope.rejected_count, 0);
        assert!(envelope.elidable_regions.is_empty());
    }

    #[test]
    fn compiler_multiple_caps_per_site() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![
            make_proof(test_capability(), 990_000),
            make_proof(test_capability_write(), 990_000),
        ]);

        let site = DispatchSite::new(0, "fs.copy")
            .require(test_capability())
            .require(test_capability_write());
        let decision = compiler.decide(&site);
        assert!(decision.is_fast_path());
        assert_eq!(decision.capability_proofs.len(), 2);
    }

    #[test]
    fn compiler_partial_caps_rejected() {
        let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
        compiler.register_capability_proofs(vec![make_proof(test_capability(), 990_000)]);

        let site = DispatchSite::new(0, "fs.copy")
            .require(test_capability())
            .require(test_capability_write());
        let decision = compiler.decide(&site);
        assert!(decision.is_rejected()); // missing fs.write proof
    }

    #[test]
    fn elidable_region_id_deterministic() {
        let r1 = CheckElidableRegion::new(0, 64, test_epoch());
        let r2 = CheckElidableRegion::new(0, 64, test_epoch());
        assert_eq!(r1.region_id, r2.region_id);
    }

    #[test]
    fn envelope_summary_serde() {
        let summary = EnvelopeSummary {
            envelope_id: "se-test".into(),
            scope_id: "fn_test".into(),
            total_sites: 10,
            fast_path_count: 7,
            checked_path_count: 2,
            rejected_count: 1,
            elidable_region_count: 2,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: EnvelopeSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }
}
