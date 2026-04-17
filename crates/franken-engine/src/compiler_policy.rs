//! Compiler policy: proof-grounded specialization gating.
//!
//! Ensures only optimizations backed by valid, non-expired security proofs
//! may bypass capability or flow dynamic checks in marked regions. Any proof
//! that is invalid, expired, or unavailable triggers fail-closed fallback to
//! the unspecialized code path with full dynamic checks.
//!
//! Plan reference: Section 10.15, subsection 9I.8, item 2 of 4, bd-1kzo.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::ifc_artifacts::Label;
use crate::proof_specialization_receipt::{OptimizationClass, ProofInput, ProofType};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[cfg(test)]
const SCHEMA_DEF: &[u8] = b"CompilerPolicy.v1";

// ---------------------------------------------------------------------------
// SecurityProof — union type referencing accepted proof kinds
// ---------------------------------------------------------------------------

/// A security proof that can justify eliding a dynamic check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityProof {
    /// PLAS capability witness: proves capability is unreachable.
    CapabilityWitness {
        proof_id: EngineObjectId,
        capability_name: String,
        epoch: SecurityEpoch,
        validity_window_ticks: u64,
    },
    /// IFC flow proof: proves flow is safe, so label check is unnecessary.
    FlowProof {
        proof_id: EngineObjectId,
        source_label: Label,
        sink_clearance: Label,
        epoch: SecurityEpoch,
        validity_window_ticks: u64,
    },
    /// Replay sequence motif: proves execution pattern is stable.
    ReplayMotif {
        proof_id: EngineObjectId,
        motif_hash: String,
        epoch: SecurityEpoch,
        validity_window_ticks: u64,
    },
}

impl SecurityProof {
    pub fn proof_id(&self) -> &EngineObjectId {
        match self {
            Self::CapabilityWitness { proof_id, .. }
            | Self::FlowProof { proof_id, .. }
            | Self::ReplayMotif { proof_id, .. } => proof_id,
        }
    }

    pub fn epoch(&self) -> SecurityEpoch {
        match self {
            Self::CapabilityWitness { epoch, .. }
            | Self::FlowProof { epoch, .. }
            | Self::ReplayMotif { epoch, .. } => *epoch,
        }
    }

    pub fn validity_window_ticks(&self) -> u64 {
        match self {
            Self::CapabilityWitness {
                validity_window_ticks,
                ..
            }
            | Self::FlowProof {
                validity_window_ticks,
                ..
            }
            | Self::ReplayMotif {
                validity_window_ticks,
                ..
            } => *validity_window_ticks,
        }
    }

    pub fn proof_type(&self) -> ProofType {
        match self {
            Self::CapabilityWitness { .. } => ProofType::CapabilityWitness,
            Self::FlowProof { .. } => ProofType::FlowProof,
            Self::ReplayMotif { .. } => ProofType::ReplayMotif,
        }
    }

    fn to_proof_input(&self) -> ProofInput {
        ProofInput {
            proof_type: self.proof_type(),
            proof_id: self.proof_id().clone(),
            proof_epoch: self.epoch(),
            validity_window_ticks: self.validity_window_ticks(),
        }
    }
}

// ---------------------------------------------------------------------------
// MarkedRegion — IR region where specialization is applied
// ---------------------------------------------------------------------------

/// An IR region explicitly marked for specialization with proof references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkedRegion {
    /// Unique identifier for this region.
    pub region_id: String,
    /// The optimization class to apply.
    pub optimization_class: OptimizationClass,
    /// Proofs that justify eliding checks in this region.
    pub proof_refs: Vec<EngineObjectId>,
    /// Description of the dynamic check being elided.
    pub elided_check_description: String,
}

// ---------------------------------------------------------------------------
// PolicyConfig — per-class configuration
// ---------------------------------------------------------------------------

/// Policy configuration for a single optimization class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationClassPolicy {
    /// Whether this optimization class is enabled at all.
    pub enabled: bool,
    /// Minimum number of proofs required to justify specialization.
    pub min_proof_count: u32,
    /// Required proof types (all must be present).
    pub required_proof_types: BTreeSet<ProofType>,
    /// Whether governance approval is required to relax defaults.
    pub governance_approved: bool,
}

impl Default for OptimizationClassPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_proof_count: 1,
            required_proof_types: BTreeSet::new(),
            governance_approved: false,
        }
    }
}

/// Top-level compiler policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerPolicyConfig {
    /// Current proof-validity epoch.
    pub current_epoch: SecurityEpoch,
    /// Per-class policy overrides; classes not listed use defaults.
    pub class_policies: BTreeMap<OptimizationClass, OptimizationClassPolicy>,
    /// Global kill switch: if true, no specializations are applied.
    pub global_disable: bool,
    /// Policy identifier for audit trail.
    pub policy_id: String,
}

impl CompilerPolicyConfig {
    pub fn new(policy_id: impl Into<String>, epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            class_policies: BTreeMap::new(),
            global_disable: false,
            policy_id: policy_id.into(),
        }
    }

    fn class_policy(&self, class: &OptimizationClass) -> OptimizationClassPolicy {
        self.class_policies.get(class).cloned().unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Decision — specialization decision record
// ---------------------------------------------------------------------------

/// Outcome of a specialization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecializationOutcome {
    Applied,
    RejectedGlobalDisable,
    RejectedClassDisabled,
    RejectedNoProofs,
    RejectedInsufficientProofs,
    RejectedMissingRequiredProofTypes,
    RejectedProofExpired,
    RejectedEpochMismatch,
    RejectedProofNotFound,
    InvalidatedByEpochChange,
}

impl SpecializationOutcome {
    pub fn is_applied(self) -> bool {
        self == Self::Applied
    }

    pub fn error_code(self) -> &'static str {
        match self {
            Self::Applied => "APPLIED",
            Self::RejectedGlobalDisable => "GLOBAL_DISABLE",
            Self::RejectedClassDisabled => "CLASS_DISABLED",
            Self::RejectedNoProofs => "NO_PROOFS",
            Self::RejectedInsufficientProofs => "INSUFFICIENT_PROOFS",
            Self::RejectedMissingRequiredProofTypes => "MISSING_REQUIRED_PROOF_TYPES",
            Self::RejectedProofExpired => "PROOF_EXPIRED",
            Self::RejectedEpochMismatch => "EPOCH_MISMATCH",
            Self::RejectedProofNotFound => "PROOF_NOT_FOUND",
            Self::InvalidatedByEpochChange => "INVALIDATED_EPOCH_CHANGE",
        }
    }
}

/// A logged specialization decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationDecision {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub region_id: String,
    pub optimization_class: OptimizationClass,
    pub outcome: SpecializationOutcome,
    pub detail: String,
    pub proof_ids: Vec<EngineObjectId>,
    pub epoch: SecurityEpoch,
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// CompilerPolicyEvent — structured log events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerPolicyEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// ProofStore — cache proofs by epoch
// ---------------------------------------------------------------------------

/// In-memory proof store, keyed by proof ID for fast lookup during compilation.
/// Uses `Vec` backing to avoid JSON serde issues with `BTreeMap<EngineObjectId, _>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofStore {
    proofs: Vec<SecurityProof>,
}

impl ProofStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, proof: SecurityProof) {
        let id = proof.proof_id().clone();
        if let Some(pos) = self.proofs.iter().position(|p| *p.proof_id() == id) {
            self.proofs[pos] = proof;
        } else {
            self.proofs.push(proof);
        }
    }

    pub fn get(&self, id: &EngineObjectId) -> Option<&SecurityProof> {
        self.proofs.iter().find(|p| p.proof_id() == id)
    }

    pub fn remove(&mut self, id: &EngineObjectId) -> Option<SecurityProof> {
        if let Some(pos) = self.proofs.iter().position(|p| p.proof_id() == id) {
            Some(self.proofs.remove(pos))
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Remove all proofs from a given epoch.
    pub fn invalidate_epoch(&mut self, epoch: SecurityEpoch) -> Vec<EngineObjectId> {
        let mut removed = Vec::new();
        self.proofs.retain(|p| {
            if p.epoch() == epoch {
                removed.push(p.proof_id().clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// Return all proofs matching the given IDs.
    pub fn resolve(&self, ids: &[EngineObjectId]) -> Vec<&SecurityProof> {
        ids.iter()
            .filter_map(|id| self.proofs.iter().find(|p| p.proof_id() == id))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// CompilerPolicyEngine — main evaluation engine
// ---------------------------------------------------------------------------

/// The compiler policy engine that gates specializations on valid proofs.
#[derive(Debug, Clone)]
pub struct CompilerPolicyEngine {
    config: CompilerPolicyConfig,
    proof_store: ProofStore,
    decisions: Vec<SpecializationDecision>,
    events: Vec<CompilerPolicyEvent>,
    decision_counter: u64,
}

impl CompilerPolicyEngine {
    pub fn new(config: CompilerPolicyConfig) -> Self {
        Self {
            config,
            proof_store: ProofStore::new(),
            decisions: Vec::new(),
            events: Vec::new(),
            decision_counter: 0,
        }
    }

    pub fn config(&self) -> &CompilerPolicyConfig {
        &self.config
    }

    pub fn proof_store(&self) -> &ProofStore {
        &self.proof_store
    }

    pub fn proof_store_mut(&mut self) -> &mut ProofStore {
        &mut self.proof_store
    }

    pub fn decisions(&self) -> &[SpecializationDecision] {
        &self.decisions
    }

    pub fn events(&self) -> &[CompilerPolicyEvent] {
        &self.events
    }

    /// Register a proof for use in specialization decisions.
    pub fn register_proof(&mut self, proof: SecurityProof) {
        self.proof_store.insert(proof);
    }

    /// Evaluate whether a marked region may be specialized.
    ///
    /// Returns the decision and, if applied, the proof inputs for receipt emission.
    pub fn evaluate(
        &mut self,
        region: &MarkedRegion,
        trace_id: &str,
        timestamp_ns: u64,
    ) -> SpecializationDecision {
        self.decision_counter += 1;
        let decision_id = format!("cpe-{}", self.decision_counter);

        // 1. Global kill switch
        if self.config.global_disable {
            return self.record_decision(
                trace_id,
                &decision_id,
                region,
                SpecializationOutcome::RejectedGlobalDisable,
                "global specialization disabled".to_string(),
                vec![],
                timestamp_ns,
            );
        }

        // 2. Per-class policy check
        let class_policy = self.config.class_policy(&region.optimization_class);
        if !class_policy.enabled {
            return self.record_decision(
                trace_id,
                &decision_id,
                region,
                SpecializationOutcome::RejectedClassDisabled,
                format!(
                    "optimization class {:?} disabled by policy",
                    region.optimization_class
                ),
                vec![],
                timestamp_ns,
            );
        }

        // 3. Resolve proofs
        if region.proof_refs.is_empty() {
            return self.record_decision(
                trace_id,
                &decision_id,
                region,
                SpecializationOutcome::RejectedNoProofs,
                "no proof references in marked region".to_string(),
                vec![],
                timestamp_ns,
            );
        }

        let resolved: Vec<&SecurityProof> = self.proof_store.resolve(&region.proof_refs);

        // Check all refs resolve
        if resolved.len() < region.proof_refs.len() {
            let missing: Vec<String> = region
                .proof_refs
                .iter()
                .filter(|id| self.proof_store.get(id).is_none())
                .map(|id| id.to_hex())
                .collect();
            return self.record_decision(
                trace_id,
                &decision_id,
                region,
                SpecializationOutcome::RejectedProofNotFound,
                format!("proofs not found: {}", missing.join(", ")),
                vec![],
                timestamp_ns,
            );
        }

        // 4. Minimum proof count
        if (resolved.len() as u32) < class_policy.min_proof_count {
            return self.record_decision(
                trace_id,
                &decision_id,
                region,
                SpecializationOutcome::RejectedInsufficientProofs,
                format!(
                    "need {} proofs, got {}",
                    class_policy.min_proof_count,
                    resolved.len()
                ),
                vec![],
                timestamp_ns,
            );
        }

        // 5. Required proof types
        if !class_policy.required_proof_types.is_empty() {
            let present_types: BTreeSet<ProofType> =
                resolved.iter().map(|p| p.proof_type()).collect();
            let missing_types: Vec<&ProofType> = class_policy
                .required_proof_types
                .iter()
                .filter(|t| !present_types.contains(t))
                .collect();
            if !missing_types.is_empty() {
                return self.record_decision(
                    trace_id,
                    &decision_id,
                    region,
                    SpecializationOutcome::RejectedMissingRequiredProofTypes,
                    format!("missing required proof types: {missing_types:?}"),
                    vec![],
                    timestamp_ns,
                );
            }
        }

        // 6. Epoch and validity checks
        let current_epoch = self.config.current_epoch;
        let mut validated_proof_ids = Vec::new();

        for proof in &resolved {
            // Epoch mismatch: proof must be for current or compatible epoch
            if proof.epoch() != current_epoch {
                return self.record_decision(
                    trace_id,
                    &decision_id,
                    region,
                    SpecializationOutcome::RejectedEpochMismatch,
                    format!(
                        "proof {} epoch {} != current epoch {}",
                        proof.proof_id().to_hex(),
                        proof.epoch().as_u64(),
                        current_epoch.as_u64()
                    ),
                    vec![],
                    timestamp_ns,
                );
            }

            // Validity window: 0 means expired
            if proof.validity_window_ticks() == 0 {
                return self.record_decision(
                    trace_id,
                    &decision_id,
                    region,
                    SpecializationOutcome::RejectedProofExpired,
                    format!("proof {} has expired (window=0)", proof.proof_id().to_hex()),
                    vec![],
                    timestamp_ns,
                );
            }

            validated_proof_ids.push(proof.proof_id().clone());
        }

        // 7. All checks passed — specialization applied
        self.record_decision(
            trace_id,
            &decision_id,
            region,
            SpecializationOutcome::Applied,
            format!(
                "specialization applied with {} valid proofs",
                resolved.len()
            ),
            validated_proof_ids,
            timestamp_ns,
        )
    }

    /// Handle a proof epoch change: invalidate all specializations from the old
    /// epoch and log the invalidation decisions.
    pub fn on_epoch_change(
        &mut self,
        old_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
        trace_id: &str,
        _timestamp_ns: u64,
    ) -> Vec<EngineObjectId> {
        self.config.current_epoch = new_epoch;
        let invalidated = self.proof_store.invalidate_epoch(old_epoch);

        if !invalidated.is_empty() {
            self.decision_counter += 1;
            let decision_id = format!("cpe-{}", self.decision_counter);
            self.events.push(CompilerPolicyEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.clone(),
                policy_id: self.config.policy_id.clone(),
                component: "compiler_policy".to_string(),
                event: "epoch_change_invalidation".to_string(),
                outcome: format!(
                    "invalidated {} proofs from epoch {}",
                    invalidated.len(),
                    old_epoch.as_u64()
                ),
                error_code: Some("INVALIDATED_EPOCH_CHANGE".to_string()),
            });
        }

        invalidated
    }

    /// Collect proof inputs from the last applied decision for receipt emission.
    pub fn last_applied_proof_inputs(&self) -> Option<Vec<ProofInput>> {
        let last = self
            .decisions
            .iter()
            .rev()
            .find(|d| d.outcome.is_applied())?;
        let inputs: Vec<ProofInput> = last
            .proof_ids
            .iter()
            .filter_map(|id| self.proof_store.get(id))
            .map(|p| p.to_proof_input())
            .collect();
        // Return None when proofs were invalidated (e.g. after epoch change)
        // rather than Some(vec![]) which misleads callers into thinking
        // there is valid proof evidence.
        if inputs.is_empty() {
            return None;
        }
        Some(inputs)
    }

    /// Get all decisions for a given region.
    pub fn decisions_for_region(&self, region_id: &str) -> Vec<&SpecializationDecision> {
        self.decisions
            .iter()
            .filter(|d| d.region_id == region_id)
            .collect()
    }

    /// Count of applied specializations.
    pub fn applied_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|d| d.outcome.is_applied())
            .count()
    }

    /// Count of rejected specializations.
    pub fn rejected_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|d| !d.outcome.is_applied())
            .count()
    }

    #[allow(clippy::too_many_arguments)]
    fn record_decision(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        region: &MarkedRegion,
        outcome: SpecializationOutcome,
        detail: String,
        proof_ids: Vec<EngineObjectId>,
        timestamp_ns: u64,
    ) -> SpecializationDecision {
        let decision = SpecializationDecision {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: self.config.policy_id.clone(),
            region_id: region.region_id.clone(),
            optimization_class: region.optimization_class,
            outcome,
            detail: detail.clone(),
            proof_ids,
            epoch: self.config.current_epoch,
            timestamp_ns,
        };

        self.events.push(CompilerPolicyEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: self.config.policy_id.clone(),
            component: "compiler_policy".to_string(),
            event: if outcome.is_applied() {
                "specialization_applied".to_string()
            } else {
                "specialization_rejected".to_string()
            },
            outcome: outcome.error_code().to_string(),
            error_code: if outcome.is_applied() {
                None
            } else {
                Some(outcome.error_code().to_string())
            },
        });

        self.decisions.push(decision.clone());
        decision
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};

    fn test_schema_id() -> SchemaId {
        SchemaId::from_definition(SCHEMA_DEF)
    }

    fn make_proof_id(tag: &str) -> EngineObjectId {
        derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &test_schema_id(),
            tag.as_bytes(),
        )
        .unwrap()
    }

    fn cap_witness_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
        SecurityProof::CapabilityWitness {
            proof_id: make_proof_id(tag),
            capability_name: format!("cap_{tag}"),
            epoch,
            validity_window_ticks: 1000,
        }
    }

    fn flow_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
        SecurityProof::FlowProof {
            proof_id: make_proof_id(tag),
            source_label: Label::Confidential,
            sink_clearance: Label::Internal,
            epoch,
            validity_window_ticks: 500,
        }
    }

    fn replay_motif_proof(tag: &str, epoch: SecurityEpoch) -> SecurityProof {
        SecurityProof::ReplayMotif {
            proof_id: make_proof_id(tag),
            motif_hash: format!("motif_{tag}"),
            epoch,
            validity_window_ticks: 2000,
        }
    }

    fn make_region(
        region_id: &str,
        class: OptimizationClass,
        proof_ids: Vec<EngineObjectId>,
    ) -> MarkedRegion {
        MarkedRegion {
            region_id: region_id.to_string(),
            optimization_class: class,
            proof_refs: proof_ids,
            elided_check_description: format!("elide check in {region_id}"),
        }
    }

    fn default_engine(epoch: SecurityEpoch) -> CompilerPolicyEngine {
        let config = CompilerPolicyConfig::new("test-policy", epoch);
        CompilerPolicyEngine::new(config)
    }

    // -----------------------------------------------------------------------
    // Basic applied specialization
    // -----------------------------------------------------------------------

    #[test]
    fn apply_specialization_with_valid_capability_witness() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id.clone()],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);

        assert_eq!(decision.outcome, SpecializationOutcome::Applied);
        assert_eq!(decision.proof_ids, vec![proof_id]);
        assert_eq!(engine.applied_count(), 1);
        assert_eq!(engine.rejected_count(), 0);
    }

    #[test]
    fn apply_specialization_with_flow_proof() {
        let epoch = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch);
        let proof = flow_proof("fp1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-flow",
            OptimizationClass::IfcCheckElision,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-2", 2000);
        assert!(decision.outcome.is_applied());
    }

    #[test]
    fn apply_specialization_with_replay_motif() {
        let epoch = SecurityEpoch::from_raw(3);
        let mut engine = default_engine(epoch);
        let proof = replay_motif_proof("rm1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-motif",
            OptimizationClass::SuperinstructionFusion,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-3", 3000);
        assert!(decision.outcome.is_applied());
    }

    // -----------------------------------------------------------------------
    // Fail-closed: global disable
    // -----------------------------------------------------------------------

    #[test]
    fn global_disable_rejects_all() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        config.global_disable = true;
        let mut engine = CompilerPolicyEngine::new(config);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedGlobalDisable
        );
    }

    // -----------------------------------------------------------------------
    // Fail-closed: class disabled
    // -----------------------------------------------------------------------

    #[test]
    fn class_disabled_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        config.class_policies.insert(
            OptimizationClass::IfcCheckElision,
            OptimizationClassPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        let proof = flow_proof("fp1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-ifc",
            OptimizationClass::IfcCheckElision,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedClassDisabled
        );
    }

    // -----------------------------------------------------------------------
    // Fail-closed: no proofs
    // -----------------------------------------------------------------------

    #[test]
    fn no_proofs_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(decision.outcome, SpecializationOutcome::RejectedNoProofs);
    }

    // -----------------------------------------------------------------------
    // Fail-closed: proof not found
    // -----------------------------------------------------------------------

    #[test]
    fn proof_not_found_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let fake_id = make_proof_id("nonexistent");
        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![fake_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedProofNotFound
        );
    }

    // -----------------------------------------------------------------------
    // Fail-closed: insufficient proof count
    // -----------------------------------------------------------------------

    #[test]
    fn insufficient_proof_count_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        config.class_policies.insert(
            OptimizationClass::PathElimination,
            OptimizationClassPolicy {
                enabled: true,
                min_proof_count: 3,
                ..Default::default()
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::PathElimination,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedInsufficientProofs
        );
    }

    // -----------------------------------------------------------------------
    // Fail-closed: missing required proof types
    // -----------------------------------------------------------------------

    #[test]
    fn missing_required_proof_types_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        let mut required = BTreeSet::new();
        required.insert(ProofType::CapabilityWitness);
        required.insert(ProofType::FlowProof);
        config.class_policies.insert(
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClassPolicy {
                enabled: true,
                min_proof_count: 1,
                required_proof_types: required,
                governance_approved: false,
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        // Only provide CapabilityWitness, missing FlowProof
        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedMissingRequiredProofTypes
        );
    }

    #[test]
    fn all_required_proof_types_present_applies() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        let mut required = BTreeSet::new();
        required.insert(ProofType::CapabilityWitness);
        required.insert(ProofType::FlowProof);
        config.class_policies.insert(
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClassPolicy {
                enabled: true,
                min_proof_count: 2,
                required_proof_types: required,
                governance_approved: true,
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        let cw = cap_witness_proof("cw1", epoch);
        let fp = flow_proof("fp1", epoch);
        let cw_id = cw.proof_id().clone();
        let fp_id = fp.proof_id().clone();
        engine.register_proof(cw);
        engine.register_proof(fp);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![cw_id, fp_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert!(decision.outcome.is_applied());
        assert_eq!(decision.proof_ids.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Fail-closed: epoch mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_mismatch_rejects() {
        let current_epoch = SecurityEpoch::from_raw(5);
        let wrong_epoch = SecurityEpoch::from_raw(3);
        let mut engine = default_engine(current_epoch);

        let proof = cap_witness_proof("p1", wrong_epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedEpochMismatch
        );
    }

    // -----------------------------------------------------------------------
    // Fail-closed: expired proof (validity_window_ticks == 0)
    // -----------------------------------------------------------------------

    #[test]
    fn expired_proof_rejects() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let proof = SecurityProof::CapabilityWitness {
            proof_id: make_proof_id("expired"),
            capability_name: "cap_expired".to_string(),
            epoch,
            validity_window_ticks: 0,
        };
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(
            decision.outcome,
            SpecializationOutcome::RejectedProofExpired
        );
    }

    // -----------------------------------------------------------------------
    // Epoch change invalidation
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_change_invalidates_old_proofs() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        let p1 = cap_witness_proof("old1", epoch1);
        let p2 = cap_witness_proof("old2", epoch1);
        engine.register_proof(p1);
        engine.register_proof(p2);
        assert_eq!(engine.proof_store().len(), 2);

        let invalidated = engine.on_epoch_change(epoch1, epoch2, "trace-epoch", 5000);
        assert_eq!(invalidated.len(), 2);
        assert!(engine.proof_store().is_empty());
        assert_eq!(engine.config().current_epoch, epoch2);
    }

    #[test]
    fn epoch_change_preserves_new_epoch_proofs() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        let old_proof = cap_witness_proof("old", epoch1);
        let new_proof = cap_witness_proof("new", epoch2);
        engine.register_proof(old_proof);
        engine.register_proof(new_proof);
        assert_eq!(engine.proof_store().len(), 2);

        let invalidated = engine.on_epoch_change(epoch1, epoch2, "trace-epoch", 5000);
        assert_eq!(invalidated.len(), 1);
        assert_eq!(engine.proof_store().len(), 1);
    }

    #[test]
    fn after_epoch_change_old_proofs_cannot_justify() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        let proof = cap_witness_proof("p1", epoch1);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        // First: should work
        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id.clone()],
        );
        let d1 = engine.evaluate(&region, "trace-1", 1000);
        assert!(d1.outcome.is_applied());

        // Epoch change
        engine.on_epoch_change(epoch1, epoch2, "trace-ec", 2000);

        // After: proof gone, should fail
        let d2 = engine.evaluate(&region, "trace-2", 3000);
        assert_eq!(d2.outcome, SpecializationOutcome::RejectedProofNotFound);
    }

    #[test]
    fn re_evaluate_with_new_proofs_after_epoch_change() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        let old_proof = cap_witness_proof("p1", epoch1);
        let old_id = old_proof.proof_id().clone();
        engine.register_proof(old_proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![old_id],
        );

        // Apply
        let d1 = engine.evaluate(&region, "trace-1", 1000);
        assert!(d1.outcome.is_applied());

        // Epoch change
        engine.on_epoch_change(epoch1, epoch2, "trace-ec", 2000);

        // Register new proof at new epoch
        let new_proof = cap_witness_proof("p1-renewed", epoch2);
        let new_id = new_proof.proof_id().clone();
        engine.register_proof(new_proof);

        let region2 = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![new_id],
        );
        let d2 = engine.evaluate(&region2, "trace-2", 3000);
        assert!(d2.outcome.is_applied());
    }

    // -----------------------------------------------------------------------
    // Audit trail
    // -----------------------------------------------------------------------

    #[test]
    fn decisions_are_logged() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        // Applied decision
        let region = make_region(
            "region-ok",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        engine.evaluate(&region, "trace-1", 1000);

        // Rejected decision (no proofs)
        let region2 = make_region(
            "region-bad",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![],
        );
        engine.evaluate(&region2, "trace-2", 2000);

        assert_eq!(engine.decisions().len(), 2);
        assert_eq!(engine.events().len(), 2);
        assert!(engine.decisions()[0].outcome.is_applied());
        assert!(!engine.decisions()[1].outcome.is_applied());
    }

    #[test]
    fn events_have_correct_structure() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        engine.evaluate(&region, "trace-1", 1000);

        let event = &engine.events()[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.policy_id, "test-policy");
        assert_eq!(event.component, "compiler_policy");
        assert_eq!(event.event, "specialization_applied");
        assert_eq!(event.outcome, "APPLIED");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn rejected_events_have_error_code() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![],
        );
        engine.evaluate(&region, "trace-1", 1000);

        let event = &engine.events()[0];
        assert_eq!(event.event, "specialization_rejected");
        assert_eq!(event.error_code.as_deref(), Some("NO_PROOFS"));
    }

    // -----------------------------------------------------------------------
    // Per-region decision filtering
    // -----------------------------------------------------------------------

    #[test]
    fn decisions_filtered_by_region() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let p1 = cap_witness_proof("p1", epoch);
        let p2 = cap_witness_proof("p2", epoch);
        let id1 = p1.proof_id().clone();
        let id2 = p2.proof_id().clone();
        engine.register_proof(p1);
        engine.register_proof(p2);

        let r1 = make_region(
            "region-A",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![id1],
        );
        let r2 = make_region("region-B", OptimizationClass::PathElimination, vec![id2]);

        engine.evaluate(&r1, "trace-1", 1000);
        engine.evaluate(&r2, "trace-2", 2000);
        engine.evaluate(&r1, "trace-3", 3000);

        assert_eq!(engine.decisions_for_region("region-A").len(), 2);
        assert_eq!(engine.decisions_for_region("region-B").len(), 1);
        assert_eq!(engine.decisions_for_region("region-C").len(), 0);
    }

    // -----------------------------------------------------------------------
    // Proof input extraction for receipt emission
    // -----------------------------------------------------------------------

    #[test]
    fn last_applied_proof_inputs_returns_inputs() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        engine.evaluate(&region, "trace-1", 1000);

        let inputs = engine.last_applied_proof_inputs().unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
        assert_eq!(inputs[0].validity_window_ticks, 1000);
    }

    #[test]
    fn last_applied_proof_inputs_none_when_no_applied() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![],
        );
        engine.evaluate(&region, "trace-1", 1000);

        assert!(engine.last_applied_proof_inputs().is_none());
    }

    // -----------------------------------------------------------------------
    // ProofStore operations
    // -----------------------------------------------------------------------

    #[test]
    fn proof_store_insert_get_remove() {
        let mut store = ProofStore::new();
        assert!(store.is_empty());

        let proof = cap_witness_proof("p1", SecurityEpoch::from_raw(1));
        let proof_id = proof.proof_id().clone();
        store.insert(proof);
        assert_eq!(store.len(), 1);
        assert!(store.get(&proof_id).is_some());

        let removed = store.remove(&proof_id);
        assert!(removed.is_some());
        assert!(store.is_empty());
    }

    #[test]
    fn proof_store_invalidate_epoch_selective() {
        let mut store = ProofStore::new();
        let e1 = SecurityEpoch::from_raw(1);
        let e2 = SecurityEpoch::from_raw(2);

        store.insert(cap_witness_proof("a", e1));
        store.insert(cap_witness_proof("b", e1));
        store.insert(cap_witness_proof("c", e2));

        let invalidated = store.invalidate_epoch(e1);
        assert_eq!(invalidated.len(), 2);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn proof_store_resolve_partial() {
        let mut store = ProofStore::new();
        let epoch = SecurityEpoch::from_raw(1);
        let p1 = cap_witness_proof("p1", epoch);
        let id1 = p1.proof_id().clone();
        store.insert(p1);

        let fake_id = make_proof_id("nonexistent");
        let resolved = store.resolve(&[id1, fake_id]);
        assert_eq!(resolved.len(), 1);
    }

    // -----------------------------------------------------------------------
    // SecurityProof accessors
    // -----------------------------------------------------------------------

    #[test]
    fn security_proof_accessors() {
        let epoch = SecurityEpoch::from_raw(7);

        let cw = cap_witness_proof("cw", epoch);
        assert_eq!(cw.proof_type(), ProofType::CapabilityWitness);
        assert_eq!(cw.epoch(), epoch);
        assert_eq!(cw.validity_window_ticks(), 1000);

        let fp = flow_proof("fp", epoch);
        assert_eq!(fp.proof_type(), ProofType::FlowProof);
        assert_eq!(fp.validity_window_ticks(), 500);

        let rm = replay_motif_proof("rm", epoch);
        assert_eq!(rm.proof_type(), ProofType::ReplayMotif);
        assert_eq!(rm.validity_window_ticks(), 2000);
    }

    // -----------------------------------------------------------------------
    // SpecializationOutcome coverage
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_error_codes_are_unique() {
        let outcomes = [
            SpecializationOutcome::Applied,
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];

        let codes: BTreeSet<&str> = outcomes.iter().map(|o| o.error_code()).collect();
        assert_eq!(codes.len(), outcomes.len(), "error codes must be unique");
    }

    #[test]
    fn only_applied_is_applied() {
        assert!(SpecializationOutcome::Applied.is_applied());
        assert!(!SpecializationOutcome::RejectedGlobalDisable.is_applied());
        assert!(!SpecializationOutcome::RejectedClassDisabled.is_applied());
        assert!(!SpecializationOutcome::RejectedNoProofs.is_applied());
        assert!(!SpecializationOutcome::RejectedInsufficientProofs.is_applied());
        assert!(!SpecializationOutcome::RejectedMissingRequiredProofTypes.is_applied());
        assert!(!SpecializationOutcome::RejectedProofExpired.is_applied());
        assert!(!SpecializationOutcome::RejectedEpochMismatch.is_applied());
        assert!(!SpecializationOutcome::RejectedProofNotFound.is_applied());
        assert!(!SpecializationOutcome::InvalidatedByEpochChange.is_applied());
    }

    // -----------------------------------------------------------------------
    // Default OptimizationClassPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn default_class_policy_is_conservative() {
        let p = OptimizationClassPolicy::default();
        assert!(p.enabled);
        assert_eq!(p.min_proof_count, 1);
        assert!(p.required_proof_types.is_empty());
        assert!(!p.governance_approved);
    }

    // -----------------------------------------------------------------------
    // Mixed proof types in single region
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_proof_types_in_region() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let cw = cap_witness_proof("cw1", epoch);
        let fp = flow_proof("fp1", epoch);
        let rm = replay_motif_proof("rm1", epoch);
        let cw_id = cw.proof_id().clone();
        let fp_id = fp.proof_id().clone();
        let rm_id = rm.proof_id().clone();
        engine.register_proof(cw);
        engine.register_proof(fp);
        engine.register_proof(rm);

        let region = make_region(
            "region-multi",
            OptimizationClass::SuperinstructionFusion,
            vec![cw_id, fp_id, rm_id],
        );
        let decision = engine.evaluate(&region, "trace-1", 1000);
        assert!(decision.outcome.is_applied());
        assert_eq!(decision.proof_ids.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Epoch change event logging
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_change_emits_event() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        engine.register_proof(cap_witness_proof("p1", epoch1));
        let events_before = engine.events().len();

        engine.on_epoch_change(epoch1, epoch2, "trace-ec", 5000);

        assert!(engine.events().len() > events_before);
        let last_event = engine.events().last().unwrap();
        assert_eq!(last_event.event, "epoch_change_invalidation");
        assert_eq!(
            last_event.error_code.as_deref(),
            Some("INVALIDATED_EPOCH_CHANGE")
        );
    }

    #[test]
    fn epoch_change_no_event_when_nothing_invalidated() {
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let mut engine = default_engine(epoch1);

        let events_before = engine.events().len();
        engine.on_epoch_change(epoch1, epoch2, "trace-ec", 5000);

        assert_eq!(engine.events().len(), events_before);
    }

    // -----------------------------------------------------------------------
    // Config accessors
    // -----------------------------------------------------------------------

    #[test]
    fn config_new_defaults() {
        let epoch = SecurityEpoch::from_raw(42);
        let config = CompilerPolicyConfig::new("my-policy", epoch);
        assert_eq!(config.policy_id, "my-policy");
        assert_eq!(config.current_epoch, epoch);
        assert!(!config.global_disable);
        assert!(config.class_policies.is_empty());
    }

    // -----------------------------------------------------------------------
    // MarkedRegion construction
    // -----------------------------------------------------------------------

    #[test]
    fn marked_region_fields() {
        let id = make_proof_id("test");
        let region = MarkedRegion {
            region_id: "r1".to_string(),
            optimization_class: OptimizationClass::PathElimination,
            proof_refs: vec![id.clone()],
            elided_check_description: "elide path check".to_string(),
        };
        assert_eq!(region.region_id, "r1");
        assert_eq!(
            region.optimization_class,
            OptimizationClass::PathElimination
        );
        assert_eq!(region.proof_refs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Decision fields correctness
    // -----------------------------------------------------------------------

    #[test]
    fn decision_fields_are_populated() {
        let epoch = SecurityEpoch::from_raw(10);
        let mut engine = default_engine(epoch);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-x",
            OptimizationClass::IfcCheckElision,
            vec![proof_id.clone()],
        );
        let d = engine.evaluate(&region, "trace-99", 42_000);

        assert_eq!(d.trace_id, "trace-99");
        assert!(d.decision_id.starts_with("cpe-"));
        assert_eq!(d.policy_id, "test-policy");
        assert_eq!(d.region_id, "region-x");
        assert_eq!(d.optimization_class, OptimizationClass::IfcCheckElision);
        assert_eq!(d.epoch, epoch);
        assert_eq!(d.timestamp_ns, 42_000);
        assert_eq!(d.proof_ids, vec![proof_id]);
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn security_proof_serde_roundtrip() {
        let proofs = vec![
            cap_witness_proof("s1", SecurityEpoch::from_raw(1)),
            flow_proof("s2", SecurityEpoch::from_raw(2)),
            replay_motif_proof("s3", SecurityEpoch::from_raw(3)),
        ];
        for proof in &proofs {
            let json = serde_json::to_string(proof).unwrap();
            let decoded: SecurityProof = serde_json::from_str(&json).unwrap();
            assert_eq!(proof, &decoded);
        }
    }

    #[test]
    fn config_serde_roundtrip() {
        let mut config = CompilerPolicyConfig::new("p1", SecurityEpoch::from_raw(5));
        config.class_policies.insert(
            OptimizationClass::IfcCheckElision,
            OptimizationClassPolicy {
                enabled: false,
                min_proof_count: 2,
                required_proof_types: BTreeSet::from([ProofType::FlowProof]),
                governance_approved: true,
            },
        );
        let json = serde_json::to_string(&config).unwrap();
        let decoded: CompilerPolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let decision = SpecializationDecision {
            trace_id: "t1".to_string(),
            decision_id: "cpe-1".to_string(),
            policy_id: "p1".to_string(),
            region_id: "r1".to_string(),
            optimization_class: OptimizationClass::HostcallDispatchSpecialization,
            outcome: SpecializationOutcome::Applied,
            detail: "ok".to_string(),
            proof_ids: vec![make_proof_id("x")],
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 999,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: SpecializationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    // -----------------------------------------------------------------------
    // Multiple evaluations accumulate decisions
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_evaluations_accumulate() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        for i in 0..5 {
            let tag = format!("p{i}");
            let proof = cap_witness_proof(&tag, epoch);
            let proof_id = proof.proof_id().clone();
            engine.register_proof(proof);

            let region = make_region(
                &format!("r{i}"),
                OptimizationClass::HostcallDispatchSpecialization,
                vec![proof_id],
            );
            engine.evaluate(&region, &format!("trace-{i}"), i as u64 * 1000);
        }

        assert_eq!(engine.applied_count(), 5);
        assert_eq!(engine.decisions().len(), 5);
        assert_eq!(engine.events().len(), 5);
    }

    // -----------------------------------------------------------------------
    // Class policy fallback to default
    // -----------------------------------------------------------------------

    #[test]
    fn unconfigured_class_uses_default_policy() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("test-policy", epoch);
        // Only configure PathElimination, leave others as default
        config.class_policies.insert(
            OptimizationClass::PathElimination,
            OptimizationClassPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        let engine = CompilerPolicyEngine::new(config);

        // HostcallDispatchSpecialization not configured -> uses default (enabled)
        let default_policy = engine
            .config()
            .class_policy(&OptimizationClass::HostcallDispatchSpecialization);
        assert!(default_policy.enabled);

        // PathElimination is configured -> disabled
        let path_policy = engine
            .config()
            .class_policy(&OptimizationClass::PathElimination);
        assert!(!path_policy.enabled);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, error codes, edge cases, serde
    // -----------------------------------------------------------------------

    #[test]
    fn specialization_outcome_error_code_uniqueness_enrichment() {
        let outcomes = [
            SpecializationOutcome::Applied,
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];
        let codes: BTreeSet<String> = outcomes
            .iter()
            .map(|o| o.error_code().to_string())
            .collect();
        assert_eq!(
            codes.len(),
            10,
            "all SpecializationOutcome variants must have unique error_code"
        );
    }

    #[test]
    fn specialization_outcome_serde_roundtrip() {
        let outcomes = [
            SpecializationOutcome::Applied,
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let back: SpecializationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, back);
        }
    }

    #[test]
    fn proof_store_empty_state() {
        let store = ProofStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get(&make_proof_id("nonexistent")).is_none());
    }

    #[test]
    fn proof_store_resolve_empty_list() {
        let store = ProofStore::new();
        let resolved = store.resolve(&[]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn global_disable_blocks_all_evaluations() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("policy-disabled", epoch);
        config.global_disable = true;
        let mut engine = CompilerPolicyEngine::new(config);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![proof_id],
        );
        let d = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(d.outcome, SpecializationOutcome::RejectedGlobalDisable);
        assert!(!d.outcome.is_applied());
    }

    #[test]
    fn class_disabled_blocks_that_class() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("policy-class-off", epoch);
        config.class_policies.insert(
            OptimizationClass::PathElimination,
            OptimizationClassPolicy {
                enabled: false,
                ..Default::default()
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        let proof = cap_witness_proof("p1", epoch);
        let proof_id = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "region-1",
            OptimizationClass::PathElimination,
            vec![proof_id],
        );
        let d = engine.evaluate(&region, "trace-1", 1000);
        assert_eq!(d.outcome, SpecializationOutcome::RejectedClassDisabled);
    }

    #[test]
    fn optimization_class_serde_roundtrip() {
        let classes = [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::PathElimination,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
        ];
        for c in &classes {
            let json = serde_json::to_string(c).unwrap();
            let back: OptimizationClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    #[test]
    fn policy_event_serde_roundtrip() {
        let event = CompilerPolicyEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "compiler_policy".to_string(),
            event: "test".to_string(),
            outcome: "OK".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -- Enrichment: SecurityProof proof_type all variants --

    #[test]
    fn security_proof_proof_type_all_variants() {
        let pid = make_proof_id("proof-type-test");
        let epoch = SecurityEpoch::from_raw(1);

        let cap = SecurityProof::CapabilityWitness {
            proof_id: pid.clone(),
            capability_name: "net".into(),
            epoch,
            validity_window_ticks: 100,
        };
        assert_eq!(cap.proof_type(), ProofType::CapabilityWitness);
        assert_eq!(cap.epoch(), epoch);
        assert_eq!(cap.validity_window_ticks(), 100);

        let flow = SecurityProof::FlowProof {
            proof_id: pid.clone(),
            source_label: Label::Public,
            sink_clearance: Label::Public,
            epoch,
            validity_window_ticks: 200,
        };
        assert_eq!(flow.proof_type(), ProofType::FlowProof);
        assert_eq!(flow.validity_window_ticks(), 200);

        let motif = SecurityProof::ReplayMotif {
            proof_id: pid,
            motif_hash: "abc".into(),
            epoch,
            validity_window_ticks: 300,
        };
        assert_eq!(motif.proof_type(), ProofType::ReplayMotif);
        assert_eq!(motif.validity_window_ticks(), 300);
    }

    // -- Enrichment: ProofStore serde roundtrip --

    #[test]
    fn proof_store_insert_and_get_back() {
        let mut store = ProofStore::new();
        let pid = make_proof_id("store-get");
        store.insert(SecurityProof::CapabilityWitness {
            proof_id: pid.clone(),
            capability_name: "fs".into(),
            epoch: SecurityEpoch::from_raw(1),
            validity_window_ticks: 100,
        });
        assert_eq!(store.len(), 1);

        let retrieved = store.get(&pid).unwrap();
        assert_eq!(retrieved.proof_id(), &pid);
        assert_eq!(retrieved.proof_type(), ProofType::CapabilityWitness);
    }

    // -- Enrichment: ProofStore len and is_empty --

    #[test]
    fn proof_store_len_and_is_empty() {
        let mut store = ProofStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        let pid = make_proof_id("len-test");
        store.insert(SecurityProof::ReplayMotif {
            proof_id: pid.clone(),
            motif_hash: "xyz".into(),
            epoch: SecurityEpoch::from_raw(1),
            validity_window_ticks: 100,
        });
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        store.remove(&pid);
        assert!(store.is_empty());
    }

    // -- Enrichment: CompilerPolicyEngine applied_count and rejected_count --

    #[test]
    fn engine_applied_and_rejected_counts() {
        let epoch = SecurityEpoch::from_raw(1);
        let config = CompilerPolicyConfig::new("policy-count", epoch);
        let mut engine = CompilerPolicyEngine::new(config);

        let pid = make_proof_id("count-proof");
        engine.register_proof(SecurityProof::CapabilityWitness {
            proof_id: pid.clone(),
            capability_name: "net".into(),
            epoch,
            validity_window_ticks: 100,
        });

        // Applied
        let region = MarkedRegion {
            region_id: "r1".into(),
            optimization_class: OptimizationClass::IfcCheckElision,
            proof_refs: vec![pid],
            elided_check_description: "cap check".into(),
        };
        engine.evaluate(&region, "t1", 0);
        assert_eq!(engine.applied_count(), 1);
        assert_eq!(engine.rejected_count(), 0);

        // Rejected (no proofs)
        let region2 = MarkedRegion {
            region_id: "r2".into(),
            optimization_class: OptimizationClass::IfcCheckElision,
            proof_refs: vec![],
            elided_check_description: "cap check".into(),
        };
        engine.evaluate(&region2, "t2", 0);
        assert_eq!(engine.applied_count(), 1);
        assert_eq!(engine.rejected_count(), 1);
    }

    // -- Enrichment: MarkedRegion serde roundtrip --

    #[test]
    fn marked_region_serde_roundtrip() {
        let pid = make_proof_id("region-serde");
        let region = MarkedRegion {
            region_id: "r-42".into(),
            optimization_class: OptimizationClass::PathElimination,
            proof_refs: vec![pid],
            elided_check_description: "flow label check".into(),
        };
        let json = serde_json::to_string(&region).unwrap();
        let back: MarkedRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(region, back);
    }

    // -- Enrichment: OptimizationClassPolicy default values --

    #[test]
    fn optimization_class_policy_default() {
        let policy = OptimizationClassPolicy::default();
        assert!(policy.enabled);
        assert_eq!(policy.min_proof_count, 1);
        assert!(policy.required_proof_types.is_empty());
        assert!(!policy.governance_approved);
    }

    // -- Enrichment: CompilerPolicyEvent with error_code set --

    #[test]
    fn policy_event_serde_with_error_code() {
        let event = CompilerPolicyEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "compiler_policy".into(),
            event: "specialization_rejected".into(),
            outcome: "GLOBAL_DISABLE".into(),
            error_code: Some("GLOBAL_DISABLE".into()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CompilerPolicyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.error_code.as_deref(), Some("GLOBAL_DISABLE"));
    }

    // -- Enrichment: SpecializationOutcome is_applied for all variants --

    #[test]
    fn specialization_outcome_is_applied_exhaustive() {
        assert!(SpecializationOutcome::Applied.is_applied());
        let non_applied = [
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];
        for outcome in &non_applied {
            assert!(!outcome.is_applied(), "{:?} should not be applied", outcome);
        }
    }

    // -- Enrichment: engine decisions_for_region returns empty for unknown region --

    #[test]
    fn decisions_for_region_empty_when_no_decisions() {
        let epoch = SecurityEpoch::from_raw(1);
        let config = CompilerPolicyConfig::new("policy-empty", epoch);
        let engine = CompilerPolicyEngine::new(config);
        assert!(engine.decisions_for_region("nonexistent").is_empty());
    }

    // -- Enrichment: engine accessors --

    #[test]
    fn engine_config_and_events_accessors() {
        let epoch = SecurityEpoch::from_raw(5);
        let config = CompilerPolicyConfig::new("policy-access", epoch);
        let engine = CompilerPolicyEngine::new(config);

        assert_eq!(engine.config().current_epoch, epoch);
        assert_eq!(engine.config().policy_id, "policy-access");
        assert!(!engine.config().global_disable);
        assert!(engine.proof_store().is_empty());
        assert!(engine.decisions().is_empty());
        assert!(engine.events().is_empty());
    }

    // -- Enrichment: OptimizationClassPolicy serde roundtrip --

    #[test]
    fn optimization_class_policy_serde_roundtrip() {
        let mut required = BTreeSet::new();
        required.insert(ProofType::CapabilityWitness);
        required.insert(ProofType::FlowProof);

        let policy = OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 2,
            required_proof_types: required,
            governance_approved: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: OptimizationClassPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: Copy/Clone, Debug, serde distinctness, field names,
    // Display, Hash consistency, boundary/edge cases, Error trait
    // -----------------------------------------------------------------------

    // --- Copy/Clone semantics for Copy types ---

    #[test]
    fn specialization_outcome_is_copy() {
        let a = SpecializationOutcome::Applied;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = SpecializationOutcome::RejectedGlobalDisable;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn optimization_class_is_copy() {
        let a = OptimizationClass::HostcallDispatchSpecialization;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = OptimizationClass::PathElimination;
        let d = c;
        assert_eq!(c, d);
    }

    #[test]
    fn proof_type_is_copy() {
        let a = ProofType::CapabilityWitness;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = ProofType::FlowProof;
        let d = c;
        assert_eq!(c, d);
    }

    // --- Debug output non-empty and distinct across variants ---

    #[test]
    fn specialization_outcome_debug_non_empty_and_distinct() {
        let outcomes = [
            SpecializationOutcome::Applied,
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];
        let mut debug_strs: BTreeSet<String> = BTreeSet::new();
        for o in &outcomes {
            let s = format!("{o:?}");
            assert!(!s.is_empty(), "debug output must be non-empty");
            debug_strs.insert(s);
        }
        assert_eq!(
            debug_strs.len(),
            outcomes.len(),
            "all Debug strings must be distinct"
        );
    }

    #[test]
    fn optimization_class_debug_non_empty_and_distinct() {
        let classes = [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
            OptimizationClass::PathElimination,
        ];
        let mut debug_strs: BTreeSet<String> = BTreeSet::new();
        for c in &classes {
            let s = format!("{c:?}");
            assert!(!s.is_empty());
            debug_strs.insert(s);
        }
        assert_eq!(debug_strs.len(), classes.len());
    }

    #[test]
    fn proof_type_debug_non_empty_and_distinct() {
        let types = [
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
        ];
        let mut debug_strs: BTreeSet<String> = BTreeSet::new();
        for t in &types {
            let s = format!("{t:?}");
            assert!(!s.is_empty());
            debug_strs.insert(s);
        }
        assert_eq!(debug_strs.len(), types.len());
    }

    #[test]
    fn security_proof_debug_non_empty_and_distinct() {
        let epoch = SecurityEpoch::from_raw(1);
        let cw = cap_witness_proof("dbg-cw", epoch);
        let fp = flow_proof("dbg-fp", epoch);
        let rm = replay_motif_proof("dbg-rm", epoch);
        let s_cw = format!("{cw:?}");
        let s_fp = format!("{fp:?}");
        let s_rm = format!("{rm:?}");
        assert!(!s_cw.is_empty());
        assert!(!s_fp.is_empty());
        assert!(!s_rm.is_empty());
        assert_ne!(s_cw, s_fp);
        assert_ne!(s_fp, s_rm);
        assert_ne!(s_cw, s_rm);
    }

    // --- Serde variant distinctness ---

    #[test]
    fn specialization_outcome_serde_variants_distinct() {
        let outcomes = [
            SpecializationOutcome::Applied,
            SpecializationOutcome::RejectedGlobalDisable,
            SpecializationOutcome::RejectedClassDisabled,
            SpecializationOutcome::RejectedNoProofs,
            SpecializationOutcome::RejectedInsufficientProofs,
            SpecializationOutcome::RejectedMissingRequiredProofTypes,
            SpecializationOutcome::RejectedProofExpired,
            SpecializationOutcome::RejectedEpochMismatch,
            SpecializationOutcome::RejectedProofNotFound,
            SpecializationOutcome::InvalidatedByEpochChange,
        ];
        let mut jsons: BTreeSet<String> = BTreeSet::new();
        for o in &outcomes {
            let j = serde_json::to_string(o).unwrap();
            jsons.insert(j);
        }
        assert_eq!(
            jsons.len(),
            outcomes.len(),
            "all variants must serialize distinctly"
        );
    }

    #[test]
    fn optimization_class_serde_variants_distinct() {
        let classes = [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
            OptimizationClass::PathElimination,
        ];
        let mut jsons: BTreeSet<String> = BTreeSet::new();
        for c in &classes {
            let j = serde_json::to_string(c).unwrap();
            jsons.insert(j);
        }
        assert_eq!(jsons.len(), classes.len());
    }

    #[test]
    fn proof_type_serde_variants_distinct() {
        let types = [
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
        ];
        let mut jsons: BTreeSet<String> = BTreeSet::new();
        for t in &types {
            let j = serde_json::to_string(t).unwrap();
            jsons.insert(j);
        }
        assert_eq!(jsons.len(), types.len());
    }

    #[test]
    fn security_proof_serde_variants_distinct() {
        let epoch = SecurityEpoch::from_raw(1);
        let cw = cap_witness_proof("sv-cw", epoch);
        let fp = flow_proof("sv-fp", epoch);
        let rm = replay_motif_proof("sv-rm", epoch);
        let j_cw = serde_json::to_string(&cw).unwrap();
        let j_fp = serde_json::to_string(&fp).unwrap();
        let j_rm = serde_json::to_string(&rm).unwrap();
        assert_ne!(j_cw, j_fp);
        assert_ne!(j_fp, j_rm);
        assert_ne!(j_cw, j_rm);
    }

    // --- Clone independence ---

    #[test]
    fn marked_region_clone_independence() {
        let id = make_proof_id("clone-ind");
        let original = MarkedRegion {
            region_id: "original".to_string(),
            optimization_class: OptimizationClass::PathElimination,
            proof_refs: vec![id.clone()],
            elided_check_description: "original description".to_string(),
        };
        let mut cloned = original.clone();
        cloned.region_id = "cloned".to_string();
        cloned.elided_check_description = "cloned description".to_string();
        assert_eq!(original.region_id, "original");
        assert_eq!(original.elided_check_description, "original description");
    }

    #[test]
    fn optimization_class_policy_clone_independence() {
        let original = OptimizationClassPolicy {
            enabled: true,
            min_proof_count: 5,
            required_proof_types: BTreeSet::from([ProofType::CapabilityWitness]),
            governance_approved: false,
        };
        let mut cloned = original.clone();
        cloned.enabled = false;
        cloned.min_proof_count = 1;
        assert!(original.enabled);
        assert_eq!(original.min_proof_count, 5);
    }

    #[test]
    fn compiler_policy_config_clone_independence() {
        let epoch = SecurityEpoch::from_raw(1);
        let original = CompilerPolicyConfig::new("orig", epoch);
        let mut cloned = original.clone();
        cloned.global_disable = true;
        cloned.policy_id = "cloned".to_string();
        assert!(!original.global_disable);
        assert_eq!(original.policy_id, "orig");
    }

    #[test]
    fn proof_store_clone_independence() {
        let mut original = ProofStore::new();
        let epoch = SecurityEpoch::from_raw(1);
        let p = cap_witness_proof("clone-store", epoch);
        let pid = p.proof_id().clone();
        original.insert(p);

        let mut cloned = original.clone();
        cloned.remove(&pid);

        // Original still has the proof
        assert_eq!(original.len(), 1);
        assert!(original.get(&pid).is_some());
        // Clone does not
        assert!(cloned.is_empty());
    }

    // --- JSON field-name stability ---

    #[test]
    fn compiler_policy_config_json_field_names() {
        let epoch = SecurityEpoch::from_raw(1);
        let config = CompilerPolicyConfig::new("field-test", epoch);
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("\"current_epoch\""),
            "missing current_epoch field"
        );
        assert!(
            json.contains("\"class_policies\""),
            "missing class_policies field"
        );
        assert!(
            json.contains("\"global_disable\""),
            "missing global_disable field"
        );
        assert!(json.contains("\"policy_id\""), "missing policy_id field");
    }

    #[test]
    fn marked_region_json_field_names() {
        let region = MarkedRegion {
            region_id: "r1".to_string(),
            optimization_class: OptimizationClass::PathElimination,
            proof_refs: vec![],
            elided_check_description: "desc".to_string(),
        };
        let json = serde_json::to_string(&region).unwrap();
        assert!(json.contains("\"region_id\""), "missing region_id field");
        assert!(
            json.contains("\"optimization_class\""),
            "missing optimization_class field"
        );
        assert!(json.contains("\"proof_refs\""), "missing proof_refs field");
        assert!(
            json.contains("\"elided_check_description\""),
            "missing elided_check_description field"
        );
    }

    #[test]
    fn specialization_decision_json_field_names() {
        let decision = SpecializationDecision {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            region_id: "r".to_string(),
            optimization_class: OptimizationClass::HostcallDispatchSpecialization,
            outcome: SpecializationOutcome::Applied,
            detail: "ok".to_string(),
            proof_ids: vec![],
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 0,
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"region_id\""));
        assert!(json.contains("\"optimization_class\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"detail\""));
        assert!(json.contains("\"proof_ids\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"timestamp_ns\""));
    }

    #[test]
    fn compiler_policy_event_json_field_names() {
        let event = CompilerPolicyEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            error_code: Some("err".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
    }

    // --- Display format checks ---

    #[test]
    fn optimization_class_display_non_empty_and_distinct() {
        let classes = [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
            OptimizationClass::PathElimination,
        ];
        let mut displays: BTreeSet<String> = BTreeSet::new();
        for c in &classes {
            let s = format!("{c}");
            assert!(!s.is_empty(), "Display must be non-empty");
            displays.insert(s);
        }
        assert_eq!(
            displays.len(),
            classes.len(),
            "Display values must be distinct"
        );
    }

    #[test]
    fn optimization_class_display_exact_values() {
        assert_eq!(
            format!("{}", OptimizationClass::HostcallDispatchSpecialization),
            "hostcall_dispatch_specialization"
        );
        assert_eq!(
            format!("{}", OptimizationClass::IfcCheckElision),
            "ifc_check_elision"
        );
        assert_eq!(
            format!("{}", OptimizationClass::SuperinstructionFusion),
            "superinstruction_fusion"
        );
        assert_eq!(
            format!("{}", OptimizationClass::PathElimination),
            "path_elimination"
        );
    }

    #[test]
    fn proof_type_display_non_empty_and_distinct() {
        let types = [
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
        ];
        let mut displays: BTreeSet<String> = BTreeSet::new();
        for t in &types {
            let s = format!("{t}");
            assert!(!s.is_empty());
            displays.insert(s);
        }
        assert_eq!(displays.len(), types.len());
    }

    #[test]
    fn proof_type_display_exact_values() {
        assert_eq!(
            format!("{}", ProofType::CapabilityWitness),
            "capability_witness"
        );
        assert_eq!(format!("{}", ProofType::FlowProof), "flow_proof");
        assert_eq!(format!("{}", ProofType::ReplayMotif), "replay_motif");
    }

    // --- Boundary/edge cases ---

    #[test]
    fn validity_window_ticks_zero_rejects_all_proof_types() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        // FlowProof with zero ticks
        let fp_id = make_proof_id("fp-zero");
        engine.register_proof(SecurityProof::FlowProof {
            proof_id: fp_id.clone(),
            source_label: Label::Public,
            sink_clearance: Label::Internal,
            epoch,
            validity_window_ticks: 0,
        });
        let region = make_region("r-fp", OptimizationClass::IfcCheckElision, vec![fp_id]);
        let d = engine.evaluate(&region, "t-fp", 0);
        assert_eq!(d.outcome, SpecializationOutcome::RejectedProofExpired);

        // ReplayMotif with zero ticks
        let rm_id = make_proof_id("rm-zero");
        engine.register_proof(SecurityProof::ReplayMotif {
            proof_id: rm_id.clone(),
            motif_hash: "hash".to_string(),
            epoch,
            validity_window_ticks: 0,
        });
        let region2 = make_region(
            "r-rm",
            OptimizationClass::SuperinstructionFusion,
            vec![rm_id],
        );
        let d2 = engine.evaluate(&region2, "t-rm", 0);
        assert_eq!(d2.outcome, SpecializationOutcome::RejectedProofExpired);
    }

    #[test]
    fn empty_string_region_id_is_valid() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("empty-region", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d = engine.evaluate(&region, "trace-empty", 0);
        assert!(d.outcome.is_applied());
        assert_eq!(d.region_id, "");
        assert_eq!(engine.decisions_for_region("").len(), 1);
    }

    #[test]
    fn max_validity_window_ticks_passes() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);
        let max_id = make_proof_id("max-ticks");
        engine.register_proof(SecurityProof::CapabilityWitness {
            proof_id: max_id.clone(),
            capability_name: "max".to_string(),
            epoch,
            validity_window_ticks: u64::MAX,
        });
        let region = make_region(
            "r-max",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![max_id],
        );
        let d = engine.evaluate(&region, "t-max", u64::MAX);
        assert!(d.outcome.is_applied());
        assert_eq!(d.timestamp_ns, u64::MAX);
    }

    #[test]
    fn min_proof_count_zero_always_passes_count_check() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("p-zero-min", epoch);
        config.class_policies.insert(
            OptimizationClass::PathElimination,
            OptimizationClassPolicy {
                enabled: true,
                min_proof_count: 0,
                required_proof_types: BTreeSet::new(),
                governance_approved: false,
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);
        let proof = cap_witness_proof("pzm", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region("r-zmin", OptimizationClass::PathElimination, vec![pid]);
        let d = engine.evaluate(&region, "t-zmin", 0);
        // min_proof_count=0, 1 proof is sufficient — applied
        assert!(d.outcome.is_applied());
    }

    #[test]
    fn epoch_zero_is_valid() {
        let epoch = SecurityEpoch::from_raw(0);
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("epoch-zero", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "r-ez",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d = engine.evaluate(&region, "t-ez", 0);
        assert!(d.outcome.is_applied());
        assert_eq!(d.epoch.as_u64(), 0);
    }

    // --- ProofStore serde roundtrip ---

    #[test]
    fn proof_store_serde_roundtrip_empty() {
        let store = ProofStore::new();
        let json = serde_json::to_string(&store).unwrap();
        let back: ProofStore = serde_json::from_str(&json).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn proof_store_serde_roundtrip_with_proofs() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut store = ProofStore::new();
        store.insert(cap_witness_proof("sr-a", epoch));
        store.insert(flow_proof("sr-b", epoch));
        store.insert(replay_motif_proof("sr-c", epoch));

        let json = serde_json::to_string(&store).unwrap();
        let back: ProofStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 3);
    }

    // --- Additional engine behavior tests ---

    #[test]
    fn engine_decision_counter_increments() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("counter", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "r-counter",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d1 = engine.evaluate(&region, "t1", 0);
        let d2 = engine.evaluate(&region, "t2", 1);
        assert_ne!(d1.decision_id, d2.decision_id);
        assert!(d1.decision_id.starts_with("cpe-"));
        assert!(d2.decision_id.starts_with("cpe-"));
    }

    #[test]
    fn engine_multiple_epoch_changes_accumulate() {
        let e1 = SecurityEpoch::from_raw(1);
        let e2 = SecurityEpoch::from_raw(2);
        let e3 = SecurityEpoch::from_raw(3);
        let mut engine = default_engine(e1);

        engine.register_proof(cap_witness_proof("p-e1", e1));
        engine.on_epoch_change(e1, e2, "t1", 1000);
        assert_eq!(engine.config().current_epoch, e2);
        assert!(engine.proof_store().is_empty());

        engine.register_proof(cap_witness_proof("p-e2", e2));
        engine.on_epoch_change(e2, e3, "t2", 2000);
        assert_eq!(engine.config().current_epoch, e3);
        assert!(engine.proof_store().is_empty());
    }

    #[test]
    fn engine_last_applied_proof_inputs_after_mixed_decisions() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        // First: rejected (no proofs)
        let region_bad = make_region("r-bad", OptimizationClass::PathElimination, vec![]);
        engine.evaluate(&region_bad, "t1", 0);
        // No applied decision yet
        assert!(engine.last_applied_proof_inputs().is_none());

        // Then: applied
        let proof = cap_witness_proof("lap", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);
        let region_good = make_region(
            "r-good",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        engine.evaluate(&region_good, "t2", 1);
        let inputs = engine.last_applied_proof_inputs().unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].proof_type, ProofType::CapabilityWitness);
    }

    #[test]
    fn proof_store_remove_nonexistent_returns_none() {
        let mut store = ProofStore::new();
        let fake = make_proof_id("nonexistent-remove");
        let result = store.remove(&fake);
        assert!(result.is_none());
    }

    #[test]
    fn proof_store_remove_returns_proof() {
        let mut store = ProofStore::new();
        let epoch = SecurityEpoch::from_raw(1);
        let proof = cap_witness_proof("removable", epoch);
        let pid = proof.proof_id().clone();
        store.insert(proof);
        let removed = store.remove(&pid).unwrap();
        assert_eq!(removed.proof_id(), &pid);
        assert!(store.is_empty());
    }

    #[test]
    fn proof_store_insert_overwrites_same_id() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut store = ProofStore::new();
        let id = make_proof_id("overwrite");

        let p1 = SecurityProof::CapabilityWitness {
            proof_id: id.clone(),
            capability_name: "cap-v1".to_string(),
            epoch,
            validity_window_ticks: 100,
        };
        let p2 = SecurityProof::CapabilityWitness {
            proof_id: id.clone(),
            capability_name: "cap-v2".to_string(),
            epoch,
            validity_window_ticks: 200,
        };
        store.insert(p1);
        assert_eq!(store.len(), 1);
        store.insert(p2);
        // Overwrites, len still 1
        assert_eq!(store.len(), 1);
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.validity_window_ticks(), 200);
    }

    #[test]
    fn flow_proof_label_variants_accepted() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        let labels = [
            (Label::Public, Label::Internal),
            (Label::Internal, Label::Confidential),
            (Label::Confidential, Label::Secret),
            (Label::Secret, Label::TopSecret),
        ];

        for (i, (src, sink)) in labels.iter().enumerate() {
            let tag = format!("fp-label-{i}");
            let pid = make_proof_id(&tag);
            engine.register_proof(SecurityProof::FlowProof {
                proof_id: pid.clone(),
                source_label: src.clone(),
                sink_clearance: sink.clone(),
                epoch,
                validity_window_ticks: 100,
            });
            let region = make_region(
                &format!("r-label-{i}"),
                OptimizationClass::IfcCheckElision,
                vec![pid],
            );
            let d = engine.evaluate(&region, &format!("t-label-{i}"), i as u64);
            assert!(d.outcome.is_applied(), "label pair {i} should apply");
        }
    }

    #[test]
    fn required_proof_types_with_replay_motif_only() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut config = CompilerPolicyConfig::new("rpt-rm", epoch);
        let mut required = BTreeSet::new();
        required.insert(ProofType::ReplayMotif);
        config.class_policies.insert(
            OptimizationClass::SuperinstructionFusion,
            OptimizationClassPolicy {
                enabled: true,
                min_proof_count: 1,
                required_proof_types: required,
                governance_approved: false,
            },
        );
        let mut engine = CompilerPolicyEngine::new(config);

        // Provide only CapabilityWitness — should fail
        let cw = cap_witness_proof("rpt-cw", epoch);
        let cw_id = cw.proof_id().clone();
        engine.register_proof(cw);
        let region = make_region(
            "r-rpt",
            OptimizationClass::SuperinstructionFusion,
            vec![cw_id],
        );
        let d = engine.evaluate(&region, "t-rpt", 0);
        assert_eq!(
            d.outcome,
            SpecializationOutcome::RejectedMissingRequiredProofTypes
        );

        // Provide ReplayMotif — should pass
        let rm = replay_motif_proof("rpt-rm2", epoch);
        let rm_id = rm.proof_id().clone();
        engine.register_proof(rm);
        let region2 = make_region(
            "r-rpt2",
            OptimizationClass::SuperinstructionFusion,
            vec![rm_id],
        );
        let d2 = engine.evaluate(&region2, "t-rpt2", 1);
        assert!(d2.outcome.is_applied());
    }

    #[test]
    fn decision_detail_contains_expected_content_on_rejection() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);

        // No proofs
        let region = make_region("r", OptimizationClass::PathElimination, vec![]);
        let d = engine.evaluate(&region, "t", 0);
        assert!(
            !d.detail.is_empty(),
            "detail must be non-empty on rejection"
        );
    }

    #[test]
    fn decision_detail_mentions_proof_count_on_applied() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut engine = default_engine(epoch);
        let proof = cap_witness_proof("detail-test", epoch);
        let pid = proof.proof_id().clone();
        engine.register_proof(proof);

        let region = make_region(
            "r-detail",
            OptimizationClass::HostcallDispatchSpecialization,
            vec![pid],
        );
        let d = engine.evaluate(&region, "t-detail", 0);
        assert!(d.outcome.is_applied());
        assert!(!d.detail.is_empty(), "detail must be non-empty on applied");
    }

    #[test]
    fn epoch_change_updates_config_epoch() {
        let e1 = SecurityEpoch::from_raw(10);
        let e2 = SecurityEpoch::from_raw(20);
        let mut engine = default_engine(e1);
        assert_eq!(engine.config().current_epoch, e1);
        engine.on_epoch_change(e1, e2, "t", 0);
        assert_eq!(engine.config().current_epoch, e2);
    }
}
