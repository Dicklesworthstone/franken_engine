//! Security-proof ingestion path for optimizer hypotheses.
//!
//! Accepts PLAS capability witnesses, IFC flow proofs, and replay sequence
//! motifs as first-class optimizer inputs.  Valid proofs are translated into
//! typed optimizer hypotheses that feed the translation-validation gate
//! (bd-2qj) for equivalence verification before activation.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 3, 9H.1, 9H.14, 9I.8.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::proof_schema::OptimizationClass;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROOF_INPUT_SCHEMA_DEF: &[u8] = b"ProofInput.v1";
const HYPOTHESIS_SCHEMA_DEF: &[u8] = b"OptimizerHypothesis.v1";
const SPECIALIZATION_RECEIPT_SCHEMA_DEF: &[u8] = b"ProofSpecializationReceipt.v1";

/// Zone for all proof-ingestion objects.
const PROOF_INGESTION_ZONE: &str = "proof-ingestion";

// ---------------------------------------------------------------------------
// ProofType — category of security proof input
// ---------------------------------------------------------------------------

/// Category of security proof consumed by the ingestion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// PLAS capability witness: minimal capability envelope from 10.15/9I.5.
    PlasCapabilityWitness,
    /// IFC flow proof: proven-safe region from 10.15/9I.7.
    IfcFlowProof,
    /// Replay sequence motif: stable call sequence from sentinel evidence.
    ReplaySequenceMotif,
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlasCapabilityWitness => f.write_str("plas-capability-witness"),
            Self::IfcFlowProof => f.write_str("ifc-flow-proof"),
            Self::ReplaySequenceMotif => f.write_str("replay-sequence-motif"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProofInput — a security proof submitted for ingestion
// ---------------------------------------------------------------------------

/// A security proof submitted for ingestion into the optimizer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInput {
    /// Unique identity derived via `EngineObjectId`.
    pub proof_id: EngineObjectId,
    /// Category of proof.
    pub proof_type: ProofType,
    /// Epoch under which this proof was issued.
    pub proof_epoch: SecurityEpoch,
    /// Start of validity window (nanosecond timestamp).
    pub validity_start_ns: u64,
    /// End of validity window (nanosecond timestamp, 0 = unbounded).
    pub validity_end_ns: u64,
    /// Signature from the proof issuer.
    pub issuer_signature: Vec<u8>,
    /// Content hash of the proof payload.
    pub canonical_hash: ContentHash,
    /// Policy ID this proof is linked to.
    pub linked_policy_id: String,
    /// Opaque proof payload (type-specific semantics).
    pub payload: Vec<u8>,
}

impl ProofInput {
    /// Canonical bytes for deterministic hashing/signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.proof_id.as_bytes());
        buf.push(self.proof_type as u8);
        buf.extend_from_slice(&self.proof_epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.validity_start_ns.to_be_bytes());
        buf.extend_from_slice(&self.validity_end_ns.to_be_bytes());
        buf.extend_from_slice(self.canonical_hash.as_bytes());
        buf.extend_from_slice(self.linked_policy_id.as_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// ProofValidationStatus — result of proof ingestion validation
// ---------------------------------------------------------------------------

/// Result of validating a submitted proof input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofValidationStatus {
    /// Proof accepted for hypothesis generation.
    Accepted,
    /// Signature verification failed.
    SignatureInvalid,
    /// Proof epoch is stale relative to current epoch.
    EpochStale {
        proof_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// Proof validity window has not started yet.
    NotYetValid {
        validity_start_ns: u64,
        current_ns: u64,
    },
    /// Proof validity window has expired.
    Expired {
        validity_end_ns: u64,
        current_ns: u64,
    },
    /// Proof policy ID does not match active policy.
    PolicyMismatch {
        proof_policy: String,
        active_policy: String,
    },
    /// Proof payload failed type-specific semantic checks.
    SemanticCheckFailed { reason: String },
    /// Duplicate proof (already ingested).
    Duplicate { existing_id: EngineObjectId },
}

impl fmt::Display for ProofValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => f.write_str("accepted"),
            Self::SignatureInvalid => f.write_str("signature-invalid"),
            Self::EpochStale {
                proof_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch-stale (proof: {proof_epoch}, current: {current_epoch})"
            ),
            Self::NotYetValid {
                validity_start_ns,
                current_ns,
            } => write!(
                f,
                "not-yet-valid (start: {validity_start_ns}, current: {current_ns})"
            ),
            Self::Expired {
                validity_end_ns,
                current_ns,
            } => write!(f, "expired (end: {validity_end_ns}, current: {current_ns})"),
            Self::PolicyMismatch {
                proof_policy,
                active_policy,
            } => write!(
                f,
                "policy-mismatch (proof: {proof_policy}, active: {active_policy})"
            ),
            Self::SemanticCheckFailed { reason } => {
                write!(f, "semantic-check-failed: {reason}")
            }
            Self::Duplicate { existing_id } => {
                write!(f, "duplicate (existing: {existing_id})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HypothesisKind — type of optimization hypothesis
// ---------------------------------------------------------------------------

/// Kind of optimization hypothesis generated from a security proof.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HypothesisKind {
    /// Dead code paths provably unreachable per capability witness.
    DeadCodeElimination,
    /// Hostcall dispatch can be specialized given capability bounds.
    DispatchSpecialization,
    /// IFC flow checks can be elided in proven-safe regions.
    FlowCheckElision,
    /// Stable call sequences can be fused into superinstructions.
    SuperinstructionFusion,
}

impl fmt::Display for HypothesisKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadCodeElimination => f.write_str("dead-code-elimination"),
            Self::DispatchSpecialization => f.write_str("dispatch-specialization"),
            Self::FlowCheckElision => f.write_str("flow-check-elision"),
            Self::SuperinstructionFusion => f.write_str("superinstruction-fusion"),
        }
    }
}

// ---------------------------------------------------------------------------
// RiskLevel — risk classification for hypotheses
// ---------------------------------------------------------------------------

/// Risk classification for an optimization hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk: removal of provably dead code.
    Low,
    /// Medium risk: specialization with fallback path.
    Medium,
    /// High risk: elision of runtime checks.
    High,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

// ---------------------------------------------------------------------------
// OptimizerHypothesis — a proposed optimization derived from proof
// ---------------------------------------------------------------------------

/// An optimization hypothesis generated from one or more security proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizerHypothesis {
    /// Unique identity.
    pub hypothesis_id: EngineObjectId,
    /// Source proof IDs that justify this hypothesis.
    pub source_proof_ids: BTreeSet<EngineObjectId>,
    /// Kind of optimization.
    pub kind: HypothesisKind,
    /// Optimization class for proof-schema integration.
    pub optimization_class: OptimizationClass,
    /// Expected speedup in millionths (1_000_000 = 1.0x, 2_000_000 = 2.0x).
    pub expected_speedup_millionths: u64,
    /// Risk assessment.
    pub risk: RiskLevel,
    /// Epoch range during which this hypothesis is valid.
    pub validity_epoch: SecurityEpoch,
    /// Content hash of the hypothesis derivation.
    pub derivation_hash: ContentHash,
}

impl OptimizerHypothesis {
    /// Canonical bytes for signing/hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.hypothesis_id.as_bytes());
        for pid in &self.source_proof_ids {
            buf.extend_from_slice(pid.as_bytes());
        }
        buf.push(self.kind.clone() as u8);
        buf.extend_from_slice(&self.expected_speedup_millionths.to_be_bytes());
        buf.push(self.risk as u8);
        buf.extend_from_slice(&self.validity_epoch.as_u64().to_be_bytes());
        buf.extend_from_slice(self.derivation_hash.as_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// IngestionEvent — audit trail entry
// ---------------------------------------------------------------------------

/// Structured audit event for the proof ingestion subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionEvent {
    /// Monotonic sequence number within this ingestion engine instance.
    pub seq: u64,
    /// Nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Event type.
    pub event_type: IngestionEventType,
    /// Security epoch at event time.
    pub epoch: SecurityEpoch,
}

/// Type of ingestion event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestionEventType {
    /// Proof submitted for validation.
    ProofSubmitted {
        proof_id: EngineObjectId,
        proof_type: ProofType,
    },
    /// Proof validation completed.
    ProofValidated {
        proof_id: EngineObjectId,
        status: ProofValidationStatus,
    },
    /// Hypothesis generated from proof.
    HypothesisGenerated {
        hypothesis_id: EngineObjectId,
        kind: HypothesisKind,
        source_proof_count: usize,
    },
    /// Proof invalidated due to epoch change.
    ProofInvalidated {
        proof_id: EngineObjectId,
        reason: String,
    },
    /// Hypothesis invalidated due to source proof invalidation.
    HypothesisInvalidated {
        hypothesis_id: EngineObjectId,
        reason: String,
    },
    /// Specialization receipt emitted.
    SpecializationReceiptEmitted {
        receipt_id: EngineObjectId,
        hypothesis_id: EngineObjectId,
    },
}

// ---------------------------------------------------------------------------
// SpecializationReceipt — proof-to-optimization linkage
// ---------------------------------------------------------------------------

/// Receipt linking security proofs to activated optimizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationReceipt {
    /// Unique receipt identity.
    pub receipt_id: EngineObjectId,
    /// Proof input IDs that justify this specialization.
    pub proof_input_ids: BTreeSet<EngineObjectId>,
    /// Hypothesis ID that was activated.
    pub hypothesis_id: EngineObjectId,
    /// Optimization class.
    pub optimization_class: OptimizationClass,
    /// Content hash of the transformation witness.
    pub transformation_witness_hash: ContentHash,
    /// Content hash of the equivalence evidence.
    pub equivalence_evidence_hash: ContentHash,
    /// Rollback token for reverting this specialization.
    pub rollback_token_hash: ContentHash,
    /// Activation stage at issuance.
    pub activation_stage: ActivationStageLocal,
    /// Epoch at issuance.
    pub epoch: SecurityEpoch,
    /// Timestamp of issuance.
    pub issued_at_ns: u64,
    /// Signature over the receipt.
    pub signature: Vec<u8>,
}

/// Activation stage for specialization receipts (local copy to avoid
/// circular dependency if proof_schema changes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActivationStageLocal {
    Shadow,
    Canary,
    Ramp,
    Default,
}

impl fmt::Display for ActivationStageLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shadow => f.write_str("shadow"),
            Self::Canary => f.write_str("canary"),
            Self::Ramp => f.write_str("ramp"),
            Self::Default => f.write_str("default"),
        }
    }
}

// ---------------------------------------------------------------------------
// IngestionError
// ---------------------------------------------------------------------------

/// Errors from the proof ingestion subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngestionError {
    /// Proof validation failed.
    ValidationFailed {
        proof_id: EngineObjectId,
        status: ProofValidationStatus,
    },
    /// No hypotheses could be generated from proof.
    NoHypothesesGenerated { proof_id: EngineObjectId },
    /// Hypothesis generation failed.
    HypothesisGenerationFailed { reason: String },
    /// Proof type not supported by current configuration.
    UnsupportedProofType { proof_type: ProofType },
    /// ID derivation failed.
    IdDerivation(String),
    /// Engine is in conservative mode due to churn dampening.
    ConservativeModeActive {
        invalidation_count: u64,
        window_ns: u64,
    },
}

impl fmt::Display for IngestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed { proof_id, status } => {
                write!(f, "validation failed for {proof_id}: {status}")
            }
            Self::NoHypothesesGenerated { proof_id } => {
                write!(f, "no hypotheses from proof {proof_id}")
            }
            Self::HypothesisGenerationFailed { reason } => {
                write!(f, "hypothesis generation failed: {reason}")
            }
            Self::UnsupportedProofType { proof_type } => {
                write!(f, "unsupported proof type: {proof_type}")
            }
            Self::IdDerivation(msg) => write!(f, "id derivation: {msg}"),
            Self::ConservativeModeActive {
                invalidation_count,
                window_ns,
            } => write!(
                f,
                "conservative mode: {invalidation_count} invalidations in {window_ns}ns"
            ),
        }
    }
}

impl std::error::Error for IngestionError {}

// ---------------------------------------------------------------------------
// ProofIngestionEngine — the core ingestion engine
// ---------------------------------------------------------------------------

/// Configuration for the proof ingestion engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionConfig {
    /// Active policy ID that proofs must match.
    pub active_policy_id: String,
    /// Signing key for receipts and signatures.
    pub signing_key: [u8; 32],
    /// Churn dampening threshold: max invalidations per window.
    pub churn_threshold: u64,
    /// Churn dampening window in nanoseconds.
    pub churn_window_ns: u64,
    /// Default expected speedup for PLAS hypotheses (millionths).
    pub plas_speedup_estimate: u64,
    /// Default expected speedup for IFC hypotheses (millionths).
    pub ifc_speedup_estimate: u64,
    /// Default expected speedup for replay hypotheses (millionths).
    pub replay_speedup_estimate: u64,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            active_policy_id: String::new(),
            signing_key: [0u8; 32],
            churn_threshold: 10,
            churn_window_ns: 60_000_000_000,    // 60 seconds
            plas_speedup_estimate: 1_200_000,   // 1.2x
            ifc_speedup_estimate: 1_100_000,    // 1.1x
            replay_speedup_estimate: 1_500_000, // 1.5x
        }
    }
}

/// The core proof ingestion engine.
///
/// Accepts security proofs, validates them, generates optimization hypotheses,
/// tracks epoch-bound validity, and emits specialization receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofIngestionEngine {
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Configuration.
    config: IngestionConfig,
    /// Ingested proofs keyed by proof_id.
    active_proofs: BTreeMap<EngineObjectId, ProofInput>,
    /// Generated hypotheses keyed by hypothesis_id.
    active_hypotheses: BTreeMap<EngineObjectId, OptimizerHypothesis>,
    /// Mapping from proof_id -> hypothesis_ids derived from it.
    proof_to_hypotheses: BTreeMap<EngineObjectId, BTreeSet<EngineObjectId>>,
    /// Emitted specialization receipts.
    receipts: Vec<SpecializationReceipt>,
    /// Audit event log.
    events: Vec<IngestionEvent>,
    /// Next event sequence number.
    event_seq: u64,
    /// Recent invalidation timestamps for churn dampening.
    recent_invalidations: Vec<u64>,
    /// Whether conservative mode is active.
    conservative_mode: bool,
    /// Supported proof types.
    supported_proof_types: BTreeSet<ProofType>,
}

impl ProofIngestionEngine {
    /// Create a new ingestion engine.
    pub fn new(epoch: SecurityEpoch, config: IngestionConfig) -> Self {
        let mut supported = BTreeSet::new();
        supported.insert(ProofType::PlasCapabilityWitness);
        supported.insert(ProofType::IfcFlowProof);
        supported.insert(ProofType::ReplaySequenceMotif);

        Self {
            current_epoch: epoch,
            config,
            active_proofs: BTreeMap::new(),
            active_hypotheses: BTreeMap::new(),
            proof_to_hypotheses: BTreeMap::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            event_seq: 0,
            recent_invalidations: Vec::new(),
            conservative_mode: false,
            supported_proof_types: supported,
        }
    }

    /// Get the current epoch.
    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Get the audit event log.
    pub fn events(&self) -> &[IngestionEvent] {
        &self.events
    }

    /// Get all active proofs.
    pub fn active_proofs(&self) -> &BTreeMap<EngineObjectId, ProofInput> {
        &self.active_proofs
    }

    /// Get all active hypotheses.
    pub fn active_hypotheses(&self) -> &BTreeMap<EngineObjectId, OptimizerHypothesis> {
        &self.active_hypotheses
    }

    /// Get emitted receipts.
    pub fn receipts(&self) -> &[SpecializationReceipt] {
        &self.receipts
    }

    /// Whether conservative mode is currently active.
    pub fn is_conservative_mode(&self) -> bool {
        self.conservative_mode
    }

    /// Update the active policy ID.
    pub fn set_active_policy(&mut self, policy_id: &str) {
        self.config.active_policy_id = policy_id.to_string();
    }

    // -----------------------------------------------------------------------
    // Proof submission and validation
    // -----------------------------------------------------------------------

    /// Submit a proof for ingestion. Returns hypotheses on success.
    pub fn ingest_proof(
        &mut self,
        proof: ProofInput,
        current_ns: u64,
    ) -> Result<Vec<OptimizerHypothesis>, IngestionError> {
        // Emit submission event.
        self.emit_event(
            current_ns,
            IngestionEventType::ProofSubmitted {
                proof_id: proof.proof_id.clone(),
                proof_type: proof.proof_type,
            },
        );

        // Validate.
        let status = self.validate_proof(&proof, current_ns);
        self.emit_event(
            current_ns,
            IngestionEventType::ProofValidated {
                proof_id: proof.proof_id.clone(),
                status: status.clone(),
            },
        );

        if status != ProofValidationStatus::Accepted {
            return Err(IngestionError::ValidationFailed {
                proof_id: proof.proof_id,
                status,
            });
        }

        // Generate hypotheses.
        let hypotheses = self.generate_hypotheses(&proof, current_ns)?;
        if hypotheses.is_empty() {
            return Err(IngestionError::NoHypothesesGenerated {
                proof_id: proof.proof_id,
            });
        }

        // Register proof and hypotheses.
        let proof_id = proof.proof_id.clone();
        self.active_proofs.insert(proof_id.clone(), proof);
        let mut hyp_ids = BTreeSet::new();
        for h in &hypotheses {
            hyp_ids.insert(h.hypothesis_id.clone());
            self.active_hypotheses
                .insert(h.hypothesis_id.clone(), h.clone());
            self.emit_event(
                current_ns,
                IngestionEventType::HypothesisGenerated {
                    hypothesis_id: h.hypothesis_id.clone(),
                    kind: h.kind.clone(),
                    source_proof_count: h.source_proof_ids.len(),
                },
            );
        }
        self.proof_to_hypotheses.insert(proof_id, hyp_ids);

        Ok(hypotheses)
    }

    /// Validate a proof input against current engine state.
    fn validate_proof(&self, proof: &ProofInput, current_ns: u64) -> ProofValidationStatus {
        // Check supported type.
        if !self.supported_proof_types.contains(&proof.proof_type) {
            return ProofValidationStatus::SemanticCheckFailed {
                reason: format!("unsupported proof type: {}", proof.proof_type),
            };
        }

        // Check for duplicates.
        if let Some(_existing) = self.active_proofs.get(&proof.proof_id) {
            return ProofValidationStatus::Duplicate {
                existing_id: proof.proof_id.clone(),
            };
        }

        // Epoch freshness: proof epoch must match current.
        if proof.proof_epoch != self.current_epoch {
            return ProofValidationStatus::EpochStale {
                proof_epoch: proof.proof_epoch,
                current_epoch: self.current_epoch,
            };
        }

        if proof.validity_end_ns > 0 && proof.validity_start_ns > proof.validity_end_ns {
            return ProofValidationStatus::SemanticCheckFailed {
                reason: format!(
                    "invalid validity window: start {} exceeds end {}",
                    proof.validity_start_ns, proof.validity_end_ns
                ),
            };
        }

        if current_ns < proof.validity_start_ns {
            return ProofValidationStatus::NotYetValid {
                validity_start_ns: proof.validity_start_ns,
                current_ns,
            };
        }

        // Validity window.
        if proof.validity_end_ns > 0 && current_ns > proof.validity_end_ns {
            return ProofValidationStatus::Expired {
                validity_end_ns: proof.validity_end_ns,
                current_ns,
            };
        }

        // Policy match.
        if !self.config.active_policy_id.is_empty()
            && proof.linked_policy_id != self.config.active_policy_id
        {
            return ProofValidationStatus::PolicyMismatch {
                proof_policy: proof.linked_policy_id.clone(),
                active_policy: self.config.active_policy_id.clone(),
            };
        }

        // Signature verification (simplified: verify hash-based signature).
        let expected_sig = self.compute_signature(&proof.canonical_bytes());
        if proof.issuer_signature != expected_sig {
            return ProofValidationStatus::SignatureInvalid;
        }

        ProofValidationStatus::Accepted
    }

    // -----------------------------------------------------------------------
    // Hypothesis generation
    // -----------------------------------------------------------------------

    /// Generate optimizer hypotheses from a validated proof.
    fn generate_hypotheses(
        &self,
        proof: &ProofInput,
        _current_ns: u64,
    ) -> Result<Vec<OptimizerHypothesis>, IngestionError> {
        let mut hypotheses = Vec::new();
        let mut source_ids = BTreeSet::new();
        source_ids.insert(proof.proof_id.clone());

        match proof.proof_type {
            ProofType::PlasCapabilityWitness => {
                // PLAS -> dead code elimination + dispatch specialization.
                let dce_id = self.derive_hypothesis_id(proof, "dce")?;
                hypotheses.push(OptimizerHypothesis {
                    hypothesis_id: dce_id,
                    source_proof_ids: source_ids.clone(),
                    kind: HypothesisKind::DeadCodeElimination,
                    optimization_class: OptimizationClass::TraceSpecialization,
                    expected_speedup_millionths: self.config.plas_speedup_estimate,
                    risk: RiskLevel::Low,
                    validity_epoch: proof.proof_epoch,
                    derivation_hash: ContentHash::compute(&proof.payload),
                });

                let ds_id = self.derive_hypothesis_id(proof, "dispatch")?;
                hypotheses.push(OptimizerHypothesis {
                    hypothesis_id: ds_id,
                    source_proof_ids: source_ids,
                    kind: HypothesisKind::DispatchSpecialization,
                    optimization_class: OptimizationClass::DevirtualizedHostcallFastPath,
                    expected_speedup_millionths: self.config.plas_speedup_estimate,
                    risk: RiskLevel::Medium,
                    validity_epoch: proof.proof_epoch,
                    derivation_hash: ContentHash::compute(&proof.payload),
                });
            }
            ProofType::IfcFlowProof => {
                // IFC -> flow check elision.
                let fce_id = self.derive_hypothesis_id(proof, "flow-elide")?;
                hypotheses.push(OptimizerHypothesis {
                    hypothesis_id: fce_id,
                    source_proof_ids: source_ids,
                    kind: HypothesisKind::FlowCheckElision,
                    optimization_class: OptimizationClass::LayoutSpecialization,
                    expected_speedup_millionths: self.config.ifc_speedup_estimate,
                    risk: RiskLevel::High,
                    validity_epoch: proof.proof_epoch,
                    derivation_hash: ContentHash::compute(&proof.payload),
                });
            }
            ProofType::ReplaySequenceMotif => {
                // Replay -> superinstruction fusion.
                let fuse_id = self.derive_hypothesis_id(proof, "fuse")?;
                hypotheses.push(OptimizerHypothesis {
                    hypothesis_id: fuse_id,
                    source_proof_ids: source_ids,
                    kind: HypothesisKind::SuperinstructionFusion,
                    optimization_class: OptimizationClass::Superinstruction,
                    expected_speedup_millionths: self.config.replay_speedup_estimate,
                    risk: RiskLevel::Medium,
                    validity_epoch: proof.proof_epoch,
                    derivation_hash: ContentHash::compute(&proof.payload),
                });
            }
        }

        Ok(hypotheses)
    }

    /// Derive a deterministic hypothesis ID from proof and suffix.
    fn derive_hypothesis_id(
        &self,
        proof: &ProofInput,
        suffix: &str,
    ) -> Result<EngineObjectId, IngestionError> {
        let schema_id = SchemaId::from_definition(HYPOTHESIS_SCHEMA_DEF);
        let mut canonical = proof.canonical_bytes();
        canonical.extend_from_slice(suffix.as_bytes());
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            PROOF_INGESTION_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| IngestionError::IdDerivation(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Epoch transitions and invalidation
    // -----------------------------------------------------------------------

    /// Advance to a new epoch, invalidating stale proofs and hypotheses.
    ///
    /// Returns the count of invalidated hypotheses.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch, current_ns: u64) -> u64 {
        let old_epoch = self.current_epoch;
        self.current_epoch = new_epoch;

        // Find proofs bound to the old epoch.
        let stale_proof_ids: Vec<EngineObjectId> = self
            .active_proofs
            .iter()
            .filter(|(_, p)| p.proof_epoch != new_epoch)
            .map(|(id, _)| id.clone())
            .collect();

        let mut invalidated_count = 0u64;

        for proof_id in &stale_proof_ids {
            // Invalidate derived hypotheses.
            if let Some(hyp_ids) = self.proof_to_hypotheses.remove(proof_id) {
                for hid in &hyp_ids {
                    self.active_hypotheses.remove(hid);
                    self.emit_event(
                        current_ns,
                        IngestionEventType::HypothesisInvalidated {
                            hypothesis_id: hid.clone(),
                            reason: format!("epoch transition: {} -> {}", old_epoch, new_epoch),
                        },
                    );
                    invalidated_count += 1;
                }
            }

            // Remove proof.
            self.active_proofs.remove(proof_id);
            self.emit_event(
                current_ns,
                IngestionEventType::ProofInvalidated {
                    proof_id: proof_id.clone(),
                    reason: format!("epoch transition: {} -> {}", old_epoch, new_epoch),
                },
            );
        }

        // Update churn tracking.
        if invalidated_count > 0 {
            self.recent_invalidations.push(current_ns);
            self.update_churn_state(current_ns);
        }

        invalidated_count
    }

    /// Invalidate a specific proof and its derived hypotheses.
    pub fn invalidate_proof(
        &mut self,
        proof_id: &EngineObjectId,
        reason: &str,
        current_ns: u64,
    ) -> u64 {
        let mut count = 0u64;

        if let Some(hyp_ids) = self.proof_to_hypotheses.remove(proof_id) {
            for hid in &hyp_ids {
                self.active_hypotheses.remove(hid);
                self.emit_event(
                    current_ns,
                    IngestionEventType::HypothesisInvalidated {
                        hypothesis_id: hid.clone(),
                        reason: reason.to_string(),
                    },
                );
                count += 1;
            }
        }

        if self.active_proofs.remove(proof_id).is_some() {
            self.emit_event(
                current_ns,
                IngestionEventType::ProofInvalidated {
                    proof_id: proof_id.clone(),
                    reason: reason.to_string(),
                },
            );
        }

        if count > 0 {
            self.recent_invalidations.push(current_ns);
            self.update_churn_state(current_ns);
        }

        count
    }

    /// Update churn dampening state.
    fn update_churn_state(&mut self, current_ns: u64) {
        // Remove invalidations outside the window.
        let cutoff = current_ns.saturating_sub(self.config.churn_window_ns);
        self.recent_invalidations.retain(|&ts| ts >= cutoff);

        self.conservative_mode =
            self.recent_invalidations.len() as u64 >= self.config.churn_threshold;
    }

    // -----------------------------------------------------------------------
    // Specialization receipt emission
    // -----------------------------------------------------------------------

    /// Emit a specialization receipt for an activated hypothesis.
    pub fn emit_receipt(
        &mut self,
        hypothesis_id: &EngineObjectId,
        transformation_witness_hash: ContentHash,
        equivalence_evidence_hash: ContentHash,
        rollback_token_hash: ContentHash,
        stage: ActivationStageLocal,
        current_ns: u64,
    ) -> Result<SpecializationReceipt, IngestionError> {
        let hypothesis = self
            .active_hypotheses
            .get(hypothesis_id)
            .ok_or_else(|| IngestionError::HypothesisGenerationFailed {
                reason: format!("hypothesis not found: {hypothesis_id}"),
            })?
            .clone();

        let receipt_id = self.derive_receipt_id(&hypothesis, current_ns)?;

        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(receipt_id.as_bytes());
        sig_input.extend_from_slice(&current_ns.to_be_bytes());
        let signature = self.compute_signature(&sig_input);

        let receipt = SpecializationReceipt {
            receipt_id: receipt_id.clone(),
            proof_input_ids: hypothesis.source_proof_ids.clone(),
            hypothesis_id: hypothesis_id.clone(),
            optimization_class: hypothesis.optimization_class.clone(),
            transformation_witness_hash,
            equivalence_evidence_hash,
            rollback_token_hash,
            activation_stage: stage,
            epoch: self.current_epoch,
            issued_at_ns: current_ns,
            signature,
        };

        self.receipts.push(receipt.clone());
        self.emit_event(
            current_ns,
            IngestionEventType::SpecializationReceiptEmitted {
                receipt_id,
                hypothesis_id: hypothesis_id.clone(),
            },
        );

        Ok(receipt)
    }

    /// Derive a deterministic receipt ID.
    fn derive_receipt_id(
        &self,
        hypothesis: &OptimizerHypothesis,
        current_ns: u64,
    ) -> Result<EngineObjectId, IngestionError> {
        let schema_id = SchemaId::from_definition(SPECIALIZATION_RECEIPT_SCHEMA_DEF);
        let mut canonical = hypothesis.hypothesis_id.as_bytes().to_vec();
        canonical.extend_from_slice(&current_ns.to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            PROOF_INGESTION_ZONE,
            &schema_id,
            &canonical,
        )
        .map_err(|e| IngestionError::IdDerivation(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Simplified HMAC-like signature using signing key.
    fn compute_signature(&self, data: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.config.signing_key);
        input.extend_from_slice(data);
        ContentHash::compute(&input).as_bytes().to_vec()
    }

    /// Emit an audit event.
    fn emit_event(&mut self, timestamp_ns: u64, event_type: IngestionEventType) {
        let event = IngestionEvent {
            seq: self.event_seq,
            timestamp_ns,
            event_type,
            epoch: self.current_epoch,
        };
        self.event_seq += 1;
        self.events.push(event);
    }

    /// Get hypotheses for a specific proof.
    pub fn hypotheses_for_proof(&self, proof_id: &EngineObjectId) -> Vec<&OptimizerHypothesis> {
        self.proof_to_hypotheses
            .get(proof_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.active_hypotheses.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all hypotheses of a specific kind.
    pub fn hypotheses_by_kind(&self, kind: &HypothesisKind) -> Vec<&OptimizerHypothesis> {
        self.active_hypotheses
            .values()
            .filter(|h| &h.kind == kind)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Helper: create a proof input with proper ID derivation
// ---------------------------------------------------------------------------

/// Build a `ProofInput` with a deterministically derived ID.
pub fn create_proof_input(
    proof_type: ProofType,
    proof_epoch: SecurityEpoch,
    validity_start_ns: u64,
    validity_end_ns: u64,
    linked_policy_id: &str,
    payload: &[u8],
    signing_key: &[u8; 32],
) -> Result<ProofInput, IngestionError> {
    let schema_id = SchemaId::from_definition(PROOF_INPUT_SCHEMA_DEF);
    let canonical_hash = ContentHash::compute(payload);
    let mut id_bytes = Vec::new();
    id_bytes.push(proof_type as u8);
    id_bytes.extend_from_slice(&proof_epoch.as_u64().to_be_bytes());
    id_bytes.extend_from_slice(canonical_hash.as_bytes());
    id_bytes.extend_from_slice(linked_policy_id.as_bytes());

    let proof_id = engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        PROOF_INGESTION_ZONE,
        &schema_id,
        &id_bytes,
    )
    .map_err(|e| IngestionError::IdDerivation(e.to_string()))?;

    let mut proof = ProofInput {
        proof_id,
        proof_type,
        proof_epoch,
        validity_start_ns,
        validity_end_ns,
        issuer_signature: Vec::new(),
        canonical_hash,
        linked_policy_id: linked_policy_id.to_string(),
        payload: payload.to_vec(),
    };

    // Sign the proof.
    let mut sig_input = Vec::with_capacity(32 + proof.canonical_bytes().len());
    sig_input.extend_from_slice(signing_key);
    sig_input.extend_from_slice(&proof.canonical_bytes());
    proof.issuer_signature = ContentHash::compute(&sig_input).as_bytes().to_vec();

    Ok(proof)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        key
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_config() -> IngestionConfig {
        IngestionConfig {
            active_policy_id: "policy-001".to_string(),
            signing_key: test_key(),
            ..Default::default()
        }
    }

    fn test_engine() -> ProofIngestionEngine {
        ProofIngestionEngine::new(test_epoch(), test_config())
    }

    fn make_proof(proof_type: ProofType, payload: &[u8], policy_id: &str) -> ProofInput {
        create_proof_input(
            proof_type,
            test_epoch(),
            0,
            0,
            policy_id,
            payload,
            &test_key(),
        )
        .expect("proof creation should succeed")
    }

    fn make_default_proof(proof_type: ProofType) -> ProofInput {
        make_proof(proof_type, b"test-payload", "policy-001")
    }

    // --- Proof creation ---

    #[test]
    fn create_proof_input_deterministic() {
        let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
        let p2 = make_default_proof(ProofType::PlasCapabilityWitness);
        assert_eq!(p1.proof_id, p2.proof_id);
        assert_eq!(p1.issuer_signature, p2.issuer_signature);
    }

    #[test]
    fn different_proof_types_different_ids() {
        let p1 = make_default_proof(ProofType::PlasCapabilityWitness);
        let p2 = make_default_proof(ProofType::IfcFlowProof);
        assert_ne!(p1.proof_id, p2.proof_id);
    }

    #[test]
    fn different_payloads_different_ids() {
        let p1 = make_proof(ProofType::PlasCapabilityWitness, b"payload-a", "policy-001");
        let p2 = make_proof(ProofType::PlasCapabilityWitness, b"payload-b", "policy-001");
        assert_ne!(p1.proof_id, p2.proof_id);
    }

    // --- Happy path ingestion ---

    #[test]
    fn ingest_plas_witness_generates_two_hypotheses() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses.len(), 2);
        assert_eq!(hypotheses[0].kind, HypothesisKind::DeadCodeElimination);
        assert_eq!(hypotheses[1].kind, HypothesisKind::DispatchSpecialization);
    }

    #[test]
    fn ingest_ifc_proof_generates_flow_elision() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::IfcFlowProof);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses.len(), 1);
        assert_eq!(hypotheses[0].kind, HypothesisKind::FlowCheckElision);
        assert_eq!(hypotheses[0].risk, RiskLevel::High);
    }

    #[test]
    fn ingest_replay_motif_generates_superinstruction() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::ReplaySequenceMotif);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses.len(), 1);
        assert_eq!(hypotheses[0].kind, HypothesisKind::SuperinstructionFusion);
    }

    #[test]
    fn ingested_proof_tracked_in_active_proofs() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let proof_id = proof.proof_id.clone();
        engine.ingest_proof(proof, 1000).unwrap();

        assert!(engine.active_proofs().contains_key(&proof_id));
        assert_eq!(engine.active_hypotheses().len(), 2);
    }

    #[test]
    fn hypotheses_for_proof_returns_correct_set() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let proof_id = proof.proof_id.clone();
        engine.ingest_proof(proof, 1000).unwrap();

        let hyps = engine.hypotheses_for_proof(&proof_id);
        assert_eq!(hyps.len(), 2);
    }

    #[test]
    fn hypotheses_by_kind_filters_correctly() {
        let mut engine = test_engine();

        let p1 = make_proof(ProofType::PlasCapabilityWitness, b"plas-1", "policy-001");
        let p2 = make_proof(ProofType::IfcFlowProof, b"ifc-1", "policy-001");
        engine.ingest_proof(p1, 1000).unwrap();
        engine.ingest_proof(p2, 1000).unwrap();

        let dce = engine.hypotheses_by_kind(&HypothesisKind::DeadCodeElimination);
        assert_eq!(dce.len(), 1);
        let fce = engine.hypotheses_by_kind(&HypothesisKind::FlowCheckElision);
        assert_eq!(fce.len(), 1);
    }

    // --- Validation failures ---

    #[test]
    fn rejects_duplicate_proof() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof.clone(), 1000).unwrap();

        let err = engine.ingest_proof(proof, 2000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::Duplicate { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_stale_epoch() {
        let mut engine = test_engine();
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            SecurityEpoch::from_raw(50), // stale
            0,
            0,
            "policy-001",
            b"test",
            &test_key(),
        )
        .unwrap();

        let err = engine.ingest_proof(proof, 1000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::EpochStale { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_not_yet_valid_proof() {
        let mut engine = test_engine();
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            test_epoch(),
            2_000,
            0,
            "policy-001",
            b"test",
            &test_key(),
        )
        .unwrap();

        let err = engine.ingest_proof(proof, 1_000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::NotYetValid { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_expired_proof() {
        let mut engine = test_engine();
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            test_epoch(),
            0,
            500, // expires at 500
            "policy-001",
            b"test",
            &test_key(),
        )
        .unwrap();

        let err = engine.ingest_proof(proof, 1000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::Expired { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_inverted_validity_window() {
        let mut engine = test_engine();
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            test_epoch(),
            2_000,
            1_000,
            "policy-001",
            b"test",
            &test_key(),
        )
        .unwrap();

        let err = engine.ingest_proof(proof, 1_500).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::SemanticCheckFailed { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_policy_mismatch() {
        let mut engine = test_engine();
        let proof = make_proof(ProofType::PlasCapabilityWitness, b"test", "wrong-policy");

        let err = engine.ingest_proof(proof, 1000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::PolicyMismatch { .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut engine = test_engine();
        let mut proof = make_default_proof(ProofType::PlasCapabilityWitness);
        proof.issuer_signature = vec![0xDE, 0xAD]; // tamper

        let err = engine.ingest_proof(proof, 1000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::SignatureInvalid,
                ..
            }
        ));
    }

    // --- Epoch transition and invalidation ---

    #[test]
    fn epoch_advance_invalidates_stale_proofs() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(engine.active_proofs().len(), 1);
        assert_eq!(engine.active_hypotheses().len(), 2);

        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
        assert_eq!(invalidated, 2); // 2 hypotheses invalidated
        assert!(engine.active_proofs().is_empty());
        assert!(engine.active_hypotheses().is_empty());
    }

    #[test]
    fn epoch_advance_preserves_current_epoch_proofs() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        // Advance to same epoch — nothing invalidated.
        let invalidated = engine.advance_epoch(test_epoch(), 2000);
        assert_eq!(invalidated, 0);
        assert_eq!(engine.active_proofs().len(), 1);
    }

    #[test]
    fn invalidate_specific_proof() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let proof_id = proof.proof_id.clone();
        engine.ingest_proof(proof, 1000).unwrap();

        let count = engine.invalidate_proof(&proof_id, "revoked", 2000);
        assert_eq!(count, 2); // 2 hypotheses
        assert!(engine.active_proofs().is_empty());
        assert!(engine.active_hypotheses().is_empty());
    }

    #[test]
    fn invalidation_cascade_events() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);

        // Should have: 2 submitted/validated events + 2 hypothesis generated +
        // 2 hypothesis invalidated + 1 proof invalidated = 7
        let invalidated_events: Vec<_> = engine
            .events()
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    IngestionEventType::HypothesisInvalidated { .. }
                        | IngestionEventType::ProofInvalidated { .. }
                )
            })
            .collect();
        assert_eq!(invalidated_events.len(), 3); // 2 hyp + 1 proof
    }

    // --- Churn dampening ---

    #[test]
    fn churn_dampening_activates() {
        let mut config = test_config();
        config.churn_threshold = 3;
        config.churn_window_ns = 10_000;
        let mut engine = ProofIngestionEngine::new(test_epoch(), config);

        // Ingest and invalidate proofs in a loop.
        for i in 0..3 {
            let proof = make_proof(
                ProofType::PlasCapabilityWitness,
                format!("payload-{i}").as_bytes(),
                "policy-001",
            );
            let proof_id = proof.proof_id.clone();
            engine.ingest_proof(proof, 1000 + i * 100).unwrap();
            engine.invalidate_proof(&proof_id, "test-churn", 1000 + i * 100 + 50);
        }

        assert!(engine.is_conservative_mode());
    }

    #[test]
    fn churn_dampening_deactivates_after_window() {
        let mut config = test_config();
        config.churn_threshold = 2;
        config.churn_window_ns = 1000;
        let mut engine = ProofIngestionEngine::new(test_epoch(), config);

        // Two rapid invalidations.
        let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
        let p1_id = p1.proof_id.clone();
        engine.ingest_proof(p1, 100).unwrap();
        engine.invalidate_proof(&p1_id, "test", 200);

        let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
        let p2_id = p2.proof_id.clone();
        engine.ingest_proof(p2, 300).unwrap();
        engine.invalidate_proof(&p2_id, "test", 400);

        assert!(engine.is_conservative_mode());

        // Ingest a proof way later (outside window) and invalidate it.
        let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");
        let p3_id = p3.proof_id.clone();
        engine.ingest_proof(p3, 5000).unwrap();
        engine.invalidate_proof(&p3_id, "test", 5100);

        // Window is 1000ns, so old invalidations at 200 and 400 should be pruned.
        // Only the one at 5100 remains, which is < threshold of 2.
        assert!(!engine.is_conservative_mode());
    }

    // --- Specialization receipt emission ---

    #[test]
    fn emit_receipt_for_activated_hypothesis() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();
        let hyp_id = hypotheses[0].hypothesis_id.clone();

        let receipt = engine
            .emit_receipt(
                &hyp_id,
                ContentHash::compute(b"transform-witness"),
                ContentHash::compute(b"equivalence-evidence"),
                ContentHash::compute(b"rollback-token"),
                ActivationStageLocal::Shadow,
                2000,
            )
            .unwrap();

        assert_eq!(receipt.hypothesis_id, hyp_id);
        assert_eq!(receipt.activation_stage, ActivationStageLocal::Shadow);
        assert_eq!(receipt.epoch, test_epoch());
        assert!(!receipt.signature.is_empty());
        assert_eq!(engine.receipts().len(), 1);
    }

    #[test]
    fn emit_receipt_fails_for_unknown_hypothesis() {
        let mut engine = test_engine();
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"fake",
        )
        .unwrap();

        let err = engine
            .emit_receipt(
                &fake_id,
                ContentHash::compute(b"a"),
                ContentHash::compute(b"b"),
                ContentHash::compute(b"c"),
                ActivationStageLocal::Default,
                1000,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            IngestionError::HypothesisGenerationFailed { .. }
        ));
    }

    // --- Audit events ---

    #[test]
    fn events_have_monotonic_sequence() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        for (i, event) in engine.events().iter().enumerate() {
            assert_eq!(event.seq, i as u64);
        }
    }

    #[test]
    fn events_record_epoch() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        for event in engine.events() {
            assert_eq!(event.epoch, test_epoch());
        }
    }

    // --- Display impls ---

    #[test]
    fn proof_type_display() {
        assert_eq!(
            ProofType::PlasCapabilityWitness.to_string(),
            "plas-capability-witness"
        );
        assert_eq!(ProofType::IfcFlowProof.to_string(), "ifc-flow-proof");
        assert_eq!(
            ProofType::ReplaySequenceMotif.to_string(),
            "replay-sequence-motif"
        );
    }

    #[test]
    fn hypothesis_kind_display() {
        assert_eq!(
            HypothesisKind::DeadCodeElimination.to_string(),
            "dead-code-elimination"
        );
        assert_eq!(
            HypothesisKind::DispatchSpecialization.to_string(),
            "dispatch-specialization"
        );
        assert_eq!(
            HypothesisKind::FlowCheckElision.to_string(),
            "flow-check-elision"
        );
        assert_eq!(
            HypothesisKind::SuperinstructionFusion.to_string(),
            "superinstruction-fusion"
        );
    }

    #[test]
    fn risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Medium.to_string(), "medium");
        assert_eq!(RiskLevel::High.to_string(), "high");
    }

    #[test]
    fn activation_stage_display() {
        assert_eq!(ActivationStageLocal::Shadow.to_string(), "shadow");
        assert_eq!(ActivationStageLocal::Canary.to_string(), "canary");
        assert_eq!(ActivationStageLocal::Ramp.to_string(), "ramp");
        assert_eq!(ActivationStageLocal::Default.to_string(), "default");
    }

    #[test]
    fn error_display_coverage() {
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"fake",
        )
        .unwrap();

        let errors = vec![
            IngestionError::ValidationFailed {
                proof_id: fake_id.clone(),
                status: ProofValidationStatus::SignatureInvalid,
            },
            IngestionError::NoHypothesesGenerated {
                proof_id: fake_id.clone(),
            },
            IngestionError::HypothesisGenerationFailed {
                reason: "test".to_string(),
            },
            IngestionError::UnsupportedProofType {
                proof_type: ProofType::PlasCapabilityWitness,
            },
            IngestionError::IdDerivation("test".to_string()),
            IngestionError::ConservativeModeActive {
                invalidation_count: 5,
                window_ns: 1000,
            },
        ];

        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "error display should not be empty: {e:?}");
        }
    }

    #[test]
    fn validation_status_display_coverage() {
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"fake",
        )
        .unwrap();

        let statuses = vec![
            ProofValidationStatus::Accepted,
            ProofValidationStatus::SignatureInvalid,
            ProofValidationStatus::EpochStale {
                proof_epoch: SecurityEpoch::from_raw(1),
                current_epoch: SecurityEpoch::from_raw(2),
            },
            ProofValidationStatus::NotYetValid {
                validity_start_ns: 300,
                current_ns: 200,
            },
            ProofValidationStatus::Expired {
                validity_end_ns: 100,
                current_ns: 200,
            },
            ProofValidationStatus::PolicyMismatch {
                proof_policy: "a".to_string(),
                active_policy: "b".to_string(),
            },
            ProofValidationStatus::SemanticCheckFailed {
                reason: "test".to_string(),
            },
            ProofValidationStatus::Duplicate {
                existing_id: fake_id,
            },
        ];

        for s in &statuses {
            let display = s.to_string();
            assert!(
                !display.is_empty(),
                "status display should not be empty: {s:?}"
            );
        }
    }

    // --- Serde roundtrip ---

    #[test]
    fn proof_input_serde_roundtrip() {
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let json = serde_json::to_string(&proof).unwrap();
        let restored: ProofInput = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, restored);
    }

    #[test]
    fn hypothesis_serde_roundtrip() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::IfcFlowProof);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        let json = serde_json::to_string(&hypotheses[0]).unwrap();
        let restored: OptimizerHypothesis = serde_json::from_str(&json).unwrap();
        assert_eq!(hypotheses[0], restored);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::ReplaySequenceMotif);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        let receipt = engine
            .emit_receipt(
                &hypotheses[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                ActivationStageLocal::Canary,
                2000,
            )
            .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: SpecializationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn ingestion_event_serde_roundtrip() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        engine.ingest_proof(proof, 1000).unwrap();

        let event = &engine.events()[0];
        let json = serde_json::to_string(event).unwrap();
        let restored: IngestionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, restored);
    }

    // --- Unbounded validity ---

    #[test]
    fn proof_with_zero_validity_end_never_expires() {
        let mut engine = test_engine();
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            test_epoch(),
            0,
            0, // unbounded
            "policy-001",
            b"test",
            &test_key(),
        )
        .unwrap();

        // Even at a very large timestamp, it shouldn't expire.
        let result = engine.ingest_proof(proof, u64::MAX / 2);
        assert!(result.is_ok());
    }

    // --- Multiple proofs ---

    #[test]
    fn multiple_proofs_accumulate() {
        let mut engine = test_engine();

        let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
        let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
        let p3 = make_proof(ProofType::ReplaySequenceMotif, b"c", "policy-001");

        engine.ingest_proof(p1, 1000).unwrap();
        engine.ingest_proof(p2, 1000).unwrap();
        engine.ingest_proof(p3, 1000).unwrap();

        assert_eq!(engine.active_proofs().len(), 3);
        assert_eq!(engine.active_hypotheses().len(), 4); // 2 + 1 + 1
    }

    #[test]
    fn epoch_advance_invalidates_all() {
        let mut engine = test_engine();

        let p1 = make_proof(ProofType::PlasCapabilityWitness, b"a", "policy-001");
        let p2 = make_proof(ProofType::IfcFlowProof, b"b", "policy-001");
        engine.ingest_proof(p1, 1000).unwrap();
        engine.ingest_proof(p2, 1000).unwrap();

        let invalidated = engine.advance_epoch(SecurityEpoch::from_raw(101), 2000);
        assert_eq!(invalidated, 3); // 2 plas + 1 ifc
        assert!(engine.active_proofs().is_empty());
        assert!(engine.active_hypotheses().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for leaf types
    // -----------------------------------------------------------------------

    #[test]
    fn proof_type_serde_roundtrip() {
        for pt in [
            ProofType::PlasCapabilityWitness,
            ProofType::IfcFlowProof,
            ProofType::ReplaySequenceMotif,
        ] {
            let json = serde_json::to_string(&pt).unwrap();
            let restored: ProofType = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, pt);
        }
    }

    #[test]
    fn hypothesis_kind_serde_roundtrip() {
        for hk in [
            HypothesisKind::DeadCodeElimination,
            HypothesisKind::DispatchSpecialization,
            HypothesisKind::FlowCheckElision,
            HypothesisKind::SuperinstructionFusion,
        ] {
            let json = serde_json::to_string(&hk).unwrap();
            let restored: HypothesisKind = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, hk);
        }
    }

    #[test]
    fn risk_level_serde_roundtrip() {
        for rl in [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High] {
            let json = serde_json::to_string(&rl).unwrap();
            let restored: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, rl);
        }
    }

    #[test]
    fn activation_stage_serde_roundtrip() {
        for stage in [
            ActivationStageLocal::Shadow,
            ActivationStageLocal::Canary,
            ActivationStageLocal::Ramp,
            ActivationStageLocal::Default,
        ] {
            let json = serde_json::to_string(&stage).unwrap();
            let restored: ActivationStageLocal = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, stage);
        }
    }

    #[test]
    fn ingestion_config_serde_roundtrip() {
        let cfg = test_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: IngestionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, cfg);
    }

    #[test]
    fn ingestion_error_serde_roundtrip_all_variants() {
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"fake",
        )
        .unwrap();

        let errors = vec![
            IngestionError::ValidationFailed {
                proof_id: fake_id.clone(),
                status: ProofValidationStatus::SignatureInvalid,
            },
            IngestionError::NoHypothesesGenerated {
                proof_id: fake_id.clone(),
            },
            IngestionError::HypothesisGenerationFailed {
                reason: "bad derivation".to_string(),
            },
            IngestionError::UnsupportedProofType {
                proof_type: ProofType::ReplaySequenceMotif,
            },
            IngestionError::IdDerivation("test error".to_string()),
            IngestionError::ConservativeModeActive {
                invalidation_count: 12,
                window_ns: 60_000_000_000,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: IngestionError = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, err);
        }
    }

    #[test]
    fn validation_status_serde_roundtrip_all_variants() {
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"fake",
        )
        .unwrap();

        let statuses = vec![
            ProofValidationStatus::Accepted,
            ProofValidationStatus::SignatureInvalid,
            ProofValidationStatus::EpochStale {
                proof_epoch: SecurityEpoch::from_raw(10),
                current_epoch: SecurityEpoch::from_raw(20),
            },
            ProofValidationStatus::NotYetValid {
                validity_start_ns: 500,
                current_ns: 100,
            },
            ProofValidationStatus::Expired {
                validity_end_ns: 500,
                current_ns: 1000,
            },
            ProofValidationStatus::PolicyMismatch {
                proof_policy: "old-pol".to_string(),
                active_policy: "new-pol".to_string(),
            },
            ProofValidationStatus::SemanticCheckFailed {
                reason: "unsupported".to_string(),
            },
            ProofValidationStatus::Duplicate {
                existing_id: fake_id,
            },
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let restored: ProofValidationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, s);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display format verification
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_format_content() {
        let err = IngestionError::ConservativeModeActive {
            invalidation_count: 15,
            window_ns: 60_000,
        };
        let s = err.to_string();
        assert!(s.contains("15") && s.contains("60000"));

        let err = IngestionError::UnsupportedProofType {
            proof_type: ProofType::IfcFlowProof,
        };
        assert!(err.to_string().contains("ifc-flow-proof"));
    }

    #[test]
    fn validation_status_display_format_content() {
        let s = ProofValidationStatus::EpochStale {
            proof_epoch: SecurityEpoch::from_raw(5),
            current_epoch: SecurityEpoch::from_raw(10),
        };
        let display = s.to_string();
        assert!(display.contains("5") && display.contains("10"));

        let s = ProofValidationStatus::PolicyMismatch {
            proof_policy: "alpha".to_string(),
            active_policy: "beta".to_string(),
        };
        let display = s.to_string();
        assert!(display.contains("alpha") && display.contains("beta"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering and default
    // -----------------------------------------------------------------------

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
    }

    #[test]
    fn activation_stage_ordering() {
        assert!(ActivationStageLocal::Shadow < ActivationStageLocal::Canary);
        assert!(ActivationStageLocal::Canary < ActivationStageLocal::Ramp);
        assert!(ActivationStageLocal::Ramp < ActivationStageLocal::Default);
    }

    #[test]
    fn ingestion_config_default_values() {
        let cfg = IngestionConfig::default();
        assert!(cfg.active_policy_id.is_empty());
        assert_eq!(cfg.signing_key, [0u8; 32]);
        assert_eq!(cfg.churn_threshold, 10);
        assert_eq!(cfg.plas_speedup_estimate, 1_200_000);
        assert_eq!(cfg.ifc_speedup_estimate, 1_100_000);
        assert_eq!(cfg.replay_speedup_estimate, 1_500_000);
    }

    // -----------------------------------------------------------------------
    // Enrichment: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_unknown_proof_returns_zero() {
        let mut engine = test_engine();
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"unknown",
        )
        .unwrap();
        let count = engine.invalidate_proof(&fake_id, "test", 1000);
        assert_eq!(count, 0);
    }

    #[test]
    fn set_active_policy_changes_validation() {
        let mut engine = test_engine();
        // Proof matches original policy.
        let proof = make_proof(ProofType::PlasCapabilityWitness, b"x", "policy-001");
        assert!(engine.ingest_proof(proof, 1000).is_ok());

        // Change policy, new proof with old policy should fail.
        engine.set_active_policy("policy-002");
        let proof = make_proof(ProofType::IfcFlowProof, b"y", "policy-001");
        let err = engine.ingest_proof(proof, 2000).unwrap_err();
        assert!(matches!(
            err,
            IngestionError::ValidationFailed {
                status: ProofValidationStatus::PolicyMismatch { .. },
                ..
            }
        ));
    }

    #[test]
    fn canonical_bytes_deterministic_for_hypothesis() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::IfcFlowProof);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        let bytes1 = hypotheses[0].canonical_bytes();
        let bytes2 = hypotheses[0].canonical_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn empty_engine_serde_roundtrip() {
        // Full engine with proofs can't roundtrip due to BTreeMap<EngineObjectId, _> key issue.
        // Test empty engine which has no entries in those maps.
        let engine = test_engine();
        let json = serde_json::to_string(&engine).unwrap();
        let restored: ProofIngestionEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.current_epoch(), test_epoch());
        assert!(restored.active_proofs().is_empty());
        assert!(restored.active_hypotheses().is_empty());
    }

    #[test]
    fn hypotheses_for_unknown_proof_returns_empty() {
        let engine = test_engine();
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"none",
        )
        .unwrap();
        assert!(engine.hypotheses_for_proof(&fake_id).is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: canonical_bytes content
    // -----------------------------------------------------------------------

    #[test]
    fn proof_input_canonical_bytes_includes_all_fields() {
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let bytes = proof.canonical_bytes();

        // Must contain proof_id bytes, proof_type byte, epoch, start_ns, end_ns,
        // canonical_hash, and linked_policy_id.
        assert!(bytes.len() > proof.proof_id.as_bytes().len());
        // Starts with proof_id bytes.
        assert_eq!(
            &bytes[..proof.proof_id.as_bytes().len()],
            proof.proof_id.as_bytes()
        );
        // Ends with linked_policy_id bytes.
        assert_eq!(
            &bytes[bytes.len() - proof.linked_policy_id.len()..],
            proof.linked_policy_id.as_bytes()
        );
    }

    #[test]
    fn hypothesis_canonical_bytes_includes_source_proof_ids() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let hypotheses = engine.ingest_proof(proof.clone(), 1000).unwrap();

        let bytes = hypotheses[0].canonical_bytes();
        // Should include hypothesis_id bytes and source proof_id bytes.
        let hid_len = hypotheses[0].hypothesis_id.as_bytes().len();
        let pid_len = proof.proof_id.as_bytes().len();
        assert!(bytes.len() >= hid_len + pid_len);
    }

    // -----------------------------------------------------------------------
    // Enrichment: hypothesis properties per proof type
    // -----------------------------------------------------------------------

    #[test]
    fn plas_hypothesis_speedup_matches_config() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        for h in &hypotheses {
            assert_eq!(h.expected_speedup_millionths, 1_200_000);
        }
    }

    #[test]
    fn ifc_hypothesis_optimization_class_and_risk() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::IfcFlowProof);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses.len(), 1);
        assert_eq!(
            hypotheses[0].optimization_class,
            OptimizationClass::LayoutSpecialization
        );
        assert_eq!(hypotheses[0].risk, RiskLevel::High);
        assert_eq!(hypotheses[0].expected_speedup_millionths, 1_100_000);
    }

    #[test]
    fn replay_hypothesis_optimization_class_and_speedup() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::ReplaySequenceMotif);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses.len(), 1);
        assert_eq!(
            hypotheses[0].optimization_class,
            OptimizationClass::Superinstruction
        );
        assert_eq!(hypotheses[0].expected_speedup_millionths, 1_500_000);
        assert_eq!(hypotheses[0].risk, RiskLevel::Medium);
    }

    #[test]
    fn plas_hypothesis_classes_dce_and_dispatch() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        assert_eq!(hypotheses[0].risk, RiskLevel::Low);
        assert_eq!(
            hypotheses[0].optimization_class,
            OptimizationClass::TraceSpecialization
        );
        assert_eq!(hypotheses[1].risk, RiskLevel::Medium);
        assert_eq!(
            hypotheses[1].optimization_class,
            OptimizationClass::DevirtualizedHostcallFastPath
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: empty policy bypasses check
    // -----------------------------------------------------------------------

    #[test]
    fn empty_active_policy_accepts_any_proof_policy() {
        let mut config = test_config();
        config.active_policy_id = String::new();
        let mut engine = ProofIngestionEngine::new(test_epoch(), config);

        let proof = make_proof(
            ProofType::PlasCapabilityWitness,
            b"arbitrary",
            "any-policy-123",
        );
        // Should succeed despite mismatched policy, because engine has empty active_policy_id.
        assert!(engine.ingest_proof(proof, 1000).is_ok());
    }

    // -----------------------------------------------------------------------
    // Enrichment: receipt linkage and determinism
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_proof_input_ids_match_hypothesis_sources() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::PlasCapabilityWitness);
        let proof_id = proof.proof_id.clone();
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();

        let receipt = engine
            .emit_receipt(
                &hypotheses[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                ActivationStageLocal::Ramp,
                2000,
            )
            .unwrap();

        assert!(receipt.proof_input_ids.contains(&proof_id));
        assert_eq!(receipt.proof_input_ids.len(), 1);
    }

    #[test]
    fn receipt_signature_deterministic() {
        let mut engine1 = test_engine();
        let proof1 = make_default_proof(ProofType::IfcFlowProof);
        let hyps1 = engine1.ingest_proof(proof1, 1000).unwrap();
        let r1 = engine1
            .emit_receipt(
                &hyps1[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                ActivationStageLocal::Canary,
                2000,
            )
            .unwrap();

        let mut engine2 = test_engine();
        let proof2 = make_default_proof(ProofType::IfcFlowProof);
        let hyps2 = engine2.ingest_proof(proof2, 1000).unwrap();
        let r2 = engine2
            .emit_receipt(
                &hyps2[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                ActivationStageLocal::Canary,
                2000,
            )
            .unwrap();

        assert_eq!(r1.receipt_id, r2.receipt_id);
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn multiple_receipts_from_same_hypothesis() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::ReplaySequenceMotif);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();
        let hyp_id = hypotheses[0].hypothesis_id.clone();

        let r1 = engine
            .emit_receipt(
                &hyp_id,
                ContentHash::compute(b"tw1"),
                ContentHash::compute(b"ee1"),
                ContentHash::compute(b"rt1"),
                ActivationStageLocal::Shadow,
                2000,
            )
            .unwrap();

        let r2 = engine
            .emit_receipt(
                &hyp_id,
                ContentHash::compute(b"tw2"),
                ContentHash::compute(b"ee2"),
                ContentHash::compute(b"rt2"),
                ActivationStageLocal::Canary,
                3000,
            )
            .unwrap();

        // Different timestamps produce different receipt IDs.
        assert_ne!(r1.receipt_id, r2.receipt_id);
        assert_eq!(engine.receipts().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: receipt emission event
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_emission_generates_event() {
        let mut engine = test_engine();
        let proof = make_default_proof(ProofType::IfcFlowProof);
        let hypotheses = engine.ingest_proof(proof, 1000).unwrap();
        let pre_event_count = engine.events().len();

        let receipt = engine
            .emit_receipt(
                &hypotheses[0].hypothesis_id,
                ContentHash::compute(b"tw"),
                ContentHash::compute(b"ee"),
                ContentHash::compute(b"rt"),
                ActivationStageLocal::Default,
                2000,
            )
            .unwrap();

        // One new event for receipt emission.
        assert_eq!(engine.events().len(), pre_event_count + 1);
        let last_event = engine.events().last().unwrap();
        assert!(matches!(
            &last_event.event_type,
            IngestionEventType::SpecializationReceiptEmitted {
                receipt_id,
                hypothesis_id,
            } if *receipt_id == receipt.receipt_id
                && *hypothesis_id == hypotheses[0].hypothesis_id
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: validity boundary
    // -----------------------------------------------------------------------

    #[test]
    fn proof_valid_at_exact_expiry_boundary() {
        let mut engine = test_engine();
        // validity_end_ns = 5000, current_ns = 5000 — condition is current_ns > validity_end_ns,
        // so exactly equal should still be accepted.
        let proof = create_proof_input(
            ProofType::PlasCapabilityWitness,
            test_epoch(),
            0,
            5000,
            "policy-001",
            b"boundary-test",
            &test_key(),
        )
        .unwrap();

        assert!(engine.ingest_proof(proof, 5000).is_ok());
    }

    // -----------------------------------------------------------------------
    // Enrichment: IngestionEventType serde for all 6 variants
    // -----------------------------------------------------------------------

    #[test]
    fn ingestion_event_type_serde_all_variants() {
        let fake_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &SchemaId::from_definition(b"fake"),
            b"evt",
        )
        .unwrap();

        let variants = vec![
            IngestionEventType::ProofSubmitted {
                proof_id: fake_id.clone(),
                proof_type: ProofType::IfcFlowProof,
            },
            IngestionEventType::ProofValidated {
                proof_id: fake_id.clone(),
                status: ProofValidationStatus::Accepted,
            },
            IngestionEventType::HypothesisGenerated {
                hypothesis_id: fake_id.clone(),
                kind: HypothesisKind::SuperinstructionFusion,
                source_proof_count: 2,
            },
            IngestionEventType::ProofInvalidated {
                proof_id: fake_id.clone(),
                reason: "epoch transition".to_string(),
            },
            IngestionEventType::HypothesisInvalidated {
                hypothesis_id: fake_id.clone(),
                reason: "source revoked".to_string(),
            },
            IngestionEventType::SpecializationReceiptEmitted {
                receipt_id: fake_id.clone(),
                hypothesis_id: fake_id.clone(),
            },
        ];

        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: IngestionEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, v);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: error trait
    // -----------------------------------------------------------------------

    #[test]
    fn ingestion_error_implements_std_error() {
        let err = IngestionError::IdDerivation("test".to_string());
        let _: &dyn std::error::Error = &err;
        // source() is None for all variants (no #[from] or #[source] attributes).
        assert!(std::error::Error::source(&err).is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: proof type ordering
    // -----------------------------------------------------------------------

    #[test]
    fn proof_type_ord_is_declaration_order() {
        assert!(ProofType::PlasCapabilityWitness < ProofType::IfcFlowProof);
        assert!(ProofType::IfcFlowProof < ProofType::ReplaySequenceMotif);
    }

    #[test]
    fn hypothesis_kind_ord_is_declaration_order() {
        assert!(HypothesisKind::DeadCodeElimination < HypothesisKind::DispatchSpecialization);
        assert!(HypothesisKind::DispatchSpecialization < HypothesisKind::FlowCheckElision);
        assert!(HypothesisKind::FlowCheckElision < HypothesisKind::SuperinstructionFusion);
    }
}
