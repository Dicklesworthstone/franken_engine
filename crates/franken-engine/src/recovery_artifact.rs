//! Proof-carrying recovery artifacts for degraded-mode repairs and
//! rejected trust transitions.
//!
//! Every recovery action (gap fill, state repair, forced reconciliation,
//! trust restoration) and every rejected trust transition (failed epoch
//! promotion, rejected revocation, failed attestation) produces a
//! machine-verifiable artifact that proves what was repaired, why, and
//! how the repair is consistent with the trust model.
//!
//! Plan references: Section 10.11 item 32, 9G.10 (anti-entropy +
//! proof-carrying recovery), Top-10 #5, #9, #10.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// ArtifactType — kinds of recovery artifacts
// ---------------------------------------------------------------------------

/// Type of recovery artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactType {
    /// Filled a gap in the object stream.
    GapFill,
    /// Repaired inconsistent state.
    StateRepair,
    /// Forced reconciliation via fallback protocol.
    ForcedReconciliation,
    /// Restored trust after degradation.
    TrustRestoration,
    /// Epoch promotion that failed validation.
    RejectedEpochPromotion,
    /// Revocation that was rejected.
    RejectedRevocation,
    /// Attestation that could not be verified.
    FailedAttestation,
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GapFill => f.write_str("gap_fill"),
            Self::StateRepair => f.write_str("state_repair"),
            Self::ForcedReconciliation => f.write_str("forced_reconciliation"),
            Self::TrustRestoration => f.write_str("trust_restoration"),
            Self::RejectedEpochPromotion => f.write_str("rejected_epoch_promotion"),
            Self::RejectedRevocation => f.write_str("rejected_revocation"),
            Self::FailedAttestation => f.write_str("failed_attestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryTrigger — what caused the recovery
// ---------------------------------------------------------------------------

/// What triggered the recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryTrigger {
    /// Anti-entropy reconciliation failure.
    ReconciliationFailure { reconciliation_id: String },
    /// Integrity check detected corruption.
    IntegrityCheckFailure { check_id: String, details: String },
    /// Operator requested manual recovery.
    OperatorIntervention { operator: String, reason: String },
    /// Automatic fallback from IBLT peel failure.
    AutomaticFallback { fallback_id: String },
    /// Epoch transition validation failed.
    EpochValidationFailure { from_epoch: u64, to_epoch: u64 },
    /// Revocation rejected due to stale attestation.
    StaleAttestation { attestation_age_ticks: u64 },
}

impl fmt::Display for RecoveryTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReconciliationFailure { reconciliation_id } => {
                write!(f, "reconciliation_failure:{reconciliation_id}")
            }
            Self::IntegrityCheckFailure { check_id, .. } => {
                write!(f, "integrity_check_failure:{check_id}")
            }
            Self::OperatorIntervention { operator, .. } => {
                write!(f, "operator_intervention:{operator}")
            }
            Self::AutomaticFallback { fallback_id } => {
                write!(f, "automatic_fallback:{fallback_id}")
            }
            Self::EpochValidationFailure {
                from_epoch,
                to_epoch,
            } => {
                write!(f, "epoch_validation_failure:{from_epoch}->{to_epoch}")
            }
            Self::StaleAttestation {
                attestation_age_ticks,
            } => {
                write!(f, "stale_attestation:age={attestation_age_ticks}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProofElement — individual proof items in a bundle
// ---------------------------------------------------------------------------

/// A single proof element in a recovery proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofElement {
    /// MMR consistency proof showing recovered state is consistent with
    /// the known-good prefix.
    MmrConsistency {
        root_hash: ContentHash,
        leaf_count: u64,
        proof_hashes: Vec<ContentHash>,
    },
    /// Hash-chain verification result for the decision marker stream.
    HashChainVerification {
        start_marker_id: u64,
        end_marker_id: u64,
        chain_hash: ContentHash,
        verified: bool,
    },
    /// Evidence entry hash linking to the decision that triggered recovery.
    EvidenceEntryLink {
        evidence_hash: ContentHash,
        decision_id: String,
    },
    /// Epoch validity check for artifacts involved in the recovery.
    EpochValidityCheck {
        epoch: SecurityEpoch,
        is_valid: bool,
        reason: String,
    },
}

impl fmt::Display for ProofElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MmrConsistency { leaf_count, .. } => {
                write!(f, "mmr_consistency(leaves={leaf_count})")
            }
            Self::HashChainVerification {
                start_marker_id,
                end_marker_id,
                verified,
                ..
            } => {
                write!(
                    f,
                    "chain_verification({start_marker_id}..{end_marker_id}, ok={verified})"
                )
            }
            Self::EvidenceEntryLink { decision_id, .. } => {
                write!(f, "evidence_link({decision_id})")
            }
            Self::EpochValidityCheck {
                epoch, is_valid, ..
            } => {
                write!(f, "epoch_check({epoch}, valid={is_valid})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OperatorAction — manual operator actions included in recovery
// ---------------------------------------------------------------------------

/// A recorded operator action during recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAction {
    /// Operator identity.
    pub operator: String,
    /// Action description.
    pub action: String,
    /// Signed authorization (Tier 3 AuthenticityHash).
    pub authorization_hash: AuthenticityHash,
    /// Virtual timestamp of the action.
    pub timestamp_ticks: u64,
}

// ---------------------------------------------------------------------------
// RecoveryArtifact — the core proof-carrying recovery artifact
// ---------------------------------------------------------------------------

/// A machine-verifiable recovery artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryArtifact {
    /// Content-addressed identifier (Tier 2 ContentHash over serialized fields).
    pub artifact_id: ContentHash,
    /// Type of recovery.
    pub artifact_type: ArtifactType,
    /// What triggered the recovery.
    pub trigger: RecoveryTrigger,
    /// Hash of the state before recovery.
    pub before_state: ContentHash,
    /// Hash of the state after recovery.
    pub after_state: ContentHash,
    /// Proof bundle verifying the recovery is valid.
    pub proof_bundle: Vec<ProofElement>,
    /// Manual operator actions, if any.
    pub operator_actions: Vec<OperatorAction>,
    /// Trace identifier.
    pub trace_id: String,
    /// Epoch at time of recovery.
    pub epoch_id: u64,
    /// Virtual timestamp.
    pub timestamp_ticks: u64,
    /// Signature over the artifact (Tier 3).
    pub signature: AuthenticityHash,
}

// ---------------------------------------------------------------------------
// RecoveryVerdict — result of artifact verification
// ---------------------------------------------------------------------------

/// Verdict from verifying a recovery artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryVerdict {
    /// All proofs check out.
    Valid,
    /// Verification failed.
    Invalid { reasons: Vec<String> },
}

impl RecoveryVerdict {
    /// Whether the verdict is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl fmt::Display for RecoveryVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::Invalid { reasons } => {
                write!(f, "invalid({})", reasons.join("; "))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VerificationError — errors during verification
// ---------------------------------------------------------------------------

/// Errors from recovery artifact verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationError {
    /// Artifact content hash does not match artifact_id.
    ArtifactIdMismatch {
        expected: ContentHash,
        computed: ContentHash,
    },
    /// Signature verification failed.
    SignatureInvalid { details: String },
    /// Proof bundle is empty.
    EmptyProofBundle,
    /// Missing required proof element.
    MissingProofElement { element_type: String },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactIdMismatch { expected, computed } => {
                write!(
                    f,
                    "artifact ID mismatch: expected {expected}, computed {computed}"
                )
            }
            Self::SignatureInvalid { details } => {
                write!(f, "signature invalid: {details}")
            }
            Self::EmptyProofBundle => f.write_str("proof bundle is empty"),
            Self::MissingProofElement { element_type } => {
                write!(f, "missing proof element: {element_type}")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

// ---------------------------------------------------------------------------
// RecoveryEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for recovery operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEvent {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Artifact type.
    pub artifact_type: String,
    /// Trigger description.
    pub trigger: String,
    /// Verification verdict.
    pub verification_verdict: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Epoch at time of event.
    pub epoch_id: u64,
    /// Event type.
    pub event: String,
}

// ---------------------------------------------------------------------------
// ArtifactBuilder — construct recovery artifacts with proof elements
// ---------------------------------------------------------------------------

/// Builder for constructing recovery artifacts incrementally.
#[derive(Debug)]
pub struct ArtifactBuilder {
    artifact_type: ArtifactType,
    trigger: RecoveryTrigger,
    before_state: ContentHash,
    after_state: Option<ContentHash>,
    proof_elements: Vec<ProofElement>,
    operator_actions: Vec<OperatorAction>,
    trace_id: String,
    epoch_id: u64,
    timestamp_ticks: u64,
    signing_key: Vec<u8>,
}

impl ArtifactBuilder {
    /// Start building a new recovery artifact.
    pub fn new(
        artifact_type: ArtifactType,
        trigger: RecoveryTrigger,
        before_state: ContentHash,
        trace_id: &str,
        epoch_id: u64,
        timestamp_ticks: u64,
        signing_key: &[u8],
    ) -> Self {
        Self {
            artifact_type,
            trigger,
            before_state,
            after_state: None,
            proof_elements: Vec::new(),
            operator_actions: Vec::new(),
            trace_id: trace_id.to_string(),
            epoch_id,
            timestamp_ticks,
            signing_key: signing_key.to_vec(),
        }
    }

    /// Set the after-recovery state hash.
    pub fn after_state(mut self, state: ContentHash) -> Self {
        self.after_state = Some(state);
        self
    }

    /// Add a proof element.
    pub fn proof(mut self, element: ProofElement) -> Self {
        self.proof_elements.push(element);
        self
    }

    /// Add an operator action.
    pub fn operator_action(mut self, action: OperatorAction) -> Self {
        self.operator_actions.push(action);
        self
    }

    /// Build the final artifact with computed content hash and signature.
    pub fn build(self) -> RecoveryArtifact {
        let after_state = self.after_state.unwrap_or(self.before_state);

        // Compute artifact_id as ContentHash over ALL deterministic fields,
        // including proof_bundle and operator_actions for tamper-evidence.
        let mut id_buf = Vec::new();
        id_buf.extend_from_slice(
            format!(
                "{}:{}:{}:{}:{}:{}:{}",
                self.artifact_type,
                self.trigger,
                self.before_state,
                after_state,
                self.epoch_id,
                self.timestamp_ticks,
                self.trace_id,
            )
            .as_bytes(),
        );
        for proof in &self.proof_elements {
            id_buf.extend_from_slice(format!("{proof}").as_bytes());
        }
        for action in &self.operator_actions {
            id_buf.extend_from_slice(action.operator.as_bytes());
            id_buf.extend_from_slice(action.action.as_bytes());
            id_buf.extend_from_slice(action.authorization_hash.as_bytes());
            id_buf.extend_from_slice(&action.timestamp_ticks.to_le_bytes());
        }
        let artifact_id = ContentHash::compute(&id_buf);

        // Sign with the epoch authentication key.
        let signature = AuthenticityHash::compute_keyed(&self.signing_key, artifact_id.as_bytes());

        RecoveryArtifact {
            artifact_id,
            artifact_type: self.artifact_type,
            trigger: self.trigger,
            before_state: self.before_state,
            after_state,
            proof_bundle: self.proof_elements,
            operator_actions: self.operator_actions,
            trace_id: self.trace_id,
            epoch_id: self.epoch_id,
            timestamp_ticks: self.timestamp_ticks,
            signature,
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryArtifactStore — manages recovery artifacts
// ---------------------------------------------------------------------------

/// Store for recovery artifacts with verification and audit.
#[derive(Debug)]
pub struct RecoveryArtifactStore {
    current_epoch: SecurityEpoch,
    signing_key: Vec<u8>,
    artifacts: BTreeMap<String, RecoveryArtifact>,
    events: Vec<RecoveryEvent>,
    event_counts: BTreeMap<String, u64>,
}

impl RecoveryArtifactStore {
    /// Create a new artifact store.
    pub fn new(epoch: SecurityEpoch, signing_key: &[u8]) -> Self {
        Self {
            current_epoch: epoch,
            signing_key: signing_key.to_vec(),
            artifacts: BTreeMap::new(),
            events: Vec::new(),
            event_counts: BTreeMap::new(),
        }
    }

    /// Record a recovery artifact.
    pub fn record(&mut self, artifact: RecoveryArtifact, trace_id: &str) {
        let artifact_id_hex = artifact.artifact_id.to_hex();

        self.emit_event(RecoveryEvent {
            artifact_id: artifact_id_hex.clone(),
            artifact_type: artifact.artifact_type.to_string(),
            trigger: artifact.trigger.to_string(),
            verification_verdict: String::new(),
            trace_id: trace_id.to_string(),
            epoch_id: artifact.epoch_id,
            event: "artifact_recorded".to_string(),
        });
        self.record_count("artifact_recorded");

        self.artifacts.insert(artifact_id_hex, artifact);
    }

    /// Verify a recovery artifact.
    ///
    /// Checks:
    /// 1. Artifact ID matches content hash.
    /// 2. Signature is valid for the signing key.
    /// 3. Proof bundle is non-empty.
    /// 4. All proof elements pass individual checks.
    pub fn verify(
        &mut self,
        artifact: &RecoveryArtifact,
        trace_id: &str,
    ) -> Result<RecoveryVerdict, VerificationError> {
        // Check artifact_id.
        let id_input = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            artifact.artifact_type,
            artifact.trigger,
            artifact.before_state,
            artifact.after_state,
            artifact.epoch_id,
            artifact.timestamp_ticks,
            artifact.trace_id,
        );
        let computed_id = ContentHash::compute(id_input.as_bytes());
        if computed_id != artifact.artifact_id {
            return Err(VerificationError::ArtifactIdMismatch {
                expected: artifact.artifact_id,
                computed: computed_id,
            });
        }

        // Check signature.
        let expected_sig =
            AuthenticityHash::compute_keyed(&self.signing_key, artifact.artifact_id.as_bytes());
        if expected_sig != artifact.signature {
            return Err(VerificationError::SignatureInvalid {
                details: "signature does not match signing key".to_string(),
            });
        }

        // Check proof bundle is non-empty.
        if artifact.proof_bundle.is_empty() {
            return Err(VerificationError::EmptyProofBundle);
        }

        // Validate individual proof elements.
        let mut reasons: Vec<String> = Vec::new();

        for element in &artifact.proof_bundle {
            match element {
                ProofElement::HashChainVerification { verified, .. } => {
                    if !verified {
                        reasons.push("hash chain verification failed".to_string());
                    }
                }
                ProofElement::EpochValidityCheck {
                    is_valid, reason, ..
                } => {
                    if !is_valid {
                        reasons.push(format!("epoch validity check failed: {reason}"));
                    }
                }
                ProofElement::MmrConsistency { .. } | ProofElement::EvidenceEntryLink { .. } => {
                    // These are informational and structurally valid by construction.
                }
            }
        }

        let verdict = if reasons.is_empty() {
            RecoveryVerdict::Valid
        } else {
            RecoveryVerdict::Invalid { reasons }
        };

        self.emit_event(RecoveryEvent {
            artifact_id: artifact.artifact_id.to_hex(),
            artifact_type: artifact.artifact_type.to_string(),
            trigger: artifact.trigger.to_string(),
            verification_verdict: verdict.to_string(),
            trace_id: trace_id.to_string(),
            epoch_id: artifact.epoch_id,
            event: "artifact_verified".to_string(),
        });
        self.record_count("artifact_verified");

        Ok(verdict)
    }

    /// Export all artifacts as a serializable list (for external audit).
    pub fn export(&self) -> Vec<&RecoveryArtifact> {
        self.artifacts.values().collect()
    }

    /// Look up an artifact by its hex ID.
    pub fn get(&self, artifact_id_hex: &str) -> Option<&RecoveryArtifact> {
        self.artifacts.get(artifact_id_hex)
    }

    /// Number of stored artifacts.
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Current epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<RecoveryEvent> {
        std::mem::take(&mut self.events)
    }

    /// Event counters.
    pub fn event_counts(&self) -> &BTreeMap<String, u64> {
        &self.event_counts
    }

    // -- Internal --

    fn emit_event(&mut self, event: RecoveryEvent) {
        self.events.push(event);
    }

    fn record_count(&mut self, event_type: &str) {
        *self.event_counts.entry(event_type.to_string()).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_key() -> Vec<u8> {
        b"test-signing-key-epoch-1".to_vec()
    }

    fn sample_before_state() -> ContentHash {
        ContentHash::compute(b"before-state")
    }

    fn sample_after_state() -> ContentHash {
        ContentHash::compute(b"after-state")
    }

    fn build_valid_artifact() -> RecoveryArtifact {
        ArtifactBuilder::new(
            ArtifactType::ForcedReconciliation,
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb-t1-1".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .after_state(sample_after_state())
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"mmr-root"),
            leaf_count: 42,
            proof_hashes: vec![ContentHash::compute(b"h1"), ContentHash::compute(b"h2")],
        })
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 10,
            chain_hash: ContentHash::compute(b"chain"),
            verified: true,
        })
        .proof(ProofElement::EvidenceEntryLink {
            evidence_hash: ContentHash::compute(b"evidence"),
            decision_id: "d-1".to_string(),
        })
        .proof(ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: true,
            reason: "current epoch".to_string(),
        })
        .build()
    }

    // -- ArtifactType --

    #[test]
    fn artifact_type_display() {
        assert_eq!(ArtifactType::GapFill.to_string(), "gap_fill");
        assert_eq!(ArtifactType::StateRepair.to_string(), "state_repair");
        assert_eq!(
            ArtifactType::ForcedReconciliation.to_string(),
            "forced_reconciliation"
        );
        assert_eq!(
            ArtifactType::RejectedEpochPromotion.to_string(),
            "rejected_epoch_promotion"
        );
        assert_eq!(
            ArtifactType::FailedAttestation.to_string(),
            "failed_attestation"
        );
    }

    // -- Builder --

    #[test]
    fn builder_produces_valid_artifact() {
        let artifact = build_valid_artifact();
        assert_eq!(artifact.artifact_type, ArtifactType::ForcedReconciliation);
        assert_eq!(artifact.epoch_id, 1);
        assert_eq!(artifact.proof_bundle.len(), 4);
        assert_eq!(artifact.before_state, sample_before_state());
        assert_eq!(artifact.after_state, sample_after_state());
    }

    #[test]
    fn builder_uses_before_state_when_no_after_set() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"root"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build();

        assert_eq!(artifact.before_state, artifact.after_state);
    }

    #[test]
    fn builder_includes_operator_actions() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::TrustRestoration,
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "manual restore".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            2000,
            &test_key(),
        )
        .after_state(sample_after_state())
        .proof(ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: true,
            reason: "current".to_string(),
        })
        .operator_action(OperatorAction {
            operator: "admin".to_string(),
            action: "force restore trust".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(
                b"admin-key",
                b"force restore trust",
            ),
            timestamp_ticks: 2000,
        })
        .build();

        assert_eq!(artifact.operator_actions.len(), 1);
        assert_eq!(artifact.operator_actions[0].operator, "admin");
    }

    // -- Verification --

    #[test]
    fn verify_valid_artifact() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        let verdict = store.verify(&artifact, "t1").unwrap();
        assert!(verdict.is_valid());
    }

    #[test]
    fn verify_detects_tampered_artifact_id() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let mut artifact = build_valid_artifact();
        artifact.artifact_id = ContentHash::compute(b"tampered");

        let result = store.verify(&artifact, "t1");
        assert!(matches!(
            result,
            Err(VerificationError::ArtifactIdMismatch { .. })
        ));
    }

    #[test]
    fn verify_detects_wrong_signing_key() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), b"wrong-key");
        let artifact = build_valid_artifact();

        let result = store.verify(&artifact, "t1");
        assert!(matches!(
            result,
            Err(VerificationError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn verify_rejects_empty_proof_bundle() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = ArtifactBuilder::new(
            ArtifactType::StateRepair,
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .build();

        let result = store.verify(&artifact, "t1");
        assert!(matches!(result, Err(VerificationError::EmptyProofBundle)));
    }

    #[test]
    fn verify_detects_failed_chain_verification() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = ArtifactBuilder::new(
            ArtifactType::StateRepair,
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 5,
            chain_hash: ContentHash::compute(b"chain"),
            verified: false, // failed
        })
        .build();

        let verdict = store.verify(&artifact, "t1").unwrap();
        assert!(!verdict.is_valid());
        if let RecoveryVerdict::Invalid { reasons } = &verdict {
            assert!(reasons[0].contains("hash chain"));
        }
    }

    #[test]
    fn verify_detects_failed_epoch_check() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = ArtifactBuilder::new(
            ArtifactType::RejectedEpochPromotion,
            RecoveryTrigger::EpochValidationFailure {
                from_epoch: 1,
                to_epoch: 2,
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::EpochValidityCheck {
            epoch: SecurityEpoch::from_raw(2),
            is_valid: false,
            reason: "quorum not met".to_string(),
        })
        .build();

        let verdict = store.verify(&artifact, "t1").unwrap();
        assert!(!verdict.is_valid());
        if let RecoveryVerdict::Invalid { reasons } = &verdict {
            assert!(reasons[0].contains("quorum not met"));
        }
    }

    // -- Store --

    #[test]
    fn store_record_and_get() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        let hex_id = artifact.artifact_id.to_hex();
        store.record(artifact.clone(), "t1");

        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert_eq!(store.get(&hex_id).unwrap().epoch_id, 1);
    }

    #[test]
    fn store_export() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        store.record(build_valid_artifact(), "t1");

        let exported = store.export();
        assert_eq!(exported.len(), 1);

        // Verify exported artifact can be serialized.
        let json = serde_json::to_string(exported[0]).expect("serialize");
        let restored: RecoveryArtifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.artifact_type, ArtifactType::ForcedReconciliation);
    }

    #[test]
    fn store_emits_events() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        store.record(artifact.clone(), "t1");
        store.verify(&artifact, "t1").unwrap();

        let events = store.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "artifact_recorded");
        assert_eq!(events[1].event, "artifact_verified");
        assert_eq!(store.event_counts().get("artifact_recorded"), Some(&1));
        assert_eq!(store.event_counts().get("artifact_verified"), Some(&1));
    }

    // -- Determinism --

    #[test]
    fn deterministic_artifact_id() {
        let a1 = build_valid_artifact();
        let a2 = build_valid_artifact();
        assert_eq!(a1.artifact_id, a2.artifact_id);
        assert_eq!(a1.signature, a2.signature);
    }

    // -- Serialization round-trips --

    #[test]
    fn artifact_type_serialization_round_trip() {
        let types = vec![
            ArtifactType::GapFill,
            ArtifactType::StateRepair,
            ArtifactType::ForcedReconciliation,
            ArtifactType::TrustRestoration,
            ArtifactType::RejectedEpochPromotion,
            ArtifactType::RejectedRevocation,
            ArtifactType::FailedAttestation,
        ];
        for t in &types {
            let json = serde_json::to_string(t).expect("serialize");
            let restored: ArtifactType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, restored);
        }
    }

    #[test]
    fn recovery_trigger_serialization_round_trip() {
        let triggers = vec![
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string(),
            },
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "restore".to_string(),
            },
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb-1".to_string(),
            },
            RecoveryTrigger::EpochValidationFailure {
                from_epoch: 1,
                to_epoch: 2,
            },
            RecoveryTrigger::StaleAttestation {
                attestation_age_ticks: 10000,
            },
        ];
        for t in &triggers {
            let json = serde_json::to_string(t).expect("serialize");
            let restored: RecoveryTrigger = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, restored);
        }
    }

    #[test]
    fn proof_element_serialization_round_trip() {
        let elements = vec![
            ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"root"),
                leaf_count: 10,
                proof_hashes: vec![ContentHash::compute(b"a")],
            },
            ProofElement::HashChainVerification {
                start_marker_id: 0,
                end_marker_id: 5,
                chain_hash: ContentHash::compute(b"chain"),
                verified: true,
            },
            ProofElement::EvidenceEntryLink {
                evidence_hash: ContentHash::compute(b"ev"),
                decision_id: "d-1".to_string(),
            },
            ProofElement::EpochValidityCheck {
                epoch: test_epoch(),
                is_valid: true,
                reason: "ok".to_string(),
            },
        ];
        for e in &elements {
            let json = serde_json::to_string(e).expect("serialize");
            let restored: ProofElement = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*e, restored);
        }
    }

    #[test]
    fn recovery_artifact_serialization_round_trip() {
        let artifact = build_valid_artifact();
        let json = serde_json::to_string(&artifact).expect("serialize");
        let restored: RecoveryArtifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(artifact, restored);
    }

    #[test]
    fn verification_error_serialization_round_trip() {
        let errors = vec![
            VerificationError::EmptyProofBundle,
            VerificationError::SignatureInvalid {
                details: "bad sig".to_string(),
            },
            VerificationError::MissingProofElement {
                element_type: "mmr".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize");
            let restored: VerificationError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*e, restored);
        }
    }

    #[test]
    fn recovery_verdict_serialization_round_trip() {
        let verdicts = vec![
            RecoveryVerdict::Valid,
            RecoveryVerdict::Invalid {
                reasons: vec!["bad".to_string()],
            },
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).expect("serialize");
            let restored: RecoveryVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*v, restored);
        }
    }

    // -- Display --

    #[test]
    fn recovery_trigger_display() {
        assert!(
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string()
            }
            .to_string()
            .contains("reconciliation_failure")
        );
        assert!(
            RecoveryTrigger::StaleAttestation {
                attestation_age_ticks: 5000
            }
            .to_string()
            .contains("stale_attestation")
        );
    }

    #[test]
    fn proof_element_display() {
        assert!(
            ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 42,
                proof_hashes: vec![],
            }
            .to_string()
            .contains("42")
        );
        assert!(
            ProofElement::HashChainVerification {
                start_marker_id: 0,
                end_marker_id: 10,
                chain_hash: ContentHash::compute(b"c"),
                verified: true,
            }
            .to_string()
            .contains("ok=true")
        );
    }

    #[test]
    fn verification_error_display() {
        assert!(
            VerificationError::EmptyProofBundle
                .to_string()
                .contains("empty")
        );
        assert!(
            VerificationError::SignatureInvalid {
                details: "bad".to_string()
            }
            .to_string()
            .contains("bad")
        );
    }

    #[test]
    fn recovery_verdict_display() {
        assert_eq!(RecoveryVerdict::Valid.to_string(), "valid");
        assert!(
            RecoveryVerdict::Invalid {
                reasons: vec!["reason1".to_string()]
            }
            .to_string()
            .contains("reason1")
        );
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn operator_action_serde_roundtrip() {
        let action = OperatorAction {
            operator: "admin".to_string(),
            action: "approve_recovery".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(b"auth", b"key"),
            timestamp_ticks: 42_000,
        };
        let json = serde_json::to_string(&action).expect("serialize");
        let restored: OperatorAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, restored);
    }

    #[test]
    fn recovery_event_serde_roundtrip() {
        let event = RecoveryEvent {
            artifact_id: "art-1".to_string(),
            artifact_type: "gap_fill".to_string(),
            trigger: "reconciliation_failure".to_string(),
            verification_verdict: "valid".to_string(),
            trace_id: "t-1".to_string(),
            epoch_id: 1,
            event: "artifact_created".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RecoveryEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn verification_error_artifact_id_mismatch_serde() {
        let err = VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"expected"),
            computed: ContentHash::compute(b"computed"),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: VerificationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn artifact_type_ordering() {
        assert!(ArtifactType::GapFill < ArtifactType::StateRepair);
        assert!(ArtifactType::StateRepair < ArtifactType::ForcedReconciliation);
        assert!(ArtifactType::ForcedReconciliation < ArtifactType::TrustRestoration);
        assert!(ArtifactType::TrustRestoration < ArtifactType::RejectedEpochPromotion);
        assert!(ArtifactType::RejectedEpochPromotion < ArtifactType::RejectedRevocation);
        assert!(ArtifactType::RejectedRevocation < ArtifactType::FailedAttestation);
    }

    // -- Enrichment: Display completeness --

    #[test]
    fn artifact_type_display_remaining_variants() {
        assert_eq!(
            ArtifactType::TrustRestoration.to_string(),
            "trust_restoration"
        );
        assert_eq!(
            ArtifactType::RejectedRevocation.to_string(),
            "rejected_revocation"
        );
    }

    #[test]
    fn verification_error_display_all_variants() {
        let e1 = VerificationError::ArtifactIdMismatch {
            expected: ContentHash::compute(b"a"),
            computed: ContentHash::compute(b"b"),
        };
        assert!(e1.to_string().contains("mismatch"));

        let e2 = VerificationError::MissingProofElement {
            element_type: "mmr".to_string(),
        };
        assert!(e2.to_string().contains("mmr"));
    }

    // -- Enrichment: std::error::Error --

    #[test]
    fn verification_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(VerificationError::EmptyProofBundle),
            Box::new(VerificationError::SignatureInvalid {
                details: "d".to_string(),
            }),
            Box::new(VerificationError::MissingProofElement {
                element_type: "t".to_string(),
            }),
            Box::new(VerificationError::ArtifactIdMismatch {
                expected: ContentHash::compute(b"a"),
                computed: ContentHash::compute(b"b"),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: trigger Display completeness --

    #[test]
    fn recovery_trigger_display_all_variants() {
        let triggers = vec![
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string(),
            },
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "bad".to_string(),
            },
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "restore".to_string(),
            },
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb-1".to_string(),
            },
            RecoveryTrigger::EpochValidationFailure {
                from_epoch: 1,
                to_epoch: 2,
            },
            RecoveryTrigger::StaleAttestation {
                attestation_age_ticks: 5000,
            },
        ];
        for t in &triggers {
            assert!(!t.to_string().is_empty());
        }
    }

    // -- Enrichment: ArtifactType display all 7 unique --

    #[test]
    fn artifact_type_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = vec![
            ArtifactType::GapFill,
            ArtifactType::StateRepair,
            ArtifactType::ForcedReconciliation,
            ArtifactType::TrustRestoration,
            ArtifactType::RejectedEpochPromotion,
            ArtifactType::RejectedRevocation,
            ArtifactType::FailedAttestation,
        ]
        .into_iter()
        .map(|t| t.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            7,
            "all 7 ArtifactType variants have distinct Display"
        );
    }

    // -- Enrichment: ProofElement display all 4 unique --

    #[test]
    fn proof_element_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = vec![
            ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            },
            ProofElement::HashChainVerification {
                start_marker_id: 0,
                end_marker_id: 1,
                chain_hash: ContentHash::compute(b"c"),
                verified: true,
            },
            ProofElement::EvidenceEntryLink {
                evidence_hash: ContentHash::compute(b"e"),
                decision_id: "d".to_string(),
            },
            ProofElement::EpochValidityCheck {
                epoch: test_epoch(),
                is_valid: true,
                reason: "ok".to_string(),
            },
        ]
        .into_iter()
        .map(|p| p.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            4,
            "all 4 ProofElement variants have distinct Display"
        );
    }

    // -- Enrichment: store get missing key --

    #[test]
    fn store_get_missing_key_returns_none() {
        let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        assert!(store.get("nonexistent").is_none());
    }

    // -- Enrichment: store is_empty on fresh --

    #[test]
    fn store_fresh_is_empty() {
        let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    // -- Enrichment: store multiple records --

    #[test]
    fn store_multiple_records() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let a1 = ArtifactBuilder::new(
            ArtifactType::GapFill,
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"root1"),
            leaf_count: 5,
            proof_hashes: vec![ContentHash::compute(b"h1")],
        })
        .build();

        let a2 = ArtifactBuilder::new(
            ArtifactType::StateRepair,
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            sample_before_state(),
            "t2",
            2,
            2000,
            &test_key(),
        )
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 10,
            chain_hash: ContentHash::compute(b"chain"),
            verified: true,
        })
        .build();

        store.record(a1, "t1");
        store.record(a2, "t2");
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    // -- Enrichment: builder with multiple proofs --

    #[test]
    fn builder_with_multiple_proofs() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::ForcedReconciliation,
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "force".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"root"),
            leaf_count: 10,
            proof_hashes: vec![ContentHash::compute(b"a")],
        })
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 5,
            chain_hash: ContentHash::compute(b"chain"),
            verified: true,
        })
        .proof(ProofElement::EvidenceEntryLink {
            evidence_hash: ContentHash::compute(b"ev"),
            decision_id: "d-1".to_string(),
        })
        .build();
        assert_eq!(artifact.proof_bundle.len(), 3);
    }

    // -- Enrichment: store event_counts tracks categories --

    #[test]
    fn store_event_counts_after_multiple_ops() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let a1 = build_valid_artifact();
        let a2 = build_valid_artifact();
        store.record(a1.clone(), "t1");
        store.record(a2, "t2");
        store.verify(&a1, "t1").unwrap();

        let counts = store.event_counts();
        assert_eq!(counts.get("artifact_recorded"), Some(&2));
        assert_eq!(counts.get("artifact_verified"), Some(&1));
    }

    // -- Enrichment: RecoveryVerdict is_valid on invalid --

    #[test]
    fn recovery_verdict_invalid_is_not_valid() {
        let verdict = RecoveryVerdict::Invalid {
            reasons: vec!["bad chain".to_string()],
        };
        assert!(!verdict.is_valid());
    }

    // -- Enrichment: OperatorAction deterministic --

    #[test]
    fn operator_action_deterministic_hash() {
        let a1 = OperatorAction {
            operator: "admin".to_string(),
            action: "approve".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(b"auth", b"key"),
            timestamp_ticks: 1000,
        };
        let a2 = OperatorAction {
            operator: "admin".to_string(),
            action: "approve".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(b"auth", b"key"),
            timestamp_ticks: 1000,
        };
        assert_eq!(a1, a2);
    }

    // -- Enrichment: verification detects wrong epoch on store --

    #[test]
    fn store_export_empty() {
        let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        assert!(store.export().is_empty());
    }

    // -- Enrichment batch 3: sensitivity, edge cases, deeper coverage --

    #[test]
    fn artifact_id_sensitive_to_artifact_type() {
        let base = |at: ArtifactType| {
            ArtifactBuilder::new(
                at,
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: "fb".to_string(),
                },
                sample_before_state(),
                "t",
                1,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        let a1 = base(ArtifactType::GapFill);
        let a2 = base(ArtifactType::StateRepair);
        assert_ne!(a1.artifact_id, a2.artifact_id);
    }

    #[test]
    fn artifact_id_sensitive_to_trigger() {
        let base = |trigger: RecoveryTrigger| {
            ArtifactBuilder::new(
                ArtifactType::GapFill,
                trigger,
                sample_before_state(),
                "t",
                1,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        let a1 = base(RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-1".to_string(),
        });
        let a2 = base(RecoveryTrigger::AutomaticFallback {
            fallback_id: "fb-2".to_string(),
        });
        assert_ne!(a1.artifact_id, a2.artifact_id);
    }

    #[test]
    fn artifact_id_sensitive_to_epoch_id() {
        let base = |epoch: u64| {
            ArtifactBuilder::new(
                ArtifactType::GapFill,
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: "fb".to_string(),
                },
                sample_before_state(),
                "t",
                epoch,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        assert_ne!(base(1).artifact_id, base(2).artifact_id);
    }

    #[test]
    fn artifact_id_sensitive_to_timestamp() {
        let base = |ts: u64| {
            ArtifactBuilder::new(
                ArtifactType::GapFill,
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: "fb".to_string(),
                },
                sample_before_state(),
                "t",
                1,
                ts,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        assert_ne!(base(1000).artifact_id, base(2000).artifact_id);
    }

    #[test]
    fn artifact_id_sensitive_to_trace_id() {
        let base = |trace: &str| {
            ArtifactBuilder::new(
                ArtifactType::GapFill,
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: "fb".to_string(),
                },
                sample_before_state(),
                trace,
                1,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        assert_ne!(base("t-a").artifact_id, base("t-b").artifact_id);
    }

    #[test]
    fn artifact_id_sensitive_to_before_state() {
        let base = |bs: ContentHash| {
            ArtifactBuilder::new(
                ArtifactType::GapFill,
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: "fb".to_string(),
                },
                bs,
                "t",
                1,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build()
        };
        assert_ne!(
            base(ContentHash::compute(b"state-A")).artifact_id,
            base(ContentHash::compute(b"state-B")).artifact_id
        );
    }

    #[test]
    fn drain_events_idempotent() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        store.record(build_valid_artifact(), "t1");
        let events1 = store.drain_events();
        assert_eq!(events1.len(), 1);
        let events2 = store.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn store_epoch_accessor() {
        let store = RecoveryArtifactStore::new(SecurityEpoch::from_raw(42), &test_key());
        assert_eq!(store.epoch(), SecurityEpoch::from_raw(42));
    }

    #[test]
    fn multiple_operator_actions_preserved_in_order() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::TrustRestoration,
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "restore".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .after_state(sample_after_state())
        .proof(ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: true,
            reason: "ok".to_string(),
        })
        .operator_action(OperatorAction {
            operator: "admin-1".to_string(),
            action: "approve".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(b"k1", b"approve"),
            timestamp_ticks: 1000,
        })
        .operator_action(OperatorAction {
            operator: "admin-2".to_string(),
            action: "confirm".to_string(),
            authorization_hash: AuthenticityHash::compute_keyed(b"k2", b"confirm"),
            timestamp_ticks: 1001,
        })
        .build();
        assert_eq!(artifact.operator_actions.len(), 2);
        assert_eq!(artifact.operator_actions[0].operator, "admin-1");
        assert_eq!(artifact.operator_actions[1].operator, "admin-2");
    }

    #[test]
    fn verify_multiple_failures_collects_all_reasons() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = ArtifactBuilder::new(
            ArtifactType::StateRepair,
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            sample_before_state(),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .proof(ProofElement::HashChainVerification {
            start_marker_id: 0,
            end_marker_id: 5,
            chain_hash: ContentHash::compute(b"chain"),
            verified: false,
        })
        .proof(ProofElement::EpochValidityCheck {
            epoch: test_epoch(),
            is_valid: false,
            reason: "expired".to_string(),
        })
        .build();

        let verdict = store.verify(&artifact, "t1").unwrap();
        assert!(!verdict.is_valid());
        if let RecoveryVerdict::Invalid { reasons } = &verdict {
            assert_eq!(reasons.len(), 2);
            assert!(reasons[0].contains("hash chain"));
            assert!(reasons[1].contains("expired"));
        } else {
            panic!("expected Invalid verdict");
        }
    }

    #[test]
    fn recovery_verdict_invalid_multiple_reasons_display() {
        let verdict = RecoveryVerdict::Invalid {
            reasons: vec!["reason-a".to_string(), "reason-b".to_string()],
        };
        let display = verdict.to_string();
        assert!(display.contains("reason-a"));
        assert!(display.contains("reason-b"));
        assert!(display.contains(';'));
    }

    #[test]
    fn recovery_verdict_invalid_empty_reasons() {
        let verdict = RecoveryVerdict::Invalid { reasons: vec![] };
        assert!(!verdict.is_valid());
        let display = verdict.to_string();
        assert!(display.contains("invalid"));
    }

    #[test]
    fn artifact_clone_preserves_all_fields() {
        let artifact = build_valid_artifact();
        let cloned = artifact.clone();
        assert_eq!(artifact, cloned);
        assert_eq!(artifact.artifact_id, cloned.artifact_id);
        assert_eq!(artifact.signature, cloned.signature);
        assert_eq!(artifact.proof_bundle.len(), cloned.proof_bundle.len());
    }

    #[test]
    fn all_artifact_types_build_ok() {
        let types = [
            ArtifactType::GapFill,
            ArtifactType::StateRepair,
            ArtifactType::ForcedReconciliation,
            ArtifactType::TrustRestoration,
            ArtifactType::RejectedEpochPromotion,
            ArtifactType::RejectedRevocation,
            ArtifactType::FailedAttestation,
        ];
        for (i, at) in types.iter().enumerate() {
            let artifact = ArtifactBuilder::new(
                at.clone(),
                RecoveryTrigger::AutomaticFallback {
                    fallback_id: format!("fb-{i}"),
                },
                sample_before_state(),
                &format!("t-{i}"),
                i as u64,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build();
            assert_eq!(artifact.artifact_type, *at);
        }
    }

    #[test]
    fn all_trigger_types_build_ok() {
        let triggers = vec![
            RecoveryTrigger::ReconciliationFailure {
                reconciliation_id: "r1".to_string(),
            },
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "bad".to_string(),
            },
            RecoveryTrigger::OperatorIntervention {
                operator: "admin".to_string(),
                reason: "manual".to_string(),
            },
            RecoveryTrigger::AutomaticFallback {
                fallback_id: "fb".to_string(),
            },
            RecoveryTrigger::EpochValidationFailure {
                from_epoch: 1,
                to_epoch: 2,
            },
            RecoveryTrigger::StaleAttestation {
                attestation_age_ticks: 5000,
            },
        ];
        for (i, trigger) in triggers.into_iter().enumerate() {
            let artifact = ArtifactBuilder::new(
                ArtifactType::GapFill,
                trigger,
                sample_before_state(),
                &format!("t-{i}"),
                1,
                1000,
                &test_key(),
            )
            .proof(ProofElement::MmrConsistency {
                root_hash: ContentHash::compute(b"r"),
                leaf_count: 1,
                proof_hashes: vec![],
            })
            .build();
            assert!(!artifact.artifact_id.to_hex().is_empty());
        }
    }

    #[test]
    fn store_event_counts_empty_on_fresh_store() {
        let store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        assert!(store.event_counts().is_empty());
    }

    #[test]
    fn verification_error_display_all_unique() {
        let errors = [
            VerificationError::EmptyProofBundle,
            VerificationError::SignatureInvalid {
                details: "sig".to_string(),
            },
            VerificationError::MissingProofElement {
                element_type: "mmr".to_string(),
            },
            VerificationError::ArtifactIdMismatch {
                expected: ContentHash::compute(b"a"),
                computed: ContentHash::compute(b"b"),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 VerificationError variants have distinct Display"
        );
    }

    #[test]
    fn trigger_display_contains_expected_substrings() {
        let cases = [
            (
                RecoveryTrigger::IntegrityCheckFailure {
                    check_id: "chk-99".to_string(),
                    details: "ignored in display".to_string(),
                },
                "chk-99",
            ),
            (
                RecoveryTrigger::OperatorIntervention {
                    operator: "ops-admin".to_string(),
                    reason: "ignored".to_string(),
                },
                "ops-admin",
            ),
            (
                RecoveryTrigger::EpochValidationFailure {
                    from_epoch: 5,
                    to_epoch: 6,
                },
                "5->6",
            ),
            (
                RecoveryTrigger::StaleAttestation {
                    attestation_age_ticks: 12345,
                },
                "12345",
            ),
        ];
        for (trigger, expected_substr) in &cases {
            assert!(
                trigger.to_string().contains(expected_substr),
                "trigger display '{}' should contain '{}'",
                trigger,
                expected_substr
            );
        }
    }

    #[test]
    fn proof_element_mmr_zero_leaves() {
        let pe = ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"empty"),
            leaf_count: 0,
            proof_hashes: vec![],
        };
        assert!(pe.to_string().contains("leaves=0"));
    }

    #[test]
    fn proof_element_chain_large_marker_ids() {
        let pe = ProofElement::HashChainVerification {
            start_marker_id: u64::MAX - 1,
            end_marker_id: u64::MAX,
            chain_hash: ContentHash::compute(b"c"),
            verified: false,
        };
        let display = pe.to_string();
        assert!(display.contains("ok=false"));
    }

    #[test]
    fn before_and_after_state_differ() {
        let artifact = ArtifactBuilder::new(
            ArtifactType::StateRepair,
            RecoveryTrigger::IntegrityCheckFailure {
                check_id: "c1".to_string(),
                details: "corrupt".to_string(),
            },
            ContentHash::compute(b"old"),
            "t1",
            1,
            1000,
            &test_key(),
        )
        .after_state(ContentHash::compute(b"new"))
        .proof(ProofElement::MmrConsistency {
            root_hash: ContentHash::compute(b"r"),
            leaf_count: 1,
            proof_hashes: vec![],
        })
        .build();
        assert_ne!(artifact.before_state, artifact.after_state);
    }

    #[test]
    fn store_record_overwrites_same_artifact_id() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        store.record(artifact.clone(), "t1");
        store.record(artifact, "t2");
        // BTreeMap insert overwrites; store should still have 1 entry
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_verify_emits_event_with_verdict() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        store.verify(&artifact, "trace-v").unwrap();
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "artifact_verified");
        assert_eq!(events[0].trace_id, "trace-v");
        assert_eq!(events[0].verification_verdict, "valid");
    }

    #[test]
    fn store_record_emits_event_with_empty_verdict() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        store.record(build_valid_artifact(), "trace-r");
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "artifact_recorded");
        assert!(events[0].verification_verdict.is_empty());
    }

    #[test]
    fn recovery_event_all_fields_populated_after_verify() {
        let mut store = RecoveryArtifactStore::new(test_epoch(), &test_key());
        let artifact = build_valid_artifact();
        store.verify(&artifact, "t-full").unwrap();
        let events = store.drain_events();
        let ev = &events[0];
        assert!(!ev.artifact_id.is_empty());
        assert!(!ev.artifact_type.is_empty());
        assert!(!ev.trigger.is_empty());
        assert!(!ev.verification_verdict.is_empty());
        assert_eq!(ev.trace_id, "t-full");
        assert_eq!(ev.epoch_id, 1);
        assert_eq!(ev.event, "artifact_verified");
    }

    #[test]
    fn proof_element_evidence_link_display() {
        let pe = ProofElement::EvidenceEntryLink {
            evidence_hash: ContentHash::compute(b"ev"),
            decision_id: "dec-42".to_string(),
        };
        assert!(pe.to_string().contains("dec-42"));
    }

    #[test]
    fn proof_element_epoch_check_display() {
        let pe = ProofElement::EpochValidityCheck {
            epoch: SecurityEpoch::from_raw(7),
            is_valid: false,
            reason: "stale".to_string(),
        };
        let display = pe.to_string();
        assert!(display.contains("valid=false"));
    }
}
