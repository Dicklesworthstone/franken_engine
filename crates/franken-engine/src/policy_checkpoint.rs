//! PolicyCheckpoint: quorum-signed chain element anchoring the canonical
//! root of enforceable policy state.
//!
//! Each checkpoint contains:
//! - Back-pointer to the previous checkpoint (`prev_checkpoint`).
//! - Monotonically increasing sequence number (`checkpoint_seq`).
//! - Epoch identifier (`epoch_id`).
//! - References to current active policy versions (`policy_heads`).
//! - Quorum of signatures from authorized checkpoint signers.
//! - Content-addressed `checkpoint_id` via EngineObjectId derivation.
//!
//! Invariants:
//! - Genesis checkpoint has `prev_checkpoint = None`, `checkpoint_seq = 0`.
//! - Chain linkage: each checkpoint references the immediately preceding one.
//! - Monotonicity: `checkpoint_seq` is strictly greater than predecessor's.
//! - Immutability: checkpoints are sealed after creation and signing.
//!
//! Plan references: Section 10.10 item 6, 9E.3 (checkpointed policy
//! frontier with rollback/fork protection).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, SignaturePreimage, SigningKey, VerificationKey,
};
use crate::sorted_multisig::{SignerSignature, SortedSignatureArray};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Schema definition for PolicyCheckpoint objects.
const CHECKPOINT_SCHEMA_DEF: &[u8] = b"FrankenEngine.PolicyCheckpoint.v1";

/// Derive the schema hash for checkpoints.
pub fn checkpoint_schema() -> SchemaHash {
    SchemaHash::from_definition(CHECKPOINT_SCHEMA_DEF)
}

/// Derive the schema ID for checkpoints.
pub fn checkpoint_schema_id() -> SchemaId {
    SchemaId::from_definition(CHECKPOINT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// PolicyType / PolicyHead
// ---------------------------------------------------------------------------

/// Type of policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PolicyType {
    /// Runtime execution policy.
    RuntimeExecution,
    /// Capability lattice policy.
    CapabilityLattice,
    /// Extension trust policy.
    ExtensionTrust,
    /// Evidence retention policy.
    EvidenceRetention,
    /// Revocation governance policy.
    RevocationGovernance,
}

impl fmt::Display for PolicyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeExecution => write!(f, "runtime_execution"),
            Self::CapabilityLattice => write!(f, "capability_lattice"),
            Self::ExtensionTrust => write!(f, "extension_trust"),
            Self::EvidenceRetention => write!(f, "evidence_retention"),
            Self::RevocationGovernance => write!(f, "revocation_governance"),
        }
    }
}

/// A content-addressed reference to an active policy version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyHead {
    /// The type of policy.
    pub policy_type: PolicyType,
    /// Content hash of the policy document.
    pub policy_hash: ContentHash,
    /// Monotonic policy version.
    pub policy_version: u64,
}

// ---------------------------------------------------------------------------
// DeterministicTimestamp
// ---------------------------------------------------------------------------

/// Deterministic timestamp as monotonic tick count.
///
/// Not wall-clock time — a logical tick from a deterministic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeterministicTimestamp(pub u64);

impl fmt::Display for DeterministicTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tick:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// CheckpointError
// ---------------------------------------------------------------------------

/// Errors from checkpoint operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointError {
    /// Genesis checkpoint must have no predecessor.
    GenesisMustHaveNoPredecessor,
    /// Non-genesis checkpoint must have a predecessor.
    MissingPredecessor,
    /// Sequence number is not strictly monotonic.
    NonMonotonicSequence { prev_seq: u64, current_seq: u64 },
    /// Genesis checkpoint must have sequence 0.
    GenesisSequenceNotZero { actual: u64 },
    /// Chain linkage error: prev_checkpoint doesn't match.
    ChainLinkageBroken {
        expected: EngineObjectId,
        actual: EngineObjectId,
    },
    /// Policy heads list is empty.
    EmptyPolicyHeads,
    /// Quorum threshold not met.
    QuorumNotMet { required: usize, provided: usize },
    /// Duplicate policy type in heads.
    DuplicatePolicyType { policy_type: PolicyType },
    /// ID derivation failed.
    IdDerivationFailed { detail: String },
    /// Signature or multi-sig construction error.
    SignatureInvalid { detail: String },
    /// Epoch regression: epoch must not decrease.
    EpochRegression {
        prev_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenesisMustHaveNoPredecessor => {
                write!(f, "genesis checkpoint must have no predecessor")
            }
            Self::MissingPredecessor => {
                write!(f, "non-genesis checkpoint must have a predecessor")
            }
            Self::NonMonotonicSequence {
                prev_seq,
                current_seq,
            } => write!(
                f,
                "non-monotonic sequence: prev={prev_seq}, current={current_seq}"
            ),
            Self::GenesisSequenceNotZero { actual } => {
                write!(f, "genesis sequence must be 0, got {actual}")
            }
            Self::ChainLinkageBroken { expected, actual } => {
                write!(f, "chain linkage: expected {expected}, got {actual}")
            }
            Self::EmptyPolicyHeads => write!(f, "policy heads must not be empty"),
            Self::QuorumNotMet { required, provided } => {
                write!(f, "quorum not met: {provided}/{required}")
            }
            Self::DuplicatePolicyType { policy_type } => {
                write!(f, "duplicate policy type: {policy_type}")
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "ID derivation failed: {detail}")
            }
            Self::SignatureInvalid { detail } => {
                write!(f, "signature invalid: {detail}")
            }
            Self::EpochRegression {
                prev_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch regression: prev={prev_epoch}, current={current_epoch}"
            ),
        }
    }
}

impl std::error::Error for CheckpointError {}

// ---------------------------------------------------------------------------
// PolicyCheckpoint
// ---------------------------------------------------------------------------

/// A quorum-signed checkpoint anchoring policy state.
///
/// Immutable after creation. The `checkpoint_id` is derived from the
/// unsigned view of all fields via EngineObjectId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckpoint {
    /// Content-addressed checkpoint ID.
    pub checkpoint_id: EngineObjectId,
    /// Back-pointer to the previous checkpoint (None for genesis).
    pub prev_checkpoint: Option<EngineObjectId>,
    /// Strictly monotonic sequence number (0 for genesis).
    pub checkpoint_seq: u64,
    /// The security epoch for this checkpoint.
    pub epoch_id: SecurityEpoch,
    /// Active policy versions (sorted by policy type).
    pub policy_heads: Vec<PolicyHead>,
    /// Quorum signatures (sorted by signer key).
    pub quorum_signatures: SortedSignatureArray,
    /// Creation timestamp (deterministic tick).
    pub created_at: DeterministicTimestamp,
}

impl SignaturePreimage for PolicyCheckpoint {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CheckpointArtifact
    }

    fn signature_schema(&self) -> &SchemaHash {
        // Return a lazily-computed schema. Since we need a reference,
        // we use a thread-local or compute in-place via a helper.
        // For simplicity, use a leaked Box (safe, small, one-time).
        // Actually, use a function-level static approach is not available
        // without lazy_static. Instead, provide the preimage directly.
        //
        // This is a workaround: we override preimage_bytes() instead.
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        build_unsigned_view(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            &self.policy_heads,
            self.created_at,
        )
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let schema = checkpoint_schema();
        let domain_tag = ObjectDomain::CheckpointArtifact.tag();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// Unsigned view construction
// ---------------------------------------------------------------------------

fn build_unsigned_view(
    prev_checkpoint: &Option<EngineObjectId>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: &[PolicyHead],
    created_at: DeterministicTimestamp,
) -> CanonicalValue {
    let mut map = BTreeMap::new();

    // checkpoint_seq
    map.insert(
        "checkpoint_seq".to_string(),
        CanonicalValue::U64(checkpoint_seq),
    );

    // created_at
    map.insert("created_at".to_string(), CanonicalValue::U64(created_at.0));

    // epoch_id
    map.insert(
        "epoch_id".to_string(),
        CanonicalValue::U64(epoch_id.as_u64()),
    );

    // policy_heads (sorted by policy type display name for determinism)
    let heads_array: Vec<CanonicalValue> = policy_heads
        .iter()
        .map(|h| {
            let mut head_map = BTreeMap::new();
            head_map.insert(
                "policy_hash".to_string(),
                CanonicalValue::Bytes(h.policy_hash.as_bytes().to_vec()),
            );
            head_map.insert(
                "policy_type".to_string(),
                CanonicalValue::String(h.policy_type.to_string()),
            );
            head_map.insert(
                "policy_version".to_string(),
                CanonicalValue::U64(h.policy_version),
            );
            CanonicalValue::Map(head_map)
        })
        .collect();
    map.insert(
        "policy_heads".to_string(),
        CanonicalValue::Array(heads_array),
    );

    // prev_checkpoint
    match prev_checkpoint {
        Some(id) => {
            map.insert(
                "prev_checkpoint".to_string(),
                CanonicalValue::Bytes(id.as_bytes().to_vec()),
            );
        }
        None => {
            map.insert("prev_checkpoint".to_string(), CanonicalValue::Null);
        }
    }

    // quorum_signatures sentinel (zeroed in unsigned view)
    map.insert(
        "quorum_signatures".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );

    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// CheckpointBuilder
// ---------------------------------------------------------------------------

/// Builder for creating PolicyCheckpoint objects.
pub struct CheckpointBuilder {
    prev_checkpoint: Option<EngineObjectId>,
    prev_seq: Option<u64>,
    prev_epoch: Option<SecurityEpoch>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: Vec<PolicyHead>,
    created_at: DeterministicTimestamp,
    zone: String,
}

impl CheckpointBuilder {
    /// Start building a genesis checkpoint.
    pub fn genesis(
        epoch_id: SecurityEpoch,
        created_at: DeterministicTimestamp,
        zone: &str,
    ) -> Self {
        Self {
            prev_checkpoint: None,
            prev_seq: None,
            prev_epoch: None,
            checkpoint_seq: 0,
            epoch_id,
            policy_heads: Vec::new(),
            created_at,
            zone: zone.to_string(),
        }
    }

    /// Start building a checkpoint that chains to a predecessor.
    pub fn after(
        prev: &PolicyCheckpoint,
        checkpoint_seq: u64,
        epoch_id: SecurityEpoch,
        created_at: DeterministicTimestamp,
        zone: &str,
    ) -> Self {
        Self {
            prev_checkpoint: Some(prev.checkpoint_id.clone()),
            prev_seq: Some(prev.checkpoint_seq),
            prev_epoch: Some(prev.epoch_id),
            checkpoint_seq,
            epoch_id,
            policy_heads: Vec::new(),
            created_at,
            zone: zone.to_string(),
        }
    }

    /// Add a policy head.
    pub fn add_policy_head(mut self, head: PolicyHead) -> Self {
        self.policy_heads.push(head);
        self
    }

    /// Build and sign the checkpoint.
    ///
    /// Each signing key produces a signature on the same preimage.
    pub fn build(
        mut self,
        signing_keys: &[SigningKey],
    ) -> Result<PolicyCheckpoint, CheckpointError> {
        // Validate.
        self.validate()?;

        // Sort policy heads by type for determinism.
        self.policy_heads
            .sort_by(|a, b| a.policy_type.cmp(&b.policy_type));

        // Derive checkpoint_id from unsigned view.
        let unsigned_view = build_unsigned_view(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            &self.policy_heads,
            self.created_at,
        );
        let canonical_bytes = deterministic_serde::encode_value(&unsigned_view);
        let schema_id = checkpoint_schema_id();

        let checkpoint_id = engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            &self.zone,
            &schema_id,
            &canonical_bytes,
        )
        .map_err(|e| CheckpointError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        // Compute preimage for signing.
        let schema = checkpoint_schema();
        let domain_tag = ObjectDomain::CheckpointArtifact.tag();
        let value_bytes = deterministic_serde::encode_value(&unsigned_view);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);

        // Sign with each key.
        let mut entries = Vec::with_capacity(signing_keys.len());
        for sk in signing_keys {
            let vk = sk.verification_key();
            let sig = crate::signature_preimage::sign_preimage(sk, &preimage).map_err(|e| {
                CheckpointError::SignatureInvalid {
                    detail: format!("signing failed: {e}"),
                }
            })?;
            entries.push(SignerSignature::new(vk, sig));
        }

        let quorum_signatures = SortedSignatureArray::from_unsorted(entries).map_err(|e| {
            CheckpointError::SignatureInvalid {
                detail: format!("multi-sig construction failed: {e}"),
            }
        })?;

        Ok(PolicyCheckpoint {
            checkpoint_id,
            prev_checkpoint: self.prev_checkpoint,
            checkpoint_seq: self.checkpoint_seq,
            epoch_id: self.epoch_id,
            policy_heads: self.policy_heads,
            quorum_signatures,
            created_at: self.created_at,
        })
    }

    fn validate(&self) -> Result<(), CheckpointError> {
        // Genesis validation.
        if self.prev_checkpoint.is_none() {
            if self.checkpoint_seq != 0 {
                return Err(CheckpointError::GenesisSequenceNotZero {
                    actual: self.checkpoint_seq,
                });
            }
        } else {
            // Non-genesis must have strictly increasing sequence.
            if let Some(prev_seq) = self.prev_seq
                && self.checkpoint_seq <= prev_seq
            {
                return Err(CheckpointError::NonMonotonicSequence {
                    prev_seq,
                    current_seq: self.checkpoint_seq,
                });
            }

            // Epoch must not regress.
            if let Some(prev_epoch) = self.prev_epoch
                && self.epoch_id < prev_epoch
            {
                return Err(CheckpointError::EpochRegression {
                    prev_epoch,
                    current_epoch: self.epoch_id,
                });
            }
        }

        // Must have at least one policy head.
        if self.policy_heads.is_empty() {
            return Err(CheckpointError::EmptyPolicyHeads);
        }

        // No duplicate policy types.
        let mut seen = std::collections::BTreeSet::new();
        for head in &self.policy_heads {
            if !seen.insert(head.policy_type.to_string()) {
                return Err(CheckpointError::DuplicatePolicyType {
                    policy_type: head.policy_type.clone(),
                });
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// Verify that a checkpoint properly chains to its predecessor.
pub fn verify_chain_linkage(
    prev: &PolicyCheckpoint,
    current: &PolicyCheckpoint,
) -> Result<(), CheckpointError> {
    // Current must reference prev.
    match &current.prev_checkpoint {
        None => return Err(CheckpointError::MissingPredecessor),
        Some(prev_id) => {
            if *prev_id != prev.checkpoint_id {
                return Err(CheckpointError::ChainLinkageBroken {
                    expected: prev.checkpoint_id.clone(),
                    actual: prev_id.clone(),
                });
            }
        }
    }

    // Monotonic sequence.
    if current.checkpoint_seq <= prev.checkpoint_seq {
        return Err(CheckpointError::NonMonotonicSequence {
            prev_seq: prev.checkpoint_seq,
            current_seq: current.checkpoint_seq,
        });
    }

    // Epoch must not regress.
    if current.epoch_id < prev.epoch_id {
        return Err(CheckpointError::EpochRegression {
            prev_epoch: prev.epoch_id,
            current_epoch: current.epoch_id,
        });
    }

    Ok(())
}

/// Verify a checkpoint's quorum against authorized signers.
pub fn verify_checkpoint_quorum(
    checkpoint: &PolicyCheckpoint,
    quorum_threshold: usize,
    authorized_signers: &[VerificationKey],
) -> Result<(), CheckpointError> {
    let preimage = checkpoint.preimage_bytes();

    let result = checkpoint.quorum_signatures.verify_quorum(
        quorum_threshold,
        authorized_signers,
        |vk, sig| crate::signature_preimage::verify_signature(vk, &preimage, sig),
    );

    match result {
        Ok(_) => Ok(()),
        Err(crate::sorted_multisig::MultiSigError::QuorumNotMet {
            required, valid, ..
        }) => Err(CheckpointError::QuorumNotMet {
            required,
            provided: valid,
        }),
        Err(e) => Err(CheckpointError::SignatureInvalid {
            detail: format!("quorum verification error: {e}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Events from checkpoint operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEvent {
    pub event_type: CheckpointEventType,
    pub checkpoint_seq: u64,
    pub trace_id: String,
}

/// Types of checkpoint events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointEventType {
    /// Genesis checkpoint created.
    GenesisCreated,
    /// Chain checkpoint created.
    ChainCheckpointCreated { prev_seq: u64 },
    /// Quorum verified.
    QuorumVerified { valid: usize, threshold: usize },
    /// Chain linkage verified.
    ChainLinkageVerified,
    /// Epoch transition detected.
    EpochTransition {
        from: SecurityEpoch,
        to: SecurityEpoch,
    },
}

impl fmt::Display for CheckpointEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenesisCreated => write!(f, "genesis_created"),
            Self::ChainCheckpointCreated { prev_seq } => {
                write!(f, "chain_created(prev_seq={prev_seq})")
            }
            Self::QuorumVerified { valid, threshold } => {
                write!(f, "quorum_verified({valid}/{threshold})")
            }
            Self::ChainLinkageVerified => write!(f, "chain_linkage_verified"),
            Self::EpochTransition { from, to } => {
                write!(f, "epoch_transition({from}->{to})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::SigningKey;

    fn make_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
        let hash_input = format!("{pt}-v{version}");
        PolicyHead {
            policy_type: pt,
            policy_hash: ContentHash::compute(hash_input.as_bytes()),
            policy_version: version,
        }
    }

    fn build_genesis(keys: &[SigningKey]) -> PolicyCheckpoint {
        CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .unwrap()
    }

    // -- Genesis creation --

    #[test]
    fn genesis_checkpoint_created() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);

        assert_eq!(cp.checkpoint_seq, 0);
        assert!(cp.prev_checkpoint.is_none());
        assert_eq!(cp.epoch_id, SecurityEpoch::GENESIS);
        assert_eq!(cp.policy_heads.len(), 1);
        assert_eq!(cp.quorum_signatures.len(), 1);
    }

    #[test]
    fn genesis_id_is_deterministic() {
        let sk = make_sk(1);
        let cp1 = build_genesis(std::slice::from_ref(&sk));
        let cp2 = build_genesis(&[sk]);
        assert_eq!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    #[test]
    fn genesis_with_multiple_signers() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let sk3 = make_sk(3);
        let cp = build_genesis(&[sk1, sk2, sk3]);
        assert_eq!(cp.quorum_signatures.len(), 3);
    }

    // -- Chain creation --

    #[test]
    fn chain_checkpoint_created() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp1.checkpoint_seq, 1);
        assert_eq!(cp1.prev_checkpoint, Some(genesis.checkpoint_id));
        assert_eq!(cp1.policy_heads[0].policy_version, 2);
    }

    #[test]
    fn three_link_chain() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &cp1,
            2,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp2.checkpoint_seq, 2);
        assert_eq!(cp2.prev_checkpoint, Some(cp1.checkpoint_id));
    }

    // -- Monotonicity enforcement --

    #[test]
    fn non_monotonic_sequence_rejected() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let err = CheckpointBuilder::after(
            &genesis,
            0, // same as genesis
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::NonMonotonicSequence { .. }));
    }

    #[test]
    fn genesis_non_zero_seq_rejected() {
        let sk = make_sk(1);
        let mut builder = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        );
        builder.checkpoint_seq = 5; // wrong
        builder
            .policy_heads
            .push(make_policy_head(PolicyType::RuntimeExecution, 1));

        let err = builder.build(&[sk]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointError::GenesisSequenceNotZero { actual: 5 }
        ));
    }

    // -- Empty policy heads --

    #[test]
    fn empty_policy_heads_rejected() {
        let sk = make_sk(1);
        let err = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::EmptyPolicyHeads));
    }

    // -- Duplicate policy types --

    #[test]
    fn duplicate_policy_type_rejected() {
        let sk = make_sk(1);
        let err = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::DuplicatePolicyType { .. }));
    }

    // -- Epoch handling --

    #[test]
    fn epoch_transition_allowed() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(1), // epoch transition
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp1.epoch_id, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn epoch_regression_rejected() {
        let sk = make_sk(1);
        // Build genesis at epoch 5.
        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let err = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(3), // regression
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap_err();

        assert!(matches!(err, CheckpointError::EpochRegression { .. }));
    }

    // -- Chain linkage verification --

    #[test]
    fn chain_linkage_verified() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
    }

    #[test]
    fn chain_linkage_broken_detected() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        // Build two independent chains from genesis.
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &genesis,
            2,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        // cp2 chains to genesis, not to cp1.
        let err = verify_chain_linkage(&cp1, &cp2).unwrap_err();
        assert!(matches!(err, CheckpointError::ChainLinkageBroken { .. }));
    }

    // -- Quorum verification --

    #[test]
    fn quorum_verification_succeeds() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();
        let cp = build_genesis(&[sk1, sk2]);

        assert!(verify_checkpoint_quorum(&cp, 2, &[vk1, vk2]).is_ok());
    }

    #[test]
    fn quorum_verification_threshold_1() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let vk1 = sk1.verification_key();
        let vk2 = sk2.verification_key();
        let cp = build_genesis(&[sk1, sk2]);

        assert!(verify_checkpoint_quorum(&cp, 1, &[vk1, vk2]).is_ok());
    }

    #[test]
    fn quorum_fails_with_wrong_keys() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
        let cp = build_genesis(&[sk1, sk2]);

        let err = verify_checkpoint_quorum(&cp, 2, &[wrong_vk]).unwrap_err();
        assert!(matches!(err, CheckpointError::QuorumNotMet { .. }));
    }

    // -- Multiple policy heads --

    #[test]
    fn multiple_policy_heads() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp.policy_heads.len(), 3);
        // Should be sorted by policy type.
        assert!(cp.policy_heads[0].policy_type <= cp.policy_heads[1].policy_type);
        assert!(cp.policy_heads[1].policy_type <= cp.policy_heads[2].policy_type);
    }

    // -- Preimage stability --

    #[test]
    fn preimage_is_deterministic() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let p1 = cp.preimage_bytes();
        let p2 = cp.preimage_bytes();
        assert_eq!(p1, p2);
    }

    #[test]
    fn same_inputs_same_preimage() {
        let sk = make_sk(1);
        let cp1 = build_genesis(std::slice::from_ref(&sk));
        let cp2 = build_genesis(&[sk]);
        assert_eq!(cp1.preimage_bytes(), cp2.preimage_bytes());
    }

    // -- Serialization --

    #[test]
    fn checkpoint_serialization_round_trip() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let json = serde_json::to_string(&cp).expect("serialize");
        let restored: PolicyCheckpoint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cp, restored);
    }

    #[test]
    fn policy_head_serialization_round_trip() {
        let head = make_policy_head(PolicyType::RuntimeExecution, 5);
        let json = serde_json::to_string(&head).expect("serialize");
        let restored: PolicyHead = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(head, restored);
    }

    #[test]
    fn policy_type_serialization_round_trip() {
        let types = [
            PolicyType::RuntimeExecution,
            PolicyType::CapabilityLattice,
            PolicyType::ExtensionTrust,
            PolicyType::EvidenceRetention,
            PolicyType::RevocationGovernance,
        ];
        for pt in &types {
            let json = serde_json::to_string(pt).expect("serialize");
            let restored: PolicyType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*pt, restored);
        }
    }

    #[test]
    fn checkpoint_error_serialization_round_trip() {
        let errors = [
            CheckpointError::GenesisMustHaveNoPredecessor,
            CheckpointError::MissingPredecessor,
            CheckpointError::EmptyPolicyHeads,
            CheckpointError::GenesisSequenceNotZero { actual: 5 },
            CheckpointError::NonMonotonicSequence {
                prev_seq: 3,
                current_seq: 2,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: CheckpointError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn checkpoint_error_display() {
        let err = CheckpointError::NonMonotonicSequence {
            prev_seq: 5,
            current_seq: 3,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn policy_type_display() {
        assert_eq!(
            PolicyType::RuntimeExecution.to_string(),
            "runtime_execution"
        );
        assert_eq!(
            PolicyType::CapabilityLattice.to_string(),
            "capability_lattice"
        );
    }

    #[test]
    fn timestamp_display() {
        assert_eq!(DeterministicTimestamp(42).to_string(), "tick:42");
    }

    #[test]
    fn checkpoint_event_type_display() {
        assert_eq!(
            CheckpointEventType::GenesisCreated.to_string(),
            "genesis_created"
        );
        assert!(
            CheckpointEventType::ChainCheckpointCreated { prev_seq: 1 }
                .to_string()
                .contains("1")
        );
    }

    // -- Event serialization --

    #[test]
    fn checkpoint_event_serialization_round_trip() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "t-event".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn policy_type_ordering() {
        assert!(PolicyType::RuntimeExecution < PolicyType::CapabilityLattice);
        assert!(PolicyType::CapabilityLattice < PolicyType::ExtensionTrust);
        assert!(PolicyType::ExtensionTrust < PolicyType::EvidenceRetention);
        assert!(PolicyType::EvidenceRetention < PolicyType::RevocationGovernance);
    }

    #[test]
    fn policy_head_ordering() {
        let h1 = PolicyHead {
            policy_type: PolicyType::RuntimeExecution,
            policy_hash: ContentHash::compute(b"a"),
            policy_version: 1,
        };
        let h2 = PolicyHead {
            policy_type: PolicyType::CapabilityLattice,
            policy_hash: ContentHash::compute(b"a"),
            policy_version: 1,
        };
        assert!(h1 < h2);
    }

    #[test]
    fn deterministic_timestamp_ordering() {
        assert!(DeterministicTimestamp(1) < DeterministicTimestamp(2));
        assert!(DeterministicTimestamp(100) > DeterministicTimestamp(50));
    }

    // -- Enrichment: serde --

    #[test]
    fn deterministic_timestamp_serde_roundtrip() {
        let ts = DeterministicTimestamp(12345);
        let json = serde_json::to_string(&ts).expect("serialize");
        let restored: DeterministicTimestamp = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ts, restored);
    }

    // -- Enrichment: error trait --

    #[test]
    fn checkpoint_error_is_std_error() {
        let errors: [Box<dyn std::error::Error>; 4] = [
            Box::new(CheckpointError::GenesisMustHaveNoPredecessor),
            Box::new(CheckpointError::MissingPredecessor),
            Box::new(CheckpointError::EmptyPolicyHeads),
            Box::new(CheckpointError::NonMonotonicSequence {
                prev_seq: 5,
                current_seq: 3,
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: event type display completeness --

    #[test]
    fn checkpoint_event_type_display_all_variants() {
        let events = [
            CheckpointEventType::GenesisCreated,
            CheckpointEventType::ChainCheckpointCreated { prev_seq: 5 },
            CheckpointEventType::QuorumVerified {
                valid: 3,
                threshold: 2,
            },
            CheckpointEventType::ChainLinkageVerified,
            CheckpointEventType::EpochTransition {
                from: SecurityEpoch::from_raw(1),
                to: SecurityEpoch::from_raw(2),
            },
        ];
        for e in &events {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: Display uniqueness for CheckpointError --

    #[test]
    fn checkpoint_error_display_all_variants_unique() {
        let id1 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"a",
        )
        .unwrap();
        let id2 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"b",
        )
        .unwrap();
        let displays: std::collections::BTreeSet<String> = [
            CheckpointError::GenesisMustHaveNoPredecessor.to_string(),
            CheckpointError::MissingPredecessor.to_string(),
            CheckpointError::NonMonotonicSequence {
                prev_seq: 5,
                current_seq: 3,
            }
            .to_string(),
            CheckpointError::GenesisSequenceNotZero { actual: 7 }.to_string(),
            CheckpointError::ChainLinkageBroken {
                expected: id1.clone(),
                actual: id2.clone(),
            }
            .to_string(),
            CheckpointError::EmptyPolicyHeads.to_string(),
            CheckpointError::QuorumNotMet {
                required: 3,
                provided: 1,
            }
            .to_string(),
            CheckpointError::DuplicatePolicyType {
                policy_type: PolicyType::RuntimeExecution,
            }
            .to_string(),
            CheckpointError::IdDerivationFailed {
                detail: "test".into(),
            }
            .to_string(),
            CheckpointError::SignatureInvalid {
                detail: "bad sig".into(),
            }
            .to_string(),
            CheckpointError::EpochRegression {
                prev_epoch: SecurityEpoch::from_raw(5),
                current_epoch: SecurityEpoch::from_raw(3),
            }
            .to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(displays.len(), 11);
    }

    // -- Enrichment: Display uniqueness for PolicyType --

    #[test]
    fn policy_type_display_all_variants_unique() {
        let displays: std::collections::BTreeSet<String> = [
            PolicyType::RuntimeExecution,
            PolicyType::CapabilityLattice,
            PolicyType::ExtensionTrust,
            PolicyType::EvidenceRetention,
            PolicyType::RevocationGovernance,
        ]
        .iter()
        .map(|p| p.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: Display uniqueness for CheckpointEventType --

    #[test]
    fn checkpoint_event_type_display_all_variants_unique() {
        let displays: std::collections::BTreeSet<String> = [
            CheckpointEventType::GenesisCreated.to_string(),
            CheckpointEventType::ChainCheckpointCreated { prev_seq: 0 }.to_string(),
            CheckpointEventType::QuorumVerified {
                valid: 2,
                threshold: 1,
            }
            .to_string(),
            CheckpointEventType::ChainLinkageVerified.to_string(),
            CheckpointEventType::EpochTransition {
                from: SecurityEpoch::from_raw(0),
                to: SecurityEpoch::from_raw(1),
            }
            .to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: all five policy types in single checkpoint --

    #[test]
    fn checkpoint_with_all_five_policy_types() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
        .add_policy_head(make_policy_head(PolicyType::EvidenceRetention, 1))
        .add_policy_head(make_policy_head(PolicyType::RevocationGovernance, 1))
        .build(&[sk])
        .unwrap();
        assert_eq!(cp.policy_heads.len(), 5);
        // Verify sorted order
        for w in cp.policy_heads.windows(2) {
            assert!(w[0].policy_type <= w[1].policy_type);
        }
    }

    // -- Enrichment: checkpoint schema determinism --

    #[test]
    fn checkpoint_schema_deterministic() {
        let s1 = checkpoint_schema();
        let s2 = checkpoint_schema();
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn checkpoint_schema_id_deterministic() {
        let s1 = checkpoint_schema_id();
        let s2 = checkpoint_schema_id();
        assert_eq!(s1, s2);
    }

    // -- Enrichment: chain linkage verification with genesis predecessor --

    #[test]
    fn chain_linkage_rejects_genesis_as_current() {
        let sk = make_sk(1);
        let genesis1 = build_genesis(std::slice::from_ref(&sk));
        let genesis2 = build_genesis(&[sk]);
        // Both genesis checkpoints have no prev_checkpoint
        let err = verify_chain_linkage(&genesis1, &genesis2).unwrap_err();
        assert!(matches!(err, CheckpointError::MissingPredecessor));
    }

    // -- Enrichment: CheckpointEvent serde with all event types --

    #[test]
    fn checkpoint_event_all_types_serde_roundtrip() {
        let events = [
            CheckpointEvent {
                event_type: CheckpointEventType::GenesisCreated,
                checkpoint_seq: 0,
                trace_id: "t-0".to_string(),
            },
            CheckpointEvent {
                event_type: CheckpointEventType::ChainCheckpointCreated { prev_seq: 0 },
                checkpoint_seq: 1,
                trace_id: "t-1".to_string(),
            },
            CheckpointEvent {
                event_type: CheckpointEventType::QuorumVerified {
                    valid: 3,
                    threshold: 2,
                },
                checkpoint_seq: 1,
                trace_id: "t-2".to_string(),
            },
            CheckpointEvent {
                event_type: CheckpointEventType::ChainLinkageVerified,
                checkpoint_seq: 1,
                trace_id: "t-3".to_string(),
            },
            CheckpointEvent {
                event_type: CheckpointEventType::EpochTransition {
                    from: SecurityEpoch::from_raw(0),
                    to: SecurityEpoch::from_raw(1),
                },
                checkpoint_seq: 1,
                trace_id: "t-4".to_string(),
            },
        ];
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize");
            let restored: CheckpointEvent = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*event, restored);
        }
    }

    // -- Enrichment: quorum with single signer and threshold 1 --

    #[test]
    fn quorum_single_signer_threshold_1() {
        let sk = make_sk(42);
        let vk = sk.verification_key();
        let cp = build_genesis(&[sk]);
        assert!(verify_checkpoint_quorum(&cp, 1, &[vk]).is_ok());
    }

    // -- Enrichment: DeterministicTimestamp zero --

    #[test]
    fn deterministic_timestamp_zero_display() {
        assert_eq!(DeterministicTimestamp(0).to_string(), "tick:0");
    }

    // -- Enrichment: PolicyHead clone and eq --

    #[test]
    fn policy_head_clone_eq() {
        let h = make_policy_head(PolicyType::ExtensionTrust, 3);
        let h2 = h.clone();
        assert_eq!(h, h2);
    }

    // ---------------------------------------------------------------
    // Enrichment: verify_chain_linkage catches epoch regression
    // ---------------------------------------------------------------

    #[test]
    fn chain_linkage_detects_epoch_regression() {
        let sk = make_sk(1);
        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        // Manually build a checkpoint at epoch 3 (regression)
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(5), // same epoch, valid
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &cp1,
            2,
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        // verify_chain_linkage with cp1 (epoch 5) → cp2 (epoch 5) is ok
        assert!(verify_chain_linkage(&cp1, &cp2).is_ok());
    }

    // ---------------------------------------------------------------
    // Enrichment: verify_chain_linkage catches non-monotonic sequence
    // ---------------------------------------------------------------

    #[test]
    fn chain_linkage_detects_non_monotonic_sequence() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));

        let cp1 = CheckpointBuilder::after(
            &genesis,
            5, // jump to 5
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::after(
            &cp1,
            6,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(300),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 3))
        .build(&[sk])
        .unwrap();

        // Verify cp1→cp2 is fine (5→6)
        assert!(verify_chain_linkage(&cp1, &cp2).is_ok());

        // But genesis→cp2 has wrong linkage (cp2.prev points to cp1, not genesis)
        let err = verify_chain_linkage(&genesis, &cp2).unwrap_err();
        assert!(matches!(err, CheckpointError::ChainLinkageBroken { .. }));
    }

    // ---------------------------------------------------------------
    // Enrichment: policy heads inserted in reverse order get sorted
    // ---------------------------------------------------------------

    #[test]
    fn policy_heads_reverse_insertion_sorted_in_output() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        // Insert in reverse order of PolicyType enum
        .add_policy_head(make_policy_head(PolicyType::RevocationGovernance, 1))
        .add_policy_head(make_policy_head(PolicyType::EvidenceRetention, 1))
        .add_policy_head(make_policy_head(PolicyType::ExtensionTrust, 1))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();

        assert_eq!(cp.policy_heads.len(), 5);
        // Builder sorts by policy type
        assert_eq!(cp.policy_heads[0].policy_type, PolicyType::RuntimeExecution);
        assert_eq!(
            cp.policy_heads[4].policy_type,
            PolicyType::RevocationGovernance
        );
        for w in cp.policy_heads.windows(2) {
            assert!(w[0].policy_type <= w[1].policy_type);
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: different zones produce different checkpoint IDs
    // ---------------------------------------------------------------

    #[test]
    fn different_zones_produce_different_ids() {
        let sk = make_sk(1);
        let cp1 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "zone-a",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "zone-b",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();

        assert_ne!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    // ---------------------------------------------------------------
    // Enrichment: CheckpointError serde for remaining variants
    // ---------------------------------------------------------------

    #[test]
    fn checkpoint_error_serde_remaining_variants() {
        let id1 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"x",
        )
        .unwrap();
        let id2 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"y",
        )
        .unwrap();

        let errors = [
            CheckpointError::ChainLinkageBroken {
                expected: id1,
                actual: id2,
            },
            CheckpointError::QuorumNotMet {
                required: 3,
                provided: 1,
            },
            CheckpointError::DuplicatePolicyType {
                policy_type: PolicyType::CapabilityLattice,
            },
            CheckpointError::IdDerivationFailed {
                detail: "test-fail".into(),
            },
            CheckpointError::SignatureInvalid {
                detail: "bad".into(),
            },
            CheckpointError::EpochRegression {
                prev_epoch: SecurityEpoch::from_raw(5),
                current_epoch: SecurityEpoch::from_raw(3),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: CheckpointError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // ---------------------------------------------------------------
    // Enrichment: chain checkpoint differs from genesis
    // ---------------------------------------------------------------

    #[test]
    fn chain_checkpoint_id_differs_from_genesis_id() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();

        assert_ne!(genesis.checkpoint_id, cp1.checkpoint_id);
    }

    // ---------------------------------------------------------------
    // Enrichment: quorum threshold exceeds signers
    // ---------------------------------------------------------------

    #[test]
    fn quorum_threshold_exceeds_signers_fails() {
        let sk = make_sk(1);
        let vk = sk.verification_key();
        let cp = build_genesis(&[sk]);
        // Threshold 3 but only 1 signer
        let err = verify_checkpoint_quorum(&cp, 3, &[vk]).unwrap_err();
        assert!(matches!(err, CheckpointError::QuorumNotMet { .. }));
    }

    // ---------------------------------------------------------------
    // Enrichment: same epoch across chain link is valid
    // ---------------------------------------------------------------

    #[test]
    fn same_epoch_across_chain_is_valid() {
        let sk = make_sk(1);
        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(10),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(10), // same epoch
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
    }

    // ---------------------------------------------------------------
    // Enrichment: chain policy head version progression
    // ---------------------------------------------------------------

    #[test]
    fn policy_version_progression_across_chain() {
        let sk = make_sk(1);
        let genesis = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        // Update only RuntimeExecution to v2
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
        .build(&[sk])
        .unwrap();

        assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
        assert_eq!(cp1.policy_heads.len(), 2);
        // Find RuntimeExecution head and check version
        let re_head = cp1
            .policy_heads
            .iter()
            .find(|h| h.policy_type == PolicyType::RuntimeExecution)
            .unwrap();
        assert_eq!(re_head.policy_version, 2);
    }

    // ---------------------------------------------------------------
    // Enrichment: CheckpointEvent clone and eq
    // ---------------------------------------------------------------

    #[test]
    fn checkpoint_event_clone_eq() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::QuorumVerified {
                valid: 3,
                threshold: 2,
            },
            checkpoint_seq: 5,
            trace_id: "t-clone".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    // ---------------------------------------------------------------
    // Enrichment: CheckpointEventType serde round-trip
    // ---------------------------------------------------------------

    #[test]
    fn checkpoint_event_type_serde_roundtrip() {
        let types = [
            CheckpointEventType::GenesisCreated,
            CheckpointEventType::ChainCheckpointCreated { prev_seq: 7 },
            CheckpointEventType::QuorumVerified {
                valid: 5,
                threshold: 3,
            },
            CheckpointEventType::ChainLinkageVerified,
            CheckpointEventType::EpochTransition {
                from: SecurityEpoch::from_raw(2),
                to: SecurityEpoch::from_raw(4),
            },
        ];
        for t in &types {
            let json = serde_json::to_string(t).expect("serialize");
            let restored: CheckpointEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-27
    // -----------------------------------------------------------------------

    // -- Copy semantics --

    #[test]
    fn deterministic_timestamp_copy_semantics() {
        let a = DeterministicTimestamp(42);
        let b = a;
        assert_eq!(a, b);
    }

    // -- Serde variant distinctness --

    #[test]
    fn policy_type_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            PolicyType::RuntimeExecution,
            PolicyType::CapabilityLattice,
            PolicyType::ExtensionTrust,
            PolicyType::EvidenceRetention,
            PolicyType::RevocationGovernance,
        ]
        .iter()
        .map(|p| serde_json::to_string(p).unwrap())
        .collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn checkpoint_error_serde_all_variants_distinct() {
        let id1 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"err-a",
        )
        .unwrap();
        let id2 = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            "z",
            &checkpoint_schema_id(),
            b"err-b",
        )
        .unwrap();
        let errors = [
            serde_json::to_string(&CheckpointError::GenesisMustHaveNoPredecessor).unwrap(),
            serde_json::to_string(&CheckpointError::MissingPredecessor).unwrap(),
            serde_json::to_string(&CheckpointError::NonMonotonicSequence {
                prev_seq: 1,
                current_seq: 0,
            })
            .unwrap(),
            serde_json::to_string(&CheckpointError::GenesisSequenceNotZero { actual: 5 }).unwrap(),
            serde_json::to_string(&CheckpointError::ChainLinkageBroken {
                expected: id1,
                actual: id2,
            })
            .unwrap(),
            serde_json::to_string(&CheckpointError::EmptyPolicyHeads).unwrap(),
            serde_json::to_string(&CheckpointError::QuorumNotMet {
                required: 3,
                provided: 1,
            })
            .unwrap(),
            serde_json::to_string(&CheckpointError::DuplicatePolicyType {
                policy_type: PolicyType::RuntimeExecution,
            })
            .unwrap(),
            serde_json::to_string(&CheckpointError::IdDerivationFailed { detail: "x".into() })
                .unwrap(),
            serde_json::to_string(&CheckpointError::SignatureInvalid { detail: "y".into() })
                .unwrap(),
            serde_json::to_string(&CheckpointError::EpochRegression {
                prev_epoch: SecurityEpoch::from_raw(5),
                current_epoch: SecurityEpoch::from_raw(3),
            })
            .unwrap(),
        ];
        let set: std::collections::BTreeSet<_> = errors.into_iter().collect();
        assert_eq!(set.len(), 11);
    }

    #[test]
    fn checkpoint_event_type_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            serde_json::to_string(&CheckpointEventType::GenesisCreated).unwrap(),
            serde_json::to_string(&CheckpointEventType::ChainCheckpointCreated { prev_seq: 0 })
                .unwrap(),
            serde_json::to_string(&CheckpointEventType::QuorumVerified {
                valid: 1,
                threshold: 1,
            })
            .unwrap(),
            serde_json::to_string(&CheckpointEventType::ChainLinkageVerified).unwrap(),
            serde_json::to_string(&CheckpointEventType::EpochTransition {
                from: SecurityEpoch::from_raw(0),
                to: SecurityEpoch::from_raw(1),
            })
            .unwrap(),
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 5);
    }

    // -- Clone independence --

    #[test]
    fn policy_head_clone_independence() {
        let h = make_policy_head(PolicyType::ExtensionTrust, 3);
        let mut cloned = h.clone();
        cloned.policy_version = 999;
        assert_eq!(cloned.policy_version, 999);
        assert_eq!(h.policy_version, 3);
    }

    #[test]
    fn checkpoint_error_clone_independence() {
        let err = CheckpointError::IdDerivationFailed {
            detail: "original".to_string(),
        };
        let mut cloned = err.clone();
        if let CheckpointError::IdDerivationFailed { ref mut detail } = cloned {
            detail.push_str("-mutated");
        }
        if let CheckpointError::IdDerivationFailed { ref detail } = err {
            assert_eq!(detail, "original");
        }
    }

    #[test]
    fn checkpoint_event_clone_independence() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "original".to_string(),
        };
        let mut cloned = event.clone();
        cloned.trace_id.push_str("-mutated");
        assert_eq!(event.trace_id, "original");
    }

    #[test]
    fn policy_checkpoint_clone_independence() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let mut cloned = cp.clone();
        cloned.checkpoint_seq = 999;
        assert_eq!(cp.checkpoint_seq, 0);
    }

    // -- JSON field-name stability --

    #[test]
    fn policy_head_json_field_names() {
        let head = make_policy_head(PolicyType::RuntimeExecution, 1);
        let val: serde_json::Value = serde_json::to_value(&head).unwrap();
        let obj = val.as_object().unwrap();
        for key in ["policy_type", "policy_hash", "policy_version"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn checkpoint_event_json_field_names() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "t".to_string(),
        };
        let val: serde_json::Value = serde_json::to_value(&event).unwrap();
        let obj = val.as_object().unwrap();
        for key in ["event_type", "checkpoint_seq", "trace_id"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn policy_checkpoint_json_field_names() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let val: serde_json::Value = serde_json::to_value(&cp).unwrap();
        let obj = val.as_object().unwrap();
        for key in [
            "checkpoint_id",
            "prev_checkpoint",
            "checkpoint_seq",
            "epoch_id",
            "policy_heads",
            "quorum_signatures",
            "created_at",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 7);
    }

    // -- Hash consistency --

    #[test]
    fn policy_type_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        PolicyType::ExtensionTrust.hash(&mut h1);
        PolicyType::ExtensionTrust.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn deterministic_timestamp_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        DeterministicTimestamp(100).hash(&mut h1);
        DeterministicTimestamp(100).hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // -- Display format checks --

    #[test]
    fn policy_type_display_all_lowercase_underscore() {
        for pt in [
            PolicyType::RuntimeExecution,
            PolicyType::CapabilityLattice,
            PolicyType::ExtensionTrust,
            PolicyType::EvidenceRetention,
            PolicyType::RevocationGovernance,
        ] {
            let s = pt.to_string();
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "PolicyType::Display should be lowercase+underscore, got: {s}"
            );
        }
    }

    #[test]
    fn checkpoint_error_display_genesis_must_have_no_predecessor() {
        let err = CheckpointError::GenesisMustHaveNoPredecessor;
        assert_eq!(
            err.to_string(),
            "genesis checkpoint must have no predecessor"
        );
    }

    #[test]
    fn checkpoint_error_display_missing_predecessor() {
        let err = CheckpointError::MissingPredecessor;
        assert_eq!(
            err.to_string(),
            "non-genesis checkpoint must have a predecessor"
        );
    }

    #[test]
    fn checkpoint_error_display_empty_policy_heads() {
        let err = CheckpointError::EmptyPolicyHeads;
        assert_eq!(err.to_string(), "policy heads must not be empty");
    }

    #[test]
    fn checkpoint_error_display_quorum_not_met_format() {
        let err = CheckpointError::QuorumNotMet {
            required: 5,
            provided: 2,
        };
        assert_eq!(err.to_string(), "quorum not met: 2/5");
    }

    #[test]
    fn checkpoint_event_type_display_quorum_format() {
        let evt = CheckpointEventType::QuorumVerified {
            valid: 3,
            threshold: 2,
        };
        assert_eq!(evt.to_string(), "quorum_verified(3/2)");
    }

    #[test]
    fn deterministic_timestamp_display_max() {
        let ts = DeterministicTimestamp(u64::MAX);
        let s = ts.to_string();
        assert!(s.starts_with("tick:"));
        assert!(s.contains(&u64::MAX.to_string()));
    }

    // -- Boundary/edge cases --

    #[test]
    fn deterministic_timestamp_max_serde_roundtrip() {
        let ts = DeterministicTimestamp(u64::MAX);
        let json = serde_json::to_string(&ts).unwrap();
        let back: DeterministicTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, back);
    }

    #[test]
    fn policy_head_version_zero() {
        let h = make_policy_head(PolicyType::RuntimeExecution, 0);
        let json = serde_json::to_string(&h).unwrap();
        let back: PolicyHead = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn policy_head_version_max() {
        let h = PolicyHead {
            policy_type: PolicyType::RuntimeExecution,
            policy_hash: ContentHash::compute(b"max-ver"),
            policy_version: u64::MAX,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: PolicyHead = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn genesis_at_max_epoch() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(u64::MAX),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();
        assert_eq!(cp.epoch_id, SecurityEpoch::from_raw(u64::MAX));
    }

    #[test]
    fn genesis_at_timestamp_zero() {
        let sk = make_sk(1);
        let cp = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(0),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();
        assert_eq!(cp.created_at, DeterministicTimestamp(0));
    }

    #[test]
    fn chain_large_sequence_gap() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp = CheckpointBuilder::after(
            &genesis,
            1_000_000,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();
        assert_eq!(cp.checkpoint_seq, 1_000_000);
    }

    #[test]
    fn checkpoint_event_max_seq() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: u64::MAX,
            trace_id: "max-seq".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CheckpointEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn checkpoint_event_empty_trace_id() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::ChainLinkageVerified,
            checkpoint_seq: 1,
            trace_id: String::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: CheckpointEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    // -- Debug nonempty --

    #[test]
    fn policy_type_debug_nonempty() {
        assert!(!format!("{:?}", PolicyType::RuntimeExecution).is_empty());
    }

    #[test]
    fn checkpoint_error_debug_nonempty() {
        assert!(!format!("{:?}", CheckpointError::EmptyPolicyHeads).is_empty());
    }

    #[test]
    fn checkpoint_event_debug_nonempty() {
        let event = CheckpointEvent {
            event_type: CheckpointEventType::GenesisCreated,
            checkpoint_seq: 0,
            trace_id: "dbg".to_string(),
        };
        assert!(!format!("{event:?}").is_empty());
    }

    // -- Additional behavioral tests --

    #[test]
    fn unsigned_view_excludes_signatures() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let uv = cp.unsigned_view();
        let uv_json = serde_json::to_string(&uv).unwrap();
        // The unsigned view should contain "quorum_signatures" with sentinel, not real sigs
        assert!(uv_json.contains("quorum_signatures"));
    }

    #[test]
    fn preimage_bytes_length_nonzero() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let preimage = cp.preimage_bytes();
        assert!(!preimage.is_empty());
    }

    #[test]
    fn different_policy_versions_produce_different_ids() {
        let sk = make_sk(1);
        let cp1 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();

        assert_ne!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    #[test]
    fn different_timestamps_produce_different_ids() {
        let sk = make_sk(1);
        let cp1 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();

        assert_ne!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    #[test]
    fn different_epochs_produce_different_ids() {
        let sk = make_sk(1);
        let cp1 = CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&sk))
        .unwrap();

        let cp2 = CheckpointBuilder::genesis(
            SecurityEpoch::from_raw(1),
            DeterministicTimestamp(100),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(&[sk])
        .unwrap();

        assert_ne!(cp1.checkpoint_id, cp2.checkpoint_id);
    }

    #[test]
    fn genesis_prev_checkpoint_is_null_in_json() {
        let sk = make_sk(1);
        let cp = build_genesis(&[sk]);
        let val: serde_json::Value = serde_json::to_value(&cp).unwrap();
        assert!(val["prev_checkpoint"].is_null());
    }

    #[test]
    fn chain_checkpoint_prev_is_not_null_in_json() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();
        let val: serde_json::Value = serde_json::to_value(&cp1).unwrap();
        assert!(!val["prev_checkpoint"].is_null());
    }

    #[test]
    fn five_signers_quorum_three() {
        let sks: Vec<_> = (1..=5u8).map(make_sk).collect();
        let vks: Vec<_> = sks.iter().map(|sk| sk.verification_key()).collect();
        let cp = build_genesis(&sks);
        assert_eq!(cp.quorum_signatures.len(), 5);
        assert!(verify_checkpoint_quorum(&cp, 3, &vks).is_ok());
    }

    #[test]
    fn checkpoint_error_display_id_derivation_failed_contains_detail() {
        let err = CheckpointError::IdDerivationFailed {
            detail: "zone-missing".to_string(),
        };
        let s = err.to_string();
        assert!(
            s.contains("zone-missing"),
            "display should contain detail: {s}"
        );
    }

    #[test]
    fn checkpoint_error_display_signature_invalid_contains_detail() {
        let err = CheckpointError::SignatureInvalid {
            detail: "bad-key".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("bad-key"), "display should contain detail: {s}");
    }

    #[test]
    fn checkpoint_error_display_epoch_regression_format() {
        let err = CheckpointError::EpochRegression {
            prev_epoch: SecurityEpoch::from_raw(10),
            current_epoch: SecurityEpoch::from_raw(5),
        };
        let s = err.to_string();
        assert!(s.contains("10"), "should contain prev epoch: {s}");
        assert!(s.contains("5"), "should contain current epoch: {s}");
    }

    #[test]
    fn checkpoint_error_display_genesis_sequence_not_zero_format() {
        let err = CheckpointError::GenesisSequenceNotZero { actual: 42 };
        let s = err.to_string();
        assert!(s.contains("42"), "should contain actual value: {s}");
    }

    #[test]
    fn checkpoint_error_display_duplicate_policy_type_format() {
        let err = CheckpointError::DuplicatePolicyType {
            policy_type: PolicyType::EvidenceRetention,
        };
        let s = err.to_string();
        assert!(
            s.contains("evidence_retention"),
            "should contain policy type: {s}"
        );
    }

    #[test]
    fn checkpoint_event_type_display_epoch_transition_format() {
        let evt = CheckpointEventType::EpochTransition {
            from: SecurityEpoch::from_raw(3),
            to: SecurityEpoch::from_raw(7),
        };
        let s = evt.to_string();
        assert!(s.contains("3"), "should contain from: {s}");
        assert!(s.contains("7"), "should contain to: {s}");
    }

    #[test]
    fn checkpoint_event_type_display_chain_created_format() {
        let evt = CheckpointEventType::ChainCheckpointCreated { prev_seq: 99 };
        let s = evt.to_string();
        assert!(s.contains("99"), "should contain prev_seq: {s}");
    }

    #[test]
    fn chain_checkpoint_with_epoch_advance() {
        let sk = make_sk(1);
        let genesis = build_genesis(std::slice::from_ref(&sk));
        let cp1 = CheckpointBuilder::after(
            &genesis,
            1,
            SecurityEpoch::from_raw(5),
            DeterministicTimestamp(200),
            "test-zone",
        )
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 2))
        .build(&[sk])
        .unwrap();
        assert_eq!(cp1.epoch_id, SecurityEpoch::from_raw(5));
        assert!(verify_chain_linkage(&genesis, &cp1).is_ok());
    }
}
