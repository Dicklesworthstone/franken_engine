use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, ObjectDomain,
    ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId, VersionedIdError,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    sign_preimage, verify_signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};
use crate::sorted_multisig::{MultiSigError, SignerSignature, SortedSignatureArray};

use super::compat::{
    checkpoint_schema_id, verify_checkpoint_quorum, DeterministicTimestamp, PolicyCheckpoint,
    PolicyHead, PolicyType,
};

const CHECKPOINT_SCHEMA_V2: &[u8] = b"FrankenEngine.PolicyCheckpoint.sha256.v2";

pub const POLICY_CHECKPOINT_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.policy-checkpoint.persistence.v2";

/// Verified context required to make a legacy checkpoint self-authenticating
/// during migration. Legacy checkpoints did not persist their trust-zone name,
/// even though that name was part of the EngineObjectId derivation preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyPolicyCheckpointProvenance {
    pub checkpoint: PolicyCheckpoint,
    pub zone: String,
    pub quorum_threshold: usize,
    pub authorized_signers: Vec<VerificationKey>,
}

impl LegacyPolicyCheckpointProvenance {
    pub fn new(
        checkpoint: PolicyCheckpoint,
        zone: impl Into<String>,
        quorum_threshold: usize,
        mut authorized_signers: Vec<VerificationKey>,
    ) -> Result<Self, VersionedCheckpointError> {
        authorized_signers.sort();
        authorized_signers.dedup();
        let provenance = Self {
            checkpoint,
            zone: zone.into(),
            quorum_threshold,
            authorized_signers,
        };
        provenance.verify()?;
        Ok(provenance)
    }

    pub fn verify(&self) -> Result<(), VersionedCheckpointError> {
        validate_zone(&self.zone)?;
        validate_quorum_parameters(self.quorum_threshold, &self.authorized_signers)?;
        if !is_strictly_sorted(&self.authorized_signers) {
            return Err(VersionedCheckpointError::AuthorizedSignersNotCanonical);
        }

        let canonical_bytes = deterministic_serde::encode_value(&self.checkpoint.unsigned_view());
        let expected_id = crate::engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            &self.zone,
            &checkpoint_schema_id(),
            &canonical_bytes,
        )
        .map_err(|error| VersionedCheckpointError::LegacyVerification(error.to_string()))?;
        if expected_id != self.checkpoint.checkpoint_id {
            return Err(VersionedCheckpointError::LegacyVerification(
                "legacy checkpoint_id does not match its persisted unsigned view and zone"
                    .to_string(),
            ));
        }

        verify_checkpoint_quorum(
            &self.checkpoint,
            self.quorum_threshold,
            &self.authorized_signers,
        )
        .map_err(|error| VersionedCheckpointError::LegacyVerification(error.to_string()))
    }

    /// Deterministic commitment to the legacy artifact plus the exact context
    /// used to validate it. Lengths are encoded as u64 so this helper is
    /// infallible for any in-memory Rust value and can safely participate in a
    /// `SignaturePreimage` implementation.
    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = Vec::new();
        append_u64_len(&mut bytes, self.zone.as_bytes());
        bytes.extend_from_slice(&(self.quorum_threshold as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.authorized_signers.len() as u64).to_be_bytes());
        for signer in &self.authorized_signers {
            bytes.extend_from_slice(signer.as_bytes());
        }
        append_u64_len(&mut bytes, &self.checkpoint.preimage_bytes());
        bytes.extend_from_slice(self.checkpoint.checkpoint_id.as_bytes());
        bytes.extend_from_slice(&(self.checkpoint.quorum_signatures.len() as u64).to_be_bytes());
        for entry in self.checkpoint.quorum_signatures.entries() {
            bytes.extend_from_slice(entry.signer.as_bytes());
            bytes.extend_from_slice(&entry.signature.to_bytes());
        }
        ContentHash::compute(&bytes)
    }
}

/// Self-describing SHA-256-v2 policy checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckpointV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub checkpoint_id: PersistedEngineObjectId,
    pub prev_checkpoint: Option<PersistedEngineObjectId>,
    pub checkpoint_seq: u64,
    pub epoch_id: SecurityEpoch,
    pub policy_heads: Vec<PolicyHead>,
    pub quorum_signatures: SortedSignatureArray,
    pub created_at: DeterministicTimestamp,
    pub zone: String,
    pub legacy_provenance: Option<LegacyPolicyCheckpointProvenance>,
}

impl PolicyCheckpointV2 {
    pub fn validate_identity(&self) -> Result<(), VersionedCheckpointError> {
        if self.persistence_schema != POLICY_CHECKPOINT_PERSISTENCE_SCHEMA_V2 {
            return Err(VersionedCheckpointError::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_zone(&self.zone)?;
        validate_checkpoint_shape(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            &self.policy_heads,
        )?;
        require_v2_schema(&self.schema_version)?;
        require_v2_object("checkpoint_id", &self.checkpoint_id)?;
        validate_legacy_mapping(self)?;

        let canonical_bytes = deterministic_serde::encode_value(&self.unsigned_view());
        verify_versioned_id(
            &self.checkpoint_id.to_versioned(),
            ObjectDomain::CheckpointArtifact,
            &self.zone,
            &self.schema_version.to_versioned(),
            &canonical_bytes,
        )?;
        Ok(())
    }

    pub fn verify_quorum(
        &self,
        quorum_threshold: usize,
        authorized_signers: &[VerificationKey],
    ) -> Result<(), VersionedCheckpointError> {
        self.validate_identity()?;
        validate_quorum_parameters(quorum_threshold, authorized_signers)?;
        let preimage = self.preimage_bytes();
        self.quorum_signatures
            .verify_quorum(quorum_threshold, authorized_signers, |key, signature| {
                verify_signature(key, &preimage, signature)
            })
            .map(|_| ())
            .map_err(VersionedCheckpointError::MultiSig)
    }

    /// Verify a legacy checkpoint and re-sign its equivalent state under v2.
    /// The predecessor remains explicitly tagged `legacy_v1`; this operation is
    /// an auditable artifact migration, not an implicit chain rewrite.
    pub fn migrate_verified_legacy(
        legacy: &PolicyCheckpoint,
        zone: &str,
        legacy_quorum_threshold: usize,
        legacy_authorized_signers: &[VerificationKey],
        new_signing_keys: &[SigningKey],
    ) -> Result<Self, VersionedCheckpointError> {
        let provenance = LegacyPolicyCheckpointProvenance::new(
            legacy.clone(),
            zone,
            legacy_quorum_threshold,
            legacy_authorized_signers.to_vec(),
        )?;
        build_checkpoint_v2(
            legacy
                .prev_checkpoint
                .clone()
                .map(PersistedEngineObjectId::legacy),
            legacy.checkpoint_seq,
            legacy.epoch_id,
            legacy.policy_heads.clone(),
            legacy.created_at,
            zone.to_string(),
            Some(provenance),
            new_signing_keys,
        )
    }
}

impl SignaturePreimage for PolicyCheckpointV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CheckpointArtifact
    }

    fn signature_schema(&self) -> &SchemaHash {
        checkpoint_signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        build_unsigned_view_v2(
            &self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            &self.policy_heads,
            self.created_at,
            &self.zone,
            self.legacy_provenance.as_ref(),
        )
    }
}

pub struct PolicyCheckpointV2Builder {
    prev_checkpoint: Option<PersistedEngineObjectId>,
    prev_seq: Option<u64>,
    prev_epoch: Option<SecurityEpoch>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: Vec<PolicyHead>,
    created_at: DeterministicTimestamp,
    zone: String,
}

impl PolicyCheckpointV2Builder {
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

    pub fn after(
        prev: &PolicyCheckpointV2,
        checkpoint_seq: u64,
        epoch_id: SecurityEpoch,
        created_at: DeterministicTimestamp,
    ) -> Result<Self, VersionedCheckpointError> {
        prev.validate_identity()?;
        Ok(Self {
            prev_checkpoint: Some(prev.checkpoint_id.clone()),
            prev_seq: Some(prev.checkpoint_seq),
            prev_epoch: Some(prev.epoch_id),
            checkpoint_seq,
            epoch_id,
            policy_heads: Vec::new(),
            created_at,
            zone: prev.zone.clone(),
        })
    }

    pub fn add_policy_head(mut self, head: PolicyHead) -> Self {
        self.policy_heads.push(head);
        self
    }

    pub fn build(
        mut self,
        signing_keys: &[SigningKey],
    ) -> Result<PolicyCheckpointV2, VersionedCheckpointError> {
        validate_zone(&self.zone)?;
        validate_builder_predecessor(
            self.prev_seq,
            self.prev_epoch,
            self.checkpoint_seq,
            self.epoch_id,
        )?;
        self.policy_heads
            .sort_by(|left, right| left.policy_type.cmp(&right.policy_type));
        validate_checkpoint_shape(&self.prev_checkpoint, self.checkpoint_seq, &self.policy_heads)?;
        build_checkpoint_v2(
            self.prev_checkpoint,
            self.checkpoint_seq,
            self.epoch_id,
            self.policy_heads,
            self.created_at,
            self.zone,
            None,
            signing_keys,
        )
    }
}

pub fn verify_chain_linkage_v2(
    prev: &PolicyCheckpointV2,
    current: &PolicyCheckpointV2,
) -> Result<(), VersionedCheckpointError> {
    prev.validate_identity()?;
    current.validate_identity()?;
    if prev.zone != current.zone {
        return Err(VersionedCheckpointError::ZoneMismatch {
            previous: prev.zone.clone(),
            current: current.zone.clone(),
        });
    }
    let Some(actual_prev) = &current.prev_checkpoint else {
        return Err(VersionedCheckpointError::MissingPredecessor);
    };
    if actual_prev != &prev.checkpoint_id {
        return Err(VersionedCheckpointError::ChainLinkageBroken);
    }
    if current.checkpoint_seq <= prev.checkpoint_seq {
        return Err(VersionedCheckpointError::NonMonotonicSequence {
            previous: prev.checkpoint_seq,
            current: current.checkpoint_seq,
        });
    }
    if current.epoch_id < prev.epoch_id {
        return Err(VersionedCheckpointError::EpochRegression {
            previous: prev.epoch_id,
            current: current.epoch_id,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_checkpoint_v2(
    prev_checkpoint: Option<PersistedEngineObjectId>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: Vec<PolicyHead>,
    created_at: DeterministicTimestamp,
    zone: String,
    legacy_provenance: Option<LegacyPolicyCheckpointProvenance>,
    signing_keys: &[SigningKey],
) -> Result<PolicyCheckpointV2, VersionedCheckpointError> {
    validate_zone(&zone)?;
    validate_checkpoint_shape(&prev_checkpoint, checkpoint_seq, &policy_heads)?;
    if signing_keys.is_empty() {
        return Err(VersionedCheckpointError::EmptySigningKeys);
    }
    if let Some(provenance) = &legacy_provenance {
        provenance.verify()?;
    }

    let schema = derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        CHECKPOINT_SCHEMA_V2,
    )?;
    let unsigned = build_unsigned_view_v2(
        &prev_checkpoint,
        checkpoint_seq,
        epoch_id,
        &policy_heads,
        created_at,
        &zone,
        legacy_provenance.as_ref(),
    );
    let canonical_bytes = deterministic_serde::encode_value(&unsigned);
    let checkpoint_id = derive_versioned_id(
        ObjectDomain::CheckpointArtifact,
        &zone,
        &schema,
        &canonical_bytes,
    )?;

    let preimage = signature_preimage_v2(&unsigned);
    let mut signatures = Vec::with_capacity(signing_keys.len());
    for signing_key in signing_keys {
        let signature = sign_preimage(signing_key, &preimage)
            .map_err(|error| VersionedCheckpointError::Signing(error.to_string()))?;
        signatures.push(SignerSignature::new(
            signing_key.verification_key(),
            signature,
        ));
    }
    let quorum_signatures =
        SortedSignatureArray::from_unsorted(signatures).map_err(VersionedCheckpointError::MultiSig)?;

    let checkpoint = PolicyCheckpointV2 {
        persistence_schema: POLICY_CHECKPOINT_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        checkpoint_id: PersistedEngineObjectId::from_versioned(checkpoint_id),
        prev_checkpoint,
        checkpoint_seq,
        epoch_id,
        policy_heads,
        quorum_signatures,
        created_at,
        zone,
        legacy_provenance,
    };
    checkpoint.validate_identity()?;
    Ok(checkpoint)
}

fn checkpoint_signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(CHECKPOINT_SCHEMA_V2));
    &HASH
}

fn signature_preimage_v2(unsigned: &CanonicalValue) -> Vec<u8> {
    let schema = checkpoint_signature_schema_v2();
    let domain = ObjectDomain::CheckpointArtifact.tag();
    let value_bytes = deterministic_serde::encode_value(unsigned);
    let mut preimage = Vec::with_capacity(domain.len() + 32 + value_bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(schema.as_bytes());
    preimage.extend_from_slice(&value_bytes);
    preimage
}

fn build_unsigned_view_v2(
    prev_checkpoint: &Option<PersistedEngineObjectId>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
    policy_heads: &[PolicyHead],
    created_at: DeterministicTimestamp,
    zone: &str,
    legacy_provenance: Option<&LegacyPolicyCheckpointProvenance>,
) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(POLICY_CHECKPOINT_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    map.insert(
        "checkpoint_seq".to_string(),
        CanonicalValue::U64(checkpoint_seq),
    );
    map.insert("created_at".to_string(), CanonicalValue::U64(created_at.0));
    map.insert(
        "epoch_id".to_string(),
        CanonicalValue::U64(epoch_id.as_u64()),
    );
    map.insert("zone".to_string(), CanonicalValue::String(zone.to_string()));
    map.insert(
        "legacy_provenance_hash".to_string(),
        CanonicalValue::Bytes(optional_legacy_hash(legacy_provenance)),
    );

    let heads = policy_heads
        .iter()
        .map(|head| {
            let mut head_map = BTreeMap::new();
            head_map.insert(
                "policy_hash".to_string(),
                CanonicalValue::Bytes(head.policy_hash.as_bytes().to_vec()),
            );
            head_map.insert(
                "policy_type".to_string(),
                CanonicalValue::String(head.policy_type.to_string()),
            );
            head_map.insert(
                "policy_version".to_string(),
                CanonicalValue::U64(head.policy_version),
            );
            CanonicalValue::Map(head_map)
        })
        .collect();
    map.insert("policy_heads".to_string(), CanonicalValue::Array(heads));

    match prev_checkpoint {
        Some(previous) => {
            map.insert(
                "prev_checkpoint_derivation_version".to_string(),
                CanonicalValue::String(previous.derivation_version.as_str().to_string()),
            );
            map.insert(
                "prev_checkpoint".to_string(),
                CanonicalValue::Bytes(previous.as_bytes().to_vec()),
            );
        }
        None => {
            map.insert(
                "prev_checkpoint_derivation_version".to_string(),
                CanonicalValue::Null,
            );
            map.insert("prev_checkpoint".to_string(), CanonicalValue::Null);
        }
    }
    map.insert(
        "quorum_signatures".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

fn optional_legacy_hash(provenance: Option<&LegacyPolicyCheckpointProvenance>) -> Vec<u8> {
    provenance
        .map(LegacyPolicyCheckpointProvenance::content_hash)
        .map(|hash| hash.as_bytes().to_vec())
        .unwrap_or_default()
}

fn validate_legacy_mapping(checkpoint: &PolicyCheckpointV2) -> Result<(), VersionedCheckpointError> {
    let Some(provenance) = &checkpoint.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.checkpoint;
    if checkpoint.zone != provenance.zone {
        return Err(VersionedCheckpointError::LegacyMappingMismatch("zone"));
    }
    if checkpoint.checkpoint_seq != legacy.checkpoint_seq {
        return Err(VersionedCheckpointError::LegacyMappingMismatch(
            "checkpoint_seq",
        ));
    }
    if checkpoint.epoch_id != legacy.epoch_id {
        return Err(VersionedCheckpointError::LegacyMappingMismatch("epoch_id"));
    }
    if checkpoint.policy_heads != legacy.policy_heads {
        return Err(VersionedCheckpointError::LegacyMappingMismatch(
            "policy_heads",
        ));
    }
    if checkpoint.created_at != legacy.created_at {
        return Err(VersionedCheckpointError::LegacyMappingMismatch("created_at"));
    }
    let expected_prev = legacy
        .prev_checkpoint
        .clone()
        .map(PersistedEngineObjectId::legacy);
    if checkpoint.prev_checkpoint != expected_prev {
        return Err(VersionedCheckpointError::LegacyMappingMismatch(
            "prev_checkpoint",
        ));
    }
    Ok(())
}

fn validate_zone(zone: &str) -> Result<(), VersionedCheckpointError> {
    if zone.trim().is_empty() {
        return Err(VersionedCheckpointError::InvalidZone);
    }
    Ok(())
}

fn validate_quorum_parameters(
    quorum_threshold: usize,
    authorized_signers: &[VerificationKey],
) -> Result<(), VersionedCheckpointError> {
    if quorum_threshold == 0 || quorum_threshold > authorized_signers.len() {
        return Err(VersionedCheckpointError::InvalidQuorumThreshold);
    }
    let unique = authorized_signers.iter().collect::<BTreeSet<_>>();
    if unique.len() != authorized_signers.len() {
        return Err(VersionedCheckpointError::DuplicateAuthorizedSigner);
    }
    Ok(())
}

fn is_strictly_sorted(values: &[VerificationKey]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_builder_predecessor(
    prev_seq: Option<u64>,
    prev_epoch: Option<SecurityEpoch>,
    checkpoint_seq: u64,
    epoch_id: SecurityEpoch,
) -> Result<(), VersionedCheckpointError> {
    if let Some(previous) = prev_seq
        && checkpoint_seq <= previous
    {
        return Err(VersionedCheckpointError::NonMonotonicSequence {
            previous,
            current: checkpoint_seq,
        });
    }
    if let Some(previous) = prev_epoch
        && epoch_id < previous
    {
        return Err(VersionedCheckpointError::EpochRegression {
            previous,
            current: epoch_id,
        });
    }
    Ok(())
}

fn validate_checkpoint_shape(
    prev_checkpoint: &Option<PersistedEngineObjectId>,
    checkpoint_seq: u64,
    policy_heads: &[PolicyHead],
) -> Result<(), VersionedCheckpointError> {
    if prev_checkpoint.is_none() && checkpoint_seq != 0 {
        return Err(VersionedCheckpointError::GenesisSequenceNotZero {
            actual: checkpoint_seq,
        });
    }
    if prev_checkpoint.is_some() && checkpoint_seq == 0 {
        return Err(VersionedCheckpointError::NonGenesisSequenceZero);
    }
    if policy_heads.is_empty() {
        return Err(VersionedCheckpointError::EmptyPolicyHeads);
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<&PolicyType> = None;
    for head in policy_heads {
        if !seen.insert(head.policy_type.clone()) {
            return Err(VersionedCheckpointError::DuplicatePolicyType(
                head.policy_type.clone(),
            ));
        }
        if previous.is_some_and(|value| value > &head.policy_type) {
            return Err(VersionedCheckpointError::PolicyHeadsNotCanonical);
        }
        previous = Some(&head.policy_type);
    }
    Ok(())
}

fn require_v2_schema(schema: &PersistedSchemaId) -> Result<(), VersionedCheckpointError> {
    if schema.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedCheckpointError::AlgorithmMismatch {
            field: "schema_version",
            actual: schema.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        CHECKPOINT_SCHEMA_V2,
    )?);
    if schema != &expected {
        return Err(VersionedCheckpointError::SchemaMismatch);
    }
    Ok(())
}

fn require_v2_object(
    field: &'static str,
    object_id: &PersistedEngineObjectId,
) -> Result<(), VersionedCheckpointError> {
    if object_id.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedCheckpointError::AlgorithmMismatch {
            field,
            actual: object_id.derivation_version,
        });
    }
    Ok(())
}

fn append_u64_len(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedCheckpointError {
    InvalidZone,
    EmptySigningKeys,
    EmptyPolicyHeads,
    InvalidQuorumThreshold,
    DuplicateAuthorizedSigner,
    AuthorizedSignersNotCanonical,
    PolicyHeadsNotCanonical,
    DuplicatePolicyType(PolicyType),
    GenesisSequenceNotZero {
        actual: u64,
    },
    NonGenesisSequenceZero,
    MissingPredecessor,
    NonMonotonicSequence {
        previous: u64,
        current: u64,
    },
    EpochRegression {
        previous: SecurityEpoch,
        current: SecurityEpoch,
    },
    ZoneMismatch {
        previous: String,
        current: String,
    },
    ChainLinkageBroken,
    UnsupportedSchema {
        actual: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch,
    LegacyMappingMismatch(&'static str),
    LegacyVerification(String),
    Signing(String),
    MultiSig(MultiSigError),
    Identity(VersionedIdError),
}

impl std::fmt::Display for VersionedCheckpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidZone => formatter.write_str("checkpoint zone must not be empty"),
            Self::EmptySigningKeys => formatter.write_str("at least one checkpoint signer is required"),
            Self::EmptyPolicyHeads => formatter.write_str("policy heads must not be empty"),
            Self::InvalidQuorumThreshold => formatter.write_str("invalid quorum threshold"),
            Self::DuplicateAuthorizedSigner => formatter.write_str("authorized signer set contains duplicates"),
            Self::AuthorizedSignersNotCanonical => {
                formatter.write_str("persisted authorized signers must be strictly sorted")
            }
            Self::PolicyHeadsNotCanonical => {
                formatter.write_str("policy heads must be sorted by policy type")
            }
            Self::DuplicatePolicyType(policy_type) => {
                write!(formatter, "duplicate policy type: {policy_type}")
            }
            Self::GenesisSequenceNotZero { actual } => {
                write!(formatter, "genesis sequence must be 0, got {actual}")
            }
            Self::NonGenesisSequenceZero => {
                formatter.write_str("non-genesis checkpoint sequence must be nonzero")
            }
            Self::MissingPredecessor => formatter.write_str("checkpoint has no predecessor"),
            Self::NonMonotonicSequence { previous, current } => {
                write!(formatter, "non-monotonic sequence: {previous} -> {current}")
            }
            Self::EpochRegression { previous, current } => {
                write!(formatter, "epoch regression: {previous} -> {current}")
            }
            Self::ZoneMismatch { previous, current } => {
                write!(formatter, "checkpoint zone changed from {previous:?} to {current:?}")
            }
            Self::ChainLinkageBroken => formatter.write_str("checkpoint predecessor identity mismatch"),
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported checkpoint persistence schema {actual:?}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch => formatter.write_str("checkpoint schema id does not match v2"),
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy checkpoint migration mismatch at {field}")
            }
            Self::LegacyVerification(detail) | Self::Signing(detail) => formatter.write_str(detail),
            Self::MultiSig(error) => write!(formatter, "multi-signature error: {error}"),
            Self::Identity(error) => write!(formatter, "checkpoint identity error: {error}"),
        }
    }
}

impl std::error::Error for VersionedCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MultiSig(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for VersionedCheckpointError {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid test key")
    }

    fn head(policy_type: PolicyType, version: u64) -> PolicyHead {
        PolicyHead {
            policy_type,
            policy_hash: ContentHash::compute(format!("policy-{version}").as_bytes()),
            policy_version: version,
        }
    }

    fn genesis(signing_keys: &[SigningKey]) -> PolicyCheckpointV2 {
        PolicyCheckpointV2Builder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(10),
            "owner",
        )
        .add_policy_head(head(PolicyType::RuntimeExecution, 1))
        .build(signing_keys)
        .expect("v2 genesis")
    }

    #[test]
    fn fresh_v2_checkpoint_is_self_describing_and_quorum_verifies() {
        let signing_key = key(1);
        let checkpoint = genesis(std::slice::from_ref(&signing_key));
        assert_eq!(
            checkpoint.checkpoint_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );
        checkpoint
            .verify_quorum(1, &[signing_key.verification_key()])
            .expect("verify quorum");
        let value = serde_json::to_value(&checkpoint).expect("serialize checkpoint");
        assert_eq!(value["persistence_schema"], POLICY_CHECKPOINT_PERSISTENCE_SCHEMA_V2);
        assert_eq!(value["checkpoint_id"]["derivation_version"], "sha256_v2");
        assert_eq!(value["zone"], "owner");
    }

    #[test]
    fn successor_links_exact_v2_identity_and_zone() {
        let signing_key = key(2);
        let first = genesis(std::slice::from_ref(&signing_key));
        let second = PolicyCheckpointV2Builder::after(
            &first,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(20),
        )
        .expect("valid predecessor")
        .add_policy_head(head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&signing_key))
        .expect("successor");
        verify_chain_linkage_v2(&first, &second).expect("chain linkage");
        assert_eq!(second.prev_checkpoint, Some(first.checkpoint_id.clone()));
    }

    #[test]
    fn predecessor_algorithm_tag_is_part_of_chain_identity() {
        let signing_key = key(3);
        let first = genesis(std::slice::from_ref(&signing_key));
        let mut second = PolicyCheckpointV2Builder::after(
            &first,
            1,
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(20),
        )
        .expect("valid predecessor")
        .add_policy_head(head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&signing_key))
        .expect("successor");
        second
            .prev_checkpoint
            .as_mut()
            .expect("predecessor")
            .derivation_version = ObjectIdDerivationVersion::LegacyV1;
        assert!(second.validate_identity().is_err());
        assert!(verify_chain_linkage_v2(&first, &second).is_err());
    }

    #[test]
    fn verified_legacy_checkpoint_migrates_with_zone_and_quorum_provenance() {
        let legacy_key = key(4);
        let legacy = super::super::compat::CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(30),
            "team",
        )
        .add_policy_head(head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&legacy_key))
        .expect("legacy checkpoint");
        let new_key = key(5);
        let migrated = PolicyCheckpointV2::migrate_verified_legacy(
            &legacy,
            "team",
            1,
            &[legacy_key.verification_key()],
            std::slice::from_ref(&new_key),
        )
        .expect("migrate checkpoint");
        assert!(migrated.legacy_provenance.is_some());
        assert_eq!(migrated.zone, "team");
        migrated
            .verify_quorum(1, &[new_key.verification_key()])
            .expect("new quorum");
    }

    #[test]
    fn wrong_legacy_zone_cannot_be_migrated() {
        let legacy_key = key(6);
        let legacy = super::super::compat::CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(30),
            "private",
        )
        .add_policy_head(head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&legacy_key))
        .expect("legacy checkpoint");
        let new_key = key(7);
        assert!(matches!(
            PolicyCheckpointV2::migrate_verified_legacy(
                &legacy,
                "wrong-zone",
                1,
                &[legacy_key.verification_key()],
                std::slice::from_ref(&new_key),
            ),
            Err(VersionedCheckpointError::LegacyVerification(_))
        ));
    }

    #[test]
    fn migrated_state_cannot_diverge_from_provenance() {
        let legacy_key = key(8);
        let legacy = super::super::compat::CheckpointBuilder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(30),
            "community",
        )
        .add_policy_head(head(PolicyType::RuntimeExecution, 1))
        .build(std::slice::from_ref(&legacy_key))
        .expect("legacy checkpoint");
        let new_key = key(9);
        let mut migrated = PolicyCheckpointV2::migrate_verified_legacy(
            &legacy,
            "community",
            1,
            &[legacy_key.verification_key()],
            std::slice::from_ref(&new_key),
        )
        .expect("migrate checkpoint");
        migrated.created_at = DeterministicTimestamp(31);
        assert!(matches!(
            migrated.validate_identity(),
            Err(VersionedCheckpointError::LegacyMappingMismatch("created_at"))
        ));
    }

    #[test]
    fn duplicate_policy_types_are_rejected_before_signing() {
        let signing_key = key(10);
        let result = PolicyCheckpointV2Builder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(10),
            "owner",
        )
        .add_policy_head(head(PolicyType::RuntimeExecution, 1))
        .add_policy_head(head(PolicyType::RuntimeExecution, 2))
        .build(std::slice::from_ref(&signing_key));
        assert!(matches!(
            result,
            Err(VersionedCheckpointError::DuplicatePolicyType(
                PolicyType::RuntimeExecution
            ))
        ));
    }

    #[test]
    fn caller_signer_order_does_not_change_quorum_semantics() {
        let first_key = key(11);
        let second_key = key(12);
        let checkpoint = genesis(&[first_key.clone(), second_key.clone()]);
        checkpoint
            .verify_quorum(
                2,
                &[second_key.verification_key(), first_key.verification_key()],
            )
            .expect("unordered verifier set is still a set");
    }
}
