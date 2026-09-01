use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, EngineObjectId,
    ObjectDomain, ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId,
    VersionedIdError,
};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::security_epoch::{EpochMetadata, EpochTracker, EpochValidationError, SecurityEpoch};
use crate::signature_preimage::{
    sign_preimage, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

use super::compat::{CapabilityToken, CheckpointRef, PrincipalId, RevocationFreshnessRef, TokenVersion};

const TOKEN_SCHEMA_V2: &[u8] = b"FrankenEngine.CapabilityToken.sha256.v2";

pub const CAPABILITY_TOKEN_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.capability-token.persistence.v2";

/// Content-addressed token identifier with an explicit derivation algorithm.
pub type VersionedTokenId = PersistedEngineObjectId;

/// Checkpoint frontier binding whose identity cannot be confused across ID algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedCheckpointRef {
    pub min_checkpoint_seq: u64,
    pub checkpoint_id: PersistedEngineObjectId,
}

impl VersionedCheckpointRef {
    pub fn new(min_checkpoint_seq: u64, checkpoint_id: PersistedEngineObjectId) -> Self {
        Self {
            min_checkpoint_seq,
            checkpoint_id,
        }
    }

    pub fn legacy(binding: &CheckpointRef) -> Self {
        Self {
            min_checkpoint_seq: binding.min_checkpoint_seq,
            checkpoint_id: PersistedEngineObjectId::legacy(binding.checkpoint_id.clone()),
        }
    }
}

/// Cryptographically verified legacy token retained as migration provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyCapabilityTokenProvenance {
    pub token: CapabilityToken,
}

impl LegacyCapabilityTokenProvenance {
    pub fn verify(&self) -> Result<(), VersionedTokenError> {
        verify_legacy_token_identity(&self.token)?;
        verify_signature(
            &self.token.issuer,
            &self.token.preimage_bytes(),
            &self.token.signature,
        )
        .map_err(|error| VersionedTokenError::LegacyVerification(error.to_string()))
    }

    pub fn content_hash(&self) -> Result<ContentHash, VersionedTokenError> {
        self.verify()?;
        let mut bytes = self.token.preimage_bytes();
        bytes.extend_from_slice(&self.token.signature.to_bytes());
        bytes.extend_from_slice(self.token.jti.as_bytes());
        Ok(ContentHash::compute(&bytes))
    }
}

/// Self-describing capability token for new persisted authority assertions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedCapabilityToken {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub version: TokenVersion,
    pub jti: VersionedTokenId,
    pub issuer: VerificationKey,
    pub audience: BTreeSet<PrincipalId>,
    pub capabilities: BTreeSet<RuntimeCapability>,
    pub nbf: DeterministicTimestamp,
    pub expiry: DeterministicTimestamp,
    pub epoch: SecurityEpoch,
    pub valid_from_epoch: SecurityEpoch,
    pub valid_until_epoch: Option<SecurityEpoch>,
    pub checkpoint_binding: Option<VersionedCheckpointRef>,
    pub revocation_freshness: Option<RevocationFreshnessRef>,
    pub signature: Signature,
    pub zone: String,
    pub legacy_provenance: Option<LegacyCapabilityTokenProvenance>,
}

impl VersionedCapabilityToken {
    pub fn epoch_metadata(&self) -> EpochMetadata {
        EpochMetadata {
            epoch_id: self.epoch,
            valid_from_epoch: self.valid_from_epoch,
            valid_until_epoch: self.valid_until_epoch,
        }
    }

    /// Recompute and verify the content-derived JTI and every migration binding.
    pub fn validate_identity(&self) -> Result<(), VersionedTokenError> {
        validate_token_fields(
            &self.audience,
            &self.capabilities,
            self.nbf,
            self.expiry,
            self.valid_from_epoch,
            self.valid_until_epoch,
            &self.zone,
        )?;
        if self.persistence_schema != CAPABILITY_TOKEN_PERSISTENCE_SCHEMA_V2 {
            return Err(VersionedTokenError::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        if self.version != TokenVersion::V2 {
            return Err(VersionedTokenError::UnsupportedTokenVersion {
                version: self.version.to_string(),
            });
        }
        require_v2_schema(&self.schema_version)?;
        require_v2_object("jti", &self.jti)?;
        validate_legacy_mapping(self)?;

        let material = identity_material(
            self.version,
            &self.issuer,
            &self.audience,
            &self.capabilities,
            self.nbf,
            self.expiry,
            self.epoch,
            self.valid_from_epoch,
            self.valid_until_epoch,
            self.checkpoint_binding.as_ref(),
            self.revocation_freshness.as_ref(),
            &self.zone,
            self.legacy_provenance.as_ref(),
        );
        verify_versioned_id(
            &self.jti.to_versioned(),
            ObjectDomain::CapabilityToken,
            &self.zone,
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), VersionedTokenError> {
        self.validate_identity()?;
        verify_signature(&self.issuer, &self.preimage_bytes(), &self.signature)
            .map_err(|error| VersionedTokenError::SignatureInvalid(error.to_string()))
    }

    /// Verify a legacy token's signature and historical JTI before re-signing
    /// the same authority semantics with the same issuer key under SHA-256-v2.
    pub fn migrate_verified_legacy(
        legacy: &CapabilityToken,
        issuer_key: &SigningKey,
    ) -> Result<Self, VersionedTokenError> {
        let provenance = LegacyCapabilityTokenProvenance {
            token: legacy.clone(),
        };
        provenance.verify()?;
        if issuer_key.verification_key() != legacy.issuer {
            return Err(VersionedTokenError::IssuerKeyMismatch);
        }
        build_versioned_token(
            issuer_key,
            legacy.audience.clone(),
            legacy.capabilities.clone(),
            legacy.nbf,
            legacy.expiry,
            legacy.epoch,
            legacy.valid_from_epoch,
            legacy.valid_until_epoch,
            legacy
                .checkpoint_binding
                .as_ref()
                .map(VersionedCheckpointRef::legacy),
            legacy.revocation_freshness.clone(),
            legacy.zone.clone(),
            Some(provenance),
        )
    }
}

impl SignaturePreimage for VersionedCapabilityToken {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CapabilityToken
    }

    fn signature_schema(&self) -> &SchemaHash {
        signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        signed_view(self)
    }
}

pub struct VersionedTokenBuilder {
    issuer_key: SigningKey,
    audience: BTreeSet<PrincipalId>,
    capabilities: BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    epoch: SecurityEpoch,
    valid_from_epoch: SecurityEpoch,
    valid_until_epoch: Option<SecurityEpoch>,
    checkpoint_binding: Option<VersionedCheckpointRef>,
    revocation_freshness: Option<RevocationFreshnessRef>,
    zone: String,
}

impl VersionedTokenBuilder {
    pub fn new(
        issuer_key: SigningKey,
        nbf: DeterministicTimestamp,
        expiry: DeterministicTimestamp,
        epoch: SecurityEpoch,
        zone: &str,
    ) -> Self {
        Self {
            issuer_key,
            audience: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            nbf,
            expiry,
            epoch,
            valid_from_epoch: epoch,
            valid_until_epoch: None,
            checkpoint_binding: None,
            revocation_freshness: None,
            zone: zone.to_string(),
        }
    }

    pub fn add_audience(mut self, principal: PrincipalId) -> Self {
        self.audience.insert(principal);
        self
    }

    pub fn add_capability(mut self, capability: RuntimeCapability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    pub fn add_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = RuntimeCapability>,
    ) -> Self {
        self.capabilities.extend(capabilities);
        self
    }

    pub fn bind_checkpoint(mut self, binding: VersionedCheckpointRef) -> Self {
        self.checkpoint_binding = Some(binding);
        self
    }

    pub fn bind_revocation_freshness(mut self, binding: RevocationFreshnessRef) -> Self {
        self.revocation_freshness = Some(binding);
        self
    }

    pub fn valid_from_epoch(mut self, epoch: SecurityEpoch) -> Self {
        self.valid_from_epoch = epoch;
        self
    }

    pub fn valid_until_epoch(mut self, epoch: SecurityEpoch) -> Self {
        self.valid_until_epoch = Some(epoch);
        self
    }

    pub fn valid_epoch_window(
        mut self,
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    ) -> Self {
        self.valid_from_epoch = valid_from;
        self.valid_until_epoch = Some(valid_until);
        self
    }

    pub fn build(self) -> Result<VersionedCapabilityToken, VersionedTokenError> {
        build_versioned_token(
            &self.issuer_key,
            self.audience,
            self.capabilities,
            self.nbf,
            self.expiry,
            self.epoch,
            self.valid_from_epoch,
            self.valid_until_epoch,
            self.checkpoint_binding,
            self.revocation_freshness,
            self.zone,
            None,
        )
    }
}

/// Verification context with algorithm-tagged accepted checkpoint identities.
#[derive(Debug, Clone)]
pub struct VersionedVerificationContext {
    pub current_tick: u64,
    pub verifier_checkpoint_seq: u64,
    pub verifier_revocation_seq: u64,
    pub epoch_tracker: EpochTracker,
    pub accepted_checkpoint_ids: BTreeSet<PersistedEngineObjectId>,
    pub accepted_revocation_head_hashes: BTreeSet<ContentHash>,
}

impl VersionedVerificationContext {
    pub fn new(
        current_tick: u64,
        verifier_checkpoint_seq: u64,
        verifier_revocation_seq: u64,
    ) -> Self {
        Self {
            current_tick,
            verifier_checkpoint_seq,
            verifier_revocation_seq,
            epoch_tracker: EpochTracker::new(),
            accepted_checkpoint_ids: BTreeSet::new(),
            accepted_revocation_head_hashes: BTreeSet::new(),
        }
    }

    pub fn with_current_epoch(mut self, current_epoch: SecurityEpoch) -> Self {
        self.epoch_tracker = EpochTracker::from_persisted(current_epoch);
        self
    }

    pub fn with_epoch_tracker(mut self, epoch_tracker: EpochTracker) -> Self {
        self.epoch_tracker = epoch_tracker;
        self
    }

    pub fn with_checkpoint_id(mut self, checkpoint_id: PersistedEngineObjectId) -> Self {
        self.accepted_checkpoint_ids.insert(checkpoint_id);
        self
    }

    pub fn with_checkpoint_ref(self, checkpoint_ref: &VersionedCheckpointRef) -> Self {
        self.with_checkpoint_id(checkpoint_ref.checkpoint_id.clone())
    }

    pub fn with_legacy_checkpoint_id(self, checkpoint_id: EngineObjectId) -> Self {
        self.with_checkpoint_id(PersistedEngineObjectId::legacy(checkpoint_id))
    }

    pub fn with_revocation_head_hash(mut self, hash: ContentHash) -> Self {
        self.accepted_revocation_head_hashes.insert(hash);
        self
    }

    pub fn with_revocation_freshness(self, freshness: &RevocationFreshnessRef) -> Self {
        self.with_revocation_head_hash(freshness.revocation_head_hash)
    }
}

pub fn verify_versioned_token(
    token: &VersionedCapabilityToken,
    presenter: &PrincipalId,
    context: &VersionedVerificationContext,
) -> Result<(), VersionedTokenError> {
    token.verify_signature()?;

    if !token.audience.contains(presenter) {
        return Err(VersionedTokenError::AudienceRejected {
            presenter: presenter.clone(),
            audience_size: token.audience.len(),
        });
    }
    if context.current_tick < token.nbf.0 {
        return Err(VersionedTokenError::NotYetValid {
            current_tick: context.current_tick,
            not_before: token.nbf.0,
        });
    }
    if context.current_tick > token.expiry.0 {
        return Err(VersionedTokenError::Expired {
            current_tick: context.current_tick,
            expiry: token.expiry.0,
        });
    }
    if let Err(errors) = context.epoch_tracker.validate_artifact(&token.epoch_metadata()) {
        return Err(VersionedTokenError::EpochValidationFailed { errors });
    }

    if let Some(binding) = &token.checkpoint_binding {
        if context.verifier_checkpoint_seq < binding.min_checkpoint_seq {
            return Err(VersionedTokenError::CheckpointBindingFailed {
                required_seq: binding.min_checkpoint_seq,
                verifier_seq: context.verifier_checkpoint_seq,
            });
        }
        if !context.accepted_checkpoint_ids.contains(&binding.checkpoint_id) {
            return Err(VersionedTokenError::CheckpointIdentityMismatch {
                checkpoint_id: binding.checkpoint_id.clone(),
            });
        }
    }

    if let Some(freshness) = &token.revocation_freshness {
        if context.verifier_revocation_seq < freshness.min_revocation_seq {
            return Err(VersionedTokenError::RevocationFreshnessStale {
                required_seq: freshness.min_revocation_seq,
                verifier_seq: context.verifier_revocation_seq,
            });
        }
        if !context
            .accepted_revocation_head_hashes
            .contains(&freshness.revocation_head_hash)
        {
            return Err(VersionedTokenError::RevocationHeadMismatch {
                revocation_head_hash: freshness.revocation_head_hash,
            });
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionedTokenEventType {
    TokenIssued { jti: VersionedTokenId },
    TokenVerified { jti: VersionedTokenId },
    TokenRejected { jti: VersionedTokenId, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedTokenEvent {
    pub event_type: VersionedTokenEventType,
    pub trace_id: String,
}

fn build_versioned_token(
    issuer_key: &SigningKey,
    audience: BTreeSet<PrincipalId>,
    capabilities: BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    epoch: SecurityEpoch,
    valid_from_epoch: SecurityEpoch,
    valid_until_epoch: Option<SecurityEpoch>,
    checkpoint_binding: Option<VersionedCheckpointRef>,
    revocation_freshness: Option<RevocationFreshnessRef>,
    zone: String,
    legacy_provenance: Option<LegacyCapabilityTokenProvenance>,
) -> Result<VersionedCapabilityToken, VersionedTokenError> {
    validate_token_fields(
        &audience,
        &capabilities,
        nbf,
        expiry,
        valid_from_epoch,
        valid_until_epoch,
        &zone,
    )?;
    if let Some(provenance) = &legacy_provenance {
        provenance.verify()?;
    }

    let issuer = issuer_key.verification_key();
    let schema = derive_versioned_schema_id(ObjectIdDerivationVersion::Sha256V2, TOKEN_SCHEMA_V2)?;
    let material = identity_material(
        TokenVersion::V2,
        &issuer,
        &audience,
        &capabilities,
        nbf,
        expiry,
        epoch,
        valid_from_epoch,
        valid_until_epoch,
        checkpoint_binding.as_ref(),
        revocation_freshness.as_ref(),
        &zone,
        legacy_provenance.as_ref(),
    );
    let jti = derive_versioned_id(
        ObjectDomain::CapabilityToken,
        &zone,
        &schema,
        &material,
    )?;

    let mut token = VersionedCapabilityToken {
        persistence_schema: CAPABILITY_TOKEN_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        version: TokenVersion::V2,
        jti: PersistedEngineObjectId::from_versioned(jti),
        issuer,
        audience,
        capabilities,
        nbf,
        expiry,
        epoch,
        valid_from_epoch,
        valid_until_epoch,
        checkpoint_binding,
        revocation_freshness,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        zone,
        legacy_provenance,
    };
    token.validate_identity()?;
    token.signature = sign_preimage(issuer_key, &token.preimage_bytes())
        .map_err(|error| VersionedTokenError::SignatureInvalid(error.to_string()))?;
    Ok(token)
}

fn validate_token_fields(
    audience: &BTreeSet<PrincipalId>,
    capabilities: &BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    valid_from_epoch: SecurityEpoch,
    valid_until_epoch: Option<SecurityEpoch>,
    zone: &str,
) -> Result<(), VersionedTokenError> {
    if audience.is_empty() {
        return Err(VersionedTokenError::EmptyAudience);
    }
    if capabilities.is_empty() {
        return Err(VersionedTokenError::EmptyCapabilities);
    }
    if zone.trim().is_empty() {
        return Err(VersionedTokenError::EmptyZone);
    }
    if nbf.0 > expiry.0 {
        return Err(VersionedTokenError::InvertedTemporalWindow {
            not_before: nbf.0,
            expiry: expiry.0,
        });
    }
    if let Some(valid_until) = valid_until_epoch
        && valid_from_epoch > valid_until
    {
        return Err(VersionedTokenError::InvertedEpochWindow {
            valid_from: valid_from_epoch,
            valid_until,
        });
    }
    Ok(())
}

fn validate_legacy_mapping(token: &VersionedCapabilityToken) -> Result<(), VersionedTokenError> {
    let Some(provenance) = &token.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.token;
    if token.version != legacy.version {
        return Err(VersionedTokenError::LegacyMappingMismatch("version"));
    }
    if token.issuer != legacy.issuer {
        return Err(VersionedTokenError::LegacyMappingMismatch("issuer"));
    }
    if token.audience != legacy.audience {
        return Err(VersionedTokenError::LegacyMappingMismatch("audience"));
    }
    if token.capabilities != legacy.capabilities {
        return Err(VersionedTokenError::LegacyMappingMismatch("capabilities"));
    }
    if token.nbf != legacy.nbf {
        return Err(VersionedTokenError::LegacyMappingMismatch("nbf"));
    }
    if token.expiry != legacy.expiry {
        return Err(VersionedTokenError::LegacyMappingMismatch("expiry"));
    }
    if token.epoch != legacy.epoch {
        return Err(VersionedTokenError::LegacyMappingMismatch("epoch"));
    }
    if token.valid_from_epoch != legacy.valid_from_epoch {
        return Err(VersionedTokenError::LegacyMappingMismatch("valid_from_epoch"));
    }
    if token.valid_until_epoch != legacy.valid_until_epoch {
        return Err(VersionedTokenError::LegacyMappingMismatch("valid_until_epoch"));
    }
    let expected_checkpoint = legacy
        .checkpoint_binding
        .as_ref()
        .map(VersionedCheckpointRef::legacy);
    if token.checkpoint_binding != expected_checkpoint {
        return Err(VersionedTokenError::LegacyMappingMismatch(
            "checkpoint_binding",
        ));
    }
    if token.revocation_freshness != legacy.revocation_freshness {
        return Err(VersionedTokenError::LegacyMappingMismatch(
            "revocation_freshness",
        ));
    }
    if token.zone != legacy.zone {
        return Err(VersionedTokenError::LegacyMappingMismatch("zone"));
    }
    Ok(())
}

fn signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(TOKEN_SCHEMA_V2));
    &HASH
}

fn signed_view(token: &VersionedCapabilityToken) -> CanonicalValue {
    let mut map = identity_map(
        token.version,
        &token.issuer,
        &token.audience,
        &token.capabilities,
        token.nbf,
        token.expiry,
        token.epoch,
        token.valid_from_epoch,
        token.valid_until_epoch,
        token.checkpoint_binding.as_ref(),
        token.revocation_freshness.as_ref(),
        &token.zone,
        token.legacy_provenance.as_ref(),
    );
    insert_schema_id(&mut map, "schema_version", &token.schema_version);
    insert_object_id(&mut map, "jti", &token.jti);
    map.insert(
        "signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

#[allow(clippy::too_many_arguments)]
fn identity_material(
    version: TokenVersion,
    issuer: &VerificationKey,
    audience: &BTreeSet<PrincipalId>,
    capabilities: &BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    epoch: SecurityEpoch,
    valid_from_epoch: SecurityEpoch,
    valid_until_epoch: Option<SecurityEpoch>,
    checkpoint_binding: Option<&VersionedCheckpointRef>,
    revocation_freshness: Option<&RevocationFreshnessRef>,
    zone: &str,
    legacy_provenance: Option<&LegacyCapabilityTokenProvenance>,
) -> Vec<u8> {
    deterministic_serde::encode_value(&CanonicalValue::Map(identity_map(
        version,
        issuer,
        audience,
        capabilities,
        nbf,
        expiry,
        epoch,
        valid_from_epoch,
        valid_until_epoch,
        checkpoint_binding,
        revocation_freshness,
        zone,
        legacy_provenance,
    )))
}

#[allow(clippy::too_many_arguments)]
fn identity_map(
    version: TokenVersion,
    issuer: &VerificationKey,
    audience: &BTreeSet<PrincipalId>,
    capabilities: &BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    epoch: SecurityEpoch,
    valid_from_epoch: SecurityEpoch,
    valid_until_epoch: Option<SecurityEpoch>,
    checkpoint_binding: Option<&VersionedCheckpointRef>,
    revocation_freshness: Option<&RevocationFreshnessRef>,
    zone: &str,
    legacy_provenance: Option<&LegacyCapabilityTokenProvenance>,
) -> BTreeMap<String, CanonicalValue> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(CAPABILITY_TOKEN_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    map.insert(
        "version".to_string(),
        CanonicalValue::String(version.to_string()),
    );
    map.insert(
        "issuer".to_string(),
        CanonicalValue::Bytes(issuer.as_bytes().to_vec()),
    );
    map.insert(
        "audience".to_string(),
        CanonicalValue::Array(
            audience
                .iter()
                .map(|principal| CanonicalValue::Bytes(principal.as_bytes().to_vec()))
                .collect(),
        ),
    );
    map.insert(
        "capabilities".to_string(),
        CanonicalValue::Array(
            capabilities
                .iter()
                .map(|capability| CanonicalValue::String(capability.to_string()))
                .collect(),
        ),
    );
    map.insert("nbf".to_string(), CanonicalValue::U64(nbf.0));
    map.insert("expiry".to_string(), CanonicalValue::U64(expiry.0));
    map.insert("epoch".to_string(), CanonicalValue::U64(epoch.as_u64()));
    map.insert(
        "valid_from_epoch".to_string(),
        CanonicalValue::U64(valid_from_epoch.as_u64()),
    );
    map.insert(
        "valid_until_epoch".to_string(),
        valid_until_epoch
            .map(|value| CanonicalValue::U64(value.as_u64()))
            .unwrap_or(CanonicalValue::Null),
    );
    match checkpoint_binding {
        Some(binding) => {
            let mut binding_map = BTreeMap::new();
            binding_map.insert(
                "min_checkpoint_seq".to_string(),
                CanonicalValue::U64(binding.min_checkpoint_seq),
            );
            insert_object_id(&mut binding_map, "checkpoint_id", &binding.checkpoint_id);
            map.insert(
                "checkpoint_binding".to_string(),
                CanonicalValue::Map(binding_map),
            );
        }
        None => {
            map.insert("checkpoint_binding".to_string(), CanonicalValue::Null);
        }
    }
    match revocation_freshness {
        Some(freshness) => {
            let mut freshness_map = BTreeMap::new();
            freshness_map.insert(
                "min_revocation_seq".to_string(),
                CanonicalValue::U64(freshness.min_revocation_seq),
            );
            freshness_map.insert(
                "revocation_head_hash".to_string(),
                CanonicalValue::Bytes(freshness.revocation_head_hash.as_bytes().to_vec()),
            );
            map.insert(
                "revocation_freshness".to_string(),
                CanonicalValue::Map(freshness_map),
            );
        }
        None => {
            map.insert("revocation_freshness".to_string(), CanonicalValue::Null);
        }
    }
    map.insert("zone".to_string(), CanonicalValue::String(zone.to_string()));
    map.insert(
        "legacy_provenance_hash".to_string(),
        CanonicalValue::Bytes(
            legacy_provenance
                .and_then(|provenance| provenance.content_hash().ok())
                .map(|hash| hash.as_bytes().to_vec())
                .unwrap_or_default(),
        ),
    );
    map
}

fn insert_object_id(
    map: &mut BTreeMap<String, CanonicalValue>,
    field: &str,
    value: &PersistedEngineObjectId,
) {
    map.insert(
        format!("{field}_derivation_version"),
        CanonicalValue::String(value.derivation_version.as_str().to_string()),
    );
    map.insert(
        field.to_string(),
        CanonicalValue::Bytes(value.as_bytes().to_vec()),
    );
}

fn insert_schema_id(
    map: &mut BTreeMap<String, CanonicalValue>,
    field: &str,
    value: &PersistedSchemaId,
) {
    map.insert(
        format!("{field}_derivation_version"),
        CanonicalValue::String(value.derivation_version.as_str().to_string()),
    );
    map.insert(
        field.to_string(),
        CanonicalValue::Bytes(value.as_bytes().to_vec()),
    );
}

fn require_v2_schema(schema: &PersistedSchemaId) -> Result<(), VersionedTokenError> {
    if schema.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedTokenError::AlgorithmMismatch {
            field: "schema_version",
            actual: schema.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        TOKEN_SCHEMA_V2,
    )?);
    if schema != &expected {
        return Err(VersionedTokenError::SchemaMismatch);
    }
    Ok(())
}

fn require_v2_object(
    field: &'static str,
    object_id: &PersistedEngineObjectId,
) -> Result<(), VersionedTokenError> {
    if object_id.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(VersionedTokenError::AlgorithmMismatch {
            field,
            actual: object_id.derivation_version,
        });
    }
    Ok(())
}

/// Recompute the historical zero-placeholder JTI convention before accepting a
/// legacy token as migration input. Signature validity alone does not prove the
/// old `jti` was actually content-derived.
fn verify_legacy_token_identity(token: &CapabilityToken) -> Result<(), VersionedTokenError> {
    let mut placeholder = token.clone();
    placeholder.jti = EngineObjectId([0; 32]);
    placeholder.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
    let canonical_bytes = deterministic_serde::encode_value(&legacy_unsigned_view(&placeholder));
    let expected = crate::engine_object_id::derive_id(
        ObjectDomain::CapabilityToken,
        &token.zone,
        &super::compat::token_schema_id(),
        &canonical_bytes,
    )
    .map_err(|error| VersionedTokenError::LegacyVerification(error.to_string()))?;
    if expected != token.jti {
        return Err(VersionedTokenError::LegacyIdentityMismatch);
    }
    Ok(())
}

/// Byte-for-byte reproduction of the legacy token unsigned-view contract.
fn legacy_unsigned_view(token: &CapabilityToken) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "audience".to_string(),
        CanonicalValue::Array(
            token
                .audience
                .iter()
                .map(|principal| CanonicalValue::Bytes(principal.as_bytes().to_vec()))
                .collect(),
        ),
    );
    map.insert(
        "capabilities".to_string(),
        CanonicalValue::Array(
            token
                .capabilities
                .iter()
                .map(|capability| CanonicalValue::String(capability.to_string()))
                .collect(),
        ),
    );
    match &token.checkpoint_binding {
        Some(binding) => {
            let mut binding_map = BTreeMap::new();
            binding_map.insert(
                "checkpoint_id".to_string(),
                CanonicalValue::Bytes(binding.checkpoint_id.as_bytes().to_vec()),
            );
            binding_map.insert(
                "min_checkpoint_seq".to_string(),
                CanonicalValue::U64(binding.min_checkpoint_seq),
            );
            map.insert(
                "checkpoint_binding".to_string(),
                CanonicalValue::Map(binding_map),
            );
        }
        None => {
            map.insert("checkpoint_binding".to_string(), CanonicalValue::Null);
        }
    }
    map.insert("epoch".to_string(), CanonicalValue::U64(token.epoch.as_u64()));
    map.insert(
        "valid_from_epoch".to_string(),
        CanonicalValue::U64(token.valid_from_epoch.as_u64()),
    );
    map.insert(
        "valid_until_epoch".to_string(),
        token
            .valid_until_epoch
            .map(|epoch| CanonicalValue::U64(epoch.as_u64()))
            .unwrap_or(CanonicalValue::Null),
    );
    map.insert("expiry".to_string(), CanonicalValue::U64(token.expiry.0));
    map.insert(
        "issuer".to_string(),
        CanonicalValue::Bytes(token.issuer.as_bytes().to_vec()),
    );
    map.insert(
        "jti".to_string(),
        CanonicalValue::Bytes(token.jti.as_bytes().to_vec()),
    );
    map.insert("nbf".to_string(), CanonicalValue::U64(token.nbf.0));
    match &token.revocation_freshness {
        Some(freshness) => {
            let mut freshness_map = BTreeMap::new();
            freshness_map.insert(
                "min_revocation_seq".to_string(),
                CanonicalValue::U64(freshness.min_revocation_seq),
            );
            freshness_map.insert(
                "revocation_head_hash".to_string(),
                CanonicalValue::Bytes(freshness.revocation_head_hash.as_bytes().to_vec()),
            );
            map.insert(
                "revocation_freshness".to_string(),
                CanonicalValue::Map(freshness_map),
            );
        }
        None => {
            map.insert("revocation_freshness".to_string(), CanonicalValue::Null);
        }
    }
    map.insert(
        "signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    map.insert(
        "version".to_string(),
        CanonicalValue::String(token.version.to_string()),
    );
    map.insert(
        "zone".to_string(),
        CanonicalValue::String(token.zone.clone()),
    );
    CanonicalValue::Map(map)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedTokenError {
    SignatureInvalid(String),
    LegacyVerification(String),
    LegacyIdentityMismatch,
    LegacyMappingMismatch(&'static str),
    IssuerKeyMismatch,
    EmptyAudience,
    EmptyCapabilities,
    EmptyZone,
    InvertedTemporalWindow {
        not_before: u64,
        expiry: u64,
    },
    InvertedEpochWindow {
        valid_from: SecurityEpoch,
        valid_until: SecurityEpoch,
    },
    UnsupportedSchema {
        actual: String,
    },
    UnsupportedTokenVersion {
        version: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch,
    AudienceRejected {
        presenter: PrincipalId,
        audience_size: usize,
    },
    NotYetValid {
        current_tick: u64,
        not_before: u64,
    },
    Expired {
        current_tick: u64,
        expiry: u64,
    },
    EpochValidationFailed {
        errors: Vec<EpochValidationError>,
    },
    CheckpointBindingFailed {
        required_seq: u64,
        verifier_seq: u64,
    },
    CheckpointIdentityMismatch {
        checkpoint_id: PersistedEngineObjectId,
    },
    RevocationFreshnessStale {
        required_seq: u64,
        verifier_seq: u64,
    },
    RevocationHeadMismatch {
        revocation_head_hash: ContentHash,
    },
    Identity(VersionedIdError),
}

impl std::fmt::Display for VersionedTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(detail) => write!(formatter, "signature invalid: {detail}"),
            Self::LegacyVerification(detail) => write!(formatter, "legacy verification failed: {detail}"),
            Self::LegacyIdentityMismatch => {
                formatter.write_str("legacy token jti is not the historical content-derived identity")
            }
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy token migration mismatch at {field}")
            }
            Self::IssuerKeyMismatch => {
                formatter.write_str("migration signing key does not match legacy token issuer")
            }
            Self::EmptyAudience => formatter.write_str("token audience must not be empty"),
            Self::EmptyCapabilities => formatter.write_str("token capabilities must not be empty"),
            Self::EmptyZone => formatter.write_str("token zone must not be empty"),
            Self::InvertedTemporalWindow { not_before, expiry } => {
                write!(formatter, "inverted temporal window: {not_before} > {expiry}")
            }
            Self::InvertedEpochWindow {
                valid_from,
                valid_until,
            } => write!(
                formatter,
                "inverted epoch window: {valid_from} > {valid_until}"
            ),
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported token persistence schema {actual:?}")
            }
            Self::UnsupportedTokenVersion { version } => {
                write!(formatter, "unsupported token version {version}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch => formatter.write_str("token schema id does not match v2"),
            Self::AudienceRejected {
                presenter,
                audience_size,
            } => write!(
                formatter,
                "audience rejected: {presenter} not in {audience_size} audience members"
            ),
            Self::NotYetValid {
                current_tick,
                not_before,
            } => write!(
                formatter,
                "not yet valid: current tick={current_tick}, nbf={not_before}"
            ),
            Self::Expired {
                current_tick,
                expiry,
            } => write!(
                formatter,
                "expired: current tick={current_tick}, expiry={expiry}"
            ),
            Self::EpochValidationFailed { errors } => write!(
                formatter,
                "epoch validation failed: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::CheckpointBindingFailed {
                required_seq,
                verifier_seq,
            } => write!(
                formatter,
                "checkpoint binding failed: required seq={required_seq}, verifier seq={verifier_seq}"
            ),
            Self::CheckpointIdentityMismatch { checkpoint_id } => write!(
                formatter,
                "checkpoint identity {}:{} is not accepted by verifier",
                checkpoint_id.derivation_version,
                checkpoint_id.to_hex()
            ),
            Self::RevocationFreshnessStale {
                required_seq,
                verifier_seq,
            } => write!(
                formatter,
                "revocation freshness stale: required seq={required_seq}, verifier seq={verifier_seq}"
            ),
            Self::RevocationHeadMismatch {
                revocation_head_hash,
            } => write!(
                formatter,
                "revocation head {} is not accepted by verifier",
                revocation_head_hash.to_hex()
            ),
            Self::Identity(error) => write!(formatter, "token identity error: {error}"),
        }
    }
}

impl std::error::Error for VersionedTokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for VersionedTokenError {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::RuntimeCapability;
    use crate::engine_object_id::{derive_versioned_id, derive_versioned_schema_id};
    use crate::policy_checkpoint::{
        PolicyCheckpointV2Builder, PolicyHead, PolicyType,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid key")
    }

    fn principal(seed: u8) -> PrincipalId {
        PrincipalId::from_bytes([seed; 32])
    }

    fn checkpoint_ref(seq: u64) -> VersionedCheckpointRef {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            b"FrankenEngine.TestCheckpoint.v2",
        )
        .expect("schema");
        let checkpoint_id = derive_versioned_id(
            ObjectDomain::CheckpointArtifact,
            "zone-a",
            &schema,
            &seq.to_be_bytes(),
        )
        .expect("checkpoint id");
        VersionedCheckpointRef::new(
            seq,
            PersistedEngineObjectId::from_versioned(checkpoint_id),
        )
    }

    fn revocation_ref(seq: u64) -> RevocationFreshnessRef {
        RevocationFreshnessRef {
            min_revocation_seq: seq,
            revocation_head_hash: ContentHash::compute(&seq.to_be_bytes()),
        }
    }

    fn basic_token(issuer: &SigningKey) -> VersionedCapabilityToken {
        VersionedTokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .expect("token")
    }

    fn context() -> VersionedVerificationContext {
        VersionedVerificationContext::new(500, 10, 10)
    }

    #[test]
    fn fresh_token_is_sha256_v2_and_signature_verifies() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        assert_eq!(token.jti.derivation_version, ObjectIdDerivationVersion::Sha256V2);
        assert_eq!(
            token.schema_version.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );
        token.verify_signature().expect("signature");
    }

    #[test]
    fn fresh_jti_is_deterministic() {
        let issuer = key(1);
        assert_eq!(basic_token(&issuer).jti, basic_token(&issuer).jti);
    }

    #[test]
    fn jti_is_recomputed_during_verification() {
        let issuer = key(1);
        let mut token = basic_token(&issuer);
        token.jti.object_id.0[0] ^= 1;
        assert!(token.validate_identity().is_err());
    }

    #[test]
    fn jti_algorithm_tag_is_recomputed_during_verification() {
        let issuer = key(1);
        let mut token = basic_token(&issuer);
        token.jti.derivation_version = ObjectIdDerivationVersion::LegacyV1;
        assert!(matches!(
            token.validate_identity(),
            Err(VersionedTokenError::AlgorithmMismatch { field: "jti", .. })
        ));
    }

    #[test]
    fn token_json_is_self_describing() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        let value = serde_json::to_value(&token).expect("serialize");
        assert_eq!(value["persistence_schema"], CAPABILITY_TOKEN_PERSISTENCE_SCHEMA_V2);
        assert_eq!(value["jti"]["derivation_version"], "sha256_v2");
        assert_eq!(value["schema_version"]["derivation_version"], "sha256_v2");
    }

    #[test]
    fn token_json_roundtrips_and_revalidates() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        let encoded = serde_json::to_vec(&token).expect("serialize");
        let decoded: VersionedCapabilityToken = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded, token);
        decoded.validate_identity().expect("identity");
    }

    #[test]
    fn empty_audience_is_rejected_before_signing() {
        let result = VersionedTokenBuilder::new(
            key(1),
            DeterministicTimestamp(1),
            DeterministicTimestamp(2),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_capability(RuntimeCapability::VmDispatch)
        .build();
        assert!(matches!(result, Err(VersionedTokenError::EmptyAudience)));
    }

    #[test]
    fn empty_capabilities_are_rejected_before_signing() {
        let result = VersionedTokenBuilder::new(
            key(1),
            DeterministicTimestamp(1),
            DeterministicTimestamp(2),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(1))
        .build();
        assert!(matches!(result, Err(VersionedTokenError::EmptyCapabilities)));
    }

    #[test]
    fn empty_zone_is_rejected_before_signing() {
        let result = VersionedTokenBuilder::new(
            key(1),
            DeterministicTimestamp(1),
            DeterministicTimestamp(2),
            SecurityEpoch::GENESIS,
            "  ",
        )
        .add_audience(principal(1))
        .add_capability(RuntimeCapability::VmDispatch)
        .build();
        assert!(matches!(result, Err(VersionedTokenError::EmptyZone)));
    }

    #[test]
    fn inverted_time_window_is_rejected() {
        let result = VersionedTokenBuilder::new(
            key(1),
            DeterministicTimestamp(3),
            DeterministicTimestamp(2),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(1))
        .add_capability(RuntimeCapability::VmDispatch)
        .build();
        assert!(matches!(
            result,
            Err(VersionedTokenError::InvertedTemporalWindow { .. })
        ));
    }

    #[test]
    fn audience_mismatch_is_rejected() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        assert!(matches!(
            verify_versioned_token(&token, &principal(99), &context()),
            Err(VersionedTokenError::AudienceRejected { .. })
        ));
    }

    #[test]
    fn not_yet_valid_is_rejected() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        let context = VersionedVerificationContext::new(99, 0, 0);
        assert!(matches!(
            verify_versioned_token(&token, &principal(10), &context),
            Err(VersionedTokenError::NotYetValid { .. })
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let issuer = key(1);
        let token = basic_token(&issuer);
        let context = VersionedVerificationContext::new(1001, 0, 0);
        assert!(matches!(
            verify_versioned_token(&token, &principal(10), &context),
            Err(VersionedTokenError::Expired { .. })
        ));
    }

    #[test]
    fn exact_checkpoint_identity_and_algorithm_are_required() {
        let issuer = key(1);
        let binding = checkpoint_ref(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(binding.clone())
        .build()
        .expect("token");
        let wrong_algorithm = PersistedEngineObjectId::legacy(binding.checkpoint_id.object_id.clone());
        let context = VersionedVerificationContext::new(500, 10, 0)
            .with_checkpoint_id(wrong_algorithm);
        assert!(matches!(
            verify_versioned_token(&token, &principal(10), &context),
            Err(VersionedTokenError::CheckpointIdentityMismatch { .. })
        ));
    }

    #[test]
    fn accepted_checkpoint_binding_verifies() {
        let issuer = key(1);
        let binding = checkpoint_ref(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(binding.clone())
        .build()
        .expect("token");
        let context = VersionedVerificationContext::new(500, 10, 0)
            .with_checkpoint_ref(&binding);
        verify_versioned_token(&token, &principal(10), &context).expect("verify");
    }

    #[test]
    fn stale_checkpoint_sequence_is_rejected_even_with_identity() {
        let issuer = key(1);
        let binding = checkpoint_ref(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(binding.clone())
        .build()
        .expect("token");
        let context = VersionedVerificationContext::new(500, 4, 0)
            .with_checkpoint_ref(&binding);
        assert!(matches!(
            verify_versioned_token(&token, &principal(10), &context),
            Err(VersionedTokenError::CheckpointBindingFailed { .. })
        ));
    }

    #[test]
    fn revocation_hash_identity_is_required() {
        let issuer = key(1);
        let freshness = revocation_ref(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_revocation_freshness(freshness.clone())
        .build()
        .expect("token");
        let context = VersionedVerificationContext::new(500, 0, 10);
        assert!(matches!(
            verify_versioned_token(&token, &principal(10), &context),
            Err(VersionedTokenError::RevocationHeadMismatch { .. })
        ));
    }

    #[test]
    fn accepted_revocation_freshness_verifies() {
        let issuer = key(1);
        let freshness = revocation_ref(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_revocation_freshness(freshness.clone())
        .build()
        .expect("token");
        let context = VersionedVerificationContext::new(500, 0, 10)
            .with_revocation_freshness(&freshness);
        verify_versioned_token(&token, &principal(10), &context).expect("verify");
    }

    #[test]
    fn legacy_token_migrates_only_with_same_issuer_key() {
        let issuer = key(2);
        let legacy = super::super::compat::TokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .expect("legacy token");
        let migrated = VersionedCapabilityToken::migrate_verified_legacy(&legacy, &issuer)
            .expect("migrate");
        assert!(migrated.legacy_provenance.is_some());
        assert_eq!(migrated.issuer, legacy.issuer);
        migrated.verify_signature().expect("new signature");
        assert!(matches!(
            VersionedCapabilityToken::migrate_verified_legacy(&legacy, &key(3)),
            Err(VersionedTokenError::IssuerKeyMismatch)
        ));
    }

    #[test]
    fn migrated_legacy_checkpoint_binding_is_explicitly_legacy() {
        let issuer = key(2);
        let checkpoint = CheckpointRef {
            min_checkpoint_seq: 5,
            checkpoint_id: EngineObjectId([7; 32]),
        };
        let legacy = super::super::compat::TokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(checkpoint)
        .build()
        .expect("legacy token");
        let migrated = VersionedCapabilityToken::migrate_verified_legacy(&legacy, &issuer)
            .expect("migrate");
        assert_eq!(
            migrated
                .checkpoint_binding
                .as_ref()
                .expect("binding")
                .checkpoint_id
                .derivation_version,
            ObjectIdDerivationVersion::LegacyV1
        );
    }

    #[test]
    fn legacy_jti_tampering_is_detected_before_migration() {
        let issuer = key(2);
        let mut legacy = super::super::compat::TokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .expect("legacy token");
        legacy.jti.0[0] ^= 1;
        assert!(matches!(
            VersionedCapabilityToken::migrate_verified_legacy(&legacy, &issuer),
            Err(VersionedTokenError::LegacyIdentityMismatch)
                | Err(VersionedTokenError::LegacyVerification(_))
        ));
    }

    #[test]
    fn migrated_semantics_cannot_diverge_from_legacy_provenance() {
        let issuer = key(2);
        let legacy = super::super::compat::TokenBuilder::new(
            issuer.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .expect("legacy token");
        let mut migrated = VersionedCapabilityToken::migrate_verified_legacy(&legacy, &issuer)
            .expect("migrate");
        migrated.capabilities.insert(RuntimeCapability::PolicyWrite);
        assert!(matches!(
            migrated.validate_identity(),
            Err(VersionedTokenError::LegacyMappingMismatch("capabilities"))
        ));
    }

    #[test]
    fn token_can_bind_real_v2_policy_checkpoint_identity() {
        let checkpoint_key = key(4);
        let checkpoint = PolicyCheckpointV2Builder::genesis(
            SecurityEpoch::GENESIS,
            DeterministicTimestamp(10),
            "zone-a",
        )
        .add_policy_head(PolicyHead {
            policy_type: PolicyType::RuntimeExecution,
            policy_hash: ContentHash::compute(b"policy"),
            policy_version: 1,
        })
        .build(std::slice::from_ref(&checkpoint_key))
        .expect("checkpoint");
        let binding = VersionedCheckpointRef::new(0, checkpoint.checkpoint_id.clone());
        let issuer = key(5);
        let token = VersionedTokenBuilder::new(
            issuer,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(binding.clone())
        .build()
        .expect("token");
        let context = VersionedVerificationContext::new(500, 0, 0)
            .with_checkpoint_ref(&binding);
        verify_versioned_token(&token, &principal(10), &context).expect("verify");
    }

    #[test]
    fn signature_tampering_is_rejected() {
        let issuer = key(1);
        let mut token = basic_token(&issuer);
        token.signature.lower[0] ^= 1;
        assert!(matches!(
            token.verify_signature(),
            Err(VersionedTokenError::SignatureInvalid(_))
        ));
    }
}
