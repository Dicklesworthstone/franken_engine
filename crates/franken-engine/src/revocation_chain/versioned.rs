use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, EngineObjectId,
    ObjectDomain, ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId,
    VersionedIdError,
};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    sign_preimage, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

use super::compat::{
    revocation_schema_id, Revocation, RevocationReason, RevocationTargetType,
};

const REVOCATION_SCHEMA_V2: &[u8] = b"FrankenEngine.Revocation.sha256.v2";
const REVOCATION_EVENT_SCHEMA_V2: &[u8] = b"FrankenEngine.RevocationEvent.sha256.v2";
const REVOCATION_HEAD_SCHEMA_V2: &[u8] = b"FrankenEngine.RevocationHead.sha256.v2";
const MAX_HEAD_EPOCH_STALENESS: u64 = 0;
const GENESIS_CHAIN_DOMAIN: &[u8] = b"frankenengine.revocation-chain.sha256.v2.genesis";

pub const REVOCATION_PERSISTENCE_SCHEMA_V2: &str = "frankenengine.revocation.persistence.v2";
pub const REVOCATION_EVENT_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.revocation-event.persistence.v2";
pub const REVOCATION_HEAD_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.revocation-head.persistence.v2";

/// Verified historical revocation retained as immutable migration provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyRevocationProvenance {
    pub revocation: Revocation,
    pub issuer_verification_key: VerificationKey,
}

impl LegacyRevocationProvenance {
    pub fn verify(&self) -> Result<(), RevocationV2Error> {
        validate_zone(&self.revocation.zone)?;
        let derived_issuer = PrincipalId::from_verification_key(&self.issuer_verification_key);
        if derived_issuer != self.revocation.issued_by {
            return Err(RevocationV2Error::LegacyVerification(
                "legacy issuer key does not match issued_by".to_string(),
            ));
        }
        let expected = crate::engine_object_id::derive_id(
            ObjectDomain::Revocation,
            &self.revocation.zone,
            &revocation_schema_id(),
            self.revocation.target_id.as_bytes(),
        )
        .map_err(|error| RevocationV2Error::LegacyVerification(error.to_string()))?;
        if expected != self.revocation.revocation_id {
            return Err(RevocationV2Error::LegacyIdentityMismatch);
        }
        verify_signature(
            &self.issuer_verification_key,
            &self.revocation.preimage_bytes(),
            &self.revocation.signature,
        )
        .map_err(|error| RevocationV2Error::LegacyVerification(error.to_string()))
    }

    pub fn content_hash(&self) -> Result<ContentHash, RevocationV2Error> {
        self.verify()?;
        let mut bytes = self.revocation.preimage_bytes();
        bytes.extend_from_slice(&self.revocation.signature.to_bytes());
        bytes.extend_from_slice(self.issuer_verification_key.as_bytes());
        Ok(ContentHash::compute(&bytes))
    }
}

/// A signed revocation with explicit ID algorithms and a recomputable identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub revocation_id: PersistedEngineObjectId,
    pub target_type: RevocationTargetType,
    pub target_id: PersistedEngineObjectId,
    pub reason: RevocationReason,
    pub issued_by: PrincipalId,
    pub issued_at: DeterministicTimestamp,
    pub zone: String,
    pub legacy_provenance: Option<LegacyRevocationProvenance>,
    pub signature: Signature,
}

impl RevocationV2 {
    pub fn new(
        target_type: RevocationTargetType,
        target_id: PersistedEngineObjectId,
        reason: RevocationReason,
        issued_at: DeterministicTimestamp,
        zone: &str,
        issuer_key: &SigningKey,
    ) -> Result<Self, RevocationV2Error> {
        build_revocation_v2(
            target_type,
            target_id,
            reason,
            issued_at,
            zone.to_string(),
            None,
            issuer_key,
        )
    }

    /// Verify the legacy content-derived ID and signature before re-signing the
    /// same revocation semantics under SHA-256-v2. The target is explicitly
    /// tagged `legacy_v1`, because the old wire format did not carry an algorithm.
    pub fn migrate_verified_legacy(
        legacy: &Revocation,
        issuer_key: &SigningKey,
    ) -> Result<Self, RevocationV2Error> {
        let provenance = LegacyRevocationProvenance {
            revocation: legacy.clone(),
            issuer_verification_key: issuer_key.verification_key(),
        };
        provenance.verify()?;
        build_revocation_v2(
            legacy.target_type,
            PersistedEngineObjectId::legacy(legacy.target_id.clone()),
            legacy.reason,
            legacy.issued_at,
            legacy.zone.clone(),
            Some(provenance),
            issuer_key,
        )
    }

    pub fn validate_identity(&self) -> Result<(), RevocationV2Error> {
        if self.persistence_schema != REVOCATION_PERSISTENCE_SCHEMA_V2 {
            return Err(RevocationV2Error::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_zone(&self.zone)?;
        require_v2_schema(
            "revocation.schema_version",
            &self.schema_version,
            REVOCATION_SCHEMA_V2,
        )?;
        require_v2_object("revocation.revocation_id", &self.revocation_id)?;
        validate_legacy_mapping(self)?;
        let material = revocation_identity_material(
            self.target_type,
            &self.target_id,
            self.reason,
            &self.issued_by,
            self.issued_at,
            &self.zone,
            self.legacy_provenance.as_ref(),
        )?;
        verify_versioned_id(
            &self.revocation_id.to_versioned(),
            ObjectDomain::Revocation,
            &self.zone,
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify(&self, issuer_key: &VerificationKey) -> Result<(), RevocationV2Error> {
        self.validate_identity()?;
        if PrincipalId::from_verification_key(issuer_key) != self.issued_by {
            return Err(RevocationV2Error::IssuerKeyMismatch);
        }
        verify_signature(issuer_key, &self.preimage_bytes(), &self.signature)
            .map_err(|error| RevocationV2Error::SignatureInvalid(error.to_string()))
    }
}

impl SignaturePreimage for RevocationV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Revocation
    }

    fn signature_schema(&self) -> &SchemaHash {
        revocation_signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        signed_revocation_view(self)
    }
}

/// Hash-linked v2 revocation-chain entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEventV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub event_id: PersistedEngineObjectId,
    pub revocation: RevocationV2,
    pub prev_event: Option<PersistedEngineObjectId>,
    pub event_seq: u64,
}

impl RevocationEventV2 {
    pub fn validate_identity(&self) -> Result<(), RevocationV2Error> {
        if self.persistence_schema != REVOCATION_EVENT_PERSISTENCE_SCHEMA_V2 {
            return Err(RevocationV2Error::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        require_v2_schema(
            "event.schema_version",
            &self.schema_version,
            REVOCATION_EVENT_SCHEMA_V2,
        )?;
        require_v2_object("event.event_id", &self.event_id)?;
        if self.event_seq == 0 && self.prev_event.is_some() {
            return Err(RevocationV2Error::InvalidGenesis);
        }
        if self.event_seq > 0 && self.prev_event.is_none() {
            return Err(RevocationV2Error::MissingPredecessor);
        }
        let material = event_identity_material(
            &self.revocation,
            self.event_seq,
            self.prev_event.as_ref(),
        );
        verify_versioned_id(
            &self.event_id.to_versioned(),
            ObjectDomain::Revocation,
            &self.revocation.zone,
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&event_canonical_view(self))
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

/// Signed head of the v2 revocation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationHeadV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub head_id: PersistedEngineObjectId,
    pub latest_event: PersistedEngineObjectId,
    pub head_seq: u64,
    pub chain_hash: ContentHash,
    pub epoch_id: SecurityEpoch,
    pub issued_at: DeterministicTimestamp,
    pub zone: String,
    pub signature: Signature,
}

impl RevocationHeadV2 {
    pub fn validate_identity(&self) -> Result<(), RevocationV2Error> {
        if self.persistence_schema != REVOCATION_HEAD_PERSISTENCE_SCHEMA_V2 {
            return Err(RevocationV2Error::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_zone(&self.zone)?;
        require_v2_schema(
            "head.schema_version",
            &self.schema_version,
            REVOCATION_HEAD_SCHEMA_V2,
        )?;
        require_v2_object("head.head_id", &self.head_id)?;
        let material = head_identity_material(
            &self.latest_event,
            self.head_seq,
            &self.chain_hash,
            self.epoch_id,
            self.issued_at,
            &self.zone,
        );
        verify_versioned_id(
            &self.head_id.to_versioned(),
            ObjectDomain::Revocation,
            &self.zone,
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify(
        &self,
        verification_key: &VerificationKey,
        current_epoch: SecurityEpoch,
    ) -> Result<(), RevocationV2Error> {
        self.validate_identity()?;
        verify_head_freshness(self, current_epoch)?;
        verify_signature(verification_key, &self.preimage_bytes(), &self.signature)
            .map_err(|error| RevocationV2Error::SignatureInvalid(error.to_string()))
    }
}

impl SignaturePreimage for RevocationHeadV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Revocation
    }

    fn signature_schema(&self) -> &SchemaHash {
        head_signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        signed_head_view(self)
    }
}

/// Append-only SHA-256-v2 revocation chain with exact algorithm-aware lookup.
#[derive(Debug)]
pub struct RevocationChainV2 {
    zone: String,
    events: Vec<RevocationEventV2>,
    head: Option<RevocationHeadV2>,
    authorized_revocation_keys: BTreeMap<PrincipalId, VerificationKey>,
    authorized_head_keys: BTreeMap<PrincipalId, VerificationKey>,
    revocation_index: BTreeMap<PersistedEngineObjectId, u64>,
    chain_hash: ContentHash,
    current_epoch: SecurityEpoch,
}

impl RevocationChainV2 {
    pub fn new(zone: &str) -> Result<Self, RevocationV2Error> {
        validate_zone(zone)?;
        Ok(Self {
            zone: zone.to_string(),
            events: Vec::new(),
            head: None,
            authorized_revocation_keys: BTreeMap::new(),
            authorized_head_keys: BTreeMap::new(),
            revocation_index: BTreeMap::new(),
            chain_hash: ContentHash::compute(GENESIS_CHAIN_DOMAIN),
            current_epoch: SecurityEpoch::GENESIS,
        })
    }

    pub fn authorize_revocation_key(&mut self, key: VerificationKey) -> PrincipalId {
        let principal = PrincipalId::from_verification_key(&key);
        self.authorized_revocation_keys.insert(principal.clone(), key);
        principal
    }

    pub fn authorize_head_key(&mut self, key: VerificationKey) -> PrincipalId {
        let principal = PrincipalId::from_verification_key(&key);
        self.authorized_head_keys.insert(principal.clone(), key);
        principal
    }

    pub fn with_authorized_revocation_key(mut self, key: VerificationKey) -> Self {
        self.authorize_revocation_key(key);
        self
    }

    pub fn with_authorized_head_key(mut self, key: VerificationKey) -> Self {
        self.authorize_head_key(key);
        self
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }

    pub fn len(&self) -> u64 {
        self.events.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[RevocationEventV2] {
        &self.events
    }

    pub fn head(&self) -> Option<&RevocationHeadV2> {
        self.head.as_ref()
    }

    pub fn chain_hash(&self) -> &ContentHash {
        &self.chain_hash
    }

    pub fn current_epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    pub fn set_current_epoch(&mut self, epoch: SecurityEpoch) -> Result<(), RevocationV2Error> {
        if epoch < self.current_epoch {
            return Err(RevocationV2Error::EpochRegression {
                previous: self.current_epoch,
                current: epoch,
            });
        }
        self.current_epoch = epoch;
        Ok(())
    }

    pub fn is_revoked(&self, target_id: &PersistedEngineObjectId) -> bool {
        self.revocation_index.contains_key(target_id)
    }

    pub fn is_legacy_revoked(&self, target_id: &EngineObjectId) -> bool {
        self.is_revoked(&PersistedEngineObjectId::legacy(target_id.clone()))
    }

    pub fn lookup_revocation(
        &self,
        target_id: &PersistedEngineObjectId,
    ) -> Option<&RevocationV2> {
        self.revocation_index
            .get(target_id)
            .and_then(|sequence| self.events.get(*sequence as usize))
            .map(|event| &event.revocation)
    }

    pub fn append(
        &mut self,
        revocation: RevocationV2,
        head_signing_key: &SigningKey,
    ) -> Result<u64, RevocationV2Error> {
        if revocation.zone != self.zone {
            return Err(RevocationV2Error::ZoneMismatch {
                expected: self.zone.clone(),
                actual: revocation.zone.clone(),
            });
        }
        if self.revocation_index.contains_key(&revocation.target_id) {
            return Err(RevocationV2Error::DuplicateTarget {
                target_id: revocation.target_id.clone(),
            });
        }
        let issuer_key = self
            .authorized_revocation_keys
            .get(&revocation.issued_by)
            .ok_or_else(|| RevocationV2Error::UnauthorizedIssuer {
                principal: revocation.issued_by.clone(),
            })?;
        revocation.verify(issuer_key)?;

        let head_key = head_signing_key.verification_key();
        let head_principal = PrincipalId::from_verification_key(&head_key);
        if !self.authorized_head_keys.contains_key(&head_principal) {
            return Err(RevocationV2Error::UnauthorizedHeadSigner {
                principal: head_principal,
            });
        }

        let event_seq = self.events.len() as u64;
        let prev_event = self.events.last().map(|event| event.event_id.clone());
        let event_schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            REVOCATION_EVENT_SCHEMA_V2,
        )?;
        let event_material = event_identity_material(&revocation, event_seq, prev_event.as_ref());
        let event_id = derive_versioned_id(
            ObjectDomain::Revocation,
            &self.zone,
            &event_schema,
            &event_material,
        )?;
        let event = RevocationEventV2 {
            persistence_schema: REVOCATION_EVENT_PERSISTENCE_SCHEMA_V2.to_string(),
            schema_version: PersistedSchemaId::from_versioned(event_schema),
            event_id: PersistedEngineObjectId::from_versioned(event_id),
            revocation,
            prev_event,
            event_seq,
        };
        event.validate_identity()?;

        let event_hash = event.content_hash();
        let mut hash_input = Vec::with_capacity(64);
        hash_input.extend_from_slice(self.chain_hash.as_bytes());
        hash_input.extend_from_slice(event_hash.as_bytes());
        let new_chain_hash = ContentHash::compute(&hash_input);
        let new_head = build_head_v2(
            &event,
            new_chain_hash,
            self.current_epoch,
            &self.zone,
            head_signing_key,
        )?;

        let target_id = event.revocation.target_id.clone();
        self.revocation_index.insert(target_id, event_seq);
        self.chain_hash = new_chain_hash;
        self.events.push(event);
        self.head = Some(new_head);
        Ok(event_seq)
    }

    pub fn verify_chain(&self) -> Result<(), RevocationV2Error> {
        if self.events.is_empty() {
            if self.head.is_some() {
                return Err(RevocationV2Error::UnexpectedHeadOnEmptyChain);
            }
            return Ok(());
        }

        let mut rolling_hash = ContentHash::compute(GENESIS_CHAIN_DOMAIN);
        let mut seen_targets = BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            let expected_seq = index as u64;
            if event.event_seq != expected_seq {
                return Err(RevocationV2Error::SequenceDiscontinuity {
                    expected: expected_seq,
                    actual: event.event_seq,
                });
            }
            let expected_prev = if index == 0 {
                None
            } else {
                Some(self.events[index - 1].event_id.clone())
            };
            if event.prev_event != expected_prev {
                return Err(RevocationV2Error::ChainLinkMismatch {
                    sequence: event.event_seq,
                });
            }
            if event.revocation.zone != self.zone {
                return Err(RevocationV2Error::ZoneMismatch {
                    expected: self.zone.clone(),
                    actual: event.revocation.zone.clone(),
                });
            }
            if !seen_targets.insert(event.revocation.target_id.clone()) {
                return Err(RevocationV2Error::DuplicateTarget {
                    target_id: event.revocation.target_id.clone(),
                });
            }
            let issuer_key = self
                .authorized_revocation_keys
                .get(&event.revocation.issued_by)
                .ok_or_else(|| RevocationV2Error::UnauthorizedIssuer {
                    principal: event.revocation.issued_by.clone(),
                })?;
            event.revocation.verify(issuer_key)?;
            event.validate_identity()?;

            let mut hash_input = Vec::with_capacity(64);
            hash_input.extend_from_slice(rolling_hash.as_bytes());
            hash_input.extend_from_slice(event.content_hash().as_bytes());
            rolling_hash = ContentHash::compute(&hash_input);
        }

        if rolling_hash != self.chain_hash {
            return Err(RevocationV2Error::ChainHashMismatch);
        }
        let head = self.head.as_ref().ok_or(RevocationV2Error::MissingHead)?;
        let last = self.events.last().ok_or(RevocationV2Error::MissingHead)?;
        if head.head_seq != last.event_seq
            || head.latest_event != last.event_id
            || head.chain_hash != rolling_hash
            || head.zone != self.zone
        {
            return Err(RevocationV2Error::HeadMismatch);
        }
        verify_head_with_authorized_keys(head, &self.authorized_head_keys, self.current_epoch)?;
        Ok(())
    }

    pub fn rebuild_verified(
        zone: &str,
        events: Vec<RevocationEventV2>,
        head: Option<RevocationHeadV2>,
        revocation_keys: impl IntoIterator<Item = VerificationKey>,
        head_keys: impl IntoIterator<Item = VerificationKey>,
        current_epoch: SecurityEpoch,
    ) -> Result<Self, RevocationV2Error> {
        let mut chain = Self::new(zone)?;
        chain.current_epoch = current_epoch;
        for key in revocation_keys {
            chain.authorize_revocation_key(key);
        }
        for key in head_keys {
            chain.authorize_head_key(key);
        }
        chain.events = events;
        chain.head = head;
        chain.rebuild_index_and_hash()?;
        chain.verify_chain()?;
        Ok(chain)
    }

    fn rebuild_index_and_hash(&mut self) -> Result<(), RevocationV2Error> {
        self.revocation_index.clear();
        self.chain_hash = ContentHash::compute(GENESIS_CHAIN_DOMAIN);
        for event in &self.events {
            if self
                .revocation_index
                .insert(event.revocation.target_id.clone(), event.event_seq)
                .is_some()
            {
                return Err(RevocationV2Error::DuplicateTarget {
                    target_id: event.revocation.target_id.clone(),
                });
            }
            let mut hash_input = Vec::with_capacity(64);
            hash_input.extend_from_slice(self.chain_hash.as_bytes());
            hash_input.extend_from_slice(event.content_hash().as_bytes());
            self.chain_hash = ContentHash::compute(&hash_input);
        }
        Ok(())
    }
}

fn build_revocation_v2(
    target_type: RevocationTargetType,
    target_id: PersistedEngineObjectId,
    reason: RevocationReason,
    issued_at: DeterministicTimestamp,
    zone: String,
    legacy_provenance: Option<LegacyRevocationProvenance>,
    issuer_key: &SigningKey,
) -> Result<RevocationV2, RevocationV2Error> {
    validate_zone(&zone)?;
    if let Some(provenance) = &legacy_provenance {
        provenance.verify()?;
    }
    let issued_by = PrincipalId::from_verification_key(&issuer_key.verification_key());
    let schema = derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        REVOCATION_SCHEMA_V2,
    )?;
    let material = revocation_identity_material(
        target_type,
        &target_id,
        reason,
        &issued_by,
        issued_at,
        &zone,
        legacy_provenance.as_ref(),
    )?;
    let revocation_id = derive_versioned_id(
        ObjectDomain::Revocation,
        &zone,
        &schema,
        &material,
    )?;
    let mut revocation = RevocationV2 {
        persistence_schema: REVOCATION_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        revocation_id: PersistedEngineObjectId::from_versioned(revocation_id),
        target_type,
        target_id,
        reason,
        issued_by,
        issued_at,
        zone,
        legacy_provenance,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    revocation.validate_identity()?;
    revocation.signature = sign_preimage(issuer_key, &revocation.preimage_bytes())
        .map_err(|error| RevocationV2Error::SignatureInvalid(error.to_string()))?;
    Ok(revocation)
}

fn build_head_v2(
    event: &RevocationEventV2,
    chain_hash: ContentHash,
    epoch_id: SecurityEpoch,
    zone: &str,
    signing_key: &SigningKey,
) -> Result<RevocationHeadV2, RevocationV2Error> {
    let schema = derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        REVOCATION_HEAD_SCHEMA_V2,
    )?;
    let material = head_identity_material(
        &event.event_id,
        event.event_seq,
        &chain_hash,
        epoch_id,
        event.revocation.issued_at,
        zone,
    );
    let head_id = derive_versioned_id(
        ObjectDomain::Revocation,
        zone,
        &schema,
        &material,
    )?;
    let mut head = RevocationHeadV2 {
        persistence_schema: REVOCATION_HEAD_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        head_id: PersistedEngineObjectId::from_versioned(head_id),
        latest_event: event.event_id.clone(),
        head_seq: event.event_seq,
        chain_hash,
        epoch_id,
        issued_at: event.revocation.issued_at,
        zone: zone.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    head.validate_identity()?;
    head.signature = sign_preimage(signing_key, &head.preimage_bytes())
        .map_err(|error| RevocationV2Error::SignatureInvalid(error.to_string()))?;
    Ok(head)
}

fn verify_head_with_authorized_keys(
    head: &RevocationHeadV2,
    authorized: &BTreeMap<PrincipalId, VerificationKey>,
    current_epoch: SecurityEpoch,
) -> Result<(), RevocationV2Error> {
    head.validate_identity()?;
    verify_head_freshness(head, current_epoch)?;
    if authorized.is_empty() {
        return Err(RevocationV2Error::NoAuthorizedHeadSigner);
    }
    if authorized
        .values()
        .any(|key| verify_signature(key, &head.preimage_bytes(), &head.signature).is_ok())
    {
        Ok(())
    } else {
        Err(RevocationV2Error::SignatureInvalid(
            "head signature did not verify with any authorized key".to_string(),
        ))
    }
}

fn verify_head_freshness(
    head: &RevocationHeadV2,
    current_epoch: SecurityEpoch,
) -> Result<(), RevocationV2Error> {
    if head
        .epoch_id
        .as_u64()
        .saturating_add(MAX_HEAD_EPOCH_STALENESS)
        < current_epoch.as_u64()
    {
        return Err(RevocationV2Error::StaleHead {
            head_epoch: head.epoch_id,
            current_epoch,
        });
    }
    Ok(())
}

fn revocation_signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(REVOCATION_SCHEMA_V2));
    &HASH
}

fn head_signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(REVOCATION_HEAD_SCHEMA_V2));
    &HASH
}

fn signed_revocation_view(revocation: &RevocationV2) -> CanonicalValue {
    let mut map = revocation_identity_map(
        revocation.target_type,
        &revocation.target_id,
        revocation.reason,
        &revocation.issued_by,
        revocation.issued_at,
        &revocation.zone,
        revocation.legacy_provenance.as_ref(),
    );
    insert_schema_id(&mut map, "schema_version", &revocation.schema_version);
    insert_object_id(&mut map, "revocation_id", &revocation.revocation_id);
    map.insert(
        "signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

fn signed_head_view(head: &RevocationHeadV2) -> CanonicalValue {
    let mut map = head_identity_map(
        &head.latest_event,
        head.head_seq,
        &head.chain_hash,
        head.epoch_id,
        head.issued_at,
        &head.zone,
    );
    insert_schema_id(&mut map, "schema_version", &head.schema_version);
    insert_object_id(&mut map, "head_id", &head.head_id);
    map.insert(
        "signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

fn event_canonical_view(event: &RevocationEventV2) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(event.persistence_schema.clone()),
    );
    insert_schema_id(&mut map, "schema_version", &event.schema_version);
    insert_object_id(&mut map, "event_id", &event.event_id);
    map.insert("event_seq".to_string(), CanonicalValue::U64(event.event_seq));
    insert_optional_object_id(&mut map, "prev_event", event.prev_event.as_ref());
    map.insert(
        "revocation".to_string(),
        CanonicalValue::Bytes(event.revocation.preimage_bytes()),
    );
    map.insert(
        "revocation_signature".to_string(),
        CanonicalValue::Bytes(event.revocation.signature.to_bytes().to_vec()),
    );
    CanonicalValue::Map(map)
}

fn revocation_identity_material(
    target_type: RevocationTargetType,
    target_id: &PersistedEngineObjectId,
    reason: RevocationReason,
    issued_by: &PrincipalId,
    issued_at: DeterministicTimestamp,
    zone: &str,
    legacy_provenance: Option<&LegacyRevocationProvenance>,
) -> Result<Vec<u8>, RevocationV2Error> {
    let map = revocation_identity_map(
        target_type,
        target_id,
        reason,
        issued_by,
        issued_at,
        zone,
        legacy_provenance,
    );
    Ok(deterministic_serde::encode_value(&CanonicalValue::Map(map)))
}

fn revocation_identity_map(
    target_type: RevocationTargetType,
    target_id: &PersistedEngineObjectId,
    reason: RevocationReason,
    issued_by: &PrincipalId,
    issued_at: DeterministicTimestamp,
    zone: &str,
    legacy_provenance: Option<&LegacyRevocationProvenance>,
) -> BTreeMap<String, CanonicalValue> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(REVOCATION_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    insert_object_id(&mut map, "target_id", target_id);
    map.insert(
        "target_type".to_string(),
        CanonicalValue::String(target_type.to_string()),
    );
    map.insert(
        "reason".to_string(),
        CanonicalValue::String(reason.to_string()),
    );
    map.insert(
        "issued_by".to_string(),
        CanonicalValue::Bytes(issued_by.as_bytes().to_vec()),
    );
    map.insert("issued_at".to_string(), CanonicalValue::U64(issued_at.0));
    map.insert("zone".to_string(), CanonicalValue::String(zone.to_string()));
    map.insert(
        "legacy_provenance_hash".to_string(),
        CanonicalValue::Bytes(optional_legacy_hash(legacy_provenance)),
    );
    map
}

fn event_identity_material(
    revocation: &RevocationV2,
    event_seq: u64,
    prev_event: Option<&PersistedEngineObjectId>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(REVOCATION_EVENT_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    map.insert("event_seq".to_string(), CanonicalValue::U64(event_seq));
    insert_optional_object_id(&mut map, "prev_event", prev_event);
    insert_object_id(&mut map, "revocation_id", &revocation.revocation_id);
    map.insert(
        "revocation_preimage".to_string(),
        CanonicalValue::Bytes(revocation.preimage_bytes()),
    );
    map.insert(
        "revocation_signature".to_string(),
        CanonicalValue::Bytes(revocation.signature.to_bytes().to_vec()),
    );
    deterministic_serde::encode_value(&CanonicalValue::Map(map))
}

fn head_identity_material(
    latest_event: &PersistedEngineObjectId,
    head_seq: u64,
    chain_hash: &ContentHash,
    epoch_id: SecurityEpoch,
    issued_at: DeterministicTimestamp,
    zone: &str,
) -> Vec<u8> {
    deterministic_serde::encode_value(&CanonicalValue::Map(head_identity_map(
        latest_event,
        head_seq,
        chain_hash,
        epoch_id,
        issued_at,
        zone,
    )))
}

fn head_identity_map(
    latest_event: &PersistedEngineObjectId,
    head_seq: u64,
    chain_hash: &ContentHash,
    epoch_id: SecurityEpoch,
    issued_at: DeterministicTimestamp,
    zone: &str,
) -> BTreeMap<String, CanonicalValue> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(REVOCATION_HEAD_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    insert_object_id(&mut map, "latest_event", latest_event);
    map.insert("head_seq".to_string(), CanonicalValue::U64(head_seq));
    map.insert(
        "chain_hash".to_string(),
        CanonicalValue::Bytes(chain_hash.as_bytes().to_vec()),
    );
    map.insert(
        "epoch_id".to_string(),
        CanonicalValue::U64(epoch_id.as_u64()),
    );
    map.insert("issued_at".to_string(), CanonicalValue::U64(issued_at.0));
    map.insert("zone".to_string(), CanonicalValue::String(zone.to_string()));
    map
}

fn validate_legacy_mapping(revocation: &RevocationV2) -> Result<(), RevocationV2Error> {
    let Some(provenance) = &revocation.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.revocation;
    if revocation.target_type != legacy.target_type {
        return Err(RevocationV2Error::LegacyMappingMismatch("target_type"));
    }
    if revocation.target_id != PersistedEngineObjectId::legacy(legacy.target_id.clone()) {
        return Err(RevocationV2Error::LegacyMappingMismatch("target_id"));
    }
    if revocation.reason != legacy.reason {
        return Err(RevocationV2Error::LegacyMappingMismatch("reason"));
    }
    if revocation.issued_by != legacy.issued_by {
        return Err(RevocationV2Error::LegacyMappingMismatch("issued_by"));
    }
    if revocation.issued_at != legacy.issued_at {
        return Err(RevocationV2Error::LegacyMappingMismatch("issued_at"));
    }
    if revocation.zone != legacy.zone {
        return Err(RevocationV2Error::LegacyMappingMismatch("zone"));
    }
    Ok(())
}

fn optional_legacy_hash(provenance: Option<&LegacyRevocationProvenance>) -> Vec<u8> {
    provenance
        .and_then(|value| value.content_hash().ok())
        .map(|hash| hash.as_bytes().to_vec())
        .unwrap_or_default()
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

fn insert_optional_object_id(
    map: &mut BTreeMap<String, CanonicalValue>,
    field: &str,
    value: Option<&PersistedEngineObjectId>,
) {
    match value {
        Some(value) => insert_object_id(map, field, value),
        None => {
            map.insert(
                format!("{field}_derivation_version"),
                CanonicalValue::Null,
            );
            map.insert(field.to_string(), CanonicalValue::Null);
        }
    }
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

fn require_v2_schema(
    field: &'static str,
    schema: &PersistedSchemaId,
    definition: &[u8],
) -> Result<(), RevocationV2Error> {
    if schema.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(RevocationV2Error::AlgorithmMismatch {
            field,
            actual: schema.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        definition,
    )?);
    if schema != &expected {
        return Err(RevocationV2Error::SchemaMismatch { field });
    }
    Ok(())
}

fn require_v2_object(
    field: &'static str,
    value: &PersistedEngineObjectId,
) -> Result<(), RevocationV2Error> {
    if value.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(RevocationV2Error::AlgorithmMismatch {
            field,
            actual: value.derivation_version,
        });
    }
    Ok(())
}

fn validate_zone(zone: &str) -> Result<(), RevocationV2Error> {
    if zone.trim().is_empty() {
        return Err(RevocationV2Error::EmptyZone);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationV2Error {
    EmptyZone,
    UnsupportedSchema {
        actual: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch {
        field: &'static str,
    },
    SignatureInvalid(String),
    IssuerKeyMismatch,
    LegacyVerification(String),
    LegacyIdentityMismatch,
    LegacyMappingMismatch(&'static str),
    UnauthorizedIssuer {
        principal: PrincipalId,
    },
    UnauthorizedHeadSigner {
        principal: PrincipalId,
    },
    NoAuthorizedHeadSigner,
    DuplicateTarget {
        target_id: PersistedEngineObjectId,
    },
    InvalidGenesis,
    MissingPredecessor,
    SequenceDiscontinuity {
        expected: u64,
        actual: u64,
    },
    ChainLinkMismatch {
        sequence: u64,
    },
    ChainHashMismatch,
    MissingHead,
    UnexpectedHeadOnEmptyChain,
    HeadMismatch,
    ZoneMismatch {
        expected: String,
        actual: String,
    },
    EpochRegression {
        previous: SecurityEpoch,
        current: SecurityEpoch,
    },
    StaleHead {
        head_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    Identity(VersionedIdError),
}

impl std::fmt::Display for RevocationV2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyZone => formatter.write_str("revocation zone must not be empty"),
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported persistence schema {actual:?}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch { field } => write!(formatter, "{field} does not match v2"),
            Self::SignatureInvalid(detail) => write!(formatter, "signature invalid: {detail}"),
            Self::IssuerKeyMismatch => formatter.write_str("issuer key does not match issued_by"),
            Self::LegacyVerification(detail) => write!(formatter, "legacy verification failed: {detail}"),
            Self::LegacyIdentityMismatch => {
                formatter.write_str("legacy revocation_id is not content-derived from target_id")
            }
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy revocation migration mismatch at {field}")
            }
            Self::UnauthorizedIssuer { principal } => {
                write!(formatter, "revocation issuer {principal} is not authorized")
            }
            Self::UnauthorizedHeadSigner { principal } => {
                write!(formatter, "revocation head signer {principal} is not authorized")
            }
            Self::NoAuthorizedHeadSigner => formatter.write_str("no authorized head signer configured"),
            Self::DuplicateTarget { target_id } => write!(
                formatter,
                "duplicate revocation target {}:{}",
                target_id.derivation_version,
                target_id.to_hex()
            ),
            Self::InvalidGenesis => formatter.write_str("genesis event must have no predecessor"),
            Self::MissingPredecessor => formatter.write_str("non-genesis event is missing predecessor"),
            Self::SequenceDiscontinuity { expected, actual } => {
                write!(formatter, "sequence discontinuity: expected {expected}, got {actual}")
            }
            Self::ChainLinkMismatch { sequence } => {
                write!(formatter, "chain predecessor mismatch at sequence {sequence}")
            }
            Self::ChainHashMismatch => formatter.write_str("revocation chain hash mismatch"),
            Self::MissingHead => formatter.write_str("non-empty revocation chain is missing a head"),
            Self::UnexpectedHeadOnEmptyChain => formatter.write_str("empty revocation chain has a head"),
            Self::HeadMismatch => formatter.write_str("revocation head does not match chain tip"),
            Self::ZoneMismatch { expected, actual } => {
                write!(formatter, "zone mismatch: expected {expected:?}, got {actual:?}")
            }
            Self::EpochRegression { previous, current } => {
                write!(formatter, "epoch regression: {previous} -> {current}")
            }
            Self::StaleHead {
                head_epoch,
                current_epoch,
            } => write!(
                formatter,
                "revocation head epoch {head_epoch} is stale for verifier epoch {current_epoch}"
            ),
            Self::Identity(error) => write!(formatter, "revocation identity error: {error}"),
        }
    }
}

impl std::error::Error for RevocationV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for RevocationV2Error {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "test-zone";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid test key")
    }

    fn target(byte: u8, version: ObjectIdDerivationVersion) -> PersistedEngineObjectId {
        let raw = EngineObjectId([byte; 32]);
        match version {
            ObjectIdDerivationVersion::LegacyV1 => PersistedEngineObjectId::legacy(raw),
            ObjectIdDerivationVersion::Sha256V2 => PersistedEngineObjectId {
                derivation_version: version,
                object_id: raw,
            },
        }
    }

    fn revocation(
        issuer: &SigningKey,
        target_id: PersistedEngineObjectId,
    ) -> RevocationV2 {
        RevocationV2::new(
            RevocationTargetType::Token,
            target_id,
            RevocationReason::Compromised,
            DeterministicTimestamp(100),
            ZONE,
            issuer,
        )
        .expect("revocation")
    }

    fn chain(issuer: &SigningKey, head: &SigningKey) -> RevocationChainV2 {
        RevocationChainV2::new(ZONE)
            .expect("chain")
            .with_authorized_revocation_key(issuer.verification_key())
            .with_authorized_head_key(head.verification_key())
    }

    #[test]
    fn revocation_id_is_sha256_v2_and_recomputed() {
        let issuer = key(1);
        let mut revocation = revocation(
            &issuer,
            target(2, ObjectIdDerivationVersion::Sha256V2),
        );
        assert_eq!(
            revocation.revocation_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );
        revocation.verify(&issuer.verification_key()).expect("verify");
        revocation.revocation_id.object_id.0[0] ^= 1;
        assert!(revocation.validate_identity().is_err());
    }

    #[test]
    fn target_algorithm_is_part_of_revocation_identity() {
        let issuer = key(1);
        let legacy = revocation(&issuer, target(3, ObjectIdDerivationVersion::LegacyV1));
        let v2 = revocation(&issuer, target(3, ObjectIdDerivationVersion::Sha256V2));
        assert_ne!(legacy.revocation_id, v2.revocation_id);
        assert_ne!(legacy.signature, v2.signature);
    }

    #[test]
    fn chain_append_recomputes_event_and_head_identities() {
        let issuer = key(1);
        let head = key(2);
        let mut chain = chain(&issuer, &head);
        chain
            .append(
                revocation(&issuer, target(4, ObjectIdDerivationVersion::Sha256V2)),
                &head,
            )
            .expect("append");
        chain.verify_chain().expect("verify chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(
            chain.events()[0].event_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );
        assert_eq!(
            chain.head().expect("head").head_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        );
    }

    #[test]
    fn persisted_event_id_tampering_is_rejected_on_rebuild() {
        let issuer = key(1);
        let head_key = key(2);
        let mut original = chain(&issuer, &head_key);
        original
            .append(
                revocation(&issuer, target(5, ObjectIdDerivationVersion::Sha256V2)),
                &head_key,
            )
            .expect("append");
        let mut events = original.events.clone();
        events[0].event_id.object_id.0[0] ^= 1;
        let result = RevocationChainV2::rebuild_verified(
            ZONE,
            events,
            original.head.clone(),
            [issuer.verification_key()],
            [head_key.verification_key()],
            SecurityEpoch::GENESIS,
        );
        assert!(result.is_err());
    }

    #[test]
    fn predecessor_algorithm_tampering_is_rejected() {
        let issuer = key(1);
        let head_key = key(2);
        let mut original = chain(&issuer, &head_key);
        original
            .append(
                revocation(&issuer, target(6, ObjectIdDerivationVersion::Sha256V2)),
                &head_key,
            )
            .expect("append first");
        original
            .append(
                revocation(&issuer, target(7, ObjectIdDerivationVersion::Sha256V2)),
                &head_key,
            )
            .expect("append second");
        let mut events = original.events.clone();
        events[1]
            .prev_event
            .as_mut()
            .expect("predecessor")
            .derivation_version = ObjectIdDerivationVersion::LegacyV1;
        let result = RevocationChainV2::rebuild_verified(
            ZONE,
            events,
            original.head.clone(),
            [issuer.verification_key()],
            [head_key.verification_key()],
            SecurityEpoch::GENESIS,
        );
        assert!(result.is_err());
    }

    #[test]
    fn head_identity_tampering_is_rejected() {
        let issuer = key(1);
        let head_key = key(2);
        let mut original = chain(&issuer, &head_key);
        original
            .append(
                revocation(&issuer, target(8, ObjectIdDerivationVersion::Sha256V2)),
                &head_key,
            )
            .expect("append");
        let mut head = original.head.clone().expect("head");
        head.head_id.object_id.0[0] ^= 1;
        let result = RevocationChainV2::rebuild_verified(
            ZONE,
            original.events.clone(),
            Some(head),
            [issuer.verification_key()],
            [head_key.verification_key()],
            SecurityEpoch::GENESIS,
        );
        assert!(result.is_err());
    }

    #[test]
    fn lookup_is_algorithm_aware() {
        let issuer = key(1);
        let head_key = key(2);
        let mut chain = chain(&issuer, &head_key);
        let legacy_target = target(9, ObjectIdDerivationVersion::LegacyV1);
        chain
            .append(revocation(&issuer, legacy_target.clone()), &head_key)
            .expect("append");
        assert!(chain.is_revoked(&legacy_target));
        assert!(!chain.is_revoked(&target(9, ObjectIdDerivationVersion::Sha256V2)));
    }

    #[test]
    fn duplicate_exact_target_is_rejected() {
        let issuer = key(1);
        let head_key = key(2);
        let mut chain = chain(&issuer, &head_key);
        let target = target(10, ObjectIdDerivationVersion::Sha256V2);
        chain
            .append(revocation(&issuer, target.clone()), &head_key)
            .expect("first append");
        assert!(matches!(
            chain.append(revocation(&issuer, target.clone()), &head_key),
            Err(RevocationV2Error::DuplicateTarget { target_id }) if target_id == target
        ));
    }

    #[test]
    fn unauthorized_issuer_and_head_signer_fail_closed() {
        let issuer = key(1);
        let head_key = key(2);
        let stranger = key(3);
        let revocation = revocation(
            &issuer,
            target(11, ObjectIdDerivationVersion::Sha256V2),
        );
        let mut no_issuer = RevocationChainV2::new(ZONE)
            .expect("chain")
            .with_authorized_head_key(head_key.verification_key());
        assert!(matches!(
            no_issuer.append(revocation.clone(), &head_key),
            Err(RevocationV2Error::UnauthorizedIssuer { .. })
        ));
        let mut no_head = RevocationChainV2::new(ZONE)
            .expect("chain")
            .with_authorized_revocation_key(issuer.verification_key());
        assert!(matches!(
            no_head.append(revocation, &stranger),
            Err(RevocationV2Error::UnauthorizedHeadSigner { .. })
        ));
    }

    #[test]
    fn legacy_revocation_migration_verifies_id_signature_and_mapping() {
        let issuer = key(4);
        let issued_by = PrincipalId::from_verification_key(&issuer.verification_key());
        let raw_target = EngineObjectId([12; 32]);
        let revocation_id = crate::engine_object_id::derive_id(
            ObjectDomain::Revocation,
            ZONE,
            &revocation_schema_id(),
            raw_target.as_bytes(),
        )
        .expect("legacy id");
        let mut legacy = Revocation {
            revocation_id,
            target_type: RevocationTargetType::Token,
            target_id: raw_target,
            reason: RevocationReason::Administrative,
            issued_by,
            issued_at: DeterministicTimestamp(200),
            zone: ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        legacy.signature = sign_preimage(&issuer, &legacy.preimage_bytes()).expect("legacy sign");
        let migrated = RevocationV2::migrate_verified_legacy(&legacy, &issuer).expect("migrate");
        assert!(migrated.legacy_provenance.is_some());
        assert_eq!(
            migrated.target_id.derivation_version,
            ObjectIdDerivationVersion::LegacyV1
        );
        migrated.verify(&issuer.verification_key()).expect("verify v2");
    }

    #[test]
    fn legacy_id_tampering_is_rejected_before_migration() {
        let issuer = key(4);
        let issued_by = PrincipalId::from_verification_key(&issuer.verification_key());
        let mut legacy = Revocation {
            revocation_id: EngineObjectId([99; 32]),
            target_type: RevocationTargetType::Token,
            target_id: EngineObjectId([13; 32]),
            reason: RevocationReason::Administrative,
            issued_by,
            issued_at: DeterministicTimestamp(200),
            zone: ZONE.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        legacy.signature = sign_preimage(&issuer, &legacy.preimage_bytes()).expect("legacy sign");
        assert!(matches!(
            RevocationV2::migrate_verified_legacy(&legacy, &issuer),
            Err(RevocationV2Error::LegacyIdentityMismatch)
        ));
    }

    #[test]
    fn stale_head_is_rejected_after_epoch_advance() {
        let issuer = key(1);
        let head_key = key(2);
        let mut chain = chain(&issuer, &head_key);
        chain
            .append(
                revocation(&issuer, target(14, ObjectIdDerivationVersion::Sha256V2)),
                &head_key,
            )
            .expect("append");
        chain
            .set_current_epoch(SecurityEpoch::from_raw(1))
            .expect("advance epoch");
        assert!(matches!(
            chain.verify_chain(),
            Err(RevocationV2Error::StaleHead { .. })
        ));
    }
}
