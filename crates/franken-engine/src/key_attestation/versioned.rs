use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, ObjectDomain,
    ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId, VersionedIdError,
};
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::principal_key_roles::KeyRole;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    sign_preimage, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

use super::compat::{
    attestation_schema_id, AttestationError, AttestationNonce, DevicePosture, DevicePostureVerifier,
    KeyAttestation,
};
use super::strict_store::NonceRegistry;

const ATTESTATION_SCHEMA_V2: &[u8] = b"FrankenEngine.KeyAttestation.sha256.v2";

pub const KEY_ATTESTATION_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.key-attestation.persistence.v2";
pub const KEY_ATTESTATION_STORE_SCHEMA_V2: &str =
    "frankenengine.key-attestation-store.persistence.v2";

/// Verified historical attestation retained as migration provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyKeyAttestationProvenance {
    pub attestation: KeyAttestation,
    pub owner_verification_key: VerificationKey,
}

impl LegacyKeyAttestationProvenance {
    pub fn verify(&self) -> Result<(), KeyAttestationV2Error> {
        validate_legacy_attestation(&self.attestation, &self.owner_verification_key)
    }

    pub fn content_hash(&self) -> Result<crate::hash_tiers::ContentHash, KeyAttestationV2Error> {
        self.verify()?;
        let mut bytes = self.attestation.preimage_bytes();
        bytes.extend_from_slice(&self.attestation.owner_signature.to_bytes());
        bytes.extend_from_slice(self.owner_verification_key.as_bytes());
        Ok(crate::hash_tiers::ContentHash::compute(&bytes))
    }
}

/// Input for a new v2 owner attestation.
///
/// `principal_id` is deliberately absent: it is derived from the owner root
/// key, making owner/principal spoofing unrepresentable through this constructor.
#[derive(Debug, Clone)]
pub struct CreateKeyAttestationV2Input<'a> {
    pub attested_key: VerificationKey,
    pub key_role: KeyRole,
    pub issued_at: DeterministicTimestamp,
    pub expires_at: DeterministicTimestamp,
    pub epoch: SecurityEpoch,
    pub nonce: AttestationNonce,
    pub device_posture: Option<DevicePosture>,
    pub zone: &'a str,
}

/// Owner-signed, self-describing SHA-256-v2 key attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestationV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub attestation_id: PersistedEngineObjectId,
    pub principal_id: PrincipalId,
    pub attested_key: VerificationKey,
    pub key_role: KeyRole,
    pub issued_at: DeterministicTimestamp,
    pub expires_at: DeterministicTimestamp,
    pub epoch: SecurityEpoch,
    pub nonce: AttestationNonce,
    pub device_posture: Option<DevicePosture>,
    pub owner_signature: Signature,
    pub zone: String,
    pub legacy_provenance: Option<LegacyKeyAttestationProvenance>,
}

impl KeyAttestationV2 {
    pub fn create_signed(
        owner_signing_key: &SigningKey,
        input: CreateKeyAttestationV2Input<'_>,
    ) -> Result<Self, KeyAttestationV2Error> {
        let principal_id = PrincipalId::from_verification_key(&owner_signing_key.verification_key());
        build_attestation_v2(
            owner_signing_key,
            principal_id,
            input.attested_key,
            input.key_role,
            input.issued_at,
            input.expires_at,
            input.epoch,
            input.nonce,
            input.device_posture,
            input.zone.to_string(),
            None,
        )
    }

    /// Verify historical identity/signature/owner binding before re-signing the
    /// same semantics under the v2 content identity.
    pub fn migrate_verified_legacy(
        legacy: &KeyAttestation,
        owner_signing_key: &SigningKey,
    ) -> Result<Self, KeyAttestationV2Error> {
        let provenance = LegacyKeyAttestationProvenance {
            attestation: legacy.clone(),
            owner_verification_key: owner_signing_key.verification_key(),
        };
        provenance.verify()?;
        build_attestation_v2(
            owner_signing_key,
            legacy.principal_id.clone(),
            legacy.attested_key.clone(),
            legacy.key_role,
            legacy.issued_at,
            legacy.expires_at,
            legacy.epoch,
            legacy.nonce,
            legacy.device_posture.clone(),
            legacy.zone.clone(),
            Some(provenance),
        )
    }

    pub fn validate_identity(&self) -> Result<(), KeyAttestationV2Error> {
        if self.persistence_schema != KEY_ATTESTATION_PERSISTENCE_SCHEMA_V2 {
            return Err(KeyAttestationV2Error::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_fields(
            &self.principal_id,
            &self.attested_key,
            self.issued_at,
            self.expires_at,
            self.nonce,
            &self.zone,
        )?;
        require_v2_schema(&self.schema_version)?;
        require_v2_object(&self.attestation_id)?;
        validate_legacy_mapping(self)?;
        let material = identity_material(
            &self.principal_id,
            &self.attested_key,
            self.key_role,
            self.issued_at,
            self.expires_at,
            self.epoch,
            self.nonce,
            self.device_posture.as_ref(),
            &self.zone,
            self.legacy_provenance.as_ref(),
        );
        verify_versioned_id(
            &self.attestation_id.to_versioned(),
            ObjectDomain::Attestation,
            &self.zone,
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify_owner_signature(
        &self,
        owner_vk: &VerificationKey,
    ) -> Result<(), KeyAttestationV2Error> {
        self.validate_identity()?;
        let owner_principal = PrincipalId::from_verification_key(owner_vk);
        if owner_principal != self.principal_id {
            return Err(KeyAttestationV2Error::OwnerPrincipalMismatch {
                expected: self.principal_id.clone(),
                actual: owner_principal,
            });
        }
        if *owner_vk == self.attested_key {
            return Err(KeyAttestationV2Error::SelfAttestationRejected);
        }
        verify_signature(owner_vk, &self.preimage_bytes(), &self.owner_signature)
            .map_err(|error| KeyAttestationV2Error::SignatureInvalid(error.to_string()))
    }

    pub fn is_expired(&self, current_time: DeterministicTimestamp) -> bool {
        current_time.0 > self.expires_at.0
    }
}

impl SignaturePreimage for KeyAttestationV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Attestation
    }

    fn signature_schema(&self) -> &SchemaHash {
        signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        signed_view(self)
    }
}

impl std::fmt::Display for KeyAttestationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "KeyAttestationV2({}:{}, principal={}, role={}, nonce={}, expires={})",
            self.attestation_id.derivation_version,
            self.attestation_id.to_hex(),
            self.principal_id.to_hex(),
            self.key_role,
            self.nonce,
            self.expires_at
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationEventTypeV2 {
    Registered {
        attestation_id: PersistedEngineObjectId,
        principal: PrincipalId,
    },
    Revoked {
        attestation_id: PersistedEngineObjectId,
        principal: PrincipalId,
    },
    RegistrationRejected {
        reason: String,
    },
    ExpiredPurged {
        count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEventV2 {
    pub event_type: AttestationEventTypeV2,
    pub zone: String,
    pub trace_id: String,
}

/// V2 lifecycle store. Authoritative attestation objects are serialized as a
/// sorted vector; principal indexes are derived in-memory and never persisted.
#[derive(Debug, Clone)]
pub struct AttestationStoreV2 {
    attestations: BTreeMap<PersistedEngineObjectId, KeyAttestationV2>,
    principal_index: BTreeMap<PrincipalId, BTreeSet<PersistedEngineObjectId>>,
    nonce_registry: NonceRegistry,
    audit_events: Vec<AttestationEventV2>,
    zone: String,
}

#[derive(Serialize, Deserialize)]
struct AttestationStoreV2Wire {
    persistence_schema: String,
    attestations: Vec<KeyAttestationV2>,
    nonce_registry: NonceRegistry,
    audit_events: Vec<AttestationEventV2>,
    zone: String,
}

impl Serialize for AttestationStoreV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        AttestationStoreV2Wire {
            persistence_schema: KEY_ATTESTATION_STORE_SCHEMA_V2.to_string(),
            attestations: self.attestations.values().cloned().collect(),
            nonce_registry: self.nonce_registry.clone(),
            audit_events: self.audit_events.clone(),
            zone: self.zone.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AttestationStoreV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AttestationStoreV2Wire::deserialize(deserializer)?;
        if wire.persistence_schema != KEY_ATTESTATION_STORE_SCHEMA_V2 {
            return Err(serde::de::Error::custom(format!(
                "unsupported attestation store schema {:?}",
                wire.persistence_schema
            )));
        }
        let mut store = Self {
            attestations: BTreeMap::new(),
            principal_index: BTreeMap::new(),
            nonce_registry: wire.nonce_registry,
            audit_events: wire.audit_events,
            zone: wire.zone,
        };
        for attestation in wire.attestations {
            let id = attestation.attestation_id.clone();
            if store.attestations.insert(id.clone(), attestation).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate persisted attestation {}:{}",
                    id.derivation_version,
                    id.to_hex()
                )));
            }
        }
        store
            .rebuild_and_validate_indexes()
            .map_err(serde::de::Error::custom)?;
        Ok(store)
    }
}

impl AttestationStoreV2 {
    pub fn new(zone: &str) -> Result<Self, KeyAttestationV2Error> {
        validate_zone(zone)?;
        Ok(Self {
            attestations: BTreeMap::new(),
            principal_index: BTreeMap::new(),
            nonce_registry: NonceRegistry::new(),
            audit_events: Vec::new(),
            zone: zone.to_string(),
        })
    }

    pub fn register(
        &mut self,
        attestation: KeyAttestationV2,
        owner_vk: &VerificationKey,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> Result<PersistedEngineObjectId, KeyAttestationV2Error> {
        if attestation.zone != self.zone {
            self.emit_event(
                AttestationEventTypeV2::RegistrationRejected {
                    reason: format!(
                        "zone mismatch: store={}, attestation={}",
                        self.zone, attestation.zone
                    ),
                },
                trace_id,
            );
            return Err(KeyAttestationV2Error::ZoneMismatch {
                expected: self.zone.clone(),
                actual: attestation.zone.clone(),
            });
        }
        attestation.verify_owner_signature(owner_vk)?;
        if attestation.is_expired(current_time) {
            return Err(KeyAttestationV2Error::Expired {
                expires_at: attestation.expires_at,
                current_time,
            });
        }
        self.nonce_registry
            .check_and_record(&attestation.principal_id, attestation.nonce)
            .map_err(KeyAttestationV2Error::LegacyStore)?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(KeyAttestationV2Error::DuplicateAttestation {
                attestation_id: attestation.attestation_id.clone(),
            });
        }
        let id = attestation.attestation_id.clone();
        let principal = attestation.principal_id.clone();
        self.principal_index
            .entry(principal.clone())
            .or_default()
            .insert(id.clone());
        self.attestations.insert(id.clone(), attestation);
        self.emit_event(
            AttestationEventTypeV2::Registered {
                attestation_id: id.clone(),
                principal,
            },
            trace_id,
        );
        Ok(id)
    }

    pub fn register_with_posture_verifier(
        &mut self,
        attestation: KeyAttestationV2,
        owner_vk: &VerificationKey,
        posture_verifier: &dyn DevicePostureVerifier,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> Result<PersistedEngineObjectId, KeyAttestationV2Error> {
        if let Some(posture) = &attestation.device_posture {
            posture_verifier
                .verify(posture)
                .map_err(KeyAttestationV2Error::LegacyStore)?;
        }
        self.register(attestation, owner_vk, current_time, trace_id)
    }

    pub fn validate_loaded(
        &self,
        owner_keys: &BTreeMap<PrincipalId, VerificationKey>,
    ) -> Result<(), KeyAttestationV2Error> {
        self.validate_structure()?;
        for attestation in self.attestations.values() {
            let owner_key = owner_keys.get(&attestation.principal_id).ok_or_else(|| {
                KeyAttestationV2Error::MissingOwnerKey {
                    principal: attestation.principal_id.clone(),
                }
            })?;
            attestation.verify_owner_signature(owner_key)?;
        }
        Ok(())
    }

    pub fn get(&self, id: &PersistedEngineObjectId) -> Option<&KeyAttestationV2> {
        self.attestations.get(id)
    }

    pub fn active_for_principal(
        &self,
        principal: &PrincipalId,
        current_time: DeterministicTimestamp,
    ) -> Vec<&KeyAttestationV2> {
        let Some(ids) = self.principal_index.get(principal) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| self.attestations.get(id))
            .filter(|attestation| !attestation.is_expired(current_time))
            .collect()
    }

    pub fn active_for_role(
        &self,
        principal: &PrincipalId,
        role: KeyRole,
        current_time: DeterministicTimestamp,
    ) -> Vec<&KeyAttestationV2> {
        self.active_for_principal(principal, current_time)
            .into_iter()
            .filter(|attestation| attestation.key_role == role)
            .collect()
    }

    pub fn revoke(
        &mut self,
        id: &PersistedEngineObjectId,
        trace_id: &str,
    ) -> Result<(), KeyAttestationV2Error> {
        let attestation = self
            .attestations
            .remove(id)
            .ok_or_else(|| KeyAttestationV2Error::NotFound {
                attestation_id: id.clone(),
            })?;
        if let Some(ids) = self.principal_index.get_mut(&attestation.principal_id) {
            ids.remove(id);
            if ids.is_empty() {
                self.principal_index.remove(&attestation.principal_id);
            }
        }
        self.emit_event(
            AttestationEventTypeV2::Revoked {
                attestation_id: id.clone(),
                principal: attestation.principal_id,
            },
            trace_id,
        );
        Ok(())
    }

    pub fn purge_expired(
        &mut self,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> usize {
        let ids = self
            .attestations
            .iter()
            .filter(|(_, attestation)| attestation.is_expired(current_time))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let count = ids.len();
        for id in ids {
            if let Some(attestation) = self.attestations.remove(&id)
                && let Some(principal_ids) = self.principal_index.get_mut(&attestation.principal_id)
            {
                principal_ids.remove(&id);
                if principal_ids.is_empty() {
                    self.principal_index.remove(&attestation.principal_id);
                }
            }
        }
        if count > 0 {
            self.emit_event(AttestationEventTypeV2::ExpiredPurged { count }, trace_id);
        }
        count
    }

    pub fn total_count(&self) -> usize {
        self.attestations.len()
    }

    pub fn principal_count(&self) -> usize {
        self.principal_index.len()
    }

    pub fn drain_events(&mut self) -> Vec<AttestationEventV2> {
        std::mem::take(&mut self.audit_events)
    }

    fn rebuild_and_validate_indexes(&mut self) -> Result<(), KeyAttestationV2Error> {
        self.principal_index.clear();
        for attestation in self.attestations.values() {
            attestation.validate_identity()?;
            if attestation.zone != self.zone {
                return Err(KeyAttestationV2Error::ZoneMismatch {
                    expected: self.zone.clone(),
                    actual: attestation.zone.clone(),
                });
            }
            let high_water = self.nonce_registry.high_water_for(&attestation.principal_id);
            if high_water < attestation.nonce.as_u64() {
                return Err(KeyAttestationV2Error::NonceHighWaterRollback {
                    principal: attestation.principal_id.clone(),
                    required: attestation.nonce.as_u64(),
                    actual: high_water,
                });
            }
            self.principal_index
                .entry(attestation.principal_id.clone())
                .or_default()
                .insert(attestation.attestation_id.clone());
        }
        validate_zone(&self.zone)
    }

    fn validate_structure(&self) -> Result<(), KeyAttestationV2Error> {
        validate_zone(&self.zone)?;
        let mut expected: BTreeMap<PrincipalId, BTreeSet<PersistedEngineObjectId>> = BTreeMap::new();
        for attestation in self.attestations.values() {
            attestation.validate_identity()?;
            if attestation.zone != self.zone {
                return Err(KeyAttestationV2Error::ZoneMismatch {
                    expected: self.zone.clone(),
                    actual: attestation.zone.clone(),
                });
            }
            let high_water = self.nonce_registry.high_water_for(&attestation.principal_id);
            if high_water < attestation.nonce.as_u64() {
                return Err(KeyAttestationV2Error::NonceHighWaterRollback {
                    principal: attestation.principal_id.clone(),
                    required: attestation.nonce.as_u64(),
                    actual: high_water,
                });
            }
            expected
                .entry(attestation.principal_id.clone())
                .or_default()
                .insert(attestation.attestation_id.clone());
        }
        if expected != self.principal_index {
            return Err(KeyAttestationV2Error::IndexMismatch);
        }
        Ok(())
    }

    fn emit_event(&mut self, event_type: AttestationEventTypeV2, trace_id: &str) {
        self.audit_events.push(AttestationEventV2 {
            event_type,
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn build_attestation_v2(
    owner_signing_key: &SigningKey,
    principal_id: PrincipalId,
    attested_key: VerificationKey,
    key_role: KeyRole,
    issued_at: DeterministicTimestamp,
    expires_at: DeterministicTimestamp,
    epoch: SecurityEpoch,
    nonce: AttestationNonce,
    device_posture: Option<DevicePosture>,
    zone: String,
    legacy_provenance: Option<LegacyKeyAttestationProvenance>,
) -> Result<KeyAttestationV2, KeyAttestationV2Error> {
    validate_fields(
        &principal_id,
        &attested_key,
        issued_at,
        expires_at,
        nonce,
        &zone,
    )?;
    let owner_vk = owner_signing_key.verification_key();
    let owner_principal = PrincipalId::from_verification_key(&owner_vk);
    if owner_principal != principal_id {
        return Err(KeyAttestationV2Error::OwnerPrincipalMismatch {
            expected: principal_id,
            actual: owner_principal,
        });
    }
    if owner_vk == attested_key {
        return Err(KeyAttestationV2Error::SelfAttestationRejected);
    }
    if let Some(provenance) = &legacy_provenance {
        provenance.verify()?;
    }

    let schema = derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        ATTESTATION_SCHEMA_V2,
    )?;
    let material = identity_material(
        &owner_principal,
        &attested_key,
        key_role,
        issued_at,
        expires_at,
        epoch,
        nonce,
        device_posture.as_ref(),
        &zone,
        legacy_provenance.as_ref(),
    );
    let attestation_id = derive_versioned_id(
        ObjectDomain::Attestation,
        &zone,
        &schema,
        &material,
    )?;
    let mut attestation = KeyAttestationV2 {
        persistence_schema: KEY_ATTESTATION_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        attestation_id: PersistedEngineObjectId::from_versioned(attestation_id),
        principal_id: owner_principal,
        attested_key,
        key_role,
        issued_at,
        expires_at,
        epoch,
        nonce,
        device_posture,
        owner_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        zone,
        legacy_provenance,
    };
    attestation.validate_identity()?;
    attestation.owner_signature = sign_preimage(owner_signing_key, &attestation.preimage_bytes())
        .map_err(|error| KeyAttestationV2Error::SignatureInvalid(error.to_string()))?;
    Ok(attestation)
}

fn validate_legacy_attestation(
    attestation: &KeyAttestation,
    owner_vk: &VerificationKey,
) -> Result<(), KeyAttestationV2Error> {
    validate_fields(
        &attestation.principal_id,
        &attestation.attested_key,
        attestation.issued_at,
        attestation.expires_at,
        attestation.nonce,
        &attestation.zone,
    )?;
    let owner_principal = PrincipalId::from_verification_key(owner_vk);
    if owner_principal != attestation.principal_id {
        return Err(KeyAttestationV2Error::OwnerPrincipalMismatch {
            expected: attestation.principal_id.clone(),
            actual: owner_principal,
        });
    }
    if *owner_vk == attestation.attested_key {
        return Err(KeyAttestationV2Error::SelfAttestationRejected);
    }
    let expected = crate::engine_object_id::derive_id(
        ObjectDomain::Attestation,
        &attestation.zone,
        &attestation_schema_id(),
        &legacy_identity_material(
            &attestation.principal_id,
            &attestation.attested_key,
            attestation.key_role,
            attestation.nonce,
        ),
    )
    .map_err(|error| KeyAttestationV2Error::LegacyVerification(error.to_string()))?;
    if expected != attestation.attestation_id {
        return Err(KeyAttestationV2Error::LegacyIdentityMismatch);
    }
    verify_signature(owner_vk, &attestation.preimage_bytes(), &attestation.owner_signature)
        .map_err(|error| KeyAttestationV2Error::LegacyVerification(error.to_string()))
}

fn legacy_identity_material(
    principal_id: &PrincipalId,
    attested_key: &VerificationKey,
    key_role: KeyRole,
    nonce: AttestationNonce,
) -> Vec<u8> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(principal_id.as_bytes());
    canonical.extend_from_slice(attested_key.as_bytes());
    canonical.extend_from_slice(key_role.derivation_domain());
    canonical.extend_from_slice(&nonce.as_u64().to_be_bytes());
    canonical
}

fn signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(ATTESTATION_SCHEMA_V2));
    &HASH
}

fn signed_view(attestation: &KeyAttestationV2) -> CanonicalValue {
    let mut map = identity_map(
        &attestation.principal_id,
        &attestation.attested_key,
        attestation.key_role,
        attestation.issued_at,
        attestation.expires_at,
        attestation.epoch,
        attestation.nonce,
        attestation.device_posture.as_ref(),
        &attestation.zone,
        attestation.legacy_provenance.as_ref(),
    );
    insert_schema_id(&mut map, "schema_version", &attestation.schema_version);
    insert_object_id(&mut map, "attestation_id", &attestation.attestation_id);
    map.insert(
        "owner_signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

#[allow(clippy::too_many_arguments)]
fn identity_material(
    principal_id: &PrincipalId,
    attested_key: &VerificationKey,
    key_role: KeyRole,
    issued_at: DeterministicTimestamp,
    expires_at: DeterministicTimestamp,
    epoch: SecurityEpoch,
    nonce: AttestationNonce,
    device_posture: Option<&DevicePosture>,
    zone: &str,
    legacy_provenance: Option<&LegacyKeyAttestationProvenance>,
) -> Vec<u8> {
    deterministic_serde::encode_value(&CanonicalValue::Map(identity_map(
        principal_id,
        attested_key,
        key_role,
        issued_at,
        expires_at,
        epoch,
        nonce,
        device_posture,
        zone,
        legacy_provenance,
    )))
}

#[allow(clippy::too_many_arguments)]
fn identity_map(
    principal_id: &PrincipalId,
    attested_key: &VerificationKey,
    key_role: KeyRole,
    issued_at: DeterministicTimestamp,
    expires_at: DeterministicTimestamp,
    epoch: SecurityEpoch,
    nonce: AttestationNonce,
    device_posture: Option<&DevicePosture>,
    zone: &str,
    legacy_provenance: Option<&LegacyKeyAttestationProvenance>,
) -> BTreeMap<String, CanonicalValue> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(KEY_ATTESTATION_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    map.insert(
        "principal_id".to_string(),
        CanonicalValue::Bytes(principal_id.as_bytes().to_vec()),
    );
    map.insert(
        "attested_key".to_string(),
        CanonicalValue::Bytes(attested_key.as_bytes().to_vec()),
    );
    map.insert(
        "key_role".to_string(),
        CanonicalValue::String(key_role.to_string()),
    );
    map.insert("issued_at".to_string(), CanonicalValue::U64(issued_at.0));
    map.insert("expires_at".to_string(), CanonicalValue::U64(expires_at.0));
    map.insert("epoch".to_string(), CanonicalValue::U64(epoch.as_u64()));
    map.insert("nonce".to_string(), CanonicalValue::U64(nonce.as_u64()));
    map.insert(
        "device_posture".to_string(),
        device_posture
            .map(|posture| {
                CanonicalValue::Map(BTreeMap::from([
                    (
                        "posture_type".to_string(),
                        CanonicalValue::String(posture.posture_type.clone()),
                    ),
                    (
                        "evidence".to_string(),
                        CanonicalValue::Bytes(posture.evidence.clone()),
                    ),
                ]))
            })
            .unwrap_or(CanonicalValue::Null),
    );
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

fn validate_legacy_mapping(attestation: &KeyAttestationV2) -> Result<(), KeyAttestationV2Error> {
    let Some(provenance) = &attestation.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.attestation;
    if attestation.principal_id != legacy.principal_id {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("principal_id"));
    }
    if attestation.attested_key != legacy.attested_key {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("attested_key"));
    }
    if attestation.key_role != legacy.key_role {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("key_role"));
    }
    if attestation.issued_at != legacy.issued_at {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("issued_at"));
    }
    if attestation.expires_at != legacy.expires_at {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("expires_at"));
    }
    if attestation.epoch != legacy.epoch {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("epoch"));
    }
    if attestation.nonce != legacy.nonce {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("nonce"));
    }
    if attestation.device_posture != legacy.device_posture {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("device_posture"));
    }
    if attestation.zone != legacy.zone {
        return Err(KeyAttestationV2Error::LegacyMappingMismatch("zone"));
    }
    Ok(())
}

fn validate_fields(
    principal_id: &PrincipalId,
    attested_key: &VerificationKey,
    issued_at: DeterministicTimestamp,
    expires_at: DeterministicTimestamp,
    nonce: AttestationNonce,
    zone: &str,
) -> Result<(), KeyAttestationV2Error> {
    validate_zone(zone)?;
    if expires_at.0 <= issued_at.0 {
        return Err(KeyAttestationV2Error::InvalidExpiry {
            issued_at,
            expires_at,
        });
    }
    if nonce.as_u64() == 0 {
        return Err(KeyAttestationV2Error::InvalidNonce);
    }
    if principal_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(KeyAttestationV2Error::InvalidPrincipal);
    }
    if attested_key.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(KeyAttestationV2Error::InvalidAttestedKey);
    }
    Ok(())
}

fn validate_zone(zone: &str) -> Result<(), KeyAttestationV2Error> {
    if zone.trim().is_empty() {
        return Err(KeyAttestationV2Error::EmptyZone);
    }
    Ok(())
}

fn require_v2_schema(schema: &PersistedSchemaId) -> Result<(), KeyAttestationV2Error> {
    if schema.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(KeyAttestationV2Error::AlgorithmMismatch {
            field: "schema_version",
            actual: schema.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        ATTESTATION_SCHEMA_V2,
    )?);
    if schema != &expected {
        return Err(KeyAttestationV2Error::SchemaMismatch);
    }
    Ok(())
}

fn require_v2_object(id: &PersistedEngineObjectId) -> Result<(), KeyAttestationV2Error> {
    if id.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(KeyAttestationV2Error::AlgorithmMismatch {
            field: "attestation_id",
            actual: id.derivation_version,
        });
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAttestationV2Error {
    EmptyZone,
    InvalidNonce,
    InvalidPrincipal,
    InvalidAttestedKey,
    InvalidExpiry {
        issued_at: DeterministicTimestamp,
        expires_at: DeterministicTimestamp,
    },
    SelfAttestationRejected,
    OwnerPrincipalMismatch {
        expected: PrincipalId,
        actual: PrincipalId,
    },
    UnsupportedSchema {
        actual: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch,
    SignatureInvalid(String),
    LegacyVerification(String),
    LegacyIdentityMismatch,
    LegacyMappingMismatch(&'static str),
    ZoneMismatch {
        expected: String,
        actual: String,
    },
    Expired {
        expires_at: DeterministicTimestamp,
        current_time: DeterministicTimestamp,
    },
    DuplicateAttestation {
        attestation_id: PersistedEngineObjectId,
    },
    NotFound {
        attestation_id: PersistedEngineObjectId,
    },
    MissingOwnerKey {
        principal: PrincipalId,
    },
    NonceHighWaterRollback {
        principal: PrincipalId,
        required: u64,
        actual: u64,
    },
    IndexMismatch,
    LegacyStore(AttestationError),
    Identity(VersionedIdError),
}

impl std::fmt::Display for KeyAttestationV2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyZone => formatter.write_str("attestation zone must not be empty"),
            Self::InvalidNonce => formatter.write_str("attestation nonce must be > 0"),
            Self::InvalidPrincipal => formatter.write_str("attestation principal must not be zero"),
            Self::InvalidAttestedKey => formatter.write_str("attested key must not be zero"),
            Self::InvalidExpiry {
                issued_at,
                expires_at,
            } => write!(formatter, "invalid expiry: {issued_at} >= {expires_at}"),
            Self::SelfAttestationRejected => formatter.write_str("self-attestation rejected"),
            Self::OwnerPrincipalMismatch { expected, actual } => write!(
                formatter,
                "owner principal mismatch: expected {}, got {}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported attestation persistence schema {actual:?}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch => formatter.write_str("attestation schema id does not match v2"),
            Self::SignatureInvalid(detail) => write!(formatter, "signature invalid: {detail}"),
            Self::LegacyVerification(detail) => write!(formatter, "legacy verification failed: {detail}"),
            Self::LegacyIdentityMismatch => formatter.write_str("legacy attestation_id is not content-derived"),
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy attestation migration mismatch at {field}")
            }
            Self::ZoneMismatch { expected, actual } => {
                write!(formatter, "zone mismatch: expected {expected:?}, got {actual:?}")
            }
            Self::Expired {
                expires_at,
                current_time,
            } => write!(formatter, "attestation expired at {expires_at}; now {current_time}"),
            Self::DuplicateAttestation { attestation_id } => write!(
                formatter,
                "duplicate attestation {}:{}",
                attestation_id.derivation_version,
                attestation_id.to_hex()
            ),
            Self::NotFound { attestation_id } => write!(
                formatter,
                "attestation not found {}:{}",
                attestation_id.derivation_version,
                attestation_id.to_hex()
            ),
            Self::MissingOwnerKey { principal } => {
                write!(formatter, "missing owner key for principal {}", principal.to_hex())
            }
            Self::NonceHighWaterRollback {
                principal,
                required,
                actual,
            } => write!(
                formatter,
                "nonce high-water rollback for {}: required >= {required}, got {actual}",
                principal.to_hex()
            ),
            Self::IndexMismatch => formatter.write_str("attestation principal index mismatch"),
            Self::LegacyStore(error) => write!(formatter, "legacy store validation: {error}"),
            Self::Identity(error) => write!(formatter, "attestation identity error: {error}"),
        }
    }
}

impl std::error::Error for KeyAttestationV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LegacyStore(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for KeyAttestationV2Error {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "owner-zone";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid key")
    }

    fn input(attested_key: VerificationKey, nonce: u64) -> CreateKeyAttestationV2Input<'static> {
        CreateKeyAttestationV2Input {
            attested_key,
            key_role: KeyRole::Signing,
            issued_at: DeterministicTimestamp(10),
            expires_at: DeterministicTimestamp(100),
            epoch: SecurityEpoch::GENESIS,
            nonce: AttestationNonce::from_counter(nonce),
            device_posture: None,
            zone: ZONE,
        }
    }

    fn fresh(owner: &SigningKey, nonce: u64) -> KeyAttestationV2 {
        KeyAttestationV2::create_signed(owner, input(key(9).verification_key(), nonce))
            .expect("attestation")
    }

    #[test]
    fn owner_principal_is_derived_not_caller_supplied() {
        let owner = key(1);
        let attestation = fresh(&owner, 1);
        assert_eq!(
            attestation.principal_id,
            PrincipalId::from_verification_key(&owner.verification_key())
        );
    }

    #[test]
    fn full_semantics_are_bound_into_v2_identity() {
        let owner = key(1);
        let mut attestation = fresh(&owner, 1);
        attestation.expires_at = DeterministicTimestamp(101);
        assert!(attestation.validate_identity().is_err());
    }

    #[test]
    fn self_attestation_is_unrepresentable_through_constructor() {
        let owner = key(1);
        assert!(matches!(
            KeyAttestationV2::create_signed(&owner, input(owner.verification_key(), 1)),
            Err(KeyAttestationV2Error::SelfAttestationRejected)
        ));
    }

    #[test]
    fn v2_store_roundtrips_as_json_without_map_key_encoding() {
        let owner = key(1);
        let attestation = fresh(&owner, 1);
        let principal = attestation.principal_id.clone();
        let mut store = AttestationStoreV2::new(ZONE).expect("store");
        store
            .register(
                attestation.clone(),
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "register",
            )
            .expect("register");
        let encoded = serde_json::to_vec(&store).expect("JSON serialize store");
        let decoded: AttestationStoreV2 = serde_json::from_slice(&encoded).expect("JSON deserialize store");
        let owners = BTreeMap::from([(principal, owner.verification_key())]);
        decoded.validate_loaded(&owners).expect("validate loaded");
        assert_eq!(decoded.total_count(), 1);
    }

    #[test]
    fn duplicate_attestation_vector_entries_fail_deserialization() {
        let owner = key(1);
        let attestation = fresh(&owner, 1);
        let mut nonce_registry = NonceRegistry::new();
        nonce_registry
            .check_and_record(&attestation.principal_id, attestation.nonce)
            .expect("nonce");
        let wire = AttestationStoreV2Wire {
            persistence_schema: KEY_ATTESTATION_STORE_SCHEMA_V2.to_string(),
            attestations: vec![attestation.clone(), attestation],
            nonce_registry,
            audit_events: Vec::new(),
            zone: ZONE.to_string(),
        };
        let encoded = serde_json::to_vec(&wire).expect("serialize wire");
        assert!(serde_json::from_slice::<AttestationStoreV2>(&encoded).is_err());
    }

    #[test]
    fn legacy_migration_verifies_owner_binding_id_and_signature() {
        let owner = key(1);
        let legacy = KeyAttestation::create_signed(
            &owner,
            super::super::compat::CreateAttestationInput {
                principal_id: PrincipalId::from_verification_key(&owner.verification_key()),
                attested_key: key(9).verification_key(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(10),
                expires_at: DeterministicTimestamp(100),
                epoch: SecurityEpoch::GENESIS,
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: ZONE,
            },
        )
        .expect("legacy");
        let migrated = KeyAttestationV2::migrate_verified_legacy(&legacy, &owner).expect("migrate");
        assert!(migrated.legacy_provenance.is_some());
        migrated
            .verify_owner_signature(&owner.verification_key())
            .expect("verify v2");
    }

    #[test]
    fn legacy_id_tampering_is_rejected_even_when_resigned() {
        let owner = key(1);
        let mut legacy = KeyAttestation::create_signed(
            &owner,
            super::super::compat::CreateAttestationInput {
                principal_id: PrincipalId::from_verification_key(&owner.verification_key()),
                attested_key: key(9).verification_key(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(10),
                expires_at: DeterministicTimestamp(100),
                epoch: SecurityEpoch::GENESIS,
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: ZONE,
            },
        )
        .expect("legacy");
        legacy.attestation_id.0[0] ^= 1;
        legacy.owner_signature =
            sign_preimage(&owner, &legacy.preimage_bytes()).expect("resign bad legacy id");
        assert!(matches!(
            KeyAttestationV2::migrate_verified_legacy(&legacy, &owner),
            Err(KeyAttestationV2Error::LegacyIdentityMismatch)
        ));
    }

    #[test]
    fn migrated_fields_cannot_diverge_from_provenance() {
        let owner = key(1);
        let legacy = KeyAttestation::create_signed(
            &owner,
            super::super::compat::CreateAttestationInput {
                principal_id: PrincipalId::from_verification_key(&owner.verification_key()),
                attested_key: key(9).verification_key(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(10),
                expires_at: DeterministicTimestamp(100),
                epoch: SecurityEpoch::GENESIS,
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: ZONE,
            },
        )
        .expect("legacy");
        let mut migrated =
            KeyAttestationV2::migrate_verified_legacy(&legacy, &owner).expect("migrate");
        migrated.epoch = SecurityEpoch::from_raw(1);
        assert!(matches!(
            migrated.validate_identity(),
            Err(KeyAttestationV2Error::LegacyMappingMismatch("epoch"))
        ));
    }
}
