use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, ObjectDomain,
    ObjectIdDerivationVersion, PersistedEngineObjectId, PersistedSchemaId, VersionedIdError,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    sign_preimage, verify_signature, Signature, SignaturePreimage, SigningKey, VerificationKey,
    SIGNATURE_SENTINEL,
};

use super::compat::{EncryptionPublicKey, OwnerKeyBundle};

const OWNER_KEY_BUNDLE_SCHEMA_V2: &[u8] = b"FrankenEngine.OwnerKeyBundle.sha256.v2";

pub const OWNER_KEY_BUNDLE_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.owner-key-bundle.persistence.v2";

/// Strictly verify the historical content-derived bundle ID as well as the
/// owner signature. The legacy inherent `verify()` authenticates the signed
/// bytes but does not recompute `id`.
pub fn verify_legacy_owner_key_bundle_strict(
    bundle: &OwnerKeyBundle,
    owner_vk: &VerificationKey,
) -> Result<(), OwnerKeyBundleV2Error> {
    let expected = OwnerKeyBundle::derive_id(
        &bundle.signing_key,
        &bundle.encryption_key,
        &bundle.issuance_key,
        bundle.epoch,
        bundle.sequence,
    )
    .map_err(|error| OwnerKeyBundleV2Error::LegacyVerification(error.to_string()))?;
    if expected != bundle.id {
        return Err(OwnerKeyBundleV2Error::LegacyIdentityMismatch);
    }
    bundle
        .verify(owner_vk)
        .map_err(|error| OwnerKeyBundleV2Error::LegacyVerification(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyOwnerKeyBundleProvenance {
    pub bundle: OwnerKeyBundle,
    pub owner_verification_key: VerificationKey,
}

impl LegacyOwnerKeyBundleProvenance {
    pub fn verify(&self) -> Result<(), OwnerKeyBundleV2Error> {
        verify_legacy_owner_key_bundle_strict(&self.bundle, &self.owner_verification_key)
    }

    pub fn owner_principal(&self) -> PrincipalId {
        PrincipalId::from_verification_key(&self.owner_verification_key)
    }

    pub fn content_hash(&self) -> Result<crate::hash_tiers::ContentHash, OwnerKeyBundleV2Error> {
        self.verify()?;
        let mut bytes = legacy_bundle_commitment(&self.bundle);
        bytes.extend_from_slice(self.owner_verification_key.as_bytes());
        Ok(crate::hash_tiers::ContentHash::compute(&bytes))
    }
}

/// Self-describing SHA-256-v2 binding of the root owner identity to the three
/// operational key roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKeyBundleV2 {
    pub persistence_schema: String,
    pub schema_version: PersistedSchemaId,
    pub id: PersistedEngineObjectId,
    pub owner_principal: PrincipalId,
    pub signing_key: VerificationKey,
    pub encryption_key: EncryptionPublicKey,
    pub issuance_key: VerificationKey,
    pub epoch: SecurityEpoch,
    pub sequence: u64,
    pub legacy_provenance: Option<LegacyOwnerKeyBundleProvenance>,
    pub owner_signature: Signature,
}

impl OwnerKeyBundleV2 {
    pub fn create_signed(
        owner_signing_key: &SigningKey,
        signing_key: VerificationKey,
        encryption_key: EncryptionPublicKey,
        issuance_key: VerificationKey,
        epoch: SecurityEpoch,
        sequence: u64,
    ) -> Result<Self, OwnerKeyBundleV2Error> {
        build_bundle_v2(
            owner_signing_key,
            signing_key,
            encryption_key,
            issuance_key,
            epoch,
            sequence,
            None,
        )
    }

    pub fn migrate_verified_legacy(
        legacy: &OwnerKeyBundle,
        owner_signing_key: &SigningKey,
    ) -> Result<Self, OwnerKeyBundleV2Error> {
        let provenance = LegacyOwnerKeyBundleProvenance {
            bundle: legacy.clone(),
            owner_verification_key: owner_signing_key.verification_key(),
        };
        provenance.verify()?;
        build_bundle_v2(
            owner_signing_key,
            legacy.signing_key.clone(),
            legacy.encryption_key.clone(),
            legacy.issuance_key.clone(),
            legacy.epoch,
            legacy.sequence,
            Some(provenance),
        )
    }

    pub fn validate_identity(&self) -> Result<(), OwnerKeyBundleV2Error> {
        if self.persistence_schema != OWNER_KEY_BUNDLE_PERSISTENCE_SCHEMA_V2 {
            return Err(OwnerKeyBundleV2Error::UnsupportedSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        require_v2_schema(&self.schema_version)?;
        require_v2_object(&self.id)?;
        validate_key_material(
            &self.owner_principal,
            &self.signing_key,
            &self.encryption_key,
            &self.issuance_key,
        )?;
        validate_legacy_mapping(self)?;
        let material = identity_material(
            &self.owner_principal,
            &self.signing_key,
            &self.encryption_key,
            &self.issuance_key,
            self.epoch,
            self.sequence,
            self.legacy_provenance.as_ref(),
        );
        verify_versioned_id(
            &self.id.to_versioned(),
            ObjectDomain::KeyBundle,
            "global",
            &self.schema_version.to_versioned(),
            &material,
        )?;
        Ok(())
    }

    pub fn verify(&self, owner_vk: &VerificationKey) -> Result<(), OwnerKeyBundleV2Error> {
        self.validate_identity()?;
        let actual_principal = PrincipalId::from_verification_key(owner_vk);
        if actual_principal != self.owner_principal {
            return Err(OwnerKeyBundleV2Error::OwnerPrincipalMismatch {
                expected: self.owner_principal.clone(),
                actual: actual_principal,
            });
        }
        verify_signature(owner_vk, &self.preimage_bytes(), &self.owner_signature)
            .map_err(|error| OwnerKeyBundleV2Error::SignatureInvalid(error.to_string()))
    }
}

impl SignaturePreimage for OwnerKeyBundleV2 {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::KeyBundle
    }

    fn signature_schema(&self) -> &SchemaHash {
        signature_schema_v2()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        signed_view(self)
    }
}

fn build_bundle_v2(
    owner_signing_key: &SigningKey,
    signing_key: VerificationKey,
    encryption_key: EncryptionPublicKey,
    issuance_key: VerificationKey,
    epoch: SecurityEpoch,
    sequence: u64,
    legacy_provenance: Option<LegacyOwnerKeyBundleProvenance>,
) -> Result<OwnerKeyBundleV2, OwnerKeyBundleV2Error> {
    if let Some(provenance) = &legacy_provenance {
        provenance.verify()?;
    }
    let owner_principal = PrincipalId::from_verification_key(&owner_signing_key.verification_key());
    validate_key_material(
        &owner_principal,
        &signing_key,
        &encryption_key,
        &issuance_key,
    )?;
    let schema = derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        OWNER_KEY_BUNDLE_SCHEMA_V2,
    )?;
    let material = identity_material(
        &owner_principal,
        &signing_key,
        &encryption_key,
        &issuance_key,
        epoch,
        sequence,
        legacy_provenance.as_ref(),
    );
    let id = derive_versioned_id(
        ObjectDomain::KeyBundle,
        "global",
        &schema,
        &material,
    )?;
    let mut bundle = OwnerKeyBundleV2 {
        persistence_schema: OWNER_KEY_BUNDLE_PERSISTENCE_SCHEMA_V2.to_string(),
        schema_version: PersistedSchemaId::from_versioned(schema),
        id: PersistedEngineObjectId::from_versioned(id),
        owner_principal,
        signing_key,
        encryption_key,
        issuance_key,
        epoch,
        sequence,
        legacy_provenance,
        owner_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    bundle.validate_identity()?;
    bundle.owner_signature = sign_preimage(owner_signing_key, &bundle.preimage_bytes())
        .map_err(|error| OwnerKeyBundleV2Error::SignatureInvalid(error.to_string()))?;
    Ok(bundle)
}

fn signature_schema_v2() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(OWNER_KEY_BUNDLE_SCHEMA_V2));
    &HASH
}

fn signed_view(bundle: &OwnerKeyBundleV2) -> CanonicalValue {
    let mut map = identity_map(
        &bundle.owner_principal,
        &bundle.signing_key,
        &bundle.encryption_key,
        &bundle.issuance_key,
        bundle.epoch,
        bundle.sequence,
        bundle.legacy_provenance.as_ref(),
    );
    insert_schema_id(&mut map, "schema_version", &bundle.schema_version);
    insert_object_id(&mut map, "id", &bundle.id);
    map.insert(
        "owner_signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );
    CanonicalValue::Map(map)
}

fn identity_material(
    owner_principal: &PrincipalId,
    signing_key: &VerificationKey,
    encryption_key: &EncryptionPublicKey,
    issuance_key: &VerificationKey,
    epoch: SecurityEpoch,
    sequence: u64,
    legacy_provenance: Option<&LegacyOwnerKeyBundleProvenance>,
) -> Vec<u8> {
    deterministic_serde::encode_value(&CanonicalValue::Map(identity_map(
        owner_principal,
        signing_key,
        encryption_key,
        issuance_key,
        epoch,
        sequence,
        legacy_provenance,
    )))
}

fn identity_map(
    owner_principal: &PrincipalId,
    signing_key: &VerificationKey,
    encryption_key: &EncryptionPublicKey,
    issuance_key: &VerificationKey,
    epoch: SecurityEpoch,
    sequence: u64,
    legacy_provenance: Option<&LegacyOwnerKeyBundleProvenance>,
) -> BTreeMap<String, CanonicalValue> {
    let mut map = BTreeMap::new();
    map.insert(
        "persistence_schema".to_string(),
        CanonicalValue::String(OWNER_KEY_BUNDLE_PERSISTENCE_SCHEMA_V2.to_string()),
    );
    map.insert(
        "owner_principal".to_string(),
        CanonicalValue::Bytes(owner_principal.as_bytes().to_vec()),
    );
    map.insert(
        "signing_key".to_string(),
        CanonicalValue::Bytes(signing_key.as_bytes().to_vec()),
    );
    map.insert(
        "encryption_key".to_string(),
        CanonicalValue::Bytes(encryption_key.as_bytes().to_vec()),
    );
    map.insert(
        "issuance_key".to_string(),
        CanonicalValue::Bytes(issuance_key.as_bytes().to_vec()),
    );
    map.insert("epoch".to_string(), CanonicalValue::U64(epoch.as_u64()));
    map.insert("sequence".to_string(), CanonicalValue::U64(sequence));
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

fn legacy_bundle_commitment(bundle: &OwnerKeyBundle) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(bundle.id.as_bytes());
    bytes.extend_from_slice(bundle.signing_key.as_bytes());
    bytes.extend_from_slice(bundle.encryption_key.as_bytes());
    bytes.extend_from_slice(bundle.issuance_key.as_bytes());
    bytes.extend_from_slice(&bundle.epoch.as_u64().to_be_bytes());
    bytes.extend_from_slice(&bundle.sequence.to_be_bytes());
    bytes.extend_from_slice(&bundle.owner_signature.to_bytes());
    bytes
}

fn validate_legacy_mapping(bundle: &OwnerKeyBundleV2) -> Result<(), OwnerKeyBundleV2Error> {
    let Some(provenance) = &bundle.legacy_provenance else {
        return Ok(());
    };
    provenance.verify()?;
    let legacy = &provenance.bundle;
    if bundle.owner_principal != provenance.owner_principal() {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch(
            "owner_principal",
        ));
    }
    if bundle.signing_key != legacy.signing_key {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("signing_key"));
    }
    if bundle.encryption_key != legacy.encryption_key {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch(
            "encryption_key",
        ));
    }
    if bundle.issuance_key != legacy.issuance_key {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("issuance_key"));
    }
    if bundle.epoch != legacy.epoch {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("epoch"));
    }
    if bundle.sequence != legacy.sequence {
        return Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("sequence"));
    }
    Ok(())
}

fn validate_key_material(
    owner_principal: &PrincipalId,
    signing_key: &VerificationKey,
    encryption_key: &EncryptionPublicKey,
    issuance_key: &VerificationKey,
) -> Result<(), OwnerKeyBundleV2Error> {
    if owner_principal.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(OwnerKeyBundleV2Error::InvalidOwnerPrincipal);
    }
    if signing_key.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(OwnerKeyBundleV2Error::InvalidRoleKey("signing"));
    }
    if encryption_key.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(OwnerKeyBundleV2Error::InvalidRoleKey("encryption"));
    }
    if issuance_key.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(OwnerKeyBundleV2Error::InvalidRoleKey("issuance"));
    }
    Ok(())
}

fn require_v2_schema(schema: &PersistedSchemaId) -> Result<(), OwnerKeyBundleV2Error> {
    if schema.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(OwnerKeyBundleV2Error::AlgorithmMismatch {
            field: "schema_version",
            actual: schema.derivation_version,
        });
    }
    let expected = PersistedSchemaId::from_versioned(derive_versioned_schema_id(
        ObjectIdDerivationVersion::Sha256V2,
        OWNER_KEY_BUNDLE_SCHEMA_V2,
    )?);
    if schema != &expected {
        return Err(OwnerKeyBundleV2Error::SchemaMismatch);
    }
    Ok(())
}

fn require_v2_object(id: &PersistedEngineObjectId) -> Result<(), OwnerKeyBundleV2Error> {
    if id.derivation_version != ObjectIdDerivationVersion::Sha256V2 {
        return Err(OwnerKeyBundleV2Error::AlgorithmMismatch {
            field: "id",
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
pub enum OwnerKeyBundleV2Error {
    InvalidOwnerPrincipal,
    InvalidRoleKey(&'static str),
    UnsupportedSchema {
        actual: String,
    },
    AlgorithmMismatch {
        field: &'static str,
        actual: ObjectIdDerivationVersion,
    },
    SchemaMismatch,
    OwnerPrincipalMismatch {
        expected: PrincipalId,
        actual: PrincipalId,
    },
    SignatureInvalid(String),
    LegacyVerification(String),
    LegacyIdentityMismatch,
    LegacyMappingMismatch(&'static str),
    Identity(VersionedIdError),
}

impl std::fmt::Display for OwnerKeyBundleV2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOwnerPrincipal => formatter.write_str("owner principal must not be zero"),
            Self::InvalidRoleKey(role) => write!(formatter, "{role} key must not be zero"),
            Self::UnsupportedSchema { actual } => {
                write!(formatter, "unsupported owner bundle schema {actual:?}")
            }
            Self::AlgorithmMismatch { field, actual } => {
                write!(formatter, "{field} uses {actual}; sha256_v2 is required")
            }
            Self::SchemaMismatch => formatter.write_str("owner bundle schema id does not match v2"),
            Self::OwnerPrincipalMismatch { expected, actual } => write!(
                formatter,
                "owner principal mismatch: expected {}, got {}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::SignatureInvalid(detail) => write!(formatter, "signature invalid: {detail}"),
            Self::LegacyVerification(detail) => write!(formatter, "legacy verification failed: {detail}"),
            Self::LegacyIdentityMismatch => formatter.write_str("legacy owner bundle id is not content-derived"),
            Self::LegacyMappingMismatch(field) => {
                write!(formatter, "legacy owner bundle migration mismatch at {field}")
            }
            Self::Identity(error) => write!(formatter, "owner bundle identity error: {error}"),
        }
    }
}

impl std::error::Error for OwnerKeyBundleV2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for OwnerKeyBundleV2Error {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid key")
    }

    fn encryption(seed: u8) -> EncryptionPublicKey {
        EncryptionPublicKey::from_bytes([seed; 32])
    }

    fn fresh(owner: &SigningKey) -> OwnerKeyBundleV2 {
        OwnerKeyBundleV2::create_signed(
            owner,
            key(2).verification_key(),
            encryption(3),
            key(4).verification_key(),
            SecurityEpoch::GENESIS,
            1,
        )
        .expect("v2 bundle")
    }

    #[test]
    fn v2_bundle_persists_owner_principal_and_sha256_identity() {
        let owner = key(1);
        let bundle = fresh(&owner);
        assert_eq!(
            bundle.owner_principal,
            PrincipalId::from_verification_key(&owner.verification_key())
        );
        assert_eq!(bundle.id.derivation_version, ObjectIdDerivationVersion::Sha256V2);
        bundle.verify(&owner.verification_key()).expect("verify");
    }

    #[test]
    fn signed_but_arbitrary_v2_id_is_rejected() {
        let owner = key(1);
        let mut bundle = fresh(&owner);
        bundle.id.object_id.0[0] ^= 1;
        bundle.owner_signature =
            sign_preimage(&owner, &bundle.preimage_bytes()).expect("resign arbitrary id");
        assert!(bundle.validate_identity().is_err());
    }

    #[test]
    fn wrong_owner_key_is_rejected_even_if_role_keys_match() {
        let owner = key(1);
        let bundle = fresh(&owner);
        assert!(matches!(
            bundle.verify(&key(9).verification_key()),
            Err(OwnerKeyBundleV2Error::OwnerPrincipalMismatch { .. })
        ));
    }

    #[test]
    fn strict_legacy_verifier_rejects_resigned_arbitrary_id() {
        let owner = key(1);
        let mut legacy = OwnerKeyBundle::create_signed(
            &owner,
            key(2).verification_key(),
            encryption(3),
            key(4).verification_key(),
            SecurityEpoch::GENESIS,
            1,
        )
        .expect("legacy bundle");
        legacy.id.0[0] ^= 1;
        let mut fields = BTreeMap::new();
        fields.insert(
            "id".to_string(),
            CanonicalValue::Bytes(legacy.id.as_bytes().to_vec()),
        );
        fields.insert(
            "signing_key".to_string(),
            CanonicalValue::Bytes(legacy.signing_key.as_bytes().to_vec()),
        );
        fields.insert(
            "encryption_key".to_string(),
            CanonicalValue::Bytes(legacy.encryption_key.as_bytes().to_vec()),
        );
        fields.insert(
            "issuance_key".to_string(),
            CanonicalValue::Bytes(legacy.issuance_key.as_bytes().to_vec()),
        );
        fields.insert(
            "epoch".to_string(),
            CanonicalValue::U64(legacy.epoch.as_u64()),
        );
        fields.insert("sequence".to_string(), CanonicalValue::U64(legacy.sequence));
        fields.insert(
            "owner_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        let preimage = crate::signature_preimage::build_preimage(
            ObjectDomain::KeyBundle,
            &super::super::compat::bundle_schema(),
            &CanonicalValue::Map(fields),
        );
        legacy.owner_signature = sign_preimage(&owner, &preimage).expect("resign legacy id");
        legacy.verify(&owner.verification_key()).expect("legacy signature alone passes");
        assert!(matches!(
            verify_legacy_owner_key_bundle_strict(&legacy, &owner.verification_key()),
            Err(OwnerKeyBundleV2Error::LegacyIdentityMismatch)
        ));
    }

    #[test]
    fn verified_legacy_bundle_migrates_with_owner_provenance() {
        let owner = key(1);
        let legacy = OwnerKeyBundle::create_signed(
            &owner,
            key(2).verification_key(),
            encryption(3),
            key(4).verification_key(),
            SecurityEpoch::GENESIS,
            1,
        )
        .expect("legacy bundle");
        let migrated = OwnerKeyBundleV2::migrate_verified_legacy(&legacy, &owner).expect("migrate");
        assert!(migrated.legacy_provenance.is_some());
        migrated.verify(&owner.verification_key()).expect("verify v2");
    }

    #[test]
    fn migrated_semantics_cannot_diverge_from_provenance() {
        let owner = key(1);
        let legacy = OwnerKeyBundle::create_signed(
            &owner,
            key(2).verification_key(),
            encryption(3),
            key(4).verification_key(),
            SecurityEpoch::GENESIS,
            1,
        )
        .expect("legacy bundle");
        let mut migrated =
            OwnerKeyBundleV2::migrate_verified_legacy(&legacy, &owner).expect("migrate");
        migrated.sequence = 2;
        assert!(matches!(
            migrated.validate_identity(),
            Err(OwnerKeyBundleV2Error::LegacyMappingMismatch("sequence"))
        ));
    }
}
