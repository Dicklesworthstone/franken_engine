use std::collections::BTreeSet;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::capability::RuntimeCapability;
use crate::engine_object_id::{
    derive_versioned_id, derive_versioned_schema_id, verify_versioned_id, EngineObjectId,
    ObjectDomain, ObjectIdDerivationVersion, PersistedEngineObjectId,
    VersionedEngineObjectId, VersionedIdError,
};

use super::{TrustZone, TrustZoneClass};

const LEGACY_TRUST_ZONE_SCHEMA: &[u8] = b"frankenengine.trust-zone.v1";
const VERSIONED_TRUST_ZONE_SCHEMA: &[u8] = b"frankenengine.trust-zone.persistence.v2";

/// Stable outer schema for self-describing persisted trust-zone records.
pub const TRUST_ZONE_PERSISTENCE_SCHEMA_V2: &str =
    "frankenengine.trust-zone.persistence.v2";

/// Self-describing persistence model for trust-zone metadata.
///
/// Legacy `TrustZone` JSON remains readable. Re-serialization emits this v2
/// outer schema while preserving legacy object-ID bytes. New SHA-256 identities
/// bind all policy-bearing fields and the parent ID's derivation version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersistedTrustZone {
    pub persistence_schema: String,
    pub zone_id: PersistedEngineObjectId,
    pub zone_name: String,
    pub class: TrustZoneClass,
    pub parent_zone: Option<PersistedEngineObjectId>,
    pub policy_version: u64,
    pub created_by: String,
    pub declared_ceiling: BTreeSet<RuntimeCapability>,
    pub effective_ceiling: BTreeSet<RuntimeCapability>,
}

impl PersistedTrustZone {
    /// Construct a new record and derive its identity under the selected
    /// algorithm. `Sha256V2` binds every field carried by this record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        derivation_version: ObjectIdDerivationVersion,
        zone_name: impl Into<String>,
        class: TrustZoneClass,
        parent_zone: Option<PersistedEngineObjectId>,
        policy_version: u64,
        created_by: impl Into<String>,
        declared_ceiling: BTreeSet<RuntimeCapability>,
        effective_ceiling: BTreeSet<RuntimeCapability>,
    ) -> Result<Self, TrustZonePersistenceError> {
        let zone_name = zone_name.into();
        let created_by = created_by.into();
        validate_policy_fields(
            &zone_name,
            &created_by,
            &declared_ceiling,
            &effective_ceiling,
        )?;
        let zone_id = derive_persisted_trust_zone_id(
            derivation_version,
            &zone_name,
            class,
            parent_zone.as_ref(),
            policy_version,
            &created_by,
            &declared_ceiling,
            &effective_ceiling,
        )?;
        let record = Self {
            persistence_schema: TRUST_ZONE_PERSISTENCE_SCHEMA_V2.to_string(),
            zone_id,
            zone_name,
            class,
            parent_zone,
            policy_version,
            created_by,
            declared_ceiling,
            effective_ceiling,
        };
        record.validate()?;
        Ok(record)
    }

    /// Upgrade a historical runtime record into the self-describing outer
    /// schema. The historical identity is verified under legacy-v1 before the
    /// record is accepted.
    pub fn from_legacy_runtime(zone: &TrustZone) -> Result<Self, TrustZonePersistenceError> {
        let record = Self {
            persistence_schema: TRUST_ZONE_PERSISTENCE_SCHEMA_V2.to_string(),
            zone_id: PersistedEngineObjectId::legacy(zone.zone_id.clone()),
            zone_name: zone.zone_name.clone(),
            class: zone.class,
            parent_zone: zone
                .parent_zone
                .clone()
                .map(PersistedEngineObjectId::legacy),
            policy_version: zone.policy_version,
            created_by: zone.created_by.clone(),
            declared_ceiling: zone.declared_ceiling.clone(),
            effective_ceiling: zone.effective_ceiling.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Verify structural invariants and re-derive the zone identity using only
    /// the persisted algorithm tag. No cross-version fallback is attempted.
    pub fn validate(&self) -> Result<(), TrustZonePersistenceError> {
        if self.persistence_schema != TRUST_ZONE_PERSISTENCE_SCHEMA_V2 {
            return Err(TrustZonePersistenceError::UnsupportedPersistenceSchema {
                actual: self.persistence_schema.clone(),
            });
        }
        validate_policy_fields(
            &self.zone_name,
            &self.created_by,
            &self.declared_ceiling,
            &self.effective_ceiling,
        )?;
        if self.parent_zone.as_ref().is_some_and(|parent| parent == &self.zone_id) {
            return Err(TrustZonePersistenceError::SelfParent {
                zone_name: self.zone_name.clone(),
            });
        }
        verify_persisted_trust_zone_id(self)
    }

    /// True only when the selected identity algorithm binds the complete
    /// persisted record. Legacy-v1 is intentionally preserved but historically
    /// covered only class, policy version, name, and parent raw bytes.
    pub const fn identity_covers_full_record(&self) -> bool {
        matches!(
            self.zone_id.derivation_version,
            ObjectIdDerivationVersion::Sha256V2
        )
    }

    /// Produce the historical unversioned runtime shape.
    ///
    /// This is intentionally named as a view: it drops algorithm metadata and
    /// must not be persisted or signed again without retaining this record.
    pub fn to_unversioned_runtime_view(&self) -> TrustZone {
        TrustZone {
            zone_id: self.zone_id.object_id.clone(),
            zone_name: self.zone_name.clone(),
            class: self.class,
            parent_zone: self
                .parent_zone
                .as_ref()
                .map(|parent| parent.object_id.clone()),
            policy_version: self.policy_version,
            created_by: self.created_by.clone(),
            declared_ceiling: self.declared_ceiling.clone(),
            effective_ceiling: self.effective_ceiling.clone(),
        }
    }
}

impl TryFrom<&TrustZone> for PersistedTrustZone {
    type Error = TrustZonePersistenceError;

    fn try_from(value: &TrustZone) -> Result<Self, Self::Error> {
        Self::from_legacy_runtime(value)
    }
}

impl<'de> Deserialize<'de> for PersistedTrustZone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = match PersistedTrustZoneRepr::deserialize(deserializer)? {
            PersistedTrustZoneRepr::V2(record) => record.into(),
            PersistedTrustZoneRepr::Legacy(zone) => Self {
                persistence_schema: TRUST_ZONE_PERSISTENCE_SCHEMA_V2.to_string(),
                zone_id: PersistedEngineObjectId::legacy(zone.zone_id),
                zone_name: zone.zone_name,
                class: zone.class,
                parent_zone: zone.parent_zone.map(PersistedEngineObjectId::legacy),
                policy_version: zone.policy_version,
                created_by: zone.created_by,
                declared_ceiling: zone.declared_ceiling,
                effective_ceiling: zone.effective_ceiling,
            },
        };
        record.validate().map_err(D::Error::custom)?;
        Ok(record)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PersistedTrustZoneRepr {
    V2(PersistedTrustZoneV2Repr),
    Legacy(TrustZone),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedTrustZoneV2Repr {
    persistence_schema: String,
    zone_id: PersistedEngineObjectId,
    zone_name: String,
    class: TrustZoneClass,
    parent_zone: Option<PersistedEngineObjectId>,
    policy_version: u64,
    created_by: String,
    declared_ceiling: BTreeSet<RuntimeCapability>,
    effective_ceiling: BTreeSet<RuntimeCapability>,
}

impl From<PersistedTrustZoneV2Repr> for PersistedTrustZone {
    fn from(value: PersistedTrustZoneV2Repr) -> Self {
        Self {
            persistence_schema: value.persistence_schema,
            zone_id: value.zone_id,
            zone_name: value.zone_name,
            class: value.class,
            parent_zone: value.parent_zone,
            policy_version: value.policy_version,
            created_by: value.created_by,
            declared_ceiling: value.declared_ceiling,
            effective_ceiling: value.effective_ceiling,
        }
    }
}

/// Derive a trust-zone ID under an explicit algorithm.
///
/// Legacy-v1 reproduces the exact historical preimage. SHA-256-v2 uses a new
/// schema and binds every policy-bearing field plus the parent's algorithm tag.
#[allow(clippy::too_many_arguments)]
pub fn derive_persisted_trust_zone_id(
    derivation_version: ObjectIdDerivationVersion,
    zone_name: &str,
    class: TrustZoneClass,
    parent_zone: Option<&PersistedEngineObjectId>,
    policy_version: u64,
    created_by: &str,
    declared_ceiling: &BTreeSet<RuntimeCapability>,
    effective_ceiling: &BTreeSet<RuntimeCapability>,
) -> Result<PersistedEngineObjectId, TrustZonePersistenceError> {
    validate_policy_fields(
        zone_name,
        created_by,
        declared_ceiling,
        effective_ceiling,
    )?;
    let schema_definition = match derivation_version {
        ObjectIdDerivationVersion::LegacyV1 => LEGACY_TRUST_ZONE_SCHEMA,
        ObjectIdDerivationVersion::Sha256V2 => VERSIONED_TRUST_ZONE_SCHEMA,
    };
    let schema = derive_versioned_schema_id(derivation_version, schema_definition)?;
    let canonical = trust_zone_identity_preimage(
        derivation_version,
        zone_name,
        class,
        parent_zone,
        policy_version,
        created_by,
        declared_ceiling,
        effective_ceiling,
    )?;
    let object_id = derive_versioned_id(
        ObjectDomain::PolicyObject,
        zone_name,
        &schema,
        &canonical,
    )?;
    Ok(PersistedEngineObjectId::from_versioned(object_id))
}

fn verify_persisted_trust_zone_id(
    record: &PersistedTrustZone,
) -> Result<(), TrustZonePersistenceError> {
    let version = record.zone_id.derivation_version;
    let schema_definition = match version {
        ObjectIdDerivationVersion::LegacyV1 => LEGACY_TRUST_ZONE_SCHEMA,
        ObjectIdDerivationVersion::Sha256V2 => VERSIONED_TRUST_ZONE_SCHEMA,
    };
    let schema = derive_versioned_schema_id(version, schema_definition)?;
    let canonical = trust_zone_identity_preimage(
        version,
        &record.zone_name,
        record.class,
        record.parent_zone.as_ref(),
        record.policy_version,
        &record.created_by,
        &record.declared_ceiling,
        &record.effective_ceiling,
    )?;
    verify_versioned_id(
        &record.zone_id.to_versioned(),
        ObjectDomain::PolicyObject,
        &record.zone_name,
        &schema,
        &canonical,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn trust_zone_identity_preimage(
    derivation_version: ObjectIdDerivationVersion,
    zone_name: &str,
    class: TrustZoneClass,
    parent_zone: Option<&PersistedEngineObjectId>,
    policy_version: u64,
    created_by: &str,
    declared_ceiling: &BTreeSet<RuntimeCapability>,
    effective_ceiling: &BTreeSet<RuntimeCapability>,
) -> Result<Vec<u8>, TrustZonePersistenceError> {
    if derivation_version == ObjectIdDerivationVersion::LegacyV1 {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(class.as_str().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(&policy_version.to_be_bytes());
        canonical.push(0);
        canonical.extend_from_slice(zone_name.as_bytes());
        if let Some(parent) = parent_zone {
            canonical.extend_from_slice(parent.as_bytes());
        }
        return Ok(canonical);
    }

    let mut canonical = Vec::new();
    append_length_prefixed(&mut canonical, "zone_name", zone_name.as_bytes())?;
    append_length_prefixed(&mut canonical, "class", class.as_str().as_bytes())?;
    canonical.extend_from_slice(&policy_version.to_be_bytes());
    append_length_prefixed(&mut canonical, "created_by", created_by.as_bytes())?;
    append_capability_set(&mut canonical, "declared_ceiling", declared_ceiling)?;
    append_capability_set(&mut canonical, "effective_ceiling", effective_ceiling)?;
    match parent_zone {
        Some(parent) => {
            canonical.push(1);
            append_length_prefixed(
                &mut canonical,
                "parent_derivation_version",
                parent.derivation_version.as_str().as_bytes(),
            )?;
            canonical.extend_from_slice(parent.as_bytes());
        }
        None => canonical.push(0),
    }
    Ok(canonical)
}

fn append_capability_set(
    output: &mut Vec<u8>,
    field: &'static str,
    capabilities: &BTreeSet<RuntimeCapability>,
) -> Result<(), TrustZonePersistenceError> {
    let count = u32::try_from(capabilities.len()).map_err(|_| {
        TrustZonePersistenceError::LengthOverflow {
            field: field.to_string(),
            length: capabilities.len(),
        }
    })?;
    output.extend_from_slice(&count.to_be_bytes());
    for capability in capabilities {
        let name = capability.to_string();
        append_length_prefixed(output, field, name.as_bytes())?;
    }
    Ok(())
}

fn append_length_prefixed(
    output: &mut Vec<u8>,
    field: impl Into<String>,
    bytes: &[u8],
) -> Result<(), TrustZonePersistenceError> {
    let field = field.into();
    let length = u32::try_from(bytes.len()).map_err(|_| {
        TrustZonePersistenceError::LengthOverflow {
            field: field.clone(),
            length: bytes.len(),
        }
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_policy_fields(
    zone_name: &str,
    created_by: &str,
    declared_ceiling: &BTreeSet<RuntimeCapability>,
    effective_ceiling: &BTreeSet<RuntimeCapability>,
) -> Result<(), TrustZonePersistenceError> {
    if zone_name.trim().is_empty() {
        return Err(TrustZonePersistenceError::EmptyField { field: "zone_name" });
    }
    if created_by.trim().is_empty() {
        return Err(TrustZonePersistenceError::EmptyField { field: "created_by" });
    }
    if !effective_ceiling.is_subset(declared_ceiling) {
        return Err(TrustZonePersistenceError::EffectiveCeilingExceedsDeclared);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustZonePersistenceError {
    UnsupportedPersistenceSchema { actual: String },
    EmptyField { field: &'static str },
    EffectiveCeilingExceedsDeclared,
    SelfParent { zone_name: String },
    LengthOverflow { field: String, length: usize },
    Identity(VersionedIdError),
}

impl std::fmt::Display for TrustZonePersistenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPersistenceSchema { actual } => write!(
                formatter,
                "unsupported trust-zone persistence schema {actual:?}"
            ),
            Self::EmptyField { field } => write!(formatter, "{field} must not be empty"),
            Self::EffectiveCeilingExceedsDeclared => formatter.write_str(
                "effective_ceiling must be a subset of declared_ceiling",
            ),
            Self::SelfParent { zone_name } => {
                write!(formatter, "trust zone {zone_name:?} cannot be its own parent")
            }
            Self::LengthOverflow { field, length } => write!(
                formatter,
                "{field} length {length} exceeds u32 identity-preimage encoding"
            ),
            Self::Identity(error) => write!(formatter, "trust-zone identity invalid: {error}"),
        }
    }
}

impl std::error::Error for TrustZonePersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VersionedIdError> for TrustZonePersistenceError {
    fn from(value: VersionedIdError) -> Self {
        Self::Identity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(values: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
        values.iter().copied().collect()
    }

    fn valid_sets() -> (
        BTreeSet<RuntimeCapability>,
        BTreeSet<RuntimeCapability>,
    ) {
        (
            capabilities(&[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]),
            capabilities(&[RuntimeCapability::VmDispatch]),
        )
    }

    fn legacy_runtime_zone() -> TrustZone {
        let (declared, effective) = valid_sets();
        let persisted = PersistedTrustZone::new(
            ObjectIdDerivationVersion::LegacyV1,
            "team",
            TrustZoneClass::Team,
            None,
            7,
            "maintainer",
            declared.clone(),
            effective.clone(),
        )
        .expect("legacy persisted zone");
        persisted.to_unversioned_runtime_view()
    }

    #[test]
    fn historical_json_decodes_as_verified_legacy_identity() {
        let legacy = legacy_runtime_zone();
        let old_json = serde_json::to_vec(&legacy).expect("legacy JSON");
        let migrated: PersistedTrustZone =
            serde_json::from_slice(&old_json).expect("migrate legacy JSON");
        assert_eq!(
            migrated.zone_id.derivation_version,
            ObjectIdDerivationVersion::LegacyV1
        );
        assert!(migrated.parent_zone.is_none());
        assert!(!migrated.identity_covers_full_record());
        migrated.validate().expect("legacy identity remains valid");

        let migrated_json = serde_json::to_value(&migrated).expect("v2 outer JSON");
        assert_eq!(
            migrated_json["persistence_schema"],
            TRUST_ZONE_PERSISTENCE_SCHEMA_V2
        );
        assert!(migrated_json["zone_id"].is_array());
    }

    #[test]
    fn sha256_v2_roundtrip_binds_full_record_and_parent_version() {
        let (declared, effective) = valid_sets();
        let parent = PersistedEngineObjectId::legacy(EngineObjectId([5; 32]));
        let record = PersistedTrustZone::new(
            ObjectIdDerivationVersion::Sha256V2,
            "team",
            TrustZoneClass::Team,
            Some(parent),
            9,
            "maintainer",
            declared,
            effective,
        )
        .expect("v2 zone");
        assert!(record.identity_covers_full_record());
        let value = serde_json::to_value(&record).expect("serialize v2 zone");
        assert_eq!(value["zone_id"]["derivation_version"], "sha256_v2");
        assert!(value["parent_zone"].is_array());
        let decoded: PersistedTrustZone =
            serde_json::from_value(value).expect("deserialize v2 zone");
        assert_eq!(decoded, record);
    }

    #[test]
    fn tampered_policy_metadata_fails_identity_verification() {
        let (declared, effective) = valid_sets();
        let record = PersistedTrustZone::new(
            ObjectIdDerivationVersion::Sha256V2,
            "team",
            TrustZoneClass::Team,
            None,
            9,
            "maintainer",
            declared,
            effective,
        )
        .expect("v2 zone");
        let mut value = serde_json::to_value(record).expect("serialize zone");
        value["created_by"] = serde_json::Value::String("attacker".to_string());
        assert!(serde_json::from_value::<PersistedTrustZone>(value).is_err());
    }

    #[test]
    fn parent_derivation_version_is_identity_bound() {
        let (declared, effective) = valid_sets();
        let raw = EngineObjectId([8; 32]);
        let legacy_parent = PersistedEngineObjectId::legacy(raw.clone());
        let v2_parent = PersistedEngineObjectId::from_versioned(
            VersionedEngineObjectId::new(ObjectIdDerivationVersion::Sha256V2, raw),
        );
        let legacy_parent_child = derive_persisted_trust_zone_id(
            ObjectIdDerivationVersion::Sha256V2,
            "team",
            TrustZoneClass::Team,
            Some(&legacy_parent),
            9,
            "maintainer",
            &declared,
            &effective,
        )
        .expect("child with legacy parent");
        let v2_parent_child = derive_persisted_trust_zone_id(
            ObjectIdDerivationVersion::Sha256V2,
            "team",
            TrustZoneClass::Team,
            Some(&v2_parent),
            9,
            "maintainer",
            &declared,
            &effective,
        )
        .expect("child with v2 parent");
        assert_ne!(legacy_parent_child, v2_parent_child);
    }

    #[test]
    fn unversioned_runtime_view_is_explicitly_lossy_but_value_preserving() {
        let (declared, effective) = valid_sets();
        let record = PersistedTrustZone::new(
            ObjectIdDerivationVersion::Sha256V2,
            "team",
            TrustZoneClass::Team,
            None,
            9,
            "maintainer",
            declared,
            effective,
        )
        .expect("v2 zone");
        let runtime = record.to_unversioned_runtime_view();
        assert_eq!(runtime.zone_id, record.zone_id.object_id);
        assert_eq!(runtime.zone_name, record.zone_name);
        assert_eq!(runtime.declared_ceiling, record.declared_ceiling);
    }

    #[test]
    fn invalid_ceiling_relation_fails_closed() {
        let declared = capabilities(&[RuntimeCapability::VmDispatch]);
        let effective = capabilities(&[RuntimeCapability::HeapAllocate]);
        assert_eq!(
            PersistedTrustZone::new(
                ObjectIdDerivationVersion::Sha256V2,
                "team",
                TrustZoneClass::Team,
                None,
                9,
                "maintainer",
                declared,
                effective,
            ),
            Err(TrustZonePersistenceError::EffectiveCeilingExceedsDeclared)
        );
    }
}
