use super::{
    EngineObjectId, ObjectIdDerivationVersion, SchemaId, VersionedEngineObjectId,
    VersionedSchemaId, OBJECT_ID_LEN,
};
use serde::de::Error as DeserializeError;
use serde::ser::Error as SerializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const ENGINE_OBJECT_ID_V2_MAGIC: &[u8; 8] = b"FEOIDV2\0";
const SCHEMA_ID_V2_MAGIC: &[u8; 8] = b"FESIDV2\0";
const SHA256_V2_WIRE_VERSION: u8 = 2;
const VERSIONED_WIRE_LEN: usize = 8 + 1 + OBJECT_ID_LEN;

/// A persisted object identifier whose derivation algorithm is explicit.
///
/// Human-readable serde formats preserve the historical bare-ID representation
/// for `legacy_v1`, while `sha256_v2` uses a tagged object. Non-self-describing
/// binary formats must use [`Self::encode_binary`] and [`Self::decode_binary`]
/// so legacy 32-byte records and versioned envelopes are unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistedEngineObjectId {
    pub derivation_version: ObjectIdDerivationVersion,
    pub object_id: EngineObjectId,
}

impl PersistedEngineObjectId {
    pub fn legacy(object_id: EngineObjectId) -> Self {
        Self {
            derivation_version: ObjectIdDerivationVersion::LegacyV1,
            object_id,
        }
    }

    pub fn from_versioned(value: VersionedEngineObjectId) -> Self {
        Self {
            derivation_version: value.derivation_version,
            object_id: value.object_id,
        }
    }

    pub fn to_versioned(&self) -> VersionedEngineObjectId {
        VersionedEngineObjectId::new(self.derivation_version, self.object_id.clone())
    }

    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        self.object_id.as_bytes()
    }

    pub fn encode_binary(&self) -> Vec<u8> {
        encode_binary_id(
            self.derivation_version,
            self.as_bytes(),
            ENGINE_OBJECT_ID_V2_MAGIC,
        )
    }

    pub fn decode_binary(bytes: &[u8]) -> Result<Self, VersionedIdWireError> {
        let (derivation_version, object_id) =
            decode_binary_id(bytes, ENGINE_OBJECT_ID_V2_MAGIC, "engine_object_id")?;
        Ok(Self {
            derivation_version,
            object_id: EngineObjectId(object_id),
        })
    }
}

impl From<EngineObjectId> for PersistedEngineObjectId {
    fn from(value: EngineObjectId) -> Self {
        Self::legacy(value)
    }
}

impl From<VersionedEngineObjectId> for PersistedEngineObjectId {
    fn from(value: VersionedEngineObjectId) -> Self {
        Self::from_versioned(value)
    }
}

impl Serialize for PersistedEngineObjectId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !serializer.is_human_readable() {
            return Err(S::Error::custom(
                "PersistedEngineObjectId requires encode_binary() for non-human-readable formats",
            ));
        }
        match self.derivation_version {
            ObjectIdDerivationVersion::LegacyV1 => self.object_id.serialize(serializer),
            ObjectIdDerivationVersion::Sha256V2 => TaggedEngineObjectIdRef {
                derivation_version: self.derivation_version,
                object_id: &self.object_id,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PersistedEngineObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if !deserializer.is_human_readable() {
            return Err(D::Error::custom(
                "PersistedEngineObjectId requires decode_binary() for non-human-readable formats",
            ));
        }
        match EngineObjectIdJsonRepr::deserialize(deserializer)? {
            EngineObjectIdJsonRepr::Tagged {
                derivation_version,
                object_id,
            } => Ok(Self {
                derivation_version,
                object_id,
            }),
            EngineObjectIdJsonRepr::Legacy(object_id) => Ok(Self::legacy(object_id)),
        }
    }
}

#[derive(Serialize)]
struct TaggedEngineObjectIdRef<'a> {
    derivation_version: ObjectIdDerivationVersion,
    object_id: &'a EngineObjectId,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EngineObjectIdJsonRepr {
    Tagged {
        derivation_version: ObjectIdDerivationVersion,
        object_id: EngineObjectId,
    },
    Legacy(EngineObjectId),
}

/// A persisted schema identifier whose derivation algorithm is explicit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistedSchemaId {
    pub derivation_version: ObjectIdDerivationVersion,
    pub schema_id: SchemaId,
}

impl PersistedSchemaId {
    pub fn legacy(schema_id: SchemaId) -> Self {
        Self {
            derivation_version: ObjectIdDerivationVersion::LegacyV1,
            schema_id,
        }
    }

    pub fn from_versioned(value: VersionedSchemaId) -> Self {
        Self {
            derivation_version: value.derivation_version,
            schema_id: value.schema_id,
        }
    }

    pub fn to_versioned(&self) -> VersionedSchemaId {
        VersionedSchemaId::new(self.derivation_version, self.schema_id.clone())
    }

    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        self.schema_id.as_bytes()
    }

    pub fn encode_binary(&self) -> Vec<u8> {
        encode_binary_id(
            self.derivation_version,
            self.as_bytes(),
            SCHEMA_ID_V2_MAGIC,
        )
    }

    pub fn decode_binary(bytes: &[u8]) -> Result<Self, VersionedIdWireError> {
        let (derivation_version, schema_id) =
            decode_binary_id(bytes, SCHEMA_ID_V2_MAGIC, "schema_id")?;
        Ok(Self {
            derivation_version,
            schema_id: SchemaId::from_bytes(schema_id),
        })
    }
}

impl From<SchemaId> for PersistedSchemaId {
    fn from(value: SchemaId) -> Self {
        Self::legacy(value)
    }
}

impl From<VersionedSchemaId> for PersistedSchemaId {
    fn from(value: VersionedSchemaId) -> Self {
        Self::from_versioned(value)
    }
}

impl Serialize for PersistedSchemaId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !serializer.is_human_readable() {
            return Err(S::Error::custom(
                "PersistedSchemaId requires encode_binary() for non-human-readable formats",
            ));
        }
        match self.derivation_version {
            ObjectIdDerivationVersion::LegacyV1 => self.schema_id.serialize(serializer),
            ObjectIdDerivationVersion::Sha256V2 => TaggedSchemaIdRef {
                derivation_version: self.derivation_version,
                schema_id: &self.schema_id,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PersistedSchemaId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if !deserializer.is_human_readable() {
            return Err(D::Error::custom(
                "PersistedSchemaId requires decode_binary() for non-human-readable formats",
            ));
        }
        match SchemaIdJsonRepr::deserialize(deserializer)? {
            SchemaIdJsonRepr::Tagged {
                derivation_version,
                schema_id,
            } => Ok(Self {
                derivation_version,
                schema_id,
            }),
            SchemaIdJsonRepr::Legacy(schema_id) => Ok(Self::legacy(schema_id)),
        }
    }
}

#[derive(Serialize)]
struct TaggedSchemaIdRef<'a> {
    derivation_version: ObjectIdDerivationVersion,
    schema_id: &'a SchemaId,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SchemaIdJsonRepr {
    Tagged {
        derivation_version: ObjectIdDerivationVersion,
        schema_id: SchemaId,
    },
    Legacy(SchemaId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionedIdWireError {
    InvalidLength {
        kind: &'static str,
        actual: usize,
    },
    InvalidMagic {
        kind: &'static str,
    },
    UnsupportedVersion {
        kind: &'static str,
        version: u8,
    },
}

impl std::fmt::Display for VersionedIdWireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { kind, actual } => write!(
                formatter,
                "invalid {kind} wire length {actual}; expected {OBJECT_ID_LEN} legacy bytes or {VERSIONED_WIRE_LEN} versioned bytes"
            ),
            Self::InvalidMagic { kind } => {
                write!(formatter, "invalid {kind} versioned wire magic")
            }
            Self::UnsupportedVersion { kind, version } => {
                write!(formatter, "unsupported {kind} wire version {version}")
            }
        }
    }
}

impl std::error::Error for VersionedIdWireError {}

fn encode_binary_id(
    derivation_version: ObjectIdDerivationVersion,
    id: &[u8; OBJECT_ID_LEN],
    magic: &[u8; 8],
) -> Vec<u8> {
    match derivation_version {
        ObjectIdDerivationVersion::LegacyV1 => id.to_vec(),
        ObjectIdDerivationVersion::Sha256V2 => {
            let mut bytes = Vec::with_capacity(VERSIONED_WIRE_LEN);
            bytes.extend_from_slice(magic);
            bytes.push(SHA256_V2_WIRE_VERSION);
            bytes.extend_from_slice(id);
            bytes
        }
    }
}

fn decode_binary_id(
    bytes: &[u8],
    expected_magic: &[u8; 8],
    kind: &'static str,
) -> Result<(ObjectIdDerivationVersion, [u8; OBJECT_ID_LEN]), VersionedIdWireError> {
    if bytes.len() == OBJECT_ID_LEN {
        return Ok((
            ObjectIdDerivationVersion::LegacyV1,
            bytes.try_into().expect("length checked"),
        ));
    }
    if bytes.len() != VERSIONED_WIRE_LEN {
        return Err(VersionedIdWireError::InvalidLength {
            kind,
            actual: bytes.len(),
        });
    }
    if &bytes[..expected_magic.len()] != expected_magic {
        return Err(VersionedIdWireError::InvalidMagic { kind });
    }
    let version = bytes[expected_magic.len()];
    if version != SHA256_V2_WIRE_VERSION {
        return Err(VersionedIdWireError::UnsupportedVersion { kind, version });
    }
    let id = bytes[expected_magic.len() + 1..]
        .try_into()
        .expect("versioned wire length checked");
    Ok((ObjectIdDerivationVersion::Sha256V2, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_object_json_is_byte_for_byte_the_old_representation() {
        let raw = EngineObjectId([7; OBJECT_ID_LEN]);
        let old_json = serde_json::to_vec(&raw).expect("legacy JSON");
        let persisted_json = serde_json::to_vec(&PersistedEngineObjectId::legacy(raw.clone()))
            .expect("persisted legacy JSON");
        assert_eq!(persisted_json, old_json);

        let decoded: PersistedEngineObjectId =
            serde_json::from_slice(&old_json).expect("decode old JSON");
        assert_eq!(decoded.derivation_version, ObjectIdDerivationVersion::LegacyV1);
        assert_eq!(decoded.object_id, raw);
    }

    #[test]
    fn v2_object_json_is_tagged_and_roundtrips() {
        let persisted = PersistedEngineObjectId::from_versioned(VersionedEngineObjectId::new(
            ObjectIdDerivationVersion::Sha256V2,
            EngineObjectId([9; OBJECT_ID_LEN]),
        ));
        let value = serde_json::to_value(&persisted).expect("v2 JSON");
        assert_eq!(value["derivation_version"], "sha256_v2");
        assert_eq!(value["object_id"][0], 9);
        let decoded: PersistedEngineObjectId =
            serde_json::from_value(value).expect("decode v2 JSON");
        assert_eq!(decoded, persisted);
    }

    #[test]
    fn binary_codec_preserves_legacy_and_tags_v2() {
        let legacy = PersistedEngineObjectId::legacy(EngineObjectId([1; OBJECT_ID_LEN]));
        let legacy_bytes = legacy.encode_binary();
        assert_eq!(legacy_bytes.len(), OBJECT_ID_LEN);
        assert_eq!(PersistedEngineObjectId::decode_binary(&legacy_bytes), Ok(legacy));

        let v2 = PersistedEngineObjectId::from_versioned(VersionedEngineObjectId::new(
            ObjectIdDerivationVersion::Sha256V2,
            EngineObjectId([2; OBJECT_ID_LEN]),
        ));
        let v2_bytes = v2.encode_binary();
        assert_eq!(v2_bytes.len(), VERSIONED_WIRE_LEN);
        assert_eq!(&v2_bytes[..8], ENGINE_OBJECT_ID_V2_MAGIC);
        assert_eq!(PersistedEngineObjectId::decode_binary(&v2_bytes), Ok(v2));
    }

    #[test]
    fn binary_codec_rejects_cross_kind_and_unknown_versions() {
        let schema = PersistedSchemaId::from_versioned(VersionedSchemaId::new(
            ObjectIdDerivationVersion::Sha256V2,
            SchemaId::from_bytes([3; OBJECT_ID_LEN]),
        ));
        let schema_bytes = schema.encode_binary();
        assert!(matches!(
            PersistedEngineObjectId::decode_binary(&schema_bytes),
            Err(VersionedIdWireError::InvalidMagic { .. })
        ));

        let mut unknown = schema_bytes;
        unknown[8] = 99;
        assert!(matches!(
            PersistedSchemaId::decode_binary(&unknown),
            Err(VersionedIdWireError::UnsupportedVersion { version: 99, .. })
        ));
    }

    #[test]
    fn schema_json_and_binary_follow_the_same_compatibility_contract() {
        let raw = SchemaId::from_bytes([4; OBJECT_ID_LEN]);
        let old_json = serde_json::to_vec(&raw).expect("legacy schema JSON");
        let persisted = PersistedSchemaId::legacy(raw.clone());
        assert_eq!(serde_json::to_vec(&persisted).expect("persisted schema JSON"), old_json);
        assert_eq!(
            serde_json::from_slice::<PersistedSchemaId>(&old_json).expect("decode schema JSON"),
            persisted
        );
        assert_eq!(
            PersistedSchemaId::decode_binary(&persisted.encode_binary()),
            Ok(persisted)
        );
    }

    #[test]
    fn malformed_binary_lengths_fail_closed() {
        assert!(matches!(
            PersistedEngineObjectId::decode_binary(&[0; OBJECT_ID_LEN - 1]),
            Err(VersionedIdWireError::InvalidLength { .. })
        ));
    }
}
