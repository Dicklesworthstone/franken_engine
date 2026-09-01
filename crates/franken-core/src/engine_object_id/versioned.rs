use super::{derive_id, EngineObjectId, IdError, ObjectDomain, SchemaId, OBJECT_ID_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for SHA-256 schema identifiers.
pub const SCHEMA_ID_SHA256_V2_DOMAIN: &[u8] = b"FrankenEngine.SchemaId.sha256.v2";
/// Domain separator for SHA-256 object identifiers.
pub const ENGINE_OBJECT_ID_SHA256_V2_DOMAIN: &[u8] =
    b"FrankenEngine.EngineObjectId.sha256.v2";

/// The derivation algorithm bound to a persisted schema or object identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ObjectIdDerivationVersion {
    /// Historical de-novo deterministic hash. Retained only for explicit replay
    /// and migration of already-persisted artifacts.
    LegacyV1,
    /// Domain-separated SHA-256 derivation contract for new security-critical
    /// identities.
    Sha256V2,
}

impl ObjectIdDerivationVersion {
    /// Stable persisted spelling of the derivation version.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LegacyV1 => "legacy_v1",
            Self::Sha256V2 => "sha256_v2",
        }
    }
}

impl std::fmt::Display for ObjectIdDerivationVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Compatibility default used by the historical unversioned APIs.
///
/// This must remain `LegacyV1` until every persisted/signed consumer carries a
/// derivation version and retained artifacts have explicit replay coverage.
pub const CURRENT_OBJECT_ID_DERIVATION_VERSION: ObjectIdDerivationVersion =
    ObjectIdDerivationVersion::LegacyV1;
/// Planned default after the persisted-consumer migration is complete.
pub const TARGET_OBJECT_ID_DERIVATION_VERSION: ObjectIdDerivationVersion =
    ObjectIdDerivationVersion::Sha256V2;

/// A schema identifier paired with the algorithm that produced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionedSchemaId {
    pub derivation_version: ObjectIdDerivationVersion,
    pub schema_id: SchemaId,
}

impl VersionedSchemaId {
    pub fn new(
        derivation_version: ObjectIdDerivationVersion,
        schema_id: SchemaId,
    ) -> Self {
        Self {
            derivation_version,
            schema_id,
        }
    }

    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        self.schema_id.as_bytes()
    }
}

impl std::fmt::Display for VersionedSchemaId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.derivation_version, self.schema_id)
    }
}

/// An object identifier paired with the algorithm that produced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionedEngineObjectId {
    pub derivation_version: ObjectIdDerivationVersion,
    pub object_id: EngineObjectId,
}

impl VersionedEngineObjectId {
    pub fn new(
        derivation_version: ObjectIdDerivationVersion,
        object_id: EngineObjectId,
    ) -> Self {
        Self {
            derivation_version,
            object_id,
        }
    }

    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        self.object_id.as_bytes()
    }

    pub fn to_hex(&self) -> String {
        self.object_id.to_hex()
    }
}

impl std::fmt::Display for VersionedEngineObjectId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}:{}", self.derivation_version, self.object_id)
    }
}

/// Errors from explicit, version-tagged object-ID operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionedIdError {
    EmptyCanonicalBytes,
    LengthOverflow {
        field: String,
        length: usize,
    },
    DerivationVersionMismatch {
        object_version: ObjectIdDerivationVersion,
        schema_version: ObjectIdDerivationVersion,
    },
    IdMismatch {
        expected: VersionedEngineObjectId,
        computed: VersionedEngineObjectId,
    },
    LegacyCompatibility(IdError),
}

impl std::fmt::Display for VersionedIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCanonicalBytes => formatter.write_str("canonical bytes are empty"),
            Self::LengthOverflow { field, length } => {
                write!(formatter, "{field} length {length} exceeds u32 preimage encoding")
            }
            Self::DerivationVersionMismatch {
                object_version,
                schema_version,
            } => write!(
                formatter,
                "object derivation version {object_version} does not match schema derivation version {schema_version}"
            ),
            Self::IdMismatch { expected, computed } => {
                write!(formatter, "ID mismatch: expected {expected}, computed {computed}")
            }
            Self::LegacyCompatibility(error) => {
                write!(formatter, "legacy-v1 derivation failed: {error}")
            }
        }
    }
}

impl std::error::Error for VersionedIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LegacyCompatibility(error) => Some(error),
            _ => None,
        }
    }
}

/// Derive a schema identifier under an explicitly selected algorithm.
pub fn derive_versioned_schema_id(
    derivation_version: ObjectIdDerivationVersion,
    schema_definition: &[u8],
) -> Result<VersionedSchemaId, VersionedIdError> {
    let schema_id = match derivation_version {
        ObjectIdDerivationVersion::LegacyV1 => SchemaId::from_definition(schema_definition),
        ObjectIdDerivationVersion::Sha256V2 => {
            let mut preimage = Vec::new();
            append_length_prefixed(
                &mut preimage,
                "schema_v2_domain",
                SCHEMA_ID_SHA256_V2_DOMAIN,
            )?;
            append_length_prefixed(
                &mut preimage,
                "schema_definition",
                schema_definition,
            )?;
            SchemaId::from_bytes(sha256(&preimage))
        }
    };
    Ok(VersionedSchemaId::new(derivation_version, schema_id))
}

/// Derive an object identifier using the algorithm carried by `schema_id`.
///
/// The returned object carries the same version. Callers cannot accidentally
/// pair a SHA-256 object with a legacy schema without constructing an explicit
/// version mismatch that verification will reject.
pub fn derive_versioned_id(
    domain: ObjectDomain,
    zone: &str,
    schema_id: &VersionedSchemaId,
    canonical_bytes: &[u8],
) -> Result<VersionedEngineObjectId, VersionedIdError> {
    if canonical_bytes.is_empty() {
        return Err(VersionedIdError::EmptyCanonicalBytes);
    }

    let object_id = match schema_id.derivation_version {
        ObjectIdDerivationVersion::LegacyV1 => derive_id(
            domain,
            zone,
            &schema_id.schema_id,
            canonical_bytes,
        )
        .map_err(map_legacy_error)?,
        ObjectIdDerivationVersion::Sha256V2 => {
            let mut preimage = Vec::new();
            append_length_prefixed(
                &mut preimage,
                "object_v2_domain",
                ENGINE_OBJECT_ID_SHA256_V2_DOMAIN,
            )?;
            append_length_prefixed(&mut preimage, "object_domain", domain.tag())?;
            append_length_prefixed(&mut preimage, "zone", zone.as_bytes())?;
            preimage.extend_from_slice(schema_id.as_bytes());
            append_length_prefixed(&mut preimage, "canonical_bytes", canonical_bytes)?;
            EngineObjectId(sha256(&preimage))
        }
    };

    Ok(VersionedEngineObjectId::new(
        schema_id.derivation_version,
        object_id,
    ))
}

/// Verify an explicitly versioned identifier without cross-version fallback.
pub fn verify_versioned_id(
    expected: &VersionedEngineObjectId,
    domain: ObjectDomain,
    zone: &str,
    schema_id: &VersionedSchemaId,
    canonical_bytes: &[u8],
) -> Result<(), VersionedIdError> {
    if expected.derivation_version != schema_id.derivation_version {
        return Err(VersionedIdError::DerivationVersionMismatch {
            object_version: expected.derivation_version,
            schema_version: schema_id.derivation_version,
        });
    }

    let computed = derive_versioned_id(domain, zone, schema_id, canonical_bytes)?;
    if constant_time_eq_versioned(expected.as_bytes(), computed.as_bytes()) {
        Ok(())
    } else {
        Err(VersionedIdError::IdMismatch {
            expected: expected.clone(),
            computed,
        })
    }
}

fn map_legacy_error(error: IdError) -> VersionedIdError {
    match error {
        IdError::EmptyCanonicalBytes => VersionedIdError::EmptyCanonicalBytes,
        other => VersionedIdError::LegacyCompatibility(other),
    }
}

fn append_length_prefixed(
    output: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), VersionedIdError> {
    let length = u32::try_from(bytes.len()).map_err(|_| VersionedIdError::LengthOverflow {
        field: field.to_string(),
        length: bytes.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; OBJECT_ID_LEN] {
    Sha256::digest(bytes).into()
}

fn constant_time_eq_versioned(
    left: &[u8; OBJECT_ID_LEN],
    right: &[u8; OBJECT_ID_LEN],
) -> bool {
    let mut difference = 0_u8;
    for index in 0..OBJECT_ID_LEN {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA_DEFINITION: &[u8] = br#"{"type":"Policy"}"#;
    const CANONICAL_BYTES: &[u8] = br#"{"allow":true}"#;

    #[test]
    fn compatibility_default_remains_explicitly_legacy_v1() {
        assert_eq!(
            CURRENT_OBJECT_ID_DERIVATION_VERSION,
            ObjectIdDerivationVersion::LegacyV1
        );
        assert_eq!(
            TARGET_OBJECT_ID_DERIVATION_VERSION,
            ObjectIdDerivationVersion::Sha256V2
        );
    }

    #[test]
    fn versioned_legacy_api_preserves_committed_vectors() {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::LegacyV1,
            SCHEMA_DEFINITION,
        )
        .expect("legacy schema derivation");
        let object = derive_versioned_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &schema,
            CANONICAL_BYTES,
        )
        .expect("legacy object derivation");

        assert_eq!(
            schema.schema_id.to_string(),
            "9704c8101b9f138f0d7ec78989eb1e1e0760f0756aeade43dee3975b8e73cce5"
        );
        assert_eq!(
            object.to_hex(),
            "242c2cd17a8607149ec8dc88944aeb507a042208a522d21a9b58c112729e1ecd"
        );
    }

    #[test]
    fn sha256_v2_api_matches_migration_tool_vectors() {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            SCHEMA_DEFINITION,
        )
        .expect("v2 schema derivation");
        let object = derive_versioned_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &schema,
            CANONICAL_BYTES,
        )
        .expect("v2 object derivation");

        assert_eq!(
            schema.schema_id.to_string(),
            "95dd1a7336da89398ea01216baed44a5170dd518af89379402227a3b12d1922a"
        );
        assert_eq!(
            object.to_hex(),
            "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545"
        );
        assert!(verify_versioned_id(
            &object,
            ObjectDomain::PolicyObject,
            "zone-a",
            &schema,
            CANONICAL_BYTES,
        )
        .is_ok());
    }

    #[test]
    fn verification_rejects_version_mismatch_without_trying_both_algorithms() {
        let v2_schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            SCHEMA_DEFINITION,
        )
        .expect("v2 schema derivation");
        let v2_object = derive_versioned_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &v2_schema,
            CANONICAL_BYTES,
        )
        .expect("v2 object derivation");
        let legacy_schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::LegacyV1,
            SCHEMA_DEFINITION,
        )
        .expect("legacy schema derivation");

        let error = verify_versioned_id(
            &v2_object,
            ObjectDomain::PolicyObject,
            "zone-a",
            &legacy_schema,
            CANONICAL_BYTES,
        )
        .expect_err("mixed derivation versions must fail closed");
        assert_eq!(
            error,
            VersionedIdError::DerivationVersionMismatch {
                object_version: ObjectIdDerivationVersion::Sha256V2,
                schema_version: ObjectIdDerivationVersion::LegacyV1,
            }
        );
    }

    #[test]
    fn v2_verification_rejects_tampered_content() {
        let schema = derive_versioned_schema_id(
            ObjectIdDerivationVersion::Sha256V2,
            SCHEMA_DEFINITION,
        )
        .expect("v2 schema derivation");
        let object = derive_versioned_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &schema,
            CANONICAL_BYTES,
        )
        .expect("v2 object derivation");

        assert!(matches!(
            verify_versioned_id(
                &object,
                ObjectDomain::PolicyObject,
                "zone-a",
                &schema,
                br#"{"allow":false}"#,
            ),
            Err(VersionedIdError::IdMismatch { .. })
        ));
    }

    #[test]
    fn derivation_version_serde_spelling_is_stable() {
        assert_eq!(
            serde_json::to_string(&ObjectIdDerivationVersion::LegacyV1)
                .expect("serialize legacy version"),
            "\"legacy_v1\""
        );
        assert_eq!(
            serde_json::to_string(&ObjectIdDerivationVersion::Sha256V2)
                .expect("serialize v2 version"),
            "\"sha256_v2\""
        );
    }
}
