use super::{PersistedEngineObjectId, PersistedSchemaId};

impl PersistedEngineObjectId {
    /// Hex-encode the raw 32-byte identifier while retaining the derivation
    /// version separately in the surrounding persisted envelope.
    pub fn to_hex(&self) -> String {
        self.object_id.to_hex()
    }
}

impl PersistedSchemaId {
    /// Hex-encode the raw 32-byte schema identifier while retaining the
    /// derivation version separately in the surrounding persisted envelope.
    pub fn to_hex(&self) -> String {
        self.schema_id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{EngineObjectId, ObjectIdDerivationVersion, SchemaId};

    #[test]
    fn persisted_object_hex_is_algorithm_independent_rendering_only() {
        let legacy = PersistedEngineObjectId::legacy(EngineObjectId([0xab; 32]));
        let mut v2 = legacy.clone();
        v2.derivation_version = ObjectIdDerivationVersion::Sha256V2;
        assert_eq!(legacy.to_hex(), "ab".repeat(32));
        assert_eq!(legacy.to_hex(), v2.to_hex());
        assert_ne!(legacy.derivation_version, v2.derivation_version);
    }

    #[test]
    fn persisted_schema_hex_renders_raw_bytes() {
        let schema = PersistedSchemaId::legacy(SchemaId::from_bytes([0xcd; 32]));
        assert_eq!(schema.to_hex(), "cd".repeat(32));
    }
}
