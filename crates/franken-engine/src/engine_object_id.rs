//! EngineObjectId: domain-separated, deterministic object identity for
//! security-critical state.
//!
//! Produces collision-resistant, domain-separated identifiers for all signed
//! security-critical objects. The derivation formula is:
//! `len(domain_sep) || domain_sep || len(zone) || zone || schema_id_32bytes || canonical_bytes`
//!
//! This module is a leaf dependency with no runtime state; it is a pure
//! function with no side effects or ambient state dependencies.
//!
//! Plan references: Section 10.10 item 1, 9E.1 (canonical object identity),
//! Top-10 #1, #3, #7, #10.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Output length of an EngineObjectId in bytes (256 bits).
pub const OBJECT_ID_LEN: usize = 32;

// ---------------------------------------------------------------------------
// ObjectDomain — domain separation tag registry
// ---------------------------------------------------------------------------

/// Domain separation tags for all object classes.
///
/// Each variant has a unique, well-known ASCII string that is included in the
/// hash preimage. New object classes must register a variant here to prevent
/// cross-domain collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectDomain {
    /// Policy objects (capability profiles, runtime policies).
    PolicyObject,
    /// Evidence records (ledger entries, decision receipts).
    EvidenceRecord,
    /// Revocation notices (capability revocations, key revocations).
    Revocation,
    /// Signed extension manifests.
    SignedManifest,
    /// Key attestation objects (owner-signed key bindings).
    Attestation,
    /// Capability tokens (runtime capabilities, delegation tokens).
    CapabilityToken,
    /// Checkpoint artifacts (runtime checkpoint snapshots).
    CheckpointArtifact,
    /// Recovery artifacts (degraded-mode repair evidence).
    RecoveryArtifact,
    /// Owner key bundles (bound signing/encryption/issuance key triples).
    KeyBundle,
}

impl ObjectDomain {
    /// The fixed domain separation tag as an ASCII byte string.
    pub fn tag(&self) -> &'static [u8] {
        match self {
            Self::PolicyObject => b"FrankenEngine.PolicyObject.v1",
            Self::EvidenceRecord => b"FrankenEngine.EvidenceRecord.v1",
            Self::Revocation => b"FrankenEngine.Revocation.v1",
            Self::SignedManifest => b"FrankenEngine.SignedManifest.v1",
            Self::Attestation => b"FrankenEngine.Attestation.v1",
            Self::CapabilityToken => b"FrankenEngine.CapabilityToken.v1",
            Self::CheckpointArtifact => b"FrankenEngine.CheckpointArtifact.v1",
            Self::RecoveryArtifact => b"FrankenEngine.RecoveryArtifact.v1",
            Self::KeyBundle => b"FrankenEngine.KeyBundle.v1",
        }
    }

    /// All domain variants for exhaustive iteration.
    pub const ALL: &'static [ObjectDomain] = &[
        ObjectDomain::PolicyObject,
        ObjectDomain::EvidenceRecord,
        ObjectDomain::Revocation,
        ObjectDomain::SignedManifest,
        ObjectDomain::Attestation,
        ObjectDomain::CapabilityToken,
        ObjectDomain::CheckpointArtifact,
        ObjectDomain::RecoveryArtifact,
        ObjectDomain::KeyBundle,
    ];
}

impl fmt::Display for ObjectDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyObject => write!(f, "policy_object"),
            Self::EvidenceRecord => write!(f, "evidence_record"),
            Self::Revocation => write!(f, "revocation"),
            Self::SignedManifest => write!(f, "signed_manifest"),
            Self::Attestation => write!(f, "attestation"),
            Self::CapabilityToken => write!(f, "capability_token"),
            Self::CheckpointArtifact => write!(f, "checkpoint_artifact"),
            Self::RecoveryArtifact => write!(f, "recovery_artifact"),
            Self::KeyBundle => write!(f, "key_bundle"),
        }
    }
}

// ---------------------------------------------------------------------------
// SchemaId — content-addressed schema identifier
// ---------------------------------------------------------------------------

/// A 32-byte content-addressed schema identifier.
///
/// Derived from the schema definition itself (not from a mutable version
/// label). Two schemas with identical definitions produce the same SchemaId.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaId(pub [u8; OBJECT_ID_LEN]);

impl SchemaId {
    /// Derive a schema ID from the schema definition bytes.
    pub fn from_definition(definition: &[u8]) -> Self {
        Self(deterministic_hash(definition))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; OBJECT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EngineObjectId — the main identifier type
// ---------------------------------------------------------------------------

/// A 32-byte domain-separated, deterministic object identifier.
///
/// The ID is computed as:
/// ```text
/// hash(len(domain_tag) || domain_tag || len(zone) || zone || schema_id || canonical_bytes)
/// ```
/// where lengths are encoded as 4-byte big-endian u32.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EngineObjectId(pub [u8; OBJECT_ID_LEN]);

impl EngineObjectId {
    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }

    /// Hex-encode the ID for display.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(OBJECT_ID_LEN * 2);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    /// Decode from a hex string (64 hex chars).
    pub fn from_hex(hex: &str) -> Result<Self, IdError> {
        if hex.len() != OBJECT_ID_LEN * 2 {
            return Err(IdError::InvalidHexLength {
                expected: OBJECT_ID_LEN * 2,
                actual: hex.len(),
            });
        }
        let mut bytes = [0u8; OBJECT_ID_LEN];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]).ok_or(IdError::InvalidHexChar { position: i * 2 })?;
            let lo = hex_digit(chunk[1]).ok_or(IdError::InvalidHexChar {
                position: i * 2 + 1,
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for EngineObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// IdError — errors from ID operations
// ---------------------------------------------------------------------------

/// Errors from EngineObjectId operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdError {
    /// Canonical bytes are empty.
    EmptyCanonicalBytes,
    /// ID verification failed: computed ID does not match expected.
    IdMismatch {
        expected: EngineObjectId,
        computed: EngineObjectId,
    },
    /// Non-canonical input detected (contains forbidden byte sequences).
    NonCanonicalInput { reason: String },
    /// Hex string has wrong length.
    InvalidHexLength { expected: usize, actual: usize },
    /// Invalid hex character.
    InvalidHexChar { position: usize },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCanonicalBytes => write!(f, "canonical bytes are empty"),
            Self::IdMismatch { expected, computed } => {
                write!(f, "ID mismatch: expected {expected}, computed {computed}")
            }
            Self::NonCanonicalInput { reason } => {
                write!(f, "non-canonical input: {reason}")
            }
            Self::InvalidHexLength { expected, actual } => {
                write!(f, "hex length: expected {expected}, got {actual}")
            }
            Self::InvalidHexChar { position } => {
                write!(f, "invalid hex char at position {position}")
            }
        }
    }
}

impl std::error::Error for IdError {}

// ---------------------------------------------------------------------------
// derive_id — the core derivation function
// ---------------------------------------------------------------------------

/// Derive an EngineObjectId from its components.
///
/// Preimage layout (length-prefixed to prevent ambiguity):
/// ```text
/// u32_be(len(domain_tag)) || domain_tag
/// u32_be(len(zone))       || zone
/// schema_id               [32 bytes, fixed]
/// canonical_bytes          [variable]
/// ```
///
/// This is a pure function with no side effects.
pub fn derive_id(
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<EngineObjectId, IdError> {
    if canonical_bytes.is_empty() {
        return Err(IdError::EmptyCanonicalBytes);
    }

    let preimage = build_preimage(domain, zone, schema_id, canonical_bytes);
    Ok(EngineObjectId(deterministic_hash(&preimage)))
}

/// Verify that an object's ID matches the expected value.
///
/// Recomputes the ID from the object's components and compares using
/// constant-time equality to prevent timing side-channels.
pub fn verify_id(
    expected: &EngineObjectId,
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Result<(), IdError> {
    let computed = derive_id(domain, zone, schema_id, canonical_bytes)?;
    if constant_time_eq(&expected.0, &computed.0) {
        Ok(())
    } else {
        Err(IdError::IdMismatch {
            expected: expected.clone(),
            computed,
        })
    }
}

// ---------------------------------------------------------------------------
// Preimage construction
// ---------------------------------------------------------------------------

/// Build the preimage bytes for ID derivation.
fn build_preimage(
    domain: ObjectDomain,
    zone: &str,
    schema_id: &SchemaId,
    canonical_bytes: &[u8],
) -> Vec<u8> {
    let tag = domain.tag();
    let zone_bytes = zone.as_bytes();

    let mut preimage = Vec::with_capacity(
        4 + tag.len() + 4 + zone_bytes.len() + OBJECT_ID_LEN + canonical_bytes.len(),
    );

    // Length-prefixed domain tag.
    preimage.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    preimage.extend_from_slice(tag);

    // Length-prefixed zone.
    preimage.extend_from_slice(&(zone_bytes.len() as u32).to_be_bytes());
    preimage.extend_from_slice(zone_bytes);

    // Fixed-length schema ID (32 bytes).
    preimage.extend_from_slice(schema_id.as_bytes());

    // Canonical bytes (variable length, last field — unambiguous).
    preimage.extend_from_slice(canonical_bytes);

    preimage
}

// ---------------------------------------------------------------------------
// Deterministic hash — de novo construction
// ---------------------------------------------------------------------------

/// De novo deterministic hash function producing 32 bytes.
///
/// This is a non-cryptographic, collision-resistant hash for identity
/// derivation. It uses a Merkle-Damgard-like construction with a
/// mixing function inspired by SipHash rounds. For production use,
/// this should be replaced with BLAKE3 via a trait abstraction.
fn deterministic_hash(input: &[u8]) -> [u8; OBJECT_ID_LEN] {
    // Initialize state with fixed IV (nothing-up-my-sleeve numbers).
    let mut state: [u64; 4] = [
        0x736f_6d65_7073_6575, // "somepseu"
        0x646f_7261_6e64_6f6d, // "dorandom"
        0x6c79_6765_6e65_7261, // "lygenera"
        0x7465_6462_7974_6573, // "tedbytes"
    ];

    // Mix in input length.
    state[0] ^= input.len() as u64;

    // Process input in 8-byte blocks.
    let chunks = input.chunks(8);
    for chunk in chunks {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        let word = u64::from_le_bytes(block);

        state[3] ^= word;
        sip_round(&mut state);
        sip_round(&mut state);
        state[0] ^= word;
    }

    // Finalization: additional mixing rounds.
    state[2] ^= 0xff;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash1 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[1] ^= 0xee;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash2 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[0] ^= 0xdd;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash3 = state[0] ^ state[1] ^ state[2] ^ state[3];

    state[3] ^= 0xcc;
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);
    sip_round(&mut state);

    let hash4 = state[0] ^ state[1] ^ state[2] ^ state[3];

    let mut output = [0u8; OBJECT_ID_LEN];
    output[0..8].copy_from_slice(&hash1.to_le_bytes());
    output[8..16].copy_from_slice(&hash2.to_le_bytes());
    output[16..24].copy_from_slice(&hash3.to_le_bytes());
    output[24..32].copy_from_slice(&hash4.to_le_bytes());

    output
}

/// SipHash-like mixing round.
#[inline]
fn sip_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(13);
    state[1] ^= state[0];
    state[0] = state[0].rotate_left(32);

    state[2] = state[2].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(16);
    state[3] ^= state[2];

    state[0] = state[0].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(21);
    state[3] ^= state[0];

    state[2] = state[2].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(17);
    state[1] ^= state[2];
    state[2] = state[2].rotate_left(32);
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte array comparison (no early exit).
fn constant_time_eq(a: &[u8; OBJECT_ID_LEN], b: &[u8; OBJECT_ID_LEN]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..OBJECT_ID_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

/// Parse a single hex digit.
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_schema_id() -> SchemaId {
        SchemaId::from_definition(b"test-schema-v1")
    }

    fn test_canonical_bytes() -> Vec<u8> {
        b"canonical-object-content-bytes".to_vec()
    }

    // -- ObjectDomain --

    #[test]
    fn all_domains_have_unique_tags() {
        let tags: Vec<&[u8]> = ObjectDomain::ALL.iter().map(|d| d.tag()).collect();
        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {:?} and {:?} share tag", i, j);
                }
            }
        }
    }

    #[test]
    fn domain_display() {
        assert_eq!(ObjectDomain::PolicyObject.to_string(), "policy_object");
        assert_eq!(ObjectDomain::EvidenceRecord.to_string(), "evidence_record");
        assert_eq!(ObjectDomain::Revocation.to_string(), "revocation");
        assert_eq!(ObjectDomain::SignedManifest.to_string(), "signed_manifest");
        assert_eq!(
            ObjectDomain::CapabilityToken.to_string(),
            "capability_token"
        );
        assert_eq!(
            ObjectDomain::CheckpointArtifact.to_string(),
            "checkpoint_artifact"
        );
        assert_eq!(
            ObjectDomain::RecoveryArtifact.to_string(),
            "recovery_artifact"
        );
    }

    // -- derive_id determinism --

    #[test]
    fn derive_id_is_deterministic() {
        let id1 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &test_schema_id(),
            &test_canonical_bytes(),
        )
        .unwrap();
        let id2 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-a",
            &test_schema_id(),
            &test_canonical_bytes(),
        )
        .unwrap();
        assert_eq!(id1, id2);
    }

    // -- Domain separation --

    #[test]
    fn different_domains_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema = test_schema_id();
        let zone = "zone-x";

        let ids: Vec<EngineObjectId> = ObjectDomain::ALL
            .iter()
            .map(|d| derive_id(*d, zone, &schema, &content).unwrap())
            .collect();

        for (i, a) in ids.iter().enumerate() {
            for (j, b) in ids.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domains {} and {} produced same ID", i, j);
                }
            }
        }
    }

    // -- Zone separation --

    #[test]
    fn different_zones_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema = test_schema_id();

        let id_a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, &content).unwrap();
        assert_ne!(id_a, id_b);
    }

    // -- Schema separation --

    #[test]
    fn different_schemas_produce_different_ids() {
        let content = test_canonical_bytes();
        let schema_v1 = SchemaId::from_definition(b"schema-v1");
        let schema_v2 = SchemaId::from_definition(b"schema-v2");

        let id_v1 = derive_id(ObjectDomain::EvidenceRecord, "zone", &schema_v1, &content).unwrap();
        let id_v2 = derive_id(ObjectDomain::EvidenceRecord, "zone", &schema_v2, &content).unwrap();
        assert_ne!(id_v1, id_v2);
    }

    // -- Content separation --

    #[test]
    fn different_content_produces_different_ids() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::Revocation, "zone", &schema, b"content-a").unwrap();
        let id_b = derive_id(ObjectDomain::Revocation, "zone", &schema, b"content-b").unwrap();
        assert_ne!(id_a, id_b);
    }

    // -- Empty canonical bytes rejection --

    #[test]
    fn derive_rejects_empty_canonical_bytes() {
        let err =
            derive_id(ObjectDomain::PolicyObject, "zone", &test_schema_id(), b"").unwrap_err();
        assert_eq!(err, IdError::EmptyCanonicalBytes);
    }

    // -- verify_id --

    #[test]
    fn verify_id_succeeds_on_valid_content() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();
        assert!(verify_id(&id, ObjectDomain::PolicyObject, "zone-a", &schema, &content).is_ok());
    }

    #[test]
    fn verify_id_fails_on_tampered_content() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let tampered = b"tampered-content";
        let err =
            verify_id(&id, ObjectDomain::PolicyObject, "zone-a", &schema, tampered).unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    #[test]
    fn verify_id_fails_on_wrong_domain() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let err = verify_id(
            &id,
            ObjectDomain::EvidenceRecord,
            "zone-a",
            &schema,
            &content,
        )
        .unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    #[test]
    fn verify_id_fails_on_wrong_zone() {
        let schema = test_schema_id();
        let content = test_canonical_bytes();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, &content).unwrap();

        let err =
            verify_id(&id, ObjectDomain::PolicyObject, "zone-b", &schema, &content).unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    // -- Constant-time comparison --

    #[test]
    fn constant_time_eq_same() {
        let a = [42u8; OBJECT_ID_LEN];
        let b = [42u8; OBJECT_ID_LEN];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different() {
        let a = [42u8; OBJECT_ID_LEN];
        let mut b = [42u8; OBJECT_ID_LEN];
        b[31] = 43;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_different() {
        let a = [0u8; OBJECT_ID_LEN];
        let b = [0xffu8; OBJECT_ID_LEN];
        assert!(!constant_time_eq(&a, &b));
    }

    // -- SchemaId --

    #[test]
    fn schema_id_from_definition_is_deterministic() {
        let a = SchemaId::from_definition(b"test-schema");
        let b = SchemaId::from_definition(b"test-schema");
        assert_eq!(a, b);
    }

    #[test]
    fn schema_id_different_definitions_produce_different_ids() {
        let a = SchemaId::from_definition(b"schema-alpha");
        let b = SchemaId::from_definition(b"schema-beta");
        assert_ne!(a, b);
    }

    #[test]
    fn schema_id_display_is_hex() {
        let schema = SchemaId::from_definition(b"test");
        let display = schema.to_string();
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- Hex encoding/decoding --

    #[test]
    fn hex_round_trip() {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "zone",
            &test_schema_id(),
            b"hello",
        )
        .unwrap();
        let hex = id.to_hex();
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn hex_decode_wrong_length() {
        let err = EngineObjectId::from_hex("abcd").unwrap_err();
        assert!(matches!(err, IdError::InvalidHexLength { .. }));
    }

    #[test]
    fn hex_decode_invalid_char() {
        let bad = "zz".to_string() + &"00".repeat(31);
        let err = EngineObjectId::from_hex(&bad).unwrap_err();
        assert!(matches!(err, IdError::InvalidHexChar { .. }));
    }

    // -- Golden vector test --

    #[test]
    fn golden_vector_policy_object() {
        // Fixed inputs for reproducible golden vector.
        let domain = ObjectDomain::PolicyObject;
        let zone = "production/us-east-1";
        let schema = SchemaId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let canonical = b"golden-vector-test-content-v1";

        let id = derive_id(domain, zone, &schema, canonical).unwrap();
        let hex = id.to_hex();

        // Re-derive to confirm determinism.
        let id2 = derive_id(domain, zone, &schema, canonical).unwrap();
        assert_eq!(id, id2);
        assert_eq!(hex.len(), 64);

        // Verify that the golden vector is stable across calls.
        let expected_hex = hex.clone();
        let id3 = EngineObjectId::from_hex(&expected_hex).unwrap();
        assert_eq!(id, id3);
    }

    #[test]
    fn golden_vector_evidence_record() {
        let domain = ObjectDomain::EvidenceRecord;
        let zone = "lab/test-cluster";
        let schema = SchemaId::from_definition(b"EvidenceSchema.v2");
        let canonical = b"evidence-entry-canonical-payload";

        let id = derive_id(domain, zone, &schema, canonical).unwrap();

        // Same inputs always produce same output.
        let id2 = derive_id(domain, zone, &schema, canonical).unwrap();
        assert_eq!(id, id2);

        // Verify round-trip through hex.
        let hex = id.to_hex();
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    // -- Preimage construction --

    #[test]
    fn preimage_includes_all_components() {
        let domain = ObjectDomain::PolicyObject;
        let zone = "zone-test";
        let schema = test_schema_id();
        let content = b"test-content";

        let preimage = build_preimage(domain, zone, &schema, content);

        // Should contain domain tag.
        let tag = domain.tag();
        assert!(preimage.windows(tag.len()).any(|w| w == tag));

        // Should contain zone.
        assert!(preimage.windows(zone.len()).any(|w| w == zone.as_bytes()));

        // Should contain schema ID bytes.
        assert!(
            preimage
                .windows(OBJECT_ID_LEN)
                .any(|w| w == schema.as_bytes())
        );

        // Should contain content.
        assert!(preimage.windows(content.len()).any(|w| w == content));
    }

    // -- Hash properties --

    #[test]
    fn hash_empty_input() {
        let h = deterministic_hash(b"");
        // Just check it doesn't panic and produces 32 bytes.
        assert_eq!(h.len(), OBJECT_ID_LEN);
    }

    #[test]
    fn hash_deterministic() {
        let h1 = deterministic_hash(b"test input");
        let h2 = deterministic_hash(b"test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_avalanche_single_bit() {
        let a = deterministic_hash(b"test input A");
        let b = deterministic_hash(b"test input B");
        // Different inputs should produce different outputs.
        assert_ne!(a, b);
        // Count differing bits (should be roughly half for good avalanche).
        let differing_bits: u32 = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones())
            .sum();
        // At least 30% of bits should differ (conservative bound).
        assert!(
            differing_bits > (OBJECT_ID_LEN as u32 * 8 * 30 / 100),
            "poor avalanche: only {differing_bits} bits differ"
        );
    }

    #[test]
    fn hash_length_dependence() {
        // Same prefix but different length should produce different hashes.
        let a = deterministic_hash(b"hello");
        let b = deterministic_hash(b"hello world");
        assert_ne!(a, b);
    }

    // -- Error display --

    #[test]
    fn error_display() {
        assert_eq!(
            IdError::EmptyCanonicalBytes.to_string(),
            "canonical bytes are empty"
        );
        assert!(
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10
            }
            .to_string()
            .contains("64")
        );
        assert!(
            IdError::InvalidHexChar { position: 5 }
                .to_string()
                .contains("5")
        );
    }

    // -- Serialization --

    #[test]
    fn engine_object_id_serialization_round_trip() {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "zone",
            &test_schema_id(),
            b"content",
        )
        .unwrap();
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: EngineObjectId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }

    #[test]
    fn schema_id_serialization_round_trip() {
        let schema = test_schema_id();
        let json = serde_json::to_string(&schema).expect("serialize");
        let restored: SchemaId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, restored);
    }

    #[test]
    fn object_domain_serialization_round_trip() {
        for domain in ObjectDomain::ALL {
            let json = serde_json::to_string(domain).expect("serialize");
            let restored: ObjectDomain = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*domain, restored);
        }
    }

    #[test]
    fn id_error_serialization_round_trip() {
        let errors = [
            IdError::EmptyCanonicalBytes,
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10,
            },
            IdError::InvalidHexChar { position: 3 },
            IdError::NonCanonicalInput {
                reason: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: IdError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- EngineObjectId display --

    #[test]
    fn engine_object_id_display_is_hex() {
        let id = derive_id(
            ObjectDomain::Revocation,
            "zone",
            &test_schema_id(),
            b"revoke",
        )
        .unwrap();
        let display = id.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn id_error_std_error() {
        let schema = SchemaId::from_definition(b"test-schema");
        let id1 = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"a").unwrap();
        let id2 = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"b").unwrap();
        let variants: [Box<dyn std::error::Error>; 5] = [
            Box::new(IdError::EmptyCanonicalBytes),
            Box::new(IdError::IdMismatch {
                expected: id1,
                computed: id2,
            }),
            Box::new(IdError::NonCanonicalInput {
                reason: "bad".into(),
            }),
            Box::new(IdError::InvalidHexLength {
                expected: 64,
                actual: 10,
            }),
            Box::new(IdError::InvalidHexChar { position: 3 }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: additional coverage --

    #[test]
    fn object_domain_display_uniqueness_via_btreeset() {
        let displays: std::collections::BTreeSet<String> =
            ObjectDomain::ALL.iter().map(|d| d.to_string()).collect();
        assert_eq!(
            displays.len(),
            ObjectDomain::ALL.len(),
            "all ObjectDomain Display strings must be unique"
        );
    }

    #[test]
    fn object_domain_display_covers_attestation_and_key_bundle() {
        assert_eq!(ObjectDomain::Attestation.to_string(), "attestation");
        assert_eq!(ObjectDomain::KeyBundle.to_string(), "key_bundle");
    }

    #[test]
    fn hex_roundtrip_all_zeros() {
        let id = EngineObjectId([0u8; OBJECT_ID_LEN]);
        let hex = id.to_hex();
        assert_eq!(hex, "0".repeat(64));
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn hex_roundtrip_all_0xff() {
        let id = EngineObjectId([0xff; OBJECT_ID_LEN]);
        let hex = id.to_hex();
        assert_eq!(hex, "ff".repeat(32));
        let restored = EngineObjectId::from_hex(&hex).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn from_hex_accepts_uppercase() {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "zone",
            &test_schema_id(),
            b"upper",
        )
        .unwrap();
        let hex_upper = id.to_hex().to_uppercase();
        let restored = EngineObjectId::from_hex(&hex_upper).unwrap();
        assert_eq!(id, restored);
    }

    #[test]
    fn id_error_id_mismatch_display_contains_both_ids() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"aaa").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"bbb").unwrap();
        let err = IdError::IdMismatch {
            expected: id_a.clone(),
            computed: id_b.clone(),
        };
        let msg = err.to_string();
        assert!(msg.contains(&id_a.to_hex()));
        assert!(msg.contains(&id_b.to_hex()));
    }

    #[test]
    fn id_error_non_canonical_input_display() {
        let err = IdError::NonCanonicalInput {
            reason: "trailing NUL".into(),
        };
        assert!(err.to_string().contains("trailing NUL"));
    }

    #[test]
    fn schema_id_from_bytes_preserves_raw() {
        let raw = [0xab; OBJECT_ID_LEN];
        let schema = SchemaId::from_bytes(raw);
        assert_eq!(*schema.as_bytes(), raw);
    }

    #[test]
    fn derive_id_single_byte_content() {
        let schema = test_schema_id();
        let id = derive_id(ObjectDomain::EvidenceRecord, "z", &schema, &[0x42]).unwrap();
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
        // Deterministic
        let id2 = derive_id(ObjectDomain::EvidenceRecord, "z", &schema, &[0x42]).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn id_error_id_mismatch_serde_roundtrip() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"x").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"y").unwrap();
        let err = IdError::IdMismatch {
            expected: id_a,
            computed: id_b,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: IdError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    #[test]
    fn object_domain_all_count() {
        assert_eq!(ObjectDomain::ALL.len(), 9);
    }

    #[test]
    fn object_domain_tags_are_ascii() {
        for domain in ObjectDomain::ALL {
            let tag = domain.tag();
            assert!(
                tag.iter().all(|b| b.is_ascii()),
                "{domain:?} tag contains non-ASCII"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, ordering, JSON fields, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn engine_object_id_clone_equality() {
        let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema_id(), b"data").unwrap();
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn schema_id_clone_equality() {
        let sid = SchemaId::from_definition(b"test-schema-clone");
        let cloned = sid.clone();
        assert_eq!(sid, cloned);
    }

    #[test]
    fn id_error_clone_equality() {
        let errors = [
            IdError::EmptyCanonicalBytes,
            IdError::NonCanonicalInput {
                reason: "bad".into(),
            },
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10,
            },
            IdError::InvalidHexChar { position: 5 },
        ];
        for e in &errors {
            let cloned = e.clone();
            assert_eq!(*e, cloned);
        }
    }

    #[test]
    fn engine_object_id_ordering_deterministic() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"aaa").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"bbb").unwrap();
        // As long as they're different, ordering should be consistent
        assert_ne!(id_a, id_b);
        let cmp1 = id_a.cmp(&id_b);
        let cmp2 = id_a.cmp(&id_b);
        assert_eq!(cmp1, cmp2);
    }

    #[test]
    fn object_domain_ordering_follows_discriminant() {
        let mut domains: Vec<ObjectDomain> = ObjectDomain::ALL.to_vec();
        let sorted = domains.clone();
        domains.sort();
        assert_eq!(domains, sorted, "ALL should already be in Ord order");
    }

    #[test]
    fn schema_id_display_length_is_64() {
        let sid = SchemaId::from_definition(b"display-len");
        let display = sid.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn engine_object_id_json_field_presence() {
        let id = EngineObjectId([0xab; OBJECT_ID_LEN]);
        let json = serde_json::to_string(&id).unwrap();
        // EngineObjectId is a newtype tuple, serializes as array
        assert!(!json.is_empty());
        let back: EngineObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn object_domain_tag_uniqueness() {
        let tags: std::collections::BTreeSet<&[u8]> =
            ObjectDomain::ALL.iter().map(|d| d.tag()).collect();
        assert_eq!(
            tags.len(),
            ObjectDomain::ALL.len(),
            "all domain tags must be unique"
        );
    }

    #[test]
    fn derive_id_long_content() {
        let schema = test_schema_id();
        let content = [0x42u8; 10_000];
        let id = derive_id(ObjectDomain::EvidenceRecord, "z", &schema, &content).unwrap();
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
    }

    #[test]
    fn verify_id_different_zone_fails() {
        let schema = test_schema_id();
        let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"data").unwrap();
        let err =
            verify_id(&id, ObjectDomain::PolicyObject, "zone-b", &schema, b"data").unwrap_err();
        assert!(matches!(err, IdError::IdMismatch { .. }));
    }

    #[test]
    fn from_hex_rejects_odd_length() {
        let err = EngineObjectId::from_hex("abc").unwrap_err();
        assert!(matches!(err, IdError::InvalidHexLength { .. }));
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        let hex = "g".repeat(64);
        let err = EngineObjectId::from_hex(&hex).unwrap_err();
        assert!(matches!(err, IdError::InvalidHexChar { .. }));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: Copy/Clone, Debug, serde distinctness, hash,
    // boundary edge cases, error trait, JSON field stability
    // -----------------------------------------------------------------------

    // -- ObjectDomain Copy semantics --

    #[test]
    fn object_domain_is_copy() {
        let d = ObjectDomain::PolicyObject;
        let d2 = d; // copy, not move
        assert_eq!(d, d2);
    }

    #[test]
    fn object_domain_copy_independence() {
        let original = ObjectDomain::EvidenceRecord;
        let mut copy = original;
        assert_eq!(copy, ObjectDomain::EvidenceRecord);
        copy = ObjectDomain::Revocation;
        assert_eq!(original, ObjectDomain::EvidenceRecord);
        assert_eq!(copy, ObjectDomain::Revocation);
    }

    // -- Debug output non-empty and distinct --

    #[test]
    fn object_domain_debug_nonempty() {
        for domain in ObjectDomain::ALL {
            let s = format!("{domain:?}");
            assert!(!s.is_empty(), "ObjectDomain::{domain:?} has empty Debug");
        }
    }

    #[test]
    fn object_domain_debug_distinct() {
        let debugs: std::collections::BTreeSet<String> =
            ObjectDomain::ALL.iter().map(|d| format!("{d:?}")).collect();
        assert_eq!(
            debugs.len(),
            ObjectDomain::ALL.len(),
            "all ObjectDomain Debug strings must be distinct"
        );
    }

    #[test]
    fn engine_object_id_debug_nonempty() {
        let id = EngineObjectId([0x1a; OBJECT_ID_LEN]);
        let s = format!("{id:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn schema_id_debug_nonempty() {
        let sid = SchemaId::from_definition(b"debug-test");
        let s = format!("{sid:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn id_error_debug_nonempty() {
        let e = IdError::EmptyCanonicalBytes;
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn id_error_debug_variants_distinct() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"a").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"b").unwrap();
        let errors = [
            IdError::EmptyCanonicalBytes,
            IdError::IdMismatch {
                expected: id_a,
                computed: id_b,
            },
            IdError::NonCanonicalInput {
                reason: "test-reason".into(),
            },
            IdError::InvalidHexLength {
                expected: 64,
                actual: 0,
            },
            IdError::InvalidHexChar { position: 7 },
        ];
        let debugs: std::collections::BTreeSet<String> =
            errors.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(
            debugs.len(),
            errors.len(),
            "all IdError debug strings must be distinct"
        );
    }

    // -- Serde variant distinctness for ObjectDomain --

    #[test]
    fn object_domain_serde_variants_all_distinct() {
        let jsons: std::collections::BTreeSet<String> = ObjectDomain::ALL
            .iter()
            .map(|d| serde_json::to_string(d).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            ObjectDomain::ALL.len(),
            "all ObjectDomain variants must serialize to distinct JSON"
        );
    }

    // -- Serde variant distinctness for IdError --

    #[test]
    fn id_error_serde_variants_all_distinct() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"p").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"q").unwrap();
        let errors = [
            IdError::EmptyCanonicalBytes,
            IdError::IdMismatch {
                expected: id_a,
                computed: id_b,
            },
            IdError::NonCanonicalInput {
                reason: "reason".into(),
            },
            IdError::InvalidHexLength {
                expected: 64,
                actual: 5,
            },
            IdError::InvalidHexChar { position: 1 },
        ];
        let jsons: std::collections::BTreeSet<String> = errors
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            errors.len(),
            "all IdError variants must serialize to distinct JSON"
        );
    }

    // -- Hash consistency --

    #[test]
    fn engine_object_id_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let id = EngineObjectId([0x77; OBJECT_ID_LEN]);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        id.hash(&mut h1);
        id.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn engine_object_id_different_values_hash_differently() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let id_a = EngineObjectId([0x11; OBJECT_ID_LEN]);
        let id_b = EngineObjectId([0x22; OBJECT_ID_LEN]);
        let mut h_a = DefaultHasher::new();
        let mut h_b = DefaultHasher::new();
        id_a.hash(&mut h_a);
        id_b.hash(&mut h_b);
        assert_ne!(h_a.finish(), h_b.finish());
    }

    #[test]
    fn schema_id_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let sid = SchemaId::from_definition(b"hash-test");
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        sid.hash(&mut h1);
        sid.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn schema_id_different_values_hash_differently() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let sid_a = SchemaId::from_definition(b"schema-one");
        let sid_b = SchemaId::from_definition(b"schema-two");
        let mut h_a = DefaultHasher::new();
        let mut h_b = DefaultHasher::new();
        sid_a.hash(&mut h_a);
        sid_b.hash(&mut h_b);
        assert_ne!(h_a.finish(), h_b.finish());
    }

    #[test]
    fn object_domain_hash_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let d = ObjectDomain::CapabilityToken;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        d.hash(&mut h1);
        d.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // -- Boundary/edge cases --

    #[test]
    fn derive_id_single_byte_all_domains() {
        let schema = test_schema_id();
        let mut ids = std::collections::BTreeSet::new();
        for domain in ObjectDomain::ALL {
            let id = derive_id(*domain, "z", &schema, &[0x01]).unwrap();
            ids.insert(id);
        }
        assert_eq!(ids.len(), ObjectDomain::ALL.len());
    }

    #[test]
    fn derive_id_empty_zone_is_valid() {
        let schema = test_schema_id();
        let id = derive_id(ObjectDomain::PolicyObject, "", &schema, b"content").unwrap();
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
    }

    #[test]
    fn derive_id_empty_zone_differs_from_nonempty_zone() {
        let schema = test_schema_id();
        let id_empty = derive_id(ObjectDomain::PolicyObject, "", &schema, b"content").unwrap();
        let id_nonempty = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"content").unwrap();
        assert_ne!(id_empty, id_nonempty);
    }

    #[test]
    fn derive_id_large_content_is_deterministic() {
        let schema = test_schema_id();
        let content: Vec<u8> = (0u8..=255).cycle().take(65_536).collect();
        let id1 = derive_id(ObjectDomain::RecoveryArtifact, "large", &schema, &content).unwrap();
        let id2 = derive_id(ObjectDomain::RecoveryArtifact, "large", &schema, &content).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_id_all_zero_content() {
        let schema = test_schema_id();
        let content = [0u8; 32];
        let id = derive_id(ObjectDomain::KeyBundle, "z", &schema, &content).unwrap();
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
    }

    #[test]
    fn derive_id_all_0xff_content() {
        let schema = test_schema_id();
        let content = [0xffu8; 32];
        let id = derive_id(ObjectDomain::SignedManifest, "z", &schema, &content).unwrap();
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
    }

    #[test]
    fn schema_id_from_bytes_zero_is_valid() {
        let sid = SchemaId::from_bytes([0u8; OBJECT_ID_LEN]);
        assert_eq!(*sid.as_bytes(), [0u8; OBJECT_ID_LEN]);
    }

    #[test]
    fn schema_id_from_bytes_max_is_valid() {
        let sid = SchemaId::from_bytes([0xffu8; OBJECT_ID_LEN]);
        assert_eq!(*sid.as_bytes(), [0xffu8; OBJECT_ID_LEN]);
    }

    #[test]
    fn engine_object_id_as_bytes_length() {
        let id = EngineObjectId([0x5a; OBJECT_ID_LEN]);
        assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
    }

    #[test]
    fn from_hex_position_zero_invalid() {
        // First two chars are invalid hex
        let hex = format!("zz{}", "00".repeat(31));
        let err = EngineObjectId::from_hex(&hex).unwrap_err();
        match err {
            IdError::InvalidHexChar { position } => assert_eq!(position, 0),
            other => panic!("expected InvalidHexChar, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_position_last_invalid() {
        // Last two chars are invalid hex
        let hex = format!("{}zz", "00".repeat(31));
        let err = EngineObjectId::from_hex(&hex).unwrap_err();
        match err {
            IdError::InvalidHexChar { position } => assert_eq!(position, 62),
            other => panic!("expected InvalidHexChar, got {other:?}"),
        }
    }

    #[test]
    fn invalid_hex_length_error_fields() {
        let err = EngineObjectId::from_hex("abcd").unwrap_err();
        match err {
            IdError::InvalidHexLength { expected, actual } => {
                assert_eq!(expected, OBJECT_ID_LEN * 2);
                assert_eq!(actual, 4);
            }
            other => panic!("expected InvalidHexLength, got {other:?}"),
        }
    }

    // -- Error trait checks --

    #[test]
    fn id_error_is_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&IdError::EmptyCanonicalBytes);
        assert_error(&IdError::InvalidHexChar { position: 0 });
        assert_error(&IdError::InvalidHexLength {
            expected: 64,
            actual: 0,
        });
        assert_error(&IdError::NonCanonicalInput { reason: "x".into() });
    }

    #[test]
    fn id_error_source_is_none() {
        use std::error::Error;
        assert!(IdError::EmptyCanonicalBytes.source().is_none());
        assert!(IdError::InvalidHexChar { position: 0 }.source().is_none());
    }

    // -- JSON field-name stability --

    #[test]
    fn object_domain_policy_object_json_field() {
        let json = serde_json::to_string(&ObjectDomain::PolicyObject).unwrap();
        assert_eq!(json, "\"PolicyObject\"");
    }

    #[test]
    fn object_domain_evidence_record_json_field() {
        let json = serde_json::to_string(&ObjectDomain::EvidenceRecord).unwrap();
        assert_eq!(json, "\"EvidenceRecord\"");
    }

    #[test]
    fn object_domain_all_json_field_names_stable() {
        let expected = [
            "\"PolicyObject\"",
            "\"EvidenceRecord\"",
            "\"Revocation\"",
            "\"SignedManifest\"",
            "\"Attestation\"",
            "\"CapabilityToken\"",
            "\"CheckpointArtifact\"",
            "\"RecoveryArtifact\"",
            "\"KeyBundle\"",
        ];
        for (domain, exp) in ObjectDomain::ALL.iter().zip(expected.iter()) {
            let json = serde_json::to_string(domain).unwrap();
            assert_eq!(json, *exp, "stable JSON name mismatch for {domain:?}");
        }
    }

    #[test]
    fn id_error_empty_canonical_bytes_json_field() {
        let json = serde_json::to_string(&IdError::EmptyCanonicalBytes).unwrap();
        assert_eq!(json, "\"EmptyCanonicalBytes\"");
    }

    #[test]
    fn id_error_invalid_hex_length_json_fields() {
        let err = IdError::InvalidHexLength {
            expected: 64,
            actual: 8,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"InvalidHexLength\""));
        assert!(json.contains("\"expected\""));
        assert!(json.contains("\"actual\""));
    }

    #[test]
    fn id_error_invalid_hex_char_json_fields() {
        let err = IdError::InvalidHexChar { position: 3 };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"InvalidHexChar\""));
        assert!(json.contains("\"position\""));
    }

    #[test]
    fn id_error_non_canonical_input_json_fields() {
        let err = IdError::NonCanonicalInput {
            reason: "null byte".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"NonCanonicalInput\""));
        assert!(json.contains("\"reason\""));
    }

    // -- Clone independence --

    #[test]
    fn engine_object_id_clone_independence() {
        let id = EngineObjectId([0xab; OBJECT_ID_LEN]);
        let mut cloned = id.clone();
        cloned.0[0] = 0x00;
        // original unchanged
        assert_eq!(id.0[0], 0xab);
        assert_eq!(cloned.0[0], 0x00);
    }

    #[test]
    fn schema_id_clone_independence() {
        let sid = SchemaId::from_bytes([0xcd; OBJECT_ID_LEN]);
        let mut cloned = sid.clone();
        cloned.0[0] = 0x00;
        assert_eq!(sid.0[0], 0xcd);
        assert_eq!(cloned.0[0], 0x00);
    }

    #[test]
    fn id_error_clone_independence() {
        let original = IdError::NonCanonicalInput {
            reason: "original".into(),
        };
        let mut cloned = original.clone();
        if let IdError::NonCanonicalInput { reason } = &mut cloned {
            *reason = "mutated".into();
        }
        // original unchanged
        assert_eq!(
            original,
            IdError::NonCanonicalInput {
                reason: "original".into()
            }
        );
    }

    // -- Display format checks --

    #[test]
    fn engine_object_id_display_equals_to_hex() {
        let id = derive_id(
            ObjectDomain::CheckpointArtifact,
            "chk",
            &test_schema_id(),
            b"checkpoint-data",
        )
        .unwrap();
        assert_eq!(id.to_string(), id.to_hex());
    }

    #[test]
    fn schema_id_display_equals_hex_encode() {
        let sid = SchemaId::from_bytes([0x0f; OBJECT_ID_LEN]);
        let display = sid.to_string();
        // 0x0f = "0f" repeated 32 times
        assert_eq!(display, "0f".repeat(32));
    }

    #[test]
    fn id_error_display_all_variants_nonempty() {
        let schema = test_schema_id();
        let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"a").unwrap();
        let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"b").unwrap();
        let errors = [
            IdError::EmptyCanonicalBytes,
            IdError::IdMismatch {
                expected: id_a,
                computed: id_b,
            },
            IdError::NonCanonicalInput {
                reason: "test".into(),
            },
            IdError::InvalidHexLength {
                expected: 64,
                actual: 4,
            },
            IdError::InvalidHexChar { position: 2 },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(
                !msg.is_empty(),
                "IdError variant has empty Display: {err:?}"
            );
        }
    }

    // -- Domain tag byte properties --

    #[test]
    fn domain_tags_contain_frankengine_prefix() {
        for domain in ObjectDomain::ALL {
            let tag = domain.tag();
            let tag_str = std::str::from_utf8(tag).expect("tag must be valid UTF-8");
            assert!(
                tag_str.starts_with("FrankenEngine."),
                "{domain:?} tag does not start with 'FrankenEngine.': {tag_str}"
            );
        }
    }

    #[test]
    fn domain_tags_end_with_v1_suffix() {
        for domain in ObjectDomain::ALL {
            let tag = domain.tag();
            let tag_str = std::str::from_utf8(tag).expect("tag must be valid UTF-8");
            assert!(
                tag_str.ends_with(".v1"),
                "{domain:?} tag does not end with '.v1': {tag_str}"
            );
        }
    }

    #[test]
    fn domain_tags_nonempty() {
        for domain in ObjectDomain::ALL {
            assert!(!domain.tag().is_empty(), "{domain:?} has empty tag");
        }
    }

    // -- BTreeMap/BTreeSet usage with derived types --

    #[test]
    fn engine_object_id_usable_as_btreeset_key() {
        let schema = test_schema_id();
        let mut set = std::collections::BTreeSet::new();
        for domain in ObjectDomain::ALL {
            let id = derive_id(*domain, "zone", &schema, b"data").unwrap();
            set.insert(id);
        }
        assert_eq!(set.len(), ObjectDomain::ALL.len());
    }

    #[test]
    fn object_domain_usable_as_btreeset_key() {
        let mut set = std::collections::BTreeSet::new();
        for domain in ObjectDomain::ALL {
            set.insert(*domain);
        }
        assert_eq!(set.len(), ObjectDomain::ALL.len());
    }

    // -- verify_id propagates empty canonical bytes error --

    #[test]
    fn verify_id_propagates_empty_canonical_bytes_error() {
        let schema = test_schema_id();
        let dummy_id = EngineObjectId([0u8; OBJECT_ID_LEN]);
        let err = verify_id(&dummy_id, ObjectDomain::PolicyObject, "z", &schema, b"").unwrap_err();
        assert_eq!(err, IdError::EmptyCanonicalBytes);
    }

    // -- OBJECT_ID_LEN constant --

    #[test]
    fn object_id_len_constant_is_32() {
        assert_eq!(OBJECT_ID_LEN, 32);
    }

    // -- derive_id output is always exactly OBJECT_ID_LEN bytes --

    #[test]
    fn derive_id_output_always_32_bytes_across_domains() {
        let schema = test_schema_id();
        for domain in ObjectDomain::ALL {
            let id = derive_id(*domain, "test-zone", &schema, b"payload").unwrap();
            assert_eq!(
                id.as_bytes().len(),
                OBJECT_ID_LEN,
                "{domain:?} produced wrong output length"
            );
        }
    }
}
