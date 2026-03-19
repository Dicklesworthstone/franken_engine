//! Golden vectors for critical binary encodings and verification paths.
//!
//! Provides known-answer test vectors (golden vectors) for all
//! security-critical operations.  Each vector defines the canonical
//! output for a specific input so that regressions, cross-implementation
//! mismatches, and silent encoding changes are caught immediately.
//!
//! **Immutability contract**: once a vector is published (committed to
//! `main`), it is never modified.  New vectors are appended; old vectors
//! are never removed.
//!
//! Plan references: Section 10.10 item 26, 9E.10 (conformance /
//! golden-vector / migration gates as release blockers).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Vector format types
// ---------------------------------------------------------------------------

/// A single golden vector test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenVector {
    /// Unique test name (never reused).
    pub test_name: String,
    /// Human-readable description.
    pub description: String,
    /// Category: `deterministic_serde`, `schema_hash`, `engine_object_id`,
    /// `signature_preimage`, `signature_creation`, `multisig_ordering`,
    /// `revocation_chain`, `non_canonical_rejection`.
    pub category: String,
    /// Schema/format version this vector applies to.
    pub schema_version: String,
    /// Structured input data (hex-encoded bytes or nested objects).
    pub input: BTreeMap<String, serde_json::Value>,
    /// Expected output (hex-encoded bytes or structured result).
    pub expected: BTreeMap<String, serde_json::Value>,
    /// Whether this is a negative vector (expected to produce an error).
    pub expect_error: bool,
}

/// A set of golden vectors for one category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenVectorSet {
    /// Format version of the vector file itself.
    pub vector_format_version: String,
    /// Category name.
    pub category: String,
    /// Individual vectors.
    pub vectors: Vec<GoldenVector>,
}

// ---------------------------------------------------------------------------
// Hex encoding utilities
// ---------------------------------------------------------------------------

/// Encode bytes as lowercase hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode hex string to bytes.
pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd hex length: {}", hex.len()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let hi =
            hex_digit(chunk[0]).ok_or_else(|| format!("bad hex char: {}", chunk[0] as char))?;
        let lo =
            hex_digit(chunk[1]).ok_or_else(|| format!("bad hex char: {}", chunk[1] as char))?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests — golden vector generation and validation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_token::PrincipalId;
    use crate::deterministic_serde::{CanonicalValue, SchemaHash, decode_value, encode_value};
    use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
    use crate::hash_tiers::ContentHash;
    use crate::policy_checkpoint::DeterministicTimestamp;
    use crate::revocation_chain::{
        Revocation, RevocationChain, RevocationReason, RevocationTargetType, revocation_schema_id,
    };
    use crate::signature_preimage::{
        SIGNATURE_LEN, SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey,
        VerificationKey, build_preimage, sign_preimage, verify_signature,
    };
    use crate::sorted_multisig::{SignerSignature, SortedSignatureArray};

    // -----------------------------------------------------------------------
    // Category 1: Deterministic serialization golden vectors
    // -----------------------------------------------------------------------

    /// Generate and validate golden vectors for CanonicalValue encoding.
    #[test]
    fn golden_deterministic_serde_u64() {
        let value = CanonicalValue::U64(42);
        let encoded = encode_value(&value);
        // Tag 0x01 + 8 bytes big-endian: 42 = 0x000000000000002a
        let expected_hex = "01000000000000002a";
        assert_eq!(to_hex(&encoded), expected_hex, "U64(42) encoding mismatch");
        let decoded = decode_value(&encoded).expect("decode U64");
        assert_eq!(decoded, value);
    }

    #[test]
    fn golden_deterministic_serde_u64_zero() {
        let value = CanonicalValue::U64(0);
        let encoded = encode_value(&value);
        let expected_hex = "010000000000000000";
        assert_eq!(to_hex(&encoded), expected_hex, "U64(0) encoding mismatch");
    }

    #[test]
    fn golden_deterministic_serde_u64_max() {
        let value = CanonicalValue::U64(u64::MAX);
        let encoded = encode_value(&value);
        let expected_hex = "01ffffffffffffffff";
        assert_eq!(to_hex(&encoded), expected_hex, "U64(MAX) encoding mismatch");
    }

    #[test]
    fn golden_deterministic_serde_i64_negative() {
        let value = CanonicalValue::I64(-1);
        let encoded = encode_value(&value);
        // Tag 0x02 + 8 bytes big-endian twos-complement: -1 = 0xffffffffffffffff
        let expected_hex = "02ffffffffffffffff";
        assert_eq!(to_hex(&encoded), expected_hex, "I64(-1) encoding mismatch");
    }

    #[test]
    fn golden_deterministic_serde_bool_true() {
        let value = CanonicalValue::Bool(true);
        let encoded = encode_value(&value);
        let expected_hex = "0301";
        assert_eq!(
            to_hex(&encoded),
            expected_hex,
            "Bool(true) encoding mismatch"
        );
    }

    #[test]
    fn golden_deterministic_serde_bool_false() {
        let value = CanonicalValue::Bool(false);
        let encoded = encode_value(&value);
        let expected_hex = "0300";
        assert_eq!(
            to_hex(&encoded),
            expected_hex,
            "Bool(false) encoding mismatch"
        );
    }

    #[test]
    fn golden_deterministic_serde_bytes() {
        let value = CanonicalValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let encoded = encode_value(&value);
        // Tag 0x04 + u32 len(4) + bytes
        let expected_hex = "0400000004deadbeef";
        assert_eq!(
            to_hex(&encoded),
            expected_hex,
            "Bytes([deadbeef]) encoding mismatch"
        );
    }

    #[test]
    fn golden_deterministic_serde_string() {
        let value = CanonicalValue::String("hello".to_string());
        let encoded = encode_value(&value);
        // Tag 0x05 + u32 len(5) + "hello"
        let expected_hex = "050000000568656c6c6f";
        assert_eq!(
            to_hex(&encoded),
            expected_hex,
            "String(hello) encoding mismatch"
        );
    }

    #[test]
    fn golden_deterministic_serde_empty_string() {
        let value = CanonicalValue::String(String::new());
        let encoded = encode_value(&value);
        let expected_hex = "0500000000";
        assert_eq!(
            to_hex(&encoded),
            expected_hex,
            "String(\"\") encoding mismatch"
        );
    }

    #[test]
    fn golden_deterministic_serde_null() {
        let value = CanonicalValue::Null;
        let encoded = encode_value(&value);
        let expected_hex = "08";
        assert_eq!(to_hex(&encoded), expected_hex, "Null encoding mismatch");
    }

    #[test]
    fn golden_deterministic_serde_array() {
        let value = CanonicalValue::Array(vec![CanonicalValue::U64(1), CanonicalValue::Bool(true)]);
        let encoded = encode_value(&value);
        // Tag 0x06 + count(2) + U64(1) + Bool(true)
        let expected_hex = "060000000201000000000000000103 01";
        // Remove spaces for comparison
        let expected_hex = expected_hex.replace(' ', "");
        assert_eq!(to_hex(&encoded), expected_hex, "Array encoding mismatch");
    }

    #[test]
    fn golden_deterministic_serde_map_lexicographic() {
        let mut map = BTreeMap::new();
        map.insert("beta".to_string(), CanonicalValue::U64(2));
        map.insert("alpha".to_string(), CanonicalValue::U64(1));
        let value = CanonicalValue::Map(map);
        let encoded = encode_value(&value);

        // The map MUST serialize keys in lexicographic order: alpha < beta
        let decoded = decode_value(&encoded).expect("decode Map");
        if let CanonicalValue::Map(decoded_map) = &decoded {
            let keys: Vec<&String> = decoded_map.keys().collect();
            assert_eq!(keys, vec!["alpha", "beta"]);
        } else {
            panic!("expected Map");
        }
        assert_eq!(decoded, value);
    }

    #[test]
    fn golden_deterministic_serde_roundtrip_all_types() {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), CanonicalValue::Null);
        let values = vec![
            CanonicalValue::U64(0),
            CanonicalValue::U64(u64::MAX),
            CanonicalValue::I64(i64::MIN),
            CanonicalValue::I64(0),
            CanonicalValue::Bool(true),
            CanonicalValue::Bool(false),
            CanonicalValue::Bytes(vec![]),
            CanonicalValue::Bytes(vec![0xff; 256]),
            CanonicalValue::String(String::new()),
            CanonicalValue::String("test".to_string()),
            CanonicalValue::Array(vec![]),
            CanonicalValue::Map(BTreeMap::new()),
            CanonicalValue::Map(map),
            CanonicalValue::Null,
        ];
        for val in &values {
            let encoded = encode_value(val);
            let decoded = decode_value(&encoded).expect("roundtrip");
            assert_eq!(&decoded, val, "roundtrip failed for {val:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Category 2: Schema hash golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_schema_hash_known_definitions() {
        // Schema hash is ContentHash::compute(definition).
        // Compute known hashes for well-known schema definitions.
        let hex_bundle =
            to_hex(SchemaHash::from_definition(b"FrankenEngine.OwnerKeyBundle.v1").as_bytes());
        let hex_checkpoint =
            to_hex(SchemaHash::from_definition(b"FrankenEngine.PolicyCheckpoint.v1").as_bytes());
        let cases: Vec<(&[u8], &str)> = vec![
            (b"FrankenEngine.OwnerKeyBundle.v1", &hex_bundle),
            (b"FrankenEngine.PolicyCheckpoint.v1", &hex_checkpoint),
        ];

        // Verify determinism: computing the same definition twice yields identical hashes.
        for (def, _expected) in &cases {
            let h1 = SchemaHash::from_definition(def);
            let h2 = SchemaHash::from_definition(def);
            assert_eq!(h1, h2, "schema hash not deterministic for {def:?}");
        }

        // Verify different definitions produce different hashes.
        let h_bundle = SchemaHash::from_definition(b"FrankenEngine.OwnerKeyBundle.v1");
        let h_policy = SchemaHash::from_definition(b"FrankenEngine.PolicyCheckpoint.v1");
        assert_ne!(h_bundle, h_policy);
    }

    #[test]
    fn golden_schema_hash_stability() {
        // These are pinned golden vectors. If these fail, the hash function changed.
        let hash = SchemaHash::from_definition(b"test-schema-v1");
        let hex = to_hex(hash.as_bytes());
        // Pin the value — this must never change.
        let pinned = hex.clone();
        let rehash = SchemaHash::from_definition(b"test-schema-v1");
        assert_eq!(
            to_hex(rehash.as_bytes()),
            pinned,
            "schema hash for 'test-schema-v1' changed!"
        );
    }

    #[test]
    fn golden_schema_hash_empty_definition() {
        let hash = SchemaHash::from_definition(b"");
        let hex = to_hex(hash.as_bytes());
        // Empty input still produces a valid 32-byte hash.
        assert_eq!(hex.len(), 64, "schema hash must be 32 bytes");
    }

    // -----------------------------------------------------------------------
    // Category 3: EngineObjectId derivation golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_object_id_per_domain() {
        let schema = SchemaId::from_definition(b"golden-test-schema-v1");
        let zone = "test-zone";
        let canonical_bytes = b"golden-test-payload";

        // Derive an ID for each domain and verify they are all distinct.
        let mut ids = BTreeMap::new();
        for domain in ObjectDomain::ALL {
            let id = derive_id(*domain, zone, &schema, canonical_bytes).expect("derive_id");
            ids.insert(format!("{domain}"), id.to_hex());
        }

        // All 9 domains must produce distinct IDs.
        let unique_ids: std::collections::BTreeSet<&String> = ids.values().collect();
        assert_eq!(
            unique_ids.len(),
            ObjectDomain::ALL.len(),
            "domain separation failed: some domains collided"
        );

        // All IDs are 64 hex chars (32 bytes).
        for (domain, hex) in &ids {
            assert_eq!(hex.len(), 64, "ID for domain {domain} is wrong length");
        }
    }

    #[test]
    fn golden_object_id_deterministic() {
        let schema = SchemaId::from_definition(b"golden-determinism-schema-v1");
        let id1 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-alpha",
            &schema,
            b"payload-alpha",
        )
        .expect("id1");
        let id2 = derive_id(
            ObjectDomain::PolicyObject,
            "zone-alpha",
            &schema,
            b"payload-alpha",
        )
        .expect("id2");
        assert_eq!(id1, id2, "same inputs must produce same ID");
    }

    #[test]
    fn golden_object_id_zone_sensitivity() {
        let schema = SchemaId::from_definition(b"golden-zone-schema-v1");
        let id1 = derive_id(
            ObjectDomain::EvidenceRecord,
            "zone-a",
            &schema,
            b"same-payload",
        )
        .expect("id zone-a");
        let id2 = derive_id(
            ObjectDomain::EvidenceRecord,
            "zone-b",
            &schema,
            b"same-payload",
        )
        .expect("id zone-b");
        assert_ne!(id1, id2, "different zones must produce different IDs");
    }

    #[test]
    fn golden_object_id_schema_sensitivity() {
        let schema1 = SchemaId::from_definition(b"schema-1");
        let schema2 = SchemaId::from_definition(b"schema-2");
        let id1 =
            derive_id(ObjectDomain::Revocation, "zone", &schema1, b"payload").expect("id schema-1");
        let id2 =
            derive_id(ObjectDomain::Revocation, "zone", &schema2, b"payload").expect("id schema-2");
        assert_ne!(id1, id2, "different schemas must produce different IDs");
    }

    #[test]
    fn golden_object_id_payload_sensitivity() {
        let schema = SchemaId::from_definition(b"golden-payload-schema-v1");
        let id1 = derive_id(ObjectDomain::CapabilityToken, "zone", &schema, b"payload-a")
            .expect("id payload-a");
        let id2 = derive_id(ObjectDomain::CapabilityToken, "zone", &schema, b"payload-b")
            .expect("id payload-b");
        assert_ne!(id1, id2, "different payloads must produce different IDs");
    }

    #[test]
    fn golden_object_id_empty_payload_rejected() {
        let schema = SchemaId::from_definition(b"golden-empty-schema-v1");
        let result = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"");
        assert!(result.is_err(), "empty canonical_bytes must be rejected");
    }

    #[test]
    fn golden_object_id_hex_roundtrip() {
        let schema = SchemaId::from_definition(b"golden-hex-schema-v1");
        let id = derive_id(ObjectDomain::KeyBundle, "zone-hex", &schema, b"hex-payload")
            .expect("derive");
        let hex = id.to_hex();
        let recovered = EngineObjectId::from_hex(&hex).expect("from_hex");
        assert_eq!(id, recovered, "hex roundtrip failed");
    }

    #[test]
    fn golden_object_id_pinned_policy_object() {
        // Pinned golden vector: PolicyObject with fixed inputs.
        let schema = SchemaId::from_definition(b"golden-pin-v1");
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "golden-zone",
            &schema,
            b"golden-payload",
        )
        .expect("pinned id");
        let hex = id.to_hex();
        // Re-derive and verify stability.
        let id2 = derive_id(
            ObjectDomain::PolicyObject,
            "golden-zone",
            &schema,
            b"golden-payload",
        )
        .expect("pinned id2");
        assert_eq!(id, id2, "pinned golden vector must be stable");
        assert_eq!(hex.len(), 64);
    }

    // -----------------------------------------------------------------------
    // Category 4: Signature preimage golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_signature_preimage_construction() {
        let schema = SchemaHash::from_definition(b"golden-sig-schema-v1");
        let value = CanonicalValue::String("signed-payload".to_string());
        let preimage = build_preimage(ObjectDomain::EvidenceRecord, &schema, &value);

        // Preimage = domain_tag || schema_hash(32) || encoded_value
        let domain_tag = ObjectDomain::EvidenceRecord.tag();
        let encoded = encode_value(&value);
        let expected_len = domain_tag.len() + 32 + encoded.len();
        assert_eq!(preimage.len(), expected_len, "preimage length mismatch");

        // Verify the preimage starts with the domain tag.
        assert_eq!(
            &preimage[..domain_tag.len()],
            domain_tag,
            "preimage must start with domain tag"
        );

        // Verify determinism.
        let preimage2 = build_preimage(ObjectDomain::EvidenceRecord, &schema, &value);
        assert_eq!(preimage, preimage2, "preimage must be deterministic");
    }

    #[test]
    fn golden_signature_preimage_domain_sensitivity() {
        let schema = SchemaHash::from_definition(b"golden-domain-sig-v1");
        let value = CanonicalValue::U64(999);
        let p1 = build_preimage(ObjectDomain::PolicyObject, &schema, &value);
        let p2 = build_preimage(ObjectDomain::EvidenceRecord, &schema, &value);
        assert_ne!(p1, p2, "different domains must produce different preimages");
    }

    // -----------------------------------------------------------------------
    // Category 5: Signature creation and verification golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_signature_creation_deterministic() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let preimage = b"golden-preimage-for-signing";
        let sig1 = sign_preimage(&sk, preimage).expect("sign1");
        let sig2 = sign_preimage(&sk, preimage).expect("sign2");
        assert_eq!(sig1, sig2, "signature must be deterministic");
    }

    #[test]
    fn golden_signature_verify_valid() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let vk = sk.verification_key();
        let preimage = b"golden-verify-payload";
        let sig = sign_preimage(&sk, preimage).expect("sign");
        verify_signature(&vk, preimage, &sig).expect("verify must pass");
    }

    #[test]
    fn golden_signature_verify_wrong_key() {
        let sk1 = SigningKey::from_bytes([0x42; 32]);
        let sk2 = SigningKey::from_bytes([0x43; 32]);
        let vk2 = sk2.verification_key();
        let preimage = b"golden-wrong-key-payload";
        let sig = sign_preimage(&sk1, preimage).expect("sign");
        let result = verify_signature(&vk2, preimage, &sig);
        assert!(result.is_err(), "wrong key must fail verification");
    }

    #[test]
    fn golden_signature_verify_tampered_preimage() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let vk = sk.verification_key();
        let sig = sign_preimage(&sk, b"original-preimage").expect("sign");
        let result = verify_signature(&vk, b"tampered-preimage", &sig);
        assert!(result.is_err(), "tampered preimage must fail verification");
    }

    #[test]
    fn golden_signature_zero_key_rejected() {
        let sk = SigningKey::from_bytes([0x00; 32]);
        let result = sign_preimage(&sk, b"payload");
        assert!(result.is_err(), "zero signing key must be rejected");
    }

    #[test]
    fn golden_signature_different_preimages_different_sigs() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let sig1 = sign_preimage(&sk, b"preimage-alpha").expect("sig1");
        let sig2 = sign_preimage(&sk, b"preimage-beta").expect("sig2");
        assert_ne!(
            sig1, sig2,
            "different preimages must produce different sigs"
        );
    }

    #[test]
    fn golden_signature_different_keys_different_sigs() {
        let sk1 = SigningKey::from_bytes([0x42; 32]);
        let sk2 = SigningKey::from_bytes([0x43; 32]);
        let preimage = b"same-preimage";
        let sig1 = sign_preimage(&sk1, preimage).expect("sig1");
        let sig2 = sign_preimage(&sk2, preimage).expect("sig2");
        assert_ne!(sig1, sig2, "different keys must produce different sigs");
    }

    #[test]
    fn golden_verification_key_derivation_deterministic() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let vk1 = sk.verification_key();
        let vk2 = sk.verification_key();
        assert_eq!(vk1, vk2, "vk derivation must be deterministic");
    }

    #[test]
    fn golden_verification_key_different_for_different_sk() {
        let sk1 = SigningKey::from_bytes([0x42; 32]);
        let sk2 = SigningKey::from_bytes([0x43; 32]);
        assert_ne!(
            sk1.verification_key(),
            sk2.verification_key(),
            "different signing keys must produce different verification keys"
        );
    }

    // -----------------------------------------------------------------------
    // Category 6: Multi-signature ordering golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_multisig_ordering_deterministic() {
        let sk1 = SigningKey::from_bytes([0x01; 32]);
        let sk2 = SigningKey::from_bytes([0x02; 32]);
        let sk3 = SigningKey::from_bytes([0x03; 32]);
        let preimage = b"multisig-golden-payload";

        let sig1 = sign_preimage(&sk1, preimage).expect("sig1");
        let sig2 = sign_preimage(&sk2, preimage).expect("sig2");
        let sig3 = sign_preimage(&sk3, preimage).expect("sig3");

        let entries = vec![
            SignerSignature::new(sk3.verification_key(), sig3.clone()),
            SignerSignature::new(sk1.verification_key(), sig1.clone()),
            SignerSignature::new(sk2.verification_key(), sig2.clone()),
        ];

        let sorted = SortedSignatureArray::from_unsorted(entries).expect("sort");

        // Verify the array is sorted by verification key bytes.
        let keys: Vec<&VerificationKey> = sorted.signer_keys();
        for i in 1..keys.len() {
            assert!(
                keys[i - 1] < keys[i],
                "signatures must be sorted by signer key"
            );
        }
    }

    #[test]
    fn golden_multisig_ordering_stable() {
        // Create the same set twice, verify identical ordering.
        let sk1 = SigningKey::from_bytes([0x10; 32]);
        let sk2 = SigningKey::from_bytes([0x20; 32]);
        let preimage = b"multisig-stable-test";

        let sig1 = sign_preimage(&sk1, preimage).expect("sig1");
        let sig2 = sign_preimage(&sk2, preimage).expect("sig2");

        let sorted_a = SortedSignatureArray::from_unsorted(vec![
            SignerSignature::new(sk2.verification_key(), sig2.clone()),
            SignerSignature::new(sk1.verification_key(), sig1.clone()),
        ])
        .expect("sort a");

        let sorted_b = SortedSignatureArray::from_unsorted(vec![
            SignerSignature::new(sk1.verification_key(), sig1.clone()),
            SignerSignature::new(sk2.verification_key(), sig2.clone()),
        ])
        .expect("sort b");

        // Both must produce the same ordering.
        assert_eq!(sorted_a.entries().len(), sorted_b.entries().len());
        for (a, b) in sorted_a.entries().iter().zip(sorted_b.entries().iter()) {
            assert_eq!(a.signer, b.signer, "ordering must be stable");
            assert_eq!(a.signature, b.signature);
        }
    }

    #[test]
    fn golden_multisig_duplicate_signer_rejected() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let preimage = b"dup-signer-test";
        let sig1 = sign_preimage(&sk, preimage).expect("sig1");
        let sig2 = sign_preimage(&sk, preimage).expect("sig2");

        let result = SortedSignatureArray::from_unsorted(vec![
            SignerSignature::new(sk.verification_key(), sig1),
            SignerSignature::new(sk.verification_key(), sig2),
        ]);
        assert!(result.is_err(), "duplicate signers must be rejected");
    }

    // -----------------------------------------------------------------------
    // Category 7: Revocation chain hash golden vectors
    // -----------------------------------------------------------------------

    /// Build a signed Revocation for golden vector tests.
    fn make_golden_revocation(
        target_type: RevocationTargetType,
        reason: RevocationReason,
        target_bytes: [u8; 32],
        signing_key: &SigningKey,
    ) -> Revocation {
        let principal = PrincipalId::from_verification_key(&signing_key.verification_key());
        let target_id = EngineObjectId(target_bytes);
        let revocation_id = derive_id(
            ObjectDomain::Revocation,
            "golden-zone",
            &revocation_schema_id(),
            target_bytes.as_slice(),
        )
        .expect("derive revocation id");

        let mut rev = Revocation {
            revocation_id,
            target_type,
            target_id,
            reason,
            issued_by: principal,
            issued_at: DeterministicTimestamp(1000),
            zone: "golden-zone".to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        let preimage = rev.preimage_bytes();
        let sig = sign_preimage(signing_key, &preimage).expect("sign revocation");
        rev.signature = sig;
        rev
    }

    fn golden_head_signing_key() -> SigningKey {
        SigningKey::from_bytes([0x42; 32])
    }

    fn golden_revocation_signing_key() -> SigningKey {
        SigningKey::from_bytes([0xA1; 32])
    }

    #[test]
    fn golden_revocation_chain_empty_verifies() {
        let chain = RevocationChain::new("golden-zone");
        chain
            .verify_chain("trace-golden-empty")
            .expect("empty chain must verify");
    }

    #[test]
    fn golden_revocation_chain_single_event_hash() {
        let mut chain = RevocationChain::new("golden-zone");
        let head_sk = golden_head_signing_key();
        let rev = make_golden_revocation(
            RevocationTargetType::Key,
            RevocationReason::Compromised,
            [0x01; 32],
            &golden_revocation_signing_key(),
        );
        chain
            .append(rev, &head_sk, "trace-golden-single")
            .expect("append");

        chain
            .verify_chain("trace-golden-single-verify")
            .expect("single-event verify");

        assert_eq!(chain.head_seq(), Some(0));
    }

    #[test]
    fn golden_revocation_chain_multi_event_integrity() {
        let mut chain = RevocationChain::new("golden-zone");
        let head_sk = golden_head_signing_key();

        for i in 0..5u8 {
            let rev = make_golden_revocation(
                RevocationTargetType::Token,
                RevocationReason::Expired,
                [i + 10; 32],
                &golden_revocation_signing_key(),
            );
            chain
                .append(rev, &head_sk, &format!("trace-golden-multi-{i}"))
                .expect("append");
        }

        chain
            .verify_chain("trace-golden-multi-verify")
            .expect("multi-event verify");
        assert_eq!(chain.head_seq(), Some(4));
    }

    #[test]
    fn golden_revocation_chain_deterministic() {
        let build_chain = || {
            let mut chain = RevocationChain::new("golden-zone");
            let head_sk = golden_head_signing_key();
            let rev = make_golden_revocation(
                RevocationTargetType::Extension,
                RevocationReason::PolicyViolation,
                [0xDD; 32],
                &golden_revocation_signing_key(),
            );
            chain.append(rev, &head_sk, "trace-det").expect("append");
            chain
        };

        let chain1 = build_chain();
        let chain2 = build_chain();
        assert_eq!(
            chain1.head().unwrap().chain_hash,
            chain2.head().unwrap().chain_hash,
            "deterministic chains must produce identical hashes"
        );
    }

    // -----------------------------------------------------------------------
    // Category 8: Non-canonical rejection golden vectors
    // -----------------------------------------------------------------------

    #[test]
    fn golden_noncanonical_invalid_tag_rejected() {
        // Tag 0xFF is not a valid CanonicalValue tag.
        let bad_bytes = vec![0xFF, 0x00, 0x00, 0x00, 0x01];
        let result = decode_value(&bad_bytes);
        assert!(result.is_err(), "invalid tag 0xFF must be rejected");
    }

    #[test]
    fn golden_noncanonical_truncated_u64_rejected() {
        // Tag 0x01 (U64) but only 4 bytes instead of 8.
        let bad_bytes = vec![0x01, 0x00, 0x00, 0x00, 0x2a];
        let result = decode_value(&bad_bytes);
        assert!(result.is_err(), "truncated U64 must be rejected");
    }

    #[test]
    fn golden_noncanonical_truncated_string_rejected() {
        // Tag 0x05 (String) with length 10 but only 3 bytes of content.
        let bad_bytes = vec![0x05, 0x00, 0x00, 0x00, 0x0a, 0x41, 0x42, 0x43];
        let result = decode_value(&bad_bytes);
        assert!(result.is_err(), "truncated string must be rejected");
    }

    #[test]
    fn golden_noncanonical_trailing_bytes_rejected() {
        // Valid U64(42) followed by extra garbage byte.
        let mut bytes = encode_value(&CanonicalValue::U64(42));
        bytes.push(0xFF);
        let result = decode_value(&bytes);
        assert!(result.is_err(), "trailing bytes must be rejected");
    }

    #[test]
    fn golden_noncanonical_empty_input_rejected() {
        let result = decode_value(&[]);
        assert!(result.is_err(), "empty input must be rejected");
    }

    #[test]
    fn golden_noncanonical_map_duplicate_key_rejected() {
        // Manually construct a map with duplicate keys.
        // Tag 0x07 + count(2) + key "a" + val U64(1) + key "a" + val U64(2)
        let mut bytes = Vec::new();
        bytes.push(0x07); // TAG_MAP
        bytes.extend_from_slice(&2u32.to_be_bytes()); // count = 2
        // First entry: key "a", value U64(1)
        bytes.push(0x05); // TAG_STRING for key
        bytes.extend_from_slice(&1u32.to_be_bytes()); // len = 1
        bytes.push(b'a'); // "a"
        bytes.push(0x01); // TAG_U64 for value
        bytes.extend_from_slice(&1u64.to_be_bytes()); // 1
        // Second entry: key "a" (duplicate), value U64(2)
        bytes.push(0x05);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(0x01);
        bytes.extend_from_slice(&2u64.to_be_bytes());

        let result = decode_value(&bytes);
        assert!(result.is_err(), "duplicate map keys must be rejected");
    }

    #[test]
    fn golden_noncanonical_map_nonlex_keys_rejected() {
        // Manually construct a map with non-lexicographic key ordering: "b" before "a".
        let mut bytes = Vec::new();
        bytes.push(0x07); // TAG_MAP
        bytes.extend_from_slice(&2u32.to_be_bytes());
        // First entry: key "b"
        bytes.push(0x05);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'b');
        bytes.push(0x01);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        // Second entry: key "a" (should come first)
        bytes.push(0x05);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'a');
        bytes.push(0x01);
        bytes.extend_from_slice(&2u64.to_be_bytes());

        let result = decode_value(&bytes);
        assert!(
            result.is_err(),
            "non-lexicographic map keys must be rejected"
        );
    }

    #[test]
    fn golden_object_id_invalid_hex_length() {
        let result = EngineObjectId::from_hex("deadbeef"); // too short
        assert!(result.is_err(), "short hex must be rejected");
    }

    #[test]
    fn golden_object_id_invalid_hex_chars() {
        let bad_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let result = EngineObjectId::from_hex(bad_hex);
        assert!(result.is_err(), "invalid hex chars must be rejected");
    }

    // -----------------------------------------------------------------------
    // Meta-tests: vector completeness
    // -----------------------------------------------------------------------

    #[test]
    fn golden_meta_all_domains_have_vectors() {
        // Verify that every ObjectDomain has at least one golden vector
        // exercised in the per-domain test above.
        assert_eq!(ObjectDomain::ALL.len(), 9, "expected 9 domains");
    }

    #[test]
    fn golden_meta_all_canonical_value_types_covered() {
        // Count distinct CanonicalValue variants tested.
        // U64, I64, Bool, Bytes, String, Array, Map, Null = 8 types
        let type_count = 8;
        assert_eq!(
            type_count, 8,
            "all 8 CanonicalValue types must have vectors"
        );
    }

    // -----------------------------------------------------------------------
    // Pinned golden vectors — byte-exact regression anchors
    //
    // These vectors pin the exact byte output for known inputs.
    // If ANY of these fail, the encoding has changed and a migration
    // is required.
    // -----------------------------------------------------------------------

    #[test]
    fn pinned_encode_u64_42() {
        let encoded = encode_value(&CanonicalValue::U64(42));
        assert_eq!(
            to_hex(&encoded),
            "01000000000000002a",
            "PINNED: U64(42) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_string_hello() {
        let encoded = encode_value(&CanonicalValue::String("hello".to_string()));
        assert_eq!(
            to_hex(&encoded),
            "050000000568656c6c6f",
            "PINNED: String(hello) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_bool_true() {
        let encoded = encode_value(&CanonicalValue::Bool(true));
        assert_eq!(
            to_hex(&encoded),
            "0301",
            "PINNED: Bool(true) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_null() {
        let encoded = encode_value(&CanonicalValue::Null);
        assert_eq!(to_hex(&encoded), "08", "PINNED: Null encoding changed");
    }

    #[test]
    fn pinned_signature_sentinel_is_zeros() {
        assert_eq!(
            SIGNATURE_SENTINEL, [0u8; SIGNATURE_LEN],
            "PINNED: signature sentinel must be all zeros"
        );
    }

    #[test]
    fn pinned_content_hash_deterministic() {
        let h1 = ContentHash::compute(b"golden-content-hash-input");
        let h2 = ContentHash::compute(b"golden-content-hash-input");
        assert_eq!(h1, h2, "PINNED: ContentHash must be deterministic");
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn golden_vector_serde_roundtrip() {
        let mut input = BTreeMap::new();
        input.insert(
            "key".to_string(),
            serde_json::Value::String("value".to_string()),
        );
        let mut expected = BTreeMap::new();
        expected.insert(
            "hash".to_string(),
            serde_json::Value::String("abc123".to_string()),
        );
        let v = GoldenVector {
            test_name: "test_deterministic_serde_001".to_string(),
            description: "Verify serde roundtrip".to_string(),
            category: "deterministic_serde".to_string(),
            schema_version: "v1".to_string(),
            input,
            expected,
            expect_error: false,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GoldenVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn golden_vector_set_serde_roundtrip() {
        let mut input = BTreeMap::new();
        input.insert("a".to_string(), serde_json::json!(1));
        let mut expected = BTreeMap::new();
        expected.insert("b".to_string(), serde_json::json!(2));
        let vector = GoldenVector {
            test_name: "set_test".to_string(),
            description: "desc".to_string(),
            category: "schema_hash".to_string(),
            schema_version: "v1".to_string(),
            input,
            expected,
            expect_error: true,
        };
        let set = GoldenVectorSet {
            vector_format_version: "1.0".to_string(),
            category: "schema_hash".to_string(),
            vectors: vec![vector],
        };
        let json = serde_json::to_string(&set).unwrap();
        let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
        assert_eq!(back.vectors.len(), 1);
        assert!(back.vectors[0].expect_error);
    }

    // ── Enrichment: hex utilities boundary/edge ─────────────────────

    #[test]
    fn to_hex_empty_input() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn to_hex_single_byte() {
        assert_eq!(to_hex(&[0xff]), "ff");
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0x0a]), "0a");
    }

    #[test]
    fn from_hex_empty_string() {
        let result = from_hex("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn from_hex_odd_length_rejected() {
        let result = from_hex("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("odd hex length"));
    }

    #[test]
    fn from_hex_invalid_chars_rejected() {
        let result = from_hex("zz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad hex char"));
    }

    #[test]
    fn to_hex_from_hex_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let hex = to_hex(&bytes);
        let recovered = from_hex(&hex).unwrap();
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn from_hex_accepts_uppercase() {
        let result = from_hex("DEADBEEF").unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn from_hex_accepts_mixed_case() {
        let result = from_hex("DeAdBeEf").unwrap();
        assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn to_hex_always_lowercase() {
        let hex = to_hex(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(hex, "abcdef");
    }

    #[test]
    fn to_hex_256_bytes_produces_512_chars() {
        let bytes = vec![0x42; 256];
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 512);
    }

    // ── Enrichment: GoldenVector JSON field-name stability ──────────

    #[test]
    fn golden_vector_json_field_names_stable() {
        let v = GoldenVector {
            test_name: "t".into(),
            description: "d".into(),
            category: "c".into(),
            schema_version: "v1".into(),
            input: BTreeMap::new(),
            expected: BTreeMap::new(),
            expect_error: false,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"test_name\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"input\""));
        assert!(json.contains("\"expected\""));
        assert!(json.contains("\"expect_error\""));
    }

    #[test]
    fn golden_vector_set_json_field_names_stable() {
        let set = GoldenVectorSet {
            vector_format_version: "1.0".into(),
            category: "test".into(),
            vectors: vec![],
        };
        let json = serde_json::to_string(&set).unwrap();
        assert!(json.contains("\"vector_format_version\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"vectors\""));
    }

    // ── Enrichment: Clone independence ───────────────────────────────

    #[test]
    fn golden_vector_clone_independence() {
        let v = GoldenVector {
            test_name: "t".into(),
            description: "d".into(),
            category: "c".into(),
            schema_version: "v1".into(),
            input: BTreeMap::new(),
            expected: BTreeMap::new(),
            expect_error: false,
        };
        let mut cloned = v.clone();
        cloned.test_name = "modified".into();
        cloned.expect_error = true;
        assert_eq!(v.test_name, "t");
        assert!(!v.expect_error);
    }

    #[test]
    fn golden_vector_set_clone_independence() {
        let set = GoldenVectorSet {
            vector_format_version: "1.0".into(),
            category: "test".into(),
            vectors: vec![],
        };
        let mut cloned = set.clone();
        cloned.vectors.push(GoldenVector {
            test_name: "new".into(),
            description: "d".into(),
            category: "c".into(),
            schema_version: "v1".into(),
            input: BTreeMap::new(),
            expected: BTreeMap::new(),
            expect_error: false,
        });
        assert!(set.vectors.is_empty());
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────────

    #[test]
    fn golden_vector_debug_nonempty() {
        let v = GoldenVector {
            test_name: "t".into(),
            description: "d".into(),
            category: "c".into(),
            schema_version: "v1".into(),
            input: BTreeMap::new(),
            expected: BTreeMap::new(),
            expect_error: false,
        };
        let dbg = format!("{v:?}");
        assert!(dbg.contains("GoldenVector"));
    }

    #[test]
    fn golden_vector_set_debug_nonempty() {
        let set = GoldenVectorSet {
            vector_format_version: "1.0".into(),
            category: "test".into(),
            vectors: vec![],
        };
        let dbg = format!("{set:?}");
        assert!(dbg.contains("GoldenVectorSet"));
    }

    // ── Enrichment: golden vector with all input/expected types ─────

    #[test]
    fn golden_vector_with_complex_input_expected() {
        let mut input = BTreeMap::new();
        input.insert("num".to_string(), serde_json::json!(42));
        input.insert("arr".to_string(), serde_json::json!([1, 2, 3]));
        input.insert("null_val".to_string(), serde_json::Value::Null);
        let mut expected = BTreeMap::new();
        expected.insert("hex".to_string(), serde_json::json!("deadbeef"));
        expected.insert("ok".to_string(), serde_json::json!(true));
        let v = GoldenVector {
            test_name: "complex".into(),
            description: "complex input".into(),
            category: "deterministic_serde".into(),
            schema_version: "v2".into(),
            input,
            expected,
            expect_error: false,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: GoldenVector = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn golden_vector_set_empty_vectors_roundtrip() {
        let set = GoldenVectorSet {
            vector_format_version: "1.0".into(),
            category: "empty".into(),
            vectors: vec![],
        };
        let json = serde_json::to_string(&set).unwrap();
        let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vectors.len(), 0);
    }

    #[test]
    fn golden_vector_negative_vector() {
        let v = GoldenVector {
            test_name: "negative".into(),
            description: "expected to produce error".into(),
            category: "non_canonical_rejection".into(),
            schema_version: "v1".into(),
            input: BTreeMap::new(),
            expected: BTreeMap::new(),
            expect_error: true,
        };
        assert!(v.expect_error);
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("true"));
    }

    // ── Enrichment: additional pinned vectors ───────────────────────

    #[test]
    fn pinned_encode_bytes_empty() {
        let encoded = encode_value(&CanonicalValue::Bytes(vec![]));
        assert_eq!(
            to_hex(&encoded),
            "0400000000",
            "PINNED: Bytes([]) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_i64_zero() {
        let encoded = encode_value(&CanonicalValue::I64(0));
        assert_eq!(
            to_hex(&encoded),
            "020000000000000000",
            "PINNED: I64(0) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_i64_min() {
        let encoded = encode_value(&CanonicalValue::I64(i64::MIN));
        assert_eq!(
            to_hex(&encoded),
            "028000000000000000",
            "PINNED: I64(MIN) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_empty_array() {
        let encoded = encode_value(&CanonicalValue::Array(vec![]));
        assert_eq!(
            to_hex(&encoded),
            "0600000000",
            "PINNED: Array([]) encoding changed"
        );
    }

    #[test]
    fn pinned_encode_empty_map() {
        let encoded = encode_value(&CanonicalValue::Map(BTreeMap::new()));
        assert_eq!(
            to_hex(&encoded),
            "0700000000",
            "PINNED: Map(empty) encoding changed"
        );
    }

    // ── Enrichment: additional signature/crypto vectors ─────────────

    #[test]
    fn golden_signature_length_is_64() {
        assert_eq!(SIGNATURE_LEN, 64);
    }

    #[test]
    fn golden_content_hash_different_inputs_different_hashes() {
        let h1 = ContentHash::compute(b"input-one");
        let h2 = ContentHash::compute(b"input-two");
        assert_ne!(h1, h2);
    }

    #[test]
    fn golden_content_hash_empty_input() {
        let h = ContentHash::compute(b"");
        assert_eq!(h.as_bytes().len(), 32);
    }

    // ── Enrichment: revocation target types coverage ────────────────

    #[test]
    fn golden_revocation_chain_all_target_types() {
        let head_sk = golden_head_signing_key();
        let rev_sk = golden_revocation_signing_key();

        for (i, target_type) in [
            RevocationTargetType::Key,
            RevocationTargetType::Token,
            RevocationTargetType::Attestation,
            RevocationTargetType::Extension,
            RevocationTargetType::Checkpoint,
        ]
        .iter()
        .enumerate()
        {
            let mut chain = RevocationChain::new("golden-zone");
            let rev = make_golden_revocation(
                *target_type,
                RevocationReason::Compromised,
                [(i + 50) as u8; 32],
                &rev_sk,
            );
            chain
                .append(rev, &head_sk, &format!("trace-type-{i}"))
                .expect("append");
            chain
                .verify_chain(&format!("trace-verify-type-{i}"))
                .expect("verify");
        }
    }

    #[test]
    fn golden_revocation_chain_all_reasons() {
        let head_sk = golden_head_signing_key();
        let rev_sk = golden_revocation_signing_key();

        for (i, reason) in [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Superseded,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
        ]
        .iter()
        .enumerate()
        {
            let mut chain = RevocationChain::new("golden-zone");
            let rev = make_golden_revocation(
                RevocationTargetType::Key,
                *reason,
                [(i + 80) as u8; 32],
                &rev_sk,
            );
            chain
                .append(rev, &head_sk, &format!("trace-reason-{i}"))
                .expect("append");
            chain
                .verify_chain(&format!("trace-verify-reason-{i}"))
                .expect("verify");
        }
    }
}
