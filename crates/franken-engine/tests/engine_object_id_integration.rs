//! Integration tests for the `engine_object_id` module.
//!
//! Tests domain-separated deterministic object identity: derive_id, verify_id,
//! ObjectDomain, SchemaId, EngineObjectId, hex encode/decode, serde.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::engine_object_id::{
    EngineObjectId, IdError, OBJECT_ID_LEN, ObjectDomain, SchemaId, derive_id, verify_id,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_schema() -> SchemaId {
    SchemaId::from_definition(b"test-schema-v1")
}

// ---------------------------------------------------------------------------
// ObjectDomain
// ---------------------------------------------------------------------------

#[test]
fn all_domains_have_unique_tags() {
    let tags: Vec<&[u8]> = ObjectDomain::ALL.iter().map(|d| d.tag()).collect();
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn domain_all_has_correct_count() {
    assert_eq!(ObjectDomain::ALL.len(), 9);
}

#[test]
fn domain_display_all_variants() {
    let expected = [
        (ObjectDomain::PolicyObject, "policy_object"),
        (ObjectDomain::EvidenceRecord, "evidence_record"),
        (ObjectDomain::Revocation, "revocation"),
        (ObjectDomain::SignedManifest, "signed_manifest"),
        (ObjectDomain::Attestation, "attestation"),
        (ObjectDomain::CapabilityToken, "capability_token"),
        (ObjectDomain::CheckpointArtifact, "checkpoint_artifact"),
        (ObjectDomain::RecoveryArtifact, "recovery_artifact"),
        (ObjectDomain::KeyBundle, "key_bundle"),
    ];
    for (domain, display) in &expected {
        assert_eq!(domain.to_string(), *display);
    }
}

#[test]
fn domain_tags_start_with_frankenengine() {
    for domain in ObjectDomain::ALL {
        let tag = std::str::from_utf8(domain.tag()).unwrap();
        assert!(
            tag.starts_with("FrankenEngine."),
            "tag '{tag}' should start with FrankenEngine."
        );
    }
}

// ---------------------------------------------------------------------------
// SchemaId
// ---------------------------------------------------------------------------

#[test]
fn schema_id_from_definition_deterministic() {
    let a = SchemaId::from_definition(b"my-schema");
    let b = SchemaId::from_definition(b"my-schema");
    assert_eq!(a, b);
}

#[test]
fn schema_id_different_definitions_differ() {
    let a = SchemaId::from_definition(b"schema-v1");
    let b = SchemaId::from_definition(b"schema-v2");
    assert_ne!(a, b);
}

#[test]
fn schema_id_display_is_64_hex_chars() {
    let schema = SchemaId::from_definition(b"test");
    let display = schema.to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn schema_id_from_bytes_roundtrip() {
    let original = SchemaId::from_definition(b"roundtrip");
    let bytes = *original.as_bytes();
    let restored = SchemaId::from_bytes(bytes);
    assert_eq!(original, restored);
}

// ---------------------------------------------------------------------------
// derive_id — determinism
// ---------------------------------------------------------------------------

#[test]
fn derive_id_is_deterministic() {
    let id1 = derive_id(
        ObjectDomain::PolicyObject,
        "zone-a",
        &test_schema(),
        b"content",
    )
    .unwrap();
    let id2 = derive_id(
        ObjectDomain::PolicyObject,
        "zone-a",
        &test_schema(),
        b"content",
    )
    .unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn derive_id_produces_32_bytes() {
    let id = derive_id(
        ObjectDomain::EvidenceRecord,
        "zone",
        &test_schema(),
        b"data",
    )
    .unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

// ---------------------------------------------------------------------------
// derive_id — domain separation
// ---------------------------------------------------------------------------

#[test]
fn different_domains_produce_different_ids() {
    let schema = test_schema();
    let ids: Vec<EngineObjectId> = ObjectDomain::ALL
        .iter()
        .map(|d| derive_id(*d, "zone", &schema, b"content").unwrap())
        .collect();
    for (i, a) in ids.iter().enumerate() {
        for (j, b) in ids.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn different_zones_produce_different_ids() {
    let schema = test_schema();
    let id_a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"x").unwrap();
    let id_b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, b"x").unwrap();
    assert_ne!(id_a, id_b);
}

#[test]
fn different_schemas_produce_different_ids() {
    let s1 = SchemaId::from_definition(b"v1");
    let s2 = SchemaId::from_definition(b"v2");
    let id1 = derive_id(ObjectDomain::Revocation, "zone", &s1, b"data").unwrap();
    let id2 = derive_id(ObjectDomain::Revocation, "zone", &s2, b"data").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn different_content_produces_different_ids() {
    let schema = test_schema();
    let id_a = derive_id(ObjectDomain::Attestation, "zone", &schema, b"aaa").unwrap();
    let id_b = derive_id(ObjectDomain::Attestation, "zone", &schema, b"bbb").unwrap();
    assert_ne!(id_a, id_b);
}

// ---------------------------------------------------------------------------
// derive_id — error cases
// ---------------------------------------------------------------------------

#[test]
fn derive_rejects_empty_canonical_bytes() {
    let err = derive_id(ObjectDomain::PolicyObject, "zone", &test_schema(), b"").unwrap_err();
    assert_eq!(err, IdError::EmptyCanonicalBytes);
}

// ---------------------------------------------------------------------------
// verify_id
// ---------------------------------------------------------------------------

#[test]
fn verify_id_succeeds_on_correct_components() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").unwrap();
    verify_id(&id, ObjectDomain::PolicyObject, "zone", &schema, b"data").unwrap();
}

#[test]
fn verify_id_fails_on_tampered_content() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").unwrap();
    let err = verify_id(
        &id,
        ObjectDomain::PolicyObject,
        "zone",
        &schema,
        b"tampered",
    )
    .unwrap_err();
    assert!(matches!(err, IdError::IdMismatch { .. }));
}

#[test]
fn verify_id_fails_on_wrong_domain() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"data").unwrap();
    let err = verify_id(&id, ObjectDomain::EvidenceRecord, "zone", &schema, b"data").unwrap_err();
    assert!(matches!(err, IdError::IdMismatch { .. }));
}

#[test]
fn verify_id_fails_on_wrong_zone() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"data").unwrap();
    let err = verify_id(&id, ObjectDomain::PolicyObject, "zone-b", &schema, b"data").unwrap_err();
    assert!(matches!(err, IdError::IdMismatch { .. }));
}

#[test]
fn verify_id_fails_on_wrong_schema() {
    let s1 = SchemaId::from_definition(b"v1");
    let s2 = SchemaId::from_definition(b"v2");
    let id = derive_id(ObjectDomain::Attestation, "zone", &s1, b"data").unwrap();
    let err = verify_id(&id, ObjectDomain::Attestation, "zone", &s2, b"data").unwrap_err();
    assert!(matches!(err, IdError::IdMismatch { .. }));
}

// ---------------------------------------------------------------------------
// EngineObjectId — hex encode/decode
// ---------------------------------------------------------------------------

#[test]
fn hex_roundtrip() {
    let id = derive_id(
        ObjectDomain::KeyBundle,
        "zone",
        &test_schema(),
        b"keybundle",
    )
    .unwrap();
    let hex = id.to_hex();
    let restored = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn hex_display_is_64_lowercase_chars() {
    let id = derive_id(ObjectDomain::Revocation, "zone", &test_schema(), b"revoke").unwrap();
    let display = id.to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
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

#[test]
fn hex_decode_uppercase_accepted() {
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &test_schema(), b"upper").unwrap();
    let hex_upper = id.to_hex().to_uppercase();
    let restored = EngineObjectId::from_hex(&hex_upper).unwrap();
    assert_eq!(id, restored);
}

// ---------------------------------------------------------------------------
// IdError — display
// ---------------------------------------------------------------------------

#[test]
fn id_error_display_all_variants() {
    let errors: Vec<(IdError, &str)> = vec![
        (IdError::EmptyCanonicalBytes, "empty"),
        (
            IdError::InvalidHexLength {
                expected: 64,
                actual: 10,
            },
            "64",
        ),
        (IdError::InvalidHexChar { position: 5 }, "5"),
        (
            IdError::NonCanonicalInput {
                reason: "bad bytes".to_string(),
            },
            "bad bytes",
        ),
    ];
    for (err, expected_substr) in &errors {
        let msg = format!("{err}");
        assert!(msg.contains(expected_substr));
    }
}

#[test]
fn id_error_id_mismatch_display() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"a").unwrap();
    let err = verify_id(&id, ObjectDomain::PolicyObject, "z", &schema, b"b").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("mismatch"));
}

#[test]
fn id_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(IdError::EmptyCanonicalBytes);
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn engine_object_id_serde_roundtrip() {
    let id = derive_id(
        ObjectDomain::PolicyObject,
        "zone",
        &test_schema(),
        b"content",
    )
    .unwrap();
    let json = serde_json::to_string(&id).unwrap();
    let decoded: EngineObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, decoded);
}

#[test]
fn schema_id_serde_roundtrip() {
    let schema = test_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let decoded: SchemaId = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, decoded);
}

#[test]
fn object_domain_serde_roundtrip_all() {
    for domain in ObjectDomain::ALL {
        let json = serde_json::to_string(domain).unwrap();
        let decoded: ObjectDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*domain, decoded);
    }
}

#[test]
fn id_error_serde_roundtrip() {
    let errors = vec![
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
        let json = serde_json::to_string(err).unwrap();
        let decoded: IdError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn single_byte_canonical_content() {
    let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema(), &[0xff]).unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

#[test]
fn large_canonical_content() {
    let big = vec![0xab; 65536];
    let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema(), &big).unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

#[test]
fn empty_zone_is_valid() {
    let id = derive_id(ObjectDomain::PolicyObject, "", &test_schema(), b"data").unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

#[test]
fn unicode_zone_is_valid() {
    let id = derive_id(
        ObjectDomain::PolicyObject,
        "zone/日本語/测试",
        &test_schema(),
        b"data",
    )
    .unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

// ---------------------------------------------------------------------------
// Determinism — multiple runs
// ---------------------------------------------------------------------------

#[test]
fn derive_deterministic_across_10_runs() {
    let ids: Vec<EngineObjectId> = (0..10)
        .map(|_| {
            derive_id(
                ObjectDomain::SignedManifest,
                "prod",
                &test_schema(),
                b"manifest-bytes",
            )
            .unwrap()
        })
        .collect();
    for id in &ids[1..] {
        assert_eq!(&ids[0], id);
    }
}

// ---------------------------------------------------------------------------
// Collision resistance — pairwise uniqueness across all 9 domains
// ---------------------------------------------------------------------------

#[test]
fn all_domain_zone_pairs_produce_unique_ids() {
    let schema = test_schema();
    let zones = ["zone-a", "zone-b", "zone-c"];
    let mut seen = std::collections::BTreeSet::new();
    for domain in ObjectDomain::ALL {
        for zone in &zones {
            let id = derive_id(*domain, zone, &schema, b"data").unwrap();
            assert!(
                seen.insert(id.to_hex()),
                "duplicate ID for domain={domain}, zone={zone}"
            );
        }
    }
    assert_eq!(seen.len(), ObjectDomain::ALL.len() * zones.len());
}

// ---------------------------------------------------------------------------
// Length-prefix unambiguity
// ---------------------------------------------------------------------------

#[test]
fn zone_prefix_length_prevents_collision() {
    // "ab" + "c" vs "a" + "bc" should differ because of length prefixes
    let schema = test_schema();
    let id1 = derive_id(ObjectDomain::PolicyObject, "abc", &schema, b"x").unwrap();
    let id2 = derive_id(ObjectDomain::PolicyObject, "ab", &schema, b"cx").unwrap();
    assert_ne!(id1, id2, "different zone+content splits must differ");
}

#[test]
fn empty_vs_nonempty_content_differs() {
    let schema = test_schema();
    let id_short = derive_id(ObjectDomain::PolicyObject, "z", &schema, &[0x00]).unwrap();
    let id_longer = derive_id(ObjectDomain::PolicyObject, "z", &schema, &[0x00, 0x00]).unwrap();
    assert_ne!(id_short, id_longer);
}

// ---------------------------------------------------------------------------
// Hex edge cases
// ---------------------------------------------------------------------------

#[test]
fn hex_empty_string_is_invalid() {
    let err = EngineObjectId::from_hex("").unwrap_err();
    assert!(matches!(err, IdError::InvalidHexLength { .. }));
}

#[test]
fn hex_odd_length_is_invalid() {
    let err = EngineObjectId::from_hex(&"a".repeat(63)).unwrap_err();
    assert!(matches!(err, IdError::InvalidHexLength { .. }));
}

#[test]
fn hex_too_long_is_invalid() {
    let err = EngineObjectId::from_hex(&"00".repeat(33)).unwrap_err();
    assert!(matches!(err, IdError::InvalidHexLength { .. }));
}

#[test]
fn hex_mixed_case_accepted() {
    let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema(), b"data").unwrap();
    let hex = id.to_hex();
    // Mix case: first half upper, second half lower
    let mixed: String = hex
        .char_indices()
        .map(|(i, c)| if i < 32 { c.to_ascii_uppercase() } else { c })
        .collect();
    let restored = EngineObjectId::from_hex(&mixed).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn hex_all_zeros_valid() {
    let id = EngineObjectId::from_hex(&"00".repeat(32)).unwrap();
    assert_eq!(id.as_bytes(), &[0u8; 32]);
}

#[test]
fn hex_all_ff_valid() {
    let id = EngineObjectId::from_hex(&"ff".repeat(32)).unwrap();
    assert_eq!(id.as_bytes(), &[0xff; 32]);
}

// ---------------------------------------------------------------------------
// Verify — correct ID passes
// ---------------------------------------------------------------------------

#[test]
fn verify_id_succeeds_for_all_domains() {
    let schema = test_schema();
    for domain in ObjectDomain::ALL {
        let id = derive_id(*domain, "zone", &schema, b"verify-all").unwrap();
        verify_id(&id, *domain, "zone", &schema, b"verify-all").unwrap();
    }
}

#[test]
fn verify_id_fails_with_flipped_bit() {
    let schema = test_schema();
    let mut id = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"data").unwrap();
    id.0[0] ^= 0x01; // flip one bit
    let err = verify_id(&id, ObjectDomain::PolicyObject, "z", &schema, b"data").unwrap_err();
    if let IdError::IdMismatch { expected, computed } = &err {
        assert_ne!(expected, computed);
    } else {
        panic!("expected IdMismatch, got {err}");
    }
}

// ---------------------------------------------------------------------------
// EngineObjectId — Display, Debug, Ord
// ---------------------------------------------------------------------------

#[test]
fn display_and_to_hex_are_identical() {
    let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema(), b"x").unwrap();
    assert_eq!(id.to_string(), id.to_hex());
}

#[test]
fn engine_object_id_has_debug() {
    let id = derive_id(ObjectDomain::PolicyObject, "z", &test_schema(), b"debug").unwrap();
    let debug = format!("{id:?}");
    assert!(!debug.is_empty());
}

#[test]
fn engine_object_id_ord_consistent_with_eq() {
    let schema = test_schema();
    let id1 = derive_id(ObjectDomain::PolicyObject, "a", &schema, b"x").unwrap();
    let id2 = derive_id(ObjectDomain::PolicyObject, "b", &schema, b"x").unwrap();
    let id1_dup = derive_id(ObjectDomain::PolicyObject, "a", &schema, b"x").unwrap();
    assert_eq!(id1.cmp(&id1_dup), std::cmp::Ordering::Equal);
    assert_ne!(id1.cmp(&id2), std::cmp::Ordering::Equal);
}

// ---------------------------------------------------------------------------
// IdError — IdMismatch carries both ids
// ---------------------------------------------------------------------------

#[test]
fn id_mismatch_contains_both_ids() {
    let schema = test_schema();
    let real = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"real").unwrap();
    let err = verify_id(&real, ObjectDomain::PolicyObject, "z", &schema, b"fake").unwrap_err();
    if let IdError::IdMismatch { expected, computed } = err {
        assert_eq!(expected, real);
        assert_ne!(expected, computed);
    } else {
        panic!("expected IdMismatch");
    }
}

// ---------------------------------------------------------------------------
// SchemaId — edge cases
// ---------------------------------------------------------------------------

#[test]
fn schema_id_from_empty_definition() {
    let schema = SchemaId::from_definition(b"");
    assert_eq!(schema.as_bytes().len(), 32);
}

#[test]
fn schema_id_large_definition() {
    let large = vec![0xaa; 100_000];
    let schema = SchemaId::from_definition(&large);
    assert_eq!(schema.as_bytes().len(), 32);
}

#[test]
fn schema_id_binary_content() {
    let binary: Vec<u8> = (0..=255).collect();
    let schema = SchemaId::from_definition(&binary);
    let schema2 = SchemaId::from_definition(&binary);
    assert_eq!(schema, schema2);
}

// ---------------------------------------------------------------------------
// ObjectDomain — ordering
// ---------------------------------------------------------------------------

#[test]
fn object_domain_ord_consistent() {
    for (i, a) in ObjectDomain::ALL.iter().enumerate() {
        for (j, b) in ObjectDomain::ALL.iter().enumerate() {
            if i < j {
                assert!(a < b, "{a} should be < {b}");
            } else if i == j {
                assert_eq!(a, b);
            } else {
                assert!(a > b, "{a} should be > {b}");
            }
        }
    }
}

#[test]
fn object_domain_hash_consistent_with_eq() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for domain in ObjectDomain::ALL {
        assert!(set.insert(*domain));
    }
    assert_eq!(set.len(), ObjectDomain::ALL.len());
    // Inserting again should fail
    for domain in ObjectDomain::ALL {
        assert!(!set.insert(*domain));
    }
}

// ---------------------------------------------------------------------------
// Domain tag uniqueness — no tag is a prefix of another
// ---------------------------------------------------------------------------

#[test]
fn no_domain_tag_is_prefix_of_another() {
    for (i, a) in ObjectDomain::ALL.iter().enumerate() {
        for (j, b) in ObjectDomain::ALL.iter().enumerate() {
            if i != j {
                let tag_a = a.tag();
                let tag_b = b.tag();
                assert!(
                    !tag_a.starts_with(tag_b) && !tag_b.starts_with(tag_a),
                    "tag {} should not be a prefix of {}",
                    std::str::from_utf8(tag_a).unwrap(),
                    std::str::from_utf8(tag_b).unwrap()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full lifecycle integration
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_derive_verify_serialize_deserialize() {
    let schema = SchemaId::from_definition(b"lifecycle-schema-v1");
    let domain = ObjectDomain::SignedManifest;
    let zone = "production/us-east-1";
    let content = b"manifest-payload-bytes-here";

    // 1. Derive
    let id = derive_id(domain, zone, &schema, content).unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);

    // 2. Verify
    verify_id(&id, domain, zone, &schema, content).unwrap();

    // 3. Hex roundtrip
    let hex = id.to_hex();
    assert_eq!(hex.len(), 64);
    let from_hex = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(from_hex, id);

    // 4. Serde roundtrip
    let json = serde_json::to_string(&id).unwrap();
    let from_json: EngineObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(from_json, id);

    // 5. Schema serde
    let schema_json = serde_json::to_string(&schema).unwrap();
    let schema_back: SchemaId = serde_json::from_str(&schema_json).unwrap();
    assert_eq!(schema_back, schema);

    // 6. Domain serde
    let domain_json = serde_json::to_string(&domain).unwrap();
    let domain_back: ObjectDomain = serde_json::from_str(&domain_json).unwrap();
    assert_eq!(domain_back, domain);
}

// ---------------------------------------------------------------------------
// Content sensitivity — single byte change produces different ID
// ---------------------------------------------------------------------------

#[test]
fn single_byte_change_produces_different_id() {
    let schema = test_schema();
    let base = vec![0x42; 100];
    let id_base = derive_id(ObjectDomain::PolicyObject, "z", &schema, &base).unwrap();
    for pos in 0..base.len() {
        let mut modified = base.clone();
        modified[pos] ^= 0x01;
        let id_mod = derive_id(ObjectDomain::PolicyObject, "z", &schema, &modified).unwrap();
        assert_ne!(
            id_base, id_mod,
            "flipping byte at position {pos} should change ID"
        );
    }
}
