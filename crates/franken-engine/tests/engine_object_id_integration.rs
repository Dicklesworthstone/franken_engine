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
