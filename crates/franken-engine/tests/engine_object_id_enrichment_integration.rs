#![forbid(unsafe_code)]

//! Enrichment integration tests for the `engine_object_id` module.
//!
//! Covers Clone independence, BTreeSet ordering, Debug/Default, serde
//! field-name stability, std::error::Error, determinism, from_hex edge
//! cases, and cross-domain collision resistance.

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

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_schema() -> SchemaId {
    SchemaId::from_definition(b"enrich-schema-v1")
}

fn test_id() -> EngineObjectId {
    derive_id(
        ObjectDomain::PolicyObject,
        "enrich-zone",
        &test_schema(),
        b"enrich-content",
    )
    .unwrap()
}

// ===========================================================================
// Copy semantics (ObjectDomain has Copy)
// ===========================================================================

#[test]
fn enrichment_object_domain_copy() {
    let a = ObjectDomain::PolicyObject;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_engine_object_id_clone_independence() {
    let original = test_id();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_schema_id_clone_independence() {
    let original = test_schema();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_id_error_clone_independence() {
    let original = IdError::EmptyCanonicalBytes;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_object_domain_btreeset_ordering() {
    let variants: BTreeSet<ObjectDomain> = ObjectDomain::ALL.iter().copied().collect();
    assert_eq!(variants.len(), ObjectDomain::ALL.len());
    // First should be PolicyObject (declaration order with derived Ord)
    let first = variants.iter().next().unwrap();
    assert_eq!(*first, ObjectDomain::PolicyObject);
}

#[test]
fn enrichment_schema_id_btreeset_ordering() {
    let a = SchemaId::from_definition(b"aaa");
    let b = SchemaId::from_definition(b"bbb");
    let c = SchemaId::from_definition(b"ccc");
    let set: BTreeSet<SchemaId> = [c.clone(), a.clone(), b.clone()].into_iter().collect();
    assert_eq!(set.len(), 3);
    // Order should be deterministic (byte-wise comparison)
}

#[test]
fn enrichment_engine_object_id_btreeset_ordering() {
    let schema = test_schema();
    let a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"content-1").unwrap();
    let b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, b"content-2").unwrap();
    let c = derive_id(
        ObjectDomain::EvidenceRecord,
        "zone-a",
        &schema,
        b"content-1",
    )
    .unwrap();
    let set: BTreeSet<EngineObjectId> = [c.clone(), a.clone(), b.clone()].into_iter().collect();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_object_domain_debug() {
    for domain in ObjectDomain::ALL {
        let dbg = format!("{:?}", domain);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_schema_id_debug() {
    let dbg = format!("{:?}", test_schema());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SchemaId"));
}

#[test]
fn enrichment_engine_object_id_debug() {
    let dbg = format!("{:?}", test_id());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EngineObjectId"));
}

#[test]
fn enrichment_id_error_debug() {
    let dbg = format!("{:?}", IdError::EmptyCanonicalBytes);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EmptyCanonicalBytes"));
}

// ===========================================================================
// Display coverage — all variants unique
// ===========================================================================

#[test]
fn enrichment_object_domain_display_all_unique() {
    let displays: BTreeSet<String> = ObjectDomain::ALL.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), ObjectDomain::ALL.len());
}

#[test]
fn enrichment_schema_id_display_is_hex() {
    let display = test_schema().to_string();
    assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_engine_object_id_display_is_hex() {
    let display = test_id().to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_id_error_display_all_variants_unique() {
    let schema = test_schema();
    let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"a").unwrap();
    let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"b").unwrap();
    let errors: Vec<IdError> = vec![
        IdError::EmptyCanonicalBytes,
        IdError::IdMismatch {
            expected: id_a,
            computed: id_b,
        },
        IdError::NonCanonicalInput {
            reason: "test".to_string(),
        },
        IdError::InvalidHexLength {
            expected: 64,
            actual: 32,
        },
        IdError::InvalidHexChar { position: 5 },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ===========================================================================
// std::error::Error
// ===========================================================================

#[test]
fn enrichment_id_error_is_std_error() {
    let e = IdError::EmptyCanonicalBytes;
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_object_domain_serde_all_variants() {
    let jsons: BTreeSet<String> = ObjectDomain::ALL
        .iter()
        .map(|d| serde_json::to_string(d).unwrap())
        .collect();
    assert_eq!(jsons.len(), ObjectDomain::ALL.len());
    for json in &jsons {
        let _back: ObjectDomain = serde_json::from_str(json).unwrap();
    }
}

#[test]
fn enrichment_schema_id_serde_roundtrip() {
    let s = test_schema();
    let json = serde_json::to_string(&s).unwrap();
    let back: SchemaId = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_engine_object_id_serde_roundtrip() {
    let id = test_id();
    let json = serde_json::to_string(&id).unwrap();
    let back: EngineObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_id_error_serde_all_variants() {
    let schema = test_schema();
    let id_a = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"a").unwrap();
    let id_b = derive_id(ObjectDomain::PolicyObject, "z", &schema, b"b").unwrap();
    let errors: Vec<IdError> = vec![
        IdError::EmptyCanonicalBytes,
        IdError::IdMismatch {
            expected: id_a,
            computed: id_b,
        },
        IdError::NonCanonicalInput {
            reason: "test".to_string(),
        },
        IdError::InvalidHexLength {
            expected: 64,
            actual: 32,
        },
        IdError::InvalidHexChar { position: 5 },
    ];
    let jsons: BTreeSet<String> = errors
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    assert_eq!(jsons.len(), errors.len());
    for json in &jsons {
        let _back: IdError = serde_json::from_str(json).unwrap();
    }
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_derive_id_determinism_20_runs() {
    let schema = test_schema();
    let mut ids = BTreeSet::new();
    for _ in 0..20 {
        let id = derive_id(
            ObjectDomain::PolicyObject,
            "det-zone",
            &schema,
            b"det-content",
        )
        .unwrap();
        ids.insert(id);
    }
    assert_eq!(ids.len(), 1, "derive_id must be deterministic");
}

#[test]
fn enrichment_schema_id_determinism_20_runs() {
    let mut schemas = BTreeSet::new();
    for _ in 0..20 {
        schemas.insert(SchemaId::from_definition(b"det-schema"));
    }
    assert_eq!(
        schemas.len(),
        1,
        "SchemaId::from_definition must be deterministic"
    );
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_object_id_len() {
    assert_eq!(OBJECT_ID_LEN, 32);
}

// ===========================================================================
// ObjectDomain methods
// ===========================================================================

#[test]
fn enrichment_all_domain_tags_nonempty() {
    for domain in ObjectDomain::ALL {
        assert!(!domain.tag().is_empty());
    }
}

#[test]
fn enrichment_all_domain_tags_unique() {
    let tags: BTreeSet<&[u8]> = ObjectDomain::ALL.iter().map(|d| d.tag()).collect();
    assert_eq!(tags.len(), ObjectDomain::ALL.len());
}

#[test]
fn enrichment_domain_all_count() {
    assert_eq!(ObjectDomain::ALL.len(), 9);
}

// ===========================================================================
// SchemaId methods
// ===========================================================================

#[test]
fn enrichment_schema_id_from_bytes_roundtrip() {
    let s = test_schema();
    let bytes = *s.as_bytes();
    let back = SchemaId::from_bytes(bytes);
    assert_eq!(s, back);
}

#[test]
fn enrichment_schema_id_different_definitions_different_ids() {
    let a = SchemaId::from_definition(b"schema-a");
    let b = SchemaId::from_definition(b"schema-b");
    assert_ne!(a, b);
}

#[test]
fn enrichment_schema_id_same_definition_same_id() {
    let a = SchemaId::from_definition(b"same-schema");
    let b = SchemaId::from_definition(b"same-schema");
    assert_eq!(a, b);
}

// ===========================================================================
// EngineObjectId methods
// ===========================================================================

#[test]
fn enrichment_engine_object_id_to_hex_from_hex_roundtrip() {
    let id = test_id();
    let hex = id.to_hex();
    let back = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_engine_object_id_from_hex_uppercase() {
    let id = test_id();
    let hex = id.to_hex().to_uppercase();
    let back = EngineObjectId::from_hex(&hex).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_engine_object_id_from_hex_wrong_length() {
    let result = EngineObjectId::from_hex("aabb");
    assert!(result.is_err());
    match result.unwrap_err() {
        IdError::InvalidHexLength { expected, actual } => {
            assert_eq!(expected, 64);
            assert_eq!(actual, 4);
        }
        other => panic!("expected InvalidHexLength, got: {other:?}"),
    }
}

#[test]
fn enrichment_engine_object_id_from_hex_invalid_char() {
    let bad_hex = "zz".to_string() + &"0".repeat(62);
    let result = EngineObjectId::from_hex(&bad_hex);
    assert!(result.is_err());
    match result.unwrap_err() {
        IdError::InvalidHexChar { position } => {
            assert_eq!(position, 0);
        }
        other => panic!("expected InvalidHexChar, got: {other:?}"),
    }
}

#[test]
fn enrichment_engine_object_id_from_hex_empty() {
    let result = EngineObjectId::from_hex("");
    assert!(result.is_err());
}

#[test]
fn enrichment_engine_object_id_as_bytes_length() {
    let id = test_id();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

// ===========================================================================
// derive_id edge cases
// ===========================================================================

#[test]
fn enrichment_derive_id_empty_canonical_bytes_error() {
    let schema = test_schema();
    let result = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdError::EmptyCanonicalBytes));
}

#[test]
fn enrichment_derive_id_different_domains_different_ids() {
    let schema = test_schema();
    let ids: BTreeSet<EngineObjectId> = ObjectDomain::ALL
        .iter()
        .map(|d| derive_id(*d, "same-zone", &schema, b"same-content").unwrap())
        .collect();
    assert_eq!(
        ids.len(),
        ObjectDomain::ALL.len(),
        "domain separation must produce unique IDs"
    );
}

#[test]
fn enrichment_derive_id_different_zones_different_ids() {
    let schema = test_schema();
    let a = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"content").unwrap();
    let b = derive_id(ObjectDomain::PolicyObject, "zone-b", &schema, b"content").unwrap();
    assert_ne!(a, b);
}

#[test]
fn enrichment_derive_id_different_schemas_different_ids() {
    let sa = SchemaId::from_definition(b"schema-a");
    let sb = SchemaId::from_definition(b"schema-b");
    let a = derive_id(ObjectDomain::PolicyObject, "zone", &sa, b"content").unwrap();
    let b = derive_id(ObjectDomain::PolicyObject, "zone", &sb, b"content").unwrap();
    assert_ne!(a, b);
}

#[test]
fn enrichment_derive_id_different_content_different_ids() {
    let schema = test_schema();
    let a = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"content-a").unwrap();
    let b = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"content-b").unwrap();
    assert_ne!(a, b);
}

#[test]
fn enrichment_derive_id_single_byte_content() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"x").unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

#[test]
fn enrichment_derive_id_empty_zone() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "", &schema, b"content").unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

#[test]
fn enrichment_derive_id_large_content() {
    let schema = test_schema();
    let content = vec![0xABu8; 10_000];
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, &content).unwrap();
    assert_eq!(id.as_bytes().len(), OBJECT_ID_LEN);
}

// ===========================================================================
// verify_id
// ===========================================================================

#[test]
fn enrichment_verify_id_matching() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"content").unwrap();
    assert!(verify_id(&id, ObjectDomain::PolicyObject, "zone", &schema, b"content").is_ok());
}

#[test]
fn enrichment_verify_id_mismatch_content() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"content-a").unwrap();
    let result = verify_id(
        &id,
        ObjectDomain::PolicyObject,
        "zone",
        &schema,
        b"content-b",
    );
    assert!(result.is_err());
    match result.unwrap_err() {
        IdError::IdMismatch { expected, computed } => {
            assert_eq!(expected, id);
            assert_ne!(expected, computed);
        }
        other => panic!("expected IdMismatch, got: {other:?}"),
    }
}

#[test]
fn enrichment_verify_id_mismatch_domain() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone", &schema, b"content").unwrap();
    let result = verify_id(
        &id,
        ObjectDomain::EvidenceRecord,
        "zone",
        &schema,
        b"content",
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_verify_id_mismatch_zone() {
    let schema = test_schema();
    let id = derive_id(ObjectDomain::PolicyObject, "zone-a", &schema, b"content").unwrap();
    let result = verify_id(
        &id,
        ObjectDomain::PolicyObject,
        "zone-b",
        &schema,
        b"content",
    );
    assert!(result.is_err());
}

#[test]
fn enrichment_verify_id_empty_bytes_error() {
    let schema = test_schema();
    let id = test_id();
    let result = verify_id(&id, ObjectDomain::PolicyObject, "zone", &schema, b"");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), IdError::EmptyCanonicalBytes));
}

// ===========================================================================
// Cross-domain collision resistance
// ===========================================================================

#[test]
fn enrichment_all_domains_all_zones_unique_ids() {
    let schema = test_schema();
    let zones = ["zone-1", "zone-2", "zone-3"];
    let mut ids = BTreeSet::new();
    for domain in ObjectDomain::ALL {
        for zone in &zones {
            let id = derive_id(*domain, zone, &schema, b"common-content").unwrap();
            assert!(
                ids.insert(id),
                "collision detected for domain={domain}, zone={zone}"
            );
        }
    }
    assert_eq!(ids.len(), ObjectDomain::ALL.len() * zones.len());
}
