//! Enrichment integration tests for `deterministic_serde` module.
//!
//! Tests additional scenarios: nested structures, boundary values,
//! error paths, registry operations, canonical hashing, Display coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaDefinition, SchemaHash, SchemaRegistry, SerdeError,
    canonical_hash, decode_value, deserialize_with_schema, encode_value,
    serialize_with_schema,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_schema() -> SchemaHash {
    SchemaHash::from_definition(b"enrichment-test-schema-v1")
}

// ---------------------------------------------------------------------------
// SchemaHash enrichment
// ---------------------------------------------------------------------------

#[test]
fn schema_hash_deterministic() {
    let a = SchemaHash::from_definition(b"deterministic-check");
    let b = SchemaHash::from_definition(b"deterministic-check");
    assert_eq!(a, b);
}

#[test]
fn schema_hash_differs_on_input() {
    let a = SchemaHash::from_definition(b"schema-alpha");
    let b = SchemaHash::from_definition(b"schema-beta");
    assert_ne!(a, b);
}

#[test]
fn schema_hash_display_length() {
    let h = SchemaHash::from_definition(b"test");
    assert_eq!(h.to_string().len(), 64);
}

#[test]
fn schema_hash_display_all_hex() {
    let h = SchemaHash::from_definition(b"hex-check");
    assert!(h.to_string().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn schema_hash_as_bytes_length() {
    let h = SchemaHash::from_definition(b"bytes-check");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn schema_hash_serde_roundtrip() {
    let h = SchemaHash::from_definition(b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let back: SchemaHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn schema_hash_clone_equality() {
    let h = SchemaHash::from_definition(b"clone-test");
    let cloned = h.clone();
    assert_eq!(h, cloned);
}

// ---------------------------------------------------------------------------
// CanonicalValue encode/decode roundtrips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_u64_zero() {
    let val = CanonicalValue::U64(0);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_u64_max() {
    let val = CanonicalValue::U64(u64::MAX);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_u64_million() {
    let val = CanonicalValue::U64(1_000_000);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_i64_min() {
    let val = CanonicalValue::I64(i64::MIN);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_i64_max() {
    let val = CanonicalValue::I64(i64::MAX);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_i64_neg_one() {
    let val = CanonicalValue::I64(-1);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_bool_true() {
    let val = CanonicalValue::Bool(true);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_bool_false() {
    let val = CanonicalValue::Bool(false);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_bytes_nonempty() {
    let val = CanonicalValue::Bytes(vec![0xCA, 0xFE, 0xBA, 0xBE]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_bytes_empty() {
    let val = CanonicalValue::Bytes(vec![]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_string_unicode() {
    let val = CanonicalValue::String("hello world \u{1F600}".to_string());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_string_empty() {
    let val = CanonicalValue::String(String::new());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_null() {
    let val = CanonicalValue::Null;
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_array_empty() {
    let val = CanonicalValue::Array(vec![]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_array_mixed() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::U64(42),
        CanonicalValue::String("hi".to_string()),
        CanonicalValue::Bool(false),
        CanonicalValue::Null,
    ]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_map_empty() {
    let val = CanonicalValue::Map(BTreeMap::new());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_map_with_entries() {
    let mut m = BTreeMap::new();
    m.insert("alpha".to_string(), CanonicalValue::U64(1));
    m.insert("beta".to_string(), CanonicalValue::I64(-1));
    m.insert("gamma".to_string(), CanonicalValue::Null);
    let val = CanonicalValue::Map(m);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_nested_array_in_map() {
    let inner = CanonicalValue::Array(vec![CanonicalValue::U64(1), CanonicalValue::U64(2)]);
    let m = BTreeMap::from([("arr".to_string(), inner)]);
    let val = CanonicalValue::Map(m);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_nested_map_in_map() {
    let inner = BTreeMap::from([("inner_key".to_string(), CanonicalValue::Bool(true))]);
    let outer = BTreeMap::from([("outer_key".to_string(), CanonicalValue::Map(inner))]);
    let val = CanonicalValue::Map(outer);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_deeply_nested_10_levels() {
    let mut val = CanonicalValue::U64(42);
    for _ in 0..10 {
        val = CanonicalValue::Array(vec![val]);
    }
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn encoding_is_deterministic_across_calls() {
    let mut m = BTreeMap::new();
    m.insert("z".to_string(), CanonicalValue::U64(1));
    m.insert("a".to_string(), CanonicalValue::U64(2));
    let val = CanonicalValue::Map(m);
    let b1 = encode_value(&val);
    let b2 = encode_value(&val);
    assert_eq!(b1, b2);
}

#[test]
fn map_keys_lexicographic_in_output() {
    let mut m = BTreeMap::new();
    m.insert("zebra".to_string(), CanonicalValue::Null);
    m.insert("apple".to_string(), CanonicalValue::Null);
    m.insert("mango".to_string(), CanonicalValue::Null);
    let bytes = encode_value(&CanonicalValue::Map(m));
    let decoded = decode_value(&bytes).unwrap();
    if let CanonicalValue::Map(dm) = decoded {
        let keys: Vec<&String> = dm.keys().collect();
        assert_eq!(keys, vec!["apple", "mango", "zebra"]);
    } else {
        panic!("expected map");
    }
}

// ---------------------------------------------------------------------------
// Schema-prefixed serialization
// ---------------------------------------------------------------------------

#[test]
fn schema_prefixed_roundtrip() {
    let schema = test_schema();
    let val = CanonicalValue::String("test-value".to_string());
    let bytes = serialize_with_schema(&schema, &val);
    assert!(bytes.len() >= 32);
    let decoded = deserialize_with_schema(&schema, &bytes).unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn schema_mismatch_error() {
    let schema = test_schema();
    let wrong = SchemaHash::from_definition(b"wrong-schema");
    let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
    let err = deserialize_with_schema(&wrong, &bytes).unwrap_err();
    assert!(matches!(err, SerdeError::SchemaMismatch { .. }));
}

#[test]
fn schema_prefixed_too_short() {
    let err = deserialize_with_schema(&test_schema(), &[0u8; 10]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

// ---------------------------------------------------------------------------
// SchemaRegistry enrichment
// ---------------------------------------------------------------------------

#[test]
fn registry_new_is_empty() {
    let r = SchemaRegistry::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn registry_register_and_lookup() {
    let mut r = SchemaRegistry::new();
    let h = r.register("TestObj", 1, b"def-test");
    assert!(r.is_known(&h));
    assert!(!r.is_empty());
    assert_eq!(r.len(), 1);
    let def = r.lookup(&h).unwrap();
    assert_eq!(def.name, "TestObj");
    assert_eq!(def.version, 1);
}

#[test]
fn registry_multiple_schemas() {
    let mut r = SchemaRegistry::new();
    let h1 = r.register("A", 1, b"def-a");
    let h2 = r.register("B", 2, b"def-b");
    assert_eq!(r.len(), 2);
    assert!(r.is_known(&h1));
    assert!(r.is_known(&h2));
}

#[test]
fn registry_unknown_schema_rejected() {
    let r = SchemaRegistry::new();
    let schema = test_schema();
    let bytes = serialize_with_schema(&schema, &CanonicalValue::Null);
    let err = r.deserialize_checked(&bytes).unwrap_err();
    assert!(matches!(err, SerdeError::UnknownSchema { .. }));
}

#[test]
fn registry_known_schema_accepted() {
    let mut r = SchemaRegistry::new();
    let h = r.register("Obj", 1, b"enrichment-test-schema-v1");
    let bytes = serialize_with_schema(&h, &CanonicalValue::U64(999));
    let (def, val) = r.deserialize_checked(&bytes).unwrap();
    assert_eq!(def.name, "Obj");
    assert_eq!(val, CanonicalValue::U64(999));
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn error_buffer_too_short_empty() {
    let err = decode_value(&[]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

#[test]
fn error_invalid_tag() {
    let err = decode_value(&[0xFF]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidTag { tag: 0xFF, .. }));
}

#[test]
fn error_invalid_bool_encoding() {
    // tag=BOOL(0x03), value=0x02 (invalid)
    let err = decode_value(&[0x03, 0x02]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidBoolEncoding { value: 0x02, .. }));
}

#[test]
fn error_trailing_bytes() {
    let mut bytes = encode_value(&CanonicalValue::Null);
    bytes.push(0x00);
    let err = decode_value(&bytes).unwrap_err();
    assert!(matches!(err, SerdeError::TrailingBytes { count: 1 }));
}

#[test]
fn error_truncated_u64() {
    let mut bytes = encode_value(&CanonicalValue::U64(42));
    bytes.truncate(5);
    let err = decode_value(&bytes).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

// ---------------------------------------------------------------------------
// SerdeError Display and serde
// ---------------------------------------------------------------------------

#[test]
fn serde_error_display_distinctness() {
    let errors: Vec<SerdeError> = vec![
        SerdeError::SchemaMismatch {
            expected: SchemaHash([0; 32]),
            actual: SchemaHash([1; 32]),
        },
        SerdeError::UnknownSchema {
            schema_hash: SchemaHash([2; 32]),
        },
        SerdeError::BufferTooShort { expected: 10, actual: 5 },
        SerdeError::InvalidTag { tag: 0xAB, offset: 0 },
        SerdeError::InvalidBoolEncoding { value: 0x05, offset: 1 },
        SerdeError::InvalidUtf8 { offset: 3 },
        SerdeError::DuplicateKey { key: "k".into() },
        SerdeError::NonLexicographicKeys {
            prev_key: "z".into(),
            current_key: "a".into(),
        },
        SerdeError::RecursionLimitExceeded { offset: 99 },
        SerdeError::TrailingBytes { count: 4 },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn serde_error_serde_roundtrip_all() {
    let errors = vec![
        SerdeError::BufferTooShort { expected: 10, actual: 5 },
        SerdeError::InvalidTag { tag: 0xFF, offset: 0 },
        SerdeError::DuplicateKey { key: "test".into() },
        SerdeError::TrailingBytes { count: 7 },
        SerdeError::InvalidUtf8 { offset: 42 },
        SerdeError::RecursionLimitExceeded { offset: 128 },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: SerdeError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn serde_error_is_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(SerdeError::InvalidTag { tag: 1, offset: 0 });
    assert!(!e.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// SchemaDefinition serde
// ---------------------------------------------------------------------------

#[test]
fn schema_definition_serde_roundtrip() {
    let def = SchemaDefinition {
        name: "EnrichmentTest".to_string(),
        version: 5,
        schema_hash: SchemaHash::from_definition(b"enrich-def"),
    };
    let json = serde_json::to_string(&def).unwrap();
    let back: SchemaDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def, back);
}

// ---------------------------------------------------------------------------
// canonical_hash enrichment
// ---------------------------------------------------------------------------

#[test]
fn canonical_hash_deterministic() {
    let s = test_schema();
    let val = CanonicalValue::U64(42);
    let h1 = canonical_hash(&s, &val);
    let h2 = canonical_hash(&s, &val);
    assert_eq!(h1, h2);
}

#[test]
fn canonical_hash_differs_on_value() {
    let s = test_schema();
    let h1 = canonical_hash(&s, &CanonicalValue::U64(1));
    let h2 = canonical_hash(&s, &CanonicalValue::U64(2));
    assert_ne!(h1, h2);
}

#[test]
fn canonical_hash_differs_on_schema() {
    let s1 = SchemaHash::from_definition(b"schema-1");
    let s2 = SchemaHash::from_definition(b"schema-2");
    let val = CanonicalValue::Null;
    assert_ne!(canonical_hash(&s1, &val), canonical_hash(&s2, &val));
}

// ---------------------------------------------------------------------------
// CanonicalValue JSON serde
// ---------------------------------------------------------------------------

#[test]
fn canonical_value_json_serde_all_variants() {
    let values = vec![
        CanonicalValue::U64(0),
        CanonicalValue::I64(-42),
        CanonicalValue::Bool(true),
        CanonicalValue::Bytes(vec![1, 2]),
        CanonicalValue::String("test".into()),
        CanonicalValue::Array(vec![CanonicalValue::Null]),
        CanonicalValue::Map(BTreeMap::from([("k".into(), CanonicalValue::U64(1))])),
        CanonicalValue::Null,
    ];
    for v in &values {
        let json = serde_json::to_string(v).unwrap();
        let back: CanonicalValue = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// Encoding size invariants
// ---------------------------------------------------------------------------

#[test]
fn u64_encoding_fixed_9_bytes() {
    assert_eq!(encode_value(&CanonicalValue::U64(0)).len(), 9);
    assert_eq!(encode_value(&CanonicalValue::U64(u64::MAX)).len(), 9);
}

#[test]
fn i64_encoding_fixed_9_bytes() {
    assert_eq!(encode_value(&CanonicalValue::I64(0)).len(), 9);
    assert_eq!(encode_value(&CanonicalValue::I64(i64::MIN)).len(), 9);
}

#[test]
fn null_encoding_1_byte() {
    assert_eq!(encode_value(&CanonicalValue::Null).len(), 1);
}

#[test]
fn bool_encoding_2_bytes() {
    assert_eq!(encode_value(&CanonicalValue::Bool(true)).len(), 2);
    assert_eq!(encode_value(&CanonicalValue::Bool(false)).len(), 2);
}

#[test]
fn string_encoding_includes_length_prefix() {
    let val = CanonicalValue::String("abc".to_string());
    // 1 tag + 4 length + 3 chars = 8
    assert_eq!(encode_value(&val).len(), 8);
}
