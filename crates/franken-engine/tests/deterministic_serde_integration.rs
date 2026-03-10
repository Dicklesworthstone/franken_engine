//! Integration tests for the `deterministic_serde` module.
//!
//! Tests canonical encoding/decoding, schema-prefixed serialization,
//! SchemaRegistry, error handling, and serde roundtrips.

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

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_serde::{
    CanonicalValue, SchemaDefinition, SchemaHash, SchemaRegistry, SerdeError, canonical_hash,
    decode_value, deserialize_with_schema, encode_value, serialize_with_schema,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_schema() -> SchemaHash {
    SchemaHash::from_definition(b"test-schema-v1")
}

// ---------------------------------------------------------------------------
// SchemaHash
// ---------------------------------------------------------------------------

#[test]
fn schema_hash_from_definition_deterministic() {
    let a = SchemaHash::from_definition(b"my-schema");
    let b = SchemaHash::from_definition(b"my-schema");
    assert_eq!(a, b);
}

#[test]
fn schema_hash_different_definitions_differ() {
    let a = SchemaHash::from_definition(b"schema-v1");
    let b = SchemaHash::from_definition(b"schema-v2");
    assert_ne!(a, b);
}

#[test]
fn schema_hash_display_is_64_hex() {
    let hash = SchemaHash::from_definition(b"test");
    let display = hash.to_string();
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn schema_hash_as_bytes_is_32() {
    let hash = SchemaHash::from_definition(b"test");
    assert_eq!(hash.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// encode_value / decode_value roundtrips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_u64() {
    let val = CanonicalValue::U64(42);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

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
fn roundtrip_i64() {
    let val = CanonicalValue::I64(-12345);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_i64_min_max() {
    for v in [i64::MIN, i64::MAX, 0] {
        let val = CanonicalValue::I64(v);
        assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
    }
}

#[test]
fn roundtrip_bool() {
    for b in [true, false] {
        let val = CanonicalValue::Bool(b);
        assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
    }
}

#[test]
fn roundtrip_bytes() {
    let val = CanonicalValue::Bytes(vec![0x01, 0x02, 0xff]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_bytes_empty() {
    let val = CanonicalValue::Bytes(vec![]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_string() {
    let val = CanonicalValue::String("hello world".to_string());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_string_empty() {
    let val = CanonicalValue::String(String::new());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_string_unicode() {
    let val = CanonicalValue::String("日本語テスト 🚀".to_string());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_null() {
    let val = CanonicalValue::Null;
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_array() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::U64(1),
        CanonicalValue::String("two".to_string()),
        CanonicalValue::Bool(true),
        CanonicalValue::Null,
    ]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_array_empty() {
    let val = CanonicalValue::Array(vec![]);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_map() {
    let mut map = BTreeMap::new();
    map.insert("alpha".to_string(), CanonicalValue::U64(1));
    map.insert("beta".to_string(), CanonicalValue::String("b".to_string()));
    map.insert("gamma".to_string(), CanonicalValue::Bool(false));
    let val = CanonicalValue::Map(map);
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_map_empty() {
    let val = CanonicalValue::Map(BTreeMap::new());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn roundtrip_nested_structure() {
    let mut inner_map = BTreeMap::new();
    inner_map.insert("key".to_string(), CanonicalValue::U64(42));

    let val = CanonicalValue::Map({
        let mut m = BTreeMap::new();
        m.insert(
            "array".to_string(),
            CanonicalValue::Array(vec![
                CanonicalValue::Map(inner_map),
                CanonicalValue::Null,
                CanonicalValue::Bytes(vec![0xfe]),
            ]),
        );
        m.insert("count".to_string(), CanonicalValue::I64(-999));
        m
    });
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

// ---------------------------------------------------------------------------
// Determinism — same input produces same bytes
// ---------------------------------------------------------------------------

#[test]
fn encoding_is_deterministic() {
    let mut map = BTreeMap::new();
    map.insert("a".to_string(), CanonicalValue::U64(1));
    map.insert("b".to_string(), CanonicalValue::U64(2));
    let val = CanonicalValue::Map(map);

    let bytes1 = encode_value(&val);
    let bytes2 = encode_value(&val);
    assert_eq!(bytes1, bytes2);
}

#[test]
fn encoding_deterministic_across_10_runs() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::String("hello".to_string()),
        CanonicalValue::I64(-42),
    ]);
    let first = encode_value(&val);
    for _ in 0..10 {
        assert_eq!(encode_value(&val), first);
    }
}

// ---------------------------------------------------------------------------
// Schema-prefixed serialization
// ---------------------------------------------------------------------------

#[test]
fn serialize_deserialize_with_schema() {
    let schema = test_schema();
    let val = CanonicalValue::U64(999);
    let data = serialize_with_schema(&schema, &val);
    let decoded = deserialize_with_schema(&schema, &data).unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn schema_prefix_is_32_bytes() {
    let schema = test_schema();
    let val = CanonicalValue::Null;
    let data = serialize_with_schema(&schema, &val);
    // 32 bytes schema + 1 byte null tag
    assert_eq!(data.len(), 33);
    assert_eq!(&data[..32], schema.as_bytes());
}

#[test]
fn schema_mismatch_detected() {
    let schema1 = SchemaHash::from_definition(b"schema-v1");
    let schema2 = SchemaHash::from_definition(b"schema-v2");
    let data = serialize_with_schema(&schema1, &CanonicalValue::Null);
    let err = deserialize_with_schema(&schema2, &data).unwrap_err();
    assert!(matches!(err, SerdeError::SchemaMismatch { .. }));
}

#[test]
fn schema_buffer_too_short() {
    let schema = test_schema();
    let err = deserialize_with_schema(&schema, &[0; 10]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

// ---------------------------------------------------------------------------
// SchemaRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_new_is_empty() {
    let reg = SchemaRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn registry_register_and_lookup() {
    let mut reg = SchemaRegistry::new();
    let hash = reg.register("test-schema", 1, b"definition-v1");
    assert_eq!(reg.len(), 1);
    assert!(reg.is_known(&hash));
    let def = reg.lookup(&hash).unwrap();
    assert_eq!(def.name, "test-schema");
    assert_eq!(def.version, 1);
}

#[test]
fn registry_unknown_schema_not_found() {
    let reg = SchemaRegistry::new();
    let unknown = SchemaHash::from_definition(b"unknown");
    assert!(!reg.is_known(&unknown));
    assert!(reg.lookup(&unknown).is_none());
}

#[test]
fn registry_deserialize_checked_success() {
    let mut reg = SchemaRegistry::new();
    let hash = reg.register("my-schema", 2, b"my-def-v2");
    let val = CanonicalValue::String("payload".to_string());
    let data = serialize_with_schema(&hash, &val);
    let (def, decoded) = reg.deserialize_checked(&data).unwrap();
    assert_eq!(def.name, "my-schema");
    assert_eq!(decoded, val);
}

#[test]
fn registry_deserialize_checked_unknown_schema() {
    let reg = SchemaRegistry::new();
    let unknown = SchemaHash::from_definition(b"unknown");
    let data = serialize_with_schema(&unknown, &CanonicalValue::Null);
    let err = reg.deserialize_checked(&data).unwrap_err();
    assert!(matches!(err, SerdeError::UnknownSchema { .. }));
}

#[test]
fn registry_deserialize_checked_too_short() {
    let reg = SchemaRegistry::new();
    let err = reg.deserialize_checked(&[0; 5]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

// ---------------------------------------------------------------------------
// canonical_hash
// ---------------------------------------------------------------------------

#[test]
fn canonical_hash_deterministic() {
    let schema = test_schema();
    let val = CanonicalValue::String("test".to_string());
    let h1 = canonical_hash(&schema, &val);
    let h2 = canonical_hash(&schema, &val);
    assert_eq!(h1, h2);
}

#[test]
fn canonical_hash_differs_for_different_values() {
    let schema = test_schema();
    let h1 = canonical_hash(&schema, &CanonicalValue::U64(1));
    let h2 = canonical_hash(&schema, &CanonicalValue::U64(2));
    assert_ne!(h1, h2);
}

#[test]
fn canonical_hash_differs_for_different_schemas() {
    let s1 = SchemaHash::from_definition(b"s1");
    let s2 = SchemaHash::from_definition(b"s2");
    let val = CanonicalValue::Null;
    let h1 = canonical_hash(&s1, &val);
    let h2 = canonical_hash(&s2, &val);
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Decoding errors
// ---------------------------------------------------------------------------

#[test]
fn decode_empty_buffer_error() {
    let err = decode_value(&[]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

#[test]
fn decode_invalid_tag_error() {
    let err = decode_value(&[0xFF]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidTag { tag: 0xFF, .. }));
}

#[test]
fn decode_invalid_bool_encoding_error() {
    let err = decode_value(&[0x03, 0x02]).unwrap_err();
    assert!(matches!(
        err,
        SerdeError::InvalidBoolEncoding {
            value: 0x02,
            offset: 1
        }
    ));
}

#[test]
fn decode_truncated_u64_error() {
    // Tag for U64 followed by only 3 bytes instead of 8
    let err = decode_value(&[0x01, 0x00, 0x00, 0x00]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

#[test]
fn decode_trailing_bytes_error() {
    let mut data = encode_value(&CanonicalValue::Null);
    data.push(0x00); // extra byte
    let err = decode_value(&data).unwrap_err();
    assert!(matches!(err, SerdeError::TrailingBytes { count: 1 }));
}

// ---------------------------------------------------------------------------
// SerdeError — display
// ---------------------------------------------------------------------------

#[test]
fn serde_error_display_all_variants() {
    let errors: Vec<(SerdeError, &str)> = vec![
        (
            SerdeError::SchemaMismatch {
                expected: test_schema(),
                actual: SchemaHash::from_definition(b"other"),
            },
            "schema mismatch",
        ),
        (
            SerdeError::UnknownSchema {
                schema_hash: test_schema(),
            },
            "unknown schema",
        ),
        (
            SerdeError::BufferTooShort {
                expected: 32,
                actual: 10,
            },
            "buffer too short",
        ),
        (
            SerdeError::InvalidTag {
                tag: 0xFF,
                offset: 0,
            },
            "invalid tag",
        ),
        (
            SerdeError::InvalidBoolEncoding {
                value: 0x02,
                offset: 1,
            },
            "invalid bool encoding",
        ),
        (SerdeError::InvalidUtf8 { offset: 5 }, "invalid UTF-8"),
        (
            SerdeError::DuplicateKey {
                key: "dup".to_string(),
            },
            "duplicate key",
        ),
        (
            SerdeError::NonLexicographicKeys {
                prev_key: "b".to_string(),
                current_key: "a".to_string(),
            },
            "non-lexicographic",
        ),
        (
            SerdeError::RecursionLimitExceeded { offset: 100 },
            "recursion limit",
        ),
        (SerdeError::TrailingBytes { count: 5 }, "trailing bytes"),
    ];
    for (err, expected_substr) in &errors {
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_substr),
            "'{msg}' should contain '{expected_substr}'"
        );
    }
}

#[test]
fn serde_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(SerdeError::InvalidTag {
        tag: 0xFF,
        offset: 0,
    });
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips (JSON)
// ---------------------------------------------------------------------------

#[test]
fn canonical_value_json_serde_all_variants() {
    let values = vec![
        CanonicalValue::U64(42),
        CanonicalValue::I64(-999),
        CanonicalValue::Bool(true),
        CanonicalValue::Bool(false),
        CanonicalValue::Bytes(vec![0x01, 0x02]),
        CanonicalValue::String("hello".to_string()),
        CanonicalValue::Array(vec![CanonicalValue::Null]),
        CanonicalValue::Map({
            let mut m = BTreeMap::new();
            m.insert("k".to_string(), CanonicalValue::U64(1));
            m
        }),
        CanonicalValue::Null,
    ];
    for val in &values {
        let json = serde_json::to_string(val).unwrap();
        let decoded: CanonicalValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, &decoded);
    }
}

#[test]
fn schema_hash_json_serde_roundtrip() {
    let hash = SchemaHash::from_definition(b"test");
    let json = serde_json::to_string(&hash).unwrap();
    let decoded: SchemaHash = serde_json::from_str(&json).unwrap();
    assert_eq!(hash, decoded);
}

#[test]
fn schema_definition_json_serde_roundtrip() {
    let def = SchemaDefinition {
        name: "test-schema".to_string(),
        version: 3,
        schema_hash: test_schema(),
    };
    let json = serde_json::to_string(&def).unwrap();
    let decoded: SchemaDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(def, decoded);
}

#[test]
fn serde_error_json_serde_roundtrip() {
    let errors = vec![
        SerdeError::BufferTooShort {
            expected: 32,
            actual: 10,
        },
        SerdeError::InvalidTag {
            tag: 0xFF,
            offset: 0,
        },
        SerdeError::InvalidBoolEncoding {
            value: 0x02,
            offset: 1,
        },
        SerdeError::DuplicateKey {
            key: "dup".to_string(),
        },
        SerdeError::TrailingBytes { count: 5 },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: SerdeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &decoded);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn large_array_roundtrip() {
    let val = CanonicalValue::Array((0..1000).map(CanonicalValue::U64).collect());
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn deeply_nested_array_roundtrip() {
    let mut val = CanonicalValue::U64(42);
    for _ in 0..50 {
        val = CanonicalValue::Array(vec![val]);
    }
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

#[test]
fn map_keys_are_lexicographic() {
    let mut map = BTreeMap::new();
    map.insert("z".to_string(), CanonicalValue::U64(1));
    map.insert("a".to_string(), CanonicalValue::U64(2));
    map.insert("m".to_string(), CanonicalValue::U64(3));
    let val = CanonicalValue::Map(map);

    let bytes = encode_value(&val);
    let decoded = decode_value(&bytes).unwrap();
    assert_eq!(val, decoded);
}
