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

// ---------------------------------------------------------------------------
// Enrichment tests (~95 new tests)
// ---------------------------------------------------------------------------

// -- SchemaHash trait contract tests --

#[test]
fn enrichment_schema_hash_debug_contains_bytes() {
    let hash = SchemaHash([0xAB; 32]);
    let dbg = format!("{hash:?}");
    assert!(dbg.contains("SchemaHash"));
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_schema_hash_clone_independence() {
    let original = SchemaHash::from_definition(b"clone-indep");
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Both produce same bytes
    assert_eq!(original.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_schema_hash_partial_ord_consistent_with_eq() {
    let a = SchemaHash([0x10; 32]);
    let b = SchemaHash([0x10; 32]);
    assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    assert_eq!(a, b);
}

#[test]
fn enrichment_schema_hash_ord_first_byte_differs() {
    let mut low = [0x00u8; 32];
    let mut high = [0x00u8; 32];
    low[0] = 0x01;
    high[0] = 0x02;
    assert!(SchemaHash(low) < SchemaHash(high));
}

#[test]
fn enrichment_schema_hash_ord_last_byte_differs() {
    let mut low = [0x00u8; 32];
    let mut high = [0x00u8; 32];
    low[31] = 0x01;
    high[31] = 0x02;
    assert!(SchemaHash(low) < SchemaHash(high));
}

#[test]
fn enrichment_schema_hash_display_lowercase_hex() {
    let hash = SchemaHash([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let s = hash.to_string();
    assert!(s.starts_with("abcdef0123456789"));
    // All lowercase
    assert!(s.chars().all(|c| !c.is_ascii_uppercase()));
}

#[test]
fn enrichment_schema_hash_from_empty_definition() {
    let h1 = SchemaHash::from_definition(b"");
    let h2 = SchemaHash::from_definition(b"");
    assert_eq!(h1, h2);
    // Empty is still a valid 32-byte hash
    assert_eq!(h1.as_bytes().len(), 32);
}

#[test]
fn enrichment_schema_hash_from_definition_long_input() {
    let long_input = vec![0xFFu8; 10_000];
    let h = SchemaHash::from_definition(&long_input);
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn enrichment_schema_hash_serde_json_roundtrip_all_zeros() {
    let hash = SchemaHash([0u8; 32]);
    let json = serde_json::to_string(&hash).unwrap();
    let back: SchemaHash = serde_json::from_str(&json).unwrap();
    assert_eq!(hash, back);
}

#[test]
fn enrichment_schema_hash_serde_json_roundtrip_all_ff() {
    let hash = SchemaHash([0xFF; 32]);
    let json = serde_json::to_string(&hash).unwrap();
    let back: SchemaHash = serde_json::from_str(&json).unwrap();
    assert_eq!(hash, back);
}

// -- CanonicalValue variant-specific encoding tests --

#[test]
fn enrichment_encode_u64_tag_byte_is_0x01() {
    let bytes = encode_value(&CanonicalValue::U64(0));
    assert_eq!(bytes[0], 0x01);
}

#[test]
fn enrichment_encode_i64_tag_byte_is_0x02() {
    let bytes = encode_value(&CanonicalValue::I64(0));
    assert_eq!(bytes[0], 0x02);
}

#[test]
fn enrichment_encode_bool_tag_byte_is_0x03() {
    let bytes = encode_value(&CanonicalValue::Bool(true));
    assert_eq!(bytes[0], 0x03);
}

#[test]
fn enrichment_encode_bytes_tag_byte_is_0x04() {
    let bytes = encode_value(&CanonicalValue::Bytes(vec![]));
    assert_eq!(bytes[0], 0x04);
}

#[test]
fn enrichment_encode_string_tag_byte_is_0x05() {
    let bytes = encode_value(&CanonicalValue::String(String::new()));
    assert_eq!(bytes[0], 0x05);
}

#[test]
fn enrichment_encode_array_tag_byte_is_0x06() {
    let bytes = encode_value(&CanonicalValue::Array(vec![]));
    assert_eq!(bytes[0], 0x06);
}

#[test]
fn enrichment_encode_map_tag_byte_is_0x07() {
    let bytes = encode_value(&CanonicalValue::Map(BTreeMap::new()));
    assert_eq!(bytes[0], 0x07);
}

#[test]
fn enrichment_encode_null_tag_byte_is_0x08() {
    let bytes = encode_value(&CanonicalValue::Null);
    assert_eq!(bytes[0], 0x08);
    assert_eq!(bytes.len(), 1);
}

// -- Bool encoding detail --

#[test]
fn enrichment_bool_true_encodes_as_0x01() {
    let bytes = encode_value(&CanonicalValue::Bool(true));
    assert_eq!(bytes, vec![0x03, 0x01]);
}

#[test]
fn enrichment_bool_false_encodes_as_0x00() {
    let bytes = encode_value(&CanonicalValue::Bool(false));
    assert_eq!(bytes, vec![0x03, 0x00]);
}

// -- U64 big-endian encoding --

#[test]
fn enrichment_u64_big_endian_encoding() {
    let bytes = encode_value(&CanonicalValue::U64(0x0102030405060708));
    // tag + 8 big-endian bytes
    assert_eq!(bytes[1..], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

#[test]
fn enrichment_i64_big_endian_encoding_negative() {
    let bytes = encode_value(&CanonicalValue::I64(-1));
    // -1 in i64 big-endian is all 0xFF
    assert_eq!(bytes[1..], [0xFF; 8]);
}

// -- String length-prefix encoding --

#[test]
fn enrichment_string_length_prefix_is_u32_be() {
    let bytes = encode_value(&CanonicalValue::String("ABCD".to_string()));
    // tag(1) + length(4) + data(4) = 9
    assert_eq!(bytes.len(), 9);
    // Length prefix = 4 in u32 BE
    assert_eq!(&bytes[1..5], &[0, 0, 0, 4]);
    assert_eq!(&bytes[5..9], b"ABCD");
}

// -- Bytes length-prefix encoding --

#[test]
fn enrichment_bytes_length_prefix_is_u32_be() {
    let bytes = encode_value(&CanonicalValue::Bytes(vec![0xAA, 0xBB, 0xCC]));
    // tag(1) + length(4) + data(3) = 8
    assert_eq!(bytes.len(), 8);
    assert_eq!(&bytes[1..5], &[0, 0, 0, 3]);
    assert_eq!(&bytes[5..8], &[0xAA, 0xBB, 0xCC]);
}

// -- Array count encoding --

#[test]
fn enrichment_array_count_is_u32_be() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::Null,
        CanonicalValue::Null,
        CanonicalValue::Null,
    ]);
    let bytes = encode_value(&val);
    // tag(1) + count(4) + 3 null tags
    assert_eq!(bytes.len(), 1 + 4 + 3);
    assert_eq!(&bytes[1..5], &[0, 0, 0, 3]);
}

// -- Map key ordering enforcement in decoded wire format --

#[test]
fn enrichment_map_single_key_roundtrip() {
    let mut map = BTreeMap::new();
    map.insert("only_key".to_string(), CanonicalValue::U64(42));
    let val = CanonicalValue::Map(map);
    let bytes = encode_value(&val);
    assert_eq!(decode_value(&bytes).unwrap(), val);
}

// -- Decode error paths --

#[test]
fn enrichment_decode_truncated_i64_error() {
    let mut data = encode_value(&CanonicalValue::I64(99));
    data.truncate(5); // tag + 4 of 8
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_string_length_error() {
    // String tag + only 2 bytes of length prefix (need 4)
    let data = vec![0x05, 0x00, 0x00];
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_string_body_error() {
    // String tag + length=5 + only 2 bytes of body
    let data = vec![0x05, 0x00, 0x00, 0x00, 0x05, b'a', b'b'];
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_bytes_length_error() {
    let data = vec![0x04, 0x00, 0x00];
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_bytes_body_error() {
    let data = vec![0x04, 0x00, 0x00, 0x00, 0x03, 0xAA];
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_array_count_error() {
    let data = vec![0x06, 0x00, 0x00]; // array tag + partial count
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_map_count_error() {
    let data = vec![0x07, 0x00]; // map tag + partial count
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_truncated_bool_error() {
    let data = vec![0x03]; // bool tag, no value byte
    assert!(matches!(decode_value(&data), Err(SerdeError::BufferTooShort { .. })));
}

#[test]
fn enrichment_decode_invalid_bool_0xff() {
    let data = vec![0x03, 0xFF];
    let err = decode_value(&data).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidBoolEncoding { value: 0xFF, offset: 1 }));
}

#[test]
fn enrichment_decode_invalid_bool_0x80() {
    let data = vec![0x03, 0x80];
    let err = decode_value(&data).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidBoolEncoding { value: 0x80, offset: 1 }));
}

#[test]
fn enrichment_decode_invalid_tag_0x00() {
    let err = decode_value(&[0x00]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidTag { tag: 0x00, offset: 0 }));
}

#[test]
fn enrichment_decode_invalid_tag_0x09() {
    let err = decode_value(&[0x09]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidTag { tag: 0x09, offset: 0 }));
}

#[test]
fn enrichment_decode_invalid_tag_0x10() {
    let err = decode_value(&[0x10]).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidTag { tag: 0x10, offset: 0 }));
}

#[test]
fn enrichment_decode_trailing_bytes_multiple() {
    let mut data = encode_value(&CanonicalValue::U64(1));
    data.extend_from_slice(&[0x00, 0x00, 0x00]);
    let err = decode_value(&data).unwrap_err();
    assert!(matches!(err, SerdeError::TrailingBytes { count: 3 }));
}

// -- Map key ordering edge cases --

#[test]
fn enrichment_decode_non_lexicographic_keys_ba() {
    // Manually build map with keys "b" then "a"
    let mut bytes = vec![0x07]; // MAP tag
    bytes.extend_from_slice(&2u32.to_be_bytes());
    // key "b"
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'b');
    bytes.push(0x08); // NULL
    // key "a"
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'a');
    bytes.push(0x08); // NULL
    let err = decode_value(&bytes).unwrap_err();
    match err {
        SerdeError::NonLexicographicKeys { prev_key, current_key } => {
            assert_eq!(prev_key, "b");
            assert_eq!(current_key, "a");
        }
        other => panic!("expected NonLexicographicKeys, got: {other}"),
    }
}

#[test]
fn enrichment_decode_duplicate_keys_detected() {
    let mut bytes = vec![0x07]; // MAP tag
    bytes.extend_from_slice(&2u32.to_be_bytes());
    // key "x"
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'x');
    bytes.push(0x08); // NULL
    // key "x" again
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'x');
    bytes.push(0x08); // NULL
    let err = decode_value(&bytes).unwrap_err();
    match err {
        SerdeError::DuplicateKey { key } => assert_eq!(key, "x"),
        other => panic!("expected DuplicateKey, got: {other}"),
    }
}

#[test]
fn enrichment_decode_map_key_invalid_utf8() {
    let mut bytes = vec![0x07]; // MAP tag
    bytes.extend_from_slice(&1u32.to_be_bytes()); // 1 entry
    bytes.extend_from_slice(&2u32.to_be_bytes()); // key length 2
    bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    bytes.push(0x08); // NULL value
    let err = decode_value(&bytes).unwrap_err();
    assert!(matches!(err, SerdeError::InvalidUtf8 { .. }));
}

// -- Recursion limit --

#[test]
fn enrichment_recursion_at_128_depth_succeeds() {
    // Build exactly 128-deep array nesting (limit is >128)
    let mut val = CanonicalValue::Null;
    for _ in 0..128 {
        val = CanonicalValue::Array(vec![val]);
    }
    let bytes = encode_value(&val);
    // depth 0..128, so max decode_at depth = 128 which is not > 128, should succeed
    assert_eq!(decode_value(&bytes).unwrap(), val);
}

#[test]
fn enrichment_recursion_at_129_depth_fails() {
    // Build 129-deep: exceeds limit of 128
    let mut bytes = Vec::new();
    for _ in 0..129 {
        bytes.push(0x06); // ARRAY tag
        bytes.extend_from_slice(&1u32.to_be_bytes());
    }
    bytes.push(0x08); // NULL at leaf
    let err = decode_value(&bytes).unwrap_err();
    assert!(matches!(err, SerdeError::RecursionLimitExceeded { .. }));
}

// -- Schema-prefixed serialization edge cases --

#[test]
fn enrichment_serialize_with_schema_starts_with_hash_bytes() {
    let schema = SchemaHash::from_definition(b"prefix-check");
    let data = serialize_with_schema(&schema, &CanonicalValue::Bool(true));
    assert_eq!(&data[..32], schema.as_bytes());
}

#[test]
fn enrichment_deserialize_with_schema_exactly_32_bytes_plus_null() {
    let schema = test_schema();
    let mut data = Vec::new();
    data.extend_from_slice(schema.as_bytes());
    data.push(0x08); // NULL tag
    let val = deserialize_with_schema(&schema, &data).unwrap();
    assert_eq!(val, CanonicalValue::Null);
}

#[test]
fn enrichment_deserialize_with_schema_exactly_32_bytes_no_payload_error() {
    let schema = test_schema();
    let data = schema.as_bytes().to_vec();
    // 32 bytes but no value payload — offset 32 >= len 32
    let err = deserialize_with_schema(&schema, &data).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { .. }));
}

#[test]
fn enrichment_deserialize_with_schema_trailing_bytes_rejected() {
    let schema = test_schema();
    let mut data = serialize_with_schema(&schema, &CanonicalValue::Null);
    data.push(0x00);
    data.push(0x00);
    let err = deserialize_with_schema(&schema, &data).unwrap_err();
    assert!(matches!(err, SerdeError::TrailingBytes { count: 2 }));
}

#[test]
fn enrichment_deserialize_with_schema_empty_buffer() {
    let schema = test_schema();
    let err = deserialize_with_schema(&schema, &[]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { expected: 32, actual: 0 }));
}

// -- SchemaRegistry edge cases --

#[test]
fn enrichment_registry_default_is_empty() {
    let reg = SchemaRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn enrichment_registry_register_returns_consistent_hash() {
    let mut reg = SchemaRegistry::new();
    let h1 = reg.register("A", 1, b"definition-for-a");
    let expected = SchemaHash::from_definition(b"definition-for-a");
    assert_eq!(h1, expected);
}

#[test]
fn enrichment_registry_register_many_schemas() {
    let mut reg = SchemaRegistry::new();
    for i in 0u32..50 {
        let def = format!("schema-def-{i}");
        reg.register(&format!("Schema{i}"), i, def.as_bytes());
    }
    assert_eq!(reg.len(), 50);
}

#[test]
fn enrichment_registry_lookup_after_overwrite_returns_latest() {
    let mut reg = SchemaRegistry::new();
    let h = reg.register("V1", 1, b"same-bytes");
    let _ = reg.register("V2", 2, b"same-bytes");
    let def = reg.lookup(&h).unwrap();
    assert_eq!(def.name, "V2");
    assert_eq!(def.version, 2);
}

#[test]
fn enrichment_registry_deserialize_checked_returns_correct_definition() {
    let mut reg = SchemaRegistry::new();
    let h = reg.register("Payload", 5, b"payload-schema");
    let val = CanonicalValue::String("content".to_string());
    let data = serialize_with_schema(&h, &val);
    let (def, decoded) = reg.deserialize_checked(&data).unwrap();
    assert_eq!(def.name, "Payload");
    assert_eq!(def.version, 5);
    assert_eq!(def.schema_hash, h);
    assert_eq!(decoded, val);
}

#[test]
fn enrichment_registry_deserialize_checked_empty_buffer() {
    let reg = SchemaRegistry::new();
    let err = reg.deserialize_checked(&[]).unwrap_err();
    assert!(matches!(err, SerdeError::BufferTooShort { expected: 32, actual: 0 }));
}

#[test]
fn enrichment_registry_is_known_false_for_unregistered() {
    let reg = SchemaRegistry::new();
    let h = SchemaHash::from_definition(b"not-registered");
    assert!(!reg.is_known(&h));
}

#[test]
fn enrichment_registry_debug_not_empty() {
    let reg = SchemaRegistry::new();
    let dbg = format!("{reg:?}");
    assert!(dbg.contains("SchemaRegistry"));
}

// -- canonical_hash edge cases --

#[test]
fn enrichment_canonical_hash_null_is_32_bytes() {
    let schema = test_schema();
    let h = canonical_hash(&schema, &CanonicalValue::Null);
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn enrichment_canonical_hash_bool_true_vs_false_differ() {
    let schema = test_schema();
    let h_true = canonical_hash(&schema, &CanonicalValue::Bool(true));
    let h_false = canonical_hash(&schema, &CanonicalValue::Bool(false));
    assert_ne!(h_true, h_false);
}

#[test]
fn enrichment_canonical_hash_empty_string_vs_empty_bytes() {
    let schema = test_schema();
    let h_str = canonical_hash(&schema, &CanonicalValue::String(String::new()));
    let h_bytes = canonical_hash(&schema, &CanonicalValue::Bytes(vec![]));
    assert_ne!(h_str, h_bytes);
}

#[test]
fn enrichment_canonical_hash_array_order_matters() {
    let schema = test_schema();
    let h1 = canonical_hash(&schema, &CanonicalValue::Array(vec![
        CanonicalValue::U64(1), CanonicalValue::U64(2),
    ]));
    let h2 = canonical_hash(&schema, &CanonicalValue::Array(vec![
        CanonicalValue::U64(2), CanonicalValue::U64(1),
    ]));
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_canonical_hash_map_vs_array_with_same_content_differ() {
    let schema = test_schema();
    let h_map = canonical_hash(&schema, &CanonicalValue::Map(BTreeMap::from([
        ("k".to_string(), CanonicalValue::U64(1)),
    ])));
    let h_arr = canonical_hash(&schema, &CanonicalValue::Array(vec![
        CanonicalValue::String("k".to_string()),
        CanonicalValue::U64(1),
    ]));
    assert_ne!(h_map, h_arr);
}

// -- CanonicalValue Clone/Debug/Eq trait contracts --

#[test]
fn enrichment_canonical_value_eq_reflexive() {
    let vals = vec![
        CanonicalValue::U64(42),
        CanonicalValue::I64(-42),
        CanonicalValue::Bool(true),
        CanonicalValue::Bytes(vec![1]),
        CanonicalValue::String("x".to_string()),
        CanonicalValue::Array(vec![CanonicalValue::Null]),
        CanonicalValue::Map(BTreeMap::from([("a".to_string(), CanonicalValue::Null)])),
        CanonicalValue::Null,
    ];
    for v in &vals {
        assert_eq!(v, v);
    }
}

#[test]
fn enrichment_canonical_value_ne_different_variants() {
    let pairs = vec![
        (CanonicalValue::U64(0), CanonicalValue::I64(0)),
        (CanonicalValue::Bool(true), CanonicalValue::U64(1)),
        (CanonicalValue::Null, CanonicalValue::Bool(false)),
        (CanonicalValue::Bytes(vec![]), CanonicalValue::String(String::new())),
        (CanonicalValue::Array(vec![]), CanonicalValue::Map(BTreeMap::new())),
    ];
    for (a, b) in &pairs {
        assert_ne!(a, b);
    }
}

#[test]
fn enrichment_canonical_value_debug_contains_variant_name() {
    assert!(format!("{:?}", CanonicalValue::U64(0)).contains("U64"));
    assert!(format!("{:?}", CanonicalValue::I64(0)).contains("I64"));
    assert!(format!("{:?}", CanonicalValue::Bool(true)).contains("Bool"));
    assert!(format!("{:?}", CanonicalValue::Bytes(vec![])).contains("Bytes"));
    assert!(format!("{:?}", CanonicalValue::String(String::new())).contains("String"));
    assert!(format!("{:?}", CanonicalValue::Array(vec![])).contains("Array"));
    assert!(format!("{:?}", CanonicalValue::Map(BTreeMap::new())).contains("Map"));
    assert!(format!("{:?}", CanonicalValue::Null).contains("Null"));
}

#[test]
fn enrichment_canonical_value_clone_deep_nested() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::Map(BTreeMap::from([
            ("inner".to_string(), CanonicalValue::Array(vec![
                CanonicalValue::I64(-999),
                CanonicalValue::Bytes(vec![0xDE, 0xAD]),
            ])),
        ])),
    ]);
    let cloned = val.clone();
    assert_eq!(val, cloned);
}

// -- SerdeError serde roundtrip for all variants --

#[test]
fn enrichment_serde_error_json_roundtrip_schema_mismatch() {
    let err = SerdeError::SchemaMismatch {
        expected: SchemaHash([0xAA; 32]),
        actual: SchemaHash([0xBB; 32]),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: SerdeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_error_json_roundtrip_unknown_schema() {
    let err = SerdeError::UnknownSchema {
        schema_hash: SchemaHash([0xCC; 32]),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: SerdeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_error_json_roundtrip_invalid_utf8() {
    let err = SerdeError::InvalidUtf8 { offset: 42 };
    let json = serde_json::to_string(&err).unwrap();
    let back: SerdeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_error_json_roundtrip_non_lexicographic() {
    let err = SerdeError::NonLexicographicKeys {
        prev_key: "z".to_string(),
        current_key: "a".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: SerdeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_error_json_roundtrip_recursion_limit() {
    let err = SerdeError::RecursionLimitExceeded { offset: 500 };
    let json = serde_json::to_string(&err).unwrap();
    let back: SerdeError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// -- SerdeError Display content verification --

#[test]
fn enrichment_display_buffer_too_short_shows_both_sizes() {
    let err = SerdeError::BufferTooShort { expected: 256, actual: 10 };
    let msg = err.to_string();
    assert!(msg.contains("256"));
    assert!(msg.contains("10"));
}

#[test]
fn enrichment_display_duplicate_key_shows_key_name() {
    let err = SerdeError::DuplicateKey { key: "my_field".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("my_field"));
}

#[test]
fn enrichment_display_invalid_utf8_shows_offset() {
    let err = SerdeError::InvalidUtf8 { offset: 777 };
    let msg = err.to_string();
    assert!(msg.contains("777"));
}

// -- SchemaDefinition tests --

#[test]
fn enrichment_schema_definition_debug_not_empty() {
    let def = SchemaDefinition {
        name: "DebugTest".to_string(),
        version: 1,
        schema_hash: test_schema(),
    };
    let dbg = format!("{def:?}");
    assert!(dbg.contains("DebugTest"));
}

#[test]
fn enrichment_schema_definition_clone_independence() {
    let mut original = SchemaDefinition {
        name: "Orig".to_string(),
        version: 1,
        schema_hash: test_schema(),
    };
    let cloned = original.clone();
    original.name = "Modified".to_string();
    assert_eq!(cloned.name, "Orig");
}

#[test]
fn enrichment_schema_definition_json_field_names() {
    let def = SchemaDefinition {
        name: "FieldNames".to_string(),
        version: 42,
        schema_hash: test_schema(),
    };
    let json = serde_json::to_string(&def).unwrap();
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"schema_hash\""));
    assert!(json.contains("\"FieldNames\""));
    assert!(json.contains("42"));
}

#[test]
fn enrichment_schema_definition_eq_by_all_fields() {
    let d1 = SchemaDefinition {
        name: "Same".to_string(),
        version: 1,
        schema_hash: test_schema(),
    };
    let d2 = SchemaDefinition {
        name: "Same".to_string(),
        version: 1,
        schema_hash: test_schema(),
    };
    assert_eq!(d1, d2);

    // Different version
    let d3 = SchemaDefinition {
        name: "Same".to_string(),
        version: 2,
        schema_hash: test_schema(),
    };
    assert_ne!(d1, d3);
}

// -- Determinism stress tests --

#[test]
fn enrichment_determinism_map_with_many_keys() {
    let mut map = BTreeMap::new();
    for i in 0u64..100 {
        map.insert(format!("key_{i:05}"), CanonicalValue::U64(i));
    }
    let val = CanonicalValue::Map(map);
    let first = encode_value(&val);
    for _ in 0..5 {
        assert_eq!(encode_value(&val), first);
    }
}

#[test]
fn enrichment_determinism_complex_nested_structure() {
    let val = CanonicalValue::Map(BTreeMap::from([
        ("alpha".to_string(), CanonicalValue::Array(vec![
            CanonicalValue::U64(1),
            CanonicalValue::I64(-1),
            CanonicalValue::Map(BTreeMap::from([
                ("nested".to_string(), CanonicalValue::Bool(true)),
            ])),
        ])),
        ("beta".to_string(), CanonicalValue::Bytes(vec![0xCA, 0xFE])),
        ("gamma".to_string(), CanonicalValue::Null),
    ]));
    let first = encode_value(&val);
    for _ in 0..10 {
        assert_eq!(encode_value(&val), first);
    }
}

#[test]
fn enrichment_determinism_schema_prefixed_complex() {
    let schema = test_schema();
    let val = CanonicalValue::Array(vec![
        CanonicalValue::String("abc".to_string()),
        CanonicalValue::Bytes(vec![1, 2, 3]),
    ]);
    let first = serialize_with_schema(&schema, &val);
    for _ in 0..10 {
        assert_eq!(serialize_with_schema(&schema, &val), first);
    }
}

// -- Roundtrip edge cases --

#[test]
fn enrichment_roundtrip_string_with_null_bytes() {
    let val = CanonicalValue::String("before\0after".to_string());
    let bytes = encode_value(&val);
    assert_eq!(decode_value(&bytes).unwrap(), val);
}

#[test]
fn enrichment_roundtrip_string_with_newlines_and_tabs() {
    let val = CanonicalValue::String("line1\nline2\ttab".to_string());
    let bytes = encode_value(&val);
    assert_eq!(decode_value(&bytes).unwrap(), val);
}

#[test]
fn enrichment_roundtrip_bytes_all_byte_values() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    let val = CanonicalValue::Bytes(all_bytes);
    let encoded = encode_value(&val);
    assert_eq!(decode_value(&encoded).unwrap(), val);
}

#[test]
fn enrichment_roundtrip_u64_powers_of_two() {
    for exp in 0..64 {
        let v: u64 = 1u64 << exp;
        let val = CanonicalValue::U64(v);
        assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
    }
}

#[test]
fn enrichment_roundtrip_i64_positive_negative_symmetry() {
    for v in [1i64, 100, 10000, 1_000_000, i64::MAX / 2] {
        let pos = CanonicalValue::I64(v);
        let neg = CanonicalValue::I64(-v);
        assert_eq!(decode_value(&encode_value(&pos)).unwrap(), pos);
        assert_eq!(decode_value(&encode_value(&neg)).unwrap(), neg);
    }
}

#[test]
fn enrichment_roundtrip_array_of_maps() {
    let arr = CanonicalValue::Array(vec![
        CanonicalValue::Map(BTreeMap::from([("a".to_string(), CanonicalValue::U64(1))])),
        CanonicalValue::Map(BTreeMap::from([("b".to_string(), CanonicalValue::I64(-2))])),
        CanonicalValue::Map(BTreeMap::new()),
    ]);
    assert_eq!(decode_value(&encode_value(&arr)).unwrap(), arr);
}

#[test]
fn enrichment_roundtrip_map_of_arrays() {
    let val = CanonicalValue::Map(BTreeMap::from([
        ("empty".to_string(), CanonicalValue::Array(vec![])),
        ("one".to_string(), CanonicalValue::Array(vec![CanonicalValue::Null])),
        ("two".to_string(), CanonicalValue::Array(vec![
            CanonicalValue::Bool(true),
            CanonicalValue::Bool(false),
        ])),
    ]));
    assert_eq!(decode_value(&encode_value(&val)).unwrap(), val);
}

// -- canonical_hash as content-address contract --

#[test]
fn enrichment_canonical_hash_same_value_same_schema_always_same() {
    let schema = SchemaHash::from_definition(b"stable-schema");
    let val = CanonicalValue::Map(BTreeMap::from([
        ("field".to_string(), CanonicalValue::U64(999)),
    ]));
    let first = canonical_hash(&schema, &val);
    for _ in 0..20 {
        assert_eq!(canonical_hash(&schema, &val), first);
    }
}

#[test]
fn enrichment_canonical_hash_single_bit_flip_differs() {
    let schema = test_schema();
    let h1 = canonical_hash(&schema, &CanonicalValue::U64(0));
    let h2 = canonical_hash(&schema, &CanonicalValue::U64(1));
    assert_ne!(h1, h2);
}

// -- CanonicalValue JSON serde edge cases --

#[test]
fn enrichment_canonical_value_json_nested_roundtrip() {
    let val = CanonicalValue::Array(vec![
        CanonicalValue::Map(BTreeMap::from([
            ("deep".to_string(), CanonicalValue::Array(vec![
                CanonicalValue::I64(i64::MIN),
                CanonicalValue::U64(u64::MAX),
            ])),
        ])),
    ]);
    let json = serde_json::to_string(&val).unwrap();
    let back: CanonicalValue = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_canonical_value_json_large_string() {
    let long_str = "a".repeat(10_000);
    let val = CanonicalValue::String(long_str.clone());
    let json = serde_json::to_string(&val).unwrap();
    let back: CanonicalValue = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_canonical_value_json_binary_field_name() {
    // JSON representation of CanonicalValue should use variant names
    let json = serde_json::to_string(&CanonicalValue::U64(42)).unwrap();
    assert!(json.contains("U64"));
    let json = serde_json::to_string(&CanonicalValue::Null).unwrap();
    assert!(json.contains("Null"));
}

// -- SerdeError std::error::Error source --

#[test]
fn enrichment_serde_error_source_none_for_all_variants() {
    let variants: Vec<SerdeError> = vec![
        SerdeError::SchemaMismatch {
            expected: test_schema(),
            actual: SchemaHash([0; 32]),
        },
        SerdeError::UnknownSchema { schema_hash: test_schema() },
        SerdeError::BufferTooShort { expected: 1, actual: 0 },
        SerdeError::InvalidTag { tag: 0xFF, offset: 0 },
        SerdeError::InvalidBoolEncoding { value: 0x02, offset: 0 },
        SerdeError::InvalidUtf8 { offset: 0 },
        SerdeError::DuplicateKey { key: "k".to_string() },
        SerdeError::NonLexicographicKeys {
            prev_key: "b".to_string(),
            current_key: "a".to_string(),
        },
        SerdeError::RecursionLimitExceeded { offset: 0 },
        SerdeError::TrailingBytes { count: 1 },
    ];
    for err in &variants {
        assert!(std::error::Error::source(err).is_none());
    }
}

// -- Encoding size contracts --

#[test]
fn enrichment_encoding_size_map_single_entry() {
    let mut map = BTreeMap::new();
    map.insert("k".to_string(), CanonicalValue::Null);
    let bytes = encode_value(&CanonicalValue::Map(map));
    // tag(1) + count(4) + key_len(4) + key("k"=1) + null_tag(1) = 11
    assert_eq!(bytes.len(), 11);
}

#[test]
fn enrichment_encoding_size_array_of_nulls() {
    let val = CanonicalValue::Array(vec![CanonicalValue::Null; 5]);
    let bytes = encode_value(&val);
    // tag(1) + count(4) + 5 * null_tag(1) = 10
    assert_eq!(bytes.len(), 10);
}

#[test]
fn enrichment_encoding_size_schema_prefixed_u64() {
    let schema = test_schema();
    let data = serialize_with_schema(&schema, &CanonicalValue::U64(42));
    // 32 schema + 1 tag + 8 data = 41
    assert_eq!(data.len(), 41);
}

// -- Mixed schema registry usage --

#[test]
fn enrichment_registry_three_schemas_all_lookup_ok() {
    let mut reg = SchemaRegistry::new();
    let h1 = reg.register("A", 1, b"def-a");
    let h2 = reg.register("B", 2, b"def-b");
    let h3 = reg.register("C", 3, b"def-c");

    assert!(reg.is_known(&h1));
    assert!(reg.is_known(&h2));
    assert!(reg.is_known(&h3));
    assert_eq!(reg.len(), 3);

    assert_eq!(reg.lookup(&h1).unwrap().name, "A");
    assert_eq!(reg.lookup(&h2).unwrap().name, "B");
    assert_eq!(reg.lookup(&h3).unwrap().name, "C");
}
