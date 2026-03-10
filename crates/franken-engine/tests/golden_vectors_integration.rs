#![forbid(unsafe_code)]

//! Comprehensive integration tests for the `golden_vectors` module.
//!
//! Covers: GoldenVector, GoldenVectorSet, to_hex, from_hex.
//! Validates construction, serde roundtrips, Display/Debug impls,
//! hex encoding/decoding edge cases, deterministic replay, and error
//! conditions.

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

use frankenengine_engine::golden_vectors::{GoldenVector, GoldenVectorSet, from_hex, to_hex};

// ---------------------------------------------------------------------------
// Section 1: GoldenVector construction and field access
// ---------------------------------------------------------------------------

fn sample_vector(name: &str, expect_error: bool) -> GoldenVector {
    let mut input = BTreeMap::new();
    input.insert(
        "data".to_string(),
        serde_json::Value::String("deadbeef".to_string()),
    );
    let mut expected = BTreeMap::new();
    expected.insert(
        "hash".to_string(),
        serde_json::Value::String("abc123".to_string()),
    );
    GoldenVector {
        test_name: name.to_string(),
        description: format!("Test vector: {name}"),
        category: "deterministic_serde".to_string(),
        schema_version: "1.0".to_string(),
        input,
        expected,
        expect_error,
    }
}

#[test]
fn golden_vector_construction_positive() {
    let v = sample_vector("test_positive_01", false);
    assert_eq!(v.test_name, "test_positive_01");
    assert_eq!(v.category, "deterministic_serde");
    assert_eq!(v.schema_version, "1.0");
    assert!(!v.expect_error);
    assert!(v.input.contains_key("data"));
    assert!(v.expected.contains_key("hash"));
}

#[test]
fn golden_vector_construction_negative() {
    let v = sample_vector("test_negative_01", true);
    assert!(v.expect_error);
}

#[test]
fn golden_vector_empty_maps() {
    let v = GoldenVector {
        test_name: "empty_maps".to_string(),
        description: String::new(),
        category: "non_canonical_rejection".to_string(),
        schema_version: "1.0".to_string(),
        input: BTreeMap::new(),
        expected: BTreeMap::new(),
        expect_error: true,
    };
    assert!(v.input.is_empty());
    assert!(v.expected.is_empty());
}

#[test]
fn golden_vector_complex_input() {
    let mut input = BTreeMap::new();
    input.insert("tag".to_string(), serde_json::Value::Number(255.into()));
    input.insert(
        "bytes".to_string(),
        serde_json::Value::Array(vec![
            serde_json::Value::Number(0.into()),
            serde_json::Value::Number(255.into()),
        ]),
    );
    input.insert("nested".to_string(), serde_json::Value::Bool(true));

    let v = GoldenVector {
        test_name: "complex_input".to_string(),
        description: "Complex structured input".to_string(),
        category: "schema_hash".to_string(),
        schema_version: "2.0".to_string(),
        input,
        expected: BTreeMap::new(),
        expect_error: false,
    };
    assert_eq!(v.input.len(), 3);
    assert_eq!(v.input["tag"], serde_json::Value::Number(255.into()));
}

// ---------------------------------------------------------------------------
// Section 2: GoldenVectorSet construction
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_construction() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "deterministic_serde".to_string(),
        vectors: vec![sample_vector("vec_a", false), sample_vector("vec_b", true)],
    };
    assert_eq!(set.vector_format_version, "1.0.0");
    assert_eq!(set.category, "deterministic_serde");
    assert_eq!(set.vectors.len(), 2);
    assert_eq!(set.vectors[0].test_name, "vec_a");
    assert_eq!(set.vectors[1].test_name, "vec_b");
}

#[test]
fn golden_vector_set_empty_vectors() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "empty".to_string(),
        vectors: Vec::new(),
    };
    assert!(set.vectors.is_empty());
}

#[test]
fn golden_vector_set_all_categories() {
    let categories = [
        "deterministic_serde",
        "schema_hash",
        "engine_object_id",
        "signature_preimage",
        "signature_creation",
        "multisig_ordering",
        "revocation_chain",
        "non_canonical_rejection",
    ];
    for category in &categories {
        let set = GoldenVectorSet {
            vector_format_version: "1.0.0".to_string(),
            category: category.to_string(),
            vectors: vec![sample_vector(&format!("{category}_01"), false)],
        };
        assert_eq!(set.category, *category);
    }
}

// ---------------------------------------------------------------------------
// Section 3: to_hex encoding
// ---------------------------------------------------------------------------

#[test]
fn to_hex_empty_input() {
    assert_eq!(to_hex(&[]), "");
}

#[test]
fn to_hex_single_byte() {
    assert_eq!(to_hex(&[0x00]), "00");
    assert_eq!(to_hex(&[0xff]), "ff");
    assert_eq!(to_hex(&[0x0a]), "0a");
    assert_eq!(to_hex(&[0xa0]), "a0");
}

#[test]
fn to_hex_known_sequence() {
    assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
}

#[test]
fn to_hex_all_zeros() {
    let bytes = vec![0u8; 32];
    let hex = to_hex(&bytes);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c == '0'));
}

#[test]
fn to_hex_all_ones() {
    let bytes = vec![0xff; 16];
    let hex = to_hex(&bytes);
    assert_eq!(hex, "ffffffffffffffffffffffffffffffff");
}

#[test]
fn to_hex_produces_lowercase() {
    let bytes: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&bytes);
    // Verify all hex chars are lowercase
    for c in hex.chars() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "unexpected char in hex output: {c}"
        );
    }
}

#[test]
fn to_hex_length_is_double_input() {
    for len in [0, 1, 16, 32, 64, 128, 256] {
        let bytes = vec![0xab; len];
        assert_eq!(to_hex(&bytes).len(), len * 2);
    }
}

// ---------------------------------------------------------------------------
// Section 4: from_hex decoding
// ---------------------------------------------------------------------------

#[test]
fn from_hex_empty_input() {
    let result = from_hex("");
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

#[test]
fn from_hex_known_sequence() {
    let result = from_hex("deadbeef").unwrap();
    assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_all_zeros() {
    let hex = "0".repeat(64);
    let result = from_hex(&hex).unwrap();
    assert_eq!(result, vec![0u8; 32]);
}

#[test]
fn from_hex_all_ones() {
    let hex = "f".repeat(32);
    let result = from_hex(&hex).unwrap();
    assert_eq!(result, vec![0xff; 16]);
}

#[test]
fn from_hex_uppercase_accepted() {
    let result = from_hex("DEADBEEF").unwrap();
    assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_mixed_case_accepted() {
    let result = from_hex("DeAdBeEf").unwrap();
    assert_eq!(result, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_odd_length_rejected() {
    let err = from_hex("abc").unwrap_err();
    assert!(err.contains("odd hex length"));
}

#[test]
fn from_hex_invalid_char_rejected() {
    let err = from_hex("zz").unwrap_err();
    assert!(err.contains("bad hex char"));
}

#[test]
fn from_hex_invalid_char_in_middle() {
    let err = from_hex("00gg00").unwrap_err();
    assert!(err.contains("bad hex char"));
}

#[test]
fn from_hex_space_rejected() {
    let err = from_hex("de ad").unwrap_err();
    assert!(err.contains("odd hex length") || err.contains("bad hex char"));
}

#[test]
fn from_hex_single_byte() {
    assert_eq!(from_hex("00").unwrap(), vec![0x00]);
    assert_eq!(from_hex("ff").unwrap(), vec![0xff]);
    assert_eq!(from_hex("7f").unwrap(), vec![0x7f]);
}

// ---------------------------------------------------------------------------
// Section 5: Hex roundtrip (to_hex -> from_hex -> to_hex)
// ---------------------------------------------------------------------------

#[test]
fn hex_roundtrip_empty() {
    let original: Vec<u8> = vec![];
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn hex_roundtrip_all_byte_values() {
    let original: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn hex_roundtrip_32_bytes() {
    let original: Vec<u8> = (0..32).collect();
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
    // Re-encode
    let re_hex = to_hex(&decoded);
    assert_eq!(re_hex, hex);
}

#[test]
fn hex_roundtrip_large_buffer() {
    let original: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn hex_roundtrip_deterministic() {
    let data = vec![0x42; 64];
    let hex1 = to_hex(&data);
    let hex2 = to_hex(&data);
    assert_eq!(hex1, hex2, "to_hex must be deterministic");
}

// ---------------------------------------------------------------------------
// Section 6: Serde roundtrips - GoldenVector
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_serde_roundtrip_positive() {
    let v = sample_vector("serde_positive", false);
    let json = serde_json::to_string(&v).expect("serialize GoldenVector");
    let restored: GoldenVector = serde_json::from_str(&json).expect("deserialize GoldenVector");
    assert_eq!(v, restored);
}

#[test]
fn golden_vector_serde_roundtrip_negative() {
    let v = sample_vector("serde_negative", true);
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: GoldenVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

#[test]
fn golden_vector_serde_roundtrip_empty_fields() {
    let v = GoldenVector {
        test_name: String::new(),
        description: String::new(),
        category: String::new(),
        schema_version: String::new(),
        input: BTreeMap::new(),
        expected: BTreeMap::new(),
        expect_error: false,
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: GoldenVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

#[test]
fn golden_vector_serde_roundtrip_complex_values() {
    let mut input = BTreeMap::new();
    input.insert(
        "nested_obj".to_string(),
        serde_json::json!({"a": 1, "b": [true, false, null]}),
    );
    input.insert(
        "number".to_string(),
        serde_json::Value::Number(serde_json::Number::from(42)),
    );

    let mut expected = BTreeMap::new();
    expected.insert(
        "result".to_string(),
        serde_json::json!({"status": "ok", "values": [1, 2, 3]}),
    );

    let v = GoldenVector {
        test_name: "complex_serde".to_string(),
        description: "Deeply nested structures".to_string(),
        category: "deterministic_serde".to_string(),
        schema_version: "1.0".to_string(),
        input,
        expected,
        expect_error: false,
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: GoldenVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

#[test]
fn golden_vector_serde_pretty_print_roundtrip() {
    let v = sample_vector("pretty", false);
    let json = serde_json::to_string_pretty(&v).expect("serialize pretty");
    let restored: GoldenVector = serde_json::from_str(&json).expect("deserialize pretty");
    assert_eq!(v, restored);
}

// ---------------------------------------------------------------------------
// Section 7: Serde roundtrips - GoldenVectorSet
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_serde_roundtrip() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "schema_hash".to_string(),
        vectors: vec![
            sample_vector("set_a", false),
            sample_vector("set_b", true),
            sample_vector("set_c", false),
        ],
    };
    let json = serde_json::to_string(&set).expect("serialize GoldenVectorSet");
    let restored: GoldenVectorSet =
        serde_json::from_str(&json).expect("deserialize GoldenVectorSet");
    assert_eq!(set, restored);
}

#[test]
fn golden_vector_set_serde_roundtrip_empty() {
    let set = GoldenVectorSet {
        vector_format_version: "0.0.1".to_string(),
        category: "empty_set".to_string(),
        vectors: Vec::new(),
    };
    let json = serde_json::to_string(&set).expect("serialize");
    let restored: GoldenVectorSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(set, restored);
}

#[test]
fn golden_vector_set_serde_pretty_roundtrip() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "engine_object_id".to_string(),
        vectors: vec![sample_vector("pretty_set", false)],
    };
    let json = serde_json::to_string_pretty(&set).expect("serialize pretty");
    let restored: GoldenVectorSet = serde_json::from_str(&json).expect("deserialize pretty");
    assert_eq!(set, restored);
}

// ---------------------------------------------------------------------------
// Section 8: Clone and PartialEq
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_clone_equals_original() {
    let v = sample_vector("clone_test", false);
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn golden_vector_set_clone_equals_original() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "test".to_string(),
        vectors: vec![sample_vector("c1", false), sample_vector("c2", true)],
    };
    let cloned = set.clone();
    assert_eq!(set, cloned);
}

#[test]
fn golden_vector_inequality_different_name() {
    let v1 = sample_vector("name_a", false);
    let v2 = sample_vector("name_b", false);
    assert_ne!(v1, v2);
}

#[test]
fn golden_vector_inequality_different_expect_error() {
    let v1 = sample_vector("same_name", false);
    let v2 = sample_vector("same_name", true);
    assert_ne!(v1, v2);
}

#[test]
fn golden_vector_set_inequality_different_category() {
    let set1 = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "cat_a".to_string(),
        vectors: Vec::new(),
    };
    let set2 = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "cat_b".to_string(),
        vectors: Vec::new(),
    };
    assert_ne!(set1, set2);
}

// ---------------------------------------------------------------------------
// Section 9: Debug impls
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_debug_contains_test_name() {
    let v = sample_vector("debug_test", false);
    let debug = format!("{v:?}");
    assert!(debug.contains("debug_test"));
    assert!(debug.contains("GoldenVector"));
}

#[test]
fn golden_vector_set_debug_contains_category() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "debug_category".to_string(),
        vectors: Vec::new(),
    };
    let debug = format!("{set:?}");
    assert!(debug.contains("debug_category"));
    assert!(debug.contains("GoldenVectorSet"));
}

// ---------------------------------------------------------------------------
// Section 10: Deterministic replay — hex encoding stability
// ---------------------------------------------------------------------------

#[test]
fn hex_encoding_deterministic_across_invocations() {
    let data: Vec<u8> = (0..=255).collect();
    let hex1 = to_hex(&data);
    let hex2 = to_hex(&data);
    let hex3 = to_hex(&data);
    assert_eq!(hex1, hex2);
    assert_eq!(hex2, hex3);
}

#[test]
fn hex_decoding_deterministic_across_invocations() {
    let hex = "0123456789abcdef";
    let d1 = from_hex(hex).unwrap();
    let d2 = from_hex(hex).unwrap();
    let d3 = from_hex(hex).unwrap();
    assert_eq!(d1, d2);
    assert_eq!(d2, d3);
}

// ---------------------------------------------------------------------------
// Section 11: Pinned hex encoding vectors
// ---------------------------------------------------------------------------

#[test]
fn pinned_hex_encoding_byte_zero() {
    assert_eq!(to_hex(&[0x00]), "00");
}

#[test]
fn pinned_hex_encoding_byte_max() {
    assert_eq!(to_hex(&[0xff]), "ff");
}

#[test]
fn pinned_hex_encoding_deadbeef() {
    assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
}

#[test]
fn pinned_hex_encoding_cafebabe() {
    assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
}

#[test]
fn pinned_hex_decoding_deadbeef() {
    assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn pinned_hex_decoding_cafebabe() {
    assert_eq!(from_hex("cafebabe").unwrap(), vec![0xca, 0xfe, 0xba, 0xbe]);
}

// ---------------------------------------------------------------------------
// Section 12: Error condition edge cases for from_hex
// ---------------------------------------------------------------------------

#[test]
fn from_hex_single_char_rejected() {
    let err = from_hex("a").unwrap_err();
    assert!(err.contains("odd hex length"));
}

#[test]
fn from_hex_three_chars_rejected() {
    let err = from_hex("abc").unwrap_err();
    assert!(err.contains("odd hex length"));
}

#[test]
fn from_hex_non_ascii_rejected() {
    // Unicode characters should fail
    let err = from_hex("\u{00e9}\u{00e9}").unwrap_err();
    assert!(
        err.contains("odd hex length") || err.contains("bad hex char"),
        "expected error for non-ASCII, got: {err}"
    );
}

#[test]
fn from_hex_newline_rejected() {
    let err = from_hex("de\nad").unwrap_err();
    assert!(
        err.contains("odd hex length") || err.contains("bad hex char"),
        "expected error for newline in hex, got: {err}"
    );
}

#[test]
fn from_hex_null_byte_rejected() {
    let err = from_hex("de\x00ad").unwrap_err();
    assert!(
        err.contains("odd hex length") || err.contains("bad hex char"),
        "expected error for null byte in hex, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Section 13: BTreeMap key ordering in GoldenVector input/expected
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_input_map_maintains_sorted_order() {
    let mut input = BTreeMap::new();
    input.insert("zeta".to_string(), serde_json::Value::Null);
    input.insert("alpha".to_string(), serde_json::Value::Null);
    input.insert("mu".to_string(), serde_json::Value::Null);

    let keys: Vec<&String> = input.keys().collect();
    assert_eq!(keys, vec!["alpha", "mu", "zeta"]);
}

#[test]
fn golden_vector_serde_preserves_key_order() {
    let mut input = BTreeMap::new();
    input.insert("z_last".to_string(), serde_json::Value::Bool(true));
    input.insert("a_first".to_string(), serde_json::Value::Bool(false));
    input.insert("m_middle".to_string(), serde_json::Value::Null);

    let v = GoldenVector {
        test_name: "key_order".to_string(),
        description: String::new(),
        category: "test".to_string(),
        schema_version: "1.0".to_string(),
        input,
        expected: BTreeMap::new(),
        expect_error: false,
    };

    let json = serde_json::to_string(&v).unwrap();
    let restored: GoldenVector = serde_json::from_str(&json).unwrap();
    let keys: Vec<&String> = restored.input.keys().collect();
    assert_eq!(keys, vec!["a_first", "m_middle", "z_last"]);
}

// ---------------------------------------------------------------------------
// Section 14: Large vector set handling
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_handles_many_vectors() {
    let vectors: Vec<GoldenVector> = (0..100)
        .map(|i| sample_vector(&format!("vector_{i:04}"), i % 3 == 0))
        .collect();
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "bulk_test".to_string(),
        vectors,
    };
    assert_eq!(set.vectors.len(), 100);

    // Serde roundtrip
    let json = serde_json::to_string(&set).unwrap();
    let restored: GoldenVectorSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, restored);
}

// ---------------------------------------------------------------------------
// Section 15: Immutability contract verification (conceptual tests)
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_fields_are_independent() {
    // Changing one field does not affect others
    let mut v = sample_vector("independent_a", false);
    let original_category = v.category.clone();
    v.test_name = "independent_b".to_string();
    assert_eq!(v.category, original_category);
}

#[test]
fn golden_vector_set_version_independent_of_vectors() {
    let set = GoldenVectorSet {
        vector_format_version: "2.0.0".to_string(),
        category: "test".to_string(),
        vectors: vec![sample_vector("v1", false)],
    };
    // Changing version does not affect vectors
    let mut cloned = set.clone();
    cloned.vector_format_version = "3.0.0".to_string();
    assert_eq!(set.vectors, cloned.vectors);
    assert_ne!(set.vector_format_version, cloned.vector_format_version);
}

// ---------------------------------------------------------------------------
// Section 16: Hex boundary values
// ---------------------------------------------------------------------------

#[test]
fn hex_boundary_every_nibble_value() {
    // Test each hex digit 0-f
    for nibble in 0..=15u8 {
        let byte = nibble << 4 | nibble;
        let hex = to_hex(&[byte]);
        let expected_char = char::from_digit(nibble as u32, 16).unwrap();
        let expected = format!("{expected_char}{expected_char}");
        assert_eq!(hex, expected, "nibble {nibble} failed");
    }
}

#[test]
fn hex_decode_each_valid_hex_digit() {
    // Decode each pair of valid hex digits
    for hi in 0..=15u8 {
        for lo in 0..=15u8 {
            let hi_c = char::from_digit(hi as u32, 16).unwrap();
            let lo_c = char::from_digit(lo as u32, 16).unwrap();
            let hex_str = format!("{hi_c}{lo_c}");
            let result = from_hex(&hex_str).unwrap();
            assert_eq!(result, vec![(hi << 4) | lo]);
        }
    }
}

// ---------------------------------------------------------------------------
// Section 17: Serde JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_json_field_names_stable() {
    let v = sample_vector("stable_fields", false);
    let json = serde_json::to_string(&v).unwrap();
    // Verify expected field names appear in the JSON
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
        vector_format_version: "1.0.0".to_string(),
        category: "test".to_string(),
        vectors: Vec::new(),
    };
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains("\"vector_format_version\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"vectors\""));
}

// ---------------------------------------------------------------------------
// Section 18: Cross-type interactions
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_hex_values_in_input_roundtrip() {
    // Put hex-encoded data in a GoldenVector input, serialize, recover, decode
    let original_bytes = vec![0x01, 0x02, 0x03, 0x04];
    let hex_val = to_hex(&original_bytes);

    let mut input = BTreeMap::new();
    input.insert(
        "hex_data".to_string(),
        serde_json::Value::String(hex_val.clone()),
    );

    let v = GoldenVector {
        test_name: "hex_in_input".to_string(),
        description: "Hex data stored in input map".to_string(),
        category: "deterministic_serde".to_string(),
        schema_version: "1.0".to_string(),
        input,
        expected: BTreeMap::new(),
        expect_error: false,
    };

    let json = serde_json::to_string(&v).unwrap();
    let restored: GoldenVector = serde_json::from_str(&json).unwrap();

    let restored_hex = restored.input["hex_data"].as_str().unwrap();
    let recovered_bytes = from_hex(restored_hex).unwrap();
    assert_eq!(recovered_bytes, original_bytes);
}

#[test]
fn golden_vector_set_with_mixed_categories() {
    // A set contains only vectors of its stated category
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".to_string(),
        category: "schema_hash".to_string(),
        vectors: vec![
            {
                let mut v = sample_vector("cat_match", false);
                v.category = "schema_hash".to_string();
                v
            },
            {
                let mut v = sample_vector("cat_mismatch", false);
                v.category = "schema_hash".to_string();
                v
            },
        ],
    };
    // All vectors should match the set category
    for v in &set.vectors {
        assert_eq!(v.category, set.category);
    }
}
