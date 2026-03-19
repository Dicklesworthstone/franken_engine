#![forbid(unsafe_code)]
//! Enrichment integration tests for `golden_vectors`.
//!
//! Tests to_hex/from_hex roundtrip, to_hex lowercase, from_hex odd length error,
//! from_hex bad chars error, from_hex empty, GoldenVector serde roundtrip,
//! GoldenVectorSet serde roundtrip, hex encoding edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;

use frankenengine_engine::golden_vectors::{GoldenVector, GoldenVectorSet, from_hex, to_hex};

// ===========================================================================
// helpers
// ===========================================================================

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

// ===========================================================================
// to_hex / from_hex roundtrip
// ===========================================================================

#[test]
fn enrichment_hex_roundtrip_all_byte_values() {
    let original: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn enrichment_hex_roundtrip_32_bytes() {
    let original: Vec<u8> = (0..32).collect();
    let hex = to_hex(&original);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(to_hex(&decoded), hex);
}

#[test]
fn enrichment_hex_roundtrip_single_byte() {
    for b in 0..=255u8 {
        let hex = to_hex(&[b]);
        let decoded = from_hex(&hex).unwrap();
        assert_eq!(decoded, vec![b]);
    }
}

#[test]
fn enrichment_hex_roundtrip_large_buffer() {
    let original: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let decoded = from_hex(&to_hex(&original)).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn enrichment_hex_roundtrip_deterministic() {
    let data = vec![0x42; 64];
    assert_eq!(to_hex(&data), to_hex(&data));
}

// ===========================================================================
// to_hex lowercase
// ===========================================================================

#[test]
fn enrichment_to_hex_always_lowercase() {
    let bytes: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&bytes);
    for c in hex.chars() {
        assert!(
            c.is_ascii_digit() || ('a'..='f').contains(&c),
            "unexpected char '{c}'"
        );
    }
}

#[test]
fn enrichment_to_hex_known_values() {
    assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
    assert_eq!(to_hex(&[0xab, 0xcd, 0xef]), "abcdef");
}

#[test]
fn enrichment_to_hex_length_is_double() {
    for len in [0, 1, 16, 32, 64, 128] {
        assert_eq!(to_hex(&vec![0xab; len]).len(), len * 2);
    }
}

// ===========================================================================
// from_hex odd length error
// ===========================================================================

#[test]
fn enrichment_from_hex_odd_length_single_char() {
    let err = from_hex("a").unwrap_err();
    assert!(err.contains("odd hex length"));
}

#[test]
fn enrichment_from_hex_odd_length_three_chars() {
    let err = from_hex("abc").unwrap_err();
    assert!(err.contains("odd hex length"));
}

#[test]
fn enrichment_from_hex_odd_length_five_chars() {
    let err = from_hex("abcde").unwrap_err();
    assert!(err.contains("odd hex length"));
}

// ===========================================================================
// from_hex bad chars error
// ===========================================================================

#[test]
fn enrichment_from_hex_bad_chars_zz() {
    let err = from_hex("zz").unwrap_err();
    assert!(err.contains("bad hex char"));
}

#[test]
fn enrichment_from_hex_bad_chars_gg() {
    let err = from_hex("gg").unwrap_err();
    assert!(err.contains("bad hex char"));
}

#[test]
fn enrichment_from_hex_bad_chars_space() {
    let err = from_hex("de ad").unwrap_err();
    assert!(err.contains("odd hex length") || err.contains("bad hex char"));
}

// ===========================================================================
// from_hex empty
// ===========================================================================

#[test]
fn enrichment_from_hex_empty_returns_empty_vec() {
    let result = from_hex("").unwrap();
    assert!(result.is_empty());
}

#[test]
fn enrichment_to_hex_empty_returns_empty_string() {
    assert_eq!(to_hex(&[]), "");
}

// ===========================================================================
// Hex encoding edge cases
// ===========================================================================

#[test]
fn enrichment_to_hex_all_zeros_32_bytes() {
    let bytes = vec![0u8; 32];
    let hex = to_hex(&bytes);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c == '0'));
}

#[test]
fn enrichment_to_hex_all_ff_16_bytes() {
    let bytes = vec![0xff; 16];
    assert_eq!(to_hex(&bytes), "ffffffffffffffffffffffffffffffff");
}

#[test]
fn enrichment_to_hex_single_byte_zero() {
    assert_eq!(to_hex(&[0x00]), "00");
}

#[test]
fn enrichment_to_hex_single_byte_ff() {
    assert_eq!(to_hex(&[0xff]), "ff");
}

#[test]
fn enrichment_from_hex_accepts_uppercase() {
    assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn enrichment_from_hex_accepts_mixed_case() {
    assert_eq!(from_hex("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn enrichment_hex_every_nibble_value() {
    for nibble in 0..=15u8 {
        let byte = nibble << 4 | nibble;
        let hex = to_hex(&[byte]);
        let ch = char::from_digit(nibble as u32, 16).unwrap();
        assert_eq!(hex, format!("{ch}{ch}"));
    }
}

// ===========================================================================
// GoldenVector serde roundtrip
// ===========================================================================

#[test]
fn enrichment_golden_vector_serde_roundtrip_positive() {
    let v = sample_vector("positive_01", false);
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_golden_vector_serde_roundtrip_negative() {
    let v = sample_vector("negative_01", true);
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert!(back.expect_error);
}

#[test]
fn enrichment_golden_vector_serde_empty_maps() {
    let v = GoldenVector {
        test_name: "empty".into(),
        description: String::new(),
        category: "test".into(),
        schema_version: "1.0".into(),
        input: BTreeMap::new(),
        expected: BTreeMap::new(),
        expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_golden_vector_serde_complex_nested() {
    let mut input = BTreeMap::new();
    input.insert("nested".into(), serde_json::json!({"a": [1,2,3], "b": null}));
    let v = GoldenVector {
        test_name: "complex".into(),
        description: "nested".into(),
        category: "schema_hash".into(),
        schema_version: "2.0".into(),
        input,
        expected: BTreeMap::new(),
        expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_golden_vector_json_field_names_stable() {
    let v = sample_vector("fields", false);
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"test_name\""));
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"input\""));
    assert!(json.contains("\"expected\""));
    assert!(json.contains("\"expect_error\""));
}

// ===========================================================================
// GoldenVectorSet serde roundtrip
// ===========================================================================

#[test]
fn enrichment_golden_vector_set_serde_roundtrip() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "schema_hash".into(),
        vectors: vec![sample_vector("a", false), sample_vector("b", true)],
    };
    let json = serde_json::to_string(&set).unwrap();
    let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, back);
}

#[test]
fn enrichment_golden_vector_set_serde_empty_vectors() {
    let set = GoldenVectorSet {
        vector_format_version: "0.0.1".into(),
        category: "empty".into(),
        vectors: Vec::new(),
    };
    let json = serde_json::to_string(&set).unwrap();
    let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, back);
    assert!(back.vectors.is_empty());
}

#[test]
fn enrichment_golden_vector_set_json_field_names_stable() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "test".into(),
        vectors: Vec::new(),
    };
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains("\"vector_format_version\""));
    assert!(json.contains("\"category\""));
    assert!(json.contains("\"vectors\""));
}

// ===========================================================================
// Clone, PartialEq, Debug
// ===========================================================================

#[test]
fn enrichment_golden_vector_clone_eq() {
    let v = sample_vector("clone_test", false);
    assert_eq!(v, v.clone());
}

#[test]
fn enrichment_golden_vector_ne_different_name() {
    assert_ne!(sample_vector("a", false), sample_vector("b", false));
}

#[test]
fn enrichment_golden_vector_ne_different_expect_error() {
    assert_ne!(sample_vector("same", false), sample_vector("same", true));
}

#[test]
fn enrichment_golden_vector_debug_contains_name() {
    let v = sample_vector("dbg_test", false);
    let d = format!("{v:?}");
    assert!(d.contains("dbg_test"));
    assert!(d.contains("GoldenVector"));
}

#[test]
fn enrichment_golden_vector_set_debug_contains_category() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "debug_cat".into(),
        vectors: Vec::new(),
    };
    let d = format!("{set:?}");
    assert!(d.contains("debug_cat"));
    assert!(d.contains("GoldenVectorSet"));
}

// ===========================================================================
// BTreeMap ordering in input
// ===========================================================================

#[test]
fn enrichment_golden_vector_input_map_sorted() {
    let mut input = BTreeMap::new();
    input.insert("zeta".into(), serde_json::Value::Null);
    input.insert("alpha".into(), serde_json::Value::Null);
    input.insert("mu".into(), serde_json::Value::Null);
    let keys: Vec<&String> = input.keys().collect();
    assert_eq!(keys, vec!["alpha", "mu", "zeta"]);
}

// ===========================================================================
// Hex integrated with golden vector
// ===========================================================================

#[test]
fn enrichment_hex_in_golden_vector_input_roundtrip() {
    let original = vec![0x01, 0x02, 0x03, 0x04];
    let hex_val = to_hex(&original);
    let mut input = BTreeMap::new();
    input.insert("hex_data".into(), serde_json::Value::String(hex_val));
    let v = GoldenVector {
        test_name: "hex_rt".into(),
        description: "hex in input".into(),
        category: "deterministic_serde".into(),
        schema_version: "1.0".into(),
        input,
        expected: BTreeMap::new(),
        expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: GoldenVector = serde_json::from_str(&json).unwrap();
    let restored_hex = restored.input["hex_data"].as_str().unwrap();
    assert_eq!(from_hex(restored_hex).unwrap(), original);
}
