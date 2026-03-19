#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `golden_vectors`.

use std::collections::BTreeMap;

use frankenengine_engine::golden_vectors::{GoldenVector, GoldenVectorSet, from_hex, to_hex};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_vector(name: &str, expect_error: bool) -> GoldenVector {
    let mut input = BTreeMap::new();
    input.insert("data".to_string(), serde_json::Value::String("deadbeef".to_string()));
    let mut expected = BTreeMap::new();
    expected.insert("hash".to_string(), serde_json::Value::String("abc123".to_string()));
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

// ---------------------------------------------------------------------------
// to_hex encoding
// ---------------------------------------------------------------------------

#[test]
fn to_hex_empty() {
    assert_eq!(to_hex(&[]), "");
}

#[test]
fn to_hex_single_bytes() {
    assert_eq!(to_hex(&[0x00]), "00");
    assert_eq!(to_hex(&[0xff]), "ff");
    assert_eq!(to_hex(&[0x0a]), "0a");
    assert_eq!(to_hex(&[0xa0]), "a0");
    assert_eq!(to_hex(&[0x42]), "42");
}

#[test]
fn to_hex_known_deadbeef() {
    assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
}

#[test]
fn to_hex_known_cafebabe() {
    assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
}

#[test]
fn to_hex_all_zeros_32_bytes() {
    let bytes = vec![0u8; 32];
    let hex = to_hex(&bytes);
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c == '0'));
}

#[test]
fn to_hex_all_ff_16_bytes() {
    let bytes = vec![0xff; 16];
    assert_eq!(to_hex(&bytes), "ffffffffffffffffffffffffffffffff");
}

#[test]
fn to_hex_lowercase_only() {
    let bytes: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&bytes);
    for c in hex.chars() {
        assert!(c.is_ascii_digit() || ('a'..='f').contains(&c));
    }
}

#[test]
fn to_hex_length_is_double() {
    for len in [0, 1, 16, 32, 64, 128] {
        assert_eq!(to_hex(&vec![0xab; len]).len(), len * 2);
    }
}

// ---------------------------------------------------------------------------
// from_hex decoding
// ---------------------------------------------------------------------------

#[test]
fn from_hex_empty() {
    assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
}

#[test]
fn from_hex_known_deadbeef() {
    assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_uppercase_accepted() {
    assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_mixed_case() {
    assert_eq!(from_hex("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn from_hex_odd_length_rejected() {
    assert!(from_hex("abc").unwrap_err().contains("odd hex length"));
}

#[test]
fn from_hex_invalid_char_rejected() {
    assert!(from_hex("zz").unwrap_err().contains("bad hex char"));
}

#[test]
fn from_hex_space_rejected() {
    let err = from_hex("de ad").unwrap_err();
    assert!(err.contains("odd hex length") || err.contains("bad hex char"));
}

#[test]
fn from_hex_single_char_rejected() {
    assert!(from_hex("a").unwrap_err().contains("odd hex length"));
}

// ---------------------------------------------------------------------------
// Hex roundtrip
// ---------------------------------------------------------------------------

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
    assert_eq!(to_hex(&decoded), hex);
}

#[test]
fn hex_roundtrip_deterministic() {
    let data = vec![0x42; 64];
    assert_eq!(to_hex(&data), to_hex(&data));
}

#[test]
fn hex_roundtrip_large_buffer() {
    let original: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let decoded = from_hex(&to_hex(&original)).unwrap();
    assert_eq!(decoded, original);
}

// ---------------------------------------------------------------------------
// GoldenVector construction and fields
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_construction_positive() {
    let v = sample_vector("pos_01", false);
    assert_eq!(v.test_name, "pos_01");
    assert!(!v.expect_error);
    assert!(v.input.contains_key("data"));
    assert!(v.expected.contains_key("hash"));
}

#[test]
fn golden_vector_construction_negative() {
    let v = sample_vector("neg_01", true);
    assert!(v.expect_error);
}

#[test]
fn golden_vector_empty_maps() {
    let v = GoldenVector {
        test_name: "empty".into(),
        description: String::new(),
        category: "test".into(),
        schema_version: "1.0".into(),
        input: BTreeMap::new(),
        expected: BTreeMap::new(),
        expect_error: false,
    };
    assert!(v.input.is_empty());
    assert!(v.expected.is_empty());
}

// ---------------------------------------------------------------------------
// GoldenVectorSet
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_construction() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "deterministic_serde".into(),
        vectors: vec![sample_vector("a", false), sample_vector("b", true)],
    };
    assert_eq!(set.vectors.len(), 2);
    assert_eq!(set.category, "deterministic_serde");
}

#[test]
fn golden_vector_set_empty() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "empty".into(),
        vectors: Vec::new(),
    };
    assert!(set.vectors.is_empty());
}

// ---------------------------------------------------------------------------
// Serde roundtrips — GoldenVector
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_serde_roundtrip() {
    let v = sample_vector("serde_rt", false);
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn golden_vector_serde_roundtrip_negative() {
    let v = sample_vector("serde_neg", true);
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn golden_vector_serde_roundtrip_empty_fields() {
    let v = GoldenVector {
        test_name: String::new(), description: String::new(),
        category: String::new(), schema_version: String::new(),
        input: BTreeMap::new(), expected: BTreeMap::new(),
        expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn golden_vector_serde_complex_nested() {
    let mut input = BTreeMap::new();
    input.insert("nested".into(), serde_json::json!({"a": [1,2,3], "b": null}));
    let v = GoldenVector {
        test_name: "complex".into(), description: "nested".into(),
        category: "schema_hash".into(), schema_version: "2.0".into(),
        input, expected: BTreeMap::new(), expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn golden_vector_serde_pretty_roundtrip() {
    let v = sample_vector("pretty", false);
    let json = serde_json::to_string_pretty(&v).unwrap();
    let back: GoldenVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// Serde roundtrips — GoldenVectorSet
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_serde_roundtrip() {
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
fn golden_vector_set_serde_empty() {
    let set = GoldenVectorSet {
        vector_format_version: "0.0.1".into(),
        category: "empty".into(),
        vectors: Vec::new(),
    };
    let json = serde_json::to_string(&set).unwrap();
    let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, back);
}

// ---------------------------------------------------------------------------
// Clone and PartialEq
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_clone_eq() {
    let v = sample_vector("clone_test", false);
    assert_eq!(v, v.clone());
}

#[test]
fn golden_vector_ne_different_name() {
    assert_ne!(sample_vector("a", false), sample_vector("b", false));
}

#[test]
fn golden_vector_ne_different_expect_error() {
    assert_ne!(sample_vector("same", false), sample_vector("same", true));
}

#[test]
fn golden_vector_set_clone_eq() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "test".into(),
        vectors: vec![sample_vector("v", false)],
    };
    assert_eq!(set, set.clone());
}

// ---------------------------------------------------------------------------
// Debug impls
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_debug_contains_name() {
    let v = sample_vector("dbg_test", false);
    let d = format!("{v:?}");
    assert!(d.contains("dbg_test"));
    assert!(d.contains("GoldenVector"));
}

#[test]
fn golden_vector_set_debug_contains_category() {
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "debug_cat".into(),
        vectors: Vec::new(),
    };
    let d = format!("{set:?}");
    assert!(d.contains("debug_cat"));
    assert!(d.contains("GoldenVectorSet"));
}

// ---------------------------------------------------------------------------
// JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_json_field_names() {
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

#[test]
fn golden_vector_set_json_field_names() {
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

// ---------------------------------------------------------------------------
// BTreeMap key ordering
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_input_map_sorted_order() {
    let mut input = BTreeMap::new();
    input.insert("zeta".into(), serde_json::Value::Null);
    input.insert("alpha".into(), serde_json::Value::Null);
    input.insert("mu".into(), serde_json::Value::Null);
    let keys: Vec<&String> = input.keys().collect();
    assert_eq!(keys, vec!["alpha", "mu", "zeta"]);
}

// ---------------------------------------------------------------------------
// Large vector set
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_set_many_vectors_roundtrip() {
    let vectors: Vec<GoldenVector> = (0..100)
        .map(|i| sample_vector(&format!("v_{i:04}"), i % 3 == 0))
        .collect();
    let set = GoldenVectorSet {
        vector_format_version: "1.0.0".into(),
        category: "bulk".into(),
        vectors,
    };
    assert_eq!(set.vectors.len(), 100);
    let json = serde_json::to_string(&set).unwrap();
    let back: GoldenVectorSet = serde_json::from_str(&json).unwrap();
    assert_eq!(set, back);
}

// ---------------------------------------------------------------------------
// Hex cross-type integration
// ---------------------------------------------------------------------------

#[test]
fn hex_in_golden_vector_input_roundtrip() {
    let original = vec![0x01, 0x02, 0x03, 0x04];
    let hex_val = to_hex(&original);
    let mut input = BTreeMap::new();
    input.insert("hex_data".into(), serde_json::Value::String(hex_val));
    let v = GoldenVector {
        test_name: "hex_rt".into(), description: "hex in input".into(),
        category: "deterministic_serde".into(), schema_version: "1.0".into(),
        input, expected: BTreeMap::new(), expect_error: false,
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: GoldenVector = serde_json::from_str(&json).unwrap();
    let restored_hex = restored.input["hex_data"].as_str().unwrap();
    assert_eq!(from_hex(restored_hex).unwrap(), original);
}

// ---------------------------------------------------------------------------
// Hex nibble boundary
// ---------------------------------------------------------------------------

#[test]
fn hex_every_nibble_value() {
    for nibble in 0..=15u8 {
        let byte = nibble << 4 | nibble;
        let hex = to_hex(&[byte]);
        let ch = char::from_digit(nibble as u32, 16).unwrap();
        assert_eq!(hex, format!("{ch}{ch}"));
    }
}

#[test]
fn hex_decode_every_valid_pair() {
    for hi in 0..=15u8 {
        for lo in 0..=15u8 {
            let hi_c = char::from_digit(hi as u32, 16).unwrap();
            let lo_c = char::from_digit(lo as u32, 16).unwrap();
            let result = from_hex(&format!("{hi_c}{lo_c}")).unwrap();
            assert_eq!(result, vec![(hi << 4) | lo]);
        }
    }
}
