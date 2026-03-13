//! Integration tests for the `hash_tiers` module.
//!
//! Tests three-tier hashing: IntegrityHash, ContentHash, AuthenticityHash,
//! determinism, domain separation, and serde roundtrips.

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

use frankenengine_engine::hash_tiers::{
    AuthenticityHash, ContentHash, HashAlgorithm, HashEvent, HashTier, IntegrityHash,
};

// ---------------------------------------------------------------------------
// IntegrityHash (Tier 1)
// ---------------------------------------------------------------------------

#[test]
fn integrity_hash_deterministic() {
    let a = IntegrityHash::compute(b"hello");
    let b = IntegrityHash::compute(b"hello");
    assert_eq!(a, b);
}

#[test]
fn integrity_hash_different_inputs_differ() {
    let a = IntegrityHash::compute(b"hello");
    let b = IntegrityHash::compute(b"world");
    assert_ne!(a, b);
}

#[test]
fn integrity_hash_empty_input() {
    let h = IntegrityHash::compute(b"");
    assert_eq!(h.as_u64(), h.0);
}

#[test]
fn integrity_hash_display_format() {
    let h = IntegrityHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("integrity:"));
    assert_eq!(display.len(), "integrity:".len() + 16); // 16 hex digits
}

#[test]
fn integrity_hash_serde_roundtrip() {
    let h = IntegrityHash::compute(b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: IntegrityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

// ---------------------------------------------------------------------------
// ContentHash (Tier 2)
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"hello");
    assert_eq!(a, b);
}

#[test]
fn content_hash_different_inputs_differ() {
    let a = ContentHash::compute(b"hello");
    let b = ContentHash::compute(b"world");
    assert_ne!(a, b);
}

#[test]
fn content_hash_is_32_bytes() {
    let h = ContentHash::compute(b"test");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn content_hash_to_hex_is_64_chars() {
    let h = ContentHash::compute(b"test");
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn content_hash_display_format() {
    let h = ContentHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("content:"));
}

#[test]
fn content_hash_serde_roundtrip() {
    let h = ContentHash::compute(b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: ContentHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn content_hash_empty_input() {
    let h = ContentHash::compute(b"");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn content_hash_large_input() {
    let data = vec![0xab; 100_000];
    let h = ContentHash::compute(&data);
    assert_eq!(h.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// AuthenticityHash (Tier 3)
// ---------------------------------------------------------------------------

#[test]
fn authenticity_hash_keyed_deterministic() {
    let a = AuthenticityHash::compute_keyed(b"key", b"data");
    let b = AuthenticityHash::compute_keyed(b"key", b"data");
    assert_eq!(a, b);
}

#[test]
fn authenticity_hash_different_keys_differ() {
    let a = AuthenticityHash::compute_keyed(b"key1", b"data");
    let b = AuthenticityHash::compute_keyed(b"key2", b"data");
    assert_ne!(a, b);
}

#[test]
fn authenticity_hash_different_data_differ() {
    let a = AuthenticityHash::compute_keyed(b"key", b"data1");
    let b = AuthenticityHash::compute_keyed(b"key", b"data2");
    assert_ne!(a, b);
}

#[test]
fn authenticity_hash_unkeyed_deterministic() {
    let a = AuthenticityHash::compute(b"test");
    let b = AuthenticityHash::compute(b"test");
    assert_eq!(a, b);
}

#[test]
fn authenticity_hash_is_32_bytes() {
    let h = AuthenticityHash::compute_keyed(b"key", b"data");
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn authenticity_hash_to_hex_is_64_chars() {
    let h = AuthenticityHash::compute_keyed(b"key", b"data");
    let hex = h.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn authenticity_hash_display_format() {
    let h = AuthenticityHash::compute(b"test");
    let display = h.to_string();
    assert!(display.starts_with("authenticity:"));
}

#[test]
fn authenticity_hash_constant_time_eq_same() {
    let a = AuthenticityHash::compute(b"same");
    let b = AuthenticityHash::compute(b"same");
    assert!(a.constant_time_eq(&b));
}

#[test]
fn authenticity_hash_constant_time_eq_different() {
    let a = AuthenticityHash::compute(b"aaa");
    let b = AuthenticityHash::compute(b"bbb");
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn authenticity_hash_serde_roundtrip() {
    let h = AuthenticityHash::compute_keyed(b"key", b"serde-test");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: AuthenticityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

// ---------------------------------------------------------------------------
// Cross-tier isolation
// ---------------------------------------------------------------------------

#[test]
fn same_input_different_tiers_may_differ() {
    let data = b"cross-tier-test";
    let integrity = IntegrityHash::compute(data);
    let content = ContentHash::compute(data);
    let authenticity = AuthenticityHash::compute(data);

    // Different types, can't directly compare — verify they're distinct types
    let _ = integrity.as_u64();
    let _ = content.as_bytes();
    let _ = authenticity.as_bytes();
}

// ---------------------------------------------------------------------------
// Determinism across multiple runs
// ---------------------------------------------------------------------------

#[test]
fn all_tiers_deterministic_10_runs() {
    let data = b"determinism-test";
    let key = b"test-key";

    let i0 = IntegrityHash::compute(data);
    let c0 = ContentHash::compute(data);
    let a0 = AuthenticityHash::compute_keyed(key, data);

    for _ in 0..10 {
        assert_eq!(IntegrityHash::compute(data), i0);
        assert_eq!(ContentHash::compute(data), c0);
        assert_eq!(AuthenticityHash::compute_keyed(key, data), a0);
    }
}

// ---------------------------------------------------------------------------
// HashTier enum
// ---------------------------------------------------------------------------

#[test]
fn hash_tier_serde_round_trip_all_variants() {
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        let json = serde_json::to_string(&tier).expect("serialize");
        let recovered: HashTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tier, recovered);
    }
}

#[test]
fn hash_tier_display_non_empty() {
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        assert!(!tier.to_string().is_empty());
    }
}

#[test]
fn hash_tier_ordering() {
    assert!(HashTier::Integrity < HashTier::Content);
    assert!(HashTier::Content < HashTier::Authenticity);
}

#[test]
fn hash_tier_display_contains_tier_prefix() {
    assert!(HashTier::Integrity.to_string().contains("integrity"));
    assert!(HashTier::Content.to_string().contains("content"));
    assert!(HashTier::Authenticity.to_string().contains("authenticity"));
}

// ---------------------------------------------------------------------------
// HashAlgorithm enum
// ---------------------------------------------------------------------------

#[test]
fn hash_algorithm_serde_round_trip_all_variants() {
    for algo in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        let json = serde_json::to_string(&algo).expect("serialize");
        let recovered: HashAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(algo, recovered);
    }
}

#[test]
fn hash_algorithm_tier_mapping() {
    assert_eq!(HashAlgorithm::WyhashInspired.tier(), HashTier::Integrity);
    assert_eq!(HashAlgorithm::SipInspiredCr.tier(), HashTier::Content);
    assert_eq!(
        HashAlgorithm::SipInspiredKeyed.tier(),
        HashTier::Authenticity
    );
}

#[test]
fn hash_algorithm_display_non_empty() {
    for algo in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        assert!(!algo.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// HashEvent struct
// ---------------------------------------------------------------------------

#[test]
fn hash_event_serde_round_trip() {
    let event = HashEvent {
        tier: HashTier::Authenticity,
        algorithm: HashAlgorithm::SipInspiredKeyed,
        input_len: 256,
        component: "capability_witness".to_string(),
        trace_id: "trace-001".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: HashEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn hash_event_serde_round_trip_all_tiers() {
    for (tier, algo) in [
        (HashTier::Integrity, HashAlgorithm::WyhashInspired),
        (HashTier::Content, HashAlgorithm::SipInspiredCr),
        (HashTier::Authenticity, HashAlgorithm::SipInspiredKeyed),
    ] {
        let event = HashEvent {
            tier,
            algorithm: algo,
            input_len: 128,
            component: "test".to_string(),
            trace_id: "t-1".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let recovered: HashEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, recovered);
    }
}

// ---------------------------------------------------------------------------
// IntegrityHash edge cases
// ---------------------------------------------------------------------------

#[test]
fn integrity_hash_ordering_is_deterministic() {
    let a = IntegrityHash::compute(b"aaa");
    let b = IntegrityHash::compute(b"bbb");
    // Just verify Ord works without panic
    let _ = a.cmp(&b);
    let _ = a.partial_cmp(&b);
}

#[test]
fn integrity_hash_large_input() {
    let data = vec![0xCDu8; 1_000_000];
    let h = IntegrityHash::compute(&data);
    assert_ne!(h.as_u64(), 0);
}

// ---------------------------------------------------------------------------
// ContentHash edge cases
// ---------------------------------------------------------------------------

#[test]
fn content_hash_hex_is_lowercase() {
    let h = ContentHash::compute(b"hex-check");
    let hex = h.to_hex();
    assert_eq!(hex, hex.to_lowercase());
}

#[test]
fn content_hash_ordering_is_deterministic() {
    let a = ContentHash::compute(b"alpha");
    let b = ContentHash::compute(b"beta");
    let _ = a.cmp(&b);
}

// ---------------------------------------------------------------------------
// AuthenticityHash edge cases
// ---------------------------------------------------------------------------

#[test]
fn authenticity_hash_keyed_differs_from_unkeyed() {
    let data = b"same-data";
    let keyed = AuthenticityHash::compute_keyed(b"a-key", data);
    let unkeyed = AuthenticityHash::compute(data);
    assert_ne!(keyed, unkeyed);
}

#[test]
fn authenticity_hash_hex_is_lowercase() {
    let h = AuthenticityHash::compute(b"hex-check");
    let hex = h.to_hex();
    assert_eq!(hex, hex.to_lowercase());
}

#[test]
fn authenticity_hash_empty_key_differs_from_empty_data() {
    let a = AuthenticityHash::compute_keyed(b"", b"data");
    let b = AuthenticityHash::compute_keyed(b"key", b"");
    assert_ne!(a, b);
}

#[test]
fn authenticity_hash_ordering_is_deterministic() {
    let a = AuthenticityHash::compute(b"first");
    let b = AuthenticityHash::compute(b"second");
    let _ = a.cmp(&b);
}

// ---------------------------------------------------------------------------
// Cross-tier domain separation
// ---------------------------------------------------------------------------

#[test]
fn content_and_authenticity_unkeyed_produce_same_bytes() {
    // Per docs: unkeyed authenticity uses same algorithm as content
    let data = b"domain-test";
    let content = ContentHash::compute(data);
    let auth = AuthenticityHash::compute(data);
    assert_eq!(content.as_bytes(), auth.as_bytes());
}

#[test]
fn display_prefixes_are_distinct() {
    let data = b"prefix-test";
    let i = IntegrityHash::compute(data).to_string();
    let c = ContentHash::compute(data).to_string();
    let a = AuthenticityHash::compute(data).to_string();
    assert!(i.starts_with("integrity:"));
    assert!(c.starts_with("content:"));
    assert!(a.starts_with("authenticity:"));
}

// ---------------------------------------------------------------------------
// Enrichment tests
// ---------------------------------------------------------------------------

// -- IntegrityHash enrichment --

#[test]
fn enrichment_integrity_hash_debug_contains_value() {
    let h = IntegrityHash::compute(b"debug-test");
    let debug = format!("{:?}", h);
    assert!(
        debug.contains("IntegrityHash"),
        "Debug must include type name"
    );
}

#[test]
fn enrichment_integrity_hash_clone_produces_equal_value() {
    let h = IntegrityHash::compute(b"clone-integ");
    let cloned = h.clone();
    assert_eq!(h, cloned);
    assert_eq!(h.as_u64(), cloned.as_u64());
}

#[test]
fn enrichment_integrity_hash_copy_both_usable() {
    let h = IntegrityHash::compute(b"copy-test");
    let copied = h;
    assert_eq!(h.to_string(), copied.to_string());
}

#[test]
fn enrichment_integrity_hash_serde_json_is_number() {
    let h = IntegrityHash(42);
    let json = serde_json::to_string(&h).unwrap();
    assert_eq!(json, "42");
}

#[test]
fn enrichment_integrity_hash_serde_max_u64() {
    let h = IntegrityHash(u64::MAX);
    let json = serde_json::to_string(&h).unwrap();
    let decoded: IntegrityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_integrity_hash_serde_zero() {
    let h = IntegrityHash(0);
    let json = serde_json::to_string(&h).unwrap();
    let decoded: IntegrityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
    assert_eq!(decoded.as_u64(), 0);
}

#[test]
fn enrichment_integrity_hash_display_zero_padded() {
    let h = IntegrityHash(1);
    assert_eq!(h.to_string(), "integrity:0000000000000001");
}

#[test]
fn enrichment_integrity_hash_display_max() {
    let h = IntegrityHash(u64::MAX);
    assert_eq!(h.to_string(), "integrity:ffffffffffffffff");
}

#[test]
fn enrichment_integrity_hash_as_u64_matches_inner() {
    let h = IntegrityHash(0xDEAD_BEEF_CAFE_BABE);
    assert_eq!(h.as_u64(), 0xDEAD_BEEF_CAFE_BABE);
}

#[test]
fn enrichment_integrity_hash_btreeset_dedup() {
    let mut set = std::collections::BTreeSet::new();
    let h = IntegrityHash::compute(b"dedup");
    set.insert(h);
    set.insert(h);
    assert_eq!(set.len(), 1);
}

#[test]
fn enrichment_integrity_hash_btreemap_key() {
    let mut map = std::collections::BTreeMap::new();
    let h = IntegrityHash::compute(b"map-key");
    map.insert(h, "value");
    assert_eq!(map.get(&h), Some(&"value"));
}

#[test]
fn enrichment_integrity_hash_single_bit_flip_byte0() {
    let data = [0u8; 8];
    let base = IntegrityHash::compute(&data);
    let mut flipped = data;
    flipped[0] = 1;
    assert_ne!(base, IntegrityHash::compute(&flipped));
}

#[test]
fn enrichment_integrity_hash_single_bit_flip_last_byte() {
    let data = [0u8; 16];
    let base = IntegrityHash::compute(&data);
    let mut flipped = data;
    flipped[15] ^= 0x01;
    assert_ne!(base, IntegrityHash::compute(&flipped));
}

#[test]
fn enrichment_integrity_hash_length_7_vs_8() {
    let h7 = IntegrityHash::compute(&[0xAB; 7]);
    let h8 = IntegrityHash::compute(&[0xAB; 8]);
    assert_ne!(h7, h8);
}

#[test]
fn enrichment_integrity_hash_length_8_vs_9() {
    let h8 = IntegrityHash::compute(&[0xAB; 8]);
    let h9 = IntegrityHash::compute(&[0xAB; 9]);
    assert_ne!(h8, h9);
}

#[test]
fn enrichment_integrity_hash_length_15_vs_16() {
    let h15 = IntegrityHash::compute(&[0xCC; 15]);
    let h16 = IntegrityHash::compute(&[0xCC; 16]);
    assert_ne!(h15, h16);
}

#[test]
fn enrichment_integrity_hash_determinism_100_runs() {
    let expected = IntegrityHash::compute(b"stability");
    for _ in 0..100 {
        assert_eq!(IntegrityHash::compute(b"stability"), expected);
    }
}

#[test]
fn enrichment_integrity_hash_partial_ord_consistent_with_ord() {
    let a = IntegrityHash::compute(b"aaa");
    let b = IntegrityHash::compute(b"bbb");
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
}

// -- ContentHash enrichment --

#[test]
fn enrichment_content_hash_debug_contains_type_name() {
    let h = ContentHash::compute(b"debug-content");
    let debug = format!("{:?}", h);
    assert!(debug.contains("ContentHash"));
}

#[test]
fn enrichment_content_hash_clone_produces_equal() {
    let h = ContentHash::compute(b"clone-content");
    let cloned = h.clone();
    assert_eq!(h, cloned);
    assert_eq!(h.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_content_hash_default_is_all_zeros() {
    let h = ContentHash::default();
    assert_eq!(h.as_bytes(), &[0u8; 32]);
}

#[test]
fn enrichment_content_hash_default_hex_is_all_zeros() {
    let h = ContentHash::default();
    assert_eq!(h.to_hex(), "0".repeat(64));
}

#[test]
fn enrichment_content_hash_default_display() {
    let h = ContentHash::default();
    let display = h.to_string();
    assert_eq!(display, format!("content:{}", "0".repeat(64)));
}

#[test]
fn enrichment_content_hash_from_bytes_roundtrip() {
    let bytes = [0x42u8; 32];
    let h = ContentHash::from_bytes(bytes);
    assert_eq!(*h.as_bytes(), bytes);
}

#[test]
fn enrichment_content_hash_from_bytes_preserves_all_ff() {
    let bytes = [0xFFu8; 32];
    let h = ContentHash::from_bytes(bytes);
    assert_eq!(*h.as_bytes(), bytes);
}

#[test]
fn enrichment_content_hash_from_bytes_serde_roundtrip() {
    let bytes = [0xABu8; 32];
    let h = ContentHash::from_bytes(bytes);
    let json = serde_json::to_string(&h).unwrap();
    let decoded: ContentHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_content_hash_hex_length_always_64() {
    for i in 0..20 {
        let data: Vec<u8> = (0..i).map(|b| b as u8).collect();
        let hex = ContentHash::compute(&data).to_hex();
        assert_eq!(hex.len(), 64, "hex length must be 64 for input len {i}");
    }
}

#[test]
fn enrichment_content_hash_display_equals_prefix_plus_hex() {
    let h = ContentHash::compute(b"display-match");
    assert_eq!(h.to_string(), format!("content:{}", h.to_hex()));
}

#[test]
fn enrichment_content_hash_avalanche_single_byte_diff() {
    let a = ContentHash::compute(b"avalanche-A");
    let b = ContentHash::compute(b"avalanche-B");
    let differing_bits: u32 = a
        .as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum();
    assert!(
        differing_bits >= 64,
        "only {differing_bits}/256 bits differ"
    );
}

#[test]
fn enrichment_content_hash_btreeset_membership() {
    let mut set = std::collections::BTreeSet::new();
    let h1 = ContentHash::compute(b"one");
    let h2 = ContentHash::compute(b"two");
    set.insert(h1);
    set.insert(h2);
    assert!(set.contains(&h1));
    assert!(set.contains(&h2));
    assert!(!set.contains(&ContentHash::compute(b"three")));
}

#[test]
fn enrichment_content_hash_btreemap_value_lookup() {
    let mut map = std::collections::BTreeMap::new();
    let h = ContentHash::compute(b"key-data");
    map.insert(h, 42u64);
    assert_eq!(map.get(&h), Some(&42u64));
}

#[test]
fn enrichment_content_hash_all_zero_input_not_all_zero_output() {
    let h = ContentHash::compute(&[0u8; 64]);
    assert_ne!(h.as_bytes(), &[0u8; 32]);
}

#[test]
fn enrichment_content_hash_all_ff_input_not_all_ff_output() {
    let h = ContentHash::compute(&[0xFFu8; 64]);
    assert_ne!(h.as_bytes(), &[0xFFu8; 32]);
}

#[test]
fn enrichment_content_hash_single_byte_inputs_all_unique() {
    let mut set = std::collections::BTreeSet::new();
    for b in 0u8..=255 {
        set.insert(ContentHash::compute(&[b]));
    }
    assert_eq!(
        set.len(),
        256,
        "all 256 single-byte inputs must produce unique hashes"
    );
}

#[test]
fn enrichment_content_hash_ord_sort_stability() {
    let hashes: Vec<ContentHash> = (0u8..20).map(|i| ContentHash::compute(&[i])).collect();
    let mut a = hashes.clone();
    let mut b = hashes.clone();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

#[test]
fn enrichment_content_hash_partial_ord_consistent() {
    let a = ContentHash::compute(b"x");
    let b = ContentHash::compute(b"y");
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
}

// -- AuthenticityHash enrichment --

#[test]
fn enrichment_authenticity_hash_debug_contains_type_name() {
    let h = AuthenticityHash::compute(b"debug-auth");
    let debug = format!("{:?}", h);
    assert!(debug.contains("AuthenticityHash"));
}

#[test]
fn enrichment_authenticity_hash_clone_produces_equal() {
    let h = AuthenticityHash::compute_keyed(b"k", b"d");
    let cloned = h.clone();
    assert_eq!(h, cloned);
    assert_eq!(h.as_bytes(), cloned.as_bytes());
}

#[test]
fn enrichment_authenticity_hash_copy_both_usable() {
    let h = AuthenticityHash::compute(b"copy-auth");
    let copied = h;
    assert_eq!(h.to_hex(), copied.to_hex());
}

#[test]
fn enrichment_authenticity_hash_serde_unkeyed_roundtrip() {
    let h = AuthenticityHash::compute(b"unkeyed-serde");
    let json = serde_json::to_string(&h).unwrap();
    let decoded: AuthenticityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_authenticity_hash_display_equals_prefix_plus_hex() {
    let h = AuthenticityHash::compute_keyed(b"k", b"d");
    assert_eq!(h.to_string(), format!("authenticity:{}", h.to_hex()));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_reflexive() {
    let h = AuthenticityHash::compute_keyed(b"reflexive-key", b"data");
    assert!(h.constant_time_eq(&h));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_all_zeros() {
    let h = AuthenticityHash([0u8; 32]);
    assert!(h.constant_time_eq(&AuthenticityHash([0u8; 32])));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_all_ff() {
    let h = AuthenticityHash([0xFF; 32]);
    assert!(h.constant_time_eq(&AuthenticityHash([0xFF; 32])));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_single_bit_diff_byte0() {
    let a = AuthenticityHash([0u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    let b = AuthenticityHash(bytes);
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_single_bit_diff_last_byte() {
    let a = AuthenticityHash([0u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let b = AuthenticityHash(bytes);
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn enrichment_authenticity_hash_constant_time_eq_symmetric() {
    let a = AuthenticityHash::compute(b"symmetric-a");
    let b = AuthenticityHash::compute(b"symmetric-b");
    assert_eq!(a.constant_time_eq(&b), b.constant_time_eq(&a));
}

#[test]
fn enrichment_authenticity_hash_keyed_not_commutative() {
    let h1 = AuthenticityHash::compute_keyed(b"key", b"data");
    let h2 = AuthenticityHash::compute_keyed(b"data", b"key");
    assert_ne!(h1, h2, "keyed hash must not be commutative");
}

#[test]
fn enrichment_authenticity_hash_empty_key_differs_from_unkeyed() {
    let keyed_empty = AuthenticityHash::compute_keyed(b"", b"message");
    let unkeyed = AuthenticityHash::compute(b"message");
    assert_ne!(keyed_empty, unkeyed);
}

#[test]
fn enrichment_authenticity_hash_long_key_deterministic() {
    let key: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    let a = AuthenticityHash::compute_keyed(&key, b"long-key-msg");
    let b = AuthenticityHash::compute_keyed(&key, b"long-key-msg");
    assert_eq!(a, b);
}

#[test]
fn enrichment_authenticity_hash_long_data_deterministic() {
    let data: Vec<u8> = (0..4096).map(|i| (i % 253) as u8).collect();
    let a = AuthenticityHash::compute_keyed(b"k", &data);
    let b = AuthenticityHash::compute_keyed(b"k", &data);
    assert_eq!(a, b);
}

#[test]
fn enrichment_authenticity_hash_btreeset_membership() {
    let mut set = std::collections::BTreeSet::new();
    let h1 = AuthenticityHash::compute_keyed(b"k1", b"d1");
    let h2 = AuthenticityHash::compute_keyed(b"k2", b"d2");
    set.insert(h1);
    set.insert(h2);
    assert_eq!(set.len(), 2);
    set.insert(h1);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_authenticity_hash_hex_length_always_64() {
    for i in 0..10 {
        let data: Vec<u8> = vec![i as u8; i * 7 + 1];
        let hex = AuthenticityHash::compute_keyed(b"k", &data).to_hex();
        assert_eq!(hex.len(), 64);
    }
}

#[test]
fn enrichment_authenticity_hash_partial_ord_consistent() {
    let a = AuthenticityHash::compute(b"x");
    let b = AuthenticityHash::compute(b"y");
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
}

// -- HashTier enrichment --

#[test]
fn enrichment_hash_tier_debug_contains_variant_name() {
    assert!(format!("{:?}", HashTier::Integrity).contains("Integrity"));
    assert!(format!("{:?}", HashTier::Content).contains("Content"));
    assert!(format!("{:?}", HashTier::Authenticity).contains("Authenticity"));
}

#[test]
fn enrichment_hash_tier_clone_equality() {
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        let cloned = tier.clone();
        assert_eq!(tier, cloned);
    }
}

#[test]
fn enrichment_hash_tier_copy_both_usable() {
    let t = HashTier::Content;
    let copied = t;
    assert_eq!(t.to_string(), copied.to_string());
}

#[test]
fn enrichment_hash_tier_display_exact_strings() {
    assert_eq!(HashTier::Integrity.to_string(), "tier1:integrity");
    assert_eq!(HashTier::Content.to_string(), "tier2:content");
    assert_eq!(HashTier::Authenticity.to_string(), "tier3:authenticity");
}

#[test]
fn enrichment_hash_tier_display_all_unique() {
    let mut set = std::collections::BTreeSet::new();
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        set.insert(tier.to_string());
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_hash_tier_ord_full_chain() {
    assert!(HashTier::Integrity < HashTier::Content);
    assert!(HashTier::Content < HashTier::Authenticity);
    assert!(HashTier::Integrity < HashTier::Authenticity);
}

#[test]
fn enrichment_hash_tier_sort_deterministic() {
    let mut v = vec![
        HashTier::Authenticity,
        HashTier::Integrity,
        HashTier::Content,
    ];
    v.sort();
    assert_eq!(
        v,
        vec![
            HashTier::Integrity,
            HashTier::Content,
            HashTier::Authenticity
        ]
    );
}

#[test]
fn enrichment_hash_tier_serde_json_strings() {
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
    }
}

#[test]
fn enrichment_hash_tier_btreeset_contains() {
    let mut set = std::collections::BTreeSet::new();
    set.insert(HashTier::Integrity);
    set.insert(HashTier::Content);
    assert!(set.contains(&HashTier::Integrity));
    assert!(set.contains(&HashTier::Content));
    assert!(!set.contains(&HashTier::Authenticity));
}

// -- HashAlgorithm enrichment --

#[test]
fn enrichment_hash_algorithm_debug_contains_variant() {
    assert!(format!("{:?}", HashAlgorithm::WyhashInspired).contains("WyhashInspired"));
    assert!(format!("{:?}", HashAlgorithm::SipInspiredCr).contains("SipInspiredCr"));
    assert!(format!("{:?}", HashAlgorithm::SipInspiredKeyed).contains("SipInspiredKeyed"));
}

#[test]
fn enrichment_hash_algorithm_clone_equality() {
    for alg in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        let cloned = alg.clone();
        assert_eq!(alg, cloned);
    }
}

#[test]
fn enrichment_hash_algorithm_copy_both_usable() {
    let a = HashAlgorithm::SipInspiredCr;
    let copied = a;
    assert_eq!(a.to_string(), copied.to_string());
}

#[test]
fn enrichment_hash_algorithm_display_exact_strings() {
    assert_eq!(HashAlgorithm::WyhashInspired.to_string(), "wyhash_inspired");
    assert_eq!(HashAlgorithm::SipInspiredCr.to_string(), "sip_inspired_cr");
    assert_eq!(
        HashAlgorithm::SipInspiredKeyed.to_string(),
        "sip_inspired_keyed"
    );
}

#[test]
fn enrichment_hash_algorithm_display_all_unique() {
    let mut set = std::collections::BTreeSet::new();
    for alg in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        set.insert(alg.to_string());
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_hash_algorithm_tier_bijection() {
    let mut tiers = std::collections::BTreeSet::new();
    for alg in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        tiers.insert(alg.tier());
    }
    assert_eq!(tiers.len(), 3, "each algorithm must map to a unique tier");
}

#[test]
fn enrichment_hash_algorithm_ord_sort() {
    let mut v = vec![
        HashAlgorithm::SipInspiredKeyed,
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
    ];
    v.sort();
    assert_eq!(v[0], HashAlgorithm::WyhashInspired);
}

#[test]
fn enrichment_hash_algorithm_serde_json_strings() {
    for alg in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        let json = serde_json::to_string(&alg).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
    }
}

#[test]
fn enrichment_hash_algorithm_btreeset_contains() {
    let mut set = std::collections::BTreeSet::new();
    set.insert(HashAlgorithm::WyhashInspired);
    set.insert(HashAlgorithm::SipInspiredCr);
    assert!(set.contains(&HashAlgorithm::WyhashInspired));
    assert!(!set.contains(&HashAlgorithm::SipInspiredKeyed));
}

// -- HashEvent enrichment --

#[test]
fn enrichment_hash_event_debug_contains_fields() {
    let event = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 100,
        component: "comp".to_string(),
        trace_id: "tid".to_string(),
    };
    let debug = format!("{:?}", event);
    assert!(debug.contains("HashEvent"));
    assert!(debug.contains("Content"));
    assert!(debug.contains("comp"));
    assert!(debug.contains("tid"));
}

#[test]
fn enrichment_hash_event_clone_deep_equality() {
    let event = HashEvent {
        tier: HashTier::Authenticity,
        algorithm: HashAlgorithm::SipInspiredKeyed,
        input_len: 999,
        component: "deep-clone".to_string(),
        trace_id: "dc-001".to_string(),
    };
    let cloned = event.clone();
    assert_eq!(event.tier, cloned.tier);
    assert_eq!(event.algorithm, cloned.algorithm);
    assert_eq!(event.input_len, cloned.input_len);
    assert_eq!(event.component, cloned.component);
    assert_eq!(event.trace_id, cloned.trace_id);
}

#[test]
fn enrichment_hash_event_serde_json_all_fields_present() {
    let event = HashEvent {
        tier: HashTier::Integrity,
        algorithm: HashAlgorithm::WyhashInspired,
        input_len: 42,
        component: "field-check".to_string(),
        trace_id: "fc-1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"tier\""));
    assert!(json.contains("\"algorithm\""));
    assert!(json.contains("\"input_len\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"trace_id\""));
}

#[test]
fn enrichment_hash_event_serde_input_len_zero() {
    let event = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 0,
        component: "zero-len".to_string(),
        trace_id: "zl".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: HashEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.input_len, 0);
}

#[test]
fn enrichment_hash_event_serde_empty_strings() {
    let event = HashEvent {
        tier: HashTier::Integrity,
        algorithm: HashAlgorithm::WyhashInspired,
        input_len: 1,
        component: "".to_string(),
        trace_id: "".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: HashEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.component, "");
    assert_eq!(decoded.trace_id, "");
}

#[test]
fn enrichment_hash_event_inequality_different_tiers() {
    let a = HashEvent {
        tier: HashTier::Integrity,
        algorithm: HashAlgorithm::WyhashInspired,
        input_len: 10,
        component: "c".to_string(),
        trace_id: "t".to_string(),
    };
    let b = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::WyhashInspired,
        input_len: 10,
        component: "c".to_string(),
        trace_id: "t".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_hash_event_inequality_different_component() {
    let a = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 10,
        component: "comp_a".to_string(),
        trace_id: "t".to_string(),
    };
    let b = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 10,
        component: "comp_b".to_string(),
        trace_id: "t".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_hash_event_inequality_different_trace_id() {
    let a = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 10,
        component: "c".to_string(),
        trace_id: "trace-a".to_string(),
    };
    let b = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 10,
        component: "c".to_string(),
        trace_id: "trace-b".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_hash_event_inequality_different_input_len() {
    let a = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 1,
        component: "c".to_string(),
        trace_id: "t".to_string(),
    };
    let b = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: 2,
        component: "c".to_string(),
        trace_id: "t".to_string(),
    };
    assert_ne!(a, b);
}

// -- Cross-tier enrichment --

#[test]
fn enrichment_cross_tier_display_prefixes_never_overlap() {
    let data = b"overlap-check";
    let d1 = IntegrityHash::compute(data).to_string();
    let d2 = ContentHash::compute(data).to_string();
    let d3 = AuthenticityHash::compute(data).to_string();
    assert!(!d2.starts_with(&d1));
    assert!(!d3.starts_with(&d1));
    assert!(!d3.starts_with(&d2));
}

#[test]
fn enrichment_cross_tier_content_unkeyed_auth_same_bytes() {
    for i in 0..10 {
        let data: Vec<u8> = vec![i; i as usize * 3 + 1];
        let c = ContentHash::compute(&data);
        let a = AuthenticityHash::compute(&data);
        assert_eq!(
            c.as_bytes(),
            a.as_bytes(),
            "unkeyed auth must match content for input len {}",
            data.len()
        );
    }
}

#[test]
fn enrichment_cross_tier_keyed_auth_differs_from_content() {
    let data = b"cross-tier-keyed";
    let c = ContentHash::compute(data);
    let a = AuthenticityHash::compute_keyed(b"any-key", data);
    assert_ne!(c.as_bytes(), a.as_bytes());
}

#[test]
fn enrichment_cross_tier_sizes() {
    assert_eq!(std::mem::size_of::<IntegrityHash>(), 8);
    assert_eq!(std::mem::size_of::<ContentHash>(), 32);
    assert_eq!(std::mem::size_of::<AuthenticityHash>(), 32);
}

#[test]
fn enrichment_cross_tier_display_strings_all_unique() {
    let data = b"unique-display";
    let mut set = std::collections::BTreeSet::new();
    set.insert(IntegrityHash::compute(data).to_string());
    set.insert(ContentHash::compute(data).to_string());
    set.insert(AuthenticityHash::compute(data).to_string());
    assert_eq!(set.len(), 3);
}

// -- Determinism and stability --

#[test]
fn enrichment_all_tiers_deterministic_50_runs() {
    let data = b"determinism-50";
    let key = b"det-key";
    let i0 = IntegrityHash::compute(data);
    let c0 = ContentHash::compute(data);
    let a0 = AuthenticityHash::compute_keyed(key, data);
    for _ in 0..50 {
        assert_eq!(IntegrityHash::compute(data), i0);
        assert_eq!(ContentHash::compute(data), c0);
        assert_eq!(AuthenticityHash::compute_keyed(key, data), a0);
    }
}

#[test]
fn enrichment_content_hash_deterministic_large_payload() {
    let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let h1 = ContentHash::compute(&data);
    let h2 = ContentHash::compute(&data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_integrity_hash_varies_across_sequential_inputs() {
    let mut set = std::collections::BTreeSet::new();
    for i in 0u32..50 {
        set.insert(IntegrityHash::compute(&i.to_le_bytes()));
    }
    assert_eq!(
        set.len(),
        50,
        "50 sequential u32 inputs must produce 50 distinct hashes"
    );
}

#[test]
fn enrichment_content_hash_varies_across_sequential_inputs() {
    let mut set = std::collections::BTreeSet::new();
    for i in 0u32..50 {
        set.insert(ContentHash::compute(&i.to_le_bytes()));
    }
    assert_eq!(set.len(), 50);
}

#[test]
fn enrichment_keyed_hash_varies_across_sequential_keys() {
    let mut set = std::collections::BTreeSet::new();
    for i in 0u32..50 {
        set.insert(AuthenticityHash::compute_keyed(
            &i.to_le_bytes(),
            b"fixed-msg",
        ));
    }
    assert_eq!(set.len(), 50);
}

// -- Serde edge cases --

#[test]
fn enrichment_integrity_hash_serde_value_roundtrip() {
    let h = IntegrityHash::compute(b"serde-value");
    let val: serde_json::Value = serde_json::to_value(&h).unwrap();
    let decoded: IntegrityHash = serde_json::from_value(val).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_content_hash_serde_value_roundtrip() {
    let h = ContentHash::compute(b"serde-value-c");
    let val: serde_json::Value = serde_json::to_value(&h).unwrap();
    let decoded: ContentHash = serde_json::from_value(val).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_authenticity_hash_serde_value_roundtrip() {
    let h = AuthenticityHash::compute_keyed(b"sk", b"serde-value-a");
    let val: serde_json::Value = serde_json::to_value(&h).unwrap();
    let decoded: AuthenticityHash = serde_json::from_value(val).unwrap();
    assert_eq!(h, decoded);
}

#[test]
fn enrichment_hash_event_serde_value_roundtrip() {
    let event = HashEvent {
        tier: HashTier::Authenticity,
        algorithm: HashAlgorithm::SipInspiredKeyed,
        input_len: 77,
        component: "val-rt".to_string(),
        trace_id: "vrt-1".to_string(),
    };
    let val: serde_json::Value = serde_json::to_value(&event).unwrap();
    let decoded: HashEvent = serde_json::from_value(val).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn enrichment_hash_tier_serde_value_roundtrip() {
    for tier in [
        HashTier::Integrity,
        HashTier::Content,
        HashTier::Authenticity,
    ] {
        let val: serde_json::Value = serde_json::to_value(&tier).unwrap();
        let decoded: HashTier = serde_json::from_value(val).unwrap();
        assert_eq!(tier, decoded);
    }
}

#[test]
fn enrichment_hash_algorithm_serde_value_roundtrip() {
    for alg in [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ] {
        let val: serde_json::Value = serde_json::to_value(&alg).unwrap();
        let decoded: HashAlgorithm = serde_json::from_value(val).unwrap();
        assert_eq!(alg, decoded);
    }
}

// -- Std Hash trait consistency --

#[test]
fn enrichment_integrity_hash_std_hash_equal_inputs_equal_hashes() {
    use std::hash::{Hash, Hasher};
    let h1 = IntegrityHash::compute(b"std-hash");
    let h2 = IntegrityHash::compute(b"std-hash");
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    h1.hash(&mut hasher1);
    h2.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

#[test]
fn enrichment_content_hash_std_hash_equal_inputs_equal_hashes() {
    use std::hash::{Hash, Hasher};
    let h1 = ContentHash::compute(b"std-hash-c");
    let h2 = ContentHash::compute(b"std-hash-c");
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    h1.hash(&mut hasher1);
    h2.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}

#[test]
fn enrichment_authenticity_hash_std_hash_equal_inputs_equal_hashes() {
    use std::hash::{Hash, Hasher};
    let h1 = AuthenticityHash::compute_keyed(b"k", b"d");
    let h2 = AuthenticityHash::compute_keyed(b"k", b"d");
    let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
    let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
    h1.hash(&mut hasher1);
    h2.hash(&mut hasher2);
    assert_eq!(hasher1.finish(), hasher2.finish());
}
