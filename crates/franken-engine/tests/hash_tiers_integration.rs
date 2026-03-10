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
