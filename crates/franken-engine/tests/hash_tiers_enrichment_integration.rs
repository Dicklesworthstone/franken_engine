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
    clippy::identity_op
)]

//! Enrichment integration tests for the `hash_tiers` module.
//!
//! Focus areas complementing existing unit and integration tests:
//! - Cross-tier isolation (same data produces different representations per tier)
//! - Avalanche quality for small input changes
//! - Large input determinism (4KB, 64KB payloads)
//! - Key-data non-commutativity for AuthenticityHash
//! - HashEvent serde across all tier/algorithm combinations
//! - Constant-time equality edge cases
//! - Ordering correctness for BTreeMap/BTreeSet usage
//! - Integration: compute hash -> serialize -> deserialize -> verify equality

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::{
    AuthenticityHash, ContentHash, HashAlgorithm, HashEvent, HashTier, IntegrityHash,
};

// ---------------------------------------------------------------------------
// Cross-tier isolation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_same_data_different_representation_per_tier() {
    let data = b"cross-tier-isolation-test-payload";
    let t1 = IntegrityHash::compute(data);
    let t2 = ContentHash::compute(data);
    let t3 = AuthenticityHash::compute(data);

    // Tier 2 and Tier 3 (unkeyed) use the same algorithm, so bytes match
    assert_eq!(t2.as_bytes(), t3.as_bytes(), "unkeyed T3 matches T2");

    // But Display representations must differ due to prefixes
    let d1 = t1.to_string();
    let d2 = t2.to_string();
    let d3 = t3.to_string();
    assert_ne!(d1, d2);
    assert_ne!(d1, d3);
    assert_ne!(d2, d3);
}

#[test]
fn enrichment_keyed_tier3_differs_from_tier2() {
    let data = b"tier-separation-data";
    let t2 = ContentHash::compute(data);
    let t3_keyed = AuthenticityHash::compute_keyed(b"any-key", data);
    assert_ne!(t2.as_bytes(), t3_keyed.as_bytes(), "keyed T3 differs from T2");
}

#[test]
fn enrichment_tier1_size_differs_from_tier2_tier3() {
    let data = b"size-check";
    let t1 = IntegrityHash::compute(data);
    let t2 = ContentHash::compute(data);
    let t3 = AuthenticityHash::compute(data);

    assert_eq!(std::mem::size_of_val(&t1), 8);
    assert_eq!(std::mem::size_of_val(&t2), 32);
    assert_eq!(std::mem::size_of_val(&t3), 32);
}

// ---------------------------------------------------------------------------
// Avalanche quality for small input changes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_avalanche_single_bit_flip() {
    let mut data = vec![0u8; 32];
    let base = ContentHash::compute(&data);

    let mut total_differing_bits: u32 = 0;
    let trials = 256; // flip each bit in first 32 bytes
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            data[byte_idx] ^= 1 << bit_idx;
            let flipped = ContentHash::compute(&data);
            let bits_diff: u32 = base.as_bytes().iter()
                .zip(flipped.as_bytes().iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            total_differing_bits += bits_diff;
            data[byte_idx] ^= 1 << bit_idx; // restore
        }
    }

    // Good avalanche: average ~50% of 256 bits differ per flip
    let avg_diff = total_differing_bits as f64 / trials as f64;
    assert!(avg_diff > 80.0, "poor avalanche: avg {avg_diff} bits differ (expected ~128)");
}

#[test]
fn enrichment_integrity_hash_avalanche_single_byte_change() {
    let base_data = b"avalanche-test-input-data-000".to_vec();
    let base_hash = IntegrityHash::compute(&base_data);

    let mut all_different = true;
    for i in 0..base_data.len() {
        let mut modified = base_data.clone();
        modified[i] = modified[i].wrapping_add(1);
        let modified_hash = IntegrityHash::compute(&modified);
        if modified_hash == base_hash {
            all_different = false;
        }
    }
    assert!(all_different, "every single-byte change should produce a different hash");
}

#[test]
fn enrichment_authenticity_hash_avalanche_key_change() {
    let data = b"fixed-message-for-key-avalanche";
    let base = AuthenticityHash::compute_keyed(b"key-base-00", data);

    for i in 1u8..20 {
        let key = format!("key-base-{i:02}");
        let h = AuthenticityHash::compute_keyed(key.as_bytes(), data);
        let bits_diff: u32 = base.as_bytes().iter()
            .zip(h.as_bytes().iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert!(bits_diff > 50, "key change should produce significant avalanche, got {bits_diff}");
    }
}

// ---------------------------------------------------------------------------
// Large input determinism (4KB, 64KB payloads)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_4kb_deterministic() {
    let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let h1 = ContentHash::compute(&data);
    let h2 = ContentHash::compute(&data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_64kb_deterministic() {
    let data: Vec<u8> = (0..65536).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let h1 = ContentHash::compute(&data);
    let h2 = ContentHash::compute(&data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_integrity_hash_64kb_deterministic() {
    let data: Vec<u8> = (0..65536).map(|i| ((i * 11 + 3) % 256) as u8).collect();
    let h1 = IntegrityHash::compute(&data);
    let h2 = IntegrityHash::compute(&data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_authenticity_hash_4kb_keyed_deterministic() {
    let key = b"test-key-for-large-input";
    let data: Vec<u8> = (0..4096).map(|i| (i % 199) as u8).collect();
    let h1 = AuthenticityHash::compute_keyed(key, &data);
    let h2 = AuthenticityHash::compute_keyed(key, &data);
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_large_inputs_differ_by_single_byte() {
    let mut data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let h1 = ContentHash::compute(&data);
    data[2048] ^= 0x01;
    let h2 = ContentHash::compute(&data);
    assert_ne!(h1, h2, "single byte change in 4KB input must change hash");
}

// ---------------------------------------------------------------------------
// Key-data non-commutativity for AuthenticityHash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_key_data_swap_produces_different_hash() {
    let a = AuthenticityHash::compute_keyed(b"alpha", b"beta");
    let b = AuthenticityHash::compute_keyed(b"beta", b"alpha");
    assert_ne!(a, b, "hash(key=alpha, data=beta) must differ from hash(key=beta, data=alpha)");
}

#[test]
fn enrichment_key_data_swap_with_identical_material() {
    let a = AuthenticityHash::compute_keyed(b"same", b"same");
    assert_eq!(a.as_bytes().len(), 32);
    let unkeyed = AuthenticityHash::compute(b"same");
    assert_ne!(a.as_bytes(), unkeyed.as_bytes());
}

#[test]
fn enrichment_empty_key_differs_from_non_empty_key() {
    let a = AuthenticityHash::compute_keyed(b"", b"data");
    let b = AuthenticityHash::compute_keyed(b"k", b"data");
    assert_ne!(a, b);
}

#[test]
fn enrichment_empty_data_differs_from_non_empty_data() {
    let a = AuthenticityHash::compute_keyed(b"key", b"");
    let b = AuthenticityHash::compute_keyed(b"key", b"d");
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// HashEvent serde across all tier/algorithm combinations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_event_all_tier_algorithm_combos_serde() {
    let combos = [
        (HashTier::Integrity, HashAlgorithm::WyhashInspired),
        (HashTier::Content, HashAlgorithm::SipInspiredCr),
        (HashTier::Authenticity, HashAlgorithm::SipInspiredKeyed),
    ];

    for (tier, alg) in &combos {
        let event = HashEvent {
            tier: *tier,
            algorithm: *alg,
            input_len: 42,
            component: format!("component_{tier}"),
            trace_id: format!("trace_{alg}"),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: HashEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

#[test]
fn enrichment_hash_event_json_all_fields_present() {
    let event = HashEvent {
        tier: HashTier::Authenticity,
        algorithm: HashAlgorithm::SipInspiredKeyed,
        input_len: 1024,
        component: "evidence_ledger".to_string(),
        trace_id: "trace-enrichment-001".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    for field in &["\"tier\"", "\"algorithm\"", "\"input_len\"", "\"component\"", "\"trace_id\""] {
        assert!(json.contains(field), "JSON must contain field {field}");
    }
}

#[test]
fn enrichment_hash_event_large_input_len_serde() {
    let event = HashEvent {
        tier: HashTier::Content,
        algorithm: HashAlgorithm::SipInspiredCr,
        input_len: usize::MAX,
        component: "huge_input".to_string(),
        trace_id: "trace-max".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HashEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Constant-time equality edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constant_time_eq_all_zeros() {
    let a = AuthenticityHash([0u8; 32]);
    let b = AuthenticityHash([0u8; 32]);
    assert!(a.constant_time_eq(&b));
}

#[test]
fn enrichment_constant_time_eq_all_ones() {
    let a = AuthenticityHash([0xFF; 32]);
    let b = AuthenticityHash([0xFF; 32]);
    assert!(a.constant_time_eq(&b));
}

#[test]
fn enrichment_constant_time_eq_last_byte_differs() {
    let a = AuthenticityHash([0u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let b = AuthenticityHash(bytes);
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn enrichment_constant_time_eq_first_byte_differs() {
    let a = AuthenticityHash([0u8; 32]);
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    let b = AuthenticityHash(bytes);
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn enrichment_constant_time_eq_middle_byte_differs() {
    let a = AuthenticityHash([0x55; 32]);
    let mut bytes = [0x55; 32];
    bytes[15] = 0x54;
    let b = AuthenticityHash(bytes);
    assert!(!a.constant_time_eq(&b));
}

#[test]
fn enrichment_constant_time_eq_is_reflexive() {
    let h = AuthenticityHash::compute_keyed(b"key", b"data");
    assert!(h.constant_time_eq(&h));
}

#[test]
fn enrichment_constant_time_eq_is_symmetric() {
    let a = AuthenticityHash::compute_keyed(b"k1", b"d1");
    let b = AuthenticityHash::compute_keyed(b"k1", b"d1");
    assert!(a.constant_time_eq(&b));
    assert!(b.constant_time_eq(&a));
}

// ---------------------------------------------------------------------------
// Ordering correctness for BTreeMap/BTreeSet usage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_in_btreeset_deduplicates() {
    let mut set = BTreeSet::new();
    let h1 = ContentHash::compute(b"unique");
    let h2 = ContentHash::compute(b"unique");
    let h3 = ContentHash::compute(b"different");

    set.insert(h1);
    set.insert(h2); // duplicate
    set.insert(h3);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_content_hash_as_btreemap_key() {
    let mut map = BTreeMap::new();
    let h1 = ContentHash::compute(b"key-a");
    let h2 = ContentHash::compute(b"key-b");
    map.insert(h1, "value-a");
    map.insert(h2, "value-b");
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(&h1), Some(&"value-a"));
    assert_eq!(map.get(&h2), Some(&"value-b"));
}

#[test]
fn enrichment_integrity_hash_in_btreeset_deduplicates() {
    let mut set = BTreeSet::new();
    for i in 0u8..50 {
        set.insert(IntegrityHash::compute(&[i]));
    }
    assert_eq!(set.len(), 50);
    for i in 0u8..50 {
        set.insert(IntegrityHash::compute(&[i]));
    }
    assert_eq!(set.len(), 50, "no duplicates after re-insertion");
}

#[test]
fn enrichment_authenticity_hash_ordering_is_consistent() {
    let hashes: Vec<AuthenticityHash> = (0u8..20)
        .map(|i| AuthenticityHash::compute_keyed(&[i], b"msg"))
        .collect();

    let mut sorted_a = hashes.clone();
    let mut sorted_b = hashes.clone();
    sorted_a.sort();
    sorted_b.sort();
    assert_eq!(sorted_a, sorted_b, "sorting must be deterministic");
}

#[test]
fn enrichment_hash_tier_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(HashTier::Authenticity);
    set.insert(HashTier::Integrity);
    set.insert(HashTier::Content);
    set.insert(HashTier::Integrity); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_hash_algorithm_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(HashAlgorithm::SipInspiredKeyed);
    set.insert(HashAlgorithm::WyhashInspired);
    set.insert(HashAlgorithm::SipInspiredCr);
    set.insert(HashAlgorithm::WyhashInspired); // duplicate
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// Integration: compute hash -> serialize -> deserialize -> verify equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_integrity_hash_compute_serde_verify() {
    let original = IntegrityHash::compute(b"integration-test-payload");
    let json = serde_json::to_string(&original).unwrap();
    let restored: IntegrityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
    assert_eq!(original.as_u64(), restored.as_u64());
    assert_eq!(original.to_string(), restored.to_string());
}

#[test]
fn enrichment_content_hash_compute_serde_verify() {
    let original = ContentHash::compute(b"integration-test-payload");
    let json = serde_json::to_string(&original).unwrap();
    let restored: ContentHash = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
    assert_eq!(original.as_bytes(), restored.as_bytes());
    assert_eq!(original.to_hex(), restored.to_hex());
    assert_eq!(original.to_string(), restored.to_string());
}

#[test]
fn enrichment_authenticity_hash_compute_serde_verify() {
    let original = AuthenticityHash::compute_keyed(b"secret-key", b"integration-test-payload");
    let json = serde_json::to_string(&original).unwrap();
    let restored: AuthenticityHash = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
    assert_eq!(original.as_bytes(), restored.as_bytes());
    assert_eq!(original.to_hex(), restored.to_hex());
    assert!(original.constant_time_eq(&restored));
}

#[test]
fn enrichment_content_hash_from_bytes_serde_roundtrip() {
    let bytes = [0xABu8; 32];
    let h = ContentHash::from_bytes(bytes);
    let json = serde_json::to_string(&h).unwrap();
    let back: ContentHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
    assert_eq!(back.as_bytes(), &bytes);
}

// ---------------------------------------------------------------------------
// Display format verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_prefixes_are_distinct() {
    let data = b"prefix-check";
    let d1 = IntegrityHash::compute(data).to_string();
    let d2 = ContentHash::compute(data).to_string();
    let d3 = AuthenticityHash::compute(data).to_string();

    assert!(d1.starts_with("integrity:"));
    assert!(d2.starts_with("content:"));
    assert!(d3.starts_with("authenticity:"));
}

#[test]
fn enrichment_hex_representations_are_lowercase() {
    let ch = ContentHash::compute(b"hex-case-check");
    let ah = AuthenticityHash::compute_keyed(b"k", b"hex-case-check");

    assert!(ch.to_hex().chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    assert!(ah.to_hex().chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[test]
fn enrichment_content_hash_hex_length_always_64() {
    let inputs: Vec<&[u8]> = vec![b"", b"a", b"short", &[0u8; 1000]];
    for input in inputs {
        let h = ContentHash::compute(input);
        assert_eq!(h.to_hex().len(), 64, "hex must always be 64 chars for {}-byte input", input.len());
    }
}

// ---------------------------------------------------------------------------
// HashAlgorithm tier mapping bijection
// ---------------------------------------------------------------------------

#[test]
fn enrichment_every_algorithm_maps_to_unique_tier() {
    let algs = [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ];
    let tiers: BTreeSet<HashTier> = algs.iter().map(|a| a.tier()).collect();
    assert_eq!(tiers.len(), 3, "bijection: each algorithm maps to a unique tier");
}

#[test]
fn enrichment_hash_tier_display_all_unique_enrichment() {
    let tiers = [HashTier::Integrity, HashTier::Content, HashTier::Authenticity];
    let displays: BTreeSet<String> = tiers.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_hash_algorithm_display_all_unique_enrichment() {
    let algs = [
        HashAlgorithm::WyhashInspired,
        HashAlgorithm::SipInspiredCr,
        HashAlgorithm::SipInspiredKeyed,
    ];
    let displays: BTreeSet<String> = algs.iter().map(|a| a.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

// ---------------------------------------------------------------------------
// Edge cases: empty inputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_tiers_handle_empty_input() {
    let t1 = IntegrityHash::compute(b"");
    let t2 = ContentHash::compute(b"");
    let t3 = AuthenticityHash::compute(b"");
    let t3k = AuthenticityHash::compute_keyed(b"", b"");

    // All should produce valid, deterministic results
    assert_eq!(t1, IntegrityHash::compute(b""));
    assert_eq!(t2, ContentHash::compute(b""));
    assert_eq!(t3, AuthenticityHash::compute(b""));
    assert_eq!(t3k, AuthenticityHash::compute_keyed(b"", b""));
}

#[test]
fn enrichment_empty_and_nonempty_always_differ() {
    assert_ne!(IntegrityHash::compute(b""), IntegrityHash::compute(b"\0"));
    assert_ne!(ContentHash::compute(b""), ContentHash::compute(b"\0"));
    assert_ne!(AuthenticityHash::compute(b""), AuthenticityHash::compute(b"\0"));
}
