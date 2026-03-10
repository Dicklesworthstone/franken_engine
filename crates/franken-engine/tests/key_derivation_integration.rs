//! Integration tests for the `key_derivation` module.
//!
//! Covers: KeyDomain, DerivationContext, DerivationRequest, DerivedKey,
//! KeyDerivationError, DeterministicTestDeriver, EpochKeyCache,
//! DerivationEvent, Display impls, serde roundtrips, deterministic replay,
//! epoch-scoped invalidation, and error conditions.

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

use std::collections::BTreeSet;

use frankenengine_engine::key_derivation::{
    DerivationContext, DerivationEvent, DerivationRequest, DerivedKey, DeterministicTestDeriver,
    EpochKeyCache, KeyDerivationError, KeyDeriver, KeyDomain,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn master_key() -> Vec<u8> {
    b"integration-test-master-key-32b!".to_vec()
}

fn alt_master_key() -> Vec<u8> {
    b"alt-integration-master-key-32b!!".to_vec()
}

// ===========================================================================
// Section 1: KeyDomain — Display, separator, ALL, ordering
// ===========================================================================

#[test]
fn domain_display_all_variants() {
    assert_eq!(KeyDomain::Symbol.to_string(), "symbol");
    assert_eq!(KeyDomain::Session.to_string(), "session");
    assert_eq!(KeyDomain::Authentication.to_string(), "authentication");
    assert_eq!(KeyDomain::Evidence.to_string(), "evidence");
    assert_eq!(KeyDomain::Attestation.to_string(), "attestation");
}

#[test]
fn domain_all_contains_five_variants() {
    assert_eq!(KeyDomain::ALL.len(), 5);
    let set: BTreeSet<&KeyDomain> = KeyDomain::ALL.iter().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn domain_separators_are_all_unique() {
    let seps: Vec<&[u8]> = KeyDomain::ALL.iter().map(|d| d.separator()).collect();
    for i in 0..seps.len() {
        for j in (i + 1)..seps.len() {
            assert_ne!(seps[i], seps[j], "domains {i} and {j} share separator");
        }
    }
}

#[test]
fn domain_separators_start_with_franken_prefix() {
    for domain in KeyDomain::ALL {
        let sep = domain.separator();
        assert!(
            sep.starts_with(b"franken::"),
            "separator for {domain} does not start with franken:: prefix"
        );
    }
}

#[test]
fn domain_separators_end_with_double_colon() {
    for domain in KeyDomain::ALL {
        let sep = domain.separator();
        assert!(
            sep.ends_with(b"::"),
            "separator for {domain} does not end with ::"
        );
    }
}

#[test]
fn domain_ordering_is_deterministic() {
    // KeyDomain derives Ord — verify ordering is stable.
    let mut domains: Vec<KeyDomain> = KeyDomain::ALL.to_vec();
    let sorted_copy = {
        let mut v = domains.clone();
        v.sort();
        v
    };
    domains.sort();
    assert_eq!(domains, sorted_copy);
}

#[test]
fn domain_clone_eq() {
    for domain in KeyDomain::ALL {
        let cloned = *domain;
        assert_eq!(*domain, cloned);
    }
}

#[test]
fn domain_serde_roundtrip() {
    for domain in KeyDomain::ALL {
        let json = serde_json::to_string(domain).expect("serialize");
        let restored: KeyDomain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*domain, restored);
    }
}

// ===========================================================================
// Section 2: DerivationContext — construction, canonical bytes, ordering
// ===========================================================================

#[test]
fn empty_context_has_zero_entries() {
    let ctx = DerivationContext::empty();
    assert!(ctx.is_empty());
    assert_eq!(ctx.len(), 0);
    assert!(ctx.to_canonical_bytes().is_empty());
}

#[test]
fn context_with_single_entry() {
    let ctx = DerivationContext::with("ext_id", "test-ext-001");
    assert_eq!(ctx.len(), 1);
    assert!(!ctx.is_empty());
    let bytes = ctx.to_canonical_bytes();
    assert!(bytes.contains(&b'='));
    // Should be: "ext_id=test-ext-001"
    assert_eq!(bytes, b"ext_id=test-ext-001");
}

#[test]
fn context_add_multiple_entries() {
    let mut ctx = DerivationContext::empty();
    ctx.add("aaa", "val_a");
    ctx.add("bbb", "val_b");
    ctx.add("ccc", "val_c");
    assert_eq!(ctx.len(), 3);
}

#[test]
fn context_canonical_bytes_are_deterministic() {
    let mut ctx1 = DerivationContext::empty();
    ctx1.add("zebra", "z_val");
    ctx1.add("alpha", "a_val");

    let mut ctx2 = DerivationContext::empty();
    ctx2.add("alpha", "a_val");
    ctx2.add("zebra", "z_val");

    assert_eq!(ctx1.to_canonical_bytes(), ctx2.to_canonical_bytes());
}

#[test]
fn context_canonical_bytes_sorted_by_key() {
    let mut ctx = DerivationContext::empty();
    ctx.add("beta", "2");
    ctx.add("alpha", "1");
    let bytes = ctx.to_canonical_bytes();
    // BTreeMap sorts by key: "alpha=1\0beta=2"
    assert_eq!(bytes, b"alpha=1\0beta=2");
}

#[test]
fn context_overwrite_existing_key() {
    let mut ctx = DerivationContext::with("key", "old_value");
    ctx.add("key", "new_value");
    assert_eq!(ctx.len(), 1);
    let bytes = ctx.to_canonical_bytes();
    assert_eq!(bytes, b"key=new_value");
}

#[test]
fn context_different_values_produce_different_bytes() {
    let ctx_a = DerivationContext::with("ext", "alpha");
    let ctx_b = DerivationContext::with("ext", "bravo");
    assert_ne!(ctx_a.to_canonical_bytes(), ctx_b.to_canonical_bytes());
}

#[test]
fn context_different_keys_produce_different_bytes() {
    let ctx_a = DerivationContext::with("key_a", "same_val");
    let ctx_b = DerivationContext::with("key_b", "same_val");
    assert_ne!(ctx_a.to_canonical_bytes(), ctx_b.to_canonical_bytes());
}

#[test]
fn context_serde_roundtrip() {
    let mut ctx = DerivationContext::empty();
    ctx.add("session_id", "sess-123");
    ctx.add("ext_id", "ext-abc");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let restored: DerivationContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, restored);
    assert_eq!(ctx.to_canonical_bytes(), restored.to_canonical_bytes());
}

#[test]
fn context_empty_serde_roundtrip() {
    let ctx = DerivationContext::empty();
    let json = serde_json::to_string(&ctx).expect("serialize");
    let restored: DerivationContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, restored);
}

// ===========================================================================
// Section 3: DeterministicTestDeriver — derive, error conditions
// ===========================================================================

#[test]
fn deriver_max_output_len() {
    let deriver = DeterministicTestDeriver;
    assert_eq!(
        deriver.max_output_len(),
        DeterministicTestDeriver::MAX_OUTPUT
    );
    assert_eq!(deriver.max_output_len(), 256);
}

#[test]
fn derive_produces_correct_length() {
    let deriver = DeterministicTestDeriver;
    for len in [1, 16, 32, 64, 128, 256] {
        let request = DerivationRequest {
            master_key: master_key(),
            epoch: SecurityEpoch::from_raw(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: len,
        };
        let key = deriver.derive(&request).unwrap();
        assert_eq!(
            key.key_bytes.len(),
            len,
            "wrong length for output_len={len}"
        );
    }
}

#[test]
fn derive_is_fully_deterministic() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(42),
        domain: KeyDomain::Session,
        context: DerivationContext::with("ext", "test-ext"),
        output_len: 32,
    };
    let key1 = deriver.derive(&request).unwrap();
    let key2 = deriver.derive(&request).unwrap();
    assert_eq!(key1.key_bytes, key2.key_bytes);
    assert_eq!(key1.domain, key2.domain);
    assert_eq!(key1.epoch, key2.epoch);
    assert_eq!(key1.context_hash, key2.context_hash);
}

#[test]
fn derive_different_domains_produce_different_keys() {
    let deriver = DeterministicTestDeriver;
    let mut seen = BTreeSet::new();
    for domain in KeyDomain::ALL {
        let request = DerivationRequest {
            master_key: master_key(),
            epoch: SecurityEpoch::from_raw(1),
            domain: *domain,
            context: DerivationContext::empty(),
            output_len: 32,
        };
        let key = deriver.derive(&request).unwrap();
        assert!(
            seen.insert(key.key_bytes.clone()),
            "domain {domain} produced duplicate key bytes"
        );
    }
}

#[test]
fn derive_different_epochs_produce_different_keys() {
    let deriver = DeterministicTestDeriver;
    let mut seen = BTreeSet::new();
    for epoch_raw in 1..=10 {
        let request = DerivationRequest {
            master_key: master_key(),
            epoch: SecurityEpoch::from_raw(epoch_raw),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 32,
        };
        let key = deriver.derive(&request).unwrap();
        assert!(
            seen.insert(key.key_bytes.clone()),
            "epoch {epoch_raw} produced duplicate key bytes"
        );
    }
}

#[test]
fn derive_different_contexts_produce_different_keys() {
    let deriver = DeterministicTestDeriver;
    let ctx_a = DerivationContext::with("ext", "alpha");
    let ctx_b = DerivationContext::with("ext", "bravo");
    let ctx_c = DerivationContext::with("session", "alpha");

    let mut keys = BTreeSet::new();
    for ctx in [&ctx_a, &ctx_b, &ctx_c] {
        let request = DerivationRequest {
            master_key: master_key(),
            epoch: SecurityEpoch::from_raw(1),
            domain: KeyDomain::Session,
            context: ctx.clone(),
            output_len: 32,
        };
        let key = deriver.derive(&request).unwrap();
        keys.insert(key.key_bytes);
    }
    assert_eq!(keys.len(), 3, "expected 3 distinct keys for 3 contexts");
}

#[test]
fn derive_different_master_keys_produce_different_keys() {
    let deriver = DeterministicTestDeriver;
    let request_a = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let request_b = DerivationRequest {
        master_key: alt_master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let key_a = deriver.derive(&request_a).unwrap();
    let key_b = deriver.derive(&request_b).unwrap();
    assert_ne!(key_a.key_bytes, key_b.key_bytes);
}

// -- Error conditions --

#[test]
fn derive_rejects_empty_master_key() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: vec![],
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let err = deriver.derive(&request).unwrap_err();
    assert_eq!(err, KeyDerivationError::EmptyMasterKey);
}

#[test]
fn derive_rejects_zero_output_length() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 0,
    };
    let err = deriver.derive(&request).unwrap_err();
    assert_eq!(err, KeyDerivationError::ZeroOutputLength);
}

#[test]
fn derive_rejects_excessive_output_length() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 257,
    };
    let err = deriver.derive(&request).unwrap_err();
    assert_eq!(
        err,
        KeyDerivationError::OutputTooLong {
            requested: 257,
            max: 256
        }
    );
}

#[test]
fn derive_accepts_max_output_length() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 256,
    };
    let key = deriver.derive(&request).unwrap();
    assert_eq!(key.key_bytes.len(), 256);
}

#[test]
fn derive_accepts_single_byte_master_key() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: vec![0xAA],
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let key = deriver.derive(&request).unwrap();
    assert_eq!(key.key_bytes.len(), 32);
}

#[test]
fn derive_accepts_single_byte_output() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 1,
    };
    let key = deriver.derive(&request).unwrap();
    assert_eq!(key.key_bytes.len(), 1);
}

// ===========================================================================
// Section 4: DerivedKey — is_valid_at, Display, serde
// ===========================================================================

#[test]
fn derived_key_valid_at_same_epoch() {
    let key = DerivedKey {
        key_bytes: vec![1, 2, 3, 4],
        domain: KeyDomain::Session,
        epoch: SecurityEpoch::from_raw(10),
        context_hash: vec![0xAB],
    };
    assert!(key.is_valid_at(SecurityEpoch::from_raw(10)));
}

#[test]
fn derived_key_invalid_at_different_epoch() {
    let key = DerivedKey {
        key_bytes: vec![1, 2, 3, 4],
        domain: KeyDomain::Session,
        epoch: SecurityEpoch::from_raw(10),
        context_hash: vec![0xAB],
    };
    assert!(!key.is_valid_at(SecurityEpoch::from_raw(9)));
    assert!(!key.is_valid_at(SecurityEpoch::from_raw(11)));
    assert!(!key.is_valid_at(SecurityEpoch::from_raw(0)));
}

#[test]
fn derived_key_display_format() {
    let key = DerivedKey {
        key_bytes: vec![0; 64],
        domain: KeyDomain::Authentication,
        epoch: SecurityEpoch::from_raw(7),
        context_hash: vec![],
    };
    let display = key.to_string();
    assert!(
        display.contains("authentication"),
        "missing domain: {display}"
    );
    assert!(display.contains("7"), "missing epoch: {display}");
    assert!(display.contains("64 bytes"), "missing length: {display}");
}

#[test]
fn derived_key_display_for_each_domain() {
    for domain in KeyDomain::ALL {
        let key = DerivedKey {
            key_bytes: vec![0; 32],
            domain: *domain,
            epoch: SecurityEpoch::from_raw(1),
            context_hash: vec![],
        };
        let display = key.to_string();
        assert!(
            display.contains(&domain.to_string()),
            "display for {domain} missing domain name: {display}"
        );
    }
}

#[test]
fn derived_key_serde_roundtrip() {
    let key = DerivedKey {
        key_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        domain: KeyDomain::Evidence,
        epoch: SecurityEpoch::from_raw(99),
        context_hash: vec![0x01, 0x02],
    };
    let json = serde_json::to_string(&key).expect("serialize");
    let restored: DerivedKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(key, restored);
}

#[test]
fn derived_key_clone_eq() {
    let key = DerivedKey {
        key_bytes: vec![1, 2, 3],
        domain: KeyDomain::Attestation,
        epoch: SecurityEpoch::from_raw(5),
        context_hash: vec![10],
    };
    let cloned = key.clone();
    assert_eq!(key, cloned);
}

// ===========================================================================
// Section 5: KeyDerivationError — Display, serde
// ===========================================================================

#[test]
fn error_display_empty_master_key() {
    let err = KeyDerivationError::EmptyMasterKey;
    assert_eq!(err.to_string(), "master key is empty");
}

#[test]
fn error_display_zero_output_length() {
    let err = KeyDerivationError::ZeroOutputLength;
    assert_eq!(err.to_string(), "requested output length is zero");
}

#[test]
fn error_display_output_too_long() {
    let err = KeyDerivationError::OutputTooLong {
        requested: 1024,
        max: 256,
    };
    assert_eq!(err.to_string(), "output length 1024 exceeds max 256");
}

#[test]
fn error_display_epoch_mismatch() {
    let err = KeyDerivationError::EpochMismatch {
        key_epoch: SecurityEpoch::from_raw(3),
        current_epoch: SecurityEpoch::from_raw(7),
    };
    let display = err.to_string();
    assert!(display.contains("3"), "missing key_epoch: {display}");
    assert!(display.contains("7"), "missing current_epoch: {display}");
}

#[test]
fn error_display_derivation_failed() {
    let err = KeyDerivationError::DerivationFailed {
        reason: "internal issue".to_string(),
    };
    assert!(err.to_string().contains("internal issue"));
}

#[test]
fn error_is_std_error() {
    let err = KeyDerivationError::EmptyMasterKey;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors = vec![
        KeyDerivationError::EmptyMasterKey,
        KeyDerivationError::ZeroOutputLength,
        KeyDerivationError::OutputTooLong {
            requested: 500,
            max: 256,
        },
        KeyDerivationError::EpochMismatch {
            key_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(5),
        },
        KeyDerivationError::DerivationFailed {
            reason: "test reason".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: KeyDerivationError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored, "roundtrip mismatch for: {err}");
    }
}

// ===========================================================================
// Section 6: DerivationEvent — serde
// ===========================================================================

#[test]
fn derivation_event_serde_roundtrip() {
    let event = DerivationEvent {
        domain: KeyDomain::Authentication,
        epoch: SecurityEpoch::from_raw(42),
        context_hash: vec![0xAA, 0xBB, 0xCC],
        algorithm: "DeterministicTestDeriver".to_string(),
        trace_id: "trace-integration-001".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: DerivationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn derivation_event_fields_accessible() {
    let event = DerivationEvent {
        domain: KeyDomain::Symbol,
        epoch: SecurityEpoch::from_raw(1),
        context_hash: vec![],
        algorithm: "test-alg".to_string(),
        trace_id: "trace-xyz".to_string(),
    };
    assert_eq!(event.domain, KeyDomain::Symbol);
    assert_eq!(event.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(event.algorithm, "test-alg");
    assert_eq!(event.trace_id, "trace-xyz");
}

// ===========================================================================
// Section 7: DerivationRequest — serde
// ===========================================================================

#[test]
fn derivation_request_serde_roundtrip() {
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(5),
        domain: KeyDomain::Session,
        context: DerivationContext::with("ext", "test-ext"),
        output_len: 32,
    };
    let json = serde_json::to_string(&request).expect("serialize");
    let restored: DerivationRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(request, restored);
}

// ===========================================================================
// Section 8: EpochKeyCache — caching, invalidation, validation
// ===========================================================================

#[test]
fn cache_starts_empty() {
    let cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    assert_eq!(cache.cached_count(), 0);
    assert!(cache.events().is_empty());
    assert_eq!(cache.current_epoch(), SecurityEpoch::from_raw(1));
}

#[test]
fn cache_derives_and_caches_key() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::with("ext", "test");
    cache
        .get_or_derive(KeyDomain::Session, &ctx, "trace-1")
        .unwrap();
    assert_eq!(cache.cached_count(), 1);
}

#[test]
fn cache_returns_same_key_on_cache_hit() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::with("ext", "cache-test");
    let key1 = cache
        .get_or_derive(KeyDomain::Session, &ctx, "t1")
        .unwrap()
        .clone();
    let key2 = cache
        .get_or_derive(KeyDomain::Session, &ctx, "t2")
        .unwrap()
        .clone();
    assert_eq!(key1.key_bytes, key2.key_bytes);
    // Second call should not create a new derivation event
    assert_eq!(cache.events().len(), 1);
}

#[test]
fn cache_different_domains_cached_separately() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::empty();
    cache.get_or_derive(KeyDomain::Symbol, &ctx, "t1").unwrap();
    cache.get_or_derive(KeyDomain::Session, &ctx, "t2").unwrap();
    cache
        .get_or_derive(KeyDomain::Evidence, &ctx, "t3")
        .unwrap();
    assert_eq!(cache.cached_count(), 3);
    assert_eq!(cache.events().len(), 3);
}

#[test]
fn cache_different_contexts_cached_separately() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx_a = DerivationContext::with("ext", "alpha");
    let ctx_b = DerivationContext::with("ext", "bravo");
    let key_a = cache
        .get_or_derive(KeyDomain::Session, &ctx_a, "t1")
        .unwrap()
        .clone();
    let key_b = cache
        .get_or_derive(KeyDomain::Session, &ctx_b, "t2")
        .unwrap()
        .clone();
    assert_ne!(key_a.key_bytes, key_b.key_bytes);
    assert_eq!(cache.cached_count(), 2);
}

#[test]
fn cache_invalidates_on_epoch_advance() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::empty();
    let key_e1 = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t1")
        .unwrap()
        .clone();
    assert_eq!(cache.cached_count(), 1);

    // Advance epoch — cache should be cleared
    cache.advance_epoch(SecurityEpoch::from_raw(2)).unwrap();
    assert_eq!(cache.cached_count(), 0);
    assert_eq!(cache.current_epoch(), SecurityEpoch::from_raw(2));

    // New derivation at epoch 2 should differ from epoch 1
    let key_e2 = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t2")
        .unwrap()
        .clone();
    assert_ne!(key_e1.key_bytes, key_e2.key_bytes);
    assert_eq!(key_e2.epoch, SecurityEpoch::from_raw(2));
}

#[test]
fn cache_multiple_epoch_advances() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::empty();

    let mut keys = Vec::new();
    for epoch in 1..=5 {
        if epoch > 1 {
            cache.advance_epoch(SecurityEpoch::from_raw(epoch)).unwrap();
        }
        let key = cache
            .get_or_derive(KeyDomain::Symbol, &ctx, &format!("t-{epoch}"))
            .unwrap()
            .clone();
        assert_eq!(key.epoch, SecurityEpoch::from_raw(epoch));
        keys.push(key.key_bytes);
    }

    // All keys should be unique
    let unique_keys: BTreeSet<_> = keys.iter().collect();
    assert_eq!(unique_keys.len(), 5);
}

#[test]
fn cache_rejects_non_monotonic_epoch_advance() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(5),
        32,
    );
    let err = cache.advance_epoch(SecurityEpoch::from_raw(3)).unwrap_err();
    assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
}

#[test]
fn cache_rejects_same_epoch_advance() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(5),
        32,
    );
    let err = cache.advance_epoch(SecurityEpoch::from_raw(5)).unwrap_err();
    assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
}

#[test]
fn cache_validates_key_at_current_epoch() {
    let cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(3),
        32,
    );
    let valid_key = DerivedKey {
        key_bytes: vec![1],
        domain: KeyDomain::Symbol,
        epoch: SecurityEpoch::from_raw(3),
        context_hash: vec![],
    };
    assert!(cache.validate_key(&valid_key).is_ok());
}

#[test]
fn cache_rejects_key_from_old_epoch() {
    let cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(5),
        32,
    );
    let old_key = DerivedKey {
        key_bytes: vec![1],
        domain: KeyDomain::Symbol,
        epoch: SecurityEpoch::from_raw(3),
        context_hash: vec![],
    };
    let err = cache.validate_key(&old_key).unwrap_err();
    assert!(matches!(
        err,
        KeyDerivationError::EpochMismatch {
            key_epoch,
            current_epoch,
        } if key_epoch.as_u64() == 3 && current_epoch.as_u64() == 5
    ));
}

#[test]
fn cache_rejects_key_from_future_epoch() {
    let cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(5),
        32,
    );
    let future_key = DerivedKey {
        key_bytes: vec![1],
        domain: KeyDomain::Symbol,
        epoch: SecurityEpoch::from_raw(10),
        context_hash: vec![],
    };
    let err = cache.validate_key(&future_key).unwrap_err();
    assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
}

// ===========================================================================
// Section 9: EpochKeyCache — event tracking
// ===========================================================================

#[test]
fn cache_records_derivation_events_with_correct_metadata() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    cache
        .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "trace-aaa")
        .unwrap();
    cache
        .get_or_derive(
            KeyDomain::Session,
            &DerivationContext::with("ext", "foo"),
            "trace-bbb",
        )
        .unwrap();

    let events = cache.events();
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].domain, KeyDomain::Symbol);
    assert_eq!(events[0].trace_id, "trace-aaa");
    assert_eq!(events[0].epoch, SecurityEpoch::from_raw(1));
    assert!(!events[0].algorithm.is_empty());

    assert_eq!(events[1].domain, KeyDomain::Session);
    assert_eq!(events[1].trace_id, "trace-bbb");
}

#[test]
fn cache_events_persist_across_epoch_advances() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    cache
        .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t-e1")
        .unwrap();
    cache.advance_epoch(SecurityEpoch::from_raw(2)).unwrap();
    cache
        .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t-e2")
        .unwrap();

    let events = cache.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].epoch, SecurityEpoch::from_raw(1));
    assert_eq!(events[1].epoch, SecurityEpoch::from_raw(2));
}

// ===========================================================================
// Section 10: Integration — old key rejected after epoch advance
// ===========================================================================

#[test]
fn old_epoch_key_rejected_after_advance() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::with("ext", "test");
    let old_key = cache
        .get_or_derive(KeyDomain::Session, &ctx, "t1")
        .unwrap()
        .clone();

    cache.advance_epoch(SecurityEpoch::from_raw(2)).unwrap();

    let err = cache.validate_key(&old_key).unwrap_err();
    assert!(matches!(
        err,
        KeyDerivationError::EpochMismatch {
            key_epoch,
            current_epoch,
        } if key_epoch.as_u64() == 1 && current_epoch.as_u64() == 2
    ));
}

#[test]
fn derive_all_domains_at_every_epoch_produces_unique_keys() {
    let mut cache = EpochKeyCache::new(
        DeterministicTestDeriver,
        master_key(),
        SecurityEpoch::from_raw(1),
        32,
    );
    let ctx = DerivationContext::empty();
    let mut all_key_bytes = BTreeSet::new();

    for epoch in 1..=3 {
        if epoch > 1 {
            cache.advance_epoch(SecurityEpoch::from_raw(epoch)).unwrap();
        }
        for domain in KeyDomain::ALL {
            let key = cache
                .get_or_derive(*domain, &ctx, &format!("e{epoch}-{domain}"))
                .unwrap();
            all_key_bytes.insert(key.key_bytes.clone());
        }
    }

    // 3 epochs * 5 domains = 15 unique keys
    assert_eq!(all_key_bytes.len(), 15);
}

// ===========================================================================
// Section 11: Deterministic replay — same inputs always yield same outputs
// ===========================================================================

#[test]
fn full_cache_replay_is_deterministic() {
    // Run the exact same sequence twice and verify identical outcomes.
    let run = || {
        let mut cache = EpochKeyCache::new(
            DeterministicTestDeriver,
            master_key(),
            SecurityEpoch::from_raw(1),
            32,
        );
        let ctx = DerivationContext::with("ext", "replay-test");
        let k1 = cache
            .get_or_derive(KeyDomain::Session, &ctx, "trace-r1")
            .unwrap()
            .clone();
        cache.advance_epoch(SecurityEpoch::from_raw(2)).unwrap();
        let k2 = cache
            .get_or_derive(KeyDomain::Session, &ctx, "trace-r2")
            .unwrap()
            .clone();
        (k1, k2)
    };

    let (k1a, k2a) = run();
    let (k1b, k2b) = run();
    assert_eq!(k1a.key_bytes, k1b.key_bytes);
    assert_eq!(k2a.key_bytes, k2b.key_bytes);
}

// ===========================================================================
// Section 12: Derived key from deriver carries correct metadata
// ===========================================================================

#[test]
fn derived_key_carries_correct_domain_and_epoch() {
    let deriver = DeterministicTestDeriver;
    for domain in KeyDomain::ALL {
        for epoch_raw in [1, 10, 100] {
            let request = DerivationRequest {
                master_key: master_key(),
                epoch: SecurityEpoch::from_raw(epoch_raw),
                domain: *domain,
                context: DerivationContext::empty(),
                output_len: 32,
            };
            let key = deriver.derive(&request).unwrap();
            assert_eq!(key.domain, *domain);
            assert_eq!(key.epoch, SecurityEpoch::from_raw(epoch_raw));
            assert!(
                !key.context_hash.is_empty(),
                "context_hash should not be empty"
            );
        }
    }
}

#[test]
fn derived_key_context_hash_matches_canonical_context_hash() {
    let deriver = DeterministicTestDeriver;
    let ctx = DerivationContext::with("session_id", "sess-42");
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::from_raw(1),
        domain: KeyDomain::Session,
        context: ctx.clone(),
        output_len: 32,
    };
    let key = deriver.derive(&request).unwrap();

    // The context_hash should be the ContentHash of the canonical bytes.
    use frankenengine_engine::hash_tiers::ContentHash;
    let expected = ContentHash::compute(&ctx.to_canonical_bytes());
    assert_eq!(key.context_hash, expected.as_bytes().to_vec());
}

// ===========================================================================
// Section 13: Genesis epoch derivation
// ===========================================================================

#[test]
fn derive_at_genesis_epoch() {
    let deriver = DeterministicTestDeriver;
    let request = DerivationRequest {
        master_key: master_key(),
        epoch: SecurityEpoch::GENESIS,
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let key = deriver.derive(&request).unwrap();
    assert_eq!(key.epoch, SecurityEpoch::GENESIS);
    assert_eq!(key.key_bytes.len(), 32);
}
