//! Enrichment integration tests for `key_derivation`.
//!
//! Covers: KeyDomain Display/serde/ordering, DerivationContext canonical
//! bytes/serde, DeterministicTestDeriver derivation/boundary/error paths,
//! DerivedKey validity/serde, EpochKeyCache caching/invalidation/events,
//! KeyDerivationError serde/Display, DerivationEvent serde, DerivationRequest
//! serde, domain separation, epoch scoping, context sensitivity, determinism,
//! and full integration scenarios.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::key_derivation::{
    DerivationContext, DerivationEvent, DerivationRequest, DerivedKey, DeterministicTestDeriver,
    EpochKeyCache, KeyDerivationError, KeyDeriver, KeyDomain,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn mk() -> Vec<u8> {
    b"integration-test-master-key-32b!".to_vec()
}

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn derive_key(domain: KeyDomain, epoch: SecurityEpoch, ctx: &DerivationContext) -> DerivedKey {
    DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: mk(),
            epoch,
            domain,
            context: ctx.clone(),
            output_len: 32,
        })
        .expect("derive")
}

// ===========================================================================
// KeyDomain tests
// ===========================================================================

#[test]
fn integ_key_domain_all_count() {
    assert_eq!(KeyDomain::ALL.len(), 5);
}

#[test]
fn integ_key_domain_display_all_unique() {
    let mut displays = BTreeSet::new();
    for d in KeyDomain::ALL {
        displays.insert(d.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_key_domain_serde_all_variants() {
    for d in KeyDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: KeyDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn integ_key_domain_ordering() {
    assert!(KeyDomain::Symbol < KeyDomain::Session);
    assert!(KeyDomain::Session < KeyDomain::Authentication);
    assert!(KeyDomain::Authentication < KeyDomain::Evidence);
    assert!(KeyDomain::Evidence < KeyDomain::Attestation);
}

#[test]
fn integ_key_domain_separators_unique() {
    let mut seps = BTreeSet::new();
    for d in KeyDomain::ALL {
        seps.insert(d.separator().to_vec());
    }
    assert_eq!(seps.len(), 5);
}

#[test]
fn integ_key_domain_separators_format() {
    for d in KeyDomain::ALL {
        let sep = d.separator();
        assert!(sep.starts_with(b"franken::"));
        assert!(sep.ends_with(b"::"));
    }
}

// ===========================================================================
// DerivationContext tests
// ===========================================================================

#[test]
fn integ_context_empty() {
    let ctx = DerivationContext::empty();
    assert!(ctx.is_empty());
    assert_eq!(ctx.len(), 0);
    assert!(ctx.to_canonical_bytes().is_empty());
}

#[test]
fn integ_context_single_entry() {
    let ctx = DerivationContext::with("key", "value");
    assert_eq!(ctx.len(), 1);
    assert_eq!(ctx.to_canonical_bytes(), b"key=value");
}

#[test]
fn integ_context_multiple_entries_sorted() {
    let mut ctx = DerivationContext::empty();
    ctx.add("zebra", "z");
    ctx.add("apple", "a");
    ctx.add("mango", "m");
    let bytes = ctx.to_canonical_bytes();
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.starts_with("apple=a"));
    assert!(s.ends_with("zebra=z"));
}

#[test]
fn integ_context_insertion_order_independent() {
    let mut ctx1 = DerivationContext::empty();
    ctx1.add("b", "2");
    ctx1.add("a", "1");
    let mut ctx2 = DerivationContext::empty();
    ctx2.add("a", "1");
    ctx2.add("b", "2");
    assert_eq!(ctx1.to_canonical_bytes(), ctx2.to_canonical_bytes());
}

#[test]
fn integ_context_overwrite() {
    let mut ctx = DerivationContext::empty();
    ctx.add("k", "old");
    ctx.add("k", "new");
    assert_eq!(ctx.len(), 1);
    assert_eq!(ctx.to_canonical_bytes(), b"k=new");
}

#[test]
fn integ_context_nul_separator() {
    let mut ctx = DerivationContext::empty();
    ctx.add("a", "1");
    ctx.add("b", "2");
    assert_eq!(ctx.to_canonical_bytes(), b"a=1\0b=2");
}

#[test]
fn integ_context_serde_roundtrip() {
    let mut ctx = DerivationContext::empty();
    ctx.add("ext_id", "abc");
    ctx.add("session", "xyz");
    let json = serde_json::to_string(&ctx).unwrap();
    let back: DerivationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, back);
}

// ===========================================================================
// DeterministicTestDeriver tests
// ===========================================================================

#[test]
fn integ_derive_produces_correct_length() {
    for len in [1, 16, 32, 64, 128, 256] {
        let key = DeterministicTestDeriver
            .derive(&DerivationRequest {
                master_key: mk(),
                epoch: ep(1),
                domain: KeyDomain::Symbol,
                context: DerivationContext::empty(),
                output_len: len,
            })
            .unwrap();
        assert_eq!(key.key_bytes.len(), len);
    }
}

#[test]
fn integ_derive_is_deterministic() {
    let k1 = derive_key(
        KeyDomain::Session,
        ep(5),
        &DerivationContext::with("ext", "x"),
    );
    let k2 = derive_key(
        KeyDomain::Session,
        ep(5),
        &DerivationContext::with("ext", "x"),
    );
    assert_eq!(k1.key_bytes, k2.key_bytes);
    assert_eq!(k1.context_hash, k2.context_hash);
}

#[test]
fn integ_different_domains_different_keys() {
    let ctx = DerivationContext::empty();
    let mut key_set = BTreeSet::new();
    for d in KeyDomain::ALL {
        let key = derive_key(*d, ep(1), &ctx);
        key_set.insert(key.key_bytes);
    }
    assert_eq!(key_set.len(), 5);
}

#[test]
fn integ_different_epochs_different_keys() {
    let ctx = DerivationContext::empty();
    let k1 = derive_key(KeyDomain::Symbol, ep(1), &ctx);
    let k2 = derive_key(KeyDomain::Symbol, ep(2), &ctx);
    let k3 = derive_key(KeyDomain::Symbol, ep(999), &ctx);
    assert_ne!(k1.key_bytes, k2.key_bytes);
    assert_ne!(k2.key_bytes, k3.key_bytes);
}

#[test]
fn integ_different_contexts_different_keys() {
    let k1 = derive_key(
        KeyDomain::Session,
        ep(1),
        &DerivationContext::with("ext", "alpha"),
    );
    let k2 = derive_key(
        KeyDomain::Session,
        ep(1),
        &DerivationContext::with("ext", "beta"),
    );
    assert_ne!(k1.key_bytes, k2.key_bytes);
    assert_ne!(k1.context_hash, k2.context_hash);
}

#[test]
fn integ_different_master_keys_different_output() {
    let deriver = DeterministicTestDeriver;
    let req1 = DerivationRequest {
        master_key: b"key-alpha-32-bytes-padding......".to_vec(),
        epoch: ep(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let req2 = DerivationRequest {
        master_key: b"key-bravo-32-bytes-padding......".to_vec(),
        epoch: ep(1),
        domain: KeyDomain::Symbol,
        context: DerivationContext::empty(),
        output_len: 32,
    };
    let k1 = deriver.derive(&req1).unwrap();
    let k2 = deriver.derive(&req2).unwrap();
    assert_ne!(k1.key_bytes, k2.key_bytes);
}

// ===========================================================================
// Error path tests
// ===========================================================================

#[test]
fn integ_derive_empty_master_key_rejected() {
    let err = DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: vec![],
            epoch: ep(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 32,
        })
        .unwrap_err();
    assert_eq!(err, KeyDerivationError::EmptyMasterKey);
}

#[test]
fn integ_derive_zero_output_rejected() {
    let err = DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: mk(),
            epoch: ep(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 0,
        })
        .unwrap_err();
    assert_eq!(err, KeyDerivationError::ZeroOutputLength);
}

#[test]
fn integ_derive_output_too_long_rejected() {
    let err = DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: mk(),
            epoch: ep(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 257,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        KeyDerivationError::OutputTooLong {
            requested: 257,
            max: 256
        }
    ));
}

#[test]
fn integ_derive_max_output_succeeds() {
    let key = DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: mk(),
            epoch: ep(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 256,
        })
        .unwrap();
    assert_eq!(key.key_bytes.len(), 256);
}

// ===========================================================================
// DerivedKey tests
// ===========================================================================

#[test]
fn integ_derived_key_valid_at_same_epoch() {
    let key = derive_key(KeyDomain::Symbol, ep(5), &DerivationContext::empty());
    assert!(key.is_valid_at(ep(5)));
    assert!(!key.is_valid_at(ep(4)));
    assert!(!key.is_valid_at(ep(6)));
}

#[test]
fn integ_derived_key_serde_roundtrip() {
    let key = derive_key(
        KeyDomain::Authentication,
        ep(3),
        &DerivationContext::with("ext", "test"),
    );
    let json = serde_json::to_string(&key).unwrap();
    let back: DerivedKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn integ_derived_key_display() {
    let key = derive_key(KeyDomain::Evidence, ep(7), &DerivationContext::empty());
    let display = key.to_string();
    assert!(display.contains("evidence"));
    assert!(display.contains("7"));
    assert!(display.contains("32 bytes"));
}

#[test]
fn integ_derived_key_json_fields() {
    let key = derive_key(KeyDomain::Symbol, ep(1), &DerivationContext::empty());
    let json = serde_json::to_string(&key).unwrap();
    assert!(json.contains("\"key_bytes\""));
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"context_hash\""));
}

// ===========================================================================
// EpochKeyCache tests
// ===========================================================================

#[test]
fn integ_cache_derive_and_cache() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::with("ext", "test");
    cache.get_or_derive(KeyDomain::Session, &ctx, "t1").unwrap();
    assert_eq!(cache.cached_count(), 1);
    // Second call is cache hit
    cache.get_or_derive(KeyDomain::Session, &ctx, "t2").unwrap();
    assert_eq!(cache.cached_count(), 1);
    assert_eq!(cache.events().len(), 1); // only one derivation
}

#[test]
fn integ_cache_returns_same_key() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::with("ext", "x");
    let k1 = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t1")
        .unwrap()
        .clone();
    let k2 = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t2")
        .unwrap()
        .clone();
    assert_eq!(k1.key_bytes, k2.key_bytes);
}

#[test]
fn integ_cache_different_domains_independent() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::empty();
    cache.get_or_derive(KeyDomain::Symbol, &ctx, "t1").unwrap();
    cache.get_or_derive(KeyDomain::Session, &ctx, "t2").unwrap();
    cache
        .get_or_derive(KeyDomain::Authentication, &ctx, "t3")
        .unwrap();
    assert_eq!(cache.cached_count(), 3);
    assert_eq!(cache.events().len(), 3);
}

#[test]
fn integ_cache_epoch_advance_clears() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::empty();
    let old_key = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t1")
        .unwrap()
        .clone();
    cache.advance_epoch(ep(2)).unwrap();
    assert_eq!(cache.cached_count(), 0);
    assert_eq!(cache.current_epoch(), ep(2));

    let new_key = cache
        .get_or_derive(KeyDomain::Symbol, &ctx, "t2")
        .unwrap()
        .clone();
    assert_ne!(old_key.key_bytes, new_key.key_bytes);
    assert_eq!(new_key.epoch, ep(2));
}

#[test]
fn integ_cache_non_monotonic_advance_rejected() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(5), 32);
    let err = cache.advance_epoch(ep(3)).unwrap_err();
    assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
}

#[test]
fn integ_cache_same_epoch_advance_rejected() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(5), 32);
    let err = cache.advance_epoch(ep(5)).unwrap_err();
    assert!(matches!(err, KeyDerivationError::EpochMismatch { .. }));
}

#[test]
fn integ_cache_validate_key_epoch() {
    let cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(3), 32);
    let valid_key = DerivedKey {
        key_bytes: vec![1],
        domain: KeyDomain::Symbol,
        epoch: ep(3),
        context_hash: vec![],
    };
    assert!(cache.validate_key(&valid_key).is_ok());

    let invalid_key = DerivedKey {
        key_bytes: vec![1],
        domain: KeyDomain::Symbol,
        epoch: ep(1),
        context_hash: vec![],
    };
    assert!(cache.validate_key(&invalid_key).is_err());
}

#[test]
fn integ_cache_old_key_rejected_after_advance() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::with("ext", "x");
    let old_key = cache
        .get_or_derive(KeyDomain::Session, &ctx, "t1")
        .unwrap()
        .clone();
    cache.advance_epoch(ep(2)).unwrap();
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
fn integ_cache_epoch_advance_chain() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::empty();
    for epoch_val in 1..=5u64 {
        cache
            .get_or_derive(KeyDomain::Symbol, &ctx, &format!("t{epoch_val}"))
            .unwrap();
        assert_eq!(cache.cached_count(), 1);
        if epoch_val < 5 {
            cache.advance_epoch(ep(epoch_val + 1)).unwrap();
            assert_eq!(cache.cached_count(), 0);
        }
    }
    assert_eq!(cache.events().len(), 5);
}

#[test]
fn integ_cache_events_epoch_correctness() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(10), 32);
    cache
        .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t1")
        .unwrap();
    assert_eq!(cache.events()[0].epoch, ep(10));
    cache.advance_epoch(ep(11)).unwrap();
    cache
        .get_or_derive(KeyDomain::Symbol, &DerivationContext::empty(), "t2")
        .unwrap();
    assert_eq!(cache.events()[1].epoch, ep(11));
}

#[test]
fn integ_cache_all_five_domains_unique_keys() {
    let mut cache = EpochKeyCache::new(DeterministicTestDeriver, mk(), ep(1), 32);
    let ctx = DerivationContext::empty();
    let mut key_set = BTreeSet::new();
    for d in KeyDomain::ALL {
        let key = cache.get_or_derive(*d, &ctx, "t").unwrap().clone();
        key_set.insert(key.key_bytes);
    }
    assert_eq!(key_set.len(), 5);
}

// ===========================================================================
// KeyDerivationError tests
// ===========================================================================

#[test]
fn integ_error_serde_all_variants() {
    let errors = vec![
        KeyDerivationError::EmptyMasterKey,
        KeyDerivationError::ZeroOutputLength,
        KeyDerivationError::OutputTooLong {
            requested: 500,
            max: 256,
        },
        KeyDerivationError::EpochMismatch {
            key_epoch: ep(1),
            current_epoch: ep(5),
        },
        KeyDerivationError::DerivationFailed {
            reason: "test".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: KeyDerivationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn integ_error_display_all_unique() {
    let errors = vec![
        KeyDerivationError::EmptyMasterKey,
        KeyDerivationError::ZeroOutputLength,
        KeyDerivationError::OutputTooLong {
            requested: 500,
            max: 256,
        },
        KeyDerivationError::EpochMismatch {
            key_epoch: ep(1),
            current_epoch: ep(5),
        },
        KeyDerivationError::DerivationFailed {
            reason: "test".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        displays.insert(err.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(KeyDerivationError::EmptyMasterKey);
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// DerivationEvent tests
// ===========================================================================

#[test]
fn integ_derivation_event_serde_roundtrip() {
    let event = DerivationEvent {
        domain: KeyDomain::Authentication,
        epoch: ep(3),
        context_hash: vec![5, 6, 7],
        algorithm: "DeterministicTestDeriver".to_string(),
        trace_id: "trace-xyz".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: DerivationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_derivation_event_json_fields() {
    let event = DerivationEvent {
        domain: KeyDomain::Symbol,
        epoch: ep(1),
        context_hash: vec![0],
        algorithm: "test".to_string(),
        trace_id: "t-1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"context_hash\""));
    assert!(json.contains("\"algorithm\""));
    assert!(json.contains("\"trace_id\""));
}

// ===========================================================================
// DerivationRequest tests
// ===========================================================================

#[test]
fn integ_derivation_request_serde_roundtrip() {
    let req = DerivationRequest {
        master_key: vec![1, 2, 3],
        epoch: ep(5),
        domain: KeyDomain::Session,
        context: DerivationContext::with("k", "v"),
        output_len: 64,
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: DerivationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// ===========================================================================
// Integration: context hash determinism
// ===========================================================================

#[test]
fn integ_same_context_same_hash() {
    let ctx = DerivationContext::with("ext", "test");
    let k1 = derive_key(KeyDomain::Symbol, ep(1), &ctx);
    let k2 = derive_key(KeyDomain::Symbol, ep(1), &ctx);
    assert_eq!(k1.context_hash, k2.context_hash);
}

#[test]
fn integ_different_context_different_hash() {
    let k1 = derive_key(
        KeyDomain::Symbol,
        ep(1),
        &DerivationContext::with("ext", "a"),
    );
    let k2 = derive_key(
        KeyDomain::Symbol,
        ep(1),
        &DerivationContext::with("ext", "b"),
    );
    assert_ne!(k1.context_hash, k2.context_hash);
}

#[test]
fn integ_deriver_max_output_len() {
    assert_eq!(DeterministicTestDeriver.max_output_len(), 256);
}

#[test]
fn integ_single_byte_master_key() {
    let key = DeterministicTestDeriver
        .derive(&DerivationRequest {
            master_key: vec![0xFF],
            epoch: ep(1),
            domain: KeyDomain::Symbol,
            context: DerivationContext::empty(),
            output_len: 32,
        })
        .unwrap();
    assert_eq!(key.key_bytes.len(), 32);
}
