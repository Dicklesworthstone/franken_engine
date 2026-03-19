#![forbid(unsafe_code)]

//! Enrichment integration tests for the `idempotency_key` module.
//!
//! Covers: key derivation determinism, different inputs produce different keys,
//! attempt number affects key, epoch binding, serde round-trips, dedup store
//! operations, prune/eviction semantics, error paths, Display formatting.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::idempotency_key::{
    DedupEntry, DedupResult, DedupStatus, IdempotencyError, IdempotencyEvent, IdempotencyKey,
    IdempotencyStore, KeyDerivationInput, RetryConfig, derive_idempotency_key,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_session_key() -> Vec<u8> {
    b"test-epoch-session-key-32bytes!!".to_vec()
}

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn test_input_hash() -> ContentHash {
    ContentHash::compute(b"test-input-data")
}

fn test_result_hash() -> ContentHash {
    ContentHash::compute(b"test-result-data")
}

fn test_derivation_input() -> KeyDerivationInput {
    KeyDerivationInput {
        computation_name: "revocation_propagate".to_string(),
        input_hash: test_input_hash(),
        trace_id: "trace-001".to_string(),
        attempt_number: 0,
    }
}

// ===========================================================================
// Key derivation — determinism
// ===========================================================================

#[test]
fn derivation_is_deterministic() {
    let input = test_derivation_input();
    let k1 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
    let k2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
    assert_eq!(k1, k2);
}

#[test]
fn derivation_deterministic_across_calls() {
    let input = test_derivation_input();
    let keys: Vec<IdempotencyKey> = (0..10)
        .map(|_| derive_idempotency_key(&test_session_key(), test_epoch(), &input))
        .collect();
    for k in &keys {
        assert_eq!(*k, keys[0]);
    }
}

// ===========================================================================
// Key derivation — different inputs produce different keys
// ===========================================================================

#[test]
fn different_computation_names_differ() {
    let mut a = test_derivation_input();
    a.computation_name = "comp_a".into();
    let mut b = test_derivation_input();
    b.computation_name = "comp_b".into();
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    assert_ne!(ka.key_hash, kb.key_hash);
}

#[test]
fn different_input_hashes_differ() {
    let mut a = test_derivation_input();
    a.input_hash = ContentHash::compute(b"input-a");
    let mut b = test_derivation_input();
    b.input_hash = ContentHash::compute(b"input-b");
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    assert_ne!(ka.key_hash, kb.key_hash);
}

#[test]
fn different_trace_ids_differ() {
    let mut a = test_derivation_input();
    a.trace_id = "trace-a".into();
    let mut b = test_derivation_input();
    b.trace_id = "trace-b".into();
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    assert_ne!(ka.key_hash, kb.key_hash);
}

#[test]
fn different_attempt_numbers_differ() {
    let mut a = test_derivation_input();
    a.attempt_number = 0;
    let mut b = test_derivation_input();
    b.attempt_number = 1;
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    assert_ne!(ka.key_hash, kb.key_hash);
}

#[test]
fn different_epochs_differ() {
    let input = test_derivation_input();
    let k1 = derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(1), &input);
    let k2 = derive_idempotency_key(&test_session_key(), SecurityEpoch::from_raw(2), &input);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn different_session_keys_differ() {
    let input = test_derivation_input();
    let k1 = derive_idempotency_key(b"key-alpha", test_epoch(), &input);
    let k2 = derive_idempotency_key(b"key-beta", test_epoch(), &input);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn length_prefix_prevents_collision() {
    let mut a = test_derivation_input();
    a.computation_name = "ab".into();
    a.trace_id = "cd".into();
    let mut b = test_derivation_input();
    b.computation_name = "abc".into();
    b.trace_id = "d".into();
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    assert_ne!(ka.key_hash, kb.key_hash);
}

// ===========================================================================
// IdempotencyKey — Display, hex, serde
// ===========================================================================

#[test]
fn key_hex_is_64_chars() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    assert_eq!(key.to_hex().len(), 64);
}

#[test]
fn key_hex_is_lowercase() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    assert!(key.to_hex().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn key_display_format() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    let display = key.to_string();
    assert!(display.starts_with("idem:"));
    assert!(display.contains('@'));
    let hex_part = display.strip_prefix("idem:").unwrap().split('@').next().unwrap();
    assert_eq!(hex_part.len(), 64);
}

#[test]
fn key_display_contains_epoch() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    let display = key.to_string();
    assert!(display.contains("epoch:1") || display.contains("@epoch:1"));
}

#[test]
fn key_serde_roundtrip() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    let json = serde_json::to_string(&key).unwrap();
    let back: IdempotencyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn key_clone_equality() {
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &test_derivation_input());
    let cloned = key.clone();
    assert_eq!(key, cloned);
    assert_eq!(key.to_hex(), cloned.to_hex());
}

#[test]
fn key_ord_in_btreeset() {
    let mut set = BTreeSet::new();
    let mut a = test_derivation_input();
    a.trace_id = "a".into();
    let mut b = test_derivation_input();
    b.trace_id = "b".into();
    let ka = derive_idempotency_key(&test_session_key(), test_epoch(), &a);
    let kb = derive_idempotency_key(&test_session_key(), test_epoch(), &b);
    set.insert(ka.clone());
    set.insert(kb);
    set.insert(ka); // dup
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// DedupStatus — Display, serde
// ===========================================================================

#[test]
fn dedup_status_display() {
    assert_eq!(DedupStatus::InProgress.to_string(), "in_progress");
    assert_eq!(
        DedupStatus::Completed { result_hash: test_result_hash() }.to_string(),
        "completed"
    );
    assert_eq!(
        DedupStatus::Failed { error_code: "err".into() }.to_string(),
        "failed"
    );
}

#[test]
fn dedup_status_display_all_unique() {
    let statuses = [
        DedupStatus::InProgress,
        DedupStatus::Completed { result_hash: test_result_hash() },
        DedupStatus::Failed { error_code: "x".into() },
    ];
    let set: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn dedup_status_serde_roundtrip() {
    let statuses = vec![
        DedupStatus::InProgress,
        DedupStatus::Completed { result_hash: test_result_hash() },
        DedupStatus::Failed { error_code: "timeout".into() },
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: DedupStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// DedupResult — Display, serde
// ===========================================================================

#[test]
fn dedup_result_display() {
    assert_eq!(DedupResult::New.to_string(), "new");
    assert_eq!(
        DedupResult::CachedResult { result_hash: test_result_hash() }.to_string(),
        "cached"
    );
    assert_eq!(DedupResult::DuplicateInProgress.to_string(), "duplicate_in_progress");
    assert_eq!(
        DedupResult::PreviouslyFailed { error_code: "err".into() }.to_string(),
        "previously_failed"
    );
}

#[test]
fn dedup_result_display_all_unique() {
    let results = [
        DedupResult::New,
        DedupResult::CachedResult { result_hash: test_result_hash() },
        DedupResult::DuplicateInProgress,
        DedupResult::PreviouslyFailed { error_code: "x".into() },
    ];
    let set: BTreeSet<String> = results.iter().map(|r| r.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn dedup_result_serde_roundtrip() {
    let results = vec![
        DedupResult::New,
        DedupResult::CachedResult { result_hash: test_result_hash() },
        DedupResult::DuplicateInProgress,
        DedupResult::PreviouslyFailed { error_code: "err".into() },
    ];
    for r in &results {
        let json = serde_json::to_string(r).unwrap();
        let back: DedupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// IdempotencyError — Display, serde
// ===========================================================================

#[test]
fn error_display_all_unique() {
    let errors = [
        IdempotencyError::EpochMismatch {
            key_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        IdempotencyError::MaxRetriesExceeded {
            computation_name: "c".into(),
            max_retries: 3,
            attempt: 4,
        },
        IdempotencyError::DuplicateInProgress {
            computation_name: "d".into(),
        },
        IdempotencyError::EntryNotFound {
            key_hex: "abc".into(),
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn error_display_epoch_mismatch() {
    let err = IdempotencyError::EpochMismatch {
        key_epoch: SecurityEpoch::from_raw(3),
        current_epoch: SecurityEpoch::from_raw(7),
    };
    let msg = err.to_string();
    assert!(msg.contains("epoch mismatch"));
}

#[test]
fn error_display_entry_not_found() {
    let err = IdempotencyError::EntryNotFound { key_hex: "deadbeef".into() };
    let msg = err.to_string();
    assert!(msg.contains("deadbeef"));
    assert!(msg.contains("not found"));
}

#[test]
fn error_serde_roundtrip() {
    let errors = vec![
        IdempotencyError::EpochMismatch {
            key_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        },
        IdempotencyError::MaxRetriesExceeded {
            computation_name: "test".into(),
            max_retries: 3,
            attempt: 4,
        },
        IdempotencyError::DuplicateInProgress {
            computation_name: "test".into(),
        },
        IdempotencyError::EntryNotFound {
            key_hex: "abc".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: IdempotencyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn error_implements_std_error() {
    let err = IdempotencyError::EntryNotFound { key_hex: "abc".into() };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
    assert!(dyn_err.source().is_none());
}

// ===========================================================================
// KeyDerivationInput, DedupEntry, RetryConfig — serde
// ===========================================================================

#[test]
fn key_derivation_input_serde_roundtrip() {
    let input = test_derivation_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: KeyDerivationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn dedup_entry_serde_roundtrip() {
    let entry = DedupEntry {
        status: DedupStatus::Completed { result_hash: test_result_hash() },
        computation_name: "comp".into(),
        created_at_ticks: 42,
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DedupEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn retry_config_serde_roundtrip() {
    let cfg = RetryConfig { max_retries: 5, entry_ttl_ticks: 1000 };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: RetryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn retry_config_default_values() {
    let cfg = RetryConfig::default();
    assert_eq!(cfg.max_retries, 3);
    assert_eq!(cfg.entry_ttl_ticks, 600);
}

#[test]
fn idempotency_event_serde_roundtrip() {
    let event = IdempotencyEvent {
        idempotency_key_hash: "abcdef".into(),
        computation_name: "test".into(),
        attempt: 0,
        dedup_result: "new".into(),
        trace_id: "trace-1".into(),
        epoch_id: 1,
        event: "dedup_check".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: IdempotencyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// IdempotencyStore — basic operations
// ===========================================================================

#[test]
fn store_new_key_returns_new() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    let result = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(result, DedupResult::New));
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn store_duplicate_returns_in_progress() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    let result = store.check_and_claim(&key, &input, 101).unwrap();
    assert!(matches!(result, DedupResult::DuplicateInProgress));
}

#[test]
fn store_completed_returns_cached() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_completed(&key, test_result_hash()).unwrap();
    let result = store.check_and_claim(&key, &input, 101).unwrap();
    if let DedupResult::CachedResult { result_hash } = result {
        assert_eq!(result_hash, test_result_hash());
    } else {
        panic!("expected CachedResult");
    }
}

#[test]
fn store_failed_returns_previously_failed() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_failed(&key, "timeout").unwrap();
    let result = store.check_and_claim(&key, &input, 101).unwrap();
    if let DedupResult::PreviouslyFailed { error_code } = result {
        assert_eq!(error_code, "timeout");
    } else {
        panic!("expected PreviouslyFailed");
    }
}

// ===========================================================================
// IdempotencyStore — epoch binding
// ===========================================================================

#[test]
fn store_old_epoch_key_rejected() {
    let mut store = IdempotencyStore::new(SecurityEpoch::from_raw(2), test_session_key());
    let input = test_derivation_input();
    let old_key = derive_idempotency_key(
        &test_session_key(),
        SecurityEpoch::from_raw(1),
        &input,
    );
    let err = store.check_and_claim(&old_key, &input, 100).unwrap_err();
    assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
}

#[test]
fn store_future_epoch_key_rejected() {
    let mut store = IdempotencyStore::new(SecurityEpoch::from_raw(1), test_session_key());
    let input = test_derivation_input();
    let future_key = derive_idempotency_key(
        &test_session_key(),
        SecurityEpoch::from_raw(99),
        &input,
    );
    let err = store.check_and_claim(&future_key, &input, 100).unwrap_err();
    assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
}

#[test]
fn store_epoch_advance_clears_entries() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    assert_eq!(store.entry_count(), 1);
    store.advance_epoch(SecurityEpoch::from_raw(2), b"new-key".to_vec());
    assert_eq!(store.entry_count(), 0);
    assert_eq!(store.epoch(), SecurityEpoch::from_raw(2));
}

// ===========================================================================
// IdempotencyStore — prune / eviction
// ===========================================================================

#[test]
fn store_evict_all_expired_removes_stale() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    for i in 0..3 {
        let mut input = test_derivation_input();
        input.trace_id = format!("trace-{i}");
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
    }
    assert_eq!(store.entry_count(), 3);
    store.evict_all_expired(100); // within TTL
    assert_eq!(store.entry_count(), 3);
    store.evict_all_expired(800); // past default TTL of 600
    assert_eq!(store.entry_count(), 0);
}

#[test]
fn store_per_computation_ttl_eviction() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    store.set_retry_config(
        "short_ttl",
        RetryConfig { max_retries: 3, entry_ttl_ticks: 50 },
    );

    let mut short = test_derivation_input();
    short.computation_name = "short_ttl".into();
    let key_short = store.derive_key(&short);
    store.check_and_claim(&key_short, &short, 100).unwrap();

    let long = test_derivation_input(); // default TTL 600
    let key_long = store.derive_key(&long);
    store.check_and_claim(&key_long, &long, 100).unwrap();

    assert_eq!(store.entry_count(), 2);
    store.evict_all_expired(160); // short_ttl expired, default not
    assert_eq!(store.entry_count(), 1);
}

// ===========================================================================
// IdempotencyStore — error paths
// ===========================================================================

#[test]
fn store_max_retries_enforced() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let mut input = test_derivation_input();
    input.attempt_number = 4; // exceeds default max of 3
    let key = store.derive_key(&input);
    let err = store.check_and_claim(&key, &input, 100).unwrap_err();
    assert!(matches!(err, IdempotencyError::MaxRetriesExceeded { .. }));
}

#[test]
fn store_mark_completed_missing_entry() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    let err = store.mark_completed(&key, test_result_hash()).unwrap_err();
    assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
}

#[test]
fn store_mark_failed_missing_entry() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    let err = store.mark_failed(&key, "error").unwrap_err();
    assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
}

// ===========================================================================
// IdempotencyStore — events and result counts
// ===========================================================================

#[test]
fn store_emits_events() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "dedup_check");
    assert_eq!(events[0].dedup_result, "new");
}

#[test]
fn store_drain_events_clears() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    assert_eq!(store.drain_events().len(), 1);
    assert!(store.drain_events().is_empty());
}

#[test]
fn store_result_counts_track_outcomes() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap(); // new
    store.check_and_claim(&key, &input, 101).unwrap(); // dup in progress
    store.mark_completed(&key, test_result_hash()).unwrap();
    store.check_and_claim(&key, &input, 102).unwrap(); // cached
    assert_eq!(store.result_counts().get("new"), Some(&1));
    assert_eq!(store.result_counts().get("duplicate_in_progress"), Some(&1));
    assert_eq!(store.result_counts().get("cached"), Some(&1));
}

// ===========================================================================
// IdempotencyStore — derive_key uses store state
// ===========================================================================

#[test]
fn store_derive_key_deterministic() {
    let store = IdempotencyStore::new(test_epoch(), test_session_key());
    let input = test_derivation_input();
    let k1 = store.derive_key(&input);
    let k2 = store.derive_key(&input);
    assert_eq!(k1, k2);
}

#[test]
fn store_derive_key_differs_with_session_key() {
    let s1 = IdempotencyStore::new(test_epoch(), b"key-A".to_vec());
    let s2 = IdempotencyStore::new(test_epoch(), b"key-B".to_vec());
    let input = test_derivation_input();
    assert_ne!(
        s1.derive_key(&input).key_hash,
        s2.derive_key(&input).key_hash,
    );
}

#[test]
fn store_initial_state_empty() {
    let store = IdempotencyStore::new(test_epoch(), test_session_key());
    assert_eq!(store.entry_count(), 0);
    assert!(store.result_counts().is_empty());
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn key_derivation_empty_computation_name() {
    let input = KeyDerivationInput {
        computation_name: String::new(),
        input_hash: test_input_hash(),
        trace_id: "trace".into(),
        attempt_number: 0,
    };
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
    assert_eq!(key.to_hex().len(), 64);
}

#[test]
fn key_derivation_empty_session_key() {
    let input = test_derivation_input();
    let key = derive_idempotency_key(&[], test_epoch(), &input);
    assert_eq!(key.to_hex().len(), 64);
    let key2 = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
    assert_ne!(key.key_hash, key2.key_hash);
}

#[test]
fn key_derivation_max_attempt_number() {
    let input = KeyDerivationInput {
        computation_name: "comp".into(),
        input_hash: test_input_hash(),
        trace_id: "trace".into(),
        attempt_number: u32::MAX,
    };
    let key = derive_idempotency_key(&test_session_key(), test_epoch(), &input);
    assert_eq!(key.to_hex().len(), 64);
}

#[test]
fn retry_config_zero_max_retries() {
    let mut store = IdempotencyStore::new(test_epoch(), test_session_key());
    store.set_retry_config(
        "zero",
        RetryConfig { max_retries: 0, entry_ttl_ticks: 600 },
    );
    let mut input = test_derivation_input();
    input.computation_name = "zero".into();
    input.attempt_number = 0;
    let key = store.derive_key(&input);
    assert!(matches!(
        store.check_and_claim(&key, &input, 100).unwrap(),
        DedupResult::New,
    ));
    input.attempt_number = 1;
    let key1 = store.derive_key(&input);
    assert!(matches!(
        store.check_and_claim(&key1, &input, 101).unwrap_err(),
        IdempotencyError::MaxRetriesExceeded { .. },
    ));
}
