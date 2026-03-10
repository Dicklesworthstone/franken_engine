#![forbid(unsafe_code)]

//! Integration tests for the `idempotency_key` module.
//!
//! Covers: IdempotencyKey, KeyDerivationInput, derive_idempotency_key(),
//! DedupStatus, DedupEntry, DedupResult, IdempotencyEvent, IdempotencyError,
//! RetryConfig, IdempotencyStore.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::idempotency_key::{
    DedupEntry, DedupResult, DedupStatus, IdempotencyError, IdempotencyEvent, IdempotencyKey,
    IdempotencyStore, KeyDerivationInput, RetryConfig, derive_idempotency_key,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn session_key() -> Vec<u8> {
    b"integration-session-key-32bytes!".to_vec()
}

fn input_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn make_input(name: &str, trace: &str, attempt: u32) -> KeyDerivationInput {
    KeyDerivationInput {
        computation_name: name.to_string(),
        input_hash: input_hash(b"standard-input"),
        trace_id: trace.to_string(),
        attempt_number: attempt,
    }
}

fn result_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// =========================================================================
// Section 1: Display implementations
// =========================================================================

#[test]
fn idempotency_key_display_format() {
    let key = derive_idempotency_key(&session_key(), epoch(5), &make_input("comp", "t", 0));
    let display = key.to_string();
    assert!(display.starts_with("idem:"), "should start with idem:");
    assert!(
        display.contains("epoch:5"),
        "should contain epoch:5 but got: {display}"
    );
    // Format: idem:<64 hex chars>@epoch:5
    assert!(display.contains('@'), "should contain @ separator");
}

#[test]
fn dedup_status_display_all_variants() {
    assert_eq!(DedupStatus::InProgress.to_string(), "in_progress");
    assert_eq!(
        DedupStatus::Completed {
            result_hash: result_hash(b"x")
        }
        .to_string(),
        "completed"
    );
    assert_eq!(
        DedupStatus::Failed {
            error_code: "err".to_string()
        }
        .to_string(),
        "failed"
    );
}

#[test]
fn dedup_result_display_all_variants() {
    assert_eq!(DedupResult::New.to_string(), "new");
    assert_eq!(
        DedupResult::CachedResult {
            result_hash: result_hash(b"r")
        }
        .to_string(),
        "cached"
    );
    assert_eq!(
        DedupResult::DuplicateInProgress.to_string(),
        "duplicate_in_progress"
    );
    assert_eq!(
        DedupResult::PreviouslyFailed {
            error_code: "x".to_string()
        }
        .to_string(),
        "previously_failed"
    );
}

#[test]
fn idempotency_error_display_epoch_mismatch() {
    let err = IdempotencyError::EpochMismatch {
        key_epoch: epoch(1),
        current_epoch: epoch(3),
    };
    let msg = err.to_string();
    assert!(msg.contains("epoch mismatch"), "got: {msg}");
    assert!(msg.contains("epoch:1"), "got: {msg}");
    assert!(msg.contains("epoch:3"), "got: {msg}");
}

#[test]
fn idempotency_error_display_max_retries() {
    let err = IdempotencyError::MaxRetriesExceeded {
        computation_name: "remote_sync".to_string(),
        max_retries: 5,
        attempt: 6,
    };
    let msg = err.to_string();
    assert!(msg.contains("max retries"), "got: {msg}");
    assert!(msg.contains("5"), "got: {msg}");
    assert!(msg.contains("remote_sync"), "got: {msg}");
    assert!(msg.contains("6"), "got: {msg}");
}

#[test]
fn idempotency_error_display_duplicate_in_progress() {
    let err = IdempotencyError::DuplicateInProgress {
        computation_name: "comp_x".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("duplicate in-progress"), "got: {msg}");
    assert!(msg.contains("comp_x"), "got: {msg}");
}

#[test]
fn idempotency_error_display_entry_not_found() {
    let err = IdempotencyError::EntryNotFound {
        key_hex: "deadbeef".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("not found"), "got: {msg}");
    assert!(msg.contains("deadbeef"), "got: {msg}");
}

#[test]
fn idempotency_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(IdempotencyError::EntryNotFound {
        key_hex: "ab".to_string(),
    });
    // Ensure it implements std::error::Error
    let _ = err.to_string();
}

// =========================================================================
// Section 2: Construction and defaults
// =========================================================================

#[test]
fn retry_config_default_values() {
    let cfg = RetryConfig::default();
    assert_eq!(cfg.max_retries, 3);
    assert_eq!(cfg.entry_ttl_ticks, 600);
}

#[test]
fn idempotency_store_new_empty() {
    let store = IdempotencyStore::new(epoch(1), session_key());
    assert_eq!(store.epoch(), epoch(1));
    assert_eq!(store.entry_count(), 0);
    assert!(store.result_counts().is_empty());
}

#[test]
fn key_derivation_input_construction() {
    let input = KeyDerivationInput {
        computation_name: "revoke_cert".to_string(),
        input_hash: input_hash(b"cert-data"),
        trace_id: "trace-99".to_string(),
        attempt_number: 2,
    };
    assert_eq!(input.computation_name, "revoke_cert");
    assert_eq!(input.trace_id, "trace-99");
    assert_eq!(input.attempt_number, 2);
}

#[test]
fn dedup_entry_construction() {
    let entry = DedupEntry {
        status: DedupStatus::InProgress,
        computation_name: "sync".to_string(),
        created_at_ticks: 100,
        epoch: epoch(1),
    };
    assert_eq!(entry.computation_name, "sync");
    assert_eq!(entry.created_at_ticks, 100);
    assert_eq!(entry.epoch, epoch(1));
}

// =========================================================================
// Section 3: Key derivation determinism
// =========================================================================

#[test]
fn derivation_deterministic_across_multiple_calls() {
    let input = make_input("comp_a", "trace-1", 0);
    let key = session_key();
    let ep = epoch(1);
    let k1 = derive_idempotency_key(&key, ep, &input);
    let k2 = derive_idempotency_key(&key, ep, &input);
    let k3 = derive_idempotency_key(&key, ep, &input);
    assert_eq!(k1, k2);
    assert_eq!(k2, k3);
}

#[test]
fn derivation_varies_with_computation_name() {
    let i1 = make_input("alpha", "t", 0);
    let i2 = make_input("beta", "t", 0);
    let k1 = derive_idempotency_key(&session_key(), epoch(1), &i1);
    let k2 = derive_idempotency_key(&session_key(), epoch(1), &i2);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn derivation_varies_with_input_hash() {
    let mut i1 = make_input("comp", "t", 0);
    i1.input_hash = input_hash(b"data-a");
    let mut i2 = make_input("comp", "t", 0);
    i2.input_hash = input_hash(b"data-b");
    let k1 = derive_idempotency_key(&session_key(), epoch(1), &i1);
    let k2 = derive_idempotency_key(&session_key(), epoch(1), &i2);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn derivation_varies_with_trace_id() {
    let i1 = make_input("comp", "trace-a", 0);
    let i2 = make_input("comp", "trace-b", 0);
    let k1 = derive_idempotency_key(&session_key(), epoch(1), &i1);
    let k2 = derive_idempotency_key(&session_key(), epoch(1), &i2);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn derivation_varies_with_attempt_number() {
    let i1 = make_input("comp", "t", 0);
    let i2 = make_input("comp", "t", 1);
    let k1 = derive_idempotency_key(&session_key(), epoch(1), &i1);
    let k2 = derive_idempotency_key(&session_key(), epoch(1), &i2);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn derivation_varies_with_epoch() {
    let input = make_input("comp", "t", 0);
    let k1 = derive_idempotency_key(&session_key(), epoch(1), &input);
    let k2 = derive_idempotency_key(&session_key(), epoch(2), &input);
    assert_ne!(k1.key_hash, k2.key_hash);
    assert_eq!(k1.epoch, epoch(1));
    assert_eq!(k2.epoch, epoch(2));
}

#[test]
fn derivation_varies_with_session_key() {
    let input = make_input("comp", "t", 0);
    let k1 = derive_idempotency_key(b"session-key-alpha-32bytes!!!!!!!", epoch(1), &input);
    let k2 = derive_idempotency_key(b"session-key-beta--32bytes!!!!!!!", epoch(1), &input);
    assert_ne!(k1.key_hash, k2.key_hash);
}

#[test]
fn key_hex_length_is_64() {
    let key = derive_idempotency_key(&session_key(), epoch(1), &make_input("comp", "t", 0));
    assert_eq!(key.to_hex().len(), 64);
    // All chars should be hex digits.
    assert!(key.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn key_hex_lowercase() {
    let key = derive_idempotency_key(&session_key(), epoch(1), &make_input("comp", "t", 0));
    assert_eq!(key.to_hex(), key.to_hex().to_lowercase());
}

#[test]
fn store_derive_key_matches_standalone() {
    let store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp_a", "trace-1", 0);
    let k_store = store.derive_key(&input);
    let k_standalone = derive_idempotency_key(&session_key(), epoch(1), &input);
    assert_eq!(k_store, k_standalone);
}

#[test]
fn derivation_produces_unique_keys_for_many_inputs() {
    let mut seen = BTreeSet::new();
    for i in 0..50 {
        let input = make_input(&format!("comp_{i}"), &format!("trace-{i}"), i as u32);
        let key = derive_idempotency_key(&session_key(), epoch(1), &input);
        assert!(seen.insert(key.key_hash), "duplicate key for input {i}");
    }
    assert_eq!(seen.len(), 50);
}

// =========================================================================
// Section 4: Dedup store state transitions
// =========================================================================

#[test]
fn new_key_returns_new_and_claims() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    let result = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(result, DedupResult::New));
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn duplicate_returns_in_progress() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    let result = store.check_and_claim(&key, &input, 101).unwrap();
    assert!(matches!(result, DedupResult::DuplicateInProgress));
}

#[test]
fn completed_returns_cached_result() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_completed(&key, result_hash(b"output")).unwrap();

    let result = store.check_and_claim(&key, &input, 101).unwrap();
    if let DedupResult::CachedResult {
        result_hash: rh, ..
    } = result
    {
        assert_eq!(rh, result_hash(b"output"));
    } else {
        panic!("expected CachedResult, got {result:?}");
    }
}

#[test]
fn failed_returns_previously_failed() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_failed(&key, "ETIMEOUT").unwrap();

    let result = store.check_and_claim(&key, &input, 101).unwrap();
    if let DedupResult::PreviouslyFailed { error_code } = result {
        assert_eq!(error_code, "ETIMEOUT");
    } else {
        panic!("expected PreviouslyFailed, got {result:?}");
    }
}

#[test]
fn mark_completed_on_missing_entry() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    let err = store.mark_completed(&key, result_hash(b"x")).unwrap_err();
    assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
}

#[test]
fn mark_failed_on_missing_entry() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    let err = store.mark_failed(&key, "error").unwrap_err();
    assert!(matches!(err, IdempotencyError::EntryNotFound { .. }));
}

#[test]
fn multiple_independent_computations() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input_a = make_input("comp_a", "t1", 0);
    let input_b = make_input("comp_b", "t2", 0);
    let key_a = store.derive_key(&input_a);
    let key_b = store.derive_key(&input_b);

    let r_a = store.check_and_claim(&key_a, &input_a, 100).unwrap();
    let r_b = store.check_and_claim(&key_b, &input_b, 100).unwrap();
    assert!(matches!(r_a, DedupResult::New));
    assert!(matches!(r_b, DedupResult::New));
    assert_eq!(store.entry_count(), 2);

    store.mark_completed(&key_a, result_hash(b"out-a")).unwrap();
    store.mark_failed(&key_b, "ERR_B").unwrap();

    // Check each independently.
    let r_a2 = store.check_and_claim(&key_a, &input_a, 101).unwrap();
    assert!(matches!(r_a2, DedupResult::CachedResult { .. }));
    let r_b2 = store.check_and_claim(&key_b, &input_b, 101).unwrap();
    assert!(matches!(r_b2, DedupResult::PreviouslyFailed { .. }));
}

// =========================================================================
// Section 5: Epoch binding
// =========================================================================

#[test]
fn old_epoch_key_rejected() {
    let mut store = IdempotencyStore::new(epoch(3), session_key());
    let input = make_input("comp", "t", 0);
    let old_key = derive_idempotency_key(&session_key(), epoch(1), &input);
    let err = store.check_and_claim(&old_key, &input, 100).unwrap_err();
    if let IdempotencyError::EpochMismatch {
        key_epoch,
        current_epoch,
    } = err
    {
        assert_eq!(key_epoch, epoch(1));
        assert_eq!(current_epoch, epoch(3));
    } else {
        panic!("expected EpochMismatch, got {err:?}");
    }
}

#[test]
fn future_epoch_key_rejected() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let future_key = derive_idempotency_key(&session_key(), epoch(5), &input);
    let err = store.check_and_claim(&future_key, &input, 100).unwrap_err();
    assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
}

#[test]
fn advance_epoch_clears_old_entries() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    assert_eq!(store.entry_count(), 1);

    store.advance_epoch(epoch(2), b"new-key".to_vec());
    assert_eq!(store.entry_count(), 0);
    assert_eq!(store.epoch(), epoch(2));
}

#[test]
fn advance_epoch_then_derive_new_key() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.advance_epoch(epoch(2), b"session-2-key".to_vec());

    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    assert_eq!(key.epoch, epoch(2));

    let result = store.check_and_claim(&key, &input, 200).unwrap();
    assert!(matches!(result, DedupResult::New));
}

#[test]
fn old_key_fails_after_epoch_advance() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key_epoch1 = store.derive_key(&input);
    store.check_and_claim(&key_epoch1, &input, 100).unwrap();

    store.advance_epoch(epoch(2), b"new-session".to_vec());

    let err = store.check_and_claim(&key_epoch1, &input, 200).unwrap_err();
    assert!(matches!(err, IdempotencyError::EpochMismatch { .. }));
}

#[test]
fn multiple_epoch_advances() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    for ep in 2..=10 {
        store.advance_epoch(epoch(ep), format!("key-{ep}").into_bytes());
        assert_eq!(store.epoch(), epoch(ep));
        assert_eq!(store.entry_count(), 0);
    }
}

// =========================================================================
// Section 6: Retry limits
// =========================================================================

#[test]
fn default_max_retries_enforced() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 4); // exceeds default max of 3
    let key = store.derive_key(&input);
    let err = store.check_and_claim(&key, &input, 100).unwrap_err();
    if let IdempotencyError::MaxRetriesExceeded {
        max_retries,
        attempt,
        ..
    } = err
    {
        assert_eq!(max_retries, 3);
        assert_eq!(attempt, 4);
    } else {
        panic!("expected MaxRetriesExceeded");
    }
}

#[test]
fn attempt_at_exactly_max_succeeds() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 3); // exactly at default max
    let key = store.derive_key(&input);
    let result = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(result, DedupResult::New));
}

#[test]
fn custom_retry_config_per_computation() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.set_retry_config(
        "low_retry",
        RetryConfig {
            max_retries: 1,
            entry_ttl_ticks: 100,
        },
    );

    // Attempt 0: OK
    let input0 = make_input("low_retry", "t", 0);
    let key0 = store.derive_key(&input0);
    assert!(store.check_and_claim(&key0, &input0, 10).is_ok());

    // Attempt 1: OK (at max)
    let input1 = make_input("low_retry", "t", 1);
    let key1 = store.derive_key(&input1);
    assert!(store.check_and_claim(&key1, &input1, 11).is_ok());

    // Attempt 2: exceeds max of 1
    let input2 = make_input("low_retry", "t", 2);
    let key2 = store.derive_key(&input2);
    let err = store.check_and_claim(&key2, &input2, 12).unwrap_err();
    if let IdempotencyError::MaxRetriesExceeded { max_retries, .. } = err {
        assert_eq!(max_retries, 1);
    } else {
        panic!("expected MaxRetriesExceeded");
    }
}

#[test]
fn different_computations_use_different_retry_configs() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.set_retry_config(
        "strict",
        RetryConfig {
            max_retries: 0,
            entry_ttl_ticks: 100,
        },
    );

    // "strict" computation: attempt 0 is at max (0), attempt 1 fails
    let input_strict = make_input("strict", "t", 1);
    let key_strict = store.derive_key(&input_strict);
    assert!(
        store
            .check_and_claim(&key_strict, &input_strict, 10)
            .is_err()
    );

    // Default computation: attempt 3 is at max (3), should succeed
    let input_default = make_input("other_comp", "t", 3);
    let key_default = store.derive_key(&input_default);
    assert!(
        store
            .check_and_claim(&key_default, &input_default, 10)
            .is_ok()
    );
}

#[test]
fn retry_config_accessor() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let default_cfg = store.retry_config("unknown_comp");
    assert_eq!(default_cfg.max_retries, 3);
    assert_eq!(default_cfg.entry_ttl_ticks, 600);

    store.set_retry_config(
        "custom",
        RetryConfig {
            max_retries: 10,
            entry_ttl_ticks: 5000,
        },
    );
    let custom_cfg = store.retry_config("custom");
    assert_eq!(custom_cfg.max_retries, 10);
    assert_eq!(custom_cfg.entry_ttl_ticks, 5000);
}

// =========================================================================
// Section 7: TTL expiration
// =========================================================================

#[test]
fn entries_expire_based_on_default_ttl() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    assert_eq!(store.entry_count(), 1);

    // Trigger eviction via a new check_and_claim after TTL (default 600)
    let input2 = make_input("comp", "t2", 0);
    let key2 = store.derive_key(&input2);
    store.check_and_claim(&key2, &input2, 800).unwrap();

    // Original entry created at tick 100 with TTL 600 -> expires at 700
    // At tick 800, it should have been evicted.
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn entries_not_expired_within_ttl() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();

    // Within TTL: check at tick 500 (600 - 100 = 500 ticks elapsed, still < 600)
    let input2 = make_input("comp", "t2", 0);
    let key2 = store.derive_key(&input2);
    store.check_and_claim(&key2, &input2, 500).unwrap();

    assert_eq!(store.entry_count(), 2);
}

#[test]
fn evict_all_expired_respects_per_computation_ttl() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.set_retry_config(
        "short_ttl",
        RetryConfig {
            max_retries: 3,
            entry_ttl_ticks: 50,
        },
    );

    let input_short = make_input("short_ttl", "t1", 0);
    let key_short = store.derive_key(&input_short);
    store
        .check_and_claim(&key_short, &input_short, 100)
        .unwrap();

    let input_default = make_input("default_comp", "t2", 0);
    let key_default = store.derive_key(&input_default);
    store
        .check_and_claim(&key_default, &input_default, 100)
        .unwrap();

    assert_eq!(store.entry_count(), 2);

    // At tick 160: short_ttl entry (created at 100, TTL 50) expired at 150.
    // Default entry (created at 100, TTL 600) still active.
    store.evict_all_expired(160);
    assert_eq!(store.entry_count(), 1);
}

#[test]
fn evict_all_expired_removes_multiple() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    for i in 0..5 {
        let input = make_input(&format!("comp_{i}"), &format!("t-{i}"), 0);
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
    }
    assert_eq!(store.entry_count(), 5);

    // All created at tick 100 with default TTL 600 -> expire at 700.
    store.evict_all_expired(800);
    assert_eq!(store.entry_count(), 0);
}

#[test]
fn evict_all_expired_keeps_fresh_entries() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();

    store.evict_all_expired(100); // Just created, should not be evicted
    assert_eq!(store.entry_count(), 1);
}

// =========================================================================
// Section 8: Retry workflow (fail then retry with new attempt)
// =========================================================================

#[test]
fn retry_after_failure_produces_new_key() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());

    // Attempt 0
    let input0 = make_input("comp", "t", 0);
    let key0 = store.derive_key(&input0);
    store.check_and_claim(&key0, &input0, 100).unwrap();
    store.mark_failed(&key0, "timeout").unwrap();

    // Attempt 1 produces a different key (attempt_number is part of derivation)
    let input1 = make_input("comp", "t", 1);
    let key1 = store.derive_key(&input1);
    assert_ne!(key0.key_hash, key1.key_hash);

    let result = store.check_and_claim(&key1, &input1, 101).unwrap();
    assert!(matches!(result, DedupResult::New));
}

#[test]
fn full_retry_sequence_until_success() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());

    // Attempts 0, 1 fail; attempt 2 succeeds
    for attempt in 0..2 {
        let input = make_input("comp", "t", attempt);
        let key = store.derive_key(&input);
        let r = store
            .check_and_claim(&key, &input, 100 + u64::from(attempt))
            .unwrap();
        assert!(matches!(r, DedupResult::New));
        store.mark_failed(&key, &format!("err_{attempt}")).unwrap();
    }

    // Attempt 2: success
    let input2 = make_input("comp", "t", 2);
    let key2 = store.derive_key(&input2);
    let r2 = store.check_and_claim(&key2, &input2, 102).unwrap();
    assert!(matches!(r2, DedupResult::New));
    store.mark_completed(&key2, result_hash(b"final")).unwrap();

    // Re-check attempt 2 returns cached
    let r2_again = store.check_and_claim(&key2, &input2, 103).unwrap();
    assert!(matches!(r2_again, DedupResult::CachedResult { .. }));
}

#[test]
fn checking_old_failed_attempt_returns_previously_failed() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input0 = make_input("comp", "t", 0);
    let key0 = store.derive_key(&input0);
    store.check_and_claim(&key0, &input0, 100).unwrap();
    store.mark_failed(&key0, "network_error").unwrap();

    // Re-checking the same failed key returns PreviouslyFailed
    let r = store.check_and_claim(&key0, &input0, 101).unwrap();
    if let DedupResult::PreviouslyFailed { error_code } = r {
        assert_eq!(error_code, "network_error");
    } else {
        panic!("expected PreviouslyFailed");
    }
}

// =========================================================================
// Section 9: Audit events
// =========================================================================

#[test]
fn check_and_claim_emits_event_for_new() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp_x", "trace-42", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "dedup_check");
    assert_eq!(events[0].dedup_result, "new");
    assert_eq!(events[0].computation_name, "comp_x");
    assert_eq!(events[0].trace_id, "trace-42");
    assert_eq!(events[0].attempt, 0);
    assert_eq!(events[0].epoch_id, 1);
}

#[test]
fn check_and_claim_emits_event_for_cached() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_completed(&key, result_hash(b"out")).unwrap();
    store.drain_events(); // clear grant event

    store.check_and_claim(&key, &input, 101).unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dedup_result, "cached");
}

#[test]
fn check_and_claim_emits_event_for_duplicate_in_progress() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.drain_events();

    store.check_and_claim(&key, &input, 101).unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dedup_result, "duplicate_in_progress");
}

#[test]
fn check_and_claim_emits_event_for_previously_failed() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();
    store.mark_failed(&key, "err").unwrap();
    store.drain_events();

    store.check_and_claim(&key, &input, 101).unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dedup_result, "previously_failed");
}

#[test]
fn drain_events_clears_buffer() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    store.check_and_claim(&key, &input, 100).unwrap();

    let e1 = store.drain_events();
    assert_eq!(e1.len(), 1);
    let e2 = store.drain_events();
    assert!(e2.is_empty());
}

#[test]
fn result_counts_accumulate() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);

    store.check_and_claim(&key, &input, 100).unwrap(); // new
    store.check_and_claim(&key, &input, 101).unwrap(); // duplicate_in_progress
    store.check_and_claim(&key, &input, 102).unwrap(); // duplicate_in_progress again

    store.mark_completed(&key, result_hash(b"r")).unwrap();
    store.check_and_claim(&key, &input, 103).unwrap(); // cached
    store.check_and_claim(&key, &input, 104).unwrap(); // cached

    assert_eq!(store.result_counts().get("new"), Some(&1));
    assert_eq!(store.result_counts().get("duplicate_in_progress"), Some(&2));
    assert_eq!(store.result_counts().get("cached"), Some(&2));
}

#[test]
fn error_cases_do_not_emit_events() {
    let mut store = IdempotencyStore::new(epoch(2), session_key());
    let input = make_input("comp", "t", 0);
    let old_key = derive_idempotency_key(&session_key(), epoch(1), &input);
    let _ = store.check_and_claim(&old_key, &input, 100); // epoch mismatch error
    let events = store.drain_events();
    assert!(
        events.is_empty(),
        "epoch mismatch should not emit events, got {} events",
        events.len()
    );
}

// =========================================================================
// Section 10: Serde round-trips
// =========================================================================

#[test]
fn idempotency_key_serde_roundtrip() {
    let key = derive_idempotency_key(&session_key(), epoch(7), &make_input("comp", "t", 2));
    let json = serde_json::to_string(&key).unwrap();
    let restored: IdempotencyKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, restored);
    assert_eq!(key.to_hex(), restored.to_hex());
}

#[test]
fn key_derivation_input_serde_roundtrip() {
    let input = KeyDerivationInput {
        computation_name: "revoke_cert".to_string(),
        input_hash: input_hash(b"cert-data"),
        trace_id: "trace-99".to_string(),
        attempt_number: 5,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: KeyDerivationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

#[test]
fn dedup_status_serde_roundtrip_all_variants() {
    let variants = [
        DedupStatus::InProgress,
        DedupStatus::Completed {
            result_hash: result_hash(b"result-bytes"),
        },
        DedupStatus::Failed {
            error_code: "ETIMEOUT".to_string(),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: DedupStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn dedup_entry_serde_roundtrip() {
    let entry = DedupEntry {
        status: DedupStatus::Completed {
            result_hash: result_hash(b"data"),
        },
        computation_name: "sync_op".to_string(),
        created_at_ticks: 12345,
        epoch: epoch(3),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: DedupEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn dedup_result_serde_roundtrip_all_variants() {
    let variants = [
        DedupResult::New,
        DedupResult::CachedResult {
            result_hash: result_hash(b"cached"),
        },
        DedupResult::DuplicateInProgress,
        DedupResult::PreviouslyFailed {
            error_code: "ERR_CONN".to_string(),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: DedupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn idempotency_event_serde_roundtrip() {
    let event = IdempotencyEvent {
        idempotency_key_hash: "abcdef0123456789".to_string(),
        computation_name: "revoke".to_string(),
        attempt: 2,
        dedup_result: "new".to_string(),
        trace_id: "trace-alpha".to_string(),
        epoch_id: 5,
        event: "dedup_check".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: IdempotencyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn idempotency_error_serde_roundtrip_all_variants() {
    let variants = [
        IdempotencyError::EpochMismatch {
            key_epoch: epoch(1),
            current_epoch: epoch(5),
        },
        IdempotencyError::MaxRetriesExceeded {
            computation_name: "sync".to_string(),
            max_retries: 7,
            attempt: 8,
        },
        IdempotencyError::DuplicateInProgress {
            computation_name: "op".to_string(),
        },
        IdempotencyError::EntryNotFound {
            key_hex: "0x1234".to_string(),
        },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: IdempotencyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn retry_config_serde_roundtrip() {
    let cfg = RetryConfig {
        max_retries: 10,
        entry_ttl_ticks: 9999,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RetryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

#[test]
fn retry_config_default_serde_roundtrip() {
    let cfg = RetryConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RetryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// Section 11: Deterministic replay
// =========================================================================

#[test]
fn deterministic_replay_same_sequence_same_results() {
    // Two stores with identical configuration should produce identical results.
    let run = |store: &mut IdempotencyStore| -> Vec<String> {
        let mut results = Vec::new();
        for i in 0..5 {
            let input = make_input(&format!("comp_{i}"), &format!("t-{i}"), 0);
            let key = store.derive_key(&input);
            let r = store.check_and_claim(&key, &input, 100 + i).unwrap();
            results.push(r.to_string());
        }
        results
    };

    let mut store1 = IdempotencyStore::new(epoch(1), session_key());
    let mut store2 = IdempotencyStore::new(epoch(1), session_key());
    let results1 = run(&mut store1);
    let results2 = run(&mut store2);
    assert_eq!(results1, results2);
}

#[test]
fn deterministic_key_derivation_across_stores() {
    let input = make_input("deterministic_comp", "trace-det", 0);
    let store1 = IdempotencyStore::new(epoch(1), session_key());
    let store2 = IdempotencyStore::new(epoch(1), session_key());
    assert_eq!(store1.derive_key(&input), store2.derive_key(&input));
}

#[test]
fn deterministic_event_replay() {
    let run = |store: &mut IdempotencyStore| -> Vec<IdempotencyEvent> {
        let input = make_input("comp", "t", 0);
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, 100).unwrap();
        store.mark_completed(&key, result_hash(b"out")).unwrap();
        store.check_and_claim(&key, &input, 101).unwrap();
        store.drain_events()
    };

    let mut s1 = IdempotencyStore::new(epoch(1), session_key());
    let mut s2 = IdempotencyStore::new(epoch(1), session_key());
    let events1 = run(&mut s1);
    let events2 = run(&mut s2);
    assert_eq!(events1.len(), events2.len());
    for (e1, e2) in events1.iter().zip(events2.iter()) {
        assert_eq!(e1.idempotency_key_hash, e2.idempotency_key_hash);
        assert_eq!(e1.dedup_result, e2.dedup_result);
    }
}

// =========================================================================
// Section 12: Full lifecycle scenarios
// =========================================================================

#[test]
fn full_lifecycle_derive_claim_complete_cache_hit() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("revocation_propagate", "trace-001", 0);

    // 1. Derive key
    let key = store.derive_key(&input);
    assert_eq!(key.epoch, epoch(1));

    // 2. Check — new
    let r1 = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(r1, DedupResult::New));

    // 3. Complete
    store.mark_completed(&key, result_hash(b"result")).unwrap();

    // 4. Cache hit
    let r2 = store.check_and_claim(&key, &input, 101).unwrap();
    if let DedupResult::CachedResult { result_hash: rh } = r2 {
        assert_eq!(rh, result_hash(b"result"));
    } else {
        panic!("expected CachedResult");
    }

    // 5. Events
    let events = store.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].dedup_result, "new");
    assert_eq!(events[1].dedup_result, "cached");
}

#[test]
fn full_lifecycle_fail_retry_succeed() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());

    // Attempt 0: fail
    let input0 = make_input("sync_data", "trace-A", 0);
    let key0 = store.derive_key(&input0);
    store.check_and_claim(&key0, &input0, 100).unwrap();
    store.mark_failed(&key0, "ECONNRESET").unwrap();

    // Attempt 1: succeed
    let input1 = make_input("sync_data", "trace-A", 1);
    let key1 = store.derive_key(&input1);
    let r = store.check_and_claim(&key1, &input1, 200).unwrap();
    assert!(matches!(r, DedupResult::New));
    store
        .mark_completed(&key1, result_hash(b"success"))
        .unwrap();

    // Cache hit on attempt 1 key
    let r2 = store.check_and_claim(&key1, &input1, 201).unwrap();
    assert!(matches!(r2, DedupResult::CachedResult { .. }));
}

#[test]
fn full_lifecycle_epoch_transition() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());

    // Epoch 1: claim and complete
    let input = make_input("comp", "t", 0);
    let key1 = store.derive_key(&input);
    store.check_and_claim(&key1, &input, 100).unwrap();
    store.mark_completed(&key1, result_hash(b"r1")).unwrap();

    // Advance epoch
    store.advance_epoch(epoch(2), b"new-session-key".to_vec());
    assert_eq!(store.entry_count(), 0);

    // Epoch 2: same computation, re-derive, returns New
    let key2 = store.derive_key(&input);
    assert_ne!(key1.key_hash, key2.key_hash); // different epoch produces different key
    let r = store.check_and_claim(&key2, &input, 200).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn concurrent_computations_with_mixed_outcomes() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());

    // Three computations running in parallel
    let inputs: Vec<_> = (0..3)
        .map(|i| make_input(&format!("parallel_{i}"), &format!("trace-{i}"), 0))
        .collect();
    let keys: Vec<_> = inputs.iter().map(|inp| store.derive_key(inp)).collect();

    // All claim
    for (key, input) in keys.iter().zip(inputs.iter()) {
        let r = store.check_and_claim(key, input, 100).unwrap();
        assert!(matches!(r, DedupResult::New));
    }
    assert_eq!(store.entry_count(), 3);

    // Mixed outcomes: 0=completed, 1=failed, 2=still in-progress
    store
        .mark_completed(&keys[0], result_hash(b"out-0"))
        .unwrap();
    store.mark_failed(&keys[1], "ERR_1").unwrap();

    // Re-check each
    let r0 = store.check_and_claim(&keys[0], &inputs[0], 101).unwrap();
    assert!(matches!(r0, DedupResult::CachedResult { .. }));

    let r1 = store.check_and_claim(&keys[1], &inputs[1], 101).unwrap();
    assert!(matches!(r1, DedupResult::PreviouslyFailed { .. }));

    let r2 = store.check_and_claim(&keys[2], &inputs[2], 101).unwrap();
    assert!(matches!(r2, DedupResult::DuplicateInProgress));
}

// =========================================================================
// Section 13: Edge cases
// =========================================================================

#[test]
fn empty_computation_name() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("", "t", 0);
    let key = store.derive_key(&input);
    let r = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn empty_trace_id() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "", 0);
    let key = store.derive_key(&input);
    let r = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn very_large_attempt_number_within_config() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.set_retry_config(
        "permissive",
        RetryConfig {
            max_retries: u32::MAX,
            entry_ttl_ticks: 600,
        },
    );
    let input = make_input("permissive", "t", u32::MAX);
    let key = store.derive_key(&input);
    let r = store.check_and_claim(&key, &input, 100).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn genesis_epoch_works() {
    let mut store = IdempotencyStore::new(SecurityEpoch::GENESIS, session_key());
    assert_eq!(store.epoch(), SecurityEpoch::GENESIS);
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    let r = store.check_and_claim(&key, &input, 0).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn zero_tick_works() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    let input = make_input("comp", "t", 0);
    let key = store.derive_key(&input);
    let r = store.check_and_claim(&key, &input, 0).unwrap();
    assert!(matches!(r, DedupResult::New));
}

#[test]
fn large_number_of_entries() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    for i in 0..100 {
        let input = make_input(&format!("comp_{i}"), &format!("t-{i}"), 0);
        let key = store.derive_key(&input);
        store.check_and_claim(&key, &input, i).unwrap();
    }
    assert_eq!(store.entry_count(), 100);
}

#[test]
fn overwrite_retry_config() {
    let mut store = IdempotencyStore::new(epoch(1), session_key());
    store.set_retry_config(
        "comp",
        RetryConfig {
            max_retries: 1,
            entry_ttl_ticks: 100,
        },
    );
    store.set_retry_config(
        "comp",
        RetryConfig {
            max_retries: 10,
            entry_ttl_ticks: 5000,
        },
    );
    assert_eq!(store.retry_config("comp").max_retries, 10);
    assert_eq!(store.retry_config("comp").entry_ttl_ticks, 5000);
}
