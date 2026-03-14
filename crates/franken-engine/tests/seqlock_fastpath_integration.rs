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

use frankenengine_engine::seqlock_fastpath::{
    FastPathFallbackReason, FastPathReadResult, FastPathReadSource, FastPathTelemetry,
    RetryBudgetPolicy, SnapshotFastPath,
};

// ---------------------------------------------------------------------------
// 1. RetryBudgetPolicy — construction and serde
// ---------------------------------------------------------------------------

#[test]
fn retry_budget_policy_construction() {
    let policy = RetryBudgetPolicy::new(5, 3);
    assert_eq!(policy.max_retries, 5);
    assert_eq!(policy.max_writer_pressure_observations, 3);
}

#[test]
fn retry_budget_policy_serde_round_trip() {
    let policy = RetryBudgetPolicy::new(10, 7);
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: RetryBudgetPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, restored);
}

#[test]
fn retry_budget_policy_serde_from_literal_json() {
    let json = r#"{"max_retries":4,"max_writer_pressure_observations":2}"#;
    let policy: RetryBudgetPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(policy.max_retries, 4);
    assert_eq!(policy.max_writer_pressure_observations, 2);
}

// ---------------------------------------------------------------------------
// 2. FastPathReadSource — serde
// ---------------------------------------------------------------------------

#[test]
fn fast_path_read_source_serde_fast_path() {
    let src = FastPathReadSource::FastPath;
    let json = serde_json::to_string(&src).expect("serialize");
    assert_eq!(json, r#""fast_path""#);
    let restored: FastPathReadSource = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, FastPathReadSource::FastPath);
}

#[test]
fn fast_path_read_source_serde_fallback() {
    let src = FastPathReadSource::Fallback;
    let json = serde_json::to_string(&src).expect("serialize");
    assert_eq!(json, r#""fallback""#);
    let restored: FastPathReadSource = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, FastPathReadSource::Fallback);
}

// ---------------------------------------------------------------------------
// 3. FastPathFallbackReason — serde
// ---------------------------------------------------------------------------

#[test]
fn fallback_reason_serde_retry_budget_exceeded() {
    let reason = FastPathFallbackReason::RetryBudgetExceeded;
    let json = serde_json::to_string(&reason).expect("serialize");
    assert_eq!(json, r#""retry_budget_exceeded""#);
    let restored: FastPathFallbackReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, FastPathFallbackReason::RetryBudgetExceeded);
}

#[test]
fn fallback_reason_serde_uninitialized() {
    let reason = FastPathFallbackReason::Uninitialized;
    let json = serde_json::to_string(&reason).expect("serialize");
    assert_eq!(json, r#""uninitialized""#);
    let restored: FastPathFallbackReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, FastPathFallbackReason::Uninitialized);
}

// ---------------------------------------------------------------------------
// 4. FastPathReadResult — serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn fast_path_read_result_serde_with_fallback_reason() {
    let result = FastPathReadResult {
        value: 42_u64,
        source: FastPathReadSource::Fallback,
        attempts: 3,
        writer_pressure_observations: 1,
        fallback_reason: Some(FastPathFallbackReason::RetryBudgetExceeded),
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: FastPathReadResult<u64> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn fast_path_read_result_serde_without_fallback_reason() {
    let result = FastPathReadResult {
        value: String::from("hello"),
        source: FastPathReadSource::FastPath,
        attempts: 0,
        writer_pressure_observations: 0,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: FastPathReadResult<String> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// 5. FastPathTelemetry — serde round-trip and all fields
// ---------------------------------------------------------------------------

#[test]
fn fast_path_telemetry_serde_round_trip() {
    let telemetry = FastPathTelemetry {
        total_reads: 100,
        fast_path_reads: 80,
        fallback_reads: 20,
        total_retries: 5,
        writer_pressure_observations: 2,
        retry_budget_fallbacks: 1,
        uninitialized_fallbacks: 15,
        writer_pressure_fallbacks: 4,
        writes: 10,
    };
    let json = serde_json::to_string(&telemetry).expect("serialize");
    let restored: FastPathTelemetry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(telemetry, restored);
}

#[test]
fn fast_path_telemetry_all_fields_zero() {
    let telemetry = FastPathTelemetry {
        total_reads: 0,
        fast_path_reads: 0,
        fallback_reads: 0,
        total_retries: 0,
        writer_pressure_observations: 0,
        retry_budget_fallbacks: 0,
        uninitialized_fallbacks: 0,
        writer_pressure_fallbacks: 0,
        writes: 0,
    };
    let json = serde_json::to_string(&telemetry).expect("serialize");
    let restored: FastPathTelemetry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(telemetry, restored);
    assert_eq!(restored.total_reads, 0);
    assert_eq!(restored.writes, 0);
}

// ---------------------------------------------------------------------------
// 6. SnapshotFastPath — construction and initial state
// ---------------------------------------------------------------------------

#[test]
fn snapshot_fast_path_initial_state() {
    let policy = RetryBudgetPolicy::new(3, 2);
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(policy);
    assert!(!fp.is_initialized());
    assert_eq!(fp.policy(), policy);
}

#[test]
fn snapshot_fast_path_initial_telemetry_is_zero() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 0);
    assert_eq!(t.fast_path_reads, 0);
    assert_eq!(t.fallback_reads, 0);
    assert_eq!(t.total_retries, 0);
    assert_eq!(t.writer_pressure_observations, 0);
    assert_eq!(t.retry_budget_fallbacks, 0);
    assert_eq!(t.uninitialized_fallbacks, 0);
    assert_eq!(t.writer_pressure_fallbacks, 0);
    assert_eq!(t.writes, 0);
}

// ---------------------------------------------------------------------------
// 7. Read before publish falls back with Uninitialized
// ---------------------------------------------------------------------------

#[test]
fn read_before_publish_returns_fallback_value() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let result = fp.read_clone_or_else(|| 999);
    assert_eq!(result.value, 999);
    assert_eq!(result.source, FastPathReadSource::Fallback);
    assert_eq!(
        result.fallback_reason,
        Some(FastPathFallbackReason::Uninitialized)
    );
}

#[test]
fn read_before_publish_telemetry_counts_uninitialized_fallback() {
    let fp: SnapshotFastPath<String> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let _result = fp.read_clone_or_else(|| String::from("default"));
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 1);
    assert_eq!(t.fallback_reads, 1);
    assert_eq!(t.uninitialized_fallbacks, 1);
    assert_eq!(t.fast_path_reads, 0);
}

// ---------------------------------------------------------------------------
// 8. Publish then read succeeds via fast path
// ---------------------------------------------------------------------------

#[test]
fn publish_then_read_returns_published_value() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(42_u64);
    let result = fp.read_clone_or_else(|| 0);
    assert_eq!(result.value, 42);
    assert_eq!(result.source, FastPathReadSource::FastPath);
    assert_eq!(result.fallback_reason, None);
}

#[test]
fn publish_marks_initialized() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    assert!(!fp.is_initialized());
    fp.publish(1_u64);
    assert!(fp.is_initialized());
}

// ---------------------------------------------------------------------------
// 9. Multiple publishes: latest value wins
// ---------------------------------------------------------------------------

#[test]
fn multiple_publishes_latest_value_wins() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(1_u64);
    fp.publish(2_u64);
    fp.publish(3_u64);
    let result = fp.read_clone_or_else(|| 0);
    assert_eq!(result.value, 3);
    assert_eq!(result.source, FastPathReadSource::FastPath);
}

// ---------------------------------------------------------------------------
// 10. seed_if_uninitialized: first true, second false
// ---------------------------------------------------------------------------

#[test]
fn seed_if_uninitialized_first_call_returns_true() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let first = fp.seed_if_uninitialized(100_u64);
    assert!(first);
    assert!(fp.is_initialized());
    let result = fp.read_clone_or_else(|| 0);
    assert_eq!(result.value, 100);
}

#[test]
fn seed_if_uninitialized_second_call_returns_false() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let first = fp.seed_if_uninitialized(100_u64);
    let second = fp.seed_if_uninitialized(200_u64);
    assert!(first);
    assert!(!second);
    // Value stays at the first seed
    let result = fp.read_clone_or_else(|| 0);
    assert_eq!(result.value, 100);
}

// ---------------------------------------------------------------------------
// 11. Seed then publish: publish value wins
// ---------------------------------------------------------------------------

#[test]
fn seed_then_publish_publish_value_wins() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(100_u64);
    fp.publish(200_u64);
    let result = fp.read_clone_or_else(|| 0);
    assert_eq!(result.value, 200);
}

// ---------------------------------------------------------------------------
// 12. Telemetry counts: reads, writes, fallbacks
// ---------------------------------------------------------------------------

#[test]
fn telemetry_counts_reads_after_publish() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(10_u64);
    for _ in 0..5 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 5);
    assert_eq!(t.fast_path_reads, 5);
    assert_eq!(t.fallback_reads, 0);
}

#[test]
fn telemetry_counts_writes() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(1_u64);
    fp.publish(2_u64);
    fp.publish(3_u64);
    let t = fp.telemetry();
    assert_eq!(t.writes, 3);
}

#[test]
fn telemetry_counts_uninitialized_fallbacks() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    for _ in 0..4 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 4);
    assert_eq!(t.fallback_reads, 4);
    assert_eq!(t.uninitialized_fallbacks, 4);
    assert_eq!(t.fast_path_reads, 0);
}

// ---------------------------------------------------------------------------
// 13. Clone resets state, preserves policy
// ---------------------------------------------------------------------------

#[test]
fn clone_preserves_policy() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(7, 4));
    fp.publish(42_u64);
    let cloned = fp.clone();
    assert_eq!(cloned.policy(), RetryBudgetPolicy::new(7, 4));
}

#[test]
fn clone_resets_initialization_and_telemetry() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(42_u64);
    let _ = fp.read_clone_or_else(|| 0);

    let cloned = fp.clone();
    assert!(!cloned.is_initialized());
    let t = cloned.telemetry();
    assert_eq!(t.total_reads, 0);
    assert_eq!(t.fast_path_reads, 0);
    assert_eq!(t.writes, 0);

    // Reading from clone should fall back since it's uninitialized
    let result = cloned.read_clone_or_else(|| 999_u64);
    assert_eq!(result.value, 999);
    assert_eq!(
        result.fallback_reason,
        Some(FastPathFallbackReason::Uninitialized)
    );
}

// ---------------------------------------------------------------------------
// 14. PartialEq: same policy equal, different policy not equal
// ---------------------------------------------------------------------------

#[test]
fn partial_eq_same_policy() {
    let fp1: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let fp2: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    assert_eq!(fp1, fp2);

    // Even after different operations, they remain equal (policy-only comparison)
    fp1.publish(42);
    assert_eq!(fp1, fp2);
}

#[test]
fn partial_eq_different_policy() {
    let fp1: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let fp2: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(5, 1));
    assert_ne!(fp1, fp2);
}

// ---------------------------------------------------------------------------
// 15. Multiple reads accumulate telemetry correctly
// ---------------------------------------------------------------------------

#[test]
fn multiple_reads_mixed_uninitialized_then_fast_path() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    // 3 reads while uninitialized
    for _ in 0..3 {
        let _ = fp.read_clone_or_else(|| 0_u64);
    }
    fp.publish(42);
    // 2 reads after publish
    for _ in 0..2 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 5);
    assert_eq!(t.uninitialized_fallbacks, 3);
    assert_eq!(t.fallback_reads, 3);
    assert_eq!(t.fast_path_reads, 2);
    assert_eq!(t.writes, 1);
}

#[test]
fn telemetry_accumulates_across_many_operations() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(10, 5));
    fp.publish(1_u64);
    fp.publish(2);
    for _ in 0..10 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    fp.publish(3);
    for _ in 0..5 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 15);
    assert_eq!(t.fast_path_reads, 15);
    assert_eq!(t.writes, 3);
    assert_eq!(t.fallback_reads, 0);
}

// ---------------------------------------------------------------------------
// 16. Determinism: same operations produce same telemetry
// ---------------------------------------------------------------------------

#[test]
fn deterministic_telemetry_for_identical_operations() {
    let run = || {
        let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
        let _ = fp.read_clone_or_else(|| 0_u64);
        fp.publish(10);
        let _ = fp.read_clone_or_else(|| 0);
        let _ = fp.read_clone_or_else(|| 0);
        fp.publish(20);
        let _ = fp.read_clone_or_else(|| 0);
        fp.telemetry()
    };
    let t1 = run();
    let t2 = run();
    assert_eq!(t1, t2);
}

// ---------------------------------------------------------------------------
// 17. FastPathReadResult fields for fast path vs fallback
// ---------------------------------------------------------------------------

#[test]
fn read_result_fields_fast_path_case() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(77_u64);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 77);
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(r.attempts, 0);
    assert_eq!(r.writer_pressure_observations, 0);
    assert_eq!(r.fallback_reason, None);
}

#[test]
fn read_result_fields_fallback_uninitialized_case() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let r = fp.read_clone_or_else(|| 55);
    assert_eq!(r.value, 55);
    assert_eq!(r.source, FastPathReadSource::Fallback);
    assert_eq!(r.attempts, 0);
    assert_eq!(r.writer_pressure_observations, 0);
    assert_eq!(
        r.fallback_reason,
        Some(FastPathFallbackReason::Uninitialized)
    );
}

// ---------------------------------------------------------------------------
// 18. Various value types (u64, String, Vec)
// ---------------------------------------------------------------------------

#[test]
fn snapshot_fast_path_with_u64() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(u64::MAX);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, u64::MAX);
    assert_eq!(r.source, FastPathReadSource::FastPath);
}

#[test]
fn snapshot_fast_path_with_string() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(String::from("hello world"));
    let r = fp.read_clone_or_else(String::new);
    assert_eq!(r.value, "hello world");
    assert_eq!(r.source, FastPathReadSource::FastPath);
}

#[test]
fn snapshot_fast_path_with_vec() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(vec![1_u32, 2, 3, 4, 5]);
    let r = fp.read_clone_or_else(Vec::new);
    assert_eq!(r.value, vec![1, 2, 3, 4, 5]);
    assert_eq!(r.source, FastPathReadSource::FastPath);
}

// ---------------------------------------------------------------------------
// Additional coverage: seed does not count as a write in telemetry
// ---------------------------------------------------------------------------

#[test]
fn seed_does_not_increment_write_counter() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(42_u64);
    let t = fp.telemetry();
    assert_eq!(t.writes, 0);
}

// ---------------------------------------------------------------------------
// Additional: concurrent reads from Arc-wrapped fast path
// ---------------------------------------------------------------------------

#[test]
fn concurrent_reads_all_see_published_value() {
    use std::sync::Arc;
    use std::thread;

    let fp = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(5, 3)));
    fp.publish(123_u64);

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fp = Arc::clone(&fp);
            thread::spawn(move || {
                let r = fp.read_clone_or_else(|| 0);
                assert_eq!(r.value, 123);
                assert_eq!(r.source, FastPathReadSource::FastPath);
            })
        })
        .collect();

    for h in handles {
        h.join().expect("reader thread panicked");
    }

    let t = fp.telemetry();
    assert_eq!(t.total_reads, 8);
    assert_eq!(t.fast_path_reads, 8);
}

// ---------------------------------------------------------------------------
// Additional: publish after seed overrides seed value and counts as write
// ---------------------------------------------------------------------------

#[test]
fn publish_after_seed_overrides_and_counts_write() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(10_u64);
    fp.publish(20);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 20);
    let t = fp.telemetry();
    assert_eq!(t.writes, 1); // only publish counts
}

// ---------------------------------------------------------------------------
// Additional: FastPathFallbackReason::WriterPressure serde
// ---------------------------------------------------------------------------

#[test]
fn fallback_reason_serde_writer_pressure() {
    let reason = FastPathFallbackReason::WriterPressure;
    let json = serde_json::to_string(&reason).expect("serialize");
    assert_eq!(json, r#""writer_pressure""#);
    let restored: FastPathFallbackReason = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, FastPathFallbackReason::WriterPressure);
}

// ---------------------------------------------------------------------------
// Additional: RetryBudgetPolicy copy semantics
// ---------------------------------------------------------------------------

#[test]
fn retry_budget_policy_is_copy() {
    let policy = RetryBudgetPolicy::new(3, 2);
    let copied = policy;
    // Both are valid after copy
    assert_eq!(policy, copied);
    assert_eq!(policy.max_retries, copied.max_retries);
}

// ---------------------------------------------------------------------------
// New tests — edge cases, Debug formatting, Copy/Clone, invariants
// ---------------------------------------------------------------------------

// 42. Debug formatting of RetryBudgetPolicy contains field values
#[test]
fn test_retry_budget_policy_debug_contains_field_values() {
    let policy = RetryBudgetPolicy::new(12, 7);
    let dbg = format!("{policy:?}");
    assert!(dbg.contains("12"));
    assert!(dbg.contains("7"));
}

// 43. Debug formatting of FastPathReadSource
#[test]
fn test_fast_path_read_source_debug_variants() {
    let fast = format!("{:?}", FastPathReadSource::FastPath);
    let fall = format!("{:?}", FastPathReadSource::Fallback);
    assert!(fast.contains("FastPath"));
    assert!(fall.contains("Fallback"));
}

// 44. Debug formatting of FastPathFallbackReason
#[test]
fn test_fast_path_fallback_reason_debug_variants() {
    let rbe = format!("{:?}", FastPathFallbackReason::RetryBudgetExceeded);
    let uninit = format!("{:?}", FastPathFallbackReason::Uninitialized);
    let wp = format!("{:?}", FastPathFallbackReason::WriterPressure);
    assert!(rbe.contains("RetryBudgetExceeded"));
    assert!(uninit.contains("Uninitialized"));
    assert!(wp.contains("WriterPressure"));
}

// 45. Debug formatting of FastPathReadResult
#[test]
fn test_fast_path_read_result_debug_contains_value() {
    let result = FastPathReadResult {
        value: 55_u64,
        source: FastPathReadSource::FastPath,
        attempts: 2,
        writer_pressure_observations: 1,
        fallback_reason: None,
    };
    let dbg = format!("{result:?}");
    assert!(dbg.contains("55"));
    assert!(dbg.contains("FastPath"));
}

// 46. Debug formatting of FastPathTelemetry
#[test]
fn test_fast_path_telemetry_debug_contains_field_names() {
    let t = FastPathTelemetry {
        total_reads: 99,
        fast_path_reads: 88,
        fallback_reads: 11,
        total_retries: 3,
        writer_pressure_observations: 1,
        retry_budget_fallbacks: 0,
        uninitialized_fallbacks: 11,
        writer_pressure_fallbacks: 0,
        writes: 5,
    };
    let dbg = format!("{t:?}");
    assert!(dbg.contains("99"));
    assert!(dbg.contains("88"));
}

// 47. Debug formatting of SnapshotFastPath
#[test]
fn test_snapshot_fast_path_debug_is_non_empty() {
    let fp = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
    let dbg = format!("{fp:?}");
    assert!(!dbg.is_empty());
}

// 48. FastPathTelemetry Copy: can be copied without moving
#[test]
fn test_fast_path_telemetry_is_copy() {
    let t = FastPathTelemetry {
        total_reads: 5,
        fast_path_reads: 4,
        fallback_reads: 1,
        total_retries: 0,
        writer_pressure_observations: 0,
        retry_budget_fallbacks: 0,
        uninitialized_fallbacks: 1,
        writer_pressure_fallbacks: 0,
        writes: 2,
    };
    let t2 = t;
    assert_eq!(t.total_reads, t2.total_reads);
    assert_eq!(t.writes, t2.writes);
}

// 49. FastPathReadSource Copy semantics
#[test]
fn test_fast_path_read_source_is_copy() {
    let src = FastPathReadSource::FastPath;
    let src2 = src;
    assert_eq!(src, src2);
}

// 50. FastPathFallbackReason Copy semantics
#[test]
fn test_fast_path_fallback_reason_is_copy() {
    let reason = FastPathFallbackReason::RetryBudgetExceeded;
    let reason2 = reason;
    assert_eq!(reason, reason2);
}

// 51. FastPathReadResult Clone produces equal value
#[test]
fn test_fast_path_read_result_clone_equals_original() {
    let result = FastPathReadResult {
        value: String::from("clone-me"),
        source: FastPathReadSource::Fallback,
        attempts: 1,
        writer_pressure_observations: 2,
        fallback_reason: Some(FastPathFallbackReason::WriterPressure),
    };
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

// 52. RetryBudgetPolicy with zero max_retries: read still works (fast path on even sequence)
#[test]
fn test_retry_budget_policy_zero_max_retries_fast_path_works() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(0, 0));
    fp.publish(42_u64);
    let r = fp.read_clone_or_else(|| 0);
    // With a quiescent writer the sequence is even; zero retries still succeeds
    assert_eq!(r.value, 42);
    assert_eq!(r.source, FastPathReadSource::FastPath);
}

// 53. Telemetry invariant: fast_path_reads + fallback_reads == total_reads
#[test]
fn test_telemetry_fast_plus_fallback_equals_total() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    // 2 uninitialized fallbacks
    let _ = fp.read_clone_or_else(|| 0_u64);
    let _ = fp.read_clone_or_else(|| 0_u64);
    fp.publish(7);
    // 3 fast-path reads
    for _ in 0..3 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.fast_path_reads + t.fallback_reads, t.total_reads);
}

// 54. SnapshotFastPath PartialEq is symmetric
#[test]
fn test_snapshot_fast_path_partial_eq_is_symmetric() {
    let fp1: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 3));
    let fp2: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 3));
    assert_eq!(fp1, fp2);
    assert_eq!(fp2, fp1);
}

// 55. SnapshotFastPath Eq reflexivity
#[test]
fn test_snapshot_fast_path_eq_reflexive() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert_eq!(fp, fp);
}

// 56. RetryBudgetPolicy zero-zero is valid and serializes
#[test]
fn test_retry_budget_policy_zero_zero_serde() {
    let policy = RetryBudgetPolicy::new(0, 0);
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: RetryBudgetPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
    assert_eq!(back.max_retries, 0);
    assert_eq!(back.max_writer_pressure_observations, 0);
}

// 57. seed_if_uninitialized: seeded value reads via fast path (not fallback)
#[test]
fn test_seeded_value_reads_from_fast_path() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let seeded = fp.seed_if_uninitialized(77_u64);
    assert!(seeded);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 77);
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(r.fallback_reason, None);
}

// 58. seed does not affect total_reads telemetry counter
#[test]
fn test_seed_does_not_affect_total_reads_counter() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(1_u64);
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 0);
}

// 59. FastPathReadResult serde with nested Vec value
#[test]
fn test_fast_path_read_result_serde_with_vec_value() {
    let result: FastPathReadResult<Vec<u32>> = FastPathReadResult {
        value: vec![10, 20, 30],
        source: FastPathReadSource::FastPath,
        attempts: 0,
        writer_pressure_observations: 0,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let back: FastPathReadResult<Vec<u32>> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, back);
    assert_eq!(back.value, vec![10, 20, 30]);
}

// 60. Many sequential publishes all increment write counter correctly
#[test]
fn test_many_sequential_publishes_increment_writes() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(5, 3));
    for i in 0_u64..20 {
        fp.publish(i);
    }
    let t = fp.telemetry();
    assert_eq!(t.writes, 20);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 19); // last published value
}

// 61. FastPathTelemetry PartialEq: identical structs are equal
#[test]
fn test_fast_path_telemetry_partial_eq() {
    let t1 = FastPathTelemetry {
        total_reads: 7,
        fast_path_reads: 5,
        fallback_reads: 2,
        total_retries: 1,
        writer_pressure_observations: 0,
        retry_budget_fallbacks: 1,
        uninitialized_fallbacks: 1,
        writer_pressure_fallbacks: 0,
        writes: 3,
    };
    let t2 = t1;
    assert_eq!(t1, t2);
}

// 62. RetryBudgetPolicy PartialEq reflexive
#[test]
fn test_retry_budget_policy_partial_eq_reflexive() {
    let p = RetryBudgetPolicy::new(8, 4);
    assert_eq!(p, p);
}

// 63. RetryBudgetPolicy PartialEq: different max_writer_pressure_observations are not equal
#[test]
fn test_retry_budget_policy_partial_eq_different_pressure() {
    let p1 = RetryBudgetPolicy::new(5, 2);
    let p2 = RetryBudgetPolicy::new(5, 3);
    assert_ne!(p1, p2);
}

// 64. SnapshotFastPath PartialEq: different max_retries differ
#[test]
fn test_snapshot_fast_path_partial_eq_different_max_retries() {
    let fp1: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(1, 2));
    let fp2: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(9, 2));
    assert_ne!(fp1, fp2);
}

// 65. Fallback closure is not called on a successful fast-path read
#[test]
fn test_fallback_closure_not_called_on_fast_path() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let counter = Arc::new(AtomicU32::new(0));
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(1_u64);

    let counter_clone = Arc::clone(&counter);
    let r = fp.read_clone_or_else(|| {
        counter_clone.fetch_add(1, Ordering::Relaxed);
        0_u64
    });
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

// 66. Fallback closure is called exactly once on uninitialized read
#[test]
fn test_fallback_closure_called_once_on_uninitialized() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let counter = Arc::new(AtomicU32::new(0));
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));

    let counter_clone = Arc::clone(&counter);
    let r = fp.read_clone_or_else(|| {
        counter_clone.fetch_add(1, Ordering::Relaxed);
        42_u64
    });
    assert_eq!(r.source, FastPathReadSource::Fallback);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert_eq!(r.value, 42);
}

// 67. FastPathReadResult attempts field is zero for a clean fast-path read
#[test]
fn test_fast_path_read_attempts_is_zero_on_clean_read() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(5, 3));
    fp.publish(100_u64);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.attempts, 0);
    assert_eq!(r.writer_pressure_observations, 0);
}
