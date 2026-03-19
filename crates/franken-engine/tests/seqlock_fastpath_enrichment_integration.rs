//! Enrichment integration tests for the `seqlock_fastpath` module.
//!
//! Deep coverage of RetryBudgetPolicy, FastPathReadSource, FastPathFallbackReason,
//! FastPathReadResult, FastPathTelemetry, SnapshotFastPath — serde, concurrency,
//! telemetry invariants, seed/publish interactions.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::sync::Arc;
use std::thread;

use frankenengine_engine::seqlock_fastpath::{
    FastPathFallbackReason, FastPathReadResult, FastPathReadSource, FastPathTelemetry,
    RetryBudgetPolicy, SnapshotFastPath,
};

// ---------------------------------------------------------------------------
// RetryBudgetPolicy — extended serde and const
// ---------------------------------------------------------------------------

#[test]
fn enrich_policy_const_new() {
    const P: RetryBudgetPolicy = RetryBudgetPolicy::new(10, 5);
    assert_eq!(P.max_retries, 10);
    assert_eq!(P.max_writer_pressure_observations, 5);
}

#[test]
fn enrich_policy_serde_various() {
    for (r, p) in [(0, 0), (1, 1), (u32::MAX, u32::MAX), (5, 3)] {
        let policy = RetryBudgetPolicy::new(r, p);
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetryBudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}

#[test]
fn enrich_policy_debug_contains_values() {
    let p = RetryBudgetPolicy::new(12, 7);
    let dbg = format!("{p:?}");
    assert!(dbg.contains("12"));
    assert!(dbg.contains("7"));
}

#[test]
fn enrich_policy_copy_semantics() {
    let p = RetryBudgetPolicy::new(3, 2);
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn enrich_policy_ne_different_retries() {
    let a = RetryBudgetPolicy::new(3, 2);
    let b = RetryBudgetPolicy::new(5, 2);
    assert_ne!(a, b);
}

#[test]
fn enrich_policy_ne_different_pressure() {
    let a = RetryBudgetPolicy::new(3, 2);
    let b = RetryBudgetPolicy::new(3, 4);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// FastPathReadSource — serde with snake_case
// ---------------------------------------------------------------------------

#[test]
fn enrich_read_source_serde_fast_path() {
    let src = FastPathReadSource::FastPath;
    let json = serde_json::to_string(&src).unwrap();
    assert_eq!(json, r#""fast_path""#);
    let back: FastPathReadSource = serde_json::from_str(&json).unwrap();
    assert_eq!(back, FastPathReadSource::FastPath);
}

#[test]
fn enrich_read_source_serde_fallback() {
    let src = FastPathReadSource::Fallback;
    let json = serde_json::to_string(&src).unwrap();
    assert_eq!(json, r#""fallback""#);
    let back: FastPathReadSource = serde_json::from_str(&json).unwrap();
    assert_eq!(back, FastPathReadSource::Fallback);
}

#[test]
fn enrich_read_source_copy_semantics() {
    let s = FastPathReadSource::FastPath;
    let s2 = s;
    assert_eq!(s, s2);
}

// ---------------------------------------------------------------------------
// FastPathFallbackReason — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_fallback_reason_serde_all() {
    let variants = [
        (
            FastPathFallbackReason::RetryBudgetExceeded,
            "\"retry_budget_exceeded\"",
        ),
        (FastPathFallbackReason::Uninitialized, "\"uninitialized\""),
        (
            FastPathFallbackReason::WriterPressure,
            "\"writer_pressure\"",
        ),
    ];
    for (reason, expected_json) in &variants {
        let json = serde_json::to_string(reason).unwrap();
        assert_eq!(json, *expected_json);
        let back: FastPathFallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn enrich_fallback_reason_debug_all() {
    for reason in [
        FastPathFallbackReason::RetryBudgetExceeded,
        FastPathFallbackReason::Uninitialized,
        FastPathFallbackReason::WriterPressure,
    ] {
        let dbg = format!("{reason:?}");
        assert!(!dbg.is_empty());
    }
}

// ---------------------------------------------------------------------------
// FastPathReadResult — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_read_result_serde_fast_path_u64() {
    let result = FastPathReadResult {
        value: 42_u64,
        source: FastPathReadSource::FastPath,
        attempts: 0,
        writer_pressure_observations: 0,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FastPathReadResult<u64> = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrich_read_result_serde_fallback_string() {
    let result = FastPathReadResult {
        value: "fallback".to_string(),
        source: FastPathReadSource::Fallback,
        attempts: 3,
        writer_pressure_observations: 1,
        fallback_reason: Some(FastPathFallbackReason::RetryBudgetExceeded),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FastPathReadResult<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrich_read_result_serde_vec_value() {
    let result: FastPathReadResult<Vec<u32>> = FastPathReadResult {
        value: vec![10, 20, 30],
        source: FastPathReadSource::FastPath,
        attempts: 0,
        writer_pressure_observations: 0,
        fallback_reason: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: FastPathReadResult<Vec<u32>> = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrich_read_result_clone_equals() {
    let result = FastPathReadResult {
        value: "clone-me".to_string(),
        source: FastPathReadSource::Fallback,
        attempts: 1,
        writer_pressure_observations: 2,
        fallback_reason: Some(FastPathFallbackReason::WriterPressure),
    };
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

// ---------------------------------------------------------------------------
// FastPathTelemetry — serde and Copy
// ---------------------------------------------------------------------------

#[test]
fn enrich_telemetry_serde_all_zeros() {
    let t = FastPathTelemetry {
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
    let json = serde_json::to_string(&t).unwrap();
    let back: FastPathTelemetry = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrich_telemetry_serde_large_values() {
    let t = FastPathTelemetry {
        total_reads: u64::MAX,
        fast_path_reads: u64::MAX - 1,
        fallback_reads: 1,
        total_retries: 999_999,
        writer_pressure_observations: 42,
        retry_budget_fallbacks: 10,
        uninitialized_fallbacks: 0,
        writer_pressure_fallbacks: 32,
        writes: 1_000_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: FastPathTelemetry = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrich_telemetry_copy_semantics() {
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

// ---------------------------------------------------------------------------
// SnapshotFastPath — construction and initial state
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_initial_not_initialized() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    assert!(!fp.is_initialized());
    assert_eq!(fp.policy(), RetryBudgetPolicy::new(3, 2));
}

#[test]
fn enrich_fp_initial_telemetry_zeros() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 0);
    assert_eq!(t.fast_path_reads, 0);
    assert_eq!(t.fallback_reads, 0);
    assert_eq!(t.writes, 0);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — publish and read
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_publish_then_read() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(42_u64);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 42);
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(r.fallback_reason, None);
    assert_eq!(r.attempts, 0);
}

#[test]
fn enrich_fp_multiple_publishes_latest_wins() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    for i in 0..10u64 {
        fp.publish(i);
    }
    let r = fp.read_clone_or_else(|| 999);
    assert_eq!(r.value, 9);
    assert_eq!(fp.telemetry().writes, 10);
}

#[test]
fn enrich_fp_publish_marks_initialized() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    assert!(!fp.is_initialized());
    fp.publish(1_u64);
    assert!(fp.is_initialized());
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — uninitialized fallback
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_uninit_fallback() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let r = fp.read_clone_or_else(|| 999);
    assert_eq!(r.value, 999);
    assert_eq!(r.source, FastPathReadSource::Fallback);
    assert_eq!(
        r.fallback_reason,
        Some(FastPathFallbackReason::Uninitialized)
    );
}

#[test]
fn enrich_fp_uninit_telemetry() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    for _ in 0..5 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, 5);
    assert_eq!(t.uninitialized_fallbacks, 5);
    assert_eq!(t.fallback_reads, 5);
    assert_eq!(t.fast_path_reads, 0);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — seed_if_uninitialized
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_seed_first_true_second_false() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    assert!(fp.seed_if_uninitialized(100_u64));
    assert!(!fp.seed_if_uninitialized(200_u64));
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 100);
}

#[test]
fn enrich_fp_seed_no_write_count() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(42_u64);
    assert_eq!(fp.telemetry().writes, 0);
}

#[test]
fn enrich_fp_seed_reads_via_fast_path() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(77_u64);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(r.value, 77);
}

#[test]
fn enrich_fp_publish_after_seed_overrides() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.seed_if_uninitialized(10_u64);
    fp.publish(20);
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 20);
    assert_eq!(fp.telemetry().writes, 1);
}

#[test]
fn enrich_fp_seed_after_publish_is_noop() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(30_u64);
    assert!(!fp.seed_if_uninitialized(40));
    let r = fp.read_clone_or_else(|| 0);
    assert_eq!(r.value, 30);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — telemetry invariants
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_telemetry_reads_invariant() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
    let _ = fp.read_clone_or_else(|| 0_u64);
    fp.publish(1);
    for _ in 0..3 {
        let _ = fp.read_clone_or_else(|| 0);
    }
    let t = fp.telemetry();
    assert_eq!(t.total_reads, t.fast_path_reads + t.fallback_reads);
}

#[test]
fn enrich_fp_telemetry_accumulates() {
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
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — clone and equality
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_clone_preserves_policy_resets_state() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(7, 4));
    fp.publish(42_u64);
    let _ = fp.read_clone_or_else(|| 0);

    let cloned = fp.clone();
    assert_eq!(cloned.policy(), RetryBudgetPolicy::new(7, 4));
    assert!(!cloned.is_initialized());
    let t = cloned.telemetry();
    assert_eq!(t.total_reads, 0);
    assert_eq!(t.writes, 0);
}

#[test]
fn enrich_fp_equality_based_on_policy() {
    let a: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let b: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    let c: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(5, 1));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn enrich_fp_eq_reflexive() {
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert_eq!(fp, fp);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — different value types
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_string_type() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish("hello".to_string());
    let r = fp.read_clone_or_else(|| "default".to_string());
    assert_eq!(r.value, "hello");
}

#[test]
fn enrich_fp_vec_type() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(vec![1u32, 2, 3]);
    let r = fp.read_clone_or_else(Vec::new);
    assert_eq!(r.value, vec![1, 2, 3]);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath — concurrent reads
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_concurrent_reads_after_publish() {
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
        h.join().unwrap();
    }
    assert_eq!(fp.telemetry().total_reads, 8);
}

#[test]
fn enrich_fp_concurrent_seed_only_one_succeeds() {
    let fp = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2)));
    let barrier = Arc::new(std::sync::Barrier::new(4));

    let handles: Vec<_> = (0..4u64)
        .map(|i| {
            let fp = Arc::clone(&fp);
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait();
                fp.seed_if_uninitialized(i)
            })
        })
        .collect();

    let successes: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(successes.iter().filter(|&&s| s).count(), 1);
    assert!(fp.is_initialized());
}

// ---------------------------------------------------------------------------
// Fallback closure behavior
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_fallback_not_called_on_fast_path() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = Arc::new(AtomicU32::new(0));
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));
    fp.publish(1_u64);

    let c = Arc::clone(&counter);
    let r = fp.read_clone_or_else(|| {
        c.fetch_add(1, Ordering::Relaxed);
        0_u64
    });
    assert_eq!(r.source, FastPathReadSource::FastPath);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn enrich_fp_fallback_called_once_on_uninit() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let counter = Arc::new(AtomicU32::new(0));
    let fp: SnapshotFastPath<u64> = SnapshotFastPath::new(RetryBudgetPolicy::new(3, 2));

    let c = Arc::clone(&counter);
    let r = fp.read_clone_or_else(|| {
        c.fetch_add(1, Ordering::Relaxed);
        42_u64
    });
    assert_eq!(r.source, FastPathReadSource::Fallback);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert_eq!(r.value, 42);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_deterministic_telemetry() {
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
// Sequential publishes
// ---------------------------------------------------------------------------

#[test]
fn enrich_fp_sequential_publishes_visible() {
    let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
    for i in 0..30u64 {
        fp.publish(i);
        let result = fp.read_clone_or_else(|| u64::MAX);
        assert_eq!(result.value, i);
    }
    assert_eq!(fp.telemetry().writes, 30);
    assert_eq!(fp.telemetry().total_reads, 30);
}
