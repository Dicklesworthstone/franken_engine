//! Sequence lock fast path implementation for lock-free reads.
//!
//! Provides optimistic read access patterns with retry budgets and writer
//! pressure detection. Enables high-performance concurrent data structure
//! access with minimal contention overhead.

use std::hint;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudgetPolicy {
    pub max_retries: u32,
    pub max_writer_pressure_observations: u32,
}

impl RetryBudgetPolicy {
    pub const fn new(max_retries: u32, max_writer_pressure_observations: u32) -> Self {
        Self {
            max_retries,
            max_writer_pressure_observations,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPathReadSource {
    FastPath,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastPathFallbackReason {
    RetryBudgetExceeded,
    Uninitialized,
    WriterPressure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPathReadResult<T> {
    pub value: T,
    pub source: FastPathReadSource,
    pub attempts: u32,
    pub writer_pressure_observations: u32,
    pub fallback_reason: Option<FastPathFallbackReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastPathTelemetry {
    pub total_reads: u64,
    pub fast_path_reads: u64,
    pub fallback_reads: u64,
    pub total_retries: u64,
    pub writer_pressure_observations: u64,
    pub retry_budget_fallbacks: u64,
    pub uninitialized_fallbacks: u64,
    pub writer_pressure_fallbacks: u64,
    pub writes: u64,
}

#[derive(Debug)]
pub struct SnapshotFastPath<T> {
    policy: RetryBudgetPolicy,
    initialized: AtomicBool,
    sequence: AtomicU64,
    writer_gate: Mutex<()>,
    snapshot: RwLock<Option<T>>,
    total_reads: AtomicU64,
    fast_path_reads: AtomicU64,
    fallback_reads: AtomicU64,
    total_retries: AtomicU64,
    writer_pressure_observations: AtomicU64,
    retry_budget_fallbacks: AtomicU64,
    uninitialized_fallbacks: AtomicU64,
    writer_pressure_fallbacks: AtomicU64,
    writes: AtomicU64,
}

struct SequencePublishGuard<'a> {
    sequence: &'a AtomicU64,
    final_sequence: u64,
}

std::thread_local! {
    static ACTIVE_SNAPSHOT_PUBLISHES: std::cell::RefCell<Vec<usize>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct ReentrantPublishGuard {
    key: usize,
}

impl ReentrantPublishGuard {
    fn enter<T>(fast_path: &SnapshotFastPath<T>) -> Self {
        let key = fast_path as *const SnapshotFastPath<T> as usize;
        ACTIVE_SNAPSHOT_PUBLISHES.with(|active_publishes| {
            let mut active_publishes = active_publishes.borrow_mut();
            assert!(
                !active_publishes.contains(&key),
                "SnapshotFastPath publish hook must not re-enter publish on the same fast path"
            );
            active_publishes.push(key);
        });
        Self { key }
    }
}

impl Drop for ReentrantPublishGuard {
    fn drop(&mut self) {
        ACTIVE_SNAPSHOT_PUBLISHES.with(|active_publishes| {
            let mut active_publishes = active_publishes.borrow_mut();
            if let Some(index) = active_publishes
                .iter()
                .rposition(|active_key| *active_key == self.key)
            {
                active_publishes.remove(index);
            }
        });
    }
}

impl Drop for SequencePublishGuard<'_> {
    fn drop(&mut self) {
        self.sequence.store(self.final_sequence, Ordering::Release);
    }
}

impl<T> SnapshotFastPath<T> {
    pub const fn policy(&self) -> RetryBudgetPolicy {
        self.policy
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub fn new(policy: RetryBudgetPolicy) -> Self {
        Self {
            policy,
            initialized: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            writer_gate: Mutex::new(()),
            snapshot: RwLock::new(None),
            total_reads: AtomicU64::new(0),
            fast_path_reads: AtomicU64::new(0),
            fallback_reads: AtomicU64::new(0),
            total_retries: AtomicU64::new(0),
            writer_pressure_observations: AtomicU64::new(0),
            retry_budget_fallbacks: AtomicU64::new(0),
            uninitialized_fallbacks: AtomicU64::new(0),
            writer_pressure_fallbacks: AtomicU64::new(0),
            writes: AtomicU64::new(0),
        }
    }

    fn lock_writer_gate(&self) -> MutexGuard<'_, ()> {
        self.writer_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot_read(&self) -> RwLockReadGuard<'_, Option<T>> {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot_write(&self) -> RwLockWriteGuard<'_, Option<T>> {
        self.snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Seed a known baseline snapshot without counting it as a runtime write.
    pub fn seed_if_uninitialized(&self, initial: T) -> bool {
        if self.is_initialized() {
            return false;
        }

        let _reentrant_guard = ReentrantPublishGuard::enter(self);
        let _writer_guard = self.lock_writer_gate();
        if self.is_initialized() {
            return false;
        }

        *self.snapshot_write() = Some(initial);
        self.initialized.store(true, Ordering::Release);
        true
    }

    pub fn publish(&self, next: T) {
        self.publish_with_hook(next, || {});
    }

    pub(crate) fn publish_with_hook<F>(&self, next: T, on_odd_sequence: F)
    where
        F: FnOnce(),
    {
        let _reentrant_guard = ReentrantPublishGuard::enter(self);
        let _writer_guard = self.lock_writer_gate();
        let start = self.sequence.load(Ordering::Acquire);
        // Treat any observed odd value as a stale in-progress marker and restart
        // this publish cycle from the last stable even epoch.
        let stable_start = start & !1;
        let final_sequence = stable_start.wrapping_add(2);
        self.sequence
            .store(stable_start.wrapping_add(1), Ordering::Release);
        let _sequence_guard = SequencePublishGuard {
            sequence: &self.sequence,
            final_sequence,
        };
        on_odd_sequence();
        *self.snapshot_write() = Some(next);
        self.initialized.store(true, Ordering::Release);
        self.writes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn telemetry(&self) -> FastPathTelemetry {
        FastPathTelemetry {
            total_reads: self.total_reads.load(Ordering::Relaxed),
            fast_path_reads: self.fast_path_reads.load(Ordering::Relaxed),
            fallback_reads: self.fallback_reads.load(Ordering::Relaxed),
            total_retries: self.total_retries.load(Ordering::Relaxed),
            writer_pressure_observations: self.writer_pressure_observations.load(Ordering::Relaxed),
            retry_budget_fallbacks: self.retry_budget_fallbacks.load(Ordering::Relaxed),
            uninitialized_fallbacks: self.uninitialized_fallbacks.load(Ordering::Relaxed),
            writer_pressure_fallbacks: self.writer_pressure_fallbacks.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
        }
    }
}

impl<T: Clone> SnapshotFastPath<T> {
    pub fn read_clone_or_else<F>(&self, fallback: F) -> FastPathReadResult<T>
    where
        F: FnOnce() -> T,
    {
        self.total_reads.fetch_add(1, Ordering::Relaxed);

        if !self.initialized.load(Ordering::Acquire) {
            self.uninitialized_fallbacks.fetch_add(1, Ordering::Relaxed);
            self.fallback_reads.fetch_add(1, Ordering::Relaxed);
            return FastPathReadResult {
                value: fallback(),
                source: FastPathReadSource::Fallback,
                attempts: 0,
                writer_pressure_observations: 0,
                fallback_reason: Some(FastPathFallbackReason::Uninitialized),
            };
        }

        let mut attempts = 0;
        let mut writer_pressure_observations = 0;
        loop {
            let start = self.sequence.load(Ordering::Acquire);
            if !start.is_multiple_of(2) {
                writer_pressure_observations += 1;
                self.total_retries.fetch_add(1, Ordering::Relaxed);
                self.writer_pressure_observations
                    .fetch_add(1, Ordering::Relaxed);
                if writer_pressure_observations > self.policy.max_writer_pressure_observations {
                    self.writer_pressure_fallbacks
                        .fetch_add(1, Ordering::Relaxed);
                    self.fallback_reads.fetch_add(1, Ordering::Relaxed);
                    return FastPathReadResult {
                        value: fallback(),
                        source: FastPathReadSource::Fallback,
                        attempts,
                        writer_pressure_observations,
                        fallback_reason: Some(FastPathFallbackReason::WriterPressure),
                    };
                }
                hint::spin_loop();
                continue;
            }

            let cloned = self.snapshot_read().clone();
            let end = self.sequence.load(Ordering::Acquire);
            if start == end && end.is_multiple_of(2) {
                if let Some(value) = cloned {
                    self.fast_path_reads.fetch_add(1, Ordering::Relaxed);
                    return FastPathReadResult {
                        value,
                        source: FastPathReadSource::FastPath,
                        attempts,
                        writer_pressure_observations,
                        fallback_reason: None,
                    };
                }

                self.uninitialized_fallbacks.fetch_add(1, Ordering::Relaxed);
                self.fallback_reads.fetch_add(1, Ordering::Relaxed);
                return FastPathReadResult {
                    value: fallback(),
                    source: FastPathReadSource::Fallback,
                    attempts,
                    writer_pressure_observations,
                    fallback_reason: Some(FastPathFallbackReason::Uninitialized),
                };
            }

            attempts += 1;
            self.total_retries.fetch_add(1, Ordering::Relaxed);
            if attempts > self.policy.max_retries {
                self.retry_budget_fallbacks.fetch_add(1, Ordering::Relaxed);
                self.fallback_reads.fetch_add(1, Ordering::Relaxed);
                return FastPathReadResult {
                    value: fallback(),
                    source: FastPathReadSource::Fallback,
                    attempts,
                    writer_pressure_observations,
                    fallback_reason: Some(FastPathFallbackReason::RetryBudgetExceeded),
                };
            }
            hint::spin_loop();
        }
    }
}

impl<T> Clone for SnapshotFastPath<T> {
    fn clone(&self) -> Self {
        Self::new(self.policy)
    }
}

impl<T> PartialEq for SnapshotFastPath<T> {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
    }
}

impl<T> Eq for SnapshotFastPath<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn published_snapshot_reads_from_fast_path() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(41_u64);

        let result = fast_path.read_clone_or_else(|| 99_u64);

        assert_eq!(result.value, 41);
        assert_eq!(result.source, FastPathReadSource::FastPath);
        assert_eq!(result.fallback_reason, None);

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.fast_path_reads, 1);
        assert_eq!(telemetry.fallback_reads, 0);
        assert_eq!(telemetry.writes, 1);
    }

    #[test]
    fn writer_pressure_falls_back_after_budget_is_exhausted() {
        let fast_path = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(1, 0)));
        fast_path.publish(7_u64);

        let barrier = Arc::new(Barrier::new(2));
        let writer_fast_path = Arc::clone(&fast_path);
        let writer_barrier = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            writer_fast_path.publish_with_hook(11_u64, || {
                writer_barrier.wait();
                thread::sleep(Duration::from_millis(10));
            });
        });

        barrier.wait();
        let result = fast_path.read_clone_or_else(|| 99_u64);
        handle.join().expect("writer thread should finish");

        assert_eq!(result.source, FastPathReadSource::Fallback);
        assert_eq!(
            result.fallback_reason,
            Some(FastPathFallbackReason::WriterPressure)
        );
        assert_eq!(result.value, 99_u64);

        let telemetry = fast_path.telemetry();
        assert!(telemetry.writer_pressure_observations >= 1);
        assert_eq!(telemetry.writer_pressure_fallbacks, 1);
    }

    #[test]
    fn clone_and_equality_ignore_runtime_caches() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(5_u64);

        let cloned = fast_path.clone();

        assert_eq!(fast_path, cloned);
        assert_eq!(cloned.policy(), RetryBudgetPolicy::new(2, 1));
    }

    // ── RetryBudgetPolicy ───────────────────────────────────────────

    #[test]
    fn retry_budget_policy_serde_round_trip() {
        let policy = RetryBudgetPolicy::new(5, 3);
        // SAFETY: Test-only unwrap for serde serialization of known valid struct
        let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
        // SAFETY: Test-only unwrap for serde deserialization of valid JSON roundtrip
        let back: RetryBudgetPolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(policy, back);
    }

    #[test]
    fn retry_budget_policy_const_new() {
        const P: RetryBudgetPolicy = RetryBudgetPolicy::new(10, 5);
        assert_eq!(P.max_retries, 10);
        assert_eq!(P.max_writer_pressure_observations, 5);
    }

    // ── enum serde ──────────────────────────────────────────────────

    #[test]
    fn fast_path_read_source_serde_round_trip() {
        for source in [FastPathReadSource::FastPath, FastPathReadSource::Fallback] {
            // SAFETY: Test-only unwrap for serde serialization of known valid enum variants
            let json =
                serde_json::to_string(&source).expect("serde deserialization should succeed");
            // SAFETY: Test-only unwrap for serde deserialization of valid JSON roundtrip
            let back: FastPathReadSource =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(source, back);
        }
    }

    #[test]
    fn fast_path_fallback_reason_serde_round_trip() {
        for reason in [
            FastPathFallbackReason::RetryBudgetExceeded,
            FastPathFallbackReason::Uninitialized,
            FastPathFallbackReason::WriterPressure,
        ] {
            // SAFETY: FastPathFallbackReason derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json =
                serde_json::to_string(&reason).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by to_string of a valid FastPathFallbackReason,
            // so from_str back to FastPathFallbackReason cannot fail (valid format + matching schema).
            let back: FastPathFallbackReason =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(reason, back);
        }
    }

    // ── FastPathReadResult serde ─────────────────────────────────────

    #[test]
    fn fast_path_read_result_serde_round_trip() {
        let result = FastPathReadResult {
            value: 42_u64,
            source: FastPathReadSource::FastPath,
            attempts: 1,
            writer_pressure_observations: 0,
            fallback_reason: None,
        };
        // SAFETY: FastPathReadResult derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by to_string of a valid FastPathReadResult,
        // so from_str back to FastPathReadResult cannot fail (valid format + matching schema).
        let back: FastPathReadResult<u64> =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    // ── FastPathTelemetry serde ──────────────────────────────────────

    #[test]
    fn fast_path_telemetry_serde_round_trip() {
        let telemetry = FastPathTelemetry {
            total_reads: 10,
            fast_path_reads: 7,
            fallback_reads: 3,
            total_retries: 2,
            writer_pressure_observations: 1,
            retry_budget_fallbacks: 1,
            uninitialized_fallbacks: 2,
            writer_pressure_fallbacks: 0,
            writes: 5,
        };
        // SAFETY: FastPathTelemetry derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&telemetry).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by valid FastPathTelemetry serialization
        let back: FastPathTelemetry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(telemetry, back);
    }

    // ── uninitialized reads ─────────────────────────────────────────

    #[test]
    fn uninitialized_fast_path_falls_back() {
        let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        let result = fast_path.read_clone_or_else(|| 999_u64);

        assert_eq!(result.value, 999);
        assert_eq!(result.source, FastPathReadSource::Fallback);
        assert_eq!(
            result.fallback_reason,
            Some(FastPathFallbackReason::Uninitialized)
        );
    }

    #[test]
    fn uninitialized_telemetry_counts_correctly() {
        let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        let _ = fast_path.read_clone_or_else(|| 0);
        let _ = fast_path.read_clone_or_else(|| 0);

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.total_reads, 2);
        assert_eq!(telemetry.uninitialized_fallbacks, 2);
        assert_eq!(telemetry.fallback_reads, 2);
        assert_eq!(telemetry.fast_path_reads, 0);
        assert_eq!(telemetry.writes, 0);
    }

    // ── seed_if_uninitialized ───────────────────────────────────────

    #[test]
    fn seed_if_uninitialized_succeeds_on_first_call() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        assert!(!fast_path.is_initialized());
        assert!(fast_path.seed_if_uninitialized(10_u64));
        assert!(fast_path.is_initialized());
    }

    #[test]
    fn seed_if_uninitialized_is_no_op_after_first_seed() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        assert!(fast_path.seed_if_uninitialized(10_u64));
        assert!(!fast_path.seed_if_uninitialized(20_u64));

        let result = fast_path.read_clone_or_else(|| 99);
        assert_eq!(result.value, 10);
    }

    #[test]
    fn seed_if_uninitialized_is_no_op_after_publish() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(30_u64);
        assert!(!fast_path.seed_if_uninitialized(40_u64));

        let result = fast_path.read_clone_or_else(|| 99);
        assert_eq!(result.value, 30);
    }

    #[test]
    fn seed_does_not_count_as_write() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.seed_if_uninitialized(1_u64);
        assert_eq!(fast_path.telemetry().writes, 0);
    }

    // ── publish ─────────────────────────────────────────────────────

    #[test]
    fn publish_overwrites_previous_value() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(1_u64);
        fast_path.publish(2_u64);
        fast_path.publish(3_u64);

        let result = fast_path.read_clone_or_else(|| 99);
        assert_eq!(result.value, 3);
        assert_eq!(fast_path.telemetry().writes, 3);
    }

    #[test]
    fn publish_marks_initialized() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        assert!(!fast_path.is_initialized());
        fast_path.publish(42_u64);
        assert!(fast_path.is_initialized());
    }

    // ── telemetry accounting ────────────────────────────────────────

    #[test]
    fn fresh_telemetry_is_all_zeros() {
        let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.total_reads, 0);
        assert_eq!(telemetry.fast_path_reads, 0);
        assert_eq!(telemetry.fallback_reads, 0);
        assert_eq!(telemetry.total_retries, 0);
        assert_eq!(telemetry.writer_pressure_observations, 0);
        assert_eq!(telemetry.retry_budget_fallbacks, 0);
        assert_eq!(telemetry.uninitialized_fallbacks, 0);
        assert_eq!(telemetry.writer_pressure_fallbacks, 0);
        assert_eq!(telemetry.writes, 0);
    }

    #[test]
    fn fast_path_read_increments_correct_counters() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(10_u64);
        let _ = fast_path.read_clone_or_else(|| 0);

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.total_reads, 1);
        assert_eq!(telemetry.fast_path_reads, 1);
        assert_eq!(telemetry.fallback_reads, 0);
    }

    // ── clone resets runtime state ──────────────────────────────────

    #[test]
    fn clone_does_not_carry_published_value() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(42_u64);
        let cloned = fast_path.clone();

        assert!(!cloned.is_initialized());
        let result = cloned.read_clone_or_else(|| 99);
        assert_eq!(result.value, 99);
        assert_eq!(result.source, FastPathReadSource::Fallback);
    }

    #[test]
    fn clone_preserves_policy() {
        let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(7, 3));
        let cloned = fast_path.clone();
        assert_eq!(cloned.policy(), RetryBudgetPolicy::new(7, 3));
    }

    // ── equality ────────────────────────────────────────────────────

    #[test]
    fn equality_based_on_policy_only() {
        let a = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        let b = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        let c = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(3, 1));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── concurrent read after publish ───────────────────────────────

    #[test]
    fn multiple_reads_all_see_latest_publish() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
        fast_path.publish(100_u64);

        for _ in 0..10 {
            let result = fast_path.read_clone_or_else(|| 0);
            assert_eq!(result.value, 100);
            assert_eq!(result.source, FastPathReadSource::FastPath);
        }

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.total_reads, 10);
        assert_eq!(telemetry.fast_path_reads, 10);
    }

    // ── multi-threaded concurrent reads ─────────────────────────────

    #[test]
    fn concurrent_reads_after_single_publish() {
        let fast_path = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(8, 4)));
        fast_path.publish(777_u64);

        let mut handles = Vec::new();
        for _ in 0..4 {
            let fp = Arc::clone(&fast_path);
            handles.push(thread::spawn(move || {
                let mut fast_count = 0u64;
                for _ in 0..50 {
                    let result = fp.read_clone_or_else(|| 0);
                    assert_eq!(result.value, 777);
                    if result.source == FastPathReadSource::FastPath {
                        fast_count += 1;
                    }
                }
                fast_count
            }));
        }

        // SAFETY: Thread handles are from test-spawned threads that should complete without panic.
        // This test controls the thread lifetime and only joins after worker completion.
        let total_fast: u64 = handles
            .into_iter()
            .map(|h| h.join().expect("serde deserialization should succeed"))
            .sum();
        // With no concurrent writer, all reads should be fast-path.
        assert_eq!(total_fast, 200);
        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.total_reads, 200);
    }

    // ── publish sequence monotonicity ───────────────────────────────

    #[test]
    fn sequential_publishes_always_visible_to_reader() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));

        for i in 0..20u64 {
            fast_path.publish(i);
            let result = fast_path.read_clone_or_else(|| u64::MAX);
            assert_eq!(result.value, i, "read after publish {i} must see {i}");
            assert_eq!(result.source, FastPathReadSource::FastPath);
        }

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.writes, 20);
        assert_eq!(telemetry.total_reads, 20);
        assert_eq!(telemetry.fast_path_reads, 20);
    }

    #[test]
    fn publish_wraps_sequence_without_panicking_at_u64_edge() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
        fast_path.seed_if_uninitialized(7_u64);
        fast_path.sequence.store(u64::MAX - 1, Ordering::Release);

        fast_path.publish(11_u64);

        let result = fast_path.read_clone_or_else(|| 0);
        assert_eq!(result.value, 11);
        assert_eq!(result.source, FastPathReadSource::FastPath);
        assert_eq!(fast_path.sequence.load(Ordering::Acquire), 0);
    }

    #[test]
    fn panicking_publish_hook_does_not_brick_future_publishes() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
        fast_path.seed_if_uninitialized(7_u64);

        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Test-only panic to intentionally test panic recovery in publish hook
            fast_path.publish_with_hook(11_u64, || panic!("boom"));
        }));
        assert!(panic_result.is_err());

        assert_eq!(fast_path.sequence.load(Ordering::Acquire), 2);

        let after_panic = fast_path.read_clone_or_else(|| 0);
        assert_eq!(after_panic.value, 7);
        assert_eq!(after_panic.source, FastPathReadSource::FastPath);

        fast_path.publish(13_u64);

        let after_recovery = fast_path.read_clone_or_else(|| 0);
        assert_eq!(after_recovery.value, 13);
        assert_eq!(after_recovery.source, FastPathReadSource::FastPath);
        assert_eq!(fast_path.telemetry().writes, 1);
    }

    #[test]
    fn reentrant_publish_hook_panics_without_self_deadlocking() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
        fast_path.seed_if_uninitialized(7_u64);

        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            fast_path.publish_with_hook(11_u64, || {
                fast_path.publish(13_u64);
            });
        }));
        assert!(panic_result.is_err());
        assert_eq!(fast_path.sequence.load(Ordering::Acquire), 2);

        let after_reentrant_attempt = fast_path.read_clone_or_else(|| 0);
        assert_eq!(after_reentrant_attempt.value, 7);
        assert_eq!(after_reentrant_attempt.source, FastPathReadSource::FastPath);

        fast_path.publish(17_u64);

        let after_recovery = fast_path.read_clone_or_else(|| 0);
        assert_eq!(after_recovery.value, 17);
        assert_eq!(after_recovery.source, FastPathReadSource::FastPath);
        assert_eq!(fast_path.telemetry().writes, 1);
    }

    #[test]
    fn reentrant_seed_hook_panics_without_self_deadlocking() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));

        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            fast_path.publish_with_hook(11_u64, || {
                fast_path.seed_if_uninitialized(13_u64);
            });
        }));
        assert!(panic_result.is_err());
        assert!(!fast_path.is_initialized());

        assert!(fast_path.seed_if_uninitialized(17_u64));
        let after_recovery = fast_path.read_clone_or_else(|| 0);
        assert_eq!(after_recovery.value, 17);
        assert_eq!(after_recovery.source, FastPathReadSource::FastPath);
    }

    #[test]
    fn odd_start_publish_normalizes_to_writer_pressure_then_even_commit() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 0));
        fast_path.seed_if_uninitialized(7_u64);
        fast_path.sequence.store(1, Ordering::Release);

        let during_write = RefCell::new(None);
        fast_path.publish_with_hook(11_u64, || {
            assert_eq!(fast_path.sequence.load(Ordering::Acquire), 1);
            *during_write.borrow_mut() = Some(fast_path.read_clone_or_else(|| 99_u64));
        });

        let during_write = during_write
            .into_inner()
            .expect("during-write probe should observe the publish state");
        assert_eq!(during_write.value, 99);
        assert_eq!(during_write.source, FastPathReadSource::Fallback);
        assert_eq!(
            during_write.fallback_reason,
            Some(FastPathFallbackReason::WriterPressure)
        );
        assert_eq!(fast_path.sequence.load(Ordering::Acquire), 2);

        let after_publish = fast_path.read_clone_or_else(|| 0_u64);
        assert_eq!(after_publish.value, 11);
        assert_eq!(after_publish.source, FastPathReadSource::FastPath);
    }

    // ── seed + publish interaction ──────────────────────────────────

    #[test]
    fn seed_then_publish_updates_value() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.seed_if_uninitialized(100_u64);

        let r1 = fast_path.read_clone_or_else(|| 0);
        assert_eq!(r1.value, 100);

        fast_path.publish(200_u64);
        let r2 = fast_path.read_clone_or_else(|| 0);
        assert_eq!(r2.value, 200);

        // Seed doesn't count as write, publish does.
        assert_eq!(fast_path.telemetry().writes, 1);
    }

    // ── telemetry accumulation ──────────────────────────────────────

    #[test]
    fn telemetry_accumulates_across_mixed_operations() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));

        // 2 uninitialized fallback reads
        let _ = fast_path.read_clone_or_else(|| 0_u64);
        let _ = fast_path.read_clone_or_else(|| 0_u64);

        // 1 publish
        fast_path.publish(42);

        // 3 fast-path reads
        for _ in 0..3 {
            let _ = fast_path.read_clone_or_else(|| 0);
        }

        let t = fast_path.telemetry();
        assert_eq!(t.total_reads, 5);
        assert_eq!(t.uninitialized_fallbacks, 2);
        assert_eq!(t.fallback_reads, 2);
        assert_eq!(t.fast_path_reads, 3);
        assert_eq!(t.writes, 1);
    }

    // ── RetryBudgetPolicy edge cases ────────────────────────────────

    #[test]
    fn retry_budget_zero_retries() {
        let policy = RetryBudgetPolicy::new(0, 0);
        assert_eq!(policy.max_retries, 0);
        assert_eq!(policy.max_writer_pressure_observations, 0);
    }

    #[test]
    fn retry_budget_large_values() {
        let policy = RetryBudgetPolicy::new(u32::MAX, u32::MAX);
        assert_eq!(policy.max_retries, u32::MAX);
        assert_eq!(policy.max_writer_pressure_observations, u32::MAX);
    }

    // ── FastPathReadResult fields ───────────────────────────────────

    #[test]
    fn read_result_fallback_with_reason() {
        let result = FastPathReadResult {
            value: 0_u64,
            source: FastPathReadSource::Fallback,
            attempts: 5,
            writer_pressure_observations: 3,
            fallback_reason: Some(FastPathFallbackReason::RetryBudgetExceeded),
        };
        assert_eq!(result.source, FastPathReadSource::Fallback);
        assert_eq!(result.attempts, 5);
        assert_eq!(result.writer_pressure_observations, 3);
        assert_eq!(
            result.fallback_reason,
            Some(FastPathFallbackReason::RetryBudgetExceeded)
        );
    }

    #[test]
    fn read_result_fast_path_no_fallback_reason() {
        let result = FastPathReadResult {
            value: 42_u64,
            source: FastPathReadSource::FastPath,
            attempts: 0,
            writer_pressure_observations: 0,
            fallback_reason: None,
        };
        assert!(result.fallback_reason.is_none());
    }

    // ── FastPathTelemetry invariants ────────────────────────────────

    #[test]
    fn telemetry_reads_sum_invariant() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));

        // Some fallback reads
        let _ = fast_path.read_clone_or_else(|| 0_u64);

        // Publish + fast-path reads
        fast_path.publish(1);
        let _ = fast_path.read_clone_or_else(|| 0);
        let _ = fast_path.read_clone_or_else(|| 0);
        let _ = fast_path.read_clone_or_else(|| 0);

        let t = fast_path.telemetry();
        // total_reads = fast_path_reads + fallback_reads
        assert_eq!(t.total_reads, t.fast_path_reads + t.fallback_reads);
    }

    // ── String snapshot type ────────────────────────────────────────

    #[test]
    fn works_with_string_type() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish("hello".to_string());

        let result = fast_path.read_clone_or_else(|| "fallback".to_string());
        assert_eq!(result.value, "hello");
        assert_eq!(result.source, FastPathReadSource::FastPath);
    }

    #[test]
    fn works_with_vec_type() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fast_path.publish(vec![1, 2, 3]);

        let result = fast_path.read_clone_or_else(std::vec::Vec::new);
        assert_eq!(result.value, vec![1, 2, 3]);
    }

    // ── concurrent seed_if_uninitialized ────────────────────────────

    #[test]
    fn concurrent_seed_only_one_succeeds() {
        let fast_path = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2)));
        let barrier = Arc::new(Barrier::new(4));

        let mut handles = Vec::new();
        for i in 0..4u64 {
            let fp = Arc::clone(&fast_path);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                fp.seed_if_uninitialized(i)
            }));
        }

        // SAFETY: Thread handles are from test-spawned threads that should complete without panic.
        // This test controls the thread lifetime and only joins after worker completion.
        let successes: Vec<bool> = handles
            .into_iter()
            .map(|h| h.join().expect("serde deserialization should succeed"))
            .collect();
        // Exactly one thread should succeed.
        assert_eq!(successes.iter().filter(|&&s| s).count(), 1);
        assert!(fast_path.is_initialized());
    }

    // ── concurrent publish + read ───────────────────────────────────

    #[test]
    fn concurrent_writer_reader_no_panic() {
        let fast_path = Arc::new(SnapshotFastPath::new(RetryBudgetPolicy::new(8, 4)));
        fast_path.publish(0_u64);

        let writer_fp = Arc::clone(&fast_path);
        let writer = thread::spawn(move || {
            for i in 1..=100u64 {
                writer_fp.publish(i);
            }
        });

        let reader_fp = Arc::clone(&fast_path);
        let reader = thread::spawn(move || {
            let mut reads = 0u64;
            for _ in 0..200 {
                let result = reader_fp.read_clone_or_else(|| 0);
                assert!(result.value <= 100, "value must be within published range");
                reads += 1;
            }
            reads
        });

        // SAFETY: Test thread without panic paths; join() will succeed
        writer.join().expect("serde deserialization should succeed");
        // SAFETY: Test thread without panic paths; join() will succeed
        let total_reads = reader.join().expect("serde deserialization should succeed");
        assert_eq!(total_reads, 200);

        let t = fast_path.telemetry();
        assert_eq!(t.writes, 101); // 1 initial + 100 from writer thread
        assert_eq!(t.total_reads, 200);
    }

    // ── policy accessor ─────────────────────────────────────────────

    #[test]
    fn policy_accessor_returns_construction_policy() {
        let policy = RetryBudgetPolicy::new(11, 7);
        let fp = SnapshotFastPath::<u64>::new(policy);
        assert_eq!(fp.policy(), policy);
    }

    // ── is_initialized transitions ──────────────────────────────────

    #[test]
    fn is_initialized_false_until_publish_or_seed() {
        let fp = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
        assert!(!fp.is_initialized());

        // Reading doesn't initialize
        let _ = fp.read_clone_or_else(|| 0);
        assert!(!fp.is_initialized());
    }

    #[test]
    fn is_initialized_true_after_seed() {
        let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fp.seed_if_uninitialized(42_u64);
        assert!(fp.is_initialized());
    }

    #[test]
    fn is_initialized_true_after_publish() {
        let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        fp.publish(42_u64);
        assert!(fp.is_initialized());
    }

    // ── seed then multiple reads ────────────────────────────────────

    #[test]
    fn seeded_value_survives_multiple_reads() {
        let fp = SnapshotFastPath::new(RetryBudgetPolicy::new(4, 2));
        fp.seed_if_uninitialized(55_u64);

        for _ in 0..10 {
            let r = fp.read_clone_or_else(|| 0);
            assert_eq!(r.value, 55);
            assert_eq!(r.source, FastPathReadSource::FastPath);
        }
    }
}
