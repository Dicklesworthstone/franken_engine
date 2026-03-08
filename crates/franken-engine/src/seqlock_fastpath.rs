use std::hint;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

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

    /// Seed a known baseline snapshot without counting it as a runtime write.
    pub fn seed_if_uninitialized(&self, initial: T) -> bool {
        if self.is_initialized() {
            return false;
        }

        let _writer_guard = self
            .writer_gate
            .lock()
            .expect("seqlock writer gate must not poison");
        if self.is_initialized() {
            return false;
        }

        *self
            .snapshot
            .write()
            .expect("seqlock snapshot write must not poison") = Some(initial);
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
        let _writer_guard = self
            .writer_gate
            .lock()
            .expect("seqlock writer gate must not poison");
        let start = self.sequence.load(Ordering::Acquire);
        self.sequence.store(start + 1, Ordering::Release);
        on_odd_sequence();
        *self
            .snapshot
            .write()
            .expect("seqlock snapshot write must not poison") = Some(next);
        self.initialized.store(true, Ordering::Release);
        self.sequence.store(start + 2, Ordering::Release);
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
            if start % 2 == 1 {
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

            let cloned = self
                .snapshot
                .read()
                .expect("seqlock snapshot read must not poison")
                .clone();
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
        let json = serde_json::to_string(&policy).unwrap();
        let back: RetryBudgetPolicy = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&source).unwrap();
            let back: FastPathReadSource = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&reason).unwrap();
            let back: FastPathFallbackReason = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&result).unwrap();
        let back: FastPathReadResult<u64> = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&telemetry).unwrap();
        let back: FastPathTelemetry = serde_json::from_str(&json).unwrap();
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
}
