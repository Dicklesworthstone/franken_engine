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

    #[test]
    fn seeding_baseline_avoids_uninitialized_fallback_without_counting_write() {
        let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
        assert!(fast_path.seed_if_uninitialized(41_u64));
        assert!(!fast_path.seed_if_uninitialized(99_u64));

        let result = fast_path.read_clone_or_else(|| 7_u64);

        assert_eq!(result.value, 41);
        assert_eq!(result.source, FastPathReadSource::FastPath);
        assert_eq!(result.fallback_reason, None);

        let telemetry = fast_path.telemetry();
        assert_eq!(telemetry.writes, 0);
        assert_eq!(telemetry.fast_path_reads, 1);
        assert_eq!(telemetry.fallback_reads, 0);
        assert_eq!(telemetry.uninitialized_fallbacks, 0);
    }
}
