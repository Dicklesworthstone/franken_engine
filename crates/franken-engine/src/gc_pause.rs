//! GC pause-time instrumentation and regression budgets.
//!
//! Measures every GC pause, records structured telemetry, and gates against
//! defined latency budgets (p50/p95/p99) to prevent GC from becoming a
//! tail-latency source.
//!
//! Plan references: Section 10.3 item 3, 9D.4 (allocation profiling),
//! 9D (extreme-software-optimization discipline), Phase C exit gate.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::gc::GcEvent;

// ---------------------------------------------------------------------------
// PauseBudget — latency budget thresholds
// ---------------------------------------------------------------------------

/// Latency budget thresholds for GC pauses (in nanoseconds).
///
/// The CI regression gate compares observed GC pause percentiles against
/// these budgets and fails the build if any threshold is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseBudget {
    /// Maximum acceptable p50 pause (nanoseconds).
    pub p50_ns: u64,
    /// Maximum acceptable p95 pause (nanoseconds).
    pub p95_ns: u64,
    /// Maximum acceptable p99 pause (nanoseconds).
    pub p99_ns: u64,
}

impl PauseBudget {
    pub fn new(p50_ns: u64, p95_ns: u64, p99_ns: u64) -> Self {
        Self {
            p50_ns,
            p95_ns,
            p99_ns,
        }
    }
}

impl Default for PauseBudget {
    fn default() -> Self {
        Self {
            p50_ns: 500_000,    // 500 µs
            p95_ns: 2_000_000,  // 2 ms
            p99_ns: 10_000_000, // 10 ms
        }
    }
}

// ---------------------------------------------------------------------------
// PauseRecord — a single GC pause measurement
// ---------------------------------------------------------------------------

/// A single recorded GC pause with structured metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseRecord {
    /// Monotonic sequence number (from GcEvent).
    pub sequence: u64,
    /// Which extension was collected.
    pub extension_id: String,
    /// Pause duration in nanoseconds.
    pub pause_ns: u64,
    /// Objects scanned during mark phase.
    pub objects_scanned: u64,
    /// Objects collected during sweep phase.
    pub objects_collected: u64,
    /// Bytes reclaimed.
    pub bytes_reclaimed: u64,
}

impl PauseRecord {
    /// Create a `PauseRecord` from a `GcEvent`.
    pub fn from_gc_event(event: &GcEvent) -> Self {
        Self {
            sequence: event.sequence,
            extension_id: event.extension_id.clone(),
            pause_ns: event.pause_ns,
            objects_scanned: event.marked_count,
            objects_collected: event.swept_count,
            bytes_reclaimed: event.bytes_reclaimed,
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetViolation — describes a budget threshold breach
// ---------------------------------------------------------------------------

/// Which percentile budget was violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Percentile {
    P50,
    P95,
    P99,
}

impl fmt::Display for Percentile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::P50 => "p50",
            Self::P95 => "p95",
            Self::P99 => "p99",
        };
        f.write_str(name)
    }
}

/// A budget violation: an observed percentile exceeded its threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetViolation {
    pub percentile: Percentile,
    /// Observed value (nanoseconds).
    pub observed_ns: u64,
    /// Budget threshold (nanoseconds).
    pub budget_ns: u64,
    /// Scope: global or per-extension.
    pub scope: String,
}

impl fmt::Display for BudgetViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} violation in '{}': observed {} ns > budget {} ns",
            self.percentile, self.scope, self.observed_ns, self.budget_ns
        )
    }
}

// ---------------------------------------------------------------------------
// PercentileSnapshot — computed percentile values
// ---------------------------------------------------------------------------

/// Computed percentile values from a set of pause measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PercentileSnapshot {
    pub count: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

impl PercentileSnapshot {
    /// Compute percentiles from a sorted slice of pause durations.
    fn from_sorted(sorted: &[u64]) -> Self {
        if sorted.is_empty() {
            return Self {
                count: 0,
                min_ns: 0,
                max_ns: 0,
                p50_ns: 0,
                p95_ns: 0,
                p99_ns: 0,
            };
        }
        let n = sorted.len();
        Self {
            count: n as u64,
            min_ns: sorted[0],
            max_ns: sorted[n - 1],
            p50_ns: percentile_value(sorted, 50),
            p95_ns: percentile_value(sorted, 95),
            p99_ns: percentile_value(sorted, 99),
        }
    }

    /// Check this snapshot against a budget, returning violations.
    pub fn check_budget(&self, budget: &PauseBudget, scope: &str) -> Vec<BudgetViolation> {
        let mut violations = Vec::new();
        if self.count == 0 {
            return violations;
        }
        if self.p50_ns > budget.p50_ns {
            violations.push(BudgetViolation {
                percentile: Percentile::P50,
                observed_ns: self.p50_ns,
                budget_ns: budget.p50_ns,
                scope: scope.to_string(),
            });
        }
        if self.p95_ns > budget.p95_ns {
            violations.push(BudgetViolation {
                percentile: Percentile::P95,
                observed_ns: self.p95_ns,
                budget_ns: budget.p95_ns,
                scope: scope.to_string(),
            });
        }
        if self.p99_ns > budget.p99_ns {
            violations.push(BudgetViolation {
                percentile: Percentile::P99,
                observed_ns: self.p99_ns,
                budget_ns: budget.p99_ns,
                scope: scope.to_string(),
            });
        }
        violations
    }
}

/// Compute the value at a given percentile from a sorted slice.
///
/// Uses the nearest-rank method for deterministic results.
fn percentile_value(sorted: &[u64], pct: u32) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((pct as f64 / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

// ---------------------------------------------------------------------------
// Pause distribution report and policy transitions
// ---------------------------------------------------------------------------

/// Stable schema identifier for pause-distribution report artifacts.
pub const PAUSE_DISTRIBUTION_REPORT_SCHEMA: &str = "franken-engine.gc-pause-distribution-report.v1";

/// Budget-enforcement policy state derived from observed pause data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseBudgetPolicyState {
    WithinBudget,
    Violated,
}

impl fmt::Display for PauseBudgetPolicyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinBudget => f.write_str("within_budget"),
            Self::Violated => f.write_str("violated"),
        }
    }
}

/// Captures a deterministic transition between two policy states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseBudgetPolicyTransition {
    pub from_state: PauseBudgetPolicyState,
    pub to_state: PauseBudgetPolicyState,
    pub transitioned: bool,
    pub violation_count: u64,
}

impl PauseBudgetPolicyTransition {
    fn from_states(
        from_state: PauseBudgetPolicyState,
        to_state: PauseBudgetPolicyState,
        violation_count: usize,
    ) -> Self {
        Self {
            from_state,
            to_state,
            transitioned: from_state != to_state,
            violation_count: violation_count as u64,
        }
    }
}

/// One deterministic histogram bucket in a pause-distribution report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseDistributionBucket {
    pub lower_bound_ns: u64,
    pub upper_bound_ns: u64,
    pub count: u64,
}

/// Deterministic pause-distribution report for artifact emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseDistributionReport {
    pub schema_version: String,
    pub sample_count: u64,
    pub budget: PauseBudget,
    pub policy_state: PauseBudgetPolicyState,
    pub policy_transition: PauseBudgetPolicyTransition,
    pub global_percentiles: PercentileSnapshot,
    pub per_extension_percentiles: BTreeMap<String, PercentileSnapshot>,
    pub histogram: Vec<PauseDistributionBucket>,
    pub budget_violations: Vec<BudgetViolation>,
}

fn build_pause_histogram(sorted: &[u64]) -> Vec<PauseDistributionBucket> {
    if sorted.is_empty() {
        return Vec::new();
    }
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let range_width = max.saturating_sub(min).saturating_add(1);
    let max_representable_buckets = usize::try_from(range_width).unwrap_or(usize::MAX);
    let bucket_count = sorted
        .len()
        .clamp(1, 10)
        .min(max_representable_buckets.max(1));
    let width = ((max.saturating_sub(min) + 1) / bucket_count as u64).max(1);

    let mut buckets = Vec::with_capacity(bucket_count);
    let mut idx = 0usize;
    for bucket_index in 0..bucket_count {
        let lower = min + width * bucket_index as u64;
        let upper = if bucket_index + 1 == bucket_count {
            max
        } else {
            lower.saturating_add(width - 1)
        };
        let mut count = 0u64;
        while idx < sorted.len() && sorted[idx] <= upper {
            count += 1;
            idx += 1;
        }
        buckets.push(PauseDistributionBucket {
            lower_bound_ns: lower,
            upper_bound_ns: upper,
            count,
        });
    }
    buckets
}

// ---------------------------------------------------------------------------
// PauseTracker — aggregates pause records and computes statistics
// ---------------------------------------------------------------------------

/// Tracks GC pause records and computes aggregate statistics.
///
/// Maintains global records and per-extension records for isolated analysis.
/// Uses `BTreeMap` for deterministic per-extension ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseTracker {
    /// All pause records in insertion order.
    records: Vec<PauseRecord>,
    /// Per-extension pause durations (for per-extension percentile computation).
    per_extension: BTreeMap<String, Vec<u64>>,
    /// Budget thresholds.
    budget: PauseBudget,
    /// Ring-buffer capacity (0 = unlimited).
    capacity: usize,
}

impl PauseTracker {
    pub fn new(budget: PauseBudget) -> Self {
        Self {
            records: Vec::new(),
            per_extension: BTreeMap::new(),
            budget,
            capacity: 0,
        }
    }

    /// Create a tracker with a ring-buffer capacity limit.
    pub fn with_capacity(budget: PauseBudget, capacity: usize) -> Self {
        Self {
            records: Vec::new(),
            per_extension: BTreeMap::new(),
            budget,
            capacity,
        }
    }

    /// Record a GC pause from a `GcEvent`.
    pub fn record(&mut self, event: &GcEvent) {
        let pause = PauseRecord::from_gc_event(event);
        self.per_extension
            .entry(event.extension_id.clone())
            .or_default()
            .push(event.pause_ns);
        self.records.push(pause);

        // Enforce ring-buffer capacity if set.
        if self.capacity > 0 && self.records.len() > self.capacity {
            let removed = self.records.remove(0);
            // Also clean up per-extension data for the removed record.
            if let Some(ext_pauses) = self.per_extension.get_mut(&removed.extension_id) {
                if let Some(pos) = ext_pauses.iter().position(|&v| v == removed.pause_ns) {
                    ext_pauses.remove(pos);
                }
                if ext_pauses.is_empty() {
                    self.per_extension.remove(&removed.extension_id);
                }
            }
        }
    }

    /// Compute global percentile snapshot across all extensions.
    pub fn global_percentiles(&self) -> PercentileSnapshot {
        let mut all_pauses: Vec<u64> = self.records.iter().map(|r| r.pause_ns).collect();
        all_pauses.sort_unstable();
        PercentileSnapshot::from_sorted(&all_pauses)
    }

    /// Compute percentile snapshot for a specific extension.
    pub fn extension_percentiles(&self, extension_id: &str) -> PercentileSnapshot {
        match self.per_extension.get(extension_id) {
            Some(pauses) => {
                let mut sorted = pauses.clone();
                sorted.sort_unstable();
                PercentileSnapshot::from_sorted(&sorted)
            }
            None => PercentileSnapshot::from_sorted(&[]),
        }
    }

    /// Check all recorded pauses against the budget.
    ///
    /// Returns violations for global and each per-extension scope.
    pub fn check_budget(&self) -> Vec<BudgetViolation> {
        let mut violations = Vec::new();

        // Global check.
        let global = self.global_percentiles();
        violations.extend(global.check_budget(&self.budget, "global"));

        // Per-extension checks (deterministic order via BTreeMap).
        for ext_id in self.per_extension.keys() {
            let snap = self.extension_percentiles(ext_id);
            violations.extend(snap.check_budget(&self.budget, ext_id));
        }

        violations
    }

    /// Current policy state derived from budget checks.
    pub fn budget_policy_state(&self) -> PauseBudgetPolicyState {
        if self.within_budget() {
            PauseBudgetPolicyState::WithinBudget
        } else {
            PauseBudgetPolicyState::Violated
        }
    }

    /// Compute a policy transition from a previous state to the current state.
    pub fn budget_policy_transition(
        &self,
        previous_state: PauseBudgetPolicyState,
    ) -> PauseBudgetPolicyTransition {
        let violations = self.check_budget();
        PauseBudgetPolicyTransition::from_states(
            previous_state,
            if violations.is_empty() {
                PauseBudgetPolicyState::WithinBudget
            } else {
                PauseBudgetPolicyState::Violated
            },
            violations.len(),
        )
    }

    /// Build a deterministic pause-distribution report using current state.
    pub fn pause_distribution_report(&self) -> PauseDistributionReport {
        self.pause_distribution_report_with_transition(self.budget_policy_state())
    }

    /// Build a deterministic pause-distribution report with explicit transition.
    pub fn pause_distribution_report_with_transition(
        &self,
        previous_state: PauseBudgetPolicyState,
    ) -> PauseDistributionReport {
        let mut global_sorted: Vec<u64> = self.records.iter().map(|r| r.pause_ns).collect();
        global_sorted.sort_unstable();
        let global_percentiles = PercentileSnapshot::from_sorted(&global_sorted);

        let mut per_extension_percentiles = BTreeMap::new();
        for (extension_id, pauses) in &self.per_extension {
            let mut sorted = pauses.clone();
            sorted.sort_unstable();
            per_extension_percentiles.insert(
                extension_id.clone(),
                PercentileSnapshot::from_sorted(&sorted),
            );
        }

        let budget_violations = self.check_budget();
        let policy_state = if budget_violations.is_empty() {
            PauseBudgetPolicyState::WithinBudget
        } else {
            PauseBudgetPolicyState::Violated
        };

        PauseDistributionReport {
            schema_version: PAUSE_DISTRIBUTION_REPORT_SCHEMA.to_string(),
            sample_count: self.records.len() as u64,
            budget: self.budget,
            policy_state,
            policy_transition: PauseBudgetPolicyTransition::from_states(
                previous_state,
                policy_state,
                budget_violations.len(),
            ),
            global_percentiles,
            per_extension_percentiles,
            histogram: build_pause_histogram(&global_sorted),
            budget_violations,
        }
    }

    /// Returns true if all pauses are within budget.
    pub fn within_budget(&self) -> bool {
        self.check_budget().is_empty()
    }

    /// All recorded pause records.
    pub fn records(&self) -> &[PauseRecord] {
        &self.records
    }

    /// Number of recorded pauses.
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Per-extension pause count.
    pub fn extension_count(&self, extension_id: &str) -> usize {
        self.per_extension.get(extension_id).map_or(0, Vec::len)
    }

    /// Total bytes reclaimed across all recorded pauses.
    pub fn total_bytes_reclaimed(&self) -> u64 {
        self.records.iter().map(|r| r.bytes_reclaimed).sum()
    }

    /// Total objects collected across all recorded pauses.
    pub fn total_objects_collected(&self) -> u64 {
        self.records.iter().map(|r| r.objects_collected).sum()
    }

    /// Extensions with recorded pauses (deterministic order).
    pub fn extensions(&self) -> Vec<&str> {
        self.per_extension.keys().map(|s| s.as_str()).collect()
    }

    /// Current budget.
    pub fn budget(&self) -> &PauseBudget {
        &self.budget
    }

    /// Update the budget thresholds.
    pub fn set_budget(&mut self, budget: PauseBudget) {
        self.budget = budget;
    }
}

impl Default for PauseTracker {
    fn default() -> Self {
        Self::new(PauseBudget::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gc::GcPhase;

    fn make_event(seq: u64, ext: &str, pause_ns: u64, swept: u64, reclaimed: u64) -> GcEvent {
        GcEvent {
            sequence: seq,
            extension_id: ext.to_string(),
            phase: GcPhase::Complete,
            marked_count: 10,
            swept_count: swept,
            bytes_reclaimed: reclaimed,
            pause_ns,
        }
    }

    // -- PauseBudget --

    #[test]
    fn default_budget_values() {
        let b = PauseBudget::default();
        assert_eq!(b.p50_ns, 500_000);
        assert_eq!(b.p95_ns, 2_000_000);
        assert_eq!(b.p99_ns, 10_000_000);
    }

    // -- PauseRecord --

    #[test]
    fn pause_record_from_gc_event() {
        let event = make_event(1, "ext-a", 1500, 5, 1024);
        let record = PauseRecord::from_gc_event(&event);
        assert_eq!(record.sequence, 1);
        assert_eq!(record.extension_id, "ext-a");
        assert_eq!(record.pause_ns, 1500);
        assert_eq!(record.objects_scanned, 10);
        assert_eq!(record.objects_collected, 5);
        assert_eq!(record.bytes_reclaimed, 1024);
    }

    // -- Percentile computation --

    #[test]
    fn percentile_from_single_value() {
        let data = [100u64];
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min_ns, 100);
        assert_eq!(snap.max_ns, 100);
        assert_eq!(snap.p50_ns, 100);
        assert_eq!(snap.p95_ns, 100);
        assert_eq!(snap.p99_ns, 100);
    }

    #[test]
    fn percentile_from_empty() {
        let snap = PercentileSnapshot::from_sorted(&[]);
        assert_eq!(snap.count, 0);
        assert_eq!(snap.p50_ns, 0);
    }

    #[test]
    fn percentile_computation_correctness() {
        // 100 values: 1, 2, 3, ..., 100
        let data: Vec<u64> = (1..=100).collect();
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 100);
        assert_eq!(snap.min_ns, 1);
        assert_eq!(snap.max_ns, 100);
        assert_eq!(snap.p50_ns, 50);
        assert_eq!(snap.p95_ns, 95);
        assert_eq!(snap.p99_ns, 99);
    }

    #[test]
    fn percentile_with_small_dataset() {
        // 5 values: 10, 20, 30, 40, 50
        let data = [10u64, 20, 30, 40, 50];
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 5);
        assert_eq!(snap.min_ns, 10);
        assert_eq!(snap.max_ns, 50);
        // p50 of 5 items: ceil(0.5*5)=3 → index 2 → value 30
        assert_eq!(snap.p50_ns, 30);
        // p95 of 5 items: ceil(0.95*5)=5 → index 4 → value 50
        assert_eq!(snap.p95_ns, 50);
        // p99 of 5 items: ceil(0.99*5)=5 → index 4 → value 50
        assert_eq!(snap.p99_ns, 50);
    }

    // -- Budget violations --

    #[test]
    fn no_violations_within_budget() {
        let budget = PauseBudget::new(1000, 2000, 5000);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 100,
            max_ns: 900,
            p50_ns: 500,
            p95_ns: 800,
            p99_ns: 900,
        };
        let violations = snap.check_budget(&budget, "test");
        assert!(violations.is_empty());
    }

    #[test]
    fn p50_violation_detected() {
        let budget = PauseBudget::new(100, 2000, 5000);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 50,
            max_ns: 900,
            p50_ns: 200, // exceeds p50 budget of 100
            p95_ns: 800,
            p99_ns: 900,
        };
        let violations = snap.check_budget(&budget, "test");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].percentile, Percentile::P50);
        assert_eq!(violations[0].observed_ns, 200);
        assert_eq!(violations[0].budget_ns, 100);
    }

    #[test]
    fn multiple_violations_detected() {
        let budget = PauseBudget::new(100, 200, 300);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 50,
            max_ns: 900,
            p50_ns: 200,
            p95_ns: 400,
            p99_ns: 900,
        };
        let violations = snap.check_budget(&budget, "test");
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn empty_snapshot_no_violations() {
        let budget = PauseBudget::new(100, 200, 300);
        let snap = PercentileSnapshot::from_sorted(&[]);
        let violations = snap.check_budget(&budget, "test");
        assert!(violations.is_empty());
    }

    // -- PauseTracker --

    #[test]
    fn tracker_records_events() {
        let mut tracker = PauseTracker::default();
        tracker.record(&make_event(1, "ext-a", 1000, 5, 512));
        tracker.record(&make_event(2, "ext-a", 2000, 3, 256));
        tracker.record(&make_event(3, "ext-b", 500, 1, 128));

        assert_eq!(tracker.count(), 3);
        assert_eq!(tracker.extension_count("ext-a"), 2);
        assert_eq!(tracker.extension_count("ext-b"), 1);
        assert_eq!(tracker.total_bytes_reclaimed(), 896);
        assert_eq!(tracker.total_objects_collected(), 9);
    }

    #[test]
    fn tracker_global_percentiles() {
        let mut tracker = PauseTracker::default();
        for i in 1..=100 {
            tracker.record(&make_event(i, "ext-a", i * 100, 0, 0));
        }

        let snap = tracker.global_percentiles();
        assert_eq!(snap.count, 100);
        assert_eq!(snap.min_ns, 100);
        assert_eq!(snap.max_ns, 10000);
        assert_eq!(snap.p50_ns, 5000);
        assert_eq!(snap.p95_ns, 9500);
        assert_eq!(snap.p99_ns, 9900);
    }

    #[test]
    fn tracker_per_extension_percentiles() {
        let mut tracker = PauseTracker::default();
        tracker.record(&make_event(1, "ext-a", 1000, 0, 0));
        tracker.record(&make_event(2, "ext-a", 2000, 0, 0));
        tracker.record(&make_event(3, "ext-a", 3000, 0, 0));
        tracker.record(&make_event(4, "ext-b", 500, 0, 0));

        let snap_a = tracker.extension_percentiles("ext-a");
        assert_eq!(snap_a.count, 3);
        assert_eq!(snap_a.min_ns, 1000);
        assert_eq!(snap_a.max_ns, 3000);

        let snap_b = tracker.extension_percentiles("ext-b");
        assert_eq!(snap_b.count, 1);
        assert_eq!(snap_b.p50_ns, 500);

        let snap_none = tracker.extension_percentiles("ext-z");
        assert_eq!(snap_none.count, 0);
    }

    #[test]
    fn tracker_budget_check_within_budget() {
        let budget = PauseBudget::new(10_000, 20_000, 50_000);
        let mut tracker = PauseTracker::new(budget);
        tracker.record(&make_event(1, "ext-a", 5000, 0, 0));
        tracker.record(&make_event(2, "ext-a", 8000, 0, 0));

        assert!(tracker.within_budget());
        assert!(tracker.check_budget().is_empty());
    }

    #[test]
    fn tracker_budget_check_violations() {
        let budget = PauseBudget::new(100, 200, 300);
        let mut tracker = PauseTracker::new(budget);
        // All pauses exceed even p50 budget
        tracker.record(&make_event(1, "ext-a", 500, 0, 0));
        tracker.record(&make_event(2, "ext-a", 600, 0, 0));

        assert!(!tracker.within_budget());
        let violations = tracker.check_budget();
        // Should have violations for global and ext-a
        assert!(!violations.is_empty());
        // Both global and ext-a p50 are violated at minimum
        assert!(
            violations
                .iter()
                .any(|v| v.scope == "global" && v.percentile == Percentile::P50)
        );
        assert!(
            violations
                .iter()
                .any(|v| v.scope == "ext-a" && v.percentile == Percentile::P50)
        );
    }

    #[test]
    fn tracker_extensions_deterministic_order() {
        let mut tracker = PauseTracker::default();
        tracker.record(&make_event(1, "ext-c", 100, 0, 0));
        tracker.record(&make_event(2, "ext-a", 200, 0, 0));
        tracker.record(&make_event(3, "ext-b", 300, 0, 0));

        let exts = tracker.extensions();
        assert_eq!(exts, vec!["ext-a", "ext-b", "ext-c"]);
    }

    #[test]
    fn tracker_ring_buffer_capacity() {
        let budget = PauseBudget::default();
        let mut tracker = PauseTracker::with_capacity(budget, 3);

        tracker.record(&make_event(1, "ext-a", 100, 0, 0));
        tracker.record(&make_event(2, "ext-a", 200, 0, 0));
        tracker.record(&make_event(3, "ext-a", 300, 0, 0));
        assert_eq!(tracker.count(), 3);

        // Adding a 4th record should evict the oldest.
        tracker.record(&make_event(4, "ext-a", 400, 0, 0));
        assert_eq!(tracker.count(), 3);
        assert_eq!(tracker.records()[0].sequence, 2);
        assert_eq!(tracker.records()[2].sequence, 4);
    }

    #[test]
    fn tracker_set_budget() {
        let mut tracker = PauseTracker::default();
        let new_budget = PauseBudget::new(100, 200, 300);
        tracker.set_budget(new_budget);
        assert_eq!(tracker.budget().p50_ns, 100);
        assert_eq!(tracker.budget().p95_ns, 200);
        assert_eq!(tracker.budget().p99_ns, 300);
    }

    #[test]
    fn violation_display() {
        let v = BudgetViolation {
            percentile: Percentile::P95,
            observed_ns: 5000,
            budget_ns: 2000,
            scope: "ext-a".to_string(),
        };
        assert_eq!(
            v.to_string(),
            "p95 violation in 'ext-a': observed 5000 ns > budget 2000 ns"
        );
    }

    #[test]
    fn percentile_display() {
        assert_eq!(Percentile::P50.to_string(), "p50");
        assert_eq!(Percentile::P95.to_string(), "p95");
        assert_eq!(Percentile::P99.to_string(), "p99");
    }

    // -- Serialization --

    #[test]
    fn pause_tracker_serialization_round_trip() {
        let mut tracker = PauseTracker::new(PauseBudget::new(1000, 2000, 5000));
        tracker.record(&make_event(1, "ext-a", 500, 3, 256));
        tracker.record(&make_event(2, "ext-b", 800, 1, 128));

        let json = serde_json::to_string(&tracker).expect("serialize");
        let restored: PauseTracker = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(tracker.count(), restored.count());
        assert_eq!(tracker.global_percentiles(), restored.global_percentiles());
        assert_eq!(
            tracker.extension_percentiles("ext-a"),
            restored.extension_percentiles("ext-a")
        );
        assert_eq!(tracker.budget().p50_ns, restored.budget().p50_ns);
    }

    // -- Integration with GcCollector --

    // -- Enrichment: serde roundtrips --

    #[test]
    fn pause_budget_serde_roundtrip() {
        let budget = PauseBudget::new(100_000, 500_000, 2_000_000);
        let json = serde_json::to_string(&budget).expect("serialize");
        let restored: PauseBudget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, restored);
    }

    #[test]
    fn pause_record_serde_roundtrip() {
        let event = make_event(7, "ext-serde", 12345, 50, 8192);
        let record = PauseRecord::from_gc_event(&event);
        let json = serde_json::to_string(&record).expect("serialize");
        let restored: PauseRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, restored);
    }

    #[test]
    fn percentile_serde_all_variants() {
        for p in [Percentile::P50, Percentile::P95, Percentile::P99] {
            let json = serde_json::to_string(&p).expect("serialize");
            let restored: Percentile = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(p, restored);
        }
    }

    #[test]
    fn budget_violation_serde_roundtrip() {
        let v = BudgetViolation {
            percentile: Percentile::P99,
            observed_ns: 15_000_000,
            budget_ns: 10_000_000,
            scope: "ext-a".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: BudgetViolation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    #[test]
    fn percentile_snapshot_serde_roundtrip() {
        let snap = PercentileSnapshot {
            count: 100,
            min_ns: 500,
            max_ns: 50_000,
            p50_ns: 5_000,
            p95_ns: 20_000,
            p99_ns: 45_000,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let restored: PercentileSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, restored);
    }

    #[test]
    fn integration_gc_collector_to_pause_tracker() {
        use crate::gc::{GcCollector, GcConfig};

        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-a".into()).unwrap();

        let obj = gc.allocate("ext-a", 100).unwrap();
        gc.unroot("ext-a", obj).unwrap();

        let event = gc.collect("ext-a").unwrap();

        let mut tracker = PauseTracker::default();
        tracker.record(&event);

        assert_eq!(tracker.count(), 1);
        let snap = tracker.global_percentiles();
        assert_eq!(snap.count, 1);
        assert_eq!(snap.p50_ns, 1000); // deterministic mode sentinel
        assert!(tracker.within_budget()); // 1000 ns < 500_000 ns p50 budget
    }

    // -- Enrichment: PauseBudget --

    #[test]
    fn pause_budget_new_values() {
        let b = PauseBudget::new(111, 222, 333);
        assert_eq!(b.p50_ns, 111);
        assert_eq!(b.p95_ns, 222);
        assert_eq!(b.p99_ns, 333);
    }

    #[test]
    fn pause_budget_equality() {
        let b1 = PauseBudget::new(1, 2, 3);
        let b2 = PauseBudget::new(1, 2, 3);
        assert_eq!(b1, b2);
        let b3 = PauseBudget::new(1, 2, 4);
        assert_ne!(b1, b3);
    }

    // -- Enrichment: PauseTracker --

    #[test]
    fn tracker_default_starts_empty() {
        let tracker = PauseTracker::default();
        assert_eq!(tracker.count(), 0);
        assert!(tracker.records().is_empty());
        assert!(tracker.extensions().is_empty());
        assert_eq!(tracker.total_bytes_reclaimed(), 0);
        assert_eq!(tracker.total_objects_collected(), 0);
    }

    #[test]
    fn tracker_extension_count_unknown_extension() {
        let tracker = PauseTracker::default();
        assert_eq!(tracker.extension_count("nonexistent"), 0);
    }

    #[test]
    fn tracker_ring_buffer_multi_extension_eviction() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 2);
        tracker.record(&make_event(1, "ext-a", 100, 0, 0));
        tracker.record(&make_event(2, "ext-b", 200, 0, 0));
        assert_eq!(tracker.count(), 2);
        assert_eq!(tracker.extension_count("ext-a"), 1);

        // Evicts ext-a's record
        tracker.record(&make_event(3, "ext-b", 300, 0, 0));
        assert_eq!(tracker.count(), 2);
        assert_eq!(tracker.extension_count("ext-a"), 0);
        assert_eq!(tracker.extension_count("ext-b"), 2);
        // ext-a should be removed from extensions list
        assert!(!tracker.extensions().contains(&"ext-a"));
    }

    // -- Enrichment: Percentile edge cases --

    #[test]
    fn percentile_two_values() {
        let data = [10u64, 20];
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 2);
        assert_eq!(snap.min_ns, 10);
        assert_eq!(snap.max_ns, 20);
        // p50 of 2 items: ceil(0.5*2)=1 → index 0 → 10
        assert_eq!(snap.p50_ns, 10);
        // p95 of 2 items: ceil(0.95*2)=2 → index 1 → 20
        assert_eq!(snap.p95_ns, 20);
    }

    // -- Enrichment: Budget violation specific percentile --

    #[test]
    fn p95_only_violation() {
        let budget = PauseBudget::new(1000, 100, 50_000);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 50,
            max_ns: 900,
            p50_ns: 80,  // within p50 budget of 1000
            p95_ns: 200, // exceeds p95 budget of 100
            p99_ns: 900, // within p99 budget of 50_000
        };
        let violations = snap.check_budget(&budget, "test");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].percentile, Percentile::P95);
    }

    #[test]
    fn p99_only_violation() {
        let budget = PauseBudget::new(1000, 2000, 100);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 50,
            max_ns: 900,
            p50_ns: 500, // within p50 budget of 1000
            p95_ns: 800, // within p95 budget of 2000
            p99_ns: 900, // exceeds p99 budget of 100
        };
        let violations = snap.check_budget(&budget, "test");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].percentile, Percentile::P99);
    }

    // -- Enrichment: Percentile ordering --

    #[test]
    fn percentile_ordering() {
        // Percentile enum should be serializable and distinguishable
        let p50 = Percentile::P50;
        let p95 = Percentile::P95;
        let p99 = Percentile::P99;
        assert_ne!(p50, p95);
        assert_ne!(p95, p99);
        assert_ne!(p50, p99);
    }

    // -- Enrichment: BudgetViolation scope --

    #[test]
    fn budget_violation_scope_preserved() {
        let v = BudgetViolation {
            percentile: Percentile::P50,
            observed_ns: 1000,
            budget_ns: 500,
            scope: "my-ext".to_string(),
        };
        assert!(v.to_string().contains("my-ext"));
        assert!(v.to_string().contains("1000"));
        assert!(v.to_string().contains("500"));
    }

    // -- Enrichment batch 2: Display uniqueness, boundaries, determinism --

    #[test]
    fn percentile_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [Percentile::P50, Percentile::P95, Percentile::P99];
        let set: BTreeSet<String> = all.iter().map(|p| p.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all Percentile Display strings must be unique"
        );
    }

    #[test]
    fn pause_tracker_deterministic_global_percentiles() {
        let run = || {
            let mut tracker = PauseTracker::default();
            for i in 1..=50 {
                tracker.record(&make_event(i, "ext-a", i * 100, i, i * 10));
            }
            tracker.global_percentiles()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn percentile_value_boundary_100_percent() {
        let data = [10u64, 20, 30, 40, 50];
        // p100 should be max value
        let val = percentile_value(&data, 100);
        assert_eq!(val, 50);
    }

    #[test]
    fn percentile_value_boundary_1_percent() {
        let data: Vec<u64> = (1..=100).collect();
        let val = percentile_value(&data, 1);
        assert_eq!(val, 1);
    }

    #[test]
    fn tracker_total_bytes_and_objects_across_extensions() {
        let mut tracker = PauseTracker::default();
        tracker.record(&make_event(1, "ext-a", 100, 10, 1024));
        tracker.record(&make_event(2, "ext-b", 200, 20, 2048));
        tracker.record(&make_event(3, "ext-c", 300, 30, 4096));

        assert_eq!(tracker.total_bytes_reclaimed(), 1024 + 2048 + 4096);
        assert_eq!(tracker.total_objects_collected(), 10 + 20 + 30);
        assert_eq!(tracker.extensions().len(), 3);
    }

    #[test]
    fn budget_at_exact_threshold_no_violation() {
        let budget = PauseBudget::new(500, 1000, 2000);
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 100,
            max_ns: 2000,
            p50_ns: 500,  // exactly at budget
            p95_ns: 1000, // exactly at budget
            p99_ns: 2000, // exactly at budget
        };
        let violations = snap.check_budget(&budget, "test");
        assert!(
            violations.is_empty(),
            "values at exact threshold should not violate"
        );
    }

    #[test]
    fn ring_buffer_capacity_zero_means_unlimited() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 0);
        for i in 1..=100 {
            tracker.record(&make_event(i, "ext-a", i * 10, 0, 0));
        }
        assert_eq!(tracker.count(), 100);
    }

    #[test]
    fn pause_record_fields_from_gc_event() {
        let event = GcEvent {
            sequence: 42,
            extension_id: "ext-detailed".to_string(),
            phase: GcPhase::Complete,
            marked_count: 100,
            swept_count: 50,
            bytes_reclaimed: 8192,
            pause_ns: 999_999,
        };
        let record = PauseRecord::from_gc_event(&event);
        assert_eq!(record.sequence, 42);
        assert_eq!(record.extension_id, "ext-detailed");
        assert_eq!(record.pause_ns, 999_999);
        assert_eq!(record.objects_scanned, 100);
        assert_eq!(record.objects_collected, 50);
        assert_eq!(record.bytes_reclaimed, 8192);
    }

    // -- Enrichment batch 3: ring buffer edge cases, percentile boundaries, budget edge cases --

    #[test]
    fn ring_buffer_capacity_of_one() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 1);
        tracker.record(&make_event(1, "ext-a", 100, 0, 64));
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.total_bytes_reclaimed(), 64);

        tracker.record(&make_event(2, "ext-a", 200, 0, 128));
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.records()[0].sequence, 2);
        assert_eq!(tracker.total_bytes_reclaimed(), 128);

        tracker.record(&make_event(3, "ext-b", 300, 0, 256));
        assert_eq!(tracker.count(), 1);
        assert_eq!(tracker.records()[0].extension_id, "ext-b");
        assert_eq!(tracker.extension_count("ext-a"), 0);
        assert_eq!(tracker.extension_count("ext-b"), 1);
    }

    #[test]
    fn all_same_value_percentiles() {
        let data = [500u64; 100];
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 100);
        assert_eq!(snap.min_ns, 500);
        assert_eq!(snap.max_ns, 500);
        assert_eq!(snap.p50_ns, 500);
        assert_eq!(snap.p95_ns, 500);
        assert_eq!(snap.p99_ns, 500);
    }

    #[test]
    fn zero_budget_flags_any_pause() {
        let budget = PauseBudget::new(0, 0, 0);
        let mut tracker = PauseTracker::new(budget);
        tracker.record(&make_event(1, "ext-a", 1, 0, 0));
        assert!(!tracker.within_budget());
        let violations = tracker.check_budget();
        assert!(violations.len() >= 3); // p50, p95, p99 violated for global
    }

    #[test]
    fn violation_display_p50() {
        let v = BudgetViolation {
            percentile: Percentile::P50,
            observed_ns: 1000,
            budget_ns: 500,
            scope: "global".to_string(),
        };
        let display = v.to_string();
        assert!(display.contains("p50"));
        assert!(display.contains("global"));
        assert!(display.contains("1000"));
        assert!(display.contains("500"));
    }

    #[test]
    fn violation_display_p99() {
        let v = BudgetViolation {
            percentile: Percentile::P99,
            observed_ns: 99999,
            budget_ns: 10000,
            scope: "ext-z".to_string(),
        };
        let display = v.to_string();
        assert!(display.contains("p99"));
        assert!(display.contains("ext-z"));
    }

    #[test]
    fn tracker_serde_preserves_percentile_computation() {
        let mut tracker = PauseTracker::new(PauseBudget::new(10000, 20000, 50000));
        for i in 1..=20 {
            tracker.record(&make_event(i, "ext-a", i * 100, i, i * 10));
        }

        let json = serde_json::to_string(&tracker).unwrap();
        let restored: PauseTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(tracker.global_percentiles(), restored.global_percentiles());
        assert_eq!(
            tracker.extension_percentiles("ext-a"),
            restored.extension_percentiles("ext-a")
        );
    }

    #[test]
    fn multiple_extensions_mixed_violation_profiles() {
        let budget = PauseBudget::new(500, 1000, 5000);
        let mut tracker = PauseTracker::new(budget);

        // ext-a: within budget
        tracker.record(&make_event(1, "ext-a", 100, 0, 0));
        tracker.record(&make_event(2, "ext-a", 200, 0, 0));

        // ext-b: violating p50
        tracker.record(&make_event(3, "ext-b", 1000, 0, 0));
        tracker.record(&make_event(4, "ext-b", 2000, 0, 0));

        let violations = tracker.check_budget();
        let ext_b_violations: Vec<_> = violations.iter().filter(|v| v.scope == "ext-b").collect();
        assert!(!ext_b_violations.is_empty());
        let ext_a_violations: Vec<_> = violations.iter().filter(|v| v.scope == "ext-a").collect();
        assert!(ext_a_violations.is_empty());
    }

    #[test]
    fn empty_tracker_within_budget() {
        let tracker = PauseTracker::default();
        assert!(tracker.within_budget());
        assert!(tracker.check_budget().is_empty());
    }

    #[test]
    fn tracker_default_budget_is_pause_budget_default() {
        let tracker = PauseTracker::default();
        let expected = PauseBudget::default();
        assert_eq!(tracker.budget().p50_ns, expected.p50_ns);
        assert_eq!(tracker.budget().p95_ns, expected.p95_ns);
        assert_eq!(tracker.budget().p99_ns, expected.p99_ns);
    }

    #[test]
    fn ring_buffer_at_exact_capacity_no_eviction() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 3);
        tracker.record(&make_event(1, "ext-a", 100, 0, 0));
        tracker.record(&make_event(2, "ext-a", 200, 0, 0));
        tracker.record(&make_event(3, "ext-a", 300, 0, 0));
        assert_eq!(tracker.count(), 3);
        assert_eq!(tracker.records()[0].sequence, 1);
    }

    #[test]
    fn percentile_value_pct_zero() {
        let data = [10u64, 20, 30, 40, 50];
        let val = percentile_value(&data, 0);
        // ceil(0.0 * 5) = 0, saturating_sub(1) = 0 -> index 0
        assert_eq!(val, 10);
    }

    #[test]
    fn total_bytes_with_ring_buffer_eviction() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 2);
        tracker.record(&make_event(1, "ext-a", 100, 0, 1000));
        tracker.record(&make_event(2, "ext-a", 200, 0, 2000));
        assert_eq!(tracker.total_bytes_reclaimed(), 3000);

        // Evicts record with 1000 bytes
        tracker.record(&make_event(3, "ext-a", 300, 0, 3000));
        assert_eq!(tracker.total_bytes_reclaimed(), 5000); // 2000 + 3000
    }

    #[test]
    fn extension_removed_after_all_records_evicted() {
        let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 2);
        tracker.record(&make_event(1, "ext-lonely", 100, 0, 0));
        tracker.record(&make_event(2, "ext-other", 200, 0, 0));
        assert!(tracker.extensions().contains(&"ext-lonely"));

        // Evict ext-lonely record
        tracker.record(&make_event(3, "ext-other", 300, 0, 0));
        assert!(!tracker.extensions().contains(&"ext-lonely"));

        // Evict first ext-other record
        tracker.record(&make_event(4, "ext-other", 400, 0, 0));
        assert_eq!(tracker.extension_count("ext-other"), 2);
    }

    #[test]
    fn percentile_three_values() {
        let data = [100u64, 200, 300];
        let snap = PercentileSnapshot::from_sorted(&data);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min_ns, 100);
        assert_eq!(snap.max_ns, 300);
        // p50 of 3: ceil(0.5*3)=2 -> index 1 -> 200
        assert_eq!(snap.p50_ns, 200);
    }

    #[test]
    fn set_budget_affects_subsequent_checks() {
        let mut tracker = PauseTracker::new(PauseBudget::new(1_000_000, 2_000_000, 5_000_000));
        tracker.record(&make_event(1, "ext", 500_000, 0, 0));
        assert!(tracker.within_budget());

        // Tighten budget
        tracker.set_budget(PauseBudget::new(100, 200, 300));
        assert!(!tracker.within_budget());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch: serde, Display, edge cases, clone/eq
    // -----------------------------------------------------------------------

    #[test]
    fn pause_budget_custom_serde_roundtrip() {
        let budget = PauseBudget::new(100, 200, 300);
        let json = serde_json::to_string(&budget).unwrap();
        let back: PauseBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, back);
    }

    #[test]
    fn pause_budget_json_field_names() {
        let budget = PauseBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        assert!(json.contains("\"p50_ns\""));
        assert!(json.contains("\"p95_ns\""));
        assert!(json.contains("\"p99_ns\""));
    }

    #[test]
    fn pause_record_full_serde_roundtrip() {
        let record = PauseRecord {
            sequence: 42,
            extension_id: "ext-test".to_string(),
            pause_ns: 1_500_000,
            objects_scanned: 100,
            objects_collected: 25,
            bytes_reclaimed: 4096,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: PauseRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn pause_record_json_field_names() {
        let record = PauseRecord {
            sequence: 1,
            extension_id: "ext".to_string(),
            pause_ns: 100,
            objects_scanned: 10,
            objects_collected: 5,
            bytes_reclaimed: 1024,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"sequence\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"pause_ns\""));
        assert!(json.contains("\"objects_scanned\""));
        assert!(json.contains("\"objects_collected\""));
        assert!(json.contains("\"bytes_reclaimed\""));
    }

    #[test]
    fn percentile_display_all_variants() {
        assert_eq!(Percentile::P50.to_string(), "p50");
        assert_eq!(Percentile::P95.to_string(), "p95");
        assert_eq!(Percentile::P99.to_string(), "p99");
    }

    #[test]
    fn percentile_serde_roundtrip() {
        for p in [Percentile::P50, Percentile::P95, Percentile::P99] {
            let json = serde_json::to_string(&p).unwrap();
            let back: Percentile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn budget_violation_display_format() {
        let v = BudgetViolation {
            percentile: Percentile::P99,
            observed_ns: 15_000_000,
            budget_ns: 10_000_000,
            scope: "global".to_string(),
        };
        let display = v.to_string();
        assert!(display.contains("p99"));
        assert!(display.contains("global"));
        assert!(display.contains("15000000"));
        assert!(display.contains("10000000"));
    }

    #[test]
    fn budget_violation_full_serde_roundtrip() {
        let v = BudgetViolation {
            percentile: Percentile::P50,
            observed_ns: 600_000,
            budget_ns: 500_000,
            scope: "ext-test".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: BudgetViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn percentile_snapshot_full_serde_roundtrip() {
        let snap = PercentileSnapshot {
            count: 100,
            min_ns: 50,
            max_ns: 5_000_000,
            p50_ns: 200_000,
            p95_ns: 1_500_000,
            p99_ns: 4_000_000,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: PercentileSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn percentile_snapshot_copy_semantics() {
        let snap = PercentileSnapshot {
            count: 10,
            min_ns: 100,
            max_ns: 1000,
            p50_ns: 500,
            p95_ns: 900,
            p99_ns: 990,
        };
        let copied = snap;
        assert_eq!(snap, copied);
    }

    #[test]
    fn pause_budget_copy_semantics() {
        let budget = PauseBudget::new(100, 200, 300);
        let copied = budget;
        assert_eq!(budget, copied);
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut tracker = PauseTracker::new(PauseBudget::default());
        tracker.record(&make_event(1, "ext-a", 100_000, 5, 512));
        tracker.record(&make_event(2, "ext-b", 200_000, 10, 1024));
        let json = serde_json::to_string(&tracker).unwrap();
        let back: PauseTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(tracker.count(), back.count());
        assert_eq!(tracker.global_percentiles(), back.global_percentiles());
    }

    #[test]
    fn tracker_default_is_empty_within_budget() {
        let tracker = PauseTracker::default();
        assert_eq!(tracker.count(), 0);
        assert!(tracker.within_budget());
        assert!(tracker.extensions().is_empty());
        assert_eq!(tracker.total_bytes_reclaimed(), 0);
        assert_eq!(tracker.total_objects_collected(), 0);
    }

    #[test]
    fn budget_violation_clone_eq() {
        let v = BudgetViolation {
            percentile: Percentile::P95,
            observed_ns: 3_000_000,
            budget_ns: 2_000_000,
            scope: "ext-test".to_string(),
        };
        let cloned = v.clone();
        assert_eq!(v, cloned);
    }

    #[test]
    fn pause_record_clone_eq() {
        let record = PauseRecord {
            sequence: 99,
            extension_id: "ext-x".to_string(),
            pause_ns: 777,
            objects_scanned: 50,
            objects_collected: 20,
            bytes_reclaimed: 8192,
        };
        let cloned = record.clone();
        assert_eq!(record, cloned);
    }

    #[test]
    fn percentile_snapshot_single_value() {
        let snap = PercentileSnapshot::from_sorted(&[42_000]);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min_ns, 42_000);
        assert_eq!(snap.max_ns, 42_000);
        assert_eq!(snap.p50_ns, 42_000);
        assert_eq!(snap.p95_ns, 42_000);
        assert_eq!(snap.p99_ns, 42_000);
    }

    #[test]
    fn check_budget_empty_snapshot_no_violations() {
        let snap = PercentileSnapshot::from_sorted(&[]);
        let violations = snap.check_budget(&PauseBudget::new(0, 0, 0), "global");
        assert!(violations.is_empty());
    }

    #[test]
    fn check_budget_at_exact_threshold_no_violation() {
        let snap = PercentileSnapshot {
            count: 1,
            min_ns: 500_000,
            max_ns: 500_000,
            p50_ns: 500_000,
            p95_ns: 500_000,
            p99_ns: 500_000,
        };
        let budget = PauseBudget::new(500_000, 500_000, 500_000);
        let violations = snap.check_budget(&budget, "global");
        assert!(violations.is_empty());
    }

    #[test]
    fn check_budget_one_ns_over_triggers_violation() {
        let snap = PercentileSnapshot {
            count: 1,
            min_ns: 500_001,
            max_ns: 500_001,
            p50_ns: 500_001,
            p95_ns: 500_001,
            p99_ns: 500_001,
        };
        let budget = PauseBudget::new(500_000, 500_000, 500_000);
        let violations = snap.check_budget(&budget, "global");
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn tracker_extensions_btree_alphabetical_order() {
        let mut tracker = PauseTracker::new(PauseBudget::default());
        tracker.record(&make_event(1, "ext-zebra", 100, 0, 0));
        tracker.record(&make_event(2, "ext-alpha", 100, 0, 0));
        tracker.record(&make_event(3, "ext-middle", 100, 0, 0));
        let exts = tracker.extensions();
        assert_eq!(exts, vec!["ext-alpha", "ext-middle", "ext-zebra"]);
    }

    #[test]
    fn pause_distribution_report_empty_tracker_is_deterministic() {
        let tracker = PauseTracker::new(PauseBudget::new(100, 200, 300));
        let report = tracker.pause_distribution_report();
        assert_eq!(
            report.schema_version,
            PAUSE_DISTRIBUTION_REPORT_SCHEMA.to_string()
        );
        assert_eq!(report.sample_count, 0);
        assert_eq!(report.global_percentiles.count, 0);
        assert!(report.histogram.is_empty());
        assert!(report.per_extension_percentiles.is_empty());
        assert!(report.budget_violations.is_empty());
        assert_eq!(report.policy_state, PauseBudgetPolicyState::WithinBudget);
        assert!(!report.policy_transition.transitioned);
    }

    #[test]
    fn pause_distribution_report_histogram_counts_match_samples() {
        let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 30_000));
        for i in 1..=25 {
            let ext = if i % 2 == 0 { "ext-a" } else { "ext-b" };
            tracker.record(&make_event(i, ext, i * 100, 0, 0));
        }

        let report = tracker.pause_distribution_report();
        let histogram_total: u64 = report.histogram.iter().map(|bucket| bucket.count).sum();
        assert_eq!(histogram_total, report.sample_count);
        assert_eq!(report.sample_count, 25);
        assert!(report.per_extension_percentiles.contains_key("ext-a"));
        assert!(report.per_extension_percentiles.contains_key("ext-b"));
    }

    #[test]
    fn pause_distribution_report_histogram_stays_valid_for_identical_pauses() {
        let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 30_000));
        for sequence in 1..=4 {
            tracker.record(&make_event(sequence, "ext-a", 1_000, 0, 0));
        }

        let report = tracker.pause_distribution_report();
        assert_eq!(report.histogram.len(), 1);
        assert_eq!(report.histogram[0].lower_bound_ns, 1_000);
        assert_eq!(report.histogram[0].upper_bound_ns, 1_000);
        assert_eq!(report.histogram[0].count, report.sample_count);
        assert!(
            report
                .histogram
                .iter()
                .all(|bucket| bucket.lower_bound_ns <= bucket.upper_bound_ns)
        );
    }

    #[test]
    fn pause_distribution_report_tracks_policy_transition_from_within_to_violated() {
        let mut tracker = PauseTracker::new(PauseBudget::new(5_000, 8_000, 9_000));
        tracker.record(&make_event(1, "ext-a", 2_000, 0, 0));
        let baseline_state = tracker.budget_policy_state();
        assert_eq!(baseline_state, PauseBudgetPolicyState::WithinBudget);

        tracker.set_budget(PauseBudget::new(500, 500, 500));
        let report = tracker.pause_distribution_report_with_transition(baseline_state);
        assert_eq!(report.policy_state, PauseBudgetPolicyState::Violated);
        assert!(report.policy_transition.transitioned);
        assert_eq!(
            report.policy_transition.from_state,
            PauseBudgetPolicyState::WithinBudget
        );
        assert_eq!(
            report.policy_transition.to_state,
            PauseBudgetPolicyState::Violated
        );
        assert!(!report.budget_violations.is_empty());
    }
}
