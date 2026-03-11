#![forbid(unsafe_code)]

//! Integration tests for the `gc_pause` module.
//!
//! Covers: PauseBudget, PauseRecord, Percentile, BudgetViolation,
//! PercentileSnapshot, PauseTracker.
//!
//! Sections: Display impls, construction/defaults, budget checks,
//! percentile computation, ring-buffer capacity, per-extension tracking,
//! serde roundtrips, deterministic ordering, integration with GcCollector.

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

use frankenengine_engine::gc::{GcCollector, GcConfig, GcEvent, GcPhase};
use frankenengine_engine::gc_pause::{
    BudgetViolation, PAUSE_DISTRIBUTION_REPORT_SCHEMA, PauseBudget, PauseBudgetPolicyState,
    PauseRecord, PauseTracker, Percentile, PercentileSnapshot,
};

// ===========================================================================
// Helpers
// ===========================================================================

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

fn make_simple_event(seq: u64, ext: &str, pause_ns: u64) -> GcEvent {
    make_event(seq, ext, pause_ns, 0, 0)
}

// ===========================================================================
// 1. PauseBudget — construction & defaults
// ===========================================================================

#[test]
fn pause_budget_default_values() {
    let b = PauseBudget::default();
    assert_eq!(b.p50_ns, 500_000); // 500 us
    assert_eq!(b.p95_ns, 2_000_000); // 2 ms
    assert_eq!(b.p99_ns, 10_000_000); // 10 ms
}

#[test]
fn pause_budget_new_constructor() {
    let b = PauseBudget::new(100, 200, 300);
    assert_eq!(b.p50_ns, 100);
    assert_eq!(b.p95_ns, 200);
    assert_eq!(b.p99_ns, 300);
}

#[test]
fn pause_budget_clone_and_copy() {
    let b = PauseBudget::new(1, 2, 3);
    let copied = b;
    assert_eq!(b, copied);
}

#[test]
fn pause_budget_serde_round_trip() {
    let b = PauseBudget::new(111, 222, 333);
    let json = serde_json::to_string(&b).unwrap();
    let restored: PauseBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, restored);
}

// ===========================================================================
// 2. PauseRecord — construction & from_gc_event
// ===========================================================================

#[test]
fn pause_record_from_gc_event_maps_all_fields() {
    let event = make_event(1, "ext-a", 1500, 5, 1024);
    let record = PauseRecord::from_gc_event(&event);
    assert_eq!(record.sequence, 1);
    assert_eq!(record.extension_id, "ext-a");
    assert_eq!(record.pause_ns, 1500);
    assert_eq!(record.objects_scanned, 10); // marked_count
    assert_eq!(record.objects_collected, 5); // swept_count
    assert_eq!(record.bytes_reclaimed, 1024);
}

#[test]
fn pause_record_serde_round_trip() {
    let event = make_event(42, "ext-test", 5000, 3, 512);
    let record = PauseRecord::from_gc_event(&event);
    let json = serde_json::to_string(&record).unwrap();
    let restored: PauseRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

#[test]
fn pause_record_clone() {
    let event = make_event(1, "ext-a", 100, 1, 64);
    let record = PauseRecord::from_gc_event(&event);
    let cloned = record.clone();
    assert_eq!(record, cloned);
}

// ===========================================================================
// 3. Percentile — Display & serde
// ===========================================================================

#[test]
fn percentile_display_all_variants() {
    assert_eq!(Percentile::P50.to_string(), "p50");
    assert_eq!(Percentile::P95.to_string(), "p95");
    assert_eq!(Percentile::P99.to_string(), "p99");
}

#[test]
fn percentile_serde_round_trip() {
    for pct in &[Percentile::P50, Percentile::P95, Percentile::P99] {
        let json = serde_json::to_string(pct).unwrap();
        let restored: Percentile = serde_json::from_str(&json).unwrap();
        assert_eq!(pct, &restored);
    }
}

#[test]
fn percentile_clone_and_copy() {
    let p = Percentile::P95;
    let copied = p;
    assert_eq!(p, copied);
}

// ===========================================================================
// 4. BudgetViolation — Display & serde
// ===========================================================================

#[test]
fn budget_violation_display() {
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
fn budget_violation_display_p50() {
    let v = BudgetViolation {
        percentile: Percentile::P50,
        observed_ns: 600,
        budget_ns: 500,
        scope: "global".to_string(),
    };
    let msg = v.to_string();
    assert!(msg.contains("p50"), "got: {msg}");
    assert!(msg.contains("global"), "got: {msg}");
    assert!(msg.contains("600"), "got: {msg}");
    assert!(msg.contains("500"), "got: {msg}");
}

#[test]
fn budget_violation_display_p99() {
    let v = BudgetViolation {
        percentile: Percentile::P99,
        observed_ns: 100_000,
        budget_ns: 50_000,
        scope: "ext-z".to_string(),
    };
    let msg = v.to_string();
    assert!(msg.contains("p99"), "got: {msg}");
    assert!(msg.contains("ext-z"), "got: {msg}");
}

#[test]
fn budget_violation_serde_round_trip() {
    let v = BudgetViolation {
        percentile: Percentile::P99,
        observed_ns: 10_000,
        budget_ns: 5_000,
        scope: "ext-b".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let restored: BudgetViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

// ===========================================================================
// 5. PercentileSnapshot — check_budget
// ===========================================================================

#[test]
fn percentile_snapshot_no_violations_within_budget() {
    let budget = PauseBudget::new(1000, 2000, 5000);
    // Construct a snapshot by recording events through PauseTracker
    let mut tracker = PauseTracker::new(budget);
    tracker.record(&make_simple_event(1, "ext-a", 500));
    tracker.record(&make_simple_event(2, "ext-a", 800));
    tracker.record(&make_simple_event(3, "ext-a", 900));

    let snap = tracker.global_percentiles();
    let violations = snap.check_budget(&budget, "test");
    assert!(violations.is_empty());
}

#[test]
fn percentile_snapshot_p50_violation() {
    let budget = PauseBudget::new(100, 2_000_000, 10_000_000);
    let mut tracker = PauseTracker::new(budget);
    // All pauses above 100 ns, so p50 will exceed budget
    for i in 1..=10 {
        tracker.record(&make_simple_event(i, "ext-a", 200));
    }

    let snap = tracker.global_percentiles();
    let violations = snap.check_budget(&budget, "test");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].percentile, Percentile::P50);
    assert_eq!(violations[0].observed_ns, 200);
    assert_eq!(violations[0].budget_ns, 100);
}

#[test]
fn percentile_snapshot_multiple_violations() {
    let budget = PauseBudget::new(100, 200, 300);
    let mut tracker = PauseTracker::new(budget);
    for i in 1..=10 {
        tracker.record(&make_simple_event(i, "ext-a", 500));
    }

    let snap = tracker.global_percentiles();
    let violations = snap.check_budget(&budget, "test");
    // All percentiles (p50, p95, p99) = 500, all exceed respective budgets
    assert_eq!(violations.len(), 3);
}

#[test]
fn percentile_snapshot_empty_no_violations() {
    let budget = PauseBudget::new(100, 200, 300);
    let tracker = PauseTracker::new(budget);
    let snap = tracker.global_percentiles();
    let violations = snap.check_budget(&budget, "test");
    assert!(violations.is_empty());
}

#[test]
fn percentile_snapshot_serde_round_trip() {
    let mut tracker = PauseTracker::default();
    for i in 1..=20 {
        tracker.record(&make_simple_event(i, "ext-a", i * 100));
    }
    let snap = tracker.global_percentiles();
    let json = serde_json::to_string(&snap).unwrap();
    let restored: PercentileSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

// ===========================================================================
// 6. PercentileSnapshot — percentile computation correctness
// ===========================================================================

#[test]
fn percentile_single_value() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-a", 100));
    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 1);
    assert_eq!(snap.min_ns, 100);
    assert_eq!(snap.max_ns, 100);
    assert_eq!(snap.p50_ns, 100);
    assert_eq!(snap.p95_ns, 100);
    assert_eq!(snap.p99_ns, 100);
}

#[test]
fn percentile_hundred_values() {
    let mut tracker = PauseTracker::default();
    for i in 1..=100 {
        tracker.record(&make_simple_event(i, "ext-a", i * 100));
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
fn percentile_five_values() {
    let mut tracker = PauseTracker::default();
    // Values: 10, 20, 30, 40, 50
    for (i, val) in [10u64, 20, 30, 40, 50].iter().enumerate() {
        tracker.record(&make_simple_event((i + 1) as u64, "ext-a", *val));
    }
    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 5);
    assert_eq!(snap.min_ns, 10);
    assert_eq!(snap.max_ns, 50);
    // p50 of 5 items: ceil(0.5*5)=3, index 2, value 30
    assert_eq!(snap.p50_ns, 30);
    // p95 of 5 items: ceil(0.95*5)=5, index 4, value 50
    assert_eq!(snap.p95_ns, 50);
    // p99 of 5 items: ceil(0.99*5)=5, index 4, value 50
    assert_eq!(snap.p99_ns, 50);
}

#[test]
fn percentile_two_values() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-a", 200));

    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 2);
    assert_eq!(snap.min_ns, 100);
    assert_eq!(snap.max_ns, 200);
    // p50: ceil(0.5*2)=1, index 0, value 100
    assert_eq!(snap.p50_ns, 100);
    // p95: ceil(0.95*2)=2, index 1, value 200
    assert_eq!(snap.p95_ns, 200);
    // p99: ceil(0.99*2)=2, index 1, value 200
    assert_eq!(snap.p99_ns, 200);
}

#[test]
fn percentile_identical_values() {
    let mut tracker = PauseTracker::default();
    for i in 1..=50 {
        tracker.record(&make_simple_event(i, "ext-a", 1000));
    }
    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 50);
    assert_eq!(snap.min_ns, 1000);
    assert_eq!(snap.max_ns, 1000);
    assert_eq!(snap.p50_ns, 1000);
    assert_eq!(snap.p95_ns, 1000);
    assert_eq!(snap.p99_ns, 1000);
}

// ===========================================================================
// 7. PauseTracker — construction & defaults
// ===========================================================================

#[test]
fn pause_tracker_default() {
    let tracker = PauseTracker::default();
    assert_eq!(tracker.count(), 0);
    assert!(tracker.records().is_empty());
    assert!(tracker.within_budget());
    let budget = tracker.budget();
    assert_eq!(budget.p50_ns, 500_000);
}

#[test]
fn pause_tracker_new_with_custom_budget() {
    let budget = PauseBudget::new(100, 200, 300);
    let tracker = PauseTracker::new(budget);
    assert_eq!(tracker.budget().p50_ns, 100);
    assert_eq!(tracker.budget().p95_ns, 200);
    assert_eq!(tracker.budget().p99_ns, 300);
    assert_eq!(tracker.count(), 0);
}

#[test]
fn pause_tracker_with_capacity() {
    let budget = PauseBudget::default();
    let tracker = PauseTracker::with_capacity(budget, 10);
    assert_eq!(tracker.count(), 0);
}

// ===========================================================================
// 8. PauseTracker — record
// ===========================================================================

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
fn tracker_records_returns_slice() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_event(1, "ext-a", 1000, 5, 512));
    tracker.record(&make_event(2, "ext-b", 2000, 3, 256));

    let records = tracker.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].sequence, 1);
    assert_eq!(records[0].extension_id, "ext-a");
    assert_eq!(records[1].sequence, 2);
    assert_eq!(records[1].extension_id, "ext-b");
}

// ===========================================================================
// 9. PauseTracker — global percentiles
// ===========================================================================

#[test]
fn tracker_global_percentiles() {
    let mut tracker = PauseTracker::default();
    for i in 1..=100 {
        tracker.record(&make_simple_event(i, "ext-a", i * 100));
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
fn tracker_global_percentiles_empty() {
    let tracker = PauseTracker::default();
    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 0);
    assert_eq!(snap.p50_ns, 0);
    assert_eq!(snap.p95_ns, 0);
    assert_eq!(snap.p99_ns, 0);
}

// ===========================================================================
// 10. PauseTracker — per-extension percentiles
// ===========================================================================

#[test]
fn tracker_per_extension_percentiles() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-a", 1000));
    tracker.record(&make_simple_event(2, "ext-a", 2000));
    tracker.record(&make_simple_event(3, "ext-a", 3000));
    tracker.record(&make_simple_event(4, "ext-b", 500));

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
fn tracker_extension_count() {
    let mut tracker = PauseTracker::default();
    assert_eq!(tracker.extension_count("ext-a"), 0);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    assert_eq!(tracker.extension_count("ext-a"), 1);

    tracker.record(&make_simple_event(2, "ext-a", 200));
    assert_eq!(tracker.extension_count("ext-a"), 2);
    assert_eq!(tracker.extension_count("ext-b"), 0);
}

// ===========================================================================
// 11. PauseTracker — budget checks
// ===========================================================================

#[test]
fn tracker_within_budget_when_all_pauses_low() {
    let budget = PauseBudget::new(10_000, 20_000, 50_000);
    let mut tracker = PauseTracker::new(budget);
    tracker.record(&make_simple_event(1, "ext-a", 5000));
    tracker.record(&make_simple_event(2, "ext-a", 8000));

    assert!(tracker.within_budget());
    assert!(tracker.check_budget().is_empty());
}

#[test]
fn tracker_budget_violations_global_and_per_extension() {
    let budget = PauseBudget::new(100, 200, 300);
    let mut tracker = PauseTracker::new(budget);
    // All pauses exceed even p50 budget
    tracker.record(&make_simple_event(1, "ext-a", 500));
    tracker.record(&make_simple_event(2, "ext-a", 600));

    assert!(!tracker.within_budget());
    let violations = tracker.check_budget();
    // Should have violations for global and ext-a
    assert!(!violations.is_empty());
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
fn tracker_budget_violations_multiple_extensions() {
    let budget = PauseBudget::new(100, 200, 300);
    let mut tracker = PauseTracker::new(budget);
    tracker.record(&make_simple_event(1, "ext-a", 500));
    tracker.record(&make_simple_event(2, "ext-b", 500));

    let violations = tracker.check_budget();
    // Violations for global, ext-a, and ext-b
    let global_violations: Vec<_> = violations.iter().filter(|v| v.scope == "global").collect();
    let ext_a_violations: Vec<_> = violations.iter().filter(|v| v.scope == "ext-a").collect();
    let ext_b_violations: Vec<_> = violations.iter().filter(|v| v.scope == "ext-b").collect();
    assert!(!global_violations.is_empty());
    assert!(!ext_a_violations.is_empty());
    assert!(!ext_b_violations.is_empty());
}

#[test]
fn tracker_budget_check_empty_tracker_no_violations() {
    let budget = PauseBudget::new(1, 1, 1);
    let tracker = PauseTracker::new(budget);
    assert!(tracker.within_budget());
    assert!(tracker.check_budget().is_empty());
}

#[test]
fn tracker_budget_exactly_at_threshold_no_violation() {
    let budget = PauseBudget::new(500, 1000, 5000);
    let mut tracker = PauseTracker::new(budget);
    // Exactly at p50 budget boundary (not exceeding)
    tracker.record(&make_simple_event(1, "ext-a", 500));
    // p50 = 500 which equals budget, NOT > budget
    assert!(tracker.within_budget());
}

#[test]
fn tracker_budget_one_above_threshold_causes_violation() {
    let budget = PauseBudget::new(500, 1000, 5000);
    let mut tracker = PauseTracker::new(budget);
    tracker.record(&make_simple_event(1, "ext-a", 501));
    // p50 = 501 > 500
    assert!(!tracker.within_budget());
}

// ===========================================================================
// 12. PauseTracker — ring-buffer capacity
// ===========================================================================

#[test]
fn tracker_ring_buffer_evicts_oldest() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 3);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-a", 200));
    tracker.record(&make_simple_event(3, "ext-a", 300));
    assert_eq!(tracker.count(), 3);

    // Adding a 4th record should evict the oldest (sequence 1)
    tracker.record(&make_simple_event(4, "ext-a", 400));
    assert_eq!(tracker.count(), 3);
    assert_eq!(tracker.records()[0].sequence, 2);
    assert_eq!(tracker.records()[1].sequence, 3);
    assert_eq!(tracker.records()[2].sequence, 4);
}

#[test]
fn tracker_ring_buffer_updates_per_extension_data() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 2);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-a", 200));
    assert_eq!(tracker.extension_count("ext-a"), 2);

    // Evict first record
    tracker.record(&make_simple_event(3, "ext-a", 300));
    assert_eq!(tracker.extension_count("ext-a"), 2);

    // Percentiles should reflect remaining records (200, 300)
    let snap = tracker.extension_percentiles("ext-a");
    assert_eq!(snap.count, 2);
    assert_eq!(snap.min_ns, 200);
    assert_eq!(snap.max_ns, 300);
}

#[test]
fn tracker_ring_buffer_removes_extension_when_all_evicted() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 2);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-b", 200));
    assert_eq!(tracker.extension_count("ext-a"), 1);

    // Evict ext-a's record
    tracker.record(&make_simple_event(3, "ext-b", 300));
    assert_eq!(tracker.extension_count("ext-a"), 0);
    assert_eq!(tracker.extension_count("ext-b"), 2);

    // ext-a should no longer appear in extensions list
    let exts = tracker.extensions();
    assert!(!exts.contains(&"ext-a"));
}

#[test]
fn tracker_ring_buffer_capacity_one() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 1);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    assert_eq!(tracker.count(), 1);

    tracker.record(&make_simple_event(2, "ext-a", 200));
    assert_eq!(tracker.count(), 1);
    assert_eq!(tracker.records()[0].sequence, 2);
    assert_eq!(tracker.records()[0].pause_ns, 200);
}

#[test]
fn tracker_unlimited_capacity_grows_unbounded() {
    let mut tracker = PauseTracker::default(); // capacity = 0 (unlimited)
    for i in 1..=1000 {
        tracker.record(&make_simple_event(i, "ext-a", i * 10));
    }
    assert_eq!(tracker.count(), 1000);
}

// ===========================================================================
// 13. PauseTracker — extensions list (deterministic order)
// ===========================================================================

#[test]
fn tracker_extensions_deterministic_order() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-c", 100));
    tracker.record(&make_simple_event(2, "ext-a", 200));
    tracker.record(&make_simple_event(3, "ext-b", 300));

    let exts = tracker.extensions();
    assert_eq!(exts, vec!["ext-a", "ext-b", "ext-c"]);
}

#[test]
fn tracker_extensions_empty_when_no_records() {
    let tracker = PauseTracker::default();
    assert!(tracker.extensions().is_empty());
}

// ===========================================================================
// 14. PauseTracker — aggregate statistics
// ===========================================================================

#[test]
fn tracker_total_bytes_reclaimed() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_event(1, "ext-a", 100, 5, 256));
    tracker.record(&make_event(2, "ext-b", 200, 3, 128));
    tracker.record(&make_event(3, "ext-a", 300, 2, 64));
    assert_eq!(tracker.total_bytes_reclaimed(), 448);
}

#[test]
fn tracker_total_objects_collected() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_event(1, "ext-a", 100, 5, 256));
    tracker.record(&make_event(2, "ext-b", 200, 3, 128));
    assert_eq!(tracker.total_objects_collected(), 8);
}

#[test]
fn tracker_total_bytes_reclaimed_zero_when_empty() {
    let tracker = PauseTracker::default();
    assert_eq!(tracker.total_bytes_reclaimed(), 0);
}

#[test]
fn tracker_total_objects_collected_zero_when_empty() {
    let tracker = PauseTracker::default();
    assert_eq!(tracker.total_objects_collected(), 0);
}

// ===========================================================================
// 15. PauseTracker — set_budget
// ===========================================================================

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
fn tracker_set_budget_affects_subsequent_checks() {
    let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 50_000));
    tracker.record(&make_simple_event(1, "ext-a", 500));
    assert!(tracker.within_budget());

    // Tighten budget so existing data now violates it
    tracker.set_budget(PauseBudget::new(100, 200, 300));
    assert!(!tracker.within_budget());
}

// ===========================================================================
// 16. PauseTracker — serialization round-trip
// ===========================================================================

#[test]
fn pause_tracker_serde_round_trip() {
    let mut tracker = PauseTracker::new(PauseBudget::new(1000, 2000, 5000));
    tracker.record(&make_event(1, "ext-a", 500, 3, 256));
    tracker.record(&make_event(2, "ext-b", 800, 1, 128));

    let json = serde_json::to_string(&tracker).unwrap();
    let restored: PauseTracker = serde_json::from_str(&json).unwrap();

    assert_eq!(tracker.count(), restored.count());
    assert_eq!(tracker.global_percentiles(), restored.global_percentiles());
    assert_eq!(
        tracker.extension_percentiles("ext-a"),
        restored.extension_percentiles("ext-a")
    );
    assert_eq!(
        tracker.extension_percentiles("ext-b"),
        restored.extension_percentiles("ext-b")
    );
    assert_eq!(tracker.budget().p50_ns, restored.budget().p50_ns);
}

#[test]
fn pause_tracker_serde_preserves_ring_buffer_capacity() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 5);
    for i in 1..=10 {
        tracker.record(&make_simple_event(i, "ext-a", i * 100));
    }
    // Should have been capped to 5 records
    assert_eq!(tracker.count(), 5);

    let json = serde_json::to_string(&tracker).unwrap();
    let mut restored: PauseTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.count(), 5);

    // Adding more should still respect capacity
    restored.record(&make_simple_event(11, "ext-a", 1100));
    assert_eq!(restored.count(), 5);
}

// ===========================================================================
// 17. PauseTracker — integration with GcCollector
// ===========================================================================

#[test]
fn integration_gc_collector_to_pause_tracker() {
    let mut gc = GcCollector::new(GcConfig::deterministic());
    gc.register_heap("ext-a".to_string()).unwrap();

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

#[test]
fn integration_gc_collector_multiple_collections() {
    let mut gc = GcCollector::new(GcConfig::deterministic());
    gc.register_heap("ext-a".to_string()).unwrap();
    gc.register_heap("ext-b".to_string()).unwrap();

    let mut tracker = PauseTracker::default();

    // Collect ext-a several times
    for _ in 0..5 {
        let obj = gc.allocate("ext-a", 50).unwrap();
        gc.unroot("ext-a", obj).unwrap();
        let event = gc.collect("ext-a").unwrap();
        tracker.record(&event);
    }

    // Collect ext-b
    let obj = gc.allocate("ext-b", 200).unwrap();
    gc.unroot("ext-b", obj).unwrap();
    let event = gc.collect("ext-b").unwrap();
    tracker.record(&event);

    assert_eq!(tracker.count(), 6);
    assert_eq!(tracker.extension_count("ext-a"), 5);
    assert_eq!(tracker.extension_count("ext-b"), 1);

    let exts = tracker.extensions();
    assert_eq!(exts, vec!["ext-a", "ext-b"]);
}

#[test]
fn integration_gc_events_feed_pause_tracker_for_budget() {
    let mut gc = GcCollector::new(GcConfig::deterministic());
    gc.register_heap("ext-a".to_string()).unwrap();

    // Use a very tight budget that the deterministic pause (1000ns) would exceed
    let tight_budget = PauseBudget::new(500, 500, 500);
    let mut tracker = PauseTracker::new(tight_budget);

    let obj = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", obj).unwrap();
    let event = gc.collect("ext-a").unwrap();
    tracker.record(&event);

    assert!(!tracker.within_budget());
    let violations = tracker.check_budget();
    // At least p50 should be violated
    assert!(
        violations
            .iter()
            .any(|v| v.percentile == Percentile::P50 && v.observed_ns == 1000)
    );
}

// ===========================================================================
// 18. Deterministic replay — identical pause tracking
// ===========================================================================

#[test]
fn deterministic_replay_produces_identical_pause_tracking() {
    fn run_tracking() -> (PercentileSnapshot, Vec<BudgetViolation>) {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-a".to_string()).unwrap();
        gc.register_heap("ext-b".to_string()).unwrap();

        let budget = PauseBudget::new(500, 800, 900);
        let mut tracker = PauseTracker::new(budget);

        for i in 0..10 {
            let obj = gc.allocate("ext-a", (i + 1) * 10).unwrap();
            gc.unroot("ext-a", obj).unwrap();
            let event = gc.collect("ext-a").unwrap();
            tracker.record(&event);
        }

        for i in 0..5 {
            let obj = gc.allocate("ext-b", (i + 1) * 20).unwrap();
            gc.unroot("ext-b", obj).unwrap();
            let event = gc.collect("ext-b").unwrap();
            tracker.record(&event);
        }

        (tracker.global_percentiles(), tracker.check_budget())
    }

    let (snap1, violations1) = run_tracking();
    let (snap2, violations2) = run_tracking();
    assert_eq!(snap1, snap2);
    assert_eq!(violations1, violations2);
}

// ===========================================================================
// 19. Edge cases
// ===========================================================================

#[test]
fn pause_record_from_zero_pause_event() {
    let event = make_event(1, "ext-a", 0, 0, 0);
    let record = PauseRecord::from_gc_event(&event);
    assert_eq!(record.pause_ns, 0);
    assert_eq!(record.objects_scanned, 10); // marked_count from helper
    assert_eq!(record.objects_collected, 0);
    assert_eq!(record.bytes_reclaimed, 0);
}

#[test]
fn tracker_with_very_large_pause_values() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-a", u64::MAX));
    let snap = tracker.global_percentiles();
    assert_eq!(snap.max_ns, u64::MAX);
    assert_eq!(snap.p99_ns, u64::MAX);
}

#[test]
fn tracker_many_extensions() {
    let mut tracker = PauseTracker::default();
    for i in 0..100 {
        let ext = format!("ext-{i:03}");
        tracker.record(&make_simple_event(i + 1, &ext, (i + 1) * 100));
    }
    assert_eq!(tracker.count(), 100);
    let exts = tracker.extensions();
    assert_eq!(exts.len(), 100);
    // BTreeMap ensures alphabetical order
    assert_eq!(exts[0], "ext-000");
    assert_eq!(exts[99], "ext-099");
}

#[test]
fn ring_buffer_with_mixed_extensions_evicts_correctly() {
    let budget = PauseBudget::default();
    let mut tracker = PauseTracker::with_capacity(budget, 3);

    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-b", 200));
    tracker.record(&make_simple_event(3, "ext-c", 300));
    assert_eq!(tracker.count(), 3);

    // Evict ext-a's record by adding a new one
    tracker.record(&make_simple_event(4, "ext-d", 400));
    assert_eq!(tracker.count(), 3);
    assert_eq!(tracker.extension_count("ext-a"), 0);
    assert_eq!(tracker.extension_count("ext-b"), 1);
    assert_eq!(tracker.extension_count("ext-c"), 1);
    assert_eq!(tracker.extension_count("ext-d"), 1);
}

#[test]
fn percentile_snapshot_clone_and_copy() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(1, "ext-a", 100));
    let snap = tracker.global_percentiles();
    let copied = snap;
    assert_eq!(snap, copied);
}

#[test]
fn budget_violation_scope_can_be_any_string() {
    // Verify the scope field is just a plain string, no constraints
    let v = BudgetViolation {
        percentile: Percentile::P50,
        observed_ns: 100,
        budget_ns: 50,
        scope: "some/complex::scope-name".to_string(),
    };
    let msg = v.to_string();
    assert!(msg.contains("some/complex::scope-name"));
}

// ===========================================================================
// 20. Percentile snapshot check_budget with exact boundary
// ===========================================================================

#[test]
fn check_budget_exactly_at_boundary_no_violation() {
    // When observed == budget, it is NOT a violation (only > is)
    let budget = PauseBudget::new(1000, 2000, 5000);
    let mut tracker = PauseTracker::new(budget);
    tracker.record(&make_simple_event(1, "ext-a", 1000));

    let snap = tracker.global_percentiles();
    let violations = snap.check_budget(&budget, "test");
    assert!(violations.is_empty());
}

// ===========================================================================
// 21. Pause tracker records preserve insertion order
// ===========================================================================

#[test]
fn records_preserve_insertion_order() {
    let mut tracker = PauseTracker::default();
    tracker.record(&make_simple_event(3, "ext-c", 300));
    tracker.record(&make_simple_event(1, "ext-a", 100));
    tracker.record(&make_simple_event(2, "ext-b", 200));

    let records = tracker.records();
    assert_eq!(records[0].sequence, 3);
    assert_eq!(records[1].sequence, 1);
    assert_eq!(records[2].sequence, 2);
}

// ===========================================================================
// 22. Global percentiles compute from all extensions combined
// ===========================================================================

#[test]
fn global_percentiles_mix_all_extensions() {
    let mut tracker = PauseTracker::default();
    // ext-a has low pauses, ext-b has high pauses
    for i in 1..=50 {
        tracker.record(&make_simple_event(i, "ext-a", 100));
    }
    for i in 51..=100 {
        tracker.record(&make_simple_event(i, "ext-b", 900));
    }

    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 100);
    assert_eq!(snap.min_ns, 100);
    assert_eq!(snap.max_ns, 900);
    // p50 of 100 items: first 50 are 100, next 50 are 900
    // sorted: [100 x 50, 900 x 50]
    // p50: ceil(0.5*100)=50, index 49, value 100
    assert_eq!(snap.p50_ns, 100);
    // p95: ceil(0.95*100)=95, index 94, value 900
    assert_eq!(snap.p95_ns, 900);
}

// ===========================================================================
// 23. Pause distribution report and policy transitions
// ===========================================================================

#[test]
fn pause_distribution_report_contains_expected_contract_fields() {
    let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 30_000));
    tracker.record(&make_simple_event(1, "ext-b", 1000));
    tracker.record(&make_simple_event(2, "ext-a", 2000));
    tracker.record(&make_simple_event(3, "ext-a", 3000));

    let report = tracker.pause_distribution_report();
    assert_eq!(report.schema_version, PAUSE_DISTRIBUTION_REPORT_SCHEMA);
    assert_eq!(report.sample_count, 3);
    assert_eq!(report.global_percentiles.count, 3);
    assert_eq!(
        report
            .per_extension_percentiles
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["ext-a".to_string(), "ext-b".to_string()]
    );
    let histogram_total: u64 = report.histogram.iter().map(|bucket| bucket.count).sum();
    assert_eq!(histogram_total, report.sample_count);
    assert_eq!(report.policy_state, PauseBudgetPolicyState::WithinBudget);
}

#[test]
fn pause_distribution_report_histogram_does_not_emit_invalid_bounds_for_identical_pauses() {
    let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 30_000));
    for sequence in 1..=4 {
        tracker.record(&make_simple_event(sequence, "ext-a", 1000));
    }

    let report = tracker.pause_distribution_report();
    assert_eq!(report.histogram.len(), 1);
    assert_eq!(report.histogram[0].lower_bound_ns, 1000);
    assert_eq!(report.histogram[0].upper_bound_ns, 1000);
    assert_eq!(report.histogram[0].count, report.sample_count);
    assert!(
        report
            .histogram
            .iter()
            .all(|bucket| bucket.lower_bound_ns <= bucket.upper_bound_ns)
    );
}

#[test]
fn pause_distribution_report_policy_transition_detects_budget_tightening() {
    let mut tracker = PauseTracker::new(PauseBudget::new(10_000, 20_000, 30_000));
    tracker.record(&make_simple_event(1, "ext-a", 500));
    let previous_state = tracker.budget_policy_state();
    assert_eq!(previous_state, PauseBudgetPolicyState::WithinBudget);

    tracker.set_budget(PauseBudget::new(100, 100, 100));
    let report = tracker.pause_distribution_report_with_transition(previous_state);
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
