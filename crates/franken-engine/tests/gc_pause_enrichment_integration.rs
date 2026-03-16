//! Enrichment integration tests for `gc_pause` module.
//!
//! Covers ring-buffer eviction edge cases, percentile computation invariants,
//! histogram boundary conditions, budget checking with mixed thresholds,
//! policy transition determinism, serde roundtrips with stress data, and
//! aggregate correctness after evictions.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::gc::{GcEvent, GcPhase};
use frankenengine_engine::gc_pause::{
    BudgetViolation, PAUSE_DISTRIBUTION_REPORT_SCHEMA, PauseBudget, PauseBudgetPolicyState,
    PauseDistributionReport, PauseRecord, PauseTracker, Percentile, PercentileSnapshot,
};

fn make_event(seq: u64, ext: &str, pause_ns: u64) -> GcEvent {
    GcEvent {
        sequence: seq,
        extension_id: ext.to_string(),
        phase: GcPhase::Complete,
        marked_count: pause_ns / 10,
        swept_count: pause_ns / 20,
        bytes_reclaimed: pause_ns * 8,
        pause_ns,
    }
}

fn tracker_with_events(budget: PauseBudget, events: &[GcEvent]) -> PauseTracker {
    let mut tracker = PauseTracker::new(budget);
    for event in events {
        tracker.record(event);
    }
    tracker
}

// =========================================================================
// Percentile ordering invariant: p50 <= p95 <= p99
// =========================================================================

#[test]
fn percentile_ordering_invariant_uniform_data() {
    let events: Vec<GcEvent> = (0..100)
        .map(|i| make_event(i, "ext-a", (i + 1) * 100))
        .collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert!(
        snap.p50_ns <= snap.p95_ns,
        "p50 ({}) > p95 ({})",
        snap.p50_ns,
        snap.p95_ns
    );
    assert!(
        snap.p95_ns <= snap.p99_ns,
        "p95 ({}) > p99 ({})",
        snap.p95_ns,
        snap.p99_ns
    );
    assert!(snap.min_ns <= snap.p50_ns);
    assert!(snap.p99_ns <= snap.max_ns);
}

#[test]
fn percentile_ordering_invariant_skewed_data() {
    // Most values small, one outlier
    let mut events: Vec<GcEvent> = (0..99).map(|i| make_event(i, "ext-a", 100)).collect();
    events.push(make_event(99, "ext-a", 1_000_000));
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert!(snap.p50_ns <= snap.p95_ns);
    assert!(snap.p95_ns <= snap.p99_ns);
}

#[test]
fn percentile_ordering_invariant_single_value() {
    let events = vec![make_event(0, "ext-a", 5000)];
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert_eq!(snap.p50_ns, 5000);
    assert_eq!(snap.p95_ns, 5000);
    assert_eq!(snap.p99_ns, 5000);
    assert_eq!(snap.min_ns, 5000);
    assert_eq!(snap.max_ns, 5000);
    assert_eq!(snap.count, 1);
}

#[test]
fn percentile_ordering_invariant_two_values() {
    let events = vec![make_event(0, "ext-a", 100), make_event(1, "ext-a", 10_000)];
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert!(snap.p50_ns <= snap.p95_ns);
    assert!(snap.p95_ns <= snap.p99_ns);
    assert_eq!(snap.min_ns, 100);
    assert_eq!(snap.max_ns, 10_000);
}

#[test]
fn percentile_ordering_all_identical_values() {
    let events: Vec<GcEvent> = (0..50).map(|i| make_event(i, "ext-a", 7777)).collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert_eq!(snap.p50_ns, 7777);
    assert_eq!(snap.p95_ns, 7777);
    assert_eq!(snap.p99_ns, 7777);
}

// =========================================================================
// Ring-buffer eviction edge cases
// =========================================================================

#[test]
fn ring_buffer_capacity_one_alternating_extensions() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 1);
    // Alternate between extensions
    for i in 0..10u64 {
        let ext = if i % 2 == 0 { "ext-a" } else { "ext-b" };
        tracker.record(&make_event(i, ext, (i + 1) * 100));
        assert_eq!(tracker.count(), 1);
    }
    // Only the last event should remain
    assert_eq!(tracker.count(), 1);
    let records = tracker.records();
    assert_eq!(records[0].sequence, 9);
    assert_eq!(records[0].extension_id, "ext-b");
}

#[test]
fn ring_buffer_eviction_preserves_per_extension_counts() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 3);
    // Add 3 events for ext-a
    for i in 0..3 {
        tracker.record(&make_event(i, "ext-a", 100));
    }
    assert_eq!(tracker.extension_count("ext-a"), 3);

    // Add 1 event for ext-b — evicts oldest ext-a
    tracker.record(&make_event(3, "ext-b", 200));
    assert_eq!(tracker.count(), 3);
    assert_eq!(tracker.extension_count("ext-a"), 2);
    assert_eq!(tracker.extension_count("ext-b"), 1);
}

#[test]
fn ring_buffer_eviction_removes_empty_extension() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 2);
    tracker.record(&make_event(0, "ext-a", 100));
    tracker.record(&make_event(1, "ext-b", 200));
    // Evict ext-a by adding ext-c
    tracker.record(&make_event(2, "ext-c", 300));
    assert_eq!(tracker.extension_count("ext-a"), 0);
    // ext-a should no longer be in extensions list
    assert!(!tracker.extensions().contains(&"ext-a"));
    assert_eq!(tracker.extensions().len(), 2);
}

#[test]
fn ring_buffer_eviction_with_duplicate_pause_values() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 3);
    // Add 3 events with same extension and same pause value
    tracker.record(&make_event(0, "ext-a", 500));
    tracker.record(&make_event(1, "ext-a", 500));
    tracker.record(&make_event(2, "ext-a", 500));
    assert_eq!(tracker.extension_count("ext-a"), 3);

    // Evict one — should remove first occurrence from per_extension
    tracker.record(&make_event(3, "ext-b", 700));
    assert_eq!(tracker.extension_count("ext-a"), 2);
    assert_eq!(tracker.count(), 3);
}

#[test]
fn ring_buffer_fifo_order() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 3);
    for i in 0..6u64 {
        tracker.record(&make_event(i, "ext-a", (i + 1) * 100));
    }
    // Only last 3 should remain
    let records = tracker.records();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].sequence, 3);
    assert_eq!(records[1].sequence, 4);
    assert_eq!(records[2].sequence, 5);
}

// =========================================================================
// Budget checking edge cases
// =========================================================================

#[test]
fn budget_exact_threshold_no_violation() {
    // Budget at exactly the pause value — strict > means no violation
    let budget = PauseBudget::new(500, 500, 500);
    let events = vec![make_event(0, "ext-a", 500)];
    let tracker = tracker_with_events(budget, &events);
    assert!(tracker.within_budget());
    assert!(tracker.check_budget().is_empty());
}

#[test]
fn budget_one_over_threshold_violation() {
    let budget = PauseBudget::new(500, 500, 500);
    let events = vec![make_event(0, "ext-a", 501)];
    let tracker = tracker_with_events(budget, &events);
    assert!(!tracker.within_budget());
    let violations = tracker.check_budget();
    assert!(!violations.is_empty());
}

#[test]
fn budget_mixed_zero_and_nonzero_thresholds() {
    // p50 budget is 0, p95 and p99 are generous
    let budget = PauseBudget::new(0, 1_000_000, 10_000_000);
    let events = vec![make_event(0, "ext-a", 1)]; // pause_ns = 1 > 0
    let tracker = tracker_with_events(budget, &events);
    let violations = tracker.check_budget();
    // Should violate p50 (1 > 0) but not p95 or p99
    let p50_violated = violations.iter().any(|v| v.percentile == Percentile::P50);
    let p95_violated = violations.iter().any(|v| v.percentile == Percentile::P95);
    assert!(p50_violated);
    assert!(!p95_violated);
}

#[test]
fn budget_empty_tracker_no_violations() {
    let budget = PauseBudget::new(0, 0, 0);
    let tracker = PauseTracker::new(budget);
    assert!(tracker.within_budget());
    assert!(tracker.check_budget().is_empty());
}

#[test]
fn budget_per_extension_violations() {
    let budget = PauseBudget::new(100, 200, 300);
    let mut tracker = PauseTracker::new(budget);
    // ext-a within budget
    tracker.record(&make_event(0, "ext-a", 50));
    // ext-b exceeds budget
    tracker.record(&make_event(1, "ext-b", 500));

    let violations = tracker.check_budget();
    let ext_b_violations: Vec<_> = violations
        .iter()
        .filter(|v| v.scope.contains("ext-b"))
        .collect();
    assert!(!ext_b_violations.is_empty());
}

// =========================================================================
// Policy transitions
// =========================================================================

#[test]
fn policy_no_transition_within_budget() {
    let budget = PauseBudget::default();
    let events = vec![make_event(0, "ext-a", 100)]; // well within budget
    let tracker = tracker_with_events(budget, &events);
    let transition = tracker.budget_policy_transition(PauseBudgetPolicyState::WithinBudget);
    assert!(!transition.transitioned);
    assert_eq!(transition.from_state, PauseBudgetPolicyState::WithinBudget);
    assert_eq!(transition.to_state, PauseBudgetPolicyState::WithinBudget);
    assert_eq!(transition.violation_count, 0);
}

#[test]
fn policy_transition_to_violated() {
    let budget = PauseBudget::new(100, 200, 300);
    let events = vec![make_event(0, "ext-a", 1_000_000)]; // way over budget
    let tracker = tracker_with_events(budget, &events);
    let transition = tracker.budget_policy_transition(PauseBudgetPolicyState::WithinBudget);
    assert!(transition.transitioned);
    assert_eq!(transition.to_state, PauseBudgetPolicyState::Violated);
    assert!(transition.violation_count > 0);
}

#[test]
fn policy_transition_back_to_within_budget() {
    let budget = PauseBudget::default();
    let events = vec![make_event(0, "ext-a", 100)]; // within budget
    let tracker = tracker_with_events(budget, &events);
    let transition = tracker.budget_policy_transition(PauseBudgetPolicyState::Violated);
    assert!(transition.transitioned);
    assert_eq!(transition.to_state, PauseBudgetPolicyState::WithinBudget);
}

#[test]
fn policy_state_display() {
    assert_eq!(
        format!("{}", PauseBudgetPolicyState::WithinBudget),
        "within_budget"
    );
    assert_eq!(format!("{}", PauseBudgetPolicyState::Violated), "violated");
}

// =========================================================================
// Aggregates after eviction
// =========================================================================

#[test]
fn aggregates_correct_after_eviction() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 3);
    tracker.record(&make_event(0, "ext-a", 100));
    tracker.record(&make_event(1, "ext-a", 200));
    tracker.record(&make_event(2, "ext-a", 300));
    // Before eviction: total bytes = (100+200+300)*8 = 4800
    assert_eq!(tracker.total_bytes_reclaimed(), 4800);

    // Evict oldest (100*8=800 bytes)
    tracker.record(&make_event(3, "ext-a", 400));
    // After eviction: total bytes = (200+300+400)*8 = 7200
    assert_eq!(tracker.total_bytes_reclaimed(), 7200);
    assert_eq!(tracker.total_objects_collected(), (200 + 300 + 400) / 20);
}

#[test]
fn aggregates_match_records_sum() {
    let events: Vec<GcEvent> = (0..20)
        .map(|i| make_event(i, &format!("ext-{}", i % 4), (i + 1) * 50))
        .collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let expected_bytes: u64 = tracker.records().iter().map(|r| r.bytes_reclaimed).sum();
    let expected_objects: u64 = tracker.records().iter().map(|r| r.objects_collected).sum();
    assert_eq!(tracker.total_bytes_reclaimed(), expected_bytes);
    assert_eq!(tracker.total_objects_collected(), expected_objects);
}

// =========================================================================
// Histogram edge cases
// =========================================================================

#[test]
fn histogram_single_value() {
    let events = vec![make_event(0, "ext-a", 1000)];
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let report = tracker.pause_distribution_report();
    assert!(!report.histogram.is_empty());
    for bucket in &report.histogram {
        assert!(bucket.lower_bound_ns <= bucket.upper_bound_ns);
    }
}

#[test]
fn histogram_two_extreme_values() {
    let events = vec![make_event(0, "ext-a", 1), make_event(1, "ext-a", 1_000_000)];
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let report = tracker.pause_distribution_report();
    assert!(!report.histogram.is_empty());
    for bucket in &report.histogram {
        assert!(
            bucket.lower_bound_ns <= bucket.upper_bound_ns,
            "invalid bucket: {} > {}",
            bucket.lower_bound_ns,
            bucket.upper_bound_ns
        );
    }
    // Total count across buckets should equal sample count
    let total: u64 = report.histogram.iter().map(|b| b.count).sum();
    assert_eq!(total, 2);
}

#[test]
fn histogram_many_identical_values() {
    let events: Vec<GcEvent> = (0..100).map(|i| make_event(i, "ext-a", 5000)).collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let report = tracker.pause_distribution_report();
    let total: u64 = report.histogram.iter().map(|b| b.count).sum();
    assert_eq!(total, 100);
}

// =========================================================================
// Serde roundtrips
// =========================================================================

#[test]
fn tracker_serde_roundtrip_preserves_percentiles() {
    let events: Vec<GcEvent> = (0..50)
        .map(|i| make_event(i, &format!("ext-{}", i % 3), (i + 1) * 100))
        .collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap_before = tracker.global_percentiles();

    let json = serde_json::to_string(&tracker).unwrap();
    let restored: PauseTracker = serde_json::from_str(&json).unwrap();
    let snap_after = restored.global_percentiles();
    assert_eq!(snap_before, snap_after);
}

#[test]
fn tracker_serde_roundtrip_preserves_extension_percentiles() {
    let mut tracker = PauseTracker::new(PauseBudget::default());
    for i in 0..20 {
        tracker.record(&make_event(i, "ext-a", (i + 1) * 100));
    }
    for i in 20..40 {
        tracker.record(&make_event(i, "ext-b", (i + 1) * 50));
    }
    let snap_a = tracker.extension_percentiles("ext-a");
    let snap_b = tracker.extension_percentiles("ext-b");

    let json = serde_json::to_string(&tracker).unwrap();
    let restored: PauseTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(snap_a, restored.extension_percentiles("ext-a"));
    assert_eq!(snap_b, restored.extension_percentiles("ext-b"));
}

#[test]
fn report_serde_roundtrip() {
    let events: Vec<GcEvent> = (0..30)
        .map(|i| make_event(i, "ext-a", (i + 1) * 200))
        .collect();
    let tracker = tracker_with_events(PauseBudget::new(1000, 5000, 10000), &events);
    let report = tracker.pause_distribution_report();
    let json = serde_json::to_string(&report).unwrap();
    let restored: PauseDistributionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.sample_count, restored.sample_count);
    assert_eq!(report.global_percentiles, restored.global_percentiles);
    assert_eq!(report.budget, restored.budget);
    assert_eq!(report.policy_state, restored.policy_state);
    assert_eq!(report.histogram.len(), restored.histogram.len());
}

#[test]
fn budget_violation_serde_roundtrip() {
    let violation = BudgetViolation {
        percentile: Percentile::P99,
        observed_ns: 50_000,
        budget_ns: 10_000,
        scope: "global".to_string(),
    };
    let json = serde_json::to_string(&violation).unwrap();
    let back: BudgetViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(violation, back);
}

#[test]
fn pause_budget_serde_roundtrip() {
    let budget = PauseBudget::new(100, 500, 1000);
    let json = serde_json::to_string(&budget).unwrap();
    let back: PauseBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

// =========================================================================
// Report with transitions
// =========================================================================

#[test]
fn report_with_transition_captures_state_change() {
    let budget = PauseBudget::new(100, 200, 300);
    let events = vec![make_event(0, "ext-a", 1_000_000)]; // exceeds all budgets
    let tracker = tracker_with_events(budget, &events);
    let report =
        tracker.pause_distribution_report_with_transition(PauseBudgetPolicyState::WithinBudget);
    assert!(report.policy_transition.transitioned);
    assert_eq!(report.policy_state, PauseBudgetPolicyState::Violated);
    assert!(report.policy_transition.violation_count > 0);
}

#[test]
fn report_schema_version_present() {
    let tracker = PauseTracker::new(PauseBudget::default());
    let report = tracker.pause_distribution_report();
    assert_eq!(report.schema_version, PAUSE_DISTRIBUTION_REPORT_SCHEMA);
}

// =========================================================================
// Extension tracking
// =========================================================================

#[test]
fn extensions_sorted_deterministically() {
    let mut tracker = PauseTracker::new(PauseBudget::default());
    tracker.record(&make_event(0, "zebra", 100));
    tracker.record(&make_event(1, "alpha", 200));
    tracker.record(&make_event(2, "middle", 300));
    let exts = tracker.extensions();
    assert_eq!(exts, vec!["alpha", "middle", "zebra"]);
}

#[test]
fn many_extensions_maintain_order() {
    let mut tracker = PauseTracker::new(PauseBudget::default());
    for i in 0..50u64 {
        tracker.record(&make_event(i, &format!("ext-{i:03}"), (i + 1) * 10));
    }
    let exts = tracker.extensions();
    assert_eq!(exts.len(), 50);
    // Verify alphabetical order
    for i in 1..exts.len() {
        assert!(
            exts[i - 1] < exts[i],
            "extensions not sorted: {} >= {}",
            exts[i - 1],
            exts[i]
        );
    }
}

#[test]
fn extension_count_consistency() {
    let mut tracker = PauseTracker::new(PauseBudget::default());
    for i in 0..30u64 {
        tracker.record(&make_event(i, &format!("ext-{}", i % 5), (i + 1) * 100));
    }
    let total_from_extensions: usize = tracker
        .extensions()
        .iter()
        .map(|e| tracker.extension_count(e))
        .sum();
    assert_eq!(total_from_extensions, tracker.count());
}

// =========================================================================
// PauseRecord from GcEvent
// =========================================================================

#[test]
fn pause_record_from_gc_event_maps_fields() {
    let event = make_event(42, "test-ext", 5000);
    let record = PauseRecord::from_gc_event(&event);
    assert_eq!(record.sequence, 42);
    assert_eq!(record.extension_id, "test-ext");
    assert_eq!(record.pause_ns, 5000);
    assert_eq!(record.objects_scanned, 500); // marked_count = 5000/10
    assert_eq!(record.objects_collected, 250); // swept_count = 5000/20
    assert_eq!(record.bytes_reclaimed, 40000); // 5000*8
}

#[test]
fn pause_record_serde_roundtrip() {
    let event = make_event(1, "ext-a", 9999);
    let record = PauseRecord::from_gc_event(&event);
    let json = serde_json::to_string(&record).unwrap();
    let back: PauseRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// =========================================================================
// Percentile display
// =========================================================================

#[test]
fn percentile_display() {
    assert_eq!(format!("{}", Percentile::P50), "p50");
    assert_eq!(format!("{}", Percentile::P95), "p95");
    assert_eq!(format!("{}", Percentile::P99), "p99");
}

#[test]
fn percentile_serde_roundtrip() {
    for p in [Percentile::P50, Percentile::P95, Percentile::P99] {
        let json = serde_json::to_string(&p).unwrap();
        let back: Percentile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

// =========================================================================
// Budget set_budget
// =========================================================================

#[test]
fn set_budget_changes_violation_status() {
    let mut tracker = PauseTracker::new(PauseBudget::new(100, 200, 300));
    tracker.record(&make_event(0, "ext-a", 500));
    assert!(!tracker.within_budget()); // 500 > all budgets

    // Relax budget — should now be within
    tracker.set_budget(PauseBudget::new(1000, 2000, 3000));
    assert!(tracker.within_budget());
}

// =========================================================================
// Stress: many events
// =========================================================================

#[test]
fn stress_1000_events_percentiles_valid() {
    let events: Vec<GcEvent> = (0..1000)
        .map(|i| make_event(i, &format!("ext-{}", i % 10), (i % 100 + 1) * 50))
        .collect();
    let tracker = tracker_with_events(PauseBudget::default(), &events);
    let snap = tracker.global_percentiles();
    assert_eq!(snap.count, 1000);
    assert!(snap.p50_ns <= snap.p95_ns);
    assert!(snap.p95_ns <= snap.p99_ns);
    assert!(snap.min_ns <= snap.p50_ns);
    assert!(snap.p99_ns <= snap.max_ns);
}

#[test]
fn stress_ring_buffer_1000_events_capacity_50() {
    let mut tracker = PauseTracker::with_capacity(PauseBudget::default(), 50);
    for i in 0..1000u64 {
        tracker.record(&make_event(
            i,
            &format!("ext-{}", i % 5),
            (i % 200 + 1) * 10,
        ));
    }
    assert_eq!(tracker.count(), 50);
    // All records should be from the last 50 events
    let records = tracker.records();
    assert_eq!(records[0].sequence, 950);
    assert_eq!(records[49].sequence, 999);
}

// =========================================================================
// Determinism verification
// =========================================================================

#[test]
fn deterministic_report_from_identical_inputs() {
    let build_tracker = || {
        let events: Vec<GcEvent> = (0..50)
            .map(|i| make_event(i, &format!("ext-{}", i % 3), (i + 1) * 100))
            .collect();
        tracker_with_events(PauseBudget::new(1000, 5000, 10000), &events)
    };
    let r1 = build_tracker().pause_distribution_report();
    let r2 = build_tracker().pause_distribution_report();
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn deterministic_percentiles_after_serde_cycle() {
    let events: Vec<GcEvent> = (0..30)
        .map(|i| make_event(i, "ext-a", (i + 1) * 200))
        .collect();
    let t1 = tracker_with_events(PauseBudget::default(), &events);
    let json = serde_json::to_string(&t1).unwrap();
    let t2: PauseTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(t1.global_percentiles(), t2.global_percentiles());
}

// =========================================================================
// Constants
// =========================================================================

#[test]
fn schema_version_non_empty() {
    assert!(!PAUSE_DISTRIBUTION_REPORT_SCHEMA.is_empty());
    assert!(PAUSE_DISTRIBUTION_REPORT_SCHEMA.starts_with("franken-engine."));
}

#[test]
fn default_budget_sensible() {
    let b = PauseBudget::default();
    assert!(b.p50_ns > 0);
    assert!(b.p95_ns > b.p50_ns);
    assert!(b.p99_ns > b.p95_ns);
}
