#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `feature_parity_tracker`.

use std::collections::BTreeSet;

use frankenengine_engine::feature_parity_tracker::{
    EsVersion, FeatureArea, FeatureEntry,
    FeatureParityTracker, FeatureStatus, LockstepMismatch, LockstepResult, LockstepRuntime,
    ParityEvent, ParityTrackerError, ReleaseGateCriteria, ReleaseGateDecision, Test262Result,
    TrackerContext, UnwaivedFailure, WaiverRecord,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> TrackerContext {
    TrackerContext {
        trace_id: "trace-enr".to_string(),
        decision_id: "dec-enr".to_string(),
        policy_id: "pol-enr".to_string(),
    }
}

fn make_waiver(waiver_id: &str, feature_id: &str) -> WaiverRecord {
    WaiverRecord {
        waiver_id: waiver_id.to_string(),
        feature_id: feature_id.to_string(),
        reason: "intentional divergence".to_string(),
        approved_by: "engineer-1".to_string(),
        approved_at_ns: 1_000_000,
        valid_until_ns: Some(2_000_000),
        test262_exemptions: vec!["t262-1".to_string()],
        lockstep_exemptions: vec!["ls-1".to_string()],
        sealed: false,
    }
}

// ---------------------------------------------------------------------------
// FeatureStatus — serde, display, ordering
// ---------------------------------------------------------------------------

#[test]
fn feature_status_serde_roundtrip() {
    for s in [FeatureStatus::NotStarted, FeatureStatus::InProgress, FeatureStatus::Passing, FeatureStatus::Waived] {
        let json = serde_json::to_string(&s).unwrap();
        let back: FeatureStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn feature_status_display_distinctness() {
    let mut seen = BTreeSet::new();
    for s in [FeatureStatus::NotStarted, FeatureStatus::InProgress, FeatureStatus::Passing, FeatureStatus::Waived] {
        assert!(seen.insert(format!("{s}")));
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn feature_status_ordering() {
    assert!(FeatureStatus::NotStarted < FeatureStatus::InProgress);
    assert!(FeatureStatus::InProgress < FeatureStatus::Passing);
    assert!(FeatureStatus::Passing < FeatureStatus::Waived);
}

// ---------------------------------------------------------------------------
// EsVersion
// ---------------------------------------------------------------------------

#[test]
fn es_version_serde_roundtrip() {
    let json = serde_json::to_string(&EsVersion::Es2020).unwrap();
    let back: EsVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, EsVersion::Es2020);
}

#[test]
fn es_version_display() {
    assert_eq!(format!("{}", EsVersion::Es2020), "ES2020");
}

// ---------------------------------------------------------------------------
// LockstepRuntime
// ---------------------------------------------------------------------------

#[test]
fn lockstep_runtime_serde_roundtrip() {
    for r in [LockstepRuntime::Node, LockstepRuntime::Bun] {
        let json = serde_json::to_string(&r).unwrap();
        let back: LockstepRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn lockstep_runtime_display_distinctness() {
    assert_ne!(format!("{}", LockstepRuntime::Node), format!("{}", LockstepRuntime::Bun));
}

// ---------------------------------------------------------------------------
// FeatureArea
// ---------------------------------------------------------------------------

#[test]
fn feature_area_all_has_ten_variants() {
    assert_eq!(FeatureArea::all().len(), 10);
}

#[test]
fn feature_area_serde_roundtrip_all() {
    for &a in FeatureArea::all() {
        let json = serde_json::to_string(&a).unwrap();
        let back: FeatureArea = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

#[test]
fn feature_area_display_matches_as_str() {
    for &a in FeatureArea::all() {
        assert_eq!(format!("{a}"), a.as_str());
    }
}

#[test]
fn feature_area_display_distinctness() {
    let mut seen = BTreeSet::new();
    for &a in FeatureArea::all() {
        assert!(seen.insert(format!("{a}")), "duplicate display for {a}");
    }
    assert_eq!(seen.len(), 10);
}

// ---------------------------------------------------------------------------
// FeatureEntry
// ---------------------------------------------------------------------------

#[test]
fn feature_entry_new_defaults() {
    let e = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    assert_eq!(e.feature_id, "ES2020-bigint");
    assert_eq!(e.status, FeatureStatus::NotStarted);
    assert_eq!(e.test262_total, 0);
    assert_eq!(e.test262_passing, 0);
    assert_eq!(e.test262_pass_rate_millionths, 0);
    assert!(e.lockstep_match_rates_millionths.is_empty());
}

#[test]
fn feature_entry_serde_roundtrip() {
    let e = FeatureEntry::new(FeatureArea::OptionalChaining, EsVersion::Es2020);
    let json = serde_json::to_string(&e).unwrap();
    let back: FeatureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Test262Result
// ---------------------------------------------------------------------------

#[test]
fn test262_result_validate_ok() {
    let r = Test262Result {
        area: FeatureArea::BigInt,
        total: 100,
        passing: 95,
        failing_test_ids: vec!["t1".into(), "t2".into(), "t3".into(), "t4".into(), "t5".into()],
    };
    assert!(r.validate().is_ok());
}

#[test]
fn test262_result_validate_passing_exceeds_total() {
    let r = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 20,
        failing_test_ids: vec![],
    };
    assert!(r.validate().is_err());
}

#[test]
fn test262_result_serde_roundtrip() {
    let r = Test262Result {
        area: FeatureArea::GlobalThis,
        total: 50,
        passing: 50,
        failing_test_ids: vec![],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: Test262Result = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// LockstepResult & LockstepMismatch
// ---------------------------------------------------------------------------

#[test]
fn lockstep_result_validate_ok() {
    let r = LockstepResult {
        area: FeatureArea::DynamicImport,
        runtime: LockstepRuntime::Node,
        total_comparisons: 10,
        matches: 8,
        mismatches: vec![
            LockstepMismatch { test_id: "t1".into(), expected: "a".into(), actual: "b".into() },
            LockstepMismatch { test_id: "t2".into(), expected: "c".into(), actual: "d".into() },
        ],
    };
    assert!(r.validate().is_ok());
}

#[test]
fn lockstep_result_validate_matches_exceed_total() {
    let r = LockstepResult {
        area: FeatureArea::DynamicImport,
        runtime: LockstepRuntime::Bun,
        total_comparisons: 5,
        matches: 10,
        mismatches: vec![],
    };
    assert!(r.validate().is_err());
}

#[test]
fn lockstep_result_validate_inconsistent_mismatch_count() {
    let r = LockstepResult {
        area: FeatureArea::DynamicImport,
        runtime: LockstepRuntime::Node,
        total_comparisons: 10,
        matches: 8,
        mismatches: vec![], // should be 2
    };
    assert!(r.validate().is_err());
}

#[test]
fn lockstep_mismatch_serde_roundtrip() {
    let m = LockstepMismatch { test_id: "test-1".into(), expected: "42".into(), actual: "43".into() };
    let json = serde_json::to_string(&m).unwrap();
    let back: LockstepMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// WaiverRecord
// ---------------------------------------------------------------------------

#[test]
fn waiver_record_validate_ok() {
    let w = make_waiver("w-1", "ES2020-bigint");
    assert!(w.validate().is_ok());
}

#[test]
fn waiver_record_validate_empty_waiver_id() {
    let mut w = make_waiver("w-1", "f-1");
    w.waiver_id = "  ".into();
    assert!(w.validate().is_err());
}

#[test]
fn waiver_record_validate_empty_reason() {
    let mut w = make_waiver("w-1", "f-1");
    w.reason = "  ".into();
    assert!(w.validate().is_err());
}

#[test]
fn waiver_record_validate_until_before_approved() {
    let mut w = make_waiver("w-1", "f-1");
    w.valid_until_ns = Some(500_000); // less than approved_at_ns (1_000_000)
    assert!(w.validate().is_err());
}

#[test]
fn waiver_record_serde_roundtrip() {
    let w = make_waiver("w-2", "ES2020-optional_chaining");
    let json = serde_json::to_string(&w).unwrap();
    let back: WaiverRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// ReleaseGateCriteria
// ---------------------------------------------------------------------------

#[test]
fn release_gate_criteria_default_values() {
    let c = ReleaseGateCriteria::default();
    assert_eq!(c.min_test262_pass_rate_millionths, 950_000);
    assert_eq!(c.min_lockstep_match_rate_millionths, 950_000);
    assert!(c.require_waiver_coverage);
}

#[test]
fn release_gate_criteria_serde_roundtrip() {
    let c = ReleaseGateCriteria::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ReleaseGateCriteria = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ParityTrackerError
// ---------------------------------------------------------------------------

#[test]
fn parity_tracker_error_code_distinctness() {
    let errors: Vec<ParityTrackerError> = vec![
        ParityTrackerError::FeatureNotFound { feature_id: "f".into() },
        ParityTrackerError::WaiverNotFound { waiver_id: "w".into() },
        ParityTrackerError::WaiverAlreadyExists { waiver_id: "w".into() },
        ParityTrackerError::WaiverSealed { waiver_id: "w".into() },
        ParityTrackerError::InvalidWaiver { detail: "d".into() },
        ParityTrackerError::InvalidMetrics { detail: "d".into() },
        ParityTrackerError::DuplicateFeature { feature_id: "f".into() },
        ParityTrackerError::GateEvaluationFailed { detail: "d".into() },
    ];
    let mut codes = BTreeSet::new();
    for e in &errors {
        assert!(codes.insert(e.code()), "duplicate code {}", e.code());
    }
    assert_eq!(codes.len(), 8);
}

#[test]
fn parity_tracker_error_serde_roundtrip() {
    let e = ParityTrackerError::FeatureNotFound { feature_id: "ES2020-bigint".into() };
    let json = serde_json::to_string(&e).unwrap();
    let back: ParityTrackerError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn parity_tracker_error_display_contains_code() {
    let e = ParityTrackerError::WaiverSealed { waiver_id: "w-42".into() };
    let msg = format!("{e}");
    assert!(msg.contains("FE-FPT-0004"));
    assert!(msg.contains("w-42"));
}

// ---------------------------------------------------------------------------
// TrackerContext
// ---------------------------------------------------------------------------

#[test]
fn tracker_context_serde_roundtrip() {
    let c = ctx();
    let json = serde_json::to_string(&c).unwrap();
    let back: TrackerContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ParityEvent
// ---------------------------------------------------------------------------

#[test]
fn parity_event_serde_roundtrip() {
    let e = ParityEvent {
        trace_id: "t".into(), decision_id: "d".into(), policy_id: "p".into(),
        component: "c".into(), event: "ev".into(), outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// UnwaivedFailure & ReleaseGateDecision
// ---------------------------------------------------------------------------

#[test]
fn unwaived_failure_serde_roundtrip() {
    let f = UnwaivedFailure {
        feature_id: "ES2020-bigint".into(),
        failure_type: "test262".into(),
        test_id: "t-1".into(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: UnwaivedFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn release_gate_decision_serde_roundtrip() {
    let d = ReleaseGateDecision {
        passed: true,
        failing_features: vec![],
        unwaived_failures: vec![],
        overall_test262_pass_rate_millionths: 1_000_000,
        overall_lockstep_match_rate_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: ReleaseGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// FeatureParityTracker — lifecycle
// ---------------------------------------------------------------------------

#[test]
fn tracker_new_has_ten_features() {
    let t = FeatureParityTracker::new();
    assert_eq!(t.features().len(), 10);
}

#[test]
fn tracker_empty_has_no_features() {
    let t = FeatureParityTracker::empty();
    assert!(t.features().is_empty());
}

#[test]
fn tracker_register_feature_duplicate_fails() {
    let mut t = FeatureParityTracker::new();
    let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    let r = t.register_feature(entry);
    assert!(r.is_err());
}

#[test]
fn tracker_set_status() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    t.set_status("ES2020-bigint", FeatureStatus::InProgress, &c).unwrap();
    let f = t.feature("ES2020-bigint").unwrap();
    assert_eq!(f.status, FeatureStatus::InProgress);
}

#[test]
fn tracker_ingest_test262() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    let r = Test262Result {
        area: FeatureArea::BigInt,
        total: 100,
        passing: 90,
        failing_test_ids: (0..10).map(|i| format!("fail-{i}")).collect(),
    };
    t.ingest_test262(&r, &c).unwrap();
    let f = t.feature("ES2020-bigint").unwrap();
    assert_eq!(f.test262_total, 100);
    assert_eq!(f.test262_passing, 90);
    assert_eq!(f.test262_pass_rate_millionths, 900_000);
}

#[test]
fn tracker_ingest_lockstep() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    let r = LockstepResult {
        area: FeatureArea::OptionalChaining,
        runtime: LockstepRuntime::Node,
        total_comparisons: 50,
        matches: 45,
        mismatches: (0..5).map(|i| LockstepMismatch {
            test_id: format!("mm-{i}"), expected: "a".into(), actual: "b".into(),
        }).collect(),
    };
    t.ingest_lockstep(&r, &c).unwrap();
    let f = t.feature("ES2020-optional_chaining").unwrap();
    assert_eq!(*f.lockstep_total_comparisons.get("node").unwrap(), 50);
    assert_eq!(*f.lockstep_matches.get("node").unwrap(), 45);
}

#[test]
fn tracker_add_waiver_and_seal() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver("w-1", "ES2020-bigint");
    t.register_waiver(w, &c).unwrap();
    assert!(t.waivers().contains_key("w-1"));

    // Seal the waiver
    t.seal_waiver("w-1", &c).unwrap();
    assert!(t.waivers().get("w-1").unwrap().sealed);

    // Cannot seal again
    let r = t.seal_waiver("w-1", &c);
    assert!(r.is_err());
}

#[test]
fn tracker_add_waiver_duplicate_fails() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver("w-dup", "ES2020-bigint");
    t.register_waiver(w.clone(), &c).unwrap();
    let r = t.register_waiver(w, &c);
    assert!(r.is_err());
}

#[test]
fn tracker_dashboard_snapshot() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    // Ingest some data to make the snapshot interesting
    let r = Test262Result {
        area: FeatureArea::GlobalThis,
        total: 20,
        passing: 20,
        failing_test_ids: vec![],
    };
    t.ingest_test262(&r, &c).unwrap();
    t.set_status("ES2020-global_this", FeatureStatus::Passing, &c).unwrap();

    let snap = t.dashboard();
    assert_eq!(snap.total_features, 10);
    assert!(snap.per_area.len() > 0);
}

#[test]
fn tracker_evaluate_gate_all_passing() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    // Make all features pass with 100%
    for &area in FeatureArea::all() {
        let r = Test262Result {
            area,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        t.ingest_test262(&r, &c).unwrap();
        t.set_status(&format!("ES2020-{}", area.as_str()), FeatureStatus::Passing, &c).unwrap();
    }
    t.set_gate_criteria(ReleaseGateCriteria {
        min_test262_pass_rate_millionths: 900_000,
        min_lockstep_match_rate_millionths: 0,
        require_waiver_coverage: false,
    });
    let decision = t.evaluate_gate(&c);
    assert!(decision.passed);
    assert!(decision.failing_features.is_empty());
}

#[test]
fn tracker_serde_roundtrip() {
    let t = FeatureParityTracker::new();
    let json = serde_json::to_string(&t).unwrap();
    let back: FeatureParityTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.features().len(), 10);
}

#[test]
fn tracker_drain_events_after_operations() {
    let mut t = FeatureParityTracker::new();
    let c = ctx();
    t.set_status("ES2020-bigint", FeatureStatus::InProgress, &c).unwrap();
    let events = t.drain_events();
    assert!(!events.is_empty());
    let events2 = t.drain_events();
    assert!(events2.is_empty());
}
