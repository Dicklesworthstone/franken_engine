//! Integration tests for the feature_parity_tracker module.
//!
//! Covers FeatureStatus, EsVersion, LockstepRuntime, FeatureArea enums,
//! FeatureEntry, Test262Result, LockstepResult, LockstepMismatch,
//! WaiverRecord, ReleaseGateCriteria, ReleaseGateDecision, UnwaivedFailure,
//! ParityEvent, DashboardSnapshot, FeatureAreaSnapshot, TrackerContext,
//! ParityTrackerError, and the FeatureParityTracker lifecycle including
//! feature registration, test262/lockstep ingestion, waiver governance,
//! seal workflow, dashboard snapshots, and release gate evaluation.

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

use std::collections::BTreeMap;

use frankenengine_engine::feature_parity_tracker::{
    DashboardSnapshot, EsVersion, FeatureArea, FeatureAreaSnapshot, FeatureEntry,
    FeatureParityTracker, FeatureStatus, LockstepMismatch, LockstepResult, LockstepRuntime,
    ParityEvent, ParityTrackerError, ReleaseGateCriteria, ReleaseGateDecision, Test262Result,
    TrackerContext, UnwaivedFailure, WaiverRecord,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> TrackerContext {
    TrackerContext {
        trace_id: "trace-int".to_string(),
        decision_id: "dec-int".to_string(),
        policy_id: "pol-int".to_string(),
    }
}

fn make_waiver(feature_id: &str, waiver_id: &str) -> WaiverRecord {
    WaiverRecord {
        waiver_id: waiver_id.to_string(),
        feature_id: feature_id.to_string(),
        reason: "intentional divergence".to_string(),
        approved_by: "operator".to_string(),
        approved_at_ns: 1_000_000_000,
        valid_until_ns: None,
        test262_exemptions: vec!["test-exempted-1".to_string()],
        lockstep_exemptions: vec!["lockstep-exempted-1".to_string()],
        sealed: false,
    }
}

fn bigint_fid() -> String {
    format!("{}-{}", EsVersion::Es2020, FeatureArea::BigInt)
}

fn all_passing_tracker() -> FeatureParityTracker {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    for &area in FeatureArea::all() {
        let result = Test262Result {
            area,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        tracker.ingest_test262(&result, &c).unwrap();
    }
    tracker
}

// ===========================================================================
// Enum display / serde
// ===========================================================================

#[test]
fn feature_status_display_all_variants() {
    assert_eq!(FeatureStatus::NotStarted.to_string(), "not_started");
    assert_eq!(FeatureStatus::InProgress.to_string(), "in_progress");
    assert_eq!(FeatureStatus::Passing.to_string(), "passing");
    assert_eq!(FeatureStatus::Waived.to_string(), "waived");
}

#[test]
fn feature_status_serde_round_trip() {
    for status in [
        FeatureStatus::NotStarted,
        FeatureStatus::InProgress,
        FeatureStatus::Passing,
        FeatureStatus::Waived,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let restored: FeatureStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, restored);
    }
}

#[test]
fn feature_status_ordering() {
    assert!(FeatureStatus::NotStarted < FeatureStatus::InProgress);
    assert!(FeatureStatus::InProgress < FeatureStatus::Passing);
    assert!(FeatureStatus::Passing < FeatureStatus::Waived);
}

#[test]
fn es_version_display() {
    assert_eq!(EsVersion::Es2020.to_string(), "ES2020");
}

#[test]
fn es_version_serde_round_trip() {
    let json = serde_json::to_string(&EsVersion::Es2020).unwrap();
    let restored: EsVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(EsVersion::Es2020, restored);
}

#[test]
fn lockstep_runtime_display() {
    assert_eq!(LockstepRuntime::Node.to_string(), "node");
    assert_eq!(LockstepRuntime::Bun.to_string(), "bun");
}

#[test]
fn lockstep_runtime_serde_round_trip() {
    for rt in [LockstepRuntime::Node, LockstepRuntime::Bun] {
        let json = serde_json::to_string(&rt).unwrap();
        let restored: LockstepRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, restored);
    }
}

#[test]
fn feature_area_all_returns_ten() {
    assert_eq!(FeatureArea::all().len(), 10);
}

#[test]
fn feature_area_display_all() {
    let names: Vec<String> = FeatureArea::all().iter().map(|a| a.to_string()).collect();
    assert!(names.contains(&"optional_chaining".to_string()));
    assert!(names.contains(&"bigint".to_string()));
    assert!(names.contains(&"for_in_order".to_string()));
    // All unique.
    let unique: std::collections::BTreeSet<&String> = names.iter().collect();
    assert_eq!(unique.len(), 10);
}

#[test]
fn feature_area_as_str_matches_display() {
    for &area in FeatureArea::all() {
        assert_eq!(area.as_str(), area.to_string());
    }
}

#[test]
fn feature_area_serde_round_trip() {
    for &area in FeatureArea::all() {
        let json = serde_json::to_string(&area).unwrap();
        let restored: FeatureArea = serde_json::from_str(&json).unwrap();
        assert_eq!(area, restored);
    }
}

// ===========================================================================
// FeatureEntry
// ===========================================================================

#[test]
fn feature_entry_new_defaults() {
    let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    assert_eq!(entry.feature_id, "ES2020-bigint");
    assert_eq!(entry.area, FeatureArea::BigInt);
    assert_eq!(entry.es_version, EsVersion::Es2020);
    assert_eq!(entry.status, FeatureStatus::NotStarted);
    assert_eq!(entry.test262_total, 0);
    assert_eq!(entry.test262_passing, 0);
    assert_eq!(entry.test262_pass_rate_millionths, 0);
    assert!(entry.lockstep_match_rates_millionths.is_empty());
    assert!(entry.lockstep_total_comparisons.is_empty());
    assert!(entry.lockstep_matches.is_empty());
}

#[test]
fn feature_entry_serde_round_trip() {
    let entry = FeatureEntry::new(FeatureArea::DynamicImport, EsVersion::Es2020);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: FeatureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn feature_entry_feature_id_format() {
    for &area in FeatureArea::all() {
        let entry = FeatureEntry::new(area, EsVersion::Es2020);
        let expected = format!("ES2020-{}", area.as_str());
        assert_eq!(entry.feature_id, expected);
    }
}

// ===========================================================================
// Test262Result
// ===========================================================================

#[test]
fn test262_result_valid() {
    let r = Test262Result {
        area: FeatureArea::BigInt,
        total: 100,
        passing: 95,
        failing_test_ids: vec![
            "t1".into(),
            "t2".into(),
            "t3".into(),
            "t4".into(),
            "t5".into(),
        ],
    };
    assert!(r.validate().is_ok());
}

#[test]
fn test262_result_passing_exceeds_total_rejected() {
    let r = Test262Result {
        area: FeatureArea::BigInt,
        total: 5,
        passing: 10,
        failing_test_ids: vec![],
    };
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

#[test]
fn test262_result_serde_round_trip() {
    let r = Test262Result {
        area: FeatureArea::GlobalThis,
        total: 50,
        passing: 48,
        failing_test_ids: vec!["f1".into(), "f2".into()],
    };
    let json = serde_json::to_string(&r).unwrap();
    let restored: Test262Result = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);
}

// ===========================================================================
// LockstepResult / LockstepMismatch
// ===========================================================================

#[test]
fn lockstep_result_valid() {
    let r = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Node,
        total_comparisons: 20,
        matches: 18,
        mismatches: vec![
            LockstepMismatch {
                test_id: "m1".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            LockstepMismatch {
                test_id: "m2".into(),
                expected: "c".into(),
                actual: "d".into(),
            },
        ],
    };
    assert!(r.validate().is_ok());
}

#[test]
fn lockstep_result_matches_exceeds_total_rejected() {
    let r = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Node,
        total_comparisons: 10,
        matches: 15,
        mismatches: vec![],
    };
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

#[test]
fn lockstep_result_mismatch_count_inconsistent_rejected() {
    let r = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Bun,
        total_comparisons: 10,
        matches: 8,
        mismatches: vec![LockstepMismatch {
            test_id: "m1".into(),
            expected: "x".into(),
            actual: "y".into(),
        }], // Should have 2 mismatches but only 1 provided.
    };
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

#[test]
fn lockstep_mismatch_serde_round_trip() {
    let m = LockstepMismatch {
        test_id: "test-42".into(),
        expected: "true".into(),
        actual: "false".into(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let restored: LockstepMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// ===========================================================================
// WaiverRecord
// ===========================================================================

#[test]
fn waiver_record_valid() {
    let w = make_waiver("feat-1", "w-1");
    assert!(w.validate().is_ok());
}

#[test]
fn waiver_empty_waiver_id_rejected() {
    let mut w = make_waiver("f", "w");
    w.waiver_id = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_empty_feature_id_rejected() {
    let mut w = make_waiver("f", "w");
    w.feature_id = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_empty_reason_rejected() {
    let mut w = make_waiver("f", "w");
    w.reason = "  ".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_empty_approved_by_rejected() {
    let mut w = make_waiver("f", "w");
    w.approved_by = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_valid_until_before_approved_at_rejected() {
    let mut w = make_waiver("f", "w");
    w.approved_at_ns = 1000;
    w.valid_until_ns = Some(500);
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_valid_until_equal_to_approved_at_rejected() {
    let mut w = make_waiver("f", "w");
    w.approved_at_ns = 1000;
    w.valid_until_ns = Some(1000);
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn waiver_valid_until_after_approved_at_accepted() {
    let mut w = make_waiver("f", "w");
    w.approved_at_ns = 1000;
    w.valid_until_ns = Some(2000);
    assert!(w.validate().is_ok());
}

#[test]
fn waiver_record_serde_round_trip() {
    let w = make_waiver("feat-1", "w-1");
    let json = serde_json::to_string(&w).unwrap();
    let restored: WaiverRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(w, restored);
}

// ===========================================================================
// ReleaseGateCriteria
// ===========================================================================

#[test]
fn release_gate_criteria_defaults() {
    let d = ReleaseGateCriteria::default();
    assert_eq!(d.min_test262_pass_rate_millionths, 950_000);
    assert_eq!(d.min_lockstep_match_rate_millionths, 950_000);
    assert!(d.require_waiver_coverage);
}

#[test]
fn release_gate_criteria_serde_round_trip() {
    let c = ReleaseGateCriteria {
        min_test262_pass_rate_millionths: 800_000,
        min_lockstep_match_rate_millionths: 900_000,
        require_waiver_coverage: false,
    };
    let json = serde_json::to_string(&c).unwrap();
    let restored: ReleaseGateCriteria = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// ===========================================================================
// ReleaseGateDecision / UnwaivedFailure
// ===========================================================================

#[test]
fn release_gate_decision_serde_round_trip() {
    let d = ReleaseGateDecision {
        passed: false,
        failing_features: vec!["f1".into()],
        unwaived_failures: vec![UnwaivedFailure {
            feature_id: "f1".into(),
            failure_type: "test262".into(),
            test_id: "t1".into(),
        }],
        overall_test262_pass_rate_millionths: 800_000,
        overall_lockstep_match_rate_millionths: 900_000,
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: ReleaseGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn unwaived_failure_serde_round_trip() {
    let f = UnwaivedFailure {
        feature_id: "f".into(),
        failure_type: "lockstep".into(),
        test_id: "t".into(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let restored: UnwaivedFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

// ===========================================================================
// ParityEvent / TrackerContext
// ===========================================================================

#[test]
fn parity_event_serde_round_trip() {
    let e = ParityEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "feature_parity_tracker".into(),
        event: "test".into(),
        outcome: "ok".into(),
        error_code: Some("E001".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let restored: ParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, restored);
}

#[test]
fn tracker_context_serde_round_trip() {
    let c = ctx();
    let json = serde_json::to_string(&c).unwrap();
    let restored: TrackerContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// ===========================================================================
// DashboardSnapshot / FeatureAreaSnapshot
// ===========================================================================

#[test]
fn dashboard_snapshot_serde_round_trip() {
    let tracker = FeatureParityTracker::new();
    let dash = tracker.dashboard();
    let json = serde_json::to_string(&dash).unwrap();
    let restored: DashboardSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(dash, restored);
}

#[test]
fn feature_area_snapshot_serde_round_trip() {
    let s = FeatureAreaSnapshot {
        feature_id: "ES2020-bigint".into(),
        area: FeatureArea::BigInt,
        status: FeatureStatus::Passing,
        test262_pass_rate_millionths: 1_000_000,
        lockstep_match_rates_millionths: BTreeMap::new(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let restored: FeatureAreaSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

// ===========================================================================
// ParityTrackerError
// ===========================================================================

#[test]
fn error_codes_all_unique() {
    let errors = [
        ParityTrackerError::FeatureNotFound {
            feature_id: "x".into(),
        },
        ParityTrackerError::WaiverNotFound {
            waiver_id: "w".into(),
        },
        ParityTrackerError::WaiverAlreadyExists {
            waiver_id: "w".into(),
        },
        ParityTrackerError::WaiverSealed {
            waiver_id: "w".into(),
        },
        ParityTrackerError::InvalidWaiver { detail: "d".into() },
        ParityTrackerError::InvalidMetrics { detail: "d".into() },
        ParityTrackerError::DuplicateFeature {
            feature_id: "x".into(),
        },
        ParityTrackerError::GateEvaluationFailed { detail: "d".into() },
    ];
    let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn error_display_non_empty() {
    let errors = vec![
        ParityTrackerError::FeatureNotFound {
            feature_id: "feat-1".into(),
        },
        ParityTrackerError::WaiverNotFound {
            waiver_id: "w-1".into(),
        },
        ParityTrackerError::WaiverAlreadyExists {
            waiver_id: "w-1".into(),
        },
        ParityTrackerError::WaiverSealed {
            waiver_id: "w-1".into(),
        },
        ParityTrackerError::InvalidWaiver {
            detail: "bad".into(),
        },
        ParityTrackerError::InvalidMetrics {
            detail: "bad".into(),
        },
        ParityTrackerError::DuplicateFeature {
            feature_id: "f".into(),
        },
        ParityTrackerError::GateEvaluationFailed {
            detail: "fail".into(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
        assert!(
            msg.contains(err.code()),
            "display should include error code"
        );
    }
}

#[test]
fn error_display_includes_context() {
    let err = ParityTrackerError::FeatureNotFound {
        feature_id: "my-feature".into(),
    };
    assert!(err.to_string().contains("my-feature"));

    let err2 = ParityTrackerError::WaiverSealed {
        waiver_id: "sealed-w".into(),
    };
    assert!(err2.to_string().contains("sealed-w"));
}

#[test]
fn error_is_std_error() {
    let err = ParityTrackerError::FeatureNotFound {
        feature_id: "x".into(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_round_trip() {
    let errors = vec![
        ParityTrackerError::FeatureNotFound {
            feature_id: "x".into(),
        },
        ParityTrackerError::WaiverNotFound {
            waiver_id: "w".into(),
        },
        ParityTrackerError::WaiverAlreadyExists {
            waiver_id: "w".into(),
        },
        ParityTrackerError::WaiverSealed {
            waiver_id: "w".into(),
        },
        ParityTrackerError::InvalidWaiver { detail: "d".into() },
        ParityTrackerError::InvalidMetrics { detail: "d".into() },
        ParityTrackerError::DuplicateFeature {
            feature_id: "x".into(),
        },
        ParityTrackerError::GateEvaluationFailed { detail: "d".into() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ParityTrackerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// FeatureParityTracker — construction
// ===========================================================================

#[test]
fn new_tracker_prepopulates_all_es2020_features() {
    let tracker = FeatureParityTracker::new();
    assert_eq!(tracker.feature_count(), 10);
    for &area in FeatureArea::all() {
        let fid = format!("ES2020-{}", area.as_str());
        let entry = tracker
            .feature(&fid)
            .unwrap_or_else(|| panic!("missing {fid}"));
        assert_eq!(entry.status, FeatureStatus::NotStarted);
        assert_eq!(entry.test262_total, 0);
    }
}

#[test]
fn empty_tracker_has_nothing() {
    let tracker = FeatureParityTracker::empty();
    assert_eq!(tracker.feature_count(), 0);
    assert_eq!(tracker.waiver_count(), 0);
    assert!(tracker.events().is_empty());
}

#[test]
fn default_equals_new() {
    let a = FeatureParityTracker::new();
    let b = FeatureParityTracker::default();
    assert_eq!(a.feature_count(), b.feature_count());
}

// ===========================================================================
// FeatureParityTracker — feature registration
// ===========================================================================

#[test]
fn register_feature_to_empty_tracker() {
    let mut tracker = FeatureParityTracker::empty();
    let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    tracker.register_feature(entry).unwrap();
    assert_eq!(tracker.feature_count(), 1);
    assert!(tracker.feature(&bigint_fid()).is_some());
}

#[test]
fn register_duplicate_feature_rejected() {
    let mut tracker = FeatureParityTracker::empty();
    let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    tracker.register_feature(entry.clone()).unwrap();
    let err = tracker.register_feature(entry).unwrap_err();
    match err {
        ParityTrackerError::DuplicateFeature { feature_id } => {
            assert_eq!(feature_id, bigint_fid());
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn feature_lookup_missing_returns_none() {
    let tracker = FeatureParityTracker::new();
    assert!(tracker.feature("nonexistent-feature").is_none());
}

#[test]
fn features_accessor_returns_all() {
    let tracker = FeatureParityTracker::new();
    assert_eq!(tracker.features().len(), 10);
}

// ===========================================================================
// FeatureParityTracker — status transitions
// ===========================================================================

#[test]
fn set_status_returns_old_status() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let old = tracker
        .set_status(&bigint_fid(), FeatureStatus::InProgress, &c)
        .unwrap();
    assert_eq!(old, FeatureStatus::NotStarted);
    assert_eq!(
        tracker.feature(&bigint_fid()).unwrap().status,
        FeatureStatus::InProgress
    );
}

#[test]
fn set_status_unknown_feature_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let err = tracker
        .set_status("nonexistent", FeatureStatus::Passing, &ctx())
        .unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0001");
}

#[test]
fn set_status_emits_event() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    tracker
        .set_status(&bigint_fid(), FeatureStatus::InProgress, &c)
        .unwrap();
    let events = tracker.events();
    assert!(events.iter().any(|e| e.event == "status_change"));
}

// ===========================================================================
// FeatureParityTracker — test262 ingestion
// ===========================================================================

#[test]
fn ingest_test262_updates_counts_and_rate() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 100,
        passing: 95,
        failing_test_ids: (0..5).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let entry = tracker.feature(&bigint_fid()).unwrap();
    assert_eq!(entry.test262_total, 100);
    assert_eq!(entry.test262_passing, 95);
    assert_eq!(entry.test262_pass_rate_millionths, 950_000);
}

#[test]
fn ingest_test262_100_percent_pass_rate() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 50,
        passing: 50,
        failing_test_ids: vec![],
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let entry = tracker.feature(&bigint_fid()).unwrap();
    assert_eq!(entry.test262_pass_rate_millionths, 1_000_000);
}

#[test]
fn ingest_test262_0_percent_pass_rate() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 0,
        failing_test_ids: (0..10).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let entry = tracker.feature(&bigint_fid()).unwrap();
    assert_eq!(entry.test262_pass_rate_millionths, 0);
}

#[test]
fn ingest_test262_auto_status_partial_to_in_progress() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 5,
        failing_test_ids: (0..5).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();
    assert_eq!(
        tracker.feature(&bigint_fid()).unwrap().status,
        FeatureStatus::InProgress
    );
}

#[test]
fn ingest_test262_auto_status_full_to_passing() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 10,
        failing_test_ids: vec![],
    };
    tracker.ingest_test262(&result, &c).unwrap();
    assert_eq!(
        tracker.feature(&bigint_fid()).unwrap().status,
        FeatureStatus::Passing
    );
}

#[test]
fn ingest_test262_does_not_override_waived_status() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = bigint_fid();

    // Waive the feature first.
    let waiver = make_waiver(&fid, "w-1");
    tracker.register_waiver(waiver, &c).unwrap();
    assert_eq!(tracker.feature(&fid).unwrap().status, FeatureStatus::Waived);

    // Ingest 100% pass — should NOT override waived.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 10,
        failing_test_ids: vec![],
    };
    tracker.ingest_test262(&result, &c).unwrap();
    assert_eq!(tracker.feature(&fid).unwrap().status, FeatureStatus::Waived);
}

#[test]
fn ingest_test262_invalid_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let bad = Test262Result {
        area: FeatureArea::BigInt,
        total: 5,
        passing: 10,
        failing_test_ids: vec![],
    };
    let err = tracker.ingest_test262(&bad, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

#[test]
fn ingest_test262_unknown_feature_rejected() {
    let mut tracker = FeatureParityTracker::empty();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 10,
        failing_test_ids: vec![],
    };
    let err = tracker.ingest_test262(&result, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0001");
}

#[test]
fn ingest_test262_emits_event() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 10,
        failing_test_ids: vec![],
    };
    tracker.ingest_test262(&result, &c).unwrap();
    assert!(
        tracker
            .events()
            .iter()
            .any(|e| e.event == "test262_ingested")
    );
}

// ===========================================================================
// FeatureParityTracker — lockstep ingestion
// ===========================================================================

#[test]
fn ingest_lockstep_updates_metrics() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = format!("ES2020-{}", FeatureArea::GlobalThis.as_str());
    let result = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Node,
        total_comparisons: 50,
        matches: 48,
        mismatches: vec![
            LockstepMismatch {
                test_id: "m1".into(),
                expected: "true".into(),
                actual: "false".into(),
            },
            LockstepMismatch {
                test_id: "m2".into(),
                expected: "42".into(),
                actual: "undefined".into(),
            },
        ],
    };
    tracker.ingest_lockstep(&result, &c).unwrap();

    let entry = tracker.feature(&fid).unwrap();
    assert_eq!(entry.lockstep_matches.get("node"), Some(&48));
    assert_eq!(entry.lockstep_total_comparisons.get("node"), Some(&50));
    assert_eq!(
        entry.lockstep_match_rates_millionths.get("node"),
        Some(&960_000)
    );
}

#[test]
fn ingest_lockstep_both_runtimes() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = format!("ES2020-{}", FeatureArea::OptionalChaining.as_str());

    // Node: 18/20
    let node = LockstepResult {
        area: FeatureArea::OptionalChaining,
        runtime: LockstepRuntime::Node,
        total_comparisons: 20,
        matches: 18,
        mismatches: vec![
            LockstepMismatch {
                test_id: "n1".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            LockstepMismatch {
                test_id: "n2".into(),
                expected: "c".into(),
                actual: "d".into(),
            },
        ],
    };
    tracker.ingest_lockstep(&node, &c).unwrap();

    // Bun: 20/20
    let bun = LockstepResult {
        area: FeatureArea::OptionalChaining,
        runtime: LockstepRuntime::Bun,
        total_comparisons: 20,
        matches: 20,
        mismatches: vec![],
    };
    tracker.ingest_lockstep(&bun, &c).unwrap();

    let entry = tracker.feature(&fid).unwrap();
    assert_eq!(
        entry.lockstep_match_rates_millionths.get("node"),
        Some(&900_000)
    );
    assert_eq!(
        entry.lockstep_match_rates_millionths.get("bun"),
        Some(&1_000_000)
    );
}

#[test]
fn ingest_lockstep_invalid_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let bad = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Node,
        total_comparisons: 10,
        matches: 15,
        mismatches: vec![],
    };
    let err = tracker.ingest_lockstep(&bad, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

#[test]
fn ingest_lockstep_emits_event() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = LockstepResult {
        area: FeatureArea::GlobalThis,
        runtime: LockstepRuntime::Bun,
        total_comparisons: 10,
        matches: 10,
        mismatches: vec![],
    };
    tracker.ingest_lockstep(&result, &c).unwrap();
    assert!(
        tracker
            .events()
            .iter()
            .any(|e| e.event == "lockstep_ingested")
    );
}

// ===========================================================================
// FeatureParityTracker — waiver governance
// ===========================================================================

#[test]
fn register_waiver_succeeds() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-1");
    tracker.register_waiver(w, &c).unwrap();
    assert_eq!(tracker.waiver_count(), 1);
}

#[test]
fn register_waiver_adds_exemptions() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-1");
    tracker.register_waiver(w, &c).unwrap();
    assert!(tracker.is_test262_waived("test-exempted-1"));
    assert!(tracker.is_lockstep_waived("lockstep-exempted-1"));
    assert!(!tracker.is_test262_waived("not-exempted"));
    assert!(!tracker.is_lockstep_waived("not-exempted"));
}

#[test]
fn register_waiver_marks_not_started_as_waived() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = bigint_fid();
    assert_eq!(
        tracker.feature(&fid).unwrap().status,
        FeatureStatus::NotStarted
    );
    let w = make_waiver(&fid, "w-1");
    tracker.register_waiver(w, &c).unwrap();
    assert_eq!(tracker.feature(&fid).unwrap().status, FeatureStatus::Waived);
}

#[test]
fn register_waiver_does_not_downgrade_passing() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = bigint_fid();
    tracker
        .set_status(&fid, FeatureStatus::Passing, &c)
        .unwrap();
    let w = make_waiver(&fid, "w-1");
    tracker.register_waiver(w, &c).unwrap();
    assert_eq!(
        tracker.feature(&fid).unwrap().status,
        FeatureStatus::Passing
    );
}

#[test]
fn register_waiver_duplicate_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-dup");
    tracker.register_waiver(w.clone(), &c).unwrap();
    let err = tracker.register_waiver(w, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0003");
}

#[test]
fn register_waiver_unknown_feature_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver("nonexistent-feature", "w-1");
    let err = tracker.register_waiver(w, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0001");
}

#[test]
fn register_waiver_invalid_waiver_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let mut w = make_waiver(&bigint_fid(), "w-1");
    w.waiver_id = "".to_string();
    let err = tracker.register_waiver(w, &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

#[test]
fn seal_waiver_succeeds() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-1");
    tracker.register_waiver(w, &c).unwrap();
    tracker.seal_waiver("w-1", &c).unwrap();
    assert!(tracker.waivers().get("w-1").unwrap().sealed);
}

#[test]
fn seal_already_sealed_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-1");
    tracker.register_waiver(w, &c).unwrap();
    tracker.seal_waiver("w-1", &c).unwrap();
    let err = tracker.seal_waiver("w-1", &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0004");
}

#[test]
fn seal_nonexistent_waiver_rejected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let err = tracker.seal_waiver("no-such-waiver", &c).unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0002");
}

#[test]
fn waivers_accessor_returns_all() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid_bigint = bigint_fid();
    let fid_global = format!("ES2020-{}", FeatureArea::GlobalThis.as_str());
    tracker
        .register_waiver(make_waiver(&fid_bigint, "w-1"), &c)
        .unwrap();
    tracker
        .register_waiver(make_waiver(&fid_global, "w-2"), &c)
        .unwrap();
    assert_eq!(tracker.waivers().len(), 2);
}

// ===========================================================================
// FeatureParityTracker — dashboard
// ===========================================================================

#[test]
fn dashboard_empty_tracker() {
    let tracker = FeatureParityTracker::empty();
    let dash = tracker.dashboard();
    assert_eq!(dash.total_features, 0);
    assert_eq!(dash.total_waivers, 0);
    assert_eq!(dash.sealed_waivers, 0);
    assert_eq!(dash.overall_test262_pass_rate_millionths, 0);
    assert!(dash.per_area.is_empty());
}

#[test]
fn dashboard_reflects_test262_results() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 100,
        passing: 80,
        failing_test_ids: (0..20).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let dash = tracker.dashboard();
    assert_eq!(dash.total_features, 10);
    let fid = bigint_fid();
    let area_snap = dash.per_area.get(&fid).unwrap();
    assert_eq!(area_snap.test262_pass_rate_millionths, 800_000);
    assert_eq!(area_snap.status, FeatureStatus::InProgress);
}

#[test]
fn dashboard_reflects_lockstep_results() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let result = LockstepResult {
        area: FeatureArea::BigInt,
        runtime: LockstepRuntime::Node,
        total_comparisons: 100,
        matches: 95,
        mismatches: (0..5)
            .map(|i| LockstepMismatch {
                test_id: format!("m{i}"),
                expected: "a".into(),
                actual: "b".into(),
            })
            .collect(),
    };
    tracker.ingest_lockstep(&result, &c).unwrap();

    let dash = tracker.dashboard();
    assert_eq!(
        dash.overall_lockstep_match_rates_millionths.get("node"),
        Some(&950_000)
    );
}

#[test]
fn dashboard_counts_waivers_and_sealed() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid_bigint = bigint_fid();
    let fid_global = format!("ES2020-{}", FeatureArea::GlobalThis.as_str());

    tracker
        .register_waiver(make_waiver(&fid_bigint, "w-1"), &c)
        .unwrap();
    tracker
        .register_waiver(make_waiver(&fid_global, "w-2"), &c)
        .unwrap();
    tracker.seal_waiver("w-1", &c).unwrap();

    let dash = tracker.dashboard();
    assert_eq!(dash.total_waivers, 2);
    assert_eq!(dash.sealed_waivers, 1);
}

#[test]
fn dashboard_status_counts() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();

    // All start as not_started.
    let dash = tracker.dashboard();
    assert_eq!(dash.status_counts.get("not_started"), Some(&10));

    // Move one to in_progress.
    tracker
        .set_status(&bigint_fid(), FeatureStatus::InProgress, &c)
        .unwrap();
    let dash = tracker.dashboard();
    assert_eq!(dash.status_counts.get("not_started"), Some(&9));
    assert_eq!(dash.status_counts.get("in_progress"), Some(&1));
}

// ===========================================================================
// FeatureParityTracker — release gate evaluation
// ===========================================================================

#[test]
fn gate_passes_all_features_100_percent() {
    let mut tracker = all_passing_tracker();
    let c = ctx();
    let decision = tracker.evaluate_gate(&c);
    assert!(decision.passed);
    assert!(decision.failing_features.is_empty());
    assert!(decision.unwaived_failures.is_empty());
}

#[test]
fn gate_fails_feature_below_threshold() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    // BigInt at 50%.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 5,
        failing_test_ids: (0..5).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let decision = tracker.evaluate_gate(&c);
    assert!(!decision.passed);
    assert!(decision.failing_features.contains(&bigint_fid()));
}

#[test]
fn gate_fails_lockstep_below_threshold() {
    let mut tracker = all_passing_tracker();
    let c = ctx();

    // Add poor lockstep result.
    let result = LockstepResult {
        area: FeatureArea::BigInt,
        runtime: LockstepRuntime::Node,
        total_comparisons: 100,
        matches: 50,
        mismatches: (0..50)
            .map(|i| LockstepMismatch {
                test_id: format!("m{i}"),
                expected: "a".into(),
                actual: "b".into(),
            })
            .collect(),
    };
    tracker.ingest_lockstep(&result, &c).unwrap();

    let decision = tracker.evaluate_gate(&c);
    assert!(!decision.passed);
    assert!(decision.failing_features.contains(&bigint_fid()));
}

#[test]
fn gate_skips_waived_features() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let fid = bigint_fid();

    // BigInt poor results.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 2,
        failing_test_ids: (0..8).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    // Waive it.
    tracker
        .register_waiver(make_waiver(&fid, "w-bigint"), &c)
        .unwrap();

    // All others pass.
    for &area in FeatureArea::all() {
        if area == FeatureArea::BigInt {
            continue;
        }
        let r = Test262Result {
            area,
            total: 10,
            passing: 10,
            failing_test_ids: vec![],
        };
        tracker.ingest_test262(&r, &c).unwrap();
    }

    let decision = tracker.evaluate_gate(&c);
    assert!(decision.passed, "waived feature should not block gate");
}

#[test]
fn gate_custom_criteria() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    tracker.set_gate_criteria(ReleaseGateCriteria {
        min_test262_pass_rate_millionths: 500_000, // 50%
        min_lockstep_match_rate_millionths: 500_000,
        require_waiver_coverage: false,
    });

    // BigInt at 60% — passes 50% threshold.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 6,
        failing_test_ids: (0..4).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let decision = tracker.evaluate_gate(&c);
    // Only BigInt has results. It passes the 50% threshold.
    // Other features have no test262 total, so they don't fail the rate check.
    assert!(decision.passed);
}

#[test]
fn gate_unwaived_failures_detected() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();

    // BigInt at 80% (below default 95% threshold) without a waiver.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 8,
        failing_test_ids: vec!["f1".into(), "f2".into()],
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let decision = tracker.evaluate_gate(&c);
    assert!(!decision.passed);
    // Should have unwaived failure since require_waiver_coverage is true by default.
    assert!(
        decision
            .unwaived_failures
            .iter()
            .any(|u| u.feature_id == bigint_fid())
    );
}

#[test]
fn gate_emits_event() {
    let mut tracker = all_passing_tracker();
    let c = ctx();
    tracker.evaluate_gate(&c);
    assert!(
        tracker
            .events()
            .iter()
            .any(|e| e.event == "release_gate_evaluated")
    );
}

#[test]
fn gate_pass_event_has_no_error_code() {
    let mut tracker = all_passing_tracker();
    let c = ctx();
    tracker.evaluate_gate(&c);
    let gate_event = tracker
        .events()
        .iter()
        .find(|e| e.event == "release_gate_evaluated")
        .unwrap();
    assert_eq!(gate_event.outcome, "pass");
    assert!(gate_event.error_code.is_none());
}

#[test]
fn gate_fail_event_has_error_code() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    // BigInt fails.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 1,
        failing_test_ids: (0..9).map(|i| format!("f{i}")).collect(),
    };
    tracker.ingest_test262(&result, &c).unwrap();
    tracker.evaluate_gate(&c);
    let gate_event = tracker
        .events()
        .iter()
        .find(|e| e.event == "release_gate_evaluated")
        .unwrap();
    assert_eq!(gate_event.outcome, "fail");
    assert_eq!(gate_event.error_code.as_deref(), Some("FE-FPT-0007"));
}

// ===========================================================================
// FeatureParityTracker — events
// ===========================================================================

#[test]
fn events_emitted_on_operations() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();

    tracker
        .set_status(&bigint_fid(), FeatureStatus::InProgress, &c)
        .unwrap();
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 10,
        failing_test_ids: vec![],
    };
    tracker.ingest_test262(&result, &c).unwrap();

    let events = tracker.events();
    assert!(events.len() >= 2);
    assert!(
        events
            .iter()
            .all(|e| e.component == "feature_parity_tracker")
    );
    assert!(events.iter().all(|e| e.trace_id == "trace-int"));
}

#[test]
fn drain_events_clears() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    tracker
        .set_status(&bigint_fid(), FeatureStatus::InProgress, &c)
        .unwrap();
    let drained = tracker.drain_events();
    assert!(!drained.is_empty());
    assert!(tracker.events().is_empty());
}

#[test]
fn events_from_waiver_operations() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();
    let w = make_waiver(&bigint_fid(), "w-1");
    tracker.register_waiver(w, &c).unwrap();
    tracker.seal_waiver("w-1", &c).unwrap();

    let events = tracker.events();
    assert!(events.iter().any(|e| e.event == "waiver_registered"));
    assert!(events.iter().any(|e| e.event == "waiver_sealed"));
}

// ===========================================================================
// FeatureParityTracker — serde
// ===========================================================================

#[test]
fn tracker_serde_round_trip() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();

    // Add some state.
    let result = Test262Result {
        area: FeatureArea::BigInt,
        total: 10,
        passing: 8,
        failing_test_ids: vec!["f1".into(), "f2".into()],
    };
    tracker.ingest_test262(&result, &c).unwrap();
    let w = make_waiver(
        &format!("ES2020-{}", FeatureArea::GlobalThis.as_str()),
        "w-gt",
    );
    tracker.register_waiver(w, &c).unwrap();

    let json = serde_json::to_string(&tracker).unwrap();
    let restored: FeatureParityTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.feature_count(), tracker.feature_count());
    assert_eq!(restored.waiver_count(), tracker.waiver_count());
    assert_eq!(restored.feature(&bigint_fid()).unwrap().test262_passing, 8);
}

// ===========================================================================
// Stress test
// ===========================================================================

#[test]
fn stress_all_areas_test262_and_lockstep() {
    let mut tracker = FeatureParityTracker::new();
    let c = ctx();

    for (i, &area) in FeatureArea::all().iter().enumerate() {
        let passing = 80 + (i % 21); // 80-100
        let total = 100;
        let result = Test262Result {
            area,
            total,
            passing,
            failing_test_ids: (0..(total - passing))
                .map(|j| format!("{}-f{j}", area.as_str()))
                .collect(),
        };
        tracker.ingest_test262(&result, &c).unwrap();

        // Node lockstep.
        let node_matches = 90 + (i % 11);
        let node = LockstepResult {
            area,
            runtime: LockstepRuntime::Node,
            total_comparisons: 100,
            matches: node_matches,
            mismatches: (0..(100 - node_matches))
                .map(|j| LockstepMismatch {
                    test_id: format!("n-{}-{j}", area.as_str()),
                    expected: "e".into(),
                    actual: "a".into(),
                })
                .collect(),
        };
        tracker.ingest_lockstep(&node, &c).unwrap();

        // Bun lockstep.
        let bun_matches = 95 + (i % 6);
        let bun = LockstepResult {
            area,
            runtime: LockstepRuntime::Bun,
            total_comparisons: 100,
            matches: bun_matches,
            mismatches: (0..(100 - bun_matches))
                .map(|j| LockstepMismatch {
                    test_id: format!("b-{}-{j}", area.as_str()),
                    expected: "e".into(),
                    actual: "a".into(),
                })
                .collect(),
        };
        tracker.ingest_lockstep(&bun, &c).unwrap();
    }

    let dash = tracker.dashboard();
    assert_eq!(dash.total_features, 10);
    assert!(dash.overall_test262_pass_rate_millionths > 0);
    assert!(
        dash.overall_lockstep_match_rates_millionths
            .contains_key("node")
    );
    assert!(
        dash.overall_lockstep_match_rates_millionths
            .contains_key("bun")
    );

    // All features have results.
    for snap in dash.per_area.values() {
        assert!(snap.test262_pass_rate_millionths > 0);
    }

    let decision = tracker.evaluate_gate(&c);
    // Some features may not meet 95% threshold.
    // Decision should be computed without panicking.
    let _ = decision.passed;
}
