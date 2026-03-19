//! Enrichment integration tests for `feature_parity_tracker` module.
//!
//! Covers: FeatureStatus, EsVersion, LockstepRuntime, FeatureArea, FeatureEntry,
//! Test262Result, LockstepResult, LockstepMismatch, WaiverRecord,
//! ReleaseGateCriteria, ReleaseGateDecision, UnwaivedFailure, ParityEvent,
//! ParityTrackerError — FeatureArea::all() completeness, Display uniqueness,
//! FeatureEntry creation and ID format, validation, serde roundtrips,
//! error code uniqueness, ReleaseGateCriteria defaults.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::feature_parity_tracker::*;

// ── helpers ──────────────────────────────────────────────────────────────

fn all_feature_statuses() -> Vec<FeatureStatus> {
    vec![FeatureStatus::NotStarted, FeatureStatus::InProgress, FeatureStatus::Passing, FeatureStatus::Waived]
}

fn all_parity_errors() -> Vec<ParityTrackerError> {
    vec![
        ParityTrackerError::FeatureNotFound { feature_id: "f1".to_string() },
        ParityTrackerError::WaiverNotFound { waiver_id: "w1".to_string() },
        ParityTrackerError::WaiverAlreadyExists { waiver_id: "w2".to_string() },
        ParityTrackerError::WaiverSealed { waiver_id: "w3".to_string() },
        ParityTrackerError::InvalidWaiver { detail: "bad waiver".to_string() },
        ParityTrackerError::InvalidMetrics { detail: "bad metrics".to_string() },
        ParityTrackerError::DuplicateFeature { feature_id: "f2".to_string() },
        ParityTrackerError::GateEvaluationFailed { detail: "gate fail".to_string() },
    ]
}

fn sample_waiver(waiver_id: &str, feature_id: &str) -> WaiverRecord {
    WaiverRecord {
        waiver_id: waiver_id.to_string(),
        feature_id: feature_id.to_string(),
        reason: "intentional divergence".to_string(),
        approved_by: "alice".to_string(),
        approved_at_ns: 1000,
        valid_until_ns: Some(2000),
        test262_exemptions: vec!["test-1".to_string()],
        lockstep_exemptions: vec!["ls-1".to_string()],
        sealed: false,
    }
}

// ── test: FeatureArea::all() completeness ────────────────────────────────

#[test]
fn enrichment_feature_area_all_completeness() {
    let all = FeatureArea::all();
    assert_eq!(all.len(), 10);
}

// ── test: FeatureArea::all() contains all expected variants ──────────────

#[test]
fn enrichment_feature_area_all_contains_expected() {
    let all_set: BTreeSet<FeatureArea> = FeatureArea::all().iter().copied().collect();
    assert!(all_set.contains(&FeatureArea::OptionalChaining));
    assert!(all_set.contains(&FeatureArea::NullishCoalescing));
    assert!(all_set.contains(&FeatureArea::DynamicImport));
    assert!(all_set.contains(&FeatureArea::BigInt));
    assert!(all_set.contains(&FeatureArea::PromiseAllSettled));
    assert!(all_set.contains(&FeatureArea::GlobalThis));
    assert!(all_set.contains(&FeatureArea::ModuleNamespaceExports));
    assert!(all_set.contains(&FeatureArea::StringMatchAll));
    assert!(all_set.contains(&FeatureArea::ImportMeta));
    assert!(all_set.contains(&FeatureArea::ForInOrder));
}

// ── test: FeatureArea Display uniqueness ──────────────────────────────────

#[test]
fn enrichment_feature_area_display_uniqueness() {
    let strs: BTreeSet<String> = FeatureArea::all().iter().map(|a| a.to_string()).collect();
    assert_eq!(strs.len(), 10);
}

// ── test: FeatureArea as_str matches Display ─────────────────────────────

#[test]
fn enrichment_feature_area_as_str_matches_display() {
    for area in FeatureArea::all() {
        assert_eq!(area.as_str(), area.to_string());
    }
}

// ── test: FeatureStatus Display uniqueness ───────────────────────────────

#[test]
fn enrichment_feature_status_display_uniqueness() {
    let strs: BTreeSet<String> = all_feature_statuses().iter().map(|s| s.to_string()).collect();
    assert_eq!(strs.len(), 4);
}

// ── test: EsVersion Display ──────────────────────────────────────────────

#[test]
fn enrichment_es_version_display() {
    assert_eq!(EsVersion::Es2020.to_string(), "ES2020");
}

// ── test: LockstepRuntime Display uniqueness ─────────────────────────────

#[test]
fn enrichment_lockstep_runtime_display_uniqueness() {
    let runtimes = [LockstepRuntime::Node, LockstepRuntime::Bun];
    let strs: BTreeSet<String> = runtimes.iter().map(|r| r.to_string()).collect();
    assert_eq!(strs.len(), 2);
}

// ── test: FeatureEntry::new creates entry with correct defaults ──────────

#[test]
fn enrichment_feature_entry_new_defaults() {
    let entry = FeatureEntry::new(FeatureArea::OptionalChaining, EsVersion::Es2020);
    assert_eq!(entry.area, FeatureArea::OptionalChaining);
    assert_eq!(entry.es_version, EsVersion::Es2020);
    assert_eq!(entry.status, FeatureStatus::NotStarted);
    assert_eq!(entry.test262_total, 0);
    assert_eq!(entry.test262_passing, 0);
    assert_eq!(entry.test262_pass_rate_millionths, 0);
    assert!(entry.lockstep_match_rates_millionths.is_empty());
}

// ── test: FeatureEntry ID format ─────────────────────────────────────────

#[test]
fn enrichment_feature_entry_id_format() {
    let entry = FeatureEntry::new(FeatureArea::BigInt, EsVersion::Es2020);
    assert_eq!(entry.feature_id, "ES2020-bigint");
}

// ── test: FeatureEntry ID unique per area ────────────────────────────────

#[test]
fn enrichment_feature_entry_id_unique_per_area() {
    let ids: BTreeSet<String> = FeatureArea::all()
        .iter()
        .map(|a| FeatureEntry::new(*a, EsVersion::Es2020).feature_id)
        .collect();
    assert_eq!(ids.len(), 10);
}

// ── test: Test262Result validate passing > total ─────────────────────────

#[test]
fn enrichment_test262_validate_passing_exceeds_total() {
    let r = Test262Result { area: FeatureArea::BigInt, total: 10, passing: 15, failing_test_ids: vec![] };
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
    assert!(err.to_string().contains("exceeds total"));
}

// ── test: Test262Result validate passes when valid ───────────────────────

#[test]
fn enrichment_test262_validate_ok() {
    let r = Test262Result { area: FeatureArea::BigInt, total: 10, passing: 8, failing_test_ids: vec!["t1".to_string(), "t2".to_string()] };
    assert!(r.validate().is_ok());
}

// ── test: Test262Result validate passing == total is ok ───────────────────

#[test]
fn enrichment_test262_validate_all_passing() {
    let r = Test262Result { area: FeatureArea::BigInt, total: 10, passing: 10, failing_test_ids: vec![] };
    assert!(r.validate().is_ok());
}

// ── test: LockstepResult validate matches > total ────────────────────────

#[test]
fn enrichment_lockstep_validate_matches_exceeds_total() {
    let r = LockstepResult { area: FeatureArea::BigInt, runtime: LockstepRuntime::Node, total_comparisons: 5, matches: 10, mismatches: vec![] };
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

// ── test: LockstepResult validate mismatch count inconsistency ───────────

#[test]
fn enrichment_lockstep_validate_mismatch_count_inconsistent() {
    let r = LockstepResult {
        area: FeatureArea::BigInt,
        runtime: LockstepRuntime::Bun,
        total_comparisons: 10,
        matches: 7,
        mismatches: vec![
            LockstepMismatch { test_id: "t1".to_string(), expected: "a".to_string(), actual: "b".to_string() },
        ],
    };
    // 10-7=3 mismatches expected but only 1 provided
    let err = r.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0006");
}

// ── test: LockstepResult validate ok ─────────────────────────────────────

#[test]
fn enrichment_lockstep_validate_ok() {
    let r = LockstepResult {
        area: FeatureArea::BigInt,
        runtime: LockstepRuntime::Node,
        total_comparisons: 5,
        matches: 3,
        mismatches: vec![
            LockstepMismatch { test_id: "t1".to_string(), expected: "a".to_string(), actual: "b".to_string() },
            LockstepMismatch { test_id: "t2".to_string(), expected: "c".to_string(), actual: "d".to_string() },
        ],
    };
    assert!(r.validate().is_ok());
}

// ── test: WaiverRecord validate empty waiver_id ──────────────────────────

#[test]
fn enrichment_waiver_validate_empty_waiver_id() {
    let mut w = sample_waiver("w1", "f1");
    w.waiver_id = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
    assert!(err.to_string().contains("waiver_id"));
}

// ── test: WaiverRecord validate empty feature_id ─────────────────────────

#[test]
fn enrichment_waiver_validate_empty_feature_id() {
    let mut w = sample_waiver("w1", "f1");
    w.feature_id = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

// ── test: WaiverRecord validate empty reason ─────────────────────────────

#[test]
fn enrichment_waiver_validate_empty_reason() {
    let mut w = sample_waiver("w1", "f1");
    w.reason = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

// ── test: WaiverRecord validate empty approved_by ────────────────────────

#[test]
fn enrichment_waiver_validate_empty_approved_by() {
    let mut w = sample_waiver("w1", "f1");
    w.approved_by = "".to_string();
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

// ── test: WaiverRecord validate valid_until <= approved_at ───────────────

#[test]
fn enrichment_waiver_validate_valid_until_before_approved() {
    let mut w = sample_waiver("w1", "f1");
    w.approved_at_ns = 5000;
    w.valid_until_ns = Some(3000);
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
    assert!(err.to_string().contains("valid_until"));
}

// ── test: WaiverRecord validate valid_until == approved_at ───────────────

#[test]
fn enrichment_waiver_validate_valid_until_equal_approved() {
    let mut w = sample_waiver("w1", "f1");
    w.approved_at_ns = 5000;
    w.valid_until_ns = Some(5000);
    let err = w.validate().unwrap_err();
    assert_eq!(err.code(), "FE-FPT-0005");
}

// ── test: WaiverRecord validate ok ───────────────────────────────────────

#[test]
fn enrichment_waiver_validate_ok() {
    let w = sample_waiver("w1", "f1");
    assert!(w.validate().is_ok());
}

// ── test: WaiverRecord validate no valid_until is ok ─────────────────────

#[test]
fn enrichment_waiver_validate_no_until_ok() {
    let mut w = sample_waiver("w1", "f1");
    w.valid_until_ns = None;
    assert!(w.validate().is_ok());
}

// ── test: ParityTrackerError code uniqueness ─────────────────────────────

#[test]
fn enrichment_error_code_uniqueness() {
    let codes: BTreeSet<String> = all_parity_errors().iter().map(|e| e.code().to_string()).collect();
    assert_eq!(codes.len(), 8);
}

// ── test: ParityTrackerError code stable values ──────────────────────────

#[test]
fn enrichment_error_code_stable_values() {
    assert_eq!(ParityTrackerError::FeatureNotFound { feature_id: "f".to_string() }.code(), "FE-FPT-0001");
    assert_eq!(ParityTrackerError::WaiverNotFound { waiver_id: "w".to_string() }.code(), "FE-FPT-0002");
    assert_eq!(ParityTrackerError::WaiverAlreadyExists { waiver_id: "w".to_string() }.code(), "FE-FPT-0003");
    assert_eq!(ParityTrackerError::WaiverSealed { waiver_id: "w".to_string() }.code(), "FE-FPT-0004");
    assert_eq!(ParityTrackerError::InvalidWaiver { detail: "d".to_string() }.code(), "FE-FPT-0005");
    assert_eq!(ParityTrackerError::InvalidMetrics { detail: "d".to_string() }.code(), "FE-FPT-0006");
    assert_eq!(ParityTrackerError::DuplicateFeature { feature_id: "f".to_string() }.code(), "FE-FPT-0007");
    assert_eq!(ParityTrackerError::GateEvaluationFailed { detail: "d".to_string() }.code(), "FE-FPT-0008");
}

// ── test: ParityTrackerError Display uniqueness ──────────────────────────

#[test]
fn enrichment_error_display_uniqueness() {
    let strs: BTreeSet<String> = all_parity_errors().iter().map(|e| e.to_string()).collect();
    assert_eq!(strs.len(), 8);
}

// ── test: ParityTrackerError Display contains code ───────────────────────

#[test]
fn enrichment_error_display_contains_code() {
    for err in all_parity_errors() {
        let msg = err.to_string();
        assert!(msg.contains(err.code()), "Display should contain error code: {msg}");
    }
}

// ── test: ParityTrackerError implements std::error::Error ────────────────

#[test]
fn enrichment_error_std_error_trait() {
    for err in all_parity_errors() {
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
        assert!(boxed.source().is_none());
    }
}

// ── test: ReleaseGateCriteria defaults ───────────────────────────────────

#[test]
fn enrichment_release_gate_criteria_defaults() {
    let c = ReleaseGateCriteria::default();
    assert_eq!(c.min_test262_pass_rate_millionths, 950_000);
    assert_eq!(c.min_lockstep_match_rate_millionths, 950_000);
    assert!(c.require_waiver_coverage);
}

// ── test: serde roundtrip FeatureStatus ──────────────────────────────────

#[test]
fn enrichment_serde_feature_status() {
    for s in all_feature_statuses() {
        let json = serde_json::to_string(&s).unwrap();
        let back: FeatureStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── test: serde roundtrip EsVersion ──────────────────────────────────────

#[test]
fn enrichment_serde_es_version() {
    let v = EsVersion::Es2020;
    let json = serde_json::to_string(&v).unwrap();
    let back: EsVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ── test: serde roundtrip LockstepRuntime ────────────────────────────────

#[test]
fn enrichment_serde_lockstep_runtime() {
    for r in [LockstepRuntime::Node, LockstepRuntime::Bun] {
        let json = serde_json::to_string(&r).unwrap();
        let back: LockstepRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ── test: serde roundtrip FeatureArea all ────────────────────────────────

#[test]
fn enrichment_serde_feature_area_all() {
    for area in FeatureArea::all() {
        let json = serde_json::to_string(area).unwrap();
        let back: FeatureArea = serde_json::from_str(&json).unwrap();
        assert_eq!(*area, back);
    }
}

// ── test: serde roundtrip FeatureEntry ───────────────────────────────────

#[test]
fn enrichment_serde_feature_entry() {
    let entry = FeatureEntry::new(FeatureArea::GlobalThis, EsVersion::Es2020);
    let json = serde_json::to_string(&entry).unwrap();
    let back: FeatureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ── test: serde roundtrip Test262Result ───────────────────────────────────

#[test]
fn enrichment_serde_test262_result() {
    let r = Test262Result { area: FeatureArea::BigInt, total: 100, passing: 95, failing_test_ids: vec!["t1".to_string()] };
    let json = serde_json::to_string(&r).unwrap();
    let back: Test262Result = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── test: serde roundtrip LockstepResult ─────────────────────────────────

#[test]
fn enrichment_serde_lockstep_result() {
    let r = LockstepResult {
        area: FeatureArea::ForInOrder,
        runtime: LockstepRuntime::Node,
        total_comparisons: 50,
        matches: 48,
        mismatches: vec![
            LockstepMismatch { test_id: "t1".to_string(), expected: "a".to_string(), actual: "b".to_string() },
            LockstepMismatch { test_id: "t2".to_string(), expected: "c".to_string(), actual: "d".to_string() },
        ],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: LockstepResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── test: serde roundtrip WaiverRecord ───────────────────────────────────

#[test]
fn enrichment_serde_waiver_record() {
    let w = sample_waiver("w1", "f1");
    let json = serde_json::to_string(&w).unwrap();
    let back: WaiverRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ── test: serde roundtrip ReleaseGateCriteria ────────────────────────────

#[test]
fn enrichment_serde_release_gate_criteria() {
    let c = ReleaseGateCriteria::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: ReleaseGateCriteria = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── test: serde roundtrip ReleaseGateDecision ────────────────────────────

#[test]
fn enrichment_serde_release_gate_decision() {
    let d = ReleaseGateDecision {
        passed: true,
        failing_features: vec![],
        unwaived_failures: vec![],
        overall_test262_pass_rate_millionths: 960_000,
        overall_lockstep_match_rate_millionths: 970_000,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: ReleaseGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ── test: serde roundtrip UnwaivedFailure ────────────────────────────────

#[test]
fn enrichment_serde_unwaived_failure() {
    let f = UnwaivedFailure { feature_id: "f1".to_string(), failure_type: "test262".to_string(), test_id: "t1".to_string() };
    let json = serde_json::to_string(&f).unwrap();
    let back: UnwaivedFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ── test: serde roundtrip ParityEvent ────────────────────────────────────

#[test]
fn enrichment_serde_parity_event() {
    let e = ParityEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "feature_parity_tracker".to_string(),
        event: "test262_ingested".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ── test: serde roundtrip ParityTrackerError all 8 ───────────────────────

#[test]
fn enrichment_serde_parity_error_all() {
    for err in all_parity_errors() {
        let json = serde_json::to_string(&err).unwrap();
        let back: ParityTrackerError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ── test: serde roundtrip LockstepMismatch ───────────────────────────────

#[test]
fn enrichment_serde_lockstep_mismatch() {
    let m = LockstepMismatch { test_id: "t1".to_string(), expected: "exp".to_string(), actual: "act".to_string() };
    let json = serde_json::to_string(&m).unwrap();
    let back: LockstepMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}
