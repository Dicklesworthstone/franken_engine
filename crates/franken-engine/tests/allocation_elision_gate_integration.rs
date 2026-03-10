//! Integration tests for the `allocation_elision_gate` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! batch processing, rollback governance, savings reports, evidence bundles,
//! and diagnostic emission.

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

use std::collections::BTreeSet;

use frankenengine_engine::allocation_elision_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn site(id: &str) -> AllocationSiteId {
    AllocationSiteId::new(id)
}

fn lane(id: &str) -> LaneId {
    LaneId::new(id)
}

fn good_gc_assessment() -> GcImpactAssessment {
    GcImpactAssessment {
        baseline_pause_p50_ns: 1_000_000,
        baseline_pause_p99_ns: 5_000_000,
        elided_pause_p50_ns: 900_000,
        elided_pause_p99_ns: 4_800_000,
        baseline_allocs_per_cycle: 1000,
        elided_allocs_per_cycle: 800,
        baseline_bytes_per_cycle: 64_000,
        elided_bytes_per_cycle: 48_000,
        sample_count: 100,
        pause_regression_millionths: 960_000,
    }
}

fn bad_gc_assessment() -> GcImpactAssessment {
    GcImpactAssessment {
        baseline_pause_p50_ns: 1_000_000,
        baseline_pause_p99_ns: 5_000_000,
        elided_pause_p50_ns: 1_500_000,
        elided_pause_p99_ns: 8_000_000,
        baseline_allocs_per_cycle: 1000,
        elided_allocs_per_cycle: 800,
        baseline_bytes_per_cycle: 64_000,
        elided_bytes_per_cycle: 48_000,
        sample_count: 100,
        pause_regression_millionths: 1_600_000,
    }
}

fn good_latency_evidence() -> TailLatencyEvidence {
    TailLatencyEvidence {
        baseline_p99_ns: 10_000_000,
        baseline_p999_ns: 50_000_000,
        elided_p99_ns: 9_500_000,
        elided_p999_ns: 48_000_000,
        baseline_p50_ns: 1_000_000,
        elided_p50_ns: 900_000,
        sample_count: 100,
        workload_id: "bench-workload-1".to_string(),
    }
}

fn bad_latency_evidence() -> TailLatencyEvidence {
    TailLatencyEvidence {
        baseline_p99_ns: 10_000_000,
        baseline_p999_ns: 50_000_000,
        elided_p99_ns: 15_000_000,
        elided_p999_ns: 80_000_000,
        baseline_p50_ns: 1_000_000,
        elided_p50_ns: 1_200_000,
        sample_count: 100,
        workload_id: "bench-workload-1".to_string(),
    }
}

fn good_support_contract() -> SupportSurfaceContract {
    SupportSurfaceContract {
        contract_id: "contract-1".to_string(),
        covered_sites: BTreeSet::from(["site-a".to_string()]),
        min_coverage_millionths: 950_000,
        actual_coverage_millionths: 980_000,
        fallback_paths_verified: true,
        validated_epoch: epoch(1),
        notes: String::new(),
    }
}

fn bad_support_contract() -> SupportSurfaceContract {
    SupportSurfaceContract {
        contract_id: "contract-2".to_string(),
        covered_sites: BTreeSet::new(),
        min_coverage_millionths: 950_000,
        actual_coverage_millionths: 800_000,
        fallback_paths_verified: false,
        validated_epoch: epoch(1),
        notes: String::new(),
    }
}

fn healthy_observability() -> ObservabilityHealth {
    ObservabilityHealth {
        gc_telemetry_active: true,
        latency_probes_active: true,
        deopt_counters_active: true,
        support_checks_scheduled: true,
        events_since_last_check: 42,
        epoch: epoch(1),
        timestamp_ns: 1_000_000,
    }
}

fn unhealthy_observability() -> ObservabilityHealth {
    ObservabilityHealth {
        gc_telemetry_active: false,
        latency_probes_active: true,
        deopt_counters_active: true,
        support_checks_scheduled: false,
        events_since_last_check: 0,
        epoch: epoch(1),
        timestamp_ns: 1_000_000,
    }
}

fn make_good_input(site_name: &str) -> ElisionEvalInput {
    ElisionEvalInput {
        site_id: site(site_name),
        lane_id: lane("lane-1"),
        gc_assessment: good_gc_assessment(),
        latency_evidence: good_latency_evidence(),
        support_contract: Some(good_support_contract()),
        observability: Some(healthy_observability()),
        has_escape_certificate: true,
        epoch: epoch(1),
        now_ns: 10_000_000,
    }
}

fn make_deopt_witness(site_name: &str) -> DeoptWitness {
    DeoptWitness {
        site_id: site(site_name),
        lane_id: lane("lane-1"),
        assumption_kind: AssumptionKind::NoEscape,
        timestamp_ns: 20_000_000,
        epoch: epoch(1),
        stack_depth: 3,
        occurrence_count: 1,
        approval_receipt_digest: ContentHash::compute(b"test"),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(ELISION_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ELISION_GATE_SCHEMA_VERSION.contains("allocation-elision"));
}

#[test]
fn component_name() {
    assert_eq!(ELISION_GATE_COMPONENT, "allocation_elision_gate");
}

#[test]
fn bead_id_format() {
    assert!(ELISION_GATE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn gc_pause_regression_default_valid() {
    assert!(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS <= 1_000_000);
}

#[test]
fn tail_latency_regression_default_valid() {
    assert!(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS <= 1_000_000);
}

#[test]
fn support_coverage_default_valid() {
    assert!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS > 0);
    assert!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS <= 1_000_000);
}

#[test]
fn min_sample_count_positive() {
    assert!(DEFAULT_MIN_SAMPLE_COUNT > 0);
}

#[test]
fn rollback_cooldown_positive() {
    assert!(DEFAULT_ROLLBACK_COOLDOWN_NS > 0);
}

#[test]
fn max_consecutive_rollbacks_positive() {
    assert!(MAX_CONSECUTIVE_ROLLBACKS > 0);
}

// ---------------------------------------------------------------------------
// ElisionVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_approved_allows_elision() {
    assert!(ElisionVerdict::Approved.is_elision_allowed());
}

#[test]
fn verdict_conditional_allows_elision() {
    assert!(ElisionVerdict::Conditional.is_elision_allowed());
}

#[test]
fn verdict_denied_disallows_elision() {
    assert!(!ElisionVerdict::Denied.is_elision_allowed());
}

#[test]
fn verdict_rolled_back_disallows_elision() {
    assert!(!ElisionVerdict::RolledBack.is_elision_allowed());
}

#[test]
fn verdict_as_str_all_variants() {
    assert_eq!(ElisionVerdict::Approved.as_str(), "approved");
    assert_eq!(ElisionVerdict::Conditional.as_str(), "conditional");
    assert_eq!(ElisionVerdict::Denied.as_str(), "denied");
    assert_eq!(ElisionVerdict::RolledBack.as_str(), "rolled_back");
}

#[test]
fn verdict_display_matches_as_str() {
    let verdicts = [
        ElisionVerdict::Approved,
        ElisionVerdict::Conditional,
        ElisionVerdict::Denied,
        ElisionVerdict::RolledBack,
    ];
    for v in &verdicts {
        assert_eq!(v.to_string(), v.as_str());
    }
}

#[test]
fn verdict_serde_roundtrip_all() {
    let verdicts = [
        ElisionVerdict::Approved,
        ElisionVerdict::Conditional,
        ElisionVerdict::Denied,
        ElisionVerdict::RolledBack,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: ElisionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// DenialReason
// ---------------------------------------------------------------------------

#[test]
fn denial_reason_as_str_all() {
    let reasons = [
        DenialReason::GcPauseRegression,
        DenialReason::TailLatencyRegression,
        DenialReason::InsufficientSupportCoverage,
        DenialReason::DeoptWitnessTriggered,
        DenialReason::RollbackLimitExceeded,
        DenialReason::InsufficientSamples,
        DenialReason::MissingEscapeCertificate,
        DenialReason::ObservabilityUnhealthy,
        DenialReason::OperatorDenied,
        DenialReason::EpochMismatch,
    ];
    let strs: BTreeSet<&str> = reasons.iter().map(|r| r.as_str()).collect();
    assert_eq!(strs.len(), 10);
}

#[test]
fn denial_reason_display_matches_as_str() {
    let reasons = [
        DenialReason::GcPauseRegression,
        DenialReason::TailLatencyRegression,
        DenialReason::InsufficientSupportCoverage,
        DenialReason::DeoptWitnessTriggered,
        DenialReason::RollbackLimitExceeded,
        DenialReason::InsufficientSamples,
        DenialReason::MissingEscapeCertificate,
        DenialReason::ObservabilityUnhealthy,
        DenialReason::OperatorDenied,
        DenialReason::EpochMismatch,
    ];
    for r in &reasons {
        assert_eq!(r.to_string(), r.as_str());
    }
}

#[test]
fn denial_reason_serde_roundtrip_all() {
    let reasons = [
        DenialReason::GcPauseRegression,
        DenialReason::TailLatencyRegression,
        DenialReason::InsufficientSupportCoverage,
        DenialReason::DeoptWitnessTriggered,
        DenialReason::RollbackLimitExceeded,
        DenialReason::InsufficientSamples,
        DenialReason::MissingEscapeCertificate,
        DenialReason::ObservabilityUnhealthy,
        DenialReason::OperatorDenied,
        DenialReason::EpochMismatch,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: DenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// AllocationSiteId / LaneId
// ---------------------------------------------------------------------------

#[test]
fn allocation_site_id_construction_and_display() {
    let s = AllocationSiteId::new("fn_foo:42");
    assert_eq!(s.as_str(), "fn_foo:42");
    assert_eq!(s.to_string(), "fn_foo:42");
}

#[test]
fn allocation_site_id_serde_roundtrip() {
    let s = AllocationSiteId::new("site-test");
    let json = serde_json::to_string(&s).unwrap();
    let back: AllocationSiteId = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn lane_id_construction_and_display() {
    let l = LaneId::new("optimized-lane-7");
    assert_eq!(l.as_str(), "optimized-lane-7");
    assert_eq!(l.to_string(), "optimized-lane-7");
}

#[test]
fn lane_id_serde_roundtrip() {
    let l = LaneId::new("lane-test");
    let json = serde_json::to_string(&l).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(l, back);
}

// ---------------------------------------------------------------------------
// AssumptionKind
// ---------------------------------------------------------------------------

#[test]
fn assumption_kind_all_count() {
    assert_eq!(AssumptionKind::ALL.len(), 8);
}

#[test]
fn assumption_kind_names_unique() {
    let names: BTreeSet<&str> = AssumptionKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(names.len(), AssumptionKind::ALL.len());
}

#[test]
fn assumption_kind_display_matches_as_str() {
    for k in AssumptionKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn assumption_kind_serde_all() {
    for k in AssumptionKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: AssumptionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

#[test]
fn rollback_trigger_display_all() {
    let triggers = [
        RollbackTrigger::GcRegression,
        RollbackTrigger::LatencyRegression,
        RollbackTrigger::DeoptEvent,
        RollbackTrigger::SupportViolation,
        RollbackTrigger::ObservabilityAnomaly,
        RollbackTrigger::OperatorInitiated,
    ];
    let strs: BTreeSet<String> = triggers.iter().map(|t| t.to_string()).collect();
    assert_eq!(strs.len(), 6);
    for t in &triggers {
        assert_eq!(t.to_string(), t.as_str());
    }
}

#[test]
fn rollback_trigger_serde_all() {
    let triggers = [
        RollbackTrigger::GcRegression,
        RollbackTrigger::LatencyRegression,
        RollbackTrigger::DeoptEvent,
        RollbackTrigger::SupportViolation,
        RollbackTrigger::ObservabilityAnomaly,
        RollbackTrigger::OperatorInitiated,
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticKind
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_kind_display_all() {
    let kinds = [
        DiagnosticKind::ElisionApproved,
        DiagnosticKind::ElisionDenied,
        DiagnosticKind::ElisionRolledBack,
        DiagnosticKind::GcAssessmentComplete,
        DiagnosticKind::LatencyEvidenceCollected,
        DiagnosticKind::DeoptWitnessRecorded,
        DiagnosticKind::SupportContractValidated,
        DiagnosticKind::HealthChecked,
        DiagnosticKind::SavingsReported,
    ];
    let strs: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(strs.len(), 9);
    for k in &kinds {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn diagnostic_kind_serde_all() {
    let kinds = [
        DiagnosticKind::ElisionApproved,
        DiagnosticKind::ElisionDenied,
        DiagnosticKind::ElisionRolledBack,
        DiagnosticKind::GcAssessmentComplete,
        DiagnosticKind::LatencyEvidenceCollected,
        DiagnosticKind::DeoptWitnessRecorded,
        DiagnosticKind::SupportContractValidated,
        DiagnosticKind::HealthChecked,
        DiagnosticKind::SavingsReported,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: DiagnosticKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// GcImpactAssessment
// ---------------------------------------------------------------------------

#[test]
fn gc_no_regression_when_improved() {
    let gc = good_gc_assessment();
    assert!(!gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
}

#[test]
fn gc_regression_when_pauses_worse() {
    let gc = bad_gc_assessment();
    assert!(gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
}

#[test]
fn gc_pause_regression_ratio() {
    let gc = good_gc_assessment();
    // 4_800_000 / 5_000_000 = 0.96 => 960_000
    assert_eq!(gc.compute_pause_regression(), 960_000);
}

#[test]
fn gc_zero_baseline_returns_zero() {
    let mut gc = good_gc_assessment();
    gc.baseline_pause_p99_ns = 0;
    assert_eq!(gc.compute_pause_regression(), 0);
    assert!(!gc.is_regressed(50_000));
}

#[test]
fn gc_bytes_saved_per_cycle() {
    let gc = good_gc_assessment();
    assert_eq!(gc.bytes_saved_per_cycle(), 16_000);
}

#[test]
fn gc_bytes_saved_no_underflow() {
    let mut gc = good_gc_assessment();
    gc.elided_bytes_per_cycle = gc.baseline_bytes_per_cycle + 100;
    assert_eq!(gc.bytes_saved_per_cycle(), 0);
}

#[test]
fn gc_digest_deterministic() {
    let gc1 = good_gc_assessment();
    let gc2 = good_gc_assessment();
    assert_eq!(gc1.digest(), gc2.digest());
}

#[test]
fn gc_different_data_different_digest() {
    assert_ne!(good_gc_assessment().digest(), bad_gc_assessment().digest());
}

#[test]
fn gc_serde_roundtrip() {
    let gc = good_gc_assessment();
    let json = serde_json::to_string(&gc).unwrap();
    let back: GcImpactAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(gc, back);
}

// ---------------------------------------------------------------------------
// TailLatencyEvidence
// ---------------------------------------------------------------------------

#[test]
fn latency_no_regression_when_improved() {
    let lat = good_latency_evidence();
    assert!(!lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
}

#[test]
fn latency_regression_detected() {
    let lat = bad_latency_evidence();
    assert!(lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
}

#[test]
fn latency_p99_regression_ratio() {
    let lat = good_latency_evidence();
    // 9_500_000 / 10_000_000 = 0.95 => 950_000
    assert_eq!(lat.p99_regression_millionths(), 950_000);
}

#[test]
fn latency_p999_regression_ratio() {
    let lat = good_latency_evidence();
    // 48_000_000 / 50_000_000 = 0.96 => 960_000
    assert_eq!(lat.p999_regression_millionths(), 960_000);
}

#[test]
fn latency_p50_improvement() {
    let lat = good_latency_evidence();
    // baseline 1_000_000 - elided 900_000 = 100_000
    assert_eq!(lat.p50_improvement_ns(), 100_000);
}

#[test]
fn latency_p50_negative_improvement() {
    let lat = bad_latency_evidence();
    // baseline 1_000_000 - elided 1_200_000 = -200_000
    assert_eq!(lat.p50_improvement_ns(), -200_000);
}

#[test]
fn latency_zero_baseline_returns_zero() {
    let mut lat = good_latency_evidence();
    lat.baseline_p99_ns = 0;
    lat.baseline_p999_ns = 0;
    assert_eq!(lat.p99_regression_millionths(), 0);
    assert_eq!(lat.p999_regression_millionths(), 0);
}

#[test]
fn latency_digest_deterministic() {
    let lat1 = good_latency_evidence();
    let lat2 = good_latency_evidence();
    assert_eq!(lat1.digest(), lat2.digest());
}

#[test]
fn latency_different_data_different_digest() {
    assert_ne!(
        good_latency_evidence().digest(),
        bad_latency_evidence().digest()
    );
}

#[test]
fn latency_serde_roundtrip() {
    let lat = good_latency_evidence();
    let json = serde_json::to_string(&lat).unwrap();
    let back: TailLatencyEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(lat, back);
}

// ---------------------------------------------------------------------------
// SupportSurfaceContract
// ---------------------------------------------------------------------------

#[test]
fn support_contract_met() {
    let c = good_support_contract();
    assert!(c.meets_coverage());
    assert!(c.is_satisfied());
    assert_eq!(c.coverage_deficit_millionths(), 0);
}

#[test]
fn support_contract_not_met() {
    let c = bad_support_contract();
    assert!(!c.meets_coverage());
    assert!(!c.is_satisfied());
}

#[test]
fn support_coverage_deficit() {
    let c = bad_support_contract();
    // min 950_000 - actual 800_000 = 150_000
    assert_eq!(c.coverage_deficit_millionths(), 150_000);
}

#[test]
fn support_fallback_not_verified_fails_satisfied() {
    let mut c = good_support_contract();
    c.fallback_paths_verified = false;
    assert!(c.meets_coverage());
    assert!(!c.is_satisfied());
}

#[test]
fn support_contract_digest_deterministic() {
    let c1 = good_support_contract();
    let c2 = good_support_contract();
    assert_eq!(c1.digest(), c2.digest());
}

#[test]
fn support_contract_different_data_different_digest() {
    assert_ne!(
        good_support_contract().digest(),
        bad_support_contract().digest()
    );
}

#[test]
fn support_contract_serde_roundtrip() {
    let c = good_support_contract();
    let json = serde_json::to_string(&c).unwrap();
    let back: SupportSurfaceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// ObservabilityHealth
// ---------------------------------------------------------------------------

#[test]
fn observability_all_healthy() {
    let h = healthy_observability();
    assert!(h.is_healthy());
    assert_eq!(h.unhealthy_count(), 0);
    assert!(h.unhealthy_subsystems().is_empty());
}

#[test]
fn observability_partial_unhealthy() {
    let h = unhealthy_observability();
    assert!(!h.is_healthy());
    assert_eq!(h.unhealthy_count(), 2);
    let subs = h.unhealthy_subsystems();
    assert!(subs.contains(&"gc_telemetry"));
    assert!(subs.contains(&"support_checks"));
}

#[test]
fn observability_all_unhealthy() {
    let h = ObservabilityHealth {
        gc_telemetry_active: false,
        latency_probes_active: false,
        deopt_counters_active: false,
        support_checks_scheduled: false,
        events_since_last_check: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
    };
    assert_eq!(h.unhealthy_count(), 4);
    assert_eq!(h.unhealthy_subsystems().len(), 4);
}

#[test]
fn observability_serde_roundtrip() {
    let h = healthy_observability();
    let json = serde_json::to_string(&h).unwrap();
    let back: ObservabilityHealth = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

#[test]
fn rollback_record_exceeds_limit() {
    let r = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::GcRegression,
        timestamp_ns: 1000,
        epoch: epoch(1),
        consecutive_count: MAX_CONSECUTIVE_ROLLBACKS,
        evidence_digest: ContentHash::compute(b"x"),
    };
    assert!(r.exceeds_limit());
}

#[test]
fn rollback_record_under_limit() {
    let r = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::LatencyRegression,
        timestamp_ns: 1000,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"x"),
    };
    assert!(!r.exceeds_limit());
}

#[test]
fn rollback_record_digest_deterministic() {
    let make = || RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::DeoptEvent,
        timestamp_ns: 1000,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"x"),
    };
    assert_eq!(make().digest(), make().digest());
}

#[test]
fn rollback_record_different_trigger_different_digest() {
    let r1 = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::GcRegression,
        timestamp_ns: 1000,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"x"),
    };
    let r2 = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::LatencyRegression,
        timestamp_ns: 1000,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"x"),
    };
    assert_ne!(r1.digest(), r2.digest());
}

#[test]
fn rollback_record_serde_roundtrip() {
    let r = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::OperatorInitiated,
        timestamp_ns: 5000,
        epoch: epoch(3),
        consecutive_count: 2,
        evidence_digest: ContentHash::compute(b"evidence"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DeoptWitness
// ---------------------------------------------------------------------------

#[test]
fn deopt_witness_digest_deterministic() {
    let make = || make_deopt_witness("s");
    assert_eq!(make().digest(), make().digest());
}

#[test]
fn deopt_witness_different_assumption_different_digest() {
    let mut w1 = make_deopt_witness("s");
    w1.assumption_kind = AssumptionKind::NoEscape;
    let mut w2 = make_deopt_witness("s");
    w2.assumption_kind = AssumptionKind::StableShape;
    assert_ne!(w1.digest(), w2.digest());
}

#[test]
fn deopt_witness_serde_roundtrip() {
    let w = make_deopt_witness("site-deopt");
    let json = serde_json::to_string(&w).unwrap();
    let back: DeoptWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// ---------------------------------------------------------------------------
// SiteElisionState
// ---------------------------------------------------------------------------

#[test]
fn site_state_new_is_denied() {
    let s = SiteElisionState::new(site("s1"), epoch(1));
    assert_eq!(s.verdict, ElisionVerdict::Denied);
    assert!(!s.permanently_denied);
    assert_eq!(s.consecutive_rollbacks, 0);
    assert_eq!(s.deopt_count_since_approval, 0);
    assert!(s.active_assumptions.is_empty());
}

#[test]
fn site_state_can_reevaluate_initially() {
    let s = SiteElisionState::new(site("s1"), epoch(1));
    assert!(s.can_reevaluate(1_000_000, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn site_state_cooldown_blocks_reevaluation() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    s.record_rollback(1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
    assert!(!s.can_reevaluate(2_000_000, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn site_state_cooldown_expires() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    s.record_rollback(1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
    let after_cooldown = 1_000_000 + DEFAULT_ROLLBACK_COOLDOWN_NS;
    assert!(s.can_reevaluate(after_cooldown, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn site_state_permanent_denial_after_max_rollbacks() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        s.record_rollback(i as u64 * 1_000_000, MAX_CONSECUTIVE_ROLLBACKS);
    }
    assert!(s.permanently_denied);
    assert!(!s.can_reevaluate(u64::MAX, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn site_state_record_approval_updates_fields() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    let assumptions = BTreeSet::from(["no_escape".to_string()]);
    s.record_approval(
        ElisionVerdict::Approved,
        assumptions.clone(),
        5_000,
        epoch(2),
    );
    assert_eq!(s.verdict, ElisionVerdict::Approved);
    assert_eq!(s.active_assumptions, assumptions);
    assert_eq!(s.verdict_epoch, epoch(2));
    assert_eq!(s.last_evaluated_ns, 5_000);
    assert_eq!(s.deopt_count_since_approval, 0);
}

#[test]
fn site_state_deopt_increments_count() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    s.record_deopt();
    s.record_deopt();
    s.record_deopt();
    assert_eq!(s.deopt_count_since_approval, 3);
}

#[test]
fn site_state_rollback_resets_deopt_count() {
    let mut s = SiteElisionState::new(site("s1"), epoch(1));
    s.record_deopt();
    s.record_deopt();
    s.record_rollback(1_000, MAX_CONSECUTIVE_ROLLBACKS);
    assert_eq!(s.deopt_count_since_approval, 0);
}

#[test]
fn site_state_serde_roundtrip() {
    let s = SiteElisionState::new(site("s1"), epoch(1));
    let json = serde_json::to_string(&s).unwrap();
    let back: SiteElisionState = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(
        cfg.max_gc_pause_regression_millionths,
        DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS
    );
    assert_eq!(
        cfg.max_tail_latency_regression_millionths,
        DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS
    );
    assert_eq!(
        cfg.min_support_coverage_millionths,
        DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS
    );
    assert_eq!(cfg.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    assert_eq!(cfg.rollback_cooldown_ns, DEFAULT_ROLLBACK_COOLDOWN_NS);
    assert_eq!(cfg.max_consecutive_rollbacks, MAX_CONSECUTIVE_ROLLBACKS);
    assert!(cfg.require_observability_health);
    assert!(cfg.require_escape_certificate);
}

#[test]
fn gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — basic evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluator_approve_good_input() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-a");
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Approved);
    assert!(result.denial_reasons.is_empty());
}

#[test]
fn evaluator_deny_gc_regression() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-b");
    input.gc_assessment = bad_gc_assessment();
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::GcPauseRegression)
    );
}

#[test]
fn evaluator_deny_latency_regression() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-c");
    input.latency_evidence = bad_latency_evidence();
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::TailLatencyRegression)
    );
}

#[test]
fn evaluator_deny_missing_escape_cert() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-d");
    input.has_escape_certificate = false;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::MissingEscapeCertificate)
    );
}

#[test]
fn evaluator_deny_insufficient_gc_samples() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-e");
    input.gc_assessment.sample_count = 5;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSamples)
    );
}

#[test]
fn evaluator_deny_insufficient_latency_samples() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-e2");
    input.latency_evidence.sample_count = 5;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSamples)
    );
}

#[test]
fn evaluator_deny_bad_support_contract() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-f");
    input.support_contract = Some(bad_support_contract());
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSupportCoverage)
    );
}

#[test]
fn evaluator_deny_missing_support_contract() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-g");
    input.support_contract = None;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSupportCoverage)
    );
}

#[test]
fn evaluator_deny_unhealthy_observability() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-h");
    input.observability = Some(unhealthy_observability());
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::ObservabilityUnhealthy)
    );
}

#[test]
fn evaluator_deny_missing_observability() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-i");
    input.observability = None;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::ObservabilityUnhealthy)
    );
}

#[test]
fn evaluator_multiple_denial_reasons() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-multi");
    input.gc_assessment = bad_gc_assessment();
    input.latency_evidence = bad_latency_evidence();
    input.has_escape_certificate = false;
    input.observability = None;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(result.denial_reasons.len() >= 4);
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — relaxed config
// ---------------------------------------------------------------------------

#[test]
fn evaluator_approve_without_observability_when_not_required() {
    let cfg = GateConfig {
        require_observability_health: false,
        ..GateConfig::default()
    };
    let mut ev = ElisionGateEvaluator::new(cfg);
    let mut input = make_good_input("site-relax-obs");
    input.observability = None;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Approved);
}

#[test]
fn evaluator_approve_without_escape_cert_when_not_required() {
    let cfg = GateConfig {
        require_escape_certificate: false,
        ..GateConfig::default()
    };
    let mut ev = ElisionGateEvaluator::new(cfg);
    let mut input = make_good_input("site-relax-cert");
    input.has_escape_certificate = false;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Approved);
}

#[test]
fn evaluator_approve_without_support_when_threshold_zero() {
    let cfg = GateConfig {
        min_support_coverage_millionths: 0,
        ..GateConfig::default()
    };
    let mut ev = ElisionGateEvaluator::new(cfg);
    let mut input = make_good_input("site-relax-support");
    input.support_contract = None;
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Approved);
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — receipt verification
// ---------------------------------------------------------------------------

#[test]
fn receipt_digest_is_valid() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-receipt");
    let result = ev.evaluate(&input);
    assert!(result.receipt.verify_digest());
}

#[test]
fn receipt_has_schema_version() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-schema");
    let result = ev.evaluate(&input);
    assert_eq!(result.receipt.schema_version, ELISION_GATE_SCHEMA_VERSION);
}

#[test]
fn receipt_tampered_digest_fails_verification() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-tamper");
    let mut result = ev.evaluate(&input);
    result.receipt.receipt_digest = ContentHash::compute(b"tampered");
    assert!(!result.receipt.verify_digest());
}

#[test]
fn receipt_approved_has_assumptions() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-assumptions");
    let result = ev.evaluate(&input);
    assert!(!result.receipt.required_assumptions.is_empty());
    assert!(result.receipt.required_assumptions.contains("no_escape"));
    assert!(result.receipt.required_assumptions.contains("stable_shape"));
}

#[test]
fn receipt_denied_has_empty_assumptions() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-deny-assm");
    input.gc_assessment = bad_gc_assessment();
    let result = ev.evaluate(&input);
    assert!(result.receipt.required_assumptions.is_empty());
}

#[test]
fn receipt_serde_roundtrip() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-receipt-serde");
    let result = ev.evaluate(&input);
    let json = serde_json::to_string(&result.receipt).unwrap();
    let back: ElisionDecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(result.receipt, back);
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — site state tracking
// ---------------------------------------------------------------------------

#[test]
fn evaluator_tracks_site_state() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-track");
    ev.evaluate(&input);
    assert_eq!(ev.tracked_site_count(), 1);
    assert_eq!(ev.approved_site_count(), 1);
}

#[test]
fn evaluator_site_verdict_none_for_unknown() {
    let ev = ElisionGateEvaluator::with_defaults();
    assert!(ev.site_verdict("no-such-site").is_none());
}

#[test]
fn evaluator_site_verdict_after_evaluation() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-verdict");
    ev.evaluate(&input);
    assert_eq!(
        ev.site_verdict("site-verdict"),
        Some(&ElisionVerdict::Approved)
    );
}

#[test]
fn evaluator_independent_sites_independent_verdicts() {
    let mut ev = ElisionGateEvaluator::with_defaults();

    let good_result = ev.evaluate(&make_good_input("good-site"));
    assert_eq!(good_result.verdict, ElisionVerdict::Approved);

    let mut bad_input = make_good_input("bad-site");
    bad_input.gc_assessment = bad_gc_assessment();
    let bad_result = ev.evaluate(&bad_input);
    assert_eq!(bad_result.verdict, ElisionVerdict::Denied);

    assert_eq!(
        ev.site_verdict("good-site"),
        Some(&ElisionVerdict::Approved)
    );
    assert_eq!(ev.site_verdict("bad-site"), Some(&ElisionVerdict::Denied));
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — diagnostics
// ---------------------------------------------------------------------------

#[test]
fn evaluator_diagnostics_on_approval() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-diag-approve");
    let result = ev.evaluate(&input);
    assert!(!result.diagnostics.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::ElisionApproved)
    );
}

#[test]
fn evaluator_diagnostics_on_denial() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-diag-deny");
    input.gc_assessment = bad_gc_assessment();
    let result = ev.evaluate(&input);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.kind == DiagnosticKind::ElisionDenied)
    );
}

#[test]
fn evaluator_diagnostic_sequence_increments() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let r1 = ev.evaluate(&make_good_input("site-seq1"));
    let r2 = ev.evaluate(&make_good_input("site-seq2"));
    let max_seq_1 = r1.diagnostics.iter().map(|d| d.sequence).max().unwrap_or(0);
    let min_seq_2 = r2.diagnostics.iter().map(|d| d.sequence).min().unwrap_or(0);
    assert!(min_seq_2 > max_seq_1);
}

#[test]
fn diagnostic_serde_roundtrip() {
    let diag = ElisionDiagnostic {
        sequence: 42,
        kind: DiagnosticKind::ElisionApproved,
        site_id: Some(site("s")),
        lane_id: lane("l"),
        message: "test message".into(),
        epoch: epoch(1),
        timestamp_ns: 1_000,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: ElisionDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — rollback via deopt
// ---------------------------------------------------------------------------

#[test]
fn process_deopt_triggers_rollback_on_approved_site() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    ev.evaluate(&make_good_input("site-deopt"));

    let witness = make_deopt_witness("site-deopt");
    let rollback = ev.process_deopt(&witness);
    assert!(rollback.is_some());
    assert_eq!(ev.approved_site_count(), 0);
    assert_eq!(ev.total_rollback_count(), 1);
}

#[test]
fn process_deopt_no_rollback_on_denied_site() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-deny-deopt");
    input.gc_assessment = bad_gc_assessment();
    ev.evaluate(&input);

    let witness = make_deopt_witness("site-deny-deopt");
    let rollback = ev.process_deopt(&witness);
    assert!(rollback.is_none());
}

#[test]
fn process_deopt_unknown_site_returns_none() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let witness = make_deopt_witness("no-such-site");
    assert!(ev.process_deopt(&witness).is_none());
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — manual rollback
// ---------------------------------------------------------------------------

#[test]
fn trigger_rollback_on_approved_site() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    ev.evaluate(&make_good_input("site-manual-rb"));

    let record = ev.trigger_rollback(
        &site("site-manual-rb"),
        &lane("lane-1"),
        RollbackTrigger::OperatorInitiated,
        ContentHash::compute(b"evidence"),
        30_000_000,
        epoch(1),
    );
    assert!(record.is_some());
    let record = record.unwrap();
    assert_eq!(record.trigger, RollbackTrigger::OperatorInitiated);
    assert_eq!(record.consecutive_count, 1);
}

#[test]
fn trigger_rollback_on_denied_site_returns_none() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut input = make_good_input("site-denied-rb");
    input.gc_assessment = bad_gc_assessment();
    ev.evaluate(&input);

    let record = ev.trigger_rollback(
        &site("site-denied-rb"),
        &lane("lane-1"),
        RollbackTrigger::GcRegression,
        ContentHash::compute(b"ev"),
        20_000_000,
        epoch(1),
    );
    assert!(record.is_none());
}

#[test]
fn trigger_rollback_unknown_site_returns_none() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let record = ev.trigger_rollback(
        &site("unknown"),
        &lane("l"),
        RollbackTrigger::LatencyRegression,
        ContentHash::compute(b"ev"),
        1_000,
        epoch(1),
    );
    assert!(record.is_none());
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — permanent denial and reset
// ---------------------------------------------------------------------------

#[test]
fn permanent_denial_after_repeated_rollbacks() {
    let mut ev = ElisionGateEvaluator::with_defaults();

    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        let mut input = make_good_input("site-perm");
        input.now_ns = (i as u64 + 1) * (DEFAULT_ROLLBACK_COOLDOWN_NS + 1_000_000);
        ev.evaluate(&input);

        ev.trigger_rollback(
            &site("site-perm"),
            &lane("lane-1"),
            RollbackTrigger::GcRegression,
            ContentHash::compute(format!("evidence-{i}").as_bytes()),
            input.now_ns + 1000,
            epoch(1),
        );
    }

    assert!(ev.is_permanently_denied("site-perm"));
    assert_eq!(ev.permanently_denied_count(), 1);
}

#[test]
fn reset_rollback_counter_clears_permanent_denial() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-reset");
    ev.evaluate(&input);

    // Trigger enough rollbacks for permanent denial.
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        // Re-approve (bypass cooldown by advancing time enough).
        let mut re_input = make_good_input("site-reset");
        re_input.now_ns = (i as u64 + 2) * (DEFAULT_ROLLBACK_COOLDOWN_NS + 1_000_000);
        ev.evaluate(&re_input);

        ev.trigger_rollback(
            &site("site-reset"),
            &lane("lane-1"),
            RollbackTrigger::LatencyRegression,
            ContentHash::compute(format!("ev-{i}").as_bytes()),
            re_input.now_ns + 1000,
            epoch(1),
        );
    }
    assert!(ev.is_permanently_denied("site-reset"));

    assert!(ev.reset_rollback_counter("site-reset"));
    let state = ev.site_states().get("site-reset").unwrap();
    assert_eq!(state.consecutive_rollbacks, 0);
    assert!(!state.permanently_denied);
    assert_eq!(state.verdict, ElisionVerdict::Denied);
}

#[test]
fn reset_nonexistent_site_returns_false() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    assert!(!ev.reset_rollback_counter("no-such-site"));
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — site rollback history
// ---------------------------------------------------------------------------

#[test]
fn site_rollbacks_returns_correct_records() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    ev.evaluate(&make_good_input("site-rb-hist"));
    ev.trigger_rollback(
        &site("site-rb-hist"),
        &lane("lane-1"),
        RollbackTrigger::SupportViolation,
        ContentHash::compute(b"ev"),
        20_000_000,
        epoch(1),
    );
    let rollbacks = ev.site_rollbacks("site-rb-hist");
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].trigger, RollbackTrigger::SupportViolation);
}

#[test]
fn site_rollbacks_empty_for_unknown_site() {
    let ev = ElisionGateEvaluator::with_defaults();
    assert!(ev.site_rollbacks("unknown").is_empty());
}

// ---------------------------------------------------------------------------
// ElisionGateEvaluator — batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn batch_empty() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let results = ev.evaluate_batch(&[]);
    assert!(results.is_empty());
}

#[test]
fn batch_all_approved() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let inputs = vec![make_good_input("batch-a"), make_good_input("batch-b")];
    let results = ev.evaluate_batch(&inputs);
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .all(|r| r.verdict == ElisionVerdict::Approved)
    );
    assert_eq!(ev.tracked_site_count(), 2);
}

#[test]
fn batch_mixed_results() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let mut bad = make_good_input("batch-bad");
    bad.gc_assessment = bad_gc_assessment();
    let inputs = vec![make_good_input("batch-good"), bad];
    let results = ev.evaluate_batch(&inputs);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].verdict, ElisionVerdict::Approved);
    assert_eq!(results[1].verdict, ElisionVerdict::Denied);
}

#[test]
fn batch_preserves_order() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let inputs = vec![
        make_good_input("batch-first"),
        make_good_input("batch-second"),
        make_good_input("batch-third"),
    ];
    let results = ev.evaluate_batch(&inputs);
    assert_eq!(results[0].receipt.site_id.as_str(), "batch-first");
    assert_eq!(results[1].receipt.site_id.as_str(), "batch-second");
    assert_eq!(results[2].receipt.site_id.as_str(), "batch-third");
}

// ---------------------------------------------------------------------------
// ElisionSavingsReport
// ---------------------------------------------------------------------------

#[test]
fn savings_report_from_evaluator() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    ev.evaluate(&make_good_input("sr-a"));
    ev.evaluate(&make_good_input("sr-b"));
    let mut bad = make_good_input("sr-c");
    bad.gc_assessment = bad_gc_assessment();
    ev.evaluate(&bad);

    let report = ev.generate_savings_report(
        &lane("lane-1"),
        1_000_000,
        500,
        10,
        50_000,
        20_000,
        epoch(1),
        50_000_000,
    );
    assert_eq!(report.total_sites_evaluated, 3);
    assert_eq!(report.sites_approved, 2);
    assert_eq!(report.sites_denied, 1);
    assert_eq!(report.sites_rolled_back, 0);
}

#[test]
fn savings_report_approval_rate() {
    let mut report = ElisionSavingsReport {
        lane_id: lane("l"),
        total_sites_evaluated: 10,
        sites_approved: 7,
        sites_denied: 2,
        sites_rolled_back: 1,
        estimated_bytes_saved_per_sec: 0,
        estimated_allocs_avoided_per_sec: 0,
        estimated_gc_cycles_saved_per_min: 0,
        net_p50_improvement_ns: 0,
        net_p99_improvement_ns: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
        report_digest: ContentHash::compute(b"placeholder"),
    };
    report.report_digest = report.compute_digest();
    assert_eq!(report.approval_rate_millionths(), 700_000);
}

#[test]
fn savings_report_effective_rate() {
    let report = ElisionSavingsReport {
        lane_id: lane("l"),
        total_sites_evaluated: 10,
        sites_approved: 7,
        sites_denied: 2,
        sites_rolled_back: 2,
        estimated_bytes_saved_per_sec: 0,
        estimated_allocs_avoided_per_sec: 0,
        estimated_gc_cycles_saved_per_min: 0,
        net_p50_improvement_ns: 0,
        net_p99_improvement_ns: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
        report_digest: ContentHash::compute(b"x"),
    };
    // effective = (7 - 2) / 10 = 0.5 => 500_000
    assert_eq!(report.effective_elision_rate_millionths(), 500_000);
}

#[test]
fn savings_report_zero_sites() {
    let report = ElisionSavingsReport {
        lane_id: lane("l"),
        total_sites_evaluated: 0,
        sites_approved: 0,
        sites_denied: 0,
        sites_rolled_back: 0,
        estimated_bytes_saved_per_sec: 0,
        estimated_allocs_avoided_per_sec: 0,
        estimated_gc_cycles_saved_per_min: 0,
        net_p50_improvement_ns: 0,
        net_p99_improvement_ns: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
        report_digest: ContentHash::compute(b"x"),
    };
    assert_eq!(report.approval_rate_millionths(), 0);
    assert_eq!(report.effective_elision_rate_millionths(), 0);
}

#[test]
fn savings_report_digest_deterministic() {
    let make = || {
        let mut r = ElisionSavingsReport {
            lane_id: lane("l"),
            total_sites_evaluated: 5,
            sites_approved: 3,
            sites_denied: 1,
            sites_rolled_back: 1,
            estimated_bytes_saved_per_sec: 1000,
            estimated_allocs_avoided_per_sec: 50,
            estimated_gc_cycles_saved_per_min: 2,
            net_p50_improvement_ns: 100,
            net_p99_improvement_ns: 50,
            epoch: epoch(1),
            timestamp_ns: 1_000,
            report_digest: ContentHash::compute(b"placeholder"),
        };
        r.report_digest = r.compute_digest();
        r
    };
    assert_eq!(make().report_digest, make().report_digest);
}

#[test]
fn savings_report_serde_roundtrip() {
    let mut report = ElisionSavingsReport {
        lane_id: lane("l"),
        total_sites_evaluated: 5,
        sites_approved: 3,
        sites_denied: 1,
        sites_rolled_back: 1,
        estimated_bytes_saved_per_sec: 1000,
        estimated_allocs_avoided_per_sec: 50,
        estimated_gc_cycles_saved_per_min: 2,
        net_p50_improvement_ns: 100,
        net_p99_improvement_ns: -50,
        epoch: epoch(1),
        timestamp_ns: 1_000,
        report_digest: ContentHash::compute(b"placeholder"),
    };
    report.report_digest = report.compute_digest();
    let json = serde_json::to_string(&report).unwrap();
    let back: ElisionSavingsReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// ElisionEvidenceBundle
// ---------------------------------------------------------------------------

#[test]
fn evidence_bundle_empty() {
    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        epoch(1),
        1_000_000,
    );
    assert_eq!(bundle.schema_version, ELISION_GATE_SCHEMA_VERSION);
    assert_eq!(bundle.approval_count(), 0);
    assert_eq!(bundle.denial_count(), 0);
}

#[test]
fn evidence_bundle_counts() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let r1 = ev.evaluate(&make_good_input("eb-a"));
    let r2 = ev.evaluate(&make_good_input("eb-b"));
    let mut bad = make_good_input("eb-c");
    bad.gc_assessment = bad_gc_assessment();
    let r3 = ev.evaluate(&bad);

    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        vec![r1.receipt, r2.receipt, r3.receipt],
        Vec::new(),
        Vec::new(),
        None,
        None,
        epoch(1),
        1_000_000,
    );
    assert_eq!(bundle.approval_count(), 2);
    assert_eq!(bundle.denial_count(), 1);
}

#[test]
fn evidence_bundle_digest_deterministic() {
    let make = || {
        ElisionEvidenceBundle::create(
            lane("l"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            None,
            epoch(1),
            1_000_000,
        )
    };
    assert_eq!(make().bundle_digest, make().bundle_digest);
}

#[test]
fn evidence_bundle_different_epoch_different_digest() {
    let b1 = ElisionEvidenceBundle::create(
        lane("l"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        epoch(1),
        1_000_000,
    );
    let b2 = ElisionEvidenceBundle::create(
        lane("l"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        epoch(2),
        1_000_000,
    );
    assert_ne!(b1.bundle_digest, b2.bundle_digest);
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        None,
        epoch(1),
        1_000_000,
    );
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ElisionEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ---------------------------------------------------------------------------
// ElisionEvalInput / ElisionEvalResult serde
// ---------------------------------------------------------------------------

#[test]
fn eval_input_serde_roundtrip() {
    let input = make_good_input("site-input-serde");
    let json = serde_json::to_string(&input).unwrap();
    let back: ElisionEvalInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn eval_result_serde_roundtrip() {
    let mut ev = ElisionGateEvaluator::with_defaults();
    let input = make_good_input("site-result-serde");
    let result = ev.evaluate(&input);
    let json = serde_json::to_string(&result).unwrap();
    let back: ElisionEvalResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_approve_deopt_rollback_reapprove() {
    let mut ev = ElisionGateEvaluator::with_defaults();

    // Step 1: approve the site.
    let input = make_good_input("site-lifecycle");
    let result = ev.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Approved);
    assert_eq!(ev.approved_site_count(), 1);

    // Step 2: deopt fires, triggering rollback.
    let witness = make_deopt_witness("site-lifecycle");
    let rollback = ev.process_deopt(&witness).unwrap();
    assert_eq!(rollback.trigger, RollbackTrigger::DeoptEvent);
    assert_eq!(ev.approved_site_count(), 0);
    assert_eq!(
        ev.site_verdict("site-lifecycle"),
        Some(&ElisionVerdict::RolledBack)
    );

    // Step 3: after cooldown, re-evaluate and re-approve.
    let mut re_input = make_good_input("site-lifecycle");
    re_input.now_ns = witness.timestamp_ns + DEFAULT_ROLLBACK_COOLDOWN_NS + 1;
    let re_result = ev.evaluate(&re_input);
    assert_eq!(re_result.verdict, ElisionVerdict::Approved);
    assert_eq!(ev.approved_site_count(), 1);

    // Step 4: generate savings report.
    let report = ev.generate_savings_report(
        &lane("lane-1"),
        500_000,
        100,
        5,
        25_000,
        10_000,
        epoch(1),
        100_000_000,
    );
    assert_eq!(report.total_sites_evaluated, 1);
    assert_eq!(report.sites_approved, 1);
    assert_eq!(report.sites_rolled_back, 0);

    // Step 5: build evidence bundle.
    let bundle = ElisionEvidenceBundle::create(
        lane("lane-1"),
        vec![result.receipt, re_result.receipt],
        vec![rollback],
        vec![witness],
        Some(report),
        Some(healthy_observability()),
        epoch(1),
        100_000_000,
    );
    assert_eq!(bundle.approval_count(), 2);
    assert_eq!(bundle.denial_count(), 0);
    assert_eq!(bundle.rollback_records.len(), 1);
    assert_eq!(bundle.deopt_witnesses.len(), 1);
    assert!(bundle.savings_report.is_some());
}
