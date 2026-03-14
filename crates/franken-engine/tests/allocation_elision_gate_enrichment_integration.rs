//! Enrichment integration tests for `allocation_elision_gate` module.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips,
//! Display coverage, Debug nonempty, Default coverage, evaluator lifecycle,
//! GC/latency regression detection, rollback, deopt witness processing,
//! evidence bundles, savings reports, JSON field-name stability, determinism.

use std::collections::BTreeSet;

use frankenengine_engine::allocation_elision_gate::{
    AllocationSiteId, AssumptionKind, DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS,
    DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS, DEFAULT_MIN_SAMPLE_COUNT,
    DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS, DEFAULT_ROLLBACK_COOLDOWN_NS, DenialReason,
    DeoptWitness, DiagnosticKind, ELISION_GATE_BEAD_ID, ELISION_GATE_COMPONENT,
    ELISION_GATE_SCHEMA_VERSION, ElisionEvalInput, ElisionEvidenceBundle, ElisionGateEvaluator,
    ElisionSavingsReport, ElisionVerdict, GateConfig, GcImpactAssessment, LaneId,
    MAX_CONSECUTIVE_ROLLBACKS, ObservabilityHealth, RollbackRecord, RollbackTrigger,
    SiteElisionState, SupportSurfaceContract, TailLatencyEvidence,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn site(id: &str) -> AllocationSiteId {
    AllocationSiteId::new(id)
}

fn lane(id: &str) -> LaneId {
    LaneId::new(id)
}

fn good_gc() -> GcImpactAssessment {
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

fn bad_gc() -> GcImpactAssessment {
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

fn good_latency() -> TailLatencyEvidence {
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

fn bad_latency() -> TailLatencyEvidence {
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

fn good_support() -> SupportSurfaceContract {
    SupportSurfaceContract {
        contract_id: "contract-1".to_string(),
        covered_sites: {
            let mut s = BTreeSet::new();
            s.insert("site-a".to_string());
            s
        },
        min_coverage_millionths: 950_000,
        actual_coverage_millionths: 980_000,
        fallback_paths_verified: true,
        validated_epoch: epoch(1),
        notes: "OK".to_string(),
    }
}

fn healthy_obs() -> ObservabilityHealth {
    ObservabilityHealth {
        gc_telemetry_active: true,
        latency_probes_active: true,
        deopt_counters_active: true,
        support_checks_scheduled: true,
        events_since_last_check: 42,
        epoch: epoch(1),
        timestamp_ns: 1_000,
    }
}

fn approved_input() -> ElisionEvalInput {
    ElisionEvalInput {
        site_id: site("site-a"),
        lane_id: lane("lane-1"),
        gc_assessment: good_gc(),
        latency_evidence: good_latency(),
        support_contract: Some(good_support()),
        observability: Some(healthy_obs()),
        has_escape_certificate: true,
        epoch: epoch(1),
        now_ns: 1_000_000,
    }
}

// =========================================================================
// Copy semantics
// =========================================================================

#[test]
fn enrichment_elision_verdict_copy() {
    let a = ElisionVerdict::Approved;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_assumption_kind_copy() {
    let a = AssumptionKind::NoEscape;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_diagnostic_kind_copy() {
    let a = DiagnosticKind::ElisionApproved;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_trigger_copy() {
    let a = RollbackTrigger::GcRegression;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_denial_reason_copy() {
    let a = DenialReason::GcPauseRegression;
    let b = a.clone();
    assert_eq!(a, b);
}

// =========================================================================
// Clone independence
// =========================================================================

#[test]
fn enrichment_gc_assessment_clone_independence() {
    let original = good_gc();
    let mut cloned = original.clone();
    cloned.sample_count = 999;
    assert_eq!(original.sample_count, 100);
    assert_ne!(original.sample_count, cloned.sample_count);
}

#[test]
fn enrichment_tail_latency_clone_independence() {
    let original = good_latency();
    let mut cloned = original.clone();
    cloned.workload_id = "different".to_string();
    assert_ne!(original.workload_id, cloned.workload_id);
}

#[test]
fn enrichment_site_state_clone_independence() {
    let original = SiteElisionState::new(site("s"), epoch(1));
    let mut cloned = original.clone();
    cloned.permanently_denied = true;
    assert!(!original.permanently_denied);
    assert!(cloned.permanently_denied);
}

#[test]
fn enrichment_gate_config_clone_independence() {
    let original = GateConfig::default();
    let cloned = original.clone();
    assert_eq!(cloned.min_sample_count, original.min_sample_count);
    assert_eq!(original.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
}

// =========================================================================
// BTreeSet ordering
// =========================================================================

#[test]
fn enrichment_elision_verdict_btreeset_ordering() {
    let set: BTreeSet<ElisionVerdict> = [
        ElisionVerdict::RolledBack,
        ElisionVerdict::Approved,
        ElisionVerdict::Denied,
        ElisionVerdict::Conditional,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(items[0], ElisionVerdict::Approved);
    assert_eq!(items[1], ElisionVerdict::Conditional);
    assert_eq!(items[2], ElisionVerdict::Denied);
    assert_eq!(items[3], ElisionVerdict::RolledBack);
}

#[test]
fn enrichment_denial_reason_btreeset_ordering() {
    let set: BTreeSet<DenialReason> = [
        DenialReason::EpochMismatch,
        DenialReason::GcPauseRegression,
        DenialReason::InsufficientSamples,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_rollback_trigger_btreeset_ordering() {
    let set: BTreeSet<RollbackTrigger> = [
        RollbackTrigger::OperatorInitiated,
        RollbackTrigger::GcRegression,
        RollbackTrigger::DeoptEvent,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_assumption_kind_btreeset_dedup() {
    let set: BTreeSet<AssumptionKind> = [
        AssumptionKind::NoEscape,
        AssumptionKind::NoEscape,
        AssumptionKind::StableShape,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 2);
}

// =========================================================================
// Serde roundtrips
// =========================================================================

#[test]
fn enrichment_elision_verdict_serde_all() {
    for v in [
        ElisionVerdict::Approved,
        ElisionVerdict::Conditional,
        ElisionVerdict::Denied,
        ElisionVerdict::RolledBack,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ElisionVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_denial_reason_serde_all() {
    for dr in [
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
    ] {
        let json = serde_json::to_string(&dr).unwrap();
        let back: DenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(dr, back);
    }
}

#[test]
fn enrichment_rollback_trigger_serde_all() {
    for rt in [
        RollbackTrigger::GcRegression,
        RollbackTrigger::LatencyRegression,
        RollbackTrigger::DeoptEvent,
        RollbackTrigger::SupportViolation,
        RollbackTrigger::ObservabilityAnomaly,
        RollbackTrigger::OperatorInitiated,
    ] {
        let json = serde_json::to_string(&rt).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, back);
    }
}

#[test]
fn enrichment_assumption_kind_serde_all() {
    for ak in AssumptionKind::ALL {
        let json = serde_json::to_string(ak).unwrap();
        let back: AssumptionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*ak, back);
    }
}

#[test]
fn enrichment_diagnostic_kind_serde_all() {
    for dk in [
        DiagnosticKind::ElisionApproved,
        DiagnosticKind::ElisionDenied,
        DiagnosticKind::ElisionRolledBack,
        DiagnosticKind::GcAssessmentComplete,
        DiagnosticKind::LatencyEvidenceCollected,
        DiagnosticKind::DeoptWitnessRecorded,
        DiagnosticKind::SupportContractValidated,
        DiagnosticKind::HealthChecked,
        DiagnosticKind::SavingsReported,
    ] {
        let json = serde_json::to_string(&dk).unwrap();
        let back: DiagnosticKind = serde_json::from_str(&json).unwrap();
        assert_eq!(dk, back);
    }
}

#[test]
fn enrichment_gc_assessment_serde_roundtrip() {
    let gc = good_gc();
    let json = serde_json::to_string(&gc).unwrap();
    let back: GcImpactAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(gc, back);
}

#[test]
fn enrichment_tail_latency_serde_roundtrip() {
    let lat = good_latency();
    let json = serde_json::to_string(&lat).unwrap();
    let back: TailLatencyEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(lat, back);
}

#[test]
fn enrichment_support_contract_serde_roundtrip() {
    let sc = good_support();
    let json = serde_json::to_string(&sc).unwrap();
    let back: SupportSurfaceContract = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, back);
}

#[test]
fn enrichment_observability_health_serde_roundtrip() {
    let oh = healthy_obs();
    let json = serde_json::to_string(&oh).unwrap();
    let back: ObservabilityHealth = serde_json::from_str(&json).unwrap();
    assert_eq!(oh, back);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_site_state_serde_roundtrip() {
    let state = SiteElisionState::new(site("s"), epoch(1));
    let json = serde_json::to_string(&state).unwrap();
    let back: SiteElisionState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn enrichment_allocation_site_id_serde_roundtrip() {
    let sid = site("my-site");
    let json = serde_json::to_string(&sid).unwrap();
    let back: AllocationSiteId = serde_json::from_str(&json).unwrap();
    assert_eq!(sid, back);
}

#[test]
fn enrichment_lane_id_serde_roundtrip() {
    let lid = lane("my-lane");
    let json = serde_json::to_string(&lid).unwrap();
    let back: LaneId = serde_json::from_str(&json).unwrap();
    assert_eq!(lid, back);
}

// =========================================================================
// Display coverage
// =========================================================================

#[test]
fn enrichment_elision_verdict_display_all() {
    assert_eq!(ElisionVerdict::Approved.to_string(), "approved");
    assert_eq!(ElisionVerdict::Conditional.to_string(), "conditional");
    assert_eq!(ElisionVerdict::Denied.to_string(), "denied");
    assert_eq!(ElisionVerdict::RolledBack.to_string(), "rolled_back");
}

#[test]
fn enrichment_denial_reason_display_all() {
    assert_eq!(
        DenialReason::GcPauseRegression.to_string(),
        "gc_pause_regression"
    );
    assert_eq!(
        DenialReason::TailLatencyRegression.to_string(),
        "tail_latency_regression"
    );
    assert_eq!(
        DenialReason::InsufficientSupportCoverage.to_string(),
        "insufficient_support_coverage"
    );
    assert_eq!(
        DenialReason::DeoptWitnessTriggered.to_string(),
        "deopt_witness_triggered"
    );
    assert_eq!(
        DenialReason::RollbackLimitExceeded.to_string(),
        "rollback_limit_exceeded"
    );
    assert_eq!(
        DenialReason::InsufficientSamples.to_string(),
        "insufficient_samples"
    );
    assert_eq!(
        DenialReason::MissingEscapeCertificate.to_string(),
        "missing_escape_certificate"
    );
    assert_eq!(
        DenialReason::ObservabilityUnhealthy.to_string(),
        "observability_unhealthy"
    );
    assert_eq!(DenialReason::OperatorDenied.to_string(), "operator_denied");
    assert_eq!(DenialReason::EpochMismatch.to_string(), "epoch_mismatch");
}

#[test]
fn enrichment_rollback_trigger_display_all() {
    assert_eq!(RollbackTrigger::GcRegression.to_string(), "gc_regression");
    assert_eq!(
        RollbackTrigger::LatencyRegression.to_string(),
        "latency_regression"
    );
    assert_eq!(RollbackTrigger::DeoptEvent.to_string(), "deopt_event");
    assert_eq!(
        RollbackTrigger::SupportViolation.to_string(),
        "support_violation"
    );
    assert_eq!(
        RollbackTrigger::ObservabilityAnomaly.to_string(),
        "observability_anomaly"
    );
    assert_eq!(
        RollbackTrigger::OperatorInitiated.to_string(),
        "operator_initiated"
    );
}

#[test]
fn enrichment_assumption_kind_display_all() {
    assert_eq!(AssumptionKind::NoEscape.to_string(), "no_escape");
    assert_eq!(AssumptionKind::ArgEscapeOnly.to_string(), "arg_escape_only");
    assert_eq!(AssumptionKind::NoAlias.to_string(), "no_alias");
    assert_eq!(AssumptionKind::StableShape.to_string(), "stable_shape");
    assert_eq!(
        AssumptionKind::NoDynamicAccess.to_string(),
        "no_dynamic_access"
    );
    assert_eq!(
        AssumptionKind::StablePrototype.to_string(),
        "stable_prototype"
    );
    assert_eq!(
        AssumptionKind::BoundedLiveness.to_string(),
        "bounded_liveness"
    );
    assert_eq!(AssumptionKind::NoModuleLeak.to_string(), "no_module_leak");
}

#[test]
fn enrichment_diagnostic_kind_display_all() {
    assert_eq!(
        DiagnosticKind::ElisionApproved.to_string(),
        "elision_approved"
    );
    assert_eq!(DiagnosticKind::ElisionDenied.to_string(), "elision_denied");
    assert_eq!(
        DiagnosticKind::ElisionRolledBack.to_string(),
        "elision_rolled_back"
    );
    assert_eq!(
        DiagnosticKind::GcAssessmentComplete.to_string(),
        "gc_assessment_complete"
    );
    assert_eq!(
        DiagnosticKind::LatencyEvidenceCollected.to_string(),
        "latency_evidence_collected"
    );
    assert_eq!(
        DiagnosticKind::DeoptWitnessRecorded.to_string(),
        "deopt_witness_recorded"
    );
    assert_eq!(
        DiagnosticKind::SupportContractValidated.to_string(),
        "support_contract_validated"
    );
    assert_eq!(DiagnosticKind::HealthChecked.to_string(), "health_checked");
    assert_eq!(
        DiagnosticKind::SavingsReported.to_string(),
        "savings_reported"
    );
}

#[test]
fn enrichment_allocation_site_id_display() {
    assert_eq!(site("alloc-42").to_string(), "alloc-42");
}

#[test]
fn enrichment_lane_id_display() {
    assert_eq!(lane("lane-x").to_string(), "lane-x");
}

// =========================================================================
// Debug nonempty
// =========================================================================

#[test]
fn enrichment_gc_assessment_debug() {
    let d = format!("{:?}", good_gc());
    assert!(!d.is_empty());
}

#[test]
fn enrichment_tail_latency_debug() {
    let d = format!("{:?}", good_latency());
    assert!(!d.is_empty());
}

#[test]
fn enrichment_site_state_debug() {
    let d = format!("{:?}", SiteElisionState::new(site("s"), epoch(1)));
    assert!(d.contains("SiteElisionState"));
}

#[test]
fn enrichment_evaluator_debug() {
    let d = format!("{:?}", ElisionGateEvaluator::with_defaults());
    assert!(d.contains("ElisionGateEvaluator"));
}

#[test]
fn enrichment_gate_config_debug() {
    let d = format!("{:?}", GateConfig::default());
    assert!(d.contains("GateConfig"));
}

// =========================================================================
// Default coverage
// =========================================================================

#[test]
fn enrichment_gate_config_default_values() {
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

// =========================================================================
// Constants
// =========================================================================

#[test]
fn enrichment_constants() {
    const {
        assert!(!ELISION_GATE_SCHEMA_VERSION.is_empty());
        assert!(!ELISION_GATE_BEAD_ID.is_empty());
        assert!(!ELISION_GATE_COMPONENT.is_empty());
        assert!(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS > 0);
        assert!(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS > 0);
        assert!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS > 0);
        assert!(DEFAULT_MIN_SAMPLE_COUNT > 0);
        assert!(DEFAULT_ROLLBACK_COOLDOWN_NS > 0);
        assert!(MAX_CONSECUTIVE_ROLLBACKS > 0);
    }
}

// =========================================================================
// as_str coverage
// =========================================================================

#[test]
fn enrichment_elision_verdict_as_str() {
    assert_eq!(ElisionVerdict::Approved.as_str(), "approved");
    assert_eq!(ElisionVerdict::Conditional.as_str(), "conditional");
    assert_eq!(ElisionVerdict::Denied.as_str(), "denied");
    assert_eq!(ElisionVerdict::RolledBack.as_str(), "rolled_back");
}

#[test]
fn enrichment_is_elision_allowed() {
    assert!(ElisionVerdict::Approved.is_elision_allowed());
    assert!(ElisionVerdict::Conditional.is_elision_allowed());
    assert!(!ElisionVerdict::Denied.is_elision_allowed());
    assert!(!ElisionVerdict::RolledBack.is_elision_allowed());
}

#[test]
fn enrichment_allocation_site_id_as_str() {
    let s = site("alloc-42");
    assert_eq!(s.as_str(), "alloc-42");
}

#[test]
fn enrichment_lane_id_as_str() {
    let l = lane("lane-x");
    assert_eq!(l.as_str(), "lane-x");
}

#[test]
fn enrichment_assumption_kind_all_has_eight() {
    assert_eq!(AssumptionKind::ALL.len(), 8);
}

#[test]
fn enrichment_assumption_kind_as_str_unique() {
    let strs: BTreeSet<&str> = AssumptionKind::ALL.iter().map(|a| a.as_str()).collect();
    assert_eq!(strs.len(), 8);
}

// =========================================================================
// GcImpactAssessment
// =========================================================================

#[test]
fn enrichment_gc_compute_pause_regression() {
    let gc = good_gc();
    let ratio = gc.compute_pause_regression();
    // 4_800_000 * 1_000_000 / 5_000_000 = 960_000
    assert_eq!(ratio, 960_000);
}

#[test]
fn enrichment_gc_not_regressed() {
    let gc = good_gc();
    assert!(!gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
}

#[test]
fn enrichment_gc_regressed() {
    let gc = bad_gc();
    assert!(gc.is_regressed(DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS));
}

#[test]
fn enrichment_gc_bytes_saved() {
    let gc = good_gc();
    assert_eq!(gc.bytes_saved_per_cycle(), 64_000 - 48_000);
}

#[test]
fn enrichment_gc_zero_baseline_regression() {
    let mut gc = good_gc();
    gc.baseline_pause_p99_ns = 0;
    assert_eq!(gc.compute_pause_regression(), 0);
}

#[test]
fn enrichment_gc_digest_deterministic() {
    let d1 = good_gc().digest();
    let d2 = good_gc().digest();
    assert_eq!(d1, d2);
}

// =========================================================================
// TailLatencyEvidence
// =========================================================================

#[test]
fn enrichment_latency_p99_regression() {
    let lat = good_latency();
    let ratio = lat.p99_regression_millionths();
    assert_eq!(ratio, 950_000);
}

#[test]
fn enrichment_latency_p999_regression() {
    let lat = good_latency();
    let ratio = lat.p999_regression_millionths();
    assert_eq!(ratio, 960_000);
}

#[test]
fn enrichment_latency_not_regressed() {
    let lat = good_latency();
    assert!(!lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
}

#[test]
fn enrichment_latency_regressed() {
    let lat = bad_latency();
    assert!(lat.is_regressed(DEFAULT_MAX_TAIL_LATENCY_REGRESSION_MILLIONTHS));
}

#[test]
fn enrichment_latency_p50_improvement() {
    let lat = good_latency();
    let improvement = lat.p50_improvement_ns();
    assert_eq!(improvement, 100_000); // 1_000_000 - 900_000
}

#[test]
fn enrichment_latency_zero_baseline() {
    let mut lat = good_latency();
    lat.baseline_p99_ns = 0;
    assert_eq!(lat.p99_regression_millionths(), 0);
}

#[test]
fn enrichment_latency_digest_deterministic() {
    let d1 = good_latency().digest();
    let d2 = good_latency().digest();
    assert_eq!(d1, d2);
}

// =========================================================================
// SupportSurfaceContract
// =========================================================================

#[test]
fn enrichment_support_meets_coverage() {
    let sc = good_support();
    assert!(sc.meets_coverage());
}

#[test]
fn enrichment_support_not_meets_coverage() {
    let mut sc = good_support();
    sc.actual_coverage_millionths = 900_000;
    assert!(!sc.meets_coverage());
}

#[test]
fn enrichment_support_is_satisfied() {
    let sc = good_support();
    assert!(sc.is_satisfied());
}

#[test]
fn enrichment_support_not_satisfied_no_fallback() {
    let mut sc = good_support();
    sc.fallback_paths_verified = false;
    assert!(!sc.is_satisfied());
}

#[test]
fn enrichment_support_coverage_deficit() {
    let mut sc = good_support();
    sc.actual_coverage_millionths = 900_000;
    assert_eq!(sc.coverage_deficit_millionths(), 50_000);
}

#[test]
fn enrichment_support_zero_deficit_when_met() {
    let sc = good_support();
    assert_eq!(sc.coverage_deficit_millionths(), 0);
}

#[test]
fn enrichment_support_digest_deterministic() {
    let d1 = good_support().digest();
    let d2 = good_support().digest();
    assert_eq!(d1, d2);
}

// =========================================================================
// ObservabilityHealth
// =========================================================================

#[test]
fn enrichment_observability_healthy() {
    let oh = healthy_obs();
    assert!(oh.is_healthy());
    assert_eq!(oh.unhealthy_count(), 0);
    assert!(oh.unhealthy_subsystems().is_empty());
}

#[test]
fn enrichment_observability_one_unhealthy() {
    let mut oh = healthy_obs();
    oh.gc_telemetry_active = false;
    assert!(!oh.is_healthy());
    assert_eq!(oh.unhealthy_count(), 1);
    assert_eq!(oh.unhealthy_subsystems(), vec!["gc_telemetry"]);
}

#[test]
fn enrichment_observability_all_unhealthy() {
    let oh = ObservabilityHealth {
        gc_telemetry_active: false,
        latency_probes_active: false,
        deopt_counters_active: false,
        support_checks_scheduled: false,
        events_since_last_check: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
    };
    assert!(!oh.is_healthy());
    assert_eq!(oh.unhealthy_count(), 4);
    assert_eq!(oh.unhealthy_subsystems().len(), 4);
}

// =========================================================================
// SiteElisionState
// =========================================================================

#[test]
fn enrichment_site_state_new_defaults() {
    let state = SiteElisionState::new(site("s"), epoch(1));
    assert_eq!(state.verdict, ElisionVerdict::Denied);
    assert_eq!(state.consecutive_rollbacks, 0);
    assert!(!state.permanently_denied);
    assert!(state.active_assumptions.is_empty());
}

#[test]
fn enrichment_site_state_can_reevaluate_never_rolled_back() {
    let state = SiteElisionState::new(site("s"), epoch(1));
    assert!(state.can_reevaluate(0, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn enrichment_site_state_can_reevaluate_cooldown_expired() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    state.last_rollback_ns = 1_000;
    assert!(state.can_reevaluate(
        DEFAULT_ROLLBACK_COOLDOWN_NS + 1_001,
        DEFAULT_ROLLBACK_COOLDOWN_NS
    ));
}

#[test]
fn enrichment_site_state_cannot_reevaluate_cooldown_active() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    state.last_rollback_ns = 1_000;
    assert!(!state.can_reevaluate(1_001, DEFAULT_ROLLBACK_COOLDOWN_NS));
}

#[test]
fn enrichment_site_state_permanently_denied_blocks() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    state.permanently_denied = true;
    assert!(!state.can_reevaluate(u64::MAX, 0));
}

#[test]
fn enrichment_site_state_record_rollback_increments() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    state.verdict = ElisionVerdict::Approved;
    state.record_rollback(100, MAX_CONSECUTIVE_ROLLBACKS);
    assert_eq!(state.verdict, ElisionVerdict::RolledBack);
    assert_eq!(state.consecutive_rollbacks, 1);
    assert!(!state.permanently_denied);
}

#[test]
fn enrichment_site_state_record_rollback_permanent_denial() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    state.verdict = ElisionVerdict::Approved;
    for i in 0..MAX_CONSECUTIVE_ROLLBACKS {
        state.record_rollback(i as u64 * 100, MAX_CONSECUTIVE_ROLLBACKS);
        state.verdict = ElisionVerdict::Approved; // re-approve for next rollback
    }
    assert!(state.permanently_denied);
}

#[test]
fn enrichment_site_state_record_approval() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    let assumptions = BTreeSet::from(["no_escape".to_string()]);
    state.record_approval(ElisionVerdict::Approved, assumptions.clone(), 500, epoch(2));
    assert_eq!(state.verdict, ElisionVerdict::Approved);
    assert_eq!(state.active_assumptions, assumptions);
    assert_eq!(state.last_evaluated_ns, 500);
    assert_eq!(state.verdict_epoch, epoch(2));
}

#[test]
fn enrichment_site_state_record_deopt() {
    let mut state = SiteElisionState::new(site("s"), epoch(1));
    assert_eq!(state.deopt_count_since_approval, 0);
    state.record_deopt();
    assert_eq!(state.deopt_count_since_approval, 1);
    state.record_deopt();
    assert_eq!(state.deopt_count_since_approval, 2);
}

// =========================================================================
// RollbackRecord
// =========================================================================

#[test]
fn enrichment_rollback_record_exceeds_limit() {
    let record = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::GcRegression,
        timestamp_ns: 100,
        epoch: epoch(1),
        consecutive_count: MAX_CONSECUTIVE_ROLLBACKS,
        evidence_digest: ContentHash::compute(b"evidence"),
    };
    assert!(record.exceeds_limit());
}

#[test]
fn enrichment_rollback_record_within_limit() {
    let record = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::GcRegression,
        timestamp_ns: 100,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"evidence"),
    };
    assert!(!record.exceeds_limit());
}

#[test]
fn enrichment_rollback_record_digest_deterministic() {
    let record = RollbackRecord {
        site_id: site("s"),
        lane_id: lane("l"),
        trigger: RollbackTrigger::DeoptEvent,
        timestamp_ns: 42,
        epoch: epoch(1),
        consecutive_count: 1,
        evidence_digest: ContentHash::compute(b"ev"),
    };
    let d1 = record.digest();
    let d2 = record.digest();
    assert_eq!(d1, d2);
}

// =========================================================================
// Evaluator lifecycle
// =========================================================================

#[test]
fn enrichment_evaluator_new_empty() {
    let eval = ElisionGateEvaluator::with_defaults();
    assert_eq!(eval.tracked_site_count(), 0);
    assert_eq!(eval.approved_site_count(), 0);
    assert_eq!(eval.permanently_denied_count(), 0);
    assert_eq!(eval.total_rollback_count(), 0);
    assert!(eval.rollback_history().is_empty());
}

#[test]
fn enrichment_evaluator_approve_good_input() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let result = eval.evaluate(&approved_input());
    assert_eq!(result.verdict, ElisionVerdict::Approved);
    assert!(result.denial_reasons.is_empty());
    assert!(result.receipt.verify_digest());
    assert_eq!(eval.tracked_site_count(), 1);
    assert_eq!(eval.approved_site_count(), 1);
}

#[test]
fn enrichment_evaluator_deny_gc_regression() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.gc_assessment = bad_gc();
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::GcPauseRegression)
    );
}

#[test]
fn enrichment_evaluator_deny_tail_latency_regression() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.latency_evidence = bad_latency();
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::TailLatencyRegression)
    );
}

#[test]
fn enrichment_evaluator_deny_missing_escape_cert() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.has_escape_certificate = false;
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::MissingEscapeCertificate)
    );
}

#[test]
fn enrichment_evaluator_deny_insufficient_samples() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.gc_assessment.sample_count = 1;
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSamples)
    );
}

#[test]
fn enrichment_evaluator_deny_no_observability() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.observability = None;
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::ObservabilityUnhealthy)
    );
}

#[test]
fn enrichment_evaluator_deny_unhealthy_observability() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    let mut oh = healthy_obs();
    oh.gc_telemetry_active = false;
    input.observability = Some(oh);
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::ObservabilityUnhealthy)
    );
}

#[test]
fn enrichment_evaluator_deny_insufficient_support_coverage() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    let mut sc = good_support();
    sc.actual_coverage_millionths = 100_000;
    input.support_contract = Some(sc);
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSupportCoverage)
    );
}

#[test]
fn enrichment_evaluator_deny_no_support_contract() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input = approved_input();
    input.support_contract = None;
    let result = eval.evaluate(&input);
    assert_eq!(result.verdict, ElisionVerdict::Denied);
    assert!(
        result
            .denial_reasons
            .contains(&DenialReason::InsufficientSupportCoverage)
    );
}

// =========================================================================
// Deopt processing & rollback
// =========================================================================

#[test]
fn enrichment_evaluator_process_deopt_triggers_rollback() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());

    let witness = DeoptWitness {
        site_id: site("site-a"),
        lane_id: lane("lane-1"),
        assumption_kind: AssumptionKind::NoEscape,
        timestamp_ns: 2_000_000,
        epoch: epoch(1),
        stack_depth: 5,
        occurrence_count: 1,
        approval_receipt_digest: ContentHash::compute(b"receipt"),
    };
    let rollback = eval.process_deopt(&witness);
    assert!(rollback.is_some());
    let rb = rollback.unwrap();
    assert_eq!(rb.trigger, RollbackTrigger::DeoptEvent);
    assert_eq!(rb.consecutive_count, 1);
    assert_eq!(eval.total_rollback_count(), 1);
}

#[test]
fn enrichment_evaluator_process_deopt_unknown_site() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let witness = DeoptWitness {
        site_id: site("unknown"),
        lane_id: lane("lane-1"),
        assumption_kind: AssumptionKind::NoEscape,
        timestamp_ns: 1_000,
        epoch: epoch(1),
        stack_depth: 1,
        occurrence_count: 1,
        approval_receipt_digest: ContentHash::compute(b"r"),
    };
    assert!(eval.process_deopt(&witness).is_none());
}

#[test]
fn enrichment_evaluator_trigger_rollback() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());

    let rb = eval.trigger_rollback(
        &site("site-a"),
        &lane("lane-1"),
        RollbackTrigger::LatencyRegression,
        ContentHash::compute(b"evidence"),
        2_000_000,
        epoch(1),
    );
    assert!(rb.is_some());
    assert_eq!(rb.unwrap().trigger, RollbackTrigger::LatencyRegression);
}

#[test]
fn enrichment_evaluator_trigger_rollback_denied_site() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    // Evaluate but deny (missing escape cert)
    let mut input = approved_input();
    input.has_escape_certificate = false;
    eval.evaluate(&input);

    let rb = eval.trigger_rollback(
        &site("site-a"),
        &lane("lane-1"),
        RollbackTrigger::GcRegression,
        ContentHash::compute(b"ev"),
        1_000,
        epoch(1),
    );
    assert!(rb.is_none());
}

// =========================================================================
// Batch evaluation
// =========================================================================

#[test]
fn enrichment_evaluator_batch_evaluate() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let mut input2 = approved_input();
    input2.site_id = site("site-b");
    input2.has_escape_certificate = false;

    let results = eval.evaluate_batch(&[approved_input(), input2]);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].verdict, ElisionVerdict::Approved);
    assert_eq!(results[1].verdict, ElisionVerdict::Denied);
    assert_eq!(eval.tracked_site_count(), 2);
}

// =========================================================================
// Savings report
// =========================================================================

#[test]
fn enrichment_savings_report_approval_rate() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());
    let report = eval.generate_savings_report(
        &lane("lane-1"),
        1000,
        500,
        10,
        50_000,
        20_000,
        epoch(1),
        3_000_000,
    );
    assert_eq!(report.total_sites_evaluated, 1);
    assert_eq!(report.sites_approved, 1);
    assert_eq!(report.approval_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_savings_report_effective_rate_with_rollback() {
    let report = ElisionSavingsReport {
        lane_id: lane("l"),
        total_sites_evaluated: 10,
        sites_approved: 8,
        sites_denied: 1,
        sites_rolled_back: 2,
        estimated_bytes_saved_per_sec: 0,
        estimated_allocs_avoided_per_sec: 0,
        estimated_gc_cycles_saved_per_min: 0,
        net_p50_improvement_ns: 0,
        net_p99_improvement_ns: 0,
        epoch: epoch(1),
        timestamp_ns: 0,
        report_digest: ContentHash::compute(b"r"),
    };
    // effective = (8 - 2) / 10 = 600_000
    assert_eq!(report.effective_elision_rate_millionths(), 600_000);
}

#[test]
fn enrichment_savings_report_zero_sites() {
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
        report_digest: ContentHash::compute(b"r"),
    };
    assert_eq!(report.approval_rate_millionths(), 0);
    assert_eq!(report.effective_elision_rate_millionths(), 0);
}

// =========================================================================
// Site verdict & query
// =========================================================================

#[test]
fn enrichment_evaluator_site_verdict() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());
    assert_eq!(eval.site_verdict("site-a"), Some(&ElisionVerdict::Approved));
    assert_eq!(eval.site_verdict("unknown"), None);
}

#[test]
fn enrichment_evaluator_is_permanently_denied() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());
    assert!(!eval.is_permanently_denied("site-a"));
    assert!(!eval.is_permanently_denied("unknown"));
}

#[test]
fn enrichment_evaluator_reset_rollback_counter() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());
    assert!(eval.reset_rollback_counter("site-a"));
    assert!(!eval.reset_rollback_counter("unknown"));
}

#[test]
fn enrichment_evaluator_site_rollbacks() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    eval.evaluate(&approved_input());
    eval.trigger_rollback(
        &site("site-a"),
        &lane("lane-1"),
        RollbackTrigger::GcRegression,
        ContentHash::compute(b"ev"),
        2_000_000,
        epoch(1),
    );
    let rollbacks = eval.site_rollbacks("site-a");
    assert_eq!(rollbacks.len(), 1);
    assert!(eval.site_rollbacks("unknown").is_empty());
}

// =========================================================================
// ElisionDecisionReceipt
// =========================================================================

#[test]
fn enrichment_receipt_verify_digest() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let result = eval.evaluate(&approved_input());
    assert!(result.receipt.verify_digest());
}

#[test]
fn enrichment_receipt_compute_digest_deterministic() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let result = eval.evaluate(&approved_input());
    let d1 = result.receipt.compute_digest();
    let d2 = result.receipt.compute_digest();
    assert_eq!(d1, d2);
}

// =========================================================================
// ElisionEvidenceBundle
// =========================================================================

#[test]
fn enrichment_evidence_bundle_empty() {
    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        vec![],
        vec![],
        vec![],
        None,
        None,
        epoch(1),
        1_000,
    );
    assert_eq!(bundle.approval_count(), 0);
    assert_eq!(bundle.denial_count(), 0);
    assert_eq!(bundle.schema_version, ELISION_GATE_SCHEMA_VERSION);
}

#[test]
fn enrichment_evidence_bundle_with_receipts() {
    let mut eval = ElisionGateEvaluator::with_defaults();
    let result = eval.evaluate(&approved_input());

    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        vec![result.receipt],
        vec![],
        vec![],
        None,
        None,
        epoch(1),
        1_000,
    );
    assert_eq!(bundle.approval_count(), 1);
    assert_eq!(bundle.denial_count(), 0);
}

#[test]
fn enrichment_evidence_bundle_serde_roundtrip() {
    let bundle = ElisionEvidenceBundle::create(
        lane("l"),
        vec![],
        vec![],
        vec![],
        None,
        None,
        epoch(1),
        1_000,
    );
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ElisionEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// =========================================================================
// JSON field-name stability
// =========================================================================

#[test]
fn enrichment_json_fields_gc_assessment() {
    let json = serde_json::to_string(&good_gc()).unwrap();
    assert!(json.contains("\"baseline_pause_p50_ns\""));
    assert!(json.contains("\"baseline_pause_p99_ns\""));
    assert!(json.contains("\"elided_pause_p50_ns\""));
    assert!(json.contains("\"elided_pause_p99_ns\""));
    assert!(json.contains("\"sample_count\""));
    assert!(json.contains("\"pause_regression_millionths\""));
}

#[test]
fn enrichment_json_fields_tail_latency() {
    let json = serde_json::to_string(&good_latency()).unwrap();
    assert!(json.contains("\"baseline_p99_ns\""));
    assert!(json.contains("\"baseline_p999_ns\""));
    assert!(json.contains("\"elided_p99_ns\""));
    assert!(json.contains("\"elided_p999_ns\""));
    assert!(json.contains("\"workload_id\""));
}

#[test]
fn enrichment_json_fields_support_contract() {
    let json = serde_json::to_string(&good_support()).unwrap();
    assert!(json.contains("\"contract_id\""));
    assert!(json.contains("\"covered_sites\""));
    assert!(json.contains("\"min_coverage_millionths\""));
    assert!(json.contains("\"actual_coverage_millionths\""));
    assert!(json.contains("\"fallback_paths_verified\""));
}

#[test]
fn enrichment_json_fields_site_state() {
    let state = SiteElisionState::new(site("s"), epoch(1));
    let json = serde_json::to_string(&state).unwrap();
    assert!(json.contains("\"site_id\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"consecutive_rollbacks\""));
    assert!(json.contains("\"permanently_denied\""));
    assert!(json.contains("\"active_assumptions\""));
}

#[test]
fn enrichment_json_fields_gate_config() {
    let json = serde_json::to_string(&GateConfig::default()).unwrap();
    assert!(json.contains("\"max_gc_pause_regression_millionths\""));
    assert!(json.contains("\"max_tail_latency_regression_millionths\""));
    assert!(json.contains("\"min_support_coverage_millionths\""));
    assert!(json.contains("\"min_sample_count\""));
    assert!(json.contains("\"rollback_cooldown_ns\""));
    assert!(json.contains("\"require_observability_health\""));
    assert!(json.contains("\"require_escape_certificate\""));
}

// =========================================================================
// Deopt witness
// =========================================================================

#[test]
fn enrichment_deopt_witness_digest_deterministic() {
    let w = DeoptWitness {
        site_id: site("s"),
        lane_id: lane("l"),
        assumption_kind: AssumptionKind::StableShape,
        timestamp_ns: 42,
        epoch: epoch(1),
        stack_depth: 3,
        occurrence_count: 1,
        approval_receipt_digest: ContentHash::compute(b"receipt"),
    };
    let d1 = w.digest();
    let d2 = w.digest();
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_deopt_witness_serde_roundtrip() {
    let w = DeoptWitness {
        site_id: site("s"),
        lane_id: lane("l"),
        assumption_kind: AssumptionKind::NoAlias,
        timestamp_ns: 100,
        epoch: epoch(2),
        stack_depth: 7,
        occurrence_count: 3,
        approval_receipt_digest: ContentHash::compute(b"r"),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: DeoptWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

// =========================================================================
// Evaluator config
// =========================================================================

#[test]
fn enrichment_evaluator_config_accessor() {
    let eval = ElisionGateEvaluator::with_defaults();
    assert_eq!(
        eval.config().max_gc_pause_regression_millionths,
        DEFAULT_MAX_GC_PAUSE_REGRESSION_MILLIONTHS
    );
}

#[test]
fn enrichment_evaluator_site_states_accessor() {
    let eval = ElisionGateEvaluator::with_defaults();
    assert!(eval.site_states().is_empty());
}
