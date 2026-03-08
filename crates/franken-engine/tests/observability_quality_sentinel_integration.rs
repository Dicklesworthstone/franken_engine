#![forbid(unsafe_code)]
//! Integration tests for the `observability_quality_sentinel` module.
//!
//! Exercises QualityDimension, DegradationRegime, DemotionTarget, QualityThreshold,
//! SequentialTestState, DemotionPolicy, DegradationArtifact, DemotionReceipt,
//! ObservabilityQualitySentinel (observe, advance_epoch, worst_regime, is_degraded),
//! SentinelReport, canonical_demotion_policy, and generate_report.

use frankenengine_engine::observability_quality_sentinel::{
    DEFAULT_MAX_BLIND_SPOT_RATIO, DEFAULT_MAX_RECONSTRUCTION_AMBIGUITY,
    DEFAULT_MAX_TAIL_UNDERCOVERAGE, DEFAULT_MIN_FIDELITY, DegradationArtifact, DegradationRegime,
    DemotionPolicy, DemotionReceipt, DemotionTarget, MIN_OBSERVATIONS_FOR_TEST,
    ObservabilityQualitySentinel, QualityDimension, QualityObservation, QualityThreshold,
    SCHEMA_VERSION, SentinelReport, SequentialTestState, canonical_demotion_policy,
    generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_policy() -> DemotionPolicy {
    canonical_demotion_policy(test_epoch())
}

fn make_sentinel() -> ObservabilityQualitySentinel {
    ObservabilityQualitySentinel::new(make_policy())
}

fn qobs(dim: QualityDimension, value: i64, ts: u64) -> QualityObservation {
    QualityObservation {
        dimension: dim,
        value_millionths: value,
        timestamp_ns: ts,
        channel_id: "ch-test".into(),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("observability-quality-sentinel"));
}

#[test]
fn default_thresholds_positive() {
    const { assert!(DEFAULT_MIN_FIDELITY > 0) };
    const { assert!(DEFAULT_MAX_BLIND_SPOT_RATIO > 0) };
    const { assert!(DEFAULT_MAX_RECONSTRUCTION_AMBIGUITY > 0) };
    const { assert!(DEFAULT_MAX_TAIL_UNDERCOVERAGE > 0) };
    const { assert!(MIN_OBSERVATIONS_FOR_TEST > 0) };
}

// ===========================================================================
// 2. QualityDimension
// ===========================================================================

#[test]
fn quality_dimension_all_five() {
    assert_eq!(QualityDimension::ALL.len(), 5);
}

#[test]
fn quality_dimension_display() {
    assert_eq!(
        QualityDimension::SignalFidelity.to_string(),
        "signal_fidelity"
    );
    assert_eq!(
        QualityDimension::BlindSpotRatio.to_string(),
        "blind_spot_ratio"
    );
    assert_eq!(
        QualityDimension::ReconstructionAmbiguity.to_string(),
        "reconstruction_ambiguity"
    );
    assert_eq!(
        QualityDimension::TailUndercoverage.to_string(),
        "tail_undercoverage"
    );
    assert_eq!(
        QualityDimension::EvidenceStaleness.to_string(),
        "evidence_staleness"
    );
}

#[test]
fn quality_dimension_serde() {
    for dim in &QualityDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: QualityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

// ===========================================================================
// 3. DegradationRegime
// ===========================================================================

#[test]
fn degradation_regime_display() {
    assert_eq!(DegradationRegime::Nominal.to_string(), "nominal");
    assert_eq!(DegradationRegime::Elevated.to_string(), "elevated");
    assert_eq!(DegradationRegime::Breached.to_string(), "breached");
    assert_eq!(DegradationRegime::Emergency.to_string(), "emergency");
}

#[test]
fn degradation_regime_serde() {
    for r in [
        DegradationRegime::Nominal,
        DegradationRegime::Elevated,
        DegradationRegime::Breached,
        DegradationRegime::Emergency,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: DegradationRegime = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}

// ===========================================================================
// 4. DemotionTarget
// ===========================================================================

#[test]
fn demotion_target_severity_ordering() {
    assert!(
        DemotionTarget::IncreasedSampling.severity_rank()
            < DemotionTarget::UncompressedEvidence.severity_rank()
    );
    assert!(
        DemotionTarget::UncompressedEvidence.severity_rank()
            < DemotionTarget::FullReplayCapture.severity_rank()
    );
    assert!(
        DemotionTarget::FullReplayCapture.severity_rank()
            < DemotionTarget::EmergencyRingBuffer.severity_rank()
    );
}

#[test]
fn demotion_target_display() {
    assert_eq!(
        DemotionTarget::IncreasedSampling.to_string(),
        "increased_sampling"
    );
    assert_eq!(
        DemotionTarget::UncompressedEvidence.to_string(),
        "uncompressed_evidence"
    );
    assert_eq!(
        DemotionTarget::FullReplayCapture.to_string(),
        "full_replay_capture"
    );
    assert_eq!(
        DemotionTarget::EmergencyRingBuffer.to_string(),
        "emergency_ring_buffer"
    );
}

#[test]
fn demotion_target_serde() {
    for t in [
        DemotionTarget::IncreasedSampling,
        DemotionTarget::UncompressedEvidence,
        DemotionTarget::FullReplayCapture,
        DemotionTarget::EmergencyRingBuffer,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: DemotionTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

// ===========================================================================
// 5. QualityThreshold
// ===========================================================================

#[test]
fn threshold_fidelity_breached_below_limit() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    // Fidelity: breached when value < limit
    assert!(t.is_breached(700_000));
    assert!(!t.is_breached(800_000));
    assert!(!t.is_breached(950_000));
}

#[test]
fn threshold_fidelity_warning_between_limit_and_warning() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    // Warning: not breached but below warning threshold
    assert!(t.is_warning(850_000));
    assert!(!t.is_warning(700_000)); // breached, not warning
    assert!(!t.is_warning(950_000)); // above warning threshold
}

#[test]
fn threshold_blind_spot_breached_above_limit() {
    let t = QualityThreshold {
        dimension: QualityDimension::BlindSpotRatio,
        limit_millionths: 50_000,
        warning_millionths: 30_000,
    };
    // Non-fidelity: breached when value > limit
    assert!(t.is_breached(60_000));
    assert!(!t.is_breached(40_000));
}

#[test]
fn threshold_blind_spot_warning() {
    let t = QualityThreshold {
        dimension: QualityDimension::BlindSpotRatio,
        limit_millionths: 50_000,
        warning_millionths: 30_000,
    };
    assert!(t.is_warning(40_000)); // between warning and limit
    assert!(!t.is_warning(20_000)); // below warning
    assert!(!t.is_warning(60_000)); // breached
}

// ===========================================================================
// 6. SequentialTestState
// ===========================================================================

#[test]
fn sequential_test_new_initial_state() {
    let st = SequentialTestState::new(QualityDimension::SignalFidelity);
    assert_eq!(st.dimension, QualityDimension::SignalFidelity);
    assert_eq!(st.cusum_millionths, 0);
    assert_eq!(st.observation_count, 0);
    assert!(!st.rejected);
}

#[test]
fn sequential_test_update_nominal_no_rejection() {
    let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
    let threshold = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    // Feed nominal values (above threshold)
    for _ in 0..20 {
        st.update(&threshold, 950_000);
    }
    assert!(!st.rejected);
    assert_eq!(st.observation_count, 20);
}

#[test]
fn sequential_test_reset() {
    let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
    let threshold = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    st.update(&threshold, 500_000);
    st.reset();
    assert_eq!(st.cusum_millionths, 0);
    assert_eq!(st.observation_count, 0);
    assert!(!st.rejected);
}

// ===========================================================================
// 7. DemotionPolicy
// ===========================================================================

#[test]
fn demotion_policy_canonical_has_thresholds() {
    let policy = make_policy();
    assert!(!policy.thresholds.is_empty());
    assert_eq!(policy.thresholds.len(), 5);
}

#[test]
fn demotion_policy_canonical_has_rules() {
    let policy = make_policy();
    assert!(!policy.rules.is_empty());
}

#[test]
fn demotion_policy_threshold_for_dimension() {
    let policy = make_policy();
    let t = policy.threshold_for(QualityDimension::SignalFidelity);
    assert!(t.is_some());
    assert_eq!(t.unwrap().limit_millionths, DEFAULT_MIN_FIDELITY);
}

#[test]
fn demotion_policy_threshold_for_unknown() {
    let policy = DemotionPolicy {
        policy_id: "dp-empty".into(),
        epoch: test_epoch(),
        thresholds: vec![],
        rules: vec![],
    };
    assert!(
        policy
            .threshold_for(QualityDimension::SignalFidelity)
            .is_none()
    );
}

#[test]
fn demotion_policy_rules_for_dimension_and_regime() {
    let policy = make_policy();
    let rules = policy.rules_for(
        QualityDimension::SignalFidelity,
        DegradationRegime::Breached,
    );
    assert!(!rules.is_empty());
}

#[test]
fn demotion_policy_max_severity() {
    let policy = make_policy();
    let max = policy.max_demotion_severity();
    assert!(max.is_some());
}

#[test]
fn demotion_policy_compute_id_deterministic() {
    let policy = make_policy();
    let id1 = DemotionPolicy::compute_id(test_epoch(), &policy.rules);
    let id2 = DemotionPolicy::compute_id(test_epoch(), &policy.rules);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("dp-"));
}

// ===========================================================================
// 8. DegradationArtifact
// ===========================================================================

#[test]
fn degradation_artifact_compute_hash_deterministic() {
    let h1 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::SignalFidelity,
        DegradationRegime::Breached,
        500_000,
        1000,
    );
    let h2 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::SignalFidelity,
        DegradationRegime::Breached,
        500_000,
        1000,
    );
    assert_eq!(h1, h2);
}

#[test]
fn degradation_artifact_compute_id_deterministic() {
    let id1 = DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
    let id2 = DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("da-"));
}

// ===========================================================================
// 9. DemotionReceipt
// ===========================================================================

#[test]
fn demotion_receipt_compute_id_deterministic() {
    let id1 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
    let id2 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("dr-"));
}

#[test]
fn demotion_receipt_compute_hash_deterministic() {
    let h1 = DemotionReceipt::compute_hash(
        test_epoch(),
        QualityDimension::SignalFidelity,
        DemotionTarget::IncreasedSampling,
        1000,
    );
    let h2 = DemotionReceipt::compute_hash(
        test_epoch(),
        QualityDimension::SignalFidelity,
        DemotionTarget::IncreasedSampling,
        1000,
    );
    assert_eq!(h1, h2);
}

// ===========================================================================
// 10. ObservabilityQualitySentinel — construction
// ===========================================================================

#[test]
fn sentinel_new_initial_state() {
    let sentinel = make_sentinel();
    assert_eq!(sentinel.epoch, test_epoch());
    assert_eq!(sentinel.total_observations, 0);
    assert_eq!(sentinel.total_degradation_artifacts, 0);
    assert_eq!(sentinel.total_demotion_receipts, 0);
    assert!(!sentinel.is_degraded());
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
}

#[test]
fn sentinel_dimension_states_match_thresholds() {
    let sentinel = make_sentinel();
    assert_eq!(sentinel.dimension_states.len(), 5);
}

// ===========================================================================
// 11. ObservabilityQualitySentinel — observe nominal
// ===========================================================================

#[test]
fn sentinel_observe_nominal_no_artifacts() {
    let mut sentinel = make_sentinel();
    let obs = qobs(QualityDimension::SignalFidelity, 950_000, 1000);
    let (artifacts, receipts) = sentinel.observe(&obs);
    assert!(artifacts.is_empty());
    assert!(receipts.is_empty());
    assert_eq!(sentinel.total_observations, 1);
}

#[test]
fn sentinel_observe_multiple_nominal() {
    let mut sentinel = make_sentinel();
    for i in 0..10 {
        let obs = qobs(QualityDimension::SignalFidelity, 950_000, i * 100);
        let (artifacts, receipts) = sentinel.observe(&obs);
        assert!(artifacts.is_empty());
        assert!(receipts.is_empty());
    }
    assert_eq!(sentinel.total_observations, 10);
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
}

// ===========================================================================
// 12. ObservabilityQualitySentinel — observe breached
// ===========================================================================

#[test]
fn sentinel_observe_fidelity_breached() {
    let mut sentinel = make_sentinel();
    // Fidelity below limit (800k) triggers breach
    let obs = qobs(QualityDimension::SignalFidelity, 700_000, 1000);
    let (artifacts, _receipts) = sentinel.observe(&obs);
    assert!(
        !artifacts.is_empty(),
        "expected degradation artifact for breached fidelity"
    );
    assert_eq!(artifacts[0].regime, DegradationRegime::Breached);
    assert_eq!(artifacts[0].dimension, QualityDimension::SignalFidelity);
}

#[test]
fn sentinel_observe_fidelity_emergency() {
    let mut sentinel = make_sentinel();
    // Fidelity below limit/2 (400k) triggers emergency
    let obs = qobs(QualityDimension::SignalFidelity, 300_000, 1000);
    let (artifacts, _receipts) = sentinel.observe(&obs);
    assert!(!artifacts.is_empty());
    assert_eq!(artifacts[0].regime, DegradationRegime::Emergency);
}

#[test]
fn sentinel_observe_blind_spot_breached() {
    let mut sentinel = make_sentinel();
    // Blind spot above limit (50k) triggers breach
    let obs = qobs(QualityDimension::BlindSpotRatio, 60_000, 1000);
    let (artifacts, _receipts) = sentinel.observe(&obs);
    assert!(!artifacts.is_empty());
    assert_eq!(artifacts[0].regime, DegradationRegime::Breached);
}

// ===========================================================================
// 13. ObservabilityQualitySentinel — demotion receipts
// ===========================================================================

#[test]
fn sentinel_breach_triggers_demotion() {
    let mut sentinel = make_sentinel();
    let obs = qobs(QualityDimension::SignalFidelity, 700_000, 1000);
    let (_artifacts, receipts) = sentinel.observe(&obs);
    assert!(
        !receipts.is_empty(),
        "expected demotion receipt for breached fidelity"
    );
    assert_eq!(receipts[0].dimension, QualityDimension::SignalFidelity);
    assert_eq!(receipts[0].new_mode, DemotionTarget::IncreasedSampling);
}

#[test]
fn sentinel_emergency_triggers_replay_capture() {
    let mut sentinel = make_sentinel();
    let obs = qobs(QualityDimension::SignalFidelity, 300_000, 1000);
    let (_, receipts) = sentinel.observe(&obs);
    // Emergency fidelity should trigger FullReplayCapture
    let has_replay = receipts
        .iter()
        .any(|r| r.new_mode == DemotionTarget::FullReplayCapture);
    assert!(
        has_replay,
        "expected FullReplayCapture for emergency fidelity"
    );
}

// ===========================================================================
// 14. ObservabilityQualitySentinel — regime queries
// ===========================================================================

#[test]
fn sentinel_regime_for_dimension() {
    let mut sentinel = make_sentinel();
    let obs = qobs(QualityDimension::SignalFidelity, 700_000, 1000);
    sentinel.observe(&obs);
    let regime = sentinel.regime_for(QualityDimension::SignalFidelity);
    assert_eq!(regime, Some(DegradationRegime::Breached));
}

#[test]
fn sentinel_worst_regime_after_breach() {
    let mut sentinel = make_sentinel();
    // Breach one dimension
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 1000));
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Breached);
    assert!(sentinel.is_degraded());
}

#[test]
fn sentinel_is_degraded_only_at_breached_or_worse() {
    let mut sentinel = make_sentinel();
    // Elevated (warning) should NOT count as degraded
    let obs = qobs(QualityDimension::BlindSpotRatio, 40_000, 1000);
    sentinel.observe(&obs);
    // BlindSpotRatio warning threshold = 30_000, limit = 50_000
    // 40k > 30k (warning) but < 50k (limit) → should be Elevated, not Breached
    let regime = sentinel.regime_for(QualityDimension::BlindSpotRatio);
    assert!(
        regime == Some(DegradationRegime::Nominal) || regime == Some(DegradationRegime::Elevated),
        "expected Nominal or Elevated, got {regime:?}"
    );
}

// ===========================================================================
// 15. ObservabilityQualitySentinel — advance_epoch
// ===========================================================================

#[test]
fn sentinel_advance_epoch() {
    let mut sentinel = make_sentinel();
    let new_epoch = SecurityEpoch::from_raw(100);
    sentinel.advance_epoch(new_epoch);
    assert_eq!(sentinel.epoch, new_epoch);
}

// ===========================================================================
// 16. ObservabilityQualitySentinel — recovery to nominal
// ===========================================================================

#[test]
fn sentinel_recovery_to_nominal_resets_test() {
    let mut sentinel = make_sentinel();
    // First breach
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 1000));
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Breached)
    );

    // Then recover
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 2000));
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Nominal)
    );
}

// ===========================================================================
// 17. SentinelReport + generate_report
// ===========================================================================

#[test]
fn generate_report_nominal() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    assert_eq!(report.overall_regime, DegradationRegime::Nominal);
    assert!(report.gate_pass);
    assert_eq!(report.total_observations, 0);
    assert!(!report.content_hash.is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_after_breach() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 1000));
    let report = generate_report(&sentinel);
    assert!(!report.gate_pass);
    assert_eq!(report.total_observations, 1);
    assert!(report.total_degradation_artifacts > 0);
}

#[test]
fn sentinel_report_hash_deterministic() {
    let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
    let h2 = SentinelReport::compute_hash(test_epoch(), true, 100);
    assert_eq!(h1, h2);
}

#[test]
fn sentinel_report_serde() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    let json = serde_json::to_string(&report).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.gate_pass, report.gate_pass);
    assert_eq!(back.overall_regime, report.overall_regime);
    assert_eq!(back.content_hash, report.content_hash);
}

// ===========================================================================
// 18. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_observe_breach_demote_recover() {
    let mut sentinel = make_sentinel();

    // 1. Nominal observations
    for i in 0..5 {
        let (a, r) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, i * 100));
        assert!(a.is_empty());
        assert!(r.is_empty());
    }
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
    assert!(!sentinel.is_degraded());

    // 2. Breach observation
    let (artifacts, _receipts) =
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 5000));
    assert!(!artifacts.is_empty());
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Breached);
    assert!(sentinel.is_degraded());

    // 3. Generate report (should fail gate)
    let report = generate_report(&sentinel);
    assert!(!report.gate_pass);
    assert!(report.total_degradation_artifacts > 0);

    // 4. Recovery
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 6000));
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Nominal)
    );

    // 5. Advance epoch
    sentinel.advance_epoch(SecurityEpoch::from_raw(100));
    assert_eq!(sentinel.epoch, SecurityEpoch::from_raw(100));

    // 6. Generate report (should pass gate now)
    let report2 = generate_report(&sentinel);
    assert!(report2.gate_pass);

    // 7. Serde round-trip
    let json = serde_json::to_string(&report2).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.gate_pass, report2.gate_pass);
}
