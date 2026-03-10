//! Enrichment integration tests for `observability_quality_sentinel` (FRX-17.4).
//!
//! Covers: constants, Display exact values, Debug distinctness, serde roundtrips,
//! JSON field-name stability, severity_rank monotonicity, QualityThreshold
//! is_breached/is_warning semantics, SequentialTestState lifecycle,
//! canonical_demotion_policy, sentinel observation pipeline, report generation.

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

use frankenengine_engine::observability_quality_sentinel::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ── helpers ──────────────────────────────────────────────────────────────

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

// ── constants ────────────────────────────────────────────────────────────

#[test]
fn constant_schema_version() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.observability-quality-sentinel.v1"
    );
}

#[test]
fn constant_default_min_fidelity() {
    assert_eq!(DEFAULT_MIN_FIDELITY, 800_000);
}

#[test]
fn constant_default_max_blind_spot_ratio() {
    assert_eq!(DEFAULT_MAX_BLIND_SPOT_RATIO, 50_000);
}

#[test]
fn constant_default_max_reconstruction_ambiguity() {
    assert_eq!(DEFAULT_MAX_RECONSTRUCTION_AMBIGUITY, 100_000);
}

#[test]
fn constant_default_max_tail_undercoverage() {
    assert_eq!(DEFAULT_MAX_TAIL_UNDERCOVERAGE, 150_000);
}

#[test]
fn constant_min_observations_for_test() {
    assert_eq!(MIN_OBSERVATIONS_FOR_TEST, 10);
}

// ── QualityDimension ─────────────────────────────────────────────────────

#[test]
fn quality_dimension_all_count_5() {
    assert_eq!(QualityDimension::ALL.len(), 5);
}

#[test]
fn quality_dimension_display_exact_all_variants() {
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
fn quality_dimension_debug_distinct() {
    let set: BTreeSet<String> = QualityDimension::ALL
        .iter()
        .map(|d| format!("{d:?}"))
        .collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn quality_dimension_serde_roundtrip_all() {
    for dim in &QualityDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: QualityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn quality_dimension_display_distinct() {
    let set: BTreeSet<String> = QualityDimension::ALL
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(set.len(), 5);
}

// ── DegradationRegime ────────────────────────────────────────────────────

#[test]
fn degradation_regime_display_exact_all_variants() {
    assert_eq!(DegradationRegime::Nominal.to_string(), "nominal");
    assert_eq!(DegradationRegime::Elevated.to_string(), "elevated");
    assert_eq!(DegradationRegime::Breached.to_string(), "breached");
    assert_eq!(DegradationRegime::Emergency.to_string(), "emergency");
}

#[test]
fn degradation_regime_debug_distinct() {
    let variants = [
        DegradationRegime::Nominal,
        DegradationRegime::Elevated,
        DegradationRegime::Breached,
        DegradationRegime::Emergency,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn degradation_regime_serde_roundtrip_all() {
    for r in [
        DegradationRegime::Nominal,
        DegradationRegime::Elevated,
        DegradationRegime::Breached,
        DegradationRegime::Emergency,
    ] {
        let json = serde_json::to_string(&r).unwrap();
        let back: DegradationRegime = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn degradation_regime_ordering() {
    assert!(DegradationRegime::Nominal < DegradationRegime::Elevated);
    assert!(DegradationRegime::Elevated < DegradationRegime::Breached);
    assert!(DegradationRegime::Breached < DegradationRegime::Emergency);
}

// ── DemotionTarget ───────────────────────────────────────────────────────

#[test]
fn demotion_target_display_exact_all_variants() {
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
fn demotion_target_severity_rank_values() {
    assert_eq!(DemotionTarget::IncreasedSampling.severity_rank(), 1);
    assert_eq!(DemotionTarget::UncompressedEvidence.severity_rank(), 2);
    assert_eq!(DemotionTarget::FullReplayCapture.severity_rank(), 3);
    assert_eq!(DemotionTarget::EmergencyRingBuffer.severity_rank(), 4);
}

#[test]
fn demotion_target_severity_rank_monotonic() {
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
fn demotion_target_debug_distinct() {
    let variants = [
        DemotionTarget::IncreasedSampling,
        DemotionTarget::UncompressedEvidence,
        DemotionTarget::FullReplayCapture,
        DemotionTarget::EmergencyRingBuffer,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn demotion_target_serde_roundtrip_all() {
    for t in [
        DemotionTarget::IncreasedSampling,
        DemotionTarget::UncompressedEvidence,
        DemotionTarget::FullReplayCapture,
        DemotionTarget::EmergencyRingBuffer,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: DemotionTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ── QualityThreshold ─────────────────────────────────────────────────────

#[test]
fn threshold_fidelity_is_breached_below_limit() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    assert!(t.is_breached(700_000));
    assert!(!t.is_breached(800_001));
    assert!(!t.is_breached(900_000));
}

#[test]
fn threshold_fidelity_is_warning_between_warning_and_limit() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    assert!(t.is_warning(850_000));
    assert!(!t.is_warning(950_000));
    assert!(!t.is_warning(700_000)); // breached, not warning
}

#[test]
fn threshold_blind_spot_is_breached_above_limit() {
    let t = QualityThreshold {
        dimension: QualityDimension::BlindSpotRatio,
        limit_millionths: 50_000,
        warning_millionths: 30_000,
    };
    assert!(t.is_breached(60_000));
    assert!(!t.is_breached(40_000));
}

#[test]
fn threshold_blind_spot_is_warning_above_warning() {
    let t = QualityThreshold {
        dimension: QualityDimension::BlindSpotRatio,
        limit_millionths: 50_000,
        warning_millionths: 30_000,
    };
    assert!(t.is_warning(40_000));
    assert!(!t.is_warning(20_000));
}

// ── JSON field-name stability ────────────────────────────────────────────

#[test]
fn quality_observation_json_fields() {
    let obs = qobs(QualityDimension::SignalFidelity, 900_000, 100);
    let json = serde_json::to_value(&obs).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "dimension",
        "value_millionths",
        "timestamp_ns",
        "channel_id",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn quality_threshold_json_fields() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    let json = serde_json::to_value(&t).unwrap();
    let obj = json.as_object().unwrap();
    for key in &["dimension", "limit_millionths", "warning_millionths"] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn sequential_test_state_json_fields() {
    let st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
    let json = serde_json::to_value(&st).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "dimension",
        "cusum_millionths",
        "e_value_millionths",
        "observation_count",
        "rejected",
        "rejection_threshold_millionths",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn demotion_rule_json_fields() {
    let rule = DemotionRule {
        rule_id: "r1".into(),
        trigger_dimension: QualityDimension::SignalFidelity,
        trigger_regime: DegradationRegime::Breached,
        target: DemotionTarget::IncreasedSampling,
        cooldown_epochs: 2,
        rationale: "test".into(),
    };
    let json = serde_json::to_value(&rule).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "rule_id",
        "trigger_dimension",
        "trigger_regime",
        "target",
        "cooldown_epochs",
        "rationale",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn demotion_receipt_json_fields() {
    let receipt = DemotionReceipt {
        receipt_id: "dr-abc".into(),
        epoch: test_epoch(),
        trigger_artifact_id: "da-xyz".into(),
        dimension: QualityDimension::SignalFidelity,
        previous_mode: "compressed".into(),
        new_mode: DemotionTarget::IncreasedSampling,
        rule_id: "r1".into(),
        timestamp_ns: 100,
        content_hash: "h".into(),
    };
    let json = serde_json::to_value(&receipt).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "receipt_id",
        "epoch",
        "trigger_artifact_id",
        "dimension",
        "previous_mode",
        "new_mode",
        "rule_id",
        "timestamp_ns",
        "content_hash",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn sentinel_report_json_fields() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    let json = serde_json::to_value(&report).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "schema_version",
        "epoch",
        "overall_regime",
        "total_observations",
        "total_degradation_artifacts",
        "total_demotion_receipts",
        "dimensions",
        "gate_pass",
        "content_hash",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

// ── serde roundtrips ─────────────────────────────────────────────────────

#[test]
fn quality_observation_serde_roundtrip() {
    let obs = qobs(QualityDimension::TailUndercoverage, 120_000, 500);
    let json = serde_json::to_string(&obs).unwrap();
    let back: QualityObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.dimension, obs.dimension);
    assert_eq!(back.value_millionths, obs.value_millionths);
}

#[test]
fn quality_threshold_serde_roundtrip() {
    let t = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: QualityThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(back.dimension, t.dimension);
    assert_eq!(back.limit_millionths, t.limit_millionths);
}

#[test]
fn sequential_test_state_serde_roundtrip() {
    let st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
    let json = serde_json::to_string(&st).unwrap();
    let back: SequentialTestState = serde_json::from_str(&json).unwrap();
    assert_eq!(back.dimension, st.dimension);
    assert_eq!(back.cusum_millionths, 0);
    assert!(!back.rejected);
}

#[test]
fn demotion_receipt_serde_roundtrip() {
    let receipt = DemotionReceipt {
        receipt_id: "dr-abc".into(),
        epoch: test_epoch(),
        trigger_artifact_id: "da-xyz".into(),
        dimension: QualityDimension::SignalFidelity,
        previous_mode: "compressed".into(),
        new_mode: DemotionTarget::IncreasedSampling,
        rule_id: "r1".into(),
        timestamp_ns: 100,
        content_hash: "h".into(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DemotionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.receipt_id, "dr-abc");
    assert_eq!(back.new_mode, DemotionTarget::IncreasedSampling);
}

#[test]
fn sentinel_report_serde_roundtrip() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    let json = serde_json::to_string(&report).unwrap();
    let back: SentinelReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.epoch.as_u64(), report.epoch.as_u64());
    assert_eq!(back.gate_pass, report.gate_pass);
    assert_eq!(back.schema_version, SCHEMA_VERSION);
}

// ── SequentialTestState ──────────────────────────────────────────────────

#[test]
fn sequential_test_new_defaults() {
    let st = SequentialTestState::new(QualityDimension::SignalFidelity);
    assert_eq!(st.dimension, QualityDimension::SignalFidelity);
    assert_eq!(st.cusum_millionths, 0);
    assert_eq!(st.e_value_millionths, 1_000_000);
    assert_eq!(st.observation_count, 0);
    assert!(!st.rejected);
    assert_eq!(st.rejection_threshold_millionths, 20_000_000);
}

#[test]
fn sequential_test_reset_clears_state() {
    let mut st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
    st.cusum_millionths = 500_000;
    st.e_value_millionths = 10_000_000;
    st.observation_count = 100;
    st.rejected = true;
    st.reset();
    assert_eq!(st.cusum_millionths, 0);
    assert_eq!(st.e_value_millionths, 1_000_000);
    assert_eq!(st.observation_count, 0);
    assert!(!st.rejected);
}

#[test]
fn sequential_test_good_observations_no_rejection() {
    let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
    let threshold = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    for _ in 0..20 {
        assert!(!st.update(&threshold, 950_000));
    }
    assert!(!st.rejected);
}

#[test]
fn sequential_test_bad_observations_eventually_reject() {
    let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
    let threshold = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    let mut rejected = false;
    for _ in 0..50 {
        if st.update(&threshold, 500_000) {
            rejected = true;
            break;
        }
    }
    assert!(rejected);
    assert!(st.rejected);
}

#[test]
fn sequential_test_needs_min_observations() {
    let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
    let threshold = QualityThreshold {
        dimension: QualityDimension::SignalFidelity,
        limit_millionths: 800_000,
        warning_millionths: 900_000,
    };
    for _ in 0..MIN_OBSERVATIONS_FOR_TEST.saturating_sub(1) {
        st.update(&threshold, 0);
    }
    assert!(!st.rejected);
}

// ── canonical_demotion_policy ────────────────────────────────────────────

#[test]
fn canonical_policy_has_5_thresholds() {
    assert_eq!(make_policy().thresholds.len(), 5);
}

#[test]
fn canonical_policy_covers_all_dimensions() {
    let policy = make_policy();
    for dim in &QualityDimension::ALL {
        assert!(
            policy.threshold_for(*dim).is_some(),
            "missing threshold for {dim}"
        );
    }
}

#[test]
fn canonical_policy_has_6_rules() {
    assert_eq!(make_policy().rules.len(), 6);
}

#[test]
fn canonical_policy_id_deterministic() {
    assert_eq!(make_policy().policy_id, make_policy().policy_id);
}

#[test]
fn canonical_policy_id_starts_with_dp() {
    assert!(make_policy().policy_id.starts_with("dp-"));
}

#[test]
fn canonical_policy_rules_for_fidelity_breached() {
    let policy = make_policy();
    let rules = policy.rules_for(
        QualityDimension::SignalFidelity,
        DegradationRegime::Breached,
    );
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].target, DemotionTarget::IncreasedSampling);
}

#[test]
fn canonical_policy_rules_for_fidelity_emergency() {
    let policy = make_policy();
    let rules = policy.rules_for(
        QualityDimension::SignalFidelity,
        DegradationRegime::Emergency,
    );
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].target, DemotionTarget::FullReplayCapture);
}

#[test]
fn canonical_policy_max_demotion_severity() {
    let policy = make_policy();
    assert_eq!(
        policy.max_demotion_severity().unwrap(),
        DemotionTarget::FullReplayCapture
    );
}

// ── DegradationArtifact / DemotionReceipt deterministic IDs ──────────────

#[test]
fn degradation_artifact_id_deterministic_and_prefixed() {
    let id1 = DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
    let id2 = DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("da-"));
}

#[test]
fn degradation_artifact_hash_deterministic() {
    let h1 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::BlindSpotRatio,
        DegradationRegime::Breached,
        60_000,
        1000,
    );
    let h2 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::BlindSpotRatio,
        DegradationRegime::Breached,
        60_000,
        1000,
    );
    assert_eq!(h1, h2);
}

#[test]
fn degradation_artifact_hash_differs_by_dimension() {
    let h1 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::BlindSpotRatio,
        DegradationRegime::Breached,
        60_000,
        1000,
    );
    let h2 = DegradationArtifact::compute_hash(
        test_epoch(),
        QualityDimension::TailUndercoverage,
        DegradationRegime::Breached,
        60_000,
        1000,
    );
    assert_ne!(h1, h2);
}

#[test]
fn demotion_receipt_id_deterministic_and_prefixed() {
    let id1 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
    let id2 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("dr-"));
}

#[test]
fn demotion_receipt_hash_deterministic() {
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

// ── ObservabilityQualitySentinel ─────────────────────────────────────────

#[test]
fn sentinel_starts_nominal_with_zero_counts() {
    let sentinel = make_sentinel();
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
    assert!(!sentinel.is_degraded());
    assert_eq!(sentinel.total_observations, 0);
    assert_eq!(sentinel.total_degradation_artifacts, 0);
    assert_eq!(sentinel.total_demotion_receipts, 0);
}

#[test]
fn sentinel_dimension_states_cover_all_thresholds() {
    let sentinel = make_sentinel();
    assert_eq!(sentinel.dimension_states.len(), 5);
}

#[test]
fn sentinel_good_observation_stays_nominal() {
    let mut sentinel = make_sentinel();
    let (artifacts, receipts) =
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 100));
    assert!(artifacts.is_empty());
    assert!(receipts.is_empty());
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
    assert_eq!(sentinel.total_observations, 1);
}

#[test]
fn sentinel_breach_triggers_degradation_artifact() {
    let mut sentinel = make_sentinel();
    let (artifacts, _) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].regime, DegradationRegime::Breached);
    assert!(artifacts[0].artifact_id.starts_with("da-"));
}

#[test]
fn sentinel_breach_triggers_demotion_receipt() {
    let mut sentinel = make_sentinel();
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].new_mode, DemotionTarget::IncreasedSampling);
    assert!(receipts[0].receipt_id.starts_with("dr-"));
}

#[test]
fn sentinel_emergency_triggers_full_replay() {
    let mut sentinel = make_sentinel();
    // value < limit/2 (800_000/2 = 400_000), so 300_000 is emergency
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 300_000, 100));
    let replay: Vec<_> = receipts
        .iter()
        .filter(|r| r.new_mode == DemotionTarget::FullReplayCapture)
        .collect();
    assert!(!replay.is_empty());
}

#[test]
fn sentinel_blind_spot_breach_triggers_uncompressed() {
    let mut sentinel = make_sentinel();
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 100));
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].new_mode, DemotionTarget::UncompressedEvidence);
}

#[test]
fn sentinel_cooldown_prevents_repeated_demotion() {
    let mut sentinel = make_sentinel();
    let (_, r1) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    assert_eq!(r1.len(), 1);
    let (_, r2) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 650_000, 200));
    assert!(r2.is_empty(), "cooldown should prevent demotion");
}

#[test]
fn sentinel_recovery_resets_to_nominal() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Breached)
    );
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Nominal)
    );
}

#[test]
fn sentinel_advance_epoch() {
    let mut sentinel = make_sentinel();
    sentinel.advance_epoch(SecurityEpoch::from_raw(43));
    assert_eq!(sentinel.epoch.as_u64(), 43);
}

#[test]
fn sentinel_is_degraded_when_breached() {
    let mut sentinel = make_sentinel();
    assert!(!sentinel.is_degraded());
    sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 100));
    assert!(sentinel.is_degraded());
}

#[test]
fn sentinel_worst_regime_across_dims() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 850_000, 100));
    sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 200));
    assert_eq!(sentinel.worst_regime(), DegradationRegime::Breached);
}

#[test]
fn sentinel_warning_regime_elevated_no_demotion() {
    let mut sentinel = make_sentinel();
    let (artifacts, receipts) =
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 850_000, 100));
    assert_eq!(artifacts.len(), 1);
    assert!(receipts.is_empty());
    assert_eq!(
        sentinel.regime_for(QualityDimension::SignalFidelity),
        Some(DegradationRegime::Elevated)
    );
}

#[test]
fn sentinel_observation_count_increments() {
    let mut sentinel = make_sentinel();
    for i in 0..5 {
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, i * 100));
    }
    assert_eq!(sentinel.total_observations, 5);
}

// ── generate_report ──────────────────────────────────────────────────────

#[test]
fn report_nominal_gate_passes() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    assert!(report.gate_pass);
    assert_eq!(report.overall_regime, DegradationRegime::Nominal);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_degraded_gate_fails() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    let report = generate_report(&sentinel);
    assert!(!report.gate_pass);
    assert_eq!(report.overall_regime, DegradationRegime::Breached);
}

#[test]
fn report_dimensions_count_5() {
    let sentinel = make_sentinel();
    let report = generate_report(&sentinel);
    assert_eq!(report.dimensions.len(), 5);
}

#[test]
fn report_hash_deterministic() {
    let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
    let h2 = SentinelReport::compute_hash(test_epoch(), true, 100);
    assert_eq!(h1, h2);
}

#[test]
fn report_hash_differs_on_gate_pass() {
    let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
    let h2 = SentinelReport::compute_hash(test_epoch(), false, 100);
    assert_ne!(h1, h2);
}

#[test]
fn report_captures_demotion_counts() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    let report = generate_report(&sentinel);
    assert!(report.total_demotion_receipts > 0);
    assert!(report.total_degradation_artifacts > 0);
}

// ── epoch cooldown edge cases ────────────────────────────────────────────

#[test]
fn cooldown_respected_after_advance() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
    sentinel.advance_epoch(SecurityEpoch::from_raw(43));
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 300));
    assert!(receipts.is_empty(), "cooldown should prevent demotion");
}

#[test]
fn cooldown_expires_after_enough_epochs() {
    let mut sentinel = make_sentinel();
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
    sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
    sentinel.advance_epoch(SecurityEpoch::from_raw(45));
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 300));
    assert!(!receipts.is_empty(), "cooldown should have expired");
}

// ── reconstruction ambiguity / staleness ─────────────────────────────────

#[test]
fn reconstruction_ambiguity_breach_triggers_uncompressed() {
    let mut sentinel = make_sentinel();
    let (artifacts, receipts) = sentinel.observe(&qobs(
        QualityDimension::ReconstructionAmbiguity,
        150_000,
        100,
    ));
    assert_eq!(artifacts.len(), 1);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].new_mode, DemotionTarget::UncompressedEvidence);
}

#[test]
fn staleness_breach_triggers_replay() {
    let mut sentinel = make_sentinel();
    let (_, receipts) = sentinel.observe(&qobs(QualityDimension::EvidenceStaleness, 250_000, 100));
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].new_mode, DemotionTarget::FullReplayCapture);
}
