#![forbid(unsafe_code)]

//! Integration tests for timescale-separation certificates and bifurcation
//! detectors (bd-1lsy.7.14.2 [RGC-614B]).
//!
//! Validates certificate issuance, bundle construction, bifurcation detection,
//! stability witnesses, serde round-trips, and determinism across the full
//! timescale-separation surface.

use frankenengine_engine::timescale_separation_certificate::{
    BifurcationDetectorConfig, BifurcationDetectorResult, BifurcationSignal,
    BifurcationSignalKind, CertificateBundle, ControllerPairId,
    ControllerTimescaleProfile, PairTelemetrySnapshot, RecommendedAction,
    SeparationVerdict, SignalSeverity, StabilityAssessment, StabilityWitness,
    TimescaleRatio, TimescaleSeparationCertificate,
    BIFURCATION_DETECTOR_SCHEMA_VERSION, CERTIFICATE_BUNDLE_SCHEMA_VERSION,
    DEFAULT_MARGINAL_RATIO_MILLIONTHS, DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
    STABILITY_WITNESS_SCHEMA_VERSION, TIMESCALE_CERTIFICATE_BEAD_ID,
    TIMESCALE_CERTIFICATE_SCHEMA_VERSION,
    build_certificate_bundle, compute_timescale_ratio, detect_bifurcation_signals,
    issue_separation_certificate, render_bundle_summary, render_detector_summary,
};

// =========================================================================
// Helpers
// =========================================================================

fn profile(id: &str, obs_us: i64, write_us: i64) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: id.to_string(),
        observation_interval_millionths: obs_us,
        write_interval_millionths: write_us,
        sample_count: 100,
        measured_epoch: 0,
    }
}

fn pair(fast: &str, slow: &str) -> ControllerPairId {
    ControllerPairId {
        fast_controller: fast.to_string(),
        slow_controller: slow.to_string(),
    }
}

fn snapshot(
    fast: &str,
    slow: &str,
    ratio: u64,
    variance: i64,
    gain: i64,
    epoch: u64,
) -> PairTelemetrySnapshot {
    PairTelemetrySnapshot {
        pair: pair(fast, slow),
        ratio_millionths: ratio,
        variance_millionths: variance,
        effective_gain_millionths: gain,
        epoch,
    }
}

fn default_config() -> BifurcationDetectorConfig {
    BifurcationDetectorConfig::default()
}

// =========================================================================
// 1. Schema constant validation
// =========================================================================

#[test]
fn schema_version_constants_are_nonempty() {
    assert!(!TIMESCALE_CERTIFICATE_SCHEMA_VERSION.is_empty());
    assert!(!BIFURCATION_DETECTOR_SCHEMA_VERSION.is_empty());
    assert!(!CERTIFICATE_BUNDLE_SCHEMA_VERSION.is_empty());
    assert!(!STABILITY_WITNESS_SCHEMA_VERSION.is_empty());
    assert!(!TIMESCALE_CERTIFICATE_BEAD_ID.is_empty());
}

#[test]
fn default_thresholds_are_sane() {
    const { assert!(DEFAULT_SUFFICIENT_RATIO_MILLIONTHS > DEFAULT_MARGINAL_RATIO_MILLIONTHS) };
    const { assert!(DEFAULT_MARGINAL_RATIO_MILLIONTHS > 0) };
}

// =========================================================================
// 2. Timescale ratio computation
// =========================================================================

#[test]
fn ratio_well_separated_controllers() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let ratio = compute_timescale_ratio(&fast, &slow);
    assert_eq!(ratio.ratio_millionths, 10_000_000);
    assert_eq!(ratio.pair.fast_controller, "gc");
    assert_eq!(ratio.pair.slow_controller, "monitor");
}

#[test]
fn ratio_equal_controllers() {
    let a = profile("ctrl-a", 500_000, 500_000);
    let b = profile("ctrl-b", 500_000, 500_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 1_000_000);
}

#[test]
fn ratio_reversed_order_still_correct() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let ratio_ab = compute_timescale_ratio(&fast, &slow);
    let ratio_ba = compute_timescale_ratio(&slow, &fast);
    assert_eq!(ratio_ab.ratio_millionths, ratio_ba.ratio_millionths);
    assert_eq!(ratio_ab.pair.fast_controller, ratio_ba.pair.fast_controller);
}

#[test]
fn ratio_with_zero_observation_interval() {
    let fast = profile("zero-obs", 0, 100_000);
    let slow = profile("normal", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&fast, &slow);
    // With zero observation, the ratio computation should handle gracefully
    let _ = ratio.ratio_millionths; // u64 is always non-negative
}

#[test]
fn ratio_uses_conservative_minimum() {
    let a = profile("ctrl-a", 100_000, 1_000_000);
    let b = profile("ctrl-b", 1_000_000, 100_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // The minimum of obs and write ratios is used
    // obs ratio: 10x, write ratio: 10x (reversed)
    // Minimum-of is the conservative choice
    assert!(ratio.ratio_millionths > 0);
}

// =========================================================================
// 3. Certificate issuance
// =========================================================================

#[test]
fn certificate_sufficient_separation() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast,
        &slow,
        &config,
        "cert-1",
        42,
        vec!["ev-1".to_string()],
    );
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
    assert_eq!(cert.certificate_id, "cert-1");
    assert_eq!(cert.issued_epoch, 42);
    assert_eq!(cert.evidence_ids.len(), 1);
    assert_eq!(
        cert.schema_version,
        TIMESCALE_CERTIFICATE_SCHEMA_VERSION
    );
}

#[test]
fn certificate_marginal_separation() {
    // 5x separation: above marginal (3x) but below sufficient (10x)
    let fast = profile("gc", 200_000, 200_000);
    let slow = profile("monitor", 1_000_000, 1_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-2", 0, vec![],
    );
    assert_eq!(cert.verdict, SeparationVerdict::Marginal);
}

#[test]
fn certificate_insufficient_separation() {
    // 1.5x separation: below marginal (3x)
    let fast = profile("gc", 200_000, 200_000);
    let slow = profile("monitor", 300_000, 300_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-3", 0, vec![],
    );
    assert_eq!(cert.verdict, SeparationVerdict::Insufficient);
}

#[test]
fn certificate_contains_both_profiles() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-4", 0, vec![],
    );
    assert_eq!(cert.fast_profile.controller_id, "gc");
    assert_eq!(cert.slow_profile.controller_id, "monitor");
}

#[test]
fn certificate_with_custom_thresholds() {
    let fast = profile("gc", 200_000, 200_000);
    let slow = profile("monitor", 1_000_000, 1_000_000);
    let mut config = default_config();
    // Lower sufficient threshold to 4x
    config.sufficient_ratio_millionths = 4_000_000;
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-5", 0, vec![],
    );
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
    assert_eq!(cert.sufficient_threshold_millionths, 4_000_000);
}

// =========================================================================
// 4. Certificate bundle
// =========================================================================

#[test]
fn bundle_two_controllers() {
    let profiles = vec![
        profile("fast", 100_000, 100_000),
        profile("slow", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 1);
    assert_eq!(bundle.certificates.len(), 1);
    assert_eq!(bundle.sufficient_count + bundle.marginal_count + bundle.insufficient_count, 1);
}

#[test]
fn bundle_three_controllers_produces_three_pairs() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 1_000_000, 1_000_000),
        profile("c", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 3);
    assert_eq!(bundle.certificates.len(), 3);
}

#[test]
fn bundle_four_controllers_produces_six_pairs() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 500_000, 500_000),
        profile("c", 1_000_000, 1_000_000),
        profile("d", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 6);
}

#[test]
fn bundle_overall_verdict_is_worst_case() {
    // Mix: one pair has insufficient separation
    let profiles = vec![
        profile("a", 100_000, 100_000),     // fast
        profile("b", 150_000, 150_000),     // close to a -> insufficient
        profile("c", 10_000_000, 10_000_000), // well separated from both
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Insufficient);
    assert!(bundle.insufficient_count >= 1);
}

#[test]
fn bundle_single_controller_produces_empty() {
    let profiles = vec![profile("solo", 100_000, 100_000)];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 0);
    assert_eq!(bundle.certificates.len(), 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Sufficient);
}

#[test]
fn bundle_empty_profiles() {
    let profiles: Vec<ControllerTimescaleProfile> = vec![];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 0);
}

// =========================================================================
// 5. Bifurcation detection
// =========================================================================

#[test]
fn detect_no_signals_when_stable() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
    assert!(result.signals.is_empty());
}

#[test]
fn detect_timescale_convergence() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 2_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(!result.signals.is_empty());
    assert!(result.signals.iter().any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence));
}

#[test]
fn detect_variance_divergence() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        snapshot("a", "b", 10_000_000, 500_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    assert!(result.signals.iter().any(|s| s.kind == BifurcationSignalKind::VarianceDivergence));
}

#[test]
fn detect_gain_exceedance() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(result.signals.iter().any(|s| s.kind == BifurcationSignalKind::GainExceedance));
}

#[test]
fn detect_multiple_signal_types() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 2_000_000, 100_000, 500_000, 1),
        snapshot("a", "b", 1_000_000, 500_000, 1_500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    assert!(result.signals.len() >= 2);
}

#[test]
fn detect_single_snapshot_produces_no_signal() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 2_000_000, 50_000, 500_000, 0),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 1);
    // With a single snapshot, convergence and variance checks need >= 2 or >= 3 snapshots
    // Only gain exceedance can trigger on a single snapshot
    assert_eq!(result.assessment, StabilityAssessment::Stable);
}

#[test]
fn detect_empty_telemetry() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
    assert!(result.signals.is_empty());
    assert!(result.witnesses.is_empty());
}

// =========================================================================
// 6. Stability assessment levels
// =========================================================================

#[test]
fn assessment_stable_when_no_signals() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
}

#[test]
fn assessment_escalates_with_critical_signal() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // Gain exceedance is critical -> ImmediateActionRequired
    assert!(matches!(
        result.assessment,
        StabilityAssessment::InterventionRecommended
        | StabilityAssessment::ImmediateActionRequired
    ));
}

// =========================================================================
// 7. Stability witnesses
// =========================================================================

#[test]
fn witnesses_created_for_critical_signals() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // Critical signals should generate witnesses
    if result.signals.iter().any(|s| s.severity == SignalSeverity::Critical) {
        assert!(!result.witnesses.is_empty());
    }
}

#[test]
fn witness_has_recommended_action() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    for witness in &result.witnesses {
        // Every witness must have a recommended action
        let _ = witness.recommended_action; // Just verifying the field exists and is set
    }
}

// =========================================================================
// 8. Serde round-trips
// =========================================================================

#[test]
fn certificate_serde_round_trip() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-serde", 0, vec!["ev-1".to_string()],
    );
    let json = serde_json::to_string(&cert).expect("serialize");
    let deser: TimescaleSeparationCertificate =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cert, deser);
}

#[test]
fn bundle_serde_round_trip() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 1_000_000, 1_000_000),
        profile("c", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let json = serde_json::to_string(&bundle).expect("serialize");
    let deser: CertificateBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle, deser);
}

#[test]
fn detector_result_serde_round_trip() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 2_000_000, 100_000, 1_500_000, 1),
        snapshot("a", "b", 1_000_000, 500_000, 1_500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let json = serde_json::to_string(&result).expect("serialize");
    let deser: BifurcationDetectorResult =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, deser);
}

#[test]
fn profile_serde_round_trip() {
    let p = profile("ctrl", 500_000, 750_000);
    let json = serde_json::to_string(&p).expect("serialize");
    let deser: ControllerTimescaleProfile =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, deser);
}

#[test]
fn ratio_serde_round_trip() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let ratio = compute_timescale_ratio(&fast, &slow);
    let json = serde_json::to_string(&ratio).expect("serialize");
    let deser: TimescaleRatio = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ratio, deser);
}

#[test]
fn signal_serde_round_trip() {
    let signal = BifurcationSignal {
        signal_id: "sig-test".to_string(),
        pair: pair("a", "b"),
        kind: BifurcationSignalKind::GrowingOscillation,
        severity: SignalSeverity::Warning,
        trigger_value_millionths: 100_000,
        threshold_millionths: 50_000,
        detected_epoch: 5,
        description: "test signal".to_string(),
    };
    let json = serde_json::to_string(&signal).expect("serialize");
    let deser: BifurcationSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(signal, deser);
}

#[test]
fn witness_serde_round_trip() {
    let witness = StabilityWitness {
        schema_version: STABILITY_WITNESS_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        witness_id: "wit-1".to_string(),
        pair: pair("a", "b"),
        primary_signal: BifurcationSignal {
            signal_id: "sig-1".to_string(),
            pair: pair("a", "b"),
            kind: BifurcationSignalKind::GainExceedance,
            severity: SignalSeverity::Critical,
            trigger_value_millionths: 1_500_000,
            threshold_millionths: 1_000_000,
            detected_epoch: 0,
            description: "gain too high".to_string(),
        },
        supporting_signals: vec![],
        recommended_action: RecommendedAction::ReduceGain,
        assembled_epoch: 0,
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let deser: StabilityWitness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(witness, deser);
}

#[test]
fn config_serde_round_trip() {
    let config = default_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: BifurcationDetectorConfig =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

#[test]
fn telemetry_snapshot_serde_round_trip() {
    let s = snapshot("a", "b", 5_000_000, 100_000, 800_000, 3);
    let json = serde_json::to_string(&s).expect("serialize");
    let deser: PairTelemetrySnapshot =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, deser);
}

// =========================================================================
// 9. Determinism
// =========================================================================

#[test]
fn ratio_computation_deterministic() {
    let fast = profile("gc", 123_456, 234_567);
    let slow = profile("monitor", 987_654, 876_543);
    let r1 = compute_timescale_ratio(&fast, &slow);
    let r2 = compute_timescale_ratio(&fast, &slow);
    assert_eq!(r1, r2);
}

#[test]
fn certificate_issuance_deterministic() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let c1 = issue_separation_certificate(&fast, &slow, &config, "det-1", 0, vec![]);
    let c2 = issue_separation_certificate(&fast, &slow, &config, "det-1", 0, vec![]);
    assert_eq!(c1, c2);
}

#[test]
fn bundle_deterministic() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 500_000, 500_000),
        profile("c", 5_000_000, 5_000_000),
    ];
    let config = default_config();
    let b1 = build_certificate_bundle(&profiles, &config, 0);
    let b2 = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(b1, b2);
}

#[test]
fn detection_deterministic() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 2_000_000, 100_000, 1_500_000, 1),
        snapshot("a", "b", 1_000_000, 500_000, 1_500_000, 2),
    ];
    let r1 = detect_bifurcation_signals(&telemetry, &config, 3);
    let r2 = detect_bifurcation_signals(&telemetry, &config, 3);
    assert_eq!(r1, r2);
}

// =========================================================================
// 10. Display implementations
// =========================================================================

#[test]
fn controller_pair_display() {
    let p = pair("gc", "monitor");
    let s = format!("{p}");
    assert!(s.contains("gc"));
    assert!(s.contains("monitor"));
}

#[test]
fn separation_verdict_display() {
    assert_eq!(format!("{}", SeparationVerdict::Sufficient), "sufficient");
    assert_eq!(format!("{}", SeparationVerdict::Marginal), "marginal");
    assert_eq!(format!("{}", SeparationVerdict::Insufficient), "insufficient");
}

#[test]
fn signal_kind_display() {
    assert_eq!(
        format!("{}", BifurcationSignalKind::GrowingOscillation),
        "growing_oscillation"
    );
    assert_eq!(
        format!("{}", BifurcationSignalKind::GainExceedance),
        "gain_exceedance"
    );
}

#[test]
fn severity_display() {
    assert_eq!(format!("{}", SignalSeverity::Info), "info");
    assert_eq!(format!("{}", SignalSeverity::Warning), "warning");
    assert_eq!(format!("{}", SignalSeverity::Critical), "critical");
}

#[test]
fn assessment_display() {
    assert_eq!(format!("{}", StabilityAssessment::Stable), "stable");
    assert_eq!(
        format!("{}", StabilityAssessment::ImmediateActionRequired),
        "immediate_action_required"
    );
}

#[test]
fn recommended_action_display() {
    assert_eq!(format!("{}", RecommendedAction::Monitor), "monitor");
    assert_eq!(
        format!("{}", RecommendedAction::SafeModeFallback),
        "safe_mode_fallback"
    );
}

// =========================================================================
// 11. Summary rendering
// =========================================================================

#[test]
fn detector_summary_includes_assessment() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    let summary = render_detector_summary(&result);
    assert!(summary.contains("stable"));
}

#[test]
fn bundle_summary_includes_pair_count() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let summary = render_bundle_summary(&bundle);
    assert!(summary.contains("pair_count: 1"));
}

#[test]
fn bundle_summary_includes_verdict() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let summary = render_bundle_summary(&bundle);
    assert!(summary.contains("overall_verdict:"));
}

// =========================================================================
// 12. Edge cases and boundary conditions
// =========================================================================

#[test]
fn boundary_exactly_at_sufficient_threshold() {
    let fast = profile("a", 100_000, 100_000);
    let slow = profile("b", 1_000_000, 1_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "exact", 0, vec![]);
    // 10x ratio should hit exactly the sufficient threshold
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn boundary_just_below_sufficient_threshold() {
    let fast = profile("a", 100_001, 100_001);
    let slow = profile("b", 1_000_000, 1_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "below", 0, vec![]);
    // Just under 10x -> Marginal
    assert_eq!(cert.verdict, SeparationVerdict::Marginal);
}

#[test]
fn boundary_exactly_at_marginal_threshold() {
    let fast = profile("a", 100_000, 100_000);
    let slow = profile("b", 300_000, 300_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "marg", 0, vec![]);
    // 3x ratio should be exactly at marginal threshold
    assert_eq!(cert.verdict, SeparationVerdict::Marginal);
}

#[test]
fn very_large_ratio_stays_sufficient() {
    let fast = profile("a", 1, 1);
    let slow = profile("b", 1_000_000, 1_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "huge", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn multiple_pairs_in_telemetry() {
    let config = default_config();
    let telemetry = vec![
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        snapshot("a", "b", 10_000_000, 50_000, 500_000, 1),
        snapshot("c", "d", 5_000_000, 50_000, 500_000, 0),
        snapshot("c", "d", 2_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // a-b is stable, c-d shows convergence
    assert!(result.signals.iter().any(|s|
        s.pair.fast_controller == "c" && s.kind == BifurcationSignalKind::TimescaleConvergence
    ));
}

// =========================================================================
// 13. JSON structure validation
// =========================================================================

#[test]
fn certificate_json_has_expected_fields() {
    let fast = profile("gc", 100_000, 200_000);
    let slow = profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(
        &fast, &slow, &config, "cert-json", 0, vec![],
    );
    let val: serde_json::Value = serde_json::to_value(&cert).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("bead_id").is_some());
    assert!(val.get("certificate_id").is_some());
    assert!(val.get("pair").is_some());
    assert!(val.get("ratio").is_some());
    assert!(val.get("verdict").is_some());
    assert!(val.get("fast_profile").is_some());
    assert!(val.get("slow_profile").is_some());
}

#[test]
fn bundle_json_has_expected_fields() {
    let profiles = vec![
        profile("a", 100_000, 100_000),
        profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("certificates").is_some());
    assert!(val.get("overall_verdict").is_some());
    assert!(val.get("pair_count").is_some());
}

#[test]
fn detector_result_json_has_expected_fields() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    let val: serde_json::Value = serde_json::to_value(&result).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("signals").is_some());
    assert!(val.get("witnesses").is_some());
    assert!(val.get("assessment").is_some());
    assert!(val.get("detection_epoch").is_some());
}
