//! Enrichment integration tests for `timescale_separation_certificate`.
//!
//! Covers enum serde roundtrips, Display uniqueness, struct construction,
//! certificate lifecycle, ratio arithmetic, bundle aggregation, bifurcation
//! detection edge cases, stability witness assembly, content hash determinism,
//! and summary rendering.

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

use frankenengine_engine::timescale_separation_certificate::*;

// ===========================================================================
// Test helpers
// ===========================================================================

fn make_profile(id: &str, obs: i64, write: i64) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: id.to_string(),
        observation_interval_millionths: obs,
        write_interval_millionths: write,
        sample_count: 100,
        measured_epoch: 1,
    }
}

fn make_pair(fast: &str, slow: &str) -> ControllerPairId {
    ControllerPairId {
        fast_controller: fast.to_string(),
        slow_controller: slow.to_string(),
    }
}

fn make_snapshot(
    fast: &str,
    slow: &str,
    ratio: u64,
    variance: i64,
    gain: i64,
    epoch: u64,
) -> PairTelemetrySnapshot {
    PairTelemetrySnapshot {
        pair: make_pair(fast, slow),
        ratio_millionths: ratio,
        variance_millionths: variance,
        effective_gain_millionths: gain,
        epoch,
    }
}

fn default_config() -> BifurcationDetectorConfig {
    BifurcationDetectorConfig::default()
}

// ===========================================================================
// 1) Enum serde roundtrips
// ===========================================================================

#[test]
fn enrichment_serde_ratio_basis_observation_roundtrip() {
    let v = RatioBasis::Observation;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"observation\"");
    let back: RatioBasis = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_serde_ratio_basis_write_roundtrip() {
    let v = RatioBasis::Write;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"write\"");
    let back: RatioBasis = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_serde_ratio_basis_minimum_of_roundtrip() {
    let v = RatioBasis::MinimumOf;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"minimum_of\"");
    let back: RatioBasis = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_serde_separation_verdict_all_variants() {
    let variants = [
        SeparationVerdict::Sufficient,
        SeparationVerdict::Marginal,
        SeparationVerdict::Insufficient,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SeparationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_serde_bifurcation_signal_kind_all_variants() {
    let variants = [
        BifurcationSignalKind::GrowingOscillation,
        BifurcationSignalKind::TimescaleConvergence,
        BifurcationSignalKind::SpectralEdgeCrossing,
        BifurcationSignalKind::VarianceDivergence,
        BifurcationSignalKind::GainExceedance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BifurcationSignalKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_serde_signal_severity_all_variants() {
    let variants = [
        SignalSeverity::Info,
        SignalSeverity::Warning,
        SignalSeverity::Critical,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SignalSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_serde_recommended_action_all_variants() {
    let variants = [
        RecommendedAction::Monitor,
        RecommendedAction::IncreaseTimescaleSeparation,
        RecommendedAction::ReduceGain,
        RecommendedAction::DisableController,
        RecommendedAction::SafeModeFallback,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: RecommendedAction = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_serde_stability_assessment_all_variants() {
    let variants = [
        StabilityAssessment::Stable,
        StabilityAssessment::MonitoringRecommended,
        StabilityAssessment::InterventionRecommended,
        StabilityAssessment::ImmediateActionRequired,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: StabilityAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

// ===========================================================================
// 2) Display uniqueness
// ===========================================================================

#[test]
fn enrichment_display_ratio_basis_all_distinct() {
    let displays: BTreeSet<String> = [
        RatioBasis::Observation,
        RatioBasis::Write,
        RatioBasis::MinimumOf,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_display_separation_verdict_all_distinct() {
    let displays: BTreeSet<String> = [
        SeparationVerdict::Sufficient,
        SeparationVerdict::Marginal,
        SeparationVerdict::Insufficient,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_display_bifurcation_signal_kind_all_distinct() {
    let displays: BTreeSet<String> = [
        BifurcationSignalKind::GrowingOscillation,
        BifurcationSignalKind::TimescaleConvergence,
        BifurcationSignalKind::SpectralEdgeCrossing,
        BifurcationSignalKind::VarianceDivergence,
        BifurcationSignalKind::GainExceedance,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_display_controller_pair_id_includes_arrow() {
    let pair = make_pair("fast_ctrl", "slow_ctrl");
    let display = pair.to_string();
    assert!(display.contains("fast_ctrl"));
    assert!(display.contains("slow_ctrl"));
    assert!(display.contains('\u{2194}')); // ↔
}

// ===========================================================================
// 3) Struct construction and field validation
// ===========================================================================

#[test]
fn enrichment_construction_controller_timescale_profile_fields() {
    let p = make_profile("gc_pressure", 500_000, 250_000);
    assert_eq!(p.controller_id, "gc_pressure");
    assert_eq!(p.observation_interval_millionths, 500_000);
    assert_eq!(p.write_interval_millionths, 250_000);
    assert_eq!(p.sample_count, 100);
    assert_eq!(p.measured_epoch, 1);
}

#[test]
fn enrichment_construction_pair_telemetry_snapshot_fields() {
    let snap = make_snapshot("router", "optimizer", 10_000_000, 50_000, 800_000, 42);
    assert_eq!(snap.pair.fast_controller, "router");
    assert_eq!(snap.pair.slow_controller, "optimizer");
    assert_eq!(snap.ratio_millionths, 10_000_000);
    assert_eq!(snap.variance_millionths, 50_000);
    assert_eq!(snap.effective_gain_millionths, 800_000);
    assert_eq!(snap.epoch, 42);
}

#[test]
fn enrichment_construction_bifurcation_detector_config_default() {
    let cfg = default_config();
    assert_eq!(
        cfg.sufficient_ratio_millionths,
        DEFAULT_SUFFICIENT_RATIO_MILLIONTHS
    );
    assert_eq!(
        cfg.marginal_ratio_millionths,
        DEFAULT_MARGINAL_RATIO_MILLIONTHS
    );
    assert_eq!(cfg.oscillation_growth_threshold_millionths, 50_000);
    assert_eq!(cfg.variance_divergence_threshold_millionths, 200_000);
    assert_eq!(cfg.gain_exceedance_threshold_millionths, 1_000_000);
}

// ===========================================================================
// 4) Certificate lifecycle
// ===========================================================================

#[test]
fn enrichment_lifecycle_certificate_schema_version_populated() {
    let fast = make_profile("fast", 100_000, 100_000);
    let slow = make_profile("slow", 1_000_000, 1_000_000);
    let cert = issue_separation_certificate(&fast, &slow, &default_config(), "cert-1", 5, vec![]);
    assert_eq!(cert.schema_version, TIMESCALE_CERTIFICATE_SCHEMA_VERSION);
    assert_eq!(cert.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
    assert_eq!(cert.certificate_id, "cert-1");
    assert_eq!(cert.issued_epoch, 5);
}

#[test]
fn enrichment_lifecycle_certificate_preserves_evidence_ids() {
    let fast = make_profile("fast", 100_000, 100_000);
    let slow = make_profile("slow", 1_000_000, 1_000_000);
    let evidence = vec!["ev-alpha".to_string(), "ev-beta".to_string()];
    let cert = issue_separation_certificate(
        &fast,
        &slow,
        &default_config(),
        "cert-ev",
        0,
        evidence.clone(),
    );
    assert_eq!(cert.evidence_ids, evidence);
}

#[test]
fn enrichment_lifecycle_certificate_correct_fast_slow_assignment() {
    // Pass slow first, fast second -- the function should still assign correctly
    let slow = make_profile("slow_one", 10_000_000, 10_000_000);
    let fast = make_profile("fast_one", 100_000, 100_000);
    let cert =
        issue_separation_certificate(&slow, &fast, &default_config(), "cert-order", 0, vec![]);
    assert_eq!(cert.pair.fast_controller, "fast_one");
    assert_eq!(cert.pair.slow_controller, "slow_one");
    assert_eq!(cert.fast_profile.controller_id, "fast_one");
    assert_eq!(cert.slow_profile.controller_id, "slow_one");
}

#[test]
fn enrichment_lifecycle_certificate_thresholds_from_config() {
    let mut cfg = default_config();
    cfg.sufficient_ratio_millionths = 20_000_000;
    cfg.marginal_ratio_millionths = 5_000_000;
    let fast = make_profile("a", 100_000, 100_000);
    let slow = make_profile("b", 1_000_000, 1_000_000);
    let cert = issue_separation_certificate(&fast, &slow, &cfg, "cert-thr", 0, vec![]);
    assert_eq!(cert.sufficient_threshold_millionths, 20_000_000);
    assert_eq!(cert.marginal_threshold_millionths, 5_000_000);
}

#[test]
fn enrichment_lifecycle_certificate_serde_full_roundtrip() {
    let fast = make_profile("router", 100_000, 200_000);
    let slow = make_profile("optimizer", 1_000_000, 2_000_000);
    let cert = issue_separation_certificate(
        &fast,
        &slow,
        &default_config(),
        "serde-full",
        7,
        vec!["e1".to_string()],
    );
    let json = serde_json::to_string(&cert).unwrap();
    let deser: TimescaleSeparationCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, deser);
}

// ===========================================================================
// 5) Ratio arithmetic
// ===========================================================================

#[test]
fn enrichment_arithmetic_ratio_100x_separation() {
    let fast = make_profile("fast", 100_000, 100_000);
    let slow = make_profile("slow", 10_000_000, 10_000_000);
    let ratio = compute_timescale_ratio(&fast, &slow);
    assert_eq!(ratio.ratio_millionths, 100_000_000); // 100x
}

#[test]
fn enrichment_arithmetic_ratio_symmetric_argument_order() {
    let a = make_profile("a", 100_000, 200_000);
    let b = make_profile("b", 1_000_000, 2_000_000);
    let ratio_ab = compute_timescale_ratio(&a, &b);
    let ratio_ba = compute_timescale_ratio(&b, &a);
    assert_eq!(ratio_ab.ratio_millionths, ratio_ba.ratio_millionths);
}

#[test]
fn enrichment_arithmetic_ratio_fast_slow_ordering_correct() {
    let a = make_profile("short_interval", 50_000, 50_000);
    let b = make_profile("long_interval", 500_000, 500_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.pair.fast_controller, "short_interval");
    assert_eq!(ratio.pair.slow_controller, "long_interval");
}

#[test]
fn enrichment_arithmetic_ratio_both_intervals_zero() {
    let a = make_profile("a", 0, 0);
    let b = make_profile("b", 0, 0);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 0);
}

#[test]
fn enrichment_arithmetic_ratio_one_obs_zero_write_nonzero() {
    let a = make_profile("a", 0, 500_000);
    let b = make_profile("b", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // obs ratio = 0 (a obs is 0), write ratio = 2x => min = 0
    assert_eq!(ratio.ratio_millionths, 0);
}

#[test]
fn enrichment_arithmetic_ratio_negative_intervals_handled() {
    // Negative intervals should use unsigned_abs for computation
    let a = make_profile("neg_a", -100_000, -200_000);
    let b = make_profile("neg_b", -1_000_000, -2_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 10_000_000); // 10x from abs values
}

#[test]
fn enrichment_arithmetic_ratio_selects_conservative_basis() {
    // obs ratio = 10x, write ratio = 5x => min = 5x (write)
    let fast = make_profile("f", 100_000, 200_000);
    let slow = make_profile("s", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&fast, &slow);
    assert_eq!(ratio.ratio_basis, RatioBasis::Write);
    assert_eq!(ratio.ratio_millionths, 5_000_000);
}

// ===========================================================================
// 6) Bundle aggregation
// ===========================================================================

#[test]
fn enrichment_bundle_five_controllers_ten_pairs() {
    let profiles: Vec<ControllerTimescaleProfile> = (0..5)
        .map(|i| {
            make_profile(
                &format!("c{i}"),
                (i + 1) as i64 * 1_000_000,
                (i + 1) as i64 * 1_000_000,
            )
        })
        .collect();
    let bundle = build_certificate_bundle(&profiles, &default_config(), 10);
    assert_eq!(bundle.pair_count, 10); // C(5,2) = 10
    assert_eq!(bundle.certificates.len(), 10);
    assert_eq!(bundle.bundle_epoch, 10);
}

#[test]
fn enrichment_bundle_all_sufficient_overall_sufficient() {
    let profiles = vec![
        make_profile("a", 100_000, 100_000),
        make_profile("b", 10_000_000, 10_000_000),
        make_profile("c", 100_000_000, 100_000_000),
    ];
    let bundle = build_certificate_bundle(&profiles, &default_config(), 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Sufficient);
    assert_eq!(bundle.sufficient_count, bundle.pair_count);
    assert_eq!(bundle.marginal_count, 0);
    assert_eq!(bundle.insufficient_count, 0);
}

#[test]
fn enrichment_bundle_counts_add_up_to_pair_count() {
    let profiles = vec![
        make_profile("a", 100_000, 100_000),
        make_profile("b", 200_000, 200_000),
        make_profile("c", 500_000, 500_000),
        make_profile("d", 10_000_000, 10_000_000),
    ];
    let bundle = build_certificate_bundle(&profiles, &default_config(), 0);
    let total = bundle.sufficient_count + bundle.marginal_count + bundle.insufficient_count;
    assert_eq!(total, bundle.pair_count);
}

#[test]
fn enrichment_bundle_schema_version_set() {
    let profiles = vec![make_profile("solo", 100_000, 100_000)];
    let bundle = build_certificate_bundle(&profiles, &default_config(), 0);
    assert_eq!(bundle.schema_version, CERTIFICATE_BUNDLE_SCHEMA_VERSION);
    assert_eq!(bundle.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
}

#[test]
fn enrichment_bundle_serde_roundtrip_nonempty() {
    let profiles = vec![
        make_profile("alpha", 100_000, 100_000),
        make_profile("beta", 1_000_000, 1_000_000),
        make_profile("gamma", 5_000_000, 5_000_000),
    ];
    let bundle = build_certificate_bundle(&profiles, &default_config(), 3);
    let json = serde_json::to_string(&bundle).unwrap();
    let deser: CertificateBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, deser);
}

// ===========================================================================
// 7) Bifurcation detection edge cases
// ===========================================================================

#[test]
fn enrichment_detection_single_snapshot_no_signals() {
    let telemetry = vec![make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0)];
    let result = detect_bifurcation_signals(&telemetry, &default_config(), 0);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
    assert!(result.signals.is_empty());
}

#[test]
fn enrichment_detection_empty_telemetry_stable() {
    let result = detect_bifurcation_signals(&[], &default_config(), 0);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
    assert!(result.signals.is_empty());
    assert!(result.witnesses.is_empty());
}

#[test]
fn enrichment_detection_convergence_critical_severity() {
    // Last ratio less than half the marginal threshold => Critical
    let cfg = default_config();
    let half_marginal = cfg.marginal_ratio_millionths / 2;
    let telemetry = vec![
        make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        make_snapshot("a", "b", half_marginal - 1, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    let convergence_signal = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
        .expect("should have convergence signal");
    assert_eq!(convergence_signal.severity, SignalSeverity::Critical);
}

#[test]
fn enrichment_detection_convergence_warning_severity() {
    // Last ratio above half marginal but below marginal => Warning
    let cfg = default_config();
    let half_marginal = cfg.marginal_ratio_millionths / 2;
    let telemetry = vec![
        make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        make_snapshot("a", "b", half_marginal + 100_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    let convergence_signal = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
        .expect("should have convergence signal");
    assert_eq!(convergence_signal.severity, SignalSeverity::Warning);
}

#[test]
fn enrichment_detection_variance_requires_three_snapshots() {
    // Two snapshots: variance difference is big, but function checks len >= 3
    let cfg = default_config();
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 10_000, 500_000, 0),
        make_snapshot("a", "b", 10_000_000, 500_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::VarianceDivergence),
        "variance divergence should not trigger with only 2 snapshots"
    );
}

#[test]
fn enrichment_detection_variance_critical_when_double_threshold() {
    let cfg = default_config();
    let threshold = cfg.variance_divergence_threshold_millionths;
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 10_000, 500_000, 0),
        make_snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        make_snapshot("a", "b", 10_000_000, 10_000 + threshold * 2 + 1, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 2);
    let var_signal = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
        .expect("should detect variance divergence");
    assert_eq!(var_signal.severity, SignalSeverity::Critical);
}

#[test]
fn enrichment_detection_gain_exceedance_at_exactly_threshold_no_signal() {
    let cfg = default_config();
    // Gain exactly at threshold (not above) should NOT trigger
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        make_snapshot(
            "a",
            "b",
            10_000_000,
            50_000,
            cfg.gain_exceedance_threshold_millionths,
            1,
        ),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance),
        "gain exactly at threshold should not trigger"
    );
}

#[test]
fn enrichment_detection_gain_exceedance_above_threshold_triggers() {
    let cfg = default_config();
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        make_snapshot(
            "a",
            "b",
            10_000_000,
            50_000,
            cfg.gain_exceedance_threshold_millionths + 1,
            1,
        ),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance),
        "gain above threshold should trigger"
    );
}

#[test]
fn enrichment_detection_multiple_pairs_independent_signals() {
    let cfg = default_config();
    let telemetry = vec![
        // Pair a-b: stable
        make_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        make_snapshot("a", "b", 10_000_000, 55_000, 500_000, 1),
        // Pair c-d: gain exceedance
        make_snapshot("c", "d", 10_000_000, 50_000, 500_000, 0),
        make_snapshot("c", "d", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    // Should have signals only for pair c-d
    assert!(!result.signals.is_empty());
    for s in &result.signals {
        assert_eq!(s.pair.fast_controller, "c");
        assert_eq!(s.pair.slow_controller, "d");
    }
}

// ===========================================================================
// 8) Stability witness assembly
// ===========================================================================

#[test]
fn enrichment_witness_no_witness_for_warning_only_signals() {
    let cfg = default_config();
    // Convergence with warning-level severity only
    let half_marginal = cfg.marginal_ratio_millionths / 2;
    let telemetry = vec![
        make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        make_snapshot("a", "b", half_marginal + 100_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert!(!result.signals.is_empty(), "should have warning signals");
    assert!(
        result.witnesses.is_empty(),
        "witnesses should only be for critical signals"
    );
}

#[test]
fn enrichment_witness_created_for_critical_gain() {
    let cfg = default_config();
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        make_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert!(
        !result.witnesses.is_empty(),
        "should have at least one witness"
    );
    let witness = &result.witnesses[0];
    assert_eq!(witness.pair.fast_controller, "a");
    assert_eq!(witness.schema_version, STABILITY_WITNESS_SCHEMA_VERSION);
    assert_eq!(witness.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
    assert_eq!(witness.recommended_action, RecommendedAction::ReduceGain);
}

#[test]
fn enrichment_witness_supporting_signals_populated() {
    let cfg = default_config();
    // Multiple critical signals for the same pair: gain exceedance in both snapshots
    let telemetry = vec![
        make_snapshot("x", "y", 10_000_000, 50_000, 1_500_000, 0),
        make_snapshot("x", "y", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert_eq!(result.witnesses.len(), 1);
    let witness = &result.witnesses[0];
    // Primary is first critical signal, supporting are the rest
    assert!(!witness.supporting_signals.is_empty());
}

// ===========================================================================
// 9) Content hash determinism
// ===========================================================================

#[test]
fn enrichment_determinism_certificate_json_identical_across_runs() {
    let fast = make_profile("r1", 100_000, 200_000);
    let slow = make_profile("r2", 1_000_000, 2_000_000);
    let cfg = default_config();
    let cert1 = issue_separation_certificate(&fast, &slow, &cfg, "det-cert", 0, vec![]);
    let cert2 = issue_separation_certificate(&fast, &slow, &cfg, "det-cert", 0, vec![]);
    let json1 = serde_json::to_string(&cert1).unwrap();
    let json2 = serde_json::to_string(&cert2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn enrichment_determinism_bundle_json_identical_across_runs() {
    let profiles = vec![
        make_profile("a", 100_000, 100_000),
        make_profile("b", 1_000_000, 1_000_000),
        make_profile("c", 10_000_000, 10_000_000),
    ];
    let cfg = default_config();
    let b1 = build_certificate_bundle(&profiles, &cfg, 42);
    let b2 = build_certificate_bundle(&profiles, &cfg, 42);
    let j1 = serde_json::to_string(&b1).unwrap();
    let j2 = serde_json::to_string(&b2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn enrichment_determinism_detector_result_json_identical() {
    let cfg = default_config();
    let telemetry = vec![
        make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        make_snapshot("a", "b", 2_000_000, 50_000, 500_000, 1),
    ];
    let r1 = detect_bifurcation_signals(&telemetry, &cfg, 1);
    let r2 = detect_bifurcation_signals(&telemetry, &cfg, 1);
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

// ===========================================================================
// 10) Summary rendering
// ===========================================================================

#[test]
fn enrichment_rendering_detector_summary_contains_schema_version() {
    let result = BifurcationDetectorResult {
        schema_version: BIFURCATION_DETECTOR_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        signals: vec![],
        witnesses: vec![],
        assessment: StabilityAssessment::Stable,
        detection_epoch: 99,
    };
    let summary = render_detector_summary(&result);
    assert!(summary.contains(BIFURCATION_DETECTOR_SCHEMA_VERSION));
    assert!(summary.contains("detection_epoch: 99"));
    assert!(summary.contains("witnesses: 0"));
}

#[test]
fn enrichment_rendering_detector_summary_with_signals_shows_kinds() {
    let cfg = default_config();
    let telemetry = vec![
        make_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        make_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    let summary = render_detector_summary(&result);
    assert!(summary.contains("signal_kinds:"));
    assert!(summary.contains("gain_exceedance"));
}

#[test]
fn enrichment_rendering_bundle_summary_all_fields_present() {
    let profiles = vec![
        make_profile("a", 100_000, 100_000),
        make_profile("b", 1_000_000, 1_000_000),
    ];
    let bundle = build_certificate_bundle(&profiles, &default_config(), 7);
    let summary = render_bundle_summary(&bundle);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("bundle_epoch: 7"));
    assert!(summary.contains("pair_count: 1"));
    assert!(summary.contains("overall_verdict:"));
    assert!(summary.contains("sufficient:"));
    assert!(summary.contains("marginal:"));
    assert!(summary.contains("insufficient:"));
}

// ===========================================================================
// 11) Schema constants
// ===========================================================================

#[test]
fn enrichment_constants_schema_versions_nonempty_and_distinct() {
    let versions = [
        TIMESCALE_CERTIFICATE_SCHEMA_VERSION,
        BIFURCATION_DETECTOR_SCHEMA_VERSION,
        CERTIFICATE_BUNDLE_SCHEMA_VERSION,
        STABILITY_WITNESS_SCHEMA_VERSION,
    ];
    for v in &versions {
        assert!(!v.is_empty());
    }
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn enrichment_constants_default_ratios_ordered() {
    assert!(
        DEFAULT_SUFFICIENT_RATIO_MILLIONTHS > DEFAULT_MARGINAL_RATIO_MILLIONTHS,
        "sufficient threshold must be greater than marginal"
    );
}

// ===========================================================================
// 12) Verdict classification boundaries
// ===========================================================================

#[test]
fn enrichment_verdict_exactly_at_sufficient_threshold() {
    let cfg = default_config();
    // ratio = exactly sufficient threshold => Sufficient
    let obs = 1_000_000i64;
    let write = obs;
    // We need slow/fast ratio to be exactly DEFAULT_SUFFICIENT_RATIO_MILLIONTHS / 1_000_000
    // That's 10x. So slow = 10 * fast.
    let fast = make_profile("f", obs, write);
    let slow = make_profile("s", obs * 10, write * 10);
    let cert = issue_separation_certificate(&fast, &slow, &cfg, "boundary", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn enrichment_verdict_just_below_sufficient_is_marginal() {
    let mut cfg = default_config();
    cfg.sufficient_ratio_millionths = 10_000_000;
    cfg.marginal_ratio_millionths = 3_000_000;
    // 9x separation: below 10x sufficient, above 3x marginal
    let fast = make_profile("f", 1_000_000, 1_000_000);
    let slow = make_profile("s", 9_000_000, 9_000_000);
    let cert = issue_separation_certificate(&fast, &slow, &cfg, "just-below", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Marginal);
}

#[test]
fn enrichment_verdict_just_below_marginal_is_insufficient() {
    let mut cfg = default_config();
    cfg.marginal_ratio_millionths = 3_000_000;
    // 2.5x separation: below 3x marginal
    let fast = make_profile("f", 1_000_000, 1_000_000);
    let slow = make_profile("s", 2_500_000, 2_500_000);
    let cert = issue_separation_certificate(&fast, &slow, &cfg, "insuff", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Insufficient);
}

// ===========================================================================
// 13) Assessment classification
// ===========================================================================

#[test]
fn enrichment_assessment_immediate_action_overrides_warning() {
    let cfg = default_config();
    // Both convergence (warning-level) and gain exceedance (critical)
    let half_marginal = cfg.marginal_ratio_millionths / 2;
    let telemetry = vec![
        make_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        make_snapshot(
            "a",
            "b",
            half_marginal + 100_000,
            50_000,
            cfg.gain_exceedance_threshold_millionths + 1,
            1,
        ),
    ];
    let result = detect_bifurcation_signals(&telemetry, &cfg, 1);
    assert_eq!(
        result.assessment,
        StabilityAssessment::ImmediateActionRequired
    );
}

#[test]
fn enrichment_assessment_detector_result_schema_version_populated() {
    let cfg = default_config();
    let result = detect_bifurcation_signals(&[], &cfg, 42);
    assert_eq!(result.schema_version, BIFURCATION_DETECTOR_SCHEMA_VERSION);
    assert_eq!(result.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
    assert_eq!(result.detection_epoch, 42);
}
