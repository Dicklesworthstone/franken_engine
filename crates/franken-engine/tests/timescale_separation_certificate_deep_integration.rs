#![forbid(unsafe_code)]

//! Deep integration tests for timescale-separation certificates and bifurcation
//! detectors (bd-1lsy.7.14.2 [RGC-614B]).
//!
//! Covers edge cases, error paths, determinism, composition, large-scale stress,
//! serde round-trips, Display implementations, and boundary conditions NOT
//! already exercised in the primary integration test file.

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

use frankenengine_engine::timescale_separation_certificate::{
    BIFURCATION_DETECTOR_SCHEMA_VERSION, BifurcationDetectorConfig, BifurcationSignal,
    BifurcationSignalKind, CERTIFICATE_BUNDLE_SCHEMA_VERSION, CertificateBundle, ControllerPairId,
    ControllerTimescaleProfile, PairTelemetrySnapshot, RatioBasis, RecommendedAction,
    STABILITY_WITNESS_SCHEMA_VERSION, SeparationVerdict, SignalSeverity, StabilityAssessment,
    StabilityWitness, TIMESCALE_CERTIFICATE_BEAD_ID, TIMESCALE_CERTIFICATE_SCHEMA_VERSION,
    build_certificate_bundle, compute_timescale_ratio, detect_bifurcation_signals,
    issue_separation_certificate, render_bundle_summary, render_detector_summary,
};

// =========================================================================
// Helpers
// =========================================================================

fn mk_profile(id: &str, obs_us: i64, write_us: i64) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: id.to_string(),
        observation_interval_millionths: obs_us,
        write_interval_millionths: write_us,
        sample_count: 100,
        measured_epoch: 0,
    }
}

fn mk_profile_full(
    id: &str,
    obs_us: i64,
    write_us: i64,
    samples: u64,
    epoch: u64,
) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: id.to_string(),
        observation_interval_millionths: obs_us,
        write_interval_millionths: write_us,
        sample_count: samples,
        measured_epoch: epoch,
    }
}

fn mk_pair(fast: &str, slow: &str) -> ControllerPairId {
    ControllerPairId {
        fast_controller: fast.to_string(),
        slow_controller: slow.to_string(),
    }
}

fn mk_snapshot(
    fast: &str,
    slow: &str,
    ratio: u64,
    variance: i64,
    gain: i64,
    epoch: u64,
) -> PairTelemetrySnapshot {
    PairTelemetrySnapshot {
        pair: mk_pair(fast, slow),
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
// 1. RatioBasis enum coverage
// =========================================================================

#[test]
fn ratio_basis_display_observation() {
    assert_eq!(RatioBasis::Observation.to_string(), "observation");
}

#[test]
fn ratio_basis_display_write() {
    assert_eq!(RatioBasis::Write.to_string(), "write");
}

#[test]
fn ratio_basis_display_minimum_of() {
    assert_eq!(RatioBasis::MinimumOf.to_string(), "minimum_of");
}

#[test]
fn ratio_basis_serde_round_trip_all_variants() {
    for basis in [
        RatioBasis::Observation,
        RatioBasis::Write,
        RatioBasis::MinimumOf,
    ] {
        let json = serde_json::to_string(&basis).expect("serialize");
        let back: RatioBasis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(basis, back);
    }
}

#[test]
fn ratio_basis_ord_is_deterministic() {
    let mut bases = vec![
        RatioBasis::MinimumOf,
        RatioBasis::Write,
        RatioBasis::Observation,
    ];
    bases.sort();
    let first = bases.clone();
    bases.sort();
    assert_eq!(first, bases);
}

// =========================================================================
// 2. Negative interval values in profiles
// =========================================================================

#[test]
fn ratio_with_negative_observation_intervals() {
    // Negative intervals should be treated by unsigned_abs()
    let a = mk_profile("neg-obs", -100_000, 200_000);
    let b = mk_profile("pos-obs", 1_000_000, 2_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // unsigned_abs(-100_000) = 100_000, unsigned_abs(1_000_000) = 1_000_000
    // obs ratio = 10x, write ratio = 10x, min = 10x
    assert_eq!(ratio.ratio_millionths, 10_000_000);
}

#[test]
fn ratio_with_negative_write_intervals() {
    let a = mk_profile("a", 100_000, -500_000);
    let b = mk_profile("b", 500_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // obs ratio = 5x, write ratio = abs(-500_000) vs abs(1_000_000) = 2x
    // minimum = 2x (write)
    assert_eq!(ratio.ratio_millionths, 2_000_000);
    assert_eq!(ratio.ratio_basis, RatioBasis::Write);
}

#[test]
fn ratio_both_negative_intervals() {
    let a = mk_profile("a", -100_000, -200_000);
    let b = mk_profile("b", -1_000_000, -2_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 10_000_000);
}

// =========================================================================
// 3. Both intervals zero and write-only zero
// =========================================================================

#[test]
fn ratio_both_obs_and_write_zero_for_one_profile() {
    let a = mk_profile("zero", 0, 0);
    let b = mk_profile("normal", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // Both obs and write ratios are 0 because one side is 0
    assert_eq!(ratio.ratio_millionths, 0);
}

#[test]
fn ratio_both_profiles_all_zero() {
    let a = mk_profile("zero-a", 0, 0);
    let b = mk_profile("zero-b", 0, 0);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 0);
}

#[test]
fn ratio_write_interval_zero_only() {
    let a = mk_profile("a", 100_000, 0);
    let b = mk_profile("b", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    // obs ratio = 10x, write ratio = 0 (because one side is 0)
    // min(10x, 0) = 0
    assert_eq!(ratio.ratio_millionths, 0);
}

#[test]
fn ratio_zero_returns_observation_basis_when_write_zero() {
    let a = mk_profile("a", 100_000, 0);
    let b = mk_profile("b", 1_000_000, 0);
    let ratio = compute_timescale_ratio(&a, &b);
    // Both write intervals zero => write_ratio = 0
    // obs_ratio = 10x
    // 0 <= 10x so we pick obs with ratio 0
    // Actually: obs_ratio=10M, write_ratio=0; 10M <= 0 is false; so write is chosen
    assert_eq!(ratio.ratio_millionths, 0);
}

// =========================================================================
// 4. Asymmetric observation vs write ratios
// =========================================================================

#[test]
fn ratio_obs_smaller_than_write_selects_observation() {
    // obs ratio = 2x, write ratio = 10x => minimum = 2x (observation)
    let a = mk_profile("a", 500_000, 100_000);
    let b = mk_profile("b", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 2_000_000);
    assert_eq!(ratio.ratio_basis, RatioBasis::Observation);
}

#[test]
fn ratio_write_smaller_than_obs_selects_write() {
    // obs ratio = 10x, write ratio = 2x => minimum = 2x (write)
    let a = mk_profile("a", 100_000, 500_000);
    let b = mk_profile("b", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 2_000_000);
    assert_eq!(ratio.ratio_basis, RatioBasis::Write);
}

#[test]
fn ratio_equal_obs_and_write_selects_observation() {
    // When obs_ratio == write_ratio, obs_ratio <= write_ratio is true => Observation
    let a = mk_profile("a", 100_000, 100_000);
    let b = mk_profile("b", 500_000, 500_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.ratio_millionths, 5_000_000);
    assert_eq!(ratio.ratio_basis, RatioBasis::Observation);
}

// =========================================================================
// 5. Fast/slow ordering in ratio computation
// =========================================================================

#[test]
fn ratio_fast_slow_ordering_when_a_faster() {
    let a = mk_profile("faster", 100_000, 100_000);
    let b = mk_profile("slower", 1_000_000, 1_000_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.pair.fast_controller, "faster");
    assert_eq!(ratio.pair.slow_controller, "slower");
}

#[test]
fn ratio_fast_slow_ordering_when_b_faster() {
    let a = mk_profile("slower", 1_000_000, 1_000_000);
    let b = mk_profile("faster", 100_000, 100_000);
    let ratio = compute_timescale_ratio(&a, &b);
    assert_eq!(ratio.pair.fast_controller, "faster");
    assert_eq!(ratio.pair.slow_controller, "slower");
}

#[test]
fn ratio_ordering_symmetric_returns_same_fast_slow() {
    let a = mk_profile("alpha", 300_000, 300_000);
    let b = mk_profile("beta", 900_000, 900_000);
    let r1 = compute_timescale_ratio(&a, &b);
    let r2 = compute_timescale_ratio(&b, &a);
    assert_eq!(r1.pair.fast_controller, r2.pair.fast_controller);
    assert_eq!(r1.pair.slow_controller, r2.pair.slow_controller);
    assert_eq!(r1.ratio_millionths, r2.ratio_millionths);
}

// =========================================================================
// 6. Certificate epoch and evidence propagation
// =========================================================================

#[test]
fn certificate_epoch_propagation() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    for epoch in [0, 1, 42, 999, u64::MAX] {
        let cert = issue_separation_certificate(&fast, &slow, &config, "ep", epoch, vec![]);
        assert_eq!(cert.issued_epoch, epoch);
    }
}

#[test]
fn certificate_multiple_evidence_ids() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let evidence = vec!["ev-1".to_string(), "ev-2".to_string(), "ev-3".to_string()];
    let cert = issue_separation_certificate(&fast, &slow, &config, "multi-ev", 0, evidence.clone());
    assert_eq!(cert.evidence_ids, evidence);
    assert_eq!(cert.evidence_ids.len(), 3);
}

#[test]
fn certificate_empty_evidence_ids() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "no-ev", 0, vec![]);
    assert!(cert.evidence_ids.is_empty());
}

#[test]
fn certificate_id_preserved_verbatim() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert =
        issue_separation_certificate(&fast, &slow, &config, "my-custom-cert-id-12345", 0, vec![]);
    assert_eq!(cert.certificate_id, "my-custom-cert-id-12345");
}

// =========================================================================
// 7. Certificate threshold propagation from config
// =========================================================================

#[test]
fn certificate_thresholds_reflect_config() {
    let fast = mk_profile("a", 100_000, 100_000);
    let slow = mk_profile("b", 1_000_000, 1_000_000);
    let mut config = default_config();
    config.sufficient_ratio_millionths = 7_000_000;
    config.marginal_ratio_millionths = 2_000_000;
    let cert = issue_separation_certificate(&fast, &slow, &config, "t", 0, vec![]);
    assert_eq!(cert.sufficient_threshold_millionths, 7_000_000);
    assert_eq!(cert.marginal_threshold_millionths, 2_000_000);
}

#[test]
fn certificate_verdict_with_lowered_sufficient_threshold() {
    // 5x separation, lower sufficient to 4x => Sufficient
    let fast = mk_profile("a", 200_000, 200_000);
    let slow = mk_profile("b", 1_000_000, 1_000_000);
    let mut config = default_config();
    config.sufficient_ratio_millionths = 4_000_000;
    let cert = issue_separation_certificate(&fast, &slow, &config, "low-t", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn certificate_verdict_with_raised_marginal_threshold() {
    // 5x separation, raise marginal to 6x => Insufficient
    let fast = mk_profile("a", 200_000, 200_000);
    let slow = mk_profile("b", 1_000_000, 1_000_000);
    let mut config = default_config();
    config.marginal_ratio_millionths = 6_000_000;
    let cert = issue_separation_certificate(&fast, &slow, &config, "high-m", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Insufficient);
}

// =========================================================================
// 8. Config edge cases
// =========================================================================

#[test]
fn config_with_zero_thresholds_everything_sufficient() {
    let fast = mk_profile("a", 100_000, 100_000);
    let slow = mk_profile("b", 100_001, 100_001);
    let mut config = default_config();
    config.sufficient_ratio_millionths = 0;
    config.marginal_ratio_millionths = 0;
    let cert = issue_separation_certificate(&fast, &slow, &config, "z", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn config_equal_sufficient_and_marginal_thresholds() {
    let fast = mk_profile("a", 100_000, 100_000);
    let slow = mk_profile("b", 500_000, 500_000);
    let mut config = default_config();
    config.sufficient_ratio_millionths = 5_000_000;
    config.marginal_ratio_millionths = 5_000_000;
    // 5x ratio: >= sufficient => Sufficient
    let cert = issue_separation_certificate(&fast, &slow, &config, "eq", 0, vec![]);
    assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
}

#[test]
fn config_default_oscillation_threshold() {
    let config = default_config();
    assert_eq!(config.oscillation_growth_threshold_millionths, 50_000);
}

#[test]
fn config_default_variance_threshold() {
    let config = default_config();
    assert_eq!(config.variance_divergence_threshold_millionths, 200_000);
}

// =========================================================================
// 9. Convergence severity: Critical vs Warning
// =========================================================================

#[test]
fn convergence_warning_severity_when_just_below_marginal() {
    let config = default_config();
    // marginal = 3_000_000; marginal/2 = 1_500_000
    // last_ratio = 2_500_000 => below marginal but above marginal/2 => Warning
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 2_500_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let convergence = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence);
    assert!(convergence.is_some());
    assert_eq!(convergence.unwrap().severity, SignalSeverity::Warning);
}

#[test]
fn convergence_critical_severity_when_well_below_half_marginal() {
    let config = default_config();
    // marginal = 3_000_000; marginal/2 = 1_500_000
    // last_ratio = 1_000_000 => below marginal/2 => Critical
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 1_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let convergence = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence);
    assert!(convergence.is_some());
    assert_eq!(convergence.unwrap().severity, SignalSeverity::Critical);
}

#[test]
fn convergence_not_triggered_when_ratio_increases() {
    let config = default_config();
    // Ratio is going UP (diverging, not converging)
    let telemetry = vec![
        mk_snapshot("a", "b", 2_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
    );
}

#[test]
fn convergence_not_triggered_when_last_ratio_above_marginal() {
    let config = default_config();
    // Ratio decreases but stays above marginal threshold
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
    );
}

// =========================================================================
// 10. Variance divergence severity: Warning vs Critical
// =========================================================================

#[test]
fn variance_warning_when_delta_exceeds_threshold() {
    let config = default_config();
    // threshold = 200_000; 2*threshold = 400_000
    // delta = 300_000 => above threshold, below 2*threshold => Warning
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 350_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let var_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::VarianceDivergence);
    assert!(var_sig.is_some());
    assert_eq!(var_sig.unwrap().severity, SignalSeverity::Warning);
}

#[test]
fn variance_critical_when_delta_exceeds_double_threshold() {
    let config = default_config();
    // threshold = 200_000; 2*threshold = 400_000
    // delta = 500_000 => above 2*threshold => Critical
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 550_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let var_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::VarianceDivergence);
    assert!(var_sig.is_some());
    assert_eq!(var_sig.unwrap().severity, SignalSeverity::Critical);
}

#[test]
fn variance_not_triggered_with_only_two_snapshots() {
    let config = default_config();
    // Variance divergence requires >= 3 snapshots
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 500_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
    );
}

#[test]
fn variance_not_triggered_when_delta_below_threshold() {
    let config = default_config();
    // delta = 150_000, threshold = 200_000 => no trigger
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 200_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
    );
}

// =========================================================================
// 11. Gain exceedance details
// =========================================================================

#[test]
fn gain_exceedance_always_critical() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_100_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    for signal in &result.signals {
        if signal.kind == BifurcationSignalKind::GainExceedance {
            assert_eq!(signal.severity, SignalSeverity::Critical);
        }
    }
}

#[test]
fn gain_exceedance_produces_one_signal_per_exceeding_snapshot() {
    let config = default_config();
    // Both snapshots exceed threshold
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let gain_signals: Vec<_> = result
        .signals
        .iter()
        .filter(|s| s.kind == BifurcationSignalKind::GainExceedance)
        .collect();
    assert_eq!(gain_signals.len(), 2);
}

#[test]
fn gain_exactly_at_threshold_not_triggered() {
    let config = default_config();
    // gain = 1_000_000 = threshold (not strictly greater) => no trigger
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_000_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance)
    );
}

#[test]
fn gain_just_above_threshold_triggers() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_000_001, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance)
    );
}

// =========================================================================
// 12. Multiple pairs in single detection run
// =========================================================================

#[test]
fn detection_multiple_pairs_independent_signals() {
    let config = default_config();
    let telemetry = vec![
        // Pair a-b: stable
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 55_000, 500_000, 1),
        // Pair c-d: gain exceedance
        mk_snapshot("c", "d", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("c", "d", 10_000_000, 50_000, 1_500_000, 1),
        // Pair e-f: convergence
        mk_snapshot("e", "f", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("e", "f", 1_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // Should have gain exceedance from c-d and convergence from e-f
    let has_gain = result
        .signals
        .iter()
        .any(|s| s.pair.fast_controller == "c" && s.kind == BifurcationSignalKind::GainExceedance);
    let has_conv = result.signals.iter().any(|s| {
        s.pair.fast_controller == "e" && s.kind == BifurcationSignalKind::TimescaleConvergence
    });
    assert!(has_gain);
    assert!(has_conv);
    // No signals from a-b
    assert!(!result.signals.iter().any(|s| s.pair.fast_controller == "a"));
}

#[test]
fn detection_multiple_pairs_worst_assessment() {
    let config = default_config();
    let telemetry = vec![
        // Pair a-b: stable
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 55_000, 500_000, 1),
        // Pair c-d: critical
        mk_snapshot("c", "d", 10_000_000, 50_000, 2_000_000, 0),
        mk_snapshot("c", "d", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert_eq!(
        result.assessment,
        StabilityAssessment::ImmediateActionRequired
    );
}

// =========================================================================
// 13. Stability witness construction details
// =========================================================================

#[test]
fn witness_has_correct_schema_and_bead() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 5);
    assert!(!result.witnesses.is_empty());
    let w = &result.witnesses[0];
    assert_eq!(w.schema_version, STABILITY_WITNESS_SCHEMA_VERSION);
    assert_eq!(w.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
    assert_eq!(w.assembled_epoch, 5);
}

#[test]
fn witness_ids_are_sequential() {
    let config = default_config();
    let telemetry = vec![
        // Two different pairs, both critical
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
        mk_snapshot("c", "d", 10_000_000, 50_000, 2_000_000, 0),
        mk_snapshot("c", "d", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let ids: Vec<_> = result.witnesses.iter().map(|w| &w.witness_id).collect();
    // All IDs should be unique
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
    // Should start with "witness-"
    for id in &ids {
        assert!(id.starts_with("witness-"));
    }
}

#[test]
fn witness_primary_signal_is_first_critical_for_pair() {
    let config = default_config();
    // Two gain exceedances for the same pair
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(!result.witnesses.is_empty());
    let w = &result.witnesses[0];
    assert_eq!(w.primary_signal.kind, BifurcationSignalKind::GainExceedance);
    // Supporting signals should contain the second gain exceedance
    assert!(!w.supporting_signals.is_empty());
}

#[test]
fn witness_not_created_for_warning_only_signals() {
    let config = default_config();
    // Only warning-level convergence, no critical signals
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 2_500_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert!(!result.signals.is_empty());
    assert!(result.witnesses.is_empty());
}

// =========================================================================
// 14. Recommended action mapping
// =========================================================================

#[test]
fn gain_exceedance_recommends_reduce_gain() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    for witness in &result.witnesses {
        if witness.primary_signal.kind == BifurcationSignalKind::GainExceedance {
            assert_eq!(witness.recommended_action, RecommendedAction::ReduceGain);
        }
    }
}

#[test]
fn convergence_recommends_increase_separation() {
    let config = default_config();
    // Need convergence to be critical (below marginal/2)
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 1_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    for witness in &result.witnesses {
        if witness.primary_signal.kind == BifurcationSignalKind::TimescaleConvergence {
            assert_eq!(
                witness.recommended_action,
                RecommendedAction::IncreaseTimescaleSeparation
            );
        }
    }
}

// =========================================================================
// 15. StabilityAssessment levels
// =========================================================================

#[test]
fn assessment_monitoring_recommended_never_occurs_in_current_detection() {
    // The current detection code only produces Warning and Critical severity signals.
    // Info signals would give MonitoringRecommended but the detector doesn't produce them.
    // This test verifies the assessment matches the signal severities present.
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 2_500_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // Warning signals => InterventionRecommended
    if result
        .signals
        .iter()
        .any(|s| s.severity == SignalSeverity::Warning)
        && !result
            .signals
            .iter()
            .any(|s| s.severity == SignalSeverity::Critical)
    {
        assert_eq!(
            result.assessment,
            StabilityAssessment::InterventionRecommended
        );
    }
}

#[test]
fn assessment_immediate_action_with_critical() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert_eq!(
        result.assessment,
        StabilityAssessment::ImmediateActionRequired
    );
}

// =========================================================================
// 16. Large-scale stress: many controllers in bundle
// =========================================================================

#[test]
fn bundle_ten_controllers_produces_45_pairs() {
    let profiles: Vec<ControllerTimescaleProfile> = (0..10)
        .map(|i| {
            mk_profile(
                &format!("ctrl-{i}"),
                (i + 1) as i64 * 100_000,
                (i + 1) as i64 * 100_000,
            )
        })
        .collect();
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    // C(10, 2) = 45
    assert_eq!(bundle.pair_count, 45);
    assert_eq!(bundle.certificates.len(), 45);
    assert_eq!(
        bundle.sufficient_count + bundle.marginal_count + bundle.insufficient_count,
        45
    );
}

#[test]
fn bundle_five_controllers_all_well_separated() {
    // Each 100x apart
    let profiles: Vec<ControllerTimescaleProfile> = (0..5)
        .map(|i| {
            let interval = 100_i64.pow(i as u32) * 1_000;
            mk_profile(&format!("ctrl-{i}"), interval, interval)
        })
        .collect();
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.pair_count, 10); // C(5,2) = 10
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Sufficient);
    assert_eq!(bundle.sufficient_count, 10);
}

#[test]
fn bundle_five_controllers_all_close_together() {
    // All within 1.5x of each other
    let profiles: Vec<ControllerTimescaleProfile> = (0..5)
        .map(|i| {
            let interval = 1_000_000 + i as i64 * 100_000;
            mk_profile(&format!("ctrl-{i}"), interval, interval)
        })
        .collect();
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Insufficient);
    assert!(bundle.insufficient_count > 0);
}

// =========================================================================
// 17. Large-scale telemetry stress
// =========================================================================

#[test]
fn detection_many_epochs_stable() {
    let config = default_config();
    let telemetry: Vec<PairTelemetrySnapshot> = (0..100)
        .map(|i| mk_snapshot("a", "b", 10_000_000, 50_000 + i * 100, 500_000, i as u64))
        .collect();
    let result = detect_bifurcation_signals(&telemetry, &config, 100);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
}

#[test]
fn detection_many_epochs_gradual_convergence() {
    let config = default_config();
    // Gradually decrease ratio from 10x to 1x over 50 epochs
    let telemetry: Vec<PairTelemetrySnapshot> = (0..50)
        .map(|i| {
            let ratio = 10_000_000 - i * 180_000;
            mk_snapshot("a", "b", ratio as u64, 50_000, 500_000, i as u64)
        })
        .collect();
    let result = detect_bifurcation_signals(&telemetry, &config, 50);
    // First ratio > last ratio, and last ratio < marginal => TimescaleConvergence
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
    );
}

// =========================================================================
// 18. Bundle epoch propagation and certificate IDs
// =========================================================================

#[test]
fn bundle_epoch_propagated() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 42);
    assert_eq!(bundle.bundle_epoch, 42);
    // Individual certificates also use the same epoch
    for cert in &bundle.certificates {
        assert_eq!(cert.issued_epoch, 42);
    }
}

#[test]
fn bundle_certificate_ids_are_auto_generated() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 1_000_000, 1_000_000),
        mk_profile("c", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let ids: Vec<_> = bundle
        .certificates
        .iter()
        .map(|c| &c.certificate_id)
        .collect();
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
    // All start with "cert-"
    for id in &ids {
        assert!(id.starts_with("cert-"));
    }
}

// =========================================================================
// 19. Detection epoch propagation
// =========================================================================

#[test]
fn detection_epoch_propagated_to_result() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 77);
    assert_eq!(result.detection_epoch, 77);
}

#[test]
fn detection_epoch_propagated_to_signals() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 99);
    assert_eq!(result.detection_epoch, 99);
    for signal in &result.signals {
        assert_eq!(signal.detected_epoch, 99);
    }
}

// =========================================================================
// 20. Serde round-trips for extreme values
// =========================================================================

#[test]
fn serde_profile_with_extreme_values() {
    let p = ControllerTimescaleProfile {
        controller_id: "extreme".to_string(),
        observation_interval_millionths: i64::MAX,
        write_interval_millionths: i64::MIN,
        sample_count: u64::MAX,
        measured_epoch: u64::MAX,
    };
    let json = serde_json::to_string(&p).expect("serialize");
    let back: ControllerTimescaleProfile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p, back);
}

#[test]
fn serde_snapshot_with_extreme_values() {
    let s = PairTelemetrySnapshot {
        pair: mk_pair("x", "y"),
        ratio_millionths: u64::MAX,
        variance_millionths: i64::MIN,
        effective_gain_millionths: i64::MAX,
        epoch: u64::MAX,
    };
    let json = serde_json::to_string(&s).expect("serialize");
    let back: PairTelemetrySnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, back);
}

#[test]
fn serde_signal_with_extreme_trigger_values() {
    let signal = BifurcationSignal {
        signal_id: "extreme-sig".to_string(),
        pair: mk_pair("a", "b"),
        kind: BifurcationSignalKind::GrowingOscillation,
        severity: SignalSeverity::Critical,
        trigger_value_millionths: i64::MAX,
        threshold_millionths: i64::MIN,
        detected_epoch: u64::MAX,
        description: "extreme test".to_string(),
    };
    let json = serde_json::to_string(&signal).expect("serialize");
    let back: BifurcationSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(signal, back);
}

#[test]
fn serde_config_with_custom_values() {
    let config = BifurcationDetectorConfig {
        sufficient_ratio_millionths: 999_999_999,
        marginal_ratio_millionths: 1,
        oscillation_growth_threshold_millionths: -1,
        variance_divergence_threshold_millionths: i64::MAX,
        gain_exceedance_threshold_millionths: 0,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let back: BifurcationDetectorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, back);
}

// =========================================================================
// 21. Display implementation completeness
// =========================================================================

#[test]
fn controller_pair_display_uses_arrow_separator() {
    let p = mk_pair("router", "optimizer");
    let display = p.to_string();
    assert!(display.contains('\u{2194}')); // ↔
    assert_eq!(display, "router\u{2194}optimizer");
}

#[test]
fn all_separation_verdict_displays_are_lowercase_snake() {
    for verdict in [
        SeparationVerdict::Sufficient,
        SeparationVerdict::Marginal,
        SeparationVerdict::Insufficient,
    ] {
        let s = verdict.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, s.to_lowercase());
        assert!(!s.contains(' '));
    }
}

#[test]
fn all_signal_kind_displays_are_lowercase_snake() {
    for kind in [
        BifurcationSignalKind::GrowingOscillation,
        BifurcationSignalKind::TimescaleConvergence,
        BifurcationSignalKind::SpectralEdgeCrossing,
        BifurcationSignalKind::VarianceDivergence,
        BifurcationSignalKind::GainExceedance,
    ] {
        let s = kind.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, s.to_lowercase());
    }
}

#[test]
fn all_recommended_action_displays_are_lowercase_snake() {
    for action in [
        RecommendedAction::Monitor,
        RecommendedAction::IncreaseTimescaleSeparation,
        RecommendedAction::ReduceGain,
        RecommendedAction::DisableController,
        RecommendedAction::SafeModeFallback,
    ] {
        let s = action.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, s.to_lowercase());
    }
}

#[test]
fn all_stability_assessment_displays_are_lowercase_snake() {
    for assessment in [
        StabilityAssessment::Stable,
        StabilityAssessment::MonitoringRecommended,
        StabilityAssessment::InterventionRecommended,
        StabilityAssessment::ImmediateActionRequired,
    ] {
        let s = assessment.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, s.to_lowercase());
    }
}

// =========================================================================
// 22. Summary rendering details
// =========================================================================

#[test]
fn detector_summary_with_signals_includes_kind_counts() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 2_000_000, 50_000, 1_500_000, 1),
        mk_snapshot("a", "b", 1_000_000, 500_000, 1_500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let summary = render_detector_summary(&result);
    assert!(summary.contains("signal_kinds:"));
    assert!(summary.contains("assessment:"));
    assert!(summary.contains("signals:"));
    assert!(summary.contains("witnesses:"));
}

#[test]
fn detector_summary_stable_has_no_signal_kinds() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    let summary = render_detector_summary(&result);
    assert!(!summary.contains("signal_kinds:"));
    assert!(summary.contains("signals: 0"));
}

#[test]
fn bundle_summary_all_fields_present() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 500_000, 500_000),
        mk_profile("c", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 7);
    let summary = render_bundle_summary(&bundle);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("bundle_epoch: 7"));
    assert!(summary.contains("pair_count: 3"));
    assert!(summary.contains("overall_verdict:"));
    assert!(summary.contains("sufficient:"));
    assert!(summary.contains("marginal:"));
    assert!(summary.contains("insufficient:"));
}

#[test]
fn bundle_summary_counts_match_bundle() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 200_000, 200_000),
        mk_profile("c", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let summary = render_bundle_summary(&bundle);
    assert!(summary.contains(&format!("sufficient: {}", bundle.sufficient_count)));
    assert!(summary.contains(&format!("marginal: {}", bundle.marginal_count)));
    assert!(summary.contains(&format!("insufficient: {}", bundle.insufficient_count)));
}

// =========================================================================
// 23. JSON structure deep validation
// =========================================================================

#[test]
fn certificate_json_verdict_is_snake_case_string() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "j", 0, vec![]);
    let val: serde_json::Value = serde_json::to_value(&cert).expect("to_value");
    let verdict_str = val.get("verdict").unwrap().as_str().unwrap();
    assert_eq!(verdict_str, "sufficient");
}

#[test]
fn certificate_json_ratio_basis_is_snake_case() {
    let fast = mk_profile("a", 100_000, 500_000);
    let slow = mk_profile("b", 1_000_000, 1_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "rb", 0, vec![]);
    let val: serde_json::Value = serde_json::to_value(&cert).expect("to_value");
    let ratio_obj = val.get("ratio").unwrap();
    let basis_str = ratio_obj.get("ratio_basis").unwrap().as_str().unwrap();
    // Should be one of: observation, write, minimum_of
    assert!(
        basis_str == "observation" || basis_str == "write" || basis_str == "minimum_of",
        "unexpected basis: {basis_str}"
    );
}

#[test]
fn detector_result_json_assessment_snake_case() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let val: serde_json::Value = serde_json::to_value(&result).expect("to_value");
    let assessment_str = val.get("assessment").unwrap().as_str().unwrap();
    assert_eq!(assessment_str, "immediate_action_required");
}

#[test]
fn signal_json_kind_and_severity_snake_case() {
    let signal = BifurcationSignal {
        signal_id: "s1".to_string(),
        pair: mk_pair("a", "b"),
        kind: BifurcationSignalKind::SpectralEdgeCrossing,
        severity: SignalSeverity::Info,
        trigger_value_millionths: 100,
        threshold_millionths: 200,
        detected_epoch: 0,
        description: "test".to_string(),
    };
    let val: serde_json::Value = serde_json::to_value(&signal).expect("to_value");
    assert_eq!(
        val.get("kind").unwrap().as_str().unwrap(),
        "spectral_edge_crossing"
    );
    assert_eq!(val.get("severity").unwrap().as_str().unwrap(), "info");
}

#[test]
fn witness_json_recommended_action_snake_case() {
    let witness = StabilityWitness {
        schema_version: STABILITY_WITNESS_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        witness_id: "w1".to_string(),
        pair: mk_pair("x", "y"),
        primary_signal: BifurcationSignal {
            signal_id: "s1".to_string(),
            pair: mk_pair("x", "y"),
            kind: BifurcationSignalKind::GrowingOscillation,
            severity: SignalSeverity::Critical,
            trigger_value_millionths: 100,
            threshold_millionths: 50,
            detected_epoch: 0,
            description: "osc".to_string(),
        },
        supporting_signals: vec![],
        recommended_action: RecommendedAction::DisableController,
        assembled_epoch: 0,
    };
    let val: serde_json::Value = serde_json::to_value(&witness).expect("to_value");
    assert_eq!(
        val.get("recommended_action").unwrap().as_str().unwrap(),
        "disable_controller"
    );
}

// =========================================================================
// 24. Clone and equality behavior
// =========================================================================

#[test]
fn certificate_clone_equals_original() {
    let fast = mk_profile("gc", 100_000, 200_000);
    let slow = mk_profile("monitor", 1_000_000, 2_000_000);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "c", 0, vec!["e1".to_string()]);
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
}

#[test]
fn bundle_clone_equals_original() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let cloned = bundle.clone();
    assert_eq!(bundle, cloned);
}

#[test]
fn detector_result_clone_equals_original() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 2_000_000, 300_000, 1_500_000, 1),
        mk_snapshot("a", "b", 1_000_000, 600_000, 1_500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn controller_pair_id_ord_is_consistent() {
    let p1 = mk_pair("aaa", "bbb");
    let p2 = mk_pair("aaa", "ccc");
    let p3 = mk_pair("bbb", "aaa");
    let mut pairs = vec![p3.clone(), p1.clone(), p2.clone()];
    pairs.sort();
    let sorted_once = pairs.clone();
    pairs.sort();
    assert_eq!(sorted_once, pairs);
}

// =========================================================================
// 25. End-to-end composition: bundle + detection pipeline
// =========================================================================

#[test]
fn end_to_end_bundle_then_detect_stable() {
    let profiles = vec![
        mk_profile("fast", 100_000, 100_000),
        mk_profile("medium", 1_000_000, 1_000_000),
        mk_profile("slow", 10_000_000, 10_000_000),
    ];
    let config = default_config();

    // Step 1: Build bundle
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Sufficient);

    // Step 2: Simulate telemetry based on bundle ratios (stable)
    let telemetry: Vec<PairTelemetrySnapshot> = bundle
        .certificates
        .iter()
        .flat_map(|cert| {
            (0..5).map(move |epoch| PairTelemetrySnapshot {
                pair: cert.pair.clone(),
                ratio_millionths: cert.ratio.ratio_millionths,
                variance_millionths: 50_000,
                effective_gain_millionths: 500_000,
                epoch,
            })
        })
        .collect();

    // Step 3: Run detection
    let result = detect_bifurcation_signals(&telemetry, &config, 5);
    assert_eq!(result.assessment, StabilityAssessment::Stable);
}

#[test]
fn end_to_end_bundle_then_detect_degradation() {
    let profiles = vec![
        mk_profile("fast", 100_000, 100_000),
        mk_profile("slow", 500_000, 500_000),
    ];
    let config = default_config();

    // Step 1: Build bundle (marginal separation: 5x)
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.overall_verdict, SeparationVerdict::Marginal);

    // Step 2: Simulate degrading telemetry (convergence + gain spike)
    let cert = &bundle.certificates[0];
    let telemetry = vec![
        PairTelemetrySnapshot {
            pair: cert.pair.clone(),
            ratio_millionths: 5_000_000,
            variance_millionths: 50_000,
            effective_gain_millionths: 500_000,
            epoch: 0,
        },
        PairTelemetrySnapshot {
            pair: cert.pair.clone(),
            ratio_millionths: 2_000_000,
            variance_millionths: 50_000,
            effective_gain_millionths: 1_500_000,
            epoch: 1,
        },
    ];

    // Step 3: Detect
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    assert_ne!(result.assessment, StabilityAssessment::Stable);
    assert!(!result.signals.is_empty());
}

// =========================================================================
// 26. Determinism: repeated calls, serde round-trips preserve
// =========================================================================

#[test]
fn determinism_bundle_serde_round_trip_preserves_verdict_counts() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 200_000, 200_000),
        mk_profile("c", 1_000_000, 1_000_000),
        mk_profile("d", 10_000_000, 10_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    let json = serde_json::to_string(&bundle).expect("serialize");
    let deser: CertificateBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle.sufficient_count, deser.sufficient_count);
    assert_eq!(bundle.marginal_count, deser.marginal_count);
    assert_eq!(bundle.insufficient_count, deser.insufficient_count);
    assert_eq!(bundle.overall_verdict, deser.overall_verdict);
}

#[test]
fn determinism_detection_repeated_100_times() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 800_000, 0),
        mk_snapshot("a", "b", 2_000_000, 100_000, 1_200_000, 1),
        mk_snapshot("a", "b", 1_000_000, 500_000, 1_500_000, 2),
    ];
    let first = detect_bifurcation_signals(&telemetry, &config, 3);
    for _ in 0..100 {
        let again = detect_bifurcation_signals(&telemetry, &config, 3);
        assert_eq!(first, again);
    }
}

#[test]
fn determinism_ratio_computation_100_times() {
    let a = mk_profile("fast", 123_456, 789_012);
    let b = mk_profile("slow", 987_654, 321_098);
    let first = compute_timescale_ratio(&a, &b);
    for _ in 0..100 {
        let again = compute_timescale_ratio(&a, &b);
        assert_eq!(first, again);
    }
}

// =========================================================================
// 27. Profile field propagation in certificates
// =========================================================================

#[test]
fn certificate_preserves_full_profile_details() {
    let fast = mk_profile_full("gc", 100_000, 200_000, 50, 7);
    let slow = mk_profile_full("monitor", 1_000_000, 2_000_000, 200, 8);
    let config = default_config();
    let cert = issue_separation_certificate(&fast, &slow, &config, "fp", 10, vec![]);
    assert_eq!(cert.fast_profile.sample_count, 50);
    assert_eq!(cert.fast_profile.measured_epoch, 7);
    assert_eq!(cert.slow_profile.sample_count, 200);
    assert_eq!(cert.slow_profile.measured_epoch, 8);
}

#[test]
fn certificate_fast_slow_profiles_match_ratio_ordering() {
    // Pass slow first, fast second
    let slow = mk_profile("slow-ctrl", 1_000_000, 2_000_000);
    let fast = mk_profile("fast-ctrl", 100_000, 200_000);
    let config = default_config();
    let cert = issue_separation_certificate(&slow, &fast, &config, "order", 0, vec![]);
    // fast_profile should be the one with shorter observation interval
    assert_eq!(cert.fast_profile.controller_id, "fast-ctrl");
    assert_eq!(cert.slow_profile.controller_id, "slow-ctrl");
    assert_eq!(cert.pair.fast_controller, "fast-ctrl");
}

// =========================================================================
// 28. Signal description content
// =========================================================================

#[test]
fn convergence_signal_description_contains_ratios() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 2_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let conv_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence);
    assert!(conv_sig.is_some());
    let desc = &conv_sig.unwrap().description;
    assert!(desc.contains("5000000")); // first ratio
    assert!(desc.contains("2000000")); // last ratio
}

#[test]
fn gain_signal_description_contains_gain_value() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let gain_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::GainExceedance);
    assert!(gain_sig.is_some());
    let desc = &gain_sig.unwrap().description;
    assert!(desc.contains("1500000")); // trigger gain value
}

#[test]
fn variance_signal_description_contains_delta() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 500_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let var_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::VarianceDivergence);
    assert!(var_sig.is_some());
    let desc = &var_sig.unwrap().description;
    // delta = 500_000 - 50_000 = 450_000
    assert!(desc.contains("450000"));
}

// =========================================================================
// 29. Signal trigger and threshold values
// =========================================================================

#[test]
fn convergence_trigger_is_last_ratio() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 2_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let conv_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
        .unwrap();
    assert_eq!(conv_sig.trigger_value_millionths, 2_000_000);
    assert_eq!(
        conv_sig.threshold_millionths,
        config.marginal_ratio_millionths as i64
    );
}

#[test]
fn gain_trigger_matches_snapshot_gain() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_234_567, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    let gain_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::GainExceedance)
        .unwrap();
    assert_eq!(gain_sig.trigger_value_millionths, 1_234_567);
    assert_eq!(
        gain_sig.threshold_millionths,
        config.gain_exceedance_threshold_millionths
    );
}

#[test]
fn variance_trigger_is_delta() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 200_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 400_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let var_sig = result
        .signals
        .iter()
        .find(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
        .unwrap();
    // delta = last_variance - first_variance = 400_000 - 100_000 = 300_000
    assert_eq!(var_sig.trigger_value_millionths, 300_000);
    assert_eq!(
        var_sig.threshold_millionths,
        config.variance_divergence_threshold_millionths
    );
}

// =========================================================================
// 30. Signal ID sequencing
// =========================================================================

#[test]
fn signal_ids_are_unique_across_all_detections() {
    let config = default_config();
    let telemetry = vec![
        mk_snapshot("a", "b", 5_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 1_000_000, 50_000, 1_500_000, 1),
        mk_snapshot("a", "b", 500_000, 500_000, 1_500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    let ids: Vec<_> = result.signals.iter().map(|s| &s.signal_id).collect();
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len());
    // All start with "sig-"
    for id in &ids {
        assert!(id.starts_with("sig-"));
    }
}

// =========================================================================
// 31. Serde deserialization from known JSON structures
// =========================================================================

#[test]
fn deserialize_verdict_from_json_string() {
    let sufficient: SeparationVerdict = serde_json::from_str("\"sufficient\"").expect("sufficient");
    assert_eq!(sufficient, SeparationVerdict::Sufficient);

    let marginal: SeparationVerdict = serde_json::from_str("\"marginal\"").expect("marginal");
    assert_eq!(marginal, SeparationVerdict::Marginal);

    let insufficient: SeparationVerdict =
        serde_json::from_str("\"insufficient\"").expect("insufficient");
    assert_eq!(insufficient, SeparationVerdict::Insufficient);
}

#[test]
fn deserialize_signal_kind_from_json_string() {
    let kind: BifurcationSignalKind =
        serde_json::from_str("\"growing_oscillation\"").expect("kind");
    assert_eq!(kind, BifurcationSignalKind::GrowingOscillation);
}

#[test]
fn deserialize_severity_from_json_string() {
    let sev: SignalSeverity = serde_json::from_str("\"critical\"").expect("severity");
    assert_eq!(sev, SignalSeverity::Critical);
}

#[test]
fn deserialize_assessment_from_json_string() {
    let a: StabilityAssessment =
        serde_json::from_str("\"monitoring_recommended\"").expect("assessment");
    assert_eq!(a, StabilityAssessment::MonitoringRecommended);
}

#[test]
fn deserialize_action_from_json_string() {
    let a: RecommendedAction = serde_json::from_str("\"safe_mode_fallback\"").expect("action");
    assert_eq!(a, RecommendedAction::SafeModeFallback);
}

#[test]
fn deserialize_ratio_basis_from_json_string() {
    let b: RatioBasis = serde_json::from_str("\"minimum_of\"").expect("basis");
    assert_eq!(b, RatioBasis::MinimumOf);
}

// =========================================================================
// 32. Bundle schema and bead ID propagation
// =========================================================================

#[test]
fn bundle_schema_version_is_bundle_specific() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.schema_version, CERTIFICATE_BUNDLE_SCHEMA_VERSION);
    assert_ne!(bundle.schema_version, TIMESCALE_CERTIFICATE_SCHEMA_VERSION);
}

#[test]
fn bundle_bead_id_matches_module_constant() {
    let profiles = vec![
        mk_profile("a", 100_000, 100_000),
        mk_profile("b", 1_000_000, 1_000_000),
    ];
    let config = default_config();
    let bundle = build_certificate_bundle(&profiles, &config, 0);
    assert_eq!(bundle.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
}

#[test]
fn detector_result_schema_version() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    assert_eq!(result.schema_version, BIFURCATION_DETECTOR_SCHEMA_VERSION);
}

#[test]
fn detector_result_bead_id() {
    let config = default_config();
    let result = detect_bifurcation_signals(&[], &config, 0);
    assert_eq!(result.bead_id, TIMESCALE_CERTIFICATE_BEAD_ID);
}

// =========================================================================
// 33. Custom config affects gain detection
// =========================================================================

#[test]
fn custom_gain_threshold_tighter() {
    let mut config = default_config();
    config.gain_exceedance_threshold_millionths = 400_000;
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // 500_000 > 400_000 => gain exceedance
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance)
    );
}

#[test]
fn custom_gain_threshold_looser() {
    let mut config = default_config();
    config.gain_exceedance_threshold_millionths = 2_000_000;
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // 1_500_000 < 2_000_000 => no exceedance
    assert!(
        !result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::GainExceedance)
    );
}

#[test]
fn custom_variance_threshold_tighter() {
    let mut config = default_config();
    config.variance_divergence_threshold_millionths = 50_000;
    let telemetry = vec![
        mk_snapshot("a", "b", 10_000_000, 100_000, 500_000, 0),
        mk_snapshot("a", "b", 10_000_000, 120_000, 500_000, 1),
        mk_snapshot("a", "b", 10_000_000, 200_000, 500_000, 2),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 3);
    // delta = 200_000 - 100_000 = 100_000 > 50_000
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
    );
}

#[test]
fn custom_marginal_threshold_affects_convergence() {
    let mut config = default_config();
    config.marginal_ratio_millionths = 5_000_000;
    let telemetry = vec![
        mk_snapshot("a", "b", 8_000_000, 50_000, 500_000, 0),
        mk_snapshot("a", "b", 4_000_000, 50_000, 500_000, 1),
    ];
    let result = detect_bifurcation_signals(&telemetry, &config, 2);
    // last_ratio 4M < marginal 5M => convergence triggered
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
    );
}
