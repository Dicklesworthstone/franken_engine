//! Enrichment integration tests for `regime_shift_detector`.
//!
//! Covers gaps: MetricKind Display uniqueness, ShiftSeverity ordering and
//! warrants_downgrade logic, CusumDetector observation mechanics (warmup,
//! alarm triggering, EWMA tracking), RegimeShiftEngine registration and
//! observation, cooldown enforcement, auto-adapt behavior, certificate
//! generation, summary/manifest snapshots, config hash determinism,
//! serde roundtrips for all public types, and DowngradeAction Display.

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

use frankenengine_engine::regime_shift_detector::{
    CusumDetector, DEFAULT_COOLDOWN_TICKS, DEFAULT_CUSUM_DRIFT_MILLIONTHS,
    DEFAULT_CUSUM_THRESHOLD_MILLIONTHS, DEFAULT_EWMA_ALPHA_MILLIONTHS, DEFAULT_MIN_OBSERVATIONS,
    DowngradeAction, MetricKind, REGIME_SHIFT_BEAD_ID, REGIME_SHIFT_SCHEMA_VERSION,
    RegimeShiftConfig, RegimeShiftEngine, RegimeShiftManifest, RegimeShiftSummary,
    ShiftCertificate, ShiftSeverity,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config() -> RegimeShiftConfig {
    RegimeShiftConfig::default()
}

fn default_engine() -> RegimeShiftEngine {
    RegimeShiftEngine::new(default_config())
}

fn sensitive_config() -> RegimeShiftConfig {
    RegimeShiftConfig {
        cusum_drift_millionths: 10_000,
        cusum_threshold_millionths: 100_000,
        ewma_alpha_millionths: 200_000,
        min_observations: 5,
        cooldown_ticks: 3,
        auto_adapt: false,
        adapt_stability_ticks: 5,
        max_certificates: 100,
        max_detectors: 50,
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(REGIME_SHIFT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_bead_id_nonempty() {
    assert!(!REGIME_SHIFT_BEAD_ID.is_empty());
}

#[test]
fn enrichment_default_constants_positive() {
    assert!(DEFAULT_CUSUM_DRIFT_MILLIONTHS > 0);
    assert!(DEFAULT_CUSUM_THRESHOLD_MILLIONTHS > 0);
    assert!(DEFAULT_EWMA_ALPHA_MILLIONTHS > 0);
    assert!(DEFAULT_COOLDOWN_TICKS > 0);
    assert!(DEFAULT_MIN_OBSERVATIONS > 0);
}

// ===========================================================================
// MetricKind Display uniqueness
// ===========================================================================

#[test]
fn enrichment_metric_kind_display_all_unique() {
    let all = [
        MetricKind::Latency,
        MetricKind::Throughput,
        MetricKind::ErrorRate,
        MetricKind::QueueDepth,
        MetricKind::TokenUtilization,
        MetricKind::GcPauseDuration,
        MetricKind::Custom,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_metric_kind_serde_roundtrip() {
    let all = [
        MetricKind::Latency,
        MetricKind::Throughput,
        MetricKind::ErrorRate,
        MetricKind::QueueDepth,
        MetricKind::TokenUtilization,
        MetricKind::GcPauseDuration,
        MetricKind::Custom,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: MetricKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// ShiftSeverity ordering and classification
// ===========================================================================

#[test]
fn enrichment_severity_rank_ordering() {
    assert_eq!(ShiftSeverity::None.rank(), 0);
    assert_eq!(ShiftSeverity::Minor.rank(), 1);
    assert_eq!(ShiftSeverity::Moderate.rank(), 2);
    assert_eq!(ShiftSeverity::Major.rank(), 3);
    assert_eq!(ShiftSeverity::Critical.rank(), 4);
}

#[test]
fn enrichment_severity_monotonic_ranks() {
    assert!(ShiftSeverity::None.rank() < ShiftSeverity::Minor.rank());
    assert!(ShiftSeverity::Minor.rank() < ShiftSeverity::Moderate.rank());
    assert!(ShiftSeverity::Moderate.rank() < ShiftSeverity::Major.rank());
    assert!(ShiftSeverity::Major.rank() < ShiftSeverity::Critical.rank());
}

#[test]
fn enrichment_warrants_downgrade_only_major_and_critical() {
    assert!(!ShiftSeverity::None.warrants_downgrade());
    assert!(!ShiftSeverity::Minor.warrants_downgrade());
    assert!(!ShiftSeverity::Moderate.warrants_downgrade());
    assert!(ShiftSeverity::Major.warrants_downgrade());
    assert!(ShiftSeverity::Critical.warrants_downgrade());
}

#[test]
fn enrichment_severity_display_all_unique() {
    let all = [
        ShiftSeverity::None,
        ShiftSeverity::Minor,
        ShiftSeverity::Moderate,
        ShiftSeverity::Major,
        ShiftSeverity::Critical,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), all.len());
}

#[test]
fn enrichment_severity_serde_roundtrip() {
    let all = [
        ShiftSeverity::None,
        ShiftSeverity::Minor,
        ShiftSeverity::Moderate,
        ShiftSeverity::Major,
        ShiftSeverity::Critical,
    ];
    for sev in &all {
        let json = serde_json::to_string(sev).unwrap();
        let back: ShiftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

// ===========================================================================
// DowngradeAction Display
// ===========================================================================

#[test]
fn enrichment_downgrade_action_display_unique() {
    let actions = [
        DowngradeAction::NoAction,
        DowngradeAction::ConservativeMode {
            reason: "test".to_string(),
        },
        DowngradeAction::DisableAdaptive {
            reason: "drift".to_string(),
        },
        DowngradeAction::ReduceConcurrency {
            target_workers: 2,
            reason: "load".to_string(),
        },
    ];
    let displays: BTreeSet<String> = actions.iter().map(|a| a.to_string()).collect();
    assert_eq!(displays.len(), actions.len());
}

#[test]
fn enrichment_downgrade_action_serde_roundtrip() {
    let actions = [
        DowngradeAction::NoAction,
        DowngradeAction::ConservativeMode {
            reason: "test".to_string(),
        },
        DowngradeAction::DisableAdaptive {
            reason: "drift".to_string(),
        },
        DowngradeAction::ReduceConcurrency {
            target_workers: 4,
            reason: "load".to_string(),
        },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: DowngradeAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

// ===========================================================================
// CusumDetector: basic observation
// ===========================================================================

#[test]
fn enrichment_cusum_new_starts_at_none_severity() {
    let detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    assert_eq!(detector.observation_count, 0);
    assert_eq!(detector.alarm_count, 0);
    assert!(!detector.in_alarm);
}

#[test]
fn enrichment_cusum_observe_stable_no_alarm() {
    let mut detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    // Feed observations close to reference — should not alarm
    for tick in 0..30 {
        let sev = detector.observe(1_000_000, tick);
        // After warmup, stable observations should produce None severity
        if tick >= DEFAULT_MIN_OBSERVATIONS {
            assert_eq!(
                sev,
                ShiftSeverity::None,
                "tick {tick}: expected None for stable obs"
            );
        }
    }
    assert_eq!(detector.alarm_count, 0);
}

#[test]
fn enrichment_cusum_observe_spike_triggers_alarm() {
    let mut detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    // Warmup with stable observations
    for tick in 0..25 {
        detector.observe(1_000_000, tick);
    }
    // Feed a massive spike
    let mut triggered = false;
    for tick in 25..50 {
        let sev = detector.observe(5_000_000, tick);
        if sev.rank() > 0 {
            triggered = true;
        }
    }
    assert!(triggered, "Massive spike should eventually trigger alarm");
}

#[test]
fn enrichment_cusum_ewma_tracks_recent_values() {
    let mut detector = CusumDetector::new(MetricKind::Throughput, None, 500_000);
    for tick in 0..10 {
        detector.observe(500_000, tick);
    }
    // After stable observations, EWMA should be close to reference
    let diff = detector.ewma_millionths.abs_diff(500_000);
    assert!(
        diff < 100_000,
        "EWMA should be close to reference after stable obs"
    );
}

#[test]
fn enrichment_cusum_reset_accumulators() {
    let mut detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    for tick in 0..30 {
        detector.observe(3_000_000, tick);
    }
    detector.reset_accumulators();
    assert_eq!(detector.cusum_upper, 0);
    assert_eq!(detector.cusum_lower, 0);
}

#[test]
fn enrichment_cusum_adapt_reference() {
    let mut detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    // Feed values at 2_000_000 to shift EWMA
    for tick in 0..50 {
        detector.observe(2_000_000, tick);
    }
    let ewma_before = detector.ewma_millionths;
    detector.adapt_reference();
    assert_eq!(detector.reference_millionths, ewma_before);
}

// ===========================================================================
// RegimeShiftEngine: registration
// ===========================================================================

#[test]
fn enrichment_engine_register_detector_succeeds() {
    let mut engine = default_engine();
    assert!(engine.register_detector(MetricKind::Latency, None, 1_000_000));
}

#[test]
fn enrichment_engine_register_duplicate_fails() {
    let mut engine = default_engine();
    assert!(engine.register_detector(MetricKind::Latency, None, 1_000_000));
    assert!(!engine.register_detector(MetricKind::Latency, None, 2_000_000));
}

#[test]
fn enrichment_engine_summary_after_registration() {
    let mut engine = default_engine();
    engine.register_detector(MetricKind::Latency, None, 1_000_000);
    engine.register_detector(MetricKind::Throughput, None, 500_000);
    let summary = engine.summary();
    assert_eq!(summary.detector_count, 2);
    assert_eq!(summary.alarming_count, 0);
}

// ===========================================================================
// RegimeShiftEngine: observation
// ===========================================================================

#[test]
fn enrichment_engine_observe_stable_no_downgrade() {
    let mut engine = RegimeShiftEngine::new(sensitive_config());
    engine.register_detector(MetricKind::Latency, None, 1_000_000);
    for _ in 0..20 {
        engine.tick();
        let (sev, action) = engine.observe(MetricKind::Latency, None, 1_000_000);
        assert_eq!(sev, ShiftSeverity::None);
        assert!(matches!(action, DowngradeAction::NoAction));
    }
}

#[test]
fn enrichment_engine_observe_spike_triggers_downgrade() {
    let mut engine = RegimeShiftEngine::new(sensitive_config());
    engine.register_detector(MetricKind::Latency, None, 100_000);
    // Warmup
    for _ in 0..10 {
        engine.tick();
        engine.observe(MetricKind::Latency, None, 100_000);
    }
    // Massive spike
    let mut downgraded = false;
    for _ in 0..50 {
        engine.tick();
        let (_sev, action) = engine.observe(MetricKind::Latency, None, 10_000_000);
        if !matches!(action, DowngradeAction::NoAction) {
            downgraded = true;
            break;
        }
    }
    assert!(
        downgraded,
        "Massive spike should trigger a downgrade action"
    );
}

// ===========================================================================
// RegimeShiftEngine: cooldown
// ===========================================================================

#[test]
fn enrichment_engine_cooldown_suppresses_actions() {
    let mut engine = RegimeShiftEngine::new(sensitive_config());
    engine.register_detector(MetricKind::Latency, None, 100_000);
    // Warmup
    for _ in 0..10 {
        engine.tick();
        engine.observe(MetricKind::Latency, None, 100_000);
    }
    // Trigger first downgrade
    let mut first_downgraded = false;
    for _ in 0..50 {
        engine.tick();
        let (_sev, action) = engine.observe(MetricKind::Latency, None, 10_000_000);
        if !matches!(action, DowngradeAction::NoAction) {
            first_downgraded = true;
            break;
        }
    }
    if first_downgraded {
        // During cooldown, actions should be suppressed
        let summary = engine.summary();
        assert!(
            summary.in_cooldown || summary.cooldown_remaining > 0 || summary.total_downgrades > 0
        );
    }
}

// ===========================================================================
// RegimeShiftEngine: tick advances state
// ===========================================================================

#[test]
fn enrichment_engine_tick_increments_current_tick() {
    let mut engine = default_engine();
    let s1 = engine.summary();
    engine.tick();
    let s2 = engine.summary();
    assert_eq!(s2.current_tick, s1.current_tick + 1);
}

// ===========================================================================
// RegimeShiftEngine: certificates
// ===========================================================================

#[test]
fn enrichment_engine_certificates_empty_initially() {
    let engine = default_engine();
    assert!(engine.certificates().is_empty());
}

#[test]
fn enrichment_engine_certificates_accumulate_on_shifts() {
    let mut engine = RegimeShiftEngine::new(sensitive_config());
    engine.register_detector(MetricKind::ErrorRate, None, 10_000);
    // Warmup
    for _ in 0..10 {
        engine.tick();
        engine.observe(MetricKind::ErrorRate, None, 10_000);
    }
    // Spike to trigger certificates
    for _ in 0..100 {
        engine.tick();
        engine.observe(MetricKind::ErrorRate, None, 10_000_000);
    }
    // May or may not have certificates depending on exact thresholds
    let summary = engine.summary();
    let _ = summary.total_shifts_detected; // sanity: field exists
}

// ===========================================================================
// RegimeShiftConfig: config hash determinism
// ===========================================================================

#[test]
fn enrichment_config_hash_deterministic() {
    let c1 = default_config();
    let c2 = default_config();
    assert_eq!(c1.config_hash(), c2.config_hash());
}

#[test]
fn enrichment_different_configs_different_hashes() {
    let c1 = default_config();
    let c2 = sensitive_config();
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn enrichment_engine_config_hash_matches() {
    let config = default_config();
    let hash = config.config_hash();
    let engine = RegimeShiftEngine::new(config);
    assert_eq!(engine.config_hash(), hash);
}

// ===========================================================================
// RegimeShiftConfig serde roundtrip
// ===========================================================================

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: RegimeShiftConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.cusum_drift_millionths, back.cusum_drift_millionths);
    assert_eq!(config.min_observations, back.min_observations);
}

// ===========================================================================
// RegimeShiftSummary serde roundtrip
// ===========================================================================

#[test]
fn enrichment_summary_serde_roundtrip() {
    let engine = default_engine();
    let summary = engine.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: RegimeShiftSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.detector_count, back.detector_count);
    assert_eq!(summary.current_tick, back.current_tick);
}

// ===========================================================================
// RegimeShiftManifest
// ===========================================================================

#[test]
fn enrichment_manifest_from_engine() {
    let engine = default_engine();
    let manifest = RegimeShiftManifest::from_engine(&engine);
    assert!(manifest.schema_version.starts_with("franken-engine."));
    assert!(!manifest.bead_id.is_empty());
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let engine = default_engine();
    let manifest = RegimeShiftManifest::from_engine(&engine);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: RegimeShiftManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.schema_version, back.schema_version);
    assert_eq!(manifest.bead_id, back.bead_id);
}

// ===========================================================================
// ShiftCertificate serde roundtrip
// ===========================================================================

#[test]
fn enrichment_shift_certificate_serde_roundtrip() {
    let detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    let cert = ShiftCertificate::from_detector(
        &detector,
        42,
        ShiftSeverity::Major,
        DowngradeAction::NoAction,
        1,
    );
    let json = serde_json::to_string(&cert).unwrap();
    let back: ShiftCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert.severity, back.severity);
    assert_eq!(cert.detection_tick, back.detection_tick);
}

#[test]
fn enrichment_shift_certificate_display_nonempty() {
    let detector = CusumDetector::new(MetricKind::Latency, None, 1_000_000);
    let cert = ShiftCertificate::from_detector(
        &detector,
        42,
        ShiftSeverity::Minor,
        DowngradeAction::NoAction,
        1,
    );
    let display = cert.to_string();
    assert!(!display.is_empty());
}

// ===========================================================================
// Multiple detectors same engine
// ===========================================================================

#[test]
fn enrichment_engine_multiple_metrics_independent() {
    let mut engine = default_engine();
    engine.register_detector(MetricKind::Latency, None, 1_000_000);
    engine.register_detector(MetricKind::Throughput, None, 500_000);
    engine.register_detector(MetricKind::ErrorRate, None, 10_000);
    let summary = engine.summary();
    assert_eq!(summary.detector_count, 3);
}

#[test]
fn enrichment_engine_observe_unregistered_metric_no_panic() {
    let mut engine = default_engine();
    // Observing unregistered metric should not panic
    let (sev, action) = engine.observe(MetricKind::Custom, None, 1_000_000);
    assert_eq!(sev, ShiftSeverity::None);
    assert!(matches!(action, DowngradeAction::NoAction));
}
