//! Integration tests for regime_shift_detector module.
//!
//! Bead: bd-1lsy.7.8.2 [RGC-608B]

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

use frankenengine_engine::regime_shift_detector::*;
use frankenengine_engine::stage_envelope_certificate::ExecutionStage;

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn default_engine() -> RegimeShiftEngine {
    RegimeShiftEngine::new(RegimeShiftConfig::default())
}

fn fast_engine() -> RegimeShiftEngine {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 5;
    config.cooldown_ticks = 5;
    RegimeShiftEngine::new(config)
}

fn sensitive_engine() -> RegimeShiftEngine {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 3;
    config.cooldown_ticks = 0;
    config.cusum_threshold_millionths = 200_000; // lower threshold
    RegimeShiftEngine::new(config)
}

// ---------------------------------------------------------------------------
// E2E shift detection
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_stable_no_shift() {
    let mut engine = fast_engine();
    engine.register_detector(MetricKind::Latency, None, 500_000);
    for _ in 0..100 {
        let (sev, action) = engine.observe(MetricKind::Latency, None, 500_000);
        assert_eq!(action, DowngradeAction::NoAction);
        assert!(!sev.warrants_downgrade());
    }
    assert_eq!(engine.total_shifts_detected, 0);
    assert_eq!(engine.total_downgrades, 0);
}

#[test]
fn test_e2e_upward_shift_triggers_downgrade() {
    let mut engine = fast_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    let mut downgraded = false;
    for _ in 0..300 {
        let (_, action) = engine.observe(MetricKind::Latency, None, 900_000);
        if action != DowngradeAction::NoAction {
            downgraded = true;
            break;
        }
    }
    assert!(downgraded);
    assert!(engine.total_shifts_detected > 0);
    assert!(engine.total_downgrades > 0);
}

#[test]
fn test_e2e_downward_shift_detected() {
    let mut engine = fast_engine();
    engine.register_detector(MetricKind::Throughput, None, 800_000);
    let mut shifted = false;
    for _ in 0..300 {
        let (sev, _) = engine.observe(MetricKind::Throughput, None, 100_000);
        if sev.warrants_downgrade() {
            shifted = true;
            break;
        }
    }
    assert!(shifted);
}

#[test]
fn test_e2e_warmup_suppresses_detection() {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 50;
    let mut engine = RegimeShiftEngine::new(config);
    engine.register_detector(MetricKind::Latency, None, 100_000);
    // Even extreme values during warmup should be suppressed
    for _ in 0..48 {
        let (sev, action) = engine.observe(MetricKind::Latency, None, 999_000);
        assert_eq!(sev, ShiftSeverity::None);
        assert_eq!(action, DowngradeAction::NoAction);
    }
}

#[test]
fn test_e2e_cooldown_blocks_repeat_downgrade() {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 3;
    config.cooldown_ticks = 100;
    let mut engine = RegimeShiftEngine::new(config);
    engine.register_detector(MetricKind::Latency, None, 100_000);

    // Trigger first downgrade
    let mut first_downgrade_at = None;
    for i in 0..500 {
        let (_, action) = engine.observe(MetricKind::Latency, None, 900_000);
        if action != DowngradeAction::NoAction && first_downgrade_at.is_none() {
            first_downgrade_at = Some(i);
            break;
        }
    }
    assert!(first_downgrade_at.is_some());
    let downgrades_after_first = engine.total_downgrades;

    // Continue observing during cooldown — no more downgrades
    for _ in 0..50 {
        let (_, action) = engine.observe(MetricKind::Latency, None, 900_000);
        assert_eq!(action, DowngradeAction::NoAction);
    }
    assert_eq!(engine.total_downgrades, downgrades_after_first);
}

#[test]
fn test_e2e_cooldown_expires_allows_new_downgrade() {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 3;
    config.cooldown_ticks = 5;
    config.cusum_threshold_millionths = 200_000;
    let mut engine = RegimeShiftEngine::new(config);
    engine.register_detector(MetricKind::Latency, None, 100_000);

    // Trigger first downgrade
    for _ in 0..200 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    let first_downgrades = engine.total_downgrades;
    assert!(first_downgrades > 0);

    // Expire cooldown
    for _ in 0..10 {
        engine.tick();
    }

    // Continue extreme values — should eventually trigger another downgrade
    let mut got_another = false;
    for _ in 0..200 {
        let (_, action) = engine.observe(MetricKind::Latency, None, 900_000);
        if action != DowngradeAction::NoAction {
            got_another = true;
            break;
        }
    }
    assert!(got_another);
    assert!(engine.total_downgrades > first_downgrades);
}

// ---------------------------------------------------------------------------
// Multi-metric independence
// ---------------------------------------------------------------------------

#[test]
fn test_multi_metric_independent_detectors() {
    let mut engine = fast_engine();
    engine.register_detector(MetricKind::Latency, None, 500_000);
    engine.register_detector(MetricKind::Throughput, None, 500_000);
    engine.register_detector(MetricKind::ErrorRate, None, 100_000);

    // Only disturb latency
    for _ in 0..50 {
        engine.observe(MetricKind::Latency, None, 900_000);
        engine.observe(MetricKind::Throughput, None, 500_000);
        engine.observe(MetricKind::ErrorRate, None, 100_000);
    }

    let summary = engine.summary();
    assert_eq!(summary.detector_count, 3);
    // Throughput and error rate detectors should not be in alarm
    let thr_det = engine
        .detectors
        .get(&(MetricKind::Throughput, None))
        .unwrap();
    assert!(!thr_det.in_alarm);
}

#[test]
fn test_stage_scoped_detectors_independent() {
    let mut engine = fast_engine();
    engine.register_detector(MetricKind::Latency, Some(ExecutionStage::Parse), 500_000);
    engine.register_detector(MetricKind::Latency, Some(ExecutionStage::GcPause), 500_000);

    // Only disturb Parse stage
    for _ in 0..100 {
        engine.observe(MetricKind::Latency, Some(ExecutionStage::Parse), 900_000);
        engine.observe(MetricKind::Latency, Some(ExecutionStage::GcPause), 500_000);
    }

    let parse_det = engine
        .detectors
        .get(&(MetricKind::Latency, Some(ExecutionStage::Parse)))
        .unwrap();
    let gc_det = engine
        .detectors
        .get(&(MetricKind::Latency, Some(ExecutionStage::GcPause)))
        .unwrap();
    assert!(
        parse_det.cusum_upper > gc_det.cusum_upper || parse_det.alarm_count > gc_det.alarm_count
    );
}

#[test]
fn test_unregistered_metric_returns_none() {
    let mut engine = fast_engine();
    let (sev, action) = engine.observe(MetricKind::Custom, None, 999_000);
    assert_eq!(sev, ShiftSeverity::None);
    assert_eq!(action, DowngradeAction::NoAction);
}

// ---------------------------------------------------------------------------
// CUSUM detector direct tests
// ---------------------------------------------------------------------------

#[test]
fn test_cusum_tracks_observation_count() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    assert_eq!(det.observation_count, 0);
    for i in 0..25 {
        det.observe(500_000, i);
    }
    assert_eq!(det.observation_count, 25);
}

#[test]
fn test_cusum_ewma_converges() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    for i in 0..500 {
        det.observe(700_000, i);
    }
    // After 500 observations, EWMA should be very close to 700_000
    let diff = if det.ewma_millionths > 700_000 {
        det.ewma_millionths - 700_000
    } else {
        700_000 - det.ewma_millionths
    };
    assert!(diff < 10_000, "EWMA should converge, diff={diff}");
}

#[test]
fn test_cusum_accumulator_grows_with_deviation() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 100_000);
    det.observe(500_000, 0);
    assert!(det.cusum_upper > 0);
}

#[test]
fn test_cusum_lower_accumulator_downward() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    det.observe(100_000, 0);
    assert!(det.cusum_lower > 0);
}

#[test]
fn test_cusum_reset_clears_state() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    for i in 0..50 {
        det.observe(900_000, i);
    }
    assert!(det.cusum_upper > 0);
    det.reset_accumulators();
    assert_eq!(det.cusum_upper, 0);
    assert_eq!(det.cusum_lower, 0);
    assert!(!det.in_alarm);
    // observation count NOT reset
    assert_eq!(det.observation_count, 50);
}

#[test]
fn test_cusum_adapt_reference_updates() {
    let mut det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    for i in 0..200 {
        det.observe(800_000, i);
    }
    let old_ref = det.reference_millionths;
    det.adapt_reference();
    assert!(det.reference_millionths > old_ref);
    assert_eq!(det.cusum_upper, 0);
}

// ---------------------------------------------------------------------------
// Downgrade action types
// ---------------------------------------------------------------------------

#[test]
fn test_latency_shift_produces_fallback() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, Some(ExecutionStage::Parse), 100_000);
    let mut got_fallback = false;
    for _ in 0..300 {
        let (_, action) = engine.observe(MetricKind::Latency, Some(ExecutionStage::Parse), 900_000);
        if matches!(action, DowngradeAction::FallbackToDefault { .. }) {
            got_fallback = true;
            break;
        }
        // Could also be DisableAdaptive for Critical
        if matches!(action, DowngradeAction::DisableAdaptive { .. }) {
            got_fallback = true;
            break;
        }
    }
    assert!(got_fallback);
}

#[test]
fn test_queue_depth_shift_produces_reduce_concurrency() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::QueueDepth, None, 100_000);
    let mut got_reduce = false;
    for _ in 0..300 {
        let (_, action) = engine.observe(MetricKind::QueueDepth, None, 900_000);
        if matches!(action, DowngradeAction::ReduceConcurrency { .. }) {
            got_reduce = true;
            break;
        }
        if matches!(action, DowngradeAction::DisableAdaptive { .. }) {
            got_reduce = true;
            break;
        }
    }
    assert!(got_reduce);
}

#[test]
fn test_error_rate_shift_produces_conservative_mode() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::ErrorRate, None, 50_000);
    let mut got_conservative = false;
    for _ in 0..300 {
        let (_, action) = engine.observe(MetricKind::ErrorRate, None, 900_000);
        if matches!(action, DowngradeAction::ConservativeMode { .. }) {
            got_conservative = true;
            break;
        }
        if matches!(action, DowngradeAction::DisableAdaptive { .. }) {
            got_conservative = true;
            break;
        }
    }
    assert!(got_conservative);
}

// ---------------------------------------------------------------------------
// Certificate system
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_emitted_on_downgrade() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..300 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    assert!(!engine.certificates().is_empty());
    let cert = &engine.certificates()[0];
    assert_eq!(cert.schema_version, REGIME_SHIFT_SCHEMA_VERSION);
    assert!(cert.certificate_id.starts_with("shift-"));
    assert!(cert.observation_count > 0);
}

#[test]
fn test_certificate_content_hash_unique() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..500 {
        engine.observe(MetricKind::Latency, None, 900_000);
        engine.tick();
    }
    let certs = engine.certificates();
    if certs.len() >= 2 {
        assert_ne!(certs[0].content_hash, certs[1].content_hash);
    }
}

#[test]
fn test_certificates_bounded_eviction() {
    let mut config = RegimeShiftConfig::default();
    config.min_observations = 2;
    config.cooldown_ticks = 0;
    config.max_certificates = 5;
    config.cusum_threshold_millionths = 200_000;
    let mut engine = RegimeShiftEngine::new(config);
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..1000 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    assert!(engine.certificates().len() <= 5);
}

#[test]
fn test_certificate_captures_detector_state() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..300 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    if let Some(cert) = engine.certificates().first() {
        assert_eq!(cert.metric, MetricKind::Latency);
        assert!(cert.severity.warrants_downgrade());
        assert!(cert.reference_millionths > 0);
    }
}

// ---------------------------------------------------------------------------
// Tick and auto-adapt
// ---------------------------------------------------------------------------

#[test]
fn test_tick_advances_counter() {
    let mut engine = default_engine();
    assert_eq!(engine.current_tick, 0);
    engine.tick();
    assert_eq!(engine.current_tick, 1);
    for _ in 0..99 {
        engine.tick();
    }
    assert_eq!(engine.current_tick, 100);
}

#[test]
fn test_tick_decrements_cooldown() {
    let mut engine = default_engine();
    engine.cooldown_remaining = 10;
    for _ in 0..5 {
        engine.tick();
    }
    assert_eq!(engine.cooldown_remaining, 5);
    for _ in 0..10 {
        engine.tick();
    }
    assert_eq!(engine.cooldown_remaining, 0);
}

#[test]
fn test_auto_adapt_after_stability() {
    let mut config = RegimeShiftConfig::default();
    config.auto_adapt = true;
    config.adapt_stability_ticks = 10;
    config.min_observations = 3;
    let mut engine = RegimeShiftEngine::new(config);
    engine.register_detector(MetricKind::Latency, None, 500_000);

    // Feed elevated values and tick
    for _ in 0..50 {
        engine.observe(MetricKind::Latency, None, 800_000);
    }

    // Tick enough to trigger auto-adaptation
    for _ in 0..15 {
        engine.tick();
    }

    let det = engine.detectors.get(&(MetricKind::Latency, None)).unwrap();
    // After auto-adapt, reference should have moved toward EWMA
    // and accumulators should be reset
    assert_eq!(det.cusum_upper, 0);
    assert_eq!(det.cusum_lower, 0);
}

// ---------------------------------------------------------------------------
// Registration edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_register_duplicate_returns_false() {
    let mut engine = default_engine();
    assert!(engine.register_detector(MetricKind::Latency, None, 500_000));
    assert!(!engine.register_detector(MetricKind::Latency, None, 500_000));
}

#[test]
fn test_register_same_metric_different_stages() {
    let mut engine = default_engine();
    assert!(engine.register_detector(MetricKind::Latency, Some(ExecutionStage::Parse), 500_000));
    assert!(engine.register_detector(MetricKind::Latency, Some(ExecutionStage::GcPause), 500_000));
    assert!(engine.register_detector(MetricKind::Latency, None, 500_000));
    assert_eq!(engine.detectors.len(), 3);
}

#[test]
fn test_register_max_capacity() {
    let mut config = RegimeShiftConfig::default();
    config.max_detectors = 3;
    let mut engine = RegimeShiftEngine::new(config);
    assert!(engine.register_detector(MetricKind::Latency, None, 500_000));
    assert!(engine.register_detector(MetricKind::Throughput, None, 500_000));
    assert!(engine.register_detector(MetricKind::ErrorRate, None, 500_000));
    assert!(!engine.register_detector(MetricKind::QueueDepth, None, 500_000));
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

#[test]
fn test_summary_initial_state() {
    let engine = default_engine();
    let summary = engine.summary();
    assert_eq!(summary.detector_count, 0);
    assert_eq!(summary.alarming_count, 0);
    assert_eq!(summary.total_shifts_detected, 0);
    assert_eq!(summary.total_downgrades, 0);
    assert_eq!(summary.certificate_count, 0);
    assert!(!summary.in_cooldown);
}

#[test]
fn test_summary_after_registrations() {
    let mut engine = default_engine();
    engine.register_detector(MetricKind::Latency, None, 500_000);
    engine.register_detector(MetricKind::Throughput, None, 500_000);
    let summary = engine.summary();
    assert_eq!(summary.detector_count, 2);
}

#[test]
fn test_summary_cooldown_flag() {
    let mut engine = default_engine();
    engine.cooldown_remaining = 5;
    let summary = engine.summary();
    assert!(summary.in_cooldown);
    assert_eq!(summary.cooldown_remaining, 5);
}

#[test]
fn test_summary_after_shifts() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..300 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    let summary = engine.summary();
    assert!(summary.total_shifts_detected > 0);
    assert!(summary.certificate_count > 0);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_schema_version() {
    let engine = default_engine();
    let manifest = RegimeShiftManifest::from_engine(&engine);
    assert_eq!(manifest.schema_version, REGIME_SHIFT_SCHEMA_VERSION);
    assert_eq!(manifest.bead_id, REGIME_SHIFT_BEAD_ID);
}

#[test]
fn test_manifest_includes_config() {
    let engine = default_engine();
    let manifest = RegimeShiftManifest::from_engine(&engine);
    assert_eq!(
        manifest.config.cusum_drift_millionths,
        DEFAULT_CUSUM_DRIFT_MILLIONTHS
    );
}

#[test]
fn test_manifest_includes_certificates() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..300 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    let manifest = RegimeShiftManifest::from_engine(&engine);
    assert!(!manifest.recent_certificates.is_empty());
}

#[test]
fn test_manifest_content_hash_deterministic() {
    let e1 = default_engine();
    let e2 = default_engine();
    let m1 = RegimeShiftManifest::from_engine(&e1);
    let m2 = RegimeShiftManifest::from_engine(&e2);
    assert_eq!(m1.content_hash, m2.content_hash);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_serde_config_roundtrip() {
    let config = RegimeShiftConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: RegimeShiftConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn test_serde_severity_roundtrip() {
    for sev in [
        ShiftSeverity::None,
        ShiftSeverity::Minor,
        ShiftSeverity::Moderate,
        ShiftSeverity::Major,
        ShiftSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let restored: ShiftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, restored);
    }
}

#[test]
fn test_serde_metric_kind_roundtrip() {
    for mk in [
        MetricKind::Latency,
        MetricKind::Throughput,
        MetricKind::ErrorRate,
        MetricKind::QueueDepth,
        MetricKind::TokenUtilization,
        MetricKind::GcPauseDuration,
        MetricKind::Custom,
    ] {
        let json = serde_json::to_string(&mk).unwrap();
        let restored: MetricKind = serde_json::from_str(&json).unwrap();
        assert_eq!(mk, restored);
    }
}

#[test]
fn test_serde_downgrade_action_roundtrip() {
    let actions = vec![
        DowngradeAction::NoAction,
        DowngradeAction::FallbackToDefault {
            stage: Some(ExecutionStage::Parse),
            reason: "test".to_string(),
        },
        DowngradeAction::DisableAdaptive {
            reason: "critical".to_string(),
        },
        DowngradeAction::ReduceConcurrency {
            target_workers: 4,
            reason: "overload".to_string(),
        },
        DowngradeAction::ConservativeMode {
            reason: "drift".to_string(),
        },
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let restored: DowngradeAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }
}

#[test]
fn test_serde_manifest_roundtrip() {
    let mut engine = sensitive_engine();
    engine.register_detector(MetricKind::Latency, None, 100_000);
    for _ in 0..200 {
        engine.observe(MetricKind::Latency, None, 900_000);
    }
    let manifest = RegimeShiftManifest::from_engine(&engine);
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: RegimeShiftManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn test_serde_certificate_roundtrip() {
    let det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    let cert = ShiftCertificate::from_detector(
        &det,
        42,
        ShiftSeverity::Major,
        DowngradeAction::NoAction,
        1,
    );
    let json = serde_json::to_string(&cert).unwrap();
    let restored: ShiftCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, restored);
}

// ---------------------------------------------------------------------------
// Config hash
// ---------------------------------------------------------------------------

#[test]
fn test_config_hash_deterministic() {
    let c1 = RegimeShiftConfig::default();
    let c2 = RegimeShiftConfig::default();
    assert_eq!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_config_hash_changes_with_params() {
    let c1 = RegimeShiftConfig::default();
    let mut c2 = RegimeShiftConfig::default();
    c2.cusum_threshold_millionths = 999_999;
    assert_ne!(c1.config_hash(), c2.config_hash());
}

#[test]
fn test_engine_config_hash_stable() {
    let engine = default_engine();
    let h1 = engine.config_hash().clone();
    let h2 = engine.config_hash().clone();
    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Display / formatting
// ---------------------------------------------------------------------------

#[test]
fn test_severity_display_all_variants() {
    assert_eq!(format!("{}", ShiftSeverity::None), "none");
    assert_eq!(format!("{}", ShiftSeverity::Minor), "minor");
    assert_eq!(format!("{}", ShiftSeverity::Moderate), "moderate");
    assert_eq!(format!("{}", ShiftSeverity::Major), "major");
    assert_eq!(format!("{}", ShiftSeverity::Critical), "critical");
}

#[test]
fn test_metric_kind_display_all_variants() {
    assert_eq!(format!("{}", MetricKind::Latency), "latency");
    assert_eq!(format!("{}", MetricKind::Throughput), "throughput");
    assert_eq!(format!("{}", MetricKind::ErrorRate), "error_rate");
    assert_eq!(format!("{}", MetricKind::QueueDepth), "queue_depth");
    assert_eq!(
        format!("{}", MetricKind::TokenUtilization),
        "token_utilization"
    );
    assert_eq!(
        format!("{}", MetricKind::GcPauseDuration),
        "gc_pause_duration"
    );
    assert_eq!(format!("{}", MetricKind::Custom), "custom");
}

#[test]
fn test_downgrade_action_display() {
    assert_eq!(format!("{}", DowngradeAction::NoAction), "no_action");
    let fb = DowngradeAction::FallbackToDefault {
        stage: None,
        reason: "x".to_string(),
    };
    assert_eq!(format!("{fb}"), "fallback_to_default");
    let rc = DowngradeAction::ReduceConcurrency {
        target_workers: 7,
        reason: "y".to_string(),
    };
    assert!(format!("{rc}").contains("7"));
}

#[test]
fn test_certificate_display() {
    let det = CusumDetector::new(MetricKind::Latency, None, 500_000);
    let cert = ShiftCertificate::from_detector(
        &det,
        99,
        ShiftSeverity::Major,
        DowngradeAction::NoAction,
        1,
    );
    let s = format!("{cert}");
    assert!(s.contains("shift-"));
    assert!(s.contains("99"));
    assert!(s.contains("latency"));
    assert!(s.contains("major"));
}

// ---------------------------------------------------------------------------
// Severity rank and ordering
// ---------------------------------------------------------------------------

#[test]
fn test_severity_rank_monotonic() {
    let severities = [
        ShiftSeverity::None,
        ShiftSeverity::Minor,
        ShiftSeverity::Moderate,
        ShiftSeverity::Major,
        ShiftSeverity::Critical,
    ];
    for i in 1..severities.len() {
        assert!(severities[i].rank() > severities[i - 1].rank());
    }
}

#[test]
fn test_severity_warrants_downgrade_boundary() {
    assert!(!ShiftSeverity::Moderate.warrants_downgrade());
    assert!(ShiftSeverity::Major.warrants_downgrade());
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_constants() {
    assert!(!REGIME_SHIFT_SCHEMA_VERSION.is_empty());
    assert!(REGIME_SHIFT_SCHEMA_VERSION.contains("regime-shift"));
    assert!(!REGIME_SHIFT_BEAD_ID.is_empty());
    assert!(REGIME_SHIFT_BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_default_constants() {
    const {
        assert!(DEFAULT_CUSUM_DRIFT_MILLIONTHS > 0);
        assert!(DEFAULT_CUSUM_THRESHOLD_MILLIONTHS > DEFAULT_CUSUM_DRIFT_MILLIONTHS);
        assert!(DEFAULT_EWMA_ALPHA_MILLIONTHS > 0);
        assert!(DEFAULT_EWMA_ALPHA_MILLIONTHS <= 1_000_000);
        assert!(DEFAULT_COOLDOWN_TICKS > 0);
        assert!(DEFAULT_MIN_OBSERVATIONS > 0);
    }
}
