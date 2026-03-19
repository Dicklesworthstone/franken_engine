#![forbid(unsafe_code)]
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

//! Enrichment integration tests for the `regime_detector` module.

use std::collections::BTreeSet;

use frankenengine_engine::regime_detector::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config(stream: &str) -> DetectorConfig {
    DetectorConfig {
        detector_id: "det-enrich".to_string(),
        metric_stream: stream.to_string(),
        max_run_length: 50,
        classifier: RegimeClassifier::default(),
        prior: NormalStats::default_prior(),
        hazard_lambda: 100,
    }
}

fn test_detector(stream: &str) -> RegimeDetector {
    RegimeDetector::new(test_config(stream), SecurityEpoch::GENESIS)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regime_all_variants_serde_roundtrip() {
    let regimes = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ];
    for r in &regimes {
        let json = serde_json::to_string(r).unwrap();
        let back: Regime = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_regime_display_all_distinct() {
    let displays: BTreeSet<String> = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ]
    .iter()
    .map(|r| r.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_regime_ordering_complete() {
    assert!(Regime::Normal < Regime::Elevated);
    assert!(Regime::Elevated < Regime::Attack);
    assert!(Regime::Attack < Regime::Degraded);
    assert!(Regime::Degraded < Regime::Recovery);
}

#[test]
fn enrichment_constant_hazard_rate_computation() {
    let h = ConstantHazard { lambda: 200 };
    // 1/200 = 0.005 = 5000 millionths
    assert_eq!(h.hazard(0), 5_000);
    assert_eq!(h.hazard(999), 5_000);
}

#[test]
fn enrichment_constant_hazard_lambda_one_always_change() {
    let h = ConstantHazard { lambda: 1 };
    assert_eq!(h.hazard(0), 1_000_000);
}

#[test]
fn enrichment_constant_hazard_zero_lambda_degenerate() {
    let h = ConstantHazard { lambda: 0 };
    assert_eq!(h.hazard(0), 1_000_000);
}

#[test]
fn enrichment_constant_hazard_serde_roundtrip() {
    let h = ConstantHazard { lambda: 42 };
    let json = serde_json::to_string(&h).unwrap();
    let back: ConstantHazard = serde_json::from_str(&json).unwrap();
    assert_eq!(back.lambda, 42);
}

#[test]
fn enrichment_normal_stats_default_prior_values() {
    let s = NormalStats::default_prior();
    assert_eq!(s.mu0, 0);
    assert_eq!(s.kappa0, 100_000);
    assert_eq!(s.alpha0, 1_000_000);
    assert_eq!(s.beta0, 1_000_000);
}

#[test]
fn enrichment_normal_stats_serde_roundtrip() {
    let s = NormalStats {
        mu0: 500_000,
        kappa0: 200_000,
        alpha0: 2_000_000,
        beta0: 500_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: NormalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_classifier_default_thresholds() {
    let c = RegimeClassifier::default();
    assert_eq!(c.elevated_threshold, 700_000);
    assert_eq!(c.attack_threshold, 900_000);
    assert_eq!(c.degraded_threshold, -500_000);
}

#[test]
fn enrichment_classifier_boundary_normal_to_elevated() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(699_999), Regime::Normal);
    assert_eq!(c.classify(700_000), Regime::Elevated);
}

#[test]
fn enrichment_classifier_boundary_elevated_to_attack() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(899_999), Regime::Elevated);
    assert_eq!(c.classify(900_000), Regime::Attack);
}

#[test]
fn enrichment_classifier_boundary_normal_to_degraded() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(-499_999), Regime::Normal);
    assert_eq!(c.classify(-500_000), Regime::Degraded);
}

#[test]
fn enrichment_classifier_custom_thresholds() {
    let c = RegimeClassifier {
        elevated_threshold: 400_000,
        attack_threshold: 600_000,
        degraded_threshold: -100_000,
    };
    assert_eq!(c.classify(300_000), Regime::Normal);
    assert_eq!(c.classify(400_000), Regime::Elevated);
    assert_eq!(c.classify(600_000), Regime::Attack);
    assert_eq!(c.classify(-100_000), Regime::Degraded);
}

#[test]
fn enrichment_classifier_serde_roundtrip() {
    let c = RegimeClassifier::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: RegimeClassifier = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_detector_new_starts_normal() {
    let det = test_detector("cpu");
    assert_eq!(det.regime(), Regime::Normal);
    assert_eq!(det.observation_count(), 0);
    assert_eq!(det.most_probable_run_length(), 0);
    assert_eq!(det.change_point_probability(), 1_000_000);
}

#[test]
fn enrichment_detector_single_observation() {
    let mut det = test_detector("cpu");
    let regime = det.observe(300_000).unwrap();
    assert_eq!(regime, Regime::Normal);
    assert_eq!(det.observation_count(), 1);
}

#[test]
fn enrichment_detector_stable_normal_no_events() {
    let mut det = test_detector("metric");
    for _ in 0..20 {
        det.observe(300_000).unwrap();
    }
    assert_eq!(det.regime(), Regime::Normal);
    let events = det.drain_events();
    assert!(events.is_empty());
}

#[test]
fn enrichment_detector_normal_to_attack_emits_events() {
    let mut det = test_detector("metric");
    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    assert!(det.regime() >= Regime::Elevated);
    let events = det.drain_events();
    assert!(!events.is_empty());
    for event in &events {
        assert_eq!(event.detector_id, "det-enrich");
    }
}

#[test]
fn enrichment_detector_degraded_on_negative() {
    let mut det = test_detector("health");
    for _ in 0..15 {
        det.observe(-600_000).unwrap();
    }
    assert_eq!(det.regime(), Regime::Degraded);
}

#[test]
fn enrichment_detector_recovery_cycle() {
    let mut det = test_detector("metric");
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    assert!(det.regime() >= Regime::Elevated);
    for _ in 0..15 {
        det.observe(200_000).unwrap();
    }
    assert_eq!(det.regime(), Regime::Normal);
}

#[test]
fn enrichment_detector_run_length_increases_with_stability() {
    let mut det = test_detector("metric");
    for _ in 0..30 {
        det.observe(500_000).unwrap();
    }
    assert!(det.most_probable_run_length() > 0);
}

#[test]
fn enrichment_detector_change_point_probability_decreases() {
    let mut det = test_detector("metric");
    let initial = det.change_point_probability();
    for _ in 0..20 {
        det.observe(500_000).unwrap();
    }
    assert!(det.change_point_probability() < initial);
}

#[test]
fn enrichment_detector_set_epoch_updates() {
    let mut det = test_detector("metric");
    det.set_epoch(SecurityEpoch::from_raw(42));
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    let events = det.drain_events();
    if let Some(event) = events.last() {
        assert_eq!(event.epoch, SecurityEpoch::from_raw(42));
    }
}

#[test]
fn enrichment_detector_config_accessor() {
    let det = test_detector("cpu_load");
    let cfg = det.config();
    assert_eq!(cfg.detector_id, "det-enrich");
    assert_eq!(cfg.metric_stream, "cpu_load");
    assert_eq!(cfg.max_run_length, 50);
    assert_eq!(cfg.hazard_lambda, 100);
}

#[test]
fn enrichment_detector_drain_events_idempotent() {
    let mut det = test_detector("metric");
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    let events1 = det.drain_events();
    assert!(!events1.is_empty());
    let events2 = det.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn enrichment_detector_deterministic_replay() {
    let observations: Vec<i64> = vec![
        300_000, 300_000, 500_000, 700_000, 950_000, 950_000, 950_000, 200_000, 200_000, 300_000,
    ];
    let run = |obs: &[i64]| -> (Vec<Regime>, Vec<RegimeChangeEvent>) {
        let mut det = test_detector("det");
        let regimes: Vec<Regime> = obs.iter().map(|&x| det.observe(x).unwrap()).collect();
        let events = det.drain_events();
        (regimes, events)
    };
    let (r1, e1) = run(&observations);
    let (r2, e2) = run(&observations);
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_detector_max_run_length_truncation() {
    let config = DetectorConfig {
        detector_id: "det".to_string(),
        metric_stream: "m".to_string(),
        max_run_length: 5,
        classifier: RegimeClassifier::default(),
        prior: NormalStats::default_prior(),
        hazard_lambda: 100,
    };
    let mut det = RegimeDetector::new(config, SecurityEpoch::GENESIS);
    for _ in 0..30 {
        det.observe(500_000).unwrap();
    }
    assert!(det.most_probable_run_length() <= 5);
}

#[test]
fn enrichment_detector_large_values_no_panic() {
    let mut det = test_detector("stress");
    for _ in 0..10 {
        det.observe(10_000_000).unwrap();
    }
    assert_eq!(det.observation_count(), 10);
    assert_eq!(det.regime(), Regime::Attack);
}

#[test]
fn enrichment_multi_stream_new_empty() {
    let multi = MultiStreamDetector::new();
    assert_eq!(multi.stream_count(), 0);
    assert_eq!(multi.overall_regime(), Regime::Normal);
}

#[test]
fn enrichment_multi_stream_register_and_observe() {
    let mut multi = MultiStreamDetector::new();
    multi.register(test_detector("cpu"));
    multi.register(test_detector("mem"));
    assert_eq!(multi.stream_count(), 2);
    multi.observe("cpu", 300_000).unwrap();
    assert_eq!(multi.get("cpu").unwrap().observation_count(), 1);
}

#[test]
fn enrichment_multi_stream_unknown_stream_error() {
    let mut multi = MultiStreamDetector::new();
    let err = multi.observe("nonexistent", 100_000).unwrap_err();
    assert_eq!(
        err,
        DetectorError::UnknownMetricStream {
            stream: "nonexistent".to_string(),
        }
    );
}

#[test]
fn enrichment_multi_stream_overall_worst_case() {
    let mut multi = MultiStreamDetector::new();
    multi.register(test_detector("a"));
    multi.register(test_detector("b"));
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }
    for _ in 0..15 {
        multi.observe("b", 300_000).unwrap();
    }
    assert!(multi.overall_regime() >= Regime::Elevated);
}

#[test]
fn enrichment_multi_stream_drain_all_events_both_streams() {
    let mut multi = MultiStreamDetector::new();
    multi.register(test_detector("a"));
    multi.register(test_detector("b"));
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
        multi.observe("b", 950_000).unwrap();
    }
    let events = multi.drain_all_events();
    let streams: BTreeSet<&str> = events.iter().map(|e| e.metric_stream.as_str()).collect();
    assert!(streams.contains("a"));
    assert!(streams.contains("b"));
    assert!(multi.drain_all_events().is_empty());
}

#[test]
fn enrichment_multi_stream_set_epoch() {
    let mut multi = MultiStreamDetector::new();
    multi.register(test_detector("a"));
    multi.set_epoch(SecurityEpoch::from_raw(99));
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }
    let events = multi.drain_all_events();
    if let Some(event) = events.last() {
        assert_eq!(event.epoch, SecurityEpoch::from_raw(99));
    }
}

#[test]
fn enrichment_multi_stream_regime_for_missing() {
    let multi = MultiStreamDetector::new();
    assert!(multi.regime("missing").is_none());
}

#[test]
fn enrichment_multi_stream_get_for_missing() {
    let multi = MultiStreamDetector::new();
    assert!(multi.get("missing").is_none());
}

#[test]
fn enrichment_multi_stream_register_replaces() {
    let mut multi = MultiStreamDetector::new();
    multi.register(test_detector("a"));
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }
    assert!(multi.regime("a").unwrap() >= Regime::Elevated);
    multi.register(test_detector("a"));
    assert_eq!(multi.regime("a"), Some(Regime::Normal));
}

#[test]
fn enrichment_detector_error_display() {
    let e1 = DetectorError::InvalidObservation {
        reason: "out of range".to_string(),
    };
    assert!(e1.to_string().contains("out of range"));
    let e2 = DetectorError::UnknownMetricStream {
        stream: "xyz".to_string(),
    };
    assert!(e2.to_string().contains("xyz"));
}

#[test]
fn enrichment_detector_error_serde_roundtrip() {
    let errors = vec![
        DetectorError::InvalidObservation {
            reason: "test".to_string(),
        },
        DetectorError::UnknownMetricStream {
            stream: "s".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: DetectorError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_regime_change_event_serde_roundtrip() {
    let event = RegimeChangeEvent {
        detector_id: "det-1".to_string(),
        metric_stream: "cpu".to_string(),
        old_regime: Regime::Normal,
        new_regime: Regime::Attack,
        confidence_millionths: 500_000,
        change_point_index: 25,
        epoch: SecurityEpoch::from_raw(10),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RegimeChangeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_regime_change_event_fields_correct() {
    let mut det = RegimeDetector::new(
        DetectorConfig {
            detector_id: "det-field-check".to_string(),
            metric_stream: "cpu_load".to_string(),
            max_run_length: 50,
            classifier: RegimeClassifier::default(),
            prior: NormalStats::default_prior(),
            hazard_lambda: 100,
        },
        SecurityEpoch::from_raw(7),
    );
    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    let events = det.drain_events();
    assert!(!events.is_empty());
    let event = &events[0];
    assert_eq!(event.detector_id, "det-field-check");
    assert_eq!(event.metric_stream, "cpu_load");
    assert_eq!(event.old_regime, Regime::Normal);
    assert!(event.confidence_millionths >= 0);
    assert!(event.change_point_index > 0);
    assert_eq!(event.epoch, SecurityEpoch::from_raw(7));
}

#[test]
fn enrichment_detector_config_serde_roundtrip() {
    let config = test_config("test_stream");
    let json = serde_json::to_string(&config).unwrap();
    let back: DetectorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.detector_id, back.detector_id);
    assert_eq!(config.metric_stream, back.metric_stream);
    assert_eq!(config.max_run_length, back.max_run_length);
    assert_eq!(config.hazard_lambda, back.hazard_lambda);
    assert_eq!(config.classifier, back.classifier);
    assert_eq!(config.prior, back.prior);
}

#[test]
fn enrichment_multi_stream_deterministic_replay() {
    let observations = [
        ("a", 300_000i64),
        ("b", 500_000),
        ("a", 950_000),
        ("b", -600_000),
        ("a", 200_000),
    ];
    let run = || {
        let mut multi = MultiStreamDetector::new();
        multi.register(test_detector("a"));
        multi.register(test_detector("b"));
        let regimes: Vec<(String, Regime)> = observations
            .iter()
            .map(|(stream, val)| {
                let r = multi.observe(stream, *val).unwrap();
                (stream.to_string(), r)
            })
            .collect();
        let events = multi.drain_all_events();
        (regimes, events)
    };
    let (r1, e1) = run();
    let (r2, e2) = run();
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_detector_zero_observations_normal() {
    let mut det = test_detector("metric");
    for _ in 0..15 {
        det.observe(0).unwrap();
    }
    assert_eq!(det.regime(), Regime::Normal);
}

#[test]
fn enrichment_regime_transitions_chronological() {
    let mut det = test_detector("metric");
    for _ in 0..15 {
        det.observe(750_000).unwrap();
    }
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    for _ in 0..15 {
        det.observe(200_000).unwrap();
    }
    let events = det.drain_events();
    for w in events.windows(2) {
        assert!(w[1].change_point_index > w[0].change_point_index);
    }
}
