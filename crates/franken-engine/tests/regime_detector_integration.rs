//! Integration tests for the `regime_detector` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! regime classification, BOCPD change-point detection, multi-stream
//! coordination, epoch management, deterministic replay, error conditions,
//! and serde round-trips.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;

use frankenengine_engine::regime_detector::{
    ConstantHazard, DetectorConfig, DetectorError, HazardFunction, MultiStreamDetector,
    NormalStats, Regime, RegimeChangeEvent, RegimeClassifier, RegimeDetector,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config(stream: &str) -> DetectorConfig {
    DetectorConfig {
        detector_id: "det-int".to_string(),
        metric_stream: stream.to_string(),
        max_run_length: 50,
        classifier: RegimeClassifier::default(),
        prior: NormalStats::default_prior(),
        hazard_lambda: 100,
    }
}

fn make_detector(stream: &str) -> RegimeDetector {
    RegimeDetector::new(default_config(stream), SecurityEpoch::GENESIS)
}

// ===========================================================================
// Section 1: Regime Display
// ===========================================================================

#[test]
fn regime_display_all_variants() {
    assert_eq!(Regime::Normal.to_string(), "normal");
    assert_eq!(Regime::Elevated.to_string(), "elevated");
    assert_eq!(Regime::Attack.to_string(), "attack");
    assert_eq!(Regime::Degraded.to_string(), "degraded");
    assert_eq!(Regime::Recovery.to_string(), "recovery");
}

#[test]
fn regime_ordering_is_correct() {
    assert!(Regime::Normal < Regime::Elevated);
    assert!(Regime::Elevated < Regime::Attack);
    assert!(Regime::Attack < Regime::Degraded);
    assert!(Regime::Degraded < Regime::Recovery);
}

#[test]
fn regime_ordering_is_total() {
    let regimes = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ];
    for (i, a) in regimes.iter().enumerate() {
        for (j, b) in regimes.iter().enumerate() {
            if i < j {
                assert!(a < b, "{:?} should be < {:?}", a, b);
            } else if i == j {
                assert_eq!(a, b);
            } else {
                assert!(a > b, "{:?} should be > {:?}", a, b);
            }
        }
    }
}

#[test]
fn regime_clone_and_copy() {
    let r = Regime::Attack;
    let cloned = r;
    assert_eq!(r, cloned);
}

// ===========================================================================
// Section 2: Regime serde
// ===========================================================================

#[test]
fn regime_serde_round_trip_all_variants() {
    let regimes = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ];
    for regime in &regimes {
        let json = serde_json::to_string(regime).expect("serialize Regime");
        let restored: Regime = serde_json::from_str(&json).expect("deserialize Regime");
        assert_eq!(*regime, restored, "serde failed for {:?}", regime);
    }
}

#[test]
fn regime_btree_map_key_deterministic() {
    let mut map = BTreeMap::new();
    map.insert(Regime::Attack, "attack");
    map.insert(Regime::Normal, "normal");
    map.insert(Regime::Elevated, "elevated");

    let keys: Vec<Regime> = map.keys().copied().collect();
    assert_eq!(keys, vec![Regime::Normal, Regime::Elevated, Regime::Attack]);
}

// ===========================================================================
// Section 3: ConstantHazard
// ===========================================================================

#[test]
fn constant_hazard_rate_correct() {
    let h = ConstantHazard { lambda: 100 };
    // 1/100 = 0.01 = 10_000 millionths
    assert_eq!(h.hazard(0), 10_000);
    assert_eq!(h.hazard(50), 10_000);
    assert_eq!(h.hazard(u64::MAX), 10_000);
}

#[test]
fn constant_hazard_zero_lambda_always_changes() {
    let h = ConstantHazard { lambda: 0 };
    assert_eq!(h.hazard(0), 1_000_000);
    assert_eq!(h.hazard(999), 1_000_000);
}

#[test]
fn constant_hazard_lambda_one_gives_certainty() {
    let h = ConstantHazard { lambda: 1 };
    assert_eq!(h.hazard(0), 1_000_000); // 1/1 = 1.0
}

#[test]
fn constant_hazard_large_lambda_gives_small_rate() {
    let h = ConstantHazard { lambda: 1_000_000 };
    // 1/1M = 0.000001 = 1 millionth
    assert_eq!(h.hazard(0), 1);
}

#[test]
fn constant_hazard_serde_round_trip() {
    let h = ConstantHazard { lambda: 42 };
    let json = serde_json::to_string(&h).expect("serialize");
    let restored: ConstantHazard = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(h.lambda, restored.lambda);
}

#[test]
fn constant_hazard_is_independent_of_run_length() {
    let h = ConstantHazard { lambda: 50 };
    let rate0 = h.hazard(0);
    let rate100 = h.hazard(100);
    let rate10000 = h.hazard(10000);
    assert_eq!(rate0, rate100);
    assert_eq!(rate100, rate10000);
}

// ===========================================================================
// Section 4: NormalStats
// ===========================================================================

#[test]
fn normal_stats_default_prior_values() {
    let prior = NormalStats::default_prior();
    assert_eq!(prior.mu0, 0);
    assert_eq!(prior.kappa0, 100_000); // 0.1
    assert_eq!(prior.alpha0, 1_000_000); // 1.0
    assert_eq!(prior.beta0, 1_000_000); // 1.0
}

#[test]
fn normal_stats_serde_round_trip() {
    let stats = NormalStats::default_prior();
    let json = serde_json::to_string(&stats).expect("serialize");
    let restored: NormalStats = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stats, restored);
}

#[test]
fn normal_stats_custom_prior_serde() {
    let stats = NormalStats {
        mu0: 500_000,
        kappa0: 200_000,
        alpha0: 2_000_000,
        beta0: 3_000_000,
    };
    let json = serde_json::to_string(&stats).expect("serialize");
    let restored: NormalStats = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(stats, restored);
}

// ===========================================================================
// Section 5: RegimeClassifier
// ===========================================================================

#[test]
fn classifier_default_thresholds() {
    let c = RegimeClassifier::default();
    assert_eq!(c.elevated_threshold, 700_000);
    assert_eq!(c.attack_threshold, 900_000);
    assert_eq!(c.degraded_threshold, -500_000);
}

#[test]
fn classifier_normal_range() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(0), Regime::Normal);
    assert_eq!(c.classify(100_000), Regime::Normal);
    assert_eq!(c.classify(500_000), Regime::Normal);
    assert_eq!(c.classify(699_999), Regime::Normal);
}

#[test]
fn classifier_elevated_range() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(700_000), Regime::Elevated);
    assert_eq!(c.classify(800_000), Regime::Elevated);
    assert_eq!(c.classify(899_999), Regime::Elevated);
}

#[test]
fn classifier_attack_range() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(900_000), Regime::Attack);
    assert_eq!(c.classify(1_000_000), Regime::Attack);
    assert_eq!(c.classify(10_000_000), Regime::Attack);
}

#[test]
fn classifier_degraded_range() {
    let c = RegimeClassifier::default();
    assert_eq!(c.classify(-500_000), Regime::Degraded);
    assert_eq!(c.classify(-1_000_000), Regime::Degraded);
    assert_eq!(c.classify(-999_999_999), Regime::Degraded);
}

#[test]
fn classifier_boundary_values() {
    let c = RegimeClassifier::default();
    // Exactly at thresholds.
    assert_eq!(c.classify(-500_000), Regime::Degraded);
    assert_eq!(c.classify(-499_999), Regime::Normal);
    assert_eq!(c.classify(700_000), Regime::Elevated);
    assert_eq!(c.classify(899_999), Regime::Elevated);
    assert_eq!(c.classify(900_000), Regime::Attack);
}

#[test]
fn classifier_custom_thresholds() {
    let c = RegimeClassifier {
        elevated_threshold: 500_000,
        attack_threshold: 800_000,
        degraded_threshold: -200_000,
    };
    assert_eq!(c.classify(0), Regime::Normal);
    assert_eq!(c.classify(499_999), Regime::Normal);
    assert_eq!(c.classify(500_000), Regime::Elevated);
    assert_eq!(c.classify(800_000), Regime::Attack);
    assert_eq!(c.classify(-200_000), Regime::Degraded);
    assert_eq!(c.classify(-199_999), Regime::Normal);
}

#[test]
fn classifier_serde_round_trip() {
    let c = RegimeClassifier::default();
    let json = serde_json::to_string(&c).expect("serialize");
    let restored: RegimeClassifier = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, restored);
}

// ===========================================================================
// Section 6: DetectorError — Display and serde
// ===========================================================================

#[test]
fn detector_error_display_invalid_observation() {
    let err = DetectorError::InvalidObservation {
        reason: "NaN detected".to_string(),
    };
    assert_eq!(err.to_string(), "invalid observation: NaN detected");
}

#[test]
fn detector_error_display_unknown_stream() {
    let err = DetectorError::UnknownMetricStream {
        stream: "cpu_load".to_string(),
    };
    assert_eq!(err.to_string(), "unknown metric stream: cpu_load");
}

#[test]
fn detector_error_is_std_error() {
    let err = DetectorError::InvalidObservation {
        reason: "test".to_string(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.to_string().contains("invalid observation"));
}

#[test]
fn detector_error_serde_round_trip() {
    let errors = vec![
        DetectorError::InvalidObservation {
            reason: "overflow".to_string(),
        },
        DetectorError::UnknownMetricStream {
            stream: "mem_usage".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize DetectorError");
        let restored: DetectorError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// Section 7: RegimeChangeEvent serde
// ===========================================================================

#[test]
fn regime_change_event_serde_round_trip() {
    let event = RegimeChangeEvent {
        detector_id: "det-1".to_string(),
        metric_stream: "hostcall_rate".to_string(),
        old_regime: Regime::Normal,
        new_regime: Regime::Attack,
        confidence_millionths: 750_000,
        change_point_index: 42,
        epoch: SecurityEpoch::from_raw(3),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: RegimeChangeEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn regime_change_event_all_regime_transitions() {
    let transitions = [
        (Regime::Normal, Regime::Elevated),
        (Regime::Elevated, Regime::Attack),
        (Regime::Attack, Regime::Degraded),
        (Regime::Degraded, Regime::Recovery),
        (Regime::Recovery, Regime::Normal),
    ];
    for (old, new) in &transitions {
        let event = RegimeChangeEvent {
            detector_id: "det-t".to_string(),
            metric_stream: "stream-t".to_string(),
            old_regime: *old,
            new_regime: *new,
            confidence_millionths: 500_000,
            change_point_index: 1,
            epoch: SecurityEpoch::GENESIS,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: RegimeChangeEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }
}

// ===========================================================================
// Section 8: RegimeDetector — construction and initial state
// ===========================================================================

#[test]
fn new_detector_starts_in_normal_regime() {
    let det = make_detector("test-stream");
    assert_eq!(det.regime(), Regime::Normal);
}

#[test]
fn new_detector_has_zero_observation_count() {
    let det = make_detector("test-stream");
    assert_eq!(det.observation_count(), 0);
}

#[test]
fn new_detector_most_probable_run_length_is_zero() {
    let det = make_detector("test-stream");
    assert_eq!(det.most_probable_run_length(), 0);
}

#[test]
fn new_detector_change_point_probability_is_full() {
    let det = make_detector("test-stream");
    // Initially all mass at run-length 0.
    assert_eq!(det.change_point_probability(), 1_000_000);
}

#[test]
fn new_detector_config_accessible() {
    let det = make_detector("my-stream");
    assert_eq!(det.config().detector_id, "det-int");
    assert_eq!(det.config().metric_stream, "my-stream");
    assert_eq!(det.config().max_run_length, 50);
    assert_eq!(det.config().hazard_lambda, 100);
}

#[test]
fn new_detector_drains_empty_events() {
    let mut det = make_detector("s");
    let events = det.drain_events();
    assert!(events.is_empty());
}

// ===========================================================================
// Section 9: RegimeDetector — single observations
// ===========================================================================

#[test]
fn single_observation_increments_count() {
    let mut det = make_detector("s");
    det.observe(300_000).unwrap();
    assert_eq!(det.observation_count(), 1);
}

#[test]
fn single_normal_observation_stays_normal() {
    let mut det = make_detector("s");
    let regime = det.observe(300_000).unwrap();
    assert_eq!(regime, Regime::Normal);
}

#[test]
fn multiple_observations_increment_count() {
    let mut det = make_detector("s");
    for i in 0..10 {
        det.observe(300_000).unwrap();
        assert_eq!(det.observation_count(), (i + 1) as u64);
    }
}

// ===========================================================================
// Section 10: Normal regime stability
// ===========================================================================

#[test]
fn normal_observations_maintain_normal() {
    let mut det = make_detector("s");
    for _ in 0..30 {
        let regime = det.observe(300_000).unwrap(); // 0.3 well within normal
        assert_eq!(regime, Regime::Normal);
    }
    let events = det.drain_events();
    assert!(events.is_empty(), "no regime changes expected");
}

#[test]
fn run_length_increases_during_stable_observations() {
    let mut det = make_detector("s");
    for _ in 0..30 {
        det.observe(500_000).unwrap();
    }
    assert!(
        det.most_probable_run_length() > 0,
        "stable observations should increase most-probable run length"
    );
}

#[test]
fn change_point_probability_decreases_during_stability() {
    let mut det = make_detector("s");
    let initial_cp = det.change_point_probability();

    for _ in 0..20 {
        det.observe(300_000).unwrap();
    }

    let cp_after = det.change_point_probability();
    assert!(
        cp_after < initial_cp,
        "CP prob should decrease during stability: {} vs {}",
        cp_after,
        initial_cp
    );
}

// ===========================================================================
// Section 11: Regime transitions
// ===========================================================================

#[test]
fn high_observations_trigger_elevated_or_attack() {
    let mut det = make_detector("s");

    // Fill window with normal.
    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }
    assert_eq!(det.regime(), Regime::Normal);

    // Push with very high observations (attack territory: 0.95).
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    // After many high observations, window mean should be above elevated.
    assert!(
        det.regime() >= Regime::Elevated,
        "regime should be at least Elevated, got {:?}",
        det.regime()
    );
}

#[test]
fn transition_emits_regime_change_event() {
    let mut det = make_detector("hostcall");

    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }

    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    let events = det.drain_events();
    assert!(
        !events.is_empty(),
        "at least one regime change event expected"
    );

    for event in &events {
        assert_eq!(event.detector_id, "det-int");
        assert_eq!(event.metric_stream, "hostcall");
        assert_ne!(event.old_regime, event.new_regime);
        assert!(event.change_point_index > 0);
        assert_eq!(event.epoch, SecurityEpoch::GENESIS);
    }
}

#[test]
fn negative_observations_trigger_degraded() {
    let mut det = make_detector("s");

    // Fill window with very negative values.
    for _ in 0..15 {
        det.observe(-1_000_000).unwrap();
    }

    assert_eq!(
        det.regime(),
        Regime::Degraded,
        "very negative observations should trigger Degraded"
    );
}

#[test]
fn transition_back_to_normal_from_attack() {
    let mut det = make_detector("s");

    // Push to attack.
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    assert!(det.regime() >= Regime::Elevated);

    // Transition back to normal.
    for _ in 0..15 {
        det.observe(300_000).unwrap();
    }

    assert_eq!(
        det.regime(),
        Regime::Normal,
        "should return to Normal after sustained normal observations"
    );
}

// ===========================================================================
// Section 12: Drain events clears buffer
// ===========================================================================

#[test]
fn drain_events_clears_internal_buffer() {
    let mut det = make_detector("s");

    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    let events1 = det.drain_events();
    assert!(!events1.is_empty());

    let events2 = det.drain_events();
    assert!(events2.is_empty(), "second drain should be empty");
}

// ===========================================================================
// Section 13: set_epoch
// ===========================================================================

#[test]
fn set_epoch_updates_events() {
    let mut det = make_detector("s");

    let new_epoch = SecurityEpoch::from_raw(7);
    det.set_epoch(new_epoch);

    // Trigger a transition.
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    let events = det.drain_events();
    if let Some(event) = events.last() {
        assert_eq!(event.epoch, new_epoch);
    }
}

#[test]
fn set_epoch_to_genesis_then_advance() {
    let mut det = make_detector("s");
    assert_eq!(det.config().detector_id, "det-int");

    det.set_epoch(SecurityEpoch::GENESIS);
    det.observe(300_000).unwrap();

    det.set_epoch(SecurityEpoch::from_raw(1));
    // Trigger transition.
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    let events = det.drain_events();
    if let Some(event) = events.last() {
        assert_eq!(event.epoch, SecurityEpoch::from_raw(1));
    }
}

// ===========================================================================
// Section 14: Deterministic replay
// ===========================================================================

#[test]
fn deterministic_replay_identical_regime_sequence() {
    let observations = vec![
        300_000i64, 300_000, 310_000, 290_000, 300_000, 950_000, 960_000, 940_000, 950_000,
        950_000, 300_000, 300_000, 300_000, 300_000, 300_000,
    ];

    let run = |obs: &[i64]| -> (Vec<Regime>, Vec<RegimeChangeEvent>) {
        let mut det = make_detector("m");
        let regimes: Vec<Regime> = obs.iter().map(|&x| det.observe(x).unwrap()).collect();
        let events = det.drain_events();
        (regimes, events)
    };

    let (regimes1, events1) = run(&observations);
    let (regimes2, events2) = run(&observations);

    assert_eq!(regimes1, regimes2, "regime sequences must match on replay");
    assert_eq!(events1, events2, "events must match on replay");
}

#[test]
fn deterministic_replay_run_lengths_match() {
    let observations: Vec<i64> = (0..30).map(|i| 300_000 + (i * 1000)).collect();

    let run = |obs: &[i64]| -> usize {
        let mut det = make_detector("m");
        for &x in obs {
            det.observe(x).unwrap();
        }
        det.most_probable_run_length()
    };

    let rl1 = run(&observations);
    let rl2 = run(&observations);
    assert_eq!(rl1, rl2);
}

#[test]
fn deterministic_replay_change_point_probability_matches() {
    let observations: Vec<i64> = (0..20)
        .map(|i| if i < 10 { 300_000 } else { 950_000 })
        .collect();

    let run = |obs: &[i64]| -> i64 {
        let mut det = make_detector("m");
        for &x in obs {
            det.observe(x).unwrap();
        }
        det.change_point_probability()
    };

    let cp1 = run(&observations);
    let cp2 = run(&observations);
    assert_eq!(cp1, cp2);
}

// ===========================================================================
// Section 15: MultiStreamDetector — construction
// ===========================================================================

#[test]
fn multi_stream_new_is_empty() {
    let multi = MultiStreamDetector::new();
    assert_eq!(multi.stream_count(), 0);
}

#[test]
fn multi_stream_default_is_empty() {
    let multi = MultiStreamDetector::default();
    assert_eq!(multi.stream_count(), 0);
}

#[test]
fn multi_stream_register_adds_stream() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));
    assert_eq!(multi.stream_count(), 1);

    multi.register(make_detector("mem_usage"));
    assert_eq!(multi.stream_count(), 2);
}

#[test]
fn multi_stream_register_overwrites_duplicate_stream() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));
    multi.register(make_detector("cpu_load")); // re-register same stream
    assert_eq!(multi.stream_count(), 1);
}

// ===========================================================================
// Section 16: MultiStreamDetector — regime queries
// ===========================================================================

#[test]
fn multi_stream_regime_returns_some_for_registered() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));
    assert_eq!(multi.regime("cpu_load"), Some(Regime::Normal));
}

#[test]
fn multi_stream_regime_returns_none_for_unregistered() {
    let multi = MultiStreamDetector::new();
    assert_eq!(multi.regime("nonexistent"), None);
}

#[test]
fn multi_stream_get_returns_detector() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));

    let det = multi.get("cpu_load").expect("detector should exist");
    assert_eq!(det.config().metric_stream, "cpu_load");
}

#[test]
fn multi_stream_get_returns_none_for_missing() {
    let multi = MultiStreamDetector::new();
    assert!(multi.get("ghost").is_none());
}

// ===========================================================================
// Section 17: MultiStreamDetector — observe
// ===========================================================================

#[test]
fn multi_stream_observe_updates_detector() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));

    multi.observe("cpu_load", 300_000).unwrap();
    assert_eq!(multi.get("cpu_load").unwrap().observation_count(), 1);
}

#[test]
fn multi_stream_observe_unknown_stream_returns_error() {
    let mut multi = MultiStreamDetector::new();
    let err = multi.observe("nonexistent", 100_000).unwrap_err();
    assert_eq!(
        err,
        DetectorError::UnknownMetricStream {
            stream: "nonexistent".to_string()
        }
    );
}

#[test]
fn multi_stream_observe_returns_regime() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu_load"));

    let regime = multi.observe("cpu_load", 300_000).unwrap();
    assert_eq!(regime, Regime::Normal);
}

// ===========================================================================
// Section 18: MultiStreamDetector — overall_regime (worst case)
// ===========================================================================

#[test]
fn multi_stream_overall_regime_empty_returns_normal() {
    let multi = MultiStreamDetector::new();
    assert_eq!(multi.overall_regime(), Regime::Normal);
}

#[test]
fn multi_stream_overall_regime_worst_case() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));
    multi.register(make_detector("b"));

    // Push "a" to attack.
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }
    // Keep "b" normal.
    for _ in 0..15 {
        multi.observe("b", 300_000).unwrap();
    }

    assert!(
        multi.overall_regime() >= Regime::Elevated,
        "overall should be worst-case across streams"
    );
}

#[test]
fn multi_stream_overall_regime_all_normal() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));
    multi.register(make_detector("b"));

    for _ in 0..15 {
        multi.observe("a", 300_000).unwrap();
        multi.observe("b", 200_000).unwrap();
    }

    assert_eq!(multi.overall_regime(), Regime::Normal);
}

// ===========================================================================
// Section 19: MultiStreamDetector — drain_all_events
// ===========================================================================

#[test]
fn multi_stream_drain_all_events_collects_from_all_detectors() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));
    multi.register(make_detector("b"));

    // Trigger regime change on "a".
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }

    let events = multi.drain_all_events();
    assert!(!events.is_empty());

    // All events should be from stream "a".
    for event in &events {
        assert_eq!(event.metric_stream, "a");
    }
}

#[test]
fn multi_stream_drain_all_events_clears_buffers() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));

    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }

    let events1 = multi.drain_all_events();
    assert!(!events1.is_empty());

    let events2 = multi.drain_all_events();
    assert!(events2.is_empty(), "second drain should be empty");
}

// ===========================================================================
// Section 20: MultiStreamDetector — set_epoch
// ===========================================================================

#[test]
fn multi_stream_set_epoch_updates_all_detectors() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));
    multi.register(make_detector("b"));

    let epoch5 = SecurityEpoch::from_raw(5);
    multi.set_epoch(epoch5);

    // Trigger change event on "a".
    for _ in 0..15 {
        multi.observe("a", 950_000).unwrap();
    }

    let events = multi.drain_all_events();
    if let Some(event) = events.last() {
        assert_eq!(event.epoch, epoch5);
    }
}

// ===========================================================================
// Section 21: DetectorConfig serde
// ===========================================================================

#[test]
fn detector_config_serde_round_trip() {
    let config = default_config("hostcall_rate");
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: DetectorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.detector_id, config.detector_id);
    assert_eq!(restored.metric_stream, config.metric_stream);
    assert_eq!(restored.max_run_length, config.max_run_length);
    assert_eq!(restored.hazard_lambda, config.hazard_lambda);
}

// ===========================================================================
// Section 22: Edge cases
// ===========================================================================

#[test]
fn zero_observation_does_not_panic() {
    let mut det = make_detector("s");
    let regime = det.observe(0).unwrap();
    assert_eq!(regime, Regime::Normal);
}

#[test]
fn large_positive_observation_classifies_as_attack() {
    let mut det = make_detector("s");
    for _ in 0..15 {
        det.observe(10_000_000).unwrap(); // way above attack threshold
    }
    assert_eq!(det.regime(), Regime::Attack);
}

#[test]
fn large_negative_observation_classifies_as_degraded() {
    let mut det = make_detector("s");
    for _ in 0..15 {
        det.observe(-10_000_000).unwrap();
    }
    assert_eq!(det.regime(), Regime::Degraded);
}

#[test]
fn alternating_observations_settle_to_normal() {
    let mut det = make_detector("s");
    // Alternate between 300K and 400K (both well within normal).
    for i in 0..30 {
        let val = if i % 2 == 0 { 300_000 } else { 400_000 };
        det.observe(val).unwrap();
    }
    assert_eq!(det.regime(), Regime::Normal);
}

#[test]
fn rapid_oscillation_between_normal_and_attack() {
    let mut det = make_detector("s");
    // Feed rapid oscillation: should settle based on window mean.
    for i in 0..30 {
        let val = if i % 2 == 0 { 100_000 } else { 950_000 };
        det.observe(val).unwrap();
    }
    // Mean of window = (100K + 950K) / 2 = 525K -> Normal.
    assert_eq!(det.regime(), Regime::Normal);
}

// ===========================================================================
// Section 23: Max run-length truncation
// ===========================================================================

#[test]
fn max_run_length_is_respected() {
    let config = DetectorConfig {
        detector_id: "short".to_string(),
        metric_stream: "s".to_string(),
        max_run_length: 5, // very small
        classifier: RegimeClassifier::default(),
        prior: NormalStats::default_prior(),
        hazard_lambda: 100,
    };
    let mut det = RegimeDetector::new(config, SecurityEpoch::GENESIS);

    // Feed many observations.
    for _ in 0..50 {
        det.observe(300_000).unwrap();
    }

    // Most probable run length should be <= max_run_length.
    assert!(
        det.most_probable_run_length() <= 5,
        "run length should be <= max: {}",
        det.most_probable_run_length()
    );
}

// ===========================================================================
// Section 24: Custom prior affects sensitivity
// ===========================================================================

#[test]
fn tight_prior_detects_change_faster() {
    let tight_config = DetectorConfig {
        detector_id: "tight".to_string(),
        metric_stream: "s".to_string(),
        max_run_length: 50,
        classifier: RegimeClassifier::default(),
        prior: NormalStats {
            mu0: 300_000,    // centered at normal
            kappa0: 500_000, // tighter prior (0.5 vs 0.1)
            alpha0: 2_000_000,
            beta0: 500_000, // smaller variance
        },
        hazard_lambda: 50, // shorter expected run
    };

    let mut det = RegimeDetector::new(tight_config, SecurityEpoch::GENESIS);

    // Feed normal observations.
    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }

    // Shift to attack-level.
    for _ in 0..10 {
        det.observe(950_000).unwrap();
    }

    // With tighter prior and shorter hazard, should detect more quickly.
    assert!(
        det.regime() >= Regime::Elevated,
        "tight prior should detect regime shift"
    );
}

// ===========================================================================
// Section 25: Multiple streams independent behavior
// ===========================================================================

#[test]
fn multi_stream_detectors_are_independent() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu"));
    multi.register(make_detector("mem"));
    multi.register(make_detector("net"));

    // Only push "cpu" to attack.
    for _ in 0..15 {
        multi.observe("cpu", 950_000).unwrap();
        multi.observe("mem", 300_000).unwrap();
        multi.observe("net", 300_000).unwrap();
    }

    assert!(multi.regime("cpu").unwrap() >= Regime::Elevated);
    assert_eq!(multi.regime("mem").unwrap(), Regime::Normal);
    assert_eq!(multi.regime("net").unwrap(), Regime::Normal);
}

#[test]
fn multi_stream_events_from_different_streams() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("cpu"));
    multi.register(make_detector("mem"));

    // Push both to attack but at different times.
    for _ in 0..15 {
        multi.observe("cpu", 950_000).unwrap();
    }
    for _ in 0..15 {
        multi.observe("mem", 950_000).unwrap();
    }

    let events = multi.drain_all_events();
    let cpu_events: Vec<_> = events.iter().filter(|e| e.metric_stream == "cpu").collect();
    let mem_events: Vec<_> = events.iter().filter(|e| e.metric_stream == "mem").collect();

    assert!(!cpu_events.is_empty(), "cpu should have regime events");
    assert!(!mem_events.is_empty(), "mem should have regime events");
}

// ===========================================================================
// Section 26: Observation count across multi-stream
// ===========================================================================

#[test]
fn multi_stream_observation_counts_independent() {
    let mut multi = MultiStreamDetector::new();
    multi.register(make_detector("a"));
    multi.register(make_detector("b"));

    for _ in 0..5 {
        multi.observe("a", 300_000).unwrap();
    }
    for _ in 0..10 {
        multi.observe("b", 300_000).unwrap();
    }

    assert_eq!(multi.get("a").unwrap().observation_count(), 5);
    assert_eq!(multi.get("b").unwrap().observation_count(), 10);
}

// ===========================================================================
// Section 27: Window-based classification
// ===========================================================================

#[test]
fn window_size_affects_regime_detection_latency() {
    // Default window size is 10. After 10 high observations, mean should be high.
    let mut det = make_detector("s");

    // Fill with normal first.
    for _ in 0..10 {
        det.observe(300_000).unwrap();
    }

    // Transition: feed 10 high observations.
    for i in 0..10 {
        det.observe(950_000).unwrap();
        // After enough high observations to push the window mean up.
        if i >= 9 {
            assert!(
                det.regime() >= Regime::Elevated,
                "regime should be elevated after window fills with high values"
            );
        }
    }
}

// ===========================================================================
// Section 28: SecurityEpoch integration
// ===========================================================================

#[test]
fn detector_uses_specified_epoch_in_events() {
    let epoch = SecurityEpoch::from_raw(42);
    let mut det = RegimeDetector::new(default_config("s"), epoch);

    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }

    let events = det.drain_events();
    for event in &events {
        assert_eq!(event.epoch, epoch);
    }
}

#[test]
fn detector_epoch_changes_reflected_in_subsequent_events() {
    let mut det = make_detector("s");

    // Trigger event with GENESIS epoch.
    for _ in 0..15 {
        det.observe(950_000).unwrap();
    }
    let events1 = det.drain_events();

    // Change epoch.
    det.set_epoch(SecurityEpoch::from_raw(10));

    // Trigger another event by transitioning back.
    for _ in 0..15 {
        det.observe(300_000).unwrap();
    }
    let events2 = det.drain_events();

    if !events1.is_empty() {
        assert_eq!(events1[0].epoch, SecurityEpoch::GENESIS);
    }
    if !events2.is_empty() {
        assert_eq!(events2.last().unwrap().epoch, SecurityEpoch::from_raw(10));
    }
}
