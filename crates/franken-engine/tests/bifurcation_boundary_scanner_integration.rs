#![forbid(unsafe_code)]
//! Integration tests for the `bifurcation_boundary_scanner` module.
//!
//! Covers: public constants, all public enums (Display, serde round-trip),
//! all public structs (construction, field access, serde round-trip),
//! OperatingEnvelope methods (range, in_bounds, proximity_millionths),
//! EarlyWarningIndicator::is_critical, ScanResult query methods,
//! BifurcationBoundaryScanner lifecycle (new, observe, update_parameter,
//! scan, stability_maps), validation error paths, determinism, and
//! multi-parameter full-lifecycle scenarios.

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

use frankenengine_engine::bifurcation_boundary_scanner::{
    BIFURCATION_SCHEMA_VERSION, BifurcationBoundaryScanner, BifurcationPoint, BifurcationType,
    ControlParameter, EarlyWarningIndicator, OperatingEnvelope, ParameterDomain,
    ParameterObservation, PreemptiveAction, ScanResult, ScannerConfig, ScannerError,
    StabilityMapEntry,
};
use frankenengine_engine::runtime_decision_theory::{LaneAction, RegimeLabel};
use frankenengine_engine::security_epoch::SecurityEpoch;

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_param(id: &str, value: i64) -> ControlParameter {
    ControlParameter {
        id: id.to_string(),
        label: format!("{id} parameter"),
        domain: ParameterDomain::RiskThreshold,
        current_value_millionths: value,
        policy_tunable: true,
    }
}

fn make_param_domain(id: &str, value: i64, domain: ParameterDomain) -> ControlParameter {
    ControlParameter {
        id: id.to_string(),
        label: format!("{id} parameter"),
        domain,
        current_value_millionths: value,
        policy_tunable: true,
    }
}

fn make_envelope(param_id: &str, lower: i64, upper: i64, nominal: i64) -> OperatingEnvelope {
    OperatingEnvelope {
        parameter_id: param_id.to_string(),
        lower_bound_millionths: lower,
        upper_bound_millionths: upper,
        nominal_millionths: nominal,
        criticality_millionths: MILLION / 2,
    }
}

fn default_scanner() -> BifurcationBoundaryScanner {
    let params = vec![
        make_param("threshold-1", 500_000),
        make_param("calibration-1", 750_000),
    ];
    let envelopes = vec![
        make_envelope("threshold-1", 100_000, 900_000, 500_000),
        make_envelope("calibration-1", 200_000, 800_000, 500_000),
    ];
    BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Public constant
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_nonempty_and_correct() {
    assert!(!BIFURCATION_SCHEMA_VERSION.is_empty());
    assert!(BIFURCATION_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BIFURCATION_SCHEMA_VERSION.contains("bifurcation"));
}

// ---------------------------------------------------------------------------
// 2. ParameterDomain enum — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn parameter_domain_display_exact_strings() {
    assert_eq!(ParameterDomain::RiskThreshold.to_string(), "risk-threshold");
    assert_eq!(ParameterDomain::Calibration.to_string(), "calibration");
    assert_eq!(
        ParameterDomain::ResourceAllocation.to_string(),
        "resource-allocation"
    );
    assert_eq!(ParameterDomain::LaneRouting.to_string(), "lane-routing");
    assert_eq!(
        ParameterDomain::SafetyBoundary.to_string(),
        "safety-boundary"
    );
    assert_eq!(ParameterDomain::Environment.to_string(), "environment");
}

#[test]
fn parameter_domain_serde_roundtrip_all_variants() {
    let all = [
        ParameterDomain::RiskThreshold,
        ParameterDomain::Calibration,
        ParameterDomain::ResourceAllocation,
        ParameterDomain::LaneRouting,
        ParameterDomain::SafetyBoundary,
        ParameterDomain::Environment,
    ];
    for d in all {
        let json = serde_json::to_string(&d).unwrap();
        let back: ParameterDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back, "roundtrip failed for {d}");
    }
}

// ---------------------------------------------------------------------------
// 3. BifurcationType enum — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn bifurcation_type_display_exact_strings() {
    assert_eq!(BifurcationType::SaddleNode.to_string(), "saddle-node");
    assert_eq!(BifurcationType::Transcritical.to_string(), "transcritical");
    assert_eq!(BifurcationType::Pitchfork.to_string(), "pitchfork");
    assert_eq!(BifurcationType::Hopf.to_string(), "hopf");
    assert_eq!(BifurcationType::Catastrophic.to_string(), "catastrophic");
    assert_eq!(BifurcationType::Gradual.to_string(), "gradual");
}

#[test]
fn bifurcation_type_serde_roundtrip_all_variants() {
    let all = [
        BifurcationType::SaddleNode,
        BifurcationType::Transcritical,
        BifurcationType::Pitchfork,
        BifurcationType::Hopf,
        BifurcationType::Catastrophic,
        BifurcationType::Gradual,
    ];
    for t in all {
        let json = serde_json::to_string(&t).unwrap();
        let back: BifurcationType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back, "roundtrip failed for {t}");
    }
}

// ---------------------------------------------------------------------------
// 4. ScannerError enum — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn scanner_error_display_all_variants_nonempty() {
    let variants: Vec<ScannerError> = vec![
        ScannerError::NoParameters,
        ScannerError::TooManyParameters {
            count: 200,
            max: 128,
        },
        ScannerError::NoEnvelopes,
        ScannerError::TooManyEnvelopes {
            count: 100,
            max: 64,
        },
        ScannerError::UnknownParameter {
            parameter_id: "x".into(),
        },
        ScannerError::DuplicateParameter {
            parameter_id: "x".into(),
        },
        ScannerError::InvertedBounds {
            parameter_id: "x".into(),
        },
        ScannerError::InvalidRiskBudget { value: -1 },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty(), "Display was empty for {v:?}");
    }
}

#[test]
fn scanner_error_display_specific_messages() {
    assert_eq!(
        ScannerError::NoParameters.to_string(),
        "no control parameters configured"
    );
    assert!(
        ScannerError::TooManyParameters {
            count: 200,
            max: 128
        }
        .to_string()
        .contains("200")
    );
    assert!(
        ScannerError::UnknownParameter {
            parameter_id: "xyz".into()
        }
        .to_string()
        .contains("xyz")
    );
}

#[test]
fn scanner_error_serde_roundtrip_all_variants() {
    let variants: Vec<ScannerError> = vec![
        ScannerError::NoParameters,
        ScannerError::TooManyParameters {
            count: 200,
            max: 128,
        },
        ScannerError::NoEnvelopes,
        ScannerError::TooManyEnvelopes {
            count: 100,
            max: 64,
        },
        ScannerError::UnknownParameter {
            parameter_id: "uk".into(),
        },
        ScannerError::DuplicateParameter {
            parameter_id: "dup".into(),
        },
        ScannerError::InvertedBounds {
            parameter_id: "inv".into(),
        },
        ScannerError::InvalidRiskBudget { value: -42 },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: ScannerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back, "roundtrip failed for {err:?}");
    }
}

#[test]
fn scanner_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ScannerError::NoParameters);
    assert!(!err.to_string().is_empty());
}

// ---------------------------------------------------------------------------
// 5. ControlParameter struct — construction, Display, serde, Clone
// ---------------------------------------------------------------------------

#[test]
fn control_parameter_display_contains_id_and_value() {
    let p = make_param("my-param", 123_456);
    let s = p.to_string();
    assert!(s.contains("my-param"));
    assert!(s.contains("123456"));
}

#[test]
fn control_parameter_serde_roundtrip() {
    let p = make_param_domain("cp-1", 750_000, ParameterDomain::Calibration);
    let json = serde_json::to_string(&p).unwrap();
    let back: ControlParameter = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn control_parameter_clone_eq() {
    let a = make_param("clone-test", 999);
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 6. OperatingEnvelope — methods (range, in_bounds, proximity_millionths)
// ---------------------------------------------------------------------------

#[test]
fn envelope_range_computation() {
    let env = make_envelope("x", 100_000, 900_000, 500_000);
    assert_eq!(env.range(), 800_000);
}

#[test]
fn envelope_in_bounds_inclusive() {
    let env = make_envelope("x", 100_000, 900_000, 500_000);
    // At boundaries (inclusive)
    assert!(env.in_bounds(100_000));
    assert!(env.in_bounds(900_000));
    // Inside
    assert!(env.in_bounds(500_000));
    // Outside
    assert!(!env.in_bounds(99_999));
    assert!(!env.in_bounds(900_001));
}

#[test]
fn envelope_proximity_at_center_is_max() {
    let env = make_envelope("x", 0, MILLION, 500_000);
    assert_eq!(env.proximity_millionths(500_000), MILLION);
}

#[test]
fn envelope_proximity_at_boundaries_is_zero() {
    let env = make_envelope("x", 0, MILLION, 500_000);
    assert_eq!(env.proximity_millionths(0), 0);
    assert_eq!(env.proximity_millionths(MILLION), 0);
}

#[test]
fn envelope_proximity_out_of_bounds_is_zero() {
    let env = make_envelope("x", 100_000, 900_000, 500_000);
    assert_eq!(env.proximity_millionths(50_000), 0);
    assert_eq!(env.proximity_millionths(950_000), 0);
}

#[test]
fn envelope_proximity_quarter_from_lower() {
    // [0, 1_000_000], half_range = 500_000
    // At value 250_000: dist_lower=250_000, dist_upper=750_000, min=250_000
    // proximity = 250_000 * 1_000_000 / 500_000 = 500_000
    let env = make_envelope("x", 0, MILLION, 500_000);
    assert_eq!(env.proximity_millionths(250_000), 500_000);
}

#[test]
fn envelope_zero_range_returns_million() {
    // When lower == upper, range() <= 0 => returns MILLION
    let env = make_envelope("x", 500_000, 500_000, 500_000);
    assert_eq!(env.range(), 0);
    assert_eq!(env.proximity_millionths(500_000), MILLION);
}

#[test]
fn envelope_serde_roundtrip() {
    let env = make_envelope("env-rt", 10_000, 990_000, 500_000);
    let json = serde_json::to_string(&env).unwrap();
    let back: OperatingEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

// ---------------------------------------------------------------------------
// 7. BifurcationPoint struct — construction, Clone, serde
// ---------------------------------------------------------------------------

#[test]
fn bifurcation_point_construction_and_fields() {
    let bp = BifurcationPoint {
        parameter_id: "bp-test".into(),
        critical_value_millionths: 400_000,
        bifurcation_type: BifurcationType::Hopf,
        regime_before: RegimeLabel::Normal,
        regime_after: RegimeLabel::Elevated,
        confidence_millionths: 850_000,
    };
    assert_eq!(bp.parameter_id, "bp-test");
    assert_eq!(bp.critical_value_millionths, 400_000);
    assert_eq!(bp.confidence_millionths, 850_000);
}

#[test]
fn bifurcation_point_serde_roundtrip() {
    let bp = BifurcationPoint {
        parameter_id: "bp-serde".into(),
        critical_value_millionths: 200_000,
        bifurcation_type: BifurcationType::Catastrophic,
        regime_before: RegimeLabel::Degraded,
        regime_after: RegimeLabel::Attack,
        confidence_millionths: 900_000,
    };
    let json = serde_json::to_string(&bp).unwrap();
    let back: BifurcationPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, back);
}

// ---------------------------------------------------------------------------
// 8. EarlyWarningIndicator — is_critical logic
// ---------------------------------------------------------------------------

#[test]
fn indicator_critical_when_active_and_above_threshold() {
    let ind = EarlyWarningIndicator {
        indicator_id: "ew-1".into(),
        parameter_id: "p".into(),
        risk_value_millionths: 900_000,
        threshold_millionths: 750_000,
        active: true,
        trend_millionths: 5_000,
        observation_count: 20,
    };
    assert!(ind.is_critical());
}

#[test]
fn indicator_not_critical_when_inactive() {
    let ind = EarlyWarningIndicator {
        indicator_id: "ew-2".into(),
        parameter_id: "p".into(),
        risk_value_millionths: 900_000,
        threshold_millionths: 750_000,
        active: false,
        trend_millionths: 0,
        observation_count: 0,
    };
    assert!(!ind.is_critical());
}

#[test]
fn indicator_not_critical_when_below_threshold() {
    let ind = EarlyWarningIndicator {
        indicator_id: "ew-3".into(),
        parameter_id: "p".into(),
        risk_value_millionths: 500_000,
        threshold_millionths: 750_000,
        active: true,
        trend_millionths: 0,
        observation_count: 10,
    };
    assert!(!ind.is_critical());
}

#[test]
fn indicator_serde_roundtrip() {
    let ind = EarlyWarningIndicator {
        indicator_id: "ew-serde".into(),
        parameter_id: "p-serde".into(),
        risk_value_millionths: 600_000,
        threshold_millionths: 750_000,
        active: true,
        trend_millionths: -5_000,
        observation_count: 42,
    };
    let json = serde_json::to_string(&ind).unwrap();
    let back: EarlyWarningIndicator = serde_json::from_str(&json).unwrap();
    assert_eq!(ind, back);
}

// ---------------------------------------------------------------------------
// 9. PreemptiveAction struct — construction, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn preemptive_action_display_contains_action_id() {
    let action = PreemptiveAction {
        action_id: "pa-display".into(),
        trigger_indicator_id: "ew-display".into(),
        parameter_id: "p-display".into(),
        lane_action: LaneAction::FallbackSafe,
        epoch: SecurityEpoch::GENESIS,
        trigger_risk_millionths: 800_000,
        rationale: "testing display".into(),
    };
    let s = action.to_string();
    assert!(s.contains("pa-display"));
    assert!(s.contains("800000"));
}

#[test]
fn preemptive_action_serde_roundtrip() {
    let action = PreemptiveAction {
        action_id: "pa-serde".into(),
        trigger_indicator_id: "ew-serde".into(),
        parameter_id: "p-serde".into(),
        lane_action: LaneAction::SuspendAdaptive,
        epoch: SecurityEpoch::from_raw(5),
        trigger_risk_millionths: 950_000,
        rationale: "roundtrip test".into(),
    };
    let json = serde_json::to_string(&action).unwrap();
    let back: PreemptiveAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, back);
}

// ---------------------------------------------------------------------------
// 10. StabilityMapEntry — construction, Clone, serde
// ---------------------------------------------------------------------------

#[test]
fn stability_map_entry_clone_eq() {
    let entry = StabilityMapEntry {
        value_millionths: 333_333,
        regime: RegimeLabel::Degraded,
        stability_millionths: 80_000,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn stability_map_entry_serde_roundtrip() {
    let entry = StabilityMapEntry {
        value_millionths: 750_000,
        regime: RegimeLabel::Normal,
        stability_millionths: 950_000,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: StabilityMapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// 11. ScannerConfig — Default values, serde
// ---------------------------------------------------------------------------

#[test]
fn scanner_config_default_values() {
    let cfg = ScannerConfig::default();
    assert_eq!(cfg.proximity_threshold_millionths, 250_000);
    assert_eq!(cfg.risk_budget_millionths, 500_000);
    assert_eq!(cfg.scan_steps, 20);
    assert_eq!(cfg.epoch, SecurityEpoch::GENESIS);
    assert!(!cfg.record_stability_maps);
}

#[test]
fn scanner_config_serde_roundtrip_custom() {
    let cfg = ScannerConfig {
        proximity_threshold_millionths: 50_000,
        risk_budget_millionths: 800_000,
        scan_steps: 50,
        epoch: SecurityEpoch::from_raw(7),
        record_stability_maps: true,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ScannerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// 12. ParameterObservation — serde
// ---------------------------------------------------------------------------

#[test]
fn parameter_observation_serde_roundtrip() {
    let obs = ParameterObservation {
        parameter_id: "obs-param".into(),
        value_millionths: 600_000,
        tick: 42,
        regime: RegimeLabel::Normal,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: ParameterObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

// ---------------------------------------------------------------------------
// 13. Scanner construction — validation error paths
// ---------------------------------------------------------------------------

#[test]
fn new_rejects_empty_parameters() {
    let r = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        vec![],
        vec![make_envelope("x", 0, MILLION, 500_000)],
    );
    assert!(matches!(r, Err(ScannerError::NoParameters)));
}

#[test]
fn new_rejects_empty_envelopes() {
    let r = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        vec![make_param("x", 500_000)],
        vec![],
    );
    assert!(matches!(r, Err(ScannerError::NoEnvelopes)));
}

#[test]
fn new_rejects_too_many_parameters() {
    let params: Vec<_> = (0..129)
        .map(|i| make_param(&format!("p-{i}"), 500_000))
        .collect();
    let envelopes = vec![make_envelope("p-0", 0, MILLION, 500_000)];
    let r = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
    assert!(matches!(
        r,
        Err(ScannerError::TooManyParameters {
            count: 129,
            max: 128
        })
    ));
}

#[test]
fn new_rejects_too_many_envelopes() {
    // Need 65 parameters + 65 envelopes to trigger TooManyEnvelopes
    let params: Vec<_> = (0..65)
        .map(|i| make_param(&format!("p-{i}"), 500_000))
        .collect();
    let envelopes: Vec<_> = (0..65)
        .map(|i| make_envelope(&format!("p-{i}"), 0, MILLION, 500_000))
        .collect();
    let r = BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes);
    assert!(matches!(
        r,
        Err(ScannerError::TooManyEnvelopes { count: 65, max: 64 })
    ));
}

#[test]
fn new_rejects_unknown_parameter_in_envelope() {
    let r = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        vec![make_param("a", 500_000)],
        vec![make_envelope("nonexistent", 0, MILLION, 500_000)],
    );
    assert!(matches!(r, Err(ScannerError::UnknownParameter { .. })));
}

#[test]
fn new_rejects_duplicate_parameter_ids() {
    let r = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        vec![make_param("dup", 500_000), make_param("dup", 600_000)],
        vec![make_envelope("dup", 0, MILLION, 500_000)],
    );
    assert!(matches!(r, Err(ScannerError::DuplicateParameter { .. })));
}

#[test]
fn new_rejects_inverted_bounds() {
    let r = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        vec![make_param("x", 500_000)],
        vec![make_envelope("x", MILLION, 0, 500_000)],
    );
    assert!(matches!(r, Err(ScannerError::InvertedBounds { .. })));
}

#[test]
fn new_rejects_zero_risk_budget() {
    let cfg = ScannerConfig {
        risk_budget_millionths: 0,
        ..Default::default()
    };
    let r = BifurcationBoundaryScanner::new(
        cfg,
        vec![make_param("x", 500_000)],
        vec![make_envelope("x", 0, MILLION, 500_000)],
    );
    assert!(matches!(
        r,
        Err(ScannerError::InvalidRiskBudget { value: 0 })
    ));
}

#[test]
fn new_rejects_negative_risk_budget() {
    let cfg = ScannerConfig {
        risk_budget_millionths: -1,
        ..Default::default()
    };
    let r = BifurcationBoundaryScanner::new(
        cfg,
        vec![make_param("x", 500_000)],
        vec![make_envelope("x", 0, MILLION, 500_000)],
    );
    assert!(matches!(
        r,
        Err(ScannerError::InvalidRiskBudget { value: -1 })
    ));
}

// ---------------------------------------------------------------------------
// 14. Scanner — happy-path construction and accessors
// ---------------------------------------------------------------------------

#[test]
fn scanner_initial_state() {
    let scanner = default_scanner();
    assert_eq!(scanner.scan_count(), 0);
    assert_eq!(scanner.parameter_count(), 2);
    assert_eq!(scanner.observation_count(), 0);
    assert!(scanner.stability_maps().is_empty());
}

#[test]
fn scanner_config_accessor() {
    let scanner = default_scanner();
    let cfg = scanner.config();
    assert_eq!(cfg.proximity_threshold_millionths, 250_000);
    assert_eq!(cfg.scan_steps, 20);
}

// ---------------------------------------------------------------------------
// 15. Scanner — observe and update_parameter
// ---------------------------------------------------------------------------

#[test]
fn observe_increments_count_and_updates_value() {
    let mut scanner = default_scanner();
    scanner.observe(ParameterObservation {
        parameter_id: "threshold-1".into(),
        value_millionths: 800_000,
        tick: 1,
        regime: RegimeLabel::Normal,
    });
    assert_eq!(scanner.observation_count(), 1);
}

#[test]
fn observe_for_unknown_parameter_still_records() {
    let mut scanner = default_scanner();
    scanner.observe(ParameterObservation {
        parameter_id: "nonexistent".into(),
        value_millionths: 123_456,
        tick: 1,
        regime: RegimeLabel::Normal,
    });
    // The observation is still stored even if the parameter_id is unknown
    assert_eq!(scanner.observation_count(), 1);
}

#[test]
fn update_parameter_changes_value_used_in_scan() {
    let mut scanner = default_scanner();
    scanner.update_parameter("threshold-1", 110_000); // Near lower boundary
    let result = scanner.scan().unwrap();
    // Should detect the near-boundary condition
    assert!(result.has_active_warnings());
}

#[test]
fn update_unknown_parameter_is_noop() {
    let mut scanner = default_scanner();
    scanner.update_parameter("nonexistent", 0);
    // No crash; scanner state unchanged
    assert_eq!(scanner.parameter_count(), 2);
}

// ---------------------------------------------------------------------------
// 16. Scanner — scan (happy path)
// ---------------------------------------------------------------------------

#[test]
fn scan_stable_parameters_schema_and_counts() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    assert_eq!(result.schema_version, BIFURCATION_SCHEMA_VERSION);
    assert_eq!(result.parameters_scanned, 2);
    assert!(result.stability_score_millionths > 0);
}

#[test]
fn scan_count_increments_per_call() {
    let mut scanner = default_scanner();
    assert_eq!(scanner.scan_count(), 0);
    scanner.scan().unwrap();
    assert_eq!(scanner.scan_count(), 1);
    scanner.scan().unwrap();
    assert_eq!(scanner.scan_count(), 2);
}

#[test]
fn scan_produces_bifurcation_points() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    // With a wide-range envelope and 20 scan steps, regime transitions are expected
    assert!(!result.bifurcation_points.is_empty());
}

#[test]
fn scan_result_has_nonzero_artifact_hash() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    assert_ne!(result.artifact_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn scan_result_has_regime_summary() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    assert!(!result.regime_summary.is_empty());
}

// ---------------------------------------------------------------------------
// 17. ScanResult query methods
// ---------------------------------------------------------------------------

#[test]
fn is_stable_at_nominal_values() {
    let params = vec![make_param("a", 500_000), make_param("b", 500_000)];
    let envelopes = vec![
        make_envelope("a", 100_000, 900_000, 500_000),
        make_envelope("b", 200_000, 800_000, 500_000),
    ];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(result.is_stable());
}

#[test]
fn not_stable_when_preemptive_actions_present() {
    let params = vec![make_param("x", 50_000)]; // Below lower bound
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(!result.is_stable());
    assert!(result.has_preemptive_actions());
}

#[test]
fn has_active_warnings_near_boundary() {
    let params = vec![make_param("x", 110_000)]; // Near lower boundary
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(result.has_active_warnings());
}

#[test]
fn no_warnings_at_nominal() {
    let params = vec![make_param("x", 500_000)];
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(!result.has_active_warnings());
    assert!(!result.has_preemptive_actions());
}

#[test]
fn critical_warning_count_bounded() {
    let params = vec![make_param("x", 105_000)];
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(result.critical_warning_count() <= 1);
}

// ---------------------------------------------------------------------------
// 18. Preemptive action — out-of-bounds triggers SuspendAdaptive
// ---------------------------------------------------------------------------

#[test]
fn preemptive_action_out_of_bounds_suspends_adaptive() {
    let params = vec![make_param("x", -100_000)]; // Way below lower bound
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert!(result.has_preemptive_actions());
    let action = &result.preemptive_actions[0];
    assert!(matches!(action.lane_action, LaneAction::SuspendAdaptive));
    assert_eq!(action.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn preemptive_action_near_boundary_demotes_or_fallback() {
    let params = vec![make_param("x", 105_000)];
    let envelopes = vec![make_envelope("x", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    if result.has_preemptive_actions() {
        let action = &result.preemptive_actions[0];
        assert!(matches!(
            action.lane_action,
            LaneAction::Demote { .. } | LaneAction::FallbackSafe
        ));
    }
}

// ---------------------------------------------------------------------------
// 19. Stability maps — enabled vs disabled
// ---------------------------------------------------------------------------

#[test]
fn stability_maps_recorded_when_enabled() {
    let cfg = ScannerConfig {
        record_stability_maps: true,
        ..Default::default()
    };
    let params = vec![make_param("x", 500_000)];
    let envelopes = vec![make_envelope("x", 0, MILLION, 500_000)];
    let mut scanner = BifurcationBoundaryScanner::new(cfg, params, envelopes).unwrap();
    scanner.scan().unwrap();
    let maps = scanner.stability_maps();
    assert!(!maps.is_empty());
    let map = maps.get("x").unwrap();
    assert!(!map.is_empty());
    // All entries should have regime and stability
    for entry in map {
        assert!(entry.stability_millionths >= 0);
        assert!(entry.stability_millionths <= MILLION);
    }
}

#[test]
fn stability_maps_empty_when_disabled() {
    let mut scanner = default_scanner();
    scanner.scan().unwrap();
    assert!(scanner.stability_maps().is_empty());
}

// ---------------------------------------------------------------------------
// 20. Observation trend detection
// ---------------------------------------------------------------------------

#[test]
fn trend_computed_with_enough_observations() {
    let mut scanner = default_scanner();
    // Add 10 observations with upward trend
    for i in 0..10 {
        scanner.observe(ParameterObservation {
            parameter_id: "threshold-1".into(),
            value_millionths: 400_000 + i * 20_000,
            tick: i as u64,
            regime: RegimeLabel::Normal,
        });
    }
    let result = scanner.scan().unwrap();
    let warning = result
        .warnings
        .iter()
        .find(|w| w.parameter_id == "threshold-1")
        .unwrap();
    assert!(warning.observation_count >= 10);
    // With upward trend, trend should be positive
    assert!(warning.trend_millionths > 0);
}

#[test]
fn trend_zero_with_insufficient_observations() {
    let mut scanner = default_scanner();
    // Add only 3 observations (below MIN_OBSERVATIONS = 5)
    for i in 0..3 {
        scanner.observe(ParameterObservation {
            parameter_id: "threshold-1".into(),
            value_millionths: 400_000 + i * 20_000,
            tick: i as u64,
            regime: RegimeLabel::Normal,
        });
    }
    let result = scanner.scan().unwrap();
    let warning = result
        .warnings
        .iter()
        .find(|w| w.parameter_id == "threshold-1")
        .unwrap();
    assert_eq!(warning.trend_millionths, 0);
    assert_eq!(warning.observation_count, 3);
}

// ---------------------------------------------------------------------------
// 21. Determinism — same inputs produce same outputs
// ---------------------------------------------------------------------------

#[test]
fn scan_is_fully_deterministic() {
    let params = vec![make_param("a", 300_000), make_param("b", 700_000)];
    let envelopes = vec![
        make_envelope("a", 100_000, 900_000, 500_000),
        make_envelope("b", 200_000, 800_000, 500_000),
    ];

    let mut s1 = BifurcationBoundaryScanner::new(
        ScannerConfig::default(),
        params.clone(),
        envelopes.clone(),
    )
    .unwrap();
    let mut s2 =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();

    let r1 = s1.scan().unwrap();
    let r2 = s2.scan().unwrap();

    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(r1.stability_score_millionths, r2.stability_score_millionths);
    assert_eq!(r1.bifurcation_points.len(), r2.bifurcation_points.len());
    assert_eq!(r1.warnings.len(), r2.warnings.len());
    assert_eq!(r1.regime_summary, r2.regime_summary);
}

// ---------------------------------------------------------------------------
// 22. ScanResult serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn scan_result_serde_roundtrip() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: ScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.artifact_hash, back.artifact_hash);
    assert_eq!(result.parameters_scanned, back.parameters_scanned);
    assert_eq!(
        result.stability_score_millionths,
        back.stability_score_millionths
    );
    assert_eq!(result.schema_version, back.schema_version);
}

#[test]
fn scan_result_json_field_presence() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    let j = serde_json::to_string(&result).unwrap();
    assert!(j.contains("\"schema_version\""));
    assert!(j.contains("\"stability_score_millionths\""));
    assert!(j.contains("\"artifact_hash\""));
    assert!(j.contains("\"regime_summary\""));
    assert!(j.contains("\"bifurcation_points\""));
    assert!(j.contains("\"warnings\""));
    assert!(j.contains("\"preemptive_actions\""));
}

// ---------------------------------------------------------------------------
// 23. Scanner serde roundtrip (the scanner itself)
// ---------------------------------------------------------------------------

#[test]
fn scanner_serde_roundtrip() {
    let mut scanner = default_scanner();
    scanner.observe(ParameterObservation {
        parameter_id: "threshold-1".into(),
        value_millionths: 600_000,
        tick: 1,
        regime: RegimeLabel::Normal,
    });
    scanner.scan().unwrap();
    let json = serde_json::to_string(&scanner).unwrap();
    let back: BifurcationBoundaryScanner = serde_json::from_str(&json).unwrap();
    assert_eq!(back.scan_count(), 1);
    assert_eq!(back.observation_count(), 1);
    assert_eq!(back.parameter_count(), 2);
}

// ---------------------------------------------------------------------------
// 24. Unmonitored parameter (param without matching envelope)
// ---------------------------------------------------------------------------

#[test]
fn unmonitored_parameter_counted_as_stable() {
    let params = vec![
        make_param("monitored", 500_000),
        make_param("unmonitored", 500_000),
    ];
    // Only provide envelope for "monitored"
    let envelopes = vec![make_envelope("monitored", 100_000, 900_000, 500_000)];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert_eq!(result.parameters_scanned, 2);
    assert!(result.regime_summary.contains_key("unmonitored"));
}

// ---------------------------------------------------------------------------
// 25. Full lifecycle — multi-step observe/update/scan
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_observe_update_scan_repeat() {
    let params = vec![
        make_param_domain("risk", 500_000, ParameterDomain::RiskThreshold),
        make_param_domain("cal", 500_000, ParameterDomain::Calibration),
    ];
    let envelopes = vec![
        make_envelope("risk", 100_000, 900_000, 500_000),
        make_envelope("cal", 200_000, 800_000, 500_000),
    ];
    let cfg = ScannerConfig {
        record_stability_maps: true,
        scan_steps: 10,
        ..Default::default()
    };
    let mut scanner = BifurcationBoundaryScanner::new(cfg, params, envelopes).unwrap();

    // Phase 1: stable
    let r1 = scanner.scan().unwrap();
    assert!(r1.is_stable());
    assert_eq!(scanner.scan_count(), 1);

    // Phase 2: add observations and move risk parameter toward boundary
    for i in 0..8 {
        scanner.observe(ParameterObservation {
            parameter_id: "risk".into(),
            value_millionths: 500_000 - i * 40_000,
            tick: i as u64,
            regime: RegimeLabel::Normal,
        });
    }
    // Now risk is at 500_000 - 7*40_000 = 220_000 — near lower boundary
    let r2 = scanner.scan().unwrap();
    assert_eq!(scanner.scan_count(), 2);
    // Stability should have decreased
    assert!(r2.stability_score_millionths <= r1.stability_score_millionths);

    // Phase 3: push out of bounds
    scanner.update_parameter("risk", 50_000);
    let r3 = scanner.scan().unwrap();
    assert_eq!(scanner.scan_count(), 3);
    assert!(r3.has_preemptive_actions());
    assert!(!r3.is_stable());

    // Stability maps should be populated
    assert!(!scanner.stability_maps().is_empty());
}

#[test]
fn multiple_parameters_mixed_domains() {
    let params = vec![
        make_param_domain("env-temp", 500_000, ParameterDomain::Environment),
        make_param_domain("lane-w", 400_000, ParameterDomain::LaneRouting),
        make_param_domain("safe-b", 600_000, ParameterDomain::SafetyBoundary),
        make_param_domain("res-a", 300_000, ParameterDomain::ResourceAllocation),
    ];
    let envelopes = vec![
        make_envelope("env-temp", 0, MILLION, 500_000),
        make_envelope("lane-w", 100_000, 700_000, 400_000),
        make_envelope("safe-b", 200_000, 800_000, 500_000),
        make_envelope("res-a", 100_000, 600_000, 350_000),
    ];
    let mut scanner =
        BifurcationBoundaryScanner::new(ScannerConfig::default(), params, envelopes).unwrap();
    assert_eq!(scanner.parameter_count(), 4);
    let result = scanner.scan().unwrap();
    assert_eq!(result.parameters_scanned, 4);
    // Each parameter should contribute a warning (active or not)
    assert_eq!(result.warnings.len(), 4);
}

// ---------------------------------------------------------------------------
// 26. Custom epoch propagation
// ---------------------------------------------------------------------------

#[test]
fn custom_epoch_propagated_to_scan_result() {
    let cfg = ScannerConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..Default::default()
    };
    let params = vec![make_param("x", 500_000)];
    let envelopes = vec![make_envelope("x", 0, MILLION, 500_000)];
    let mut scanner = BifurcationBoundaryScanner::new(cfg, params, envelopes).unwrap();
    let result = scanner.scan().unwrap();
    assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
}

// ---------------------------------------------------------------------------
// 27. Bifurcation point details from scan
// ---------------------------------------------------------------------------

#[test]
fn bifurcation_points_have_valid_fields() {
    let mut scanner = default_scanner();
    let result = scanner.scan().unwrap();
    for bp in &result.bifurcation_points {
        assert!(!bp.parameter_id.is_empty());
        assert!(bp.confidence_millionths >= 0);
        assert!(bp.confidence_millionths <= MILLION);
    }
}

// ---------------------------------------------------------------------------
// 28. Downward trend detection
// ---------------------------------------------------------------------------

#[test]
fn downward_trend_detected() {
    let mut scanner = default_scanner();
    // Observations with downward trend (values decreasing toward lower boundary)
    for i in 0..10 {
        scanner.observe(ParameterObservation {
            parameter_id: "threshold-1".into(),
            value_millionths: 800_000 - i * 30_000,
            tick: i as u64,
            regime: RegimeLabel::Normal,
        });
    }
    let result = scanner.scan().unwrap();
    let warning = result
        .warnings
        .iter()
        .find(|w| w.parameter_id == "threshold-1")
        .unwrap();
    assert!(warning.trend_millionths < 0, "expected negative trend");
}
